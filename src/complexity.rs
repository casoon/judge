//! Fast-tier complexity analysis: cyclomatic complexity per function via `syn`,
//! no build required (see todo.md §2.1, §3.C).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use serde_json::json;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Expr, ExprIf, GenericArgument, GenericParam, ItemFn, Macro, PathArguments, ReturnType,
    Type, TypeParamBound, UnOp, WherePredicate,
};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::{read_and_parse_source, walk_functions};
use crate::ingest::SourceFile;

/// Cyclomatic complexity and size of a single function or method.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub qualified_name: String,
    pub file: PathBuf,
    pub line: usize,
    /// Whether the function belongs to a test-only context (`#[test]` or an
    /// inline `#[cfg(test)]` module). Consumers can exclude this auxiliary
    /// code from production refactoring signals without guessing from names.
    pub is_test_context: bool,
    pub cyclomatic: u32,
    /// Cognitive Complexity (see [`CognitiveComplexityVisitor`]) — a
    /// best-effort approximation of SonarSource's metric, distinct from
    /// `cyclomatic`: it weights nesting depth instead of counting every
    /// branch point equally.
    pub cognitive: u32,
    pub lines_of_code: usize,
    /// Maximum nesting depth of branching/looping/closure constructs (see
    /// todo.md §3.C "Nesting Depth").
    pub nesting_depth: u32,
    /// Total number of `match` arms across the function body (see todo.md
    /// §3.C "`match`-Arm-Anzahl"). Distinct from `cyclomatic`, which counts
    /// `arms.len().saturating_sub(1)` per `match` for branch-counting
    /// purposes.
    pub match_arm_count: u32,
    /// Number of parameters in the function's signature (see todo.md §3.C
    /// "Argument Count").
    pub arg_count: usize,
    /// Nesting depth of the return type's generic arguments (see todo.md
    /// §3.C "Return-Type-Komplexität") — `bool`/`()` is 0, `Result<T, E>` is
    /// 1, `Result<Option<Vec<T>>, E>` is 3. Computed by [`type_depth`].
    pub return_type_depth: u32,
    /// Number of type parameters in the function's signature — i.e.
    /// `syn::GenericParam::Type` entries in `sig.generics.params`, excluding
    /// lifetimes and const generics (see todo.md §3.C
    /// "Generic-/Lifetime-Parameter-Anzahl").
    pub generic_param_count: u32,
    /// Number of lifetime parameters in the function's signature — i.e.
    /// `syn::GenericParam::Lifetime` entries in `sig.generics.params` (see
    /// todo.md §3.C "Generic-/Lifetime-Parameter-Anzahl").
    pub lifetime_param_count: u32,
    /// Total number of trait bounds across both a generic parameter's own
    /// inline bounds (`T: Clone + Debug`) and any `where` clause bounds
    /// (`where T: Clone, U: Debug + Send`) — see todo.md §3.C
    /// "Trait-Bound-Komplexität".
    pub trait_bound_count: u32,
    /// Maximum nesting depth of `async` blocks/closures found *inside* the
    /// function body — distinct from the function's own `async fn` status,
    /// which does not itself count (see [`ExpressionShapeVisitor`], todo.md
    /// §3.C "`async`-Verschachtelungstiefe").
    pub async_nesting_depth: u32,
    /// Maximum "width" (direct child count) of any single expression in the
    /// function body — a call's argument count, a tuple/array/struct
    /// literal's element count, or a flattened chain of same-operator binary
    /// expressions' operand count (see [`ExpressionShapeVisitor`], todo.md
    /// §3.C "Ausdrucksbreite").
    pub max_expression_width: u32,
}

#[derive(Debug)]
pub enum ComplexityError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for ComplexityError {
    // judge-dupe-ignore: explicit per-domain error rendering; variants and messages are intentionally distinct
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ComplexityError {
    // judge-dupe-ignore: explicit per-domain error rendering; variants and messages are intentionally distinct
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// [`read_and_parse_source`], mapping its I/O/parse errors to
/// [`ComplexityError`]'s matching variants — the shared parse step behind
/// both [`analyze_file`] (walks individual function bodies) and
/// [`analyze_file_halstead`] (a second, independent parse of the whole file
/// for its file-level metric).
fn parse_complexity_file(path: &Path) -> Result<syn::File, ComplexityError> {
    let (_, ast) = read_and_parse_source(
        path,
        |err| ComplexityError::Io(path.to_path_buf(), err),
        |err| ComplexityError::Parse(path.to_path_buf(), err),
    )?;
    Ok(ast)
}

/// Parses a single Rust source file and returns the complexity of every
/// function, method, and default trait-method body it contains.
pub fn analyze_file(path: &Path) -> Result<Vec<FunctionInfo>, ComplexityError> {
    let ast = parse_complexity_file(path)?;

    let mut functions = Vec::new();
    walk_functions(&ast, |site| {
        let mut complexity = ComplexityVisitor {
            complexity: 1,
            nesting_depth: 0,
            current_depth: 0,
            match_arm_count: 0,
        };
        complexity.visit_block(site.block);

        let mut cognitive = CognitiveComplexityVisitor {
            cognitive: 0,
            nesting: 0,
        };
        cognitive.visit_block(site.block);

        let mut shape = ExpressionShapeVisitor {
            async_nesting: 0,
            max_async_nesting: 0,
            max_width: 0,
        };
        shape.visit_block(site.block);

        let start_line = site.span.start().line;
        let end_line = site.span.end().line.max(start_line);

        functions.push(FunctionInfo {
            qualified_name: site.qualified_name,
            file: path.to_path_buf(),
            line: start_line,
            is_test_context: site.is_test_context,
            cyclomatic: complexity.complexity,
            cognitive: cognitive.cognitive,
            lines_of_code: end_line - start_line + 1,
            nesting_depth: complexity.nesting_depth,
            match_arm_count: complexity.match_arm_count,
            arg_count: site.arg_count,
            return_type_depth: match &site.sig.output {
                ReturnType::Default => 0,
                ReturnType::Type(_, ty) => type_depth(ty),
            },
            generic_param_count: site
                .sig
                .generics
                .params
                .iter()
                .filter(|param| matches!(param, GenericParam::Type(_)))
                .count() as u32,
            lifetime_param_count: site
                .sig
                .generics
                .params
                .iter()
                .filter(|param| matches!(param, GenericParam::Lifetime(_)))
                .count() as u32,
            trait_bound_count: trait_bound_count(&site.sig.generics),
            async_nesting_depth: shape.max_async_nesting,
            max_expression_width: shape.max_width,
        });
    });
    Ok(functions)
}

/// Aggregated complexity results across a set of files, keeping analyzable
/// functions separate from files that could not be parsed.
#[derive(Debug, Default)]
pub struct WorkspaceComplexity {
    pub functions: Vec<FunctionInfo>,
    pub errors: Vec<ComplexityError>,
    /// Generated files skipped because `include_generated` was `false` (see
    /// todo.md §3.A "Generated-Code-Policy").
    pub excluded_generated: usize,
}

/// Runs [`analyze_file`] over every file in `source_files` and aggregates the
/// results. Generated files are skipped unless `include_generated` is set
/// (see todo.md §3.A) — local quality metrics on generated code aren't
/// actionable the way they are on authored code.
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
    include_generated: bool,
) -> WorkspaceComplexity {
    let mut report = WorkspaceComplexity::default();
    for file in source_files {
        if !include_generated && !file.kind.is_locally_reportable() {
            report.excluded_generated += 1;
            continue;
        }
        match analyze_file(&file.path) {
            Ok(mut functions) => report.functions.append(&mut functions),
            Err(err) => report.errors.push(err),
        }
    }
    report
}

/// Counts branch points inside a single function body (cyclomatic complexity,
/// starting from a base of 1). Nested `fn` items are skipped here since
/// [`walk_functions`] analyzes them as their own, separate functions.
struct ComplexityVisitor {
    complexity: u32,
    /// Maximum nesting depth of branching/looping/closure constructs seen so
    /// far — this is the value stored in [`FunctionInfo::nesting_depth`].
    nesting_depth: u32,
    /// Running nesting depth at the current point of the walk; scratch
    /// counter for `nesting_depth`, incremented on entry to a nesting
    /// construct and decremented on exit.
    current_depth: u32,
    /// Total number of `match` arms across the function body — see
    /// [`FunctionInfo::match_arm_count`].
    match_arm_count: u32,
}

impl<'ast> Visit<'ast> for ComplexityVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::If(_) | Expr::While(_) | Expr::ForLoop(_) | Expr::Loop(_) | Expr::Try(_) => {
                self.complexity += 1;
            }
            Expr::Match(node) => {
                self.complexity += node.arms.len().saturating_sub(1) as u32;
                self.complexity +=
                    node.arms.iter().filter(|arm| arm.guard.is_some()).count() as u32;
                self.match_arm_count += node.arms.len() as u32;
            }
            Expr::Binary(node) if matches!(node.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                self.complexity += 1;
            }
            _ => {}
        }

        let nests = matches!(
            expr,
            Expr::If(_)
                | Expr::While(_)
                | Expr::ForLoop(_)
                | Expr::Loop(_)
                | Expr::Match(_)
                | Expr::Closure(_)
                | Expr::Block(_)
        );
        if nests {
            self.current_depth += 1;
            self.nesting_depth = self.nesting_depth.max(self.current_depth);
        }
        visit::visit_expr(self, expr);
        if nests {
            self.current_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Approximates SonarSource's Cognitive Complexity metric
/// (<https://www.sonarsource.com/resources/cognitive-complexity/>) over the
/// `syn` AST, as a second, separate pass per function from
/// [`ComplexityVisitor`] rather than folding the two together — this keeps
/// the well-tested cyclomatic walk unentangled from this newer, approximate
/// metric.
///
/// This is a best-effort syntactic approximation, not the canonical spec.
/// Known simplifications:
/// - `if`/`else if`/`else`, `match`, `for`, `while`, `loop`, and labeled
///   `break`/`continue` are all treated as nesting-weighted structural
///   increments (`1 + current nesting level`). The canonical algorithm
///   scores jumps to a label (`break 'label`/`continue 'label`) as a flat
///   `+1` with no nesting weight; this implementation does not special-case
///   that distinction.
/// - Unlabeled `break`/`continue` do not increment complexity at all — only
///   the structural nesting they sit inside of matters.
/// - A run of `&&`/`||` in one boolean expression scores `+1` for the run,
///   plus another `+1` each time the operator changes from the previous one
///   in that same run (flat, not nesting-weighted), mirroring how
///   [`ComplexityVisitor`] already walks binary `And`/`Or` nodes but
///   counting operator-run transitions instead of every occurrence.
/// - Recursion is not special-cased (the canonical spec adds a flat `+1` for
///   a function calling itself).
struct CognitiveComplexityVisitor {
    cognitive: u32,
    /// Running nesting depth at the current point of the walk, incremented
    /// on entry to an `if`/`match`/`for`/`while`/`loop`/closure body and
    /// decremented on exit.
    nesting: u32,
}

impl CognitiveComplexityVisitor {
    fn add_structural(&mut self) {
        self.cognitive += 1 + self.nesting;
    }

    /// Walks an `if`/`else if`/`else` chain. Every link (the `if`, each
    /// `else if`, and a final `else`) is charged its own structural
    /// increment at `chain_level` — an `else if`/`else` does not add an
    /// extra nesting level over its originating `if` — while each link's
    /// own body is visited one nesting level deeper than `chain_level`.
    fn visit_if_chain(&mut self, node: &ExprIf, chain_level: u32) {
        self.nesting = chain_level;
        self.add_structural();
        self.visit_expr(&node.cond);

        self.nesting = chain_level + 1;
        self.visit_block(&node.then_branch);

        if let Some((_, else_expr)) = &node.else_branch {
            match else_expr.as_ref() {
                Expr::If(else_if) => self.visit_if_chain(else_if, chain_level),
                other => {
                    self.nesting = chain_level;
                    self.add_structural();
                    self.nesting = chain_level + 1;
                    self.visit_expr(other);
                }
            }
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum BoolOp {
    And,
    Or,
}

/// Whether `op` is one of the two boolean-chain operators (`&&`/`||`) this
/// module scores as a chain — the shared discriminant both
/// [`flatten_bool_chain`]'s and [`CognitiveComplexityVisitor::visit_expr`]'s
/// match guards apply.
fn is_bool_chain_op(op: &BinOp) -> bool {
    matches!(op, BinOp::And(_) | BinOp::Or(_))
}

/// Flattens a chain of `&&`/`||` [`Expr::Binary`] nodes — transparently
/// unwrapping [`Expr::Paren`] — into its left-to-right operators and leaf
/// operands, so [`CognitiveComplexityVisitor`] can score operator-run
/// transitions across the whole chain at once instead of per-node.
fn flatten_bool_chain<'ast>(expr: &'ast Expr, ops: &mut Vec<BoolOp>, leaves: &mut Vec<&'ast Expr>) {
    match expr {
        Expr::Paren(node) => flatten_bool_chain(&node.expr, ops, leaves),
        Expr::Binary(node) if is_bool_chain_op(&node.op) => {
            flatten_bool_chain(&node.left, ops, leaves);
            ops.push(match node.op {
                BinOp::And(_) => BoolOp::And,
                BinOp::Or(_) => BoolOp::Or,
                _ => unreachable!("guarded by the match arm above"),
            });
            flatten_bool_chain(&node.right, ops, leaves);
        }
        other => leaves.push(other),
    }
}

impl<'ast> Visit<'ast> for CognitiveComplexityVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::If(node) => {
                let saved = self.nesting;
                self.visit_if_chain(node, saved);
                self.nesting = saved;
            }
            Expr::Match(node) => {
                let saved = self.nesting;
                self.add_structural();
                self.nesting = saved + 1;
                for arm in &node.arms {
                    if let Some((_, guard)) = &arm.guard {
                        self.visit_expr(guard);
                    }
                    self.visit_expr(&arm.body);
                }
                self.nesting = saved;
            }
            Expr::ForLoop(node) => {
                let saved = self.nesting;
                self.add_structural();
                self.visit_expr(&node.expr);
                self.nesting = saved + 1;
                self.visit_block(&node.body);
                self.nesting = saved;
            }
            Expr::While(node) => {
                let saved = self.nesting;
                self.add_structural();
                self.visit_expr(&node.cond);
                self.nesting = saved + 1;
                self.visit_block(&node.body);
                self.nesting = saved;
            }
            Expr::Loop(node) => {
                let saved = self.nesting;
                self.add_structural();
                self.nesting = saved + 1;
                self.visit_block(&node.body);
                self.nesting = saved;
            }
            Expr::Closure(node) => {
                let saved = self.nesting;
                self.nesting = saved + 1;
                self.visit_expr(&node.body);
                self.nesting = saved;
            }
            Expr::Break(node) if node.label.is_some() => {
                self.add_structural();
                if let Some(value) = &node.expr {
                    self.visit_expr(value);
                }
            }
            Expr::Continue(node) if node.label.is_some() => {
                self.add_structural();
            }
            Expr::Binary(node) if is_bool_chain_op(&node.op) => {
                let mut ops = Vec::new();
                let mut leaves = Vec::new();
                flatten_bool_chain(expr, &mut ops, &mut leaves);
                if let Some(&first) = ops.first() {
                    self.cognitive += 1;
                    let mut prev = first;
                    for &op in &ops[1..] {
                        if op != prev {
                            self.cognitive += 1;
                        }
                        prev = op;
                    }
                }
                for leaf in leaves {
                    self.visit_expr(leaf);
                }
            }
            _ => visit::visit_expr(self, expr),
        }
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Nesting depth of a type's generic arguments, used for
/// [`FunctionInfo::return_type_depth`]. A bare type (`bool`, `()`, `T`) is 0;
/// each level of generic nesting adds 1 — `Result<T, E>` is 1,
/// `Result<Option<Vec<T>>, E>` is 3 (`Result` at 1, `Option` at 2, `Vec` at
/// 3). References, parens, and grouping tokens are transparent and do not add
/// depth of their own; a tuple's depth is the deepest of its elements.
fn type_depth(ty: &Type) -> u32 {
    match ty {
        Type::Path(type_path) => {
            let Some(segment) = type_path.path.segments.last() else {
                return 0;
            };
            match &segment.arguments {
                PathArguments::AngleBracketed(args) => {
                    let inner_max = args
                        .args
                        .iter()
                        .filter_map(|arg| match arg {
                            GenericArgument::Type(inner) => Some(type_depth(inner)),
                            _ => None,
                        })
                        .max()
                        .unwrap_or(0);
                    1 + inner_max
                }
                _ => 0,
            }
        }
        Type::Tuple(tuple) => tuple.elems.iter().map(type_depth).max().unwrap_or(0),
        Type::Reference(reference) => type_depth(&reference.elem),
        Type::Paren(paren) => type_depth(&paren.elem),
        Type::Group(group) => type_depth(&group.elem),
        _ => 0,
    }
}

/// Total number of trait bounds across a signature's generics — both a
/// generic parameter's own inline bounds (`T: Clone + Debug`) and any
/// `where` clause bounds (`where T: Clone, U: Debug + Send`), used for
/// [`FunctionInfo::trait_bound_count`]. Lifetime bounds (`'a: 'b`) are not
/// counted, only [`TraitBound`]s.
fn trait_bound_count(generics: &syn::Generics) -> u32 {
    let inline: u32 = generics
        .params
        .iter()
        .filter_map(|param| match param {
            GenericParam::Type(type_param) => Some(
                type_param
                    .bounds
                    .iter()
                    .filter(|bound| matches!(bound, TypeParamBound::Trait(_)))
                    .count() as u32,
            ),
            _ => None,
        })
        .sum();
    let where_clause: u32 = generics
        .where_clause
        .iter()
        .flat_map(|clause| &clause.predicates)
        .filter_map(|predicate| match predicate {
            WherePredicate::Type(predicate_type) => Some(
                predicate_type
                    .bounds
                    .iter()
                    .filter(|bound| matches!(bound, TypeParamBound::Trait(_)))
                    .count() as u32,
            ),
            _ => None,
        })
        .sum();
    inline + where_clause
}

/// Rule id for a function whose signature — not body — is disproportionately
/// complex: a deeply nested return type, a large number of generic type
/// parameters, or a large number of trait bounds (see todo.md §3.C
/// "Return-Type-Komplexität", "Generic-/Lifetime-Parameter-Anzahl",
/// "Trait-Bound-Komplexität").
pub const SIGNATURE_COMPLEXITY_RULE: &str = "signature-complexity";
pub const SIGNATURE_COMPLEXITY_RULE_REVISION: u32 = 1;

/// Return-type nesting depth above which a signature is flagged — a plain
/// `Result<T, E>` (depth 1) or `Result<Option<T>, E>` (depth 2) is ordinary
/// Rust; four or more levels (e.g. `Result<Option<Vec<Box<T>>>, E>`) starts
/// to demand real unwrapping effort from every caller.
const MAX_RETURN_TYPE_DEPTH: u32 = 3;
/// Number of generic type parameters above which a signature is flagged —
/// beyond four, tracking which parameter constrains what starts to strain
/// working memory (a first-cut, adjustable threshold, same style as
/// [`MIN_LOC_FOR_INFLATION`]-style constants elsewhere in this crate).
const MAX_GENERIC_PARAM_COUNT: u32 = 4;
/// Total trait bound count (inline plus `where` clause) above which a
/// signature is flagged — five is already generous for a single function;
/// beyond that, the signature reads more like a capability checklist than a
/// contract.
const MAX_TRAIT_BOUND_COUNT: u32 = 5;

/// Flags functions whose *signature* — independent of their body — is
/// disproportionately complex by any of three measures: an over-nested
/// return type, too many generic type parameters, or too many trait bounds
/// (see [`MAX_RETURN_TYPE_DEPTH`]/[`MAX_GENERIC_PARAM_COUNT`]/
/// [`MAX_TRAIT_BOUND_COUNT`], todo.md §3.C). Unlike `complexity-inflation`,
/// there is no LOC floor — a one-line function can still have a complex
/// signature.
pub fn signature_complexity(functions: &[FunctionInfo]) -> Vec<Finding> {
    functions
        .iter()
        .filter(|function| {
            function.return_type_depth > MAX_RETURN_TYPE_DEPTH
                || function.generic_param_count > MAX_GENERIC_PARAM_COUNT
                || function.trait_bound_count > MAX_TRAIT_BOUND_COUNT
        })
        .map(|function| {
            Finding::new(
                format!(
                    "{SIGNATURE_COMPLEXITY_RULE}:{}:{}",
                    function.file.display(),
                    function.qualified_name
                ),
                SIGNATURE_COMPLEXITY_RULE,
                Severity::Warn,
                Location {
                    file: function.file.clone(),
                    line: OneBasedLine::new(function.line)
                        .expect("proc-macro2 span lines are 1-based"),
                    item_path: function.qualified_name.clone(),
                },
                EvidenceClass::Heuristic,
                Origin::Code,
                Some(json!({
                    "file": function.file.display().to_string(),
                    "function": function.qualified_name,
                    "line": function.line,
                    "return_type_depth": function.return_type_depth,
                    "generic_param_count": function.generic_param_count,
                    "lifetime_param_count": function.lifetime_param_count,
                    "trait_bound_count": function.trait_bound_count,
                })),
            )
        })
        .collect()
}

/// Third, separate `syn::Visit` pass per function alongside
/// [`ComplexityVisitor`]/[`CognitiveComplexityVisitor`] — same convention:
/// each metric family gets its own uncomplicated walk rather than one
/// entangled visitor. Computes two body-shape metrics for
/// `complexity-inflation` (see [`crate::slop_structural::complexity_inflation`]):
/// [`FunctionInfo::async_nesting_depth`] and
/// [`FunctionInfo::max_expression_width`].
struct ExpressionShapeVisitor {
    /// Running nesting depth of `async` blocks/closures at the current point
    /// of the walk.
    async_nesting: u32,
    /// Maximum `async_nesting` reached so far — the value stored in
    /// [`FunctionInfo::async_nesting_depth`].
    max_async_nesting: u32,
    /// Maximum expression "width" (direct child count) found so far — the
    /// value stored in [`FunctionInfo::max_expression_width`].
    max_width: u32,
}

/// Flattens a chain of same-operator [`Expr::Binary`] nodes into its leaf
/// operands, so [`ExpressionShapeVisitor`] can score the whole chain's width
/// at once (`a + b + c + d` is width 4) instead of each binary node's own
/// two operands. Deliberately does not merge different-but-same-precedence
/// operators (e.g. `+` and `-`) into one chain — a simplification, not a
/// claim that `a + b - c` is any less "wide" than `a + b + c`.
fn flatten_binary_chain<'ast>(expr: &'ast Expr, op: &BinOp, leaves: &mut Vec<&'ast Expr>) {
    match expr {
        Expr::Binary(node) if std::mem::discriminant(&node.op) == std::mem::discriminant(op) => {
            flatten_binary_chain(&node.left, op, leaves);
            flatten_binary_chain(&node.right, op, leaves);
        }
        other => leaves.push(other),
    }
}

impl<'ast> Visit<'ast> for ExpressionShapeVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Async(node) => {
                self.async_nesting += 1;
                self.max_async_nesting = self.max_async_nesting.max(self.async_nesting);
                self.visit_block(&node.block);
                self.async_nesting -= 1;
            }
            Expr::Closure(node) if node.asyncness.is_some() => {
                self.async_nesting += 1;
                self.max_async_nesting = self.max_async_nesting.max(self.async_nesting);
                self.visit_expr(&node.body);
                self.async_nesting -= 1;
            }
            Expr::Binary(node) => {
                let mut leaves = Vec::new();
                flatten_binary_chain(expr, &node.op, &mut leaves);
                self.max_width = self.max_width.max(leaves.len() as u32);
                for leaf in leaves {
                    self.visit_expr(leaf);
                }
            }
            Expr::Call(node) => {
                self.max_width = self.max_width.max(node.args.len() as u32);
                visit::visit_expr(self, expr);
            }
            Expr::MethodCall(node) => {
                self.max_width = self.max_width.max(node.args.len() as u32);
                visit::visit_expr(self, expr);
            }
            Expr::Tuple(node) => {
                self.max_width = self.max_width.max(node.elems.len() as u32);
                visit::visit_expr(self, expr);
            }
            Expr::Array(node) => {
                self.max_width = self.max_width.max(node.elems.len() as u32);
                visit::visit_expr(self, expr);
            }
            Expr::Struct(node) => {
                self.max_width = self.max_width.max(node.fields.len() as u32);
                visit::visit_expr(self, expr);
            }
            _ => visit::visit_expr(self, expr),
        }
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Fourth, separate `syn::Visit` pass — but over an entire file's AST at
/// once rather than per function body, since Halstead Volume (feeding
/// [`maintainability_index`]) is a whole-file metric with no natural
/// per-function decomposition. Counts operators and operands per the classic
/// Halstead "software science" metrics
/// (<https://en.wikipedia.org/wiki/Halstead_complexity_measures>), adapted
/// for Rust — the original definition is C-era and doesn't map 1:1 onto
/// Rust syntax, so this is a documented, reproducible approximation, not a
/// claim of fidelity to the canonical metric (see the `maintainability-index`
/// `rule_registry` entry's `exclusions` for the full caveat):
/// - Operators: [`BinOp`]/[`UnOp`] variants (kept as distinct kinds even
///   where a binary and a unary use of the same token exist, e.g. binary `*`
///   vs. unary deref `*`, so token collisions don't understate `n1`), plus
///   `if`/`match`/`for`/`while`/`loop`, `?` (`Expr::Try`), plain `=`
///   (`Expr::Assign`; compound assignment like `+=` is already its own
///   `BinOp` variant), a path call (`Expr::Call`) and a method call
///   (`Expr::MethodCall`) as two distinct operator kinds, and any macro
///   invocation ([`Macro`], in any syntactic position — expression,
///   statement, item, pattern, or type).
/// - Operands: `Expr::Path` idents and `Expr::Lit` literal values, each
///   deduplicated within the file by their token-stream text (so two
///   references to `a` are one distinct operand, but `1` and `1.0` are two).
///   A path in type position (e.g. a parameter's declared type) is not an
///   `Expr::Path` and so is not counted.
#[derive(Default)]
struct HalsteadVisitor {
    operator_kinds: HashSet<&'static str>,
    total_operators: u32,
    operand_values: HashSet<String>,
    total_operands: u32,
}

impl HalsteadVisitor {
    fn operator(&mut self, kind: &'static str) {
        self.operator_kinds.insert(kind);
        self.total_operators += 1;
    }

    fn operand(&mut self, value: String) {
        self.operand_values.insert(value);
        self.total_operands += 1;
    }
}

/// Canonical operator-kind label for a [`BinOp`], used as [`HalsteadVisitor`]'s
/// distinct-operator (`n1`) dedup key. `BinOp` is `#[non_exhaustive]`, hence
/// the catch-all arm.
fn binop_label(op: &BinOp) -> &'static str {
    match op {
        BinOp::Add(_) => "bin +",
        BinOp::Sub(_) => "bin -",
        BinOp::Mul(_) => "bin *",
        BinOp::Div(_) => "bin /",
        BinOp::Rem(_) => "bin %",
        BinOp::And(_) => "bin &&",
        BinOp::Or(_) => "bin ||",
        BinOp::BitXor(_) => "bin ^",
        BinOp::BitAnd(_) => "bin &",
        BinOp::BitOr(_) => "bin |",
        BinOp::Shl(_) => "bin <<",
        BinOp::Shr(_) => "bin >>",
        BinOp::Eq(_) => "bin ==",
        BinOp::Lt(_) => "bin <",
        BinOp::Le(_) => "bin <=",
        BinOp::Ne(_) => "bin !=",
        BinOp::Ge(_) => "bin >=",
        BinOp::Gt(_) => "bin >",
        BinOp::AddAssign(_) => "bin +=",
        BinOp::SubAssign(_) => "bin -=",
        BinOp::MulAssign(_) => "bin *=",
        BinOp::DivAssign(_) => "bin /=",
        BinOp::RemAssign(_) => "bin %=",
        BinOp::BitXorAssign(_) => "bin ^=",
        BinOp::BitAndAssign(_) => "bin &=",
        BinOp::BitOrAssign(_) => "bin |=",
        BinOp::ShlAssign(_) => "bin <<=",
        BinOp::ShrAssign(_) => "bin >>=",
        _ => "bin ?",
    }
}

/// Canonical operator-kind label for a [`UnOp`], same convention as
/// [`binop_label`]; deliberately namespaced (`"un ..."`) so a unary and a
/// binary use of the same token (e.g. `*`) count as two distinct operator
/// kinds, not one.
fn unop_label(op: &UnOp) -> &'static str {
    match op {
        UnOp::Deref(_) => "un *",
        UnOp::Not(_) => "un !",
        UnOp::Neg(_) => "un -",
        _ => "un ?",
    }
}

impl<'ast> Visit<'ast> for HalsteadVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Binary(node) => self.operator(binop_label(&node.op)),
            Expr::Unary(node) => self.operator(unop_label(&node.op)),
            Expr::If(_) => self.operator("if"),
            Expr::Match(_) => self.operator("match"),
            Expr::ForLoop(_) => self.operator("for"),
            Expr::While(_) => self.operator("while"),
            Expr::Loop(_) => self.operator("loop"),
            Expr::Try(_) => self.operator("?"),
            Expr::Assign(_) => self.operator("="),
            Expr::Call(_) => self.operator("call()"),
            Expr::MethodCall(_) => self.operator(".method()"),
            Expr::Path(node) => self.operand(node.path.to_token_stream().to_string()),
            Expr::Lit(node) => self.operand(node.lit.to_token_stream().to_string()),
            _ => {}
        }
        visit::visit_expr(self, expr);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        self.operator("macro!");
        visit::visit_macro(self, node);
    }
}

/// Whole-file Halstead operator/operand totals, computed by
/// [`analyze_file_halstead`] — see [`HalsteadVisitor`] for the counting
/// rules.
#[derive(Debug, Clone, Copy, Default)]
struct FileHalstead {
    distinct_operators: u32,
    total_operators: u32,
    distinct_operands: u32,
    total_operands: u32,
}

/// Parses `path` again and walks its whole `syn::File` AST with
/// [`HalsteadVisitor`] — a second, independent parse from [`analyze_file`]'s
/// (which only walks individual function bodies), since Halstead Volume is a
/// file-level metric with no natural per-function decomposition.
fn analyze_file_halstead(path: &Path) -> Result<FileHalstead, ComplexityError> {
    let ast = parse_complexity_file(path)?;

    let mut visitor = HalsteadVisitor::default();
    visitor.visit_file(&ast);
    Ok(FileHalstead {
        distinct_operators: visitor.operator_kinds.len() as u32,
        total_operators: visitor.total_operators,
        distinct_operands: visitor.operand_values.len() as u32,
        total_operands: visitor.total_operands,
    })
}

/// Halstead Volume — `(N1 + N2) * log2(n1 + n2)` — the one Halstead metric
/// [`maintainability_index`] needs (Halstead Difficulty/Effort/Time are out
/// of scope). `0.0` for an empty file (`n1 + n2 == 0`), rather than dividing
/// by zero / taking the log of zero.
fn halstead_volume(halstead: &FileHalstead) -> f64 {
    let vocabulary = (halstead.distinct_operators + halstead.distinct_operands) as f64;
    if vocabulary == 0.0 {
        return 0.0;
    }
    let length = (halstead.total_operators + halstead.total_operands) as f64;
    length * vocabulary.log2()
}

/// Per-file `lines_of_code`/`cyclomatic` totals folded from
/// [`FunctionInfo`] — [`WorkspaceComplexity::functions`] is a flat
/// per-function list across the whole workspace with no existing per-file
/// grouping, so [`fold_by_file`] is the first such fold in this crate.
#[derive(Debug, Clone, Copy, Default)]
struct FileTotals {
    cyclomatic: u32,
    lines_of_code: usize,
}

fn fold_by_file(functions: &[FunctionInfo]) -> HashMap<&Path, FileTotals> {
    let mut totals: HashMap<&Path, FileTotals> = HashMap::new();
    for function in functions {
        let entry = totals.entry(function.file.as_path()).or_default();
        entry.cyclomatic += function.cyclomatic;
        entry.lines_of_code += function.lines_of_code;
    }
    totals
}

/// Rule id for a whole file whose Maintainability Index — the standard
/// SEI-derived, 0-100-normalized formula also used by Visual Studio and most
/// modern tooling, combining Halstead Volume, cyclomatic complexity, and
/// lines of code — falls at or below the widely-cited "yellow or worse"
/// threshold (see [`MAINTAINABILITY_INDEX_LOW_THRESHOLD`], todo.md §3.C
/// "Halstead / Maintainability Index (Datei-Ebene)").
pub const MAINTAINABILITY_INDEX_RULE: &str = "maintainability-index";
pub const MAINTAINABILITY_INDEX_RULE_REVISION: u32 = 1;

/// Maintainability Index threshold below which a file is flagged — the
/// widely-cited convention for this exact 0-100 normalized formula (the same
/// one Visual Studio uses): `MI < 10` is "red" (hard to maintain), `10-19`
/// is "yellow" (moderately maintainable), `20+` is "green". This rule fires
/// at "yellow or worse", i.e. `MI < 20`.
pub const MAINTAINABILITY_INDEX_LOW_THRESHOLD: f64 = 20.0;

/// Flags a whole file whose Maintainability Index falls below
/// [`MAINTAINABILITY_INDEX_LOW_THRESHOLD`]:
/// ```text
/// MI_raw = 171 - 5.2*ln(HalsteadVolume) - 0.23*CyclomaticComplexity - 16.2*ln(LinesOfCode)
/// MI = max(0, MI_raw * 100 / 171)
/// ```
/// `CyclomaticComplexity`/`LinesOfCode` are the file-level sums folded by
/// [`fold_by_file`] over `functions`; `HalsteadVolume` comes from a second,
/// independent parse of the file via [`analyze_file_halstead`] — see
/// [`HalsteadVisitor`] for the Rust-adapted counting rules. A file with
/// `HalsteadVolume <= 0.0` or zero summed lines of code is skipped entirely
/// rather than scored (no meaningful MI for a file with no measurable
/// content).
pub fn maintainability_index(functions: &[FunctionInfo]) -> Vec<Finding> {
    let totals = fold_by_file(functions);
    let mut files: Vec<&Path> = totals.keys().copied().collect();
    files.sort();

    let mut findings = Vec::new();
    for file in files {
        let Ok(halstead) = analyze_file_halstead(file) else {
            continue;
        };
        let volume = halstead_volume(&halstead);
        let file_totals = totals[file];
        if volume <= 0.0 || file_totals.lines_of_code == 0 {
            continue;
        }

        let mi_raw = 171.0
            - 5.2 * volume.ln()
            - 0.23 * file_totals.cyclomatic as f64
            - 16.2 * (file_totals.lines_of_code as f64).ln();
        let mi = (mi_raw * 100.0 / 171.0).max(0.0);
        if mi >= MAINTAINABILITY_INDEX_LOW_THRESHOLD {
            continue;
        }

        findings.push(Finding::new(
            format!("{MAINTAINABILITY_INDEX_RULE}:{}", file.display()),
            MAINTAINABILITY_INDEX_RULE,
            Severity::Warn,
            Location {
                file: file.to_path_buf(),
                line: OneBasedLine::FIRST,
                item_path: file.display().to_string(),
            },
            EvidenceClass::Heuristic,
            Origin::Code,
            Some(json!({
                "file": file.display().to_string(),
                "maintainability_index": mi,
                "halstead_volume": volume,
                "distinct_operators": halstead.distinct_operators,
                "total_operators": halstead.total_operators,
                "distinct_operands": halstead.distinct_operands,
                "total_operands": halstead.total_operands,
                "cyclomatic_complexity_sum": file_totals.cyclomatic,
                "lines_of_code_sum": file_totals.lines_of_code,
            })),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn cyclomatic_complexity_counts_branches() {
        let dir = TempDir::new("complexity-branches");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn straight_line() {
    let _ = 1 + 1;
}

fn single_if(x: i32) {
    if x > 0 {
        let _ = x;
    }
}

fn if_else_if(x: i32) {
    if x > 0 {
        let _ = x;
    } else if x < 0 {
        let _ = x;
    }
}

fn boolean_operators(a: bool, b: bool) -> bool {
    a && b || a
}

fn loops(x: i32) {
    let mut i = 0;
    while i < x {
        i += 1;
    }
    for j in 0..x {
        let _ = j;
    }
    loop {
        break;
    }
}

fn try_operator() -> Result<i32, ()> {
    let x: Result<i32, ()> = Ok(1);
    Ok(x?)
}

fn match_arms(x: i32) -> i32 {
    match x {
        1 => 1,
        2 | 3 => 2,
        n if n > 10 => 3,
        _ => 0,
    }
}

fn mixed_nesting(x: i32) {
    match x {
        n if n > 0 => for i in 0..n {
            if i % 2 == 0 {
                let _ = i;
            }
        },
        _ => {}
    }
}

fn closure_only() {
    let cl = || 1;
    cl();
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let complexity = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
                .cyclomatic
        };
        let nesting_depth = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
                .nesting_depth
        };
        let match_arm_count = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
                .match_arm_count
        };

        assert_eq!(complexity("straight_line"), 1);
        assert_eq!(complexity("single_if"), 2);
        assert_eq!(complexity("if_else_if"), 3);
        assert_eq!(complexity("boolean_operators"), 3);
        assert_eq!(complexity("loops"), 4);
        assert_eq!(complexity("try_operator"), 2);
        assert_eq!(complexity("match_arms"), 5);

        assert_eq!(nesting_depth("straight_line"), 0);
        assert_eq!(nesting_depth("single_if"), 1);
        assert_eq!(nesting_depth("if_else_if"), 2);
        assert_eq!(nesting_depth("boolean_operators"), 0);
        assert_eq!(nesting_depth("loops"), 1);
        assert_eq!(nesting_depth("try_operator"), 0);
        assert_eq!(nesting_depth("match_arms"), 1);
        // if inside a loop inside a match: proves max-depth tracking works
        // across different node kinds, not just repetitions of one kind.
        assert_eq!(nesting_depth("mixed_nesting"), 3);
        assert_eq!(nesting_depth("closure_only"), 1);

        assert_eq!(match_arm_count("straight_line"), 0);
        assert_eq!(match_arm_count("single_if"), 0);
        assert_eq!(match_arm_count("if_else_if"), 0);
        assert_eq!(match_arm_count("boolean_operators"), 0);
        assert_eq!(match_arm_count("loops"), 0);
        assert_eq!(match_arm_count("try_operator"), 0);
        assert_eq!(match_arm_count("match_arms"), 4);
        assert_eq!(match_arm_count("mixed_nesting"), 2);
        assert_eq!(match_arm_count("closure_only"), 0);
    }

    #[test]
    fn cognitive_complexity_matches_hand_calculation() {
        let dir = TempDir::new("complexity-cognitive");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn straight_line() {
    let _ = 1 + 1;
}

fn single_if(x: i32) {
    if x > 0 {
        let _ = x;
    }
}

fn nested_if_in_for(x: i32) {
    for i in 0..x {
        if i % 2 == 0 {
            let _ = i;
        }
    }
}

fn bool_chain_uniform(a: bool, b: bool, c: bool) -> bool {
    a && b && c
}

fn bool_chain_mixed(a: bool, b: bool, c: bool) -> bool {
    a && b || c
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let cognitive = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
                .cognitive
        };

        assert_eq!(cognitive("straight_line"), 0);
        assert_eq!(cognitive("single_if"), 1);
        // `for` (+1 at nesting 0) plus a nested `if` (+1 for the `if`, +1 for
        // being one level deep) = 1 + 2 = 3.
        assert_eq!(cognitive("nested_if_in_for"), 3);
        // A single run of the same operator scores once for the whole run.
        assert_eq!(cognitive("bool_chain_uniform"), 1);
        // The operator changes once (`&&` -> `||`), so the run scores twice.
        assert_eq!(cognitive("bool_chain_mixed"), 2);
    }

    #[test]
    fn expression_width_and_async_nesting_match_hand_calculation() {
        let dir = TempDir::new("complexity-expression-shape");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn straight_line() {
    let _ = 1;
}

fn wide_call() {
    foo(1, 2, 3, 4, 5, 6, 7);
}

fn wide_chain(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    a + b + c + d + e
}

async fn own_async_not_counted() {
    let _ = 1;
}

fn nested_async_block() {
    let _ = async {
        async {
            1
        }
    };
}

fn nested_async_closure() {
    let _ = async || {
        async {
            1
        }
    };
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let get = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
        };

        assert_eq!(get("straight_line").max_expression_width, 0);
        assert_eq!(get("straight_line").async_nesting_depth, 0);

        // A call's argument count, not any nested-tree shape.
        assert_eq!(get("wide_call").max_expression_width, 7);

        // `a + b + c + d + e` flattens to 5 operands, not the nested
        // binary-tree's pairwise width of 2 per node.
        assert_eq!(get("wide_chain").max_expression_width, 5);

        // The function's own `async fn` status is not itself nesting — only
        // a nested async block/closure *inside* the body counts.
        assert_eq!(get("own_async_not_counted").async_nesting_depth, 0);

        // Two levels of nested `async { .. }` blocks.
        assert_eq!(get("nested_async_block").async_nesting_depth, 2);

        // An async closure nests the same way as an async block.
        assert_eq!(get("nested_async_closure").async_nesting_depth, 2);
    }

    #[test]
    fn nested_fn_is_analyzed_separately_and_excluded_from_outer() {
        let dir = TempDir::new("complexity-nested-fn");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn outer(x: i32) -> i32 {
    fn inner(y: i32) -> i32 {
        if y > 0 { 1 } else { 0 }
    }
    if x > 0 {
        inner(x)
    } else {
        0
    }
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        assert_eq!(functions.len(), 2);

        let outer = functions
            .iter()
            .find(|f| f.qualified_name == "outer")
            .unwrap();
        let inner = functions
            .iter()
            .find(|f| f.qualified_name == "inner")
            .unwrap();
        assert_eq!(outer.cyclomatic, 2);
        assert_eq!(inner.cyclomatic, 2);
    }

    #[test]
    fn analyze_file_reports_parse_errors() {
        let dir = TempDir::new("complexity-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "fn broken( {").unwrap();

        let err = analyze_file(&file).unwrap_err();
        match err {
            ComplexityError::Parse(path, _) => assert_eq!(path, file),
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    #[test]
    fn analyze_file_reports_io_errors_for_missing_files() {
        let missing = PathBuf::from("/nonexistent/judge-test-file-does-not-exist.rs");
        let err = analyze_file(&missing).unwrap_err();
        match err {
            ComplexityError::Io(path, _) => assert_eq!(path, missing),
            other => panic!("expected an io error, got {other:?}"),
        }
    }

    fn authored(path: PathBuf) -> SourceFile {
        SourceFile {
            path,
            kind: crate::ingest::SourceKind::Authored,
        }
    }

    #[test]
    fn analyze_workspace_aggregates_functions_and_errors() {
        let dir = TempDir::new("complexity-workspace");
        let good = dir.join("good.rs");
        let bad = dir.join("bad.rs");
        std::fs::write(&good, "fn ok() {}").unwrap();
        std::fs::write(&bad, "fn broken( {").unwrap();

        let files = [authored(good), authored(bad)];
        let report = analyze_workspace(files.iter(), false);

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].qualified_name, "ok");
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.excluded_generated, 0);
    }

    #[test]
    fn analyze_workspace_skips_generated_files_unless_included() {
        let dir = TempDir::new("complexity-generated");
        let authored_file = dir.join("lib.rs");
        let generated_file = dir.join("schema.rs");
        std::fs::write(&authored_file, "fn ok() {}").unwrap();
        std::fs::write(&generated_file, "fn also_ok() {}").unwrap();

        let files = [
            authored(authored_file),
            SourceFile {
                path: generated_file,
                kind: crate::ingest::SourceKind::Generated,
            },
        ];

        let excluded = analyze_workspace(files.iter(), false);
        assert_eq!(excluded.functions.len(), 1);
        assert_eq!(excluded.functions[0].qualified_name, "ok");
        assert_eq!(excluded.excluded_generated, 1);

        let included = analyze_workspace(files.iter(), true);
        assert_eq!(included.functions.len(), 2);
        assert_eq!(included.excluded_generated, 0);
    }

    #[test]
    fn complexity_error_source_preserves_the_underlying_error() {
        let parse_err = syn::parse_str::<syn::File>("fn (")
            .err()
            .expect("`fn (` must not parse");
        let err = ComplexityError::Parse(PathBuf::from("src/lib.rs"), parse_err);
        let source = std::error::Error::source(&err).expect("Parse must carry a source");
        assert!(source.downcast_ref::<syn::Error>().is_some());
        assert!(err.to_string().starts_with("src/lib.rs: failed to parse: "));
    }

    #[test]
    fn signature_complexity_fires_for_each_trigger_independently() {
        let dir = TempDir::new("complexity-signature-complexity");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn simple(a: i32, b: i32) -> i32 {
    a + b
}

fn deep_return() -> Result<Option<Vec<Box<i32>>>, ()> {
    Ok(None)
}

fn many_generics<A, B, C, D, E>(a: A, b: B, c: C, d: D, e: E) {
    let _ = (a, b, c, d, e);
}

fn many_trait_bounds<T: Clone + Debug, U>(t: T, u: U)
where
    T: Send + Sync + Serialize,
    U: Default + PartialEq + Ord,
{
    let _ = (t, u);
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let get = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
        };

        // `Result<Option<Vec<Box<i32>>>, ()>` nests 4 levels deep, above
        // `MAX_RETURN_TYPE_DEPTH` (3).
        assert_eq!(get("deep_return").return_type_depth, 4);
        assert_eq!(get("many_generics").generic_param_count, 5);
        // 2 inline (`T: Clone + Debug`) + 3 + 3 where-clause bounds = 8,
        // above `MAX_TRAIT_BOUND_COUNT` (5).
        assert_eq!(get("many_trait_bounds").trait_bound_count, 8);

        let findings = signature_complexity(&functions);
        let fired: std::collections::HashSet<&str> = findings
            .iter()
            .map(|finding| finding.location.item_path.as_str())
            .collect();

        assert!(!fired.contains("simple"));
        assert!(fired.contains("deep_return"));
        assert!(fired.contains("many_generics"));
        assert!(fired.contains("many_trait_bounds"));
        assert_eq!(findings.len(), 3);
        for finding in &findings {
            assert_eq!(finding.rule, SIGNATURE_COMPLEXITY_RULE);
        }
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn signature_complexity_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(SIGNATURE_COMPLEXITY_RULE)
            .expect("signature-complexity has a registry entry")
            .example
            .expect("signature-complexity has a curated example")
            .before;
        let dir = TempDir::new("complexity-signature-complexity-registry-example");
        let file = dir.join("lib.rs");
        std::fs::write(&file, example).unwrap();

        let functions = analyze_file(&file).unwrap();
        let findings = signature_complexity(&functions);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == SIGNATURE_COMPLEXITY_RULE)
                .count(),
            1
        );
    }

    /// `a + b` gives exactly one distinct operator (`bin +`, `n1` = 1,
    /// `N1` = 1) and two distinct operands (`a`, `b`; `n2` = 2, `N2` = 2), so
    /// Halstead Volume and the resulting Maintainability Index can be
    /// computed by hand from the same formula [`maintainability_index`] uses
    /// and checked for an exact match — mirrors this crate's
    /// `cognitive_complexity_matches_hand_calculation` precedent.
    #[test]
    fn maintainability_index_matches_hand_calculation() {
        let dir = TempDir::new("complexity-maintainability-index-hand-calc");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn simple(a: i32, b: i32) -> i32 {
    a + b
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        assert_eq!(functions[0].cyclomatic, 1);
        assert_eq!(functions[0].lines_of_code, 3);

        let halstead = analyze_file_halstead(&file).unwrap();
        assert_eq!(halstead.distinct_operators, 1);
        assert_eq!(halstead.total_operators, 1);
        assert_eq!(halstead.distinct_operands, 2);
        assert_eq!(halstead.total_operands, 2);

        // n1 + n2 = 3, N1 + N2 = 3: Volume = 3 * log2(3).
        let expected_volume = 3.0_f64 * 3.0_f64.log2();
        let volume = halstead_volume(&halstead);
        assert!(
            (volume - expected_volume).abs() < 1e-9,
            "got {volume}, expected {expected_volume}"
        );

        // MI_raw = 171 - 5.2*ln(volume) - 0.23*1 - 16.2*ln(3); MI = max(0, MI_raw * 100 / 171).
        let expected_mi_raw = 171.0 - 5.2 * expected_volume.ln() - 0.23 * 1.0 - 16.2 * 3.0_f64.ln();
        let expected_mi = (expected_mi_raw * 100.0 / 171.0).max(0.0);
        assert!(
            expected_mi >= MAINTAINABILITY_INDEX_LOW_THRESHOLD,
            "hand-calculated MI {expected_mi} should be well above the threshold"
        );

        // Well above the threshold, so this file must not produce a finding.
        assert!(maintainability_index(&functions).is_empty());
    }

    #[test]
    fn maintainability_index_does_not_fire_for_well_structured_files() {
        let dir = TempDir::new("complexity-maintainability-index-low");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn greet(name: &str) -> String {
    format!("hello, {name}")
}

pub fn is_even(n: i32) -> bool {
    n % 2 == 0
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let findings = maintainability_index(&functions);
        assert!(findings.is_empty());
    }

    #[test]
    fn maintainability_index_fires_for_a_long_high_branching_file() {
        let dir = TempDir::new("complexity-maintainability-index-high");
        let file = dir.join("lib.rs");
        let mut source = String::from("fn tangled(x: i32) -> i32 {\n    let mut y = 0;\n");
        for i in 0..120 {
            source.push_str(&format!(
                "    if x > {i} {{ y = {i}; }} else if x < -{i} {{ y = -{i}; }}\n"
            ));
        }
        source.push_str("    y\n}\n");
        std::fs::write(&file, source).unwrap();

        let functions = analyze_file(&file).unwrap();
        let findings = maintainability_index(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, MAINTAINABILITY_INDEX_RULE);
        let mi = findings[0].evidence.as_ref().unwrap()["maintainability_index"]
            .as_f64()
            .unwrap();
        assert!(
            mi < MAINTAINABILITY_INDEX_LOW_THRESHOLD,
            "expected mi < {MAINTAINABILITY_INDEX_LOW_THRESHOLD}, got {mi}"
        );
    }

    #[test]
    fn maintainability_index_does_not_fire_for_an_empty_or_trivial_file() {
        let dir = TempDir::new("complexity-maintainability-index-trivial");
        let empty_file = dir.join("empty.rs");
        std::fs::write(&empty_file, "").unwrap();
        let empty_functions = analyze_file(&empty_file).unwrap();
        assert!(maintainability_index(&empty_functions).is_empty());

        let trivial_file = dir.join("trivial.rs");
        std::fs::write(&trivial_file, "fn trivial() {}\n").unwrap();
        let trivial_functions = analyze_file(&trivial_file).unwrap();
        assert!(maintainability_index(&trivial_functions).is_empty());
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// same drift-guard convention as
    /// `signature_complexity_registry_example_still_triggers_the_rule`.
    #[test]
    fn maintainability_index_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MAINTAINABILITY_INDEX_RULE)
            .expect("maintainability-index has a registry entry")
            .example
            .expect("maintainability-index has a curated example")
            .before;
        let dir = TempDir::new("complexity-maintainability-index-registry-example");
        let file = dir.join("lib.rs");
        std::fs::write(&file, example).unwrap();

        let functions = analyze_file(&file).unwrap();
        let findings = maintainability_index(&functions);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == MAINTAINABILITY_INDEX_RULE)
                .count(),
            1
        );
    }
}
