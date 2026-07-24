//! Fast-tier complexity analysis: cyclomatic complexity per function via `syn`,
//! no build required (see todo.md §2.1, §3.C).

use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprIf, ItemFn};

use crate::functions::walk_functions;
use crate::ingest::SourceFile;

/// Cyclomatic complexity and size of a single function or method.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub qualified_name: String,
    pub file: PathBuf,
    pub line: usize,
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
}

#[derive(Debug)]
pub enum ComplexityError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for ComplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ComplexityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// Parses a single Rust source file and returns the complexity of every
/// function, method, and default trait-method body it contains.
pub fn analyze_file(path: &Path) -> Result<Vec<FunctionInfo>, ComplexityError> {
    let source = std::fs::read_to_string(path)
        .map_err(|err| ComplexityError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| ComplexityError::Parse(path.to_path_buf(), err))?;

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

        let start_line = site.span.start().line;
        let end_line = site.span.end().line.max(start_line);

        functions.push(FunctionInfo {
            qualified_name: site.qualified_name,
            file: path.to_path_buf(),
            line: start_line,
            cyclomatic: complexity.complexity,
            cognitive: cognitive.cognitive,
            lines_of_code: end_line - start_line + 1,
            nesting_depth: complexity.nesting_depth,
            match_arm_count: complexity.match_arm_count,
            arg_count: site.arg_count,
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

/// Flattens a chain of `&&`/`||` [`Expr::Binary`] nodes — transparently
/// unwrapping [`Expr::Paren`] — into its left-to-right operators and leaf
/// operands, so [`CognitiveComplexityVisitor`] can score operator-run
/// transitions across the whole chain at once instead of per-node.
fn flatten_bool_chain<'ast>(expr: &'ast Expr, ops: &mut Vec<BoolOp>, leaves: &mut Vec<&'ast Expr>) {
    match expr {
        Expr::Paren(node) => flatten_bool_chain(&node.expr, ops, leaves),
        Expr::Binary(node) if matches!(node.op, BinOp::And(_) | BinOp::Or(_)) => {
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
            Expr::Binary(node) if matches!(node.op, BinOp::And(_) | BinOp::Or(_)) => {
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
}
