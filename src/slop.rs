//! Fast-tier AI-slop signal detection (see todo.md §G "AI-Slop-Signale", §G1
//! "Error-Masking"). Only the four `G1` rules that are detectable from syntax
//! alone via `syn` are implemented here — `silent-default` and
//! `context-free-propagation` need real type information (is this
//! expression's type actually a `Result`? does this `?` really cross a
//! meaningful module boundary?) that isn't available without a type checker
//! (Deep Tier, not built yet), so they are intentionally not attempted.
//!
//! Per todo.md §12 "Entscheidungen": "Der Slop-Block ist Teil von `health`,
//! kein eigener Sub-Command" — this module has no CLI command of its own;
//! `cargo judge health` merges its findings into its own report.
//!
//! `suppression-debt` (new/current `#[allow(...)]`/`#[expect(...)]`) is
//! emitted here as `Severity::Info` findings for the *current* state only —
//! the "trend against baseline" that todo.md calls for is already handled by
//! the existing baseline/delta system (see [`crate::baseline`]); this module
//! just reports what exists today.

use std::path::{Path, PathBuf};

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, GenericArgument, ImplItemFn, ItemFn, ItemImpl, ItemMod, ItemTrait, Local,
    Pat, Path as SynPath, PathArguments, Stmt, Token, TraitItemFn, Type, TypeParamBound,
    Visibility,
};

use crate::finding::{Finding, Location, Origin, Severity};
use crate::ingest::SourceFile;

/// Rule id for a discarded fallible result: `let _ = fallible();` or a bare
/// `.ok();` statement (see todo.md §G1).
pub const SWALLOWED_RESULT_RULE: &str = "swallowed-result";
/// Bump when the swallowed-result rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const SWALLOWED_RESULT_RULE_REVISION: u32 = 1;

/// Rule id for an empty `Err(_)`/`Err(..)` match arm, or an `if let Err(_) =
/// ... { }` with no `else` (see todo.md §G1).
pub const EMPTY_ERROR_ARM_RULE: &str = "empty-error-arm";
pub const EMPTY_ERROR_ARM_RULE_REVISION: u32 = 1;

/// Rule id for a `pub fn` whose error type is erased (`Box<dyn Error>` /
/// `anyhow::Error`) at a public API boundary (see todo.md §G1).
pub const CATCH_ALL_ERROR_RULE: &str = "catch-all-error";
pub const CATCH_ALL_ERROR_RULE_REVISION: u32 = 1;

/// Rule id for an `#[allow(...)]`/`#[expect(...)]` attribute occurrence — the
/// "wichtigster Rust-Slop-Marker" per todo.md §G1.
pub const SUPPRESSION_DEBT_RULE: &str = "suppression-debt";
pub const SUPPRESSION_DEBT_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum SlopError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for SlopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for SlopError {}

/// Aggregated slop findings across a set of files, keeping findings separate
/// from files that could not be parsed.
#[derive(Debug, Default)]
pub struct WorkspaceSlop {
    pub findings: Vec<Finding>,
    pub errors: Vec<SlopError>,
    /// Generated files skipped because `include_generated` was `false` (see
    /// todo.md §3.A "Generated-Code-Policy").
    pub excluded_generated: usize,
}

/// Parses a single Rust source file and returns every slop finding in it.
pub fn analyze_file(path: &Path) -> Result<Vec<Finding>, SlopError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| SlopError::Io(path.to_path_buf(), err))?;
    let ast = syn::parse_file(&source).map_err(|err| SlopError::Parse(path.to_path_buf(), err))?;

    let mut visitor = SlopVisitor {
        file: path,
        path: Vec::new(),
        findings: Vec::new(),
    };
    visitor.visit_file(&ast);
    Ok(visitor.findings)
}

/// Runs [`analyze_file`] over every file in `source_files` and aggregates the
/// results. Generated files are skipped unless `include_generated` is set
/// (see todo.md §3.A) — slop signals on generated code aren't actionable the
/// way they are on authored code.
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
    include_generated: bool,
) -> WorkspaceSlop {
    let mut report = WorkspaceSlop::default();
    for file in source_files {
        if !include_generated && !file.kind.is_locally_reportable() {
            report.excluded_generated += 1;
            continue;
        }
        match analyze_file(&file.path) {
            Ok(mut findings) => report.findings.append(&mut findings),
            Err(err) => report.errors.push(err),
        }
    }
    report
}

/// Walks a whole parsed file (not just function bodies — attributes and
/// public fn signatures can appear anywhere at item level), tracking the
/// enclosing `mod`/`impl`/`trait`/`fn` path for a finding's `item_path` (same
/// idea as [`crate::functions::walk_functions`], but broader: this visitor
/// doesn't stop at function boundaries since `suppression-debt` attributes
/// can sit on any item, statement, or expression).
struct SlopVisitor<'a> {
    file: &'a Path,
    path: Vec<String>,
    findings: Vec<Finding>,
}

impl SlopVisitor<'_> {
    /// The qualified name of the innermost enclosing named item, or the file
    /// path if there is none.
    fn current_item_path(&self) -> String {
        if self.path.is_empty() {
            self.file.display().to_string()
        } else {
            self.path.join("::")
        }
    }

    fn record(
        &mut self,
        rule: &'static str,
        span: proc_macro2::Span,
        severity: Severity,
        confidence: f32,
        item_path: String,
    ) {
        let start = span.start();
        self.findings.push(Finding {
            id: format!(
                "{rule}:{}:{}:{}",
                self.file.display(),
                start.line,
                start.column
            ),
            rule: rule.to_string(),
            severity,
            location: Location {
                file: self.file.to_path_buf(),
                line: start.line,
                item_path,
            },
            confidence,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }

    fn check_catch_all_error(
        &mut self,
        vis: &Visibility,
        sig: &syn::Signature,
        span: proc_macro2::Span,
    ) {
        if !matches!(vis, Visibility::Public(_)) {
            return;
        }
        let syn::ReturnType::Type(_, ty) = &sig.output else {
            return;
        };
        if !contains_catch_all_error(ty) {
            return;
        }
        let item_path = self.current_item_path();
        self.record(CATCH_ALL_ERROR_RULE, span, Severity::Warn, 0.9, item_path);
    }
}

impl<'ast> Visit<'ast> for SlopVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        self.path.push(type_name(&node.self_ty));
        visit::visit_item_impl(self, node);
        self.path.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        self.path.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.path.push(node.sig.ident.to_string());
        self.check_catch_all_error(&node.vis, &node.sig, node.span());
        visit::visit_item_fn(self, node);
        self.path.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.path.push(node.sig.ident.to_string());
        self.check_catch_all_error(&node.vis, &node.sig, node.span());
        visit::visit_impl_item_fn(self, node);
        self.path.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        self.path.push(node.sig.ident.to_string());
        visit::visit_trait_item_fn(self, node);
        self.path.pop();
    }

    /// `let _ = <call-expression>;` — a call whose result is explicitly bound
    /// to `_` rather than a real name (see todo.md §G1 `swallowed-result`).
    fn visit_local(&mut self, node: &'ast Local) {
        if matches!(node.pat, Pat::Wild(_))
            && let Some(init) = &node.init
            && matches!(init.expr.as_ref(), Expr::Call(_) | Expr::MethodCall(_))
        {
            let item_path = self.current_item_path();
            self.record(
                SWALLOWED_RESULT_RULE,
                node.span(),
                Severity::Warn,
                0.8,
                item_path,
            );
        }
        visit::visit_local(self, node);
    }

    /// A bare expression-statement ending in `.ok()` — converts a `Result` to
    /// an `Option` and immediately discards it (see todo.md §G1
    /// `swallowed-result`). Only statements with a trailing `;` count: a tail
    /// expression's value isn't discarded.
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Expr(Expr::MethodCall(call), Some(_)) = stmt
            && call.method == "ok"
        {
            let item_path = self.current_item_path();
            self.record(
                SWALLOWED_RESULT_RULE,
                call.span(),
                Severity::Warn,
                0.8,
                item_path,
            );
        }
        visit::visit_stmt(self, stmt);
    }

    /// `match ... { Err(_) => {}, ... }` — an empty error-handling arm (see
    /// todo.md §G1 `empty-error-arm`).
    fn visit_arm(&mut self, arm: &'ast Arm) {
        if is_err_wildcard_pat(&arm.pat) && is_empty_block_expr(&arm.body) {
            let item_path = self.current_item_path();
            self.record(
                EMPTY_ERROR_ARM_RULE,
                arm.span(),
                Severity::Warn,
                1.0,
                item_path,
            );
        }
        visit::visit_arm(self, arm);
    }

    /// `if let Err(_) = ... { }` with no `else` — the `if let` sibling of
    /// `empty-error-arm`.
    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::If(if_expr) = expr
            && if_expr.else_branch.is_none()
            && if_expr.then_branch.stmts.is_empty()
            && let Expr::Let(let_expr) = if_expr.cond.as_ref()
            && is_err_wildcard_pat(&let_expr.pat)
        {
            let item_path = self.current_item_path();
            self.record(
                EMPTY_ERROR_ARM_RULE,
                if_expr.span(),
                Severity::Warn,
                1.0,
                item_path,
            );
        }
        visit::visit_expr(self, expr);
    }

    /// Every `#[allow(...)]`/`#[expect(...)]` attribute, anywhere (see
    /// todo.md §G1 `suppression-debt`).
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if attr.path().is_ident("allow") || attr.path().is_ident("expect") {
            let item_path = attr
                .parse_args_with(Punctuated::<SynPath, Token![,]>::parse_terminated)
                .ok()
                .map(|paths| {
                    paths
                        .iter()
                        .map(path_to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|names| !names.is_empty())
                .unwrap_or_else(|| self.file.display().to_string());
            self.record(
                SUPPRESSION_DEBT_RULE,
                attr.span(),
                Severity::Info,
                1.0,
                item_path,
            );
        }
        visit::visit_attribute(self, attr);
    }
}

fn path_to_string(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The last path segment's name, or `"?"` for a type this doesn't recognize
/// (mirrors `crate::functions::type_name`, kept local so this module doesn't
/// need to reach into the private helper of an unrelated detector).
fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map_or_else(|| "?".to_string(), |segment| segment.ident.to_string()),
        _ => "?".to_string(),
    }
}

/// Whether `pat` is `Err(_)` or `Err(..)`.
fn is_err_wildcard_pat(pat: &Pat) -> bool {
    match pat {
        Pat::TupleStruct(tuple_struct) => {
            tuple_struct
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Err")
                && tuple_struct.elems.len() == 1
                && matches!(tuple_struct.elems[0], Pat::Wild(_) | Pat::Rest(_))
        }
        _ => false,
    }
}

/// Whether `expr` is a literally empty block (`{}`).
fn is_empty_block_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Block(block) if block.block.stmts.is_empty())
}

/// Whether `ty`, written syntactically, is or contains `Box<dyn ... Error
/// ...>` or a path ending in `anyhow::Error`/`anyhow::Result` (see todo.md
/// §G1 `catch-all-error`). Recurses into generic arguments so both a bare
/// `Box<dyn Error>` return type and `Result<_, Box<dyn Error>>` match.
fn contains_catch_all_error(ty: &Type) -> bool {
    match ty {
        Type::TraitObject(trait_object) => is_error_trait_object(trait_object),
        Type::Path(type_path) => {
            let segments = &type_path.path.segments;
            if segments.len() >= 2 {
                let last = segments.last().unwrap();
                let prev = &segments[segments.len() - 2];
                if prev.ident == "anyhow" && (last.ident == "Error" || last.ident == "Result") {
                    return true;
                }
            }
            segments.iter().any(|segment| {
                let PathArguments::AngleBracketed(args) = &segment.arguments else {
                    return false;
                };
                args.args.iter().any(|arg| match arg {
                    GenericArgument::Type(inner) => contains_catch_all_error(inner),
                    _ => false,
                })
            })
        }
        _ => false,
    }
}

/// Whether a `dyn Trait [+ Trait ...]` object has a bound ending in `Error`
/// (`dyn Error`, `dyn std::error::Error`, `dyn Error + Send + Sync`, ...).
fn is_error_trait_object(trait_object: &syn::TypeTraitObject) -> bool {
    trait_object.bounds.iter().any(|bound| {
        if let TypeParamBound::Trait(trait_bound) = bound {
            trait_bound
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Error")
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::SourceKind;
    use crate::test_util::TempDir;

    fn authored(path: PathBuf) -> SourceFile {
        SourceFile {
            path,
            kind: SourceKind::Authored,
        }
    }

    fn findings_for(source: &str, name: &str) -> Vec<Finding> {
        let dir = TempDir::new(name);
        let file = dir.join("lib.rs");
        std::fs::write(&file, source).unwrap();
        analyze_file(&file).unwrap()
    }

    fn rule_findings<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
        findings.iter().filter(|f| f.rule == rule).collect()
    }

    #[test]
    fn let_underscore_call_is_flagged() {
        let findings = findings_for(
            "fn f() { let _ = some_call(); }\nfn some_call() -> i32 { 1 }\n",
            "slop-let-underscore",
        );
        let hits = rule_findings(&findings, SWALLOWED_RESULT_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].confidence, 0.8);
    }

    #[test]
    fn let_bound_to_a_real_name_is_not_flagged() {
        let findings = findings_for(
            "fn f() { let x = some_call(); let _ = x; }\nfn some_call() -> i32 { 1 }\n",
            "slop-let-real-name",
        );
        assert!(rule_findings(&findings, SWALLOWED_RESULT_RULE).is_empty());
    }

    #[test]
    fn bare_dot_ok_statement_is_flagged() {
        let findings = findings_for(
            "fn f() -> Result<i32, ()> { Ok(1) }\nfn g() { f().ok(); }\n",
            "slop-dot-ok",
        );
        let hits = rule_findings(&findings, SWALLOWED_RESULT_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn dot_ok_bound_to_a_name_is_not_flagged() {
        let findings = findings_for(
            "fn f() -> Result<i32, ()> { Ok(1) }\nfn g() { let x = f().ok(); let _ = x; }\n",
            "slop-dot-ok-bound",
        );
        assert!(rule_findings(&findings, SWALLOWED_RESULT_RULE).is_empty());
    }

    #[test]
    fn empty_err_arm_is_flagged() {
        let findings = findings_for(
            r#"
fn f(r: Result<i32, ()>) {
    match r {
        Err(_) => {}
        Ok(_) => {}
    }
}
"#,
            "slop-empty-err-arm",
        );
        let hits = rule_findings(&findings, EMPTY_ERROR_ARM_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, 1.0);
    }

    #[test]
    fn non_empty_err_arm_is_not_flagged() {
        let findings = findings_for(
            r#"
fn f(r: Result<i32, ()>) {
    match r {
        Err(e) => log::warn!("{:?}", e),
        Ok(_) => {}
    }
}
"#,
            "slop-non-empty-err-arm",
        );
        assert!(rule_findings(&findings, EMPTY_ERROR_ARM_RULE).is_empty());
    }

    #[test]
    fn empty_if_let_err_is_flagged() {
        let findings = findings_for(
            "fn f() -> Result<(), ()> { Ok(()) }\nfn g() { if let Err(_) = f() { } }\n",
            "slop-if-let-empty",
        );
        let hits = rule_findings(&findings, EMPTY_ERROR_ARM_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn non_empty_if_let_err_is_not_flagged() {
        let findings = findings_for(
            "fn f() -> Result<(), ()> { Ok(()) }\nfn g() { if let Err(_) = f() { return; } }\n",
            "slop-if-let-non-empty",
        );
        assert!(rule_findings(&findings, EMPTY_ERROR_ARM_RULE).is_empty());
    }

    #[test]
    fn pub_fn_with_boxed_dyn_error_is_flagged() {
        let findings = findings_for(
            "pub fn f() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
            "slop-catch-all-boxed",
        );
        let hits = rule_findings(&findings, CATCH_ALL_ERROR_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, 0.9);
    }

    #[test]
    fn pub_fn_with_concrete_error_type_is_not_flagged() {
        let findings = findings_for(
            "struct MyError;\npub fn f() -> Result<(), MyError> { Ok(()) }\n",
            "slop-catch-all-concrete",
        );
        assert!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).is_empty());
    }

    #[test]
    fn private_fn_with_boxed_dyn_error_is_not_flagged() {
        let findings = findings_for(
            "fn f() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
            "slop-catch-all-private",
        );
        assert!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).is_empty());
    }

    #[test]
    fn anyhow_result_is_flagged() {
        let findings = findings_for(
            "pub fn f() -> anyhow::Result<()> { Ok(()) }\n",
            "slop-catch-all-anyhow",
        );
        let hits = rule_findings(&findings, CATCH_ALL_ERROR_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn allow_and_expect_each_produce_one_finding() {
        let findings = findings_for(
            "#[allow(dead_code)]\nfn f() {}\n\n#[expect(clippy::foo)]\nfn g() {}\n",
            "slop-suppression-debt",
        );
        let hits = rule_findings(&findings, SUPPRESSION_DEBT_RULE);
        assert_eq!(hits.len(), 2);
        for hit in &hits {
            assert_eq!(hit.severity, Severity::Info);
            assert_eq!(hit.confidence, 1.0);
        }
        let item_paths: Vec<_> = hits.iter().map(|f| f.location.item_path.as_str()).collect();
        assert!(item_paths.contains(&"dead_code"));
        assert!(item_paths.contains(&"clippy::foo"));
    }

    #[test]
    fn no_suppressions_produces_zero_findings() {
        let findings = findings_for("fn f() {}\n", "slop-no-suppression-debt");
        assert!(rule_findings(&findings, SUPPRESSION_DEBT_RULE).is_empty());
    }

    #[test]
    fn generated_files_are_excluded_unless_included() {
        let dir = TempDir::new("slop-generated");
        let file = dir.join("schema.rs");
        std::fs::write(
            &file,
            "fn f() { let _ = some_call(); }\nfn some_call() -> i32 { 1 }\n",
        )
        .unwrap();

        let files = [SourceFile {
            path: file,
            kind: SourceKind::Generated,
        }];

        let excluded = analyze_workspace(files.iter(), false);
        assert!(excluded.findings.is_empty());
        assert_eq!(excluded.excluded_generated, 1);

        let included = analyze_workspace(files.iter(), true);
        assert_eq!(included.findings.len(), 1);
        assert_eq!(included.excluded_generated, 0);
    }

    #[test]
    fn analyze_workspace_reports_parse_errors() {
        let dir = TempDir::new("slop-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "fn broken( {").unwrap();

        let files = [authored(file)];
        let report = analyze_workspace(files.iter(), false);

        assert_eq!(report.errors.len(), 1);
        assert!(report.findings.is_empty());
    }
}
