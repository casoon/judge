//! Fast-tier AI-slop signal detection (see todo.md §G "AI-Slop-Signale", §G1
//! "Error-Masking", §G2 "Stub- und Theater-Code"). The four `G1` rules and
//! five of the six `G2` rules that are detectable from syntax alone via
//! `syn` are implemented here — `silent-default` and
//! `context-free-propagation` (G1) need real type information (is this
//! expression's type actually a `Result`? does this `?` really cross a
//! meaningful module boundary?) that isn't available without a type checker
//! (Deep Tier, not built yet), so they are intentionally not attempted.
//! `mock-of-sut` (G2) is intentionally skipped too, for a different reason:
//! there is no structural signal in Rust that identifies "the system under
//! test" for a given test function, so this isn't solvable syntactically —
//! and it isn't solvable with type information either, since it requires
//! knowing test *intent*, not types.
//!
//! Per todo.md §12 "Entscheidungen": "Der Slop-Block ist Teil von `health`,
//! kein eigener Sub-Command" — this module has no CLI command of its own;
//! `cargo judge health` merges its findings into its own report.
//!
//! `suppression-debt` and `ignored-test-accumulation` are emitted here as
//! `Severity::Info` findings for the *current* state only — the "trend
//! against baseline" that todo.md calls for is already handled by the
//! existing baseline/delta system (see [`crate::baseline`]); this module
//! just reports what exists today.
//!
//! `assertion-free-test` and `ignored-test-accumulation` only match the
//! literal `#[test]`/`#[ignore]` attributes, not third-party test-framework
//! attributes (`#[tokio::test]`, `#[rstest]`, ...) — accepted v1 scope.
//!
//! `G3` ("Sprachliche Marker", see todo.md §3.G) splits across two modules.
//! `generic-naming` and `doc-restates-signature` are structural/lexical
//! checks over identifiers and `#[doc = ...]` attributes, so they extend
//! [`SlopVisitor`] here exactly like the `G1`/`G2` rules above. The other
//! three — `conversational-artifact`, `restating-comment`,
//! `step-comment-inflation` — target plain `//`/`/* */` prose, which `syn`
//! discards entirely during parsing (only `///`/`//!` doc comments survive,
//! desugared to `#[doc = "..."]` attributes); there is no AST node for a
//! regular comment, so those three live in [`crate::slop_text`], a
//! raw-source-text scanner run alongside this visitor.

use std::path::{Path, PathBuf};

use quote::quote;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Block, Expr, ExprLit, ExprMethodCall, GenericArgument, ImplItemFn, ItemFn,
    ItemImpl, ItemMod, ItemTrait, Lit, Local, Macro, Meta, Pat, Path as SynPath, PathArguments,
    ReturnType, Stmt, Token, TraitItemFn, Type, TypeParamBound, Visibility,
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
/// `anyhow::Error`) at a public API boundary *and* whose body discards the
/// original error via a wildcard-parameter `.map_err(|_| ..)` (see todo.md
/// §G1, [`discards_error_via_map_err`]).
pub const CATCH_ALL_ERROR_RULE: &str = "catch-all-error";
/// Bump when the catch-all-error rule's logic changes (see todo.md §5
/// "Regelversions-Schutz"). v2 (2026-07-24, GitHub issue #11): added the
/// `discards_error_via_map_err` body check — a type-erased return type
/// alone no longer fires; plain `?`/`anyhow!(..)` propagation is idiomatic,
/// not evidence of discarded error information.
pub const CATCH_ALL_ERROR_RULE_REVISION: u32 = 2;

/// Rule id for an `#[allow(...)]`/`#[expect(...)]` attribute occurrence — the
/// "wichtigster Rust-Slop-Marker" per todo.md §G1.
pub const SUPPRESSION_DEBT_RULE: &str = "suppression-debt";
pub const SUPPRESSION_DEBT_RULE_REVISION: u32 = 1;

/// Rule id for `todo!()`/`unimplemented!()` outside a `#[cfg(feature =
/// ...)]`-gated scope (see todo.md §G2).
pub const MERGED_STUB_RULE: &str = "merged-stub";
pub const MERGED_STUB_RULE_REVISION: u32 = 1;

/// Rule id for a function/method/trait-default with a doc comment and a
/// literally empty body (see todo.md §G2).
pub const EMPTY_IMPL_RULE: &str = "empty-impl";
pub const EMPTY_IMPL_RULE_REVISION: u32 = 1;

/// Rule id for a `#[test]` fn (without `#[should_panic]`) whose body has no
/// visible assertion path (see todo.md §G2).
pub const ASSERTION_FREE_TEST_RULE: &str = "assertion-free-test";
pub const ASSERTION_FREE_TEST_RULE_REVISION: u32 = 1;

/// Rule id for `assert!(true)` / `assert_eq!(x, x)` (see todo.md §G2).
pub const TAUTOLOGICAL_TEST_RULE: &str = "tautological-test";
pub const TAUTOLOGICAL_TEST_RULE_REVISION: u32 = 1;

/// Rule id for an `#[ignore]`/`#[ignore = "..."]` attribute occurrence (see
/// todo.md §G2).
pub const IGNORED_TEST_ACCUMULATION_RULE: &str = "ignored-test-accumulation";
pub const IGNORED_TEST_ACCUMULATION_RULE_REVISION: u32 = 1;

/// Rule id for a phrase leaking AI-assistant framing into a plain comment
/// (see todo.md §G3). Implemented in [`crate::slop_text`].
pub const CONVERSATIONAL_ARTIFACT_RULE: &str = "conversational-artifact";
pub const CONVERSATIONAL_ARTIFACT_RULE_REVISION: u32 = 1;

/// Rule id for a comment that only paraphrases the code line it precedes
/// (see todo.md §G3). Implemented in [`crate::slop_text`].
pub const RESTATING_COMMENT_RULE: &str = "restating-comment";
pub const RESTATING_COMMENT_RULE_REVISION: u32 = 1;

/// Rule id for a `// Step N:` comment chain of three or more (see todo.md
/// §G3). Implemented in [`crate::slop_text`].
pub const STEP_COMMENT_INFLATION_RULE: &str = "step-comment-inflation";
pub const STEP_COMMENT_INFLATION_RULE_REVISION: u32 = 1;

/// Rule id for an identifier that is exactly a generic placeholder word
/// (`data`, `temp`, `handler`, ...), see todo.md §G3.
pub const GENERIC_NAMING_RULE: &str = "generic-naming";
pub const GENERIC_NAMING_RULE_REVISION: u32 = 1;

/// Rule id for a doc comment that is a pure signature echo (see todo.md
/// §G3).
pub const DOC_RESTATES_SIGNATURE_RULE: &str = "doc-restates-signature";
pub const DOC_RESTATES_SIGNATURE_RULE_REVISION: u32 = 1;

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
/// See [`contains_catch_all_error`] for `allow_anyhow_at_boundary`.
pub fn analyze_file(
    path: &Path,
    allow_anyhow_at_boundary: bool,
) -> Result<Vec<Finding>, SlopError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| SlopError::Io(path.to_path_buf(), err))?;
    let ast = syn::parse_file(&source).map_err(|err| SlopError::Parse(path.to_path_buf(), err))?;

    let mut visitor = SlopVisitor {
        file: path,
        path: Vec::new(),
        findings: Vec::new(),
        feature_gated_depth: 0,
        item_spans: Vec::new(),
        allow_anyhow_at_boundary,
    };
    visitor.visit_file(&ast);
    let mut findings = visitor.findings;
    findings.extend(crate::slop_text::scan_comments(
        &source,
        &visitor.item_spans,
        path,
    ));
    Ok(findings)
}

/// Runs [`analyze_file`] over every file in `source_files` and aggregates the
/// results. Generated files are skipped unless `include_generated` is set
/// (see todo.md §3.A) — slop signals on generated code aren't actionable the
/// way they are on authored code. See [`contains_catch_all_error`] for
/// `allow_anyhow_at_boundary`.
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
    include_generated: bool,
    allow_anyhow_at_boundary: bool,
) -> WorkspaceSlop {
    let mut report = WorkspaceSlop::default();
    for file in source_files {
        if !include_generated && !file.kind.is_locally_reportable() {
            report.excluded_generated += 1;
            continue;
        }
        match analyze_file(&file.path, allow_anyhow_at_boundary) {
            Ok(mut findings) => report.findings.append(&mut findings),
            Err(err) => report.errors.push(err),
        }
    }
    report
}

/// The line range and qualified item path of one `fn`/method, indexed so
/// [`crate::slop_text`]'s raw-text findings (which have no `syn` span to
/// derive an item path from) can attribute a comment to its nearest
/// enclosing function (see todo.md §3.G G3).
pub(crate) struct ItemSpan {
    pub start_line: usize,
    pub end_line: usize,
    pub item_path: String,
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
    /// Depth of nesting inside a `#[cfg(feature = ...)]`-gated `mod`/`impl`/
    /// `fn` — `merged-stub` doesn't flag `todo!()`/`unimplemented!()` while
    /// this is non-zero (see [`has_feature_cfg`]).
    feature_gated_depth: usize,
    /// Every `fn`/method's line range and item path, collected while
    /// walking — feeds [`crate::slop_text::scan_comments`]'s attribution of
    /// raw-text findings (see [`ItemSpan`]).
    pub(crate) item_spans: Vec<ItemSpan>,
    /// Whether `catch-all-error` exempts `anyhow::Result`/`anyhow::Error`
    /// return types (see [`contains_catch_all_error`], GitHub issue #5).
    allow_anyhow_at_boundary: bool,
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
        item_path: String,
    ) {
        self.record_with_evidence(rule, span, severity, item_path, None);
    }

    fn record_with_evidence(
        &mut self,
        rule: &'static str,
        span: proc_macro2::Span,
        severity: Severity,
        item_path: String,
        evidence: Option<serde_json::Value>,
    ) {
        let start = span.start();
        let rule = crate::finding::RuleId::from(rule);
        let evidence_class = crate::finding::evidence_class_for_rule(&rule);
        self.findings.push(Finding {
            id: format!(
                "{rule}:{}:{}:{}",
                self.file.display(),
                start.line,
                start.column
            )
            .into(),
            rule,
            severity,
            location: Location {
                file: self.file.to_path_buf(),
                line: crate::finding::OneBasedLine::new(start.line)
                    .expect("proc-macro2 span lines are 1-based"),
                item_path,
            },
            evidence_class,
            origin: Origin::Code,
            evidence,
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }

    fn check_catch_all_error(
        &mut self,
        vis: &Visibility,
        sig: &syn::Signature,
        block: &Block,
        span: proc_macro2::Span,
    ) {
        if !matches!(vis, Visibility::Public(_)) {
            return;
        }
        let syn::ReturnType::Type(_, ty) = &sig.output else {
            return;
        };
        if !contains_catch_all_error(ty, self.allow_anyhow_at_boundary) {
            return;
        }
        if !discards_error_via_map_err(block) {
            return;
        }
        let item_path = self.current_item_path();
        self.record(CATCH_ALL_ERROR_RULE, span, Severity::Warn, item_path);
    }

    /// A doc-commented function/method/trait-default with a literally empty
    /// body (see todo.md §G2 `empty-impl`). Restricted to a *literally*
    /// empty block deliberately — a one-liner like `{ Config::default() }`
    /// never matches, since that's a legitimate (if terse) implementation,
    /// not a stub.
    fn check_empty_impl(&mut self, attrs: &[Attribute], block: &Block, span: proc_macro2::Span) {
        if has_doc_comment(attrs) && block.stmts.is_empty() {
            let item_path = self.current_item_path();
            self.record(EMPTY_IMPL_RULE, span, Severity::Warn, item_path);
        }
    }

    /// A `#[test]` fn (without `#[should_panic]`) whose body has no visible
    /// assertion path (see todo.md §G2 `assertion-free-test`).
    fn check_assertion_free_test(&mut self, node: &ItemFn) {
        if !node.attrs.iter().any(|attr| attr.path().is_ident("test"))
            || node
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("should_panic"))
        {
            return;
        }
        let returns_result = returns_result_type(&node.sig.output);
        let mut scanner = AssertionScanner {
            found: false,
            returns_result,
        };
        scanner.visit_block(&node.block);
        if !scanner.found {
            let item_path = self.current_item_path();
            self.record(
                ASSERTION_FREE_TEST_RULE,
                node.span(),
                Severity::Warn,
                item_path,
            );
        }
    }

    /// `let data1 = ...;` / `let temp2 = ...;` — a `let` binding whose name
    /// is a generic placeholder word plus a numeric suffix (see todo.md §G3
    /// `generic-naming`). Deliberately does NOT check the bare
    /// (non-suffixed) local name — `let result = do_thing()?;` is completely
    /// idiomatic Rust, and flagging every private local named `data` or
    /// `result` would be pure noise. The numeric-suffix shape (`data1`,
    /// `data2`, ...) is a distinctive enough signal on its own that it
    /// doesn't need that mitigation.
    fn check_generic_naming_local(&mut self, pat: &Pat, span: proc_macro2::Span) {
        let Pat::Ident(pat_ident) = pat else {
            return;
        };
        let name = pat_ident.ident.to_string();
        let stripped = strip_trailing_digits(&name);
        if stripped.len() == name.len() {
            return;
        }
        if is_generic_word(stripped) {
            let item_path = self.current_item_path();
            self.record(GENERIC_NAMING_RULE, span, Severity::Info, item_path);
        }
    }

    /// A top-level `pub fn` whose name is exactly a generic placeholder word
    /// (see todo.md §G3 `generic-naming`). Scoped to free `pub fn`s only —
    /// not called from `visit_impl_item_fn`, since a method's name reads
    /// very differently in context of its receiver type (`Cache::get` isn't
    /// generic the way a free function named `get` would be); the public,
    /// free-standing API surface is where a generic name is the clearest
    /// naming problem.
    fn check_generic_naming_item_fn(&mut self, node: &ItemFn) {
        if !matches!(node.vis, Visibility::Public(_)) {
            return;
        }
        if is_generic_word(&node.sig.ident.to_string()) {
            let item_path = self.current_item_path();
            self.record(GENERIC_NAMING_RULE, node.span(), Severity::Info, item_path);
        }
    }

    /// A `pub struct` whose name, or one of whose `pub` field names, is
    /// exactly a generic placeholder word (see todo.md §G3 `generic-naming`).
    fn check_generic_naming_item_struct(&mut self, node: &syn::ItemStruct) {
        if matches!(node.vis, Visibility::Public(_)) && is_generic_word(&node.ident.to_string()) {
            let item_path = self.current_item_path();
            self.record(GENERIC_NAMING_RULE, node.span(), Severity::Info, item_path);
        }
        for field in &node.fields {
            if matches!(field.vis, Visibility::Public(_))
                && let Some(ident) = &field.ident
                && is_generic_word(&ident.to_string())
            {
                let item_path = self.current_item_path();
                self.record(GENERIC_NAMING_RULE, field.span(), Severity::Info, item_path);
            }
        }
    }

    /// A `pub enum` whose name is exactly a generic placeholder word (see
    /// todo.md §G3 `generic-naming`).
    fn check_generic_naming_item_enum(&mut self, node: &syn::ItemEnum) {
        if matches!(node.vis, Visibility::Public(_)) && is_generic_word(&node.ident.to_string()) {
            let item_path = self.current_item_path();
            self.record(GENERIC_NAMING_RULE, node.span(), Severity::Info, item_path);
        }
    }

    /// A doc comment that is a pure echo of the fn's signature — e.g.
    /// `/// Returns the result.` over `fn f() -> Result<...>` (see todo.md
    /// §G3 `doc-restates-signature`). Deliberately narrow: only fires when
    /// the whole doc text is short (≤6 tokens) AND every content word in it
    /// also appears in the signature, so real prose describing *what* or
    /// *why* never matches.
    fn check_doc_restates_signature(
        &mut self,
        attrs: &[Attribute],
        sig: &syn::Signature,
        span: proc_macro2::Span,
    ) {
        let doc_text = doc_comment_text(attrs);
        let Some(doc_text) = doc_text else {
            return;
        };
        let doc_tokens = tokenize(&doc_text);
        if doc_tokens.is_empty() || doc_tokens.len() > 6 {
            return;
        }
        const STOPWORDS: &[&str] = &[
            "returns", "return", "get", "gets", "the", "a", "an", "of", "for",
        ];
        let content_tokens: Vec<&String> = doc_tokens
            .iter()
            .filter(|token| !STOPWORDS.contains(&token.as_str()))
            .collect();
        if content_tokens.is_empty() {
            return;
        }
        let sig_tokens = signature_tokens(sig);
        if content_tokens
            .iter()
            .all(|token| sig_tokens.contains(token.as_str()))
        {
            let item_path = self.current_item_path();
            self.record(DOC_RESTATES_SIGNATURE_RULE, span, Severity::Info, item_path);
        }
    }
}

impl<'ast> Visit<'ast> for SlopVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let gated = has_feature_cfg(&node.attrs);
        if gated {
            self.feature_gated_depth += 1;
        }
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
        if gated {
            self.feature_gated_depth -= 1;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let gated = has_feature_cfg(&node.attrs);
        if gated {
            self.feature_gated_depth += 1;
        }
        self.path.push(type_name(&node.self_ty));
        visit::visit_item_impl(self, node);
        self.path.pop();
        if gated {
            self.feature_gated_depth -= 1;
        }
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        self.path.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.path.pop();
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.path.push(node.ident.to_string());
        self.check_generic_naming_item_struct(node);
        visit::visit_item_struct(self, node);
        self.path.pop();
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.path.push(node.ident.to_string());
        self.check_generic_naming_item_enum(node);
        visit::visit_item_enum(self, node);
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.path.push(node.sig.ident.to_string());
        self.item_spans.push(ItemSpan {
            start_line: node.span().start().line,
            end_line: node.span().end().line,
            item_path: self.current_item_path(),
        });
        self.check_catch_all_error(&node.vis, &node.sig, &node.block, node.span());
        self.check_empty_impl(&node.attrs, &node.block, node.span());
        self.check_assertion_free_test(node);
        self.check_generic_naming_item_fn(node);
        self.check_doc_restates_signature(&node.attrs, &node.sig, node.span());
        let gated = has_feature_cfg(&node.attrs);
        if gated {
            self.feature_gated_depth += 1;
        }
        visit::visit_item_fn(self, node);
        if gated {
            self.feature_gated_depth -= 1;
        }
        self.path.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.path.push(node.sig.ident.to_string());
        self.item_spans.push(ItemSpan {
            start_line: node.span().start().line,
            end_line: node.span().end().line,
            item_path: self.current_item_path(),
        });
        self.check_catch_all_error(&node.vis, &node.sig, &node.block, node.span());
        self.check_empty_impl(&node.attrs, &node.block, node.span());
        self.check_doc_restates_signature(&node.attrs, &node.sig, node.span());
        let gated = has_feature_cfg(&node.attrs);
        if gated {
            self.feature_gated_depth += 1;
        }
        visit::visit_impl_item_fn(self, node);
        if gated {
            self.feature_gated_depth -= 1;
        }
        self.path.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        self.path.push(node.sig.ident.to_string());
        if let Some(default) = &node.default {
            self.check_empty_impl(&node.attrs, default, node.span());
        }
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
                item_path,
            );
        }
        self.check_generic_naming_local(&node.pat, node.span());
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
            self.record(EMPTY_ERROR_ARM_RULE, arm.span(), Severity::Warn, item_path);
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
                item_path,
            );
        }
        visit::visit_expr(self, expr);
    }

    /// Every `#[allow(...)]`/`#[expect(...)]` attribute, anywhere (see
    /// todo.md §G1 `suppression-debt`), and every `#[ignore]`/`#[ignore =
    /// "..."]` attribute, anywhere (see todo.md §G2
    /// `ignored-test-accumulation`).
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
                item_path,
            );
        } else if attr.path().is_ident("ignore") {
            let reason = match &attr.meta {
                Meta::NameValue(name_value) => match &name_value.value {
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(reason),
                        ..
                    }) => Some(reason.value()),
                    _ => None,
                },
                _ => None,
            };
            let item_path = self.current_item_path();
            self.record_with_evidence(
                IGNORED_TEST_ACCUMULATION_RULE,
                attr.span(),
                Severity::Info,
                item_path,
                reason.map(|reason| serde_json::json!({ "reason": reason })),
            );
        }
        visit::visit_attribute(self, attr);
    }

    /// `todo!()`/`unimplemented!()` outside a `#[cfg(feature = ...)]`-gated
    /// scope (see todo.md §G2 `merged-stub`), and tautological `assert!`s
    /// (see todo.md §G2 `tautological-test`).
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if (mac.path.is_ident("todo") || mac.path.is_ident("unimplemented"))
            && self.feature_gated_depth == 0
        {
            let item_path = self.current_item_path();
            self.record(MERGED_STUB_RULE, mac.span(), Severity::Warn, item_path);
        } else if mac.path.is_ident("assert") {
            if let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                && let Some(Expr::Lit(ExprLit {
                    lit: Lit::Bool(value),
                    ..
                })) = args.first()
                && value.value
            {
                let item_path = self.current_item_path();
                self.record(
                    TAUTOLOGICAL_TEST_RULE,
                    mac.span(),
                    Severity::Warn,
                    item_path,
                );
            }
        } else if mac.path.is_ident("assert_eq")
            && let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
            && let (Some(lhs), Some(rhs)) = (args.first(), args.get(1))
            // Token-string comparison, not `Expr: PartialEq` (`syn`'s
            // `extra-traits` feature isn't enabled here). This is an
            // accepted false-positive trap: two expressions with identical
            // source text can still differ at runtime if they have side
            // effects — an accepted, documented imprecision of this syntax fact.
            && quote!(#lhs).to_string() == quote!(#rhs).to_string()
        {
            let item_path = self.current_item_path();
            self.record(
                TAUTOLOGICAL_TEST_RULE,
                mac.span(),
                Severity::Warn,
                item_path,
            );
        }
        visit::visit_macro(self, mac);
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
/// `Box<dyn Error>` return type and `Result<_, Box<dyn Error>>` match. When
/// `allow_anyhow_at_boundary` is set, `anyhow::Error`/`anyhow::Result` no
/// longer match — but `Box<dyn Error>` still does (see GitHub issue #5:
/// anyhow is the documented propagation convention, `Box<dyn Error>` has no
/// comparable exemption).
fn contains_catch_all_error(ty: &Type, allow_anyhow_at_boundary: bool) -> bool {
    match ty {
        Type::TraitObject(trait_object) => is_error_trait_object(trait_object),
        Type::Path(type_path) => {
            let segments = &type_path.path.segments;
            if !allow_anyhow_at_boundary && segments.len() >= 2 {
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
                    GenericArgument::Type(inner) => {
                        contains_catch_all_error(inner, allow_anyhow_at_boundary)
                    }
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

/// Whether `block` contains a `.map_err(|_| ..)` call whose closure takes
/// exactly one wildcard parameter (`_` or `_: T`) — the body-level signal
/// `check_catch_all_error` requires alongside a type-erased return type
/// (see todo.md §F "Praxisbeleg", auditmysite 2026-07-24, GitHub issue #11):
/// a closure that never binds the original error value discards it, rather
/// than merely converting or propagating it. Plain `?`/`anyhow!(..)`
/// propagation — which preserves the source error chain
/// (`std::error::Error::source()`) — does not match this and is not
/// flagged; that precision audit found 0 of 8 `catch-all-error` findings
/// real in a codebase that only ever used exactly that idiomatic style
/// through a type-erased boundary. A syntax-only proxy, not a completeness
/// proof: a `.map_err` closure that *does* bind its parameter but never
/// uses it, or some other information-discarding shape (e.g. a `match`
/// collapsing distinct arms to the same message), is not distinguished
/// either way.
fn discards_error_via_map_err(block: &Block) -> bool {
    struct MapErrDiscardVisitor {
        found: bool,
    }

    impl<'ast> Visit<'ast> for MapErrDiscardVisitor {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if node.method == "map_err"
                && let Some(Expr::Closure(closure)) = node.args.first()
                && closure.inputs.len() == 1
                && pat_is_wildcard(&closure.inputs[0])
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
    }

    fn pat_is_wildcard(pat: &Pat) -> bool {
        match pat {
            Pat::Wild(_) => true,
            Pat::Type(pat_type) => pat_is_wildcard(&pat_type.pat),
            _ => false,
        }
    }

    let mut visitor = MapErrDiscardVisitor { found: false };
    visitor.visit_block(block);
    visitor.found
}

/// Whether any attribute in `attrs` is a `#[doc = ...]` (covers both `///`
/// doc comments and explicit `#[doc]` attributes — `syn` desugars both the
/// same way).
fn has_doc_comment(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

/// Whether any attribute in `attrs` is a `#[cfg(...)]` whose contents
/// mention `feature` (see todo.md §G2 `merged-stub`). Only recognizes
/// `cfg(feature = ...)`, not `cfg(test)` — a `todo!()` inside `#[cfg(test)]`
/// is still flagged, matching the literal "Nicht-Feature-Branches" wording.
fn has_feature_cfg(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("cfg") && quote!(#attr).to_string().contains("feature"))
}

/// Whether a fn's return type's last path segment is `Result` (mirrors how
/// [`contains_catch_all_error`] inspects types, but shallow — no need to
/// recurse into generic arguments here).
fn returns_result_type(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(type_path) = ty.as_ref() else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Result")
}

/// Placeholder words common in template/boilerplate naming (see todo.md §G3
/// `generic-naming`). Matched as an exact, case-insensitive, whole-identifier
/// comparison everywhere this list is used — never a substring match, so
/// `ConnectionManager` never matches `manager`.
const GENERIC_WORDS: &[&str] = &[
    "data",
    "result",
    "temp",
    "handler",
    "manager",
    "processor",
    "helper",
    "utils",
];

/// Whether `word`, lowercased, exactly equals one of [`GENERIC_WORDS`].
fn is_generic_word(word: &str) -> bool {
    let lower = word.to_lowercase();
    GENERIC_WORDS.contains(&lower.as_str())
}

/// Strips a trailing run of ASCII digits from `name`, if any (`"data1"` ->
/// `"data"`, `"data"` -> `"data"`).
fn strip_trailing_digits(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit())
}

/// Collects every `#[doc = "..."]` attribute's string literal (covers both
/// `///` doc comments and explicit `#[doc]` attributes, which `syn` desugars
/// the same way — see [`has_doc_comment`]), joins them with spaces, and
/// trims. `None` if there's no doc comment at all. Reuses the exact
/// `Meta::NameValue`/`Lit::Str` extraction pattern already used for
/// `#[ignore = "..."]` in `visit_attribute`.
fn doc_comment_text(attrs: &[Attribute]) -> Option<String> {
    let parts: Vec<String> = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(name_value) => match &name_value.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        return None;
    }
    let joined = parts.join(" ").trim().to_string();
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Lowercases `text` and splits it on non-alphanumeric boundaries (used by
/// [`SlopVisitor::check_doc_restates_signature`]; `crate::slop_text` has its
/// own copy since it has no reason to depend on this module for a
/// three-line helper).
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// The token set a doc comment is compared against in
/// [`SlopVisitor::check_doc_restates_signature`]: the fn's own name, its
/// return type's last path segment name, and — if there's exactly one
/// non-`self` parameter — that parameter's identifier and its type's last
/// path segment, all lowercased.
fn signature_tokens(sig: &syn::Signature) -> std::collections::HashSet<String> {
    let mut tokens = std::collections::HashSet::new();
    tokens.insert(sig.ident.to_string().to_lowercase());
    if let ReturnType::Type(_, ty) = &sig.output {
        tokens.insert(type_name(ty).to_lowercase());
    }
    let non_self_params: Vec<&syn::PatType> = sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => Some(pat_type),
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    if let [pat_type] = non_self_params.as_slice() {
        if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
            tokens.insert(pat_ident.ident.to_string().to_lowercase());
        }
        tokens.insert(type_name(&pat_type.ty).to_lowercase());
    }
    tokens
}

/// Nested scanner run over a `#[test]` fn's body to find a visible assertion
/// path (see todo.md §G2 `assertion-free-test`). Recurses into closures like
/// any other `Visit` implementation, so an assert-free closure body still
/// counts as "no assertion found" rather than being skipped.
struct AssertionScanner {
    found: bool,
    /// Whether the enclosing fn's return type is `Result<..>` — a bare `?`
    /// only counts as "the assertion" when the fn can actually propagate an
    /// `Err` out as a test failure.
    returns_result: bool,
}

impl<'ast> Visit<'ast> for AssertionScanner {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        const ASSERT_MACROS: [&str; 16] = [
            "assert",
            "assert_eq",
            "assert_ne",
            "debug_assert",
            "debug_assert_eq",
            "debug_assert_ne",
            "panic",
            "unreachable",
            "assert_snapshot",
            "assert_json_snapshot",
            "assert_debug_snapshot",
            "assert_display_snapshot",
            "assert_yaml_snapshot",
            "assert_ron_snapshot",
            "assert_csv_snapshot",
            "assert_toml_snapshot",
        ];
        // Matches the last path segment, not just single-segment paths via
        // `is_ident` — otherwise a qualified call like
        // `insta::assert_snapshot!(...)` or `pretty_assertions::assert_eq!`
        // is invisible to this scanner (see GitHub issue #6).
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| ASSERT_MACROS.contains(&segment.ident.to_string().as_str()))
        {
            self.found = true;
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if matches!(
            node.method.to_string().as_str(),
            "unwrap" | "expect" | "unwrap_err" | "expect_err"
        ) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Try(_) = expr
            && self.returns_result
        {
            self.found = true;
        }
        visit::visit_expr(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::EvidenceClass;
    use crate::ingest::SourceKind;
    use crate::test_util::TempDir;

    fn authored(path: PathBuf) -> SourceFile {
        SourceFile {
            path,
            kind: SourceKind::Authored,
        }
    }

    fn findings_for(source: &str, name: &str) -> Vec<Finding> {
        findings_for_with_config(source, name, false)
    }

    fn findings_for_with_config(
        source: &str,
        name: &str,
        allow_anyhow_at_boundary: bool,
    ) -> Vec<Finding> {
        let dir = TempDir::new(name);
        let file = dir.join("lib.rs");
        std::fs::write(&file, source).unwrap();
        analyze_file(&file, allow_anyhow_at_boundary).unwrap()
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
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn swallowed_result_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(SWALLOWED_RESULT_RULE)
            .expect("swallowed-result has a registry entry")
            .example
            .expect("swallowed-result has a curated example")
            .before;
        let findings = findings_for(example, "slop-swallowed-result-registry-example");
        assert_eq!(rule_findings(&findings, SWALLOWED_RESULT_RULE).len(), 1);
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

    /// `swallowed-result` — unentscheidbar (same mechanism as
    /// `stringly-error-boundary`'s cfg-gated golden test in `pattern.rs`):
    /// the `let _ = ...;` sits inside a `#[cfg(feature =
    /// "not-enabled-by-default")]`-gated fn. `syn::parse_file` has no cfg
    /// resolution and parses every `cfg` branch regardless of actual
    /// feature activation, so a real build without that feature would never
    /// contain this statement at all — yet it is still flagged.
    /// `feature_gated_depth` exists in `SlopVisitor` but `visit_local`
    /// never consults it (only `merged-stub`'s `visit_macro` does), so this
    /// is consistent, documented Fast-Tier behavior, not a bug: making
    /// `swallowed-result` respect cfg-gating while `catch-all-error` (see
    /// below) doesn't would be the inconsistent choice, and todo.md's G1
    /// entry promises nothing about cfg resolution ("rein syntaktisch").
    #[test]
    fn swallowed_result_inside_cfg_gated_fn_still_flagged() {
        let findings = findings_for(
            "#[cfg(feature = \"not-enabled-by-default\")]\nfn f() { let _ = some_call(); }\nfn some_call() -> i32 { 1 }\n",
            "slop-swallowed-result-cfg-gated",
        );
        let hits = rule_findings(&findings, SWALLOWED_RESULT_RULE);
        assert_eq!(hits.len(), 1);
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
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
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

    /// `empty-error-arm` — unentscheidbar, same class as `boolean-state-
    /// cluster`'s `macro_rules!` golden test in `pattern.rs`: the actual
    /// empty `Err(_) => {}` arm only exists inside a `macro_rules!` body,
    /// never written out as source `syn` parses into an AST. `syn` treats a
    /// macro definition's body as an opaque token stream, and the
    /// invocation `handle_it!(r);` is an opaque `Stmt::Macro` too — neither
    /// is expanded, so `visit_arm` never sees the `match` this rule would
    /// otherwise flag. A real build would 100% contain the empty arm this
    /// rule targets, but it is structurally invisible to a syntax-only
    /// scanner: the rule stays silent rather than guessing at an
    /// unexpanded macro body's contents.
    #[test]
    fn empty_error_arm_inside_macro_body_produces_no_finding() {
        let findings = findings_for(
            r#"
macro_rules! handle_it {
    ($r:expr) => {
        match $r {
            Err(_) => {}
            Ok(_) => {}
        }
    };
}
fn f(r: Result<i32, ()>) {
    handle_it!(r);
}
"#,
            "slop-empty-error-arm-macro-body",
        );
        assert!(rule_findings(&findings, EMPTY_ERROR_ARM_RULE).is_empty());
    }

    #[test]
    fn pub_fn_with_boxed_dyn_error_is_flagged() {
        let findings = findings_for(
            "pub fn f() -> Result<(), Box<dyn std::error::Error>> {\n    std::fs::read_to_string(\"x\").map_err(|_| \"failed\".into())?;\n    Ok(())\n}\n",
            "slop-catch-all-boxed",
        );
        let hits = rule_findings(&findings, CATCH_ALL_ERROR_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    /// See todo.md §F "Praxisbeleg" (GitHub issue #11): a type-erased return
    /// type alone is not enough — plain `?` propagation preserves the
    /// source error chain and is idiomatic `anyhow`/`thiserror` style, not
    /// evidence of discarded error information.
    #[test]
    fn pub_fn_with_boxed_dyn_error_and_plain_propagation_is_not_flagged() {
        let findings = findings_for(
            "pub fn f() -> Result<(), Box<dyn std::error::Error>> {\n    std::fs::read_to_string(\"x\")?;\n    Ok(())\n}\n",
            "slop-catch-all-boxed-plain-propagation",
        );
        assert!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).is_empty());
    }

    /// A `.map_err` closure that binds and uses its parameter converts the
    /// error but does not discard it — still not flagged.
    #[test]
    fn map_err_with_a_bound_parameter_is_not_flagged() {
        let findings = findings_for(
            "pub fn f() -> Result<(), Box<dyn std::error::Error>> {\n    std::fs::read_to_string(\"x\").map_err(|e| format!(\"failed: {e}\").into())?;\n    Ok(())\n}\n",
            "slop-catch-all-boxed-bound-map-err",
        );
        assert!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).is_empty());
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
            "pub fn f() -> anyhow::Result<()> {\n    std::fs::read_to_string(\"x\").map_err(|_| anyhow::anyhow!(\"failed\"))?;\n    Ok(())\n}\n",
            "slop-catch-all-anyhow",
        );
        let hits = rule_findings(&findings, CATCH_ALL_ERROR_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn anyhow_result_is_not_flagged_when_allowed_at_boundary() {
        let findings = findings_for_with_config(
            "pub fn f() -> anyhow::Result<()> {\n    std::fs::read_to_string(\"x\").map_err(|_| anyhow::anyhow!(\"failed\"))?;\n    Ok(())\n}\n",
            "slop-catch-all-anyhow-allowed",
            true,
        );
        assert!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).is_empty());
    }

    #[test]
    fn boxed_dyn_error_is_still_flagged_when_anyhow_allowed_at_boundary() {
        let findings = findings_for_with_config(
            "pub fn f() -> Result<(), Box<dyn std::error::Error>> {\n    std::fs::read_to_string(\"x\").map_err(|_| \"failed\".into())?;\n    Ok(())\n}\n",
            "slop-catch-all-boxed-allowed",
            true,
        );
        let hits = rule_findings(&findings, CATCH_ALL_ERROR_RULE);
        assert_eq!(hits.len(), 1);
    }

    /// `catch-all-error` — unentscheidbar, same mechanism as
    /// `stringly-error-boundary`'s cfg-gated golden test in `pattern.rs`:
    /// the `pub fn` itself sits behind `#[cfg(feature =
    /// "not-enabled-by-default")]`, so a real build without that feature
    /// would never expose this boundary at all. `check_catch_all_error` is
    /// called unconditionally from `visit_item_fn` — `feature_gated_depth`
    /// is tracked but only `merged-stub` consults it — so the finding still
    /// fires. Documented, honest Fast-Tier limitation (`syn::parse_file`
    /// has no cfg resolution), not a bug.
    #[test]
    fn catch_all_error_inside_cfg_gated_pub_fn_still_flagged() {
        let findings = findings_for(
            "#[cfg(feature = \"not-enabled-by-default\")]\npub fn f() -> Result<(), Box<dyn std::error::Error>> {\n    std::fs::read_to_string(\"x\").map_err(|_| \"failed\".into())?;\n    Ok(())\n}\n",
            "slop-catch-all-error-cfg-gated",
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
            assert_eq!(hit.evidence_class, EvidenceClass::DerivedFact);
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

    /// `suppression-debt` — unentscheidbar, but the inverse of the other
    /// three rules' cfg/macro blind spots: here macro-blindness
    /// *undercounts* rather than overcounts. The `#[allow(dead_code)]`
    /// exists only inside a `macro_rules!` body, which `syn` treats as an
    /// opaque token stream, never expanded into a real `Item::Fn` with a
    /// visible `Attribute` — and the invocation `define_it!();` is itself
    /// an opaque `Item::Macro`. A real build's expanded code would contain
    /// this `#[allow(...)]` and count against the suppression-debt trend,
    /// but `visit_attribute` never sees it, so it silently doesn't count.
    /// Documented, honest Fast-Tier limitation (no macro expansion
    /// available without a real compiler), not a bug: undercounting a
    /// trend metric is a materially different (and here, unavoidable)
    /// failure mode than misreporting a specific finding's location.
    #[test]
    fn suppression_debt_inside_macro_body_is_not_counted() {
        let findings = findings_for(
            "macro_rules! define_it {\n    () => {\n        #[allow(dead_code)]\n        fn generated() {}\n    };\n}\ndefine_it!();\n",
            "slop-suppression-debt-macro-body",
        );
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

        let excluded = analyze_workspace(files.iter(), false, false);
        assert!(excluded.findings.is_empty());
        assert_eq!(excluded.excluded_generated, 1);

        let included = analyze_workspace(files.iter(), true, false);
        assert_eq!(included.findings.len(), 1);
        assert_eq!(included.excluded_generated, 0);
    }

    #[test]
    fn analyze_workspace_reports_parse_errors() {
        let dir = TempDir::new("slop-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "fn broken( {").unwrap();

        let files = [authored(file)];
        let report = analyze_workspace(files.iter(), false, false);

        assert_eq!(report.errors.len(), 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn ignored_test_is_flagged() {
        let findings = findings_for(
            "#[test]\n#[ignore]\nfn f() { assert_eq!(1 + 1, 2); }\n",
            "slop-ignored-test",
        );
        let hits = rule_findings(&findings, IGNORED_TEST_ACCUMULATION_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Info);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
        assert_eq!(hits[0].evidence, None);
    }

    #[test]
    fn ignored_test_with_reason_captures_evidence() {
        let findings = findings_for(
            "#[test]\n#[ignore = \"slow\"]\nfn f() { assert_eq!(1 + 1, 2); }\n",
            "slop-ignored-test-reason",
        );
        let hits = rule_findings(&findings, IGNORED_TEST_ACCUMULATION_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence,
            Some(serde_json::json!({ "reason": "slow" }))
        );
    }

    #[test]
    fn test_without_ignore_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { assert_eq!(1 + 1, 2); }\n",
            "slop-not-ignored-test",
        );
        assert!(rule_findings(&findings, IGNORED_TEST_ACCUMULATION_RULE).is_empty());
    }

    #[test]
    fn assert_true_is_flagged() {
        let findings = findings_for("fn f() { assert!(true); }\n", "slop-assert-true");
        let hits = rule_findings(&findings, TAUTOLOGICAL_TEST_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn assert_condition_is_not_flagged() {
        let findings = findings_for(
            "fn f() { assert!(condition()); }\nfn condition() -> bool { true }\n",
            "slop-assert-condition",
        );
        assert!(rule_findings(&findings, TAUTOLOGICAL_TEST_RULE).is_empty());
    }

    #[test]
    fn assert_eq_same_expr_is_flagged() {
        let findings = findings_for(
            "fn f(x: i32) { assert_eq!(x, x); }\n",
            "slop-assert-eq-same",
        );
        let hits = rule_findings(&findings, TAUTOLOGICAL_TEST_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn assert_eq_different_exprs_is_not_flagged() {
        let findings = findings_for(
            "fn f(a: i32, b: i32) { assert_eq!(a, b); }\n",
            "slop-assert-eq-different",
        );
        assert!(rule_findings(&findings, TAUTOLOGICAL_TEST_RULE).is_empty());
    }

    #[test]
    fn doc_commented_empty_fn_is_flagged() {
        let findings = findings_for("/// Does nothing yet.\nfn f() {}\n", "slop-empty-impl-fn");
        let hits = rule_findings(&findings, EMPTY_IMPL_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn doc_commented_nonempty_fn_is_not_flagged() {
        let findings = findings_for(
            "/// Returns a default.\nfn f() -> i32 { some_default() }\nfn some_default() -> i32 { 1 }\n",
            "slop-empty-impl-nonempty",
        );
        assert!(rule_findings(&findings, EMPTY_IMPL_RULE).is_empty());
    }

    #[test]
    fn empty_fn_without_doc_comment_is_not_flagged() {
        let findings = findings_for("fn f() {}\n", "slop-empty-impl-no-doc");
        assert!(rule_findings(&findings, EMPTY_IMPL_RULE).is_empty());
    }

    #[test]
    fn doc_commented_empty_impl_method_is_flagged() {
        let findings = findings_for(
            "struct S;\nimpl S {\n    /// Does nothing yet.\n    fn f(&self) {}\n}\n",
            "slop-empty-impl-method",
        );
        let hits = rule_findings(&findings, EMPTY_IMPL_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn doc_commented_empty_trait_default_is_flagged() {
        let findings = findings_for(
            "trait T {\n    /// Does nothing yet.\n    fn f(&self) {}\n}\n",
            "slop-empty-impl-trait-default",
        );
        let hits = rule_findings(&findings, EMPTY_IMPL_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn todo_macro_is_flagged() {
        let findings = findings_for("fn f() { todo!() }\n", "slop-merged-stub-todo");
        let hits = rule_findings(&findings, MERGED_STUB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn unimplemented_macro_is_flagged() {
        let findings = findings_for(
            "fn f() { unimplemented!() }\n",
            "slop-merged-stub-unimplemented",
        );
        assert_eq!(rule_findings(&findings, MERGED_STUB_RULE).len(), 1);
    }

    #[test]
    fn feature_gated_fn_todo_is_not_flagged() {
        let findings = findings_for(
            "#[cfg(feature = \"wip\")]\nfn f() { todo!() }\n",
            "slop-merged-stub-gated-fn",
        );
        assert!(rule_findings(&findings, MERGED_STUB_RULE).is_empty());
    }

    #[test]
    fn feature_gated_mod_todo_is_not_flagged() {
        let findings = findings_for(
            "#[cfg(feature = \"wip\")]\nmod m {\n    fn f() { todo!() }\n}\n",
            "slop-merged-stub-gated-mod",
        );
        assert!(rule_findings(&findings, MERGED_STUB_RULE).is_empty());
    }

    #[test]
    fn test_without_assertion_is_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { let x = 1 + 1; }\n",
            "slop-assertion-free-test",
        );
        let hits = rule_findings(&findings, ASSERTION_FREE_TEST_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn test_with_assert_eq_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { assert_eq!(1 + 1, 2); }\n",
            "slop-assertion-free-with-assert",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn test_with_unwrap_only_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { let x: Option<i32> = Some(1); x.unwrap(); }\n",
            "slop-assertion-free-unwrap",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn test_returning_result_with_try_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() -> Result<(), String> { might_fail()?; Ok(()) }\nfn might_fail() -> Result<(), String> { Ok(()) }\n",
            "slop-assertion-free-try",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn should_panic_test_without_assertion_is_not_flagged() {
        let findings = findings_for(
            "#[test]\n#[should_panic]\nfn f() { let x = 1 + 1; }\n",
            "slop-assertion-free-should-panic",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn test_with_assert_free_closure_is_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { let closure = || { let y = 1 + 1; }; closure(); }\n",
            "slop-assertion-free-closure",
        );
        assert_eq!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).len(), 1);
    }

    #[test]
    fn test_with_qualified_insta_snapshot_macro_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { insta::assert_snapshot!(\"value\"); }\n",
            "slop-assertion-free-insta-snapshot",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn test_with_qualified_insta_json_snapshot_macro_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { insta::assert_json_snapshot!(value); }\n",
            "slop-assertion-free-insta-json-snapshot",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn test_with_qualified_pretty_assertions_assert_eq_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn f() { pretty_assertions::assert_eq!(1 + 1, 2); }\n",
            "slop-assertion-free-pretty-assertions",
        );
        assert!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).is_empty());
    }

    #[test]
    fn generic_naming_numeric_suffix_locals_are_flagged() {
        let findings = findings_for(
            "fn f() { let data1 = 1; let data2 = 2; }\n",
            "slop-generic-naming-numeric-suffix",
        );
        let hits = rule_findings(&findings, GENERIC_NAMING_RULE);
        assert_eq!(hits.len(), 2);
        for hit in &hits {
            assert_eq!(hit.evidence_class, EvidenceClass::DerivedFact);
        }
    }

    #[test]
    fn generic_naming_private_bare_local_is_not_flagged() {
        let findings = findings_for(
            "fn g() -> Result<i32, String> { let result = do_thing()?; Ok(result) }\nfn do_thing() -> Result<i32, String> { Ok(1) }\n",
            "slop-generic-naming-private-result",
        );
        assert!(rule_findings(&findings, GENERIC_NAMING_RULE).is_empty());
    }

    #[test]
    fn generic_naming_pub_struct_exact_word_is_flagged() {
        let findings = findings_for("pub struct Manager;\n", "slop-generic-naming-struct");
        let hits = rule_findings(&findings, GENERIC_NAMING_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn generic_naming_pub_struct_substring_is_not_flagged() {
        let findings = findings_for(
            "pub struct ConnectionManager;\n",
            "slop-generic-naming-struct-substring",
        );
        assert!(rule_findings(&findings, GENERIC_NAMING_RULE).is_empty());
    }

    #[test]
    fn generic_naming_pub_fn_exact_word_is_flagged() {
        let findings = findings_for("pub fn helper() {}\n", "slop-generic-naming-fn");
        let hits = rule_findings(&findings, GENERIC_NAMING_RULE);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn generic_naming_pub_impl_method_is_not_flagged() {
        let findings = findings_for(
            "struct S;\nimpl S {\n    pub fn helper(&self) {}\n}\n",
            "slop-generic-naming-impl-method",
        );
        assert!(rule_findings(&findings, GENERIC_NAMING_RULE).is_empty());
    }

    #[test]
    fn doc_restates_signature_pure_echo_is_flagged() {
        let findings = findings_for(
            "/// Returns the result.\npub fn f() -> Result<(), String> { Ok(()) }\n",
            "slop-doc-restates-signature-echo",
        );
        let hits = rule_findings(&findings, DOC_RESTATES_SIGNATURE_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn doc_restates_signature_real_prose_is_not_flagged() {
        let findings = findings_for(
            "/// Parses the config file and validates required fields.\nfn f() {}\n",
            "slop-doc-restates-signature-prose",
        );
        assert!(rule_findings(&findings, DOC_RESTATES_SIGNATURE_RULE).is_empty());
    }

    #[test]
    fn conversational_artifact_tier1_phrase_is_flagged() {
        let findings = findings_for(
            "fn f() {\n    // As an AI, I can't do that.\n}\n",
            "slop-conversational-artifact-tier1",
        );
        let hits = rule_findings(&findings, CONVERSATIONAL_ARTIFACT_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    #[test]
    fn conversational_artifact_doc_comment_is_excluded() {
        let findings = findings_for(
            "/// In a real implementation, this would also validate input.\nfn f() {}\n",
            "slop-conversational-artifact-doc",
        );
        assert!(rule_findings(&findings, CONVERSATIONAL_ARTIFACT_RULE).is_empty());
    }

    #[test]
    fn conversational_artifact_tier2_phrase_past_word_eight_is_not_flagged() {
        let findings = findings_for(
            "fn f() {\n    // This example function shows some basic arithmetic logic in a real implementation context.\n    let _ = 1;\n}\n",
            "slop-conversational-artifact-tier2-position",
        );
        assert!(rule_findings(&findings, CONVERSATIONAL_ARTIFACT_RULE).is_empty());
    }

    #[test]
    fn conversational_artifact_tier2_phrase_is_not_flagged_inside_an_unrelated_word() {
        // Two of CONVERSATIONAL_TIER2's short entries are a raw substring of
        // this sentence's opening word — a plain `.contains()` would
        // misclassify ordinary prose as AI-assistant leakage.
        let findings = findings_for(
            "fn f() {\n    // There is no other way to express this invariant.\n}\n",
            "slop-conversational-artifact-tier2-word-boundary",
        );
        assert!(rule_findings(&findings, CONVERSATIONAL_ARTIFACT_RULE).is_empty());
    }

    #[test]
    fn step_comment_inflation_three_step_chain_is_flagged() {
        let findings = findings_for(
            "fn f() {\n    // Step 1: initialize\n    let x = 1;\n    // Step 2: compute\n    let y = x + 1;\n    // Step 3: finish\n    let _ = y;\n}\n",
            "slop-step-comment-inflation-chain",
        );
        let hits = rule_findings(&findings, STEP_COMMENT_INFLATION_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence,
            Some(serde_json::json!({ "chain_length": 3, "lines": [2, 4, 6] }))
        );
    }

    #[test]
    fn step_comment_inflation_single_step_is_not_flagged() {
        let findings = findings_for(
            "fn f() {\n    // Step 1: initialize\n    let x = 1;\n    let _ = x;\n}\n",
            "slop-step-comment-inflation-single",
        );
        assert!(rule_findings(&findings, STEP_COMMENT_INFLATION_RULE).is_empty());
    }

    #[test]
    fn restating_comment_short_comment_is_not_flagged() {
        let findings = findings_for(
            "fn f(counter: &mut i32) {\n    // increment counter\n    *counter += 1;\n}\n",
            "slop-restating-comment-short",
        );
        assert!(rule_findings(&findings, RESTATING_COMMENT_RULE).is_empty());
    }

    #[test]
    fn restating_comment_verbose_paraphrase_is_flagged() {
        let findings = findings_for(
            "struct S { user_name_field: String }\nimpl S {\n    fn set(&mut self, given_value: String) {\n        // set the user name field to the given value\n        self.user_name_field = given_value;\n    }\n}\n",
            "slop-restating-comment-verbose",
        );
        let hits = rule_findings(&findings, RESTATING_COMMENT_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
    }

    /// `merged-stub` — unentscheidbar, macro-blindness (companion to the
    /// existing `feature_gated_fn_todo_is_not_flagged` cfg-blindness tests
    /// above, which already confirm `feature_gated_depth` suppresses a
    /// cfg-gated `todo!()`): here the `todo!()` exists only inside a
    /// `macro_rules!` body. `syn` treats a macro definition's body as an
    /// opaque token stream — `visit_macro` never sees the inner `todo!()`
    /// as a real `Macro` node — and the invocation `define_it!();` is
    /// itself an opaque `Item::Macro`, never expanded. A real build's
    /// expanded code would contain this `todo!()`, but it's structurally
    /// invisible to a syntax-only scanner: an undercount, not a bug.
    #[test]
    fn merged_stub_inside_macro_body_produces_no_finding() {
        let findings = findings_for(
            "macro_rules! define_it {\n    () => {\n        fn generated() { todo!() }\n    };\n}\ndefine_it!();\n",
            "slop-merged-stub-macro-body",
        );
        assert!(rule_findings(&findings, MERGED_STUB_RULE).is_empty());
    }

    /// `empty-impl` — unentscheidbar, macro-blindness: the doc-commented,
    /// literally-empty fn only exists inside a `macro_rules!` body. `syn`
    /// parses the macro definition's body as an opaque token stream, never
    /// as a real `ItemFn` — `check_empty_impl` is never called on it — and
    /// the invocation `define_stub!();` is itself an opaque `Item::Macro`,
    /// never expanded into the real stub it produces. Same undercount class
    /// as `merged_stub_inside_macro_body_produces_no_finding` above.
    #[test]
    fn empty_impl_inside_macro_body_produces_no_finding() {
        let findings = findings_for(
            "macro_rules! define_stub {\n    () => {\n        /// Does nothing yet.\n        fn generated() {}\n    };\n}\ndefine_stub!();\n",
            "slop-empty-impl-macro-body",
        );
        assert!(rule_findings(&findings, EMPTY_IMPL_RULE).is_empty());
    }

    /// `assertion-free-test` — unentscheidbar: the test's only assertion
    /// goes through a local `macro_rules! check { ... }` wrapper that
    /// itself calls `assert!` internally. `AssertionScanner::visit_macro`
    /// only recognizes a fixed list of assertion-macro names (plus
    /// qualified paths ending in one of them, per the `insta`/
    /// `pretty_assertions` fix) — `check` isn't on that list, and `syn`
    /// never expands the wrapper to see the `assert!` inside it, so the
    /// scanner finds nothing and flags a test that does, in fact, assert.
    /// Documented false positive, not a bug: recognizing arbitrary
    /// user-defined wrapper macros isn't solvable without macro expansion.
    #[test]
    fn test_using_custom_assertion_wrapper_macro_is_still_flagged() {
        let findings = findings_for(
            "macro_rules! check {\n    ($cond:expr) => {\n        assert!($cond);\n    };\n}\n#[test]\nfn f() { check!(1 + 1 == 2); }\n",
            "slop-assertion-free-custom-wrapper",
        );
        let hits = rule_findings(&findings, ASSERTION_FREE_TEST_RULE);
        assert_eq!(hits.len(), 1);
    }

    /// `tautological-test` — confirms the rule is purely syntactic (token
    /// comparison), not semantic: `VALUE` is a `const` whose value is
    /// produced by a `macro_rules!` invocation, not written out literally,
    /// yet `assert_eq!(VALUE, VALUE)` is flagged exactly the same as
    /// `assert_eq!(x, x)` would be. The rule never looks at how `VALUE` was
    /// defined — it only compares the two macro arguments' token strings —
    /// so a macro-generated definition changes nothing about detectability
    /// here (unlike the other rules in this block, this one has no blind
    /// spot to demonstrate; the golden test documents that fact).
    #[test]
    fn assert_eq_macro_generated_const_is_flagged_syntactically() {
        let findings = findings_for(
            "macro_rules! define_const {\n    ($name:ident, $val:expr) => {\n        const $name: i32 = $val;\n    };\n}\ndefine_const!(VALUE, 42);\nfn f() { assert_eq!(VALUE, VALUE); }\n",
            "slop-tautological-macro-const",
        );
        let hits = rule_findings(&findings, TAUTOLOGICAL_TEST_RULE);
        assert_eq!(hits.len(), 1);
    }

    /// `ignored-test-accumulation` — unentscheidbar, macro-blindness
    /// (undercount, same class as `suppression_debt_inside_macro_body_is_
    /// not_counted` above): the `#[ignore]` attribute exists only inside a
    /// `macro_rules!` body. `visit_attribute` never sees it — the macro
    /// definition's body is an opaque token stream, and the invocation
    /// `define_ignored_test!();` is itself an opaque `Item::Macro`, never
    /// expanded — so a real build's ignored test doesn't count toward this
    /// rule's total.
    #[test]
    fn ignored_test_inside_macro_body_is_not_counted() {
        let findings = findings_for(
            "macro_rules! define_ignored_test {\n    () => {\n        #[test]\n        #[ignore]\n        fn generated() { assert!(true); }\n    };\n}\ndefine_ignored_test!();\n",
            "slop-ignored-test-macro-body",
        );
        assert!(rule_findings(&findings, IGNORED_TEST_ACCUMULATION_RULE).is_empty());
    }

    /// `generic-naming` — unentscheidbar, cfg-blindness: `check_generic_
    /// naming_item_fn` is called unconditionally from `visit_item_fn`, the
    /// same as `check_catch_all_error` — `feature_gated_depth` is tracked
    /// but this check never consults it. A `pub fn` named `manager` behind
    /// `#[cfg(feature = "wip")]` is still flagged even though a build
    /// without that feature would never compile it in. Same class as
    /// `catch_all_error_inside_cfg_gated_pub_fn_still_flagged` above.
    #[test]
    fn generic_naming_pub_fn_inside_cfg_gated_mod_still_flagged() {
        let findings = findings_for(
            "#[cfg(feature = \"wip\")]\nmod m {\n    pub fn manager() {}\n}\n",
            "slop-generic-naming-cfg-gated",
        );
        let hits = rule_findings(&findings, GENERIC_NAMING_RULE);
        assert_eq!(hits.len(), 1);
    }

    /// `doc-restates-signature` — unentscheidbar, macro-blindness
    /// (undercount): the pure-echo doc comment and its fn signature exist
    /// only inside a `macro_rules!` body. `check_doc_restates_signature` is
    /// never called on it — the macro definition's body is an opaque token
    /// stream, and the invocation `define_getter!();` is itself an opaque
    /// `Item::Macro`, never expanded into the real, matching fn it
    /// produces.
    #[test]
    fn doc_restates_signature_inside_macro_body_produces_no_finding() {
        let findings = findings_for(
            "macro_rules! define_getter {\n    () => {\n        /// Returns the result.\n        pub fn f() -> Result<(), String> { Ok(()) }\n    };\n}\ndefine_getter!();\n",
            "slop-doc-restates-signature-macro-body",
        );
        assert!(rule_findings(&findings, DOC_RESTATES_SIGNATURE_RULE).is_empty());
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn empty_error_arm_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(EMPTY_ERROR_ARM_RULE)
            .expect("empty-error-arm has a registry entry")
            .example
            .expect("empty-error-arm has a curated example")
            .before;
        let findings = findings_for(example, "slop-empty-error-arm-registry-example");
        assert_eq!(rule_findings(&findings, EMPTY_ERROR_ARM_RULE).len(), 1);
    }

    #[test]
    fn catch_all_error_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(CATCH_ALL_ERROR_RULE)
            .expect("catch-all-error has a registry entry")
            .example
            .expect("catch-all-error has a curated example")
            .before;
        let findings = findings_for(example, "slop-catch-all-error-registry-example");
        assert_eq!(rule_findings(&findings, CATCH_ALL_ERROR_RULE).len(), 1);
    }

    #[test]
    fn suppression_debt_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(SUPPRESSION_DEBT_RULE)
            .expect("suppression-debt has a registry entry")
            .example
            .expect("suppression-debt has a curated example")
            .before;
        let findings = findings_for(example, "slop-suppression-debt-registry-example");
        assert_eq!(rule_findings(&findings, SUPPRESSION_DEBT_RULE).len(), 1);
    }

    #[test]
    fn merged_stub_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MERGED_STUB_RULE)
            .expect("merged-stub has a registry entry")
            .example
            .expect("merged-stub has a curated example")
            .before;
        let findings = findings_for(example, "slop-merged-stub-registry-example");
        assert_eq!(rule_findings(&findings, MERGED_STUB_RULE).len(), 1);
    }

    #[test]
    fn empty_impl_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(EMPTY_IMPL_RULE)
            .expect("empty-impl has a registry entry")
            .example
            .expect("empty-impl has a curated example")
            .before;
        let findings = findings_for(example, "slop-empty-impl-registry-example");
        assert_eq!(rule_findings(&findings, EMPTY_IMPL_RULE).len(), 1);
    }

    #[test]
    fn assertion_free_test_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(ASSERTION_FREE_TEST_RULE)
            .expect("assertion-free-test has a registry entry")
            .example
            .expect("assertion-free-test has a curated example")
            .before;
        let findings = findings_for(example, "slop-assertion-free-test-registry-example");
        assert_eq!(rule_findings(&findings, ASSERTION_FREE_TEST_RULE).len(), 1);
    }

    #[test]
    fn tautological_test_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(TAUTOLOGICAL_TEST_RULE)
            .expect("tautological-test has a registry entry")
            .example
            .expect("tautological-test has a curated example")
            .before;
        let findings = findings_for(example, "slop-tautological-test-registry-example");
        assert_eq!(rule_findings(&findings, TAUTOLOGICAL_TEST_RULE).len(), 1);
    }

    #[test]
    fn ignored_test_accumulation_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(IGNORED_TEST_ACCUMULATION_RULE)
            .expect("ignored-test-accumulation has a registry entry")
            .example
            .expect("ignored-test-accumulation has a curated example")
            .before;
        let findings = findings_for(example, "slop-ignored-test-accumulation-registry-example");
        assert_eq!(
            rule_findings(&findings, IGNORED_TEST_ACCUMULATION_RULE).len(),
            1
        );
    }

    #[test]
    fn conversational_artifact_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(CONVERSATIONAL_ARTIFACT_RULE)
            .expect("conversational-artifact has a registry entry")
            .example
            .expect("conversational-artifact has a curated example")
            .before;
        let findings = findings_for(example, "slop-conversational-artifact-registry-example");
        assert_eq!(
            rule_findings(&findings, CONVERSATIONAL_ARTIFACT_RULE).len(),
            1
        );
    }

    #[test]
    fn restating_comment_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(RESTATING_COMMENT_RULE)
            .expect("restating-comment has a registry entry")
            .example
            .expect("restating-comment has a curated example")
            .before;
        let findings = findings_for(example, "slop-restating-comment-registry-example");
        assert_eq!(rule_findings(&findings, RESTATING_COMMENT_RULE).len(), 1);
    }

    #[test]
    fn step_comment_inflation_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(STEP_COMMENT_INFLATION_RULE)
            .expect("step-comment-inflation has a registry entry")
            .example
            .expect("step-comment-inflation has a curated example")
            .before;
        let findings = findings_for(example, "slop-step-comment-inflation-registry-example");
        assert_eq!(
            rule_findings(&findings, STEP_COMMENT_INFLATION_RULE).len(),
            1
        );
    }

    #[test]
    fn generic_naming_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(GENERIC_NAMING_RULE)
            .expect("generic-naming has a registry entry")
            .example
            .expect("generic-naming has a curated example")
            .before;
        let findings = findings_for(example, "slop-generic-naming-registry-example");
        assert_eq!(rule_findings(&findings, GENERIC_NAMING_RULE).len(), 1);
    }

    #[test]
    fn doc_restates_signature_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(DOC_RESTATES_SIGNATURE_RULE)
            .expect("doc-restates-signature has a registry entry")
            .example
            .expect("doc-restates-signature has a curated example")
            .before;
        let findings = findings_for(example, "slop-doc-restates-signature-registry-example");
        assert_eq!(
            rule_findings(&findings, DOC_RESTATES_SIGNATURE_RULE).len(),
            1
        );
    }
}
