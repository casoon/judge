//! `dead-trait-impl` (see todo.md §A "Reachability & Dead Code"): a trait
//! impl block (`impl Trait for Type { .. }`) whose methods are never called
//! through that concrete type anywhere in the analyzed workspace. Requires
//! the `deep` feature — attributing a `.method()` call site to the *specific*
//! impl it dispatches to needs real semantic resolution, not just a
//! reference count.
//!
//! ## Scoped to workspace-local traits only — a deliberate, permanent cut
//!
//! This rule only checks impls of a trait whose own `trait Foo { .. }`
//! definition lives inside the analyzed workspace's own source — never a
//! trait from `std`/`core`/`alloc` or an external dependency crate. This is
//! not an arbitrary restriction; it is the one clean cut that sidesteps an
//! entire category of guaranteed false positives a naive "was `.method()`
//! ever called" check would otherwise produce:
//!
//! - `Drop::drop` is invoked implicitly by the compiler at scope-exit, never
//!   via explicit `.drop()` call syntax.
//! - The `std::ops::*` operator traits (`Add`, `Sub`, `Index`, `PartialEq`,
//!   `PartialOrd`, …) are invoked via operator syntax (`a + b`, `a == b`,
//!   `a[i]`), never as an [`ast::MethodCallExpr`] — [`Semantics::resolve_method_call`]
//!   only sees explicit `.method()` calls.
//! - `Display`/`Debug::fmt` are invoked by formatting macros through
//!   non-obvious internal paths, not a plain `.fmt()` call in user code.
//! - `Default::default()`/`From::from()` are typically called as associated
//!   functions (`Type::default()`), which parse as [`ast::CallExpr`], not
//!   [`ast::MethodCallExpr`] — invisible to this check.
//! - `Hash`, `Iterator`/`IntoIterator` (for-loop desugaring), serde's
//!   `Serialize`/`Deserialize` (invoked reflectively by derive-generated
//!   code) — the same class of compiler/macro-implicit invocation.
//!
//! A custom, workspace-defined trait has none of that compiler magic or
//! operator sugar: for such a trait, an explicit `.method()` call really is
//! (barring the generic-dispatch blind spot below) the only way it gets
//! invoked, so scoping to workspace-local trait definitions excludes all of
//! the above in one principled step instead of maintaining a blocklist of
//! "known compiler-magic traits".
//!
//! ## Detection
//!
//! 1. **Fast-Tier candidate collection** (`syn`): every `impl Trait for Type`
//!    block (trait present, i.e. not an inherent impl) where `Type` is a
//!    concrete named type — a blanket impl (`impl<T: Trait> Trait for T`,
//!    where the impl's own generic type parameter *is* the self type) is
//!    skipped, and so is any impl gated by `#[cfg(test)]` on itself or an
//!    enclosing item. An impl that overrides none of the trait's methods
//!    (relying entirely on the trait's default method bodies) has no assoc
//!    items of its own for a call site to resolve to — see "Ehrliche Grenze"
//!    below — so it is skipped too, rather than being flagged unconditionally.
//! 2. **Deep-Tier trait-origin check**: each remaining candidate's trait is
//!    resolved via [`Semantics::to_def`]/[`ra_ap_hir::Impl::trait_`], and kept
//!    only if that trait's defining crate is one of the analyzed workspace's
//!    own crates (see [`is_workspace_local_trait`]) — never `std`/`core`/
//!    `alloc` or an external dependency.
//! 3. **Deep-Tier call-site scan**: one pass over every [`ast::MethodCallExpr`]
//!    in the whole workspace, resolving each via
//!    [`Semantics::resolve_method_call`] to the concrete [`ra_ap_hir::Function`]
//!    Rust's own static dispatch selected — already the specific impl's own
//!    function, not the trait's abstract signature — then
//!    [`ra_ap_hir::AsAssocItem::as_assoc_item`]/[`ra_ap_hir::AssocItem::container`]
//!    to recover the exact [`ra_ap_hir::Impl`] block a call site resolved to.
//!    No find-all-refs/reference-search ambiguity to resolve: this directly
//!    answers "which impl" per call site.
//! 4. **Flag**: any step-2 candidate whose [`ra_ap_hir::Impl`] never appears
//!    among the step-3 resolved call sites — one [`Finding`] per dead impl
//!    block, not per method (the todo.md wording is about the impl block as a
//!    whole, not individual methods).
//!
//! ## Ehrliche Grenze — documented boundary, not a bug
//!
//! A call through a generic bound (`fn foo<T: Trait>(x: T) { x.bar() }`) is
//! not concretely dispatched at the call site — [`Semantics::resolve_method_call`]
//! resolves it to the trait's own method, not any specific impl, so it never
//! marks a candidate impl as called. This is legitimate and consistent with
//! this rule's semantics ("never called through that *concrete* type"), the
//! same generic-dispatch caveat [`crate::reachability::classify_call_kind`]'s
//! own doc comment documents for its own, analogous blind spot.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use proc_macro2::Span;
use ra_ap_hir::{AsAssocItem, AssocItemContainer, Semantics};
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, TextRange, ast};
use serde_json::json;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::dead_code::DeadCodeError;
use crate::deep::{DeepContext, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::type_name;
use crate::ingest::Workspace;

/// A non-absolute claim: only that no `.method()` call site resolved to this
/// impl block anywhere in the examined workspace — never that the impl is
/// unreachable in every real build, and never for a trait defined outside the
/// workspace (see the module docs, todo.md §17.3, §17.4).
pub const DEAD_TRAIT_IMPL_RULE: &str = "dead-trait-impl";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const DEAD_TRAIT_IMPL_RULE_REVISION: u32 = 1;

const DEAD_TRAIT_IMPL_REASON: &str =
    "no resolved .method() call site found for this trait impl anywhere in the examined workspace";

#[derive(Debug, Default)]
pub struct DeadTraitImplReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<DeadCodeError>,
    /// Number of candidate impl blocks whose trait was confirmed
    /// workspace-local and were actually checked against the call-site scan
    /// (see todo.md §7) — not the same as the raw `syn` candidate count,
    /// since a candidate whose trait resolves to `std`/an external crate is
    /// never checked at all (see the module docs).
    pub checked: usize,
}

/// One `impl Trait for Type` block found by the Fast-Tier `syn` walk (see
/// the module docs, step 1).
struct ImplCandidate {
    file_path: PathBuf,
    trait_name: String,
    type_name: String,
    impl_token_span: Span,
    line: usize,
}

/// Mirrors `crate::api_surface`'s own private `attrs_have_cfg_test` — a
/// crude but conservative parse of a `#[cfg(...)]` attribute's raw tokens
/// for the word `test`, kept local rather than shared for the same reason
/// that helper is kept local in every module that needs it.
fn attrs_have_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.tokens
            .to_string()
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|word| word == "test")
    })
}

/// Whether `node` is a blanket impl (`impl<T: Trait> Trait for T`) — its self
/// type is a bare reference to one of the impl's own generic type
/// parameters, not a concrete named type. See the module docs, step 1.
fn is_blanket_impl(node: &syn::ItemImpl) -> bool {
    let generic_idents: HashSet<String> = node
        .generics
        .type_params()
        .map(|param| param.ident.to_string())
        .collect();
    if generic_idents.is_empty() {
        return false;
    }
    match &*node.self_ty {
        syn::Type::Path(type_path)
            if type_path.qself.is_none() && type_path.path.segments.len() == 1 =>
        {
            generic_idents.contains(&type_path.path.segments[0].ident.to_string())
        }
        _ => false,
    }
}

/// Builds an [`ImplCandidate`] for `node`, or `None` if it isn't a checkable
/// `impl Trait for Type` candidate: an inherent impl (no `trait_`), a
/// blanket impl (see [`is_blanket_impl`]), or one overriding none of the
/// trait's methods (see the module docs' "Ehrliche Grenze" — such an impl has
/// no assoc items of its own for a call site to resolve to).
fn candidate_from_impl(file_path: &Path, node: &syn::ItemImpl) -> Option<ImplCandidate> {
    let (_, trait_path, _) = node.trait_.as_ref()?;
    let method_count = node
        .items
        .iter()
        .filter(|item| matches!(item, syn::ImplItem::Fn(_)))
        .count();
    if method_count == 0 || is_blanket_impl(node) {
        return None;
    }
    let trait_name = trait_path.segments.last()?.ident.to_string();
    Some(ImplCandidate {
        file_path: file_path.to_path_buf(),
        trait_name,
        type_name: type_name(&node.self_ty),
        impl_token_span: node.impl_token.span(),
        line: node.impl_token.span().start().line,
    })
}

struct ImplWalker<'a> {
    cfg_test_depth: usize,
    file_path: &'a Path,
    candidates: Vec<ImplCandidate>,
}

impl<'ast> Visit<'ast> for ImplWalker<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        visit::visit_item_mod(self, node);
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let gated = attrs_have_cfg_test(&node.attrs);
        let excluded = self.cfg_test_depth > 0 || gated;
        if gated {
            self.cfg_test_depth += 1;
        }
        if !excluded {
            self.candidates
                .extend(candidate_from_impl(self.file_path, node));
        }
        visit::visit_item_impl(self, node);
        if gated {
            self.cfg_test_depth -= 1;
        }
    }
}

/// Collects every `impl Trait for Type` candidate once, across the whole
/// workspace (see the module docs, step 1). A per-file read/parse failure is
/// a non-fatal, reported error — matching `crate::dead_code`'s own "skip this
/// file, keep going" handling, not a hard stop for the whole run.
fn collect_candidates(workspace: &Workspace) -> (Vec<ImplCandidate>, Vec<DeadCodeError>) {
    let mut candidates = Vec::new();
    let mut errors = Vec::new();

    for krate in &workspace.crates {
        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }

            let source = match std::fs::read_to_string(&file.path) {
                Ok(source) => source,
                Err(err) => {
                    errors.push(DeadCodeError::Io(file.path.clone(), err));
                    continue;
                }
            };
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    errors.push(DeadCodeError::Parse(file.path.clone(), err));
                    continue;
                }
            };

            let mut walker = ImplWalker {
                cfg_test_depth: 0,
                file_path: &file.path,
                candidates: Vec::new(),
            };
            walker.visit_file(&ast);
            candidates.extend(walker.candidates);
        }
    }

    (candidates, errors)
}

/// Resolves `impl_token_span` (an [`ImplCandidate::impl_token_span`]) to the
/// enclosing [`ast::Impl`] syntax node in the Deep Tier's own parse of
/// `file_id` — the same "step from a `syn` position down to `ra_ap_syntax`"
/// move `crate::api_surface_deep::resolve_fn_node` makes for a function
/// candidate. `None` when the position doesn't line up with a token at all,
/// skipped rather than reported as an error (same "im Zweifel nicht melden"
/// stance).
fn resolve_impl_node(
    sema: &Semantics<'_, RootDatabase>,
    file_id: FileId,
    impl_token_span: Span,
) -> Option<ast::Impl> {
    let byte_range = impl_token_span.byte_range();
    let text_range = TextRange::new(
        (byte_range.start as u32).into(),
        (byte_range.end as u32).into(),
    );
    let source_file = sema.parse_guess_edition(file_id);
    let token = source_file
        .syntax()
        .token_at_offset(text_range.start())
        .find(|token| token.text_range() == text_range)?;
    token.parent()?.ancestors().find_map(ast::Impl::cast)
}

/// The `to_string()` of a crate's own display name, or `"?"` if it has none
/// (mirrors `crate::api_surface_deep`'s own private `crate_display_name`).
fn crate_display_name(krate: ra_ap_hir::Crate, db: &RootDatabase) -> String {
    krate
        .display_name(db)
        .map_or_else(|| "?".to_string(), |name| name.to_string())
}

/// Whether `trait_def`'s own defining crate is one of the analyzed
/// workspace's crates — never `std`/`core`/`alloc` (the sysroot crates
/// `DeepContext::load` always loads) or an external dependency crate (see the
/// module docs' "Scoped to workspace-local traits only"). `workspace_crate_names`
/// holds each workspace crate's Cargo package name normalized the same way
/// Cargo/rustc normalize a package name into its crate identifier (`-` to
/// `_`) — `ra_ap_hir::Crate::display_name` always returns that normalized
/// form, never the raw, possibly-hyphenated Cargo.toml name.
fn is_workspace_local_trait(
    trait_def: ra_ap_hir::Trait,
    db: &RootDatabase,
    workspace_crate_names: &HashSet<String>,
) -> bool {
    let krate = trait_def.module(db).krate(db);
    workspace_crate_names.contains(&crate_display_name(krate, db))
}

fn finding_for(candidate: &ImplCandidate) -> Finding {
    let evidence = json!({
        "tier": "deep",
        "file": candidate.file_path,
        "trait_name": candidate.trait_name,
        "type_name": candidate.type_name,
        "reason": DEAD_TRAIT_IMPL_REASON,
    });
    Finding {
        id: format!(
            "{DEAD_TRAIT_IMPL_RULE}:{}:{}:{}",
            candidate.file_path.display(),
            candidate.type_name,
            candidate.trait_name,
        )
        .into(),
        rule: DEAD_TRAIT_IMPL_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: candidate.file_path.clone(),
            line: OneBasedLine::new(candidate.line).expect("proc-macro2 span lines are 1-based"),
            item_path: format!("{} as {}", candidate.type_name, candidate.trait_name),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Runs the `dead-trait-impl` check over `workspace` (see the module docs).
/// Loads its own [`DeepContext`] — the same accepted, documented extra cost
/// every other Deep-Tier detector in this crate takes for the same reason
/// (see e.g. `crate::api_surface_deep::analyze_workspace`'s doc comment).
pub fn analyze_workspace(workspace: &Workspace) -> Result<DeadTraitImplReport, DeadCodeError> {
    let ctx = DeepContext::load(&workspace.root).map_err(DeadCodeError::Deep)?;
    let db = ctx.raw_database();
    let sema = Semantics::new(db);

    let (syn_candidates, collect_errors) = collect_candidates(workspace);
    let workspace_crate_names: HashSet<String> = workspace
        .crates
        .iter()
        .map(|krate| krate.name.replace('-', "_"))
        .collect();

    // Calling `hir::Impl`/`hir::Trait`/`Semantics::resolve_method_call`
    // methods directly (rather than through `ra_ap_ide::Analysis`'s facade)
    // needs the next-trait-solver's db attached explicitly — see
    // `crate::api_surface_deep::analyze_workspace`'s identical wrapping and
    // its doc comment for why.
    ra_ap_hir::attach_db(db, || {
        let mut report = DeadTraitImplReport {
            errors: collect_errors,
            ..DeadTraitImplReport::default()
        };

        // Step 2: resolve each syn candidate to its `hir::Impl`, keeping
        // only those whose trait is defined within the analyzed workspace.
        let mut resolved: Vec<(ImplCandidate, ra_ap_hir::Impl)> = Vec::new();
        for candidate in syn_candidates {
            let Some(file_id) = ctx.file_id(&candidate.file_path) else {
                continue;
            };
            let Some(impl_node) = resolve_impl_node(&sema, file_id, candidate.impl_token_span)
            else {
                continue;
            };
            let Some(hir_impl) = sema.to_def(&impl_node) else {
                continue;
            };
            let Some(trait_def) = hir_impl.trait_(db) else {
                continue;
            };
            if !is_workspace_local_trait(trait_def, db, &workspace_crate_names) {
                continue;
            }
            resolved.push((candidate, hir_impl));
        }
        report.checked = resolved.len();

        // Step 3: one pass over every method-call expression in the whole
        // workspace, resolving each to the exact `hir::Impl` it dispatches
        // to (see the module docs).
        let mut called: HashSet<ra_ap_hir::Impl> = HashSet::new();
        for krate in &workspace.crates {
            for file in &krate.source_files {
                if !file.kind.is_locally_reportable() {
                    continue;
                }
                let Some(file_id) = ctx.file_id(&file.path) else {
                    continue;
                };
                let source_file = sema.parse_guess_edition(file_id);
                for method_call in source_file
                    .syntax()
                    .descendants()
                    .filter_map(ast::MethodCallExpr::cast)
                {
                    let Some(function) = sema.resolve_method_call(&method_call) else {
                        continue;
                    };
                    let Some(assoc_item) = function.as_assoc_item(db) else {
                        continue;
                    };
                    if let AssocItemContainer::Impl(impl_) = assoc_item.container(db) {
                        called.insert(impl_);
                    }
                }
            }
        }

        // Step 4: flag every resolved candidate whose impl never appeared
        // among the resolved call sites.
        for (candidate, hir_impl) in &resolved {
            if !called.contains(hir_impl) {
                report.findings.push(finding_for(candidate));
            }
        }

        Ok(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn load_single_crate_workspace(dir: &TempDir, lib_source: &str) -> Workspace {
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-trait-impl-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    fn dead_trait_impl_findings(report: &DeadTraitImplReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|finding| finding.rule == DEAD_TRAIT_IMPL_RULE)
            .collect()
    }

    /// A workspace-local trait with an impl whose method is never called
    /// anywhere — must fire.
    #[test]
    fn workspace_local_trait_impl_never_called_fires() {
        let dir = TempDir::new("dead-trait-impl-never-called");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"
pub trait Greeter {
    fn greet(&self) -> String;
}

pub struct Robot;

impl Greeter for Robot {
    fn greet(&self) -> String {
        "beep".to_string()
    }
}
"#,
        );

        let report = analyze_workspace(&workspace).unwrap();
        let findings = dead_trait_impl_findings(&report);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one dead-trait-impl finding: {findings:?}"
        );
        assert!(findings[0].location.item_path.contains("Robot"));
        assert!(findings[0].location.item_path.contains("Greeter"));
    }

    /// The same trait, with an impl whose method IS called via `.method()`
    /// syntax elsewhere — must not fire.
    #[test]
    fn workspace_local_trait_impl_called_does_not_fire() {
        let dir = TempDir::new("dead-trait-impl-called");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"
pub trait Greeter {
    fn greet(&self) -> String;
}

pub struct Robot;

impl Greeter for Robot {
    fn greet(&self) -> String {
        "beep".to_string()
    }
}

pub fn run() -> String {
    Robot.greet()
}
"#,
        );

        let report = analyze_workspace(&workspace).unwrap();
        assert!(
            dead_trait_impl_findings(&report).is_empty(),
            "a called trait impl must not fire: {:?}",
            report.findings
        );
    }

    /// A blanket impl (`impl<T: SomeTrait> SomeTrait for T`) — excluded,
    /// never fires regardless of usage.
    #[test]
    fn blanket_impl_is_excluded() {
        let dir = TempDir::new("dead-trait-impl-blanket");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"
pub trait Loud {
    fn shout(&self) -> String;
}

impl<T: std::fmt::Debug> Loud for T {
    fn shout(&self) -> String {
        format!("{:?}!", self)
    }
}
"#,
        );

        let report = analyze_workspace(&workspace).unwrap();
        assert!(
            dead_trait_impl_findings(&report).is_empty(),
            "a blanket impl must never be a candidate, even though it's never called: {:?}",
            report.findings
        );
    }

    /// An impl of a trait NOT defined in the workspace (`std::fmt::Display`,
    /// never explicitly `.fmt()`-called) — must not fire. Proves the
    /// workspace-local-trait-only scoping: the single most important
    /// negative test, since it's the core false-positive-avoidance mechanism.
    #[test]
    fn non_workspace_trait_impl_does_not_fire() {
        let dir = TempDir::new("dead-trait-impl-std-trait");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"
use std::fmt;

pub struct Widget;

impl fmt::Display for Widget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "widget")
    }
}
"#,
        );

        let report = analyze_workspace(&workspace).unwrap();
        assert!(
            dead_trait_impl_findings(&report).is_empty(),
            "an impl of a non-workspace trait (std::fmt::Display) must never be a candidate: {:?}",
            report.findings
        );
    }

    /// A trait with two impls (for two different types), where only one
    /// type's methods are ever called — only the unused type's impl fires,
    /// proving per-impl, not per-trait, resolution.
    #[test]
    fn only_the_unused_impl_of_a_multiply_implemented_trait_fires() {
        let dir = TempDir::new("dead-trait-impl-two-impls");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"
pub trait Greeter {
    fn greet(&self) -> String;
}

pub struct Robot;

impl Greeter for Robot {
    fn greet(&self) -> String {
        "beep".to_string()
    }
}

pub struct Human;

impl Greeter for Human {
    fn greet(&self) -> String {
        "hello".to_string()
    }
}

pub fn run() -> String {
    Robot.greet()
}
"#,
        );

        let report = analyze_workspace(&workspace).unwrap();
        let findings = dead_trait_impl_findings(&report);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one dead-trait-impl finding (Human, not Robot): {findings:?}"
        );
        assert!(findings[0].location.item_path.contains("Human"));
        assert!(!findings[0].location.item_path.contains("Robot"));
    }
}
