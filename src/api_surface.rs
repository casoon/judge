//! Fast-tier public-API-surface analysis (see todo.md §I "Public-API-
//! Oberfläche"): `undocumented-public-item`, a `syn`-only check for a
//! module-level `pub` item with no doc comment, and `semver-hazard`, a
//! `syn`-only check for two API-evolvability gaps.
//!
//! ## `semver-hazard` scope
//!
//! Two of the three sub-cases todo.md §I lists are implemented, both exact
//! syntax facts distinguished by `evidence.kind` (the same bundling
//! [`crate::slop_structural::ABSTRACTION_INFLATION_RULE`] uses for its own
//! sub-patterns): a `pub enum` with at least two variants and no
//! `#[non_exhaustive]` attribute (`missing_non_exhaustive_enum`), and a
//! `pub struct` with at least one `pub` field and no `#[non_exhaustive]`
//! attribute (`missing_non_exhaustive_struct_fields`). The third sub-case —
//! a dependency's type leaking through a public signature — needs type
//! resolution across crate boundaries the Fast Tier doesn't have; it is
//! deliberately out of scope here, not merely forgotten.
//!
//! ## Item-level visibility only
//!
//! This detector checks only whether the item **itself** is written `pub` —
//! it does not propagate the full visibility chain up through enclosing
//! modules (a heuristic, not module-graph resolution, matching how
//! [`crate::deps`]'s `UsageDomain` classification documents its own scope
//! boundary). A `pub fn` inside a private `mod` is not actually reachable
//! from outside the crate, but is still checked here as if it were —
//! resolving that would need semantic module-visibility resolution the Fast
//! Tier doesn't have. A known, accepted simplification, not hidden.
//!
//! ## Scope
//!
//! Checked item kinds: free `fn`, `struct`, `enum`, `trait`, `const`,
//! `static`, and `type` alias at module level, plus methods inside an
//! *inherent* `impl` block. Not checked: methods inside `impl Trait for
//! Type` (they typically inherit the trait's own documentation — see
//! [`crate::functions::FunctionSite::in_trait_impl`]'s doc comment for the
//! same exclusion reasoning elsewhere in this crate), `#[test]`-attributed
//! functions, and anything gated by `#[cfg(test)]` (on the item itself or an
//! enclosing item).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemStruct,
    ItemTrait, ItemType, Type, Visibility,
};

use crate::finding::{Finding, Location, Origin, Severity};
use crate::ingest::CrateInfo;

/// Rule id for a module-level `pub` item with no doc comment (see todo.md
/// §I).
pub const UNDOCUMENTED_PUBLIC_ITEM_RULE: &str = "undocumented-public-item";
/// Bump when the undocumented-public-item rule's logic changes (see todo.md
/// §5 "Regelversions-Schutz").
pub const UNDOCUMENTED_PUBLIC_ITEM_RULE_REVISION: u32 = 1;

/// Rule id shared by both `semver-hazard` sub-cases (see the module doc
/// comment's "`semver-hazard` scope" section); `evidence.kind` distinguishes
/// `missing_non_exhaustive_enum` from `missing_non_exhaustive_struct_fields`.
pub const SEMVER_HAZARD_RULE: &str = "semver-hazard";
/// Bump when either semver-hazard sub-case's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const SEMVER_HAZARD_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum ApiSurfaceError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for ApiSurfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ApiSurfaceError {}

/// Per-crate count of public top-level API items — `pub fn`/`struct`/`enum`/
/// `trait`/`const`/`static`/`type` at module level, plus a `pub fn` inside an
/// inherent `impl` (the same item kinds
/// [`check_doc`](ApiSurfaceVisitor::check_doc) already visits for
/// `undocumented-public-item`, reused rather than duplicated). A pure count,
/// not a finding — a report metadatum like `Report.counts`/
/// `analysis_universe`, with no fail/warn/info severity of its own (see
/// todo.md §I "API-Surface-Größe pro Crate, Trend gegen Baseline").
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApiSurfaceSize {
    pub per_crate: HashMap<String, usize>,
}

/// One crate's api-surface-size trend against a baseline (see
/// [`ApiSurfaceSize`]'s doc comment). `delta` is `None` when the baseline
/// recorded no `api_surface_size` at all — an older baseline schema, or one
/// saved by a different command — or the crate didn't exist in it yet,
/// mirroring how [`crate::health_score::Trend::NotComparable`] reports an
/// explicit reason instead of a false delta, at per-crate granularity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSizeTrend {
    pub crate_name: String,
    pub item_count: usize,
    pub delta: Option<i64>,
}

/// Computes [`CrateSizeTrend`] for every crate in `current`, sorted by crate
/// name for stable output. `baseline_size` is the baseline's stored
/// `api_surface_size` (`None` when absent — see [`CrateSizeTrend`]'s doc
/// comment).
pub fn size_trend(
    current: &ApiSurfaceSize,
    baseline_size: Option<&HashMap<String, usize>>,
) -> Vec<CrateSizeTrend> {
    let mut trend: Vec<CrateSizeTrend> = current
        .per_crate
        .iter()
        .map(|(crate_name, &item_count)| {
            let delta = baseline_size
                .and_then(|baseline| baseline.get(crate_name))
                .map(|&previous| item_count as i64 - previous as i64);
            CrateSizeTrend {
                crate_name: crate_name.clone(),
                item_count,
                delta,
            }
        })
        .collect();
    trend.sort_by(|a, b| a.crate_name.cmp(&b.crate_name));
    trend
}

/// Aggregated api-surface findings across a set of files, keeping findings
/// separate from files that could not be parsed.
#[derive(Debug, Default)]
pub struct WorkspaceApiSurface {
    pub findings: Vec<Finding>,
    pub errors: Vec<ApiSurfaceError>,
    /// Generated files skipped because `include_generated` was `false` (see
    /// todo.md §3.A "Generated-Code-Policy").
    pub excluded_generated: usize,
    /// Per-crate api-surface-size count (see [`ApiSurfaceSize`]).
    pub api_surface_size: ApiSurfaceSize,
}

/// Parses a single Rust source file, returning every
/// `undocumented-public-item`/`semver-hazard` finding plus the number of
/// public top-level items counted along the way (see [`ApiSurfaceSize`]) —
/// the shared implementation behind both [`analyze_file`] and
/// [`analyze_workspace`], so the item-collection walk itself is written once.
fn analyze_file_inner(path: &Path) -> Result<(Vec<Finding>, usize), ApiSurfaceError> {
    let source = std::fs::read_to_string(path)
        .map_err(|err| ApiSurfaceError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| ApiSurfaceError::Parse(path.to_path_buf(), err))?;

    let mut visitor = ApiSurfaceVisitor {
        file: path,
        path: Vec::new(),
        findings: Vec::new(),
        cfg_test_depth: 0,
        in_trait_impl: Vec::new(),
        item_count: 0,
    };
    visitor.visit_file(&ast);
    Ok((visitor.findings, visitor.item_count))
}

/// Parses a single Rust source file and returns every `undocumented-public-item`
/// finding in it.
pub fn analyze_file(path: &Path) -> Result<Vec<Finding>, ApiSurfaceError> {
    analyze_file_inner(path).map(|(findings, _)| findings)
}

/// Runs [`analyze_file`] over every crate's source files and aggregates the
/// results, plus each crate's api-surface-size count (see [`ApiSurfaceSize`]).
/// Generated files are skipped unless `include_generated` is set (see
/// todo.md §3.A) — documentation completeness, and surface size, on
/// generated code isn't actionable the way it is on authored code.
pub fn analyze_workspace<'a>(
    crates: impl IntoIterator<Item = &'a CrateInfo>,
    include_generated: bool,
) -> WorkspaceApiSurface {
    let mut report = WorkspaceApiSurface::default();
    for krate in crates {
        let mut crate_item_count = 0;
        for file in &krate.source_files {
            if !include_generated && !file.kind.is_locally_reportable() {
                report.excluded_generated += 1;
                continue;
            }
            match analyze_file_inner(&file.path) {
                Ok((mut findings, item_count)) => {
                    report.findings.append(&mut findings);
                    crate_item_count += item_count;
                }
                Err(err) => report.errors.push(err),
            }
        }
        report
            .api_surface_size
            .per_crate
            .insert(krate.name.clone(), crate_item_count);
    }
    report
}

/// Walks a whole parsed file, tracking the enclosing `mod`/`impl`/`trait`/
/// item path for a finding's `item_path`, `#[cfg(test)]` nesting depth, and
/// whether the current `impl` block is a trait impl (see the module doc
/// comment's scope section).
struct ApiSurfaceVisitor<'a> {
    file: &'a Path,
    path: Vec<String>,
    findings: Vec<Finding>,
    /// Depth of nesting inside an item gated by `#[cfg(test)]` (on itself or
    /// an ancestor) — no item under this is checked (see
    /// [`attrs_have_cfg_test`]).
    cfg_test_depth: usize,
    /// Stack of "is the enclosing `impl` a trait impl" flags, one per
    /// enclosing `impl` block — mirrors [`crate::functions::Walker`]'s same
    /// stack.
    in_trait_impl: Vec<bool>,
    /// Count of `pub`, non-`#[cfg(test)]`-gated items visited so far — the
    /// api-surface-size count (see [`ApiSurfaceSize`]), incremented
    /// alongside `undocumented-public-item`'s own check in
    /// [`check_doc`](Self::check_doc) instead of a second walk.
    item_count: usize,
}

impl ApiSurfaceVisitor<'_> {
    fn current_item_path(&self) -> String {
        if self.path.is_empty() {
            self.file.display().to_string()
        } else {
            self.path.join("::")
        }
    }

    fn current_in_trait_impl(&self) -> bool {
        self.in_trait_impl.last().copied().unwrap_or(false)
    }

    /// Shared finding constructor for both rules this module reports —
    /// `rule_id` picks the rule, `evidence` is `None` for
    /// `undocumented-public-item` and `Some(json!({"kind": ...}))` for
    /// `semver-hazard` (mirrors [`crate::slop_structural`]'s single
    /// `abstraction_finding` helper backing several `evidence.kind`s).
    fn record(
        &mut self,
        rule_id: &str,
        span: proc_macro2::Span,
        evidence: Option<serde_json::Value>,
    ) {
        let start = span.start();
        let rule = crate::finding::RuleId::from(rule_id);
        let evidence_class = crate::finding::evidence_class_for_rule(&rule);
        let item_path = self.current_item_path();
        self.findings.push(Finding {
            id: format!(
                "{rule}:{}:{}:{}",
                self.file.display(),
                start.line,
                start.column
            )
            .into(),
            rule,
            severity: Severity::Info,
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

    /// A `pub` item with no `#[doc = ...]` attribute (see [`has_doc_comment`]),
    /// unless it — or an enclosing item — is gated by `#[cfg(test)]`. Callers
    /// pass the item's own attrs and span *before* pushing that item's own
    /// name onto `path`, so `current_item_path` already reflects it.
    ///
    /// Also increments `item_count` for every `pub`, non-`#[cfg(test)]`-gated
    /// item this visits, whether or not it ends up flagged — that is exactly
    /// the api-surface-size count (see [`ApiSurfaceSize`]): the same item
    /// kinds this rule already checks, counted once each instead of walked a
    /// second time.
    fn check_doc(&mut self, vis: &Visibility, attrs: &[Attribute], span: proc_macro2::Span) {
        if self.cfg_test_depth > 0 || attrs_have_cfg_test(attrs) {
            return;
        }
        if !matches!(vis, Visibility::Public(_)) {
            return;
        }
        self.item_count += 1;
        if has_doc_comment(attrs) {
            return;
        }
        self.record(UNDOCUMENTED_PUBLIC_ITEM_RULE, span, None);
    }

    /// Same as [`check_doc`](Self::check_doc), additionally skipping a
    /// `#[test]`-attributed function (see todo.md §I, point 3).
    fn check_doc_fn(&mut self, vis: &Visibility, attrs: &[Attribute], span: proc_macro2::Span) {
        if attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.check_doc(vis, attrs, span);
    }

    /// `semver-hazard` sub-case A: a `pub enum` with at least two variants
    /// and no `#[non_exhaustive]` attribute — adding a variant is a breaking
    /// change for an external exhaustive `match` with no wildcard arm. Same
    /// `#[cfg(test)]` exemption as [`check_doc`](Self::check_doc); a
    /// single-variant enum is exempt (see the module's `semver-hazard`
    /// scope section — a lone variant is usually deliberate, e.g. a wrapper
    /// pattern).
    fn check_semver_hazard_enum(&mut self, node: &ItemEnum) {
        if self.cfg_test_depth > 0 || attrs_have_cfg_test(&node.attrs) {
            return;
        }
        if !matches!(node.vis, Visibility::Public(_)) {
            return;
        }
        if node.variants.len() < 2 || has_non_exhaustive(&node.attrs) {
            return;
        }
        self.record(
            SEMVER_HAZARD_RULE,
            node.span(),
            Some(json!({
                "kind": "missing_non_exhaustive_enum",
                "variant_count": node.variants.len(),
            })),
        );
    }

    /// `semver-hazard` sub-case B: a `pub struct` with at least one `pub`
    /// field and no `#[non_exhaustive]` attribute — a new or removed field
    /// is a breaking change for struct-literal syntax at consumers. A unit
    /// struct, or one whose fields are all private, already encapsulates its
    /// layout and is not checked. Same `#[cfg(test)]` exemption as
    /// [`check_doc`](Self::check_doc).
    fn check_semver_hazard_struct(&mut self, node: &ItemStruct) {
        if self.cfg_test_depth > 0 || attrs_have_cfg_test(&node.attrs) {
            return;
        }
        if !matches!(node.vis, Visibility::Public(_)) {
            return;
        }
        if has_non_exhaustive(&node.attrs) {
            return;
        }
        let pub_field_count = node
            .fields
            .iter()
            .filter(|field| matches!(field.vis, Visibility::Public(_)))
            .count();
        if pub_field_count == 0 {
            return;
        }
        self.record(
            SEMVER_HAZARD_RULE,
            node.span(),
            Some(json!({
                "kind": "missing_non_exhaustive_struct_fields",
                "pub_field_count": pub_field_count,
            })),
        );
    }
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

/// Whether any attribute in `attrs` is a `#[doc = ...]` (covers both `///`
/// doc comments and explicit `#[doc]` attributes — `syn` desugars both the
/// same way).
fn has_doc_comment(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

/// Whether any attribute in `attrs` is `#[non_exhaustive]` — the exact
/// syntax fact both `semver-hazard` sub-cases turn on.
fn has_non_exhaustive(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("non_exhaustive"))
}

/// Whether `attrs` contains a `#[cfg(...)]` attribute whose predicate
/// mentions `test` as a whole word (`#[cfg(test)]`, `#[cfg(any(test, ...))]`,
/// `#[cfg(all(test, ...))]`) — a crude but conservative parse of the
/// attribute's raw tokens, not a full `cfg` predicate evaluator (mirrors
/// `deps.rs`'s private `attrs_have_cfg_test`, kept local for the same reason
/// `type_name` is).
fn attrs_have_cfg_test(attrs: &[Attribute]) -> bool {
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

impl<'ast> Visit<'ast> for ApiSurfaceVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(type_name(&node.self_ty));
        self.in_trait_impl.push(node.trait_.is_some());
        visit::visit_item_impl(self, node);
        self.in_trait_impl.pop();
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        visit::visit_item_trait(self, node);
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        self.check_semver_hazard_struct(node);
        visit::visit_item_struct(self, node);
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        self.check_semver_hazard_enum(node);
        visit::visit_item_enum(self, node);
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        self.path.pop();
        visit::visit_item_const(self, node);
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        self.path.pop();
        visit::visit_item_static(self, node);
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.ident.to_string());
        self.check_doc(&node.vis, &node.attrs, node.span());
        self.path.pop();
        visit::visit_item_type(self, node);
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.sig.ident.to_string());
        self.check_doc_fn(&node.vis, &node.attrs, node.span());
        visit::visit_item_fn(self, node);
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        self.path.push(node.sig.ident.to_string());
        if !self.current_in_trait_impl() {
            self.check_doc_fn(&node.vis, &node.attrs, node.span());
        }
        visit::visit_impl_item_fn(self, node);
        self.path.pop();
        if gated {
            self.cfg_test_depth -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::SourceFile;
    use crate::test_util::TempDir;

    fn write_and_analyze(dir: &TempDir, source: &str) -> Vec<Finding> {
        let file = dir.join("lib.rs");
        std::fs::write(&file, source).unwrap();
        analyze_file(&file).unwrap()
    }

    #[test]
    fn pub_fn_without_doc_comment_is_flagged() {
        let dir = TempDir::new("api-surface-pub-fn");
        let findings = write_and_analyze(&dir, "pub fn undocumented() {}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, UNDOCUMENTED_PUBLIC_ITEM_RULE);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].evidence_class,
            crate::finding::EvidenceClass::DerivedFact
        );
    }

    #[test]
    fn pub_struct_and_pub_enum_without_doc_comment_are_flagged() {
        let dir = TempDir::new("api-surface-pub-struct-enum");
        let findings = write_and_analyze(&dir, "pub struct Foo;\n\npub enum Bar { A, B }\n");
        // `Bar` also has 2 variants and no `#[non_exhaustive]`, so it additionally
        // fires `semver-hazard` — filter down to this test's own rule.
        let undocumented: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == UNDOCUMENTED_PUBLIC_ITEM_RULE)
            .collect();
        assert_eq!(undocumented.len(), 2);
    }

    #[test]
    fn pub_item_with_doc_comment_is_not_flagged() {
        let dir = TempDir::new("api-surface-documented");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Does the thing.
pub fn documented() {}

/// A documented struct.
pub struct Documented;
"#,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn non_pub_item_is_not_flagged() {
        let dir = TempDir::new("api-surface-non-pub");
        let findings = write_and_analyze(
            &dir,
            "pub(crate) fn crate_visible() {}\n\nfn private() {}\n",
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn method_in_trait_impl_without_own_doc_comment_is_not_flagged() {
        let dir = TempDir::new("api-surface-trait-impl");
        let findings = write_and_analyze(
            &dir,
            r#"
pub struct Foo;

pub trait Greet {
    fn hi(&self);
}

impl Greet for Foo {
    fn hi(&self) {}
}
"#,
        );
        // `Foo` and `Greet` are pub without doc comments (2 findings); the
        // trait-impl method `hi` is exempt.
        assert_eq!(findings.len(), 2);
        assert!(
            findings.iter().all(|f| f.location.item_path != "Foo::hi"),
            "trait-impl method must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn pub_method_in_inherent_impl_without_doc_comment_is_flagged() {
        let dir = TempDir::new("api-surface-inherent-impl");
        let findings = write_and_analyze(
            &dir,
            r#"
pub struct Foo;

impl Foo {
    pub fn bar(&self) {}
}
"#,
        );
        assert!(
            findings.iter().any(|f| f.location.item_path == "Foo::bar"),
            "inherent-impl pub method must be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_attributed_function_is_not_flagged() {
        let dir = TempDir::new("api-surface-test-fn");
        let findings = write_and_analyze(
            &dir,
            r#"
#[test]
pub fn a_test() {
    assert!(true);
}
"#,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn cfg_test_gated_item_is_not_flagged() {
        let dir = TempDir::new("api-surface-cfg-test");
        let findings = write_and_analyze(
            &dir,
            r#"
#[cfg(test)]
mod tests {
    pub fn helper() {}
}
"#,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    fn authored(path: PathBuf) -> SourceFile {
        SourceFile {
            path,
            kind: crate::ingest::SourceKind::Authored,
        }
    }

    /// A minimal [`CrateInfo`] fixture wrapping `source_files` — the other
    /// fields aren't read by this module's own analysis (mirrors
    /// `deps.rs`'s own `CrateInfo` test fixtures).
    fn test_crate(dir: &TempDir, name: &str, source_files: Vec<SourceFile>) -> CrateInfo {
        CrateInfo {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            manifest_path: dir.join("Cargo.toml"),
            root: dir.to_path_buf(),
            source_files,
            entry_points: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn analyze_workspace_skips_generated_files_unless_included() {
        let dir = TempDir::new("api-surface-generated");
        let authored_file = dir.join("lib.rs");
        let generated_file = dir.join("schema.rs");
        std::fs::write(&authored_file, "pub fn ok() {}\n").unwrap();
        std::fs::write(&generated_file, "pub fn also_ok() {}\n").unwrap();

        let krate = test_crate(
            &dir,
            "fixture",
            vec![
                authored(authored_file),
                SourceFile {
                    path: generated_file,
                    kind: crate::ingest::SourceKind::Generated,
                },
            ],
        );

        let excluded = analyze_workspace([&krate], false);
        assert_eq!(excluded.findings.len(), 1);
        assert_eq!(excluded.excluded_generated, 1);
        assert_eq!(excluded.api_surface_size.per_crate["fixture"], 1);

        let included = analyze_workspace([&krate], true);
        assert_eq!(included.findings.len(), 2);
        assert_eq!(included.excluded_generated, 0);
        assert_eq!(included.api_surface_size.per_crate["fixture"], 2);
    }

    #[test]
    fn analyze_workspace_counts_public_items_per_crate() {
        let dir = TempDir::new("api-surface-size");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "/// Doc.\npub fn a() {}\n\n/// Doc.\npub fn b() {}\n\nfn private() {}\n",
        )
        .unwrap();
        let krate = test_crate(&dir, "fixture", vec![authored(file)]);

        let report = analyze_workspace([&krate], false);
        assert!(
            report.findings.is_empty(),
            "unexpected findings: {:?}",
            report.findings
        );
        assert_eq!(report.api_surface_size.per_crate.len(), 1);
        assert_eq!(report.api_surface_size.per_crate["fixture"], 2);
    }

    #[test]
    fn analyze_workspace_counts_each_crate_separately() {
        let dir_a = TempDir::new("api-surface-size-crate-a");
        let file_a = dir_a.join("lib.rs");
        std::fs::write(&file_a, "/// Doc.\npub fn a() {}\n").unwrap();
        let krate_a = test_crate(&dir_a, "crate-a", vec![authored(file_a)]);

        let dir_b = TempDir::new("api-surface-size-crate-b");
        let file_b = dir_b.join("lib.rs");
        std::fs::write(
            &file_b,
            "/// Doc.\npub fn a() {}\n\n/// Doc.\npub fn b() {}\n\n/// Doc.\npub fn c() {}\n",
        )
        .unwrap();
        let krate_b = test_crate(&dir_b, "crate-b", vec![authored(file_b)]);

        let report = analyze_workspace([&krate_a, &krate_b], false);
        assert_eq!(report.api_surface_size.per_crate.len(), 2);
        assert_eq!(report.api_surface_size.per_crate["crate-a"], 1);
        assert_eq!(report.api_surface_size.per_crate["crate-b"], 3);
    }

    #[test]
    fn size_trend_reports_delta_against_a_baseline() {
        let mut current = ApiSurfaceSize::default();
        current.per_crate.insert("fixture".to_string(), 5);
        let baseline = HashMap::from([("fixture".to_string(), 3)]);

        let trend = size_trend(&current, Some(&baseline));
        assert_eq!(trend.len(), 1);
        assert_eq!(trend[0].crate_name, "fixture");
        assert_eq!(trend[0].item_count, 5);
        assert_eq!(trend[0].delta, Some(2));
    }

    #[test]
    fn size_trend_is_not_comparable_without_a_baseline_size() {
        let mut current = ApiSurfaceSize::default();
        current.per_crate.insert("fixture".to_string(), 5);

        let trend = size_trend(&current, None);
        assert_eq!(trend.len(), 1);
        assert_eq!(trend[0].item_count, 5);
        assert_eq!(trend[0].delta, None);
    }

    #[test]
    fn analyze_file_reports_parse_errors() {
        let dir = TempDir::new("api-surface-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "pub fn broken( {").unwrap();

        let err = analyze_file(&file).unwrap_err();
        match err {
            ApiSurfaceError::Parse(path, _) => assert_eq!(path, file),
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    fn semver_hazard_findings(findings: &[Finding]) -> Vec<&Finding> {
        findings
            .iter()
            .filter(|f| f.rule == SEMVER_HAZARD_RULE)
            .collect()
    }

    #[test]
    fn pub_enum_with_two_variants_and_no_non_exhaustive_is_flagged() {
        let dir = TempDir::new("api-surface-semver-enum-flagged");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
pub enum Bar {
    A,
    B,
}
"#,
        );
        let hits = semver_hazard_findings(&findings);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["kind"],
            "missing_non_exhaustive_enum"
        );
        assert_eq!(hits[0].evidence.as_ref().unwrap()["variant_count"], 2);
        assert_eq!(hits[0].severity, Severity::Info);
        assert_eq!(
            hits[0].evidence_class,
            crate::finding::EvidenceClass::DerivedFact
        );
    }

    #[test]
    fn pub_enum_with_non_exhaustive_is_not_flagged() {
        let dir = TempDir::new("api-surface-semver-enum-exempt");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
#[non_exhaustive]
pub enum Bar {
    A,
    B,
}
"#,
        );
        assert!(semver_hazard_findings(&findings).is_empty());
    }

    #[test]
    fn pub_enum_with_single_variant_is_not_flagged() {
        let dir = TempDir::new("api-surface-semver-enum-single-variant");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
pub enum Bar {
    A,
}
"#,
        );
        assert!(semver_hazard_findings(&findings).is_empty());
    }

    #[test]
    fn pub_struct_with_pub_field_and_no_non_exhaustive_is_flagged() {
        let dir = TempDir::new("api-surface-semver-struct-flagged");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
pub struct Foo {
    pub value: i32,
}
"#,
        );
        let hits = semver_hazard_findings(&findings);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["kind"],
            "missing_non_exhaustive_struct_fields"
        );
        assert_eq!(hits[0].evidence.as_ref().unwrap()["pub_field_count"], 1);
    }

    #[test]
    fn pub_struct_with_non_exhaustive_is_not_flagged() {
        let dir = TempDir::new("api-surface-semver-struct-exempt");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
#[non_exhaustive]
pub struct Foo {
    pub value: i32,
}
"#,
        );
        assert!(semver_hazard_findings(&findings).is_empty());
    }

    #[test]
    fn pub_struct_with_only_private_fields_is_not_flagged() {
        let dir = TempDir::new("api-surface-semver-struct-private-fields");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
pub struct Foo {
    value: i32,
}
"#,
        );
        assert!(semver_hazard_findings(&findings).is_empty());
    }

    #[test]
    fn tuple_and_unit_structs_are_not_flagged() {
        let dir = TempDir::new("api-surface-semver-struct-tuple-unit");
        let findings = write_and_analyze(
            &dir,
            r#"
/// Doc.
pub struct Tuple(i32);

/// Doc.
pub struct Unit;
"#,
        );
        assert!(semver_hazard_findings(&findings).is_empty());
    }

    #[test]
    fn analyze_workspace_hides_semver_hazard_in_generated_files_by_default() {
        let dir = TempDir::new("api-surface-semver-generated");
        let generated_file = dir.join("schema.rs");
        std::fs::write(
            &generated_file,
            r#"
/// Doc.
pub enum Bar {
    A,
    B,
}
"#,
        )
        .unwrap();

        let krate = test_crate(
            &dir,
            "fixture",
            vec![SourceFile {
                path: generated_file,
                kind: crate::ingest::SourceKind::Generated,
            }],
        );

        let excluded = analyze_workspace([&krate], false);
        assert!(semver_hazard_findings(&excluded.findings).is_empty());
        assert_eq!(excluded.excluded_generated, 1);

        let included = analyze_workspace([&krate], true);
        assert_eq!(semver_hazard_findings(&included.findings).len(), 1);
    }
}
