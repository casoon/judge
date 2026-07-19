//! Workspace-wide dead-code detection via the Deep Tier (see todo.md §3.A
//! "Reachability & Dead Code", §14.2 P1). Requires the `deep` feature —
//! semantic reachability isn't available at the Fast Tier.
//!
//! Scope: `unused-pub-workspace` only, for free functions, impl/trait
//! methods ([`crate::functions::walk_functions`]'s items), and top-level
//! structs/enums/traits/consts/statics plus associated consts/types inside
//! impls ([`walk_type_items`], below).
//!
//! **Simplification, documented rather than hidden:** every workspace crate
//! is treated as workspace-internal. todo.md §3.A distinguishes
//! `unused-pub-workspace` (a real finding) from `unused-pub-api` on a
//! *published* crate (info-only, semver-sensitive) — this module doesn't yet
//! check a crate's `publish` field to tell the two apart.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;
use proc_macro2::Span;
use syn::visit::{self, Visit};

use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::{type_name, walk_functions};
use crate::ingest::{SourceFile, Workspace};

pub const UNUSED_PUB_WORKSPACE_RULE: &str = "unused-pub-workspace";
/// Bump when the unused-pub-workspace rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNUSED_PUB_WORKSPACE_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum DeadCodeError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    Metadata(cargo_metadata::Error),
}

impl std::fmt::Display for DeadCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
        }
    }
}

impl std::error::Error for DeadCodeError {}

#[derive(Debug, Default)]
pub struct WorkspaceDeadCode {
    pub findings: Vec<Finding>,
    pub errors: Vec<DeadCodeError>,
    /// Number of `pub` items actually queried (functions, methods, structs,
    /// enums, traits, consts — see todo.md §7, evidence for how thorough the
    /// run was, not just its findings).
    pub checked: usize,
}

/// A `pub` struct/enum/trait/const/static declaration, or a `pub` associated
/// const/type inside an `impl` block, discovered while walking a file — the
/// type-level counterpart to [`crate::functions::walk_functions`]'s
/// function-like items. Anonymous consts (`const _: () = ...`) aren't
/// covered.
struct TypeItemSite<'ast> {
    qualified_name: String,
    ident_span: Span,
    vis: &'ast syn::Visibility,
}

/// Visits every top-level `struct`, `enum`, `trait`, `const`, and `static` in
/// `file`, plus every associated const/type inside an `impl` block, tracking
/// the enclosing `mod`/`impl`/`trait` path the same way
/// [`crate::functions::walk_functions`] does, so the two produce consistent
/// qualified names.
fn walk_type_items<'ast>(file: &'ast syn::File, on_item: impl FnMut(TypeItemSite<'ast>)) {
    struct Walker<F> {
        path: Vec<String>,
        on_item: F,
    }

    impl<F> Walker<F> {
        fn qualified_name(&self, name: &str) -> String {
            if self.path.is_empty() {
                name.to_string()
            } else {
                format!("{}::{name}", self.path.join("::"))
            }
        }
    }

    impl<'ast, F: FnMut(TypeItemSite<'ast>)> Walker<F> {
        fn emit(&mut self, name: &str, ident_span: Span, vis: &'ast syn::Visibility) {
            if name == "_" {
                return;
            }
            let qualified_name = self.qualified_name(name);
            (self.on_item)(TypeItemSite {
                qualified_name,
                ident_span,
                vis,
            });
        }
    }

    impl<'ast, F: FnMut(TypeItemSite<'ast>)> Visit<'ast> for Walker<F> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if node.content.is_some() {
                self.path.push(node.ident.to_string());
                visit::visit_item_mod(self, node);
                self.path.pop();
            } else {
                visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_struct(self, node);
        }

        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_enum(self, node);
        }

        fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            self.path.push(node.ident.to_string());
            visit::visit_item_trait(self, node);
            self.path.pop();
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            self.path.push(type_name(&node.self_ty));
            visit::visit_item_impl(self, node);
            self.path.pop();
        }

        fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_const(self, node);
        }

        fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_static(self, node);
        }

        fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_impl_item_const(self, node);
        }

        fn visit_impl_item_type(&mut self, node: &'ast syn::ImplItemType) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_impl_item_type(self, node);
        }
    }

    let mut walker = Walker {
        path: Vec::new(),
        on_item,
    };
    walker.visit_file(file);
}

/// Workspace member crate names with at least one direct (`normal` or
/// `build`, not `dev`) dependency whose own compiled target is a proc-macro
/// (`cargo_metadata::Target::is_proc_macro`). Attached to
/// `unused-pub-workspace` findings (see `check_item`) as a
/// `proc_macro_expansion_disabled` limitation: [`crate::deep::DeepContext::load`]
/// loads with `ProcMacroServerChoice::None`, so `find_all_refs` can never see
/// a caller that only exists in a proc-macro's expanded output (see the
/// `a_pub_fn_reachable_only_through_an_unexpanded_proc_macro_derive_is_falsely_flagged_dead`
/// test below), and a crate that pulls in a proc-macro dependency is exactly
/// where that blind spot can bite.
///
/// **Crate-wide, over-approximate signal — not item-level.** This answers
/// "does this crate have a proc-macro dependency", not "is this specific
/// item proc-macro-reachable" — the analysis has no way to narrow the signal
/// down that far without actually expanding the macro (out of scope; see
/// todo.md §2.1). Attaching the limitation to every `unused-pub-workspace`
/// finding in an exposed crate, rather than trying to guess which findings
/// are actually affected, is the same "im Zweifel nicht [fälschlich sicher]
/// melden" stance the rest of this module takes: more disclosure than
/// strictly necessary is safer than missing a real blind spot.
///
/// Needs a full (non-`--no-deps`) `cargo metadata` resolve: [`crate::ingest::load`]
/// runs `cargo metadata --no-deps` (see its module doc), which never fetches
/// a dependency's own package/target metadata — only the workspace members'
/// declared dependencies are visible that way. [`crate::dep_graph`] needs the
/// same full resolve for its own rules and documents why in its module doc;
/// this runs its own `cargo_metadata::MetadataCommand`, once per
/// [`analyze_workspace`] call, following that module's pattern rather than
/// sharing its `Metadata` value — neither `dead_code` nor `ingest` currently
/// holds one already loaded, and threading dep_graph's through would widen
/// that module's API for a dependency this module doesn't otherwise need.
fn proc_macro_exposed_crates(
    workspace_root: &Path,
) -> Result<HashSet<String>, cargo_metadata::Error> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()?;

    let proc_macro_packages: HashSet<&cargo_metadata::PackageId> = metadata
        .packages
        .iter()
        .filter(|package| {
            package
                .targets
                .iter()
                .any(cargo_metadata::Target::is_proc_macro)
        })
        .map(|package| &package.id)
        .collect();

    let Some(resolve) = &metadata.resolve else {
        return Ok(HashSet::new());
    };

    let mut exposed = HashSet::new();
    for member_id in &metadata.workspace_members {
        let Some(node) = resolve.nodes.iter().find(|node| &node.id == member_id) else {
            continue;
        };
        let has_direct_proc_macro_dep = node.deps.iter().any(|dep| {
            proc_macro_packages.contains(&dep.pkg)
                && dep.dep_kinds.iter().any(|dep_kind| {
                    matches!(
                        dep_kind.kind,
                        cargo_metadata::DependencyKind::Normal
                            | cargo_metadata::DependencyKind::Build
                    )
                })
        });
        if has_direct_proc_macro_dep
            && let Some(package) = metadata.packages.iter().find(|pkg| &pkg.id == member_id)
        {
            exposed.insert(package.name.clone());
        }
    }
    Ok(exposed)
}

/// Checks one `pub` item for cross-crate usage and records a finding if
/// neither that nor entry-point reachability found it live — the shared
/// logic both [`walk_functions`]'s and [`walk_type_items`]'s callbacks
/// funnel into.
///
/// The entry-point check matters most for single-crate workspaces — the
/// common case — where cross-crate usage is vacuously impossible (there is
/// no other crate), which would otherwise make every `pub` item look
/// unused. An item reachable from its own crate's `fn main` is genuinely
/// live even with zero cross-crate references (see
/// [`crate::reachability::is_reachable_from_entry`]'s own entry-point scope
/// caveats — this inherits them).
#[allow(clippy::too_many_arguments)]
fn check_item(
    analysis: &ra_ap_ide::Analysis,
    crate_of_file: &HashMap<FileId, &str>,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    proc_macro_exposed: &HashSet<String>,
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    qualified_name: &str,
    offset: u32,
    line: usize,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) {
    report.checked += 1;
    let position = ra_ap_ide::FilePosition {
        file_id,
        offset: offset.into(),
    };

    let referencing = match crate::deep::referencing_files(analysis, position, include_tests) {
        Ok(referencing) => referencing,
        Err(err) => {
            report.errors.push(DeadCodeError::Deep(err));
            return;
        }
    };
    let used_externally = referencing.iter().any(|referencing_file| {
        crate_of_file
            .get(referencing_file)
            .is_some_and(|owner| *owner != krate_name)
    });
    if used_externally {
        return;
    }

    match crate::reachability::is_reachable_from_entry(
        analysis,
        entry_keys,
        position,
        include_tests,
    ) {
        Ok(true) => {}
        Ok(false) => {
            let searched_crates: std::collections::HashSet<&str> =
                crate_of_file.values().copied().collect();
            let mut evidence = serde_json::json!({
                "tier": "deep",
                "searched_crates": searched_crates.len(),
                "references_found": referencing.len(),
                "root_set_size": entry_keys.len(),
                "reason": "no reference from another workspace crate and unreachable \
                    from any recognized entry point (fn main in a [[bin]] or [[example]] target)",
            });
            if proc_macro_exposed.contains(krate_name) {
                evidence["limitations"] = serde_json::json!(["proc_macro_expansion_disabled"]);
            }
            report.findings.push(Finding {
                id: format!(
                    "{UNUSED_PUB_WORKSPACE_RULE}:{}:{qualified_name}",
                    file.path.display()
                )
                .into(),
                rule: UNUSED_PUB_WORKSPACE_RULE.into(),
                severity: Severity::Warn,
                location: Location {
                    file: file.path.clone(),
                    line: OneBasedLine::new(line).expect("source line numbers are 1-based"),
                    item_path: qualified_name.to_string(),
                },
                evidence_class: EvidenceClass::BoundedSemantic,
                origin: Origin::Code,
                evidence: Some(evidence),
                caused_by: Vec::new(),
                causes: Vec::new(),
            });
        }
        Err(err) => report.errors.push(reachability_error(err)),
    }
}

/// Converts a [`crate::reachability::ReachabilityError`] into the closest
/// matching [`DeadCodeError`] variant, so the two modules' errors can share
/// one `errors` list.
fn reachability_error(err: crate::reachability::ReachabilityError) -> DeadCodeError {
    use crate::reachability::ReachabilityError;
    match err {
        ReachabilityError::Deep(deep_err) => DeadCodeError::Deep(deep_err),
        ReachabilityError::Io(path, io_err) => DeadCodeError::Io(path, io_err),
        ReachabilityError::Parse(path, parse_err) => DeadCodeError::Parse(path, parse_err),
        ReachabilityError::UnknownItem(item) => {
            DeadCodeError::Deep(DeepError::Cancelled(format!("unknown item: {item}")))
        }
        // `find_item_position`'s ambiguity is only reachable via `--why-live`'s
        // CLI item-path lookup — `analyze_workspace` never calls it.
        ReachabilityError::AmbiguousItem(item, _) => {
            DeadCodeError::Deep(DeepError::Cancelled(format!("ambiguous item: {item}")))
        }
    }
}

/// Finds `pub` functions/methods referenced only from their own defining
/// crate — or not at all — never from another workspace crate. This is
/// `unused-pub-workspace`, todo.md §3.A's "Kernregel": exposing something as
/// `pub` that nothing outside the crate uses only widens the API surface;
/// `pub(crate)` would do the same job with a smaller footprint.
///
/// `include_tests` selects between the "production" and "all" reachability
/// modes from todo.md §3.A — a reference only from a `#[test]` doesn't count
/// as external use when `include_tests` is `false`.
pub fn analyze_workspace(
    workspace: &Workspace,
    include_tests: bool,
) -> Result<WorkspaceDeadCode, DeadCodeError> {
    let ctx = DeepContext::load(&workspace.root).map_err(DeadCodeError::Deep)?;
    let analysis = ctx.analysis();

    let mut crate_of_file: HashMap<FileId, &str> = HashMap::new();
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if let Some(file_id) = ctx.file_id(&file.path) {
                crate_of_file.insert(file_id, krate.name.as_str());
            }
        }
    }

    let entries = crate::reachability::entry_point_positions(workspace, &ctx, include_tests)
        .map_err(reachability_error)?;
    let entry_keys: std::collections::HashSet<(FileId, u32)> = entries
        .iter()
        .map(|(_, position)| crate::reachability::position_key(*position))
        .collect();

    let mut report = WorkspaceDeadCode::default();

    let proc_macro_exposed = match proc_macro_exposed_crates(&workspace.root) {
        Ok(exposed) => exposed,
        Err(err) => {
            report.errors.push(DeadCodeError::Metadata(err));
            HashSet::new()
        }
    };

    for krate in &workspace.crates {
        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }
            let Some(file_id) = ctx.file_id(&file.path) else {
                // Not indexed by the loader (e.g. excluded, or the loader
                // failed to discover this target) — nothing to query.
                continue;
            };

            let source = match std::fs::read_to_string(&file.path) {
                Ok(source) => source,
                Err(err) => {
                    report
                        .errors
                        .push(DeadCodeError::Io(file.path.clone(), err));
                    continue;
                }
            };
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    report
                        .errors
                        .push(DeadCodeError::Parse(file.path.clone(), err));
                    continue;
                }
            };

            walk_functions(&ast, |site| {
                let Some(syn::Visibility::Public(_)) = site.vis else {
                    return;
                };
                check_item(
                    &analysis,
                    &crate_of_file,
                    &entry_keys,
                    &proc_macro_exposed,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    site.ident_span.byte_range().start as u32,
                    site.ident_span.start().line,
                    include_tests,
                    &mut report,
                );
            });

            walk_type_items(&ast, |site| {
                if !matches!(site.vis, syn::Visibility::Public(_)) {
                    return;
                }
                check_item(
                    &analysis,
                    &crate_of_file,
                    &entry_keys,
                    &proc_macro_exposed,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    site.ident_span.byte_range().start as u32,
                    site.ident_span.start().line,
                    include_tests,
                    &mut report,
                );
            });
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::test_util::TempDir;

    fn load_single_crate_workspace(dir: &TempDir, lib_source: &str) -> Workspace {
        load_single_crate_workspace_with_edition(dir, "2021", lib_source)
    }

    fn load_single_crate_workspace_with_edition(
        dir: &TempDir,
        edition: &str,
        lib_source: &str,
    ) -> Workspace {
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "{edition}"
"#
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    fn write_crate(dir: &TempDir, name: &str, deps: &[(&str, &str)], lib_source: &str) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        let mut manifest =
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
        if !deps.is_empty() {
            manifest.push_str("\n[dependencies]\n");
            for (dep_name, rel_path) in deps {
                manifest.push_str(&format!("{dep_name} = {{ path = \"{rel_path}\" }}\n"));
            }
        }
        std::fs::write(dir.join(name).join("Cargo.toml"), manifest).unwrap();
        std::fs::write(dir.join(name).join("src/lib.rs"), lib_source).unwrap();
    }

    fn write_workspace_manifest(dir: &TempDir, members: &[&str]) {
        let members_toml = members
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[workspace]\nmembers = [{members_toml}]\nresolver = \"2\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn a_pub_fn_called_from_another_workspace_crate_is_not_flagged() {
        let dir = TempDir::new("dead-code-cross-crate");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn used_by_consumer() -> i32 {
    1
}

pub fn never_called() -> i32 {
    2
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::used_by_consumer()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: Vec<_> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains(&"used_by_consumer"),
            "called from `consumer`, a different workspace crate — must not be flagged"
        );
        assert!(
            names.contains(&"never_called"),
            "never referenced anywhere — must be flagged"
        );
    }

    #[test]
    fn does_not_flag_a_completely_unused_private_fn() {
        let dir = TempDir::new("dead-code-private-fn");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"fn private_and_unused() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.checked, 0);
    }

    #[test]
    fn finding_shape_matches_the_documented_contract() {
        let dir = TempDir::new("dead-code-finding-shape");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, UNUSED_PUB_WORKSPACE_RULE);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.origin, Origin::Code);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(finding.location.item_path, "never_called");

        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(evidence["tier"], "deep");
        assert_eq!(evidence["searched_crates"], 1);
        assert_eq!(evidence["references_found"], 0);
        assert_eq!(evidence["root_set_size"], 0);
        assert!(evidence["reason"].is_string());
    }

    #[test]
    fn structs_enums_traits_and_consts_are_checked_the_same_way_as_functions() {
        let dir = TempDir::new("dead-code-type-items");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub struct UsedStruct;
pub struct DeadStruct;

pub enum UsedEnum {
    A,
}
pub enum DeadEnum {
    A,
}

pub trait UsedTrait {}
pub trait DeadTrait {}

pub const USED_CONST: i32 = 1;
pub const DEAD_CONST: i32 = 2;
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"struct Local;
impl core::UsedTrait for Local {}

pub fn run() -> i32 {
    let _ = core::UsedStruct;
    let _ = core::UsedEnum::A;
    core::USED_CONST
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        for used in ["UsedStruct", "UsedEnum", "UsedTrait", "USED_CONST"] {
            assert!(
                !names.contains(used),
                "{used} is referenced from `consumer` and must not be flagged"
            );
        }
        for dead in ["DeadStruct", "DeadEnum", "DeadTrait", "DEAD_CONST"] {
            assert!(
                names.contains(dead),
                "{dead} is never referenced and must be flagged"
            );
        }
    }

    #[test]
    fn associated_consts_types_and_statics_are_checked_the_same_way_as_functions() {
        let dir = TempDir::new("dead-code-assoc-items-and-statics");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub struct Widget;

impl Widget {
    pub const USED_ASSOC_CONST: i32 = 1;
    pub const DEAD_ASSOC_CONST: i32 = 2;
}

pub trait Converter {
    type Output;
}

impl Converter for Widget {
    type Output = i32;
}

pub static USED_STATIC: i32 = 1;
pub static DEAD_STATIC: i32 = 2;
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::USED_STATIC + core::Widget::USED_ASSOC_CONST
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        for used in ["Widget::USED_ASSOC_CONST", "USED_STATIC"] {
            assert!(
                !names.contains(used),
                "{used} is referenced from `consumer` and must not be flagged"
            );
        }
        for dead in ["Widget::DEAD_ASSOC_CONST", "DEAD_STATIC"] {
            assert!(
                names.contains(dead),
                "{dead} is never referenced and must be flagged"
            );
        }
    }

    #[test]
    fn a_private_struct_is_not_checked() {
        let dir = TempDir::new("dead-code-private-struct");
        let workspace = load_single_crate_workspace(&dir, "struct PrivateStruct;\n");

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.checked, 0);
    }

    #[test]
    fn a_single_crate_workspace_does_not_flag_items_reachable_from_its_own_main() {
        // The common case this closes a real gap for: a single-crate
        // workspace has no "other crate" to ever reference anything, so the
        // cross-crate check alone would flag the entire public API. An item
        // reachable from this crate's own `fn main` is genuinely live.
        let dir = TempDir::new("dead-code-single-crate-entry");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn used_by_main() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            r#"fn main() {
    dead_code_fixture::used_by_main();
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_main"),
            "reachable from this crate's own `fn main` — must not be flagged even with no cross-crate reference"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    #[test]
    fn an_item_only_used_by_a_no_mangle_export_is_not_flagged() {
        let dir = TempDir::new("dead-code-no-mangle-entry");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn used_by_export() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}

#[no_mangle]
pub extern "C" fn exported() -> i32 {
    used_by_export()
}
"#,
        );

        let report = analyze_workspace(&workspace, false).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_export"),
            "reachable from a #[no_mangle] export — must not be flagged even in production-only mode"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    /// The Rust-2024 unsafe-attribute spellings — `#[unsafe(no_mangle)]` and
    /// `#[unsafe(export_name = "...")]` — mark external roots exactly like
    /// their bare pre-2024 forms (see
    /// [`an_item_only_used_by_a_no_mangle_export_is_not_flagged`]). The
    /// fixture is `edition = "2024"` because `unsafe(...)` in attributes is
    /// only valid syntax from that edition on.
    #[test]
    fn an_item_only_used_by_an_unsafe_wrapped_export_is_not_flagged() {
        let dir = TempDir::new("dead-code-unsafe-attr-entry");
        let workspace = load_single_crate_workspace_with_edition(
            &dir,
            "2024",
            r#"pub fn used_by_no_mangle_export() -> i32 {
    1
}

pub fn used_by_export_name_export() -> i32 {
    2
}

pub fn truly_dead() -> i32 {
    3
}

#[unsafe(no_mangle)]
pub extern "C" fn exported_a() -> i32 {
    used_by_no_mangle_export()
}

#[unsafe(export_name = "exported_b_symbol")]
pub extern "C" fn exported_b() -> i32 {
    used_by_export_name_export()
}
"#,
        );

        let report = analyze_workspace(&workspace, false).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_no_mangle_export"),
            "reachable from a #[unsafe(no_mangle)] export — must not be flagged"
        );
        assert!(
            !names.contains("used_by_export_name_export"),
            "reachable from a #[unsafe(export_name = ...)] export — must not be flagged"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    /// A position the Deep Tier cannot semantically resolve — here literally
    /// on whitespace instead of on an identifier, the same probe
    /// `crate::deep`'s own three-state test uses — must be collected as an
    /// analyzer error and must never become a dead-code finding. Before the
    /// three-state query modeling (todo.md §15.1), `find_all_refs`'s `None`
    /// was collapsed into "zero references" and turned into exactly the
    /// finding this test forbids. Exercised through [`check_item`] directly
    /// because `analyze_workspace`'s positions always come from syn ident
    /// spans, which by construction sit on identifiers.
    #[test]
    fn an_unresolvable_position_is_a_collected_error_not_a_finding() {
        let dir = TempDir::new("dead-code-unresolvable-position");
        let lib_source = "pub fn item() -> i32 {\n    1\n}\n";
        let workspace = load_single_crate_workspace(&dir, lib_source);

        let ctx = DeepContext::load(&workspace.root).unwrap();
        let analysis = ctx.analysis();
        let krate = &workspace.crates[0];
        let file = krate
            .source_files
            .iter()
            .find(|file| file.path.ends_with("src/lib.rs"))
            .unwrap();
        let file_id = ctx.file_id(&file.path).unwrap();
        let crate_of_file = HashMap::from([(file_id, krate.name.as_str())]);
        let entry_keys = std::collections::HashSet::new();

        // Strictly inside the body's indentation whitespace — no symbol.
        let offset = lib_source.find("    1").unwrap() as u32 + 1;

        let mut report = WorkspaceDeadCode::default();
        let proc_macro_exposed = HashSet::new();
        check_item(
            &analysis,
            &crate_of_file,
            &entry_keys,
            &proc_macro_exposed,
            file,
            file_id,
            &krate.name,
            "not_a_symbol",
            offset,
            2,
            true,
            &mut report,
        );

        assert!(
            report.findings.is_empty(),
            "an unresolvable position must never become a dead-code finding: {:?}",
            report.findings
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| matches!(err, DeadCodeError::Deep(DeepError::UnresolvedSymbol(_)))),
            "the failed resolution must be collected as an analyzer error: {:?}",
            report.errors
        );
    }

    /// **Known gap, documented rather than hidden — not a regression to fix
    /// here.** todo.md §3.A/§7 requires that proc-macro blind spots produce
    /// `analysis_incomplete` rather than a finding ("im Zweifel nicht
    /// melden" — a false positive costs more trust than ten false negatives
    /// are worth; todo.md line 1696 lists "Proc-Macros und unbekannte
    /// Consumer" explicitly among the cases that must come back
    /// `analysis_incomplete`). [`crate::deep::DeepContext::load`] already
    /// documents *why* this can't hold today: the Deep Tier loads with
    /// `ProcMacroServerChoice::None`, so a proc-macro-derive's generated
    /// code is never expanded and never enters rust-analyzer's semantic
    /// model at all.
    ///
    /// This matters for `unused-pub-workspace` specifically: unlike the
    /// unresolvable-position case above (an item whose *own* position fails
    /// to resolve, caught by [`DeepError::UnresolvedSymbol`]), here `helper`
    /// itself resolves perfectly fine — it's the *caller*, hidden inside
    /// unexpanded macro output, that's invisible. `find_all_refs` therefore
    /// legitimately answers "zero references" (`Some(empty)`, not `None`),
    /// so the three-state error handling that protects the
    /// unresolvable-position case doesn't fire here — there's no error to
    /// collect. `helper` is only reachable via the derive's expansion (never
    /// called from anywhere the analysis can see), so it is genuinely
    /// flagged dead, contradicting the documented policy. Fixing this needs
    /// proc-macro-usage detection across the workspace, a real feature, not
    /// a small fix — pinning down today's actual behavior here so the gap
    /// is tracked rather than silently assumed away.
    ///
    /// **Partial mitigation:** [`proc_macro_exposed_crates`] can't eliminate
    /// this false positive (that needs real proc-macro expansion), but since
    /// `core` here has a direct proc-macro dependency, the finding for
    /// `helper` now carries `"limitations": ["proc_macro_expansion_disabled"]`
    /// in its evidence — the uncertainty is surfaced instead of hidden behind
    /// an unqualified `unused-pub-workspace` warning.
    #[test]
    fn a_pub_fn_reachable_only_through_an_unexpanded_proc_macro_derive_is_falsely_flagged_dead() {
        let dir = TempDir::new("dead-code-proc-macro-blind-spot");
        std::fs::create_dir_all(dir.join("macros/src")).unwrap();
        std::fs::write(
            dir.join("macros/Cargo.toml"),
            r#"[package]
name = "macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("macros/src/lib.rs"),
            r#"use proc_macro::TokenStream;

/// Would-be expansion (never actually run — the Deep Tier loads with no
/// proc-macro server): a call to `helper()` the analysis never sees.
#[proc_macro_derive(CallsHelper)]
pub fn calls_helper(_input: TokenStream) -> TokenStream {
    "fn __generated_caller() { crate::helper(); }".parse().unwrap()
}
"#,
        )
        .unwrap();
        write_crate(
            &dir,
            "core",
            &[("macros", "../macros")],
            r#"#[derive(macros::CallsHelper)]
pub struct Widget;

pub fn helper() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}
"#,
        );
        write_workspace_manifest(&dir, &["macros", "core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            report.errors.is_empty(),
            "no analyzer error is raised for this case today — `helper` resolves fine, only its \
             caller is invisible: {:?}",
            report.errors
        );
        assert!(
            names.contains("helper"),
            "documents today's actual (policy-violating) behavior: `helper` is only reachable \
             through the derive's unexpanded generated code, so it is flagged dead instead of \
             producing analysis_incomplete — see this test's doc comment"
        );
        assert!(
            names.contains("truly_dead"),
            "genuinely dead regardless — control for the fixture"
        );

        let helper_finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "helper")
            .expect("helper must be flagged, per the assertion above");
        let evidence = helper_finding
            .evidence
            .as_ref()
            .expect("evidence must be present");
        assert_eq!(
            evidence["limitations"],
            serde_json::json!(["proc_macro_expansion_disabled"]),
            "`core` has a direct proc-macro dependency (`macros`), so the finding must disclose \
             that proc-macro expansion was disabled instead of presenting `helper` as an \
             unqualified dead-code finding: {evidence:?}"
        );
    }

    /// A crate whose `unused-pub-workspace` finding has nothing to do with a
    /// proc-macro derive at all — the dead item and the proc-macro
    /// dependency are unrelated — still gets the disclosure, because
    /// [`proc_macro_exposed_crates`] is deliberately crate-wide, not
    /// item-level (see that function's doc comment): the analysis can't tell
    /// whether *this specific* finding is affected, only that the crate has
    /// a proc-macro dependency somewhere, so it discloses on every finding in
    /// that crate.
    #[test]
    fn a_pub_item_in_a_proc_macro_exposed_crate_discloses_the_limitation() {
        let dir = TempDir::new("dead-code-proc-macro-exposed-limitation");
        std::fs::create_dir_all(dir.join("macros/src")).unwrap();
        std::fs::write(
            dir.join("macros/Cargo.toml"),
            r#"[package]
name = "macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("macros/src/lib.rs"),
            r#"use proc_macro::TokenStream;

#[proc_macro]
pub fn noop(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
"#,
        )
        .unwrap();
        write_crate(
            &dir,
            "core",
            &[("macros", "../macros")],
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );
        write_workspace_manifest(&dir, &["macros", "core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "never_called")
            .expect("never_called must be flagged dead");
        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(
            evidence["limitations"],
            serde_json::json!(["proc_macro_expansion_disabled"]),
            "`core` directly depends on the proc-macro crate `macros`, so the finding must \
             disclose that proc-macro expansion was disabled, even though this particular dead \
             item is unrelated to the derive: {evidence:?}"
        );
    }

    /// The negative control for the disclosure above: a workspace with no
    /// proc-macro dependency anywhere must not carry the `limitations` field
    /// at all — an always-present empty array would blur the signal between
    /// "checked, no proc-macro exposure" and "checked, exposure found".
    #[test]
    fn a_pub_item_in_a_crate_without_any_proc_macro_dependency_has_no_limitations() {
        let dir = TempDir::new("dead-code-no-proc-macro-dependency");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "never_called")
            .expect("never_called must be flagged dead");
        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert!(
            evidence.get("limitations").is_none(),
            "no proc-macro dependency anywhere in this workspace — the finding must not carry a \
             `limitations` field: {evidence:?}"
        );
    }

    /// Regression test for a fixed false positive: [`crate::deep`]'s
    /// `CargoConfig` used to never activate any non-default Cargo feature
    /// (it only overrode `sysroot`/`set_test`, leaving `features` at
    /// `ra_ap_project_model::CargoConfig::default()`'s `Selected { features:
    /// vec![], no_default_features: false }` — default features only). A
    /// caller reachable only through a non-default, non-enabled feature was
    /// invisible the same way a proc-macro-only caller is: the position
    /// resolves fine (`Some`, not `None`), so no [`DeepError::UnresolvedSymbol`]
    /// fired — it just never showed up in `helper`'s incoming calls, and
    /// `check_item`'s [`crate::reachability::is_reachable_from_entry`] BFS
    /// (this rule's actual same-crate liveness test, not raw reference
    /// counting — see `check_item`'s doc comment) never found a path to it,
    /// even though a real `cargo build --features extra` (or
    /// `--all-features`, as CI commonly runs) would show it reachable. That
    /// violated todo.md §3.A/§7's "im Zweifel nicht melden" stance.
    ///
    /// The caller here has to itself be a recognized entry point (a
    /// `#[test]`, gated the same way `#[cfg(test)]` test modules normally
    /// are) rather than just any `pub fn` — [`walk_functions`] discovers
    /// `#[test]`-attributed functions syntactically regardless of `cfg`, but
    /// [`crate::reachability::is_reachable_from_entry`]'s BFS still needs the
    /// feature-gated function to *semantically resolve* to reach `helper`
    /// through it. A caller that is itself just an ordinary, uncalled `pub
    /// fn` wouldn't do: it would stay unreachable-from-any-entry-point
    /// regardless of the feature fix, which would make this test pass for
    /// the wrong reason.
    ///
    /// [`crate::deep::DeepContext::load`] now loads the workspace with
    /// `CargoFeatures::All` (`--all-features`-equivalent), so the `extra`
    /// feature is active, the test function resolves as a live entry point,
    /// and `helper` is reachable through it — no finding for `helper`
    /// anymore.
    #[test]
    fn a_pub_fn_reachable_only_through_a_non_default_cargo_feature_is_not_flagged_dead() {
        let dir = TempDir::new("dead-code-feature-gate-blind-spot");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"

[features]
extra = []
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn helper() -> i32 {
    1
}

#[cfg(feature = "extra")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_helper() {
        assert_eq!(helper(), 1);
    }
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            report.errors.is_empty(),
            "no analyzer error is raised for this case today: {:?}",
            report.errors
        );
        assert!(
            !names.contains("helper"),
            "`helper` is called from `calls_helper`, a #[test] fn only active with the \
             non-default `extra` feature — now that the Deep Tier loads with all features, the \
             test is a live entry point and `helper` must not be flagged dead"
        );
    }
}
