//! Workspace-wide dead-code detection via the Deep Tier (see todo.md §3.A
//! "Reachability & Dead Code", §14.2 P1). Requires the `deep` feature —
//! semantic reachability isn't available at the Fast Tier.
//!
//! Scope: `unused-pub-workspace` only, for free functions, impl/trait
//! methods ([`crate::functions::walk_functions`]'s items), and top-level
//! structs/enums/traits/consts ([`walk_type_items`], below). Associated
//! consts/types inside impls and statics aren't covered yet.
//!
//! **Simplification, documented rather than hidden:** every workspace crate
//! is treated as workspace-internal. todo.md §3.A distinguishes
//! `unused-pub-workspace` (a real finding) from `unused-pub-api` on a
//! *published* crate (info-only, semver-sensitive) — this module doesn't yet
//! check a crate's `publish` field to tell the two apart.

use std::collections::HashMap;
use std::path::PathBuf;

use proc_macro2::Span;
use syn::visit::{self, Visit};

use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{Finding, Location, Origin, Severity};
use crate::functions::walk_functions;
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
}

impl std::fmt::Display for DeadCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
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

/// A `pub` struct/enum/trait/const declaration discovered while walking a
/// file — the type-level counterpart to
/// [`crate::functions::walk_functions`]'s function-like items. Anonymous
/// consts (`const _: () = ...`), associated consts/types inside impls, and
/// statics aren't covered.
struct TypeItemSite<'ast> {
    qualified_name: String,
    ident_span: Span,
    vis: &'ast syn::Visibility,
}

/// Visits every top-level `struct`, `enum`, `trait`, and `const` in `file`,
/// tracking the enclosing `mod`/`trait` path the same way
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

        fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_const(self, node);
        }
    }

    let mut walker = Walker {
        path: Vec::new(),
        on_item,
    };
    walker.visit_file(file);
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
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    qualified_name: &str,
    ident_span: Span,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) {
    report.checked += 1;
    let offset = ident_span.byte_range().start as u32;
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

    match crate::reachability::is_reachable_from_entry(analysis, entry_keys, position, include_tests) {
        Ok(true) => {}
        Ok(false) => {
            let line = ident_span.start().line;
            report.findings.push(Finding {
                id: format!(
                    "{UNUSED_PUB_WORKSPACE_RULE}:{}:{qualified_name}",
                    file.path.display()
                ),
                rule: UNUSED_PUB_WORKSPACE_RULE.to_string(),
                severity: Severity::Warn,
                location: Location {
                    file: file.path.clone(),
                    line,
                    item_path: qualified_name.to_string(),
                },
                confidence: 1.0,
                origin: Origin::Code,
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

    let entries =
        crate::reachability::entry_point_positions(workspace, &ctx).map_err(reachability_error)?;
    let entry_keys: std::collections::HashSet<(FileId, u32)> = entries
        .iter()
        .map(|(_, position)| crate::reachability::position_key(*position))
        .collect();

    let mut report = WorkspaceDeadCode::default();

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
                    report.errors.push(DeadCodeError::Io(file.path.clone(), err));
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
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    site.ident_span,
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
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    site.ident_span,
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
        assert_eq!(finding.confidence, 1.0);
        assert_eq!(finding.location.item_path, "never_called");
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
            assert!(names.contains(dead), "{dead} is never referenced and must be flagged");
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
}
