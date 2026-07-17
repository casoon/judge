//! Workspace-wide dead-code detection via the Deep Tier (see todo.md §3.A
//! "Reachability & Dead Code", §14.2 P1). Requires the `deep` feature —
//! semantic reachability isn't available at the Fast Tier.
//!
//! Scope: `unused-pub-workspace` only, and only for free functions and
//! impl/trait methods — the items [`crate::functions::walk_functions`]
//! already enumerates for `complexity`/`duplication`. Structs, enums,
//! traits, consts, and statics aren't covered yet.
//!
//! **Simplification, documented rather than hidden:** every workspace crate
//! is treated as workspace-internal. todo.md §3.A distinguishes
//! `unused-pub-workspace` (a real finding) from `unused-pub-api` on a
//! *published* crate (info-only, semver-sensitive) — this module doesn't yet
//! check a crate's `publish` field to tell the two apart.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{Finding, Location, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::Workspace;

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
    /// Number of `pub` functions/methods actually queried (see todo.md §7 —
    /// evidence for how thorough the run was, not just its findings).
    pub checked: usize,
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
                report.checked += 1;

                let offset = site.ident_span.byte_range().start as u32;
                let position = ra_ap_ide::FilePosition {
                    file_id,
                    offset: offset.into(),
                };

                match crate::deep::referencing_files(&analysis, position, include_tests) {
                    Ok(referencing) => {
                        let used_externally = referencing.iter().any(|referencing_file| {
                            crate_of_file
                                .get(referencing_file)
                                .is_some_and(|owner| *owner != krate.name)
                        });
                        if !used_externally {
                            let line = site.ident_span.start().line;
                            report.findings.push(Finding {
                                id: format!(
                                    "{UNUSED_PUB_WORKSPACE_RULE}:{}:{}",
                                    file.path.display(),
                                    site.qualified_name
                                ),
                                rule: UNUSED_PUB_WORKSPACE_RULE.to_string(),
                                severity: Severity::Warn,
                                location: Location {
                                    file: file.path.clone(),
                                    line,
                                    item_path: site.qualified_name.clone(),
                                },
                                confidence: 1.0,
                                origin: Origin::Code,
                                caused_by: Vec::new(),
                                causes: Vec::new(),
                            });
                        }
                    }
                    Err(err) => report.errors.push(DeadCodeError::Deep(err)),
                }
            });
        }
    }

    Ok(report)
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
}
