//! Deterministic impact context for one workspace source file.
//!
//! An impact map does not predict findings or refactorings. Instead it makes
//! the analysis contract explicit: which judge commands consume this file,
//! which default exclusions apply, and which Cargo targets share its crate.
//! That is useful before changing a file and stays truthful when the file is
//! temporarily unparsable during an edit.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::deps::{UsageDomain, classify_domain};
use crate::ingest::{SourceKind, Workspace};

/// Schema version for [`ImpactMap`]'s independent JSON contract.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct ImpactMap {
    pub schema_version: u32,
    pub target: PathBuf,
    pub crate_name: String,
    pub source_kind: &'static str,
    /// Path-based build domain. `test` also covers Cargo examples and benches;
    /// it is a Cargo-target convention, not a reachability claim.
    pub source_domain: &'static str,
    /// Every target Cargo declares for the containing crate. A listed target
    /// shares the crate, but this does not prove that it reaches `target`.
    pub crate_targets: Vec<TargetSummary>,
    /// Commands whose implementation reads the target file as direct input.
    /// This is deliberately not a prediction of which individual findings or
    /// rules will fire after an edit.
    pub direct_analysis: Vec<AnalysisEffect>,
}

#[derive(Debug, Serialize)]
pub struct TargetSummary {
    pub kind: &'static str,
    pub name: String,
    pub source: PathBuf,
    /// `true` only when this file is the target's Cargo-declared root.
    pub is_target_root: bool,
}

#[derive(Debug, Serialize)]
pub struct AnalysisEffect {
    pub command: &'static str,
    pub input: &'static str,
    /// Whether the command reads this source kind with its default flags.
    pub included_by_default: bool,
    /// Explicit flag required when the target is excluded by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_opt_in: Option<&'static str>,
}

#[derive(Debug)]
pub enum ImpactError {
    UnknownSource(PathBuf),
}

impl std::fmt::Display for ImpactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSource(path) => write!(
                f,
                "{} is not a discovered Rust source file in this workspace",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ImpactError {}

/// Builds impact context for `target`, which may be workspace-relative or
/// absolute. The result is pure metadata: no source parsing, git access, or
/// network call is needed.
pub fn analyze(workspace: &Workspace, target: &Path) -> Result<ImpactMap, ImpactError> {
    let absolute_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        workspace.root.join(target)
    };
    let Some((krate, source_file)) = workspace.crates.iter().find_map(|krate| {
        krate
            .source_files
            .iter()
            .find(|source_file| source_file.path == absolute_target)
            .map(|source_file| (krate, source_file))
    }) else {
        return Err(ImpactError::UnknownSource(target.to_path_buf()));
    };

    let relative_target = relative_path(&workspace.root, &source_file.path);
    let relative_to_crate = source_file
        .path
        .strip_prefix(&krate.root)
        .unwrap_or(source_file.path.as_path());
    let source_domain = usage_domain_label(classify_domain(relative_to_crate));
    let crate_targets = krate
        .entry_points
        .iter()
        .map(|entry| TargetSummary {
            kind: entry.kind.label(),
            name: entry.name.clone(),
            source: relative_path(&workspace.root, &entry.path),
            is_target_root: entry.path == source_file.path,
        })
        .collect();

    Ok(ImpactMap {
        schema_version: SCHEMA_VERSION,
        target: relative_target,
        crate_name: krate.name.clone(),
        source_kind: source_file.kind.label(),
        source_domain,
        crate_targets,
        direct_analysis: direct_analysis(source_file.kind),
    })
}

fn direct_analysis(source_kind: SourceKind) -> Vec<AnalysisEffect> {
    let included_by_default = source_kind.is_locally_reportable();
    let required_opt_in = (!included_by_default).then_some("--include-generated");
    vec![
        AnalysisEffect {
            command: "cargo judge",
            input: "combined Fast-Tier findings",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge health",
            input: "complexity, slop, structural, and security checks",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge dupes",
            input: "workspace-wide token duplication analysis",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge map",
            input: "per-file complexity facts",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge api-surface",
            input: "public API syntax checks",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge module-graph",
            input: "module-tree and unlinked-file checks",
            included_by_default,
            required_opt_in,
        },
        AnalysisEffect {
            command: "cargo judge deps",
            input: "dependency identifier usage",
            included_by_default: true,
            required_opt_in: None,
        },
    ]
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn usage_domain_label(domain: UsageDomain) -> &'static str {
    match domain {
        UsageDomain::Normal => "production",
        UsageDomain::Dev => "test",
        UsageDomain::Build => "build",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{CrateInfo, EntryPoint, EntryPointKind, SourceFile};

    fn workspace(root: &Path) -> Workspace {
        Workspace {
            root: root.to_path_buf(),
            crates: vec![CrateInfo {
                name: "fixture".to_string(),
                version: "0.1.0".to_string(),
                manifest_path: root.join("Cargo.toml"),
                root: root.to_path_buf(),
                source_files: vec![
                    SourceFile {
                        path: root.join("src/lib.rs"),
                        kind: SourceKind::Authored,
                    },
                    SourceFile {
                        path: root.join("tests/integration.rs"),
                        kind: SourceKind::Authored,
                    },
                    SourceFile {
                        path: root.join("src/generated.rs"),
                        kind: SourceKind::Generated,
                    },
                ],
                entry_points: vec![
                    EntryPoint {
                        kind: EntryPointKind::Lib,
                        name: "fixture".to_string(),
                        path: root.join("src/lib.rs"),
                    },
                    EntryPoint {
                        kind: EntryPointKind::Test,
                        name: "integration".to_string(),
                        path: root.join("tests/integration.rs"),
                    },
                ],
                dependencies: Vec::new(),
            }],
        }
    }

    #[test]
    fn reports_target_scope_and_direct_analysis_for_an_authored_source_file() {
        let root = crate::test_util::TempDir::new("impact-map");
        let map = analyze(&workspace(&root), Path::new("src/lib.rs")).unwrap();

        assert_eq!(map.target, PathBuf::from("src/lib.rs"));
        assert_eq!(map.crate_name, "fixture");
        assert_eq!(map.source_kind, "authored");
        assert_eq!(map.source_domain, "production");
        assert!(map.crate_targets[0].is_target_root);
        assert!(
            map.direct_analysis
                .iter()
                .all(|effect| effect.included_by_default)
        );
    }

    #[test]
    fn reports_test_target_and_generated_opt_in_without_predicting_findings() {
        let root = crate::test_util::TempDir::new("impact-generated");
        let workspace = workspace(&root);
        let test_map = analyze(&workspace, Path::new("tests/integration.rs")).unwrap();
        assert_eq!(test_map.source_domain, "test");
        assert!(test_map.crate_targets[1].is_target_root);

        let generated_map = analyze(&workspace, Path::new("src/generated.rs")).unwrap();
        let map_effect = generated_map
            .direct_analysis
            .iter()
            .find(|effect| effect.command == "cargo judge map")
            .unwrap();
        assert!(!map_effect.included_by_default);
        assert_eq!(map_effect.required_opt_in, Some("--include-generated"));
    }
}
