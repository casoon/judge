//! Compact, deterministic workspace facts for planning refactoring work.
//!
//! This module deliberately ranks files only by measured aggregate
//! cyclomatic complexity. It does not claim that a complex file must be
//! changed, nor does it prescribe a refactoring; it gives callers a stable
//! first place to investigate with the underlying facts attached.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::rules::complexity;
use crate::ingest::{CrateInfo, EntryPointKind, Workspace};

/// Schema version for [`RefactorMap`]'s independent JSON contract.
pub const SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Serialize)]
pub struct RefactorMap {
    pub schema_version: u32,
    /// Whether `complexity_rank` includes the separate test metrics.
    pub includes_tests: bool,
    pub crates: Vec<CrateSummary>,
    pub files: Vec<FileSummary>,
    /// Highest-volume production clone families. These are repeated-token
    /// facts to inspect, not automatic extraction instructions.
    pub duplication: crate::rules::duplication::RefactoringSummary,
    pub analysis_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CrateSummary {
    pub name: String,
    pub source_files: usize,
    pub authored_files: usize,
    pub production: ComplexitySummary,
    pub tests: ComplexitySummary,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ComplexitySummary {
    pub functions: usize,
    pub total_cyclomatic: u32,
    pub max_cyclomatic: u32,
}

impl ComplexitySummary {
    fn add_function(&mut self, cyclomatic: u32) {
        self.functions += 1;
        self.total_cyclomatic += cyclomatic;
        self.max_cyclomatic = self.max_cyclomatic.max(cyclomatic);
    }

    fn combined(self, other: Self) -> Self {
        Self {
            functions: self.functions + other.functions,
            total_cyclomatic: self.total_cyclomatic + other.total_cyclomatic,
            max_cyclomatic: self.max_cyclomatic.max(other.max_cyclomatic),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FileSummary {
    pub crate_name: String,
    pub file: PathBuf,
    pub source_kind: &'static str,
    /// Functions compiled in the regular production build.
    pub production: ComplexitySummary,
    /// Functions in test-only contexts, including helpers inside inline
    /// `#[cfg(test)]` modules and integration-test targets.
    pub tests: ComplexitySummary,
    /// One-based position among authored files with functions in the selected
    /// scope, ordered by total cyclomatic complexity descending. Generated
    /// files are never ranked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity_rank: Option<usize>,
}

impl FileSummary {
    /// The measured complexity selected for this map's ranking mode.
    pub fn complexity_in_scope(&self, include_tests: bool) -> ComplexitySummary {
        if include_tests {
            self.production.combined(self.tests)
        } else {
            self.production
        }
    }
}

#[derive(Debug, Default)]
struct FileMetrics {
    production: ComplexitySummary,
    tests: ComplexitySummary,
}

/// Builds a compact refactoring map from Fast-Tier workspace facts.
///
/// Test-only code is reported separately. It affects the ranking only when
/// `include_tests` is set, so the default attention list stays focused on
/// production code while still exposing the omitted evidence in JSON.
pub fn analyze(workspace: &Workspace, include_tests: bool) -> RefactorMap {
    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity = complexity::analyze_workspace(source_files, false);
    let duplication_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let duplication = crate::rules::duplication::analyze_workspace_with_options(
        duplication_source_files,
        crate::rules::duplication::DupeMode::Mild,
        crate::rules::duplication::DEFAULT_MIN_TOKENS,
        false,
        include_tests,
    );
    let duplication_summary = duplication.refactoring_summary(&workspace.root, 5);
    let mut analysis_errors: Vec<String> =
        complexity.errors.iter().map(ToString::to_string).collect();
    analysis_errors.extend(duplication.errors.iter().map(ToString::to_string));
    let test_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| {
            krate
                .source_files
                .iter()
                .filter(|source_file| is_test_source_file(krate, &source_file.path))
                .map(|source_file| source_file.path.clone())
        })
        .collect::<HashSet<_>>();
    let mut metrics = HashMap::<PathBuf, FileMetrics>::new();
    for function in complexity.functions {
        let entry = metrics.entry(function.file.clone()).or_default();
        if function.is_test_context || test_source_files.contains(&function.file) {
            entry.tests.add_function(function.cyclomatic);
        } else {
            entry.production.add_function(function.cyclomatic);
        }
    }

    let mut files = Vec::new();
    let mut crates = Vec::new();
    for krate in &workspace.crates {
        let mut production = ComplexitySummary::default();
        let mut tests = ComplexitySummary::default();
        let mut authored_files = 0;
        for source_file in &krate.source_files {
            let metrics = metrics.remove(&source_file.path).unwrap_or_default();
            if source_file.kind.is_locally_reportable() {
                authored_files += 1;
            }
            production = production.combined(metrics.production);
            tests = tests.combined(metrics.tests);
            files.push(FileSummary {
                crate_name: krate.name.clone(),
                file: relative_path(&workspace.root, &source_file.path),
                source_kind: source_file.kind.label(),
                production: metrics.production,
                tests: metrics.tests,
                complexity_rank: None,
            });
        }
        crates.push(CrateSummary {
            name: krate.name.clone(),
            source_files: krate.source_files.len(),
            authored_files,
            production,
            tests,
        });
    }

    files.sort_by(|left, right| {
        right
            .complexity_in_scope(include_tests)
            .total_cyclomatic
            .cmp(&left.complexity_in_scope(include_tests).total_cyclomatic)
            .then_with(|| left.file.cmp(&right.file))
    });
    for (index, file) in files
        .iter_mut()
        .filter(|file| {
            file.source_kind == "authored" && file.complexity_in_scope(include_tests).functions > 0
        })
        .enumerate()
    {
        file.complexity_rank = Some(index + 1);
    }
    crates.sort_by(|left, right| left.name.cmp(&right.name));

    RefactorMap {
        schema_version: SCHEMA_VERSION,
        includes_tests: include_tests,
        crates,
        files,
        duplication: duplication_summary,
        analysis_errors,
    }
}

fn is_test_source_file(krate: &CrateInfo, path: &Path) -> bool {
    krate.entry_points.iter().any(|entry| {
        entry.path == path && matches!(entry.kind, EntryPointKind::Test | EntryPointKind::Bench)
    }) || matches!(
        path.strip_prefix(&krate.root)
            .ok()
            .and_then(|relative| relative.components().next()),
        Some(std::path::Component::Normal(name)) if name == "tests" || name == "benches"
    )
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{CrateInfo, SourceFile, SourceKind};

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
                        path: root.join("src/high.rs"),
                        kind: SourceKind::Authored,
                    },
                    SourceFile {
                        path: root.join("src/low.rs"),
                        kind: SourceKind::Authored,
                    },
                    SourceFile {
                        path: root.join("src/generated.rs"),
                        kind: SourceKind::Generated,
                    },
                ],
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        }
    }

    #[test]
    fn separates_test_context_from_production_ranking() {
        let root = crate::test_util::TempDir::new("refactor-map");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/high.rs"),
            r#"
fn production(x: bool, y: bool) { if x { if y {} } }

#[cfg(test)]
mod tests {
    fn expensive_helper(x: bool, y: bool, z: bool) {
        if x { if y { if z {} } }
    }
}
"#,
        )
        .unwrap();
        std::fs::write(root.join("src/low.rs"), "fn low() {}").unwrap();
        std::fs::write(root.join("src/generated.rs"), "fn generated() {}").unwrap();

        let production_map = analyze(&workspace(&root), false);

        assert!(production_map.analysis_errors.is_empty());
        assert!(!production_map.includes_tests);
        assert_eq!(production_map.duplication.clone_families, 0);
        assert_eq!(production_map.crates[0].production.functions, 2);
        assert_eq!(production_map.crates[0].tests.functions, 1);
        assert_eq!(production_map.files[0].file, PathBuf::from("src/high.rs"));
        assert_eq!(production_map.files[0].complexity_rank, Some(1));
        assert_eq!(production_map.files[0].production.total_cyclomatic, 3);
        assert_eq!(production_map.files[0].tests.total_cyclomatic, 4);
        let generated = production_map
            .files
            .iter()
            .find(|file| file.file == Path::new("src/generated.rs"))
            .unwrap();
        assert_eq!(generated.complexity_rank, None);
        assert_eq!(generated.production.functions, 0);

        let test_aware_map = analyze(&workspace(&root), true);
        assert!(test_aware_map.includes_tests);
        assert_eq!(test_aware_map.files[0].complexity_rank, Some(1));
        assert_eq!(
            test_aware_map.files[0]
                .complexity_in_scope(true)
                .total_cyclomatic,
            7
        );
    }

    #[test]
    fn includes_compact_production_duplication_facts() {
        let root = crate::test_util::TempDir::new("refactor-map-duplication");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/high.rs"),
            r#"
fn first() {
    let mut total = 0;
    for value in 0..10 { total += value; }
    if total > 0 { total -= 1; }
    let _ = total;
}

fn second() {
    let mut total = 0;
    for value in 0..10 { total += value; }
    if total > 0 { total -= 1; }
    let _ = total;
}
"#,
        )
        .unwrap();
        std::fs::write(root.join("src/low.rs"), "fn low() {}\n").unwrap();
        std::fs::write(root.join("src/generated.rs"), "fn generated() {}\n").unwrap();

        let map = analyze(&workspace(&root), false);

        assert_eq!(map.schema_version, SCHEMA_VERSION);
        assert_eq!(map.duplication.schema_version, 1);
        assert_eq!(map.duplication.clone_families, 1);
        assert_eq!(map.duplication.clone_members, 2);
        assert_eq!(
            map.duplication.top_families[0].files,
            [PathBuf::from("src/high.rs")]
        );
    }
}
