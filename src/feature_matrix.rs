//! `feature-gated-dead-code`: reachability under a user-configured, finite
//! Cargo feature matrix (see todo.md §A "Reachability & Dead Code", `judge.toml`
//! `[feature_matrix]`). Requires the `deep` feature — semantic reachability
//! isn't available at the Fast Tier.
//!
//! **Opt-in, and deliberately cautious.** [`crate::deep::DeepContext::load`]
//! (used by every other Deep-Tier reachability rule in
//! [`crate::dead_code`]/[`crate::reachability`]) always loads with
//! `CargoFeatures::All` — every feature active at once — which is the right
//! default for "is this reachable under *some* real build" but cannot answer
//! "is this reachable under one of *these specific* feature combinations", the
//! question a project shipping several supported feature configurations
//! actually needs answered (e.g. a library published with `default`, a
//! `minimal` build, and an `extended` build, each with a distinct real
//! audience). This module answers that instead: it re-loads the workspace
//! once per configured combination — a real, accepted cost, not a shortcut —
//! via [`crate::deep::DeepContext::load_with_features`] with
//! `CargoFeatures::Selected { features: combination.clone(),
//! no_default_features: true }`, so a combination's meaning is fully explicit
//! (a combination wanting Cargo's own default features must list `"default"`
//! itself, matching `cargo build --no-default-features --features default`).
//!
//! **Correctness depends entirely on the configured matrix being
//! representative.** A combination not listed in `judge.toml` is never
//! checked — an item reachable only under an unconfigured combination (e.g.
//! one a downstream consumer of this crate actually builds with, but the
//! matrix omits) is indistinguishable from genuinely dead code to this rule.
//! That is why [`FEATURE_GATED_DEAD_CODE_RULE`] is classified
//! [`crate::finding::EvidenceClass::Heuristic`] (never gating) rather than
//! the `bounded_semantic` classification `unreachable-from-entry`'s
//! single-load reachability check uses — see the registry entry in
//! `crate::rule_registry` for the full wording constraint.
//!
//! Candidate items are collected once, via [`crate::functions::walk_functions`]
//! and [`crate::dead_code::walk_type_items`] (the same Fast-Tier `syn` walkers
//! `crate::dead_code` itself uses) — independent of any single combination's
//! active `#[cfg]` state, and scoped to both `pub` and non-`pub` items alike:
//! unlike `unreachable-from-entry`'s pub/non-pub split (which exists to avoid
//! duplicating `unused-pub-workspace`'s cross-crate reference check), this
//! rule checks reachability only, a different axis visibility does not
//! affect.

use std::collections::HashSet;
use std::path::PathBuf;

use ra_ap_ide::FilePosition;

use crate::dead_code::{DeadCodeError, reachability_error, walk_type_items};
use crate::deep::{CargoFeatures, DeepContext, DeepError, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::Workspace;
use crate::reachability::{self, ReachabilityError};

/// A non-absolute claim: only that no reachability was found under any of the
/// *configured* combinations, in the examined view — never that the item is
/// dead under every possible real-world feature combination (todo.md §17.3,
/// §17.4; see the module docs' "Correctness depends..." section).
pub const FEATURE_GATED_DEAD_CODE_RULE: &str = "feature-gated-dead-code";
/// Bump when the feature-gated-dead-code rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const FEATURE_GATED_DEAD_CODE_RULE_REVISION: u32 = 1;

const FEATURE_GATED_DEAD_CODE_REASON: &str = "not reachable from any recognized entry point \
    under any of the configured [feature_matrix] combinations, in the examined reachability view";

#[derive(Debug, Default)]
pub struct FeatureMatrixReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<DeadCodeError>,
    /// Number of (candidate item, configured combination) reachability
    /// queries actually attempted — evidence for how thorough the run was,
    /// not just its findings (see todo.md §7), mirroring
    /// [`crate::dead_code::WorkspaceDeadCode::checked`]'s same intent.
    pub checked: usize,
}

/// One function-like or type-level item discovered by the Fast-Tier walkers,
/// independent of any single combination's `#[cfg]` state — see the module
/// docs.
struct Candidate {
    file_path: PathBuf,
    qualified_name: String,
    offset: u32,
    line: usize,
}

/// Collects every candidate item once, via the same [`walk_functions`]/
/// [`walk_type_items`] walkers `crate::dead_code::analyze_workspace` uses,
/// scoped to both `pub` and non-`pub` items alike (see module docs). A
/// per-file read/parse failure is a non-fatal, reported error — matching
/// `crate::dead_code::analyze_workspace`'s own "skip this file, keep going"
/// handling — not a hard stop for the whole run.
fn collect_candidates(workspace: &Workspace) -> (Vec<Candidate>, Vec<DeadCodeError>) {
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

            walk_functions(&ast, |site| {
                candidates.push(Candidate {
                    file_path: file.path.clone(),
                    qualified_name: site.qualified_name,
                    offset: site.ident_span.byte_range().start as u32,
                    line: site.ident_span.start().line,
                });
            });
            walk_type_items(&ast, |site| {
                candidates.push(Candidate {
                    file_path: file.path.clone(),
                    qualified_name: site.qualified_name,
                    offset: site.ident_span.byte_range().start as u32,
                    line: site.ident_span.start().line,
                });
            });
        }
    }

    (candidates, errors)
}

fn finding_for(candidate: &Candidate, combinations: &[Vec<String>]) -> Finding {
    let evidence = serde_json::json!({
        "tier": "deep",
        "file": candidate.file_path,
        "item_path": candidate.qualified_name,
        "combinations_checked": combinations,
        "line": candidate.line,
        "reason": FEATURE_GATED_DEAD_CODE_REASON,
    });
    Finding {
        id: format!(
            "{FEATURE_GATED_DEAD_CODE_RULE}:{}:{}",
            candidate.file_path.display(),
            candidate.qualified_name
        )
        .into(),
        rule: FEATURE_GATED_DEAD_CODE_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: candidate.file_path.clone(),
            line: OneBasedLine::new(candidate.line).expect("source line numbers are 1-based"),
            item_path: candidate.qualified_name.clone(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Checks every candidate item's reachability under every configured
/// `combinations` entry — see the module docs for the full algorithm and its
/// cost/precision trade-offs.
///
/// `combinations` empty (whether `[feature_matrix]` is absent from
/// `judge.toml` entirely, or present with an empty `combinations` list) skips
/// analysis outright: zero findings, zero errors, no `DeepContext::load` at
/// all — never to be read as "no feature-gated dead code found" (see
/// `crate::boundaries::FeatureMatrixConfig`).
pub fn analyze_workspace(
    workspace: &Workspace,
    combinations: &[Vec<String>],
    include_tests: bool,
) -> Result<FeatureMatrixReport, DeadCodeError> {
    let mut report = FeatureMatrixReport::default();
    if combinations.is_empty() {
        return Ok(report);
    }

    let (candidates, collect_errors) = collect_candidates(workspace);
    report.errors.extend(collect_errors);

    // Whether each candidate (by index) was found present-and-reachable
    // under at least one configured combination — flagged only if this stays
    // `false` across every combination (see module docs).
    let mut reachable_anywhere = vec![false; candidates.len()];

    for combination in combinations {
        let features = CargoFeatures::Selected {
            features: combination.clone(),
            no_default_features: true,
        };
        let ctx = match DeepContext::load_with_features(&workspace.root, features) {
            Ok(ctx) => ctx,
            Err(err) => {
                report.errors.push(DeadCodeError::Deep(err));
                continue;
            }
        };
        let analysis = ctx.analysis();

        let entries = match reachability::entry_point_positions(workspace, &ctx, include_tests) {
            Ok(entries) => entries,
            Err(err) => {
                report.errors.push(reachability_error(err));
                continue;
            }
        };
        let entry_keys: HashSet<(FileId, u32)> = entries
            .iter()
            .map(|(_, position)| reachability::position_key(*position))
            .collect();

        for (index, candidate) in candidates.iter().enumerate() {
            report.checked += 1;
            // Not indexed by this load's vfs at all — rust-analyzer's own
            // `#[cfg]` evaluation excluded this file under this combination.
            // Expected signal that the item isn't compiled in here, not an
            // error.
            let Some(file_id) = ctx.file_id(&candidate.file_path) else {
                continue;
            };
            let position = FilePosition {
                file_id,
                offset: candidate.offset.into(),
            };
            match reachability::is_reachable_from_entry(
                &analysis,
                &entry_keys,
                position,
                include_tests,
            ) {
                Ok(true) => reachable_anywhere[index] = true,
                Ok(false) => {}
                // The file resolved, but this specific position didn't — the
                // item itself is `#[cfg]`-inactive under this combination
                // (e.g. `#[cfg(feature = "x")] fn ...` with `x` not in this
                // combination). Same "not present here" signal as an
                // unresolved file id above, just caught one step later.
                Err(ReachabilityError::Deep(DeepError::UnresolvedSymbol(_))) => {}
                Err(err) => report.errors.push(reachability_error(err)),
            }
        }
    }

    for (index, candidate) in candidates.iter().enumerate() {
        if !reachable_anywhere[index] {
            report.findings.push(finding_for(candidate, combinations));
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
name = "feature-matrix-fixture"
version = "0.1.0"
edition = "2021"

[features]
default = []
x = []
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    /// No `[feature_matrix]` config at all (an empty `combinations` slice,
    /// the same shape `main.rs` passes when `judge.toml` doesn't declare the
    /// table) must skip analysis entirely: zero findings, zero errors, zero
    /// checked — not "clean".
    #[test]
    fn empty_combinations_skips_analysis_entirely() {
        let dir = TempDir::new("feature-matrix-no-config");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"#[cfg(feature = "x")]
pub fn only_under_x() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, &[], true).unwrap();
        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.checked, 0);
    }

    /// A function gated behind a feature that is in *none* of the configured
    /// combinations, and unreachable — must fire.
    #[test]
    fn item_gated_behind_an_unconfigured_feature_fires() {
        let dir = TempDir::new("feature-matrix-unconfigured-feature-fires");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"#[cfg(feature = "x")]
pub fn only_under_x() -> i32 {
    1
}
"#,
        );

        let combinations = vec![vec![], vec!["default".to_string()]];
        let report = analyze_workspace(&workspace, &combinations, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == FEATURE_GATED_DEAD_CODE_RULE
                    && f.location.item_path == "only_under_x")
                .count(),
            1,
            "expected exactly one feature-gated-dead-code finding for only_under_x: {:?}",
            report.findings
        );
    }

    /// A function gated behind a feature that *is* one of the configured
    /// combinations, and reachable from `main` under that combination — must
    /// not fire.
    #[test]
    fn item_reachable_under_a_configured_combination_does_not_fire() {
        let dir = TempDir::new("feature-matrix-configured-and-reachable");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "feature-matrix-fixture"
version = "0.1.0"
edition = "2021"

[features]
default = []
x = []

[[bin]]
name = "tool"
path = "src/bin/tool.rs"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"#[cfg(feature = "x")]
pub fn only_under_x() -> i32 {
    1
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            r#"#[cfg(feature = "x")]
fn main() {
    feature_matrix_fixture::only_under_x();
}

#[cfg(not(feature = "x"))]
fn main() {}
"#,
        )
        .unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let combinations = vec![vec!["x".to_string()]];
        let report = analyze_workspace(&workspace, &combinations, true).unwrap();

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.location.item_path != "only_under_x"),
            "only_under_x is reachable under the configured `x` combination and must not fire: \
             {:?}",
            report.findings
        );
    }

    /// An ungated (always-compiled) function, reachable under at least one
    /// combination, must not fire — proves the "at least one combination"
    /// logic, not "all combinations".
    #[test]
    fn ungated_reachable_item_does_not_fire() {
        let dir = TempDir::new("feature-matrix-ungated-reachable");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "feature-matrix-fixture"
version = "0.1.0"
edition = "2021"

[features]
default = []
x = []

[[bin]]
name = "tool"
path = "src/bin/tool.rs"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn always_here() -> i32 {\n    1\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            "fn main() {\n    feature_matrix_fixture::always_here();\n}\n",
        )
        .unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let combinations = vec![vec![], vec!["x".to_string()]];
        let report = analyze_workspace(&workspace, &combinations, true).unwrap();

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.location.item_path != "always_here"),
            "always_here is reachable under every combination and must not fire: {:?}",
            report.findings
        );
    }
}
