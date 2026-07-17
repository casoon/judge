//! Health score: a single 0–100 number plus letter grade summarizing
//! severity-weighted, LOC-density-normalized findings (see todo.md §4
//! "Health Score & Decision Surface").
//!
//! Deliberately narrow, matching §4's own guardrails:
//! 1. **Erklärbar** — every input (fail/warn counts, total LOC, deduction) is
//!    carried on [`HealthScore`] alongside the score, not hidden inside an
//!    opaque formula.
//! 2. **Nicht optimierbar** — weights are fixed per severity
//!    ([`FAIL_WEIGHT`]/[`WARN_WEIGHT`]), not configurable per rule, so
//!    there's no per-rule knob to game.
//! 3. **Kontextrelativ** — crate-type profiles are opt-in via `judge.toml`
//!    (`[[crate_profile]]`, see [`crate::boundaries::CrateProfile`]), not
//!    auto-guessed from crate contents.
//! 4. **Trend vor Absolutwert** — [`Trend`] recomputes the same formula over
//!    a saved baseline's stored findings, so the score is never shown
//!    without its delta.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::boundaries::CrateProfile;
use crate::finding::{Finding, Severity};
use crate::ingest::{CrateInfo, Workspace};

/// Fixed per-severity deduction weight (see module docs, point 2 — not
/// configurable per rule).
pub const FAIL_WEIGHT: f64 = 10.0;
pub const WARN_WEIGHT: f64 = 3.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    fn from_score(score: f64) -> Self {
        if score >= 90.0 {
            Self::A
        } else if score >= 80.0 {
            Self::B
        } else if score >= 70.0 {
            Self::C
        } else if score >= 60.0 {
            Self::D
        } else {
            Self::F
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

/// A computed health score: every number that went into it, so the result
/// stays explainable (see module docs, point 1).
#[derive(Debug, Clone, Serialize)]
pub struct HealthScore {
    pub score: f64,
    pub grade: Grade,
    pub total_loc: usize,
    pub fail_count: usize,
    pub warn_count: usize,
    /// The density-normalized deduction subtracted from 100 to get `score`.
    pub deduction: f64,
}

fn score_from(
    fail_count: usize,
    warn_count: usize,
    deduction: f64,
    total_loc: usize,
) -> HealthScore {
    let density_deduction = if total_loc == 0 {
        0.0
    } else {
        deduction / (total_loc as f64 / 1000.0)
    };
    let score = (100.0 - density_deduction).clamp(0.0, 100.0);

    HealthScore {
        score,
        grade: Grade::from_score(score),
        total_loc,
        fail_count,
        warn_count,
        deduction: density_deduction,
    }
}

/// Counts authored lines of code across `workspace` (generated files are
/// excluded, same policy as `complexity`/`duplication`, see todo.md §3.A) —
/// the denominator for density-normalized deductions.
pub fn total_authored_loc(workspace: &Workspace) -> usize {
    workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter())
        .filter(|file| file.kind.is_locally_reportable())
        .filter_map(|file| std::fs::read_to_string(&file.path).ok())
        .map(|content| content.lines().count())
        .sum()
}

/// Like [`total_authored_loc`], but scoped to `files` (repository-root
/// relative paths — see [`crate::git::changed_files_since`]) — the LOC
/// denominator for a ratio gate judged against only what changed (see
/// `audit --since`, todo.md §6), not the whole workspace total.
pub fn authored_loc_in(workspace: &Workspace, files: &HashSet<PathBuf>) -> usize {
    workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter())
        .filter(|file| file.kind.is_locally_reportable())
        .filter(|file| {
            file.path
                .strip_prefix(&workspace.root)
                .is_ok_and(|relative| files.contains(relative))
        })
        .filter_map(|file| std::fs::read_to_string(&file.path).ok())
        .map(|content| content.lines().count())
        .sum()
}

/// Finds the workspace crate that owns `file` — the one whose `root` is the
/// longest matching prefix, to handle nested crates correctly. Returns
/// `None` for findings that aren't inside any single crate's directory
/// (e.g. a boundary violation, whose location is the workspace root
/// `Cargo.toml` in a multi-crate workspace) — those get the default `1.0`
/// multiplier.
fn crate_for_file<'a>(workspace: &'a Workspace, file: &Path) -> Option<&'a CrateInfo> {
    workspace
        .crates
        .iter()
        .filter(|krate| file.starts_with(&krate.root))
        .max_by_key(|krate| krate.root.as_os_str().len())
}

/// Computes a [`HealthScore`] from `findings` (only `Fail`/`Warn` severities
/// count — `Info` findings are descriptive, not scored, matching
/// `baseline::Delta::verdict`'s same carve-out) and `total_loc`, scaling each
/// finding's deduction by its crate's `deduction_multiplier` from
/// `crate_profiles`, if configured (default `1.0`).
pub fn compute(
    findings: &[Finding],
    total_loc: usize,
    workspace: &Workspace,
    crate_profiles: &[CrateProfile],
) -> HealthScore {
    let mut fail_count = 0;
    let mut warn_count = 0;
    let mut deduction = 0.0;

    for finding in findings {
        let weight = match finding.severity {
            Severity::Fail => {
                fail_count += 1;
                FAIL_WEIGHT
            }
            Severity::Warn => {
                warn_count += 1;
                WARN_WEIGHT
            }
            Severity::Info => continue,
        };

        let multiplier = crate_for_file(workspace, &finding.location.file)
            .and_then(|krate| {
                crate_profiles
                    .iter()
                    .find(|profile| profile.crates.iter().any(|name| name == &krate.name))
            })
            .map_or(1.0, |profile| profile.deduction_multiplier);

        deduction += weight * multiplier;
    }

    score_from(fail_count, warn_count, deduction, total_loc)
}

/// Computes the score a saved [`crate::baseline::Baseline`] represents, using
/// its stored `total_loc` and each finding's stored `severity` — the same
/// formula as [`compute`]. Crate profiles aren't applied retroactively: a
/// baseline only stores each finding's path at save time, not enough to
/// re-resolve it against the *current* workspace layout.
pub fn baseline_score(baseline: &crate::baseline::Baseline) -> HealthScore {
    let mut fail_count = 0;
    let mut warn_count = 0;
    let mut deduction = 0.0;

    for finding in &baseline.findings {
        match finding.severity {
            Severity::Fail => {
                fail_count += 1;
                deduction += FAIL_WEIGHT;
            }
            Severity::Warn => {
                warn_count += 1;
                deduction += WARN_WEIGHT;
            }
            Severity::Info => {}
        }
    }

    score_from(fail_count, warn_count, deduction, baseline.total_loc)
}

/// The score trend against a baseline (see module docs, point 4 — the score
/// is never shown without this).
#[derive(Debug, Clone, Serialize)]
pub struct Trend {
    pub current: HealthScore,
    pub baseline_score: f64,
    pub baseline_grade: Grade,
}

impl Trend {
    pub fn delta(&self) -> f64 {
        self.current.score - self.baseline_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Origin};
    use crate::ingest::{CrateInfo, SourceFile, SourceKind};
    use std::path::PathBuf;

    fn finding(severity: Severity, file: &str) -> Finding {
        Finding {
            id: "id".to_string(),
            rule: "rule".to_string(),
            severity,
            location: Location {
                file: PathBuf::from(file),
                line: 1,
                item_path: "item".to_string(),
            },
            confidence: 1.0,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }

    fn workspace_with_crate(root: &str, name: &str) -> Workspace {
        Workspace {
            root: PathBuf::from(root),
            crates: vec![CrateInfo {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                manifest_path: PathBuf::from(root).join("Cargo.toml"),
                root: PathBuf::from(root),
                source_files: vec![SourceFile {
                    path: PathBuf::from(root).join("src/lib.rs"),
                    kind: SourceKind::Authored,
                }],
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        }
    }

    #[test]
    fn no_findings_scores_perfectly() {
        let workspace = workspace_with_crate("/repo", "core");
        let score = compute(&[], 1000, &workspace, &[]);

        assert_eq!(score.score, 100.0);
        assert_eq!(score.grade, Grade::A);
        assert_eq!(score.fail_count, 0);
        assert_eq!(score.warn_count, 0);
    }

    #[test]
    fn info_findings_do_not_affect_the_score() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Info, "/repo/src/lib.rs")];
        let score = compute(&findings, 1000, &workspace, &[]);

        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn fail_and_warn_findings_are_weighted_and_density_normalized() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![
            finding(Severity::Fail, "/repo/src/lib.rs"),
            finding(Severity::Warn, "/repo/src/lib.rs"),
        ];
        // total_loc = 1000 -> density factor 1.0, deduction = 10 + 3 = 13
        let score = compute(&findings, 1000, &workspace, &[]);

        assert_eq!(score.fail_count, 1);
        assert_eq!(score.warn_count, 1);
        assert_eq!(score.deduction, 13.0);
        assert_eq!(score.score, 87.0);
        assert_eq!(score.grade, Grade::B);
    }

    #[test]
    fn same_findings_score_worse_on_a_smaller_codebase() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Fail, "/repo/src/lib.rs")];

        let large = compute(&findings, 10_000, &workspace, &[]);
        let small = compute(&findings, 100, &workspace, &[]);

        assert!(small.score < large.score);
    }

    #[test]
    fn zero_loc_does_not_panic_and_scores_perfectly() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Fail, "/repo/src/lib.rs")];
        let score = compute(&findings, 0, &workspace, &[]);

        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn authored_loc_in_counts_only_the_given_files() {
        let dir = crate::test_util::TempDir::new("health-score-authored-loc-in");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn a() {}\nfn a2() {}\n").unwrap();
        std::fs::write(dir.join("src/b.rs"), "fn b() {}\n").unwrap();

        let workspace = Workspace {
            root: dir.to_path_buf(),
            crates: vec![CrateInfo {
                name: "fixture".to_string(),
                version: "0.1.0".to_string(),
                manifest_path: dir.join("Cargo.toml"),
                root: dir.to_path_buf(),
                source_files: vec![
                    SourceFile {
                        path: dir.join("src/a.rs"),
                        kind: SourceKind::Authored,
                    },
                    SourceFile {
                        path: dir.join("src/b.rs"),
                        kind: SourceKind::Authored,
                    },
                ],
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        };

        let touched = HashSet::from([PathBuf::from("src/a.rs")]);
        let loc = authored_loc_in(&workspace, &touched);

        assert_eq!(loc, 2);
    }

    #[test]
    fn crate_profile_multiplier_scales_that_crates_deductions() {
        let workspace = workspace_with_crate("/repo", "parser");
        let findings = vec![finding(Severity::Fail, "/repo/src/lib.rs")];
        let profiles = vec![CrateProfile {
            name: "lenient".to_string(),
            crates: vec!["parser".to_string()],
            deduction_multiplier: 0.5,
        }];

        let scaled = compute(&findings, 1000, &workspace, &profiles);
        let unscaled = compute(&findings, 1000, &workspace, &[]);

        assert_eq!(scaled.deduction, unscaled.deduction * 0.5);
    }

    #[test]
    fn baseline_score_uses_stored_severity_and_total_loc() {
        let findings = vec![
            finding(Severity::Fail, "src/lib.rs"),
            finding(Severity::Warn, "src/lib.rs"),
        ];
        let baseline = crate::baseline::Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
        );

        let score = baseline_score(&baseline);

        assert_eq!(score.fail_count, 1);
        assert_eq!(score.warn_count, 1);
        assert_eq!(score.score, 87.0);
    }

    #[test]
    fn trend_delta_is_current_minus_baseline() {
        let workspace = workspace_with_crate("/repo", "core");
        let current = compute(&[], 1000, &workspace, &[]);
        let trend = Trend {
            current,
            baseline_score: 90.0,
            baseline_grade: Grade::A,
        };

        assert_eq!(trend.delta(), 10.0);
    }
}
