//! Health score: a single 0–100 number plus letter grade summarizing
//! severity-weighted, LOC-density-normalized findings (see todo.md §4
//! "Health Score & Decision Surface").
//!
//! Only *gating* findings are scored (see
//! [`crate::finding::EvidenceClass::is_gating`]): heuristic findings are
//! advisory by default (todo.md §17.2, §17.5) and produce no deduction, so
//! the score speaks only about `derived_fact`/`bounded_semantic`/
//! `external_measurement` findings.
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
//! 4. **Trend vor Absolutwert** — [`trend`] recomputes the same formula over
//!    a saved baseline's stored findings, but only under the same formula
//!    and profile conditions ([`ScoreContext`]); otherwise the trend is
//!    explicitly [`Trend::NotComparable`] instead of a false delta.
//!
//! An incomplete basis never scores: unreadable source files are a
//! [`LocError`], a zero-LOC workspace is [`ScoreOutcome::Unavailable`], and
//! an out-of-range `deduction_multiplier` is rejected at deserialization
//! (see todo.md §15.1) — all three are errors, not perfect scores.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::boundaries::CrateProfile;
use crate::finding::{Finding, Severity};
use crate::ingest::{CrateInfo, Workspace};

/// Fixed per-severity deduction weight (see module docs, point 2 — not
/// configurable per rule).
pub const FAIL_WEIGHT: f64 = 10.0;
pub const WARN_WEIGHT: f64 = 3.0;

/// Version of the score formula itself (severity weights, density
/// normalization, grade cutoffs). Stored on saved baselines via
/// [`ScoreContext`] so a trend is only computed when both scores used the
/// same formula — bump this on any formula change.
///
/// v2: heuristic findings no longer deduct — the score covers only gating
/// findings (see module docs). Baselines scored under v1 are
/// [`Trend::NotComparable`], not a false delta.
pub const SCORE_FORMULA_VERSION: u32 = 2;

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

/// A crate profile's validated deduction multiplier (see
/// [`crate::boundaries::CrateProfile`] and module docs, point 3).
///
/// Valid range: finite and within `(0.0, 10.0]`. Zero or negative values
/// would silently erase findings from the score, `NaN`/infinite values would
/// poison every downstream sum, and anything above [`Self::MAX`] is beyond
/// any sensible strictness scaling — all of these are config errors
/// (rejected by [`TryFrom`] and therefore at deserialization), not scores.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct DeductionMultiplier(f64);

impl DeductionMultiplier {
    /// Upper bound of the valid range `(0.0, MAX]`.
    pub const MAX: f64 = 10.0;

    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for DeductionMultiplier {
    /// `1.0` — findings count unscaled (crates not named in any profile).
    fn default() -> Self {
        Self(1.0)
    }
}

impl TryFrom<f64> for DeductionMultiplier {
    type Error = String;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if value.is_finite() && value > 0.0 && value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(format!(
                "deduction_multiplier must be finite and within (0.0, {}], got {value}",
                Self::MAX
            ))
        }
    }
}

impl From<DeductionMultiplier> for f64 {
    fn from(multiplier: DeductionMultiplier) -> Self {
        multiplier.0
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

/// Why a health score could not be computed (see [`ScoreOutcome`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreReason {
    /// Zero authored LOC — the density normalization has no denominator, so
    /// any score (least of all a perfect 100/A) would be fabricated.
    NoAuthoredLoc,
}

impl std::fmt::Display for ScoreReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAuthoredLoc => {
                write!(
                    f,
                    "no authored lines of code were analyzed (nothing to score)"
                )
            }
        }
    }
}

/// A health score, or the explicit reason there isn't one — an incomplete
/// basis produces [`ScoreOutcome::Unavailable`], never a perfect default
/// (see todo.md §15.1). The CLI turns `Unavailable` into `exit 2`, matching
/// `IngestError`/`GitError`/`BaselineError`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreOutcome {
    Available(HealthScore),
    Unavailable(ScoreReason),
}

/// `total_loc` must be non-zero — [`compute`] and [`trend`] guard that
/// before calling (a zero denominator is [`ScoreOutcome::Unavailable`], not
/// a division).
fn score_from(
    fail_count: usize,
    warn_count: usize,
    deduction: f64,
    total_loc: usize,
) -> HealthScore {
    let density_deduction = deduction / (total_loc as f64 / 1000.0);
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

/// A source file that could not be read while counting the LOC denominator —
/// surfaced instead of silently under-counting, which would shrink the
/// denominator and distort the score (see todo.md §15.1). The CLI turns this
/// into `exit 2`, matching `IngestError`/`GitError`/`BaselineError`.
#[derive(Debug)]
pub struct LocError {
    pub path: PathBuf,
    pub source: std::io::Error,
}

impl std::fmt::Display for LocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for LocError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Counts authored lines of code across `workspace` (generated files are
/// excluded, same policy as `complexity`/`duplication`, see todo.md §3.A) —
/// the denominator for density-normalized deductions.
///
/// Unreadable files are silently skipped; score paths must use
/// [`total_authored_loc_checked`] instead, so a read failure can never
/// masquerade as a smaller codebase.
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

/// Like [`total_authored_loc`], but a read failure is a [`LocError`] instead
/// of a silently skipped file (see todo.md §15.1).
pub fn total_authored_loc_checked(workspace: &Workspace) -> Result<usize, LocError> {
    workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter())
        .filter(|file| file.kind.is_locally_reportable())
        .map(|file| {
            std::fs::read_to_string(&file.path)
                .map(|content| content.lines().count())
                .map_err(|err| LocError {
                    path: file.path.clone(),
                    source: err,
                })
        })
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

/// The deduction multiplier for a finding in `file`: the first profile in
/// `crate_profiles` naming the owning crate wins, and files outside any
/// profiled crate get the default `1.0`.
fn multiplier_for(
    workspace: &Workspace,
    file: &Path,
    crate_profiles: &[CrateProfile],
) -> DeductionMultiplier {
    crate_for_file(workspace, file)
        .and_then(|krate| {
            crate_profiles
                .iter()
                .find(|profile| profile.crates.iter().any(|name| name == &krate.name))
        })
        .map_or_else(DeductionMultiplier::default, |profile| {
            profile.deduction_multiplier
        })
}

/// Computes a [`HealthScore`] from `findings` (only *gating* `Fail`/`Warn`
/// findings count — `Info` findings are descriptive and heuristic findings
/// advisory, neither is scored, matching `baseline::Delta::verdict`'s same
/// carve-outs) and `total_loc`, scaling each
/// finding's deduction by its crate's `deduction_multiplier` from
/// `crate_profiles`, if configured (default `1.0`). A `total_loc` of zero is
/// [`ScoreOutcome::Unavailable`] — even with fail findings there is no basis
/// for a score, least of all a perfect one (see todo.md §15.1).
pub fn compute(
    findings: &[Finding],
    total_loc: usize,
    workspace: &Workspace,
    crate_profiles: &[CrateProfile],
) -> ScoreOutcome {
    if total_loc == 0 {
        return ScoreOutcome::Unavailable(ScoreReason::NoAuthoredLoc);
    }

    let mut fail_count = 0;
    let mut warn_count = 0;
    let mut deduction = 0.0;

    for finding in findings {
        if !finding.is_gating() {
            continue;
        }
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

        let multiplier = multiplier_for(workspace, &finding.location.file, crate_profiles);
        deduction += weight * multiplier.value();
    }

    ScoreOutcome::Available(score_from(fail_count, warn_count, deduction, total_loc))
}

/// The score-formula conditions a baseline's findings were saved under:
/// formula version plus the effective `judge.toml` crate-profile
/// multipliers. A trend is only computed when these match the current run —
/// otherwise the delta would compare scores produced by different formulas
/// (see todo.md §15.1 and [`trend`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreContext {
    /// [`SCORE_FORMULA_VERSION`] active at save time.
    pub formula_version: u32,
    /// Effective crate-name → multiplier mapping (first matching profile
    /// wins, mirroring [`compute`]). Crates without a profile — and explicit
    /// `1.0` entries, which don't change the score — are omitted, so
    /// semantically identical configs compare equal.
    pub profile_multipliers: BTreeMap<String, DeductionMultiplier>,
}

impl ScoreContext {
    pub fn from_profiles(crate_profiles: &[CrateProfile]) -> Self {
        let mut profile_multipliers = BTreeMap::new();
        for profile in crate_profiles {
            for name in &profile.crates {
                profile_multipliers
                    .entry(name.clone())
                    .or_insert(profile.deduction_multiplier);
            }
        }
        profile_multipliers.retain(|_, multiplier| multiplier.value() != 1.0);
        Self {
            formula_version: SCORE_FORMULA_VERSION,
            profile_multipliers,
        }
    }
}

/// Why a baseline score can't be directly compared with the current one
/// (see [`Trend::NotComparable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotComparableReason {
    /// The baseline was saved before judge recorded a [`ScoreContext`].
    MissingScoreContext,
    /// The baseline was scored with a different [`SCORE_FORMULA_VERSION`].
    FormulaVersionChanged,
    /// `judge.toml` crate profiles changed since the baseline was saved.
    ProfilesChanged,
    /// The baseline recorded no authored LOC, so its historical score is
    /// unavailable (see [`ScoreReason::NoAuthoredLoc`]).
    BaselineLocUnavailable,
}

impl NotComparableReason {
    /// Stable snake_case identifier for JSON output.
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingScoreContext => "missing_score_context",
            Self::FormulaVersionChanged => "formula_version_changed",
            Self::ProfilesChanged => "profiles_changed",
            Self::BaselineLocUnavailable => "baseline_loc_unavailable",
        }
    }
}

impl std::fmt::Display for NotComparableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MissingScoreContext => {
                "the baseline predates score-context tracking (re-save it with --save-baseline)"
            }
            Self::FormulaVersionChanged => {
                "the score formula changed since the baseline was saved (re-save it with --save-baseline)"
            }
            Self::ProfilesChanged => {
                "judge.toml crate profiles changed since the baseline was saved (re-save it with --save-baseline)"
            }
            Self::BaselineLocUnavailable => {
                "the baseline recorded no authored LOC, so its score is unavailable"
            }
        };
        f.write_str(text)
    }
}

/// The score trend against a baseline (see module docs, point 4 — the score
/// is never shown without this). Only [`Trend::Comparable`] carries a delta:
/// when the baseline was scored under different conditions the trend says so
/// explicitly instead of comparing scores from different formulas.
#[derive(Debug, Clone)]
pub enum Trend {
    Comparable {
        current: HealthScore,
        baseline_score: f64,
        baseline_grade: Grade,
    },
    NotComparable {
        current: HealthScore,
        reason: NotComparableReason,
    },
}

impl Trend {
    pub fn current(&self) -> &HealthScore {
        match self {
            Self::Comparable { current, .. } | Self::NotComparable { current, .. } => current,
        }
    }

    /// `None` when the baseline isn't directly comparable.
    pub fn delta(&self) -> Option<f64> {
        match self {
            Self::Comparable {
                current,
                baseline_score,
                ..
            } => Some(current.score - baseline_score),
            Self::NotComparable { .. } => None,
        }
    }
}

/// Computes the score trend of `current` against `baseline`, using the same
/// formula as [`compute`] — including crate profiles, which is only sound
/// because comparability requires the baseline's [`ScoreContext`] (formula
/// version and profile multipliers) to match the current run's exactly.
/// Unchanged findings under unchanged profiles therefore yield a delta of
/// zero; any mismatch is [`Trend::NotComparable`] (see todo.md §15.1).
pub fn trend(
    current: HealthScore,
    baseline: &Baseline,
    workspace: &Workspace,
    crate_profiles: &[CrateProfile],
) -> Trend {
    let Some(context) = &baseline.score_context else {
        return Trend::NotComparable {
            current,
            reason: NotComparableReason::MissingScoreContext,
        };
    };
    if context.formula_version != SCORE_FORMULA_VERSION {
        return Trend::NotComparable {
            current,
            reason: NotComparableReason::FormulaVersionChanged,
        };
    }
    if *context != ScoreContext::from_profiles(crate_profiles) {
        return Trend::NotComparable {
            current,
            reason: NotComparableReason::ProfilesChanged,
        };
    }
    if baseline.total_loc == 0 {
        return Trend::NotComparable {
            current,
            reason: NotComparableReason::BaselineLocUnavailable,
        };
    }

    let mut fail_count = 0;
    let mut warn_count = 0;
    let mut deduction = 0.0;

    for finding in &baseline.findings {
        // Same gating carve-out as `compute` — heuristic baseline findings
        // are advisory and never deducted (see module docs).
        if !finding.evidence_class.is_gating() {
            continue;
        }
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

        // Stored paths are workspace-relative (`join` is a no-op for older
        // baselines that stored absolute paths).
        let file = workspace.root.join(&finding.file);
        deduction += weight * multiplier_for(workspace, &file, crate_profiles).value();
    }

    let baseline_score = score_from(fail_count, warn_count, deduction, baseline.total_loc);
    Trend::Comparable {
        current,
        baseline_score: baseline_score.score,
        baseline_grade: baseline_score.grade,
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
            evidence_class: crate::finding::EvidenceClass::DerivedFact,
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

    fn multiplier(value: f64) -> DeductionMultiplier {
        DeductionMultiplier::try_from(value).unwrap()
    }

    fn available(outcome: ScoreOutcome) -> HealthScore {
        match outcome {
            ScoreOutcome::Available(score) => score,
            ScoreOutcome::Unavailable(reason) => panic!("score unavailable: {reason}"),
        }
    }

    #[test]
    fn no_findings_scores_perfectly() {
        let workspace = workspace_with_crate("/repo", "core");
        let score = available(compute(&[], 1000, &workspace, &[]));

        assert_eq!(score.score, 100.0);
        assert_eq!(score.grade, Grade::A);
        assert_eq!(score.fail_count, 0);
        assert_eq!(score.warn_count, 0);
    }

    #[test]
    fn info_findings_do_not_affect_the_score() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Info, "/repo/src/lib.rs")];
        let score = available(compute(&findings, 1000, &workspace, &[]));

        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn heuristic_findings_do_not_deduct_and_are_not_counted() {
        let workspace = workspace_with_crate("/repo", "core");
        let mut heuristic_fail = finding(Severity::Fail, "/repo/src/lib.rs");
        heuristic_fail.evidence_class = crate::finding::EvidenceClass::Heuristic;
        let mut heuristic_warn = finding(Severity::Warn, "/repo/src/lib.rs");
        heuristic_warn.evidence_class = crate::finding::EvidenceClass::Heuristic;

        let score = available(compute(
            &[heuristic_fail, heuristic_warn],
            1000,
            &workspace,
            &[],
        ));

        assert_eq!(score.score, 100.0);
        assert_eq!(score.grade, Grade::A);
        assert_eq!(score.fail_count, 0);
        assert_eq!(score.warn_count, 0);
        assert_eq!(score.deduction, 0.0);
    }

    #[test]
    fn fail_and_warn_findings_are_weighted_and_density_normalized() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![
            finding(Severity::Fail, "/repo/src/lib.rs"),
            finding(Severity::Warn, "/repo/src/lib.rs"),
        ];
        // total_loc = 1000 -> density factor 1.0, deduction = 10 + 3 = 13
        let score = available(compute(&findings, 1000, &workspace, &[]));

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

        let large = available(compute(&findings, 10_000, &workspace, &[]));
        let small = available(compute(&findings, 100, &workspace, &[]));

        assert!(small.score < large.score);
    }

    #[test]
    fn zero_loc_is_unavailable_not_a_perfect_score() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Fail, "/repo/src/lib.rs")];

        let outcome = compute(&findings, 0, &workspace, &[]);

        assert!(matches!(
            outcome,
            ScoreOutcome::Unavailable(ScoreReason::NoAuthoredLoc)
        ));
    }

    #[test]
    fn total_authored_loc_checked_counts_authored_lines() {
        let dir = crate::test_util::TempDir::new("health-score-loc-checked");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();

        let mut workspace = workspace_with_crate("/ignored", "fixture");
        workspace.root = dir.to_path_buf();
        workspace.crates[0].root = dir.to_path_buf();
        workspace.crates[0].source_files = vec![SourceFile {
            path: dir.join("src/lib.rs"),
            kind: SourceKind::Authored,
        }];

        assert_eq!(total_authored_loc_checked(&workspace).unwrap(), 2);
    }

    #[test]
    fn unreadable_source_file_is_a_loc_error_not_a_smaller_codebase() {
        let workspace = workspace_with_crate("/nonexistent-judge-fixture", "core");

        let err = total_authored_loc_checked(&workspace).unwrap_err();

        assert_eq!(
            err.path,
            PathBuf::from("/nonexistent-judge-fixture/src/lib.rs")
        );
    }

    #[test]
    fn deduction_multiplier_rejects_out_of_range_values() {
        assert!(DeductionMultiplier::try_from(-1.0).is_err());
        assert!(DeductionMultiplier::try_from(0.0).is_err());
        assert!(DeductionMultiplier::try_from(f64::NAN).is_err());
        assert!(DeductionMultiplier::try_from(f64::INFINITY).is_err());
        assert!(DeductionMultiplier::try_from(f64::NEG_INFINITY).is_err());
        assert!(DeductionMultiplier::try_from(10.1).is_err());

        assert_eq!(DeductionMultiplier::try_from(0.5).unwrap().value(), 0.5);
        assert_eq!(DeductionMultiplier::try_from(10.0).unwrap().value(), 10.0);
        assert_eq!(DeductionMultiplier::default().value(), 1.0);
    }

    #[test]
    fn invalid_multiplier_in_judge_toml_is_a_config_error_not_a_score() {
        for value in ["-1.0", "0.0", "nan", "inf", "100.0"] {
            let source = format!(
                "[[crate_profile]]\nname = \"lenient\"\ncrates = [\"parser\"]\ndeduction_multiplier = {value}\n"
            );
            let result = toml::from_str::<crate::boundaries::BoundaryConfig>(&source);
            assert!(result.is_err(), "multiplier {value} should be rejected");
        }
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
            deduction_multiplier: multiplier(0.5),
        }];

        let scaled = available(compute(&findings, 1000, &workspace, &profiles));
        let unscaled = available(compute(&findings, 1000, &workspace, &[]));

        assert_eq!(scaled.deduction, unscaled.deduction * 0.5);
    }

    #[test]
    fn trend_is_zero_for_unchanged_findings_and_profiles() {
        let workspace = workspace_with_crate("/repo", "parser");
        let profiles = vec![CrateProfile {
            name: "lenient".to_string(),
            crates: vec!["parser".to_string()],
            deduction_multiplier: multiplier(0.5),
        }];
        let findings = vec![
            finding(Severity::Fail, "/repo/src/lib.rs"),
            finding(Severity::Warn, "/repo/src/lib.rs"),
        ];
        let baseline = Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
            ScoreContext::from_profiles(&profiles),
        );

        let current = available(compute(&findings, 1000, &workspace, &profiles));
        let trend = trend(current, &baseline, &workspace, &profiles);

        assert_eq!(trend.delta(), Some(0.0));
        assert!(matches!(trend, Trend::Comparable { .. }));
    }

    #[test]
    fn profile_change_makes_the_trend_not_comparable() {
        let workspace = workspace_with_crate("/repo", "parser");
        let findings = vec![finding(Severity::Fail, "/repo/src/lib.rs")];
        let baseline = Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
            ScoreContext::from_profiles(&[]),
        );
        let profiles = vec![CrateProfile {
            name: "lenient".to_string(),
            crates: vec!["parser".to_string()],
            deduction_multiplier: multiplier(0.5),
        }];

        let current = available(compute(&findings, 1000, &workspace, &profiles));
        let trend = trend(current, &baseline, &workspace, &profiles);

        assert_eq!(trend.delta(), None);
        assert!(matches!(
            trend,
            Trend::NotComparable {
                reason: NotComparableReason::ProfilesChanged,
                ..
            }
        ));
    }

    #[test]
    fn trend_skips_heuristic_baseline_findings_like_compute_does() {
        // Baseline stored under the current formula, containing one gating
        // and one heuristic finding; the current run carries the same pair.
        // Both sides must skip the heuristic finding, so the delta is zero —
        // not a phantom improvement from the advisory carve-out.
        let workspace = workspace_with_crate("/repo", "core");
        let mut heuristic = finding(Severity::Warn, "/repo/src/lib.rs");
        heuristic.evidence_class = crate::finding::EvidenceClass::Heuristic;
        let findings = vec![finding(Severity::Warn, "/repo/src/lib.rs"), heuristic];
        let baseline = Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
            ScoreContext::from_profiles(&[]),
        );

        let current = available(compute(&findings, 1000, &workspace, &[]));
        assert_eq!(current.warn_count, 1);
        let trend = trend(current, &baseline, &workspace, &[]);

        assert_eq!(trend.delta(), Some(0.0));
    }

    #[test]
    fn formula_version_change_makes_the_trend_not_comparable() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Warn, "/repo/src/lib.rs")];
        let mut baseline = Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
            ScoreContext::from_profiles(&[]),
        );
        // Version 1: the formula before heuristic findings became
        // advisory-only.
        baseline.score_context.as_mut().unwrap().formula_version = 1;

        let current = available(compute(&findings, 1000, &workspace, &[]));
        let trend = trend(current, &baseline, &workspace, &[]);

        assert!(matches!(
            trend,
            Trend::NotComparable {
                reason: NotComparableReason::FormulaVersionChanged,
                ..
            }
        ));
    }

    #[test]
    fn baseline_without_score_context_is_not_comparable() {
        let workspace = workspace_with_crate("/repo", "core");
        let findings = vec![finding(Severity::Warn, "/repo/src/lib.rs")];
        let mut baseline = Baseline::new(
            &findings,
            "abc123".to_string(),
            std::collections::HashMap::new(),
            1000,
            ScoreContext::from_profiles(&[]),
        );
        baseline.score_context = None;

        let current = available(compute(&findings, 1000, &workspace, &[]));
        let trend = trend(current, &baseline, &workspace, &[]);

        assert!(matches!(
            trend,
            Trend::NotComparable {
                reason: NotComparableReason::MissingScoreContext,
                ..
            }
        ));
    }
}
