//! Baseline snapshots and diffs for [`crate::pattern::PatternCandidate`]s
//! (see todo.md §16 "Pattern-Kandidaten separat baselinen").
//!
//! Deliberately a separate, parallel mechanism from [`crate::baseline`], not
//! a reuse of its types: `PatternCandidate` structurally carries no
//! `Severity`/`EvidenceClass`/`Origin`/verdict (see `pattern.rs`'s module
//! docs — "nothing in this module is wired into ... a baseline verdict"), so
//! there is nothing here to gate a CI verdict on. This module only answers
//! "which pattern candidates are new since last time, and which disappeared"
//! — advisory information, never a pass/fail outcome.
//!
//! Unlike [`crate::baseline::Delta`], there is no `code_introduced` /
//! `rule_introduced` split here. That split exists for `Finding` baselines
//! because a rule-logic change silently reclassifying old code as a new
//! finding could otherwise fail a delta verdict for a change the diff never
//! touched (todo.md §5 "Regelversions-Schutz") — the stakes are a false CI
//! failure. Pattern candidates never gate anything, so a detector-logic
//! change relabeling a candidate as "new" has no CI-breaking consequence: at
//! worst it's a heuristic suggestion resurfacing. A flat new/resolved/
//! unchanged split is honest and sufficient here.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::pattern::{PatternCandidate, PatternCandidateId, RustPattern};

pub const SCHEMA_VERSION: u32 = 1;

/// The minimal record kept per candidate in a pattern baseline file — enough
/// to tell whether a current candidate was already known.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselinePatternCandidate {
    pub id: PatternCandidateId,
    pub pattern: RustPattern,
    pub krate: String,
}

/// A saved snapshot of pattern candidates, deliberately simpler than
/// [`crate::baseline::Baseline`]: no `rule_revisions`, `total_loc`, or
/// `score_context` — those exist for `Finding`'s gating/scoring concerns,
/// which don't apply to advisory pattern candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternBaseline {
    pub schema_version: u32,
    /// judge version active when this baseline was saved.
    pub judge_version: String,
    pub candidates: Vec<BaselinePatternCandidate>,
}

impl PatternBaseline {
    pub fn new(candidates: &[PatternCandidate]) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            judge_version: env!("CARGO_PKG_VERSION").to_string(),
            candidates: candidates
                .iter()
                .map(|candidate| BaselinePatternCandidate {
                    id: candidate.id.clone(),
                    pattern: candidate.pattern,
                    krate: candidate.scope.krate.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug)]
pub enum PatternBaselineError {
    Io(PathBuf, std::io::Error),
    Serialize(serde_json::Error),
    Deserialize(PathBuf, serde_json::Error),
    /// The baseline declares a `schema_version` this judge has no support
    /// for — typically one written by a newer judge.
    UnsupportedSchemaVersion {
        path: PathBuf,
        found: Option<u64>,
    },
}

impl std::fmt::Display for PatternBaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = match self {
            Self::Io(path, err) => crate::baseline::StoreErrorRef::Io(path, err),
            Self::Serialize(err) => crate::baseline::StoreErrorRef::Serialize(err),
            Self::Deserialize(path, err) => crate::baseline::StoreErrorRef::Deserialize(path, err),
            Self::UnsupportedSchemaVersion { path, found } => {
                crate::baseline::StoreErrorRef::UnsupportedSchemaVersion {
                    path,
                    found: *found,
                }
            }
        };
        crate::baseline::fmt_store_error(
            f,
            "pattern baseline",
            SCHEMA_VERSION,
            "cargo judge patterns --save-pattern-baseline",
            error,
        )
    }
}

impl std::error::Error for PatternBaselineError {}

/// Writes `baseline` to `path` as pretty-printed JSON, creating parent
/// directories (e.g. `.judge/`) as needed.
pub fn save(path: &Path, baseline: &PatternBaseline) -> Result<(), PatternBaselineError> {
    crate::baseline::write_json_pretty(
        path,
        baseline,
        PatternBaselineError::Io,
        PatternBaselineError::Serialize,
    )
}

pub fn load(path: &Path) -> Result<PatternBaseline, PatternBaselineError> {
    let value = crate::baseline::read_json_value(
        path,
        PatternBaselineError::Io,
        PatternBaselineError::Deserialize,
    )?;
    let found = crate::baseline::schema_version_of(&value);
    match found {
        Some(version) if version == u64::from(SCHEMA_VERSION) => {
            crate::baseline::deserialize_value(path, value, PatternBaselineError::Deserialize)
        }
        _ => Err(PatternBaselineError::UnsupportedSchemaVersion {
            path: path.to_path_buf(),
            found,
        }),
    }
}

/// The result of comparing a fresh set of pattern candidates against a
/// [`PatternBaseline`] — a flat three-way split (see this module's docs for
/// why there is no `code_introduced`/`rule_introduced` distinction here).
#[derive(Debug, Clone, Serialize)]
pub struct PatternDelta {
    /// Candidates not present in the baseline.
    pub new: Vec<PatternCandidate>,
    /// Baseline candidates that no longer appear in the current run.
    pub resolved: Vec<BaselinePatternCandidate>,
    /// Candidates present in both the baseline and the current run.
    pub unchanged_count: usize,
}

/// Compares `current` pattern candidates against `baseline`, classifying
/// every candidate not already in the baseline as `new`.
pub fn diff_patterns(current: &[PatternCandidate], baseline: &PatternBaseline) -> PatternDelta {
    let known_ids: HashSet<&str> = baseline
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();

    let mut new = Vec::new();
    let mut unchanged_count = 0;
    for candidate in current {
        if known_ids.contains(candidate.id.as_str()) {
            unchanged_count += 1;
        } else {
            new.push(candidate.clone());
        }
    }

    let current_ids: HashSet<&str> = current
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    let resolved = baseline
        .candidates
        .iter()
        .filter(|candidate| !current_ids.contains(candidate.id.as_str()))
        .cloned()
        .collect();

    PatternDelta {
        new,
        resolved,
        unchanged_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{CodeScope, CorroboratedEvidence, Evidence};

    /// `PatternCandidateId::compute` is private to `pattern.rs` (its inputs
    /// are meaningful only to the aggregation rules that call it), so tests
    /// here build one the same way `save`/`load` round-trip it: through its
    /// `#[serde(transparent)]` string representation.
    fn candidate_id(raw: &str) -> PatternCandidateId {
        serde_json::from_value(serde_json::json!(raw)).unwrap()
    }

    fn candidate(id: &str, pattern: RustPattern, krate: &str) -> PatternCandidate {
        PatternCandidate {
            id: candidate_id(id),
            pattern,
            scope: CodeScope {
                krate: krate.to_string(),
                modules: Vec::new(),
            },
            evidence: CorroboratedEvidence {
                primary: Evidence {
                    description: "primary".to_string(),
                    locations: Vec::new(),
                },
                independent: Evidence {
                    description: "independent".to_string(),
                    locations: Vec::new(),
                },
                additional: Vec::new(),
            },
            preconditions: Vec::new(),
            contraindications: Vec::new(),
            migration: Vec::new(),
            related_findings: Vec::new(),
        }
    }

    fn baseline_with(candidates: &[PatternCandidate]) -> PatternBaseline {
        PatternBaseline::new(candidates)
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = crate::test_util::TempDir::new("pattern-baseline-round-trip");
        let path = dir.join(".judge/baseline-patterns.json");
        let baseline = baseline_with(&[candidate("a", RustPattern::Builder, "fixture")]);

        save(&path, &baseline).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.judge_version, baseline.judge_version);
        assert_eq!(loaded.candidates.len(), 1);
        assert_eq!(loaded.candidates[0].id.as_str(), "a");
        assert_eq!(loaded.candidates[0].pattern, RustPattern::Builder);
        assert_eq!(loaded.candidates[0].krate, "fixture");
    }

    #[test]
    fn baseline_with_future_schema_version_is_rejected() {
        let dir = crate::test_util::TempDir::new("pattern-baseline-future-schema");
        let path = dir.join("baseline.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": 99,
                "judge_version": "9.9.9",
                "candidates": []
            }"#,
        )
        .unwrap();

        let err = load(&path).unwrap_err();

        assert!(matches!(
            err,
            PatternBaselineError::UnsupportedSchemaVersion {
                found: Some(99),
                ..
            }
        ));
    }

    #[test]
    fn known_candidate_is_unchanged_not_new() {
        let baseline = baseline_with(&[candidate("a", RustPattern::Builder, "fixture")]);
        let current = [candidate("a", RustPattern::Builder, "fixture")];

        let delta = diff_patterns(&current, &baseline);

        assert_eq!(delta.unchanged_count, 1);
        assert!(delta.new.is_empty());
        assert!(delta.resolved.is_empty());
    }

    #[test]
    fn candidate_only_in_current_is_new() {
        let baseline = baseline_with(&[]);
        let current = [candidate("a", RustPattern::Builder, "fixture")];

        let delta = diff_patterns(&current, &baseline);

        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].id.as_str(), "a");
        assert_eq!(delta.unchanged_count, 0);
    }

    #[test]
    fn candidate_only_in_baseline_is_resolved() {
        let baseline = baseline_with(&[candidate("gone", RustPattern::Builder, "fixture")]);

        let delta = diff_patterns(&[], &baseline);

        assert_eq!(delta.resolved.len(), 1);
        assert_eq!(delta.resolved[0].id.as_str(), "gone");
    }
}
