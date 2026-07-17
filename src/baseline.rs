//! Baseline snapshots and delta verdicts (see todo.md §5, §14.2 P0#5).
//!
//! A baseline freezes which findings were already known at a given commit,
//! plus the judge version and rule revisions active then. Comparing a fresh
//! run against it separates truly new findings (`code-introduced`) from
//! findings that only appear because a rule changed on otherwise-untouched
//! code (`rule-introduced`, protected by "Regelversions-Schutz") — only the
//! former may fail a delta verdict.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Origin, Severity};

pub const SCHEMA_VERSION: u32 = 1;

/// The minimal record kept per finding in a baseline file — enough to tell
/// whether a current finding was already known, and where to look when
/// deciding whether its file was touched since.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub origin: Origin,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    /// judge version active when this baseline was saved.
    pub judge_version: String,
    /// The commit this baseline was saved from (`first_seen_commit` for
    /// every finding it contains).
    pub commit: String,
    /// Revision of every rule active when this baseline was saved.
    pub rule_revisions: HashMap<String, u32>,
    /// Authored lines of code analyzed when this baseline was saved (see
    /// [`crate::health_score`]) — lets a later run compute the historical
    /// score density this baseline represents, not just its raw finding
    /// count.
    pub total_loc: usize,
    pub findings: Vec<BaselineFinding>,
}

impl Baseline {
    pub fn new(
        findings: &[Finding],
        commit: String,
        rule_revisions: HashMap<String, u32>,
        total_loc: usize,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            judge_version: env!("CARGO_PKG_VERSION").to_string(),
            commit,
            rule_revisions,
            total_loc,
            findings: findings
                .iter()
                .map(|finding| BaselineFinding {
                    id: finding.id.clone(),
                    rule: finding.rule.clone(),
                    severity: finding.severity,
                    origin: finding.origin,
                    file: finding.location.file.clone(),
                })
                .collect(),
        }
    }

    /// Migrates baselines written by older judge versions in the same
    /// checkout, which stored absolute paths in both `file` and `id`.
    pub fn relativize_paths(&mut self, workspace_root: &Path) {
        for finding in &mut self.findings {
            let Ok(relative) = finding.file.strip_prefix(workspace_root) else {
                continue;
            };
            let relative = relative.to_path_buf();
            let absolute_text = finding.file.to_string_lossy();
            let relative_text = relative.to_string_lossy();
            finding.id = finding
                .id
                .replace(absolute_text.as_ref(), relative_text.as_ref());
            finding.file = relative;
        }
    }
}

#[derive(Debug)]
pub enum BaselineError {
    Io(PathBuf, std::io::Error),
    Serialize(serde_json::Error),
    Deserialize(PathBuf, serde_json::Error),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: {err}", path.display()),
            Self::Serialize(err) => write!(f, "failed to serialize baseline: {err}"),
            Self::Deserialize(path, err) => {
                write!(f, "{}: failed to parse baseline: {err}", path.display())
            }
        }
    }
}

impl std::error::Error for BaselineError {}

/// Writes `baseline` to `path` as pretty-printed JSON, creating parent
/// directories (e.g. `.judge/`) as needed.
pub fn save(path: &Path, baseline: &Baseline) -> Result<(), BaselineError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| BaselineError::Io(parent.to_path_buf(), err))?;
    }
    let json = serde_json::to_string_pretty(baseline).map_err(BaselineError::Serialize)?;
    std::fs::write(path, json).map_err(|err| BaselineError::Io(path.to_path_buf(), err))
}

pub fn load(path: &Path) -> Result<Baseline, BaselineError> {
    let content =
        std::fs::read_to_string(path).map_err(|err| BaselineError::Io(path.to_path_buf(), err))?;
    serde_json::from_str(&content)
        .map_err(|err| BaselineError::Deserialize(path.to_path_buf(), err))
}

/// The result of comparing a fresh set of findings against a [`Baseline`].
#[derive(Debug, Clone, Serialize)]
pub struct Delta {
    /// New findings whose file changed since the baseline commit — a real
    /// regression introduced by this code change.
    pub code_introduced: Vec<Finding>,
    /// New findings whose file did *not* change since the baseline commit —
    /// they can only have appeared because a rule (or judge itself) changed
    /// on code that was already there (see todo.md §5 "Regelversions-Schutz").
    pub rule_introduced: Vec<Finding>,
    /// Baseline findings that no longer appear in the current run.
    pub resolved: Vec<BaselineFinding>,
    /// Findings present in both the baseline and the current run.
    pub unchanged_count: usize,
}

/// Compares `current` findings against `baseline`, classifying every finding
/// not already in the baseline as `code_introduced` or `rule_introduced`
/// depending on whether `touched_files` (paths changed since the baseline
/// commit — see [`crate::git::changed_files_since`]) contains its file.
pub fn diff(
    current: &[Finding],
    baseline: &Baseline,
    touched_files: &HashSet<PathBuf>,
    current_rule_revisions: &HashMap<String, u32>,
) -> Delta {
    let known_ids: HashSet<&str> = baseline.findings.iter().map(|f| f.id.as_str()).collect();

    let mut code_introduced = Vec::new();
    let mut rule_introduced = Vec::new();
    let mut unchanged_count = 0;

    for finding in current {
        let rule_changed =
            baseline.rule_revisions.get(&finding.rule) != current_rule_revisions.get(&finding.rule);
        if known_ids.contains(finding.id.as_str()) && !rule_changed {
            unchanged_count += 1;
        } else if rule_changed && !touched_files.contains(&finding.location.file) {
            rule_introduced.push(finding.clone());
        } else {
            code_introduced.push(finding.clone());
        }
    }

    let current_ids: HashSet<&str> = current.iter().map(|f| f.id.as_str()).collect();
    let resolved = baseline
        .findings
        .iter()
        .filter(|finding| !current_ids.contains(finding.id.as_str()))
        .cloned()
        .collect();

    Delta {
        code_introduced,
        rule_introduced,
        resolved,
        unchanged_count,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
}

/// A three-way verdict distinguishing `Warn` from `Fail` among
/// `code_introduced` findings, instead of collapsing both into `Fail` like
/// [`Delta::verdict`] does. Used by `audit --since` (see todo.md §6), which
/// reports on `Warn`-severity findings rather than hard-failing on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriVerdict {
    Pass,
    Warn,
    Fail,
}

impl Delta {
    /// Only actionable (`Warn`/`Fail`) code-introduced findings can fail the
    /// verdict. `Info` findings remain visible in the delta but are explicitly
    /// descriptive, not pass/fail judgements.
    pub fn verdict(&self) -> Verdict {
        if self
            .code_introduced
            .iter()
            .all(|finding| finding.severity == crate::finding::Severity::Info)
        {
            Verdict::Pass
        } else {
            Verdict::Fail
        }
    }

    /// Like [`Delta::verdict`], but keeps `Warn` and `Fail` distinct instead
    /// of collapsing both into `Fail` (see [`TriVerdict`]).
    pub fn tri_verdict(&self) -> TriVerdict {
        let mut has_warn = false;
        for finding in &self.code_introduced {
            match finding.severity {
                crate::finding::Severity::Fail => return TriVerdict::Fail,
                crate::finding::Severity::Warn => has_warn = true,
                crate::finding::Severity::Info => {}
            }
        }
        if has_warn {
            TriVerdict::Warn
        } else {
            TriVerdict::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Location, Severity};

    fn finding(id: &str, file: &str) -> Finding {
        Finding {
            id: id.to_string(),
            rule: "duplicate-code".to_string(),
            severity: Severity::Warn,
            location: Location {
                file: PathBuf::from(file),
                line: 1,
                item_path: "f".to_string(),
            },
            confidence: 1.0,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }

    fn baseline_with(findings: &[Finding]) -> Baseline {
        Baseline::new(
            findings,
            "abc123".to_string(),
            HashMap::from([("duplicate-code".to_string(), 1)]),
            1000,
        )
    }

    fn current_revisions() -> HashMap<String, u32> {
        HashMap::from([("duplicate-code".to_string(), 1)])
    }

    #[test]
    fn save_and_load_round_trips() {
        let dir = crate::test_util::TempDir::new("baseline-round-trip");
        let path = dir.join(".judge/baseline.json");
        let baseline = baseline_with(&[finding("a", "src/a.rs")]);

        save(&path, &baseline).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.commit, baseline.commit);
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].id, "a");
    }

    #[test]
    fn known_finding_is_unchanged_not_introduced() {
        let baseline = baseline_with(&[finding("a", "src/a.rs")]);
        let current = [finding("a", "src/a.rs")];

        let delta = diff(&current, &baseline, &HashSet::new(), &current_revisions());

        assert_eq!(delta.unchanged_count, 1);
        assert!(delta.code_introduced.is_empty());
        assert!(delta.rule_introduced.is_empty());
        assert_eq!(delta.verdict(), Verdict::Pass);
    }

    #[test]
    fn new_finding_in_a_touched_file_is_code_introduced() {
        let baseline = baseline_with(&[]);
        let current = [finding("new", "src/a.rs")];
        let touched = HashSet::from([PathBuf::from("src/a.rs")]);

        let delta = diff(&current, &baseline, &touched, &current_revisions());

        assert_eq!(delta.code_introduced.len(), 1);
        assert!(delta.rule_introduced.is_empty());
        assert_eq!(delta.verdict(), Verdict::Fail);
    }

    #[test]
    fn new_finding_in_an_untouched_file_is_rule_introduced_and_does_not_fail() {
        let baseline = baseline_with(&[]);
        let current = [finding("new", "src/a.rs")];

        let mut revised = current_revisions();
        revised.insert("duplicate-code".to_string(), 2);
        let delta = diff(&current, &baseline, &HashSet::new(), &revised);

        assert!(delta.code_introduced.is_empty());
        assert_eq!(delta.rule_introduced.len(), 1);
        assert_eq!(delta.verdict(), Verdict::Pass);
    }

    #[test]
    fn finding_missing_from_the_current_run_is_resolved() {
        let baseline = baseline_with(&[finding("gone", "src/a.rs")]);

        let delta = diff(&[], &baseline, &HashSet::new(), &current_revisions());

        assert_eq!(delta.resolved.len(), 1);
        assert_eq!(delta.resolved[0].id, "gone");
    }

    #[test]
    fn new_finding_without_a_rule_change_fails_even_in_an_untouched_file() {
        let baseline = baseline_with(&[]);
        let current = [finding("new", "src/a.rs")];

        let delta = diff(&current, &baseline, &HashSet::new(), &current_revisions());

        assert_eq!(delta.code_introduced.len(), 1);
        assert!(delta.rule_introduced.is_empty());
        assert_eq!(delta.verdict(), Verdict::Fail);
    }

    #[test]
    fn changed_rule_rechecks_an_existing_finding() {
        let baseline = baseline_with(&[finding("known", "src/a.rs")]);
        let current = [finding("known", "src/a.rs")];
        let revised = HashMap::from([("duplicate-code".to_string(), 2)]);

        let delta = diff(&current, &baseline, &HashSet::new(), &revised);

        assert_eq!(delta.unchanged_count, 0);
        assert_eq!(delta.rule_introduced.len(), 1);
    }

    #[test]
    fn informational_code_finding_does_not_fail_the_verdict() {
        let baseline = baseline_with(&[]);
        let mut info = finding("info", "src/a.rs");
        info.severity = Severity::Info;
        let touched = HashSet::from([PathBuf::from("src/a.rs")]);

        let delta = diff(&[info], &baseline, &touched, &current_revisions());

        assert_eq!(delta.code_introduced.len(), 1);
        assert_eq!(delta.verdict(), Verdict::Pass);
    }

    #[test]
    fn tri_verdict_is_warn_for_warn_only_code_introduced_findings() {
        let baseline = baseline_with(&[]);
        let current = [finding("new", "src/a.rs")];
        let touched = HashSet::from([PathBuf::from("src/a.rs")]);

        let delta = diff(&current, &baseline, &touched, &current_revisions());

        assert_eq!(delta.tri_verdict(), TriVerdict::Warn);
    }

    #[test]
    fn tri_verdict_is_fail_when_any_code_introduced_finding_fails() {
        let baseline = baseline_with(&[]);
        let mut fail = finding("fail", "src/a.rs");
        fail.severity = Severity::Fail;
        let warn = finding("warn", "src/a.rs");
        let touched = HashSet::from([PathBuf::from("src/a.rs")]);

        let delta = diff(&[fail, warn], &baseline, &touched, &current_revisions());

        assert_eq!(delta.tri_verdict(), TriVerdict::Fail);
    }

    #[test]
    fn tri_verdict_is_pass_for_empty_or_info_only_code_introduced_findings() {
        let baseline = baseline_with(&[]);
        assert_eq!(
            diff(&[], &baseline, &HashSet::new(), &current_revisions()).tri_verdict(),
            TriVerdict::Pass
        );

        let mut info = finding("info", "src/a.rs");
        info.severity = Severity::Info;
        let touched = HashSet::from([PathBuf::from("src/a.rs")]);
        let delta = diff(&[info], &baseline, &touched, &current_revisions());

        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);
    }
}
