//! The common output unit for detectors: a `Finding`. Findings can reference
//! each other (`caused_by`/`causes`) so a single root cause — e.g. a missed
//! entry point — doesn't present as dozens of unrelated findings (see
//! todo.md §7 "Kausale Finding-Gruppen", §14.2 P0#1).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Stable identifier for a finding, referenced by `caused_by`/`causes` links.
pub type FindingId = String;

/// Ordered `Info < Warn < Fail` (derive order follows declaration order) so
/// findings can be sorted worst-first across detectors — see
/// [`sort_by_severity_desc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Fail,
}

/// How a finding's claim is backed — the categorical replacement for the
/// former numeric `confidence` score (todo.md §17.2, §17.5: numbers like
/// `0.95` suggest a calibrated probability that never existed).
///
/// Rule → class mapping (see [`evidence_class_for_rule`], todo.md §17.3):
///
/// | Rule | Class |
/// |---|---|
/// | `swallowed-result`, `empty-error-arm`, `catch-all-error`, `suppression-debt`, `merged-stub`, `empty-impl`, `assertion-free-test`, `tautological-test`, `ignored-test-accumulation`, `conversational-artifact`, `restating-comment`, `step-comment-inflation`, `generic-naming`, `doc-restates-signature` | `derived_fact` (G1–G3: the reported pattern is a syntax fact) |
/// | `duplicate-code` | `derived_fact` for `Strict`/`Mild` token equality; `heuristic` for `Weak`/`Semantic` normalization (see [`crate::duplication::CloneMember::to_finding`]) |
/// | `unused-pub-workspace`, `crate-boundary-violation`, `dependency-cycle` | `bounded_semantic` (proven only within the loaded workspace / configured crate graph) |
/// | `phantom-crate`, `phantom-version`, `fresh-low-reputation-dep` | `external_measurement` (a crates.io lookup snapshot) |
/// | `hotspot`, `churn-hotspot`, `low-bus-factor`, `abstraction-inflation`, `complexity-inflation`, `legacy-freeze`, `duplicative-reinvention`, `connectivity-drop`, `name-collision-risk`, `misplaced-dependency-kind`, `provenance-churn`, `provenance-duplication-rate`, `provenance-suppression-debt` | `heuristic` (reproducible interpretation, not proof) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Exactly derived from the declared inputs — syntax facts, strict/mild
    /// token duplicates, manifest facts, suppressions (todo.md §17.2).
    DerivedFact,
    /// Semantically backed, but only within a fully described analysis view —
    /// e.g. "no reference found in the loaded workspace for the searched
    /// crates/entry points" (todo.md §17.2).
    BoundedSemantic,
    /// The result of a concrete external run/snapshot — e.g. a crates.io
    /// index/API query. Valid for that snapshot, not a timeless truth
    /// (todo.md §17.2).
    ExternalMeasurement,
    /// A reproducible interpretation of facts/measurements — a hint by
    /// default, never proof (todo.md §17.2).
    Heuristic,
}

/// The single authoritative rule-id → [`EvidenceClass`] mapping (see the
/// table on [`EvidenceClass`]). Used by detectors whose constructors take a
/// rule id, and by the baseline v1→v2 migration, which must derive a class
/// from nothing but the stored rule id.
///
/// `duplicate-code` maps to its `Strict`/`Mild` (default-mode, fact-backed)
/// class here; `Weak`/`Semantic` creation sites override to `Heuristic` at
/// the source (see [`crate::duplication::CloneMember::to_finding`]) — a
/// migrated v1 baseline entry can't recover the mode, and baseline entries
/// only serve identity matching. Unknown rule ids (e.g. from a v1 baseline
/// written by a different judge) conservatively map to `Heuristic`.
pub fn evidence_class_for_rule(rule: &str) -> EvidenceClass {
    match rule {
        "swallowed-result"
        | "empty-error-arm"
        | "catch-all-error"
        | "suppression-debt"
        | "merged-stub"
        | "empty-impl"
        | "assertion-free-test"
        | "tautological-test"
        | "ignored-test-accumulation"
        | "conversational-artifact"
        | "restating-comment"
        | "step-comment-inflation"
        | "generic-naming"
        | "doc-restates-signature"
        | "duplicate-code" => EvidenceClass::DerivedFact,
        "unused-pub-workspace" | "crate-boundary-violation" | "dependency-cycle" => {
            EvidenceClass::BoundedSemantic
        }
        "phantom-crate" | "phantom-version" | "fresh-low-reputation-dep" => {
            EvidenceClass::ExternalMeasurement
        }
        _ => EvidenceClass::Heuristic,
    }
}

/// Where a finding comes from. Distinguishes an actual code issue from a
/// finding about judge's own configuration or analyzer state, which must
/// not be suppressed or baselined the same way (see todo.md §14.2 P0#1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Code,
    Config,
    Analyzer,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: usize,
    pub item_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: FindingId,
    pub rule: String,
    pub severity: Severity,
    pub location: Location,
    pub evidence_class: EvidenceClass,
    pub origin: Origin,
    /// Free-form, rule-specific proof for why this finding fired — e.g. how
    /// many crates/entry points were searched, and what backs
    /// `evidence_class` (see todo.md §7). `None` where a detector doesn't
    /// yet populate it; not every rule does.
    pub evidence: Option<serde_json::Value>,
    /// Findings that caused this one to appear (the root-cause direction).
    pub caused_by: Vec<FindingId>,
    /// Findings this one caused to appear (the cascade direction).
    pub causes: Vec<FindingId>,
}

/// Current version of the JSON report schema (see todo.md §7). Bump whenever
/// a field is removed or changes meaning; additive fields don't require it.
/// v2: `Finding.confidence: f32` replaced by `Finding.evidence_class`
/// (todo.md §17.5).
pub const SCHEMA_VERSION: u32 = 2;

/// The versioned, agent-readable output envelope (see todo.md §7). Always
/// carries the full finding graph — TTY/Markdown reduce to root findings by
/// default, JSON never does.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub findings: Vec<Finding>,
    /// Analyzer failures that made the report incomplete. An empty list means
    /// every requested detector completed successfully.
    pub errors: Vec<String>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self::with_errors(findings, Vec::new())
    }

    pub fn with_errors(findings: Vec<Finding>, errors: Vec<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            findings,
            errors,
        }
    }
}

/// Findings with no recorded cause — what TTY/Markdown show by default
/// (see todo.md §7 "Kausale Finding-Gruppen", §14.2 P0#2). `--show-cascades`
/// bypasses this and shows every finding, root or not.
pub fn root_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.caused_by.is_empty()).collect()
}

/// Sorts findings worst-first (`Fail` before `Warn` before `Info`), stable
/// otherwise. Used to merge findings from multiple detectors into one
/// ranked view without inventing a numeric score across them (see todo.md
/// §4 "Decision Surface" — the score itself needs crate-type profiles that
/// don't exist yet; this is the part that doesn't).
pub fn sort_by_severity_desc(findings: &mut [Finding]) {
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
}

/// Rewrites workspace-local absolute paths to repository-relative paths.
/// Finding ids embed their location in several detectors, so the id must be
/// rebased together with the structured location to remain stable across
/// different checkout directories.
pub fn relativize_paths(findings: &mut [Finding], workspace_root: &Path) {
    for finding in findings {
        let Ok(relative) = finding.location.file.strip_prefix(workspace_root) else {
            continue;
        };
        let relative = relative.to_path_buf();
        let absolute_text = finding.location.file.to_string_lossy();
        let relative_text = relative.to_string_lossy();
        finding.id = finding
            .id
            .replace(absolute_text.as_ref(), relative_text.as_ref());
        if finding.location.item_path == absolute_text {
            finding.location.item_path = relative_text.into_owned();
        }
        finding.location.file = relative;
    }
}

/// A cycle detected in the `causes` graph, reported as the sequence of
/// finding IDs that closes the loop (first and last entry are the same id).
#[derive(Debug, PartialEq, Eq)]
pub struct CycleError {
    pub cycle: Vec<FindingId>,
}

impl std::fmt::Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cycle in finding graph: {}", self.cycle.join(" -> "))
    }
}

impl std::error::Error for CycleError {}

/// Validates that the `causes` edges among `findings` form a DAG. Edges to
/// ids outside the given slice are ignored — aggregation may run over a
/// subset (e.g. one detector's output) and dangling references there are
/// not a cycle.
pub fn check_for_cycles(findings: &[Finding]) -> Result<(), CycleError> {
    use std::collections::HashMap;

    let index_by_id: HashMap<&str, usize> = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (finding.id.as_str(), index))
        .collect();

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Unvisited,
        InProgress,
        Done,
    }

    let mut marks = vec![Mark::Unvisited; findings.len()];
    let mut stack = Vec::new();

    fn visit(
        index: usize,
        findings: &[Finding],
        index_by_id: &HashMap<&str, usize>,
        marks: &mut [Mark],
        stack: &mut Vec<FindingId>,
    ) -> Result<(), CycleError> {
        marks[index] = Mark::InProgress;
        stack.push(findings[index].id.clone());

        for target_id in &findings[index].causes {
            let Some(&target_index) = index_by_id.get(target_id.as_str()) else {
                continue;
            };
            match marks[target_index] {
                Mark::Done => continue,
                Mark::Unvisited => visit(target_index, findings, index_by_id, marks, stack)?,
                Mark::InProgress => {
                    let start = stack.iter().position(|id| id == target_id).unwrap_or(0);
                    let mut cycle = stack[start..].to_vec();
                    cycle.push(target_id.clone());
                    return Err(CycleError { cycle });
                }
            }
        }

        stack.pop();
        marks[index] = Mark::Done;
        Ok(())
    }

    for index in 0..findings.len() {
        if marks[index] == Mark::Unvisited {
            visit(index, findings, &index_by_id, &mut marks, &mut stack)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, causes: &[&str]) -> Finding {
        Finding {
            id: id.to_string(),
            rule: "test-rule".to_string(),
            severity: Severity::Warn,
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                item_path: "crate::lib".to_string(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: causes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn acyclic_graph_passes() {
        let findings = vec![
            finding("a", &["b"]),
            finding("b", &["c"]),
            finding("c", &[]),
        ];
        assert!(check_for_cycles(&findings).is_ok());
    }

    #[test]
    fn direct_cycle_is_detected() {
        let findings = vec![finding("a", &["b"]), finding("b", &["a"])];
        let err = check_for_cycles(&findings).unwrap_err();
        assert_eq!(
            err.cycle,
            vec!["a".to_string(), "b".to_string(), "a".to_string()]
        );
    }

    #[test]
    fn indirect_cycle_is_detected() {
        let findings = vec![
            finding("a", &["b"]),
            finding("b", &["c"]),
            finding("c", &["a"]),
        ];
        assert!(check_for_cycles(&findings).is_err());
    }

    #[test]
    fn self_cycle_is_detected() {
        let findings = vec![finding("a", &["a"])];
        let err = check_for_cycles(&findings).unwrap_err();
        assert_eq!(err.cycle, vec!["a".to_string(), "a".to_string()]);
    }

    #[test]
    fn dangling_edges_outside_the_given_set_are_ignored() {
        let findings = vec![finding("a", &["not-in-this-batch"])];
        assert!(check_for_cycles(&findings).is_ok());
    }

    #[test]
    fn root_findings_excludes_those_with_a_recorded_cause() {
        let mut root = finding("a", &["b"]);
        let mut dependent = finding("b", &[]);
        dependent.caused_by = vec!["a".to_string()];
        root.causes = vec!["b".to_string()];

        let findings = vec![root, dependent];
        let roots = root_findings(&findings);

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "a");
    }

    #[test]
    fn report_serializes_with_schema_version_and_snake_case_enums() {
        let report = Report::new(vec![finding("a", &[])]);
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["findings"][0]["severity"], "warn");
        assert_eq!(json["findings"][0]["origin"], "code");
        assert_eq!(json["findings"][0]["evidence_class"], "heuristic");
        assert_eq!(json["errors"], serde_json::json!([]));
    }

    #[test]
    fn sort_by_severity_desc_puts_fail_before_warn_before_info() {
        let mut info = finding("info", &[]);
        info.severity = Severity::Info;
        let mut warn = finding("warn", &[]);
        warn.severity = Severity::Warn;
        let mut fail = finding("fail", &[]);
        fail.severity = Severity::Fail;

        let mut findings = vec![info, warn, fail];
        sort_by_severity_desc(&mut findings);

        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["fail", "warn", "info"]);
    }

    #[test]
    fn relativize_paths_rebases_location_and_embedded_id() {
        let mut finding = finding("hotspot:/tmp/project/src/lib.rs", &[]);
        finding.location.file = PathBuf::from("/tmp/project/src/lib.rs");
        finding.location.item_path = "/tmp/project/src/lib.rs".to_string();

        relativize_paths(
            std::slice::from_mut(&mut finding),
            Path::new("/tmp/project"),
        );

        assert_eq!(finding.id, "hotspot:src/lib.rs");
        assert_eq!(finding.location.file, PathBuf::from("src/lib.rs"));
        assert_eq!(finding.location.item_path, "src/lib.rs");
    }
}
