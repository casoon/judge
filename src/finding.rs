//! The common output unit for detectors: a `Finding`. Findings can reference
//! each other (`caused_by`/`causes`) so a single root cause — e.g. a missed
//! entry point — doesn't present as dozens of unrelated findings (see
//! todo.md §7 "Kausale Finding-Gruppen", §14.2 P0#1).

use std::path::PathBuf;

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
    pub confidence: f32,
    pub origin: Origin,
    /// Findings that caused this one to appear (the root-cause direction).
    pub caused_by: Vec<FindingId>,
    /// Findings this one caused to appear (the cascade direction).
    pub causes: Vec<FindingId>,
}

/// Current version of the JSON report schema (see todo.md §7). Bump whenever
/// a field is removed or changes meaning; additive fields don't require it.
pub const SCHEMA_VERSION: u32 = 1;

/// The versioned, agent-readable output envelope (see todo.md §7). Always
/// carries the full finding graph — TTY/Markdown reduce to root findings by
/// default, JSON never does.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            findings,
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
                    let start = stack
                        .iter()
                        .position(|id| id == target_id)
                        .unwrap_or(0);
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
            confidence: 1.0,
            origin: Origin::Code,
            caused_by: Vec::new(),
            causes: causes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn acyclic_graph_passes() {
        let findings = vec![finding("a", &["b"]), finding("b", &["c"]), finding("c", &[])];
        assert!(check_for_cycles(&findings).is_ok());
    }

    #[test]
    fn direct_cycle_is_detected() {
        let findings = vec![finding("a", &["b"]), finding("b", &["a"])];
        let err = check_for_cycles(&findings).unwrap_err();
        assert_eq!(err.cycle, vec!["a".to_string(), "b".to_string(), "a".to_string()]);
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
}
