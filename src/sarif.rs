//! SARIF 2.1.0 rendering of a [`Report`] (todo.md §7 "Formate", §0) — the
//! interchange format GitHub code scanning and most CI annotators consume.
//! [`render`] is pure: it maps an already-built report to a
//! `serde_json::Value` without touching the CLI, so it is testable in
//! isolation. Artifact URIs are emitted with forward slashes; callers
//! relativize finding paths (see [`crate::finding::relativize_paths`])
//! before building the report, matching SARIF's relative-URI convention.

use std::collections::BTreeSet;
use std::path::Path;

use crate::finding::{Report, Severity};

/// The SARIF `level` for a finding severity: `Fail` → `error`,
/// `Warn` → `warning`, `Info` → `note`.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Fail => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

/// Renders `path` as a SARIF artifact URI: forward slashes only. Windows
/// separators are rewritten textually, so a report produced on Windows still
/// yields portable URIs.
pub(crate) fn artifact_uri(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Renders `report` as a minimal, valid SARIF 2.1.0 log: one run, one
/// `ReportingDescriptor` per occurring rule (sorted, deduped), and one
/// result per finding. `evidence_class` and the advisory/gating split are
/// carried in each result's `properties` bag; the report's
/// `analysis_universe` (when present) in the run's `properties` bag — SARIF
/// has no native slot for either (todo.md §17.2, §17.5).
pub fn render(report: &Report) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| finding.rule.as_str())
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(|rule| {
            serde_json::json!({
                "id": rule,
                "shortDescription": { "text": rule },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.rule.as_str(),
                "level": level(finding.severity),
                "message": {
                    "text": format!("{}: {}", finding.rule, finding.location.item_path),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": artifact_uri(&finding.location.file) },
                        "region": { "startLine": finding.location.line.get() },
                    },
                }],
                "properties": {
                    "evidence_class": finding.evidence_class,
                    "gating": finding.is_gating(),
                },
            })
        })
        .collect();

    let mut run = serde_json::json!({
        "tool": {
            "driver": {
                "name": "judge",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/casoon/judge",
                "rules": rules,
            },
        },
        "results": results,
    });
    if let Some(universe) = &report.analysis_universe {
        run["properties"] = serde_json::json!({ "analysis_universe": universe });
    }

    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};

    fn finding(rule: &str, severity: Severity, class: EvidenceClass, file: &str) -> Finding {
        Finding::new(
            format!("{rule}:{file}"),
            rule.to_string(),
            severity,
            Location {
                file: PathBuf::from(file),
                line: OneBasedLine::new(42).unwrap(),
                item_path: "crate::item".to_string(),
            },
            class,
            Origin::Code,
            None,
        )
    }

    #[test]
    fn render_produces_a_minimal_valid_sarif_log() {
        let report = Report::new(vec![finding(
            "duplicate-code",
            Severity::Warn,
            EvidenceClass::DerivedFact,
            "src/lib.rs",
        )]);

        let sarif = render(&report);

        assert_eq!(sarif["version"], "2.1.0");
        assert!(
            sarif["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "judge");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            driver["informationUri"]
                .as_str()
                .unwrap()
                .starts_with("https://")
        );
        assert_eq!(driver["rules"][0]["id"], "duplicate-code");
        assert_eq!(
            driver["rules"][0]["shortDescription"]["text"],
            "duplicate-code"
        );

        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "duplicate-code");
        assert_eq!(result["level"], "warning");
        assert_eq!(result["message"]["text"], "duplicate-code: crate::item");
        let physical = &result["locations"][0]["physicalLocation"];
        assert_eq!(physical["artifactLocation"]["uri"], "src/lib.rs");
        assert_eq!(physical["region"]["startLine"], 42);
        assert_eq!(result["properties"]["evidence_class"], "derived_fact");
        assert_eq!(result["properties"]["gating"], true);
    }

    #[test]
    fn severity_maps_to_sarif_levels_and_heuristics_are_marked_advisory() {
        let report = Report::new(vec![
            finding(
                "empty-impl",
                Severity::Fail,
                EvidenceClass::DerivedFact,
                "src/a.rs",
            ),
            finding(
                "hotspot",
                Severity::Info,
                EvidenceClass::Heuristic,
                "src/b.rs",
            ),
        ]);

        let results = &render(&report)["runs"][0]["results"];

        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
        assert_eq!(results[1]["properties"]["evidence_class"], "heuristic");
        assert_eq!(results[1]["properties"]["gating"], false);
    }

    #[test]
    fn each_occurring_rule_appears_exactly_once_under_driver_rules() {
        let report = Report::new(vec![
            finding(
                "duplicate-code",
                Severity::Warn,
                EvidenceClass::DerivedFact,
                "src/a.rs",
            ),
            finding(
                "duplicate-code",
                Severity::Warn,
                EvidenceClass::DerivedFact,
                "src/b.rs",
            ),
            finding(
                "hotspot",
                Severity::Info,
                EvidenceClass::Heuristic,
                "src/c.rs",
            ),
        ]);

        let sarif = render(&report);
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        let ids: Vec<&str> = rules
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["duplicate-code", "hotspot"]);
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn artifact_uris_use_forward_slashes_even_for_windows_style_paths() {
        assert_eq!(
            artifact_uri(Path::new(r"src\nested\file.rs")),
            "src/nested/file.rs"
        );
        assert_eq!(artifact_uri(Path::new("src/lib.rs")), "src/lib.rs");
    }

    #[test]
    fn the_analysis_universe_lands_in_the_run_properties_bag() {
        let bare = render(&Report::new(Vec::new()));
        assert!(
            bare["runs"][0].get("properties").is_none(),
            "a universe-less report must omit run properties, not emit null"
        );

        let dir = crate::test_util::TempDir::new("sarif-universe");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"sarif-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = Report::new(Vec::new())
            .with_universe(crate::finding::AnalysisUniverse::fast(&workspace, false));
        let sarif = render(&report);
        assert_eq!(
            sarif["runs"][0]["properties"]["analysis_universe"]["tier"],
            "fast"
        );
    }
}
