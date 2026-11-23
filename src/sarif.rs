//! SARIF 2.1.0 rendering of a [`Report`] (todo.md §7 "Formate", §0) — the
//! interchange format GitHub code scanning and most CI annotators consume.
//! [`render`] is pure: it maps an already-built report to a
//! `serde_json::Value` without touching the CLI, so it is testable in
//! isolation. Artifact URIs are emitted with forward slashes; callers
//! relativize finding paths (see [`crate::finding::relativize_paths`])
//! before building the report, matching SARIF's relative-URI convention.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::finding::{Report, Severity};
use crate::rule_registry::RuleLevel;

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

/// Position-independent identity of each finding, for SARIF
/// `partialFingerprints`: `rule|file|item|n`, where `n` numbers findings that
/// share the first three parts in source order. Code scanning uses it to
/// match a result across runs, so an unrelated edit above a finding that
/// shifts its line does not read as "fixed" plus "new".
fn fingerprints(report: &Report) -> Vec<String> {
    let mut order: Vec<usize> = (0..report.findings.len()).collect();
    order.sort_by_key(|&index| report.findings[index].location.line.get());
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut result = vec![String::new(); report.findings.len()];
    for index in order {
        let finding = &report.findings[index];
        let key = format!(
            "{}|{}|{}",
            finding.rule,
            artifact_uri(&finding.location.file),
            finding.location.item_path
        );
        let occurrence = seen.entry(key.clone()).or_insert(0);
        result[index] = format!("{key}|{occurrence}");
        *occurrence += 1;
    }
    result
}

/// Renders `report` as a minimal, valid SARIF 2.1.0 log: one run, one
/// `ReportingDescriptor` per occurring rule (sorted, deduped), and one
/// result per finding. `evidence_class` and the advisory/gating split are
/// carried in each result's `properties` bag; the report's
/// `analysis_universe` (when present) in the run's `properties` bag — SARIF
/// has no native slot for either (todo.md §17.2, §17.5). Active
/// `judge.toml` `[rules.<id>] level` overrides become the invocation's
/// `ruleConfigurationOverrides`.
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

    let fingerprints = fingerprints(report);
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .zip(&fingerprints)
        .map(|(finding, fingerprint)| {
            let mut result = serde_json::json!({
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
                "partialFingerprints": { "judgeFinding/v1": fingerprint },
                "properties": {
                    "evidence_class": finding.evidence_class,
                    "gating": finding.is_gating(),
                },
            });
            if let Some(cfg) = finding.cfg() {
                result["properties"][crate::cfg::EVIDENCE_KEY] = cfg.into();
            }
            result
        })
        .collect();

    let mut notifications: Vec<serde_json::Value> = report
        .errors
        .iter()
        .map(|error| serde_json::json!({ "level": "error", "message": { "text": error } }))
        .collect();
    notifications.extend(
        report
            .analysis_universe
            .iter()
            .flat_map(|universe| &universe.unparsed_files)
            .map(unparsed_file_notification),
    );

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
        "invocations": [{
            "executionSuccessful": report.errors.is_empty(),
            "toolExecutionNotifications": notifications,
        }],
    });
    if !report.rule_overrides.is_empty() {
        run["invocations"][0]["ruleConfigurationOverrides"] = report
            .rule_overrides
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "descriptor": { "id": entry.rule },
                    "configuration": {
                        "enabled": entry.level != RuleLevel::Off,
                        "properties": { "level": entry.level, "default": entry.default },
                    },
                })
            })
            .collect();
    }
    if let Some(universe) = &report.analysis_universe {
        run["properties"] = serde_json::json!({ "analysis_universe": universe });
    }

    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    })
}

/// A file the syntax-based rules could not analyze, as a warning-level
/// `toolExecutionNotification` pointing at the file (and, for a `syn` error,
/// the line and column). A warning, not an error: whether the run counts as
/// incomplete stays each rule's own policy, reported through `errors`.
fn unparsed_file_notification(file: &crate::parse::UnparsedFile) -> serde_json::Value {
    let mut physical_location = serde_json::json!({
        "artifactLocation": { "uri": artifact_uri(&file.path) },
    });
    if let (Some(line), Some(column)) = (file.line, file.column) {
        physical_location["region"] = serde_json::json!({
            "startLine": line,
            "startColumn": column,
        });
    }
    serde_json::json!({
        "level": "warning",
        "message": {
            "text": format!("not analyzed by syntax-based rules: {}", file.reason),
        },
        "locations": [{ "physicalLocation": physical_location }],
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
    fn cfg_condition_is_an_additive_result_property() {
        let plain = finding(
            "duplicate-code",
            Severity::Warn,
            EvidenceClass::DerivedFact,
            "src/a.rs",
        );
        let mut gated = finding(
            "duplicate-code",
            Severity::Warn,
            EvidenceClass::DerivedFact,
            "src/b.rs",
        );
        gated.evidence = Some(serde_json::json!({ "token_count": 20, "cfg": "unix" }));

        let sarif = render(&Report::new(vec![plain, gated]));

        let results = &sarif["runs"][0]["results"];
        assert!(results[0]["properties"].get("cfg").is_none());
        assert_eq!(results[1]["properties"]["cfg"], "unix");
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
    fn rule_overrides_become_rule_configuration_overrides() {
        let report =
            Report::new(Vec::new()).with_rule_overrides(vec![crate::rule_registry::RuleOverride {
                rule: "duplicate-code".to_string(),
                level: RuleLevel::Off,
                default: RuleLevel::Gating,
            }]);

        let sarif = render(&report);

        let overrides = &sarif["runs"][0]["invocations"][0]["ruleConfigurationOverrides"];
        assert_eq!(overrides[0]["descriptor"]["id"], "duplicate-code");
        assert_eq!(overrides[0]["configuration"]["enabled"], false);
        assert_eq!(overrides[0]["configuration"]["properties"]["level"], "off");
        assert_eq!(
            overrides[0]["configuration"]["properties"]["default"],
            "gating"
        );
        assert!(
            render(&Report::new(Vec::new()))["runs"][0]["invocations"][0]
                .get("ruleConfigurationOverrides")
                .is_none()
        );
    }

    #[test]
    fn fingerprints_ignore_the_line_and_number_repeated_findings() {
        let mut first = finding(
            "swallowed-result",
            Severity::Warn,
            EvidenceClass::DerivedFact,
            "src/a.rs",
        );
        let mut second = first.clone();
        second.id = "swallowed-result:src/a.rs:b".into();
        second.location.line = OneBasedLine::new(50).unwrap();
        first.location.line = OneBasedLine::new(10).unwrap();

        let before = render(&Report::new(vec![first.clone(), second.clone()]));
        // An edit above both findings shifts their lines.
        first.location.line = OneBasedLine::new(11).unwrap();
        second.location.line = OneBasedLine::new(51).unwrap();
        let after = render(&Report::new(vec![first, second]));

        let prints = |sarif: &serde_json::Value| -> Vec<String> {
            sarif["runs"][0]["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|result| {
                    result["partialFingerprints"]["judgeFinding/v1"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(prints(&before), prints(&after));
        assert_ne!(prints(&before)[0], prints(&before)[1]);
    }

    #[test]
    fn analysis_errors_become_tool_notifications() {
        let mut report = Report::new(Vec::new());
        report.errors.push("src/broken.rs: parse error".to_string());

        let sarif = render(&report);

        let invocation = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        assert_eq!(
            invocation["toolExecutionNotifications"][0]["message"]["text"],
            "src/broken.rs: parse error"
        );
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
