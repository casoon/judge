//! Imports `cargo-mutants`' `outcomes.json` mutation-testing report and
//! flags `mutation-survivor` findings: mutants the tool mutated, compiled,
//! and ran the test suite against, where no test failed (`summary:
//! "MissedMutant"`). This is evidence about test *strength*, not test
//! *coverage* — a line can be fully covered by the line-coverage sense
//! `crate::coverage` imports and still have a surviving mutant, if the
//! covering test never actually asserts on the mutated behavior (todo.md §J
//! "Optional: cargo-mutants-Import für Test-Aussagekraft statt
//! Test-Menge").
//!
//! judge never runs `cargo-mutants` itself — same established precedent as
//! `crate::advisories`/`crate::coverage`: only an already-generated report
//! is read, via `cargo judge coverage --mutants-json PATH` (see
//! `run_coverage` in `src/main.rs`). Generate one with `cargo mutants`
//! first, which writes `mutants.out/outcomes.json`.
//!
//! ## Known, unavoidable source of noise: equivalent mutants
//!
//! A mutant that is semantically identical to the original code (e.g.
//! replacing `x >= 0` with `x > -1` for an unsigned type, or a mutation in
//! genuinely dead code) can never be "caught" by any test, however
//! thorough — there is no observable behavior difference to assert on. This
//! is a well-known, unavoidable limitation of mutation testing itself, not
//! a defect in this rule (see the registry entry's `exclusions`); a
//! `mutation-survivor` finding is never proof that a test is missing, only
//! that no test currently distinguishes the mutated behavior from the
//! original.

use std::path::{Path, PathBuf};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};

/// Rule id for a surviving mutant imported from `cargo-mutants`'
/// `outcomes.json` (see module docs).
pub const MUTATION_SURVIVOR_RULE: &str = "mutation-survivor";
/// Bump when the mutation-survivor rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const MUTATION_SURVIVOR_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum MutantsImportError {
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for MutantsImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
        }
    }
}

impl std::error::Error for MutantsImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
        }
    }
}

/// One `"MissedMutant"` outcome, reduced to the fields this module needs.
/// `cargo-mutants` nests these under `outcomes[]`, where `scenario` is
/// `{"Mutant": {...}}` and `summary` is `"MissedMutant"` — see
/// [`parse_mutants_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissedMutant {
    pub name: String,
    pub file: String,
    pub function_name: Option<String>,
    pub line: usize,
    pub genre: String,
    pub replacement: String,
}

/// Findings plus non-fatal errors from importing a `cargo-mutants`
/// `outcomes.json` report — same shape as
/// [`crate::advisories::AdvisoryReport`].
#[derive(Debug, Default)]
pub struct MutantsReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

/// Parses `cargo-mutants`' `outcomes.json`, extracting one [`Finding`] per
/// `"MissedMutant"` entry under `outcomes[]`. Tolerant of the unparsable,
/// the malformed, and the merely unexpected: invalid JSON, a missing
/// `outcomes` key, or an entry missing a required field
/// (`scenario.Mutant.name`/`file`/`span.start.line`/`genre`/`replacement`)
/// all produce an empty result or skip just that entry, rather than failing
/// outright — the same "malformed records are skipped" precedent
/// [`crate::advisories::parse_audit_report`] documents. `function` is
/// `Option` in the upstream schema (absent for mutants outside any
/// function, e.g. top-level const expressions); a missing/null `function`
/// still produces a finding, using `file`+`line` only.
///
/// Cross-checks the parsed `"MissedMutant"` count against the report's own
/// top-level `missed` field (present and normally reliable) as a sanity
/// check, but a mismatch is recorded in [`MutantsReport::errors`] rather
/// than dropping or failing the parse — `cargo-mutants`' JSON schema is not
/// itself a versioned, guaranteed-stable API, so tolerance here is a
/// deliberate hedge, not laziness.
pub fn parse_mutants_report(text: &str) -> MutantsReport {
    let mut report = MutantsReport::default();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return report;
    };
    let Some(outcomes) = root.get("outcomes").and_then(|v| v.as_array()) else {
        return report;
    };

    let missed_mutants: Vec<MissedMutant> = outcomes
        .iter()
        .filter(|outcome| outcome.get("summary").and_then(|v| v.as_str()) == Some("MissedMutant"))
        .filter_map(|outcome| {
            let mutant = outcome.get("scenario")?.get("Mutant")?;
            let name = mutant.get("name")?.as_str()?.to_string();
            let file = mutant.get("file")?.as_str()?.to_string();
            let genre = mutant.get("genre")?.as_str()?.to_string();
            let replacement = mutant.get("replacement")?.as_str()?.to_string();
            let line = mutant.get("span")?.get("start")?.get("line")?.as_u64()? as usize;
            let function_name = mutant
                .get("function")
                .and_then(|f| f.as_object())
                .and_then(|f| f.get("function_name"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some(MissedMutant {
                name,
                file,
                function_name,
                line,
                genre,
                replacement,
            })
        })
        .collect();

    if let Some(declared_missed) = root.get("missed").and_then(|v| v.as_u64())
        && declared_missed as usize != missed_mutants.len()
    {
        report.errors.push(format!(
            "outcomes.json declares missed={declared_missed}, but {} \
             \"MissedMutant\" outcomes were parsed from outcomes[] — the report \
             may be from a different run, or partially malformed",
            missed_mutants.len()
        ));
    }

    report.findings = missed_mutants.iter().map(missed_mutant_finding).collect();
    report
}

/// Reads and parses a `cargo-mutants` `outcomes.json` report from `path`
/// (see [`parse_mutants_report`]). Only the file read can fail; parsing
/// never does.
pub fn read_mutants_report(path: &Path) -> Result<MutantsReport, MutantsImportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| MutantsImportError::Io(path.to_path_buf(), err))?;
    Ok(parse_mutants_report(&text))
}

/// Builds a `mutation-survivor` finding. Its evidence class is
/// `external_measurement` — the same class `untested-hotspot` uses (see
/// [`crate::finding::evidence_class_for_rule`]), for consistency across
/// judge's two external-tool-derived test-strength signals: the mutant
/// survived at report-generation time, not a timeless fact — a later added
/// test could kill the same mutant on a re-run.
fn missed_mutant_finding(mutant: &MissedMutant) -> Finding {
    let item_path = mutant
        .function_name
        .clone()
        .unwrap_or_else(|| format!("{}:{}", mutant.file, mutant.line));
    Finding {
        id: format!("{MUTATION_SURVIVOR_RULE}:{}", mutant.name).into(),
        rule: MUTATION_SURVIVOR_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: PathBuf::from(&mutant.file),
            line: OneBasedLine::new(mutant.line).unwrap_or(OneBasedLine::FIRST),
            item_path,
        },
        evidence_class: EvidenceClass::ExternalMeasurement,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "file": mutant.file,
            "function": mutant.function_name,
            "line": mutant.line,
            "genre": mutant.genre,
            "replacement": mutant.replacement,
            "name": mutant.name,
        })),
        limitations: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    // -- parse_mutants_report --

    #[test]
    fn parses_a_realistic_multi_outcome_report_and_only_flags_missed_mutants() {
        let text = r#"{
            "outcomes": [
                {
                    "scenario": "Baseline",
                    "summary": "Success",
                    "log_path": "baseline.log",
                    "diff_path": null,
                    "phase_results": []
                },
                {
                    "scenario": { "Mutant": {
                        "name": "src/foo.rs:12:5: replace foo -> bool with false",
                        "package": "my-crate",
                        "file": "src/foo.rs",
                        "function": {
                            "function_name": "foo",
                            "return_type": "-> bool",
                            "span": { "start": {"line": 10, "column": 1}, "end": {"line": 14, "column": 1} }
                        },
                        "span": { "start": {"line": 12, "column": 5}, "end": {"line": 12, "column": 20} },
                        "replacement": "false",
                        "genre": "FnValue"
                    }},
                    "summary": "CaughtMutant",
                    "log_path": "caught.log",
                    "diff_path": "caught.diff",
                    "phase_results": []
                },
                {
                    "scenario": { "Mutant": {
                        "name": "src/bar.rs:20:9: replace >= with < in is_valid",
                        "package": "my-crate",
                        "file": "src/bar.rs",
                        "function": {
                            "function_name": "is_valid",
                            "return_type": "-> bool",
                            "span": { "start": {"line": 18, "column": 1}, "end": {"line": 24, "column": 1} }
                        },
                        "span": { "start": {"line": 20, "column": 9}, "end": {"line": 20, "column": 11} },
                        "replacement": "<",
                        "genre": "BinaryOperator"
                    }},
                    "summary": "MissedMutant",
                    "log_path": "missed.log",
                    "diff_path": "missed.diff",
                    "phase_results": []
                },
                {
                    "scenario": { "Mutant": {
                        "name": "src/baz.rs:5:1: replace baz with ()",
                        "package": "my-crate",
                        "file": "src/baz.rs",
                        "function": null,
                        "span": { "start": {"line": 5, "column": 1}, "end": {"line": 5, "column": 3} },
                        "replacement": "()",
                        "genre": "FnValue"
                    }},
                    "summary": "Unviable",
                    "log_path": "unviable.log",
                    "diff_path": "unviable.diff",
                    "phase_results": []
                }
            ],
            "total_mutants": 4,
            "missed": 1,
            "caught": 1,
            "timeout": 0,
            "unviable": 1,
            "success": 0,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:05:00Z",
            "cargo_mutants_version": "25.0.0"
        }"#;

        let report = parse_mutants_report(text);

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, MUTATION_SURVIVOR_RULE);
        assert_eq!(finding.location.file, PathBuf::from("src/bar.rs"));
        assert_eq!(finding.location.line, 20);
        assert_eq!(finding.location.item_path, "is_valid");
        let evidence = finding.evidence.as_ref().unwrap();
        assert_eq!(evidence["file"], "src/bar.rs");
        assert_eq!(evidence["function"], "is_valid");
        assert_eq!(evidence["line"], 20);
        assert_eq!(evidence["genre"], "BinaryOperator");
        assert_eq!(evidence["replacement"], "<");
        assert_eq!(
            evidence["name"],
            "src/bar.rs:20:9: replace >= with < in is_valid"
        );
    }

    #[test]
    fn a_missed_mutant_with_no_function_still_produces_a_finding() {
        let text = r#"{
            "outcomes": [
                {
                    "scenario": { "Mutant": {
                        "name": "src/consts.rs:3:1: replace LIMIT with 0",
                        "package": "my-crate",
                        "file": "src/consts.rs",
                        "function": null,
                        "span": { "start": {"line": 3, "column": 1}, "end": {"line": 3, "column": 10} },
                        "replacement": "0",
                        "genre": "FnValue"
                    }},
                    "summary": "MissedMutant",
                    "log_path": "missed.log",
                    "diff_path": "missed.diff",
                    "phase_results": []
                }
            ],
            "total_mutants": 1,
            "missed": 1,
            "caught": 0,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:05:00Z",
            "cargo_mutants_version": "25.0.0"
        }"#;

        let report = parse_mutants_report(text);

        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.location.file, PathBuf::from("src/consts.rs"));
        assert_eq!(finding.location.line, 3);
        assert_eq!(finding.location.item_path, "src/consts.rs:3");
        assert!(finding.evidence.as_ref().unwrap()["function"].is_null());
    }

    #[test]
    fn invalid_json_yields_an_empty_report_rather_than_panicking() {
        let report = parse_mutants_report("this is not json");
        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn a_missing_outcomes_key_yields_an_empty_report() {
        let report = parse_mutants_report("{}");
        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn an_entry_missing_a_required_field_is_skipped_not_fatal() {
        let text = r#"{
            "outcomes": [
                {
                    "summary": "MissedMutant",
                    "log_path": "missed.log",
                    "diff_path": "missed.diff",
                    "phase_results": []
                },
                {
                    "scenario": { "Mutant": {
                        "name": "src/ok.rs:1:1: replace ok with false",
                        "package": "my-crate",
                        "file": "src/ok.rs",
                        "function": null,
                        "span": { "start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 5} },
                        "replacement": "false",
                        "genre": "FnValue"
                    }},
                    "summary": "MissedMutant",
                    "log_path": "missed2.log",
                    "diff_path": "missed2.diff",
                    "phase_results": []
                }
            ],
            "total_mutants": 2,
            "missed": 2,
            "caught": 0,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:05:00Z",
            "cargo_mutants_version": "25.0.0"
        }"#;

        let report = parse_mutants_report(text);

        // The malformed entry (missing `scenario`) is skipped, so only one
        // finding is produced even though `missed` declares 2 — a real,
        // reported discrepancy, not a silent drop.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].location.file, PathBuf::from("src/ok.rs"));
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("missed=2"));
    }

    #[test]
    fn read_mutants_report_errors_clearly_for_a_missing_file() {
        let dir = TempDir::new("mutants-missing-file");
        let err = read_mutants_report(&dir.join("nope.json")).unwrap_err();
        assert!(err.to_string().contains("failed to read file"));
    }

    // -- registry example --

    /// The registry's curated `example.before` for `mutation-survivor` (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// same drift guard as
    /// `advisories::known_vulnerability_registry_example_still_triggers_the_rule`.
    #[test]
    fn mutation_survivor_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MUTATION_SURVIVOR_RULE)
            .expect("mutation-survivor has a registry entry")
            .example
            .expect("mutation-survivor has a curated example")
            .before;

        let report = parse_mutants_report(example);

        assert_eq!(
            report.findings.len(),
            1,
            "curated example must parse to exactly one mutation-survivor finding"
        );
        assert_eq!(report.findings[0].rule, MUTATION_SURVIVOR_RULE);
    }
}
