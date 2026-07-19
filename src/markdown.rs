//! Markdown rendering of baseline/audit deltas (todo.md §7) — the
//! PR-comment use case: a compact verdict + gates + per-finding table that
//! reads well pasted into a GitHub comment. Pure functions over the
//! already-computed [`Delta`]; the CLI only writes the returned string.
//! Deliberately not a general report format — commands without a delta
//! reject `--format markdown` instead of producing half-baked output.

use std::fmt::Write;

use crate::baseline::{Delta, TriVerdict, Verdict};
use crate::finding::{Finding, Severity};
use crate::gate::{GateVerdict, RatioGate};

/// One named gate slot of the audit output: the evaluated gate, or `None`
/// plus the threshold flag that would enable it — a skipped gate stays
/// visible (todo.md §6), never a silent pass.
pub struct GateSlot<'a> {
    pub name: &'a str,
    pub threshold_flag: &'a str,
    pub gate: Option<&'a RatioGate>,
}

/// `audit --since` as Markdown: verdict, every gate (including
/// not-evaluated ones), then the delta table.
pub fn render_audit(delta: &Delta, verdict: TriVerdict, gates: &[GateSlot<'_>]) -> String {
    let verdict_label = match verdict {
        TriVerdict::Pass => "pass",
        TriVerdict::Warn => "warn",
        TriVerdict::Fail => "fail",
    };
    let mut out = format!("**verdict: {verdict_label}**\n\n");
    for slot in gates {
        match slot.gate {
            Some(gate) => {
                let gate_verdict = match gate.verdict {
                    GateVerdict::Pass => "pass",
                    GateVerdict::Fail => "fail",
                    GateVerdict::NotEvaluatedSmallSample => "not_evaluated_small_sample",
                };
                writeln!(
                    out,
                    "- gate `{}`: {gate_verdict} — {}/{} (min sample {}, max ratio {})",
                    gate.name,
                    gate.numerator,
                    gate.sample_size,
                    gate.minimum_sample,
                    gate.max_ratio
                )
                .unwrap();
            }
            None => writeln!(
                out,
                "- gate `{}`: not evaluated (pass --audit-min-sample and {} to enable)",
                slot.name, slot.threshold_flag
            )
            .unwrap(),
        }
    }
    out.push('\n');
    push_delta_body(&mut out, delta);
    out
}

/// A baseline comparison (`--baseline`) as the same compact Markdown delta,
/// with the two-state verdict every non-audit command uses.
pub fn render_delta(delta: &Delta, verdict: Verdict) -> String {
    let verdict_label = match verdict {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
    };
    let mut out = format!("**verdict: {verdict_label}**\n\n");
    push_delta_body(&mut out, delta);
    out
}

fn push_delta_body(out: &mut String, delta: &Delta) {
    writeln!(
        out,
        "unchanged: {} — resolved: {}",
        delta.unchanged_count,
        delta.resolved.len()
    )
    .unwrap();
    let (gating, advisory): (Vec<&Finding>, Vec<&Finding>) = delta
        .code_introduced
        .iter()
        .partition(|finding| finding.is_gating());
    push_section(out, "code-introduced", &gating);
    push_section(
        out,
        "code-introduced advisory (heuristic — no verdict effect)",
        &advisory,
    );
    let rule_introduced: Vec<&Finding> = delta.rule_introduced.iter().collect();
    push_section(
        out,
        "rule-introduced (protected, does not fail)",
        &rule_introduced,
    );
}

fn push_section(out: &mut String, title: &str, findings: &[&Finding]) {
    write!(out, "\n### {title}: {}\n", findings.len()).unwrap();
    if findings.is_empty() {
        return;
    }
    out.push_str("\n| rule | severity | location | item |\n|---|---|---|---|\n");
    for finding in findings {
        writeln!(
            out,
            "| {} | {} | {}:{} | {} |",
            finding.rule,
            severity_label(finding.severity),
            crate::sarif::artifact_uri(&finding.location.file),
            finding.location.line,
            finding.location.item_path
        )
        .unwrap();
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Fail => "fail",
        Severity::Warn => "warn",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::finding::{EvidenceClass, Location, OneBasedLine, Origin};

    fn finding(
        rule: &str,
        severity: Severity,
        class: EvidenceClass,
        file: &str,
        line: usize,
        item: &str,
    ) -> Finding {
        Finding::new(
            format!("{rule}:{file}:{line}"),
            rule.to_string(),
            severity,
            Location {
                file: PathBuf::from(file),
                line: OneBasedLine::new(line).unwrap(),
                item_path: item.to_string(),
            },
            class,
            Origin::Code,
            None,
        )
    }

    #[test]
    fn render_audit_golden() {
        let delta = Delta {
            code_introduced: vec![
                finding(
                    "duplicate-code",
                    Severity::Warn,
                    EvidenceClass::DerivedFact,
                    "src/a.rs",
                    3,
                    "foo",
                ),
                finding(
                    "hotspot",
                    Severity::Info,
                    EvidenceClass::Heuristic,
                    "src/b.rs",
                    1,
                    "src/b.rs",
                ),
            ],
            rule_introduced: vec![finding(
                "generic-naming",
                Severity::Warn,
                EvidenceClass::DerivedFact,
                "src/c.rs",
                7,
                "handle_data",
            )],
            resolved: Vec::new(),
            unchanged_count: 4,
        };
        let evaluated = crate::gate::ratio_gate("duplication-ratio", 3, 100, 1, 0.0);
        let gates = [
            GateSlot {
                name: "duplication-ratio",
                threshold_flag: "--max-duplication-ratio",
                gate: Some(&evaluated),
            },
            GateSlot {
                name: "suppression-debt-ratio",
                threshold_flag: "--max-suppression-ratio",
                gate: None,
            },
        ];

        let text = render_audit(&delta, TriVerdict::Warn, &gates);

        assert_eq!(
            text,
            "\
**verdict: warn**

- gate `duplication-ratio`: fail — 3/100 (min sample 1, max ratio 0)
- gate `suppression-debt-ratio`: not evaluated (pass --audit-min-sample and --max-suppression-ratio to enable)

unchanged: 4 — resolved: 0

### code-introduced: 1

| rule | severity | location | item |
|---|---|---|---|
| duplicate-code | warn | src/a.rs:3 | foo |

### code-introduced advisory (heuristic — no verdict effect): 1

| rule | severity | location | item |
|---|---|---|---|
| hotspot | info | src/b.rs:1 | src/b.rs |

### rule-introduced (protected, does not fail): 1

| rule | severity | location | item |
|---|---|---|---|
| generic-naming | warn | src/c.rs:7 | handle_data |
"
        );
    }

    #[test]
    fn render_delta_uses_the_two_state_verdict_and_skips_empty_tables() {
        let delta = Delta {
            code_introduced: Vec::new(),
            rule_introduced: Vec::new(),
            resolved: Vec::new(),
            unchanged_count: 2,
        };

        let text = render_delta(&delta, Verdict::Pass);

        assert_eq!(
            text,
            "\
**verdict: pass**

unchanged: 2 — resolved: 0

### code-introduced: 0

### code-introduced advisory (heuristic — no verdict effect): 0

### rule-introduced (protected, does not fail): 0
"
        );
    }

    #[test]
    fn table_locations_use_forward_slashes_for_windows_style_paths() {
        let delta = Delta {
            code_introduced: vec![finding(
                "duplicate-code",
                Severity::Warn,
                EvidenceClass::DerivedFact,
                r"src\win\a.rs",
                3,
                "foo",
            )],
            rule_introduced: Vec::new(),
            resolved: Vec::new(),
            unchanged_count: 0,
        };

        let text = render_delta(&delta, Verdict::Fail);
        assert!(text.contains("| src/win/a.rs:3 |"), "text: {text}");
    }
}
