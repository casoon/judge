//! Markdown rendering of baseline comparison deltas (todo.md §7) — the
//! PR-comment use case: a compact verdict + gates + per-finding table that
//! reads well pasted into a GitHub comment. Pure functions over the
//! already-computed [`Delta`]; the CLI only writes the returned string.
//! Deliberately not a general report format — commands without a delta
//! reject `--format markdown` instead of producing half-baked output.

use std::fmt::Write;

use crate::baseline::{Delta, Verdict, partition_gating};
use crate::finding::{Finding, Severity};

/// An artifact baseline comparison as a compact Markdown delta.
pub fn render_delta(delta: &Delta, verdict: Verdict) -> String {
    let mut out = format!("**verdict: {}**\n\n", verdict.label());
    push_delta_body(&mut out, delta);
    out
}

fn push_delta_body(out: &mut String, delta: &Delta) {
    writeln!(
        out,
        "unchanged: {} — resolved: {} — severity changed: {}",
        delta.unchanged_count,
        delta.resolved.len(),
        delta.severity_changed.len(),
    )
    .unwrap();
    let (gating, advisory) = partition_gating(&delta.introduced);
    push_section(out, "introduced", &gating);
    push_section(
        out,
        "introduced advisory (heuristic — no verdict effect)",
        &advisory,
    );
    if !delta.severity_changed.is_empty() {
        writeln!(
            out,
            "\n### severity changed: {}",
            delta.severity_changed.len()
        )
        .unwrap();
        out.push_str("\n| rule | previous | current | location | item |\n|---|---|---|---|---|\n");
        for change in &delta.severity_changed {
            let (rule, before, after) = change.transition();
            writeln!(
                out,
                "| {} | {} | {} | {}:{} | {} |",
                rule,
                severity_label(before),
                severity_label(after),
                crate::sarif::artifact_uri(&change.after.location.file),
                change.after.location.line,
                change.after.location.item_path
            )
            .unwrap();
        }
    }
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
    fn render_delta_uses_the_two_state_verdict_and_skips_empty_tables() {
        let delta = Delta {
            introduced: Vec::new(),
            code_introduced: Vec::new(),
            rule_introduced: Vec::new(),
            resolved: Vec::new(),
            severity_changed: Vec::new(),
            unchanged_count: 2,
        };

        let text = render_delta(&delta, Verdict::Pass);

        assert_eq!(
            text,
            "\
**verdict: pass**

unchanged: 2 — resolved: 0 — severity changed: 0

### introduced: 0

### introduced advisory (heuristic — no verdict effect): 0
"
        );
    }

    #[test]
    fn table_locations_use_forward_slashes_for_windows_style_paths() {
        let delta = Delta {
            introduced: vec![finding(
                "duplicate-code",
                Severity::Warn,
                EvidenceClass::DerivedFact,
                r"src\win\a.rs",
                3,
                "foo",
            )],
            code_introduced: Vec::new(),
            rule_introduced: Vec::new(),
            resolved: Vec::new(),
            severity_changed: Vec::new(),
            unchanged_count: 0,
        };

        let text = render_delta(&delta, Verdict::Fail);
        assert!(text.contains("| src/win/a.rs:3 |"), "text: {text}");
    }
}
