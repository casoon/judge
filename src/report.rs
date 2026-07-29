//! Shared presentation model for human-readable command reports (issue
//! #12): a command builds a [`Report`] from its own domain-specific status
//! lines and finding groups, then hands it to [`Report::write_tty`] instead
//! of hand-rolling terminal layout. JSON remains the exhaustive automation
//! contract; this model covers only the human-readable TTY views.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use crate::finding::{Finding, Severity};
use runemark::{
    ColorMode, Confidence, Console, DetailLevel, Finding as TerminalFinding,
    FindingGroup as TerminalFindingGroup, Location as TerminalLocation, Metric, NextStep,
    Report as TerminalReport, ScopeNote as TerminalScopeNote, Tone, Verdict,
};

/// Rule families shown per group in the compact view before collapsing into
/// an "… N more" line.
const RULE_SUMMARY_LIMIT: usize = 12;

/// The shared sections of a human-readable report: overall status,
/// scope/completeness, one or more finding groups, and next steps.
pub struct Report<'a> {
    status_lines: Vec<String>,
    scope_notes: Vec<ScopeNote<'a>>,
    groups: Vec<FindingGroup<'a>>,
    next_steps: Vec<String>,
}

struct ScopeNote<'a> {
    heading: String,
    items: Vec<Cow<'a, str>>,
}

struct FindingGroup<'a> {
    heading: String,
    findings: Vec<&'a Finding>,
    /// Marks the compact view's "… N more" collapse line as advisory.
    advisory: bool,
}

impl<'a> Report<'a> {
    pub fn new(status_lines: Vec<String>) -> Self {
        Self {
            status_lines,
            scope_notes: Vec::new(),
            groups: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    /// Adds a scope/completeness note (analysis errors, unavailable
    /// history, …). A no-op when `items` is empty, so callers do not need
    /// their own emptiness check.
    pub fn with_scope_note(mut self, heading: impl Into<String>, items: Vec<Cow<'a, str>>) -> Self {
        if !items.is_empty() {
            self.scope_notes.push(ScopeNote {
                heading: heading.into(),
                items,
            });
        }
        self
    }

    /// Adds a named finding group (e.g. evidence-backed vs advisory).
    pub fn with_group(
        mut self,
        heading: impl Into<String>,
        findings: Vec<&'a Finding>,
        advisory: bool,
    ) -> Self {
        self.groups.push(FindingGroup {
            heading: heading.into(),
            findings,
            advisory,
        });
        self
    }

    pub fn with_next_steps(mut self, next_steps: Vec<String>) -> Self {
        self.next_steps = next_steps;
        self
    }

    /// Renders the compact decision summary (default), or with `details`
    /// the exhaustive per-finding listing (e.g. `--details`).
    pub fn write_tty(
        &self,
        out: &mut dyn Write,
        workspace_root: &Path,
        details: bool,
    ) -> std::io::Result<()> {
        self.write_tty_colored(out, workspace_root, details, false)
    }

    /// Renders the TTY view with an explicit color choice. The CLI resolves
    /// `auto`/`always`/`never` before calling this method.
    pub fn write_tty_colored(
        &self,
        out: &mut dyn Write,
        workspace_root: &Path,
        details: bool,
        color: bool,
    ) -> std::io::Result<()> {
        let console = Console::new(
            if color {
                ColorMode::Always
            } else {
                ColorMode::Never
            },
            color,
        );
        write!(
            out,
            "{}",
            self.terminal_report(workspace_root, details)
                .render(console)
        )?;
        Ok(())
    }

    fn terminal_report(&self, workspace_root: &Path, details: bool) -> TerminalReport {
        let evidence_count = self
            .groups
            .iter()
            .filter(|group| !group.advisory)
            .map(|group| group.findings.len())
            .sum::<usize>();
        let advisory_count = self
            .groups
            .iter()
            .filter(|group| group.advisory)
            .map(|group| group.findings.len())
            .sum::<usize>();
        let has_fail = self
            .groups
            .iter()
            .filter(|group| !group.advisory)
            .flat_map(|group| group.findings.iter())
            .any(|finding| finding.severity == Severity::Fail);
        let verdict = match (evidence_count, has_fail, advisory_count) {
            (0, _, 0) => Verdict::Passed,
            (0, _, _) => Verdict::Info,
            (_, true, _) => Verdict::Failed,
            _ => Verdict::Warning,
        };
        let title = self
            .status_lines
            .first()
            .map(String::as_str)
            .unwrap_or("Judge summary");

        let mut report = TerminalReport::new(title, verdict)
            .with_detail_level(if details {
                DetailLevel::Detailed
            } else {
                DetailLevel::Compact
            })
            .add_metric(
                Metric::new("Evidence", evidence_count.to_string()).with_tone(if has_fail {
                    Tone::Error
                } else if evidence_count > 0 {
                    Tone::Warning
                } else {
                    Tone::Success
                }),
            )
            .add_metric(Metric::new("Advisory", advisory_count.to_string()).with_tone(Tone::Info));

        let context = self
            .status_lines
            .iter()
            .skip(1)
            .filter(|line| {
                !line.contains("evidence-backed findings") && !line.contains("advisory heuristics")
            })
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();
        if !context.is_empty() {
            report = report.add_scope_note(TerminalScopeNote::new("Analysis context", context));
        }
        for note in &self.scope_notes {
            report = report.add_scope_note(TerminalScopeNote::new(
                note.heading.clone(),
                note.items.iter().map(ToString::to_string).collect(),
            ));
        }
        for group in &self.groups {
            let terminal_group = group.findings.iter().fold(
                TerminalFindingGroup::new(&group.heading).with_advisory(group.advisory),
                |terminal_group, finding| {
                    terminal_group.add_finding(terminal_finding(workspace_root, finding))
                },
            );
            report = report.add_group(terminal_group);
        }
        for step in &self.next_steps {
            let (text, command) = split_next_step(step);
            let step = command
                .map(|command| NextStep::new(command).with_command(text))
                .unwrap_or_else(|| NextStep::new(text));
            report = report.add_next_step(step);
        }
        report
    }

    /// Renders the shared model as Markdown for review handoff (issue #14):
    /// an executive summary (status, scope, completeness), the same
    /// deterministic per-rule grouping as the TTY compact view (never a raw
    /// per-finding dump), and a next-steps section.
    pub fn write_markdown(&self, workspace_root: &Path) -> String {
        let mut out = String::new();
        if let Some((heading, status)) = self.status_lines.split_first() {
            let _ = writeln!(out, "# {heading}\n");
            for line in status {
                let _ = writeln!(out, "- {}", line.trim());
            }
        }
        for note in &self.scope_notes {
            let _ = writeln!(out, "\n**{}**\n", note.heading);
            for item in &note.items {
                let _ = writeln!(out, "- {item}");
            }
        }
        for group in &self.groups {
            write_markdown_group(&mut out, workspace_root, group);
        }
        if !self.next_steps.is_empty() {
            let _ = writeln!(out, "\n## Next steps\n");
            for step in &self.next_steps {
                // Next-step text is column-padded for the TTY's monospace
                // layout; collapse that padding for prose rendering here.
                let collapsed = step.split_whitespace().collect::<Vec<_>>().join(" ");
                let _ = writeln!(out, "- {collapsed}");
            }
        }
        out
    }
}

/// Renders a focused, current-state command with Runemark's standard terminal
/// conventions. JSON and SARIF remain the exhaustive machine contracts; this
/// is the shared concise human view for commands that return only findings.
pub fn write_findings_tty(
    out: &mut dyn Write,
    workspace_root: &Path,
    title: impl Into<String>,
    findings: &[Finding],
    errors: &[String],
) -> std::io::Result<()> {
    let (gating, advisory): (Vec<_>, Vec<_>) =
        findings.iter().partition(|finding| finding.is_gating());
    let error_items = errors
        .iter()
        .map(|error| Cow::Borrowed(error.as_str()))
        .collect();
    Report::new(vec![title.into()])
        .with_scope_note(
            format!("Analysis incomplete: {} error(s)", errors.len()),
            error_items,
        )
        .with_group("Evidence-backed findings", gating, false)
        .with_group("Advisory heuristics", advisory, true)
        .with_next_steps(vec![
            "cargo judge --format json      full machine-readable evidence".to_string(),
        ])
        .write_tty(out, workspace_root, false)
}

/// Groups `findings` by rule, worst-count first (ties broken
/// alphabetically) — the one deterministic grouping shared by every
/// rendering of this model.
fn rule_groups<'a>(findings: &[&'a Finding]) -> Vec<(&'a str, usize, &'a Finding)> {
    let mut grouped = std::collections::BTreeMap::<&str, (usize, &Finding)>::new();
    for finding in findings {
        let entry = grouped
            .entry(finding.rule.as_str())
            .or_insert((0, *finding));
        entry.0 += 1;
    }
    let mut groups: Vec<_> = grouped
        .into_iter()
        .map(|(rule, (count, example))| (rule, count, example))
        .collect();
    groups.sort_by(|(left_rule, left_count, _), (right_rule, right_count, _)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_rule.cmp(right_rule))
    });
    groups
}

fn write_markdown_group(out: &mut String, workspace_root: &Path, group: &FindingGroup<'_>) {
    if group.findings.is_empty() {
        return;
    }

    let groups = rule_groups(&group.findings);
    let _ = writeln!(out, "\n## {}: {}\n", group.heading, group.findings.len());
    let _ = writeln!(out, "| rule | count | representative location |");
    let _ = writeln!(out, "|---|---|---|");
    for (rule, count, example) in groups.iter().take(RULE_SUMMARY_LIMIT) {
        let path = display_workspace_path(workspace_root, &example.location.file);
        let _ = writeln!(
            out,
            "| {rule} | {count} | {path}:{} ({}) |",
            example.location.line,
            display_item_path(workspace_root, &example.location.item_path)
        );
    }
    if groups.len() > RULE_SUMMARY_LIMIT {
        let _ = writeln!(
            out,
            "\n… {} more rule families{}",
            groups.len() - RULE_SUMMARY_LIMIT,
            if group.advisory { " (advisory)" } else { "" }
        );
    }
}

fn split_next_step(step: &str) -> (&str, Option<&str>) {
    let Some((command, description)) = step.split_once("  ") else {
        return (step, None);
    };
    let description = description.trim_start();
    (command, (!description.is_empty()).then_some(description))
}

fn terminal_finding(workspace_root: &Path, finding: &Finding) -> TerminalFinding {
    let tone = match finding.severity {
        Severity::Fail => Tone::Error,
        Severity::Warn => Tone::Warning,
        Severity::Info => Tone::Info,
    };
    let confidence = if finding.is_gating() {
        Confidence::High
    } else {
        Confidence::Low
    };
    let item_path = display_item_path(workspace_root, &finding.location.item_path);
    let file =
        Path::new(&display_workspace_path(workspace_root, &finding.location.file).to_string())
            .to_path_buf();

    TerminalFinding::new(tone, format!("{} in {item_path}", finding.rule))
        .with_rule_id(finding.rule.to_string())
        .with_location(TerminalLocation::file_line(
            file,
            finding.location.line.get(),
        ))
        .with_confidence(confidence)
}

/// Renders `path` relative to the workspace root, matching the standardized
/// relative-path display used across shared-model reports (issue #13).
pub fn display_workspace_path<'a>(workspace_root: &Path, path: &'a Path) -> std::path::Display<'a> {
    path.strip_prefix(workspace_root).unwrap_or(path).display()
}

fn display_item_path<'a>(workspace_root: &Path, item_path: &'a str) -> Cow<'a, str> {
    Path::new(item_path)
        .strip_prefix(workspace_root)
        .map(|path| Cow::Owned(path.display().to_string()))
        .unwrap_or_else(|_| Cow::Borrowed(item_path))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::finding::{EvidenceClass, Location, OneBasedLine, Origin};

    fn finding(rule: &str, file: &str, line: usize) -> Finding {
        Finding::new(
            format!("{rule}:{file}:{line}"),
            rule.to_string(),
            Severity::Warn,
            Location {
                file: PathBuf::from(file),
                line: OneBasedLine::new(line).unwrap(),
                item_path: format!("{file}::item"),
            },
            EvidenceClass::DerivedFact,
            Origin::Code,
            None,
        )
    }

    #[test]
    fn compact_view_orders_sections_status_then_groups_then_next_steps() {
        let a = finding("rule-a", "src/a.rs", 1);
        let report = Report::new(vec!["Judge summary".to_string()])
            .with_group("Evidence-backed findings", vec![&a], false)
            .with_next_steps(vec!["cargo judge --details".to_string()]);

        let mut out = Vec::new();
        report
            .write_tty(&mut out, Path::new("/work"), false)
            .unwrap();
        let text = String::from_utf8(out).unwrap();

        let status_at = text.find("Judge summary").unwrap();
        let group_at = text.find("Evidence-backed findings").unwrap();
        let next_steps_at = text.find("Next steps").unwrap();
        assert!(
            status_at < group_at && group_at < next_steps_at,
            "sections must appear in status/groups/next-steps order: {text}"
        );
    }

    #[test]
    fn details_view_includes_each_finding() {
        let a = finding("rule-a", "src/a.rs", 1);
        let report = Report::new(vec!["Judge summary".to_string()])
            .with_group("Evidence-backed findings", vec![&a], false)
            .with_next_steps(vec!["cargo judge --details".to_string()]);

        let mut out = Vec::new();
        report
            .write_tty(&mut out, Path::new("/work"), true)
            .unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("rule-a in src/a.rs::item"), "{text}");
        assert!(text.contains("Next steps"), "{text}");
    }

    #[test]
    fn compact_view_preserves_the_command_provided_finding_order() {
        let a1 = finding("rule-a", "src/a.rs", 1);
        let a2 = finding("rule-a", "src/a.rs", 2);
        let b1 = finding("rule-b", "src/b.rs", 1);
        let z1 = finding("rule-z", "src/z.rs", 1);
        let report = Report::new(Vec::new()).with_group(
            "Evidence-backed findings",
            vec![&z1, &b1, &a1, &a2],
            false,
        );

        let mut out = Vec::new();
        report
            .write_tty(&mut out, Path::new("/work"), false)
            .unwrap();
        let text = String::from_utf8(out).unwrap();

        let z_at = text.find("rule-z").unwrap();
        let b_at = text.find("rule-b").unwrap();
        let a_at = text.find("rule-a").unwrap();
        assert!(
            z_at < b_at && b_at < a_at,
            "runemark must preserve the deterministic command order: {text}"
        );
        assert!(
            text.contains("Evidence: 4"),
            "expected summary metric: {text}"
        );
    }

    #[test]
    fn compact_view_collapses_rule_families_beyond_the_summary_limit() {
        let findings: Vec<Finding> = (0..RULE_SUMMARY_LIMIT + 3)
            .map(|i| finding(&format!("rule-{i:02}"), "src/a.rs", 1))
            .collect();
        let refs: Vec<&Finding> = findings.iter().collect();
        let report = Report::new(Vec::new()).with_group("Evidence-backed findings", refs, false);

        let mut out = Vec::new();
        report
            .write_tty(&mut out, Path::new("/work"), false)
            .unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            text.contains("... 12 more finding(s)"),
            "runemark must indicate compact-output truncation: {text}"
        );
    }

    #[test]
    fn colored_tty_view_uses_ansi_but_preserves_the_structured_text() {
        let a = finding("rule-a", "src/a.rs", 1);
        let report = Report::new(vec!["Judge summary".to_string()])
            .with_group("Evidence-backed findings", vec![&a], false)
            .with_next_steps(vec![
                "cargo judge --details          every finding and location".to_string(),
            ]);

        let mut out = Vec::new();
        report
            .write_tty_colored(&mut out, Path::new("/work"), false, true)
            .unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("\x1b["));
        assert!(text.contains("Evidence-backed findings"));
        assert!(text.contains("$ cargo judge --details"));
    }

    #[test]
    fn workspace_relative_paths_strip_the_workspace_root() {
        let root = Path::new("/work/repo");
        let path = Path::new("/work/repo/src/a.rs");
        assert_eq!(display_workspace_path(root, path).to_string(), "src/a.rs");
    }

    #[test]
    fn markdown_renders_an_executive_summary_grouped_findings_and_next_steps() {
        let a = finding("rule-a", "src/a.rs", 1);
        let b = finding("rule-b", "src/b.rs", 2);
        let report = Report::new(vec![
            "Judge summary".to_string(),
            "  1 evidence-backed findings · 1 advisory heuristics".to_string(),
        ])
        .with_scope_note(
            "History unavailable for 1 uncommitted file(s)",
            vec![Cow::Borrowed("src/uncommitted.rs")],
        )
        .with_group("Evidence-backed findings", vec![&a], false)
        .with_group(
            "Advisory heuristics (no verdict or score effect)",
            vec![&b],
            true,
        )
        .with_next_steps(vec![
            "cargo judge --details          every finding and location".to_string(),
        ]);

        let markdown = report.write_markdown(Path::new("/work"));

        assert!(
            markdown.starts_with("# Judge summary\n"),
            "executive summary must lead with a heading: {markdown}"
        );
        assert!(
            markdown.contains("- 1 evidence-backed findings · 1 advisory heuristics"),
            "status must render as summary bullets: {markdown}"
        );
        assert!(
            markdown.contains("**History unavailable for 1 uncommitted file(s)**"),
            "scope/completeness notes must render: {markdown}"
        );
        assert!(
            markdown.contains("## Evidence-backed findings: 1")
                && markdown.contains("| rule-a | 1 | src/a.rs:1"),
            "evidence-backed group must render as a counted table: {markdown}"
        );
        assert!(
            markdown.contains("## Advisory heuristics (no verdict or score effect): 1")
                && markdown.contains("| rule-b | 1 | src/b.rs:2"),
            "advisory group must render separately: {markdown}"
        );
        assert!(
            markdown.contains("## Next steps")
                && markdown.contains("- cargo judge --details every finding and location"),
            "next steps must render as a concise, collapsed bullet list: {markdown}"
        );
    }

    #[test]
    fn markdown_never_dumps_individual_findings_beyond_the_summary_limit() {
        let findings: Vec<Finding> = (0..RULE_SUMMARY_LIMIT + 3)
            .map(|i| finding(&format!("rule-{i:02}"), "src/a.rs", 1))
            .collect();
        let refs: Vec<&Finding> = findings.iter().collect();
        let report = Report::new(Vec::new()).with_group("Evidence-backed findings", refs, false);

        let markdown = report.write_markdown(Path::new("/work"));

        assert!(
            markdown.contains("… 3 more rule families"),
            "markdown must collapse beyond the limit rather than dumping every finding: {markdown}"
        );
    }
}
