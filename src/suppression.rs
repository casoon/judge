//! Generic inline suppression via a `judge-ignore` marker comment (see
//! todo.md §5 "Suppression": the three-tier precedence is baseline, then
//! config-rule, then inline). The full syntax: `// judge-ignore: <rule-id> — <reason>`.
//!
//! Unlike `judge-dupe-off`/`judge-dupe-on` in `duplication.rs` (a
//! duplication-only *range* suppression scanned once per file), this
//! applies to any [`Finding`] regardless of rule: [`apply_inline_suppressions`]
//! matches a finding's `rule` against the comment's rule-id, scoped to the
//! finding's own source line or the line immediately before it (mirroring
//! ESLint's `disable-line`/`disable-next-line` duality). A rule-id that
//! never matches a real rule simply never suppresses anything — that's not
//! an error (future work, not this module's scope).
//!
//! A missing or empty reason after the separator is a hard config error
//! (todo.md §5: "Das Fehlen der Begründung ist ein Syntaxfakt; eine
//! Wartbarkeitsschuld ist die konfigurierte Interpretation"), matching
//! [`crate::duplication::DuplicationError::MissingSuppressionReason`]'s
//! precedent for `judge-dupe-off`.
//!
//! Note for anyone editing this module's own comments: a doc line that
//! contains the marker text followed by a colon but not a complete,
//! validly-formed example reads as a broken suppression directive when
//! `judge` analyzes its own source (as every example above is) — keep any
//! such mention either colon-free in prose or a single complete, valid
//! example on one physical line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::finding::Finding;

const MARKER: &str = "judge-ignore:";
const SEPARATORS: [&str; 3] = ["—", "--", "-"];

#[derive(Debug)]
pub enum SuppressionError {
    Io(PathBuf, std::io::Error),
    /// A `judge-ignore` marker with no separator, an unrecognized separator,
    /// or a separator with nothing after it. Carries the file, 1-based
    /// line, and the raw line for diagnosis.
    MissingReason(PathBuf, usize, String),
}

impl std::fmt::Display for SuppressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::MissingReason(path, line, raw) => write!(
                f,
                "{}:{line}: `judge-ignore` requires a reason, e.g. `// judge-ignore: <rule-id> — <reason>` (found: `{}`)",
                path.display(),
                raw.trim()
            ),
        }
    }
}

impl std::error::Error for SuppressionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::MissingReason(..) => None,
        }
    }
}

/// One parsed `judge-ignore` comment: the rule it targets. The reason itself
/// is only checked for non-emptiness here, not carried further — its
/// purpose is to make the suppression a deliberate, documented decision,
/// not to be machine-read.
struct Suppression {
    rule_id: String,
}

/// Parses a single source line for a `judge-ignore` marker comment, whose
/// full syntax is `// judge-ignore: <rule-id> — <reason>` (the separator may
/// also be spelled `--` or `-`, whitespace-delimited on both sides).
/// Returns `Ok(None)` for lines without the marker at all; `Err` for a
/// marker with no valid separator or an empty reason.
fn parse_suppression(
    path: &Path,
    line_number: usize,
    text: &str,
) -> Result<Option<Suppression>, SuppressionError> {
    let Some(at) = text.find(MARKER) else {
        return Ok(None);
    };
    let rest = &text[at + MARKER.len()..];
    let words: Vec<&str> = rest.split_whitespace().collect();
    let missing_reason = || {
        SuppressionError::MissingReason(path.to_path_buf(), line_number, text.trim().to_string())
    };
    let [rule_id, sep, reason @ ..] = words.as_slice() else {
        return Err(missing_reason());
    };
    if !SEPARATORS.contains(sep) || reason.is_empty() {
        return Err(missing_reason());
    }
    Ok(Some(Suppression {
        rule_id: (*rule_id).to_string(),
    }))
}

/// Filters `findings`, dropping any whose `rule` matches a `judge-ignore`
/// comment on its own source line or the line immediately before it.
/// Suppressed findings are dropped entirely — before baseline diff, verdict,
/// or score computation, as if they had never fired (todo.md §5) — the
/// returned count is the only trace they leave.
///
/// The finding's own line accepts a *trailing* comment after real code
/// (`disable-line`-style); the preceding line only counts if it is a
/// comment on its own (`disable-next-line`-style) — otherwise a trailing
/// comment written for whatever code sits on that previous line would leak
/// forward and suppress the finding below it too.
///
/// Reads each affected file at most once regardless of how many findings it
/// holds, caching lines per file for the duration of one filter pass.
pub fn apply_inline_suppressions(
    findings: Vec<Finding>,
    workspace_root: &Path,
) -> Result<(Vec<Finding>, usize), SuppressionError> {
    let mut lines_by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = 0usize;

    for finding in findings {
        let path = workspace_root.join(&finding.location.file);
        if !lines_by_file.contains_key(&path) {
            let content = std::fs::read_to_string(&path)
                .map_err(|err| SuppressionError::Io(path.clone(), err))?;
            lines_by_file.insert(path.clone(), content.lines().map(str::to_string).collect());
        }
        let lines = &lines_by_file[&path];

        let finding_line = finding.location.line.get();
        let rule = finding.rule.as_str();
        let matched = suppression_matches(&path, lines, finding_line, false, rule)?
            || suppression_matches(&path, lines, finding_line.saturating_sub(1), true, rule)?;

        if matched {
            suppressed += 1;
        } else {
            kept.push(finding);
        }
    }

    Ok((kept, suppressed))
}

/// Whether line `line_number` (1-based; `0` means "no such line") carries a
/// `judge-ignore` comment targeting `rule`. `require_comment_only` enforces
/// the `disable-next-line` restriction: the line must be nothing but a `//`
/// comment, not a trailing comment after real code.
fn suppression_matches(
    path: &Path,
    lines: &[String],
    line_number: usize,
    require_comment_only: bool,
    rule: &str,
) -> Result<bool, SuppressionError> {
    if line_number == 0 {
        return Ok(false);
    }
    let Some(text) = lines.get(line_number - 1) else {
        return Ok(false);
    };
    if require_comment_only && !text.trim_start().starts_with("//") {
        return Ok(false);
    }
    let Some(suppression) = parse_suppression(path, line_number, text)? else {
        return Ok(false);
    };
    Ok(suppression.rule_id == rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{EvidenceClass, Location, OneBasedLine, Origin, Severity};
    use crate::test_util::TempDir;

    fn finding_at(rule: &str, file: PathBuf, line: usize) -> Finding {
        Finding::new(
            format!("{rule}:{}:{line}", file.display()),
            rule,
            Severity::Warn,
            Location {
                file,
                line: OneBasedLine::new(line).unwrap(),
                item_path: "fixture::item".to_string(),
            },
            EvidenceClass::DerivedFact,
            Origin::Code,
            None,
        )
    }

    /// The `judge-ignore` marker text, assembled at runtime rather than
    /// written as one literal in this file — a fixture string containing it
    /// verbatim (especially the deliberately-malformed, missing-reason
    /// cases below) would itself read as a real directive when `judge`
    /// analyzes its own `suppression.rs`, wherever a `duplicate-code`/
    /// `legacy-freeze`/etc. finding happens to land on or next to that line.
    fn ignore_marker() -> String {
        ["judge", "-ignore:"].concat()
    }

    /// (a) A `judge-ignore` comment trailing the finding's own line
    /// suppresses a matching finding.
    #[test]
    fn suppresses_a_finding_via_a_same_line_trailing_comment() {
        let dir = TempDir::new("suppression-same-line");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    let _ = 1; // {} some-rule — best-effort cleanup\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 2);
        let (kept, suppressed) = apply_inline_suppressions(vec![finding], &dir).unwrap();
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
    }

    /// (b) A `judge-ignore` comment on the line immediately *before* the
    /// finding's line also suppresses it (ESLint `disable-next-line` style).
    #[test]
    fn suppresses_a_finding_via_a_preceding_line_comment() {
        let dir = TempDir::new("suppression-prev-line");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    // {} some-rule — best-effort cleanup\n    let _ = 1;\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 3);
        let (kept, suppressed) = apply_inline_suppressions(vec![finding], &dir).unwrap();
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
    }

    /// (c) A comment naming a different rule than the finding's own doesn't
    /// suppress it.
    #[test]
    fn does_not_suppress_a_finding_when_the_rule_id_differs() {
        let dir = TempDir::new("suppression-rule-mismatch");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    let _ = 1; // {} other-rule — unrelated\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 2);
        let (kept, suppressed) = apply_inline_suppressions(vec![finding], &dir).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 0);
    }

    /// (d) A `judge-ignore` comment with no reason at all is a hard error.
    #[test]
    fn missing_reason_is_a_hard_error() {
        let dir = TempDir::new("suppression-missing-reason");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    let _ = 1; // {} some-rule\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 2);
        let err = apply_inline_suppressions(vec![finding], &dir).unwrap_err();
        match err {
            SuppressionError::MissingReason(_, line, _) => assert_eq!(line, 2),
            other => panic!("expected MissingReason, got {other:?}"),
        }
    }

    /// (d) A separator with nothing after it is also a hard error.
    #[test]
    fn separator_without_a_reason_is_a_hard_error() {
        let dir = TempDir::new("suppression-empty-reason");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    let _ = 1; // {} some-rule —\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 2);
        let err = apply_inline_suppressions(vec![finding], &dir).unwrap_err();
        assert!(matches!(err, SuppressionError::MissingReason(..)));
    }

    /// (e) All three separator spellings are accepted.
    #[test]
    fn all_three_separator_spellings_work() {
        for sep in ["—", "--", "-"] {
            let dir = TempDir::new("suppression-separator");
            let file = dir.join("lib.rs");
            std::fs::write(
                &file,
                format!(
                    "fn main() {{\n    let _ = 1; // {} some-rule {sep} reason\n}}\n",
                    ignore_marker()
                ),
            )
            .unwrap();

            let finding = finding_at("some-rule", file, 2);
            let (kept, suppressed) = apply_inline_suppressions(vec![finding], &dir).unwrap();
            assert!(kept.is_empty(), "separator {sep:?} did not suppress");
            assert_eq!(suppressed, 1);
        }
    }

    /// (g) Multiple findings in the same file are all handled correctly in
    /// one pass (the per-file line cache is exercised, not just a single
    /// finding).
    #[test]
    fn multiple_findings_in_one_file_are_each_evaluated_independently() {
        let dir = TempDir::new("suppression-multi-finding");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{\n    let _ = 1; // {} some-rule — cleanup\n    let _ = 2;\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let findings = vec![
            finding_at("some-rule", file.clone(), 2),
            finding_at("some-rule", file, 3),
        ];
        let (kept, suppressed) = apply_inline_suppressions(findings, &dir).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(suppressed, 1);
        assert_eq!(kept[0].location.line, 3);
    }

    /// A finding on line 1 has no preceding line to check — must not panic
    /// on the line-0 underflow.
    #[test]
    fn a_finding_on_the_first_line_only_checks_its_own_line() {
        let dir = TempDir::new("suppression-first-line");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "fn main() {{}} // {} some-rule — cleanup\n",
                ignore_marker()
            ),
        )
        .unwrap();

        let finding = finding_at("some-rule", file, 1);
        let (kept, suppressed) = apply_inline_suppressions(vec![finding], &dir).unwrap();
        assert!(kept.is_empty());
        assert_eq!(suppressed, 1);
    }
}
