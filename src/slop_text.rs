//! Raw-source-text scanning for the three `G3` rules (see todo.md §3.G G3)
//! that `syn` cannot see: `conversational-artifact`, `restating-comment`,
//! `step-comment-inflation`. `syn` discards regular `//`/`/* */` comments
//! entirely during parsing — only `///`/`//!` doc comments survive, desugared
//! into `#[doc = "..."]` attributes — so there is no AST node a `Visit`
//! implementation could hook into for a plain comment. This module instead
//! runs a small line-by-line scanner over the original source text,
//! independent of `syn::parse_file`, and is invoked once per file from
//! [`crate::slop::analyze_file`] alongside the `syn`-based [`crate::slop`]
//! checks.
//!
//! Two accepted v1 limitations, both documented again at their point of use
//! below: [`extract_comments`] does not handle nested `/* /* */ */` block
//! comments (Rust's own lexer nests them; this heuristic scanner doesn't),
//! and consecutive `//` lines are never joined into one logical comment
//! block — each line is scanned independently.

use std::path::Path;

use crate::finding::{Finding, Location, Origin, Severity};
use crate::slop::ItemSpan;

/// One `//`/`///`/`//!` or `/* */`/`/** */`/`/*! */` comment, as found by
/// [`extract_comments`].
struct CommentSpan {
    start_line: usize,
    end_line: usize,
    text: String,
    is_doc: bool,
}

/// Which comment marker [`find_comment_start`] found.
#[derive(PartialEq, Eq)]
enum CommentMarker {
    Line,
    Block,
}

/// Finds the earliest `//` or `/*` in `text` that isn't inside a string
/// literal. `in_string` is tracked with a simple unescaped-`"` toggle (a
/// backslash-count-parity check), not full Rust string-literal lexing — good
/// enough to keep `"http://example.com"` from being mistaken for a line
/// comment, not a general-purpose lexer.
fn find_comment_start(text: &str) -> Option<(usize, CommentMarker)> {
    let bytes = text.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            let mut backslashes = 0;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                backslashes += 1;
                j -= 1;
            }
            if backslashes % 2 == 0 {
                in_string = !in_string;
            }
            i += 1;
            continue;
        }
        if !in_string && c == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                return Some((i, CommentMarker::Line));
            }
            if bytes[i + 1] == b'*' {
                return Some((i, CommentMarker::Block));
            }
        }
        i += 1;
    }
    None
}

/// Single left-to-right, line-by-line scan of `source`, carrying an
/// `in_block_comment` flag across lines so a `/* ... */` that spans multiple
/// lines is still returned as one [`CommentSpan`]. Does NOT handle nested
/// `/* /* */ */` block comments — the first `*/` closes the outermost
/// comment, unlike `rustc`'s own nesting lexer. This is an accepted v1
/// limitation of a heuristic scanner, not a parser.
fn extract_comments(source: &str) -> Vec<CommentSpan> {
    let mut spans = Vec::new();
    let mut in_block_comment = false;
    let mut block_start_line = 0usize;
    let mut block_is_doc = false;
    let mut block_text = String::new();

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let mut rest = line;

        loop {
            if in_block_comment {
                if let Some(end) = rest.find("*/") {
                    let before = rest[..end].trim();
                    if !before.is_empty() {
                        block_text.push(' ');
                        block_text.push_str(before);
                    }
                    spans.push(CommentSpan {
                        start_line: block_start_line,
                        end_line: line_no,
                        text: block_text.trim().to_string(),
                        is_doc: block_is_doc,
                    });
                    in_block_comment = false;
                    block_text.clear();
                    rest = &rest[end + 2..];
                    continue;
                }
                let trimmed = rest.trim();
                if !trimmed.is_empty() {
                    block_text.push(' ');
                    block_text.push_str(trimmed);
                }
                break;
            }

            match find_comment_start(rest) {
                Some((pos, CommentMarker::Line)) => {
                    let marker = &rest[pos..];
                    let is_doc = (marker.starts_with("///") && !marker.starts_with("////"))
                        || marker.starts_with("//!");
                    spans.push(CommentSpan {
                        start_line: line_no,
                        end_line: line_no,
                        text: rest[pos + 2..].trim().to_string(),
                        is_doc,
                    });
                    break;
                }
                Some((pos, CommentMarker::Block)) => {
                    let marker = &rest[pos..];
                    block_is_doc = marker.starts_with("/**") || marker.starts_with("/*!");
                    block_start_line = line_no;
                    in_block_comment = true;
                    rest = &rest[pos + 2..];
                }
                None => break,
            }
        }
    }

    spans
}

/// Returns the innermost item (smallest line span) among `item_spans` whose
/// range contains `line`, or `file`'s path if none contains it.
fn nearest_item_path(item_spans: &[ItemSpan], line: usize, file: &Path) -> String {
    item_spans
        .iter()
        .filter(|span| span.start_line <= line && line <= span.end_line)
        .min_by_key(|span| span.end_line - span.start_line)
        .map(|span| span.item_path.clone())
        .unwrap_or_else(|| file.display().to_string())
}

/// Builds a `Finding` for a raw-text match. There's no `proc_macro2::Span`
/// available here (these findings come from a plain line scan, not `syn`),
/// so the column is hardcoded to `1` — a known simplification, since these
/// are line-based, not token-based, findings.
fn build_finding(
    rule: &'static str,
    line: usize,
    file: &Path,
    item_spans: &[ItemSpan],
    severity: Severity,
    evidence: Option<serde_json::Value>,
) -> Finding {
    let rule = crate::finding::RuleId::from(rule);
    let evidence_class = crate::finding::evidence_class_for_rule(&rule);
    Finding {
        id: format!("{rule}:{}:{line}:1", file.display()).into(),
        rule,
        severity,
        location: Location {
            file: file.to_path_buf(),
            line: crate::finding::OneBasedLine::new(line)
                .expect("text-scan line numbers are 1-based"),
            item_path: nearest_item_path(item_spans, line, file),
        },
        evidence_class,
        origin: Origin::Code,
        evidence,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Lowercases `text` and splits it on non-alphanumeric boundaries (naturally
/// splits `snake_case` on `_`, since `_` isn't alphanumeric). Kept local —
/// `crate::slop` has its own copy for `doc-restates-signature`, not shared,
/// since it's a three-line helper and the two modules otherwise have no
/// reason to depend on each other.
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// Runs the three raw-text `G3` matchers over every comment in `source` and
/// returns their combined findings.
pub(crate) fn scan_comments(source: &str, item_spans: &[ItemSpan], file: &Path) -> Vec<Finding> {
    let comments = extract_comments(source);
    let source_lines: Vec<&str> = source.lines().collect();

    let mut findings = Vec::new();
    findings.extend(conversational_artifact_findings(
        &comments, item_spans, file,
    ));
    findings.extend(step_comment_inflation_findings(
        &comments,
        &source_lines,
        item_spans,
        file,
    ));
    findings.extend(restating_comment_findings(
        &comments,
        &source_lines,
        item_spans,
        file,
    ));
    findings
}

/// Near-certain AI-assistant framing leaking into a comment (see todo.md
/// §3.G `conversational-artifact`). Fires regardless of where in the comment
/// the phrase appears.
pub(crate) const CONVERSATIONAL_TIER1: &[&str] = &[
    "as an ai",
    "as an ai language model",
    "as a language model",
    "i'm an ai",
    "i cannot browse the internet",
];

/// Plausible but weaker prose habits (see todo.md §3.G
/// `conversational-artifact`). Only counted if the phrase starts within the
/// first 8 whitespace-separated words of the comment — mitigates legitimate
/// mid-sentence technical usage (e.g. "here is" showing up deep in an
/// otherwise unremarkable explanation).
pub(crate) const CONVERSATIONAL_TIER2: &[&str] = &[
    "here is",
    "here's",
    "note that this is a simplified",
    "in a real implementation",
    "in a production implementation",
    "for the purposes of this example",
];

/// The whitespace-separated word index at which `pos` (a byte offset into
/// `text`) falls — i.e. how many whole words precede it.
fn word_index_at(text: &str, pos: usize) -> usize {
    text[..pos].split_whitespace().count()
}

/// `conversational-artifact` (see todo.md §3.G): AI-assistant phrase leakage
/// into a plain comment. Only non-doc [`CommentSpan`]s are checked —
/// legitimate stub-limitation prose like "in a real implementation you would
/// also handle X" is common and appropriate in a `///` doc comment
/// explaining a stub, and excluding doc comments entirely sidesteps that
/// false-positive class. For a multi-line run of consecutive `//` comments,
/// each line is scanned independently — they are deliberately not joined
/// into one logical block (v1 scope-narrowing).
fn conversational_artifact_findings(
    comments: &[CommentSpan],
    item_spans: &[ItemSpan],
    file: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for comment in comments {
        if comment.is_doc {
            continue;
        }
        let lower = comment.text.to_lowercase();

        if CONVERSATIONAL_TIER1
            .iter()
            .any(|phrase| lower.contains(phrase))
        {
            findings.push(build_finding(
                crate::slop::CONVERSATIONAL_ARTIFACT_RULE,
                comment.start_line,
                file,
                item_spans,
                Severity::Warn,
                None,
            ));
            continue;
        }

        let hit = CONVERSATIONAL_TIER2.iter().any(|phrase| {
            lower
                .find(phrase)
                .is_some_and(|pos| word_index_at(&lower, pos) < 8)
        });
        if hit {
            findings.push(build_finding(
                crate::slop::CONVERSATIONAL_ARTIFACT_RULE,
                comment.start_line,
                file,
                item_spans,
                Severity::Info,
                None,
            ));
        }
    }
    findings
}

/// Whether `text`, trimmed, starts with the literal `Step\s*\d+` shape,
/// case-insensitive (`"Step 1:"`, `"Step1"`, `"STEP 2 -"`) — and if so, the
/// step number. Deliberately narrow: bare `1)`/`1.` numbering is not
/// recognized (too generic — would false-positive on legitimate ordered
/// documentation).
fn step_number(text: &str) -> Option<u32> {
    let trimmed = text.trim_start();
    // `get(..4)` instead of `[..4]`: byte 4 may fall inside a multi-byte
    // character (e.g. a comment starting `v1 — …`), which would panic.
    let prefix = trimmed.get(..4)?;
    if !prefix.eq_ignore_ascii_case("step") {
        return None;
    }
    let rest = trimmed[4..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// One `// Step N: ...`-shaped comment, as classified by [`step_number`].
struct StepComment {
    number: u32,
    start_line: usize,
    item_path: String,
}

/// Count of non-blank source lines strictly between `from_line` and
/// `to_line` (both 1-indexed, exclusive on both ends).
fn non_blank_lines_between(source_lines: &[&str], from_line: usize, to_line: usize) -> usize {
    if to_line <= from_line + 1 {
        return 0;
    }
    source_lines[from_line..to_line - 1]
        .iter()
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// `step-comment-inflation` (see todo.md §3.G): a `// Step N:` comment chain
/// of three or more, grouped by enclosing item. Only non-doc
/// [`CommentSpan`]s are checked. A run continues as long as the step number
/// increases by exactly 1, the enclosing item stays the same, and at most 2
/// non-blank lines separate consecutive steps; a chain of 1-2 is normal and
/// not flagged.
fn step_comment_inflation_findings(
    comments: &[CommentSpan],
    source_lines: &[&str],
    item_spans: &[ItemSpan],
    file: &Path,
) -> Vec<Finding> {
    let steps: Vec<StepComment> = comments
        .iter()
        .filter(|comment| !comment.is_doc)
        .filter_map(|comment| {
            step_number(&comment.text).map(|number| StepComment {
                number,
                start_line: comment.start_line,
                item_path: nearest_item_path(item_spans, comment.start_line, file),
            })
        })
        .collect();

    let mut findings = Vec::new();
    let mut chain: Vec<&StepComment> = Vec::new();

    for step in &steps {
        let continues_chain = match chain.last() {
            Some(last) => {
                last.item_path == step.item_path
                    && step.number == last.number + 1
                    && non_blank_lines_between(source_lines, last.start_line, step.start_line) <= 2
            }
            None => true,
        };
        if !continues_chain {
            flush_step_chain(&mut chain, &mut findings, file, item_spans);
        }
        chain.push(step);
    }
    flush_step_chain(&mut chain, &mut findings, file, item_spans);

    findings
}

/// Emits one finding for `chain` if it has 3 or more steps, then clears it.
fn flush_step_chain(
    chain: &mut Vec<&StepComment>,
    findings: &mut Vec<Finding>,
    file: &Path,
    item_spans: &[ItemSpan],
) {
    if chain.len() >= 3 {
        let lines: Vec<usize> = chain.iter().map(|step| step.start_line).collect();
        findings.push(build_finding(
            crate::slop::STEP_COMMENT_INFLATION_RULE,
            chain[0].start_line,
            file,
            item_spans,
            Severity::Info,
            Some(serde_json::json!({ "chain_length": chain.len(), "lines": lines })),
        ));
    }
    chain.clear();
}

/// Stopwords dropped before comparing a comment against the code line it
/// precedes (see todo.md §3.G `restating-comment`).
const RESTATING_STOPWORDS: &[&str] = &[
    "the", "a", "an", "to", "of", "and", "this", "is", "let", "mut", "fn", "if", "else", "return",
];

/// Tokenizes `text` and drops [`RESTATING_STOPWORDS`].
fn content_tokens(text: &str) -> std::collections::HashSet<String> {
    tokenize(text)
        .into_iter()
        .filter(|token| !RESTATING_STOPWORDS.contains(&token.as_str()))
        .collect()
}

/// The first non-blank line after 1-indexed `after_line`, if any.
fn next_non_blank_line<'a>(source_lines: &[&'a str], after_line: usize) -> Option<&'a str> {
    source_lines
        .iter()
        .skip(after_line)
        .find(|line| !line.trim().is_empty())
        .copied()
}

/// Item-declaration prefixes that, when the next code line starts with one,
/// exclude that comment from `restating-comment` — keeps the check scoped to
/// statement-level restating inside function bodies, not doc-comment-shaped
/// prose sitting above an item declaration.
const RESTATING_ITEM_KEYWORDS: &[&str] = &[
    "fn ", "pub fn", "struct ", "enum ", "impl ", "trait ", "mod ", "#[",
];

/// `restating-comment` (see todo.md §3.G): a single-line comment that only
/// paraphrases the next line of code. Multi-line block comments are excluded
/// from v1 (scope limitation) — only single-line (`start_line == end_line`),
/// non-doc [`CommentSpan`]s are checked. Requires both a comment-token floor
/// (≥4, post-stopword) and a code-line-token floor (≥3, post-stopword)
/// before scoring at all — the mitigation for short, legitimate comments
/// like `// increment i` above `i += 1;`, which never reach the floor.
fn restating_comment_findings(
    comments: &[CommentSpan],
    source_lines: &[&str],
    item_spans: &[ItemSpan],
    file: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for comment in comments {
        if comment.is_doc || comment.start_line != comment.end_line {
            continue;
        }
        let Some(code_line) = next_non_blank_line(source_lines, comment.end_line) else {
            continue;
        };
        let trimmed_code = code_line.trim();
        if trimmed_code.starts_with("//")
            || trimmed_code.starts_with("/*")
            || RESTATING_ITEM_KEYWORDS
                .iter()
                .any(|keyword| trimmed_code.starts_with(keyword))
        {
            continue;
        }

        let comment_tokens = content_tokens(&comment.text);
        let code_tokens = content_tokens(trimmed_code);
        if comment_tokens.len() < 4 || code_tokens.len() < 3 {
            continue;
        }

        let intersection = comment_tokens.intersection(&code_tokens).count();
        let union = comment_tokens.union(&code_tokens).count();
        if union == 0 {
            continue;
        }
        let similarity = intersection as f32 / union as f32;
        if similarity >= 0.7 {
            findings.push(build_finding(
                crate::slop::RESTATING_COMMENT_RULE,
                comment.start_line,
                file,
                item_spans,
                Severity::Info,
                None,
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_multibyte_char_at_byte_four_does_not_panic_step_number() {
        // Regression: `trimmed[..4]` panicked when byte 4 fell inside a
        // multi-byte character, aborting the whole analysis run.
        assert_eq!(step_number("v1 — new format"), None);
        assert_eq!(step_number("äöü"), None);
        assert_eq!(step_number("Step 3:"), Some(3));
    }

    #[test]
    fn string_literal_containing_comment_markers_is_not_a_comment() {
        let spans = extract_comments("let url = \"http://example.com\";\n");
        assert!(spans.is_empty());
    }

    #[test]
    fn line_comment_after_a_string_literal_is_still_found() {
        let spans = extract_comments("let url = \"http://example.com\"; // real comment\n");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text, "real comment");
        assert!(!spans[0].is_doc);
    }

    #[test]
    fn triple_slash_is_doc_quadruple_slash_is_not() {
        let spans = extract_comments("/// doc\n//// not doc\n");
        assert_eq!(spans.len(), 2);
        assert!(spans[0].is_doc);
        assert!(!spans[1].is_doc);
    }

    #[test]
    fn block_comment_spans_multiple_lines() {
        let spans = extract_comments("/* line one\nline two */\ncode();\n");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start_line, 1);
        assert_eq!(spans[0].end_line, 2);
        assert!(spans[0].text.contains("line one"));
        assert!(spans[0].text.contains("line two"));
    }
}
