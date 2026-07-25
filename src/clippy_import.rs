//! Imports `cargo clippy --message-format=json` output, extracting
//! `clippy::fn_params_excessive_bools` hits to use as a third,
//! cross-call-site corroborating evidence signal for the
//! `boolean-state-cluster` pattern candidate (todo.md §16
//! "Clippy-JSON optional importieren und als zusätzliche Evidenz nutzen").
//!
//! judge never runs `cargo clippy` itself — same established precedent as
//! [`crate::advisories`]'s `cargo audit --json` import and
//! [`crate::coverage`]'s LCOV import: only an already-generated report is
//! read, via `cargo judge patterns --clippy-json PATH` (see `run_patterns`
//! in `src/main.rs`). Generate one with e.g. `cargo clippy
//! --message-format=json > clippy.json`.
//!
//! `cargo clippy --message-format=json` emits one JSON object per line
//! (JSON-lines, not a single JSON array) — most entries are
//! `compiler-artifact` or other non-`compiler-message` noise. Only
//! `clippy::fn_params_excessive_bools` is imported today — the rule this
//! corroborates ([`crate::pattern::boolean_state_cluster_candidates`]) is
//! scoped to that one lint.

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ClippyImportError {
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for ClippyImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
        }
    }
}

impl std::error::Error for ClippyImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
        }
    }
}

/// One `clippy::fn_params_excessive_bools` hit, reduced to the fields
/// [`crate::pattern::boolean_state_cluster_candidates`] needs to match it
/// against a function it already found via its own AST signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClippyBoolParamsHit {
    pub file: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
}

const FN_PARAMS_EXCESSIVE_BOOLS_LINT: &str = "clippy::fn_params_excessive_bools";

/// Parses `cargo clippy --message-format=json`'s NDJSON output, extracting
/// every `clippy::fn_params_excessive_bools` hit. Tolerant of the
/// unparsable, the malformed, and the merely irrelevant: a line that isn't
/// valid JSON, isn't a `"reason": "compiler-message"` entry, or is missing a
/// field this needs is silently skipped rather than failing the whole
/// import — same "malformed records are skipped" precedent
/// [`crate::advisories::parse_audit_report`] documents.
pub fn parse_clippy_report(text: &str) -> Vec<ClippyBoolParamsHit> {
    text.lines()
        .filter_map(|line| {
            let entry = serde_json::from_str::<serde_json::Value>(line).ok()?;
            if entry.get("reason")?.as_str()? != "compiler-message" {
                return None;
            }
            let message = entry.get("message")?;
            let code = message.get("code")?.get("code")?.as_str()?;
            if code != FN_PARAMS_EXCESSIVE_BOOLS_LINT {
                return None;
            }
            let span = message.get("spans")?.as_array()?.first()?;
            let file = span.get("file_name")?.as_str()?;
            let line_start = span.get("line_start")?.as_u64()?;
            let line_end = span.get("line_end")?.as_u64()?;
            Some(ClippyBoolParamsHit {
                file: PathBuf::from(file),
                line_start: line_start as usize,
                line_end: line_end as usize,
            })
        })
        .collect()
}

/// Reads and parses a `cargo clippy --message-format=json` report from
/// `path` (see [`parse_clippy_report`]). Only the file read can fail;
/// parsing never does.
pub fn read_clippy_report(path: &Path) -> Result<Vec<ClippyBoolParamsHit>, ClippyImportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| ClippyImportError::Io(path.to_path_buf(), err))?;
    Ok(parse_clippy_report(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    // -- parse_clippy_report --

    #[test]
    fn parses_a_realistic_ndjson_stream_and_extracts_only_the_relevant_hit() {
        let text = concat!(
            r#"{"reason":"compiler-artifact","package_id":"judge","target":{"name":"judge"}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::needless_return"},"message":"unneeded `return` statement","spans":[{"file_name":"src/lib.rs","line_start":10,"line_end":10,"byte_start":100,"byte_end":110}]}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::fn_params_excessive_bools"},"message":"more than 3 bools in function parameters","spans":[{"file_name":"src/config.rs","line_start":42,"line_end":48,"byte_start":900,"byte_end":1000}]}}"#,
            "\n",
        );

        let hits = parse_clippy_report(text);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file, PathBuf::from("src/config.rs"));
        assert_eq!(hits[0].line_start, 42);
        assert_eq!(hits[0].line_end, 48);
    }

    #[test]
    fn an_incomplete_compiler_message_line_is_skipped_not_fatal() {
        let text = concat!(
            r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::fn_params_excessive_bools"},"message":"more than 3 bools in function parameters"}}"#,
            "\n",
        );

        assert!(parse_clippy_report(text).is_empty());
    }

    #[test]
    fn a_malformed_json_line_is_skipped_not_fatal() {
        let text = "not json at all\n";
        assert!(parse_clippy_report(text).is_empty());
    }

    #[test]
    fn an_empty_report_yields_an_empty_list() {
        assert!(parse_clippy_report("").is_empty());
    }

    // -- read_clippy_report --

    #[test]
    fn read_clippy_report_errors_clearly_for_a_missing_file() {
        let dir = TempDir::new("clippy-import-missing-file");
        let err = read_clippy_report(&dir.join("nope.json")).unwrap_err();
        assert!(err.to_string().contains("failed to read file"));
    }
}
