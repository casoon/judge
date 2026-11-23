//! The shared read-and-parse step for syntax-based rules (issue #57).
//!
//! Every Fast-Tier rule that needs a `syn` AST goes through [`read_and_parse`]
//! instead of calling `std::fs::read_to_string` and `syn::parse_file` itself.
//! Inside a [`with_parse_session`] scope each source file is read and parsed
//! at most once: later requests for the same path reuse the cached AST, or
//! the cached failure. Every failure is recorded with its reason and returned
//! in the [`ParseSummary`], so a rule that continues without a file (heuristic
//! evidence) no longer does so silently, while a rule that needs completeness
//! still turns the same failure into an analysis error.
//!
//! Outside a session (library callers, focused commands), [`read_and_parse`]
//! reads and parses the file on every call, as before.

use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// One successfully read and parsed source file.
pub(crate) struct ParsedSource {
    /// The file's text. Several rules also inspect comments or source spans.
    pub(crate) source: String,
    pub(crate) ast: syn::File,
}

/// Why a file could not be parsed. Callers map it into their own error type.
pub(crate) enum ParseFailure {
    Io(std::io::Error),
    Syntax(syn::Error),
}

/// A source file that syntax-based rules could not analyze, with the reason.
/// Serialized into `analysis_universe.unparsed_files`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnparsedFile {
    pub path: PathBuf,
    /// The I/O error or the `syn` error message.
    pub reason: String,
    /// One-based line of a `syn` error; `None` for an I/O error.
    pub line: Option<usize>,
    /// One-based column of a `syn` error; `None` for an I/O error.
    pub column: Option<usize>,
}

impl std::fmt::Display for UnparsedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())?;
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(f, ":{line}:{column}")?;
        }
        write!(f, ": {}", self.reason)
    }
}

/// What one [`with_parse_session`] scope parsed.
#[derive(Debug, Default)]
pub struct ParseSummary {
    unparsed: Vec<UnparsedFile>,
    parse_counts: BTreeMap<PathBuf, usize>,
}

impl ParseSummary {
    /// The files that could not be read or parsed, sorted by path, with
    /// paths shown relative to `workspace_root` where possible.
    pub fn unparsed_files(&self, workspace_root: &Path) -> Vec<UnparsedFile> {
        let mut files: Vec<UnparsedFile> = self
            .unparsed
            .iter()
            .map(|file| UnparsedFile {
                path: file
                    .path
                    .strip_prefix(workspace_root)
                    .unwrap_or(&file.path)
                    .to_path_buf(),
                ..file.clone()
            })
            .collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        files
    }

    /// How often each path was read and parsed during the session.
    pub fn parse_counts(&self) -> &BTreeMap<PathBuf, usize> {
        &self.parse_counts
    }
}

enum CachedFailure {
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    Syntax(syn::Error),
}

#[derive(Default)]
struct Session {
    entries: HashMap<PathBuf, Result<Rc<ParsedSource>, CachedFailure>>,
    summary: ParseSummary,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Restores the previously active session (normally none) when the scope
/// ends, including on unwind.
struct SessionGuard {
    previous: Option<Session>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        SESSION.with(|session| *session.borrow_mut() = previous);
    }
}

/// Runs `run` with a shared parse cache: within it every source file is read
/// and parsed at most once. Returns `run`'s result together with the
/// files that could not be parsed and the per-file parse counts.
pub fn with_parse_session<T>(run: impl FnOnce() -> T) -> (T, ParseSummary) {
    let previous = SESSION.with(|session| session.borrow_mut().replace(Session::default()));
    let guard = SessionGuard { previous };
    let result = run();
    let session = SESSION.with(|session| session.borrow_mut().take());
    drop(guard);
    (result, session.map(|s| s.summary).unwrap_or_default())
}

/// Reads and parses `path` — once per session, or on every call outside one.
pub(crate) fn read_and_parse(path: &Path) -> Result<Rc<ParsedSource>, ParseFailure> {
    let cached = SESSION.with(|session| {
        let session = session.borrow();
        let entry = session.as_ref()?.entries.get(path)?;
        Some(match entry {
            Ok(parsed) => Ok(Rc::clone(parsed)),
            Err(CachedFailure::Io { kind, message }) => Err(ParseFailure::Io(std::io::Error::new(
                *kind,
                message.clone(),
            ))),
            Err(CachedFailure::Syntax(err)) => Err(ParseFailure::Syntax(err.clone())),
        })
    });
    if let Some(cached) = cached {
        return cached;
    }

    let result = parse_uncached(path);
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let Some(session) = session.as_mut() else {
            return;
        };
        *session
            .summary
            .parse_counts
            .entry(path.to_path_buf())
            .or_default() += 1;
        let entry = match &result {
            Ok(parsed) => Ok(Rc::clone(parsed)),
            Err(ParseFailure::Io(err)) => {
                session.summary.unparsed.push(UnparsedFile {
                    path: path.to_path_buf(),
                    reason: err.to_string(),
                    line: None,
                    column: None,
                });
                Err(CachedFailure::Io {
                    kind: err.kind(),
                    message: err.to_string(),
                })
            }
            Err(ParseFailure::Syntax(err)) => {
                let start = err.span().start();
                session.summary.unparsed.push(UnparsedFile {
                    path: path.to_path_buf(),
                    reason: err.to_string(),
                    line: Some(start.line),
                    column: Some(start.column + 1),
                });
                Err(CachedFailure::Syntax(err.clone()))
            }
        };
        session.entries.insert(path.to_path_buf(), entry);
    });
    result
}

fn parse_uncached(path: &Path) -> Result<Rc<ParsedSource>, ParseFailure> {
    let source = std::fs::read_to_string(path).map_err(ParseFailure::Io)?;
    let ast = syn::parse_file(&source).map_err(ParseFailure::Syntax)?;
    Ok(Rc::new(ParsedSource { source, ast }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn a_session_parses_each_file_once_and_records_failures() {
        let dir = TempDir::new("parse-session");
        let good = dir.join("good.rs");
        let bad = dir.join("bad.rs");
        let missing = dir.join("missing.rs");
        std::fs::write(&good, "fn ok() {}\n").unwrap();
        std::fs::write(&bad, "fn ok() {}\nfn broken( {\n").unwrap();

        let ((), summary) = with_parse_session(|| {
            for _ in 0..3 {
                assert!(read_and_parse(&good).is_ok());
                assert!(matches!(read_and_parse(&bad), Err(ParseFailure::Syntax(_))));
                assert!(matches!(read_and_parse(&missing), Err(ParseFailure::Io(_))));
            }
        });

        assert!(summary.parse_counts().values().all(|count| *count == 1));
        assert_eq!(summary.parse_counts().len(), 3);
        let unparsed = summary.unparsed_files(&dir);
        assert_eq!(unparsed.len(), 2);
        assert_eq!(unparsed[0].path, PathBuf::from("bad.rs"));
        assert_eq!(unparsed[0].line, Some(2));
        assert!(unparsed[0].column.is_some());
        assert_eq!(unparsed[1].path, PathBuf::from("missing.rs"));
        assert_eq!(unparsed[1].line, None);

        // Outside a session nothing is cached or recorded.
        let ((), outer) = with_parse_session(|| {});
        assert!(outer.parse_counts().is_empty());
    }
}
