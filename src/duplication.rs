//! Fast-tier duplication detection: groups function bodies into clone
//! families by comparing normalized representations (see todo.md §3.D).
//!
//! Two modes are implemented here (`weak`/`semantic` are not — see todo.md):
//! - [`DupeMode::Strict`]: byte-identical function body source (trimmed).
//! - [`DupeMode::Mild`] (default): normalized token stream — comments and
//!   whitespace differences are ignored, since tokenizing discards them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::spanned::Spanned;

use crate::functions::walk_functions;

/// How aggressively two function bodies must match to count as duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupeMode {
    Strict,
    Mild,
}

/// Functions shorter than this are excluded — trivial one-liners
/// (`fn new() -> Self { Self }`) would otherwise dominate every family.
const MIN_LINES_OF_CODE: usize = 5;

/// One member of a clone family: a function whose body matched others'.
#[derive(Debug, Clone)]
pub struct CloneMember {
    pub qualified_name: String,
    pub file: PathBuf,
    pub line: usize,
    pub lines_of_code: usize,
}

/// A group of function bodies considered duplicates of each other.
#[derive(Debug)]
pub struct CloneFamily {
    pub members: Vec<CloneMember>,
}

#[derive(Debug)]
pub enum DuplicationError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for DuplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for DuplicationError {}

/// Aggregated duplication results across a set of files, keeping clone
/// families separate from files that could not be parsed.
#[derive(Debug, Default)]
pub struct WorkspaceDuplication {
    pub families: Vec<CloneFamily>,
    pub errors: Vec<DuplicationError>,
}

struct Candidate {
    member: CloneMember,
    digest: String,
}

/// Runs duplication detection over `source_files` in the given `mode` and
/// groups matching function bodies into clone families (families with a
/// single member are dropped — they're not duplicates of anything).
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a PathBuf>,
    mode: DupeMode,
) -> WorkspaceDuplication {
    let mut candidates = Vec::new();
    let mut errors = Vec::new();

    for path in source_files {
        match collect_candidates(path, mode) {
            Ok(mut found) => candidates.append(&mut found),
            Err(err) => errors.push(err),
        }
    }

    let mut groups: HashMap<String, Vec<CloneMember>> = HashMap::new();
    for candidate in candidates {
        groups.entry(candidate.digest).or_default().push(candidate.member);
    }

    let mut families: Vec<CloneFamily> = groups
        .into_values()
        .filter(|members| members.len() > 1)
        .map(|mut members| {
            members.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
            CloneFamily { members }
        })
        .collect();
    families.sort_by_key(|family| std::cmp::Reverse(family.members.len()));

    WorkspaceDuplication { families, errors }
}

fn collect_candidates(path: &Path, mode: DupeMode) -> Result<Vec<Candidate>, DuplicationError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| DuplicationError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| DuplicationError::Parse(path.to_path_buf(), err))?;

    let mut candidates = Vec::new();
    walk_functions(&ast, |site| {
        let start_line = site.span.start().line;
        let end_line = site.span.end().line.max(start_line);
        let lines_of_code = end_line - start_line + 1;
        if lines_of_code < MIN_LINES_OF_CODE {
            return;
        }

        let digest = match mode {
            DupeMode::Strict => source[site.block.span().byte_range()].trim().to_string(),
            DupeMode::Mild => site.block.to_token_stream().to_string(),
        };

        candidates.push(Candidate {
            member: CloneMember {
                qualified_name: site.qualified_name,
                file: path.to_path_buf(),
                line: start_line,
                lines_of_code,
            },
            digest,
        });
    });
    Ok(candidates)
}
