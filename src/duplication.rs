//! Fast-tier duplication detection: finds maximal duplicated *token spans*
//! across function bodies and groups them into clone families (see
//! todo.md §3.D, §14.2). A duplicated block need not be a whole function
//! body — a repeated chunk inside an otherwise unique function is detected
//! too, at a granularity of `min_tokens` tokens.
//!
//! Two modes are implemented here (`weak`/`semantic` are not — see todo.md):
//! - [`DupeMode::Strict`]: byte-identical source for the matched span,
//!   including whitespace and comments.
//! - [`DupeMode::Mild`] (default): normalized token stream — whitespace and
//!   comments between tokens are ignored, since tokenizing discards them.
//!
//! ## Approach
//!
//! Each function body is flattened into a linear sequence of tokens (nested
//! `{}`/`()`/`[]` groups are unwrapped into explicit open/close tokens so a
//! window can cross brace boundaries). For every function, every window of
//! exactly `min_tokens` tokens is hashed into a shared table keyed by its
//! digest text; windows from *different* functions that land in the same
//! bucket are seed matches. Each seed is then extended one token at a time,
//! forward and backward, for as long as the two sides keep matching — which
//! yields the maximal duplicated span for that particular alignment. This is
//! the "hash all `min_tokens`-windows, then extend/merge per function pair"
//! strategy: simpler than a cross-function suffix automaton, and sufficient
//! at fast-tier scale.
//!
//! Maximal spans that share identical content are grouped into one clone
//! family (same idea as the old whole-body digest grouping, now applied to
//! spans). Spans fully contained in a larger reported span for the same
//! function are dropped — only the maximal match is worth reporting.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::finding::{Finding, Location, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::SourceFile;

/// Rule id used for duplicate-code findings (see todo.md §3.D).
pub const DUPLICATE_RULE: &str = "duplicate-code";
/// Bump when the duplication rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const DUPLICATE_RULE_REVISION: u32 = 1;

/// How aggressively two token spans must match to count as duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupeMode {
    Strict,
    Mild,
}

/// Default minimum span length, in tokens. Chosen so a small multi-statement
/// block (roughly what `MIN_LINES_OF_CODE = 5` used to select for whole
/// bodies) still qualifies, while a trivial one-liner (`fn new() -> Self {
/// Self }`, 3 tokens) does not.
pub const DEFAULT_MIN_TOKENS: usize = 20;

/// One member of a clone family: a duplicated token span within a function.
#[derive(Debug, Clone)]
pub struct CloneMember {
    pub qualified_name: String,
    pub file: PathBuf,
    /// First source line covered by the span.
    pub start_line: usize,
    /// Last source line covered by the span.
    pub end_line: usize,
    /// Index (within the function's flattened token stream) of the first
    /// token in the span.
    pub start_token: usize,
    /// Index (within the function's flattened token stream) of the last
    /// token in the span, inclusive.
    pub end_token: usize,
    pub token_count: usize,
}

impl CloneMember {
    /// Renders this member as a [`Finding`]. Confidence is `1.0`: fast-tier
    /// token matching is deterministic, not a heuristic guess (see todo.md
    /// §7).
    pub fn to_finding(&self) -> Finding {
        Finding {
            id: format!(
                "{DUPLICATE_RULE}:{}:{}:{}-{}",
                self.file.display(),
                self.qualified_name,
                self.start_token,
                self.end_token
            ),
            rule: DUPLICATE_RULE.to_string(),
            severity: Severity::Warn,
            location: Location {
                file: self.file.clone(),
                line: self.start_line,
                item_path: self.qualified_name.clone(),
            },
            confidence: 1.0,
            origin: Origin::Code,
            // Carries the span's token count through to a `Finding` so a
            // ratio gate (e.g. `audit --since`'s duplication gate, see
            // todo.md §6) can use duplicated-token density as its numerator
            // instead of a raw finding count, once findings have been
            // diffed against a baseline and only the `Finding` survives.
            evidence: Some(serde_json::json!({ "token_count": self.token_count })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }
}

/// A group of token spans considered duplicates of each other.
#[derive(Debug)]
pub struct CloneFamily {
    pub members: Vec<CloneMember>,
}

#[derive(Debug)]
pub enum DuplicationError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    /// A `// judge-dupe-off:` comment with no reason after the colon. An
    /// unjustified suppression is itself a slop signal (see todo.md §3.D),
    /// so this is a hard error rather than a silently ignored range.
    MissingSuppressionReason(PathBuf, usize),
}

impl std::fmt::Display for DuplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::MissingSuppressionReason(path, line) => write!(
                f,
                "{}:{line}: `judge-dupe-off` requires a reason, e.g. `// judge-dupe-off: <why>`",
                path.display()
            ),
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
    /// Generated files skipped because `include_generated` was `false` (see
    /// todo.md §3.A "Generated-Code-Policy").
    pub excluded_generated: usize,
}

impl WorkspaceDuplication {
    /// One [`Finding`] per clone-family member (see [`CloneMember::to_finding`]).
    pub fn to_findings(&self) -> Vec<Finding> {
        self.families
            .iter()
            .flat_map(|family| family.members.iter().map(CloneMember::to_finding))
            .collect()
    }
}

/// A single token in a function's flattened body stream.
struct TokenUnit {
    byte_start: usize,
    byte_end: usize,
    /// Normalized text used by [`DupeMode::Mild`] (identifier/literal/punct
    /// text, or a synthetic bracket character for group delimiters).
    mild_text: String,
    start_line: usize,
    end_line: usize,
}

impl TokenUnit {
    fn new(span: proc_macro2::Span, mild_text: String) -> Self {
        let range = span.byte_range();
        Self {
            byte_start: range.start,
            byte_end: range.end,
            mild_text,
            start_line: span.start().line,
            end_line: span.end().line,
        }
    }
}

/// A function body's flattened tokens, plus everything needed to compute
/// span digests: the file's own source (for [`DupeMode::Strict`] slicing)
/// and its `judge-dupe-off`/`judge-dupe-on` suppression ranges.
struct FuncTokens {
    qualified_name: String,
    file: PathBuf,
    source: Rc<str>,
    tokens: Vec<TokenUnit>,
    suppressed: Rc<Vec<(usize, usize)>>,
}

/// Runs duplication detection over `source_files` in the given `mode`,
/// reporting only spans of at least `min_tokens` tokens, and groups matching
/// spans into clone families (families with a single member are dropped —
/// they're not duplicates of anything). Generated files are skipped unless
/// `include_generated` is set (see todo.md §3.A "Generated-Code-Policy").
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
    mode: DupeMode,
    min_tokens: usize,
    include_generated: bool,
) -> WorkspaceDuplication {
    let min_tokens = min_tokens.max(1);
    let mut functions = Vec::new();
    let mut errors = Vec::new();
    let mut excluded_generated = 0;

    for file in source_files {
        if !include_generated && !file.kind.is_locally_reportable() {
            excluded_generated += 1;
            continue;
        }
        match collect_function_tokens(&file.path, min_tokens) {
            Ok(mut found) => functions.append(&mut found),
            Err(err) => errors.push(err),
        }
    }

    let families = find_clone_families(&functions, mode, min_tokens);
    WorkspaceDuplication {
        families,
        errors,
        excluded_generated,
    }
}

fn collect_function_tokens(
    path: &Path,
    min_tokens: usize,
) -> Result<Vec<FuncTokens>, DuplicationError> {
    let source = std::fs::read_to_string(path)
        .map_err(|err| DuplicationError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| DuplicationError::Parse(path.to_path_buf(), err))?;
    let suppressed = Rc::new(suppressed_ranges(path, &source)?);
    let source: Rc<str> = Rc::from(source.into_boxed_str());

    let mut functions = Vec::new();
    walk_functions(&ast, |site| {
        let mut nested_functions = NestedFunctionRanges::default();
        nested_functions.visit_block(site.block);
        let mut tokens = Vec::new();
        flatten_tokens(
            site.block.to_token_stream(),
            &mut tokens,
            &nested_functions.ranges,
        );
        if tokens.len() < min_tokens {
            return;
        }
        functions.push(FuncTokens {
            qualified_name: site.qualified_name,
            file: path.to_path_buf(),
            source: Rc::clone(&source),
            tokens,
            suppressed: Rc::clone(&suppressed),
        });
    });
    Ok(functions)
}

/// Flattens a token stream into a linear sequence, unwrapping `{}`/`()`/`[]`
/// groups into explicit open/close tokens so windows can cross brace
/// boundaries. Invisible (`Delimiter::None`) groups are transparent.
#[derive(Default)]
struct NestedFunctionRanges {
    ranges: Vec<std::ops::Range<usize>>,
}

impl<'ast> Visit<'ast> for NestedFunctionRanges {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.ranges.push(node.span().byte_range());
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.ranges.push(node.span().byte_range());
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if node.default.is_some() {
            self.ranges.push(node.span().byte_range());
        }
    }
}

fn flatten_tokens(
    stream: proc_macro2::TokenStream,
    out: &mut Vec<TokenUnit>,
    excluded_ranges: &[std::ops::Range<usize>],
) {
    for tt in stream {
        let token_range = tt.span().byte_range();
        if excluded_ranges
            .iter()
            .any(|excluded| excluded.start <= token_range.start && token_range.end <= excluded.end)
        {
            continue;
        }
        match tt {
            proc_macro2::TokenTree::Group(group) => match group.delimiter() {
                proc_macro2::Delimiter::None => {
                    flatten_tokens(group.stream(), out, excluded_ranges)
                }
                delimiter => {
                    let (open, close) = delimiter_chars(delimiter);
                    out.push(TokenUnit::new(group.span_open(), open.to_string()));
                    flatten_tokens(group.stream(), out, excluded_ranges);
                    out.push(TokenUnit::new(group.span_close(), close.to_string()));
                }
            },
            proc_macro2::TokenTree::Ident(ident) => {
                out.push(TokenUnit::new(ident.span(), ident.to_string()));
            }
            proc_macro2::TokenTree::Punct(punct) => {
                out.push(TokenUnit::new(punct.span(), punct.to_string()));
            }
            proc_macro2::TokenTree::Literal(lit) => {
                out.push(TokenUnit::new(lit.span(), lit.to_string()));
            }
        }
    }
}

fn delimiter_chars(delimiter: proc_macro2::Delimiter) -> (&'static str, &'static str) {
    match delimiter {
        proc_macro2::Delimiter::Parenthesis => ("(", ")"),
        proc_macro2::Delimiter::Brace => ("{", "}"),
        proc_macro2::Delimiter::Bracket => ("[", "]"),
        proc_macro2::Delimiter::None => ("", ""),
    }
}

/// Scans `source` for `// judge-dupe-off: <reason>` … `// judge-dupe-on`
/// ranges (by source line). A span that falls *fully* inside such a range is
/// excluded from detection later on; a span only partially overlapping one
/// is still reported, since it isn't wholly what the suppression justified.
/// An unterminated `judge-dupe-off` suppresses to the end of the file.
fn suppressed_ranges(path: &Path, source: &str) -> Result<Vec<(usize, usize)>, DuplicationError> {
    const OFF: &str = "// judge-dupe-off:";
    const ON: &str = "// judge-dupe-on";

    let mut ranges = Vec::new();
    let mut open: Option<usize> = None;
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if let Some(at) = line.find(OFF) {
            if line[at + OFF.len()..].trim().is_empty() {
                return Err(DuplicationError::MissingSuppressionReason(
                    path.to_path_buf(),
                    line_number,
                ));
            }
            open.get_or_insert(line_number);
        } else if line.contains(ON)
            && let Some(start) = open.take()
        {
            ranges.push((start, line_number));
        }
    }
    if let Some(start) = open {
        ranges.push((start, usize::MAX));
    }
    Ok(ranges)
}

/// Digest text for the token window `[start, end)` of `func`, in `mode`.
/// [`DupeMode::Strict`] re-slices the raw source, so whitespace and comments
/// between tokens make two otherwise-equal windows differ; [`DupeMode::Mild`]
/// joins each token's normalized text instead, ignoring both.
fn window_digest(func: &FuncTokens, mode: DupeMode, start: usize, end: usize) -> String {
    match mode {
        DupeMode::Strict => {
            func.source[func.tokens[start].byte_start..func.tokens[end - 1].byte_end].to_string()
        }
        DupeMode::Mild => func.tokens[start..end]
            .iter()
            .map(|token| token.mild_text.as_str())
            .collect::<Vec<_>>()
            .join("\u{0}"),
    }
}

/// Finds every maximal duplicated span between different functions in
/// `functions` and groups spans with identical content into clone families.
fn find_clone_families(
    functions: &[FuncTokens],
    mode: DupeMode,
    min_tokens: usize,
) -> Vec<CloneFamily> {
    let mut seeds: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for (func_index, func) in functions.iter().enumerate() {
        let n = func.tokens.len();
        if n < min_tokens {
            continue;
        }
        for start in 0..=(n - min_tokens) {
            let digest = window_digest(func, mode, start, start + min_tokens);
            seeds.entry(digest).or_default().push((func_index, start));
        }
    }

    let mut matches: HashSet<(usize, usize, usize, usize, usize, usize)> = HashSet::new();
    for occurrences in seeds.values() {
        if occurrences.len() < 2 {
            continue;
        }
        for i in 0..occurrences.len() {
            let (func_a, start_a) = occurrences[i];
            for &(func_b, start_b) in &occurrences[i + 1..] {
                if func_a == func_b {
                    continue;
                }
                let (sa, ea, sb, eb) = extend_match(
                    functions, func_a, start_a, func_b, start_b, min_tokens, mode,
                );
                matches.insert((func_a, sa, ea, func_b, sb, eb));
            }
        }
    }

    let mut groups: HashMap<String, Vec<CloneMember>> = HashMap::new();
    for (func_a, sa, ea, func_b, sb, eb) in matches {
        let a = &functions[func_a];
        let b = &functions[func_b];
        if is_suppressed(a, sa, ea) || is_suppressed(b, sb, eb) {
            continue;
        }
        let digest = window_digest(a, mode, sa, ea);
        let members = groups.entry(digest).or_default();
        push_unique(members, member_from(a, sa, ea));
        push_unique(members, member_from(b, sb, eb));
    }

    let mut families: Vec<CloneFamily> = groups
        .into_values()
        .filter(|members| members.len() > 1)
        .map(|mut members| {
            members.sort_by(|x, y| x.file.cmp(&y.file).then(x.start_line.cmp(&y.start_line)));
            CloneFamily { members }
        })
        .collect();

    dedupe_contained_spans(&mut families);
    families.retain(|family| family.members.len() > 1);
    families.sort_by_key(|family| std::cmp::Reverse(family.members.len()));
    families
}

/// Extends a `min_tokens`-long seed match at `(func_a, start_a)` /
/// `(func_b, start_b)` as far as possible in both directions, returning the
/// maximal `(start_a, end_a, start_b, end_b)` span (end exclusive).
fn extend_match(
    functions: &[FuncTokens],
    func_a: usize,
    start_a: usize,
    func_b: usize,
    start_b: usize,
    seed_len: usize,
    mode: DupeMode,
) -> (usize, usize, usize, usize) {
    let a = &functions[func_a];
    let b = &functions[func_b];

    let mut back = 0;
    while start_a > back
        && start_b > back
        && backward_step_matches(a, b, start_a, start_b, back, mode)
    {
        back += 1;
    }

    let mut fwd = seed_len;
    while start_a + fwd < a.tokens.len()
        && start_b + fwd < b.tokens.len()
        && forward_step_matches(a, b, start_a, start_b, fwd, mode)
    {
        fwd += 1;
    }

    (start_a - back, start_a + fwd, start_b - back, start_b + fwd)
}

/// Whether the token at `start + fwd` — together with everything between it
/// and the previously last-included token — still matches on both sides.
fn forward_step_matches(
    a: &FuncTokens,
    b: &FuncTokens,
    start_a: usize,
    start_b: usize,
    fwd: usize,
    mode: DupeMode,
) -> bool {
    match mode {
        DupeMode::Strict => {
            let prev_a = a.tokens[start_a + fwd - 1].byte_end;
            let prev_b = b.tokens[start_b + fwd - 1].byte_end;
            let next_a = a.tokens[start_a + fwd].byte_end;
            let next_b = b.tokens[start_b + fwd].byte_end;
            a.source[prev_a..next_a] == b.source[prev_b..next_b]
        }
        DupeMode::Mild => a.tokens[start_a + fwd].mild_text == b.tokens[start_b + fwd].mild_text,
    }
}

/// Mirror of [`forward_step_matches`] for extending backward: whether the
/// token at `start - back - 1`, plus the gap up to the window's previous
/// first token, still matches on both sides.
fn backward_step_matches(
    a: &FuncTokens,
    b: &FuncTokens,
    start_a: usize,
    start_b: usize,
    back: usize,
    mode: DupeMode,
) -> bool {
    match mode {
        DupeMode::Strict => {
            let new_a = a.tokens[start_a - back - 1].byte_start;
            let new_b = b.tokens[start_b - back - 1].byte_start;
            let old_a = a.tokens[start_a - back].byte_start;
            let old_b = b.tokens[start_b - back].byte_start;
            a.source[new_a..old_a] == b.source[new_b..old_b]
        }
        DupeMode::Mild => {
            a.tokens[start_a - back - 1].mild_text == b.tokens[start_b - back - 1].mild_text
        }
    }
}

fn is_suppressed(func: &FuncTokens, start: usize, end: usize) -> bool {
    let start_line = func.tokens[start].start_line;
    let end_line = func.tokens[end - 1].end_line;
    func.suppressed
        .iter()
        .any(|&(off, on)| off <= start_line && end_line <= on)
}

fn member_from(func: &FuncTokens, start: usize, end: usize) -> CloneMember {
    CloneMember {
        qualified_name: func.qualified_name.clone(),
        file: func.file.clone(),
        start_line: func.tokens[start].start_line,
        end_line: func.tokens[end - 1].end_line,
        start_token: start,
        end_token: end - 1,
        token_count: end - start,
    }
}

fn push_unique(members: &mut Vec<CloneMember>, member: CloneMember) {
    let already_present = members.iter().any(|existing| {
        existing.file == member.file
            && existing.qualified_name == member.qualified_name
            && existing.start_token == member.start_token
            && existing.end_token == member.end_token
    });
    if !already_present {
        members.push(member);
    }
}

/// Drops family members whose span is fully contained in a larger reported
/// span for the same function — e.g. a short match against one partner that
/// happens to be a strict subset of a longer match found against another
/// partner. Only the maximal span is worth reporting; families that shrink
/// to a single member afterward are removed by the caller.
fn dedupe_contained_spans(families: &mut [CloneFamily]) {
    let mut locations = Vec::new();
    for (family_index, family) in families.iter().enumerate() {
        for (member_index, member) in family.members.iter().enumerate() {
            locations.push((
                family_index,
                member_index,
                member.file.clone(),
                member.qualified_name.clone(),
                member.start_token,
                member.end_token,
            ));
        }
    }

    let mut drop: HashSet<(usize, usize)> = HashSet::new();
    for (fi_a, mi_a, file_a, name_a, start_a, end_a) in &locations {
        for (fi_b, mi_b, file_b, name_b, start_b, end_b) in &locations {
            if (fi_a, mi_a) == (fi_b, mi_b) || file_a != file_b || name_a != name_b {
                continue;
            }
            let contained = start_a >= start_b && end_a <= end_b;
            if contained {
                drop.insert((*fi_a, *mi_a));
            }
        }
    }

    for (family_index, family) in families.iter_mut().enumerate() {
        let mut member_index = 0;
        family.members.retain(|_| {
            let keep = !drop.contains(&(family_index, member_index));
            member_index += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::SourceKind;
    use crate::test_util::TempDir;

    fn authored(paths: impl IntoIterator<Item = PathBuf>) -> Vec<SourceFile> {
        paths
            .into_iter()
            .map(|path| SourceFile {
                path,
                kind: SourceKind::Authored,
            })
            .collect()
    }

    fn write_duplicate_fixtures(dir: &TempDir) -> (PathBuf, PathBuf) {
        let file_a = dir.join("a.rs");
        let file_b = dir.join("b.rs");
        std::fs::write(
            &file_a,
            r#"
fn dup_one(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}

fn unique_one() -> i32 {
    let mut total = 0;
    for i in 0..3 {
        total += i * 2;
    }
    total
}
"#,
        )
        .unwrap();
        std::fs::write(
            &file_b,
            r#"
fn dup_two(x: i32) -> i32 {
    // reformatted duplicate of dup_one
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}
"#,
        )
        .unwrap();
        (file_a, file_b)
    }

    #[test]
    fn mild_mode_ignores_whitespace_and_comments() {
        let dir = TempDir::new("dup-mild");
        let (file_a, file_b) = write_duplicate_fixtures(&dir);

        let files = authored([file_a, file_b]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);

        assert_eq!(report.families.len(), 1);
        let members = &report.families[0].members;
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["dup_one", "dup_two"]);
    }

    #[test]
    fn strict_mode_requires_byte_identical_spans() {
        let dir = TempDir::new("dup-strict");
        let (file_a, file_b) = write_duplicate_fixtures(&dir);

        let files = authored([file_a, file_b]);
        let report = analyze_workspace(files.iter(), DupeMode::Strict, DEFAULT_MIN_TOKENS, false);

        // The extra comment in dup_two breaks byte-identity for the whole
        // body, but strict mode should still find the exact matching tail
        // (the `for` loop and final `total`) as a shorter span.
        assert_eq!(report.families.len(), 1);
        let members = &report.families[0].members;
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["dup_one", "dup_two"]);
        for member in members {
            assert!(member.token_count < DEFAULT_MIN_TOKENS + 5);
        }
    }

    #[test]
    fn spans_shorter_than_the_minimum_are_excluded() {
        let dir = TempDir::new("dup-too-short");
        let file = dir.join("short.rs");
        std::fs::write(
            &file,
            "fn short_one() -> i32 { 1 }\nfn short_two() -> i32 { 1 }\n",
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);

        assert!(report.families.is_empty());
    }

    #[test]
    fn analyze_workspace_reports_parse_errors() {
        let dir = TempDir::new("dup-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "fn broken( {").unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);

        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn finds_a_duplicated_span_nested_inside_a_larger_unique_function() {
        let dir = TempDir::new("dup-nested-span");
        let file = dir.join("nested.rs");
        std::fs::write(
            &file,
            r#"
fn contains_dup_block(n: i32) -> i32 {
    let a = 1;
    let b = 2;
    let mut total = 0;
    for i in 0..n {
        total += i;
    }

    let c = a + b;
    c + total
}

fn other_contains_dup_block(n: i32) -> i32 {
    let unrelated = 7;
    let mut total = 0;
    for i in 0..n {
        total += i;
    }
    unrelated * total
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, 10, false);

        assert_eq!(report.families.len(), 1);
        let members = &report.families[0].members;
        assert_eq!(members.len(), 2);
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["contains_dup_block", "other_contains_dup_block"]);

        // The matched span is the inner loop block, not the whole body: it
        // must start after the preceding, non-matching statements.
        let contains = members
            .iter()
            .find(|m| m.qualified_name == "contains_dup_block")
            .unwrap();
        assert!(contains.start_token > 0);
    }

    #[test]
    fn nested_function_is_not_reported_as_a_duplicate_of_its_parent() {
        let dir = TempDir::new("dup-nested-function");
        let file = dir.join("nested.rs");
        std::fs::write(
            &file,
            r#"
fn outer() {
    fn inner() {
        let mut total = 0;
        total += 1;
        total += 2;
        total += 3;
        total += 4;
        println!("{total}");
    }
    inner();
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, 8, false);

        assert!(report.families.is_empty());
    }

    #[test]
    fn contained_spans_are_deduped_to_the_maximal_match() {
        let dir = TempDir::new("dup-contained-span");
        let file = dir.join("contained.rs");
        std::fs::write(
            &file,
            r#"
fn fn_big(x: i32) -> i32 {
    let mut total = 0;
    total += x;
    total += x * 2;
    total
}

fn fn_partner_one(x: i32) -> i32 {
    let mut total = 0;
    total += x;
    total += x * 2;
    total
}

fn fn_partner_two(x: i32) -> i32 {
    let mut total = 0;
    total += x;
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, 10, false);

        // fn_big/fn_partner_two would otherwise form their own family over
        // the shared prefix — but that span is fully contained in the
        // larger fn_big/fn_partner_one match, so it must be dropped.
        assert_eq!(report.families.len(), 1);
        let members = &report.families[0].members;
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["fn_big", "fn_partner_one"]);
    }

    #[test]
    fn judge_dupe_off_suppresses_a_fully_contained_span() {
        let dir = TempDir::new("dup-suppressed");
        let file_a = dir.join("a.rs");
        let file_b = dir.join("b.rs");
        std::fs::write(
            &file_a,
            r#"
// judge-dupe-off: intentional protocol table duplication
fn dup_one(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}
// judge-dupe-on
"#,
        )
        .unwrap();
        std::fs::write(
            &file_b,
            r#"
fn dup_two(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}
"#,
        )
        .unwrap();

        let files = authored([file_a, file_b]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);

        assert!(report.families.is_empty());
    }

    #[test]
    fn judge_dupe_off_without_a_reason_is_a_hard_error() {
        let dir = TempDir::new("dup-missing-reason");
        let file = dir.join("bad_suppression.rs");
        std::fs::write(
            &file,
            r#"
fn dup_one(x: i32) -> i32 {
    // judge-dupe-off:
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
    // judge-dupe-on
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);

        assert_eq!(report.errors.len(), 1);
        match &report.errors[0] {
            DuplicationError::MissingSuppressionReason(_, line) => assert_eq!(*line, 3),
            other => panic!("expected a missing-reason error, got {other:?}"),
        }
    }

    #[test]
    fn to_findings_emits_one_warn_finding_per_member() {
        let dir = TempDir::new("dup-findings");
        let (file_a, file_b) = write_duplicate_fixtures(&dir);

        let files = authored([file_a, file_b]);
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);
        let findings = report.to_findings();

        assert_eq!(findings.len(), 2);
        for finding in &findings {
            assert_eq!(finding.rule, DUPLICATE_RULE);
            assert_eq!(finding.severity, Severity::Warn);
            assert_eq!(finding.origin, Origin::Code);
        }
        let ids: HashSet<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids.len(), 2, "each member must get a distinct id");
    }

    #[test]
    fn generated_files_are_excluded_unless_included() {
        let dir = TempDir::new("dup-generated");
        let (file_a, file_b) = write_duplicate_fixtures(&dir);

        let files = [
            SourceFile {
                path: file_a,
                kind: SourceKind::Authored,
            },
            SourceFile {
                path: file_b,
                kind: SourceKind::Generated,
            },
        ];

        let excluded = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);
        assert!(excluded.families.is_empty());
        assert_eq!(excluded.excluded_generated, 1);

        let included = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, true);
        assert_eq!(included.families.len(), 1);
        assert_eq!(included.excluded_generated, 0);
    }
}
