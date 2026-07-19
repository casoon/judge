//! Fast-tier duplication detection: finds maximal duplicated *token spans*
//! across function bodies and groups them into clone families (see
//! todo.md §3.D, §14.2). A duplicated block need not be a whole function
//! body — a repeated chunk inside an otherwise unique function is detected
//! too, at a granularity of `min_tokens` tokens.
//!
//! Four modes are implemented here, from most to least literal (see
//! [`DupeMode`] for the evidence class each one gets):
//! - [`DupeMode::Strict`]: byte-identical source for the matched span,
//!   including whitespace and comments.
//! - [`DupeMode::Mild`] (default): normalized token stream — whitespace and
//!   comments between tokens are ignored, since tokenizing discards them.
//! - [`DupeMode::Weak`]: like `Mild`, plus literal values are normalized to a
//!   type-specific placeholder, so a span differing only in a literal's
//!   value still matches.
//! - [`DupeMode::Semantic`]: like `Weak`, plus bare local variable/parameter
//!   identifiers are normalized to positional placeholders, so a
//!   renamed-but-otherwise-identical clone still matches. See
//!   [`assign_semantic_text`] for the identifier-role heuristic and its
//!   known recall/precision limitations.
//!
//! ## Approach
//!
//! Each function body is flattened into a linear sequence of tokens (nested
//! `{}`/`()`/`[]` groups are unwrapped into explicit open/close tokens so a
//! window can cross brace boundaries). Token texts are interned to integer
//! ids per mode (`Strict` fingerprints raw source bytes instead, since its
//! matches include inter-token whitespace/comments), and every window of
//! exactly `min_tokens` tokens is fingerprinted with an O(1) polynomial
//! rolling hash into a shared table — no per-window `String` is ever built
//! (see [`build_fingerprints`]). Windows from *different* functions that
//! land in the same bucket are seed matches; a hash bucket can contain
//! collisions, so every seed pair is verified with an exact slice comparison
//! before use. Seed pairs that can be extended one token backward are
//! skipped: the pair one position to the left lands in the same bucket and
//! extends to the identical maximal span, so only the leftmost seed of each
//! alignment does the work. Each surviving seed is extended one token at a
//! time, forward and backward, for as long as the two sides keep matching —
//! which yields the maximal duplicated span for that particular alignment.
//! This is the "fingerprint all `min_tokens`-windows, then extend/merge per
//! function pair" strategy: simpler than a cross-function suffix automaton,
//! and sufficient at fast-tier scale.
//!
//! Maximal spans that share identical content are grouped into one clone
//! family (bucketed by span fingerprint and length, then verified exactly —
//! same idea as the old whole-body digest grouping, now applied to spans).
//! Spans fully contained in a larger reported span for the same function are
//! dropped — only the maximal match is worth reporting.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
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
    /// Like [`DupeMode::Mild`], but literal values (`1`, `"x"`, `'c'`, `true`,
    /// …) are normalized to a type-specific placeholder, so two spans that
    /// differ only in a literal's value still match. Non-literal tokens are
    /// compared exactly as in `Mild`. Confidence `0.85`.
    Weak,
    /// Like [`DupeMode::Weak`], plus bare local variable/parameter
    /// identifiers are normalized to positional placeholders (`__ID_0__`,
    /// `__ID_1__`, …) so a renamed-but-otherwise-identical clone still
    /// matches. See [`assign_semantic_text`] for the identifier-role
    /// heuristic and its known precision/recall limitations. Confidence
    /// `0.55`.
    Semantic,
}

/// Coarse literal category, used to pick a type-specific placeholder text at
/// [`DupeMode::Weak`]/[`DupeMode::Semantic`] (see [`flatten_tokens`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralKind {
    Str,
    ByteStr,
    Byte,
    Char,
    Int,
    Float,
    /// Anything `syn::Lit` doesn't recognize as one of the above — falls back
    /// to a generic placeholder.
    Verbatim,
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
    /// Mode this member was matched under; drives [`CloneMember::to_finding`]'s
    /// evidence class.
    pub mode: DupeMode,
    /// Deduplicated placeholder → original-identifier pairs, in
    /// first-occurrence order, for identifiers positionally normalized
    /// within this member's span. Only populated for [`DupeMode::Semantic`]
    /// — empty for `Strict`/`Mild`/`Weak`.
    pub identifier_mapping: Vec<(String, String)>,
    /// Deduplicated literal-kind names (e.g. `"int"`, `"str"`) actually
    /// normalized within this member's span. Only populated for
    /// [`DupeMode::Weak`]/[`DupeMode::Semantic`] — empty for
    /// `Strict`/`Mild`.
    pub normalized_literal_kinds: Vec<String>,
}

impl CloneMember {
    /// Renders this member as a [`Finding`]. The evidence class reflects how
    /// aggressively [`Self::mode`] normalized the matched tokens: `Strict`/
    /// `Mild` are deterministic, exact-token matches (`derived_fact`); `Weak`
    /// and `Semantic` are heuristic normalizations (`heuristic` — see
    /// todo.md §17.3).
    pub fn to_finding(&self) -> Finding {
        let evidence_class = match self.mode {
            DupeMode::Strict | DupeMode::Mild => EvidenceClass::DerivedFact,
            DupeMode::Weak | DupeMode::Semantic => EvidenceClass::Heuristic,
        };
        let mut evidence = serde_json::json!({ "token_count": self.token_count });
        if !self.identifier_mapping.is_empty() {
            let mapping: Vec<_> = self
                .identifier_mapping
                .iter()
                .map(|(placeholder, identifier)| {
                    serde_json::json!({ "placeholder": placeholder, "identifier": identifier })
                })
                .collect();
            evidence["identifier_mapping"] = serde_json::Value::Array(mapping);
        }
        if !self.normalized_literal_kinds.is_empty() {
            evidence["normalized_literal_kinds"] = serde_json::Value::Array(
                self.normalized_literal_kinds
                    .iter()
                    .map(|kind| serde_json::Value::String(kind.clone()))
                    .collect(),
            );
        }
        Finding {
            id: format!(
                "{DUPLICATE_RULE}:{}:{}:{}-{}",
                self.file.display(),
                self.qualified_name,
                self.start_token,
                self.end_token
            )
            .into(),
            rule: DUPLICATE_RULE.into(),
            severity: Severity::Warn,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::new(self.start_line)
                    .expect("proc-macro2 span lines are 1-based"),
                item_path: self.qualified_name.clone(),
            },
            evidence_class,
            origin: Origin::Code,
            // Carries the span's token count through to a `Finding` so a
            // ratio gate (e.g. `audit --since`'s duplication gate, see
            // todo.md §6) can use duplicated-token density as its numerator
            // instead of a raw finding count, once findings have been
            // diffed against a baseline and only the `Finding` survives.
            evidence: Some(evidence),
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

impl std::error::Error for DuplicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
            Self::MissingSuppressionReason(_, _) => None,
        }
    }
}

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
    /// Text used by [`DupeMode::Weak`]: same as `mild_text`, except literal
    /// tokens (and the `true`/`false` bool idents) are replaced with a
    /// type-specific placeholder.
    weak_text: String,
    /// Text used by [`DupeMode::Semantic`]: same as `weak_text`, except bare
    /// local variable/parameter identifiers are replaced with a positional
    /// placeholder (see [`assign_semantic_text`]).
    semantic_text: String,
    /// Set only for tokens built from `TokenTree::Literal` (never for the
    /// `true`/`false` bool special case, which isn't a `Literal` token at
    /// this layer — see [`flatten_tokens`]).
    literal_kind: Option<LiteralKind>,
    /// True only for tokens built from `TokenTree::Ident`, excluding the
    /// `true`/`false` bool special case.
    is_ident: bool,
    /// Set only for tokens whose `semantic_text` was positionally renamed:
    /// `(placeholder_text, original_identifier_text)`.
    semantic_identifier_mapping: Option<(String, String)>,
    start_line: usize,
    end_line: usize,
}

impl TokenUnit {
    fn new(span: proc_macro2::Span, mild_text: String) -> Self {
        let range = span.byte_range();
        Self {
            byte_start: range.start,
            byte_end: range.end,
            weak_text: mild_text.clone(),
            semantic_text: mild_text.clone(),
            mild_text,
            literal_kind: None,
            is_ident: false,
            semantic_identifier_mapping: None,
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
        assign_semantic_text(&mut tokens);
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
                let mild_text = ident.to_string();
                let mut token = TokenUnit::new(ident.span(), mild_text.clone());
                if mild_text == "true" || mild_text == "false" {
                    token.weak_text = BOOL_LIT_PLACEHOLDER.to_string();
                    token.semantic_text = BOOL_LIT_PLACEHOLDER.to_string();
                } else {
                    token.is_ident = true;
                }
                out.push(token);
            }
            proc_macro2::TokenTree::Punct(punct) => {
                out.push(TokenUnit::new(punct.span(), punct.to_string()));
            }
            proc_macro2::TokenTree::Literal(lit) => {
                let mild_text = lit.to_string();
                let mut token = TokenUnit::new(lit.span(), mild_text);
                let kind = literal_kind(&lit);
                let placeholder = literal_placeholder(kind);
                token.weak_text = placeholder.to_string();
                token.semantic_text = placeholder.to_string();
                token.literal_kind = Some(kind);
                out.push(token);
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

/// Placeholder for the `true`/`false` bool idents (see [`flatten_tokens`] —
/// these arrive as `TokenTree::Ident`, not `TokenTree::Literal`, so they
/// can't carry a [`LiteralKind`], but should still be treated as a literal
/// rather than sent through positional identifier numbering).
const BOOL_LIT_PLACEHOLDER: &str = "__BOOL_LIT__";

/// Classifies a raw literal token via `syn::Lit::new` (never produces
/// `Lit::Bool` — see [`BOOL_LIT_PLACEHOLDER`]).
fn literal_kind(lit: &proc_macro2::Literal) -> LiteralKind {
    match syn::Lit::new(lit.clone()) {
        syn::Lit::Str(_) => LiteralKind::Str,
        syn::Lit::ByteStr(_) => LiteralKind::ByteStr,
        syn::Lit::Byte(_) => LiteralKind::Byte,
        syn::Lit::Char(_) => LiteralKind::Char,
        syn::Lit::Int(_) => LiteralKind::Int,
        syn::Lit::Float(_) => LiteralKind::Float,
        _ => LiteralKind::Verbatim,
    }
}

/// Type-specific placeholder text for a literal, used by
/// [`DupeMode::Weak`]/[`DupeMode::Semantic`].
fn literal_placeholder(kind: LiteralKind) -> &'static str {
    match kind {
        LiteralKind::Str => "__STR_LIT__",
        LiteralKind::ByteStr => "__BYTESTR_LIT__",
        LiteralKind::Byte => "__BYTE_LIT__",
        LiteralKind::Char => "__CHAR_LIT__",
        LiteralKind::Int => "__INT_LIT__",
        LiteralKind::Float => "__FLOAT_LIT__",
        LiteralKind::Verbatim => "__LIT__",
    }
}

/// Short name for a [`LiteralKind`], used in a [`CloneMember`]'s
/// `normalized_literal_kinds` evidence.
fn literal_kind_name(kind: LiteralKind) -> &'static str {
    match kind {
        LiteralKind::Str => "str",
        LiteralKind::ByteStr => "bytestr",
        LiteralKind::Byte => "byte",
        LiteralKind::Char => "char",
        LiteralKind::Int => "int",
        LiteralKind::Float => "float",
        LiteralKind::Verbatim => "verbatim",
    }
}

/// Computes `semantic_text` for every ident token in one function's flattened
/// token stream (called once per function, right after [`flatten_tokens`]).
/// Literal tokens and the bool special case already have their
/// `semantic_text` set to the same placeholder as `weak_text` by
/// [`flatten_tokens`]; non-ident, non-literal tokens already have
/// `semantic_text == mild_text` from [`TokenUnit::new`] — operators and
/// delimiters are never normalized in any mode. This function only decides,
/// for each `is_ident` token, whether it looks like a bare local
/// variable/parameter (get a positional `__ID_n__` placeholder) or something
/// else — a call/macro name, a path segment, a field/method access target, a
/// keyword-like ident, or a probable type/const (`self`, `Self`, `crate`,
/// `super`, or an uppercase-first-letter ident) — which stays literal.
///
/// The heuristic looks only at neighboring tokens' `mild_text`, never
/// re-parses or consults the AST, so it can misclassify: a local closure
/// variable called as `callback(x)` is indistinguishable at the token level
/// from a real function call and is kept literal (under-normalization, a
/// safe failure direction — it can only cost recall, never cause a false
/// match). Likewise, struct-literal/pattern field names (`Foo { field: value
/// }`) look identical to a local variable at this layer, so `field` gets
/// normalized as if it were one — a bounded precision risk, consistent with
/// `Semantic` mode's `heuristic` evidence class.
///
/// Numbering is positional within the *whole function body*, assigned in
/// first-occurrence order while scanning left-to-right — not re-numbered
/// per matched window, since window boundaries aren't known yet at this
/// point in the pipeline. This means a duplicated inner block embedded at
/// different relative positions in two otherwise-different functions can
/// get different placeholder numbers for identifiers introduced before the
/// block starts, and fail to match even though the block itself is a
/// genuine renamed clone — `Semantic` mode's recall is effectively scoped to
/// near-whole-function clones, not the same sub-span granularity
/// `Strict`/`Mild` have.
/// Rust keywords (strict and reserved, 2018+). At the raw `TokenTree` layer
/// keywords and identifiers are indistinguishable — both are just
/// `TokenTree::Ident` — so without this list a keyword like `let`/`for`/`in`
/// would otherwise look like a normalizable local-variable candidate.
/// `self`/`Self`/`crate`/`super` are handled separately (see
/// [`assign_semantic_text`]); `true`/`false` never reach this check (see the
/// bool special case in [`flatten_tokens`]).
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "dyn", "else", "enum", "extern", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "static", "struct", "trait", "type", "unsafe", "use", "where", "while", "abstract",
    "become", "box", "do", "final", "macro", "override", "priv", "try", "typeof", "unsized",
    "virtual", "yield", "union",
];

fn is_rust_keyword(name: &str) -> bool {
    RUST_KEYWORDS.contains(&name)
}

fn assign_semantic_text(tokens: &mut [TokenUnit]) {
    let mut numbering: HashMap<String, usize> = HashMap::new();
    for index in 0..tokens.len() {
        if !tokens[index].is_ident {
            continue;
        }

        let next = tokens.get(index + 1).map(|t| t.mild_text.as_str());
        let next2 = tokens.get(index + 2).map(|t| t.mild_text.as_str());
        let prev = index
            .checked_sub(1)
            .and_then(|i| tokens.get(i))
            .map(|t| t.mild_text.as_str());
        let prev2 = index
            .checked_sub(2)
            .and_then(|i| tokens.get(i))
            .map(|t| t.mild_text.as_str());

        let name = tokens[index].mild_text.as_str();
        let keep_literal = next == Some("(")
            || next == Some("!")
            || (prev == Some(":") && prev2 == Some(":"))
            || (next == Some(":") && next2 == Some(":"))
            || prev == Some(".")
            || matches!(name, "self" | "Self" | "crate" | "super")
            || name.chars().next().is_some_and(char::is_uppercase)
            || is_rust_keyword(name);

        if keep_literal {
            continue;
        }

        let name = tokens[index].mild_text.clone();
        let next_n = numbering.len();
        let n = *numbering.entry(name.clone()).or_insert(next_n);
        let placeholder = format!("__ID_{n}__");
        tokens[index].semantic_text = placeholder.clone();
        tokens[index].semantic_identifier_mapping = Some((placeholder, name));
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

/// Multiplier for the polynomial rolling hash (an odd 64-bit constant, the
/// FNV-64 prime); arithmetic wraps mod 2^64. Hash equality is only a bucket
/// key — exact equality is always re-verified via [`Fingerprints::spans_equal`],
/// so collisions cost time, never correctness.
const FINGERPRINT_BASE: u64 = 0x0000_0100_0000_01b3;

/// Per-function fingerprint data: the replacement for the old per-window
/// digest `String`s. Building it costs O(tokens) (or O(source bytes) for
/// [`DupeMode::Strict`]) per function, after which any window's fingerprint
/// is an O(1) prefix-hash difference.
struct FuncFingerprint {
    /// Interned id per token for the run's mode. Empty for
    /// [`DupeMode::Strict`], which fingerprints the raw source bytes instead
    /// (a strict match includes inter-token whitespace and comments, so
    /// per-token ids can't represent it).
    ids: Vec<u64>,
    /// `prefix[i]` = polynomial hash of the first `i` units, where a unit is
    /// a token id (`Mild`/`Weak`/`Semantic`) or a byte of the function's
    /// source slice (`Strict`).
    prefix: Vec<u64>,
    /// [`DupeMode::Strict`] only: byte offset of the function's first token
    /// in `source`, the origin of `prefix`'s byte indexing.
    byte_base: usize,
}

struct Fingerprints {
    per_func: Vec<FuncFingerprint>,
    /// `pow[k]` = [`FINGERPRINT_BASE`]^k (wrapping), sized to the longest
    /// unit sequence of any function.
    pow: Vec<u64>,
}

/// Interns each token's mode-normalized text into an integer id (shared
/// across all functions, so equal texts get equal ids workspace-wide) and
/// precomputes per-function prefix hashes over the id sequence. `Strict`
/// instead prefix-hashes the raw bytes of each function's source slice, so a
/// window fingerprint covers inter-token whitespace/comments exactly like
/// the old raw-source digest did.
fn build_fingerprints(functions: &[FuncTokens], mode: DupeMode) -> Fingerprints {
    fn prefix_hashes(units: impl Iterator<Item = u64>, capacity: usize) -> Vec<u64> {
        let mut prefix = Vec::with_capacity(capacity + 1);
        let mut hash = 0u64;
        prefix.push(hash);
        for unit in units {
            hash = hash.wrapping_mul(FINGERPRINT_BASE).wrapping_add(unit);
            prefix.push(hash);
        }
        prefix
    }

    let mut interner: HashMap<String, u64> = HashMap::new();
    let mut per_func = Vec::with_capacity(functions.len());
    for func in functions {
        let fingerprint = if mode == DupeMode::Strict {
            let byte_base = func.tokens[0].byte_start;
            let byte_end = func.tokens[func.tokens.len() - 1].byte_end;
            let bytes = func.source[byte_base..byte_end].as_bytes();
            FuncFingerprint {
                ids: Vec::new(),
                prefix: prefix_hashes(bytes.iter().map(|&b| u64::from(b) + 1), bytes.len()),
                byte_base,
            }
        } else {
            let mut ids = Vec::with_capacity(func.tokens.len());
            for token in &func.tokens {
                let text = match mode {
                    DupeMode::Strict => unreachable!(),
                    DupeMode::Mild => &token.mild_text,
                    DupeMode::Weak => &token.weak_text,
                    DupeMode::Semantic => &token.semantic_text,
                };
                let id = match interner.get(text.as_str()) {
                    Some(&id) => id,
                    None => {
                        let id = interner.len() as u64 + 1;
                        interner.insert(text.clone(), id);
                        id
                    }
                };
                ids.push(id);
            }
            let prefix = prefix_hashes(ids.iter().copied(), ids.len());
            FuncFingerprint {
                ids,
                prefix,
                byte_base: 0,
            }
        };
        per_func.push(fingerprint);
    }

    let max_units = per_func
        .iter()
        .map(|fingerprint| fingerprint.prefix.len())
        .max()
        .unwrap_or(1);
    let mut pow = Vec::with_capacity(max_units);
    pow.push(1u64);
    for k in 1..max_units {
        pow.push(pow[k - 1].wrapping_mul(FINGERPRINT_BASE));
    }
    Fingerprints { per_func, pow }
}

impl Fingerprints {
    /// O(1) rolling-hash fingerprint of the token window `[start, end)` of
    /// function `func`. Equal window contents (per `mode`'s equality — raw
    /// source bytes for `Strict`, normalized token texts otherwise) always
    /// fingerprint equal; the converse is enforced by [`Self::spans_equal`].
    fn window_hash(
        &self,
        functions: &[FuncTokens],
        mode: DupeMode,
        func: usize,
        start: usize,
        end: usize,
    ) -> u64 {
        let fingerprint = &self.per_func[func];
        let (from, to) = match mode {
            DupeMode::Strict => {
                let tokens = &functions[func].tokens;
                (
                    tokens[start].byte_start - fingerprint.byte_base,
                    tokens[end - 1].byte_end - fingerprint.byte_base,
                )
            }
            DupeMode::Mild | DupeMode::Weak | DupeMode::Semantic => (start, end),
        };
        fingerprint.prefix[to]
            .wrapping_sub(fingerprint.prefix[from].wrapping_mul(self.pow[to - from]))
    }

    /// Exact equality of two token spans under `mode` — the verification
    /// step behind every fingerprint bucket hit, which is what keeps hash
    /// collisions harmless. A raw slice comparison, no allocation.
    #[allow(clippy::too_many_arguments)]
    fn spans_equal(
        &self,
        functions: &[FuncTokens],
        mode: DupeMode,
        func_a: usize,
        start_a: usize,
        end_a: usize,
        func_b: usize,
        start_b: usize,
        end_b: usize,
    ) -> bool {
        match mode {
            DupeMode::Strict => {
                let a = &functions[func_a];
                let b = &functions[func_b];
                a.source[a.tokens[start_a].byte_start..a.tokens[end_a - 1].byte_end]
                    == b.source[b.tokens[start_b].byte_start..b.tokens[end_b - 1].byte_end]
            }
            DupeMode::Mild | DupeMode::Weak | DupeMode::Semantic => {
                end_a - start_a == end_b - start_b
                    && self.per_func[func_a].ids[start_a..end_a]
                        == self.per_func[func_b].ids[start_b..end_b]
            }
        }
    }
}

/// Finds every maximal duplicated span between different functions in
/// `functions` and groups spans with identical content into clone families.
fn find_clone_families(
    functions: &[FuncTokens],
    mode: DupeMode,
    min_tokens: usize,
) -> Vec<CloneFamily> {
    let fingerprints = build_fingerprints(functions, mode);

    let mut seeds: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
    for (func_index, func) in functions.iter().enumerate() {
        let n = func.tokens.len();
        if n < min_tokens {
            continue;
        }
        for start in 0..=(n - min_tokens) {
            let hash =
                fingerprints.window_hash(functions, mode, func_index, start, start + min_tokens);
            seeds.entry(hash).or_default().push((func_index, start));
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
                // Leftmost-seed filter: if this pair extends one token
                // backward, then the windows one to the left are also equal
                // (drop the last token from the equal windows, prepend the
                // matching predecessor), land in the same bucket, and extend
                // to the identical maximal span — so this pair is redundant.
                // On a hash-collision pair the skip is also safe: it would
                // have produced nothing anyway. This turns repetitive code
                // from O(pairs × span) extension work into one extension per
                // alignment.
                if start_a > 0
                    && start_b > 0
                    && backward_step_matches(
                        &functions[func_a],
                        &functions[func_b],
                        start_a,
                        start_b,
                        0,
                        mode,
                    )
                {
                    continue;
                }
                // Buckets are keyed by rolling hash, so verify the windows
                // really match before extending.
                if !fingerprints.spans_equal(
                    functions,
                    mode,
                    func_a,
                    start_a,
                    start_a + min_tokens,
                    func_b,
                    start_b,
                    start_b + min_tokens,
                ) {
                    continue;
                }
                let (sa, ea, sb, eb) = extend_match(
                    functions, func_a, start_a, func_b, start_b, min_tokens, mode,
                );
                matches.insert((func_a, sa, ea, func_b, sb, eb));
            }
        }
    }

    // Group maximal spans with identical content: bucket by (fingerprint,
    // token length), then verify candidates exactly against each group's
    // representative span — same content-equality grouping as the old
    // digest-string keying, without materializing the span text.
    let mut group_members: Vec<Vec<CloneMember>> = Vec::new();
    let mut group_reps: Vec<(usize, usize, usize)> = Vec::new();
    let mut group_index: HashMap<(u64, usize), Vec<usize>> = HashMap::new();
    for (func_a, sa, ea, func_b, sb, eb) in matches {
        let a = &functions[func_a];
        let b = &functions[func_b];
        if is_suppressed(a, sa, ea) || is_suppressed(b, sb, eb) {
            continue;
        }
        let hash = fingerprints.window_hash(functions, mode, func_a, sa, ea);
        let candidates = group_index.entry((hash, ea - sa)).or_default();
        let group = candidates
            .iter()
            .copied()
            .find(|&group| {
                let (rep_func, rep_start, rep_end) = group_reps[group];
                fingerprints.spans_equal(
                    functions, mode, rep_func, rep_start, rep_end, func_a, sa, ea,
                )
            })
            .unwrap_or_else(|| {
                let group = group_members.len();
                group_members.push(Vec::new());
                group_reps.push((func_a, sa, ea));
                candidates.push(group);
                group
            });
        let members = &mut group_members[group];
        push_unique(members, member_from(a, sa, ea, mode));
        push_unique(members, member_from(b, sb, eb, mode));
    }

    let mut families: Vec<CloneFamily> = group_members
        .into_iter()
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
        DupeMode::Weak => a.tokens[start_a + fwd].weak_text == b.tokens[start_b + fwd].weak_text,
        DupeMode::Semantic => {
            a.tokens[start_a + fwd].semantic_text == b.tokens[start_b + fwd].semantic_text
        }
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
        DupeMode::Weak => {
            a.tokens[start_a - back - 1].weak_text == b.tokens[start_b - back - 1].weak_text
        }
        DupeMode::Semantic => {
            a.tokens[start_a - back - 1].semantic_text == b.tokens[start_b - back - 1].semantic_text
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

fn member_from(func: &FuncTokens, start: usize, end: usize, mode: DupeMode) -> CloneMember {
    let mut identifier_mapping = Vec::new();
    let mut normalized_literal_kinds = Vec::new();
    // Only `Weak`/`Semantic` actually normalize literals/identifiers — leave
    // this evidence empty for `Strict`/`Mild`, even though the underlying
    // per-token data is always computed (see `flatten_tokens`/
    // `assign_semantic_text`).
    if matches!(mode, DupeMode::Weak | DupeMode::Semantic) {
        for token in &func.tokens[start..end] {
            if let Some(kind) = token.literal_kind {
                let name = literal_kind_name(kind).to_string();
                if !normalized_literal_kinds.contains(&name) {
                    normalized_literal_kinds.push(name);
                }
            }
        }
    }
    if mode == DupeMode::Semantic {
        for token in &func.tokens[start..end] {
            if let Some(mapping) = &token.semantic_identifier_mapping
                && !identifier_mapping.contains(mapping)
            {
                identifier_mapping.push(mapping.clone());
            }
        }
    }
    CloneMember {
        qualified_name: func.qualified_name.clone(),
        file: func.file.clone(),
        start_line: func.tokens[start].start_line,
        end_line: func.tokens[end - 1].end_line,
        start_token: start,
        end_token: end - 1,
        token_count: end - start,
        mode,
        identifier_mapping,
        normalized_literal_kinds,
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

    #[test]
    fn weak_mode_normalizes_literals() {
        let dir = TempDir::new("dup-weak-literal");
        let file = dir.join("lit.rs");
        std::fs::write(
            &file,
            r#"
fn lit_one(x: i32) -> i32 {
    let a = 1;
    let b = 2;
    let c = 3;
    a + b + c + x
}

fn lit_two(x: i32) -> i32 {
    let a = 1;
    let b = 2;
    let c = 99;
    a + b + c + x
}
"#,
        )
        .unwrap();

        let files = authored([file]);

        let mild = analyze_workspace(files.iter(), DupeMode::Mild, 15, false);
        assert!(mild.families.is_empty());

        let weak = analyze_workspace(files.iter(), DupeMode::Weak, 15, false);
        assert_eq!(weak.families.len(), 1);
        let names: Vec<_> = weak.families[0]
            .members
            .iter()
            .map(|m| m.qualified_name.as_str())
            .collect();
        assert_eq!(names, ["lit_one", "lit_two"]);
    }

    #[test]
    fn semantic_mode_matches_renamed_clone() {
        let dir = TempDir::new("dup-semantic-rename");
        let file = dir.join("rename.rs");
        std::fs::write(
            &file,
            r#"
fn semantic_one(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}

fn semantic_two(x: i32) -> i32 {
    let mut sum = 0;
    for idx in 0..x {
        sum += idx;
    }
    sum
}
"#,
        )
        .unwrap();

        let files = authored([file]);

        let mild = analyze_workspace(files.iter(), DupeMode::Mild, 15, false);
        assert!(mild.families.is_empty());

        let semantic = analyze_workspace(files.iter(), DupeMode::Semantic, 15, false);
        assert_eq!(semantic.families.len(), 1);
        let members = &semantic.families[0].members;
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["semantic_one", "semantic_two"]);

        let findings = WorkspaceDuplication {
            families: semantic.families,
            errors: Vec::new(),
            excluded_generated: 0,
        }
        .to_findings();

        let one_evidence = findings
            .iter()
            .find(|f| f.location.item_path == "semantic_one")
            .unwrap()
            .evidence
            .clone()
            .unwrap();
        let one_mapping = one_evidence["identifier_mapping"].as_array().unwrap();
        assert!(one_mapping.contains(&serde_json::json!({
            "placeholder": "__ID_0__",
            "identifier": "total"
        })));
        assert!(one_mapping.contains(&serde_json::json!({
            "placeholder": "__ID_1__",
            "identifier": "i"
        })));

        let two_evidence = findings
            .iter()
            .find(|f| f.location.item_path == "semantic_two")
            .unwrap()
            .evidence
            .clone()
            .unwrap();
        let two_mapping = two_evidence["identifier_mapping"].as_array().unwrap();
        assert!(two_mapping.contains(&serde_json::json!({
            "placeholder": "__ID_0__",
            "identifier": "sum"
        })));
        assert!(two_mapping.contains(&serde_json::json!({
            "placeholder": "__ID_1__",
            "identifier": "idx"
        })));
    }

    #[test]
    fn semantic_mode_does_not_collapse_different_identifier_reuse_patterns() {
        let dir = TempDir::new("dup-semantic-reuse-pattern");
        let file = dir.join("reuse.rs");
        std::fs::write(
            &file,
            r#"
fn distinct_params(a: i32, b: i32) -> i32 {
    let x = 1;
    let y = 2;
    let z = 3;
    a + b + x + y + z
}

fn reused_param(a: i32) -> i32 {
    let x = 1;
    let y = 2;
    let z = 3;
    a + a + x + y + z
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Semantic, 19, false);

        assert!(
            report.families.is_empty(),
            "a distinct a+b vs reused a+a pattern must not collapse into one family, got: {:?}",
            report.families
        );
    }

    #[test]
    fn semantic_mode_keeps_call_names_literal() {
        let dir = TempDir::new("dup-semantic-call-names");
        let file = dir.join("calls.rs");
        std::fs::write(
            &file,
            r#"
fn calls_helper_one(x: i32) -> i32 {
    let y = 1;
    let z = 2;
    helper_one(x) + y + z
}

fn calls_helper_two(x: i32) -> i32 {
    let y = 1;
    let z = 2;
    helper_two(x) + y + z
}
"#,
        )
        .unwrap();

        let files = authored([file]);
        let report = analyze_workspace(files.iter(), DupeMode::Semantic, 12, false);

        assert!(
            report.families.is_empty(),
            "calls to different helper functions must not collapse under Semantic mode, got: {:?}",
            report.families
        );
    }

    /// Two functions whose bodies are `reps` repetitions of the same small
    /// two-line block — the pathological input for duplication detection.
    fn write_repetitive_fixture(dir: &TempDir, reps: usize) -> PathBuf {
        let file = dir.join("repetitive.rs");
        let mut source = String::new();
        for name in ["rep_one", "rep_two"] {
            source.push_str(&format!("fn {name}(x: i32) -> i32 {{\n"));
            source.push_str("    let mut total = 0;\n");
            for _ in 0..reps {
                source.push_str("    total += x * 3 + 1;\n");
                source.push_str("    total -= x / 2;\n");
            }
            source.push_str("    total\n}\n");
        }
        std::fs::write(&file, source).unwrap();
        file
    }

    /// Perf guard for the fingerprint pipeline (todo.md §15.3): a strongly
    /// repetitive file — two functions, each 1000× the same small block —
    /// must terminate in reasonable time.
    ///
    /// Measured on this fixture (release build, single run, Apple Silicon):
    /// - Old per-window-`String` + extend-every-seed-pair detector:
    ///   50 reps 78 ms, 100 reps 519 ms, 200 reps 4.26 s (≈×8 per doubling,
    ///   i.e. ~cubic in repetitions); 1000 reps aborted after 150 s.
    /// - Fingerprint pipeline (interning → rolling hash → exact-slice
    ///   verification, leftmost-seed extension): 50 reps 2.6 ms, 100 reps
    ///   6.3 ms, 200 reps 17.8 ms; 1000 reps 304 ms (1.7 s debug).
    ///
    /// Complexity of the new pipeline, with T total tokens, W windows, P
    /// bucket pairs, and A distinct match alignments of span length S:
    /// O(T) interning/prefix-hash memory and time, O(W) window fingerprints
    /// (O(1) each, no per-window allocation), O(P) constant-time bucket-pair
    /// checks, and O(A·S) extension — instead of O(W·min_tokens) digest
    /// strings and O(P·S) extension before.
    #[test]
    fn strongly_repetitive_file_terminates_in_reasonable_time() {
        let dir = TempDir::new("dup-repetitive");
        let file = write_repetitive_fixture(&dir, 1000);

        let files = authored([file]);
        let started = std::time::Instant::now();
        let report = analyze_workspace(files.iter(), DupeMode::Mild, DEFAULT_MIN_TOKENS, false);
        let elapsed = started.elapsed();

        // The two identical bodies collapse into one whole-body family; every
        // shifted alignment is strictly contained in it and deduped away.
        assert_eq!(report.families.len(), 1);
        let members = &report.families[0].members;
        let names: Vec<_> = members.iter().map(|m| m.qualified_name.as_str()).collect();
        assert_eq!(names, ["rep_one", "rep_two"]);
        assert!(members.iter().all(|m| m.token_count > 16_000));
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "repetitive file took {elapsed:?}"
        );
    }

    #[test]
    fn weak_and_semantic_are_heuristic_while_strict_and_mild_are_derived_facts() {
        let dir = TempDir::new("dup-evidence-class");
        let (file_a, file_b) = write_duplicate_fixtures(&dir);
        let files = authored([file_a, file_b]);

        for (mode, expected) in [
            (DupeMode::Strict, EvidenceClass::DerivedFact),
            (DupeMode::Mild, EvidenceClass::DerivedFact),
            (DupeMode::Weak, EvidenceClass::Heuristic),
            (DupeMode::Semantic, EvidenceClass::Heuristic),
        ] {
            let report = analyze_workspace(files.iter(), mode, DEFAULT_MIN_TOKENS, false);
            let findings = report.to_findings();
            assert!(
                !findings.is_empty(),
                "{mode:?} should find the fixture duplicate"
            );
            for finding in &findings {
                assert_eq!(finding.evidence_class, expected, "{mode:?}");
            }
        }
    }

    #[test]
    fn duplication_error_source_preserves_the_underlying_error() {
        let err = DuplicationError::Io(PathBuf::from("src/lib.rs"), std::io::Error::other("boom"));
        let source = std::error::Error::source(&err).expect("Io must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "src/lib.rs: failed to read file: boom");
        let no_reason = DuplicationError::MissingSuppressionReason(PathBuf::from("a.rs"), 1);
        assert!(std::error::Error::source(&no_reason).is_none());
    }
}
