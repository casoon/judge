//! Fast-tier security-shaped signals (see todo.md §F "Security-Candidates").
//! Four syntax-only detectors live here: `unsafe-surface` (an `unsafe { .. }`
//! expression block with no adjacent `// SAFETY:` comment), `integer-cast-risk`
//! (an `as` cast whose target type is a narrow integer type — a syntax-only
//! proxy for a possible truncation, not a proof), `panic-in-lib`
//! (`.unwrap()`/`.expect(..)`/`panic!(..)`/indexing reachable from a `pub`
//! item — a syntax-only proxy for an unhandled panic, not a proof), and
//! `hardcoded-secret` (a string literal matching a known secret-provider
//! pattern, or bound to a suspiciously-named `let`/`const`/`static` with high
//! Shannon entropy — a syntax-only proxy for a real secret, not a proof).
//!
//! None fits an existing home: `complexity.rs`/`functions.rs` have no prior
//! `unsafe`-block handling, and `slop_structural.rs`'s G4 scope (structural
//! slop — churn, boilerplate, abstraction shape) is deliberately kept
//! unblurred rather than absorbing security-shaped checks. The first three
//! detectors reuse [`crate::functions::walk_functions`] for the
//! per-function-body traversal, exactly like [`crate::complexity`] and
//! [`crate::duplication`] already do; `hardcoded-secret` needs its own
//! whole-file traversal instead (see its own scope section below) since it
//! must also see module-level `const`/`static` items, which
//! `walk_functions` never visits.
//!
//! `unsafe-surface` additionally needs [`crate::slop_text::extract_comments`]:
//! `syn` discards plain `//`/`/* */` comments entirely during parsing (only
//! `///`/`//!` doc comments survive, desugared to `#[doc = "..."]`
//! attributes — see that module's own doc comment), so a `// SAFETY:`
//! comment is invisible to a pure `syn::visit::Visit` pass. This module runs
//! that same raw-source-text scanner alongside its `syn` pass, rather than
//! duplicating the comment-extraction logic.
//!
//! `integer-cast-risk` is an honestly-labeled proxy, not a truncation proof:
//! knowing whether a cast can really lose precision needs the *source*
//! expression's real type (a type checker), which isn't available at the
//! Fast Tier — the same limitation already documented for `silent-default`/
//! `context-free-propagation` in [`crate::slop`]'s module doc, deferred
//! there to a future Deep Tier. This detector only ever looks at the cast's
//! written target type — with one syntax-only exemption: a cast whose
//! direct inner expression is itself a call to `clamp`/`min`/`max`/one of
//! the `saturating_*` methods (see [`is_clamped_immediately`]) is not
//! flagged, since the value is already bounded to a safe range immediately
//! before the cast. Added after a 2026-07-24 precision audit against a real
//! 135k-LOC corpus (`auditmysite`) found this the single largest
//! false-positive source: 311 of 312 findings, nearly all bounded
//! scoring/percentage arithmetic already guarded this way (see todo.md §F
//! "Praxisbeleg", GitHub issue #9).
//!
//! ## `panic-in-lib` scope
//!
//! Flags four panic-shaped constructs — `.unwrap()`, `.expect(..)`, a
//! `panic!(..)` macro invocation, and an indexing expression (`expr[i]`) —
//! but only inside a function whose own written visibility is `pub` (same
//! "item-level visibility only" simplification as `undocumented-public-item`,
//! see [`crate::api_surface`] module docs: a `pub fn` inside a private `mod`
//! is still checked here as if it were reachable). `#[test]`-attributed
//! functions are excluded directly; a `#[cfg(test)] mod tests { .. }` block
//! is not tracked explicitly (this module doesn't walk module nesting, only
//! individual function bodies via [`crate::functions::walk_functions`]), but
//! its functions are almost never themselves `pub`, so the visibility filter
//! already excludes nearly all of them in practice. A trait's default method
//! (no visibility of its own) is never in scope — there is nothing to check
//! it against.
//!
//! The claim itself is a syntax fact, matching `swallowed-result`'s `.ok()`
//! name match in [`crate::slop`] (same `derived_fact` class, not
//! `integer-cast-risk`'s `heuristic`): a `.unwrap()`/`.expect(..)` call, a
//! `panic!(..)` invocation, or an indexing expression exists at this exact
//! location on a `pub` path — never a claim that it *will* panic at runtime,
//! which depends on values this Fast Tier does not evaluate. A type that
//! happens to define its own non-panicking method or index operator of the
//! same name is not distinguished from the standard, panicking one — the
//! same accepted name-match imprecision `swallowed-result` already carries.
//! An indexing expression's `evidence.kind` further distinguishes the index
//! operand's shape (see [`classify_index_kind`]), added after the same
//! 2026-07-24 precision audit (todo.md §F "Praxisbeleg", GitHub issue #10)
//! found ~100 of 116 `panic-in-lib` findings in `auditmysite` were
//! `parsed["key"]`-style string-literal indexing into `serde_json::Value` —
//! whose `Index<&str>` impl returns `Value::Null` for a missing key or
//! wrong variant rather than panicking — while the only real bug in that
//! same audit was a range-slice (`expr[a..b]`), the genuinely dangerous
//! shape (bounds *and* UTF-8 char-boundary risk). A string-literal index is
//! reported as `"string_key_indexing"`, a range index as `"range_slice"`,
//! anything else stays plain `"indexing"` — still three shapes of the same
//! rule, not three rules, since none of this is proof either way without a
//! type checker (a `HashMap<String, _>` genuinely panics on a missing key
//! and looks identical to a `serde_json::Value` at this syntax level).
//! Also does not distinguish a `[lib]` target's public API surface from a
//! `[[bin]]`-only crate's `pub` items (which, for a binary, are never
//! actually reachable by another crate) — judge's Fast Tier has no
//! per-target source-file mapping to draw that line; see the module doc's
//! `pub`-scoping note above for the same simplification applied elsewhere.
//!
//! ## `hardcoded-secret` scope
//!
//! Two independent lanes, both reported under the same rule id
//! (`evidence.kind` distinguishes them, same bundling
//! [`crate::slop_structural::ABSTRACTION_INFLATION_RULE`] uses for its own
//! sub-patterns):
//!
//! - **Pattern lane** (`known_pattern`): every string literal in the file,
//!   regardless of where it appears, checked against a small, publicly
//!   documented list of secret-provider formats (AWS access key ids, GitHub
//!   tokens, Slack tokens, Google API keys, PEM private key headers). Not
//!   exhaustive — several providers issue plain random tokens with no fixed,
//!   recognizable prefix at all, which this lane cannot catch.
//! - **Entropy lane** (`high_entropy_assignment`): a string literal that is
//!   the direct initializer of a `let`/`const`/`static` whose own name
//!   contains a suspicious marker (`secret`, `token`, `password`, `api_key`,
//!   …; see [`SUSPICIOUS_NAME_MARKERS`]), is at least [`MIN_SECRET_LENGTH`]
//!   characters long, and has a Shannon entropy of at least
//!   [`MIN_SECRET_ENTROPY`] bits/char. Both thresholds are first-cut,
//!   adjustable constants, not calibrated against a corpus (mirrors
//!   [`crate::git::SIZE_DISTRIBUTION_GINI_THRESHOLD`]'s same honest style).
//!   Gating the entropy lane on a suspicious *name* (rather than checking
//!   every literal's entropy) is deliberate: plenty of ordinary strings
//!   (hashes, UUIDs, encoded binary blobs) are legitimately high-entropy, and
//!   without a name signal those would dominate the findings.
//!
//! Neither lane proves a *live* secret: a matched pattern is frequently a
//! provider's own publicly documented example value (AWS's own docs use
//! `AKIAIOSFODNN7EXAMPLE`), and a high-entropy named literal could be a
//! placeholder, a rotated/revoked credential, or a hash — hence
//! `heuristic`, not `derived_fact` (unlike `unsafe-surface`/`panic-in-lib`,
//! whose underlying construct is unambiguous). The finding's `evidence`
//! never includes the literal's actual text — only its kind, matched
//! pattern name (if any), and length — so a saved baseline or JSON report
//! does not itself become a place the secret is now written down in plain
//! text.
//!
//! This detector runs its own [`syn::visit::Visit`] pass over the whole
//! file rather than [`crate::functions::walk_functions`] (see the module
//! doc above), so it can see `const`/`static` items outside any function
//! body — a common real-world location for a hardcoded secret. It tracks
//! `mod`/`fn` nesting only (not `impl`/`trait` type names, unlike
//! [`crate::functions::Walker`]) for a finding's `item_path` — a deliberately
//! coarser location hint than the other three rules in this module, kept
//! simple since it is supplementary context, not the finding's evidence.
//! `#[test]`-attributed functions and any item nested under `#[cfg(test)]`
//! (checked on `mod`/`fn`/`impl` — a crude, conservative raw-token parse
//! mirroring `crate::api_surface`'s own local `attrs_have_cfg_test`, kept
//! local for the same reason [`crate::functions::type_name`] is) are
//! excluded from both lanes: real secrets don't belong in test fixtures
//! either, but a *placeholder* test credential is the single most common
//! false-positive source this detector would otherwise have.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCast, ExprIndex, ExprLit, ExprMacro, ExprMethodCall, ExprUnsafe,
    ImplItemFn, ItemConst, ItemFn, ItemImpl, ItemMod, ItemStatic, Lit, Local, Pat, TraitItemFn,
    Type, Visibility,
};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::{type_name, walk_functions};
use crate::ingest::SourceFile;
use crate::slop_text::{CommentSpan, extract_comments};

/// Rule id for an `unsafe { .. }` expression block with no `// SAFETY:`
/// comment found adjacent to it (see todo.md §F). Scoped to `unsafe`
/// expression blocks only — `unsafe fn`/`unsafe impl`/`unsafe trait`
/// declarations are out of scope (see the module doc and this rule's
/// [`crate::rule_registry`] entry).
pub const UNSAFE_SURFACE_RULE: &str = "unsafe-surface";
/// Bump when the unsafe-surface rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNSAFE_SURFACE_RULE_REVISION: u32 = 1;

/// Rule id for an `as` cast whose target type is a narrow integer type (see
/// todo.md §F). A syntax-only proxy for a possible truncation, not a proof —
/// see the module doc.
pub const INTEGER_CAST_RISK_RULE: &str = "integer-cast-risk";
/// Bump when the integer-cast-risk rule's logic changes (see todo.md §5
/// "Regelversions-Schutz"). v2 (2026-07-24, GitHub issue #9): added the
/// clamp-guard exemption (see module doc and [`is_clamped_immediately`]).
pub const INTEGER_CAST_RISK_RULE_REVISION: u32 = 2;

/// Rule id for a panic-shaped construct (`.unwrap()`, `.expect(..)`,
/// `panic!(..)`, or an indexing expression) on a `pub` path (see todo.md §F,
/// module doc "`panic-in-lib` scope").
pub const PANIC_IN_LIB_RULE: &str = "panic-in-lib";
/// Bump when the panic-in-lib rule's logic changes (see todo.md §5
/// "Regelversions-Schutz"). v2 (2026-07-24, GitHub issue #10): split
/// indexing's `evidence.kind` by index-operand shape (see module doc and
/// [`classify_index_kind`]).
pub const PANIC_IN_LIB_RULE_REVISION: u32 = 2;

/// Rule id for a string literal matching a known secret-provider pattern, or
/// bound to a suspiciously-named `let`/`const`/`static` with high entropy
/// (see todo.md §F, module doc "`hardcoded-secret` scope").
pub const HARDCODED_SECRET_RULE: &str = "hardcoded-secret";
/// Bump when the hardcoded-secret rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const HARDCODED_SECRET_RULE_REVISION: u32 = 1;

/// Identifier substrings (case-insensitive) `hardcoded-secret`'s entropy
/// lane requires the enclosing `let`/`const`/`static` name to contain (see
/// module doc). First-cut, adjustable list.
const SUSPICIOUS_NAME_MARKERS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "client_secret",
    "auth_token",
    "credential",
];

/// Minimum character length `hardcoded-secret`'s entropy lane requires (see
/// module doc) — shorter strings can't carry meaningfully high entropy
/// anyway. First-cut, adjustable constant.
const MIN_SECRET_LENGTH: usize = 16;

/// Minimum Shannon entropy, in bits per character, `hardcoded-secret`'s
/// entropy lane requires (see module doc and [`shannon_entropy`]). First-cut,
/// adjustable constant.
const MIN_SECRET_ENTROPY: f64 = 3.5;

/// Cast target type names `integer-cast-risk` flags (see module doc):
/// int-to-int narrowing targets, plus the pointer-sized integers (whose
/// width is platform-dependent and therefore also a narrowing risk on some
/// targets). Deliberately does not include `u64`/`i64`/`u128`/`i128` — a
/// float cast to one of those can still truncate a fractional value, but
/// telling a float source from an int source apart needs type information
/// this Fast Tier pass doesn't have (see module doc), so v1 stays scoped to
/// target types that are always a narrowing risk regardless of source.
const RISKY_CAST_TARGETS: &[&str] = &["u8", "i8", "u16", "i16", "u32", "i32", "usize", "isize"];

/// Method names that, when one of them is the outermost method call of an
/// `as` cast's direct inner expression, are treated as evidence the value is
/// already bounded to a safe range immediately before the cast — see
/// [`is_clamped_immediately`] and the module doc's `integer-cast-risk`
/// section. Added after a 2026-07-24 precision audit (todo.md §F
/// "Praxisbeleg", GitHub issue #9) found this the single largest
/// `integer-cast-risk` false-positive source in a real 135k-LOC corpus:
/// score/percentage arithmetic normalized to a fixed range before
/// narrowing.
const CLAMP_GUARD_METHODS: &[&str] = &[
    "clamp",
    "min",
    "max",
    "saturating_add",
    "saturating_sub",
    "saturating_mul",
    "saturating_div",
    "saturating_pow",
    "saturating_abs",
    "saturating_neg",
];

#[derive(Debug)]
pub enum SecurityError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for SecurityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// Aggregated security findings across a set of files, keeping analyzable
/// files separate from files that could not be parsed (same shape as
/// [`crate::slop::WorkspaceSlop`]).
#[derive(Debug, Default)]
pub struct WorkspaceSecurity {
    pub findings: Vec<Finding>,
    pub errors: Vec<SecurityError>,
    /// Generated files skipped because `include_generated` was `false` (see
    /// todo.md §3.A "Generated-Code-Policy").
    pub excluded_generated: usize,
}

/// Parses a single Rust source file and returns every `unsafe-surface`/
/// `integer-cast-risk`/`panic-in-lib`/`hardcoded-secret` finding in it.
pub fn analyze_file(path: &Path) -> Result<Vec<Finding>, SecurityError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| SecurityError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| SecurityError::Parse(path.to_path_buf(), err))?;
    let comments = extract_comments(&source);

    let mut findings = Vec::new();
    walk_functions(&ast, |site| {
        let mut unsafe_visitor = UnsafeVisitor {
            file: path,
            item_path: &site.qualified_name,
            comments: &comments,
            findings: Vec::new(),
        };
        unsafe_visitor.visit_block(site.block);
        findings.append(&mut unsafe_visitor.findings);

        let mut cast_visitor = CastVisitor {
            file: path,
            item_path: &site.qualified_name,
            findings: Vec::new(),
        };
        cast_visitor.visit_block(site.block);
        findings.append(&mut cast_visitor.findings);

        if is_public_and_not_test(site.vis, site.attrs) {
            let mut panic_visitor = PanicVisitor {
                file: path,
                item_path: &site.qualified_name,
                findings: Vec::new(),
            };
            panic_visitor.visit_block(site.block);
            findings.append(&mut panic_visitor.findings);
        }
    });

    let mut secret_visitor = SecretVisitor {
        file: path,
        path: Vec::new(),
        cfg_test_depth: 0,
        binding_name: None,
        findings: Vec::new(),
    };
    secret_visitor.visit_file(&ast);
    findings.append(&mut secret_visitor.findings);

    Ok(findings)
}

/// Whether `panic-in-lib` is in scope for a function with this written
/// visibility and attributes (see module doc "`panic-in-lib` scope"): its
/// own visibility must be exactly `pub` (`None` — a trait default method —
/// is never in scope), and it must not itself be `#[test]`-attributed.
fn is_public_and_not_test(vis: Option<&Visibility>, attrs: &[Attribute]) -> bool {
    matches!(vis, Some(Visibility::Public(_)))
        && !attrs.iter().any(|attr| attr.path().is_ident("test"))
}

/// Runs [`analyze_file`] over every file in `source_files` and aggregates the
/// results. Generated files are skipped unless `include_generated` is set
/// (see todo.md §3.A), matching [`crate::slop::analyze_workspace`]'s
/// convention.
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
    include_generated: bool,
) -> WorkspaceSecurity {
    let mut report = WorkspaceSecurity::default();
    for file in source_files {
        if !include_generated && !file.kind.is_locally_reportable() {
            report.excluded_generated += 1;
            continue;
        }
        match analyze_file(&file.path) {
            Ok(mut findings) => report.findings.append(&mut findings),
            Err(err) => report.errors.push(err),
        }
    }
    report
}

/// Whether any comment in `comments` containing the literal substring
/// `SAFETY:` sits immediately adjacent to an unsafe block starting at
/// `unsafe_start_line`: either its line range ends on the line directly
/// before the block (`// SAFETY: ...` on its own line above `unsafe {`), or
/// it starts on the same line as the `unsafe` keyword or the line right
/// after it (a comment on the `unsafe {` line itself, or as the first line
/// inside the block).
fn has_adjacent_safety_comment(comments: &[CommentSpan], unsafe_start_line: usize) -> bool {
    comments.iter().any(|comment| {
        comment.text.contains("SAFETY:")
            && (comment.end_line + 1 == unsafe_start_line
                || comment.start_line == unsafe_start_line
                || comment.start_line == unsafe_start_line + 1)
    })
}

/// Whether `ty`'s written name is one of [`RISKY_CAST_TARGETS`].
fn is_risky_cast_target(ty: &Type) -> bool {
    RISKY_CAST_TARGETS.contains(&type_name(ty).as_str())
}

/// Whether `expr` — an `as` cast's direct inner expression — is itself a
/// call to one of [`CLAMP_GUARD_METHODS`], meaning the value has already
/// been bounded to a safe range immediately before the cast. Deliberately
/// shallow: only the cast's immediate child is checked (after unwrapping
/// any enclosing parentheses), not a binary expression's operands or a
/// deeper nesting — `x.clamp(0, 100) as u32` is recognized, `(a.min(50) +
/// b.min(50)) as u32` is not (no type information to reason about the sum's
/// bound). A syntax-only heuristic, same spirit as the rest of this
/// detector: it narrows false positives, it does not eliminate them (see
/// module doc).
fn is_clamped_immediately(expr: &Expr) -> bool {
    let mut expr = expr;
    while let Expr::Paren(inner) = expr {
        expr = &inner.expr;
    }
    matches!(
        expr,
        Expr::MethodCall(call) if CLAMP_GUARD_METHODS.contains(&call.method.to_string().as_str())
    )
}

/// Classifies an indexing expression's `[..]` operand shape into one of
/// three `panic-in-lib` `evidence.kind` values (see module doc
/// "`panic-in-lib` scope") — syntax-only, no type resolution:
///  - a range (`expr[a..b]`, `expr[..b]`, `expr[a..]`) is `"range_slice"`:
///    real bounds risk, and for a `str` receiver, a char-boundary risk too.
///  - a string literal (`expr["key"]`) is `"string_key_indexing"`: in
///    practice almost always a map-like `Index<&str>` receiver
///    (`serde_json::Value`, `toml::Value`, ...) whose accessor returns a
///    null/default value for a missing key rather than panicking — still
///    reported, since a `HashMap`/`BTreeMap<String, _>` genuinely does
///    panic on a missing key and this Fast Tier cannot tell the two apart,
///    just under a distinguishable, separately-triageable kind.
///  - anything else (an integer literal, a variable, an arithmetic
///    expression, ...) stays `"indexing"`, unchanged: the classic
///    `Vec`/array/slice out-of-bounds panic risk.
fn classify_index_kind(index: &Expr) -> &'static str {
    match index {
        Expr::Range(_) => "range_slice",
        Expr::Lit(ExprLit {
            lit: Lit::Str(_), ..
        }) => "string_key_indexing",
        _ => "indexing",
    }
}

/// Builds an `unsafe-surface` finding. Its evidence class is `derived_fact`
/// (see [`crate::finding::evidence_class_for_rule`]): both halves of the
/// claim — the unsafe block's span, and the absence of a `// SAFETY:`
/// comment adjacent to it in the examined source text — are read directly
/// from the parsed file, not interpreted.
fn unsafe_surface_finding(file: &Path, span: proc_macro2::Span, item_path: &str) -> Finding {
    let start = span.start();
    Finding {
        id: format!(
            "{UNSAFE_SURFACE_RULE}:{}:{}:{}",
            file.display(),
            start.line,
            start.column
        )
        .into(),
        rule: UNSAFE_SURFACE_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(start.line).expect("proc-macro2 span lines are 1-based"),
            item_path: item_path.to_string(),
        },
        evidence_class: EvidenceClass::DerivedFact,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "reason": "no `SAFETY:` comment found adjacent to this unsafe block",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Builds an `integer-cast-risk` finding. Its evidence class is `heuristic`
/// (see [`crate::finding::evidence_class_for_rule`]'s catch-all, same as
/// `heavy-dependency`): the cast's target type is an exact syntax fact, but
/// whether it actually truncates depends on the source expression's real
/// type, which this Fast Tier pass does not resolve (see module doc) — so
/// the finding is a possible-candidate hint, never a truncation claim.
fn integer_cast_risk_finding(
    file: &Path,
    span: proc_macro2::Span,
    item_path: &str,
    target_type: &str,
) -> Finding {
    let start = span.start();
    Finding {
        id: format!(
            "{INTEGER_CAST_RISK_RULE}:{}:{}:{}",
            file.display(),
            start.line,
            start.column
        )
        .into(),
        rule: INTEGER_CAST_RISK_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(start.line).expect("proc-macro2 span lines are 1-based"),
            item_path: item_path.to_string(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "target_type": target_type,
            "reason": "a possible truncation candidate based on the cast's target type; the \
                source expression's real type is not resolved at the Fast Tier, so this is a \
                syntax-only proxy, not a truncation proof",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Builds a `panic-in-lib` finding. Its evidence class is `derived_fact`
/// (see [`crate::finding::evidence_class_for_rule`], module doc "`panic-in-lib`
/// scope"): the construct's kind and span, and the enclosing function's
/// `pub` visibility, are both read directly from the parsed file — only the
/// claim that it *will* panic at runtime is an interpretation, and this
/// finding never makes that claim.
fn panic_in_lib_finding(
    file: &Path,
    span: proc_macro2::Span,
    item_path: &str,
    kind: &str,
) -> Finding {
    let start = span.start();
    Finding {
        id: format!(
            "{PANIC_IN_LIB_RULE}:{}:{}:{}",
            file.display(),
            start.line,
            start.column
        )
        .into(),
        rule: PANIC_IN_LIB_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(start.line).expect("proc-macro2 span lines are 1-based"),
            item_path: item_path.to_string(),
        },
        evidence_class: EvidenceClass::DerivedFact,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "kind": kind,
            "reason": "a panicking construct reachable from a `pub` path; not a claim that it \
                will panic at runtime",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Visits a single function body for `unsafe { .. }` expression blocks (see
/// [`UNSAFE_SURFACE_RULE`]). Overrides `visit_item_fn` to a no-op, same
/// convention as `crate::complexity::ComplexityVisitor`: a local `fn` item
/// nested inside this body is a separate function that
/// [`crate::functions::walk_functions`] already visits (and checks) on its
/// own, so descending into it here would double-count its unsafe blocks.
struct UnsafeVisitor<'a> {
    file: &'a Path,
    item_path: &'a str,
    comments: &'a [CommentSpan],
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for UnsafeVisitor<'_> {
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let start_line = node.span().start().line;
        if !has_adjacent_safety_comment(self.comments, start_line) {
            self.findings.push(unsafe_surface_finding(
                self.file,
                node.span(),
                self.item_path,
            ));
        }
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Visits a single function body for `as` casts to a narrow integer type
/// (see [`INTEGER_CAST_RISK_RULE`]). Same nested-`fn`-item exclusion as
/// [`UnsafeVisitor`].
struct CastVisitor<'a> {
    file: &'a Path,
    item_path: &'a str,
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for CastVisitor<'_> {
    fn visit_expr_cast(&mut self, node: &'ast ExprCast) {
        if is_risky_cast_target(&node.ty) && !is_clamped_immediately(&node.expr) {
            self.findings.push(integer_cast_risk_finding(
                self.file,
                node.span(),
                self.item_path,
                &type_name(&node.ty),
            ));
        }
        visit::visit_expr_cast(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Visits a single `pub` function body for panic-shaped constructs — a
/// `.unwrap()`/`.expect(..)` call, a `panic!(..)` invocation, or an indexing
/// expression (see [`PANIC_IN_LIB_RULE`]). Same nested-`fn`-item exclusion as
/// [`UnsafeVisitor`]/[`CastVisitor`]; only constructed for functions that
/// pass [`is_public_and_not_test`] (see [`analyze_file`]).
struct PanicVisitor<'a> {
    file: &'a Path,
    item_path: &'a str,
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for PanicVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let kind = match node.method.to_string().as_str() {
            "unwrap" => Some("unwrap"),
            "expect" => Some("expect"),
            _ => None,
        };
        if let Some(kind) = kind {
            self.findings.push(panic_in_lib_finding(
                self.file,
                node.span(),
                self.item_path,
                kind,
            ));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        if node.mac.path.is_ident("panic") {
            self.findings.push(panic_in_lib_finding(
                self.file,
                node.span(),
                self.item_path,
                "panic_macro",
            ));
        }
        visit::visit_expr_macro(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        self.findings.push(panic_in_lib_finding(
            self.file,
            node.span(),
            self.item_path,
            classify_index_kind(&node.index),
        ));
        visit::visit_expr_index(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

/// Whether `value` matches a known secret-provider format (see module doc
/// "`hardcoded-secret` scope", pattern lane) — a small, publicly documented
/// list, not exhaustive. Returns the matched pattern's name for
/// `evidence.pattern`.
fn matches_known_secret_pattern(value: &str) -> Option<&'static str> {
    if value.len() == 20
        && value.starts_with("AKIA")
        && value[4..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("aws_access_key_id");
    }

    const GITHUB_TOKEN_PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
    if value.len() == 40
        && GITHUB_TOKEN_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        && value[4..].chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Some("github_token");
    }

    const SLACK_TOKEN_PREFIXES: &[&str] = &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"];
    if value.len() >= 20
        && SLACK_TOKEN_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
    {
        return Some("slack_token");
    }

    if value.len() == 39
        && value.starts_with("AIza")
        && value[4..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Some("google_api_key");
    }

    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----") {
        return Some("pem_private_key");
    }

    None
}

/// Shannon entropy, in bits per character, of `value` (`0.0` for an empty
/// string) — see module doc "`hardcoded-secret` scope", entropy lane.
fn shannon_entropy(value: &str) -> f64 {
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut total = 0u32;
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    counts.values().fold(0.0, |acc, &count| {
        let p = f64::from(count) / f64::from(total);
        acc - p * p.log2()
    })
}

/// Whether `name` contains one of [`SUSPICIOUS_NAME_MARKERS`] (see module
/// doc, entropy lane), case-insensitively.
/// Lowercases `name` and splits it into underscore-delimited words (both on
/// literal `_`/`-` and on camelCase boundaries), joined back with `_` and
/// wrapped in a leading/trailing `_` — e.g. `"authToken"` and `"AUTH_TOKEN"`
/// both become `"_auth_token_"`. Used by [`is_suspicious_name`] so a marker
/// only matches a whole word, not an arbitrary substring: `"token"` must not
/// match `"MIN_TOKENS"` (a lexical-token count, not a secret) just because
/// it's a prefix of the plural.
fn normalized_words(name: &str) -> String {
    let mut result = String::from("_");
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c == '_' || c == '-' {
            if !result.ends_with('_') {
                result.push('_');
            }
            prev_lower_or_digit = false;
            continue;
        }
        if c.is_uppercase() && prev_lower_or_digit {
            result.push('_');
        }
        result.extend(c.to_lowercase());
        prev_lower_or_digit = c.is_lowercase() || c.is_numeric();
    }
    if !result.ends_with('_') {
        result.push('_');
    }
    result
}

fn is_suspicious_name(name: &str) -> bool {
    let normalized = normalized_words(name);
    SUSPICIOUS_NAME_MARKERS
        .iter()
        .any(|marker| normalized.contains(&format!("_{marker}_")))
}

/// Whether `attrs` contains a `#[cfg(...)]` attribute whose predicate
/// mentions `test` as a whole word (`#[cfg(test)]`, `#[cfg(any(test, ...))]`,
/// `#[cfg(all(test, ...))]`) — a crude but conservative parse of the
/// attribute's raw tokens, not a full `cfg` predicate evaluator (mirrors
/// `crate::api_surface`'s private `attrs_have_cfg_test`, kept local for the
/// same reason `type_name` is).
fn attrs_have_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.tokens
            .clone()
            .into_iter()
            .any(|token| matches!(&token, proc_macro2::TokenTree::Ident(ident) if ident == "test"))
    })
}

/// Whether an item with these attributes is out of scope for
/// `hardcoded-secret` (see module doc): itself `#[cfg(test)]`-gated,
/// nested under one (`cfg_test_depth > 0`), or itself `#[test]`-attributed.
fn is_test_scoped(cfg_test_depth: usize, attrs: &[Attribute]) -> bool {
    cfg_test_depth > 0
        || attrs_have_cfg_test(attrs)
        || attrs.iter().any(|attr| attr.path().is_ident("test"))
}

/// Builds a `hardcoded-secret` finding. Its evidence class is `heuristic`
/// (see [`crate::finding::evidence_class_for_rule`]'s catch-all, module doc
/// "`hardcoded-secret` scope"): neither lane proves a *live* secret. The
/// evidence deliberately never includes the literal's own text — only its
/// kind, matched pattern name (if any), and length — so a saved baseline or
/// JSON report does not itself leak the secret it just found.
fn hardcoded_secret_finding(
    file: &Path,
    span: proc_macro2::Span,
    item_path: &str,
    kind: &str,
    pattern: Option<&str>,
    length: usize,
) -> Finding {
    let start = span.start();
    let mut evidence = serde_json::json!({
        "kind": kind,
        "length": length,
    });
    if let Some(pattern) = pattern {
        evidence["pattern"] = serde_json::Value::String(pattern.to_string());
    }
    Finding {
        id: format!(
            "{HARDCODED_SECRET_RULE}:{}:{}:{}",
            file.display(),
            start.line,
            start.column
        )
        .into(),
        rule: HARDCODED_SECRET_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(start.line).expect("proc-macro2 span lines are 1-based"),
            item_path: item_path.to_string(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Whole-file `hardcoded-secret` visitor (see module doc "`hardcoded-secret`
/// scope") — unlike [`UnsafeVisitor`]/[`CastVisitor`]/[`PanicVisitor`], this
/// one is driven directly over the parsed [`syn::File`] (see [`analyze_file`]),
/// not per-function via [`walk_functions`], so it can also see module-level
/// `const`/`static` items.
struct SecretVisitor<'a> {
    file: &'a Path,
    /// `mod`/`fn` name stack, joined with `::` for a finding's `item_path`
    /// (coarser than [`crate::functions::Walker`]'s — see module doc).
    path: Vec<String>,
    /// Depth of nesting inside an item gated by `#[cfg(test)]` (on itself or
    /// an ancestor) — see [`attrs_have_cfg_test`]/[`is_test_scoped`].
    cfg_test_depth: usize,
    /// The name of the innermost enclosing `let`/`const`/`static` binding
    /// whose initializer expression is currently being visited — `None`
    /// everywhere else. Consulted by the entropy lane only; the pattern
    /// lane runs regardless (see module doc).
    binding_name: Option<String>,
    findings: Vec<Finding>,
}

impl<'a> SecretVisitor<'a> {
    fn current_path(&self) -> String {
        if self.path.is_empty() {
            self.file.display().to_string()
        } else {
            self.path.join("::")
        }
    }

    fn item_path_for(&self) -> String {
        match &self.binding_name {
            Some(name) if self.path.is_empty() => name.clone(),
            Some(name) => format!("{}::{name}", self.path.join("::")),
            None => self.current_path(),
        }
    }
}

/// Extracts a `Local`'s simple binding name — `x` from `let x = ..;` or
/// `let x: T = ..;` — or `None` for any other pattern (tuple/struct
/// destructuring, wildcards, …), which the entropy lane then never applies
/// to (see module doc).
fn local_binding_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
        Pat::Type(pat_type) => local_binding_name(&pat_type.pat),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for SecretVisitor<'_> {
    /// Never descends into an attribute at all — in particular, never into a
    /// `#[doc = "..."]` attribute's string literal (`syn` desugars every
    /// `///`/`//!` doc comment into exactly that attribute shape). Without
    /// this override, `syn`'s default field-order traversal (`attrs` visited
    /// *before* `expr` on `ItemConst`/`ItemStatic`) would run doc-comment
    /// prose through both lanes while `binding_name` is already set to the
    /// *following* item's name — misattributing unrelated documentation text
    /// as if it were that item's own initializer.
    fn visit_attribute(&mut self, _node: &'ast Attribute) {}

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let gated = attrs_have_cfg_test(&node.attrs);
        if gated {
            self.cfg_test_depth += 1;
        }
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            visit::visit_item_mod(self, node);
        }
        if gated {
            self.cfg_test_depth -= 1;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        self.path.push(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.path.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        self.path.push(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.path.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        self.path.push(node.sig.ident.to_string());
        visit::visit_trait_item_fn(self, node);
        self.path.pop();
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        let previous = self.binding_name.take();
        self.binding_name = Some(node.ident.to_string());
        visit::visit_item_const(self, node);
        self.binding_name = previous;
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        if is_test_scoped(self.cfg_test_depth, &node.attrs) {
            return;
        }
        let previous = self.binding_name.take();
        self.binding_name = Some(node.ident.to_string());
        visit::visit_item_static(self, node);
        self.binding_name = previous;
    }

    fn visit_local(&mut self, node: &'ast Local) {
        let previous = self.binding_name.take();
        self.binding_name = local_binding_name(&node.pat);
        visit::visit_local(self, node);
        self.binding_name = previous;
    }

    fn visit_expr_lit(&mut self, node: &'ast ExprLit) {
        if self.cfg_test_depth == 0
            && let Lit::Str(lit_str) = &node.lit
        {
            let value = lit_str.value();
            if let Some(pattern) = matches_known_secret_pattern(&value) {
                self.findings.push(hardcoded_secret_finding(
                    self.file,
                    node.span(),
                    &self.item_path_for(),
                    "known_pattern",
                    Some(pattern),
                    value.len(),
                ));
            } else if self.binding_name.as_deref().is_some_and(is_suspicious_name)
                && value.len() >= MIN_SECRET_LENGTH
                && shannon_entropy(&value) >= MIN_SECRET_ENTROPY
            {
                self.findings.push(hardcoded_secret_finding(
                    self.file,
                    node.span(),
                    &self.item_path_for(),
                    "high_entropy_assignment",
                    None,
                    value.len(),
                ));
            }
        }
        visit::visit_expr_lit(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn findings_for(source: &str, name: &str) -> Vec<Finding> {
        let dir = TempDir::new(name);
        let file = dir.join("lib.rs");
        std::fs::write(&file, source).unwrap();
        analyze_file(&file).unwrap()
    }

    fn rule_findings<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
        findings.iter().filter(|f| f.rule == rule).collect()
    }

    #[test]
    fn unsafe_block_without_safety_comment_is_flagged() {
        let findings = findings_for(
            "fn f() {\n    unsafe {\n        std::hint::unreachable_unchecked();\n    }\n}\n",
            "security-unsafe-no-comment",
        );
        let hits = rule_findings(&findings, UNSAFE_SURFACE_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
        assert!(hits[0].is_gating());
    }

    #[test]
    fn unsafe_block_with_preceding_safety_comment_is_not_flagged() {
        let findings = findings_for(
            "fn f() {\n    // SAFETY: caller guarantees the pointer is valid\n    unsafe {\n        std::hint::unreachable_unchecked();\n    }\n}\n",
            "security-unsafe-preceding-comment",
        );
        assert!(rule_findings(&findings, UNSAFE_SURFACE_RULE).is_empty());
    }

    #[test]
    fn unsafe_block_with_inner_safety_comment_is_not_flagged() {
        let findings = findings_for(
            "fn f() {\n    unsafe {\n        // SAFETY: caller guarantees the pointer is valid\n        std::hint::unreachable_unchecked();\n    }\n}\n",
            "security-unsafe-inner-comment",
        );
        assert!(rule_findings(&findings, UNSAFE_SURFACE_RULE).is_empty());
    }

    #[test]
    fn unsafe_fn_declaration_alone_is_not_flagged() {
        // Scope check: `unsafe fn` is a function-level declaration, not an
        // `unsafe { .. }` expression block, and this rule is deliberately
        // scoped to the latter only (see module doc/exclusions).
        let findings = findings_for(
            "unsafe fn f() {\n    std::hint::unreachable_unchecked();\n}\n",
            "security-unsafe-fn-decl",
        );
        assert!(rule_findings(&findings, UNSAFE_SURFACE_RULE).is_empty());
    }

    #[test]
    fn nested_local_fn_unsafe_block_is_not_double_counted() {
        let findings = findings_for(
            "fn outer() {\n    fn inner() {\n        unsafe {\n            std::hint::unreachable_unchecked();\n        }\n    }\n    inner();\n}\n",
            "security-unsafe-nested-fn",
        );
        assert_eq!(rule_findings(&findings, UNSAFE_SURFACE_RULE).len(), 1);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn unsafe_surface_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(UNSAFE_SURFACE_RULE)
            .expect("unsafe-surface has a registry entry")
            .example
            .expect("unsafe-surface has a curated example")
            .before;
        let findings = findings_for(example, "unsafe-surface-registry-example");
        assert_eq!(rule_findings(&findings, UNSAFE_SURFACE_RULE).len(), 1);
    }

    #[test]
    fn cast_to_narrow_int_type_is_flagged() {
        let findings = findings_for(
            "fn f(x: i64) -> i32 {\n    x as i32\n}\n",
            "security-cast-narrow",
        );
        let hits = rule_findings(&findings, INTEGER_CAST_RISK_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::Heuristic);
        assert!(!hits[0].is_gating());
        assert_eq!(hits[0].evidence.as_ref().unwrap()["target_type"], "i32");
    }

    #[test]
    fn cast_to_wide_int_type_is_not_flagged() {
        let findings = findings_for(
            "fn f(x: i32) -> i64 {\n    x as i64\n}\n",
            "security-cast-wide",
        );
        assert!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).is_empty());
    }

    #[test]
    fn cast_to_a_type_outside_the_risky_list_is_not_flagged() {
        let findings = findings_for(
            "fn f(x: i32) -> f64 {\n    x as f64\n}\n",
            "security-cast-other",
        );
        assert!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).is_empty());
    }

    /// See todo.md §F "Praxisbeleg" (GitHub issue #9): a cast whose direct
    /// input is already bounded by `.clamp(..)` is not a truncation
    /// candidate and should not be flagged.
    #[test]
    fn cast_of_a_clamped_value_is_not_flagged() {
        let findings = findings_for(
            "fn f(x: i64) -> i32 {\n    x.clamp(0, 100) as i32\n}\n",
            "security-cast-clamped",
        );
        assert!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).is_empty());
    }

    /// Same exemption via `.min`/`.max`/`saturating_sub`, and unwrapped
    /// through parentheses — mirrors the real-world shapes found in the
    /// audit (`cv.signal_count.saturating_sub(cv.problem_count) as u32`,
    /// `score.round().max(1.0) as u32`).
    #[test]
    fn cast_of_a_saturating_sub_result_is_not_flagged() {
        let findings = findings_for(
            "fn f(a: usize, b: usize) -> u32 {\n    a.saturating_sub(b) as u32\n}\n",
            "security-cast-saturating-sub",
        );
        assert!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).is_empty());
    }

    #[test]
    fn cast_of_a_parenthesized_clamped_value_is_not_flagged() {
        let findings = findings_for(
            "fn f(x: i64) -> i32 {\n    (x.max(0)) as i32\n}\n",
            "security-cast-paren-clamped",
        );
        assert!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).is_empty());
    }

    /// The clamp-guard exemption only looks at the cast's immediate child —
    /// a clamped operand buried inside a binary expression is not
    /// recognized (documented limitation, see `is_clamped_immediately`), so
    /// this still fires.
    #[test]
    fn cast_of_a_sum_of_clamped_values_is_still_flagged() {
        let findings = findings_for(
            "fn f(a: i64, b: i64) -> i32 {\n    (a.max(0) + b.max(0)) as i32\n}\n",
            "security-cast-sum-of-clamped",
        );
        assert_eq!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).len(), 1);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn integer_cast_risk_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(INTEGER_CAST_RISK_RULE)
            .expect("integer-cast-risk has a registry entry")
            .example
            .expect("integer-cast-risk has a curated example")
            .before;
        let findings = findings_for(example, "integer-cast-risk-registry-example");
        assert_eq!(rule_findings(&findings, INTEGER_CAST_RISK_RULE).len(), 1);
    }

    #[test]
    fn is_risky_cast_target_matches_exactly_the_documented_list() {
        for name in RISKY_CAST_TARGETS {
            let ty: Type = syn::parse_str(name).unwrap();
            assert!(is_risky_cast_target(&ty), "{name} should be risky");
        }
        for name in ["u64", "i64", "u128", "i128", "bool", "f32", "f64"] {
            let ty: Type = syn::parse_str(name).unwrap();
            assert!(!is_risky_cast_target(&ty), "{name} should not be risky");
        }
    }

    #[test]
    fn unwrap_in_a_pub_fn_is_flagged() {
        let findings = findings_for(
            "pub fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n",
            "security-panic-unwrap-pub",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::DerivedFact);
        assert!(hits[0].is_gating());
        assert_eq!(hits[0].evidence.as_ref().unwrap()["kind"], "unwrap");
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn panic_in_lib_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(PANIC_IN_LIB_RULE)
            .expect("panic-in-lib has a registry entry")
            .example
            .expect("panic-in-lib has a curated example")
            .before;
        let findings = findings_for(example, "security-panic-in-lib-registry-example");
        assert_eq!(rule_findings(&findings, PANIC_IN_LIB_RULE).len(), 1);
    }

    #[test]
    fn expect_in_a_pub_fn_is_flagged() {
        let findings = findings_for(
            "pub fn f(x: Option<i32>) -> i32 {\n    x.expect(\"missing\")\n}\n",
            "security-panic-expect-pub",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["kind"], "expect");
    }

    #[test]
    fn panic_macro_in_a_pub_fn_is_flagged() {
        let findings = findings_for(
            "pub fn f() {\n    panic!(\"unreachable\")\n}\n",
            "security-panic-macro-pub",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["kind"], "panic_macro");
    }

    #[test]
    fn indexing_in_a_pub_fn_is_flagged() {
        let findings = findings_for(
            "pub fn f(xs: &[i32]) -> i32 {\n    xs[0]\n}\n",
            "security-panic-indexing-pub",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["kind"], "indexing");
    }

    /// See todo.md §F "Praxisbeleg" (GitHub issue #10): a range index
    /// (`expr[a..b]`) is the genuinely dangerous shape — real bounds *and*
    /// UTF-8 char-boundary risk — and gets its own `evidence.kind`.
    #[test]
    fn range_indexing_in_a_pub_fn_is_flagged_as_range_slice() {
        let findings = findings_for(
            "pub fn f(s: &str, end: usize) -> &str {\n    &s[1..end]\n}\n",
            "security-panic-indexing-range",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["kind"], "range_slice");
    }

    /// A string-literal index is almost always a `serde_json::Value`/
    /// `toml::Value`-style non-panicking accessor in practice — reported
    /// under a separate, lower-signal `evidence.kind` instead of being
    /// indistinguishable from classic `Vec`/array indexing.
    #[test]
    fn string_key_indexing_in_a_pub_fn_is_flagged_as_string_key_indexing() {
        let findings = findings_for(
            "pub fn f(v: &serde_json::Value) -> &serde_json::Value {\n    &v[\"key\"]\n}\n",
            "security-panic-indexing-string-key",
        );
        let hits = rule_findings(&findings, PANIC_IN_LIB_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["kind"],
            "string_key_indexing"
        );
    }

    #[test]
    fn unwrap_in_a_private_fn_is_not_flagged() {
        let findings = findings_for(
            "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n",
            "security-panic-unwrap-private",
        );
        assert!(rule_findings(&findings, PANIC_IN_LIB_RULE).is_empty());
    }

    #[test]
    fn unwrap_in_a_pub_test_fn_is_not_flagged() {
        let findings = findings_for(
            "#[test]\npub fn f() {\n    Some(1).unwrap();\n}\n",
            "security-panic-unwrap-pub-test",
        );
        assert!(rule_findings(&findings, PANIC_IN_LIB_RULE).is_empty());
    }

    #[test]
    fn unwrap_in_a_pub_trait_default_method_is_not_flagged() {
        // A trait default method has no visibility of its own (`vis` is
        // `None`) — see module doc "no visibility of its own" and
        // `is_public_and_not_test`'s doc comment.
        let findings = findings_for(
            "pub trait T {\n    fn f(x: Option<i32>) -> i32 {\n        x.unwrap()\n    }\n}\n",
            "security-panic-unwrap-trait-default",
        );
        assert!(rule_findings(&findings, PANIC_IN_LIB_RULE).is_empty());
    }

    #[test]
    fn unwrap_on_ok_method_named_call_in_a_pub_fn_is_not_flagged() {
        // `.ok()` is not one of the panic-shaped names this rule matches.
        let findings = findings_for(
            "pub fn f(x: Result<i32, ()>) -> Option<i32> {\n    x.ok()\n}\n",
            "security-panic-ok-pub",
        );
        assert!(rule_findings(&findings, PANIC_IN_LIB_RULE).is_empty());
    }

    #[test]
    fn nested_local_fn_pub_unwrap_is_not_double_counted() {
        let findings = findings_for(
            "pub fn outer() {\n    pub fn inner(x: Option<i32>) -> i32 {\n        x.unwrap()\n    }\n    inner(Some(1));\n}\n",
            "security-panic-nested-fn",
        );
        assert_eq!(rule_findings(&findings, PANIC_IN_LIB_RULE).len(), 1);
    }

    #[test]
    fn aws_access_key_id_pattern_is_flagged_as_a_bare_function_argument() {
        // The pattern lane runs regardless of binding context — no `let`/
        // `const`/`static` involved here at all.
        let findings = findings_for(
            "pub fn f() {\n    validate(\"AKIAIOSFODNN7EXAMPLE\");\n}\n",
            "security-secret-aws-key",
        );
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].evidence_class, EvidenceClass::Heuristic);
        assert!(!hits[0].is_gating());
        let evidence = hits[0].evidence.as_ref().unwrap();
        assert_eq!(evidence["kind"], "known_pattern");
        assert_eq!(evidence["pattern"], "aws_access_key_id");
        assert!(
            evidence.get("value").is_none(),
            "must not leak the literal's text"
        );
    }

    #[test]
    fn github_token_pattern_is_flagged() {
        let findings = findings_for(
            "const TOKEN: &str = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\";\n",
            "security-secret-github-token",
        );
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["pattern"],
            "github_token"
        );
    }

    #[test]
    fn slack_token_pattern_is_flagged() {
        let findings = findings_for(
            "const TOKEN: &str = \"xoxb-123456789012345\";\n",
            "security-secret-slack-token",
        );
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["pattern"], "slack_token");
    }

    #[test]
    fn google_api_key_pattern_is_flagged() {
        // The literal is assembled at test-runtime from two halves rather
        // than written out contiguously — a real Google API key has no
        // checksum, so any 39-char `AIza`-prefixed alphanumeric string
        // written verbatim here would also trip GitHub's own secret
        // scanning on this file. Assembling it keeps the fixture source
        // (what `findings_for` actually parses) byte-identical to the
        // literal case, without the full pattern ever appearing contiguous
        // in `security.rs` itself.
        let source = format!(
            "const KEY: &str = \"{}{}\";\n",
            "AIzaSyD1234567890abcdefg", "hijklmnopqrstuv"
        );
        let findings = findings_for(&source, "security-secret-google-key");
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["pattern"],
            "google_api_key"
        );
    }

    #[test]
    fn pem_private_key_header_is_flagged() {
        let findings = findings_for(
            "const KEY: &str = \"-----BEGIN RSA PRIVATE KEY-----\";\n",
            "security-secret-pem",
        );
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].evidence.as_ref().unwrap()["pattern"],
            "pem_private_key"
        );
    }

    #[test]
    fn high_entropy_literal_with_a_suspicious_module_level_const_name_is_flagged() {
        // Exercises the reason `hardcoded-secret` needs its own whole-file
        // visitor instead of `walk_functions`: this `const` sits outside any
        // function body.
        let findings = findings_for(
            "const API_SECRET: &str = \"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!\";\n",
            "security-secret-entropy-const",
        );
        let hits = rule_findings(&findings, HARDCODED_SECRET_RULE);
        assert_eq!(hits.len(), 1);
        let evidence = hits[0].evidence.as_ref().unwrap();
        assert_eq!(evidence["kind"], "high_entropy_assignment");
        assert!(evidence.get("pattern").is_none());
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags. The registry entry
    /// deliberately uses the entropy lane, not a real provider key shape —
    /// see the comment at that call site.
    #[test]
    fn hardcoded_secret_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(HARDCODED_SECRET_RULE)
            .expect("hardcoded-secret has a registry entry")
            .example
            .expect("hardcoded-secret has a curated example")
            .before;
        let findings = findings_for(example, "security-secret-registry-example");
        assert_eq!(rule_findings(&findings, HARDCODED_SECRET_RULE).len(), 1);
    }

    #[test]
    fn high_entropy_literal_with_a_suspicious_let_name_inside_a_fn_is_flagged() {
        let findings = findings_for(
            "fn f() {\n    let auth_token = \"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!\";\n    use_token(auth_token);\n}\n",
            "security-secret-entropy-let",
        );
        assert_eq!(rule_findings(&findings, HARDCODED_SECRET_RULE).len(), 1);
    }

    #[test]
    fn high_entropy_literal_without_a_suspicious_name_is_not_flagged() {
        let findings = findings_for(
            "const DATA: &str = \"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!\";\n",
            "security-secret-entropy-non-suspicious-name",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }

    #[test]
    fn low_entropy_literal_with_a_suspicious_name_is_not_flagged() {
        let findings = findings_for(
            "const PASSWORD: &str = \"aaaaaaaaaaaaaaaa\";\n",
            "security-secret-low-entropy",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }

    #[test]
    fn short_high_entropy_literal_with_a_suspicious_name_is_not_flagged() {
        // Below `MIN_SECRET_LENGTH` regardless of entropy.
        let findings = findings_for(
            "const SECRET: &str = \"Kx7$mQ2#\";\n",
            "security-secret-too-short",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }

    #[test]
    fn known_pattern_inside_a_test_attributed_fn_is_not_flagged() {
        let findings = findings_for(
            "#[test]\nfn t() {\n    validate(\"AKIAIOSFODNN7EXAMPLE\");\n}\n",
            "security-secret-test-fn",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }

    #[test]
    fn entropy_literal_inside_a_cfg_test_mod_is_not_flagged() {
        let findings = findings_for(
            "#[cfg(test)]\nmod tests {\n    const API_SECRET: &str = \"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!\";\n}\n",
            "security-secret-cfg-test-mod",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }

    #[test]
    fn shannon_entropy_is_zero_for_an_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_is_zero_for_a_single_repeated_character() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_matches_log2_of_the_alphabet_size_when_every_character_is_distinct() {
        let entropy = shannon_entropy("abcdefgh");
        assert!((entropy - 8.0_f64.log2()).abs() < 1e-9, "got {entropy}");
    }

    #[test]
    fn is_suspicious_name_matches_common_secret_markers_case_insensitively() {
        for name in ["API_SECRET", "authToken", "client_secret", "PASSWORD"] {
            assert!(is_suspicious_name(name), "{name} should be suspicious");
        }
        for name in ["data", "message", "counter"] {
            assert!(!is_suspicious_name(name), "{name} should not be suspicious");
        }
    }

    #[test]
    fn is_suspicious_name_does_not_match_a_marker_as_a_mere_substring() {
        // Regression test (found dogfooding this rule against judge's own
        // codebase): "token" must not match "MIN_TOKENS" — a lexical-token
        // count, unrelated to authentication tokens — just because it's a
        // prefix of the plural.
        for name in ["DEFAULT_MIN_TOKENS", "TOKENIZER", "PASSWORDLESS"] {
            assert!(!is_suspicious_name(name), "{name} should not be suspicious");
        }
    }

    #[test]
    fn high_entropy_doc_comment_before_a_const_is_not_attributed_to_that_const() {
        // Regression test (found dogfooding this rule): `syn` desugars a
        // `///` doc comment into a `#[doc = "..."]` attribute, and its
        // default traversal order visits an item's `attrs` before its
        // `expr`. Without `visit_attribute`'s no-op override, this doc
        // comment's high-entropy-looking prose would have been checked
        // against `API_SECRET`'s name, which follows it.
        let findings = findings_for(
            "/// Kx7$mQ2#Lp9@Rn4^Wz6&Tb3! see the design doc for details.\nconst API_SECRET: &str = \"short\";\n",
            "security-secret-doc-comment-not-leaked",
        );
        assert!(rule_findings(&findings, HARDCODED_SECRET_RULE).is_empty());
    }
}
