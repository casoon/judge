//! Fast-tier security-shaped signals (see todo.md §F "Security-Candidates").
//! Two syntax-only detectors live here: `unsafe-surface` (an `unsafe { .. }`
//! expression block with no adjacent `// SAFETY:` comment) and
//! `integer-cast-risk` (an `as` cast whose target type is a narrow integer
//! type — a syntax-only proxy for a possible truncation, not a proof).
//!
//! Neither fits an existing home: `complexity.rs`/`functions.rs` have no
//! prior `unsafe`-block handling, and `slop_structural.rs`'s G4 scope
//! (structural slop — churn, boilerplate, abstraction shape) is deliberately
//! kept unblurred rather than absorbing security-shaped checks. Both
//! detectors reuse [`crate::functions::walk_functions`] for the
//! per-function-body traversal, exactly like [`crate::complexity`] and
//! [`crate::duplication`] already do.
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
//! written target type.

use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprCast, ExprUnsafe, ItemFn, Type};

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
/// "Regelversions-Schutz").
pub const INTEGER_CAST_RISK_RULE_REVISION: u32 = 1;

/// Cast target type names `integer-cast-risk` flags (see module doc):
/// int-to-int narrowing targets, plus the pointer-sized integers (whose
/// width is platform-dependent and therefore also a narrowing risk on some
/// targets). Deliberately does not include `u64`/`i64`/`u128`/`i128` — a
/// float cast to one of those can still truncate a fractional value, but
/// telling a float source from an int source apart needs type information
/// this Fast Tier pass doesn't have (see module doc), so v1 stays scoped to
/// target types that are always a narrowing risk regardless of source.
const RISKY_CAST_TARGETS: &[&str] = &["u8", "i8", "u16", "i16", "u32", "i32", "usize", "isize"];

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
/// `integer-cast-risk` finding in it.
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
    });
    Ok(findings)
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
        if is_risky_cast_target(&node.ty) {
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
}
