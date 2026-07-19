//! Structural slop signals (see todo.md §3.G "G4 — Strukturelle
//! Slop-Signale"). Four of the six G4 rules live here: `churn-hotspot`,
//! `complexity-inflation`, `legacy-freeze`, `abstraction-inflation`. Unlike
//! [`crate::slop`], most of these don't parse files as their primary
//! signal — `churn-hotspot`/`legacy-freeze` aggregate [`crate::git::churn`]
//! output, `complexity-inflation` aggregates
//! [`crate::complexity::FunctionInfo`]. `abstraction-inflation` is the
//! exception: it needs its own workspace-wide `syn` pass (trait-impl
//! counts, wrapper-struct delegation, builder-struct shape), since none of
//! the existing analyzers already compute that.
//!
//! The other two G4 rules, `duplicative-reinvention` and
//! `connectivity-drop`, need cross-file reference data (fan-in per item)
//! that only the Deep Tier's `find_all_refs` (see [`crate::deep`]) can
//! supply reliably — they are implemented separately as Deep Tier rules
//! reusing that infrastructure, not here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, Fields, FnArg, GenericArgument, ImplItem, ImplItemFn, ItemImpl, ItemStruct, Member,
    PathArguments, ReturnType, Stmt, Type,
};

use crate::complexity::FunctionInfo;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::{SourceFile, SourceKind};

/// Rule id for a file reworked often within a short window (see todo.md
/// §3.G).
pub const CHURN_HOTSPOT_RULE: &str = "churn-hotspot";
/// Bump when the churn-hotspot rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const CHURN_HOTSPOT_RULE_REVISION: u32 = 1;

/// Rule id for a long function with implausibly low branching (see todo.md
/// §3.G).
pub const COMPLEXITY_INFLATION_RULE: &str = "complexity-inflation";
pub const COMPLEXITY_INFLATION_RULE_REVISION: u32 = 1;

/// Rule id for a file untouched for a year while its neighbors keep
/// changing (see todo.md §3.G).
pub const LEGACY_FREEZE_RULE: &str = "legacy-freeze";
pub const LEGACY_FREEZE_RULE_REVISION: u32 = 1;

/// Rule id shared by all three `abstraction-inflation` sub-patterns
/// (single-impl trait, delegating wrapper, builder for a small struct —
/// see todo.md §3.G); `evidence.kind` distinguishes them, the same way
/// [`crate::slop::MERGED_STUB_RULE`] covers both `todo!()` and
/// `unimplemented!()` under one id.
pub const ABSTRACTION_INFLATION_RULE: &str = "abstraction-inflation";
pub const ABSTRACTION_INFLATION_RULE_REVISION: u32 = 1;

/// Minimum commits touching a single file within the 14-day churn window
/// (see todo.md §3.G `churn-hotspot`: "hoher 2-Wochen-Churn — Rework, nicht
/// Fortschritt") for it to count as a hotspot. First-cut, adjustable
/// threshold — not yet backed by a distribution study of what counts as
/// normal churn for a healthy file (mirrors
/// [`crate::duplication::DEFAULT_MIN_TOKENS`]'s arbitrary-but-documented
/// style).
/// `pub(crate)`: also reused by `crate::coverage::untested_hotspots`, so the
/// two rules agree on what "high churn" means for the same workspace.
pub(crate) const CHURN_HOTSPOT_THRESHOLD: u32 = 5;
/// The churn window this rule assumes its caller used — see [`churn_hotspots`].
/// `pub(crate)`: see [`CHURN_HOTSPOT_THRESHOLD`].
pub(crate) const CHURN_HOTSPOT_WINDOW_DAYS: i64 = 14;

/// Renders churn counts (see [`crate::git::churn`], called by the caller
/// with a 14-day window) at or above [`CHURN_HOTSPOT_THRESHOLD`] as
/// findings — a file reworked this often in two weeks is a rewrite in
/// progress, not steady forward progress (todo.md §3.G). `churn`'s paths
/// are already relative to the repository root, so findings here carry
/// that same relative path, unlike most other `collect_findings` rules
/// (which use absolute paths sourced from [`crate::ingest::SourceFile`]).
pub fn churn_hotspots(churn: &HashMap<PathBuf, u32>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = churn
        .iter()
        .filter(|&(_, &count)| count >= CHURN_HOTSPOT_THRESHOLD)
        .map(|(file, &count)| Finding {
            id: format!("{CHURN_HOTSPOT_RULE}:{}", file.display()).into(),
            rule: CHURN_HOTSPOT_RULE.into(),
            severity: Severity::Warn,
            location: Location {
                file: file.clone(),
                line: OneBasedLine::FIRST,
                item_path: file.display().to_string(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(json!({
                "commits_in_window": count,
                "window_days": CHURN_HOTSPOT_WINDOW_DAYS,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
        .collect();
    // `churn` is a `HashMap`, so its iteration order isn't stable — sort for
    // deterministic output.
    findings.sort_by(|a, b| a.location.file.cmp(&b.location.file));
    findings
}

/// Minimum function size, in lines, for `complexity-inflation` to consider
/// firing (see todo.md §3.G: "Hohe LOC bei niedriger Cyclomatic Complexity
/// → Boilerplate-Wucherung"). First-cut, adjustable threshold.
const MIN_LOC_FOR_INFLATION: usize = 40;
/// Maximum cyclomatic complexity a function this long may have and still
/// count as boilerplate rather than real branching logic.
const MAX_COMPLEXITY_FOR_INFLATION: u32 = 3;

/// Flags functions that are long but barely branch — a shape more typical
/// of copy-pasted/boilerplate-heavy code than of hand-written logic (see
/// todo.md §3.G).
pub fn complexity_inflation(functions: &[FunctionInfo]) -> Vec<Finding> {
    functions
        .iter()
        .filter(|function| {
            function.lines_of_code >= MIN_LOC_FOR_INFLATION
                && function.cyclomatic <= MAX_COMPLEXITY_FOR_INFLATION
        })
        .map(|function| Finding {
            id: format!(
                "{COMPLEXITY_INFLATION_RULE}:{}:{}",
                function.file.display(),
                function.qualified_name
            )
            .into(),
            rule: COMPLEXITY_INFLATION_RULE.into(),
            severity: Severity::Warn,
            location: Location {
                file: function.file.clone(),
                line: OneBasedLine::new(function.line).expect("proc-macro2 span lines are 1-based"),
                item_path: function.qualified_name.clone(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(json!({
                "lines_of_code": function.lines_of_code,
                "cyclomatic": function.cyclomatic,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
        .collect()
}

/// Minimum number of sibling files (same parent directory) that changed
/// within the last 12 months for an unchanged file to count as frozen (see
/// todo.md §3.G: "Module ohne Änderung >12 Monate bei gleichzeitig
/// wachsendem Umfeld"). Below this, an unchanged file is just as likely to
/// be a quiet corner of a quiet directory as a frozen spot in an otherwise
/// active one.
const MIN_ACTIVE_SIBLINGS: u32 = 2;
/// The churn window this rule assumes its caller used — see [`legacy_freeze`].
const LEGACY_FREEZE_WINDOW_DAYS: i64 = 365;

/// Flags files with zero commits in the last 12 months whose directory
/// otherwise keeps changing — a module the rest of its neighborhood has
/// moved past (see todo.md §3.G). `churn_12mo` and `all_files` must use the
/// same path representation (both relative to the repository root,
/// matching [`crate::git::churn`]'s own convention) for the
/// membership/sibling comparisons below to line up.
pub fn legacy_freeze(churn_12mo: &HashMap<PathBuf, u32>, all_files: &[PathBuf]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in all_files {
        let is_active = churn_12mo.get(file).is_some_and(|&count| count > 0);
        if is_active {
            continue;
        }
        let Some(parent) = file.parent() else {
            continue;
        };
        let active_siblings = all_files
            .iter()
            .filter(|other| other.as_path() != file.as_path() && other.parent() == Some(parent))
            .filter(|other| churn_12mo.get(*other).is_some_and(|&count| count > 0))
            .count() as u32;
        if active_siblings < MIN_ACTIVE_SIBLINGS {
            continue;
        }
        findings.push(Finding {
            id: format!("{LEGACY_FREEZE_RULE}:{}", file.display()).into(),
            rule: LEGACY_FREEZE_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: file.clone(),
                line: OneBasedLine::FIRST,
                item_path: file.display().to_string(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(json!({
                "active_siblings": active_siblings,
                "window_days": LEGACY_FREEZE_WINDOW_DAYS,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }
    findings
}

/// Builders targeting a struct with at most this many fields are considered
/// "small enough that a builder is unnecessary ceremony" (todo.md §3.G:
/// "Builder für Struct mit ≤2 Feldern").
const MAX_TARGET_FIELDS_FOR_BUILDER_INFLATION: usize = 2;

/// The sole field of a single-field struct, identified well enough to
/// recognize a `self.<field>` access in a method body.
#[derive(Clone)]
enum SoleField {
    Named(String),
    Unnamed,
}

impl SoleField {
    fn label(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::Unnamed => "0".to_string(),
        }
    }
}

struct StructRecord {
    name: String,
    field_count: usize,
    sole_field: Option<SoleField>,
    line: usize,
}

/// A single-file pass over every `syn::ItemStruct`/`syn::ItemImpl`,
/// collecting exactly the information the three `abstraction-inflation`
/// sub-checks need. Every other Fast Tier analyzer (`complexity`,
/// `duplication`, `slop`) independently re-parses each file too, rather
/// than sharing a parsed-AST cache across modules — this follows that same,
/// already-established pattern.
#[derive(Default)]
struct FileCollector<'ast> {
    structs: Vec<StructRecord>,
    /// (trait_name, self_type, impl's own line) — collected per file, then
    /// merged into a workspace-wide map by the caller.
    trait_impls: Vec<(String, String, usize)>,
    /// Inherent (non-trait) impl methods, keyed by the `Self` type name.
    inherent_methods: HashMap<String, Vec<&'ast ImplItemFn>>,
}

/// The last path segment's name, or `"?"` for a type this doesn't
/// recognize (mirrors `crate::functions::type_name`, kept local so this
/// module doesn't need to reach into the private helper of an unrelated
/// detector — same rationale as `crate::slop`'s own copy).
fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map_or_else(|| "?".to_string(), |segment| segment.ident.to_string()),
        _ => "?".to_string(),
    }
}

impl<'ast> Visit<'ast> for FileCollector<'ast> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let (field_count, sole_field) = match &node.fields {
            Fields::Named(fields) => {
                let count = fields.named.len();
                let sole = (count == 1)
                    .then(|| fields.named.first().and_then(|field| field.ident.as_ref()))
                    .flatten()
                    .map(|ident| SoleField::Named(ident.to_string()));
                (count, sole)
            }
            Fields::Unnamed(fields) => {
                let count = fields.unnamed.len();
                (count, (count == 1).then_some(SoleField::Unnamed))
            }
            Fields::Unit => (0, None),
        };
        self.structs.push(StructRecord {
            name: node.ident.to_string(),
            field_count,
            sole_field,
            line: node.span().start().line,
        });
        visit::visit_item_struct(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let self_type = type_name(&node.self_ty);
        if let Some((_, path, _)) = &node.trait_ {
            let trait_name = path
                .segments
                .last()
                .map_or_else(|| "?".to_string(), |segment| segment.ident.to_string());
            self.trait_impls
                .push((trait_name, self_type, node.span().start().line));
        } else {
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    self.inherent_methods
                        .entry(self_type.clone())
                        .or_default()
                        .push(method);
                }
            }
        }
        visit::visit_item_impl(self, node);
    }
}

/// Whether `expr` is exactly `self.<field>.<some method>(...)` — a
/// single-expression delegation to the struct's sole field.
fn is_sole_field_method_call(expr: &Expr, field: &SoleField) -> bool {
    let Expr::MethodCall(call) = expr else {
        return false;
    };
    let Expr::Field(field_expr) = call.receiver.as_ref() else {
        return false;
    };
    let Expr::Path(path_expr) = field_expr.base.as_ref() else {
        return false;
    };
    if !path_expr.path.is_ident("self") {
        return false;
    }
    match (&field_expr.member, field) {
        (Member::Named(ident), SoleField::Named(name)) => ident == name,
        (Member::Unnamed(index), SoleField::Unnamed) => index.index == 0,
        _ => false,
    }
}

/// Whether `method`'s entire body is [`is_sole_field_method_call`] — see
/// todo.md §3.G "Wrapper-Typ ohne eigenes Verhalten". Restricted to a
/// single-statement body deliberately: a method that does anything besides
/// forwarding to the field is real behavior, not pure delegation.
fn is_delegating_method(method: &ImplItemFn, field: &SoleField) -> bool {
    let [Stmt::Expr(expr, _)] = method.block.stmts.as_slice() else {
        return false;
    };
    is_sole_field_method_call(expr, field)
}

/// Whether `method` is `fn build(self) -> <target_name>` or `fn build(self)
/// -> Result<<target_name>, _>` — see todo.md §3.G "Builder für Struct mit
/// ≤2 Feldern".
fn is_build_method_for(method: &ImplItemFn, target_name: &str) -> bool {
    if method.sig.ident != "build" {
        return false;
    }
    let takes_self_by_value = matches!(
        method.sig.inputs.first(),
        Some(FnArg::Receiver(receiver)) if receiver.reference.is_none()
    );
    if !takes_self_by_value {
        return false;
    }
    let ReturnType::Type(_, ty) = &method.sig.output else {
        return false;
    };
    let Type::Path(type_path) = ty.as_ref() else {
        return false;
    };
    let Some(last) = type_path.path.segments.last() else {
        return false;
    };
    if last.ident == target_name {
        return true;
    }
    if last.ident != "Result" {
        return false;
    }
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return false;
    };
    matches!(
        args.args.first(),
        Some(GenericArgument::Type(Type::Path(inner)))
            if inner.path.segments.last().is_some_and(|segment| segment.ident == target_name)
    )
}

fn abstraction_finding(
    file: &Path,
    line: usize,
    item_path: String,
    evidence: serde_json::Value,
) -> Finding {
    Finding {
        id: format!(
            "{ABSTRACTION_INFLATION_RULE}:{}:{line}:{item_path}",
            file.display()
        )
        .into(),
        rule: ABSTRACTION_INFLATION_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(line).expect("proc-macro2 span lines are 1-based"),
            item_path,
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Three structural sub-patterns from todo.md §3.G `abstraction-inflation`
/// ("Trait mit genau einem Impl; Wrapper-Typ ohne eigenes Verhalten;
/// Builder für Struct mit ≤2 Feldern"), all reported under one rule id —
/// `evidence.kind` distinguishes `single-impl-trait` / `delegating-wrapper`
/// / `builder-for-small-struct`.
///
/// Only [`SourceKind::Authored`] files are analyzed, matching the rest of
/// the codebase's Generated-Code-Policy (todo.md §3.A).
///
/// Sub-check 2 (delegating wrapper) and the `build()`-method half of
/// sub-check 3 (builder) only look at impl blocks in the *same file* as the
/// struct they belong to — a cross-file impl block for the same struct is a
/// known v1 simplification. Sub-check 1 (single-impl trait) and the
/// struct-shape half of sub-check 3 are workspace-wide, since that's
/// exactly the correlation they need (an impl can live in a different file
/// than its trait; a builder's target struct is often defined elsewhere).
pub fn analyze_workspace_structural<'a>(
    source_files: impl IntoIterator<Item = &'a SourceFile>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut trait_impls: HashMap<String, Vec<(PathBuf, String, usize)>> = HashMap::new();
    let mut struct_field_counts: HashMap<String, usize> = HashMap::new();
    let mut builder_matches: Vec<(String, String, PathBuf, usize)> = Vec::new();

    for file in source_files {
        if file.kind != SourceKind::Authored {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&file.path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&source) else {
            continue;
        };

        let mut collector = FileCollector::default();
        collector.visit_file(&ast);

        for (trait_name, self_type, line) in collector.trait_impls {
            trait_impls
                .entry(trait_name)
                .or_default()
                .push((file.path.clone(), self_type, line));
        }
        for record in &collector.structs {
            struct_field_counts
                .entry(record.name.clone())
                .or_insert(record.field_count);
        }

        // Sub-check 2: delegating wrapper.
        for record in collector.structs.iter().filter(|r| r.field_count == 1) {
            let Some(sole_field) = &record.sole_field else {
                continue;
            };
            let Some(methods) = collector.inherent_methods.get(&record.name) else {
                continue;
            };
            if methods.is_empty() {
                continue;
            }
            if methods
                .iter()
                .all(|method| is_delegating_method(method, sole_field))
            {
                findings.push(abstraction_finding(
                    &file.path,
                    record.line,
                    record.name.clone(),
                    json!({
                        "kind": "delegating-wrapper",
                        "struct": record.name,
                        "delegates_to_field": sole_field.label(),
                    }),
                ));
            }
        }

        // Sub-check 3a: builder candidates, matched against a same-file
        // `build()` method here; the target struct's field count is only
        // known once every file has been visited, so that half happens
        // after this loop (see sub-check 3b below).
        for record in &collector.structs {
            let Some(target_name) = record
                .name
                .strip_suffix("Builder")
                .filter(|target| !target.is_empty())
            else {
                continue;
            };
            let Some(methods) = collector.inherent_methods.get(&record.name) else {
                continue;
            };
            if methods
                .iter()
                .any(|method| is_build_method_for(method, target_name))
            {
                builder_matches.push((
                    record.name.clone(),
                    target_name.to_string(),
                    file.path.clone(),
                    record.line,
                ));
            }
        }
    }

    // Sub-check 1: trait with exactly one impl.
    for (trait_name, impls) in &trait_impls {
        let [(file, self_type, line)] = impls.as_slice() else {
            continue;
        };
        findings.push(abstraction_finding(
            file,
            *line,
            format!("<{self_type} as {trait_name}>"),
            json!({
                "kind": "single-impl-trait",
                "trait": trait_name,
                "self_type": self_type,
            }),
        ));
    }

    // Sub-check 3b: does the builder's target struct exist workspace-wide
    // with at most `MAX_TARGET_FIELDS_FOR_BUILDER_INFLATION` fields?
    for (builder_name, target_name, file, line) in &builder_matches {
        let Some(&target_field_count) = struct_field_counts.get(target_name) else {
            continue;
        };
        if target_field_count > MAX_TARGET_FIELDS_FOR_BUILDER_INFLATION {
            continue;
        }
        findings.push(abstraction_finding(
            file,
            *line,
            builder_name.clone(),
            json!({
                "kind": "builder-for-small-struct",
                "builder": builder_name,
                "target": target_name,
                "target_field_count": target_field_count,
            }),
        ));
    }

    // Deterministic output: `trait_impls`/`struct_field_counts` are
    // `HashMap`s, so the order findings were pushed above isn't stable.
    findings.sort_by(|a, b| {
        (&a.location.file, a.location.line, &a.id).cmp(&(&b.location.file, b.location.line, &b.id))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn churn_hotspots_fires_at_or_above_threshold() {
        let churn = HashMap::from([(PathBuf::from("hot.rs"), 5), (PathBuf::from("cold.rs"), 2)]);

        let findings = churn_hotspots(&churn);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, CHURN_HOTSPOT_RULE);
        assert_eq!(findings[0].location.file, PathBuf::from("hot.rs"));
        assert_eq!(
            findings[0].evidence,
            Some(json!({"commits_in_window": 5, "window_days": 14}))
        );
    }

    fn function_info(lines_of_code: usize, cyclomatic: u32) -> FunctionInfo {
        FunctionInfo {
            qualified_name: "f".to_string(),
            file: PathBuf::from("src/lib.rs"),
            line: 1,
            cyclomatic,
            lines_of_code,
        }
    }

    #[test]
    fn complexity_inflation_fires_for_long_low_branching_functions_only() {
        let functions = vec![
            function_info(50, 2),
            function_info(50, 10),
            function_info(10, 1),
        ];

        let findings = complexity_inflation(&functions);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, COMPLEXITY_INFLATION_RULE);
        assert_eq!(
            findings[0].evidence,
            Some(json!({"lines_of_code": 50, "cyclomatic": 2}))
        );
    }

    #[test]
    fn legacy_freeze_fires_when_enough_siblings_are_active() {
        let churn = HashMap::from([
            (PathBuf::from("src/a.rs"), 3),
            (PathBuf::from("src/b.rs"), 1),
        ]);
        let all_files = vec![
            PathBuf::from("src/a.rs"),
            PathBuf::from("src/b.rs"),
            PathBuf::from("src/frozen.rs"),
        ];

        let findings = legacy_freeze(&churn, &all_files);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.file, PathBuf::from("src/frozen.rs"));
        assert_eq!(
            findings[0].evidence,
            Some(json!({"active_siblings": 2, "window_days": 365}))
        );
    }

    #[test]
    fn legacy_freeze_does_not_fire_with_zero_active_siblings() {
        let churn: HashMap<PathBuf, u32> = HashMap::new();
        let all_files = vec![PathBuf::from("src/a.rs"), PathBuf::from("src/frozen.rs")];

        assert!(legacy_freeze(&churn, &all_files).is_empty());
    }

    #[test]
    fn legacy_freeze_does_not_fire_with_only_one_active_sibling() {
        let churn = HashMap::from([(PathBuf::from("src/a.rs"), 3)]);
        let all_files = vec![
            PathBuf::from("src/a.rs"),
            PathBuf::from("src/b.rs"),
            PathBuf::from("src/frozen.rs"),
        ];

        assert!(legacy_freeze(&churn, &all_files).is_empty());
    }

    fn authored(paths: impl IntoIterator<Item = PathBuf>) -> Vec<SourceFile> {
        paths
            .into_iter()
            .map(|path| SourceFile {
                path,
                kind: SourceKind::Authored,
            })
            .collect()
    }

    #[test]
    fn single_impl_trait_fires_but_two_impls_do_not() {
        let dir = TempDir::new("abstraction-single-impl");
        let one_impl = dir.join("one_impl.rs");
        std::fs::write(
            &one_impl,
            r#"
trait Greet {
    fn hi(&self);
}
struct A;
impl Greet for A {
    fn hi(&self) {}
}
"#,
        )
        .unwrap();

        let files = authored([one_impl]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "single-impl-trait")
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["trait"], "Greet");

        let dir = TempDir::new("abstraction-two-impls");
        let two_impls = dir.join("two_impls.rs");
        std::fs::write(
            &two_impls,
            r#"
trait Greet {
    fn hi(&self);
}
struct A;
struct B;
impl Greet for A {
    fn hi(&self) {}
}
impl Greet for B {
    fn hi(&self) {}
}
"#,
        )
        .unwrap();

        let files = authored([two_impls]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "single-impl-trait")
            .collect();
        assert!(hits.is_empty());
    }

    #[test]
    fn delegating_wrapper_fires_but_non_delegating_method_does_not() {
        let dir = TempDir::new("abstraction-wrapper-delegating");
        let wrapper = dir.join("wrapper.rs");
        std::fs::write(
            &wrapper,
            r#"
struct Wrapper(Vec<i32>);
impl Wrapper {
    fn len(&self) -> usize {
        self.0.len()
    }
}
"#,
        )
        .unwrap();

        let files = authored([wrapper]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "delegating-wrapper")
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["struct"], "Wrapper");

        let dir = TempDir::new("abstraction-wrapper-non-delegating");
        let non_delegating = dir.join("non_delegating.rs");
        std::fs::write(
            &non_delegating,
            r#"
struct Wrapper(Vec<i32>);
impl Wrapper {
    fn len(&self) -> usize {
        self.0.len() + 1
    }
}
"#,
        )
        .unwrap();

        let files = authored([non_delegating]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "delegating-wrapper")
            .collect();
        assert!(hits.is_empty());
    }

    #[test]
    fn builder_for_small_struct_fires_but_not_for_a_larger_target() {
        let dir = TempDir::new("abstraction-builder-small");
        let small = dir.join("small.rs");
        std::fs::write(
            &small,
            r#"
struct Foo {
    a: i32,
    b: i32,
}
struct FooBuilder;
impl FooBuilder {
    fn build(self) -> Foo {
        Foo { a: 0, b: 0 }
    }
}
"#,
        )
        .unwrap();

        let files = authored([small]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "builder-for-small-struct")
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence.as_ref().unwrap()["target"], "Foo");

        let dir = TempDir::new("abstraction-builder-large");
        let large = dir.join("large.rs");
        std::fs::write(
            &large,
            r#"
struct Foo {
    a: i32,
    b: i32,
    c: i32,
}
struct FooBuilder;
impl FooBuilder {
    fn build(self) -> Foo {
        Foo { a: 0, b: 0, c: 0 }
    }
}
"#,
        )
        .unwrap();

        let files = authored([large]);
        let findings = analyze_workspace_structural(files.iter());
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.evidence.as_ref().unwrap()["kind"] == "builder-for-small-struct")
            .collect();
        assert!(hits.is_empty());
    }
}
