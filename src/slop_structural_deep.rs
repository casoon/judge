//! The two G4 "Strukturelle Slop-Signale" rules that
//! [`crate::slop_structural`] deliberately leaves out (see its module docs
//! and todo.md §3.G G4): `duplicative-reinvention` and `connectivity-drop`.
//!
//! Both need to know whether a function is actually *referenced from outside
//! its own file* — "Neue Clone-Familie, deren Mitglieder in isolierten neuen
//! Dateien liegen und keinen Fan-in haben" and "Neue Funktionen ohne
//! Cross-File-Aufrufe" are claims about real call graphs, not about
//! identifier text. `syn` alone can't tell "this name is called from another
//! file" apart from "there happens to be a same-named identifier somewhere
//! else" — that requires semantic reference resolution, which only the Deep
//! Tier's `find_all_refs` (via [`crate::deep`]) provides. This is the same
//! machinery [`crate::dead_code`]'s `unused-pub-workspace` and
//! [`crate::reachability`]'s `--why-live` already use, just filtered by
//! *file* instead of by *crate*.
//!
//! `duplicative-reinvention` and `connectivity-drop` are current-state
//! `Info` findings, not `Warn`/`Fail` — the same "let baseline diff handle
//! the trend" pattern [`crate::slop`]'s `suppression-debt` and
//! `ignored-test-accumulation` already use (see that module's docs): emit
//! what exists today, unconditionally, with a `Finding.id` stable across
//! runs (embeds file + qualified name), and the existing baseline/delta
//! system turns a genuinely new occurrence into `code_introduced` on its
//! own.
//!
//! **Two function shapes are excluded from both rules' candidate sets
//! entirely, not just down-weighted** (see
//! [`is_reliably_checkable_for_fan_in`]):
//!
//! - `#[test]`/`#[bench]`-attributed functions. These are entry points by
//!   design — [`crate::reachability`]'s own entry-point model already
//!   recognizes them as such (`has_attr_ending_in(attrs, "test"/"bench")`).
//!   A test having zero cross-file callers is normal, not a slop signal, so
//!   this reuses that exact recognition logic rather than a second one.
//! - Methods inside `impl TraitName for SomeType { .. }` blocks. These are
//!   routinely invoked through operator/macro sugar the reference search
//!   can't see — `{}`/`println!` calls `Display::fmt`, `for` loops call
//!   `Iterator::next`, drop-glue calls `Drop::drop` — never through a
//!   literal `.method_name()` call site. `find_all_refs` only finds literal
//!   references, so trait-impl methods systematically look unreferenced
//!   even when genuinely used everywhere. This is a structural blind spot
//!   of the reference-search approach, not something `deep.rs` can fix.
//!
//! Both are "this candidate should never have been considered", not "keep
//! but weaker evidence" — flagging a test function or a `Display` impl as
//! structurally unwired would actively mislead, and a false positive here
//! costs more trust than the false negatives it avoids are worth (todo.md
//! §3.A).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::deep::{DeepContext, DeepError, FileId};
use crate::duplication::WorkspaceDuplication;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::Workspace;
use crate::reachability::has_attr_ending_in;

pub const DUPLICATIVE_REINVENTION_RULE: &str = "duplicative-reinvention";
/// Bump when the duplicative-reinvention rule's logic changes (see todo.md
/// §5 "Regelversions-Schutz").
pub const DUPLICATIVE_REINVENTION_RULE_REVISION: u32 = 1;

pub const CONNECTIVITY_DROP_RULE: &str = "connectivity-drop";
pub const CONNECTIVITY_DROP_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum SlopStructuralDeepError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for SlopStructuralDeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for SlopStructuralDeepError {}

#[derive(Debug, Default)]
pub struct DeepStructuralReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<SlopStructuralDeepError>,
    /// Number of functions actually queried (every function-like item
    /// `walk_functions` finds, not just `pub` ones — see the module docs'
    /// note on `connectivity-drop`'s broader scope).
    pub checked: usize,
}

/// One function's cross-file fan-in, resolved once and reused by both rules
/// below.
struct FunctionFanIn {
    qualified_name: String,
    file: PathBuf,
    line: usize,
    /// Number of distinct files, other than `file` itself, containing a
    /// genuine reference to this function (see
    /// [`cross_file_reference_count`]).
    cross_file_references: usize,
}

/// Counts the files — other than `file_id`, the item's own defining file —
/// that contain a genuine reference to the item at `position`. This is the
/// shared "cross-file fan-in" primitive both rules need: it reuses
/// [`crate::deep::referencing_files`], the exact same file-level reference
/// set [`crate::dead_code`] already computes for its own cross-*crate*
/// check, just filtered by *file* instead of by crate. No changes to
/// `dead_code.rs` or `deep.rs` were needed — `referencing_files` already
/// returns per-file granularity, `dead_code`'s own cross-crate check simply
/// maps each file to its owning crate before comparing, where this maps
/// each file to itself.
fn cross_file_reference_count(
    analysis: &ra_ap_ide::Analysis,
    file_id: FileId,
    position: ra_ap_ide::FilePosition,
    include_tests: bool,
) -> Result<usize, DeepError> {
    let referencing = crate::deep::referencing_files(analysis, position, include_tests)?;
    Ok(referencing
        .iter()
        .filter(|&&referencing_file| referencing_file != file_id)
        .count())
}

/// Whether a function's cross-file reference count is a reliable "unused"
/// signal at all (see module docs for why the two excluded shapes aren't).
/// `false` for `#[test]`/`#[bench]`-attributed functions and for methods
/// inside `impl TraitName for SomeType` blocks; `true` otherwise. Shared by
/// [`collect_function_fan_in`] (so `connectivity-drop` never sees these
/// candidates) and, transitively, by `duplicative_reinvention_findings`
/// (whose fan-in lookup only has entries for functions this let through, so
/// a clone member outside this set is treated as "not isolated" the same
/// way a generated-and-excluded member already is).
fn is_reliably_checkable_for_fan_in(attrs: &[syn::Attribute], in_trait_impl: bool) -> bool {
    !in_trait_impl && !has_attr_ending_in(attrs, "test") && !has_attr_ending_in(attrs, "bench")
}

/// Walks every function-like item in the workspace (see
/// [`crate::functions::walk_functions`] — free functions, impl/trait
/// methods, same population [`crate::complexity`] and [`crate::duplication`]
/// already analyze), resolving each to its cross-file fan-in. Deliberately
/// not restricted to `pub` items — unlike `unused-pub-workspace`,
/// `connectivity-drop` is about *any* function that looks structurally
/// unwired, `pub` or not (see module docs). Functions for which fan-in
/// isn't a reliable signal (see [`is_reliably_checkable_for_fan_in`]) are
/// skipped entirely, not just excluded from the findings — they never enter
/// `records` at all.
fn collect_function_fan_in(
    workspace: &Workspace,
    ctx: &DeepContext,
    analysis: &ra_ap_ide::Analysis,
    include_tests: bool,
) -> (Vec<FunctionFanIn>, Vec<SlopStructuralDeepError>) {
    let mut records = Vec::new();
    let mut errors = Vec::new();

    for krate in &workspace.crates {
        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }
            let Some(file_id) = ctx.file_id(&file.path) else {
                continue;
            };

            let source = match std::fs::read_to_string(&file.path) {
                Ok(source) => source,
                Err(err) => {
                    errors.push(SlopStructuralDeepError::Io(file.path.clone(), err));
                    continue;
                }
            };
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    errors.push(SlopStructuralDeepError::Parse(file.path.clone(), err));
                    continue;
                }
            };

            walk_functions(&ast, |site| {
                if !is_reliably_checkable_for_fan_in(site.attrs, site.in_trait_impl) {
                    return;
                }

                let offset = site.ident_span.byte_range().start as u32;
                let position = ra_ap_ide::FilePosition {
                    file_id,
                    offset: offset.into(),
                };
                match cross_file_reference_count(analysis, file_id, position, include_tests) {
                    Ok(cross_file_references) => records.push(FunctionFanIn {
                        qualified_name: site.qualified_name,
                        file: file.path.clone(),
                        line: site.ident_span.start().line,
                        cross_file_references,
                    }),
                    Err(err) => errors.push(SlopStructuralDeepError::Deep(err)),
                }
            });
        }
    }

    (records, errors)
}

/// `connectivity-drop`: a function with zero references from any file other
/// than its own (see todo.md §3.G — "Neue Funktionen ohne
/// Cross-File-Aufrufe"). `records` already excludes `#[test]`/`#[bench]`
/// functions and trait-impl methods (see [`is_reliably_checkable_for_fan_in`]
/// and the module docs), so this doesn't need to re-check either.
///
/// **Accepted false-positive class, documented rather than hidden:** a
/// brand-new private helper function that's only ever used within its own
/// file *by design* is completely normal Rust, not a slop signal — this
/// rule can't distinguish that from genuinely unwired, never-integrated
/// code. Hence `evidence_class: heuristic` (the reference resolution itself
/// is exact; framing "no cross-file callers" as a slop signal is
/// interpretive) and `Severity::Info` rather than `Warn`.
fn connectivity_drop_findings(records: &[FunctionFanIn]) -> Vec<Finding> {
    records
        .iter()
        .filter(|record| record.cross_file_references == 0)
        .map(|record| Finding {
            id: format!(
                "{CONNECTIVITY_DROP_RULE}:{}:{}",
                record.file.display(),
                record.qualified_name
            )
            .into(),
            rule: CONNECTIVITY_DROP_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: record.file.clone(),
                line: OneBasedLine::new(record.line).expect("proc-macro2 span lines are 1-based"),
                item_path: record.qualified_name.clone(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(json!({
                "tier": "deep",
                "cross_file_references": 0,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
        .collect()
}

/// `duplicative-reinvention`: a clone family (see [`crate::duplication`])
/// every one of whose members has zero cross-file references — "Neue
/// Clone-Familie, deren Mitglieder in isolierten neuen Dateien liegen und
/// keinen Fan-in haben" (todo.md §3.G). One finding per family, not per
/// member — "eine Familie ist eine Entscheidung, ein Paar ist Rauschen"
/// (todo.md §3.D) applies here too.
///
/// **Precision level, a documented judgment call:** the spec's fuller check
/// ("no other symbol in the member's file has cross-file references either
/// — the whole file is isolated") would need correlating every clone
/// member's file against every other function *and* every other
/// clone/type/const in that file. This implements the simpler, dominant
/// signal instead: the member's own function has zero cross-file
/// references. A member whose file is otherwise well-connected but whose
/// specific duplicated function isn't called from elsewhere still matches
/// the rule's core claim ("this clone was reinvented, not reused") closely
/// enough to be worth the simpler check.
///
/// **Anchor location:** `duplication.rs` doesn't yet compute a
/// canonicalization candidate (todo.md §3.D describes one — "das Exemplar
/// mit der höchsten Fan-in" — but it isn't built), so this anchors on the
/// family's first member, which [`crate::duplication::find_clone_families`]
/// already sorts by `(file, start_line)` for determinism.
fn duplicative_reinvention_findings(
    duplication: &WorkspaceDuplication,
    records: &[FunctionFanIn],
) -> Vec<Finding> {
    let fan_in: HashMap<(&Path, &str), usize> = records
        .iter()
        .map(|record| {
            (
                (record.file.as_path(), record.qualified_name.as_str()),
                record.cross_file_references,
            )
        })
        .collect();

    let mut findings = Vec::new();
    for family in &duplication.families {
        // A member whose function isn't in `records` at all — excluded as
        // generated, or excluded as a `#[test]`/`#[bench]` function or
        // trait-impl method whose fan-in isn't a reliable signal (see
        // `is_reliably_checkable_for_fan_in`) — is treated as *not*
        // isolated: "im Zweifel nicht melden" (todo.md §3.A) rather than
        // guessing. A family made entirely of such members therefore never
        // gets flagged on the strength of a fan-in signal that doesn't mean
        // anything for those shapes.
        let all_isolated = family.members.iter().all(|member| {
            fan_in
                .get(&(member.file.as_path(), member.qualified_name.as_str()))
                .is_some_and(|&cross_file_references| cross_file_references == 0)
        });
        if !all_isolated {
            continue;
        }

        // `find_clone_families` only ever keeps families with more than one
        // member (see `duplication.rs`), so this is always populated.
        let anchor = &family.members[0];
        findings.push(Finding {
            id: format!(
                "{DUPLICATIVE_REINVENTION_RULE}:{}:{}",
                anchor.file.display(),
                anchor.qualified_name
            )
            .into(),
            rule: DUPLICATIVE_REINVENTION_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: anchor.file.clone(),
                line: OneBasedLine::new(anchor.start_line)
                    .expect("proc-macro2 span lines are 1-based"),
                item_path: anchor.qualified_name.clone(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(json!({
                "tier": "deep",
                "member_count": family.members.len(),
                "files": family.members.iter()
                    .map(|member| member.file.display().to_string())
                    .collect::<Vec<_>>(),
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }
    findings
}

/// Runs `connectivity-drop` and `duplicative-reinvention` over `workspace`,
/// sharing one Deep Tier workspace load and one function-fan-in pass across
/// both rules. `duplication` is the caller's already-computed
/// [`WorkspaceDuplication`] (Fast Tier, cheap) — this function only adds the
/// Deep Tier fan-in check on top of it, it doesn't re-run duplicate
/// detection itself.
pub fn analyze_workspace(
    workspace: &Workspace,
    duplication: &WorkspaceDuplication,
    include_tests: bool,
) -> Result<DeepStructuralReport, SlopStructuralDeepError> {
    let ctx = DeepContext::load(&workspace.root).map_err(SlopStructuralDeepError::Deep)?;
    let analysis = ctx.analysis();

    let (records, errors) = collect_function_fan_in(workspace, &ctx, &analysis, include_tests);
    let checked = records.len();

    let mut findings = connectivity_drop_findings(&records);
    findings.extend(duplicative_reinvention_findings(duplication, &records));

    Ok(DeepStructuralReport {
        findings,
        errors,
        checked,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::duplication::{CloneFamily, CloneMember, DupeMode};
    use crate::test_util::TempDir;

    fn write_crate(dir: &TempDir, name: &str, deps: &[(&str, &str)], lib_source: &str) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        let mut manifest =
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
        if !deps.is_empty() {
            manifest.push_str("\n[dependencies]\n");
            for (dep_name, rel_path) in deps {
                manifest.push_str(&format!("{dep_name} = {{ path = \"{rel_path}\" }}\n"));
            }
        }
        std::fs::write(dir.join(name).join("Cargo.toml"), manifest).unwrap();
        std::fs::write(dir.join(name).join("src/lib.rs"), lib_source).unwrap();
    }

    fn write_workspace_manifest(dir: &TempDir, members: &[&str]) {
        let members_toml = members
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[workspace]\nmembers = [{members_toml}]\nresolver = \"2\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn connectivity_drop_flags_a_function_with_no_cross_file_callers() {
        let dir = TempDir::new("connectivity-drop-isolated");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn called_from_elsewhere() -> i32 {
    1
}

fn isolated_helper() -> i32 {
    2
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::called_from_elsewhere()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, true).unwrap();

        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("called_from_elsewhere"),
            "called from `consumer` — must not be flagged"
        );
        assert!(
            names.contains("isolated_helper"),
            "never referenced from another file — must be flagged"
        );
    }

    #[test]
    fn connectivity_drop_does_not_flag_a_test_function() {
        let dir = TempDir::new("connectivity-drop-test-fn");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn called_from_elsewhere() -> i32 {
    1
}

#[test]
fn some_test() {
    assert_eq!(1, 1);
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::called_from_elsewhere()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, true).unwrap();

        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("some_test"),
            "test functions are entry points by design — zero cross-file callers is expected, not a slop signal"
        );
    }

    #[test]
    fn connectivity_drop_does_not_flag_a_trait_impl_method() {
        let dir = TempDir::new("connectivity-drop-trait-impl");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub struct Foo;

impl std::fmt::Display for Foo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "foo")
    }
}
"#,
        );
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"[workspace]
members = ["core"]
resolver = "2"
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, true).unwrap();

        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("Foo::fmt"),
            "trait-impl methods are invoked via implicit dispatch (`{{}}` calls `Display::fmt`) \
             a literal-reference search can't see — must not be flagged"
        );
    }

    #[test]
    fn connectivity_drop_finding_shape_matches_the_documented_contract() {
        let dir = TempDir::new("connectivity-drop-shape");
        write_crate(&dir, "core", &[], "fn isolated() -> i32 {\n    1\n}\n");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"[workspace]
members = ["core"]
resolver = "2"
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, true).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .expect("isolated() must be flagged");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert_eq!(finding.origin, Origin::Code);
        assert_eq!(
            finding.evidence,
            Some(json!({"tier": "deep", "cross_file_references": 0}))
        );
    }

    #[test]
    fn duplicative_reinvention_flags_a_family_with_no_fan_in_on_any_member() {
        let dir = TempDir::new("duplicative-reinvention-isolated");
        write_crate(
            &dir,
            "core",
            &[],
            "fn clone_one() -> i32 {\n    1\n}\n\nfn clone_two() -> i32 {\n    1\n}\n",
        );
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"[workspace]
members = ["core"]
resolver = "2"
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let core_lib = dir.join("core/src/lib.rs");

        let member_a = CloneMember {
            qualified_name: "clone_one".to_string(),
            file: core_lib.clone(),
            start_line: 1,
            end_line: 1,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let member_b = CloneMember {
            qualified_name: "clone_two".to_string(),
            file: core_lib.clone(),
            start_line: 5,
            end_line: 5,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let duplication = WorkspaceDuplication {
            families: vec![CloneFamily {
                members: vec![member_a, member_b],
            }],
            errors: Vec::new(),
            excluded_generated: 0,
        };

        let report = analyze_workspace(&workspace, &duplication, true).unwrap();
        let hit = report
            .findings
            .iter()
            .find(|f| f.rule == DUPLICATIVE_REINVENTION_RULE)
            .expect("a family whose members are never referenced in `records` must be flagged");
        assert_eq!(hit.severity, Severity::Info);
        assert_eq!(hit.evidence_class, EvidenceClass::Heuristic);
        assert_eq!(hit.location.item_path, "clone_one");
        assert_eq!(hit.evidence.as_ref().unwrap()["member_count"], 2);
    }

    #[test]
    fn duplicative_reinvention_does_not_flag_a_family_with_a_referenced_member() {
        let dir = TempDir::new("duplicative-reinvention-referenced");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn clone_one() -> i32 {
    1
}

fn clone_two() -> i32 {
    1
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::clone_one()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let core_lib = dir.join("core/src/lib.rs");

        let member_a = CloneMember {
            qualified_name: "clone_one".to_string(),
            file: core_lib.clone(),
            start_line: 1,
            end_line: 1,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let member_b = CloneMember {
            qualified_name: "clone_two".to_string(),
            file: core_lib.clone(),
            start_line: 5,
            end_line: 5,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let duplication = WorkspaceDuplication {
            families: vec![CloneFamily {
                members: vec![member_a, member_b],
            }],
            errors: Vec::new(),
            excluded_generated: 0,
        };

        let report = analyze_workspace(&workspace, &duplication, true).unwrap();
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DUPLICATIVE_REINVENTION_RULE),
            "clone_one is referenced from `consumer` — the family must not be flagged"
        );
    }

    #[test]
    fn duplicative_reinvention_does_not_flag_a_family_of_test_functions() {
        let dir = TempDir::new("duplicative-reinvention-test-family");
        write_crate(
            &dir,
            "core",
            &[],
            r#"#[test]
fn clone_test_one() {
    assert_eq!(1, 1);
}

#[test]
fn clone_test_two() {
    assert_eq!(1, 1);
}
"#,
        );
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"[workspace]
members = ["core"]
resolver = "2"
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let core_lib = dir.join("core/src/lib.rs");

        let member_a = CloneMember {
            qualified_name: "clone_test_one".to_string(),
            file: core_lib.clone(),
            start_line: 1,
            end_line: 1,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let member_b = CloneMember {
            qualified_name: "clone_test_two".to_string(),
            file: core_lib.clone(),
            start_line: 5,
            end_line: 5,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let duplication = WorkspaceDuplication {
            families: vec![CloneFamily {
                members: vec![member_a, member_b],
            }],
            errors: Vec::new(),
            excluded_generated: 0,
        };

        let report = analyze_workspace(&workspace, &duplication, true).unwrap();
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DUPLICATIVE_REINVENTION_RULE),
            "a family made entirely of #[test] functions must not be flagged — fan-in isn't a \
             reliable signal for test functions"
        );
    }

    /// Undecidable fixture (todo.md §17.5): a function whose only cross-file
    /// caller is a `#[test]` fn in another file. `include_tests: true` is the
    /// same "count every usage" mode [`crate::deep::find_refs`] documents —
    /// this proves a test-only cross-file reference counts exactly like a
    /// production one for `connectivity-drop` in that mode, not a weaker
    /// signal. See the companion test below for the `include_tests: false`
    /// side of this same fixture.
    #[test]
    fn connectivity_drop_counts_a_test_only_cross_file_caller_when_include_tests_is_true() {
        let dir = TempDir::new("connectivity-drop-test-only-caller-included");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn used_only_in_test() -> i32 {
    1
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"#[test]
fn calls_it() {
    assert_eq!(core::used_only_in_test(), 1);
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, true).unwrap();

        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_only_in_test"),
            "called from a #[test] fn in another file — with include_tests: true this counts as \
             a cross-file reference, the same as production usage, so it must not be flagged"
        );
    }

    /// Same fixture as
    /// [`connectivity_drop_counts_a_test_only_cross_file_caller_when_include_tests_is_true`],
    /// with `include_tests: false`: documents that mode's actual, intended
    /// behavior — a cross-file caller that only exists inside a `#[test]` fn
    /// is filtered out just like any other test-only usage, so a function
    /// with no production callers looks structurally unwired even though a
    /// real (test-only) caller exists. This is the "getrennte Graphen für
    /// production, tests und all" design (todo.md §3.A) working as intended,
    /// not a bug — `include_tests` is a caller-selected mode, not an
    /// accident.
    #[test]
    fn connectivity_drop_does_not_count_a_test_only_cross_file_caller_when_include_tests_is_false()
    {
        let dir = TempDir::new("connectivity-drop-test-only-caller-excluded");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn used_only_in_test() -> i32 {
    1
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"#[test]
fn calls_it() {
    assert_eq!(core::used_only_in_test(), 1);
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(&workspace, &duplication, false).unwrap();

        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            names.contains("used_only_in_test"),
            "its only cross-file caller lives inside a #[test] fn — with include_tests: false \
             that reference is filtered out same as any other test-only usage, so the function \
             looks structurally unwired even though a real (test-only) caller exists"
        );
    }

    /// Undecidable fixture (todo.md §17.5): a clone family with one member
    /// in a header-marked generated file (`// @generated` — the same marker
    /// [`crate::ingest`] already recognizes). Real duplication detection run
    /// with `--include-generated` (Fast Tier, `syn`-based) finds and pairs it
    /// just fine — a generated file is still ordinary, parseable Rust source.
    /// [`collect_function_fan_in`] is different: it skips every file whose
    /// `file.kind.is_locally_reportable()` is `false`, unconditionally, with
    /// no `include_generated` override, so `clone_generated` never enters
    /// `records` at all. Per the documented contract on
    /// [`duplicative_reinvention_findings`] ("a member whose function isn't
    /// in records at all ... is treated as *not* isolated"), the whole
    /// family must stay unflagged even though its other, authored member
    /// genuinely has zero cross-file references on its own — "im Zweifel
    /// nicht melden" wins over a signal built on an admittedly incomplete
    /// fan-in table. This confirms the already-documented behavior rather
    /// than uncovering a new one.
    #[test]
    fn duplicative_reinvention_does_not_flag_a_family_with_a_generated_file_member() {
        let dir = TempDir::new("duplicative-reinvention-generated-member");
        std::fs::create_dir_all(dir.join("core/src")).unwrap();
        std::fs::write(
            dir.join("core/Cargo.toml"),
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("core/src/lib.rs"),
            "mod authored;\nmod generated;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("core/src/authored.rs"),
            "fn clone_authored() -> i32 {\n    42\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("core/src/generated.rs"),
            "// @generated by codegen. DO NOT EDIT.\nfn clone_generated() -> i32 {\n    42\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"core\"]\nresolver = \"2\"\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let source_files = workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter());
        let duplication =
            crate::duplication::analyze_workspace(source_files, DupeMode::Strict, 1, true);
        assert_eq!(
            duplication.families.len(),
            1,
            "clone_authored and clone_generated must form one real clone family: {:?}",
            duplication.families
        );

        let report = analyze_workspace(&workspace, &duplication, true).unwrap();
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DUPLICATIVE_REINVENTION_RULE),
            "clone_generated's file is skipped by the fan-in scan (generated code, \
             unconditionally excluded there), so it never enters `records` — the family must be \
             treated as not-all-isolated rather than flagged on an incomplete signal"
        );
    }

    /// Undecidable fixture (todo.md §17.5): a clone family whose only real
    /// caller is invisible proc-macro-generated code — the same blind spot
    /// [`crate::dead_code`] already documents for `unused-pub-workspace`
    /// (see that module's `proc_macro_exposed_crates` and its
    /// `a_pub_fn_reachable_only_through_an_unexpanded_proc_macro_derive_is_falsely_flagged_dead`
    /// test). `duplicative-reinvention` shares [`cross_file_reference_count`]
    /// with `connectivity-drop`, so it inherits the same gap: the Deep Tier
    /// loads with no proc-macro server ([`crate::deep::DeepContext::load`]),
    /// so a call that exists only inside a derive macro's expanded output is
    /// invisible to `find_all_refs`. Here `clone_two`'s only real caller is
    /// such a call — genuinely used, but from generated code the analysis
    /// can never see — so its cross-file reference count comes back `0`,
    /// indistinguishable from `clone_one`, which really is unused, and the
    /// family gets flagged as though neither member had a caller.
    ///
    /// **Known gap, documented rather than hidden — not fixed here.** A full
    /// fix needs real proc-macro expansion across the workspace (todo.md
    /// §2.1, out of scope). Unlike `unused-pub-workspace`, this module
    /// doesn't attach a `proc_macro_expansion_disabled` limitation
    /// disclosure — `duplicative-reinvention` and `connectivity-drop` are
    /// already `Info`-severity, advisory-only findings with no score/verdict
    /// effect (see module docs), so the false positive's cost is lower than
    /// an equivalent gating one; wiring the same crate-wide disclosure this
    /// module doesn't yet have is separate follow-up work, not a "clearly
    /// fixable" bug within this fixture task's scope.
    #[test]
    fn duplicative_reinvention_flags_a_family_whose_only_caller_is_invisible_proc_macro_generated_code()
     {
        let dir = TempDir::new("duplicative-reinvention-proc-macro-blind-spot");
        std::fs::create_dir_all(dir.join("macros/src")).unwrap();
        std::fs::write(
            dir.join("macros/Cargo.toml"),
            r#"[package]
name = "macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("macros/src/lib.rs"),
            r#"use proc_macro::TokenStream;

/// Would-be expansion (never actually run — the Deep Tier loads with no
/// proc-macro server): a call to `clone_two()` the analysis never sees.
#[proc_macro_derive(CallsCloneTwo)]
pub fn calls_clone_two(_input: TokenStream) -> TokenStream {
    "fn __generated_caller() { crate::clone_two(); }".parse().unwrap()
}
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("core/src")).unwrap();
        std::fs::write(
            dir.join("core/Cargo.toml"),
            r#"[package]
name = "core"
version = "0.1.0"
edition = "2021"

[dependencies]
macros = { path = "../macros" }
"#,
        )
        .unwrap();
        std::fs::write(dir.join("core/src/lib.rs"), "mod a;\nmod b;\nmod widget;\n").unwrap();
        std::fs::write(
            dir.join("core/src/a.rs"),
            "pub fn clone_one() -> i32 {\n    7\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("core/src/b.rs"),
            "pub fn clone_two() -> i32 {\n    7\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("core/src/widget.rs"),
            "#[derive(macros::CallsCloneTwo)]\npub struct Widget;\n",
        )
        .unwrap();
        write_workspace_manifest(&dir, &["macros", "core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let source_files = workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter());
        let duplication =
            crate::duplication::analyze_workspace(source_files, DupeMode::Strict, 1, false);
        assert_eq!(
            duplication.families.len(),
            1,
            "clone_one and clone_two must form one real clone family: {:?}",
            duplication.families
        );

        let report = analyze_workspace(&workspace, &duplication, true).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == DUPLICATIVE_REINVENTION_RULE),
            "documents today's actual (policy-violating) behavior: clone_two's only real caller \
             is invisible generated code, so it looks just as isolated as the genuinely-unused \
             clone_one and the family is flagged — see this test's doc comment"
        );
    }
}
