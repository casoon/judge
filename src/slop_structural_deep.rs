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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::complexity::FunctionInfo;
use crate::deep::{DeepContext, DeepError, FileId};
use crate::duplication::WorkspaceDuplication;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::Workspace;
use crate::reachability::{
    ReachabilityError, entry_point_positions, has_attr_ending_in, is_reachable_from_entry,
    position_key,
};

pub const DUPLICATIVE_REINVENTION_RULE: &str = "duplicative-reinvention";
/// Bump when the duplicative-reinvention rule's logic changes (see todo.md
/// §5 "Regelversions-Schutz").
pub const DUPLICATIVE_REINVENTION_RULE_REVISION: u32 = 1;

pub const CONNECTIVITY_DROP_RULE: &str = "connectivity-drop";
pub const CONNECTIVITY_DROP_RULE_REVISION: u32 = 1;

/// Rule id for a function judge's Deep Tier finds no fan-in for, no test
/// path to, and whose file's dominant blame author is no longer active in
/// the repo — see [`orphaned_code_findings`] (todo.md §3.E "orphaned-code").
pub const ORPHANED_CODE_RULE: &str = "orphaned-code";
/// Bump when the orphaned-code rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const ORPHANED_CODE_RULE_REVISION: u32 = 1;

/// Rule id for `monomorphization-load` (todo.md §3.C "Rust-spezifisch:
/// Monomorphisierungs-Last (Proxy für `cargo-llvm-lines`)") — see
/// [`monomorphization_load_findings`].
pub const MONOMORPHIZATION_LOAD_RULE: &str = "monomorphization-load";
/// Bump when the monomorphization-load rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const MONOMORPHIZATION_LOAD_RULE_REVISION: u32 = 1;

/// `monomorphization_load_score = generic_param_count * cross_file_call_sites`
/// above which a generic function is flagged. An illustrative starting
/// point, not a rigorously derived cutoff — e.g. 2 generic params × 11 call
/// sites, or 4 params × 6 sites. There is no ground truth to calibrate this
/// against short of actually running `cargo-llvm-lines`, so this threshold
/// is explicitly subject to revision (see [`monomorphization_load_findings`]
/// for the full proxy caveat).
const MONOMORPHIZATION_LOAD_THRESHOLD: u32 = 20;

#[derive(Debug)]
pub enum SlopStructuralDeepError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    Reachability(ReachabilityError),
}

impl std::fmt::Display for SlopStructuralDeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Reachability(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SlopStructuralDeepError {}

/// Maps a [`ReachabilityError`] into this module's own error type, the same
/// conversion [`crate::dead_code::reachability_error`] already does for
/// `DeadCodeError` — [`orphaned_code_findings`]'s only source of
/// `ReachabilityError`.
fn reachability_error(err: ReachabilityError) -> SlopStructuralDeepError {
    SlopStructuralDeepError::Reachability(err)
}

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
    /// Byte offset of the function's identifier within `file`, kept around
    /// so [`orphaned_code_findings`] can re-derive the same `FilePosition`
    /// this record was originally resolved at, for its own reachability
    /// check — without this, it would need to re-parse `file` and re-walk
    /// its functions just to get back to the position `collect_function_fan_in`
    /// already had.
    offset: u32,
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
            let file_id = match ctx.file_id(&file.path) {
                Ok(Some(file_id)) => file_id,
                Ok(None) => continue,
                Err(err) => {
                    errors.push(SlopStructuralDeepError::Deep(err));
                    continue;
                }
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
                        offset,
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
            limitations: None,
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
            limitations: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }
    findings
}

/// `orphaned-code` (todo.md §3.E: "braucht Deep-Tier-Fan-in (kein Commit des
/// Blame-Hauptautors, kein Testpfad, kein Fan-in)"): a function is flagged
/// only when all three independent signals hold at once —
///
/// 1. **No fan-in**: zero cross-file references, reusing `records`'
///    existing `cross_file_references` count (same candidate set and same
///    exclusions as `connectivity-drop` — see [`is_reliably_checkable_for_fan_in`]
///    and the module docs; a `#[test]`/`#[bench]` function or trait-impl
///    method is never a candidate).
/// 2. **No test path**: not reachable from a test-only entry point.
///    `entries_all` (`include_tests: true`) minus `entries_production`
///    (`include_tests: false`) is exactly the set of entries that only
///    exist *because* tests are counted — `fn main`/FFI/wasm-bindgen
///    exports are entries either way, so they cancel out of the
///    difference, leaving only `#[test]`/`#[bench]` functions. Checking
///    [`is_reachable_from_entry`] against that difference (with
///    `include_tests: true`, so the BFS itself is allowed to traverse
///    test-authored call edges) answers "does any test path reach this
///    function at all" — a different question from `connectivity-drop`'s
///    plain fan-in, since a test in the *same* file as its target has
///    cross-file fan-in of zero but very much has a test path.
/// 3. **Dominant blame author inactive**: `dominant_author_by_file` maps a
///    file to its *file-level* dominant blame author
///    (`FileOwnership.authors[0]`, from [`crate::ownership`]), checked
///    against `active_authors`. This is a **file-level proxy for the
///    item's author**, a deliberate, documented approximation — true
///    per-function blame isn't threaded through here — reasonable because a
///    small file's dominant author is usually representative of any single
///    item within it. A file this rule has no ownership data for at all
///    (e.g. blame failed, or it's untracked) is skipped, not assumed
///    inactive.
///
/// `Severity::Info`, `EvidenceClass::Heuristic`: even though the fan-in and
/// reachability legs are exact Deep Tier facts, "the file-level dominant
/// author is inactive" is inherently interpretive (the same classification
/// `low-bus-factor` already uses for that judgment), and this rule compounds
/// several heterogeneous signal types into one claim — never "totter
/// Code"/"sicher löschbar", only that these three conditions co-occurred in
/// the examined view.
fn orphaned_code_findings(
    workspace: &Workspace,
    ctx: &DeepContext,
    analysis: &ra_ap_ide::Analysis,
    records: &[FunctionFanIn],
    dominant_author_by_file: &HashMap<PathBuf, String>,
    active_authors: &HashSet<String>,
) -> (Vec<Finding>, Vec<SlopStructuralDeepError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let candidates: Vec<&FunctionFanIn> = records
        .iter()
        .filter(|record| record.cross_file_references == 0)
        .collect();
    if candidates.is_empty() {
        return (findings, errors);
    }

    let entries_production = match entry_point_positions(workspace, ctx, false) {
        Ok(entries) => entries,
        Err(err) => {
            errors.push(reachability_error(err));
            return (findings, errors);
        }
    };
    let entries_all = match entry_point_positions(workspace, ctx, true) {
        Ok(entries) => entries,
        Err(err) => {
            errors.push(reachability_error(err));
            return (findings, errors);
        }
    };
    let production_keys: HashSet<(FileId, u32)> = entries_production
        .iter()
        .map(|(_, position)| position_key(*position))
        .collect();
    let test_only_keys: HashSet<(FileId, u32)> = entries_all
        .iter()
        .map(|(_, position)| position_key(*position))
        .filter(|key| !production_keys.contains(key))
        .collect();

    for record in candidates {
        let Some(dominant_author) = dominant_author_by_file.get(&record.file) else {
            continue;
        };
        if active_authors.contains(dominant_author) {
            continue;
        }
        let file_id = match ctx.file_id(&record.file) {
            Ok(Some(file_id)) => file_id,
            Ok(None) => continue,
            Err(err) => {
                errors.push(SlopStructuralDeepError::Deep(err));
                continue;
            }
        };
        let position = ra_ap_ide::FilePosition {
            file_id,
            offset: record.offset.into(),
        };
        match is_reachable_from_entry(analysis, &test_only_keys, position, true) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(err) => {
                errors.push(reachability_error(err));
                continue;
            }
        }

        findings.push(Finding {
            id: format!(
                "{ORPHANED_CODE_RULE}:{}:{}",
                record.file.display(),
                record.qualified_name
            )
            .into(),
            rule: ORPHANED_CODE_RULE.into(),
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
                "file": record.file.display().to_string(),
                "function": record.qualified_name,
                "line": record.line,
                "dominant_author": dominant_author,
                "active_authors_count": active_authors.len(),
            })),
            limitations: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }

    (findings, errors)
}

/// `monomorphization-load` (todo.md §3.C "Rust-spezifisch:
/// Monomorphisierungs-Last (Proxy für `cargo-llvm-lines`)"): a Fast-signal
/// PROXY for `cargo-llvm-lines`-style monomorphization bloat — judge never
/// runs `cargo-llvm-lines` itself, the same "delegate/proxy to the real
/// external tool, don't rebuild it" philosophy `untested-hotspot`/
/// `mutation-survivor` already use for their imported reports, except this
/// rule needs no import at all, only a cheap local estimate.
///
/// **The proxy, stated plainly — the single most important caveat for this
/// rule:** `cargo-llvm-lines` measures actual generated-LLVM-IR line count
/// per monomorphized instantiation of a generic function, which needs a real
/// compile judge never performs. The cheap, honest stand-in used here
/// instead: `monomorphization_load_score = generic_param_count *
/// cross_file_call_sites` — more type parameters means more code gets
/// duplicated per instantiation, and more call sites means more
/// instantiations plausibly get generated. This does **not** count distinct
/// *type arguments* at each call site (that would need real type
/// resolution, unavailable here) — it uses call-site *count* as a cheap
/// stand-in for instantiation-context diversity, on the reasoning that more
/// callers plausibly means more distinct instantiation contexts on average.
/// This is a proxy for a proxy: the least measurement-backed rule in this
/// batch.
///
/// Only functions with at least one generic type parameter
/// (`generic_param_count >= 1`, from [`FunctionInfo`], already computed for
/// `signature-complexity`) are candidates — a non-generic function trivially
/// has zero monomorphization load, so it's skipped rather than reported at a
/// load of 0. `production_records` must already be a
/// [`collect_function_fan_in`] pass run with `include_tests: false` — a
/// test-only call site never produces production binary bloat, so it must
/// not count toward this score (mirrors [`orphaned_code_findings`]'s own
/// dedicated production-only `entry_point_positions(.., false)` pass for the
/// same reason). `Severity::Info`/`EvidenceClass::Heuristic`, the same
/// current-state-only framing this module's other two rules use (see module
/// docs) — trend-against-baseline is handled by the existing baseline/delta
/// system.
fn monomorphization_load_findings(
    production_records: &[FunctionFanIn],
    complexity_functions: &[FunctionInfo],
) -> Vec<Finding> {
    let generic_param_counts: HashMap<(&Path, &str), u32> = complexity_functions
        .iter()
        .map(|function| {
            (
                (function.file.as_path(), function.qualified_name.as_str()),
                function.generic_param_count,
            )
        })
        .collect();

    production_records
        .iter()
        .filter_map(|record| {
            let generic_param_count = *generic_param_counts
                .get(&(record.file.as_path(), record.qualified_name.as_str()))?;
            if generic_param_count == 0 {
                return None;
            }
            let cross_file_call_sites = record.cross_file_references as u32;
            let monomorphization_load_score = generic_param_count * cross_file_call_sites;
            if monomorphization_load_score <= MONOMORPHIZATION_LOAD_THRESHOLD {
                return None;
            }

            Some(Finding {
                id: format!(
                    "{MONOMORPHIZATION_LOAD_RULE}:{}:{}",
                    record.file.display(),
                    record.qualified_name
                )
                .into(),
                rule: MONOMORPHIZATION_LOAD_RULE.into(),
                severity: Severity::Info,
                location: Location {
                    file: record.file.clone(),
                    line: OneBasedLine::new(record.line)
                        .expect("proc-macro2 span lines are 1-based"),
                    item_path: record.qualified_name.clone(),
                },
                evidence_class: EvidenceClass::Heuristic,
                origin: Origin::Code,
                evidence: Some(json!({
                    "tier": "deep",
                    "file": record.file.display().to_string(),
                    "function": record.qualified_name,
                    "line": record.line,
                    "generic_param_count": generic_param_count,
                    "cross_file_call_sites": cross_file_call_sites,
                    "monomorphization_load_score": monomorphization_load_score,
                })),
                limitations: None,
                caused_by: Vec::new(),
                causes: Vec::new(),
            })
        })
        .collect()
}

/// Runs `connectivity-drop`, `duplicative-reinvention`, `orphaned-code`, and
/// `monomorphization-load` over `workspace`, sharing one Deep Tier workspace
/// load and one function-fan-in pass across the first three. `duplication`
/// is the caller's already-computed [`WorkspaceDuplication`] (Fast Tier,
/// cheap) — this function only adds the Deep Tier fan-in check on top of it,
/// it doesn't re-run duplicate detection itself. `dominant_author_by_file`
/// and `active_authors` are the caller's already-computed
/// [`crate::ownership`]/`active_authors_since` data (Fast Tier, git-blame
/// based) — see [`orphaned_code_findings`] for how they're used.
/// `complexity_functions` is the caller's already-computed
/// [`crate::complexity::WorkspaceComplexity::functions`] (Fast Tier), reused
/// as-is for its `generic_param_count` — see [`monomorphization_load_findings`].
/// `orphaned-code` is skipped entirely (same as `low-bus-factor`, see
/// [`crate::ownership::LOW_BUS_FACTOR_MIN_REPO_AUTHORS`]) if the repository
/// doesn't have enough distinct active authors for "inactive" to be a
/// meaningful comparison.
pub fn analyze_workspace(
    workspace: &Workspace,
    duplication: &WorkspaceDuplication,
    include_tests: bool,
    dominant_author_by_file: &HashMap<PathBuf, String>,
    active_authors: &HashSet<String>,
    complexity_functions: &[FunctionInfo],
) -> Result<DeepStructuralReport, SlopStructuralDeepError> {
    let ctx = DeepContext::load(&workspace.root).map_err(SlopStructuralDeepError::Deep)?;
    let analysis = ctx.analysis();

    let (records, mut errors) = collect_function_fan_in(workspace, &ctx, &analysis, include_tests);
    let checked = records.len();

    let mut findings = connectivity_drop_findings(&records);
    findings.extend(duplicative_reinvention_findings(duplication, &records));

    // `monomorphization-load` needs production-only fan-in specifically
    // (test-only call sites never produce production binary bloat, see
    // `monomorphization_load_findings`) — reuse `records` as-is when it's
    // already production-only, otherwise run one dedicated extra pass rather
    // than let a caller-requested `include_tests: true` leak into this
    // rule's score.
    if include_tests {
        let (production_records, production_errors) =
            collect_function_fan_in(workspace, &ctx, &analysis, false);
        errors.extend(production_errors);
        findings.extend(monomorphization_load_findings(
            &production_records,
            complexity_functions,
        ));
    } else {
        findings.extend(monomorphization_load_findings(
            &records,
            complexity_functions,
        ));
    }

    if active_authors.len() >= crate::ownership::LOW_BUS_FACTOR_MIN_REPO_AUTHORS {
        let (orphaned_code, orphaned_code_errors) = orphaned_code_findings(
            workspace,
            &ctx,
            &analysis,
            &records,
            dominant_author_by_file,
            active_authors,
        );
        findings.extend(orphaned_code);
        errors.extend(orphaned_code_errors);
    }

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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();
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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();
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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();
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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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
        let report = analyze_workspace(
            &workspace,
            &duplication,
            false,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();
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
    fn duplicative_reinvention_flags_a_family_whose_only_caller_is_invisible_proc_macro_generated_code(
    ) {
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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();
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

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[cfg(feature = "deep")]
    #[test]
    fn connectivity_drop_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(CONNECTIVITY_DROP_RULE)
            .expect("connectivity-drop has a registry entry")
            .example
            .expect("connectivity-drop has a curated example")
            .before;

        let dir = TempDir::new("connectivity-drop-registry-example");
        write_crate(&dir, "core", &[], example);
        write_workspace_manifest(&dir, &["core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == CONNECTIVITY_DROP_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    /// See `connectivity_drop_registry_example_still_triggers_the_rule`'s
    /// doc comment. Constructs the `WorkspaceDuplication` fixture by hand,
    /// the same way this module's own canonical positive tests do (see
    /// `duplicative_reinvention_flags_a_family_with_no_fan_in_on_any_member`)
    /// — `duplicative-reinvention` takes an already-computed clone report as
    /// input rather than running the Fast-Tier duplicate detector itself.
    #[cfg(feature = "deep")]
    #[test]
    fn duplicative_reinvention_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(DUPLICATIVE_REINVENTION_RULE)
            .expect("duplicative-reinvention has a registry entry")
            .example
            .expect("duplicative-reinvention has a curated example")
            .before;

        let dir = TempDir::new("duplicative-reinvention-registry-example");
        write_crate(&dir, "core", &[], example);
        write_workspace_manifest(&dir, &["core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let core_lib = dir.join("core/src/lib.rs");

        let member_a = CloneMember {
            qualified_name: "calculate_discount_v1".to_string(),
            file: core_lib.clone(),
            start_line: 1,
            end_line: 3,
            start_token: 0,
            end_token: 0,
            token_count: 1,
            mode: DupeMode::Strict,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        };
        let member_b = CloneMember {
            qualified_name: "calculate_discount_v2".to_string(),
            file: core_lib.clone(),
            start_line: 5,
            end_line: 7,
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

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &Vec::new(),
        )
        .unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == DUPLICATIVE_REINVENTION_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn orphaned_code_fires_when_no_fan_in_no_test_path_and_dominant_author_inactive() {
        let dir = TempDir::new("orphaned-code-fires");
        write_crate(
            &dir,
            "core",
            &[],
            r#"fn orphaned_helper() -> i32 {
    1
}
"#,
        );
        write_workspace_manifest(&dir, &["core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let core_lib = dir.join("core/src/lib.rs");

        let dominant_author_by_file = HashMap::from([(core_lib, "gone@example.com".to_string())]);
        let active_authors = HashSet::from([
            "recent-a@example.com".to_string(),
            "recent-b@example.com".to_string(),
        ]);

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &dominant_author_by_file,
            &active_authors,
            &Vec::new(),
        )
        .unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == ORPHANED_CODE_RULE && f.location.item_path == "orphaned_helper");
        assert!(finding.is_some(), "{:?}", report.findings);
        let finding = finding.unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        let evidence = finding.evidence.as_ref().expect("evidence must be set");
        assert_eq!(evidence["dominant_author"], "gone@example.com");
        assert_eq!(evidence["active_authors_count"], 2);
    }

    #[test]
    fn orphaned_code_does_not_fire_when_a_test_calls_it() {
        let dir = TempDir::new("orphaned-code-test-path");
        write_crate(
            &dir,
            "core",
            &[],
            r#"fn orphaned_helper() -> i32 {
    1
}

#[test]
fn calls_orphaned_helper() {
    assert_eq!(orphaned_helper(), 1);
}
"#,
        );
        write_workspace_manifest(&dir, &["core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let core_lib = dir.join("core/src/lib.rs");

        let dominant_author_by_file = HashMap::from([(core_lib, "gone@example.com".to_string())]);
        let active_authors = HashSet::from([
            "recent-a@example.com".to_string(),
            "recent-b@example.com".to_string(),
        ]);

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &dominant_author_by_file,
            &active_authors,
            &Vec::new(),
        )
        .unwrap();

        assert!(
            !report.findings.iter().any(|f| f.rule == ORPHANED_CODE_RULE),
            "a test in the same file reaches it via a test-only entry point — must not fire: {:?}",
            report.findings
        );
    }

    #[test]
    fn orphaned_code_does_not_fire_when_a_non_test_caller_exists() {
        let dir = TempDir::new("orphaned-code-fan-in");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn orphaned_helper() -> i32 {
    1
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::orphaned_helper()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let core_lib = dir.join("core/src/lib.rs");

        let dominant_author_by_file = HashMap::from([(core_lib, "gone@example.com".to_string())]);
        let active_authors = HashSet::from([
            "recent-a@example.com".to_string(),
            "recent-b@example.com".to_string(),
        ]);

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &dominant_author_by_file,
            &active_authors,
            &Vec::new(),
        )
        .unwrap();

        assert!(
            !report.findings.iter().any(|f| f.rule == ORPHANED_CODE_RULE),
            "called from another crate — has fan-in, must not fire: {:?}",
            report.findings
        );
    }

    #[test]
    fn orphaned_code_does_not_fire_when_dominant_author_is_active() {
        let dir = TempDir::new("orphaned-code-author-active");
        write_crate(
            &dir,
            "core",
            &[],
            r#"fn orphaned_helper() -> i32 {
    1
}
"#,
        );
        write_workspace_manifest(&dir, &["core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let core_lib = dir.join("core/src/lib.rs");

        let dominant_author_by_file =
            HashMap::from([(core_lib, "still-here@example.com".to_string())]);
        let active_authors = HashSet::from([
            "still-here@example.com".to_string(),
            "recent-b@example.com".to_string(),
        ]);

        let report = analyze_workspace(
            &workspace,
            &duplication,
            true,
            &dominant_author_by_file,
            &active_authors,
            &Vec::new(),
        )
        .unwrap();

        assert!(
            !report.findings.iter().any(|f| f.rule == ORPHANED_CODE_RULE),
            "the file's dominant author is still active — must not fire: {:?}",
            report.findings
        );
    }

    /// Writes a single-crate fixture with a `mod`-declared generic function
    /// and `caller_count` distinct caller files, each calling it once — the
    /// same "several files, one crate" pattern already used above for
    /// `duplicative_reinvention_does_not_flag_a_family_with_a_generated_file_member`,
    /// reused here so [`FunctionFanIn::cross_file_references`] counts one
    /// per caller file. `generic_fn_source` must define a `pub fn` whose
    /// name is `generic_fn_name` in `generic.rs`; `caller_body` is the
    /// caller file's full source, called `caller_N.rs`.
    fn write_monomorphization_fixture(
        dir: &TempDir,
        generic_fn_source: &str,
        caller_body: &str,
        caller_count: usize,
    ) {
        std::fs::create_dir_all(dir.join("core/src")).unwrap();
        std::fs::write(
            dir.join("core/Cargo.toml"),
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let mut lib_source = String::from("mod generic;\n");
        for i in 0..caller_count {
            lib_source.push_str(&format!("mod caller_{i};\n"));
        }
        std::fs::write(dir.join("core/src/lib.rs"), lib_source).unwrap();
        std::fs::write(dir.join("core/src/generic.rs"), generic_fn_source).unwrap();
        for i in 0..caller_count {
            std::fs::write(dir.join(format!("core/src/caller_{i}.rs")), caller_body).unwrap();
        }
        write_workspace_manifest(dir, &["core"]);
    }

    /// Runs `monomorphization-load` end to end over a fixture built by
    /// [`write_monomorphization_fixture`]: loads the workspace, computes the
    /// real `Vec<FunctionInfo>` via [`crate::complexity::analyze_workspace`]
    /// (the same Fast Tier pass `main.rs` runs in production), then the Deep
    /// Tier `analyze_workspace` above.
    fn run_monomorphization_fixture(dir: &TempDir) -> DeepStructuralReport {
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let duplication = WorkspaceDuplication::default();
        let source_files = workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter());
        let complexity = crate::complexity::analyze_workspace(source_files, false);

        analyze_workspace(
            &workspace,
            &duplication,
            true,
            &HashMap::new(),
            &HashSet::new(),
            &complexity.functions,
        )
        .unwrap()
    }

    #[test]
    fn monomorphization_load_fires_for_a_generic_function_with_many_cross_file_callers() {
        let dir = TempDir::new("monomorphization-load-fires");
        write_monomorphization_fixture(
            &dir,
            "pub fn wrap_triple<T, U, E>(first: T, second: U, _tag: E) -> (T, U) {\n    (first, second)\n}\n",
            "pub fn run() -> (i32, i32) {\n    crate::generic::wrap_triple(1, 2, \"tag\")\n}\n",
            7,
        );

        let report = run_monomorphization_fixture(&dir);

        let finding = report.findings.iter().find(|f| {
            f.rule == MONOMORPHIZATION_LOAD_RULE && f.location.item_path == "wrap_triple"
        });
        assert!(finding.is_some(), "{:?}", report.findings);
        let evidence = finding.unwrap().evidence.as_ref().unwrap();
        assert_eq!(evidence["generic_param_count"], 3);
        assert_eq!(evidence["cross_file_call_sites"], 7);
        assert_eq!(evidence["monomorphization_load_score"], 21);
    }

    #[test]
    fn monomorphization_load_does_not_fire_for_a_generic_function_with_few_callers() {
        let dir = TempDir::new("monomorphization-load-few-callers");
        write_monomorphization_fixture(
            &dir,
            "pub fn wrap_triple<T, U, E>(first: T, second: U, _tag: E) -> (T, U) {\n    (first, second)\n}\n",
            "pub fn run() -> (i32, i32) {\n    crate::generic::wrap_triple(1, 2, \"tag\")\n}\n",
            1,
        );

        let report = run_monomorphization_fixture(&dir);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == MONOMORPHIZATION_LOAD_RULE),
            "generic_param_count 3 * cross_file_call_sites 1 = 3, well under the threshold — \
             must not fire: {:?}",
            report.findings
        );
    }

    #[test]
    fn monomorphization_load_does_not_fire_for_a_non_generic_function_with_many_callers() {
        let dir = TempDir::new("monomorphization-load-non-generic");
        write_monomorphization_fixture(
            &dir,
            "pub fn wrap_triple(first: i32, second: i32, _tag: &str) -> (i32, i32) {\n    (first, second)\n}\n",
            "pub fn run() -> (i32, i32) {\n    crate::generic::wrap_triple(1, 2, \"tag\")\n}\n",
            7,
        );

        let report = run_monomorphization_fixture(&dir);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == MONOMORPHIZATION_LOAD_RULE),
            "zero generic params means zero monomorphization load regardless of fan-in — must \
             not fire: {:?}",
            report.findings
        );
    }

    /// Splits a `// file: <name>.rs` marked multi-module source (see the
    /// `monomorphization-load` registry example in `rule_registry.rs`) into
    /// `(file_name, source)` pairs, in encounter order — this module's
    /// counterpart to `dead_code.rs`'s own `split_marked_files` helper.
    fn split_marked_files(source: &str) -> Vec<(&str, String)> {
        let mut result: Vec<(&str, String)> = Vec::new();
        for line in source.lines() {
            if let Some(name) = line.strip_prefix("// file: ") {
                result.push((name, String::new()));
            } else if let Some(entry) = result.last_mut() {
                entry.1.push_str(line);
                entry.1.push('\n');
            }
        }
        result
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[cfg(feature = "deep")]
    #[test]
    fn monomorphization_load_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MONOMORPHIZATION_LOAD_RULE)
            .expect("monomorphization-load has a registry entry")
            .example
            .expect("monomorphization-load has a curated example")
            .before;

        let files = split_marked_files(example);
        assert_eq!(files.len(), 8, "expected 8 marked files: {files:?}");

        let dir = TempDir::new("monomorphization-load-registry-example");
        std::fs::create_dir_all(dir.join("core/src")).unwrap();
        std::fs::write(
            dir.join("core/Cargo.toml"),
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let mod_declarations: String = files
            .iter()
            .map(|(name, _)| {
                let mod_name = name.strip_suffix(".rs").expect("marked file ends in .rs");
                format!("mod {mod_name};\n")
            })
            .collect();
        std::fs::write(dir.join("core/src/lib.rs"), mod_declarations).unwrap();
        for (name, source) in &files {
            std::fs::write(dir.join("core/src").join(name), source).unwrap();
        }
        write_workspace_manifest(&dir, &["core"]);

        let report = run_monomorphization_fixture(&dir);

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == MONOMORPHIZATION_LOAD_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }
}
