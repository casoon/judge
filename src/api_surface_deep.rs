//! The third `semver-hazard` sub-case [`crate::api_surface`] deliberately
//! leaves out (see that module's docs and todo.md §I): `leaked_dependency_type`
//! — a dependency's type leaking through a `pub fn`'s parameter or return
//! type. Adding a field to that type, or yanking/removing it, is a breaking
//! change for anyone who took a hard dependency on it just by calling this
//! crate's own `pub fn` — exactly the same "consumer can't evolve
//! independently" shape the other two `semver-hazard` sub-cases flag, just
//! via a dependency's type instead of the crate's own. Needs type
//! resolution across crate boundaries, which only the Deep Tier's
//! `ra_ap_hir::Semantics` provides (see [`crate::deep`]).
//!
//! ## Item population
//!
//! Exactly [`crate::api_surface::PubFnCandidate`]'s population: a module-
//! level free fn or inherent-impl method that is `pub`, not `#[test]`-
//! attributed, and not `#[cfg(test)]`-gated (on itself or an enclosing
//! item) — the same walk `check_doc_fn` already runs for
//! `undocumented-public-item`, reused rather than re-derived so the two
//! Tiers' item populations for this rule family can't drift apart.
//!
//! ## Filter
//!
//! A parameter or return type is only a candidate if it resolves to a
//! concrete ADT (`struct`/`enum`/`union`) — see "Ehrliche Grenze" below for
//! what that excludes. Types defined in `std`/`core`/`alloc` are not a leak
//! — they're part of the language, not a dependency (recognized by their
//! crate's own display name; `DeepContext::load`'s explicit `sysroot:
//! Discover` is what makes these crates present in the loaded workspace at
//! all — see that function's doc comment). A type defined in the *same*
//! crate as the checked `pub fn` is not a leak either — that's the crate's
//! own API, not a dependency's. Anything else — another workspace crate, or
//! an external dependency crate — is a candidate.
//!
//! ## Ehrliche Grenze — documented boundary, not a bug
//!
//! Only *direct* parameter/return types are checked, plus **one level** of
//! generic unwrapping for a `std`/`core`/`alloc` generic container
//! (`Vec<T>`, `Option<T>`, `Result<T, E>`, `Box<T>`, …): if the container
//! itself is a language type, each of its resolvable type arguments is
//! checked the same way the direct type would be, but *those* arguments'
//! own type arguments are not — `Vec<Vec<OtherCrateType>>` is not caught. A
//! generic type parameter of the checked `pub fn` itself (`fn foo<T>(x: T)`)
//! never resolves to a concrete ADT and so is never flagged — correctly:
//! `T` isn't a leaked type, it's the caller's choice. A `dyn Trait` receiver,
//! a raw pointer, a function pointer, a tuple, or a slice/array element type
//! are not unwrapped either — all documented, deliberate simplifications
//! rather than an attempt at full structural recursion.
//!
//! ## Evidence class
//!
//! [`crate::finding::evidence_class_for_rule`] maps `semver-hazard` to
//! `derived_fact` by default — correct for the other two sub-cases (an exact
//! syntax fact: an attribute is present or absent), but not for this one: a
//! type's defining crate is a semantic fact, true only within the Deep
//! Tier's loaded view (its crate graph, sysroot, and `--all-features`
//! selection — see [`crate::deep::DeepContext::load`]), not derivable from
//! syntax alone. This sub-case overrides `evidence_class` to
//! [`crate::finding::EvidenceClass::BoundedSemantic`] at its own finding
//! creation site instead — the same pattern
//! [`crate::duplication::CloneMember::to_finding`] uses for its own
//! `Weak`/`Semantic` modes: `evidence_class_for_rule("semver-hazard")` stays
//! `derived_fact` as the rule-level default, and only this sub-case's
//! creation site overrides it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ra_ap_hir::{ModuleDef, PathResolution, Semantics};
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::ast::{HasModuleItem, HasName, HasVisibility};
use ra_ap_syntax::{AstNode, TextRange, ast};
use serde_json::json;

use crate::api_surface::{self, PubFnCandidate, SEMVER_HAZARD_RULE};
use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

/// Rule id for `internal-leak` (see todo.md §3.H): a narrower, explicitly
/// user-configured view of the same `leaked_dependency_type` resolution
/// above — a `pub fn`'s signature resolving to an ADT defined in one of the
/// crate names the user names as `internal_crates` in `judge.toml` (see
/// `crate::boundaries::BoundaryConfig::internal_crates`). Deep-Tier-only,
/// with no Fast-Tier counterpart, so it declares its own rule id/revision
/// constants locally rather than sharing `SEMVER_HAZARD_RULE`'s — the same
/// precedent `crate::dead_code`'s rules follow for their own rule ids.
pub const INTERNAL_LEAK_RULE: &str = "internal-leak";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const INTERNAL_LEAK_RULE_REVISION: u32 = 1;

/// Rule id for `re-export-chain` (see todo.md §H "mehrstufige `pub use`-
/// Ketten, die Ownership verschleiern"): a `pub use` whose public path
/// resolves through one or more *further* `pub use` re-exports before
/// reaching the item's actual, original definition — a re-export facade over
/// another re-export facade, which obscures where the item is really owned.
/// A single direct re-export (one hop) is an extremely common, legitimate
/// pattern (curated top-level re-exports, prelude modules, workspace
/// umbrella crates) and is deliberately *not* the signal on its own — only a
/// chain of [`RE_EXPORT_CHAIN_MIN_HOP_COUNT`] or more hops is.
///
/// Deep-Tier-only, no Fast-Tier counterpart: following a `pub use` path
/// across crate boundaries needs the same cross-crate `ra_ap_hir::Semantics`
/// resolution [`leaked_type`] already relies on, plus one further step this
/// rule alone needs — at each hop, whether the resolved target is *itself*
/// another `pub use` rather than an original item definition. That check
/// needs the raw syntax of the target module's own source (see
/// [`find_named_top_level_item`]), because `ra_ap_hir`'s own path resolution
/// does not stop at one hop: it resolves a `use` path (its qualifier and its
/// full leaf path alike) through the same crate-def-map import resolution
/// used for any other path, and that resolution is not lazy per level —
/// nested re-exports are already fully flattened to the original definition
/// by the time `Semantics::resolve_path` returns anything at all (confirmed
/// against the vendored `ra_ap_hir` 0.0.342 source: `goto_declaration`, the
/// one IDE feature that *does* stop at one `use` hop, explicitly does not
/// support structs/enums/fns — only module outlines, trait assoc items, and
/// `extern crate`). This is why [`walk_hops`] resolves only a hop's
/// *qualifier* to a module via HIR, then classifies that module's own
/// top-level item by syntax alone, one hop at a time, instead of resolving
/// the whole path once and trying to recover a hop count from the result.
///
/// Declares its own rule id/revision constants locally rather than sharing
/// `internal-leak`'s, the same precedent that rule's own doc comment follows
/// for `crate::dead_code`'s rule ids.
pub const RE_EXPORT_CHAIN_RULE: &str = "re-export-chain";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const RE_EXPORT_CHAIN_RULE_REVISION: u32 = 1;

/// Minimum hop count (see [`ReExportChain::hop_count`]) for a chain to be
/// flagged: a hop count of exactly 1 is a direct, single re-export — the
/// common, unremarkable case documented on [`RE_EXPORT_CHAIN_RULE`] — so
/// this rule only fires starting at 2 (at least one *intermediate*
/// re-export between the public-facing path and the original definition).
const RE_EXPORT_CHAIN_MIN_HOP_COUNT: usize = 2;

/// Fixed cap on how many `pub use` hops [`walk_hops`] follows before giving
/// up and reporting "chain length >= this cap" instead of an exact count
/// (see [`ReExportChain::hop_count`]). An arbitrary-but-stated threshold —
/// mirrors [`crate::git::SIZE_DISTRIBUTION_GINI_THRESHOLD`]'s documented-
/// not-derived style — chosen mainly to bound the walk against a `pub use`
/// cycle (legal Rust as long as at least one path in and out of the cycle
/// is not itself part of it; a rare but real footgun), not from any study of
/// real-world re-export chain depths.
const RE_EXPORT_CHAIN_MAX_HOPS: usize = 5;

/// Crate names the "part of the language, not a dependency" filter
/// recognizes (see the module docs). A plain name comparison rather than a
/// `CrateOrigin`-based check — the sysroot crates `DeepContext::load` always
/// loads have exactly these fixed, rustc-controlled names, so this is not a
/// meaningfully weaker check, and avoids a second `ra_ap_*` crate dependency
/// for a single enum comparison.
const LANGUAGE_CRATE_NAMES: [&str; 3] = ["std", "core", "alloc"];

#[derive(Debug)]
pub enum ApiSurfaceDeepError {
    Deep(DeepError),
    ApiSurface(api_surface::ApiSurfaceError),
}

impl std::fmt::Display for ApiSurfaceDeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::ApiSurface(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ApiSurfaceDeepError {}

#[derive(Debug, Default)]
pub struct DeepApiSurfaceReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<ApiSurfaceDeepError>,
    /// Number of `pub fn` candidates actually queried (see
    /// [`PubFnCandidate`]).
    pub checked: usize,
}

/// One leaked type found in a checked parameter/return type.
struct LeakedType {
    type_name: String,
    defining_crate: String,
}

/// One resolved `pub use` chain (see [`RE_EXPORT_CHAIN_RULE`]): the
/// public-facing path a consumer would actually write, where the item is
/// really defined, and how many `pub use` hops separate the two. Kept as its
/// own type rather than folded into [`LeakedType`] — unlike that struct,
/// which only records a defining crate, this rule's finding needs the exact
/// defining *path* plus a hop count, neither of which `LeakedType` carries.
struct ReExportChain {
    /// The path a consumer outside the exporting crate would actually write
    /// — the crate name plus the name the chain's starting `pub use`
    /// introduces (its rename, if any, otherwise its own leaf segment).
    exported_path: String,
    /// Where the item is actually defined, fully resolved via
    /// [`ra_ap_hir::ModuleDef::module`] regardless of how many hops
    /// [`walk_hops`] itself could confirm (see [`defining_path_of`]) — always
    /// exact, never affected by [`RE_EXPORT_CHAIN_MAX_HOPS`].
    defining_path: String,
    /// Number of `pub use` hops walked before reaching a non-`use` original
    /// definition, or [`RE_EXPORT_CHAIN_MAX_HOPS`] if the cap was hit first
    /// (see [`walk_hops`]) — in that case a floor, not an exact count.
    hop_count: usize,
}

/// One workspace source file's own [`ra_ap_hir::Module`] — the whole-
/// workspace index [`walk_hops`] uses to jump from a resolved hop's target
/// module back to that module's own parsed source, so its top-level items
/// can be scanned by syntax (see [`find_named_top_level_item`]). Built once,
/// up front, across every crate (see [`build_module_index`]) — a re-export
/// chain routinely crosses crate boundaries, unlike [`analyze_workspace`]'s
/// own per-crate loop for `semver-hazard`/`internal-leak`.
struct ModuleFile {
    file_id: FileId,
    path: PathBuf,
    module: ra_ap_hir::Module,
}

/// Builds the whole-workspace [`ModuleFile`] index (see that type's doc
/// comment): every locally-reportable source file in every crate, paired
/// with the `ra_ap_hir::Module` it constitutes. A file with no corresponding
/// `FileId` (not loaded into the Deep Tier's `vfs`) or no resolvable
/// `Module` (e.g. not part of any compiled target's module tree) is skipped
/// — the same "im Zweifel nicht melden" stance [`resolve_fn_node`]'s own
/// doc comment takes for its own unresolvable cases.
fn build_module_index(
    workspace: &Workspace,
    ctx: &DeepContext,
    sema: &Semantics<'_, RootDatabase>,
) -> Vec<ModuleFile> {
    let mut index = Vec::new();
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }
            let Some(file_id) = ctx.file_id(&file.path) else {
                continue;
            };
            let Some(module) = sema.file_to_module_def(file_id) else {
                continue;
            };
            index.push(ModuleFile {
                file_id,
                path: file.path.clone(),
                module,
            });
        }
    }
    index
}

/// Whether `vis` is a plain, unrestricted `pub` — not absent, and not a
/// restricted form (`pub(crate)`, `pub(super)`, `pub(in ...)`), which parse
/// with a `VisibilityInner` child that plain `pub` lacks. Mirrors
/// [`crate::api_surface`]'s own `syn`-based `Visibility::Public(_)` check
/// (only a bare `pub` counts there either), re-derived here in
/// `ra_ap_syntax` terms since this rule's scan never goes through `syn`.
fn is_plain_pub(vis: Option<ast::Visibility>) -> bool {
    vis.is_some_and(|vis| vis.pub_token().is_some() && vis.visibility_inner().is_none())
}

/// The final segment's name of `path` (e.g. `"Foo"` for `other::Foo`), or
/// `None` if `path` has no segment or the segment has no plain identifier
/// (`self`/`super`/`crate`/`Self` name refs don't carry an ordinary name).
fn leaf_name(path: &ast::Path) -> Option<String> {
    Some(path.segment()?.name_ref()?.text().to_string())
}

/// Resolves `path`'s qualifier (everything but its final segment) to the
/// `ra_ap_hir::Module` it names — the "one hop" target a `use` path's
/// qualifier textually names, as opposed to resolving the *whole* path,
/// which (see [`RE_EXPORT_CHAIN_RULE`]'s doc comment) collapses straight
/// through to the final, fully-resolved item regardless of chain depth.
/// `None` when `path` has no qualifier (a bare single-segment path — never
/// true for a `use` path this rule considers, since every candidate needs at
/// least a crate-name qualifier) or the qualifier doesn't resolve to a
/// module at all.
fn resolve_qualifier_module(
    sema: &Semantics<'_, RootDatabase>,
    path: &ast::Path,
) -> Option<ra_ap_hir::Module> {
    let qualifier = path.qualifier()?;
    match sema.resolve_path(&qualifier)? {
        PathResolution::Def(ModuleDef::Module(module)) => Some(module),
        _ => None,
    }
}

/// What a matching top-level item in a module introduces under a given name
/// — either another `pub use` (continue the hop, with its own target path)
/// or an original, non-`use` definition (the chain ends here). See
/// [`find_named_top_level_item`] for what counts as "matching".
enum NamedTopLevelItem {
    ReExport(ast::Path),
    Original,
}

/// Whether `name` (an `ast::Name`, e.g. a `struct`'s own name) textually
/// equals `target`.
fn name_matches(name: Option<ast::Name>, target: &str) -> bool {
    name.is_some_and(|name| name.text() == target)
}

/// Scans `source_file`'s own top-level items (module-root level only — see
/// [`re_export_chain_findings`]'s "Ehrliche Grenze" scope note) for the one
/// that introduces `name` into this module's namespace, classifying it as
/// [`NamedTopLevelItem::ReExport`] (a plain, non-glob, non-braced `pub use`
/// — see [`ast::UseTree::is_simple_path`]) or [`NamedTopLevelItem::Original`]
/// (a genuine `fn`/`struct`/`enum`/
/// `trait`/`const`/`static`/`type`/`union` definition). `None` when no
/// top-level item matches, or the matching `use` is a form this rule
/// deliberately doesn't parse (glob, braced group, or non-`pub`) — treated
/// as "can't tell", never guessed, the same conservative stance
/// [`resolve_fn_node`] takes for its own unresolvable cases.
fn find_named_top_level_item(
    source_file: &ast::SourceFile,
    name: &str,
) -> Option<NamedTopLevelItem> {
    for item in source_file.items() {
        match &item {
            ast::Item::Use(use_item) => {
                if !is_plain_pub(use_item.visibility()) {
                    continue;
                }
                let Some(tree) = use_item.use_tree() else {
                    continue;
                };
                if !tree.is_simple_path() {
                    continue;
                }
                let Some(use_path) = tree.path() else {
                    continue;
                };
                let introduced = tree
                    .rename()
                    .and_then(|rename| rename.name())
                    .map(|name| name.text().to_string())
                    .or_else(|| leaf_name(&use_path));
                let Some(introduced) = introduced else {
                    continue;
                };
                if introduced == name {
                    return Some(NamedTopLevelItem::ReExport(use_path));
                }
            }
            ast::Item::Fn(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Struct(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Enum(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Trait(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Const(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Static(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::TypeAlias(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            ast::Item::Union(it) if name_matches(it.name(), name) => {
                return Some(NamedTopLevelItem::Original);
            }
            _ => {}
        }
    }
    None
}

/// Walks the `pub use` chain starting at `start_path` (see
/// [`RE_EXPORT_CHAIN_RULE`]'s doc comment for why this can't just resolve
/// the whole path once): resolves each hop's qualifier to a module via HIR
/// ([`resolve_qualifier_module`]), then classifies that module's matching
/// top-level item by syntax alone ([`find_named_top_level_item`]) — another
/// `pub use` continues the walk, an original definition ends it. Returns
/// `Some(hop_count)` only when the walk reaches a confident conclusion: a
/// non-`use` original definition, or [`RE_EXPORT_CHAIN_MAX_HOPS`] reached
/// without one (a floor, not an exact count — see
/// [`ReExportChain::hop_count`]). `None` when the walk hits anything it
/// can't confidently classify (an unindexed target module, e.g. an inline
/// `mod { .. }` block never captured in `index`, or a `use` form
/// [`find_named_top_level_item`] doesn't parse) — never guessed past that
/// point, the same conservative stance [`resolve_fn_node`] takes elsewhere
/// in this module. Bounded by construction: `hop_count` only increases, and
/// the loop returns as soon as it reaches [`RE_EXPORT_CHAIN_MAX_HOPS`], so a
/// genuine `pub use` cycle (a footgun this cap is partly meant to guard
/// against — see [`RE_EXPORT_CHAIN_MAX_HOPS`]'s doc comment) can drive at
/// most that many iterations, never an infinite loop.
fn walk_hops(
    sema: &Semantics<'_, RootDatabase>,
    index: &[ModuleFile],
    start_path: &ast::Path,
) -> Option<usize> {
    let mut current_path = start_path.clone();
    let mut hop_count = 1usize;
    loop {
        if hop_count >= RE_EXPORT_CHAIN_MAX_HOPS {
            return Some(RE_EXPORT_CHAIN_MAX_HOPS);
        }
        let target_module = resolve_qualifier_module(sema, &current_path)?;
        let name = leaf_name(&current_path)?;
        let target_file = index.iter().find(|entry| entry.module == target_module)?;
        let target_source = sema.parse_guess_edition(target_file.file_id);
        match find_named_top_level_item(&target_source, &name) {
            Some(NamedTopLevelItem::ReExport(next_path)) => {
                hop_count += 1;
                current_path = next_path;
            }
            Some(NamedTopLevelItem::Original) => return Some(hop_count),
            None => return None,
        }
    }
}

/// The fully-qualified `crate::mod::path::Item` string for `def`'s own
/// defining location — always the *final*, fully-resolved location
/// regardless of how many `pub use` hops led there (see
/// [`RE_EXPORT_CHAIN_RULE`]'s doc comment on why `ra_ap_hir` resolution
/// itself already collapses through every hop). `None` when `def` has no
/// name or no home module (e.g. [`ra_ap_hir::ModuleDef::BuiltinType`]).
fn defining_path_of(def: ModuleDef, db: &RootDatabase) -> Option<String> {
    let name = def.name(db)?.as_str().to_string();
    let module = def.module(db)?;
    let mut segments: Vec<String> = module
        .path_to_root(db)
        .into_iter()
        .rev()
        .skip(1)
        .filter_map(|module| module.name(db).map(|name| name.as_str().to_string()))
        .collect();
    segments.push(name);
    let mut full = vec![crate_display_name(module.krate(db), db)];
    full.append(&mut segments);
    Some(full.join("::"))
}

/// 1-based line number of the byte `offset` within `source_text` — a plain
/// newline count rather than `proc-macro2`'s span-provided line numbers
/// (unavailable here since this rule's own item scan is `ra_ap_syntax`-only,
/// never `syn` — see [`RE_EXPORT_CHAIN_RULE`]'s doc comment). Falls back to
/// line 1 for an out-of-bounds or non-char-boundary offset rather than
/// panicking — `TextSize` offsets from a real parse are always on a char
/// boundary, so this is a defensive fallback, not an expected path.
fn line_number(source_text: &str, offset: usize) -> usize {
    source_text
        .get(..offset.min(source_text.len()))
        .map_or(1, |prefix| prefix.matches('\n').count() + 1)
}

fn re_export_chain_finding(file: &Path, line: OneBasedLine, chain: &ReExportChain) -> Finding {
    Finding {
        id: format!(
            "{RE_EXPORT_CHAIN_RULE}:{}:{}",
            file.display(),
            chain.exported_path
        )
        .into(),
        rule: RE_EXPORT_CHAIN_RULE.into(),
        severity: Severity::Info,
        location: Location {
            file: file.to_path_buf(),
            line,
            item_path: chain.exported_path.clone(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(json!({
            "kind": "re_export_chain",
            "exported_path": chain.exported_path,
            "defining_path": chain.defining_path,
            "hop_count": chain.hop_count,
            "capped": chain.hop_count == RE_EXPORT_CHAIN_MAX_HOPS,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Every `re-export-chain` finding across the whole workspace (see
/// [`RE_EXPORT_CHAIN_RULE`]): every plain, non-glob, non-braced `pub use` at
/// any locally-reportable file's own module-root level, whose [`walk_hops`]
/// result is confidently known and at least [`RE_EXPORT_CHAIN_MIN_HOP_COUNT`].
/// **Ehrliche Grenze — documented boundary, not a bug:** scans only each
/// file's own top-level items — a `pub use` nested inside an inline
/// `mod foo { .. }` block in the same file is invisible to this scan (it
/// would need locating that inline module's own source range within the
/// file, which the whole-workspace [`ModuleFile`] index doesn't attempt),
/// the same "one file, one module" simplification real Rust code overwhelmingly
/// follows in practice.
fn re_export_chain_findings(
    workspace: &Workspace,
    ctx: &DeepContext,
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
) -> Vec<Finding> {
    let index = build_module_index(workspace, ctx, sema);
    let mut findings = Vec::new();

    for entry in &index {
        let source_file = sema.parse_guess_edition(entry.file_id);
        let source_text = source_file.syntax().text().to_string();
        let own_crate_name = crate_display_name(entry.module.krate(db), db);

        for item in source_file.items() {
            let ast::Item::Use(use_item) = &item else {
                continue;
            };
            if !is_plain_pub(use_item.visibility()) {
                continue;
            }
            let Some(tree) = use_item.use_tree() else {
                continue;
            };
            if !tree.is_simple_path() {
                continue;
            }
            let Some(use_path) = tree.path() else {
                continue;
            };
            let introduced = tree
                .rename()
                .and_then(|rename| rename.name())
                .map(|name| name.text().to_string())
                .or_else(|| leaf_name(&use_path));
            let Some(introduced) = introduced else {
                continue;
            };

            let Some(PathResolution::Def(final_def)) = sema.resolve_path(&use_path) else {
                continue;
            };
            let Some(defining_path) = defining_path_of(final_def, db) else {
                continue;
            };
            let Some(hop_count) = walk_hops(sema, &index, &use_path) else {
                continue;
            };
            if hop_count < RE_EXPORT_CHAIN_MIN_HOP_COUNT {
                continue;
            }

            let chain = ReExportChain {
                exported_path: format!("{own_crate_name}::{introduced}"),
                defining_path,
                hop_count,
            };
            let offset = u32::from(use_item.syntax().text_range().start()) as usize;
            let line =
                OneBasedLine::new(line_number(&source_text, offset)).unwrap_or(OneBasedLine::FIRST);
            findings.push(re_export_chain_finding(&entry.path, line, &chain));
        }
    }

    findings
}

/// Whether `krate` is one of the language's own crates (see
/// [`LANGUAGE_CRATE_NAMES`]) — `false` when it has no display name at all
/// (conservatively not a language crate, since only `std`/`core`/`alloc`
/// legitimately lack one being irrelevant here — an unnamed crate is never
/// one of the three names either way).
fn is_language_crate(krate: ra_ap_hir::Crate, db: &RootDatabase) -> bool {
    krate
        .display_name(db)
        .is_some_and(|name| LANGUAGE_CRATE_NAMES.contains(&name.to_string().as_str()))
}

/// Checks one resolved parameter/return type for a leaked dependency type
/// (see the module docs' "Filter" and "Ehrliche Grenze" sections). `None`
/// when the type isn't a concrete ADT, is the language's own, or belongs to
/// `own_crate` itself.
fn leaked_type(
    ty: &ra_ap_hir::Type<'_>,
    db: &RootDatabase,
    own_crate: ra_ap_hir::Crate,
) -> Option<LeakedType> {
    let stripped = ty.strip_references();
    let (adt, args) = stripped.as_adt_with_args()?;
    let container_crate = adt.module(db).krate(db);

    if !is_language_crate(container_crate, db) {
        if container_crate == own_crate {
            return None;
        }
        return Some(LeakedType {
            type_name: adt.name(db).as_str().to_string(),
            defining_crate: crate_display_name(container_crate, db),
        });
    }

    // The container itself is a language type (`Vec<T>`, `Option<T>`,
    // `Result<T, E>`, `Box<T>`, …) — check one level into its resolvable
    // type arguments (see "Ehrliche Grenze" in the module docs).
    args.into_iter().flatten().find_map(|arg| {
        let inner_adt = arg.as_adt()?;
        let inner_crate = inner_adt.module(db).krate(db);
        if is_language_crate(inner_crate, db) || inner_crate == own_crate {
            return None;
        }
        Some(LeakedType {
            type_name: inner_adt.name(db).as_str().to_string(),
            defining_crate: crate_display_name(inner_crate, db),
        })
    })
}

fn crate_display_name(krate: ra_ap_hir::Crate, db: &RootDatabase) -> String {
    krate
        .display_name(db)
        .map_or_else(|| "?".to_string(), |name| name.to_string())
}

/// Resolves `ident_span` (a [`PubFnCandidate::ident_span`]) to the enclosing
/// `ast::Fn` syntax node in the Deep Tier's own parse of `file_id` — the same
/// "step from a `syn` position down to `ra_ap_syntax`" move
/// [`crate::reachability::classify_call_kind`] makes for a call site.
/// `None` when the position doesn't line up with a token at all (an edge
/// case `token_at_offset` can't resolve) or that token isn't inside a
/// function — skipped rather than reported as an error, the same "im
/// Zweifel nicht melden" stance `classify_call_kind`'s own `CallKind::Unknown`
/// fallback takes (todo.md §3.A).
fn resolve_fn_node(
    sema: &Semantics<'_, RootDatabase>,
    file_id: FileId,
    ident_span: proc_macro2::Span,
) -> Option<ast::Fn> {
    let byte_range = ident_span.byte_range();
    let text_range = TextRange::new(
        (byte_range.start as u32).into(),
        (byte_range.end as u32).into(),
    );
    let source_file = sema.parse_guess_edition(file_id);
    let token = source_file
        .syntax()
        .token_at_offset(text_range.start())
        .find(|token| token.text_range() == text_range)?;
    token.parent()?.ancestors().find_map(ast::Fn::cast)
}

/// Every parameter type plus the return type (if any) of `fn_node`, each
/// labeled with a `site` string used both for the finding's `evidence.site`
/// and to keep multiple leaked types on the same function from colliding on
/// [`Finding::id`].
fn checked_types(fn_node: &ast::Fn) -> Vec<(String, ast::Type)> {
    let mut types = Vec::new();
    if let Some(param_list) = fn_node.param_list() {
        for (index, param) in param_list.params().enumerate() {
            if let Some(ty) = param.ty() {
                types.push((format!("parameter{index}"), ty));
            }
        }
    }
    if let Some(ty) = fn_node.ret_type().and_then(|ret_type| ret_type.ty()) {
        types.push(("return".to_string(), ty));
    }
    types
}

fn leak_finding(candidate: &PubFnCandidate, site: &str, leak: &LeakedType) -> Finding {
    Finding {
        id: format!(
            "{SEMVER_HAZARD_RULE}:{}:{}:{site}:{}",
            candidate.file.display(),
            candidate.item_path,
            leak.type_name,
        )
        .into(),
        rule: SEMVER_HAZARD_RULE.into(),
        severity: Severity::Info,
        location: Location {
            file: candidate.file.clone(),
            line: OneBasedLine::new(candidate.ident_span.start().line)
                .expect("proc-macro2 span lines are 1-based"),
            item_path: candidate.item_path.clone(),
        },
        // Overrides the rule-level `derived_fact` default (see
        // `evidence_class_for_rule`'s doc comment) — see the module docs'
        // "Evidence class" section for why this sub-case alone is
        // `bounded_semantic`.
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(json!({
            "kind": "leaked_dependency_type",
            "type_name": leak.type_name,
            "defining_crate": leak.defining_crate,
            "site": site,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Every `(site, LeakedType)` pair found among `candidate`'s resolved
/// parameter/return types (see the module docs) — the shared resolution step
/// [`leaked_types_for_candidate`] (`semver-hazard`) builds its findings from
/// directly, and `internal-leak` (see [`internal_leak_finding`]) reuses
/// rather than re-deriving, so the two rules can never disagree about which
/// types a candidate leaks.
fn resolve_leaks_for_candidate(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    file_id: FileId,
    own_crate: ra_ap_hir::Crate,
    candidate: &PubFnCandidate,
) -> Vec<(String, LeakedType)> {
    let Some(fn_node) = resolve_fn_node(sema, file_id, candidate.ident_span) else {
        return Vec::new();
    };

    checked_types(&fn_node)
        .into_iter()
        .filter_map(|(site, ty)| {
            let resolved = sema.resolve_type(&ty)?;
            let leak = leaked_type(&resolved, db, own_crate)?;
            Some((site, leak))
        })
        .collect()
}

/// Resolves `candidate`'s parameter and return types and reports one
/// [`Finding`] per leaked type found among them (see the module docs).
fn leaked_types_for_candidate(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    file_id: FileId,
    own_crate: ra_ap_hir::Crate,
    candidate: &PubFnCandidate,
) -> Vec<Finding> {
    resolve_leaks_for_candidate(sema, db, file_id, own_crate, candidate)
        .iter()
        .map(|(site, leak)| leak_finding(candidate, site, leak))
        .collect()
}

/// Renders an `internal-leak` finding: `candidate`'s signature resolves to
/// `leak.type_name`, defined in `leak.defining_crate` — a crate named in the
/// user's configured `internal_crates` (see
/// `crate::boundaries::BoundaryConfig::internal_crates`). `evidence_class` is
/// `bounded_semantic`, the same reasoning
/// [`crate::boundaries::MODULE_BOUNDARY_VIOLATION_RULE`] and
/// `leaked_dependency_type`'s own override use: an explicitly configured edge
/// over a semantically resolved type reference. Unlike `leaked_dependency_type`
/// (`Severity::Info`, a general API-evolvability observation), this rule is
/// gating (see the `RULE_REGISTRY` entry) — the user explicitly declared
/// `leak.defining_crate` internal, so crossing it is a real, user-asserted
/// boundary violation, not merely an observation about signature shape.
fn internal_leak_finding(candidate: &PubFnCandidate, site: &str, leak: &LeakedType) -> Finding {
    Finding {
        id: format!(
            "{INTERNAL_LEAK_RULE}:{}:{}:{site}:{}",
            candidate.file.display(),
            candidate.item_path,
            leak.type_name,
        )
        .into(),
        rule: INTERNAL_LEAK_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: candidate.file.clone(),
            line: OneBasedLine::new(candidate.ident_span.start().line)
                .expect("proc-macro2 span lines are 1-based"),
            item_path: candidate.item_path.clone(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(json!({
            "kind": "internal_leak",
            "type_name": leak.type_name,
            "defining_crate": leak.defining_crate,
            "site": site,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Runs the `leaked_dependency_type` `semver-hazard` sub-case over every
/// crate in `workspace` (see the module docs), plus — additively, reusing
/// the exact same per-candidate type resolution rather than a second,
/// separate walk — the `internal-leak` rule (see [`INTERNAL_LEAK_RULE`]),
/// narrowed to leaked types whose defining crate is named in
/// `internal_crates` (see `crate::boundaries::BoundaryConfig::internal_crates`).
/// When `internal_crates` is empty (the default), no `internal-leak`
/// resolution is performed at all for any candidate — not "resolved and
/// filtered to nothing" — the same "zero configured entries, zero
/// iterations, not zero findings" empty-scope shape
/// `crate::boundaries::evaluate`'s own `config.boundaries`/
/// `config.module_boundaries` loops already have when their config is empty
/// (todo.md §17 "Kein Raten von Projektabsicht"). Loads its own
/// [`DeepContext`] rather than sharing one with another detector — the same
/// accepted, documented extra cost
/// [`crate::slop_structural_deep::analyze_workspace`] takes for the same
/// reason (see that function's doc comment).
pub fn analyze_workspace(
    workspace: &Workspace,
    internal_crates: &[String],
) -> Result<DeepApiSurfaceReport, ApiSurfaceDeepError> {
    let internal_crates: HashSet<&str> = internal_crates.iter().map(String::as_str).collect();
    let ctx = DeepContext::load(&workspace.root).map_err(ApiSurfaceDeepError::Deep)?;
    let db = ctx.raw_database();
    let sema = Semantics::new(db);

    // `ra_ap_ide::Analysis`'s own query methods (`find_all_refs`, etc.)
    // internally wrap themselves in `attach_db` before touching type-system
    // internals (see `ra_ap_ide::Analysis::with_db`); calling `hir::Type`
    // methods (`resolve_type`, `strip_references`, `as_adt_with_args`)
    // directly through `Semantics`/`RootDatabase` the way this module does
    // bypasses that wrapper, so it must attach explicitly here instead —
    // without it, the next-trait-solver internals panic with "Try to use
    // attached db, but not db is attached".
    ra_ap_hir::attach_db(db, || {
        let mut report = DeepApiSurfaceReport::default();

        for krate in &workspace.crates {
            for file in &krate.source_files {
                if !file.kind.is_locally_reportable() {
                    continue;
                }
                let Some(file_id) = ctx.file_id(&file.path) else {
                    continue;
                };
                let Some(own_module) = sema.file_to_module_def(file_id) else {
                    continue;
                };
                let own_crate = own_module.krate(db);

                let candidates = match api_surface::pub_fn_candidates(&file.path) {
                    Ok(candidates) => candidates,
                    Err(err) => {
                        report.errors.push(ApiSurfaceDeepError::ApiSurface(err));
                        continue;
                    }
                };

                for candidate in &candidates {
                    report.checked += 1;
                    report.findings.extend(leaked_types_for_candidate(
                        &sema, db, file_id, own_crate, candidate,
                    ));
                    if !internal_crates.is_empty() {
                        let leaks =
                            resolve_leaks_for_candidate(&sema, db, file_id, own_crate, candidate);
                        report.findings.extend(
                            leaks
                                .iter()
                                .filter(|(_, leak)| {
                                    internal_crates.contains(leak.defining_crate.as_str())
                                })
                                .map(|(site, leak)| internal_leak_finding(candidate, site, leak)),
                        );
                    }
                }
            }
        }

        report
            .findings
            .extend(re_export_chain_findings(workspace, &ctx, &sema, db));

        Ok(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn semver_hazard_findings(report: &DeepApiSurfaceReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.rule == SEMVER_HAZARD_RULE)
            .collect()
    }

    fn internal_leak_findings(report: &DeepApiSurfaceReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.rule == INTERNAL_LEAK_RULE)
            .collect()
    }

    /// (a) A `pub fn` whose parameter type comes from another crate must be
    /// flagged with `evidence.kind: "leaked_dependency_type"`. With
    /// `internal_crates` empty (the default), the same cross-crate reference
    /// must *not* produce an `internal-leak` finding — empty config means no
    /// analysis was performed for that rule, not "checked, found nothing"
    /// (see [`analyze_workspace`]'s doc comment).
    #[test]
    fn a_pub_fn_with_a_dependency_type_parameter_is_flagged() {
        let dir = TempDir::new("api-surface-deep-leaked-param");
        write_crate(
            &dir,
            "other",
            &[],
            "pub struct OtherCrateType {\n    pub value: i32,\n}\n",
        );
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub fn process(x: other::OtherCrateType) -> i32 {\n    x.value\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        let hits = semver_hazard_findings(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "process")
            .expect("process(x: other::OtherCrateType) must be flagged");
        assert_eq!(
            hit.evidence.as_ref().unwrap()["kind"],
            "leaked_dependency_type"
        );
        assert_eq!(
            hit.evidence.as_ref().unwrap()["type_name"],
            "OtherCrateType"
        );
        assert_eq!(hit.evidence.as_ref().unwrap()["defining_crate"], "other");
        assert_eq!(hit.evidence.as_ref().unwrap()["site"], "parameter0");
        assert_eq!(hit.severity, Severity::Info);
        assert_eq!(hit.evidence_class, EvidenceClass::BoundedSemantic);

        assert!(
            internal_leak_findings(&report).is_empty(),
            "empty internal_crates must produce zero internal-leak findings, even though process() leaks other::OtherCrateType: {:?}",
            internal_leak_findings(&report)
        );
    }

    /// (b) The same cross-crate leak as above, but with `other` named in
    /// `internal_crates` — this must now also fire `internal-leak`,
    /// gating, alongside the unaffected `semver-hazard` finding.
    #[test]
    fn a_pub_fn_leaking_a_configured_internal_crate_type_is_flagged() {
        let dir = TempDir::new("api-surface-deep-internal-leak-hit");
        write_crate(
            &dir,
            "other",
            &[],
            "pub struct OtherCrateType {\n    pub value: i32,\n}\n",
        );
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub fn process(x: other::OtherCrateType) -> i32 {\n    x.value\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &["other".to_string()]).unwrap();

        let hits = internal_leak_findings(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "process")
            .expect("process(x: other::OtherCrateType) must be flagged as internal-leak");
        assert_eq!(hit.evidence.as_ref().unwrap()["kind"], "internal_leak");
        assert_eq!(
            hit.evidence.as_ref().unwrap()["type_name"],
            "OtherCrateType"
        );
        assert_eq!(hit.evidence.as_ref().unwrap()["defining_crate"], "other");
        assert_eq!(hit.severity, Severity::Warn);
        assert_eq!(hit.evidence_class, EvidenceClass::BoundedSemantic);

        // `semver-hazard`'s own `leaked_dependency_type` sub-case is
        // unaffected — `internal-leak` is additive, not a replacement.
        assert!(
            semver_hazard_findings(&report)
                .iter()
                .any(|f| f.location.item_path == "process"),
            "internal-leak must not suppress the existing semver-hazard finding"
        );
    }

    /// (c) The same leak, but `internal_crates` names a crate *other* than
    /// the one that actually owns the leaked type — must not fire.
    #[test]
    fn a_pub_fn_leaking_a_non_configured_crate_type_is_not_flagged() {
        let dir = TempDir::new("api-surface-deep-internal-leak-miss");
        write_crate(&dir, "other", &[], "pub struct OtherCrateType;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub fn process(x: other::OtherCrateType) {\n    let _ = x;\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &["some-unrelated-crate".to_string()]).unwrap();

        assert!(
            internal_leak_findings(&report).is_empty(),
            "internal_crates naming a different crate than the one that owns the leaked type must not fire: {:?}",
            internal_leak_findings(&report)
        );
    }

    /// (a, return-type variant) The same leak, but through the return type
    /// instead of a parameter.
    #[test]
    fn a_pub_fn_with_a_dependency_type_return_is_flagged() {
        let dir = TempDir::new("api-surface-deep-leaked-return");
        write_crate(&dir, "other", &[], "pub struct OtherCrateType;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub fn make() -> other::OtherCrateType {\n    other::OtherCrateType\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        let hits = semver_hazard_findings(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "make")
            .expect("make() -> other::OtherCrateType must be flagged");
        assert_eq!(hit.evidence.as_ref().unwrap()["site"], "return");
    }

    /// (b) A `pub fn` using only its own crate's types and `std` types must
    /// not be flagged.
    #[test]
    fn a_pub_fn_with_only_own_and_std_types_is_not_flagged() {
        let dir = TempDir::new("api-surface-deep-no-leak");
        write_crate(
            &dir,
            "core_crate",
            &[],
            r#"pub struct Local {
    pub value: i32,
}

pub fn process(x: Local, y: i32) -> String {
    let _ = x.value;
    let _ = y;
    String::new()
}
"#,
        );
        write_workspace_manifest(&dir, &["core_crate"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            semver_hazard_findings(&report)
                .iter()
                .all(|f| f.location.item_path != "process"),
            "own/std types only must not be flagged: {:?}",
            semver_hazard_findings(&report)
        );
    }

    /// (c) One level of generic unwrapping: `Vec<OtherCrateType>` must still
    /// be flagged, because `Vec` is a `std`/`alloc` container and its single
    /// type argument is checked the same way a direct parameter would be.
    /// **Documented scope, not a bug:** only one level deep — see the module
    /// docs' "Ehrliche Grenze" section.
    #[test]
    fn a_pub_fn_with_a_dependency_type_one_level_inside_a_vec_is_flagged() {
        let dir = TempDir::new("api-surface-deep-leaked-generic");
        write_crate(&dir, "other", &[], "pub struct OtherCrateType;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub fn process(x: Vec<other::OtherCrateType>) -> usize {\n    x.len()\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        let hits = semver_hazard_findings(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "process")
            .expect("process(x: Vec<other::OtherCrateType>) must be flagged one level deep");
        assert_eq!(
            hit.evidence.as_ref().unwrap()["type_name"],
            "OtherCrateType"
        );
    }

    /// (d) A generically nested `std`-only type (`Option<i32>`) must not be
    /// flagged — the type argument itself resolves to a `std`/primitive
    /// type, not a dependency's.
    #[test]
    fn a_pub_fn_with_only_std_types_nested_in_a_generic_is_not_flagged() {
        let dir = TempDir::new("api-surface-deep-no-leak-generic");
        write_crate(
            &dir,
            "core_crate",
            &[],
            "pub fn process(x: Option<i32>) -> Option<i32> {\n    x\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            semver_hazard_findings(&report)
                .iter()
                .all(|f| f.location.item_path != "process"),
            "Option<i32> is std-only, even nested: {:?}",
            semver_hazard_findings(&report)
        );
    }

    /// A `pub fn` inside an inherent `impl` block is checked the same as a
    /// free function — same item population as the Fast-Tier sub-cases (see
    /// the module docs).
    #[test]
    fn a_pub_method_in_an_inherent_impl_with_a_dependency_type_parameter_is_flagged() {
        let dir = TempDir::new("api-surface-deep-inherent-impl");
        write_crate(&dir, "other", &[], "pub struct OtherCrateType;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            r#"pub struct Local;

impl Local {
    pub fn process(&self, x: other::OtherCrateType) {
        let _ = x;
    }
}
"#,
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            semver_hazard_findings(&report)
                .iter()
                .any(|f| f.location.item_path == "Local::process"),
            "inherent-impl method with a leaked type parameter must be flagged: {:?}",
            semver_hazard_findings(&report)
        );
    }

    /// A `pub fn` whose parameter type comes from a dependency crate that is
    /// *not* itself a workspace member (only referenced via a path
    /// dependency) must also be flagged — the filter is "not
    /// `std`/`core`/`alloc` and not the same crate", not "not a workspace
    /// crate".
    #[test]
    fn a_pub_fn_with_a_non_member_dependency_type_is_flagged() {
        let dir = TempDir::new("api-surface-deep-external-dep");
        write_crate(&dir, "external", &[], "pub struct ExternalType;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("external", "../external")],
            "pub fn accept(x: external::ExternalType) {\n    let _ = x;\n}\n",
        );
        // `external` is deliberately not listed as a workspace member —
        // only reachable through `core_crate`'s path dependency, the same
        // shape a crates.io dependency has.
        write_workspace_manifest(&dir, &["core_crate"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            semver_hazard_findings(&report)
                .iter()
                .any(|f| f.location.item_path == "accept"),
            "a type from a dependency crate outside the workspace member list must be flagged: {:?}",
            semver_hazard_findings(&report)
        );
    }

    fn re_export_chain_findings_in(report: &DeepApiSurfaceReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.rule == RE_EXPORT_CHAIN_RULE)
            .collect()
    }

    /// (a) A direct, single re-export (hop count 1: `core_crate` re-exports
    /// `other`'s `Foo` directly) must *not* be flagged — a lone hop is the
    /// common, unremarkable case (see [`RE_EXPORT_CHAIN_MIN_HOP_COUNT`]).
    #[test]
    fn a_direct_single_reexport_is_not_flagged() {
        let dir = TempDir::new("api-surface-deep-reexport-single-hop");
        write_crate(&dir, "other", &[], "pub struct Foo;\n");
        write_crate(
            &dir,
            "core_crate",
            &[("other", "../other")],
            "pub use other::Foo;\n",
        );
        write_workspace_manifest(&dir, &["core_crate", "other"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            re_export_chain_findings_in(&report).is_empty(),
            "a single-hop pub use re-export must not be flagged: {:?}",
            re_export_chain_findings_in(&report)
        );
    }

    /// (b) A genuine multi-hop chain — `crate_a` re-exports `crate_b`'s
    /// `Foo`, which is itself a re-export of `crate_c`'s `Foo`, which defines
    /// it — must be flagged with `hop_count: 2` and the correct
    /// `defining_path` pointing at `crate_c`, not `crate_b`.
    #[test]
    fn a_two_hop_reexport_chain_is_flagged() {
        let dir = TempDir::new("api-surface-deep-reexport-two-hops");
        write_crate(&dir, "crate_c", &[], "pub struct Foo;\n");
        write_crate(
            &dir,
            "crate_b",
            &[("crate_c", "../crate_c")],
            "pub use crate_c::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_a",
            &[("crate_b", "../crate_b")],
            "pub use crate_b::Foo;\n",
        );
        write_workspace_manifest(&dir, &["crate_a", "crate_b", "crate_c"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        let hits = re_export_chain_findings_in(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "crate_a::Foo")
            .unwrap_or_else(|| panic!("crate_a::Foo's two-hop chain must be flagged: {hits:?}"));
        assert_eq!(hit.evidence.as_ref().unwrap()["hop_count"], 2);
        assert_eq!(
            hit.evidence.as_ref().unwrap()["defining_path"],
            "crate_c::Foo"
        );
        assert_eq!(
            hit.evidence.as_ref().unwrap()["exported_path"],
            "crate_a::Foo"
        );
        assert_eq!(hit.evidence.as_ref().unwrap()["capped"], false);
        assert_eq!(hit.severity, Severity::Info);
        assert_eq!(hit.evidence_class, EvidenceClass::Heuristic);
    }

    /// (c) A chain deep enough to hit the hop cap (`RE_EXPORT_CHAIN_MAX_HOPS`,
    /// 5) must report `hop_count: 5` and `capped: true` rather than an exact,
    /// deeper count — and, just as importantly, must terminate at all rather
    /// than looping. Six re-exporting crates (`crate_a` through `crate_f`)
    /// forward to a seventh (`crate_g`) that defines the item, six real hops
    /// deep — one more than the cap.
    #[test]
    fn a_chain_deeper_than_the_cap_is_reported_as_capped() {
        let dir = TempDir::new("api-surface-deep-reexport-capped");
        write_crate(&dir, "crate_g", &[], "pub struct Foo;\n");
        write_crate(
            &dir,
            "crate_f",
            &[("crate_g", "../crate_g")],
            "pub use crate_g::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_e",
            &[("crate_f", "../crate_f")],
            "pub use crate_f::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_d",
            &[("crate_e", "../crate_e")],
            "pub use crate_e::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_c",
            &[("crate_d", "../crate_d")],
            "pub use crate_d::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_b",
            &[("crate_c", "../crate_c")],
            "pub use crate_c::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_a",
            &[("crate_b", "../crate_b")],
            "pub use crate_b::Foo;\n",
        );
        write_workspace_manifest(
            &dir,
            &[
                "crate_a", "crate_b", "crate_c", "crate_d", "crate_e", "crate_f", "crate_g",
            ],
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        let hits = re_export_chain_findings_in(&report);
        let hit = hits
            .iter()
            .find(|f| f.location.item_path == "crate_a::Foo")
            .unwrap_or_else(|| panic!("crate_a::Foo's deep chain must be flagged: {hits:?}"));
        assert_eq!(hit.evidence.as_ref().unwrap()["hop_count"], 5);
        assert_eq!(hit.evidence.as_ref().unwrap()["capped"], true);
    }

    /// (c, alternate form) A genuine `pub use` cycle with no original
    /// definition anywhere (`crate_x` re-exports `crate_y`'s `Foo`, which
    /// re-exports `crate_x`'s own `Foo` right back) — this is not valid,
    /// compilable Rust (rustc would reject it as an unresolved cyclic
    /// import), but the Deep Tier only loads and semantically resolves the
    /// workspace, it never requires a successful `cargo build`. The point of
    /// this fixture is purely defensive: confirm `analyze_workspace` neither
    /// panics nor hangs on a cyclic `pub use` shape, and — since there is no
    /// real definition anywhere for `sema.resolve_path` to resolve to —
    /// correctly produces no `re-export-chain` finding for it rather than
    /// guessing one.
    #[test]
    fn a_pub_use_cycle_does_not_panic_or_hang() {
        let dir = TempDir::new("api-surface-deep-reexport-cycle");
        write_crate(
            &dir,
            "crate_x",
            &[("crate_y", "../crate_y")],
            "pub use crate_y::Foo;\n",
        );
        write_crate(
            &dir,
            "crate_y",
            &[("crate_x", "../crate_x")],
            "pub use crate_x::Foo;\n",
        );
        write_workspace_manifest(&dir, &["crate_x", "crate_y"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            re_export_chain_findings_in(&report)
                .iter()
                .all(|f| f.location.item_path != "crate_x::Foo"
                    && f.location.item_path != "crate_y::Foo"),
            "an unresolvable pub use cycle must not be reported as a resolved chain: {:?}",
            re_export_chain_findings_in(&report)
        );
    }

    /// (d) An item defined and used directly, with no re-export anywhere,
    /// must never even become a candidate — no `pub use` exists to scan.
    #[test]
    fn an_item_with_no_reexport_is_not_flagged() {
        let dir = TempDir::new("api-surface-deep-reexport-none");
        write_crate(
            &dir,
            "core_crate",
            &[],
            "pub struct Foo;\n\npub fn make() -> Foo {\n    Foo\n}\n",
        );
        write_workspace_manifest(&dir, &["core_crate"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, &[]).unwrap();

        assert!(
            re_export_chain_findings_in(&report).is_empty(),
            "an item with no pub use anywhere must not be flagged: {:?}",
            re_export_chain_findings_in(&report)
        );
    }
}
