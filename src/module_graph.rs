//! Reachability within a crate's own `mod` tree, and cross-module reference
//! scanning — two Fast-Tier rules built on real `mod`-graph resolution
//! rather than directory-convention guessing (see todo.md §A "Reachability &
//! Dead Code", §14.2 P1/P2):
//!
//! - **`unlinked-file`**: a `.rs` file belonging to a crate (per
//!   [`crate::ingest::CrateInfo::source_files`]) that is never reached by
//!   resolving `mod foo;`/`mod foo { .. }` declarations (including
//!   `#[path = "..."]` overrides) starting from any of the crate's own
//!   Cargo target roots (`src/lib.rs`, `src/main.rs`, `src/bin/*.rs`, every
//!   `[[test]]`/`[[example]]`/`[[bench]]` target's own root file, and
//!   `build.rs` — see [`crate::ingest::EntryPoint`]). Each of those roots is
//!   its own independent tree; a `[[test]]`/`[[example]]`/`[[bench]]` file is
//!   never itself "unlinked" even though nothing `mod`-declares it — it *is*
//!   a root, by Cargo convention.
//! - **`orphan-module`**: a module reached by that same traversal (i.e. not
//!   `unlinked-file`, and not a crate root itself) that no file *outside*
//!   it — anywhere in the workspace — references via a `crate::<module_path>`
//!   or `<crate-name>::<module_path>` path.
//!
//! ## Fast Tier, not Deep Tier — the design call this module makes
//!
//! Earlier detectors in this crate that reason about reachability
//! (`unused-pub-workspace`, `duplicative-reinvention`, `connectivity-drop`)
//! need the Deep Tier's `ra_ap_hir`/`find_all_refs` because they reason
//! about *item*-level reference resolution — knowing whether a specific
//! function is called requires type-aware name resolution. Both rules here
//! only reason about *file*-level `mod` structure and textual
//! `crate::`/`<crate-name>::` path prefixes — the same class of problem
//! `boundaries.rs`'s `module_path_for_file`/`ModuleBoundaryCollector` and
//! `principle.rs`'s `dependency-inversion` already solve without semantic
//! resolution. So this module is Fast Tier: always available, no `--features
//! deep`.
//!
//! Unlike `boundaries.rs`'s directory-convention `module_path_for_file`,
//! this module resolves the *actual* `mod` graph: `#[path = "..."]` is read
//! and resolved (relative to the declaring file's own directory — the same
//! rule rustc itself uses), and only files actually reachable via a `mod`
//! chain are considered part of the tree. This is deliberately more precise
//! than `boundaries.rs`'s heuristic — that module doesn't do the same
//! because its own job (resolving arbitrary `use`/path *expressions*, not
//! just `mod` declarations) is a bigger scope that doesn't reduce to file
//! resolution alone.
//!
//! ## Bare/self-relative reference resolution — a narrow, sound exception
//!
//! Like `boundaries.rs`'s `resolve_leading_segments`, [`ReferenceCollector`]
//! only resolves a path whose leading segment is `crate`, `super`, or a
//! known workspace crate's own identifier — a bare/unqualified reference
//! (including `self::...`) is **not** resolved in general, since telling
//! apart a submodule name, a `use`-imported item, and a local binding needs
//! real name resolution this Fast Tier doesn't have.
//!
//! One narrow, provably-sound exception is made: a bare leading segment that
//! exactly matches a `mod` name declared at the *top level of the same
//! file* is resolved relative to that file's own module path. This targets
//! the extremely common re-export idiom `mod foo; pub use foo::Bar;` (both
//! lines in the same file) — without it, virtually every module using this
//! idiom (and no *other*, absolute `crate::`-qualified reference) would
//! false-positive as `orphan-module`, since the file that both declares and
//! consumes the module is otherwise invisible to a `crate::`/`super::`-only
//! scan. It's sound because in valid Rust, a bare path segment inside a file
//! that declares `mod foo;` unambiguously refers to that submodule — no
//! other binding can share the name without a compile error. A bare
//! reference to a *nested* module (not declared at the referencing file's
//! own top level) is not resolved by this exception; that stays a
//! documented gap, same spirit as `boundaries.rs`'s own accepted limitation.
//!
//! ## Known blind spot: `include!`
//!
//! A file spliced into another via `include!("other.rs")` has no `mod`
//! declaration of its own — it becomes part of the includer's token stream
//! at macro-expansion time, invisible to a syntactic pass. Such a file would
//! be reported `unlinked-file` here even though it is genuinely part of the
//! build. Resolving `include!` needs the same expansion machinery the Deep
//! Tier's `DeepContext` deliberately doesn't run either (see `crate::deep`'s
//! own proc-macro/build-script trade-off) — not implemented here, left as
//! documented follow-up work rather than a reason to promote this whole
//! module to the Deep Tier for one macro form.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Item, ItemUse, UseTree};

use crate::finding::{
    EvidenceClass, Finding, FindingGraph, FindingId, Location, OneBasedLine, Origin, Severity,
};
use crate::ingest::{CrateInfo, EntryPointKind, SourceFile, SourceKind, Workspace};

/// Rule id for a `.rs` file never reached by resolving `mod` declarations
/// from any of its crate's own Cargo target roots (see module docs).
pub const UNLINKED_FILE_RULE: &str = "unlinked-file";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const UNLINKED_FILE_RULE_REVISION: u32 = 1;

/// Rule id for a reached, non-root module no file outside it references (see
/// module docs).
pub const ORPHAN_MODULE_RULE: &str = "orphan-module";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const ORPHAN_MODULE_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum ModuleGraphError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for ModuleGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ModuleGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// One out-of-line `mod name;` declaration resolved to its child file (see
/// module docs). Inline `mod name { .. }` declarations are not represented
/// here — they have no file of their own, so neither `unlinked-file` (which
/// only ever reports on `.rs` files) nor `orphan-module` (scoped to a
/// "file/file-group" per todo.md's own note) has anything to say about them.
#[derive(Debug, Clone)]
struct ModuleNode {
    /// Fully qualified, `::`-joined module path relative to the crate root
    /// the containing tree traversal started from (e.g. `"foo::bar"`).
    /// Never empty — the crate-root file itself is not a node.
    module_path: String,
    file: PathBuf,
    declared_at_file: PathBuf,
    declared_at_line: usize,
}

/// One crate's resolved `mod` tree: every file reached from any of the
/// crate's own Cargo target roots, and the [`ModuleNode`] for each
/// out-of-line `mod` declaration found along the way.
#[derive(Debug, Default)]
struct CrateModuleTree {
    /// File -> its resolved module path (a tree root maps to `""`).
    file_module_path: HashMap<PathBuf, String>,
    nodes: Vec<ModuleNode>,
    /// Human-readable root labels for evidence (e.g. `"lib"`, `"bin:tool"`).
    root_labels: Vec<String>,
}

fn entry_point_label(entry: &crate::ingest::EntryPoint) -> String {
    match entry.kind {
        EntryPointKind::Lib => "lib".to_string(),
        EntryPointKind::Bin => format!("bin:{}", entry.name),
        EntryPointKind::Example => format!("example:{}", entry.name),
        EntryPointKind::Test => format!("test:{}", entry.name),
        EntryPointKind::Bench => format!("bench:{}", entry.name),
        EntryPointKind::BuildScript => "build-script".to_string(),
    }
}

/// Builds [`CrateModuleTree`] by traversing `mod` declarations from every one
/// of `krate`'s own Cargo target roots (see module docs). Read/parse
/// failures are collected as [`ModuleGraphError`]s and otherwise skipped —
/// the traversal just doesn't discover anything past that point, the same
/// accepted-limitation shape `boundaries.rs`/`deps.rs` already use for their
/// own file scans.
fn build_crate_module_tree(krate: &CrateInfo) -> (CrateModuleTree, Vec<ModuleGraphError>) {
    let mut tree = CrateModuleTree::default();
    let mut errors = Vec::new();

    for entry in &krate.entry_points {
        tree.root_labels.push(entry_point_label(entry));
        if tree.file_module_path.contains_key(&entry.path) {
            continue;
        }
        tree.file_module_path
            .insert(entry.path.clone(), String::new());
        visit_mod_file(&entry.path, String::new(), &mut tree, &mut errors);
    }

    (tree, errors)
}

fn join_module_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}::{name}")
    }
}

fn module_path_segments(module_path: &str) -> Vec<String> {
    if module_path.is_empty() {
        Vec::new()
    } else {
        module_path.split("::").map(str::to_string).collect()
    }
}

fn visit_mod_file(
    file: &Path,
    module_path: String,
    tree: &mut CrateModuleTree,
    errors: &mut Vec<ModuleGraphError>,
) {
    let source = match std::fs::read_to_string(file) {
        Ok(source) => source,
        Err(err) => {
            errors.push(ModuleGraphError::Io(file.to_path_buf(), err));
            return;
        }
    };
    let ast = match syn::parse_file(&source) {
        Ok(ast) => ast,
        Err(err) => {
            errors.push(ModuleGraphError::Parse(file.to_path_buf(), err));
            return;
        }
    };
    visit_items(&ast.items, file, &module_path, tree, errors);
}

fn visit_items(
    items: &[Item],
    file: &Path,
    module_path: &str,
    tree: &mut CrateModuleTree,
    errors: &mut Vec<ModuleGraphError>,
) {
    for item in items {
        let Item::Mod(item_mod) = item else { continue };
        let child_module_path = join_module_path(module_path, &item_mod.ident.to_string());

        if let Some((_, content_items)) = &item_mod.content {
            // Inline module: same file, recurse directly — no new node.
            visit_items(content_items, file, &child_module_path, tree, errors);
            continue;
        }

        let Some(child_file) = resolve_mod_file(file, &item_mod.attrs, &item_mod.ident.to_string())
        else {
            continue; // unresolved mod target — undiscoverable, not an error
        };
        if tree.file_module_path.contains_key(&child_file) {
            continue; // already visited — avoids infinite recursion on a cycle
        }
        let line = item_mod.ident.span().start().line;
        tree.nodes.push(ModuleNode {
            module_path: child_module_path.clone(),
            file: child_file.clone(),
            declared_at_file: file.to_path_buf(),
            declared_at_line: line,
        });
        tree.file_module_path
            .insert(child_file.clone(), child_module_path.clone());
        visit_mod_file(&child_file, child_module_path, tree, errors);
    }
}

/// Resolves one `mod name;` declaration to its child file: `#[path = "..."]`
/// takes precedence (resolved relative to the *declaring file's own*
/// directory), else the Rust 2018+ convention (`<name>.rs`, `<name>/mod.rs`,
/// both relative to [`module_own_dir`]). `None` when neither resolves to an
/// existing file.
fn resolve_mod_file(
    declaring_file: &Path,
    attrs: &[syn::Attribute],
    name: &str,
) -> Option<PathBuf> {
    if let Some(path_value) = path_attr_value(attrs) {
        let base = declaring_file.parent().unwrap_or_else(|| Path::new(""));
        let candidate = base.join(path_value);
        return candidate.is_file().then_some(candidate);
    }
    let own_dir = module_own_dir(declaring_file);
    let as_file = own_dir.join(format!("{name}.rs"));
    if as_file.is_file() {
        return Some(as_file);
    }
    let as_mod_dir = own_dir.join(name).join("mod.rs");
    if as_mod_dir.is_file() {
        return Some(as_mod_dir);
    }
    None
}

/// Reads a `#[path = "..."]` attribute's string value, if present. Unlike
/// `boundaries.rs`'s `module_path_for_file`, which deliberately does not
/// resolve `#[path]` (that module's own documented gap), resolving it here
/// is what keeps `unlinked-file` from false-positiving on every
/// non-conventionally-wired file.
fn path_attr_value(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(name_value) = &attr.meta else {
            return None;
        };
        let syn::Expr::Lit(expr_lit) = &name_value.value else {
            return None;
        };
        let syn::Lit::Str(lit_str) = &expr_lit.lit else {
            return None;
        };
        Some(lit_str.value())
    })
}

/// The directory a file's own out-of-line `mod` children resolve relative
/// to, absent a `#[path]` override — Rust 2018+ convention: `lib.rs`,
/// `main.rs`, and `mod.rs` resolve children in their own parent directory;
/// any other file (including a `[[bin]]`/`[[test]]`/... target's own root,
/// e.g. `src/bin/tool.rs`) resolves children under a same-named subdirectory
/// (`src/bin/tool/`).
fn module_own_dir(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or_else(|| Path::new(""));
    match file.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => parent.to_path_buf(),
        _ => parent.join(file.file_stem().unwrap_or_default()),
    }
}

/// Every file whose resolved module path is `module_path` itself or a
/// descendant of it — a node's own "file group" (see module docs).
fn module_file_set<'a>(tree: &'a CrateModuleTree, module_path: &str) -> HashSet<&'a Path> {
    let prefix = format!("{module_path}::");
    tree.file_module_path
        .iter()
        .filter(|(_, path)| path.as_str() == module_path || path.starts_with(&prefix))
        .map(|(file, _)| file.as_path())
        .collect()
}

/// Whether `hit_path` (a resolved reference's module path) names `node_path`
/// itself, or something inside it — a `::`-segment prefix match, mirroring
/// `boundaries.rs`'s `module_path_under`/`segments_match_forbidden`.
fn module_path_references(hit_path: &str, node_path: &str) -> bool {
    hit_path == node_path || hit_path.starts_with(&format!("{node_path}::"))
}

/// Aggregated results across the whole workspace.
#[derive(Debug, Default)]
pub struct WorkspaceModuleGraph {
    pub findings: Vec<Finding>,
    /// Generated files/modules skipped by default (see
    /// [`crate::ingest::SourceKind`]) — combined count across both rules,
    /// matching how other Fast-Tier commands report a single
    /// `excluded_generated` total.
    pub excluded_generated: usize,
    pub errors: Vec<ModuleGraphError>,
}

/// Runs both `unlinked-file` and `orphan-module` over `workspace`.
pub fn analyze_workspace(workspace: &Workspace, include_generated: bool) -> WorkspaceModuleGraph {
    let mut errors = Vec::new();
    let trees: HashMap<&str, CrateModuleTree> = workspace
        .crates
        .iter()
        .map(|krate| {
            let (tree, tree_errors) = build_crate_module_tree(krate);
            errors.extend(tree_errors);
            (krate.name.as_str(), tree)
        })
        .collect();

    let mut excluded_generated = 0;
    let mut findings = unlinked_file_findings(
        workspace,
        &trees,
        include_generated,
        &mut excluded_generated,
    );
    findings.extend(orphan_module_findings(
        workspace,
        &trees,
        include_generated,
        &mut excluded_generated,
    ));

    WorkspaceModuleGraph {
        findings,
        excluded_generated,
        errors,
    }
}

/// `unlinked-file`: every crate source file never reached by
/// [`build_crate_module_tree`]'s traversal. Causally groups a missing root's
/// own cascade of unreached children under it (see module docs' "Kausale
/// Gruppierung" reference, todo.md §0): if unreached file `A` itself
/// declares (via a parseable `mod` item) a child that resolves to another
/// unreached file `B`, `A` is recorded as the cause of `B` via
/// [`FindingGraph`] — so a whole missing subtree collapses to its one
/// topmost root finding under `--show-cascades`-free (root-only) rendering.
fn unlinked_file_findings(
    workspace: &Workspace,
    trees: &HashMap<&str, CrateModuleTree>,
    include_generated: bool,
    excluded_generated: &mut usize,
) -> Vec<Finding> {
    let mut unreached_by_crate: HashMap<&str, Vec<&SourceFile>> = HashMap::new();
    for krate in &workspace.crates {
        let tree = &trees[krate.name.as_str()];
        let mut unreached = Vec::new();
        for file in &krate.source_files {
            if tree.file_module_path.contains_key(&file.path) {
                continue;
            }
            if file.kind == SourceKind::Generated && !include_generated {
                *excluded_generated += 1;
                continue;
            }
            unreached.push(file);
        }
        unreached_by_crate.insert(krate.name.as_str(), unreached);
    }

    let mut graph = FindingGraph::new();
    let mut id_by_path: HashMap<&Path, FindingId> = HashMap::new();
    for krate in &workspace.crates {
        let tree = &trees[krate.name.as_str()];
        for file in &unreached_by_crate[krate.name.as_str()] {
            let finding = unlinked_file_finding(krate, file, tree);
            let id = finding.id.clone();
            graph
                .add_finding(finding)
                .expect("unlinked-file ids are unique per source file path");
            id_by_path.insert(file.path.as_path(), id);
        }
    }

    for krate in &workspace.crates {
        for file in &unreached_by_crate[krate.name.as_str()] {
            let Some(cause_id) = id_by_path.get(file.path.as_path()).cloned() else {
                continue;
            };
            let Ok(source) = std::fs::read_to_string(&file.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&source) else {
                continue;
            };
            for item in &ast.items {
                let Item::Mod(item_mod) = item else { continue };
                if item_mod.content.is_some() {
                    continue;
                }
                let Some(child_file) =
                    resolve_mod_file(&file.path, &item_mod.attrs, &item_mod.ident.to_string())
                else {
                    continue;
                };
                if let Some(effect_id) = id_by_path.get(child_file.as_path()) {
                    // A duplicate/cyclic edge is impossible here (each file
                    // is unreached at most once, and this only ever walks
                    // downward from a parent's own `mod` items), but ignore
                    // rather than panic if the graph ever disagrees.
                    let _ = graph.add_edge(&cause_id, effect_id);
                }
            }
        }
    }

    graph.into_findings()
}

fn unlinked_file_finding(krate: &CrateInfo, file: &SourceFile, tree: &CrateModuleTree) -> Finding {
    let mut roots_searched = tree.root_labels.clone();
    roots_searched.sort();
    roots_searched.dedup();
    Finding {
        id: format!("{UNLINKED_FILE_RULE}:{}", file.path.display()).into(),
        rule: UNLINKED_FILE_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.path.clone(),
            line: OneBasedLine::FIRST,
            item_path: format!("{}: {}", krate.name, file.path.display()),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "crate": krate.name,
            "roots_searched": roots_searched,
            "reason": "not reached by resolving `mod` declarations (including #[path] \
                overrides) from any of this crate's own Cargo target roots",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// One resolved reference found anywhere in the workspace, from
/// [`ReferenceCollector`].
struct ReferenceHit {
    referencing_file: PathBuf,
    owning_crate: String,
    module_path: String,
}

/// Collects every `crate::…`/`super::…`/`<crate-name>::…`-qualified
/// reference (plus the narrow bare-reference exception — see module docs) in
/// one parsed file, resolved to `(owning crate, module path)` pairs.
/// Duplicates `boundaries.rs`'s `resolve_leading_segments`/
/// `use_tree_leaf_segments` shape — that module's helpers are private, the
/// same trade-off `principle.rs` already documents for its own duplication
/// of them.
struct ReferenceCollector<'a> {
    own_crate: &'a str,
    /// `None` when the current file's own module path is unknown (the file
    /// itself is `unlinked-file` — outside the resolved tree). `super::` and
    /// the bare-reference exception are then unresolvable, but a
    /// `crate::…`/`<crate-name>::…` reference still resolves fine, since
    /// those don't need the current file's position.
    current_module: Option<&'a str>,
    crate_by_identifier: &'a HashMap<String, String>,
    /// `mod` names declared at the top level of the current file — see
    /// module docs "Bare/self-relative reference resolution".
    local_mod_names: &'a HashSet<String>,
    hits: Vec<(String, String)>,
}

impl ReferenceCollector<'_> {
    fn resolve(&self, mut segments: Vec<String>) -> Option<(String, String)> {
        if segments.is_empty() {
            return None;
        }
        let head = segments.remove(0);
        if head == "crate" {
            return Some((self.own_crate.to_string(), segments.join("::")));
        }
        if let Some(owner) = self.crate_by_identifier.get(&head) {
            return Some((owner.clone(), segments.join("::")));
        }
        if head == "super" {
            let mut parts = module_path_segments(self.current_module?);
            parts.pop()?;
            while segments.first().map(String::as_str) == Some("super") {
                segments.remove(0);
                parts.pop()?;
            }
            parts.extend(segments);
            return Some((self.own_crate.to_string(), parts.join("::")));
        }
        if self.local_mod_names.contains(&head) {
            let mut parts = module_path_segments(self.current_module?);
            parts.push(head);
            parts.extend(segments);
            return Some((self.own_crate.to_string(), parts.join("::")));
        }
        None
    }
}

/// Collects every leaf path of a `use` tree as a flat segment chain,
/// including its leading identifier — duplicates
/// `boundaries.rs::use_tree_leaf_segments` (private there).
fn use_tree_leaf_segments(tree: &UseTree, acc: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(use_path) => {
            acc.push(use_path.ident.to_string());
            use_tree_leaf_segments(&use_path.tree, acc, out);
            acc.pop();
        }
        UseTree::Name(use_name) => {
            let mut leaf = acc.clone();
            leaf.push(use_name.ident.to_string());
            out.push(leaf);
        }
        UseTree::Rename(use_rename) => {
            let mut leaf = acc.clone();
            leaf.push(use_rename.ident.to_string());
            out.push(leaf);
        }
        UseTree::Glob(_) => out.push(acc.clone()),
        UseTree::Group(group) => {
            for item in &group.items {
                use_tree_leaf_segments(item, acc, out);
            }
        }
    }
}

impl<'ast> Visit<'ast> for ReferenceCollector<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let mut leaves = Vec::new();
        use_tree_leaf_segments(&node.tree, &mut Vec::new(), &mut leaves);
        for leaf in leaves {
            if let Some(hit) = self.resolve(leaf) {
                self.hits.push(hit);
            }
        }
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        let segments: Vec<String> = node.segments.iter().map(|s| s.ident.to_string()).collect();
        if let Some(hit) = self.resolve(segments) {
            self.hits.push(hit);
        }
        visit::visit_path(self, node);
    }
}

/// Whether any file among a module node's own (transitive) file set contains
/// a recognized entry point — `fn main` at file top level, or a
/// `#[test]`-like-attributed function anywhere. Such a module is "referenced"
/// by the Cargo build/test harness itself, even with zero code references
/// (see module docs, todo.md's `orphan-module` exception for `#[test]`
/// functions).
fn module_has_recognized_entry_point(krate: &CrateInfo, file_set: &HashSet<&Path>) -> bool {
    krate
        .source_files
        .iter()
        .filter(|file| file_set.contains(file.path.as_path()))
        .any(|file| {
            let Ok(source) = std::fs::read_to_string(&file.path) else {
                return false;
            };
            let Ok(ast) = syn::parse_file(&source) else {
                return false;
            };
            file_has_recognized_entry_point(&ast)
        })
}

fn attr_looks_like_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

fn file_has_recognized_entry_point(ast: &syn::File) -> bool {
    let mut found = false;
    crate::functions::walk_functions(ast, |site| {
        if found {
            return;
        }
        if site.qualified_name == "main" || attr_looks_like_test(site.attrs) {
            found = true;
        }
    });
    found
}

/// `orphan-module`: every reached, non-root module node with zero references
/// from outside its own file set anywhere in the workspace (see module
/// docs).
fn orphan_module_findings(
    workspace: &Workspace,
    trees: &HashMap<&str, CrateModuleTree>,
    include_generated: bool,
    excluded_generated: &mut usize,
) -> Vec<Finding> {
    let crate_by_identifier: HashMap<String, String> = workspace
        .crates
        .iter()
        .map(|krate| (krate.name.replace('-', "_"), krate.name.clone()))
        .collect();

    let mut hits: Vec<ReferenceHit> = Vec::new();
    let mut files_scanned = 0usize;
    for krate in &workspace.crates {
        let tree = &trees[krate.name.as_str()];
        for file in &krate.source_files {
            let Ok(source) = std::fs::read_to_string(&file.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&source) else {
                continue;
            };
            files_scanned += 1;
            let current_module = tree.file_module_path.get(&file.path).cloned();
            let local_mod_names: HashSet<String> = ast
                .items
                .iter()
                .filter_map(|item| match item {
                    Item::Mod(item_mod) => Some(item_mod.ident.to_string()),
                    _ => None,
                })
                .collect();
            let mut collector = ReferenceCollector {
                own_crate: krate.name.as_str(),
                current_module: current_module.as_deref(),
                crate_by_identifier: &crate_by_identifier,
                local_mod_names: &local_mod_names,
                hits: Vec::new(),
            };
            collector.visit_file(&ast);
            for (owning_crate, module_path) in collector.hits {
                hits.push(ReferenceHit {
                    referencing_file: file.path.clone(),
                    owning_crate,
                    module_path,
                });
            }
        }
    }

    let mut findings = Vec::new();
    for krate in &workspace.crates {
        let tree = &trees[krate.name.as_str()];
        for node in &tree.nodes {
            let node_kind = krate
                .source_files
                .iter()
                .find(|file| file.path == node.file)
                .map_or(SourceKind::Authored, |file| file.kind);
            if node_kind == SourceKind::Generated && !include_generated {
                *excluded_generated += 1;
                continue;
            }

            let file_set = module_file_set(tree, &node.module_path);
            if module_has_recognized_entry_point(krate, &file_set) {
                continue;
            }

            let referenced = hits.iter().any(|hit| {
                hit.owning_crate == krate.name
                    && module_path_references(&hit.module_path, &node.module_path)
                    && !file_set.contains(hit.referencing_file.as_path())
            });
            if !referenced {
                findings.push(orphan_module_finding(krate, node, files_scanned));
            }
        }
    }
    findings
}

fn orphan_module_finding(krate: &CrateInfo, node: &ModuleNode, files_scanned: usize) -> Finding {
    Finding {
        id: format!("{ORPHAN_MODULE_RULE}:{}:{}", krate.name, node.module_path).into(),
        rule: ORPHAN_MODULE_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: node.declared_at_file.clone(),
            line: OneBasedLine::new(node.declared_at_line).unwrap_or(OneBasedLine::FIRST),
            item_path: format!("{}::{}", krate.name, node.module_path),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "crate": krate.name,
            "module_path": node.module_path,
            "searched_files": files_scanned,
            "reason": "no reference found anywhere in the examined workspace matching \
                `crate::<module_path>` or `<crate-name>::<module_path>` from outside the \
                module's own files",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn write_single_crate_manifest(dir: &TempDir, name: &str) {
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .unwrap();
    }

    fn rule_findings<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
        findings.iter().filter(|f| f.rule == rule).collect()
    }

    // (a) A `.rs` file in `src/` referenced by no `mod` is `unlinked-file`.
    #[test]
    fn an_unreferenced_source_file_is_unlinked() {
        let dir = TempDir::new("module-graph-unlinked");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(dir.join("src/orphan.rs"), "pub fn never_wired() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        let hits = rule_findings(&report.findings, UNLINKED_FILE_RULE);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].location.file.ends_with("orphan.rs"));
        assert_eq!(hits[0].evidence_class, EvidenceClass::BoundedSemantic);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn unlinked_file_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(UNLINKED_FILE_RULE)
            .expect("unlinked-file has a registry entry")
            .example
            .expect("unlinked-file has a curated example")
            .before;
        let dir = TempDir::new("module-graph-unlinked-file-registry-example");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(dir.join("src/legacy_config.rs"), example).unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert_eq!(rule_findings(&report.findings, UNLINKED_FILE_RULE).len(), 1);
    }

    // (b) The same file, linked via `mod foo;` in `lib.rs` — no finding.
    #[test]
    fn a_file_linked_via_a_conventional_mod_declaration_is_not_unlinked() {
        let dir = TempDir::new("module-graph-linked-conventional");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod foo;\n").unwrap();
        std::fs::write(dir.join("src/foo.rs"), "pub fn hello() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, UNLINKED_FILE_RULE).is_empty());
    }

    // (c) Linked via `#[path = "other.rs"] mod foo;` — resolved correctly.
    #[test]
    fn a_file_linked_via_a_path_attribute_is_not_unlinked() {
        let dir = TempDir::new("module-graph-linked-path-attr");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "#[path = \"unusual_name.rs\"]\nmod foo;\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/unusual_name.rs"), "pub fn hello() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, UNLINKED_FILE_RULE).is_empty());
    }

    // (d) `build.rs` is its own root — never flagged as unlinked.
    #[test]
    fn build_rs_is_never_flagged_as_unlinked() {
        let dir = TempDir::new("module-graph-build-rs");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, UNLINKED_FILE_RULE).is_empty());
    }

    // A `[[test]]`/`[[example]]`/`[[bench]]` root is its own root too, even
    // though nothing `mod`-declares it.
    #[test]
    fn an_integration_test_target_is_its_own_root_not_unlinked() {
        let dir = TempDir::new("module-graph-test-target");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::create_dir_all(dir.join("tests")).unwrap();
        std::fs::write(dir.join("tests/it.rs"), "#[test]\nfn works() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, UNLINKED_FILE_RULE).is_empty());
    }

    // Generated files are excluded from `unlinked-file` by default.
    #[test]
    fn a_generated_unlinked_file_is_excluded_by_default() {
        let dir = TempDir::new("module-graph-generated-excluded");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(
            dir.join("src/schema.rs"),
            "// @generated. DO NOT EDIT.\npub struct Schema;\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let default_report = analyze_workspace(&workspace, false);
        assert!(rule_findings(&default_report.findings, UNLINKED_FILE_RULE).is_empty());
        assert_eq!(default_report.excluded_generated, 1);

        let included_report = analyze_workspace(&workspace, true);
        assert_eq!(
            rule_findings(&included_report.findings, UNLINKED_FILE_RULE).len(),
            1
        );
    }

    // A missing root causes a whole cascade of unreached files — grouped
    // under the topmost unreached one via `caused_by`/`causes`.
    #[test]
    fn a_missing_root_groups_its_own_cascade_of_unreached_children() {
        let dir = TempDir::new("module-graph-cascade");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        // `foo.rs` is itself unreached (lib.rs never declares `mod foo;`),
        // but it declares `mod bar;`, which resolves to `foo/bar.rs` — also
        // unreached, and caused by `foo.rs` being unreached in the first
        // place.
        std::fs::write(dir.join("src/foo.rs"), "mod bar;\n").unwrap();
        std::fs::create_dir_all(dir.join("src/foo")).unwrap();
        std::fs::write(dir.join("src/foo/bar.rs"), "pub fn hello() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        let hits = rule_findings(&report.findings, UNLINKED_FILE_RULE);
        assert_eq!(hits.len(), 2);
        let root = hits
            .iter()
            .find(|f| f.location.file.ends_with("foo.rs"))
            .unwrap();
        let child = hits
            .iter()
            .find(|f| f.location.file.ends_with("bar.rs"))
            .unwrap();
        assert!(root.caused_by().is_empty());
        assert_eq!(root.causes().to_vec(), vec![child.id.clone()]);
        assert_eq!(child.caused_by().to_vec(), vec![root.id.clone()]);

        let roots = crate::finding::root_findings(&report.findings);
        assert_eq!(roots.len(), 1);
        assert!(roots[0].location.file.ends_with("foo.rs"));
    }

    // (e) A module used only internally (no external reference) is orphaned.
    #[test]
    fn a_module_with_no_external_reference_is_orphaned() {
        let dir = TempDir::new("module-graph-orphan");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod foo;\n").unwrap();
        std::fs::write(
            dir.join("src/foo.rs"),
            "pub fn bar() {}\n\npub fn calls_self() {\n    bar();\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        let hits = rule_findings(&report.findings, ORPHAN_MODULE_RULE);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].location.item_path, "fixture::foo");
        assert_eq!(hits[0].evidence_class, EvidenceClass::BoundedSemantic);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn orphan_module_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(ORPHAN_MODULE_RULE)
            .expect("orphan-module has a registry entry")
            .example
            .expect("orphan-module has a curated example")
            .before;
        let dir = TempDir::new("module-graph-orphan-module-registry-example");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod text_utils;\n").unwrap();
        std::fs::write(dir.join("src/text_utils.rs"), example).unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert_eq!(rule_findings(&report.findings, ORPHAN_MODULE_RULE).len(), 1);
    }

    // (f) A module referenced by another file via `crate::foo::bar()` — no
    // finding.
    #[test]
    fn a_module_referenced_via_an_absolute_crate_path_is_not_orphaned() {
        let dir = TempDir::new("module-graph-referenced-absolute");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "mod foo;\nmod baz;\n\npub fn bar() -> i32 {\n    0\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/foo.rs"), "pub fn bar() -> i32 {\n    1\n}\n").unwrap();
        std::fs::write(
            dir.join("src/baz.rs"),
            "pub fn calls_foo() -> i32 {\n    crate::foo::bar()\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        let hits: Vec<&str> = rule_findings(&report.findings, ORPHAN_MODULE_RULE)
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();
        assert!(!hits.contains(&"fixture::foo"));
    }

    // (g) A module with a `#[test]` function, otherwise unreferenced — no
    // finding (entry-point exception).
    #[test]
    fn a_module_with_a_test_function_is_not_orphaned_even_when_unreferenced() {
        let dir = TempDir::new("module-graph-test-exception");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod tests;\n").unwrap();
        std::fs::write(
            dir.join("src/tests.rs"),
            "#[test]\nfn it_works() {\n    assert!(true);\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, ORPHAN_MODULE_RULE).is_empty());
    }

    // The narrow bare-reference exception: `mod foo; pub use foo::Bar;` in
    // the same file counts as a reference from outside `foo`'s own file set.
    #[test]
    fn a_same_file_reexport_of_a_declared_submodule_counts_as_a_reference() {
        let dir = TempDir::new("module-graph-bare-reexport");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod foo;\npub use foo::Bar;\n").unwrap();
        std::fs::write(dir.join("src/foo.rs"), "pub struct Bar;\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, ORPHAN_MODULE_RULE).is_empty());
    }

    // Cross-crate reference via `<crate-name>::<module_path>` also counts.
    #[test]
    fn a_module_referenced_from_another_workspace_crate_by_crate_name_is_not_orphaned() {
        let dir = TempDir::new("module-graph-cross-crate");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"lib_crate\", \"consumer\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("lib_crate/src")).unwrap();
        std::fs::write(
            dir.join("lib_crate/Cargo.toml"),
            "[package]\nname = \"lib_crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.join("lib_crate/src/lib.rs"), "mod foo;\n").unwrap();
        std::fs::write(
            dir.join("lib_crate/src/foo.rs"),
            "pub fn bar() -> i32 {\n    1\n}\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("consumer/src")).unwrap();
        std::fs::write(
            dir.join("consumer/Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nlib_crate = { path = \"../lib_crate\" }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("consumer/src/lib.rs"),
            "pub fn use_it() -> i32 {\n    lib_crate::foo::bar()\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        let hits: Vec<&str> = rule_findings(&report.findings, ORPHAN_MODULE_RULE)
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();
        assert!(!hits.contains(&"lib_crate::foo"));
    }

    // `mod.rs` (the older out-of-line directory convention) resolves too.
    #[test]
    fn a_mod_rs_file_resolves_via_the_directory_convention() {
        let dir = TempDir::new("module-graph-mod-rs");
        write_single_crate_manifest(&dir, "fixture");
        std::fs::create_dir_all(dir.join("src/foo")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "mod foo;\n").unwrap();
        std::fs::write(dir.join("src/foo/mod.rs"), "pub fn hello() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true);

        assert!(rule_findings(&report.findings, UNLINKED_FILE_RULE).is_empty());
    }
}
