//! Dependency-hygiene, Fast Tier (see todo.md §3.B, §14.2 P1
//! "Dependency-Nutzung pro Cargo-Target und `cfg` sammeln; nur eindeutige
//! `misplaced-dependency-kind`-Vorschläge erzeugen, Feature-only-Nutzung als
//! Evidenz erhalten"). This module implements `misplaced-dependency-kind`'s
//! two unambiguous cases:
//!
//! a. A `normal` dependency whose code identifier is referenced only from
//!    `Dev`-domain files (`tests/`, `examples/`, `benches/`), never from
//!    `Normal`-domain files — it probably belongs in `[dev-dependencies]`.
//! b. A `build` dependency whose code identifier is never referenced from
//!    `build.rs` — it appears unused by the build script.
//!
//! The third case from todo.md §3.B's table — "a target dependency could be
//! declared more narrowly" — is intentionally *not* implemented here: it
//! needs correlating usage sites with the specific `cfg(...)` predicate
//! guarding them, which is Deep-Tier-grade semantic analysis, not something a
//! directory-convention heuristic can support without false positives.
//!
//! It also implements two usage-based rules built on top of the same
//! per-crate usage evidence (todo.md §B): `unused-dev-dependency` (a
//! `[dev-dependencies]` entry with no usage found in any `Dev`-domain file or
//! `#[cfg(test)]` module) and `heavy-dependency` (a dependency whose resolved
//! transitive footprint is large relative to how many distinct items of it
//! the crate actually references).
//!
//! ## Usage-domain classification
//!
//! Source files are classified into a [`UsageDomain`] purely by path
//! convention relative to the crate root — `tests/`, `examples/`, `benches/`
//! → `Dev`; `build.rs` → `Build`; everything else → `Normal`. This is a
//! heuristic, not module-graph resolution (see todo.md §2.1 "heuristisch,
//! false positives möglich"): a file could in principle be wired into the
//! build in an unconventional way that this classification misses.
//!
//! ## Feature-only evidence
//!
//! A dependency that is never referenced by identifier *anywhere* but that
//! declares a non-empty `features` list is deliberately **not** turned into a
//! misplaced-kind finding — judge cannot see which code path a feature
//! enables, so asserting a kind mismatch there would be an unbacked claim.
//! Such dependencies are instead recorded as `feature_only_candidates`, kept
//! as evidence for a future detector or a human to look at.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{ItemUse, UseTree};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::{CrateInfo, DependencyKind, Workspace};

/// Rule id used for misplaced-dependency-kind findings (see todo.md §3.B).
pub const MISPLACED_DEPENDENCY_KIND_RULE: &str = "misplaced-dependency-kind";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const MISPLACED_DEPENDENCY_KIND_RULE_REVISION: u32 = 1;

/// Rule id used for unused-dev-dependency findings (see todo.md §B).
pub const UNUSED_DEV_DEPENDENCY_RULE: &str = "unused-dev-dependency";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const UNUSED_DEV_DEPENDENCY_RULE_REVISION: u32 = 1;

/// Rule id used for heavy-dependency findings (see todo.md §B).
pub const HEAVY_DEPENDENCY_RULE: &str = "heavy-dependency";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const HEAVY_DEPENDENCY_RULE_REVISION: u32 = 1;

/// Above this many transitive dependencies (from a full, non `--no-deps`
/// resolve — see `resolve_transitive_dependency_counts`), combined with
/// fewer than [`HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD`] distinct items used
/// from it, a dependency is flagged as heavy for its usage footprint (see
/// `is_heavy_dependency`).
const HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD: usize = 20;
/// See [`HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD`].
const HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD: usize = 3;

/// Above this many declared features, judge doesn't assert that a `normal`
/// dependency used only in `Dev`-domain files should move to
/// `dev-dependencies`: a longer feature list is itself weak evidence that the
/// dependency does more than identifier scanning can see (the same concern
/// that motivates the feature-only-evidence bucket for zero-usage
/// dependencies, just short of zero usage here).
const SHORT_FEATURE_LIST_MAX: usize = 1;

/// Where a source file sits, classified purely by path convention relative
/// to its crate root (Fast Tier, directory-convention heuristic — not exact
/// module-graph resolution, see todo.md §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageDomain {
    Normal,
    Dev,
    Build,
}

/// Classifies `relative` (a source file path relative to its crate root).
fn classify_domain(relative: &Path) -> UsageDomain {
    if relative == Path::new("build.rs") {
        return UsageDomain::Build;
    }
    let is_dev_dir = matches!(
        relative.components().next(),
        Some(std::path::Component::Normal(name))
            if name == "tests" || name == "examples" || name == "benches"
    );
    if is_dev_dir {
        UsageDomain::Dev
    } else {
        UsageDomain::Normal
    }
}

#[derive(Debug)]
pub enum DepsError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    /// A full (non `--no-deps`) `cargo metadata` resolve failed — only
    /// produced by `heavy-dependency`'s transitive-count lookup (see
    /// `resolve_transitive_dependency_counts`).
    Metadata(cargo_metadata::Error),
}

impl std::fmt::Display for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Metadata(err) => write!(f, "failed to resolve full dependency graph: {err}"),
        }
    }
}

impl std::error::Error for DepsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
            Self::Metadata(err) => Some(err),
        }
    }
}

/// Aggregated dependency-hygiene results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceDeps {
    pub findings: Vec<Finding>,
    /// Dependencies with zero identifier usages found anywhere, but a
    /// non-empty `features` list — kept as evidence rather than asserted as
    /// findings (see module docs "Feature-only evidence").
    pub feature_only_candidates: Vec<String>,
    pub errors: Vec<DepsError>,
}

/// Runs the `misplaced-dependency-kind` detector over every crate in
/// `workspace`.
///
/// Unlike [`crate::complexity::analyze_workspace`] and
/// [`crate::duplication::analyze_workspace`], which take a flat iterator of
/// `&SourceFile`, this detector needs a crate's declared dependencies *and*
/// its source files together to correlate usage — it is fundamentally
/// per-crate. Flattening to a cross-crate iterator of source files first
/// would throw away exactly the grouping this rule depends on, so this takes
/// the whole [`Workspace`] instead.
pub fn analyze_workspace(workspace: &Workspace) -> WorkspaceDeps {
    let mut findings = Vec::new();
    let mut feature_only_candidates = Vec::new();
    let mut errors = Vec::new();

    for krate in &workspace.crates {
        let (usage, failed_domains, crate_errors) = collect_crate_usage(krate);
        errors.extend(crate_errors);

        for dep in &krate.dependencies {
            let domains = usage.get(&dep.code_identifier);
            let has_normal = domains.is_some_and(|d| d.contains(&UsageDomain::Normal));
            let has_dev = domains.is_some_and(|d| d.contains(&UsageDomain::Dev));
            let has_build = domains.is_some_and(|d| d.contains(&UsageDomain::Build));
            let used_anywhere = domains.is_some_and(|d| !d.is_empty());

            if !used_anywhere && !dep.features.is_empty() && failed_domains.is_empty() {
                feature_only_candidates.push(dep.name.clone());
                continue;
            }

            if dep.kind == DependencyKind::Development
                && !has_dev
                && failed_domains.is_empty()
                && !krate.dependencies.iter().any(|other| {
                    other.name == dep.name && other.kind != DependencyKind::Development
                })
            {
                findings.push(unused_dev_dependency_finding(krate, dep));
            }

            let flagged = match dep.kind {
                DependencyKind::Normal => {
                    has_dev
                        && !has_normal
                        && dep.features.len() <= SHORT_FEATURE_LIST_MAX
                        && !failed_domains.contains(&UsageDomain::Normal)
                }
                DependencyKind::Build => {
                    !has_build && !failed_domains.contains(&UsageDomain::Build)
                }
                DependencyKind::Development => false,
            };

            if flagged {
                findings.push(misplaced_finding(krate, dep));
            }
        }
    }

    let (heavy_findings, heavy_errors) = analyze_heavy_dependencies(workspace);
    findings.extend(heavy_findings);
    errors.extend(heavy_errors);

    WorkspaceDeps {
        findings,
        feature_only_candidates,
        errors,
    }
}

/// Renders a misplaced-dependency-kind finding. Its evidence class is
/// `heuristic` (todo.md §17.3: a wrong dependency kind is an
/// interpretation): usage-domain classification is a directory-convention
/// heuristic, not full module-graph resolution (see todo.md §2.1), so this
/// is suggestive rather than proven. `location.file` is the crate's manifest
/// path — the "location" of a dependency-kind mismatch is `Cargo.toml`, not
/// a source file — and `location.item_path` is the dependency name.
fn misplaced_finding(krate: &CrateInfo, dep: &crate::ingest::DeclaredDependency) -> Finding {
    Finding {
        id: format!(
            "{MISPLACED_DEPENDENCY_KIND_RULE}:{}:{}",
            krate.name, dep.name
        )
        .into(),
        rule: MISPLACED_DEPENDENCY_KIND_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Renders an `unused-dev-dependency` finding. Its evidence class is
/// `bounded_semantic` (todo.md §17.3: "no reference found ... for the
/// searched crates/entry points") — the search is bounded to `Dev`-domain
/// files (`tests/`, `examples/`, `benches/`) and `#[cfg(test)]` modules in
/// `Normal`-domain files, and doctests are never scanned (a known gap). The
/// message and severity stay honest about that bound: `Warn`, "no use found
/// in the examined view", never an absolute "unused" claim (todo.md §17
/// language discipline). Same `location` convention as [`misplaced_finding`].
fn unused_dev_dependency_finding(
    krate: &CrateInfo,
    dep: &crate::ingest::DeclaredDependency,
) -> Finding {
    Finding {
        id: format!("{UNUSED_DEV_DEPENDENCY_RULE}:{}:{}", krate.name, dep.name).into(),
        rule: UNUSED_DEV_DEPENDENCY_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "searched": ["tests/", "examples/", "benches/", "#[cfg(test)] modules in src/"],
            "reason": "no use found in the examined view (tests/examples/benches of this \
                package, and #[cfg(test)] modules in its src files; doctests are not scanned)",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Whether a dependency counts as heavy: more than
/// [`HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD`] transitive dependencies while
/// fewer than [`HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD`] distinct items are
/// used from it. Pure and side-effect free so the threshold logic is
/// unit-testable without a `cargo metadata` resolve.
fn is_heavy_dependency(transitive_deps: usize, used_items: usize) -> bool {
    transitive_deps > HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD
        && used_items < HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD
}

/// Runs the `heavy-dependency` detector (todo.md §B) over every crate in
/// `workspace`. Always `heuristic` (todo.md §17.3, `evidence_class_for_rule`'s
/// catch-all — no explicit arm for this rule): the transitive count depends
/// on feature unification and platform/target resolution this Fast Tier pass
/// doesn't fully model, and "used items" is a path-segment approximation
/// (see [`collect_used_items`]), not resolved item usage.
fn analyze_heavy_dependencies(workspace: &Workspace) -> (Vec<Finding>, Vec<DepsError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let manifest_path = workspace.root.join("Cargo.toml");
    let counts = match resolve_transitive_dependency_counts(&manifest_path) {
        Ok(counts) => counts,
        Err(err) => {
            errors.push(DepsError::Metadata(err));
            return (findings, errors);
        }
    };

    for krate in &workspace.crates {
        for dep in &krate.dependencies {
            let Some(&transitive_deps) = counts.get(&dep.name) else {
                continue;
            };
            let used_items = collect_used_items(krate, &dep.code_identifier);
            if is_heavy_dependency(transitive_deps, used_items.len()) {
                findings.push(heavy_dependency_finding(
                    krate,
                    dep,
                    transitive_deps,
                    &used_items,
                ));
            }
        }
    }

    (findings, errors)
}

/// Renders a `heavy-dependency` finding. Same `location` convention as
/// [`misplaced_finding`]; `evidence.examples` is a small, sorted sample of
/// the distinct used-item names, for a human to sanity-check the count.
fn heavy_dependency_finding(
    krate: &CrateInfo,
    dep: &crate::ingest::DeclaredDependency,
    transitive_deps: usize,
    used_items: &HashSet<String>,
) -> Finding {
    let mut examples: Vec<&String> = used_items.iter().collect();
    examples.sort();
    examples.truncate(5);

    Finding {
        id: format!("{HEAVY_DEPENDENCY_RULE}:{}:{}", krate.name, dep.name).into(),
        rule: HEAVY_DEPENDENCY_RULE.into(),
        severity: Severity::Info,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "transitive_deps": transitive_deps,
            "used_items": used_items.len(),
            "examples": examples,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Runs a full (non `--no-deps`) `cargo metadata` resolve to compute how many
/// transitive dependencies each package in the graph pulls in — needed for
/// `heavy-dependency`, which [`crate::ingest::load`]'s deliberately
/// `--no-deps` ingest (todo.md §14.2 P1) cannot answer. Runs its own metadata
/// command rather than reusing another module's resolve: a parallel
/// `dep_graph.rs` effort resolves a full graph too, for its own manifest/graph
/// rules; consolidating the two runs into one is left as follow-up work.
fn resolve_transitive_dependency_counts(
    manifest_path: &Path,
) -> Result<HashMap<String, usize>, cargo_metadata::Error> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(manifest_path)
        .exec()?;
    let Some(resolve) = metadata.resolve else {
        return Ok(HashMap::new());
    };

    let adjacency: HashMap<&cargo_metadata::PackageId, &[cargo_metadata::PackageId]> = resolve
        .nodes
        .iter()
        .map(|node| (&node.id, node.dependencies.as_slice()))
        .collect();
    let id_to_name: HashMap<&cargo_metadata::PackageId, String> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package.name.to_string()))
        .collect();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for node in &resolve.nodes {
        let mut visited: HashSet<&cargo_metadata::PackageId> = HashSet::new();
        let mut stack: Vec<&cargo_metadata::PackageId> = node.dependencies.iter().collect();
        while let Some(dep_id) = stack.pop() {
            if visited.insert(dep_id)
                && let Some(children) = adjacency.get(dep_id)
            {
                stack.extend(children.iter());
            }
        }
        if let Some(name) = id_to_name.get(&node.id) {
            counts.entry(name.clone()).or_insert(visited.len());
        }
    }
    Ok(counts)
}

/// Distinct next-level path segments referenced under `target` (a
/// dependency's `code_identifier`) across every source file in `krate`,
/// regardless of usage domain — `heavy-dependency` cares about total usage
/// footprint, not where it is used. `use dep::{Foo, bar::Baz}` records `Foo`
/// and `bar`; `dep::foo::bar()` records `foo`. An approximation of "how many
/// distinct items of this dependency does the crate use", not exact item
/// resolution. Files that fail to read or parse are silently skipped: this is
/// advisory (`heuristic`) evidence, not a completeness claim like
/// `unused-dev-dependency`'s.
fn collect_used_items(krate: &CrateInfo, target: &str) -> HashSet<String> {
    let mut items = HashSet::new();
    for file in &krate.source_files {
        let Ok(source) = std::fs::read_to_string(&file.path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&source) else {
            continue;
        };
        let mut collector = DepItemCollector {
            target,
            items: HashSet::new(),
        };
        collector.visit_file(&ast);
        items.extend(collector.items);
    }
    items
}

struct DepItemCollector<'a> {
    target: &'a str,
    items: HashSet<String>,
}

impl DepItemCollector<'_> {
    /// Mirrors [`PathIdentCollector::walk_use_tree`]'s hand-rolled walk (`use`
    /// trees have no `syn::Path` node), but one level deeper: `matched` tracks
    /// whether the segment just consumed was `target`, so the *next* segment
    /// is the item to record.
    fn walk_use_tree(&mut self, tree: &UseTree, matched: bool) {
        match tree {
            UseTree::Path(use_path) => {
                let ident = use_path.ident.to_string();
                if matched {
                    self.items.insert(ident);
                    self.walk_use_tree(&use_path.tree, false);
                } else {
                    self.walk_use_tree(&use_path.tree, ident == self.target);
                }
            }
            UseTree::Name(use_name) => {
                if matched {
                    self.items.insert(use_name.ident.to_string());
                }
            }
            UseTree::Rename(use_rename) => {
                if matched {
                    self.items.insert(use_rename.ident.to_string());
                }
            }
            UseTree::Glob(_) => {}
            UseTree::Group(group) => {
                for item in &group.items {
                    self.walk_use_tree(item, matched);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for DepItemCollector<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.walk_use_tree(&node.tree, false);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.len() >= 2 && node.segments[0].ident == self.target {
            self.items.insert(node.segments[1].ident.to_string());
        }
        visit::visit_path(self, node);
    }
}

/// Builds the `code_identifier -> domains observed` map for one crate, by
/// classifying each source file's domain and parsing it for referenced path
/// identifiers.
fn collect_crate_usage(
    krate: &CrateInfo,
) -> (
    HashMap<String, HashSet<UsageDomain>>,
    HashSet<UsageDomain>,
    Vec<DepsError>,
) {
    let mut usage: HashMap<String, HashSet<UsageDomain>> = HashMap::new();
    let mut failed_domains = HashSet::new();
    let mut errors = Vec::new();

    for file in &krate.source_files {
        let relative = file
            .path
            .strip_prefix(&krate.root)
            .unwrap_or(file.path.as_path());
        let domain = classify_domain(relative);

        match collect_identifiers(&file.path) {
            Ok((idents, cfg_test_idents)) => {
                for ident in idents {
                    usage.entry(ident).or_default().insert(domain);
                }
                // A `#[cfg(test)]` module in an otherwise `Normal`-domain
                // file (e.g. `mod tests` at the bottom of `src/lib.rs`) is
                // Dev-domain usage in spirit, even though the file it lives
                // in isn't — see `unused-dev-dependency` (todo.md §B). This
                // is additive: identifiers found there already counted
                // towards the file's own domain above (whole-file
                // classification is unchanged); this just also credits
                // `Dev`.
                for ident in cfg_test_idents {
                    usage.entry(ident).or_default().insert(UsageDomain::Dev);
                }
            }
            Err(err) => {
                failed_domains.insert(domain);
                errors.push(err);
            }
        }
    }

    (usage, failed_domains, errors)
}

/// Parses `path` and collects two identifier sets from a single parse: the
/// first-segment identifier of every referenced path — `use` trees,
/// expression paths, type paths, and macro-invocation paths — that isn't
/// `self`/`super`/`crate`/`Self` (each such identifier is a candidate
/// reference to an external crate's `code_identifier`); and the same, scoped
/// to identifiers referenced only inside `#[cfg(test)]`-attributed modules
/// (see [`CfgTestIdentCollector`]).
fn collect_identifiers(path: &Path) -> Result<(HashSet<String>, HashSet<String>), DepsError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| DepsError::Io(path.to_path_buf(), err))?;
    let ast = syn::parse_file(&source).map_err(|err| DepsError::Parse(path.to_path_buf(), err))?;

    let mut collector = PathIdentCollector::default();
    collector.visit_file(&ast);

    let mut cfg_test_collector = CfgTestIdentCollector::default();
    cfg_test_collector.visit_file(&ast);

    Ok((collector.idents, cfg_test_collector.idents))
}

/// Whether `attrs` contains a `#[cfg(...)]` attribute whose predicate
/// mentions `test` as a whole word (`#[cfg(test)]`, `#[cfg(any(test, ...))]`,
/// `#[cfg(all(test, ...))]`) — a crude but conservative parse of the
/// attribute's raw tokens, not a full `cfg` predicate evaluator.
fn attrs_have_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.tokens
            .to_string()
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|word| word == "test")
    })
}

/// Collects identifiers referenced inside `#[cfg(test)]`-attributed modules
/// (see [`attrs_have_cfg_test`]) — the common `#[cfg(test)] mod tests { ... }`
/// pattern in an otherwise non-test source file. Deliberately narrower than
/// "any cfg(test)-gated item": individual `#[cfg(test)] fn`s outside such a
/// module aren't recognized, matching todo.md §B's scope ("`#[cfg(test)]`-
/// Module in normalen src-Dateien zählen als Dev-Nutzung").
#[derive(Default)]
struct CfgTestIdentCollector {
    idents: HashSet<String>,
}

impl<'ast> Visit<'ast> for CfgTestIdentCollector {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attrs_have_cfg_test(&node.attrs) {
            let mut inner = PathIdentCollector::default();
            inner.visit_item_mod(node);
            self.idents.extend(inner.idents);
        } else {
            visit::visit_item_mod(self, node);
        }
    }
}

#[derive(Default)]
struct PathIdentCollector {
    idents: HashSet<String>,
}

impl PathIdentCollector {
    fn record(&mut self, ident: &str) {
        if !matches!(ident, "self" | "super" | "crate" | "Self") {
            self.idents.insert(ident.to_string());
        }
    }

    /// `UseTree` doesn't contain `syn::Path` nodes, so `visit_path` never
    /// sees `use` items — walk the tree by hand instead, recording only the
    /// first segment of each `Path`/`Name`/`Rename` chain (the rest of the
    /// tree doesn't add new *external* identifiers to record).
    fn walk_use_tree(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(use_path) => self.record(&use_path.ident.to_string()),
            UseTree::Name(use_name) => self.record(&use_name.ident.to_string()),
            UseTree::Rename(use_rename) => self.record(&use_rename.ident.to_string()),
            UseTree::Glob(_) => {}
            UseTree::Group(group) => {
                for item in &group.items {
                    self.walk_use_tree(item);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for PathIdentCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.walk_use_tree(&node.tree);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if let Some(first) = node.segments.first() {
            self.record(&first.ident.to_string());
        }
        visit::visit_path(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    /// Writes a two-crate fixture: `main` depends on a path dependency named
    /// `dep_crate_name` (or a renamed alias, if `rename` is given), declared
    /// in `dependency_section` (e.g. `"[dependencies]"` or
    /// `"[build-dependencies]"`). Path dependencies keep these tests fully
    /// offline — no registry/network access needed (verified against a real
    /// `cargo metadata --no-deps` run).
    fn write_fixture(
        dir: &TempDir,
        dependency_section: &str,
        dep_crate_name: &str,
        rename: Option<&str>,
        features: &[&str],
        main_files: &[(&str, &str)],
    ) -> PathBuf {
        std::fs::create_dir_all(dir.join("main/src")).unwrap();
        std::fs::create_dir_all(dir.join("dep_crate/src")).unwrap();

        let dep_line = match rename {
            Some(alias) => format!(
                "{alias} = {{ package = \"{dep_crate_name}\", path = \"../dep_crate\"{} }}",
                features_toml(features)
            ),
            None => format!(
                "{dep_crate_name} = {{ path = \"../dep_crate\"{} }}",
                features_toml(features)
            ),
        };
        std::fs::write(
            dir.join("main/Cargo.toml"),
            format!(
                r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

{dependency_section}
{dep_line}
"#
            ),
        )
        .unwrap();
        std::fs::write(dir.join("main/src/lib.rs"), "pub fn hello() {}\n").unwrap();
        for (relative, content) in main_files {
            let file_path = dir.join("main").join(relative);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(file_path, content).unwrap();
        }

        std::fs::write(
            dir.join("dep_crate/Cargo.toml"),
            format!(
                r#"
[package]
name = "{dep_crate_name}"
version = "0.1.0"
edition = "2021"
"#
            ),
        )
        .unwrap();
        std::fs::write(dir.join("dep_crate/src/lib.rs"), "pub fn noop() {}\n").unwrap();

        dir.join("main/Cargo.toml")
    }

    fn features_toml(features: &[&str]) -> String {
        if features.is_empty() {
            String::new()
        } else {
            let joined = features
                .iter()
                .map(|f| format!("\"{f}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!(", features = [{joined}]")
        }
    }

    #[test]
    fn a_normal_dependency_used_only_from_tests_is_flagged_as_dev() {
        let dir = TempDir::new("deps-dev-only");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[("tests/it.rs", "fn t() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].location.item_path, "depcrate");
        assert!(report.feature_only_candidates.is_empty());
    }

    #[test]
    fn a_normal_dependency_used_from_src_and_tests_is_not_flagged() {
        let dir = TempDir::new("deps-src-and-tests");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[
                ("src/lib.rs", "pub fn hello() { depcrate::noop(); }\n"),
                ("tests/it.rs", "fn t() { depcrate::noop(); }\n"),
            ],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_build_dependency_never_referenced_in_build_rs_is_flagged_as_unused() {
        let dir = TempDir::new("deps-build-unused");
        let manifest = write_fixture(
            &dir,
            "[build-dependencies]",
            "depcrate",
            None,
            &[],
            &[("build.rs", "fn main() {}\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].location.item_path, "depcrate");
    }

    #[test]
    fn a_build_dependency_referenced_in_build_rs_is_not_flagged() {
        let dir = TempDir::new("deps-build-used");
        let manifest = write_fixture(
            &dir,
            "[build-dependencies]",
            "depcrate",
            None,
            &[],
            &[("build.rs", "fn main() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_parse_error_in_build_rs_does_not_claim_the_dependency_is_unused() {
        let dir = TempDir::new("deps-build-parse-error");
        let manifest = write_fixture(
            &dir,
            "[build-dependencies]",
            "depcrate",
            None,
            &[],
            &[("build.rs", "fn main( { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert_eq!(report.errors.len(), 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_dependency_with_zero_usage_and_features_is_a_feature_only_candidate() {
        let dir = TempDir::new("deps-feature-only");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &["some-feature"],
            &[],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(report.findings.is_empty());
        assert_eq!(report.feature_only_candidates, vec!["depcrate".to_string()]);
    }

    #[test]
    fn a_renamed_dependency_is_matched_by_its_local_alias() {
        let dir = TempDir::new("deps-renamed");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "real-name",
            Some("some_dep"),
            &[],
            &[("tests/it.rs", "fn t() { some_dep::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        // Matched via `some_dep::`, not `real_name::` — proves code_identifier
        // (the rename) is what's used for matching, not the registry name.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].location.item_path, "real-name");
    }

    #[test]
    fn finding_shape_matches_the_documented_contract() {
        let dir = TempDir::new("deps-finding-shape");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[("tests/it.rs", "fn t() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, MISPLACED_DEPENDENCY_KIND_RULE);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.origin, Origin::Code);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert_eq!(finding.location.file, workspace.crates[0].manifest_path);
    }

    #[test]
    fn classify_domain_recognizes_dev_directories_and_build_rs() {
        assert_eq!(classify_domain(Path::new("build.rs")), UsageDomain::Build);
        assert_eq!(classify_domain(Path::new("tests/it.rs")), UsageDomain::Dev);
        assert_eq!(
            classify_domain(Path::new("examples/demo.rs")),
            UsageDomain::Dev
        );
        assert_eq!(
            classify_domain(Path::new("benches/bench.rs")),
            UsageDomain::Dev
        );
        assert_eq!(
            classify_domain(Path::new("src/lib.rs")),
            UsageDomain::Normal
        );
    }

    #[test]
    fn deps_error_source_preserves_the_underlying_error() {
        let err = DepsError::Io(PathBuf::from("src/lib.rs"), std::io::Error::other("boom"));
        let source = std::error::Error::source(&err).expect("Io must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "src/lib.rs: failed to read file: boom");
    }

    #[test]
    fn a_dev_dependency_used_only_from_tests_is_not_flagged_as_unused() {
        let dir = TempDir::new("deps-dev-used-in-tests");
        let manifest = write_fixture(
            &dir,
            "[dev-dependencies]",
            "depcrate",
            None,
            &[],
            &[("tests/it.rs", "fn t() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_DEV_DEPENDENCY_RULE)
        );
    }

    #[test]
    fn a_dev_dependency_never_used_is_flagged_with_a_hedged_message() {
        let dir = TempDir::new("deps-dev-unused");
        let manifest = write_fixture(&dir, "[dev-dependencies]", "depcrate", None, &[], &[]);

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == UNUSED_DEV_DEPENDENCY_RULE)
            .expect("expected an unused-dev-dependency finding");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(finding.location.item_path, "depcrate");
        let reason = finding.evidence.as_ref().unwrap()["reason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("no use found in the examined view"));
        assert!(!reason.contains("is unused"));
    }

    #[test]
    fn a_dev_dependency_used_only_in_a_cfg_test_module_in_src_is_not_flagged() {
        let dir = TempDir::new("deps-dev-cfg-test");
        let manifest = write_fixture(
            &dir,
            "[dev-dependencies]",
            "depcrate",
            None,
            &[],
            &[(
                "src/lib.rs",
                "pub fn hello() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { depcrate::noop(); }\n}\n",
            )],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_DEV_DEPENDENCY_RULE)
        );
    }

    #[test]
    fn a_dev_dependency_also_declared_as_a_normal_dependency_is_not_flagged() {
        let dir = TempDir::new("deps-dev-also-normal");
        std::fs::create_dir_all(dir.join("main/src")).unwrap();
        std::fs::create_dir_all(dir.join("dep_crate/src")).unwrap();
        std::fs::write(
            dir.join("main/Cargo.toml"),
            r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
depcrate = { path = "../dep_crate" }

[dev-dependencies]
depcrate = { path = "../dep_crate" }
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main/src/lib.rs"),
            "pub fn hello() { depcrate::noop(); }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("dep_crate/Cargo.toml"),
            r#"
[package]
name = "depcrate"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::write(dir.join("dep_crate/src/lib.rs"), "pub fn noop() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("main/Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_DEV_DEPENDENCY_RULE)
        );
    }

    #[test]
    fn collect_used_items_records_next_level_path_segments() {
        let dir = TempDir::new("deps-used-items");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let file_path = dir.join("src/lib.rs");
        std::fs::write(
            &file_path,
            "use depcrate::{Foo, bar::Baz};\nfn use_it() { depcrate::other::thing(); }\n",
        )
        .unwrap();

        let krate = CrateInfo {
            name: "fixture".to_string(),
            version: "0.1.0".to_string(),
            manifest_path: dir.join("Cargo.toml"),
            root: dir.to_path_buf(),
            source_files: vec![crate::ingest::SourceFile {
                path: file_path,
                kind: crate::ingest::SourceKind::Authored,
            }],
            entry_points: Vec::new(),
            dependencies: Vec::new(),
        };

        let mut items: Vec<String> = collect_used_items(&krate, "depcrate").into_iter().collect();
        items.sort();
        assert_eq!(items, vec!["Foo", "bar", "other"]);
    }

    #[test]
    fn is_heavy_dependency_requires_both_thresholds_to_be_crossed() {
        assert!(!is_heavy_dependency(
            HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD,
            0
        ));
        assert!(!is_heavy_dependency(
            HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD + 1,
            HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD
        ));
        assert!(is_heavy_dependency(
            HEAVY_DEPENDENCY_TRANSITIVE_THRESHOLD + 1,
            HEAVY_DEPENDENCY_USED_ITEMS_THRESHOLD - 1
        ));
    }

    #[test]
    fn heavy_dependency_finding_is_advisory_only() {
        let krate = CrateInfo {
            name: "fixture".to_string(),
            version: "0.1.0".to_string(),
            manifest_path: PathBuf::from("fixture/Cargo.toml"),
            root: PathBuf::from("fixture"),
            source_files: Vec::new(),
            entry_points: Vec::new(),
            dependencies: Vec::new(),
        };
        let dep = crate::ingest::DeclaredDependency {
            name: "heavy_crate".to_string(),
            kind: DependencyKind::Normal,
            code_identifier: "heavy_crate".to_string(),
            target: None,
            features: Vec::new(),
            version_req: "*".to_string(),
        };
        let used_items: HashSet<String> = HashSet::new();
        let finding = heavy_dependency_finding(&krate, &dep, 42, &used_items);

        assert_eq!(finding.rule, HEAVY_DEPENDENCY_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert!(!finding.is_gating());
        assert_eq!(finding.evidence.unwrap()["transitive_deps"], 42);
    }
}
