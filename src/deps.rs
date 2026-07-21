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
//! `dep-without-repo` (todo.md §F) shares `heavy-dependency`'s single full
//! (non `--no-deps`) `cargo_metadata` resolve (see [`resolve_full_metadata`],
//! [`analyze_full_metadata_dependencies`]) rather than resolving again: it
//! flags a declared dependency whose own manifest has no (or an empty)
//! `repository` field. A missing `repository` field is not itself a defect —
//! private/internal crates legitimately omit it — so this is reported as
//! `Severity::Info`, the same hygiene-signal precedent as `heavy-dependency`.
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
//! Such dependencies are still recorded in `feature_only_candidates`, and
//! also drive two further findings built on that same zero-usage evidence
//! (todo.md §B) — never on knowledge of a specific dependency's feature
//! vocabulary:
//!
//! - **`unused-feature-flag`**: one finding per declared feature name, for a
//!   dependency with zero usage found anywhere (the case above). Deliberately
//!   does *not* cover prominent "bundle" features with a well-known naming
//!   convention (e.g. `tokio = { features = ["full"] }`), even when the
//!   dependency itself *is* used — recognizing those needs a hardcoded
//!   feature vocabulary per dependency, which judge does not maintain.
//! - **`default-features-unused`**: a dependency whose manifest entry
//!   explicitly sets `default-features = true` — the raw TOML text says so
//!   (see [`manifest_explicitly_enables_default_features`]), not just
//!   Cargo's own implicit default — and that has the same zero-usage
//!   evidence as above. Deliberately does *not* cover "used, but only
//!   non-default features": telling default from non-default items apart
//!   needs per-dependency feature-to-symbol knowledge judge does not have.
//!
//! ## Importing rustc's `unused_crate_dependencies` lint
//!
//! [`analyze_rustc_unused_dependencies`] runs `cargo check --workspace
//! --all-targets` with rustc's stable, allow-by-default
//! `unused_crate_dependencies` lint turned on (`-W unused_crate_dependencies`
//! — a stable rustc lint, not nightly-only; do not confuse it with Cargo's
//! separate, narrower, nightly-only `unused_workspace_dependencies` lint,
//! which only checks `[workspace.dependencies]` inheritance). It is opt-in
//! (`cargo judge deps --check-rustc-lints`) — a full `cargo check` is a
//! different order of cost than the rest of this module's instant syntactic
//! passes, so it never runs as part of [`analyze_workspace`], bare `cargo
//! judge`/`audit`, or `cargo judge deps` without the flag.
//!
//! The raw lint runs once per compiled unit (Cargo target: `lib`, each
//! `[[test]]`/`[[example]]`/`[[bench]]`, ...), each with its own `--extern`
//! set, and is documented to false-positive on multi-target packages: a
//! dependency used only by one target (e.g. a normal dependency referenced
//! solely from an integration test) is reported "unused" by every *other*
//! target's compilation. judge closes that gap by only turning a dependency
//! into a finding when it is reported unused in *every* target compiled for
//! its package — the intersection over all target runs, never a union (see
//! [`analyze_rustc_unused_dependencies`]). Restricted to `normal`
//! dependencies: `dev`/`build` dependencies are out of scope here
//! (`dev-dependencies` already has its own `unused-dev-dependency` detector
//! above, built on judge's own usage scan rather than an imported lint).

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

/// Rule id used for unused-feature-flag findings (see todo.md §B, module
/// docs "Feature-only evidence").
pub const UNUSED_FEATURE_FLAG_RULE: &str = "unused-feature-flag";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const UNUSED_FEATURE_FLAG_RULE_REVISION: u32 = 1;

/// Rule id used for default-features-unused findings (see todo.md §B, module
/// docs "Feature-only evidence").
pub const DEFAULT_FEATURES_UNUSED_RULE: &str = "default-features-unused";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const DEFAULT_FEATURES_UNUSED_RULE_REVISION: u32 = 1;

/// Rule id used for unused-dependency findings — imports rustc's stable
/// `unused_crate_dependencies` lint (see module docs "Importing rustc's
/// `unused_crate_dependencies` lint", todo.md §B).
pub const UNUSED_DEPENDENCY_RULE: &str = "unused-dependency";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const UNUSED_DEPENDENCY_RULE_REVISION: u32 = 1;

/// Rule id used for dep-without-repo findings (see todo.md §F): a dependency
/// whose own manifest declares no `repository` field, read from the same
/// full `cargo_metadata` resolve as `heavy-dependency` (see
/// [`resolve_full_metadata`]).
pub const DEP_WITHOUT_REPO_RULE: &str = "dep-without-repo";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const DEP_WITHOUT_REPO_RULE_REVISION: u32 = 1;

/// Above this many transitive dependencies (from a full, non `--no-deps`
/// resolve — see [`resolve_full_metadata`]), combined with
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
    /// produced by `heavy-dependency`'s transitive-count lookup and
    /// `dep-without-repo`'s repository-field lookup, which share one resolve
    /// (see [`resolve_full_metadata`]).
    Metadata(cargo_metadata::Error),
    /// A crate's manifest failed to parse as TOML — only produced by
    /// `default-features-unused`'s manifest lookup (see
    /// `manifest_explicitly_enables_default_features`), which reads the raw
    /// manifest text directly rather than trusting `cargo_metadata`.
    ManifestParse(PathBuf, toml::de::Error),
    /// The `cargo check` run behind `unused-dependency`'s rustc-lint import
    /// (see [`analyze_rustc_unused_dependencies`]) did not complete: either
    /// the `cargo` binary failed to spawn, or `cargo check --workspace
    /// --all-targets` exited unsuccessfully (e.g. the workspace does not
    /// currently compile). Collected as a report error, never a panic or a
    /// finding — judge cannot assert anything about dependency usage from a
    /// build it could not observe (todo.md §B "Graceful Degradation").
    RustcCheck(String),
}

impl std::fmt::Display for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Metadata(err) => write!(f, "failed to resolve full dependency graph: {err}"),
            Self::ManifestParse(path, err) => {
                write!(f, "{}: failed to parse: {err}", path.display())
            }
            Self::RustcCheck(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DepsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
            Self::Metadata(err) => Some(err),
            Self::ManifestParse(_, err) => Some(err),
            Self::RustcCheck(_) => None,
        }
    }
}

/// Aggregated dependency-hygiene results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceDeps {
    pub findings: Vec<Finding>,
    /// Dependencies with zero identifier usages found anywhere, but a
    /// non-empty `features` list (see module docs "Feature-only evidence").
    /// Kept alongside the `unused-feature-flag` findings derived from the
    /// same evidence, for a human to skim the affected dependency names at a
    /// glance.
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
        let manifest = read_manifest_toml(&krate.manifest_path, &mut errors);

        for dep in &krate.dependencies {
            let domains = usage.get(&dep.code_identifier);
            let has_normal = domains.is_some_and(|d| d.contains(&UsageDomain::Normal));
            let has_dev = domains.is_some_and(|d| d.contains(&UsageDomain::Dev));
            let has_build = domains.is_some_and(|d| d.contains(&UsageDomain::Build));
            let used_anywhere = domains.is_some_and(|d| !d.is_empty());
            let zero_usage = !used_anywhere && failed_domains.is_empty();

            if zero_usage && !dep.features.is_empty() {
                feature_only_candidates.push(dep.name.clone());
                findings.extend(unused_feature_flag_findings(krate, dep));
            }

            if zero_usage
                && manifest.as_ref().is_some_and(|manifest| {
                    manifest_explicitly_enables_default_features(manifest, &dep.name)
                })
            {
                findings.push(default_features_unused_finding(krate, dep));
            }

            if zero_usage && !dep.features.is_empty() {
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

    let (metadata_findings, metadata_errors) = analyze_full_metadata_dependencies(workspace);
    findings.extend(metadata_findings);
    errors.extend(metadata_errors);

    WorkspaceDeps {
        findings,
        feature_only_candidates,
        errors,
    }
}

/// Reads and parses `manifest_path` as TOML, once per crate — needed only by
/// `default-features-unused`'s manifest lookup (see
/// [`manifest_explicitly_enables_default_features`]): `cargo_metadata`'s
/// resolved `Dependency` doesn't distinguish an explicit `default-features =
/// true` from Cargo's own implicit default, so that rule reads the manifest
/// text directly instead. A read or parse failure is pushed to `errors` and
/// `None` is returned — the rule is then silently skipped for this crate
/// rather than asserting an unbacked claim.
fn read_manifest_toml(manifest_path: &Path, errors: &mut Vec<DepsError>) -> Option<toml::Value> {
    let text = match std::fs::read_to_string(manifest_path) {
        Ok(text) => text,
        Err(err) => {
            errors.push(DepsError::Io(manifest_path.to_path_buf(), err));
            return None;
        }
    };
    match toml::from_str(&text) {
        Ok(manifest) => Some(manifest),
        Err(err) => {
            errors.push(DepsError::ManifestParse(manifest_path.to_path_buf(), err));
            None
        }
    }
}

/// Whether `manifest`'s raw TOML text explicitly sets `default-features =
/// true` for the dependency named `dep_name`, in `[dependencies]`,
/// `[dev-dependencies]`, `[build-dependencies]`, or their per-platform
/// `[target.'cfg(...)'.*]` equivalents. Deliberately reads the manifest text
/// rather than `cargo_metadata::Dependency::uses_default_features`: that
/// field is `true` both when the manifest says so explicitly and when the
/// key is simply absent (Cargo's own default), and only the manifest text
/// itself can tell those two apart (see module docs "Feature-only
/// evidence").
fn manifest_explicitly_enables_default_features(manifest: &toml::Value, dep_name: &str) -> bool {
    const DEPENDENCY_TABLE_KEYS: [&str; 3] =
        ["dependencies", "dev-dependencies", "build-dependencies"];

    fn table_sets_default_features_true(table: &toml::Value, dep_name: &str) -> bool {
        table
            .get(dep_name)
            .and_then(|dep| dep.get("default-features"))
            .and_then(toml::Value::as_bool)
            == Some(true)
    }

    let found_at_top_level = DEPENDENCY_TABLE_KEYS.iter().any(|key| {
        manifest
            .get(key)
            .is_some_and(|table| table_sets_default_features_true(table, dep_name))
    });
    if found_at_top_level {
        return true;
    }

    manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|platforms| {
            platforms.values().any(|platform| {
                DEPENDENCY_TABLE_KEYS.iter().any(|key| {
                    platform
                        .get(key)
                        .is_some_and(|table| table_sets_default_features_true(table, dep_name))
                })
            })
        })
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

/// Renders one `unused-feature-flag` finding per feature name declared by
/// `dep`, for a dependency with zero identifier usages found anywhere (see
/// module docs "Feature-only evidence") — the only feature-related claim
/// judge can back without knowing what a feature enables: that the feature
/// is turned on for a dependency nothing in the examined view references at
/// all. Its evidence class is `derived_fact`: both halves of the claim (the
/// feature is declared; no usage was found) are read directly from the
/// declared inputs. Same `location` convention as [`misplaced_finding`].
fn unused_feature_flag_findings(
    krate: &CrateInfo,
    dep: &crate::ingest::DeclaredDependency,
) -> Vec<Finding> {
    dep.features
        .iter()
        .map(|feature| Finding {
            id: format!(
                "{UNUSED_FEATURE_FLAG_RULE}:{}:{}:{feature}",
                krate.name, dep.name
            )
            .into(),
            rule: UNUSED_FEATURE_FLAG_RULE.into(),
            severity: Severity::Warn,
            location: Location {
                file: krate.manifest_path.clone(),
                line: OneBasedLine::FIRST,
                item_path: dep.name.clone(),
            },
            evidence_class: EvidenceClass::DerivedFact,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "feature": feature,
                "reason": "no other usage of this dependency was found in the examined view",
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
        .collect()
}

/// Renders a `default-features-unused` finding: `dep`'s manifest entry
/// explicitly sets `default-features = true` (see
/// [`manifest_explicitly_enables_default_features`]) and has zero identifier
/// usages found anywhere (see module docs "Feature-only evidence"). Its
/// evidence class is `derived_fact` for the same reason as
/// [`unused_feature_flag_findings`]: both halves are read directly from the
/// declared inputs, not interpreted. Same `location` convention as
/// [`misplaced_finding`].
fn default_features_unused_finding(
    krate: &CrateInfo,
    dep: &crate::ingest::DeclaredDependency,
) -> Finding {
    Finding {
        id: format!("{DEFAULT_FEATURES_UNUSED_RULE}:{}:{}", krate.name, dep.name).into(),
        rule: DEFAULT_FEATURES_UNUSED_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::DerivedFact,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "reason": "no other usage of this dependency was found in the examined view, and \
                the manifest explicitly sets default-features = true",
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

/// Runs both `heavy-dependency` and `dep-without-repo` (todo.md §B, §F) over
/// every crate in `workspace`, sharing the single full (non `--no-deps`)
/// `cargo metadata` resolve both need (see [`resolve_full_metadata`]) rather
/// than running it twice. `heavy-dependency` is always `heuristic` (todo.md
/// §17.3, `evidence_class_for_rule`'s catch-all — no explicit arm for this
/// rule): the transitive count depends on feature unification and
/// platform/target resolution this Fast Tier pass doesn't fully model, and
/// "used items" is a path-segment approximation (see [`collect_used_items`]),
/// not resolved item usage. `dep-without-repo` is `derived_fact`: the
/// dependency's own `repository` field is read directly from the resolve.
fn analyze_full_metadata_dependencies(workspace: &Workspace) -> (Vec<Finding>, Vec<DepsError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let manifest_path = workspace.root.join("Cargo.toml");
    let metadata = match resolve_full_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(err) => {
            errors.push(DepsError::Metadata(err));
            return (findings, errors);
        }
    };

    for krate in &workspace.crates {
        for dep in &krate.dependencies {
            if let Some(&transitive_deps) = metadata.transitive_deps.get(&dep.name) {
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

            if let Some(repository) = metadata.repository.get(&dep.name)
                && repository_is_missing(repository)
            {
                findings.push(dep_without_repo_finding(krate, dep));
            }
        }
    }

    (findings, errors)
}

/// Whether a dependency's own `repository` field counts as missing for
/// `dep-without-repo`: either the manifest omits the field entirely
/// (`None`), or it is present but blank.
fn repository_is_missing(repository: &Option<String>) -> bool {
    match repository {
        None => true,
        Some(text) => text.trim().is_empty(),
    }
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

/// Renders a `dep-without-repo` finding (todo.md §F). `Severity::Info`,
/// mirroring `heavy-dependency`'s hygiene-signal precedent above: a missing
/// `repository` field is not inherently a defect — private/internal crates
/// legitimately omit it. Same `location` convention as [`misplaced_finding`].
fn dep_without_repo_finding(krate: &CrateInfo, dep: &crate::ingest::DeclaredDependency) -> Finding {
    Finding {
        id: format!("{DEP_WITHOUT_REPO_RULE}:{}:{}", krate.name, dep.name).into(),
        rule: DEP_WITHOUT_REPO_RULE.into(),
        severity: Severity::Info,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::DerivedFact,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "reason": "no `repository` field found in this dependency's own manifest",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Package metadata read from a single full (non `--no-deps`)
/// `cargo_metadata` resolve, shared by [`analyze_full_metadata_dependencies`]
/// — needed for `heavy-dependency`/`dep-without-repo`, which
/// [`crate::ingest::load`]'s deliberately `--no-deps` ingest (todo.md §14.2
/// P1) cannot answer either half of.
#[derive(Debug, Default)]
struct FullMetadataResolve {
    /// Package name -> count of distinct transitive dependencies (see
    /// [`is_heavy_dependency`]).
    transitive_deps: HashMap<String, usize>,
    /// Package name -> its own manifest's `repository` field, exactly as
    /// `cargo_metadata` read it (`None` when the manifest omits the field
    /// entirely — see [`repository_is_missing`]).
    repository: HashMap<String, Option<String>>,
}

/// Runs a full (non `--no-deps`) `cargo metadata` resolve and reads both
/// pieces of package metadata `heavy-dependency` and `dep-without-repo` need
/// from it (see [`FullMetadataResolve`]) — one resolve, not two. Runs its own
/// metadata command rather than reusing another module's resolve: a parallel
/// `dep_graph.rs` effort resolves a full graph too, for its own manifest/graph
/// rules; consolidating the two runs into one is left as follow-up work.
fn resolve_full_metadata(
    manifest_path: &Path,
) -> Result<FullMetadataResolve, cargo_metadata::Error> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(manifest_path)
        .exec()?;
    let repository: HashMap<String, Option<String>> = metadata
        .packages
        .iter()
        .map(|package| (package.name.to_string(), package.repository.clone()))
        .collect();
    let Some(resolve) = metadata.resolve else {
        return Ok(FullMetadataResolve {
            transitive_deps: HashMap::new(),
            repository,
        });
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

    let mut transitive_deps: HashMap<String, usize> = HashMap::new();
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
            transitive_deps.entry(name.clone()).or_insert(visited.len());
        }
    }
    Ok(FullMetadataResolve {
        transitive_deps,
        repository,
    })
}

/// Result of [`analyze_rustc_unused_dependencies`] — kept separate from
/// [`WorkspaceDeps`] since this detector is opt-in and invoked by its own
/// caller (`cargo judge deps --check-rustc-lints`), never folded into
/// [`analyze_workspace`]'s always-on pass.
#[derive(Debug, Default)]
pub struct RustcLintDeps {
    pub findings: Vec<Finding>,
    pub errors: Vec<DepsError>,
}

/// Runs `cargo check --workspace --all-targets` with rustc's stable,
/// allow-by-default `unused_crate_dependencies` lint turned on and turns its
/// diagnostics into `unused-dependency` findings (see module docs "Importing
/// rustc's `unused_crate_dependencies` lint", todo.md §B). Opt-in only
/// (`cargo judge deps --check-rustc-lints`) — unlike every other detector in
/// this module, this one runs a full `cargo check`, not an instant syntactic
/// pass, so it is never part of [`analyze_workspace`] or bare `cargo judge`.
pub fn analyze_rustc_unused_dependencies(workspace: &Workspace) -> RustcLintDeps {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let manifest_path = workspace.root.join("Cargo.toml");
    let metadata = match cargo_metadata::MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
    {
        Ok(metadata) => metadata,
        Err(err) => {
            errors.push(DepsError::Metadata(err));
            return RustcLintDeps { findings, errors };
        }
    };

    let workspace_members: HashSet<cargo_metadata::PackageId> =
        metadata.workspace_members.iter().cloned().collect();
    let name_to_id: HashMap<&str, cargo_metadata::PackageId> = metadata
        .packages
        .iter()
        .filter(|package| workspace_members.contains(&package.id))
        .map(|package| (package.name.as_str(), package.id.clone()))
        .collect();

    let messages = match run_cargo_check_with_unused_crate_dependencies_lint(&manifest_path) {
        Ok(messages) => messages,
        Err(err) => {
            errors.push(err);
            return RustcLintDeps { findings, errors };
        }
    };

    // Per package, every distinct target compiled (see `target_identity`) —
    // the universe the intersection below runs over.
    let mut targets_seen: HashMap<cargo_metadata::PackageId, HashSet<String>> = HashMap::new();
    // Per (package, target), the dependency identifiers rustc reported
    // unused for that one compiled unit.
    let mut unused_per_target: HashMap<(cargo_metadata::PackageId, String), HashSet<String>> =
        HashMap::new();

    for message in messages {
        match message {
            cargo_metadata::Message::CompilerArtifact(artifact) => {
                if !workspace_members.contains(&artifact.package_id) {
                    continue;
                }
                targets_seen
                    .entry(artifact.package_id)
                    .or_default()
                    .insert(target_identity(&artifact.target));
            }
            cargo_metadata::Message::CompilerMessage(compiler_message) => {
                if !workspace_members.contains(&compiler_message.package_id) {
                    continue;
                }
                let is_unused_crate_dependency = compiler_message
                    .message
                    .code
                    .as_ref()
                    .is_some_and(|code| code.code == "unused_crate_dependencies");
                if !is_unused_crate_dependency {
                    continue;
                }
                let Some(dep_identifier) =
                    extract_unused_crate_name(&compiler_message.message.message)
                else {
                    continue;
                };
                unused_per_target
                    .entry((
                        compiler_message.package_id,
                        target_identity(&compiler_message.target),
                    ))
                    .or_default()
                    .insert(dep_identifier);
            }
            _ => {}
        }
    }

    for krate in &workspace.crates {
        let Some(package_id) = name_to_id.get(krate.name.as_str()) else {
            continue;
        };
        let Some(all_targets) = targets_seen.get(package_id) else {
            continue;
        };
        if all_targets.is_empty() {
            continue;
        }

        // Multi-target false-positive gap (see module docs): only a
        // dependency reported unused in *every* target run of this package
        // is finding-worthy — the intersection, not the union.
        let mut always_unused: Option<HashSet<String>> = None;
        for target in all_targets {
            let unused_here = unused_per_target
                .get(&(package_id.clone(), target.clone()))
                .cloned()
                .unwrap_or_default();
            always_unused = Some(match always_unused {
                None => unused_here,
                Some(acc) => acc.intersection(&unused_here).cloned().collect(),
            });
        }
        let Some(always_unused) = always_unused else {
            continue;
        };

        let mut targets_checked: Vec<&String> = all_targets.iter().collect();
        targets_checked.sort();

        for dep_identifier in &always_unused {
            let Some(dep) = krate.dependencies.iter().find(|dep| {
                dep.kind == DependencyKind::Normal && dep.code_identifier == *dep_identifier
            }) else {
                continue;
            };
            findings.push(unused_dependency_finding(krate, dep, &targets_checked));
        }
    }

    RustcLintDeps { findings, errors }
}

/// A target's identity for the purposes of the multi-target intersection in
/// [`analyze_rustc_unused_dependencies`]: its Cargo target kind(s) (`lib`,
/// `test`, `example`, `bench`, ...) and name, e.g. `"lib:mycrate"` or
/// `"test:it"`. Deliberately not further split by the `profile.test` build
/// variant — the crate's own unit-test compile of `lib`/`bin` shares this
/// same identity with its non-test compile, since both compile the same
/// source file and "target" here means what `Cargo.toml` itself calls a
/// target, not each individual rustc invocation.
fn target_identity(target: &cargo_metadata::Target) -> String {
    let kinds = target
        .kind
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{kinds}:{}", target.name)
}

/// Extracts the unused crate's code identifier from an
/// `unused_crate_dependencies` diagnostic's short message, e.g. "extern
/// crate `depcrate` is unused in crate `fixture`" → `Some("depcrate")`. The
/// message text is rustc's own and not otherwise structured in the JSON
/// diagnostic, so this parses the one stable landmark: the first
/// backtick-quoted name.
fn extract_unused_crate_name(message: &str) -> Option<String> {
    if !message.contains("is unused in crate") {
        return None;
    }
    message.split('`').nth(1).map(str::to_string)
}

/// Runs `cargo check --workspace --all-targets --message-format=json` with
/// `-W unused_crate_dependencies` added to `RUSTFLAGS` (preserving any
/// `RUSTFLAGS` already set in the environment) and parses the resulting
/// message stream via `cargo_metadata::Message::parse_stream`. A spawn
/// failure or a non-zero exit status (e.g. the workspace doesn't currently
/// compile) is returned as a [`DepsError::RustcCheck`] rather than treated
/// as a finding source — see module docs "Importing rustc's
/// `unused_crate_dependencies` lint".
fn run_cargo_check_with_unused_crate_dependencies_lint(
    manifest_path: &Path,
) -> Result<Vec<cargo_metadata::Message>, DepsError> {
    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    if !rustflags.is_empty() {
        rustflags.push(' ');
    }
    rustflags.push_str("-W unused_crate_dependencies");

    let output = std::process::Command::new("cargo")
        .arg("check")
        .arg("--workspace")
        .arg("--all-targets")
        .arg("--message-format=json")
        .arg("--manifest-path")
        .arg(manifest_path)
        .env("RUSTFLAGS", rustflags)
        .output()
        .map_err(|err| DepsError::RustcCheck(format!("failed to run `cargo check`: {err}")))?;

    if !output.status.success() {
        return Err(DepsError::RustcCheck(format!(
            "`cargo check --workspace --all-targets` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(
        cargo_metadata::Message::parse_stream(output.stdout.as_slice())
            .filter_map(Result::ok)
            .collect(),
    )
}

/// Renders an `unused-dependency` finding — rustc's own
/// `unused_crate_dependencies` lint result, narrowed to the packages this
/// workspace actually owns and to the multi-target intersection described in
/// the module docs. Its evidence class is `bounded_semantic` (todo.md
/// §17.3): the claim is scoped to "no use found across the targets this run
/// checked", not an absolute "unused". Same `location` convention as
/// [`misplaced_finding`].
fn unused_dependency_finding(
    krate: &CrateInfo,
    dep: &crate::ingest::DeclaredDependency,
    targets_checked: &[&String],
) -> Finding {
    Finding {
        id: format!("{UNUSED_DEPENDENCY_RULE}:{}:{}", krate.name, dep.name).into(),
        rule: UNUSED_DEPENDENCY_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: OneBasedLine::FIRST,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "source": "rustc:unused_crate_dependencies",
            "targets_checked": targets_checked,
            "package": krate.name,
            "reason": "no use found by rustc's unused_crate_dependencies lint \
                across all targets of this package",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
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
    /// `cargo metadata --no-deps` run). The vendored dependency declares a
    /// `repository` field so these otherwise-unrelated fixtures don't also
    /// pick up a `dep-without-repo` finding from the full-resolve pass that
    /// `analyze_workspace` always runs alongside `heavy-dependency`.
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
repository = "https://example.com/{dep_crate_name}"
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
    fn a_normal_dependency_used_only_inside_a_platform_cfg_gate_is_not_misclassified_as_dev_only() {
        // The dependency is referenced only inside a
        // `#[cfg(target_os = "windows")]`-gated module in src/lib.rs -- code
        // that will never actually compile on most developer/CI machines.
        // Usage-domain classification is purely path-based (see module
        // docs "Usage-domain classification"), and `collect_identifiers`'s
        // syn-based scan doesn't evaluate `cfg` predicates at all -- it just
        // records the path reference inside a file that isn't under
        // tests/examples/benches. So this still counts as `Normal`-domain
        // usage: the todo.md §17.5 hypothesis (fast-tier usage detection
        // mis-attributing cfg-gated usage as "only from tests/examples")
        // does not hold here. Documents the actual (correct, non-buggy)
        // behavior.
        let dir = TempDir::new("deps-platform-cfg-gate");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[(
                "src/lib.rs",
                "#[cfg(target_os = \"windows\")]\nmod windows {\n    pub fn go() { depcrate::noop(); }\n}\n",
            )],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == MISPLACED_DEPENDENCY_KIND_RULE),
            "a cfg-gated normal-domain usage must not be misclassified as dev-only: {:?}",
            report.findings
        );
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
    fn a_dependency_with_zero_usage_and_features_is_flagged_per_feature() {
        let dir = TempDir::new("deps-feature-only");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &["some-feature", "other-feature"],
            &[],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert_eq!(report.feature_only_candidates, vec!["depcrate".to_string()]);

        let flagged: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule == UNUSED_FEATURE_FLAG_RULE)
            .collect();
        assert_eq!(flagged.len(), 2);
        for finding in &flagged {
            assert_eq!(finding.severity, Severity::Warn);
            assert_eq!(finding.evidence_class, EvidenceClass::DerivedFact);
            assert_eq!(finding.location.item_path, "depcrate");
        }
        let features: Vec<&str> = flagged
            .iter()
            .map(|f| f.evidence.as_ref().unwrap()["feature"].as_str().unwrap())
            .collect();
        assert!(features.contains(&"some-feature"));
        assert!(features.contains(&"other-feature"));
    }

    #[test]
    fn a_dependency_used_anywhere_has_no_unused_feature_flag_finding_despite_many_features() {
        let dir = TempDir::new("deps-feature-used");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &["some-feature", "other-feature"],
            &[("src/lib.rs", "pub fn hello() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_FEATURE_FLAG_RULE)
        );
        assert!(report.feature_only_candidates.is_empty());
    }

    /// Writes a fixture like [`write_fixture`], but with a caller-supplied
    /// dependency line — needed for `default-features-unused` tests, which
    /// must control whether `default-features = true` is present in the
    /// manifest text verbatim (something [`write_fixture`]'s `features`-only
    /// knobs can't express).
    fn write_fixture_with_dep_line(
        dir: &TempDir,
        dep_line: &str,
        main_files: &[(&str, &str)],
    ) -> PathBuf {
        std::fs::create_dir_all(dir.join("main/src")).unwrap();
        std::fs::create_dir_all(dir.join("dep_crate/src")).unwrap();

        std::fs::write(
            dir.join("main/Cargo.toml"),
            format!(
                r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
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
            r#"
[package]
name = "depcrate"
version = "0.1.0"
edition = "2021"
repository = "https://example.com/depcrate"
"#,
        )
        .unwrap();
        std::fs::write(dir.join("dep_crate/src/lib.rs"), "pub fn noop() {}\n").unwrap();

        dir.join("main/Cargo.toml")
    }

    #[test]
    fn explicit_default_features_true_and_zero_usage_is_flagged() {
        let dir = TempDir::new("deps-default-features-unused");
        let manifest = write_fixture_with_dep_line(
            &dir,
            r#"depcrate = { path = "../dep_crate", default-features = true }"#,
            &[],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == DEFAULT_FEATURES_UNUSED_RULE)
            .expect("expected a default-features-unused finding");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::DerivedFact);
        assert_eq!(finding.location.item_path, "depcrate");
    }

    #[test]
    fn explicit_default_features_true_but_used_is_not_flagged() {
        let dir = TempDir::new("deps-default-features-used");
        let manifest = write_fixture_with_dep_line(
            &dir,
            r#"depcrate = { path = "../dep_crate", default-features = true }"#,
            &[("src/lib.rs", "pub fn hello() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DEFAULT_FEATURES_UNUSED_RULE)
        );
    }

    #[test]
    fn no_explicit_default_features_and_zero_usage_is_not_flagged() {
        let dir = TempDir::new("deps-default-features-implicit");
        let manifest =
            write_fixture_with_dep_line(&dir, r#"depcrate = { path = "../dep_crate" }"#, &[]);

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DEFAULT_FEATURES_UNUSED_RULE)
        );
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

    #[test]
    fn repository_is_missing_treats_absent_and_blank_as_missing() {
        assert!(repository_is_missing(&None));
        assert!(repository_is_missing(&Some(String::new())));
        assert!(repository_is_missing(&Some("   ".to_string())));
        assert!(!repository_is_missing(&Some(
            "https://example.com/repo".to_string()
        )));
    }

    #[test]
    fn dep_without_repo_finding_is_gating_info() {
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
            name: "norepo_crate".to_string(),
            kind: DependencyKind::Normal,
            code_identifier: "norepo_crate".to_string(),
            target: None,
            features: Vec::new(),
            version_req: "*".to_string(),
        };
        let finding = dep_without_repo_finding(&krate, &dep);

        assert_eq!(finding.rule, DEP_WITHOUT_REPO_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::DerivedFact);
        assert!(finding.is_gating());
        assert_eq!(finding.location.item_path, "norepo_crate");
    }

    /// End-to-end: a real (non `--no-deps`) `cargo metadata` resolve over a
    /// vendored path dependency whose manifest has no `repository` field —
    /// proves [`resolve_full_metadata`]/`analyze_workspace` wire the field
    /// through, not just the pure `dep_without_repo_finding` builder above.
    #[test]
    fn a_dependency_without_a_repository_field_is_flagged_end_to_end() {
        let dir = TempDir::new("deps-dep-without-repo");
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
norepo = { path = "../dep_crate" }
"#,
        )
        .unwrap();
        std::fs::write(dir.join("main/src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(
            dir.join("dep_crate/Cargo.toml"),
            r#"
[package]
name = "norepo"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::write(dir.join("dep_crate/src/lib.rs"), "pub fn noop() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("main/Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace);

        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == DEP_WITHOUT_REPO_RULE)
            .expect("expected a dep-without-repo finding");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::DerivedFact);
        assert_eq!(finding.location.item_path, "norepo");
    }

    #[test]
    fn a_dependency_with_a_repository_field_is_not_flagged_end_to_end() {
        let dir = TempDir::new("deps-dep-with-repo");
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
hasrepo = { path = "../dep_crate" }
"#,
        )
        .unwrap();
        std::fs::write(dir.join("main/src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(
            dir.join("dep_crate/Cargo.toml"),
            r#"
[package]
name = "hasrepo"
version = "0.1.0"
edition = "2021"
repository = "https://example.com/hasrepo"
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
                .any(|f| f.rule == DEP_WITHOUT_REPO_RULE)
        );
    }

    #[test]
    fn extract_unused_crate_name_parses_the_first_backtick_quoted_name() {
        assert_eq!(
            extract_unused_crate_name("extern crate `depcrate` is unused in crate `fixture`"),
            Some("depcrate".to_string())
        );
        assert_eq!(extract_unused_crate_name("some unrelated warning"), None);
    }

    #[test]
    fn target_identity_joins_kind_and_name() {
        let json = serde_json::json!({
            "name": "it",
            "kind": ["test"],
            "crate_types": ["bin"],
            "required-features": [],
            "src_path": "tests/it.rs",
            "edition": "2021",
            "doc": false,
            "doctest": false,
            "test": true,
        });
        let target: cargo_metadata::Target = serde_json::from_value(json).unwrap();
        assert_eq!(target_identity(&target), "test:it");
    }

    // The following three tests drive a real `cargo check --workspace
    // --all-targets` subprocess (see `run_cargo_check_with_unused_crate_dependencies_lint`)
    // against a path-dependency-only fixture — offline, but genuinely slow
    // compared to every other test in this file (a fraction of a second per
    // fixture, verified against a real run rather than mocked, see todo.md
    // §B). They are the proof that `analyze_rustc_unused_dependencies`'s
    // whole pipeline — spawn, JSON parse, multi-target intersection — works
    // end to end, not just its pure helpers above.

    #[test]
    fn rustc_lint_import_flags_a_normal_dependency_never_referenced_anywhere() {
        let dir = TempDir::new("deps-rustc-lint-unused");
        let manifest = write_fixture(&dir, "[dependencies]", "depcrate", None, &[], &[]);

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_rustc_unused_dependencies(&workspace);

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == UNUSED_DEPENDENCY_RULE)
            .expect("expected an unused-dependency finding");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(finding.location.item_path, "depcrate");
        let evidence = finding.evidence.as_ref().unwrap();
        assert_eq!(evidence["source"], "rustc:unused_crate_dependencies");
        assert_eq!(evidence["package"], "fixture");
        assert!(
            evidence["reason"]
                .as_str()
                .unwrap()
                .contains("unused_crate_dependencies")
        );
    }

    #[test]
    fn rustc_lint_import_does_not_flag_a_dependency_used_in_every_target() {
        let dir = TempDir::new("deps-rustc-lint-used-everywhere");
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
        let report = analyze_rustc_unused_dependencies(&workspace);

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_DEPENDENCY_RULE)
        );
    }

    #[test]
    fn rustc_lint_import_does_not_flag_a_dependency_used_by_only_one_target() {
        // `depcrate` is referenced only from the integration test target,
        // never from `lib` — rustc's raw per-target lint would report it
        // unused for the `lib` compile alone, the documented multi-target
        // false positive this detector's intersection logic is meant to
        // avoid (see module docs "Importing rustc's
        // `unused_crate_dependencies` lint").
        let dir = TempDir::new("deps-rustc-lint-single-target");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[("tests/it.rs", "fn t() { depcrate::noop(); }\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_rustc_unused_dependencies(&workspace);

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == UNUSED_DEPENDENCY_RULE)
        );
    }

    #[test]
    fn a_genuine_compile_error_surfaces_as_a_report_error_not_as_zero_findings() {
        // If `cargo check --workspace --all-targets` fails because the
        // workspace doesn't compile at all (a real syntax error here,
        // unrelated to the lint), that must not be silently read as "the
        // lint ran and found zero unused dependencies" -- those two outcomes
        // look identical as an empty `findings` vec, but mean very different
        // things. It has to surface as a `DepsError::RustcCheck` instead, so
        // the caller can tell "checked, nothing unused" apart from "could not
        // check at all".
        let dir = TempDir::new("deps-rustc-lint-compile-error");
        let manifest = write_fixture(
            &dir,
            "[dependencies]",
            "depcrate",
            None,
            &[],
            &[("src/lib.rs", "this is not valid rust syntax {{{\n")],
        );

        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_rustc_unused_dependencies(&workspace);

        assert!(
            report.findings.is_empty(),
            "unexpected findings from an unbuildable workspace: {:?}",
            report.findings
        );
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(report.errors[0], DepsError::RustcCheck(_)));
    }
}
