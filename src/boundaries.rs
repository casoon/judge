//! Architecture boundaries: crate-level dependency rules and cycle
//! detection, plus a second, independent module-level boundary layer within
//! a single crate (see todo.md §3.H "Architektur & Boundaries", §14.2 P1/P2
//! bullets 1-2, §9 "Modul-Boundaries").
//!
//! ## Crate-level boundaries
//!
//! [`BoundaryRule`]/[`evaluate`] are deliberately scoped to *crate-level*
//! dependency edges, fully knowable from `cargo_metadata` without a build.
//! `[layers]` (see todo.md §9) is a crate-level convenience on top of the
//! same model — it expands a compact layer/role/group assignment into the
//! same [`BoundaryRule`] edges a hand-written `[[boundary]]` entry produces.
//!
//! ## Module-level boundaries (`[[module_boundary]]`)
//!
//! [`ModuleBoundaryRule`] checks a second, independent boundary layer
//! *within* one crate — e.g. "the `domain` module must not reach
//! `io`/`cli`". Two Fast-Tier limitations, by design rather than oversight:
//!
//! - **Module path resolution is a directory-convention heuristic, not
//!   `mod`-graph resolution** — the same trade-off `deps.rs`'s
//!   `UsageDomain` classification documents. A `.rs` file's module path is
//!   derived purely from its position under `src/` (see
//!   [`module_path_for_file`]). A file wired into the build in an
//!   unconventional way — e.g. via a `#[path = "..."]` attribute — is
//!   missed.
//! - **Only `direct` reach is supported**, unlike crate-level
//!   [`BoundaryRule`]'s `direct`/`transitive` choice: `transitive` would
//!   need a real module call graph, which needs a Deep Tier judge doesn't
//!   have yet. Requesting it in `[[module_boundary]]` is a config error.
//!
//! `required` (crate-level boundaries' other half) is also not part of this
//! first slice — only `forbidden` is supported.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use cargo_metadata::MetadataCommand;
use serde::Deserialize;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ItemUse, UseTree};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::health_score::DeductionMultiplier;
use crate::ingest::{CrateInfo, Workspace};
use crate::slopsquat::SlopsquatConfig;

/// One user-configured `[[provenance_label]]` rule (see `crate::provenance`,
/// todo.md §3.G G6): a trusted, explicitly-provided signal that wins outright
/// over heuristic classification for any commit it matches.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvenanceLabel {
    pub name: String,
    #[serde(default)]
    pub trailer_contains: Vec<String>,
    #[serde(default)]
    pub author_email_contains: Vec<String>,
}

/// The `judge.toml` `[[provenance_label]]` table (see `crate::provenance`,
/// todo.md §3.G G6).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProvenanceConfig {
    #[serde(rename = "provenance_label", default)]
    pub labels: Vec<ProvenanceLabel>,
}

/// Rule id used for both forbidden-edge and missing-required violations (see
/// todo.md §14.2 P1/P2 bullet 1).
pub const BOUNDARY_VIOLATION_RULE: &str = "crate-boundary-violation";
/// Bump when the boundary-violation rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const BOUNDARY_VIOLATION_RULE_REVISION: u32 = 1;

/// Rule id used for detected dependency cycles.
pub const DEPENDENCY_CYCLE_RULE: &str = "dependency-cycle";
/// Bump when the cycle-detection rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const DEPENDENCY_CYCLE_RULE_REVISION: u32 = 1;

/// Rule id used for `[[module_boundary]]` violations — deliberately distinct
/// from [`BOUNDARY_VIOLATION_RULE`]: a module-boundary finding makes a claim
/// on a heuristically-derived module view within one crate, a different
/// statement than a crate-to-crate dependency edge (see module docs
/// "Module-level boundaries").
pub const MODULE_BOUNDARY_VIOLATION_RULE: &str = "module-boundary-violation";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const MODULE_BOUNDARY_VIOLATION_RULE_REVISION: u32 = 1;

/// Whether a boundary is checked against direct neighbors only, or against
/// anything reachable via any number of hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    Direct,
    Transitive,
}

impl Reach {
    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Transitive => "transitive",
        }
    }
}

/// One named boundary rule from `judge.toml` (see todo.md §14.2 P1/P2
/// bullet 1). A rule may name `forbidden` crates, `required` crates, or
/// both.
#[derive(Debug, Clone, Deserialize)]
pub struct BoundaryRule {
    pub name: String,
    pub from: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
    #[serde(default)]
    pub required: Vec<String>,
    pub reach: Reach,
    /// Skips config validation for this rule when it names a crate the
    /// workspace doesn't have (see todo.md §14.2 P1/P2 bullet 2).
    #[serde(default)]
    pub allow_empty: bool,
}

/// One named `[[module_boundary]]` rule from `judge.toml` (see todo.md §9,
/// module docs "Module-level boundaries"): a boundary within a single
/// crate's module tree, scoped by directory-convention module paths rather
/// than crate names. Unlike [`BoundaryRule`], `from` is a single module path
/// prefix (not a list) and there is no `required`/`reach` choice — see the
/// module docs for why.
#[derive(Debug, Clone, Deserialize)]
pub struct ModuleBoundaryRule {
    pub name: String,
    /// The workspace crate this rule scopes to. Validated to exist, same as
    /// [`BoundaryRule::from`]/`forbidden`/`required`.
    #[serde(rename = "crate")]
    pub krate: String,
    /// A module path prefix relative to the crate root, e.g. `"domain"`
    /// matches `crate::domain` and any of its descendants.
    pub from: String,
    /// Module path prefixes `from` must not reference. Must be non-empty —
    /// a rule with no forbidden targets is vacuous.
    #[serde(default)]
    pub forbidden: Vec<String>,
    /// Only present so a `reach = "transitive"` entry (a field that exists
    /// on the crate-level `[[boundary]]` table) produces a clear config
    /// error instead of being silently accepted or rejected by serde as an
    /// unknown field. `None`/`Some(Reach::Direct)` are the only valid
    /// values — see module docs "Module-level boundaries".
    #[serde(default)]
    pub reach: Option<Reach>,
}

/// One named crate-type profile from `judge.toml` (see todo.md §4 "Health
/// Score", point 3 "Kontextrelativ"). Findings from a crate listed here have
/// their score deduction scaled by `deduction_multiplier` — e.g. a parser
/// crate can legitimately carry more complexity than a CLI crate, without
/// judge guessing that classification itself. Crates not named in any
/// profile use a multiplier of `1.0`.
#[derive(Debug, Clone, Deserialize)]
pub struct CrateProfile {
    pub name: String,
    pub crates: Vec<String>,
    /// Validated at deserialization (see [`DeductionMultiplier`]) — an
    /// out-of-range value is a config error, not a score. Missing means the
    /// default `1.0`.
    #[serde(default)]
    pub deduction_multiplier: DeductionMultiplier,
}

/// A named preset for `[layers]` (see todo.md §9 "Layer-Presets/Modul-
/// Boundaries"). Each preset expands a compact crate-to-layer/role/group
/// assignment into the same [`BoundaryRule`] edges a hand-written
/// `[[boundary]]` entry produces, via [`generate_layer_rules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerPreset {
    Layered,
    Hexagonal,
    FeatureSliced,
}

impl LayerPreset {
    fn label(self) -> &'static str {
        match self {
            Self::Layered => "layered",
            Self::Hexagonal => "hexagonal",
            Self::FeatureSliced => "feature-sliced",
        }
    }
}

/// The `judge.toml` `[layers]` table (see todo.md §9). Crates not named in
/// `assign` are ignored — never auto-assigned to a layer, since guessing
/// project intent is exactly what todo.md §17 forbids.
#[derive(Debug, Clone, Deserialize)]
pub struct LayersConfig {
    pub preset: LayerPreset,
    /// `layered` only: layer names from innermost (index 0, e.g. `"domain"`)
    /// to outermost (e.g. `"infrastructure"`). Inner layers may not reach
    /// outer layers; outer layers may freely reach inner ones.
    #[serde(default)]
    pub order: Vec<String>,
    /// `feature-sliced` only: the group name (a value used in `assign`)
    /// every other group may reference without being flagged.
    #[serde(default)]
    pub shared: Option<String>,
    /// Crate name -> layer/role/group name. For `layered`, values must be
    /// entries of `order`. For `hexagonal`, values must be `"core"`,
    /// `"ports"`, or `"adapters"`. For `feature-sliced`, values are
    /// free-form group names.
    #[serde(default)]
    pub assign: HashMap<String, String>,
}

/// The `judge.toml` `[[boundary]]`, `[layers]`, `[[crate_profile]]`, and
/// `[slopsquat]` tables (see todo.md §8, §9). `[slopsquat]` lives here rather
/// than in its own top-level config struct because this is already the one
/// struct every `judge.toml` table deserializes into (see `main.rs`'s
/// `load_judge_toml`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BoundaryConfig {
    #[serde(rename = "boundary", default)]
    pub boundaries: Vec<BoundaryRule>,
    #[serde(rename = "module_boundary", default)]
    pub module_boundaries: Vec<ModuleBoundaryRule>,
    #[serde(default)]
    pub layers: Option<LayersConfig>,
    #[serde(rename = "crate_profile", default)]
    pub crate_profiles: Vec<CrateProfile>,
    #[serde(default)]
    pub slopsquat: SlopsquatConfig,
    /// Flattened so `[[provenance_label]]` sits at the top level of
    /// `judge.toml`, alongside `[[boundary]]`/`[[crate_profile]]`, rather
    /// than nested under a `[provenance]` table.
    #[serde(flatten)]
    pub provenance: ProvenanceConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

/// The `judge.toml` `[rules.*]` tables — per-rule configuration, keyed by
/// rule id (see GitHub issue #5). A precedent for future per-rule config
/// beyond `catch-all-error`, not a one-off.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(rename = "catch-all-error", default)]
    pub catch_all_error: CatchAllErrorConfig,
}

/// `[rules.catch-all-error]`: opts a codebase following the "thiserror for
/// error types, anyhow for propagation at public boundaries" convention out
/// of `catch-all-error` findings on `anyhow::Result`/`anyhow::Error` — but
/// not on `Box<dyn Error>`, which has no comparable convention argument (see
/// GitHub issue #5).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct CatchAllErrorConfig {
    #[serde(default)]
    pub allow_anyhow_at_boundary: bool,
}

/// A configuration error, distinct from a [`Finding`] — this means the rule
/// itself is unusable, not that it found a violation (see todo.md §14.2
/// P1/P2 bullet 2). The CLI turns this into `exit 2`, matching
/// `IngestError`/`GitError`/`BaselineError`.
#[derive(Debug)]
pub enum BoundaryConfigError {
    Metadata(cargo_metadata::Error),
    /// A rule's `from`/`forbidden`/`required` names a crate the workspace
    /// doesn't have, and `allow_empty` isn't set to permit that.
    UnknownCrate {
        rule: String,
        crate_name: String,
    },
    /// A `[layers]` preset is missing a required role/order assignment, or
    /// its `assign`/`order`/`shared` values are inconsistent (see todo.md
    /// §9).
    InvalidLayers(String),
    /// A `[[module_boundary]]` rule has an empty `forbidden` list, or
    /// requests `reach = "transitive"` (see [`ModuleBoundaryRule::reach`],
    /// module docs "Module-level boundaries").
    InvalidModuleBoundary(String),
}

impl std::fmt::Display for BoundaryConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
            Self::UnknownCrate { rule, crate_name } => write!(
                f,
                "boundary rule `{rule}` references unknown crate `{crate_name}` (set allow_empty = true to permit this)"
            ),
            Self::InvalidLayers(message) => write!(f, "invalid [layers] config: {message}"),
            Self::InvalidModuleBoundary(message) => {
                write!(f, "invalid [[module_boundary]] config: {message}")
            }
        }
    }
}

impl std::error::Error for BoundaryConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(err) => Some(err),
            Self::UnknownCrate { .. } | Self::InvalidLayers(_) | Self::InvalidModuleBoundary(_) => {
                None
            }
        }
    }
}

/// The workspace-internal crate dependency graph: crate name -> names of
/// workspace crates it depends on. Dependency `kind` (normal/dev/build)
/// doesn't matter here — all of them count as an architectural edge, since
/// even a dev- or build-only dependency crosses the same boundary.
#[derive(Debug, Clone, Default)]
pub struct CrateGraph {
    pub edges: HashMap<String, Vec<String>>,
}

/// Builds a [`CrateGraph`] by running a lightweight `cargo metadata
/// --no-deps` call scoped to `manifest_path` (or the current directory's
/// workspace, if `None`). An edge `crate_a -> crate_b` exists whenever
/// `crate_a`'s `Cargo.toml` declares a dependency named `crate_b`, and
/// `crate_b` is itself a workspace member. Edges are sorted, so graph
/// traversal is deterministic.
pub fn build_crate_graph(manifest_path: Option<&Path>) -> Result<CrateGraph, BoundaryConfigError> {
    let mut cmd = MetadataCommand::new();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }
    let metadata = cmd
        .no_deps()
        .exec()
        .map_err(BoundaryConfigError::Metadata)?;

    let workspace_crate_names: HashSet<String> = metadata
        .packages
        .iter()
        .map(|package| package.name.to_string())
        .collect();

    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    for package in &metadata.packages {
        let mut deps: Vec<String> = package
            .dependencies
            .iter()
            .map(|dep| dep.name.clone())
            .filter(|name| workspace_crate_names.contains(name))
            .collect();
        deps.sort();
        deps.dedup();
        edges.insert(package.name.to_string(), deps);
    }

    Ok(CrateGraph { edges })
}

/// Result of a full boundary evaluation: every violation and cycle found,
/// rendered as [`Finding`]s.
#[derive(Debug, Default)]
pub struct WorkspaceBoundaries {
    pub findings: Vec<Finding>,
}

/// Validates that every crate name a rule references actually exists in the
/// workspace, unless the rule opts out via `allow_empty` (see todo.md §14.2
/// P1/P2 bullet 2).
fn validate_config(
    config: &BoundaryConfig,
    crate_names: &HashSet<&str>,
) -> Result<(), BoundaryConfigError> {
    for rule in &config.boundaries {
        if rule.allow_empty {
            continue;
        }
        for name in rule
            .from
            .iter()
            .chain(rule.forbidden.iter())
            .chain(rule.required.iter())
        {
            if !crate_names.contains(name.as_str()) {
                return Err(BoundaryConfigError::UnknownCrate {
                    rule: rule.name.clone(),
                    crate_name: name.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Validates every `[[module_boundary]]` rule: its `crate` must name a
/// workspace crate, `forbidden` must be non-empty (an empty-scope rule is
/// vacuous — see todo.md §14.1), and `reach` must not request
/// `"transitive"` (see [`ModuleBoundaryRule::reach`]).
fn validate_module_boundary_config(
    config: &BoundaryConfig,
    crate_names: &HashSet<&str>,
) -> Result<(), BoundaryConfigError> {
    for rule in &config.module_boundaries {
        if !crate_names.contains(rule.krate.as_str()) {
            return Err(BoundaryConfigError::UnknownCrate {
                rule: rule.name.clone(),
                crate_name: rule.krate.clone(),
            });
        }
        if rule.forbidden.is_empty() {
            return Err(BoundaryConfigError::InvalidModuleBoundary(format!(
                "module boundary rule `{}` has no forbidden targets — a rule with no forbidden targets is vacuous",
                rule.name
            )));
        }
        if rule.reach == Some(Reach::Transitive) {
            return Err(BoundaryConfigError::InvalidModuleBoundary(format!(
                "module boundary rule `{}`: module boundaries only support direct reach in the Fast Tier",
                rule.name
            )));
        }
    }
    Ok(())
}

/// Every crate assigned to `group_name` in `assign`, in ascending crate-name
/// order (`assign` is pre-sorted by [`generate_layer_rules`], so this is
/// just a filter — deterministic without a re-sort).
fn group_crates(assigned: &[(&str, &str)], group_name: &str) -> Vec<String> {
    assigned
        .iter()
        .filter(|(_, group)| *group == group_name)
        .map(|(krate, _)| (*krate).to_string())
        .collect()
}

const HEXAGONAL_ROLES: [&str; 3] = ["core", "ports", "adapters"];

/// `layered`: for each layer, forbids that layer's crates from reaching
/// (directly or transitively) any crate assigned to a layer later in
/// `order` (i.e. further out). A layer with no crates assigned, or with no
/// outer layers to forbid, generates nothing.
fn generate_layered_rules(
    layers: &LayersConfig,
    assigned: &[(&str, &str)],
) -> Result<Vec<BoundaryRule>, BoundaryConfigError> {
    if layers.order.len() < 2 {
        return Err(BoundaryConfigError::InvalidLayers(
            "preset \"layered\" needs at least 2 entries in `order`".to_string(),
        ));
    }
    let known_layers: HashSet<&str> = layers.order.iter().map(String::as_str).collect();
    for (krate, group) in assigned {
        if !known_layers.contains(group) {
            return Err(BoundaryConfigError::InvalidLayers(format!(
                "`layers.assign` names crate `{krate}` as layer `{group}`, which is not in `order`"
            )));
        }
    }

    let mut rules = Vec::new();
    for (i, inner) in layers.order.iter().enumerate() {
        let from = group_crates(assigned, inner);
        if from.is_empty() {
            continue;
        }
        let forbidden: Vec<String> = layers.order[i + 1..]
            .iter()
            .flat_map(|outer| group_crates(assigned, outer))
            .collect();
        if forbidden.is_empty() {
            continue;
        }
        rules.push(BoundaryRule {
            name: format!("preset:layered:{inner}"),
            from,
            forbidden,
            required: Vec::new(),
            reach: Reach::Transitive,
            allow_empty: false,
        });
    }
    Ok(rules)
}

/// `hexagonal`: a minimal 3-role model (`core`, `ports`, `adapters`). `core`
/// must not reach `adapters`; `adapters` must not reach `core` directly, and
/// must reach `ports` directly (adapters reach the domain only through a
/// port). All three roles need at least one assigned crate.
fn generate_hexagonal_rules(
    assigned: &[(&str, &str)],
) -> Result<Vec<BoundaryRule>, BoundaryConfigError> {
    for (krate, role) in assigned {
        if !HEXAGONAL_ROLES.contains(role) {
            return Err(BoundaryConfigError::InvalidLayers(format!(
                "`layers.assign` names crate `{krate}` as role `{role}`, but preset \"hexagonal\" only knows {HEXAGONAL_ROLES:?}"
            )));
        }
    }
    let core = group_crates(assigned, "core");
    let ports = group_crates(assigned, "ports");
    let adapters = group_crates(assigned, "adapters");
    if core.is_empty() || ports.is_empty() || adapters.is_empty() {
        return Err(BoundaryConfigError::InvalidLayers(
            "preset \"hexagonal\" needs at least one crate assigned to each of \"core\", \"ports\", \"adapters\"".to_string(),
        ));
    }

    Ok(vec![
        BoundaryRule {
            name: "preset:hexagonal:core".to_string(),
            from: core.clone(),
            forbidden: adapters.clone(),
            required: Vec::new(),
            reach: Reach::Direct,
            allow_empty: false,
        },
        BoundaryRule {
            name: "preset:hexagonal:adapters".to_string(),
            from: adapters,
            forbidden: core,
            required: ports,
            reach: Reach::Direct,
            allow_empty: false,
        },
    ])
}

/// `feature-sliced`: every non-`shared` group is mutually isolated from
/// every other non-`shared` group (forbidden, both directions); `shared`
/// crates aren't restricted, and any group may reach them.
fn generate_feature_sliced_rules(
    layers: &LayersConfig,
    assigned: &[(&str, &str)],
) -> Result<Vec<BoundaryRule>, BoundaryConfigError> {
    if assigned.is_empty() {
        return Err(BoundaryConfigError::InvalidLayers(
            "preset \"feature-sliced\" needs at least one crate in `layers.assign`".to_string(),
        ));
    }
    let mut groups: Vec<&str> = assigned.iter().map(|(_, group)| *group).collect();
    groups.sort();
    groups.dedup();

    if let Some(shared) = &layers.shared
        && !groups.contains(&shared.as_str())
    {
        return Err(BoundaryConfigError::InvalidLayers(format!(
            "`layers.shared = \"{shared}\"` does not match any group in `layers.assign`"
        )));
    }

    let non_shared: Vec<&str> = groups
        .into_iter()
        .filter(|group| Some(*group) != layers.shared.as_deref())
        .collect();
    if non_shared.len() < 2 {
        return Err(BoundaryConfigError::InvalidLayers(
            "preset \"feature-sliced\" needs at least 2 non-shared groups in `layers.assign`"
                .to_string(),
        ));
    }

    let mut rules = Vec::new();
    for &from_group in &non_shared {
        let from = group_crates(assigned, from_group);
        let forbidden: Vec<String> = non_shared
            .iter()
            .filter(|&&group| group != from_group)
            .flat_map(|group| group_crates(assigned, group))
            .collect();
        rules.push(BoundaryRule {
            name: format!("preset:feature-sliced:{from_group}"),
            from,
            forbidden,
            required: Vec::new(),
            reach: Reach::Transitive,
            allow_empty: false,
        });
    }
    Ok(rules)
}

/// Expands `[layers]` into the [`BoundaryRule`]s its preset implies (see
/// todo.md §9). Validates that every crate named in `assign` exists in the
/// workspace and that the preset's required roles/order are satisfied,
/// before generating anything — an invalid `[layers]` config is an exit-2
/// condition, same as an invalid `[[boundary]]` rule.
fn generate_layer_rules(
    layers: &LayersConfig,
    crate_names: &HashSet<&str>,
) -> Result<Vec<BoundaryRule>, BoundaryConfigError> {
    let mut assigned: Vec<(&str, &str)> = layers
        .assign
        .iter()
        .map(|(krate, group)| (krate.as_str(), group.as_str()))
        .collect();
    assigned.sort();

    for (krate, _) in &assigned {
        if !crate_names.contains(krate) {
            return Err(BoundaryConfigError::UnknownCrate {
                rule: "layers".to_string(),
                crate_name: (*krate).to_string(),
            });
        }
    }

    match layers.preset {
        LayerPreset::Layered => generate_layered_rules(layers, &assigned),
        LayerPreset::Hexagonal => generate_hexagonal_rules(&assigned),
        LayerPreset::FeatureSliced => generate_feature_sliced_rules(layers, &assigned),
    }
}

/// Evaluates every rule in `config` against `workspace`'s crate dependency
/// graph, plus a whole-graph cycle scan, and returns the resulting findings.
/// Fails with [`BoundaryConfigError`] if a rule's config is invalid — that is
/// an exit-2 condition for the caller, not a finding.
pub fn evaluate(
    workspace: &Workspace,
    config: &BoundaryConfig,
) -> Result<WorkspaceBoundaries, BoundaryConfigError> {
    let crate_names: HashSet<&str> = workspace
        .crates
        .iter()
        .map(|krate| krate.name.as_str())
        .collect();
    validate_config(config, &crate_names)?;
    validate_module_boundary_config(config, &crate_names)?;
    let layer_rules = match &config.layers {
        Some(layers) => generate_layer_rules(layers, &crate_names)?,
        None => Vec::new(),
    };

    let manifest = workspace.root.join("Cargo.toml");
    let graph = build_crate_graph(Some(&manifest))?;
    let cargo_toml = workspace.root.join("Cargo.toml");

    let mut findings = Vec::new();
    for rule in &config.boundaries {
        findings.extend(evaluate_rule(rule, &graph, &cargo_toml));
    }
    if let Some(layers) = &config.layers {
        let preset_source = format!("preset:{}", layers.preset.label());
        for rule in &layer_rules {
            for mut finding in evaluate_rule(rule, &graph, &cargo_toml) {
                finding.evidence = Some(serde_json::json!({ "source": preset_source }));
                findings.push(finding);
            }
        }
    }
    for cycle in find_cycles(&graph) {
        findings.push(cycle_finding(&cycle, &cargo_toml));
    }
    for rule in &config.module_boundaries {
        if let Some(krate) = workspace
            .crates
            .iter()
            .find(|krate| krate.name == rule.krate)
        {
            findings.extend(evaluate_module_boundary_rule(rule, krate));
        }
    }

    Ok(WorkspaceBoundaries { findings })
}

/// Breadth-first search from `start` over `graph`, returning every crate
/// name reachable (excluding `start` itself) plus BFS parent pointers for
/// shortest-path reconstruction. Neighbors are visited in the order
/// `CrateGraph::edges` lists them (sorted), so the result is deterministic.
fn bfs_from(graph: &CrateGraph, start: &str) -> (HashSet<String>, HashMap<String, String>) {
    let mut visited: HashSet<String> = HashSet::new();
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    visited.insert(start.to_string());
    queue.push_back(start.to_string());

    while let Some(current) = queue.pop_front() {
        if let Some(neighbors) = graph.edges.get(current.as_str()) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    parent.insert(neighbor.clone(), current.clone());
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    visited.remove(start);
    (visited, parent)
}

/// Reconstructs the shortest path from `start` to `target` using BFS parent
/// pointers produced by [`bfs_from`].
fn reconstruct_path(parent: &HashMap<String, String>, start: &str, target: &str) -> Vec<String> {
    let mut path = vec![target.to_string()];
    let mut current = target.to_string();
    while current != start {
        let Some(prev) = parent.get(&current) else {
            break;
        };
        path.push(prev.clone());
        current = prev.clone();
    }
    path.reverse();
    path
}

/// Evaluates a single rule for every crate in its `from` list, producing one
/// [`Finding`] per forbidden-edge violation (with a representative path) and
/// at most one per `from` crate for a missing required dependency.
fn evaluate_rule(rule: &BoundaryRule, graph: &CrateGraph, cargo_toml: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for from in &rule.from {
        match rule.reach {
            Reach::Direct => {
                let neighbors: &[String] = graph
                    .edges
                    .get(from.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                for forbidden in &rule.forbidden {
                    if neighbors.iter().any(|n| n == forbidden) {
                        let path = vec![from.clone(), forbidden.clone()];
                        findings.push(violation_finding(rule, &path, cargo_toml));
                    }
                }
                if !rule.required.is_empty()
                    && !rule
                        .required
                        .iter()
                        .any(|r| neighbors.iter().any(|n| n == r))
                {
                    findings.push(missing_required_finding(rule, from, cargo_toml));
                }
            }
            Reach::Transitive => {
                let (reachable, parent) = bfs_from(graph, from);
                for forbidden in &rule.forbidden {
                    if reachable.contains(forbidden) {
                        let path = reconstruct_path(&parent, from, forbidden);
                        findings.push(violation_finding(rule, &path, cargo_toml));
                    }
                }
                if !rule.required.is_empty() && !rule.required.iter().any(|r| reachable.contains(r))
                {
                    findings.push(missing_required_finding(rule, from, cargo_toml));
                }
            }
        }
    }

    findings
}

fn violation_finding(rule: &BoundaryRule, path: &[String], cargo_toml: &Path) -> Finding {
    let path_str = path.join(" -> ");
    Finding {
        id: format!("{BOUNDARY_VIOLATION_RULE}:{}:{path_str}", rule.name).into(),
        rule: BOUNDARY_VIOLATION_RULE.into(),
        severity: Severity::Fail,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: OneBasedLine::FIRST,
            item_path: format!("{} [{}]: {path_str}", rule.name, rule.reach.label()),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

fn missing_required_finding(rule: &BoundaryRule, from: &str, cargo_toml: &Path) -> Finding {
    Finding {
        id: format!(
            "{BOUNDARY_VIOLATION_RULE}:{}:missing-required:{from}",
            rule.name
        )
        .into(),
        rule: BOUNDARY_VIOLATION_RULE.into(),
        severity: Severity::Fail,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: OneBasedLine::FIRST,
            item_path: format!(
                "{} [{}]: {from} does not reach any of [{}]",
                rule.name,
                rule.reach.label(),
                rule.required.join(", ")
            ),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

fn cycle_finding(cycle: &[String], cargo_toml: &Path) -> Finding {
    let path_str = cycle.join(" -> ");
    Finding {
        id: format!("{DEPENDENCY_CYCLE_RULE}:{path_str}").into(),
        rule: DEPENDENCY_CYCLE_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: OneBasedLine::FIRST,
            item_path: path_str,
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

// --- Module-level boundaries (`[[module_boundary]]`) --------------------
//
// See module docs "Module-level boundaries" for the two Fast-Tier
// limitations this section implements: directory-convention module path
// resolution, and direct-reach-only checking.

/// Derives a source file's module path purely from its position under
/// `crate_root/src/` — a directory-convention heuristic, not `mod`-graph
/// resolution (see module docs "Module-level boundaries"). Rust 2018+
/// convention: `src/foo/bar.rs` -> `Some("foo::bar")`, `src/foo.rs` ->
/// `Some("foo")`, `src/foo/mod.rs` -> `Some("foo")` (the older but still
/// valid `mod.rs` convention), `src/lib.rs`/`src/main.rs`/`src/bin/*.rs` ->
/// `Some("")` (the crate root module). Anything not under `src/` (e.g.
/// `build.rs`) returns `None` — it has no place in a module tree
/// `[[module_boundary]]` can reason about.
fn module_path_for_file(crate_root: &Path, file_path: &Path) -> Option<String> {
    let relative = file_path.strip_prefix(crate_root).ok()?;
    let mut components: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if components.first().map(String::as_str) != Some("src") {
        return None;
    }
    components.remove(0);
    if components.is_empty() {
        return None;
    }
    if components.len() == 1 && matches!(components[0].as_str(), "lib.rs" | "main.rs") {
        return Some(String::new());
    }
    if components.first().map(String::as_str) == Some("bin") {
        return Some(String::new());
    }

    let last = components.last().cloned()?;
    if last == "mod.rs" {
        components.pop();
    } else if let Some(stem) = last.strip_suffix(".rs") {
        let stem = stem.to_string();
        *components.last_mut().expect("just checked non-empty") = stem;
    } else {
        return None;
    }
    Some(components.join("::"))
}

/// Whether `module_path` is `prefix` itself, or a descendant of it — a
/// `::`-segment prefix match, not a raw string prefix match (`"io"` must not
/// match `"ioutils"`).
fn module_path_under(module_path: &str, prefix: &str) -> bool {
    module_path == prefix || module_path.starts_with(&format!("{prefix}::"))
}

/// Whether `segments` (a fully crate-root-relative path, see
/// [`resolve_leading_segments`]) references something under `forbidden` — a
/// `::`-segment prefix match against `forbidden`'s own segments.
fn segments_match_forbidden(segments: &[String], forbidden: &str) -> bool {
    let forbidden_segments: Vec<&str> = forbidden.split("::").collect();
    if segments.len() < forbidden_segments.len() {
        return false;
    }
    segments
        .iter()
        .zip(forbidden_segments.iter())
        .all(|(segment, forbidden_segment)| segment == forbidden_segment)
}

/// Resolves a raw identifier-segment chain (from a `use` tree leaf or a
/// `syn::Path`) to a crate-root-relative module path, if and only if its
/// leading segment is `crate` or (one or more) `super` — see module docs
/// "Module-level boundaries": these are the only two forms judge resolves
/// without full `mod`-graph resolution. Any other leading segment (a local,
/// unqualified reference relative to the *current* module, an external
/// crate name, or `self`) returns `None` — not a violation judge can prove
/// without guessing.
fn resolve_leading_segments(
    current_module: &str,
    mut segments: Vec<String>,
) -> Option<Vec<String>> {
    if segments.is_empty() {
        return None;
    }
    let head = segments.remove(0);
    let mut resolved: Vec<String> = match head.as_str() {
        "crate" => Vec::new(),
        "super" => {
            let mut parts = current_module_segments(current_module);
            parts.pop()?;
            parts
        }
        _ => return None,
    };
    while segments.first().map(String::as_str) == Some("super") {
        segments.remove(0);
        resolved.pop()?;
    }
    resolved.extend(segments);
    Some(resolved)
}

fn current_module_segments(current_module: &str) -> Vec<String> {
    if current_module.is_empty() {
        Vec::new()
    } else {
        current_module.split("::").map(str::to_string).collect()
    }
}

/// Collects every leaf path of a `use` tree as a flat segment chain,
/// including its leading identifier (`crate`, `super`, an external crate
/// name, ...) — mirrors `deps.rs`'s `DepItemCollector::walk_use_tree`, one
/// level shallower (it records the whole chain, not just one segment past a
/// target). A `use a::{b, c::d}` yields `[["a", "b"], ["a", "c", "d"]]`; a
/// glob `use a::*` yields `[["a"]]` (no synthetic wildcard segment).
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

/// Collects every `(line, forbidden target matched)` hit in one parsed file,
/// scanning `use` statements and `crate::`/`super::`-qualified path
/// expressions (see [`resolve_leading_segments`]).
struct ModuleBoundaryCollector<'a> {
    current_module: &'a str,
    forbidden: &'a [String],
    hits: Vec<(usize, String)>,
}

impl ModuleBoundaryCollector<'_> {
    fn record_if_forbidden(&mut self, segments: &[String], line: usize) {
        if let Some(forbidden) = self
            .forbidden
            .iter()
            .find(|forbidden| segments_match_forbidden(segments, forbidden))
        {
            self.hits.push((line, forbidden.clone()));
        }
    }
}

impl<'ast> Visit<'ast> for ModuleBoundaryCollector<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let mut leaves = Vec::new();
        use_tree_leaf_segments(&node.tree, &mut Vec::new(), &mut leaves);
        let line = node.span().start().line;
        for leaf in leaves {
            if let Some(resolved) = resolve_leading_segments(self.current_module, leaf) {
                self.record_if_forbidden(&resolved, line);
            }
        }
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        let segments: Vec<String> = node.segments.iter().map(|s| s.ident.to_string()).collect();
        if let Some(resolved) = resolve_leading_segments(self.current_module, segments) {
            self.record_if_forbidden(&resolved, node.span().start().line);
        }
        visit::visit_path(self, node);
    }
}

/// Evaluates one `[[module_boundary]]` rule against every source file of
/// `krate` whose derived module path (see [`module_path_for_file`]) falls
/// under `rule.from`. Files that fail to read or parse are silently skipped
/// — this is advisory (`bounded_semantic`, not a completeness proof)
/// evidence within the examined view, matching how `deps.rs`'s
/// `collect_used_items` treats the same failure mode. One finding per
/// violating file, at its earliest offending line — "a violation" is a file
/// referencing a forbidden module, not each individual reference.
fn evaluate_module_boundary_rule(rule: &ModuleBoundaryRule, krate: &CrateInfo) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in &krate.source_files {
        let Some(module_path) = module_path_for_file(&krate.root, &file.path) else {
            continue;
        };
        if !module_path_under(&module_path, &rule.from) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&file.path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&source) else {
            continue;
        };
        let mut collector = ModuleBoundaryCollector {
            current_module: &module_path,
            forbidden: &rule.forbidden,
            hits: Vec::new(),
        };
        collector.visit_file(&ast);
        if let Some((line, forbidden)) = collector.hits.into_iter().min_by_key(|(line, _)| *line) {
            findings.push(module_boundary_finding(
                rule,
                &file.path,
                line,
                &module_path,
                &forbidden,
            ));
        }
    }
    findings
}

/// Renders a `module-boundary-violation` finding. `evidence_class` is
/// `bounded_semantic` — an explicitly configured edge over a heuristically
/// derived module view (see module docs "Module-level boundaries"), the
/// same class as `crate-boundary-violation` but with that extra unsureness
/// named honestly in `evidence`.
fn module_boundary_finding(
    rule: &ModuleBoundaryRule,
    file: &Path,
    line: usize,
    module_path: &str,
    forbidden: &str,
) -> Finding {
    let line = OneBasedLine::new(line).unwrap_or(OneBasedLine::FIRST);
    Finding {
        id: format!(
            "{MODULE_BOUNDARY_VIOLATION_RULE}:{}:{}:{line}",
            rule.name,
            file.display()
        )
        .into(),
        rule: MODULE_BOUNDARY_VIOLATION_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line,
            item_path: format!("{} [direct]: {module_path} -> {forbidden}", rule.name),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "module_path_resolution": "directory-convention heuristic, not module-graph resolution — e.g. #[path = \"...\"] attributes are not recognized"
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Finds every simple cycle in the whole `graph` (not scoped to any one rule).
/// Each DFS is rooted at the lexicographically smallest node permitted in that
/// traversal, so rotations of the same directed cycle are produced once.
pub fn find_cycles(graph: &CrateGraph) -> Vec<Vec<String>> {
    let mut node_names: Vec<String> = graph.edges.keys().cloned().collect();
    node_names.sort();

    fn visit_from(
        start: &str,
        current: &str,
        graph: &CrateGraph,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut HashSet<Vec<String>>,
    ) {
        if let Some(neighbors) = graph.edges.get(current) {
            for neighbor in neighbors {
                if neighbor == start {
                    let mut cycle = path.clone();
                    cycle.push(start.to_string());
                    cycles.insert(cycle);
                } else if neighbor.as_str() >= start && visited.insert(neighbor.clone()) {
                    path.push(neighbor.clone());
                    visit_from(start, neighbor, graph, visited, path, cycles);
                    path.pop();
                    visited.remove(neighbor);
                }
            }
        }
    }

    let mut found = HashSet::new();
    for start in &node_names {
        let mut visited = HashSet::from([start.clone()]);
        let mut path = vec![start.clone()];
        visit_from(start, start, graph, &mut visited, &mut path, &mut found);
    }

    let mut cycles: Vec<Vec<String>> = found.into_iter().collect();
    cycles.sort();
    cycles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn write_crate(dir: &TempDir, name: &str, deps: &[(&str, &str)]) {
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
        std::fs::write(
            dir.join(name).join("src/lib.rs"),
            format!("pub fn {name}() {{}}\n"),
        )
        .unwrap();
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

    fn rule(name: &str, from: &[&str], reach: Reach) -> BoundaryRule {
        BoundaryRule {
            name: name.to_string(),
            from: from.iter().map(|s| s.to_string()).collect(),
            forbidden: Vec::new(),
            required: Vec::new(),
            reach,
            allow_empty: false,
        }
    }

    #[test]
    fn transitive_forbidden_violation_reports_the_shortest_path() {
        let dir = TempDir::new("boundaries-transitive");
        write_crate(&dir, "ui", &[("core", "../core")]);
        write_crate(&dir, "core", &[("db", "../db")]);
        write_crate(&dir, "db", &[]);
        write_workspace_manifest(&dir, &["ui", "core", "db"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("ui-must-not-touch-db", &["ui"], Reach::Transitive);
        r.forbidden = vec!["db".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.rule, BOUNDARY_VIOLATION_RULE);
        assert_eq!(finding.severity, Severity::Fail);
        assert!(finding.location.item_path.contains("ui -> core -> db"));
    }

    #[test]
    fn direct_reach_does_not_flag_a_transitive_only_dependency() {
        let dir = TempDir::new("boundaries-direct-no-violation");
        write_crate(&dir, "ui", &[("core", "../core")]);
        write_crate(&dir, "core", &[("db", "../db")]);
        write_crate(&dir, "db", &[]);
        write_workspace_manifest(&dir, &["ui", "core", "db"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("ui-must-not-touch-db-direct", &["ui"], Reach::Direct);
        r.forbidden = vec!["db".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(result.findings.is_empty());
    }

    #[test]
    fn crate_boundary_violation_fires_regardless_of_cfg_gating_on_the_dependency_declaration() {
        // `crate-boundary-violation` is deliberately scoped to what
        // `cargo_metadata` reports for a crate's declared dependencies (see
        // module docs) — it never inspects the actual code, so it cannot be
        // cfg-aware either. `cargo metadata` (without `--filter-platform`,
        // which `build_crate_graph` never passes) reports every
        // `[target.'cfg(...)'.dependencies]` entry unconditionally,
        // regardless of the host running judge. This test documents that: a
        // dependency gated to `cfg(target_os = "windows")` still produces a
        // graph edge — and therefore still fires the rule — even though this
        // test itself does not run on Windows.
        let dir = TempDir::new("boundaries-cfg-gated-dependency");
        std::fs::create_dir_all(dir.join("ui").join("src")).unwrap();
        std::fs::write(
            dir.join("ui").join("Cargo.toml"),
            "[package]\nname = \"ui\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[target.'cfg(target_os = \"windows\")'.dependencies]\ndb = { path = \"../db\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("ui").join("src/lib.rs"), "pub fn ui() {}\n").unwrap();
        write_crate(&dir, "db", &[]);
        write_workspace_manifest(&dir, &["ui", "db"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("ui-must-not-touch-db", &["ui"], Reach::Direct);
        r.forbidden = vec!["db".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule, BOUNDARY_VIOLATION_RULE);
    }

    #[test]
    fn required_rule_violates_when_unreachable() {
        let dir = TempDir::new("boundaries-required-missing");
        write_crate(&dir, "core", &[]);
        write_crate(&dir, "io-abstraction", &[]);
        write_workspace_manifest(&dir, &["core", "io-abstraction"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("core-needs-approved-io", &["core"], Reach::Direct);
        r.required = vec!["io-abstraction".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule, BOUNDARY_VIOLATION_RULE);
    }

    #[test]
    fn required_rule_passes_when_reachable_direct() {
        let dir = TempDir::new("boundaries-required-direct-ok");
        write_crate(&dir, "io-abstraction", &[]);
        write_crate(&dir, "core", &[("io-abstraction", "../io-abstraction")]);
        write_workspace_manifest(&dir, &["core", "io-abstraction"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("core-needs-approved-io", &["core"], Reach::Direct);
        r.required = vec!["io-abstraction".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(result.findings.is_empty());
    }

    #[test]
    fn required_rule_passes_when_reachable_transitively() {
        let dir = TempDir::new("boundaries-required-transitive-ok");
        write_crate(&dir, "io-abstraction", &[]);
        write_crate(&dir, "core", &[("mid", "../mid")]);
        write_crate(&dir, "mid", &[("io-abstraction", "../io-abstraction")]);
        write_workspace_manifest(&dir, &["core", "mid", "io-abstraction"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("core-needs-approved-io", &["core"], Reach::Transitive);
        r.required = vec!["io-abstraction".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(result.findings.is_empty());
    }

    #[test]
    fn a_rule_naming_an_unknown_crate_is_a_config_error_by_default() {
        let dir = TempDir::new("boundaries-unknown-crate");
        write_crate(&dir, "ui", &[]);
        write_workspace_manifest(&dir, &["ui"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("ui-must-not-touch-db", &["ui"], Reach::Transitive);
        r.forbidden = vec!["db".to_string()]; // "db" isn't a workspace crate
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let err = evaluate(&workspace, &config).unwrap_err();
        assert!(matches!(err, BoundaryConfigError::UnknownCrate { .. }));
    }

    #[test]
    fn allow_empty_permits_a_rule_naming_an_unknown_crate() {
        let dir = TempDir::new("boundaries-unknown-crate-allowed");
        write_crate(&dir, "ui", &[]);
        write_workspace_manifest(&dir, &["ui"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut r = rule("ui-must-not-touch-db", &["ui"], Reach::Transitive);
        r.forbidden = vec!["db".to_string()];
        r.allow_empty = true;
        let config = BoundaryConfig {
            boundaries: vec![r],
            crate_profiles: Vec::new(),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn a_real_circular_workspace_produces_exactly_one_deduped_cycle_finding() {
        // Verified separately that `cargo metadata --no-deps` parses a
        // circular path-dependency workspace without error even though it
        // wouldn't build — so this goes through the real ingest/metadata
        // pipeline rather than a synthetic CrateGraph.
        let dir = TempDir::new("boundaries-cycle");
        write_crate(&dir, "a", &[("b", "../b")]);
        write_crate(&dir, "b", &[("a", "../a")]);
        write_workspace_manifest(&dir, &["a", "b"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig::default();

        let result = evaluate(&workspace, &config).unwrap();

        let cycle_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule == DEPENDENCY_CYCLE_RULE)
            .collect();
        assert_eq!(cycle_findings.len(), 1);
        assert_eq!(cycle_findings[0].severity, Severity::Warn);
    }

    #[test]
    fn dependency_cycle_fires_for_a_cycle_formed_only_through_a_dev_dependency() {
        // `CrateGraph::edges`'s doc comment states dependency `kind`
        // (normal/dev/build) doesn't matter — every kind counts as an
        // architectural edge. This documents that in practice: `a` depends
        // on `b` normally, `b` depends on `a` only as a `[dev-dependencies]`
        // entry (which never causes a real build-graph cycle, since dev-deps
        // aren't used to build `b` itself) — `dependency-cycle` still fires,
        // because `build_crate_graph` does not distinguish dependency kinds.
        let dir = TempDir::new("boundaries-dev-dependency-cycle");
        std::fs::create_dir_all(dir.join("a").join("src")).unwrap();
        std::fs::write(
            dir.join("a").join("Cargo.toml"),
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nb = { path = \"../b\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("a").join("src/lib.rs"), "pub fn a() {}\n").unwrap();
        std::fs::create_dir_all(dir.join("b").join("src")).unwrap();
        std::fs::write(
            dir.join("b").join("Cargo.toml"),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dev-dependencies]\na = { path = \"../a\" }\n",
        )
        .unwrap();
        std::fs::write(dir.join("b").join("src/lib.rs"), "pub fn b() {}\n").unwrap();
        write_workspace_manifest(&dir, &["a", "b"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig::default();

        let result = evaluate(&workspace, &config).unwrap();

        let cycle_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule == DEPENDENCY_CYCLE_RULE)
            .collect();
        assert_eq!(cycle_findings.len(), 1);
    }

    #[test]
    fn find_cycles_dedupes_rotations_of_the_same_cycle() {
        let mut edges = HashMap::new();
        edges.insert("a".to_string(), vec!["b".to_string()]);
        edges.insert("b".to_string(), vec!["c".to_string()]);
        edges.insert("c".to_string(), vec!["a".to_string()]);
        let graph = CrateGraph { edges };

        let cycles = find_cycles(&graph);

        assert_eq!(cycles.len(), 1);
        assert_eq!(
            cycles[0],
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "a".to_string()
            ]
        );
    }

    #[test]
    fn find_cycles_returns_empty_for_an_acyclic_graph() {
        let mut edges = HashMap::new();
        edges.insert("a".to_string(), vec!["b".to_string()]);
        edges.insert("b".to_string(), vec!["c".to_string()]);
        edges.insert("c".to_string(), vec![]);
        let graph = CrateGraph { edges };

        assert!(find_cycles(&graph).is_empty());
    }

    #[test]
    fn find_cycles_reports_overlapping_cycles() {
        let graph = CrateGraph {
            edges: HashMap::from([
                ("a".to_string(), vec!["b".to_string(), "c".to_string()]),
                ("b".to_string(), vec!["c".to_string()]),
                ("c".to_string(), vec!["a".to_string()]),
            ]),
        };

        let cycles = find_cycles(&graph);

        assert_eq!(
            cycles,
            vec![
                vec!["a", "b", "c", "a"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
                vec!["a", "c", "a"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            ]
        );
    }

    #[test]
    fn toml_from_str_round_trips_a_judge_toml_fixture() {
        let source = r#"
[[boundary]]
name = "ui-must-not-touch-db"
from = ["ui"]
forbidden = ["db"]
reach = "transitive"

[[boundary]]
name = "core-needs-approved-io"
from = ["core"]
required = ["io-abstraction"]
reach = "direct"
allow_empty = false
"#;
        let config: BoundaryConfig = toml::from_str(source).unwrap();

        assert_eq!(config.boundaries.len(), 2);
        assert_eq!(config.boundaries[0].name, "ui-must-not-touch-db");
        assert_eq!(config.boundaries[0].from, vec!["ui".to_string()]);
        assert_eq!(config.boundaries[0].forbidden, vec!["db".to_string()]);
        assert!(config.boundaries[0].required.is_empty());
        assert_eq!(config.boundaries[0].reach, Reach::Transitive);
        assert!(!config.boundaries[0].allow_empty);

        assert_eq!(config.boundaries[1].name, "core-needs-approved-io");
        assert_eq!(
            config.boundaries[1].required,
            vec!["io-abstraction".to_string()]
        );
        assert_eq!(config.boundaries[1].reach, Reach::Direct);
        assert!(!config.boundaries[1].allow_empty);
    }

    #[test]
    fn toml_from_str_round_trips_crate_profiles() {
        let source = r#"
[[crate_profile]]
name = "lenient"
crates = ["parser"]
deduction_multiplier = 0.5

[[crate_profile]]
name = "strict"
crates = ["cli"]
"#;
        let config: BoundaryConfig = toml::from_str(source).unwrap();

        assert_eq!(config.crate_profiles.len(), 2);
        assert_eq!(config.crate_profiles[0].name, "lenient");
        assert_eq!(config.crate_profiles[0].crates, vec!["parser".to_string()]);
        assert_eq!(config.crate_profiles[0].deduction_multiplier.value(), 0.5);
        // Missing `deduction_multiplier` defaults to 1.0.
        assert_eq!(config.crate_profiles[1].deduction_multiplier.value(), 1.0);
    }

    #[test]
    fn toml_from_str_round_trips_provenance_labels() {
        let source = r#"
[[provenance_label]]
name = "contractor-x"
trailer_contains = ["contractor-x@example.com"]
author_email_contains = ["contractor-x@example.com"]

[[provenance_label]]
name = "internal-bot"
trailer_contains = ["internal-ci-bot"]
"#;
        let config: BoundaryConfig = toml::from_str(source).unwrap();

        assert_eq!(config.provenance.labels.len(), 2);
        assert_eq!(config.provenance.labels[0].name, "contractor-x");
        assert_eq!(
            config.provenance.labels[0].trailer_contains,
            vec!["contractor-x@example.com".to_string()]
        );
        assert_eq!(
            config.provenance.labels[0].author_email_contains,
            vec!["contractor-x@example.com".to_string()]
        );
        assert_eq!(config.provenance.labels[1].name, "internal-bot");
        assert!(config.provenance.labels[1].author_email_contains.is_empty());
    }

    #[test]
    fn toml_from_str_round_trips_catch_all_error_rule_config() {
        let source = r#"
[rules.catch-all-error]
allow-anyhow-at-boundary = true
"#;
        let config: BoundaryConfig = toml::from_str(source).unwrap();

        assert!(config.rules.catch_all_error.allow_anyhow_at_boundary);
    }

    #[test]
    fn missing_rules_table_defaults_to_false() {
        let config: BoundaryConfig = toml::from_str("").unwrap();

        assert!(!config.rules.catch_all_error.allow_anyhow_at_boundary);
    }

    #[test]
    fn boundary_config_error_source_preserves_the_metadata_error() {
        let err =
            build_crate_graph(Some(Path::new("/nonexistent/judge-test/Cargo.toml"))).unwrap_err();
        let source = std::error::Error::source(&err).expect("Metadata must carry a source");
        assert!(source.downcast_ref::<cargo_metadata::Error>().is_some());
    }

    #[test]
    fn toml_from_str_round_trips_a_layers_preset_fixture() {
        let source = r#"
[layers]
preset = "layered"
order = ["domain", "application", "infrastructure"]

[layers.assign]
"core-domain" = "domain"
"app-service" = "application"
"infra-io" = "infrastructure"
"#;
        let config: BoundaryConfig = toml::from_str(source).unwrap();

        let layers = config.layers.expect("layers table must be present");
        assert_eq!(layers.preset, LayerPreset::Layered);
        assert_eq!(
            layers.order,
            vec![
                "domain".to_string(),
                "application".to_string(),
                "infrastructure".to_string()
            ]
        );
        assert_eq!(
            layers.assign.get("core-domain").map(String::as_str),
            Some("domain")
        );
        assert!(layers.shared.is_none());
    }

    fn layers_config(
        preset: LayerPreset,
        order: &[&str],
        shared: Option<&str>,
        assign: &[(&str, &str)],
    ) -> LayersConfig {
        LayersConfig {
            preset,
            order: order.iter().map(|s| s.to_string()).collect(),
            shared: shared.map(str::to_string),
            assign: assign
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn layered_preset_flags_inner_layer_reaching_outer_layer() {
        let dir = TempDir::new("layers-layered-violation");
        write_crate(&dir, "core-domain", &[("app-service", "../app-service")]);
        write_crate(&dir, "app-service", &[]);
        write_crate(&dir, "infra-io", &[]);
        write_workspace_manifest(&dir, &["core-domain", "app-service", "infra-io"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            layers: Some(layers_config(
                LayerPreset::Layered,
                &["domain", "application", "infrastructure"],
                None,
                &[
                    ("core-domain", "domain"),
                    ("app-service", "application"),
                    ("infra-io", "infrastructure"),
                ],
            )),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.rule, BOUNDARY_VIOLATION_RULE);
        assert!(
            finding
                .location
                .item_path
                .contains("core-domain -> app-service")
        );
        assert_eq!(
            finding.evidence,
            Some(serde_json::json!({ "source": "preset:layered" }))
        );
    }

    #[test]
    fn layered_preset_allows_outer_layer_reaching_inner_layer() {
        let dir = TempDir::new("layers-layered-allowed");
        write_crate(&dir, "core-domain", &[]);
        write_crate(&dir, "app-service", &[("core-domain", "../core-domain")]);
        write_crate(&dir, "infra-io", &[]);
        write_workspace_manifest(&dir, &["core-domain", "app-service", "infra-io"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            layers: Some(layers_config(
                LayerPreset::Layered,
                &["domain", "application", "infrastructure"],
                None,
                &[
                    ("core-domain", "domain"),
                    ("app-service", "application"),
                    ("infra-io", "infrastructure"),
                ],
            )),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(result.findings.is_empty());
    }

    #[test]
    fn feature_sliced_preset_flags_cross_group_reference_but_allows_shared() {
        let dir = TempDir::new("layers-feature-sliced");
        write_crate(
            &dir,
            "feature-a",
            &[("feature-b", "../feature-b"), ("common", "../common")],
        );
        write_crate(&dir, "feature-b", &[("common", "../common")]);
        write_crate(&dir, "common", &[]);
        write_workspace_manifest(&dir, &["feature-a", "feature-b", "common"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            layers: Some(layers_config(
                LayerPreset::FeatureSliced,
                &[],
                Some("shared"),
                &[
                    ("feature-a", "group-a"),
                    ("feature-b", "group-b"),
                    ("common", "shared"),
                ],
            )),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.rule, BOUNDARY_VIOLATION_RULE);
        assert!(
            finding
                .location
                .item_path
                .contains("feature-a -> feature-b")
        );
        assert_eq!(
            finding.evidence,
            Some(serde_json::json!({ "source": "preset:feature-sliced" }))
        );
    }

    #[test]
    fn hexagonal_preset_flags_core_reaching_adapters() {
        let dir = TempDir::new("layers-hexagonal");
        write_crate(&dir, "core-crate", &[("adapter-crate", "../adapter-crate")]);
        write_crate(&dir, "adapter-crate", &[("port-crate", "../port-crate")]);
        write_crate(&dir, "port-crate", &[]);
        write_workspace_manifest(&dir, &["core-crate", "adapter-crate", "port-crate"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            layers: Some(layers_config(
                LayerPreset::Hexagonal,
                &[],
                None,
                &[
                    ("core-crate", "core"),
                    ("adapter-crate", "adapters"),
                    ("port-crate", "ports"),
                ],
            )),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.rule, BOUNDARY_VIOLATION_RULE);
        assert!(
            finding
                .location
                .item_path
                .contains("core-crate -> adapter-crate")
        );
        assert_eq!(
            finding.evidence,
            Some(serde_json::json!({ "source": "preset:hexagonal" }))
        );
    }

    #[test]
    fn unknown_crate_in_layers_assign_is_a_config_error() {
        let dir = TempDir::new("layers-unknown-crate");
        write_crate(&dir, "ui", &[]);
        write_workspace_manifest(&dir, &["ui"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            layers: Some(layers_config(
                LayerPreset::Layered,
                &["domain", "application"],
                None,
                &[("does-not-exist", "domain")],
            )),
            ..Default::default()
        };

        let err = evaluate(&workspace, &config).unwrap_err();
        assert!(matches!(err, BoundaryConfigError::UnknownCrate { .. }));
    }

    #[test]
    fn handwritten_boundary_rule_and_layers_preset_both_fire() {
        let dir = TempDir::new("layers-and-handwritten-boundary");
        write_crate(&dir, "ui", &[("db", "../db")]);
        write_crate(&dir, "db", &[]);
        write_crate(&dir, "core-domain", &[("app-service", "../app-service")]);
        write_crate(&dir, "app-service", &[]);
        write_workspace_manifest(&dir, &["ui", "db", "core-domain", "app-service"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut handwritten = rule("ui-must-not-touch-db", &["ui"], Reach::Direct);
        handwritten.forbidden = vec!["db".to_string()];
        let config = BoundaryConfig {
            boundaries: vec![handwritten],
            layers: Some(layers_config(
                LayerPreset::Layered,
                &["domain", "application"],
                None,
                &[("core-domain", "domain"), ("app-service", "application")],
            )),
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert_eq!(result.findings.len(), 2);
        let handwritten_finding = result
            .findings
            .iter()
            .find(|f| f.location.item_path.contains("ui -> db"))
            .expect("handwritten rule must still fire");
        assert!(handwritten_finding.evidence.is_none());

        let preset_finding = result
            .findings
            .iter()
            .find(|f| f.location.item_path.contains("core-domain -> app-service"))
            .expect("preset rule must also fire");
        assert_eq!(
            preset_finding.evidence,
            Some(serde_json::json!({ "source": "preset:layered" }))
        );
    }

    // --- [[module_boundary]] -------------------------------------------

    fn module_boundary_rule(
        name: &str,
        krate: &str,
        from: &str,
        forbidden: &[&str],
    ) -> ModuleBoundaryRule {
        ModuleBoundaryRule {
            name: name.to_string(),
            krate: krate.to_string(),
            from: from.to_string(),
            forbidden: forbidden.iter().map(|s| s.to_string()).collect(),
            reach: None,
        }
    }

    #[test]
    fn module_boundary_flags_a_forbidden_qualified_path_reference() {
        let dir = TempDir::new("module-boundary-violation");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod domain;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/domain")).unwrap();
        std::fs::write(
            dir.join("my-core/src/domain/mod.rs"),
            "pub fn run() {\n    crate::io::read_file();\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule == MODULE_BOUNDARY_VIOLATION_RULE)
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].evidence_class, EvidenceClass::BoundedSemantic);
        assert!(findings[0].location.item_path.contains("domain -> io"));
        assert!(findings[0].location.file.ends_with("src/domain/mod.rs"));
    }

    #[test]
    fn module_boundary_does_not_flag_a_domain_module_with_no_io_reference() {
        let dir = TempDir::new("module-boundary-clean");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod domain;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/domain")).unwrap();
        std::fs::write(
            dir.join("my-core/src/domain/mod.rs"),
            "pub fn run() -> u32 {\n    42\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(
            result
                .findings
                .iter()
                .all(|f| f.rule != MODULE_BOUNDARY_VIOLATION_RULE)
        );
    }

    #[test]
    fn module_boundary_does_not_flag_a_reference_from_outside_the_from_module() {
        let dir = TempDir::new("module-boundary-out-of-scope");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod application;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/application")).unwrap();
        std::fs::write(
            dir.join("my-core/src/application/mod.rs"),
            "pub fn run() {\n    crate::io::read_file();\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(
            result
                .findings
                .iter()
                .all(|f| f.rule != MODULE_BOUNDARY_VIOLATION_RULE)
        );
    }

    #[test]
    fn module_boundary_does_not_flag_a_self_qualified_path_reference() {
        // Module docs "Module-level boundaries" call out that module path
        // resolution only handles `crate::`/`super::`-leading paths (see
        // `resolve_leading_segments`) — `self::` is deliberately not one of
        // them. This documents the resulting false negative: a `self::`
        // qualified reference to something that would be a violation via
        // `crate::` is not recognized at all.
        let dir = TempDir::new("module-boundary-self-path");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod domain;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/domain")).unwrap();
        std::fs::write(
            dir.join("my-core/src/domain/mod.rs"),
            "pub fn run() {\n    self::io::read_file();\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(
            result
                .findings
                .iter()
                .all(|f| f.rule != MODULE_BOUNDARY_VIOLATION_RULE),
            "a `self::`-qualified reference is not resolved, so it is never flagged \
             even though the equivalent `crate::io::...` reference would be"
        );
    }

    #[test]
    fn module_boundary_misses_a_violation_in_a_file_relocated_via_path_attribute() {
        // Module docs "Module-level boundaries" call out that module path
        // resolution is a directory-convention heuristic, not `mod`-graph
        // resolution — a file wired in via `#[path = "..."]` is misplaced.
        // Here `src/domain/mod.rs` pulls in a submodule whose *physical*
        // file lives under `src/shared/`, via `#[path = "../shared/..."]`.
        // `module_path_for_file` derives the module path purely from the
        // file's position on disk, so it resolves to `shared::domain_impl`
        // — not `domain::domain_impl`, its logical position. A rule scoped
        // to `from = "domain"` therefore never examines this file at all,
        // even though it contains a real forbidden `crate::io` reference.
        let dir = TempDir::new("module-boundary-path-attribute");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod domain;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/domain")).unwrap();
        std::fs::write(
            dir.join("my-core/src/domain/mod.rs"),
            "#[path = \"../shared/domain_impl.rs\"]\nmod domain_impl;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/shared")).unwrap();
        std::fs::write(
            dir.join("my-core/src/shared/domain_impl.rs"),
            "pub fn run() {\n    crate::io::read_file();\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(
            result
                .findings
                .iter()
                .all(|f| f.rule != MODULE_BOUNDARY_VIOLATION_RULE),
            "the relocated file resolves to module path `shared::domain_impl`, \
             not `domain::domain_impl`, so it falls outside the rule's `from` scope \
             and the real crate::io reference inside it is missed"
        );
    }

    #[test]
    fn module_boundary_rule_naming_an_unknown_crate_is_a_config_error() {
        let dir = TempDir::new("module-boundary-unknown-crate");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "does-not-exist",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let err = evaluate(&workspace, &config).unwrap_err();
        assert!(matches!(err, BoundaryConfigError::UnknownCrate { .. }));
    }

    #[test]
    fn module_boundary_rule_with_empty_forbidden_is_a_config_error() {
        let dir = TempDir::new("module-boundary-empty-forbidden");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &[],
            )],
            ..Default::default()
        };

        let err = evaluate(&workspace, &config).unwrap_err();
        assert!(matches!(err, BoundaryConfigError::InvalidModuleBoundary(_)));
    }

    #[test]
    fn module_boundary_rule_with_transitive_reach_is_a_config_error() {
        let dir = TempDir::new("module-boundary-transitive-reach");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let mut rule = module_boundary_rule("domain-no-io", "my-core", "domain", &["io"]);
        rule.reach = Some(Reach::Transitive);
        let config = BoundaryConfig {
            module_boundaries: vec![rule],
            ..Default::default()
        };

        let err = evaluate(&workspace, &config).unwrap_err();
        match err {
            BoundaryConfigError::InvalidModuleBoundary(message) => {
                assert!(message.contains("direct reach"));
            }
            other => panic!("expected InvalidModuleBoundary, got {other:?}"),
        }
    }

    #[test]
    fn module_boundary_matches_nested_modules_under_from_by_prefix() {
        let dir = TempDir::new("module-boundary-nested");
        write_crate(&dir, "my-core", &[]);
        write_workspace_manifest(&dir, &["my-core"]);
        std::fs::write(
            dir.join("my-core/src/lib.rs"),
            "pub mod domain;\npub mod io;\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("my-core/src/domain/inner")).unwrap();
        std::fs::write(dir.join("my-core/src/domain/mod.rs"), "pub mod inner;\n").unwrap();
        std::fs::write(
            dir.join("my-core/src/domain/inner/thing.rs"),
            "pub fn run() {\n    crate::io::read_file();\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("my-core/src/io.rs"), "pub fn read_file() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-io",
                "my-core",
                "domain",
                &["io"],
            )],
            ..Default::default()
        };

        let result = evaluate(&workspace, &config).unwrap();

        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule == MODULE_BOUNDARY_VIOLATION_RULE)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .location
                .file
                .ends_with("src/domain/inner/thing.rs")
        );
    }

    #[test]
    fn module_path_for_file_resolves_directory_convention() {
        let root = Path::new("/ws/my-core");
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/lib.rs")),
            Some(String::new())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/main.rs")),
            Some(String::new())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/bin/tool.rs")),
            Some(String::new())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/domain.rs")),
            Some("domain".to_string())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/domain/mod.rs")),
            Some("domain".to_string())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/src/domain/inner/thing.rs")),
            Some("domain::inner::thing".to_string())
        );
        assert_eq!(
            module_path_for_file(root, Path::new("/ws/my-core/build.rs")),
            None
        );
    }
}
