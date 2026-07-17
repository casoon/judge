//! Architecture boundaries: crate-level dependency rules and cycle detection
//! (see todo.md §3.H "Architektur & Boundaries", §14.2 P1/P2 bullets 1-2).
//!
//! This is deliberately scoped to *crate-level* dependency edges, fully
//! knowable from `cargo_metadata` without a build — layer presets
//! (`layered`/`hexagonal`/`feature-sliced`) and module-level boundaries need
//! semantic module resolution the Fast Tier doesn't have yet (see todo.md §0).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use cargo_metadata::MetadataCommand;
use serde::Deserialize;

use crate::finding::{Finding, Location, Origin, Severity};
use crate::ingest::Workspace;

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

/// The `judge.toml` `[[boundary]]` table (see todo.md §8).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BoundaryConfig {
    #[serde(rename = "boundary", default)]
    pub boundaries: Vec<BoundaryRule>,
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
}

impl std::fmt::Display for BoundaryConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
            Self::UnknownCrate { rule, crate_name } => write!(
                f,
                "boundary rule `{rule}` references unknown crate `{crate_name}` (set allow_empty = true to permit this)"
            ),
        }
    }
}

impl std::error::Error for BoundaryConfigError {}

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

    let manifest = workspace.root.join("Cargo.toml");
    let graph = build_crate_graph(Some(&manifest))?;
    let cargo_toml = workspace.root.join("Cargo.toml");

    let mut findings = Vec::new();
    for rule in &config.boundaries {
        findings.extend(evaluate_rule(rule, &graph, &cargo_toml));
    }
    for cycle in find_cycles(&graph) {
        findings.push(cycle_finding(&cycle, &cargo_toml));
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
        id: format!("{BOUNDARY_VIOLATION_RULE}:{}:{path_str}", rule.name),
        rule: BOUNDARY_VIOLATION_RULE.to_string(),
        severity: Severity::Fail,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: 1,
            item_path: format!("{} [{}]: {path_str}", rule.name, rule.reach.label()),
        },
        confidence: 1.0,
        origin: Origin::Code,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

fn missing_required_finding(rule: &BoundaryRule, from: &str, cargo_toml: &Path) -> Finding {
    Finding {
        id: format!(
            "{BOUNDARY_VIOLATION_RULE}:{}:missing-required:{from}",
            rule.name
        ),
        rule: BOUNDARY_VIOLATION_RULE.to_string(),
        severity: Severity::Fail,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: 1,
            item_path: format!(
                "{} [{}]: {from} does not reach any of [{}]",
                rule.name,
                rule.reach.label(),
                rule.required.join(", ")
            ),
        },
        confidence: 1.0,
        origin: Origin::Code,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

fn cycle_finding(cycle: &[String], cargo_toml: &Path) -> Finding {
    let path_str = cycle.join(" -> ");
    Finding {
        id: format!("{DEPENDENCY_CYCLE_RULE}:{path_str}"),
        rule: DEPENDENCY_CYCLE_RULE.to_string(),
        severity: Severity::Warn,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: 1,
            item_path: path_str,
        },
        confidence: 1.0,
        origin: Origin::Code,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Finds every cycle in the whole `graph` (not scoped to any one rule),
/// structurally similar to [`crate::finding::check_for_cycles`]'s white/
/// gray/black DFS, but over crate names, collecting every cycle rather than
/// stopping at the first, and closed as `[a, b, c, a]` rather than erroring.
/// Cycles that are rotations of each other (e.g. `a->b->c->a` and
/// `b->c->a->b`) are deduplicated, canonicalized by rotating to start at the
/// lexicographically smallest crate name.
pub fn find_cycles(graph: &CrateGraph) -> Vec<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        White,
        Gray,
        Black,
    }

    let mut node_names: Vec<String> = graph.edges.keys().cloned().collect();
    node_names.sort();

    let mut marks: HashMap<String, Mark> = node_names
        .iter()
        .cloned()
        .map(|name| (name, Mark::White))
        .collect();
    let mut stack: Vec<String> = Vec::new();
    let mut raw_cycles: Vec<Vec<String>> = Vec::new();

    fn visit(
        node: &str,
        graph: &CrateGraph,
        marks: &mut HashMap<String, Mark>,
        stack: &mut Vec<String>,
        raw_cycles: &mut Vec<Vec<String>>,
    ) {
        marks.insert(node.to_string(), Mark::Gray);
        stack.push(node.to_string());

        if let Some(neighbors) = graph.edges.get(node) {
            for neighbor in neighbors {
                match marks.get(neighbor.as_str()).copied().unwrap_or(Mark::White) {
                    Mark::Black => continue,
                    Mark::White => visit(neighbor, graph, marks, stack, raw_cycles),
                    Mark::Gray => {
                        let start = stack.iter().position(|n| n == neighbor).unwrap_or(0);
                        let mut cycle = stack[start..].to_vec();
                        cycle.push(neighbor.clone());
                        raw_cycles.push(cycle);
                    }
                }
            }
        }

        stack.pop();
        marks.insert(node.to_string(), Mark::Black);
    }

    for name in &node_names {
        if marks.get(name.as_str()).copied() == Some(Mark::White) {
            visit(name, graph, &mut marks, &mut stack, &mut raw_cycles);
        }
    }

    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let mut cycles: Vec<Vec<String>> = Vec::new();
    for cycle in raw_cycles {
        let canonical = canonicalize_cycle(&cycle);
        if seen.insert(canonical.clone()) {
            cycles.push(canonical);
        }
    }
    cycles.sort();
    cycles
}

/// Rotates a closed cycle path (`[a, b, c, a]`) so it starts at its
/// lexicographically smallest crate name, then re-closes it. Used to
/// deduplicate cycles found from different starting points.
fn canonicalize_cycle(cycle: &[String]) -> Vec<String> {
    let core = &cycle[..cycle.len() - 1];
    let min_index = core
        .iter()
        .enumerate()
        .min_by_key(|(_, name)| name.as_str())
        .map(|(index, _)| index)
        .unwrap_or(0);

    let mut rotated: Vec<String> = core[min_index..]
        .iter()
        .chain(core[..min_index].iter())
        .cloned()
        .collect();
    let first = rotated[0].clone();
    rotated.push(first);
    rotated
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
        };

        let result = evaluate(&workspace, &config).unwrap();

        assert!(result.findings.is_empty());
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
}
