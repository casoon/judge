//! Manifest- and resolve-graph-level dependency rules (see todo.md §3.B):
//! `duplicate-crate-versions`, `msrv-drift`, `workspace-dep-drift`. All three
//! are facts read directly out of `cargo_metadata` — no code parsing, no
//! network access beyond what `cargo metadata` itself needs to read the
//! already-resolved `Cargo.lock`.
//!
//! [`crate::ingest::load`] runs `cargo metadata --no-deps`, scoped to
//! workspace members only — sufficient for the per-crate rules in
//! [`crate::deps`], but not for these: a duplicate-version or MSRV-drift fact
//! is a statement about the *whole* resolved graph, including transitive,
//! non-workspace dependencies. This module therefore runs its own
//! `cargo_metadata::MetadataCommand` (full resolve, not `--no-deps`), once
//! per [`analyze_workspace`] call, and derives all three rules from that one
//! [`cargo_metadata::Metadata`] value.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use cargo_metadata::{Metadata, MetadataCommand, Package, PackageId};
use semver::Version;

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

/// Rule id for semver-incompatible duplicate copies of the same crate
/// resolved into the dependency graph (see todo.md §3.B).
pub const DUPLICATE_CRATE_VERSIONS_RULE: &str = "duplicate-crate-versions";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const DUPLICATE_CRATE_VERSIONS_RULE_REVISION: u32 = 1;

/// Rule id for a dependency whose declared `rust-version` is higher than the
/// workspace manifest's own declared `rust-version` (see todo.md §3.B).
pub const MSRV_DRIFT_RULE: &str = "msrv-drift";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const MSRV_DRIFT_RULE_REVISION: u32 = 1;

/// Rule id for workspace members declaring different version requirements
/// for the same dependency (see todo.md §3.B).
pub const WORKSPACE_DEP_DRIFT_RULE: &str = "workspace-dep-drift";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const WORKSPACE_DEP_DRIFT_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum DepGraphError {
    Metadata(cargo_metadata::Error),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, toml::de::Error),
}

impl std::fmt::Display for DepGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for DepGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(err) => Some(err),
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// Aggregated results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceDepGraph {
    pub findings: Vec<Finding>,
    pub errors: Vec<DepGraphError>,
}

/// Runs all three graph-level rules over `workspace`, sharing one full
/// (non-`--no-deps`) `cargo metadata` run.
pub fn analyze_workspace(workspace: &Workspace) -> WorkspaceDepGraph {
    let mut errors = Vec::new();
    let manifest_path = workspace.root.join("Cargo.toml");

    let metadata = match MetadataCommand::new().manifest_path(&manifest_path).exec() {
        Ok(metadata) => metadata,
        Err(err) => {
            errors.push(DepGraphError::Metadata(err));
            return WorkspaceDepGraph {
                findings: Vec::new(),
                errors,
            };
        }
    };

    let mut findings = Vec::new();
    findings.extend(duplicate_crate_versions(&metadata, &workspace.root));
    findings.extend(msrv_drift(&metadata, &workspace.root, &mut errors));
    findings.extend(workspace_dep_drift(&metadata, &workspace.root));

    WorkspaceDepGraph { findings, errors }
}

/// Compatibility bucket for a resolved version, following Cargo's default
/// caret (`^`) compatibility rule: for `major > 0`, everything sharing that
/// major is compatible; for `0.minor > 0`, everything sharing that minor is
/// compatible; for `0.0.z`, only an exact patch match is compatible. Two
/// copies of a crate in different buckets are the semver-incompatible
/// duplicates this rule reports.
fn compat_bucket(version: &Version) -> (u64, u64, u64) {
    if version.major > 0 {
        (version.major, 0, 0)
    } else if version.minor > 0 {
        (0, version.minor, 0)
    } else {
        (0, 0, version.patch)
    }
}

/// Multi-source BFS from every workspace member over the resolved dependency
/// graph ([`cargo_metadata::Resolve`]), returning the shortest path (as
/// crate names, root-first) from the nearest workspace member to every
/// reachable package. Used to give `duplicate-crate-versions` a concrete
/// "how did this copy get here" trail rather than just a name.
fn shortest_paths_from_workspace(metadata: &Metadata) -> HashMap<PackageId, Vec<String>> {
    let mut paths: HashMap<PackageId, Vec<String>> = HashMap::new();
    let Some(resolve) = &metadata.resolve else {
        return paths;
    };

    let name_of = |id: &PackageId| -> String {
        metadata
            .packages
            .iter()
            .find(|package| &package.id == id)
            .map_or_else(|| id.repr.clone(), |package| package.name.clone())
    };
    let adjacency: HashMap<&PackageId, &Vec<PackageId>> = resolve
        .nodes
        .iter()
        .map(|node| (&node.id, &node.dependencies))
        .collect();

    let mut queue: VecDeque<PackageId> = VecDeque::new();
    for member_id in &metadata.workspace_members {
        if let std::collections::hash_map::Entry::Vacant(entry) = paths.entry(member_id.clone()) {
            entry.insert(vec![name_of(member_id)]);
            queue.push_back(member_id.clone());
        }
    }
    while let Some(current) = queue.pop_front() {
        let current_path = paths[&current].clone();
        let Some(deps) = adjacency.get(&current) else {
            continue;
        };
        for dep_id in deps.iter() {
            if let std::collections::hash_map::Entry::Vacant(entry) = paths.entry(dep_id.clone()) {
                let mut next_path = current_path.clone();
                next_path.push(name_of(dep_id));
                entry.insert(next_path);
                queue.push_back(dep_id.clone());
            }
        }
    }
    paths
}

/// Workspace members that declare `target` as one of their direct
/// dependencies — the fallback evidence used when `target` was not reachable
/// via [`shortest_paths_from_workspace`] (defensive: every package in a
/// resolved graph should be reachable from some workspace member, but a
/// direct-requirer list is cheap to produce and honest either way).
fn direct_requirers(metadata: &Metadata, target: &PackageId) -> Vec<String> {
    let Some(resolve) = &metadata.resolve else {
        return Vec::new();
    };
    let mut requirers: Vec<String> = resolve
        .nodes
        .iter()
        .filter(|node| node.dependencies.contains(target))
        .map(|node| {
            metadata
                .packages
                .iter()
                .find(|package| package.id == node.id)
                .map_or_else(|| node.id.repr.clone(), |package| package.name.clone())
        })
        .collect();
    requirers.sort();
    requirers.dedup();
    requirers
}

/// `duplicate-crate-versions`: multiple semver-incompatible copies of the
/// same crate name resolved into the graph (see [`compat_bucket`]). Evidence
/// carries every distinct version and, per version, either the shortest path
/// from a workspace member to that copy or — if that path could not be
/// derived — its direct requirers (see `path_kind` in the evidence).
fn duplicate_crate_versions(metadata: &Metadata, workspace_root: &Path) -> Vec<Finding> {
    let paths = shortest_paths_from_workspace(metadata);
    let manifest_path = workspace_root.join("Cargo.toml");

    let mut by_name: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
    for package in &metadata.packages {
        by_name
            .entry(package.name.as_str())
            .or_default()
            .push(package);
    }

    let mut findings = Vec::new();
    for (name, packages) in by_name {
        let mut buckets: BTreeSet<(u64, u64, u64)> = BTreeSet::new();
        for package in &packages {
            buckets.insert(compat_bucket(&package.version));
        }
        if buckets.len() < 2 {
            // Every copy is semver-compatible with every other — not the
            // fact this rule reports.
            continue;
        }

        let mut versions: Vec<String> = packages.iter().map(|p| p.version.to_string()).collect();
        versions.sort();
        versions.dedup();

        let mut copies: Vec<serde_json::Value> = packages
            .iter()
            .map(|package| match paths.get(&package.id) {
                Some(path) => serde_json::json!({
                    "version": package.version.to_string(),
                    "path": path,
                    "path_kind": "shortest_workspace_path",
                }),
                None => serde_json::json!({
                    "version": package.version.to_string(),
                    "path": direct_requirers(metadata, &package.id),
                    "path_kind": "direct_requirers",
                }),
            })
            .collect();
        copies.sort_by(|a, b| a["version"].as_str().cmp(&b["version"].as_str()));

        findings.push(Finding {
            id: format!("{DUPLICATE_CRATE_VERSIONS_RULE}:{name}").into(),
            rule: DUPLICATE_CRATE_VERSIONS_RULE.into(),
            severity: Severity::Warn,
            location: Location {
                file: manifest_path.clone(),
                line: OneBasedLine::FIRST,
                item_path: name.to_string(),
            },
            evidence_class: EvidenceClass::DerivedFact,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "crate": name,
                "versions": versions,
                "copies": copies,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }
    findings
}

/// Parses a `rust-version` manifest value ("a bare version number with two
/// or three components", per the Cargo Book) into a [`Version`], padding a
/// two-component value with `.0` — the same tolerance
/// `cargo_metadata::Package::rust_version` applies when Cargo emits it, kept
/// here for the workspace manifest's own value, which is read directly from
/// TOML rather than through `cargo_metadata::Package`.
fn parse_rust_version(raw: &str) -> Option<Version> {
    let mut buf = raw.to_string();
    if buf.matches('.').count() == 1 {
        buf.push_str(".0");
    }
    Version::parse(&buf).ok()
}

/// The workspace manifest's own declared `rust-version` promise: either
/// `[workspace.package] rust-version` (a virtual workspace's inherited
/// promise for its members) or `[package] rust-version` (a manifest that is
/// itself a crate, matching e.g. this repository's own non-workspace
/// `Cargo.toml`). `None` if the manifest declares neither — there is then no
/// promise for a dependency to drift against.
fn workspace_declared_rust_version(manifest: &toml::Value) -> Option<Version> {
    let raw = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("rust-version"))
        .and_then(toml::Value::as_str)
        .or_else(|| {
            manifest
                .get("package")
                .and_then(|package| package.get("rust-version"))
                .and_then(toml::Value::as_str)
        })?;
    parse_rust_version(raw)
}

/// `msrv-drift`: a resolved dependency (any non-workspace-member package in
/// the full graph) declares a `rust-version` higher than the workspace
/// manifest's own declared `rust-version`. Only evaluated when the workspace
/// manifest declares one itself (see [`workspace_declared_rust_version`]) —
/// otherwise there is no promise to drift against, and no finding is
/// produced.
fn msrv_drift(
    metadata: &Metadata,
    workspace_root: &Path,
    errors: &mut Vec<DepGraphError>,
) -> Vec<Finding> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) => {
            errors.push(DepGraphError::Io(manifest_path, err));
            return Vec::new();
        }
    };
    let manifest: toml::Value = match toml::from_str(&text) {
        Ok(manifest) => manifest,
        Err(err) => {
            errors.push(DepGraphError::Parse(manifest_path, err));
            return Vec::new();
        }
    };
    let Some(workspace_msrv) = workspace_declared_rust_version(&manifest) else {
        return Vec::new();
    };

    let member_ids: HashSet<&PackageId> = metadata.workspace_members.iter().collect();
    let mut findings: Vec<Finding> = metadata
        .packages
        .iter()
        .filter(|package| !member_ids.contains(&package.id))
        .filter_map(|package| {
            let dep_msrv = package.rust_version.as_ref()?;
            (*dep_msrv > workspace_msrv).then(|| Finding {
                id: format!("{MSRV_DRIFT_RULE}:{}:{}", package.name, package.version).into(),
                rule: MSRV_DRIFT_RULE.into(),
                severity: Severity::Warn,
                location: Location {
                    file: manifest_path.clone(),
                    line: OneBasedLine::FIRST,
                    item_path: package.name.clone(),
                },
                evidence_class: EvidenceClass::DerivedFact,
                origin: Origin::Code,
                evidence: Some(serde_json::json!({
                    "dependency": package.name,
                    "dependency_version": package.version.to_string(),
                    "dependency_msrv": dep_msrv.to_string(),
                    "workspace_msrv": workspace_msrv.to_string(),
                })),
                caused_by: Vec::new(),
                causes: Vec::new(),
            })
        })
        .collect();
    findings.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    findings
}

/// `workspace-dep-drift`: two or more workspace members declare different
/// version *requirements* (the manifest strings in
/// [`cargo_metadata::Package::dependencies`], not resolved versions) for the
/// same dependency name. `path`-dependencies are excluded — they carry no
/// meaningful version requirement to drift. Dependencies declared via
/// `dep.workspace = true` are not special-cased: Cargo does not allow a
/// member to override the version requirement of an inherited dependency, so
/// every member using it resolves to the identical requirement string and
/// never produces a finding here.
fn workspace_dep_drift(metadata: &Metadata, workspace_root: &Path) -> Vec<Finding> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let member_ids: HashSet<&PackageId> = metadata.workspace_members.iter().collect();

    let mut by_dep: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for package in &metadata.packages {
        if !member_ids.contains(&package.id) {
            continue;
        }
        for dep in &package.dependencies {
            if dep.path.is_some() {
                continue;
            }
            by_dep
                .entry(dep.name.clone())
                .or_default()
                .push((package.name.clone(), dep.req.to_string()));
        }
    }

    let mut findings = Vec::new();
    for (dep_name, mut entries) in by_dep {
        entries.sort();
        entries.dedup();
        let distinct_requirements: HashSet<&str> =
            entries.iter().map(|(_, req)| req.as_str()).collect();
        if distinct_requirements.len() < 2 {
            continue;
        }

        let requirements: Vec<serde_json::Value> = entries
            .iter()
            .map(|(member, req)| serde_json::json!({"member": member, "requirement": req}))
            .collect();

        findings.push(Finding {
            id: format!("{WORKSPACE_DEP_DRIFT_RULE}:{dep_name}").into(),
            rule: WORKSPACE_DEP_DRIFT_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: manifest_path.clone(),
                line: OneBasedLine::FIRST,
                item_path: dep_name.clone(),
            },
            evidence_class: EvidenceClass::DerivedFact,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "dependency": dep_name,
                "requirements": requirements,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn write_workspace_root(dir: &TempDir, members: &[&str], extra: &str) {
        let members_toml = members
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"
[workspace]
members = [{members_toml}]
resolver = "2"

{extra}
"#
            ),
        )
        .unwrap();
    }

    fn write_member(dir: &TempDir, name: &str, deps: &str) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        std::fs::write(
            dir.join(name).join("Cargo.toml"),
            format!(
                r#"
[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[dependencies]
{deps}
"#
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join(name).join("src/lib.rs"),
            format!("pub fn {name}() {{}}\n"),
        )
        .unwrap();
    }

    /// Writes a standalone vendored crate at `dir`'s own root. Deliberately
    /// placed in its own [`TempDir`] (a sibling of the workspace fixture,
    /// referenced by an absolute `path`), not nested inside the enclosing
    /// workspace's directory tree: a full (non-`--no-deps`) `cargo metadata`
    /// run — unlike `ingest.rs`'s `--no-deps` walk — refuses to resolve a
    /// path dependency that sits inside the workspace root's own directory
    /// tree while also declaring itself a `[workspace]` root ("multiple
    /// workspace roots found"), so nesting doesn't work for this module's
    /// fixtures the way it does for `ingest.rs`'s.
    fn write_vendored_crate(
        dir: &TempDir,
        package_name: &str,
        version: &str,
        rust_version: Option<&str>,
    ) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let rust_version_line = rust_version
            .map(|v| format!("rust-version = \"{v}\"\n"))
            .unwrap_or_default();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"
[package]
name = "{package_name}"
version = "{version}"
edition = "2021"
{rust_version_line}
"#
            ),
        )
        .unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn noop() {}\n").unwrap();
    }

    /// A `path = "..."` dependency line pointing at `vendor`'s absolute path.
    fn path_dep(name: &str, vendor: &TempDir) -> String {
        format!("{name} = {{ path = {:?} }}", vendor.to_path_buf())
    }

    /// Clones the single package named `package_name` in `value["packages"]`
    /// as a synthetic second copy at `new_version`, with a made-up but unique
    /// id, and mirrors it into `resolve.nodes` as a dependency of every
    /// workspace member — i.e. exactly what a second, semver-incompatible
    /// (or -compatible) resolved copy of the same crate looks like in
    /// `cargo_metadata`'s output.
    ///
    /// A real Cargo run cannot produce this scenario from two local `path`
    /// dependencies: Cargo hard-errors ("two packages named `X` in this
    /// workspace") when two *path* sources share one package name, a
    /// limitation specific to path sources (unlike registry sources, which
    /// this rule targets and which Cargo can hold multiple versions of at
    /// once). Reproducing a genuine duplicate therefore needs either a local
    /// registry source or, as here, a synthetic edit of a real, fully valid
    /// `Metadata` value — `duplicate_crate_versions` only reads `packages`
    /// and `resolve.nodes`, so this mutation exercises its real logic.
    fn add_synthetic_duplicate(
        value: &mut serde_json::Value,
        package_name: &str,
        new_version: &str,
    ) {
        let original = value["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == package_name)
            .unwrap()
            .clone();
        let original_id = original["id"].as_str().unwrap().to_string();
        let new_id = format!("{original_id}+synthetic-{new_version}");

        let mut duplicate = original.clone();
        duplicate["version"] = serde_json::json!(new_version);
        duplicate["id"] = serde_json::json!(new_id);
        value["packages"].as_array_mut().unwrap().push(duplicate);

        let mut duplicate_node = value["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == original_id)
            .unwrap()
            .clone();
        duplicate_node["id"] = serde_json::json!(new_id);
        duplicate_node["dependencies"] = serde_json::json!([]);
        duplicate_node["deps"] = serde_json::json!([]);
        value["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_node);

        let member_ids: Vec<String> = value["workspace_members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect();
        for node in value["resolve"]["nodes"].as_array_mut().unwrap() {
            let node_id = node["id"].as_str().unwrap().to_string();
            if member_ids.contains(&node_id) {
                node["dependencies"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(new_id));
            }
        }
    }

    #[test]
    fn two_semver_incompatible_copies_are_flagged() {
        let dir = TempDir::new("dep-graph-dupe-incompatible");
        write_workspace_root(&dir, &["a"], "");
        let vendor = TempDir::new("dep-graph-dupe-incompatible-vendor");
        write_vendored_crate(&vendor, "dupdep", "0.1.0", None);
        write_member(&dir, "a", &path_dep("dupdep", &vendor));

        let manifest = dir.join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest)
            .exec()
            .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        add_synthetic_duplicate(&mut value, "dupdep", "0.2.0");
        let metadata: Metadata = serde_json::from_value(value).unwrap();

        let findings = duplicate_crate_versions(&metadata, &dir);

        let finding = findings
            .iter()
            .find(|f| f.rule == DUPLICATE_CRATE_VERSIONS_RULE)
            .expect("expected a duplicate-crate-versions finding");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::DerivedFact);
        let versions = finding.evidence.as_ref().unwrap()["versions"]
            .as_array()
            .unwrap();
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn two_semver_compatible_copies_are_not_flagged() {
        let dir = TempDir::new("dep-graph-dupe-compatible");
        write_workspace_root(&dir, &["a"], "");
        let vendor = TempDir::new("dep-graph-dupe-compatible-vendor");
        write_vendored_crate(&vendor, "dupdep", "0.1.1", None);
        write_member(&dir, "a", &path_dep("dupdep", &vendor));

        let manifest = dir.join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest)
            .exec()
            .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        add_synthetic_duplicate(&mut value, "dupdep", "0.1.2");
        let metadata: Metadata = serde_json::from_value(value).unwrap();

        let findings = duplicate_crate_versions(&metadata, &dir);

        assert!(
            !findings
                .iter()
                .any(|f| f.rule == DUPLICATE_CRATE_VERSIONS_RULE)
        );
    }

    #[test]
    fn a_dependency_msrv_higher_than_the_workspace_msrv_is_flagged() {
        let dir = TempDir::new("dep-graph-msrv-drift-positive");
        write_workspace_root(
            &dir,
            &["a"],
            "[workspace.package]\nrust-version = \"1.50\"\n",
        );
        let vendor = TempDir::new("dep-graph-msrv-drift-positive-vendor");
        write_vendored_crate(&vendor, "highdep", "0.1.0", Some("1.80"));
        write_member(&dir, "a", &path_dep("highdep", &vendor));

        let manifest = dir.join("Cargo.toml");
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == MSRV_DRIFT_RULE)
            .expect("expected an msrv-drift finding");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(
            finding.evidence.as_ref().unwrap()["workspace_msrv"],
            "1.50.0"
        );
        assert_eq!(
            finding.evidence.as_ref().unwrap()["dependency_msrv"],
            "1.80.0"
        );
    }

    #[test]
    fn a_workspace_without_its_own_rust_version_produces_no_msrv_drift_finding() {
        let dir = TempDir::new("dep-graph-msrv-drift-no-promise");
        write_workspace_root(&dir, &["a"], "");
        let vendor = TempDir::new("dep-graph-msrv-drift-no-promise-vendor");
        write_vendored_crate(&vendor, "highdep", "0.1.0", Some("1.80"));
        write_member(&dir, "a", &path_dep("highdep", &vendor));

        let manifest = dir.join("Cargo.toml");
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(!report.findings.iter().any(|f| f.rule == MSRV_DRIFT_RULE));
    }

    /// A real path dependency always carries an unconstrained requirement
    /// (`path` deps aren't versioned against each other), so there is no way
    /// to produce two *different* declared requirement strings for the same
    /// dependency name purely from resolvable local path fixtures, and a
    /// real differing-requirement disagreement needs two registry sources,
    /// which would require network access. Instead this builds a real,
    /// fully-valid `cargo_metadata::Metadata` from an actual `cargo metadata`
    /// run against a local path fixture, then rewrites the two members'
    /// declared `shared` dependency in the serialized JSON to drop `path`
    /// and carry different `req` strings — exactly what two registry
    /// dependencies with different version requirements would look like —
    /// before parsing it back and calling `workspace_dep_drift` directly.
    #[test]
    fn members_declaring_different_requirements_for_the_same_dep_are_flagged() {
        let dir = TempDir::new("dep-graph-workspace-dep-drift-positive");
        write_workspace_root(&dir, &["a", "b"], "");
        let vendor = TempDir::new("dep-graph-workspace-dep-drift-positive-vendor");
        write_vendored_crate(&vendor, "shared", "0.1.0", None);
        write_member(&dir, "a", &path_dep("shared", &vendor));
        write_member(&dir, "b", &path_dep("shared", &vendor));

        let manifest = dir.join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest)
            .no_deps()
            .exec()
            .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        for package in value["packages"].as_array_mut().unwrap() {
            let member_name = package["name"].as_str().unwrap().to_string();
            let requirement = match member_name.as_str() {
                "a" => "^0.1",
                "b" => "^0.2",
                _ => continue,
            };
            for dep in package["dependencies"].as_array_mut().unwrap() {
                if dep["name"] == "shared" {
                    dep["path"] = serde_json::Value::Null;
                    dep["req"] = serde_json::Value::String(requirement.to_string());
                }
            }
        }
        let metadata: Metadata = serde_json::from_value(value).unwrap();

        let findings = workspace_dep_drift(&metadata, &dir);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, WORKSPACE_DEP_DRIFT_RULE);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].evidence_class, EvidenceClass::DerivedFact);
        let requirements = findings[0].evidence.as_ref().unwrap()["requirements"]
            .as_array()
            .unwrap();
        assert_eq!(requirements.len(), 2);
    }

    #[test]
    fn same_requirement_across_members_is_not_flagged() {
        let dir = TempDir::new("dep-graph-workspace-dep-drift-same");
        write_workspace_root(&dir, &["a", "b"], "");
        let vendor = TempDir::new("dep-graph-workspace-dep-drift-same-vendor");
        write_vendored_crate(&vendor, "shared", "0.1.0", None);
        write_member(&dir, "a", &path_dep("shared", &vendor));
        write_member(&dir, "b", &path_dep("shared", &vendor));

        let manifest = dir.join("Cargo.toml");
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == WORKSPACE_DEP_DRIFT_RULE)
        );
    }

    /// `path` dependencies are excluded outright (see `workspace_dep_drift`'s
    /// docs), and a `workspace = true` dependency cannot declare a
    /// per-member override of its version requirement at all — both members
    /// resolve to the identical inherited requirement. This fixture exercises
    /// the combination (an inherited *path* dependency) end to end via
    /// `analyze_workspace`.
    #[test]
    fn a_workspace_true_dependency_never_drifts() {
        let dir = TempDir::new("dep-graph-workspace-dep-drift-inherited");
        let vendor = TempDir::new("dep-graph-workspace-dep-drift-inherited-vendor");
        write_workspace_root(
            &dir,
            &["a", "b"],
            &format!(
                "[workspace.dependencies]\n{}\n",
                path_dep("shared", &vendor)
            ),
        );
        write_vendored_crate(&vendor, "shared", "0.1.0", None);
        write_member(&dir, "a", "shared = { workspace = true }");
        write_member(&dir, "b", "shared = { workspace = true }");

        let manifest = dir.join("Cargo.toml");
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == WORKSPACE_DEP_DRIFT_RULE)
        );
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn duplicate_crate_versions_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(DUPLICATE_CRATE_VERSIONS_RULE)
            .expect("duplicate-crate-versions has a registry entry")
            .example
            .expect("duplicate-crate-versions has a curated example")
            .before;
        let mut declarations = example.lines().filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (name, version) = line.split_once('=')?;
            Some((
                name.trim().to_string(),
                version.trim().trim_matches('"').to_string(),
            ))
        });
        let (dep_name, first_version) = declarations
            .next()
            .expect("example declares a first version");
        let (_, second_version) = declarations
            .next()
            .expect("example declares a second version");

        let dir = TempDir::new("dep-graph-dupe-registry-example");
        write_workspace_root(&dir, &["a"], "");
        let vendor = TempDir::new("dep-graph-dupe-registry-example-vendor");
        write_vendored_crate(&vendor, &dep_name, &first_version, None);
        write_member(&dir, "a", &path_dep(&dep_name, &vendor));

        let manifest = dir.join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest)
            .exec()
            .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        add_synthetic_duplicate(&mut value, &dep_name, &second_version);
        let metadata: Metadata = serde_json::from_value(value).unwrap();

        let findings = duplicate_crate_versions(&metadata, &dir);

        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == DUPLICATE_CRATE_VERSIONS_RULE)
            .collect();
        assert_eq!(hits.len(), 1);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn msrv_drift_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MSRV_DRIFT_RULE)
            .expect("msrv-drift has a registry entry")
            .example
            .expect("msrv-drift has a curated example")
            .before;
        let manifest: toml::Value = toml::from_str(example).unwrap();
        let package = manifest.get("package").expect("example declares a package");
        let dep_name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("example declares a package name")
            .to_string();
        let dep_version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .expect("example declares a package version")
            .to_string();
        let dep_rust_version = package
            .get("rust-version")
            .and_then(toml::Value::as_str)
            .expect("example declares a rust-version")
            .to_string();

        let dir = TempDir::new("dep-graph-msrv-drift-registry-example");
        write_workspace_root(
            &dir,
            &["a"],
            "[workspace.package]\nrust-version = \"1.50\"\n",
        );
        let vendor = TempDir::new("dep-graph-msrv-drift-registry-example-vendor");
        write_vendored_crate(&vendor, &dep_name, &dep_version, Some(&dep_rust_version));
        write_member(&dir, "a", &path_dep(&dep_name, &vendor));

        let manifest_path = dir.join("Cargo.toml");
        let workspace = crate::ingest::load(Some(&manifest_path)).unwrap();
        let report = analyze_workspace(&workspace);

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let hits: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule == MSRV_DRIFT_RULE)
            .collect();
        assert_eq!(hits.len(), 1);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn workspace_dep_drift_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(WORKSPACE_DEP_DRIFT_RULE)
            .expect("workspace-dep-drift has a registry entry")
            .example
            .expect("workspace-dep-drift has a curated example")
            .before;
        let mut declarations = example.lines().filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (name, req) = line.split_once('=')?;
            Some((
                name.trim().to_string(),
                req.trim().trim_matches('"').to_string(),
            ))
        });
        let (dep_name, req_a) = declarations
            .next()
            .expect("example declares a first requirement");
        let (_, req_b) = declarations
            .next()
            .expect("example declares a second requirement");

        let dir = TempDir::new("dep-graph-workspace-dep-drift-registry-example");
        write_workspace_root(&dir, &["a", "b"], "");
        let vendor = TempDir::new("dep-graph-workspace-dep-drift-registry-example-vendor");
        write_vendored_crate(&vendor, &dep_name, "0.1.0", None);
        write_member(&dir, "a", &path_dep(&dep_name, &vendor));
        write_member(&dir, "b", &path_dep(&dep_name, &vendor));

        let manifest = dir.join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest)
            .no_deps()
            .exec()
            .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        for package in value["packages"].as_array_mut().unwrap() {
            let member_name = package["name"].as_str().unwrap().to_string();
            let requirement = match member_name.as_str() {
                "a" => req_a.as_str(),
                "b" => req_b.as_str(),
                _ => continue,
            };
            for dep in package["dependencies"].as_array_mut().unwrap() {
                if dep["name"] == dep_name {
                    dep["path"] = serde_json::Value::Null;
                    dep["req"] = serde_json::Value::String(requirement.to_string());
                }
            }
        }
        let metadata: Metadata = serde_json::from_value(value).unwrap();

        let findings = workspace_dep_drift(&metadata, &dir);

        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == WORKSPACE_DEP_DRIFT_RULE)
            .collect();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn compat_bucket_groups_by_cargo_caret_compatibility() {
        assert_eq!(
            compat_bucket(&Version::parse("1.2.3").unwrap()),
            compat_bucket(&Version::parse("1.9.0").unwrap())
        );
        assert_ne!(
            compat_bucket(&Version::parse("0.1.0").unwrap()),
            compat_bucket(&Version::parse("0.2.0").unwrap())
        );
        assert_eq!(
            compat_bucket(&Version::parse("0.1.0").unwrap()),
            compat_bucket(&Version::parse("0.1.9").unwrap())
        );
        assert_ne!(
            compat_bucket(&Version::parse("0.0.1").unwrap()),
            compat_bucket(&Version::parse("0.0.2").unwrap())
        );
    }

    #[test]
    fn parse_rust_version_pads_a_two_component_value() {
        assert_eq!(
            parse_rust_version("1.70"),
            Some(Version::parse("1.70.0").unwrap())
        );
        assert_eq!(
            parse_rust_version("1.70.1"),
            Some(Version::parse("1.70.1").unwrap())
        );
    }

    #[test]
    fn dep_graph_error_source_preserves_the_underlying_error() {
        let err = DepGraphError::Io(PathBuf::from("Cargo.toml"), std::io::Error::other("boom"));
        let source = std::error::Error::source(&err).expect("Io must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "Cargo.toml: failed to read file: boom");
    }
}
