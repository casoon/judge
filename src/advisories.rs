//! Imports `cargo audit --json` output (RUSTSEC advisories checked against
//! the resolved `Cargo.lock`) and cross-references each hit with judge's own
//! dependency-graph reachability (todo.md §F "`cargo audit --json`/`cargo
//! deny --format json`-Import + Verschneidung mit Reachability — der
//! eigentliche Mehrwert laut Konzept"): is the affected package only ever
//! reached through `dev-dependency` edges (test-only, never shipped in the
//! built artifact), or does at least one path from a workspace member cross
//! a `normal`/`build` edge? `cargo audit`'s own output does not distinguish
//! the two — a RUSTSEC hit against a test-only tool looks identical to one
//! against a crate that ships in production. That split is this module's
//! entire value-add over just running `cargo audit` directly.
//!
//! judge never runs `cargo-audit` (or `cargo-deny`) itself — same
//! established precedent as [`crate::coverage`]'s LCOV import: only an
//! already-generated report is read, via `cargo judge deps --audit-json
//! PATH` (see `run_deps` in `src/main.rs`). Generate one with e.g. `cargo
//! audit --json > audit.json`.
//!
//! Only `cargo audit --json` is implemented — `cargo deny --format json`
//! (the todo item's other named alternative) additionally covers license
//! and dependency-source-ban policy, a different concern than a
//! vulnerability-reachability cross-reference; deliberately left for a
//! later, separate pass rather than folded in half-done here.
//!
//! ## Why this isn't [`crate::reachability`]
//!
//! [`crate::reachability`] (the Deep Tier `--why-live` engine) answers "is
//! *this specific function* reachable from a recognized entry point" — the
//! right question for dead-code analysis, but the wrong granularity here.
//! RUSTSEC advisories are scoped to a crate name and a version range, not to
//! specific function names in a machine-readable way, so there is no
//! function-level target to hand that engine. What this module can honestly
//! answer instead, from the *dependency graph* alone, is whether the
//! affected crate is wired into the actual build at all — see
//! [`production_reachable_packages`].
//!
//! ## Reachability classification
//!
//! Runs its own full, non-`--no-deps` `cargo metadata` resolve — same
//! established precedent as `crate::dep_graph`/
//! `crate::slopsquat::analyze_yanked_dependencies` (every detector module
//! that needs the full resolve fetches it itself). For each vulnerability:
//!
//! - **`production`**: the affected package/version is reached from some
//!   workspace member via a path where every edge carries at least one
//!   non-`dev` [`cargo_metadata::DependencyKind`] — it's part of what
//!   actually gets built and shipped.
//! - **`dev_only`**: the package/version is resolved into the graph, but
//!   every path to it from a workspace member requires at least one
//!   `dev`-only edge — it's only ever pulled in for tests.
//! - **`unknown`**: the exact package/version `cargo audit` reported was not
//!   found in *this* resolve at all (a stale report generated against a
//!   different `Cargo.lock` state, or a workspace-root mismatch). The
//!   vulnerability is still reported — `cargo audit` already confirmed it
//!   against its own `Cargo.lock` read, and a local resolve mismatch here
//!   must never make that finding disappear — just without a reachability
//!   claim this pass can't back up (see todo.md §17 "Kein Raten von
//!   Projektabsicht").

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, NodeDep, PackageId};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

/// Rule id for a RUSTSEC advisory imported from `cargo audit --json`,
/// cross-referenced with dependency-graph reachability (see module doc).
pub const KNOWN_VULNERABILITY_RULE: &str = "known-vulnerability";
/// Bump when the known-vulnerability rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const KNOWN_VULNERABILITY_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum AuditImportError {
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for AuditImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
        }
    }
}

impl std::error::Error for AuditImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
        }
    }
}

/// One `cargo audit --json` vulnerability hit, reduced to the fields this
/// module needs. `cargo audit` nests these under `vulnerabilities.list[]` —
/// see [`parse_audit_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVulnerability {
    pub advisory_id: String,
    pub package_name: String,
    pub package_version: String,
    pub title: String,
    pub url: Option<String>,
}

/// Parses `cargo audit --json`'s report, extracting every entry under
/// `vulnerabilities.list[]`. Tolerant of the unparsable, the malformed, and
/// the merely unexpected: invalid JSON, a missing `vulnerabilities`/`list`
/// key, or a list entry missing `advisory.id`/`package.name`/
/// `package.version` all produce an empty result (for the whole report) or
/// skip just that entry, rather than failing outright — the same
/// "malformed records are skipped" precedent [`crate::coverage::parse_lcov`]
/// documents. `cargo audit`'s JSON schema is not itself a versioned,
/// guaranteed-stable API, so tolerance here is a deliberate hedge against a
/// point release reshaping a field judge doesn't need, not laziness.
pub fn parse_audit_report(text: &str) -> Vec<AuditVulnerability> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(list) = root
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    list.iter()
        .filter_map(|entry| {
            let advisory = entry.get("advisory")?;
            let advisory_id = advisory.get("id")?.as_str()?.to_string();
            let title = advisory
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let url = advisory
                .get("url")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let package = entry.get("package")?;
            let package_name = package.get("name")?.as_str()?.to_string();
            let package_version = package.get("version")?.as_str()?.to_string();
            Some(AuditVulnerability {
                advisory_id,
                package_name,
                package_version,
                title,
                url,
            })
        })
        .collect()
}

/// Reads and parses a `cargo audit --json` report from `path` (see
/// [`parse_audit_report`]). Only the file read can fail; parsing never does.
pub fn read_audit_report(path: &Path) -> Result<Vec<AuditVulnerability>, AuditImportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| AuditImportError::Io(path.to_path_buf(), err))?;
    Ok(parse_audit_report(&text))
}

/// How a vulnerable package/version relates to the actual build (see module
/// doc "Reachability classification").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reachability {
    Production,
    DevOnly,
    Unknown,
}

impl Reachability {
    fn label(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::DevOnly => "dev_only",
            Self::Unknown => "unknown",
        }
    }
}

/// Multi-source BFS from every workspace member over the resolved
/// dependency graph, following only edges that carry at least one non-`dev`
/// [`DependencyKind`] (`normal` or `build`) — see module doc. An edge with no
/// `dep_kinds` at all (the field was only added in Rust 1.41's
/// `cargo_metadata` output) is conservatively treated as a production edge:
/// under-classifying a real dependency as `dev_only` would be worse than the
/// reverse here, since it's the `production` classification that gates a
/// verdict.
fn production_reachable_packages(metadata: &Metadata) -> HashSet<PackageId> {
    let Some(resolve) = &metadata.resolve else {
        return HashSet::new();
    };
    let adjacency: HashMap<&PackageId, &Vec<NodeDep>> = resolve
        .nodes
        .iter()
        .map(|node| (&node.id, &node.deps))
        .collect();

    let mut reached: HashSet<PackageId> = metadata.workspace_members.iter().cloned().collect();
    let mut queue: VecDeque<PackageId> = metadata.workspace_members.iter().cloned().collect();

    while let Some(current) = queue.pop_front() {
        let Some(deps) = adjacency.get(&current) else {
            continue;
        };
        for dep in deps.iter() {
            let is_production_edge = dep.dep_kinds.is_empty()
                || dep
                    .dep_kinds
                    .iter()
                    .any(|info| !matches!(info.kind, DependencyKind::Development));
            if !is_production_edge {
                continue;
            }
            if reached.insert(dep.pkg.clone()) {
                queue.push_back(dep.pkg.clone());
            }
        }
    }

    reached
}

/// Findings plus non-fatal errors from cross-referencing `cargo audit`
/// output against the resolved dependency graph — same shape as
/// [`crate::slopsquat::SlopsquatNetworkReport`].
#[derive(Debug, Default)]
pub struct AdvisoryReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

/// Cross-references `vulnerabilities` (from [`parse_audit_report`]/
/// [`read_audit_report`]) with `workspace`'s own resolved dependency graph
/// (see module doc). A local resolve failure never drops a vulnerability
/// `cargo audit` already confirmed — every entry is still reported, just
/// with [`Reachability::Unknown`] instead of a real classification.
pub fn analyze_vulnerabilities(
    workspace: &Workspace,
    vulnerabilities: &[AuditVulnerability],
) -> AdvisoryReport {
    let mut report = AdvisoryReport::default();
    if vulnerabilities.is_empty() {
        return report;
    }
    let manifest_path = workspace.root.join("Cargo.toml");

    let metadata = match MetadataCommand::new().manifest_path(&manifest_path).exec() {
        Ok(metadata) => metadata,
        Err(err) => {
            report
                .errors
                .push(format!("failed to resolve dependency graph: {err}"));
            for vuln in vulnerabilities {
                report.findings.push(known_vulnerability_finding(
                    &manifest_path,
                    vuln,
                    Reachability::Unknown,
                ));
            }
            report
                .findings
                .sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            return report;
        }
    };

    let reachable = production_reachable_packages(&metadata);

    for vuln in vulnerabilities {
        let reachability = metadata
            .packages
            .iter()
            .find(|package| {
                package.name == vuln.package_name
                    && package.version.to_string() == vuln.package_version
            })
            .map_or(Reachability::Unknown, |package| {
                if reachable.contains(&package.id) {
                    Reachability::Production
                } else {
                    Reachability::DevOnly
                }
            });
        report.findings.push(known_vulnerability_finding(
            &manifest_path,
            vuln,
            reachability,
        ));
    }

    report
        .findings
        .sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    report
}

/// Builds a `known-vulnerability` finding. Its evidence class is
/// `external_measurement` (see [`crate::finding::evidence_class_for_rule`]):
/// the vulnerability itself is a snapshot from `cargo audit`'s RUSTSEC
/// database read, valid at report-generation time, not a timeless fact — an
/// advisory can later be withdrawn, or the dependency upgraded. Severity
/// reflects the reachability cross-reference: `Fail` only when the package
/// is actually reachable in the production build; a `dev_only` or `unknown`
/// classification is `Warn` — real information either way, but not asserted
/// with `Fail`-level confidence that it affects what ships.
fn known_vulnerability_finding(
    manifest_path: &Path,
    vuln: &AuditVulnerability,
    reachability: Reachability,
) -> Finding {
    let severity = match reachability {
        Reachability::Production => Severity::Fail,
        Reachability::DevOnly | Reachability::Unknown => Severity::Warn,
    };
    Finding {
        id: format!(
            "{KNOWN_VULNERABILITY_RULE}:{}:{}",
            vuln.package_name, vuln.advisory_id
        )
        .into(),
        rule: KNOWN_VULNERABILITY_RULE.into(),
        severity,
        location: Location {
            file: manifest_path.to_path_buf(),
            line: OneBasedLine::FIRST,
            item_path: vuln.package_name.clone(),
        },
        evidence_class: EvidenceClass::ExternalMeasurement,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "advisory_id": vuln.advisory_id,
            "package_version": vuln.package_version,
            "title": vuln.title,
            "url": vuln.url,
            "reachability": reachability.label(),
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    // -- parse_audit_report --

    #[test]
    fn parses_a_realistic_vulnerabilities_list() {
        let text = r#"{
            "vulnerabilities": {
                "found": true,
                "count": 1,
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2020-0001",
                            "title": "Example vulnerability",
                            "url": "https://rustsec.org/advisories/RUSTSEC-2020-0001"
                        },
                        "package": {
                            "name": "vulnerable-crate",
                            "version": "1.2.3"
                        }
                    }
                ]
            }
        }"#;

        let vulns = parse_audit_report(text);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].advisory_id, "RUSTSEC-2020-0001");
        assert_eq!(vulns[0].package_name, "vulnerable-crate");
        assert_eq!(vulns[0].package_version, "1.2.3");
        assert_eq!(vulns[0].title, "Example vulnerability");
        assert_eq!(
            vulns[0].url.as_deref(),
            Some("https://rustsec.org/advisories/RUSTSEC-2020-0001")
        );
    }

    #[test]
    fn a_report_with_no_vulnerabilities_found_yields_an_empty_list() {
        let text = r#"{"vulnerabilities": {"found": false, "count": 0, "list": []}}"#;
        assert!(parse_audit_report(text).is_empty());
    }

    #[test]
    fn invalid_json_yields_an_empty_list_rather_than_panicking() {
        assert!(parse_audit_report("this is not json").is_empty());
    }

    #[test]
    fn a_missing_vulnerabilities_key_yields_an_empty_list() {
        assert!(parse_audit_report("{}").is_empty());
    }

    #[test]
    fn an_entry_missing_a_required_field_is_skipped_not_fatal() {
        let text = r#"{
            "vulnerabilities": {
                "found": true,
                "count": 2,
                "list": [
                    { "advisory": { "id": "RUSTSEC-2020-0001" }, "package": { "name": "no-version" } },
                    {
                        "advisory": { "id": "RUSTSEC-2020-0002" },
                        "package": { "name": "complete-crate", "version": "2.0.0" }
                    }
                ]
            }
        }"#;

        let vulns = parse_audit_report(text);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].package_name, "complete-crate");
    }

    #[test]
    fn read_audit_report_errors_clearly_for_a_missing_file() {
        let dir = TempDir::new("advisories-missing-file");
        let err = read_audit_report(&dir.join("nope.json")).unwrap_err();
        assert!(err.to_string().contains("failed to read file"));
    }

    // -- analyze_vulnerabilities --

    fn vulnerability(name: &str, version: &str) -> AuditVulnerability {
        AuditVulnerability {
            advisory_id: "RUSTSEC-2020-0001".to_string(),
            package_name: name.to_string(),
            package_version: version.to_string(),
            title: "Example vulnerability".to_string(),
            url: None,
        }
    }

    /// A standalone vendored crate at `dir`'s own root, referenced by an
    /// absolute `path` dependency — the only way to get a *real*, fully
    /// resolved (non-`--no-deps`) external package into `cargo_metadata`'s
    /// output without real network/registry access. Mirrors
    /// `crate::dep_graph`/`crate::slopsquat`'s identical test fixtures (same
    /// technique, same reason: `path` deps resolve fully offline).
    fn write_vendored_crate(dir: &TempDir, name: &str, version: &str) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn noop() {}\n").unwrap();
    }

    /// A single-package fixture (not a `[workspace]`) with one `[dependencies]`
    /// path dep and one `[dev-dependencies]` path dep — enough to exercise
    /// all three reachability classifications in one resolve.
    fn write_manifest_with_vendored_deps(
        dir: &TempDir,
        prod_dep: (&str, &TempDir),
        dev_dep: (&str, &TempDir),
    ) -> PathBuf {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{} = {{ path = {:?} }}\n\n[dev-dependencies]\n{} = {{ path = {:?} }}\n",
                prod_dep.0,
                prod_dep.1.to_path_buf(),
                dev_dep.0,
                dev_dep.1.to_path_buf(),
            ),
        )
        .unwrap();
        dir.join("Cargo.toml")
    }

    #[test]
    fn a_vulnerability_in_a_production_dependency_is_classified_production_and_fails() {
        let prod_vendor = TempDir::new("advisories-prod-vendor");
        write_vendored_crate(&prod_vendor, "prod-dep", "1.0.0");
        let dev_vendor = TempDir::new("advisories-dev-vendor-a");
        write_vendored_crate(&dev_vendor, "dev-dep", "1.0.0");
        let dir = TempDir::new("advisories-prod-fixture");
        let manifest = write_manifest_with_vendored_deps(
            &dir,
            ("prod-dep", &prod_vendor),
            ("dev-dep", &dev_vendor),
        );
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let report = analyze_vulnerabilities(&workspace, &[vulnerability("prod-dep", "1.0.0")]);

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Fail);
        assert_eq!(
            report.findings[0].evidence.as_ref().unwrap()["reachability"],
            "production"
        );
    }

    /// The registry's curated `example.before` for `known-vulnerability` (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags. Parsed with the module's
    /// own [`parse_audit_report`] (not a second hand-written copy), then
    /// resolved as a production dependency so the reachability
    /// cross-reference actually finds it.
    #[test]
    fn known_vulnerability_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(KNOWN_VULNERABILITY_RULE)
            .expect("known-vulnerability has a registry entry")
            .example
            .expect("known-vulnerability has a curated example")
            .before;
        let vulns = parse_audit_report(example);
        assert_eq!(
            vulns.len(),
            1,
            "curated example must parse to exactly one vulnerability"
        );

        let prod_vendor = TempDir::new("advisories-registry-example-prod-vendor");
        write_vendored_crate(
            &prod_vendor,
            &vulns[0].package_name,
            &vulns[0].package_version,
        );
        let dev_vendor = TempDir::new("advisories-registry-example-dev-vendor");
        write_vendored_crate(&dev_vendor, "unused-dev-dep", "1.0.0");
        let dir = TempDir::new("advisories-registry-example-fixture");
        let manifest = write_manifest_with_vendored_deps(
            &dir,
            (&vulns[0].package_name, &prod_vendor),
            ("unused-dev-dep", &dev_vendor),
        );
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let report = analyze_vulnerabilities(&workspace, &vulns);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, KNOWN_VULNERABILITY_RULE);
        assert_eq!(
            report.findings[0].evidence.as_ref().unwrap()["reachability"],
            "production"
        );
    }

    #[test]
    fn a_vulnerability_in_a_dev_only_dependency_is_classified_dev_only_and_warns() {
        let prod_vendor = TempDir::new("advisories-prod-vendor-b");
        write_vendored_crate(&prod_vendor, "prod-dep", "1.0.0");
        let dev_vendor = TempDir::new("advisories-dev-vendor-b");
        write_vendored_crate(&dev_vendor, "dev-dep", "1.0.0");
        let dir = TempDir::new("advisories-dev-fixture");
        let manifest = write_manifest_with_vendored_deps(
            &dir,
            ("prod-dep", &prod_vendor),
            ("dev-dep", &dev_vendor),
        );
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let report = analyze_vulnerabilities(&workspace, &[vulnerability("dev-dep", "1.0.0")]);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(
            report.findings[0].evidence.as_ref().unwrap()["reachability"],
            "dev_only"
        );
    }

    #[test]
    fn a_vulnerability_for_a_package_not_in_this_resolve_is_classified_unknown() {
        let dir = TempDir::new("advisories-unknown-fixture");
        let manifest = write_manifest(&dir);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let report =
            analyze_vulnerabilities(&workspace, &[vulnerability("nowhere-to-be-found", "9.9.9")]);

        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(
            report.findings[0].evidence.as_ref().unwrap()["reachability"],
            "unknown"
        );
    }

    #[test]
    fn no_vulnerabilities_produces_no_findings_and_does_not_even_resolve_metadata() {
        // A workspace root with no Cargo.toml at all would fail a
        // `cargo metadata` resolve — proving this returns early without
        // even attempting one when there's nothing to cross-reference.
        let dir = TempDir::new("advisories-empty-list");
        let workspace = Workspace {
            root: dir.to_path_buf(),
            crates: Vec::new(),
        };

        let report = analyze_vulnerabilities(&workspace, &[]);

        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn a_metadata_resolve_failure_still_reports_every_vulnerability_as_unknown() {
        let dir = TempDir::new("advisories-resolve-failure");
        let workspace = Workspace {
            root: dir.to_path_buf(),
            crates: Vec::new(),
        };

        let report = analyze_vulnerabilities(&workspace, &[vulnerability("whatever", "1.0.0")]);

        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("failed to resolve dependency graph"));
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(
            report.findings[0].evidence.as_ref().unwrap()["reachability"],
            "unknown"
        );
    }

    /// A single-package fixture with no dependencies at all — used where
    /// only the workspace root needs to resolve, not any particular
    /// dependency.
    fn write_manifest(dir: &TempDir) -> PathBuf {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        dir.join("Cargo.toml")
    }
}
