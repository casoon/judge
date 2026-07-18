//! Dependency-hygiene, Fast Tier (see todo.md §3.B, §14.2 P1
//! "Dependency-Nutzung pro Cargo-Target und `cfg` sammeln; nur eindeutige
//! `misplaced-dependency-kind`-Vorschläge erzeugen, Feature-only-Nutzung als
//! Evidenz erhalten"). This module deliberately implements only that one
//! rule, and only its two unambiguous cases:
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

use crate::finding::{EvidenceClass, Finding, Location, Origin, Severity};
use crate::ingest::{CrateInfo, DependencyKind, Workspace};

/// Rule id used for misplaced-dependency-kind findings (see todo.md §3.B).
pub const MISPLACED_DEPENDENCY_KIND_RULE: &str = "misplaced-dependency-kind";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const MISPLACED_DEPENDENCY_KIND_RULE_REVISION: u32 = 1;

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
}

impl std::fmt::Display for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for DepsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
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
        ),
        rule: MISPLACED_DEPENDENCY_KIND_RULE.to_string(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: 1,
            item_path: dep.name.clone(),
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
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
            Ok(idents) => {
                for ident in idents {
                    usage.entry(ident).or_default().insert(domain);
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

/// Parses `path` and collects the first-segment identifier of every
/// referenced path — `use` trees, expression paths, type paths, and
/// macro-invocation paths — that isn't `self`/`super`/`crate`/`Self`. Each
/// such identifier is a candidate reference to an external crate's
/// `code_identifier`.
fn collect_identifiers(path: &Path) -> Result<HashSet<String>, DepsError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| DepsError::Io(path.to_path_buf(), err))?;
    let ast = syn::parse_file(&source).map_err(|err| DepsError::Parse(path.to_path_buf(), err))?;

    let mut collector = PathIdentCollector::default();
    collector.visit_file(&ast);
    Ok(collector.idents)
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
}
