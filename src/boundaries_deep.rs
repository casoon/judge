//! Deep-Tier upgrade to `[[module_boundary]]` (see `crate::boundaries`
//! module docs "Module-level boundaries", todo.md §H "Modul-Boundaries im
//! Deep Tier"): the same rule config, the same directory-convention
//! module-path scoping ([`crate::boundaries::module_path_for_file`]), but
//! real symbol reference resolution ([`crate::deep::referencing_files`])
//! instead of a `syn`-based qualified-path text scan — catches a
//! re-export, an aliased `use`, or any other reference shape the Fast-Tier
//! text scan can't see.
//!
//! Reported under its own rule id, `module-boundary-violation-deep`, not
//! folded into the Fast-Tier `module-boundary-violation`: the two run side
//! by side rather than one replacing the other (`cargo judge boundaries`
//! without `--features deep` keeps working exactly as before), and a
//! genuine violation the text scan already catches would otherwise be
//! double-reported under one shared rule id.
//!
//! **v1 scope, honestly narrower than the Fast-Tier text scan in one way**:
//! only free functions, inherent/trait-impl methods, and trait default
//! methods ([`crate::functions::walk_functions`]'s item population) are
//! checked as the *referenced* item. The Fast-Tier text scan is
//! item-kind-agnostic (a qualified path naming a struct/enum/const/...
//! counts equally) — this Deep-Tier pass does not yet cover those kinds.
//! That's a real reason to keep running the Fast-Tier check even under
//! `--features deep`, not a stopgap this module makes obsolete.
//!
//! `Reach::Transitive` is not supported here either — same restriction as
//! the Fast Tier. Not re-validated in this module:
//! [`crate::boundaries::validate_module_boundary_config`] already rejects
//! it (and an unknown `krate`, and an empty `forbidden`) as a config error
//! before this module ever runs, since `evaluate()` always runs first in
//! `cargo judge boundaries` (see `main.rs`'s `run_boundaries`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::boundaries::{
    BoundaryConfig, ModuleBoundaryRule, module_path_for_file, module_path_under,
};
use crate::deep::{DeepContext, DeepError, FileId, referencing_files};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::walk_functions;
use crate::ingest::Workspace;

/// Rule id for a `[[module_boundary]]` violation found via real Deep-Tier
/// symbol reference resolution (see module docs) rather than the Fast
/// Tier's `syn`-based text scan.
pub const MODULE_BOUNDARY_VIOLATION_DEEP_RULE: &str = "module-boundary-violation-deep";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const MODULE_BOUNDARY_VIOLATION_DEEP_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum BoundaryDeepError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for BoundaryDeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for BoundaryDeepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deep(err) => Some(err),
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
        }
    }
}

/// Findings plus non-fatal errors from the Deep-Tier module-boundary pass —
/// same shape as [`crate::dead_code::WorkspaceDeadCode`].
#[derive(Debug, Default)]
pub struct WorkspaceModuleBoundariesDeep {
    pub findings: Vec<Finding>,
    pub errors: Vec<BoundaryDeepError>,
}

/// Runs every `[[module_boundary]]` rule in `config` over `workspace` via
/// real Deep-Tier symbol references (see module docs). `Ok` with an empty
/// report, no Deep-Tier load attempted at all, when `config` declares no
/// `[[module_boundary]]` rules.
pub fn analyze_workspace(
    workspace: &Workspace,
    config: &BoundaryConfig,
) -> Result<WorkspaceModuleBoundariesDeep, BoundaryDeepError> {
    let mut report = WorkspaceModuleBoundariesDeep::default();
    if config.module_boundaries.is_empty() {
        return Ok(report);
    }

    let ctx = DeepContext::load(&workspace.root).map_err(BoundaryDeepError::Deep)?;
    let analysis = ctx.analysis();

    for rule in &config.module_boundaries {
        let Some(krate) = workspace.crates.iter().find(|k| k.name == rule.krate) else {
            // Already a config error surfaced by `evaluate()`'s own
            // validation, which always runs first — nothing to do here.
            continue;
        };

        let mut file_path_by_id: HashMap<FileId, PathBuf> = HashMap::new();
        for file in &krate.source_files {
            if let Some(file_id) = ctx.file_id(&file.path) {
                file_path_by_id.insert(file_id, file.path.clone());
            }
        }

        for file in &krate.source_files {
            let Some(module_path) = module_path_for_file(&krate.root, &file.path) else {
                continue;
            };
            let in_forbidden_scope = rule
                .forbidden
                .iter()
                .any(|forbidden| module_path_under(&module_path, forbidden));
            if !in_forbidden_scope {
                continue;
            }
            let Some(file_id) = ctx.file_id(&file.path) else {
                // Not indexed by the loader — nothing to query.
                continue;
            };

            let source = match std::fs::read_to_string(&file.path) {
                Ok(source) => source,
                Err(err) => {
                    report
                        .errors
                        .push(BoundaryDeepError::Io(file.path.clone(), err));
                    continue;
                }
            };
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    report
                        .errors
                        .push(BoundaryDeepError::Parse(file.path.clone(), err));
                    continue;
                }
            };

            let mut deep_error = None;
            walk_functions(&ast, |site| {
                if deep_error.is_some() {
                    return;
                }
                let offset = site.ident_span.byte_range().start as u32;
                let line = site.ident_span.start().line;
                let position = ra_ap_ide::FilePosition {
                    file_id,
                    offset: offset.into(),
                };
                let referencing = match referencing_files(&analysis, position, true) {
                    Ok(referencing) => referencing,
                    Err(err) => {
                        deep_error = Some(err);
                        return;
                    }
                };

                let mut witnesses: Vec<&PathBuf> = referencing
                    .iter()
                    .filter_map(|referencing_id| file_path_by_id.get(referencing_id))
                    .filter(|referencing_path| {
                        module_path_for_file(&krate.root, referencing_path).is_some_and(
                            |referencing_module| module_path_under(&referencing_module, &rule.from),
                        )
                    })
                    .collect();
                if witnesses.is_empty() {
                    return;
                }
                witnesses.sort();

                report.findings.push(module_boundary_violation_deep_finding(
                    rule,
                    &file.path,
                    &site.qualified_name,
                    line,
                    witnesses[0],
                ));
            });
            if let Some(err) = deep_error {
                report.errors.push(BoundaryDeepError::Deep(err));
            }
        }
    }

    report
        .findings
        .sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    Ok(report)
}

/// Builds a `module-boundary-violation-deep` finding. Its evidence class is
/// `bounded_semantic`, matching the Fast-Tier `module-boundary-violation`
/// (see module docs): the reference edge itself is now a real Deep-Tier
/// fact, but the `from`/`forbidden` *scoping* is still the same
/// directory-convention heuristic — a file wired into the build
/// unconventionally (e.g. via `#[path = "..."]`) is still missed, so the
/// overall claim stays bounded to the examined module view, not a
/// module-graph-verified fact.
fn module_boundary_violation_deep_finding(
    rule: &ModuleBoundaryRule,
    file: &Path,
    qualified_name: &str,
    line: usize,
    witness_file: &Path,
) -> Finding {
    Finding {
        id: format!(
            "{MODULE_BOUNDARY_VIOLATION_DEEP_RULE}:{}:{qualified_name}",
            file.display()
        )
        .into(),
        rule: MODULE_BOUNDARY_VIOLATION_DEEP_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.to_path_buf(),
            line: OneBasedLine::new(line).expect("proc-macro2 span lines are 1-based"),
            item_path: qualified_name.to_string(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "rule": rule.name,
            "from": rule.from,
            "witness_file": witness_file.display().to_string(),
            "basis": "deep_symbol_reference",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn write_crate(dir: &TempDir) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
    }

    fn rule(name: &str, from: &str, forbidden: &[&str]) -> ModuleBoundaryRule {
        ModuleBoundaryRule {
            name: name.to_string(),
            krate: "fixture".to_string(),
            from: from.to_string(),
            forbidden: forbidden.iter().map(|s| s.to_string()).collect(),
            reach: None,
        }
    }

    #[test]
    fn catches_a_reference_through_a_re_export_the_text_scan_would_miss() {
        let dir = TempDir::new("boundaries-deep-reexport");
        write_crate(&dir);
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub use forbidden::secret;\npub mod forbidden;\npub mod from_mod;\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/forbidden.rs"), "pub fn secret() {}\n").unwrap();
        std::fs::write(
            dir.join("src/from_mod.rs"),
            "pub fn caller() {\n    crate::secret();\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig {
            module_boundaries: vec![rule(
                "no-forbidden-from-from-mod",
                "from_mod",
                &["forbidden"],
            )],
            ..Default::default()
        };

        let report = analyze_workspace(&workspace, &config).unwrap();

        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, MODULE_BOUNDARY_VIOLATION_DEEP_RULE);
        assert_eq!(report.findings[0].location.item_path, "secret");
        let evidence = report.findings[0].evidence.as_ref().unwrap();
        assert!(
            evidence["witness_file"]
                .as_str()
                .unwrap()
                .ends_with("from_mod.rs")
        );
    }

    #[test]
    fn does_not_fire_when_from_never_references_forbidden() {
        let dir = TempDir::new("boundaries-deep-no-violation");
        write_crate(&dir);
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub mod forbidden;\npub mod from_mod;\n",
        )
        .unwrap();
        std::fs::write(dir.join("src/forbidden.rs"), "pub fn secret() {}\n").unwrap();
        std::fs::write(dir.join("src/from_mod.rs"), "pub fn caller() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig {
            module_boundaries: vec![rule(
                "no-forbidden-from-from-mod",
                "from_mod",
                &["forbidden"],
            )],
            ..Default::default()
        };

        let report = analyze_workspace(&workspace, &config).unwrap();

        assert!(report.findings.is_empty());
    }

    #[test]
    fn performs_no_analysis_without_any_module_boundary_rules() {
        let dir = TempDir::new("boundaries-deep-no-rules");
        write_crate(&dir);
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig::default();

        let report = analyze_workspace(&workspace, &config).unwrap();

        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }
}
