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

use ra_ap_hir::Semantics;
use ra_ap_ide::RootDatabase;
use ra_ap_syntax::{AstNode, TextRange, ast};
use serde_json::json;

use crate::api_surface::{self, PubFnCandidate, SEMVER_HAZARD_RULE};
use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

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

/// Resolves `candidate`'s parameter and return types and reports one
/// [`Finding`] per leaked type found among them (see the module docs).
fn leaked_types_for_candidate(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    file_id: FileId,
    own_crate: ra_ap_hir::Crate,
    candidate: &PubFnCandidate,
) -> Vec<Finding> {
    let Some(fn_node) = resolve_fn_node(sema, file_id, candidate.ident_span) else {
        return Vec::new();
    };

    checked_types(&fn_node)
        .into_iter()
        .filter_map(|(site, ty)| {
            let resolved = sema.resolve_type(&ty)?;
            let leak = leaked_type(&resolved, db, own_crate)?;
            Some(leak_finding(candidate, &site, &leak))
        })
        .collect()
}

/// Runs the `leaked_dependency_type` `semver-hazard` sub-case over every
/// crate in `workspace` (see the module docs). Loads its own [`DeepContext`]
/// rather than sharing one with another detector — the same accepted,
/// documented extra cost [`crate::slop_structural_deep::analyze_workspace`]
/// takes for the same reason (see that function's doc comment).
pub fn analyze_workspace(
    workspace: &Workspace,
) -> Result<DeepApiSurfaceReport, ApiSurfaceDeepError> {
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
                }
            }
        }

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

    /// (a) A `pub fn` whose parameter type comes from another crate must be
    /// flagged with `evidence.kind: "leaked_dependency_type"`.
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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

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
        let report = analyze_workspace(&workspace).unwrap();

        assert!(
            semver_hazard_findings(&report)
                .iter()
                .any(|f| f.location.item_path == "accept"),
            "a type from a dependency crate outside the workspace member list must be flagged: {:?}",
            semver_hazard_findings(&report)
        );
    }
}
