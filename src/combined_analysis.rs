//! Fast-Tier orchestration shared by the bare combined run and its tests.
//!
//! The phase boundaries are intentional: they are the same lifecycle exposed
//! through `cargo judge --progress PATH`, while each phase owns only the
//! findings and analysis errors it contributes.

use super::*;

pub(super) struct CollectedFindings {
    pub(super) findings: Vec<Finding>,
    pub(super) analysis_errors: Vec<String>,
    pub(super) rule_revisions: std::collections::HashMap<String, u32>,
    pub(super) boundary_rules_checked: usize,
    pub(super) boundaries_config_path: PathBuf,
    /// How many findings an inline `// judge-ignore: <rule> — <reason>`
    /// comment dropped (see [`judge::suppression::apply_inline_suppressions`]).
    pub(super) suppressed_inline: usize,
}

/// Runs every default current-state detector (complexity, duplication,
/// dependency hygiene, and structural checks) plus boundaries if a
/// `judge.toml` exists, and merges their findings. This is deliberately
/// *not* the numeric 0-100 health score from §4 — that needs crate-type
/// profiles and a weighting scheme that don't exist yet; merging findings
/// doesn't require either. Findings are returned unsorted; callers that show
/// them worst-first must sort explicitly (see [`judge::finding::sort_by_severity_desc`]).
pub(super) fn collect_findings(
    workspace: &judge::ingest::Workspace,
) -> Result<CollectedFindings, CliError> {
    collect_findings_with_progress(workspace, &mut |_| Ok(()))
}

/// Same analysis as [`collect_findings`], with lifecycle events at the
/// natural Fast-Tier phase boundaries. The observer is optional to callers:
/// tests keep a simple wrapper above,
/// while the bare combined command can expose live progress separately from
/// its final stdout report.
pub(super) fn collect_findings_with_progress(
    workspace: &judge::ingest::Workspace,
    progress: &mut dyn FnMut(combined::ProgressEvent) -> Result<(), CliError>,
) -> Result<CollectedFindings, CliError> {
    let mut findings = Vec::new();
    let mut analysis_errors = Vec::new();
    let mut rule_revisions = default_rule_revisions();

    progress(combined::ProgressEvent::started("complexity"))?;
    collect_complexity_and_history(workspace, &mut findings, &mut analysis_errors);
    progress(combined::ProgressEvent::completed("complexity"))?;

    progress(combined::ProgressEvent::started("slop"))?;
    collect_slop(workspace, &mut findings, &mut analysis_errors)?;
    progress(combined::ProgressEvent::completed("slop"))?;

    progress(combined::ProgressEvent::started("duplication"))?;
    collect_duplication(workspace, &mut findings, &mut analysis_errors);
    progress(combined::ProgressEvent::completed("duplication"))?;

    progress(combined::ProgressEvent::started("structural"))?;
    collect_structural(workspace, &mut findings);
    progress(combined::ProgressEvent::completed("structural"))?;

    progress(combined::ProgressEvent::started("security"))?;
    collect_security(workspace, &mut findings, &mut analysis_errors, false);
    progress(combined::ProgressEvent::completed("security"))?;

    progress(combined::ProgressEvent::started("dependencies"))?;
    collect_dependencies(workspace, &mut findings, &mut analysis_errors);
    progress(combined::ProgressEvent::completed("dependencies"))?;

    progress(combined::ProgressEvent::started("boundaries"))?;
    let (boundaries_config_path, boundary_rules_checked) = collect_boundaries(
        workspace,
        &mut findings,
        &mut analysis_errors,
        &mut rule_revisions,
    )?;
    progress(combined::ProgressEvent::completed("boundaries"))?;

    progress(combined::ProgressEvent::started("suppression"))?;
    let (findings, suppressed_inline) = collect_suppression(workspace, findings)?;
    progress(combined::ProgressEvent::completed("suppression"))?;

    Ok(CollectedFindings {
        findings,
        analysis_errors,
        rule_revisions,
        boundary_rules_checked,
        boundaries_config_path,
        suppressed_inline,
    })
}

fn default_rule_revisions() -> std::collections::HashMap<String, u32> {
    let mut revisions = deps_rule_revisions();
    revisions.insert(
        judge::duplication::DUPLICATE_RULE.to_string(),
        judge::duplication::DUPLICATE_RULE_REVISION,
    );
    revisions.extend(slop_structural_security_rule_revisions());
    revisions.insert(
        judge::complexity::MAINTAINABILITY_INDEX_RULE.to_string(),
        judge::complexity::MAINTAINABILITY_INDEX_RULE_REVISION,
    );
    revisions
}

/// The two `[[boundary]]`-gated rule revisions, shared between `run_boundaries`'s
/// own baseline map (see `analysis_commands::run_boundaries`, which layers
/// its Fast-Tier-only `module-boundary-violation` entry and, in a `--features
/// deep` build, the Deep-Tier upgrade rule on top) and this module's
/// `collect_boundaries`, which only ever needs these two — mirroring
/// `deps_rule_revisions`'s same "both build this identical static core"
/// precedent.
pub(super) fn boundaries_rule_revisions() -> std::collections::HashMap<String, u32> {
    std::collections::HashMap::from([
        (
            judge::boundaries::BOUNDARY_VIOLATION_RULE.to_string(),
            judge::boundaries::BOUNDARY_VIOLATION_RULE_REVISION,
        ),
        (
            judge::boundaries::DEPENDENCY_CYCLE_RULE.to_string(),
            judge::boundaries::DEPENDENCY_CYCLE_RULE_REVISION,
        ),
    ])
}

/// Dependency-hygiene and dependency-graph rule revisions, plus the one G5
/// slopsquatting rule that's fully local and always on
/// (`name-collision-risk`). Shared between this module's own default map and
/// `run_deps`'s baseline map (see `analysis_commands::run_deps`) — both build
/// this identical static core before `run_deps` layers its
/// `--check-crates-io`/`--check-rustc-lints`/`--audit-json` opt-in extras on
/// top.
pub(super) fn deps_rule_revisions() -> std::collections::HashMap<String, u32> {
    std::collections::HashMap::from([
        (
            judge::deps::MISPLACED_DEPENDENCY_KIND_RULE.to_string(),
            judge::deps::MISPLACED_DEPENDENCY_KIND_RULE_REVISION,
        ),
        (
            judge::deps::UNUSED_DEV_DEPENDENCY_RULE.to_string(),
            judge::deps::UNUSED_DEV_DEPENDENCY_RULE_REVISION,
        ),
        (
            judge::deps::HEAVY_DEPENDENCY_RULE.to_string(),
            judge::deps::HEAVY_DEPENDENCY_RULE_REVISION,
        ),
        (
            judge::deps::UNUSED_FEATURE_FLAG_RULE.to_string(),
            judge::deps::UNUSED_FEATURE_FLAG_RULE_REVISION,
        ),
        (
            judge::deps::DEFAULT_FEATURES_UNUSED_RULE.to_string(),
            judge::deps::DEFAULT_FEATURES_UNUSED_RULE_REVISION,
        ),
        (
            judge::deps::UNUSED_FEATURE_RULE.to_string(),
            judge::deps::UNUSED_FEATURE_RULE_REVISION,
        ),
        (
            judge::deps::DEP_WITHOUT_REPO_RULE.to_string(),
            judge::deps::DEP_WITHOUT_REPO_RULE_REVISION,
        ),
        (
            judge::dep_graph::DUPLICATE_CRATE_VERSIONS_RULE.to_string(),
            judge::dep_graph::DUPLICATE_CRATE_VERSIONS_RULE_REVISION,
        ),
        (
            judge::dep_graph::MSRV_DRIFT_RULE.to_string(),
            judge::dep_graph::MSRV_DRIFT_RULE_REVISION,
        ),
        (
            judge::dep_graph::WORKSPACE_DEP_DRIFT_RULE.to_string(),
            judge::dep_graph::WORKSPACE_DEP_DRIFT_RULE_REVISION,
        ),
        (
            judge::slopsquat::NAME_COLLISION_RISK_RULE.to_string(),
            judge::slopsquat::NAME_COLLISION_RISK_RULE_REVISION,
        ),
    ])
}

/// AI-slop, G4 structural, and security rule revisions. Shared between this
/// module's own default map and `cargo judge health`'s `--save-baseline`/
/// `--baseline` map (see `health_command::run`) — both commands compute these
/// findings identically over the whole workspace.
pub(super) fn slop_structural_security_rule_revisions() -> std::collections::HashMap<String, u32> {
    std::collections::HashMap::from([
        (
            judge::slop::SWALLOWED_RESULT_RULE.to_string(),
            judge::slop::SWALLOWED_RESULT_RULE_REVISION,
        ),
        (
            judge::slop::EMPTY_ERROR_ARM_RULE.to_string(),
            judge::slop::EMPTY_ERROR_ARM_RULE_REVISION,
        ),
        (
            judge::slop::CATCH_ALL_ERROR_RULE.to_string(),
            judge::slop::CATCH_ALL_ERROR_RULE_REVISION,
        ),
        (
            judge::slop::SUPPRESSION_DEBT_RULE.to_string(),
            judge::slop::SUPPRESSION_DEBT_RULE_REVISION,
        ),
        (
            judge::slop::MERGED_STUB_RULE.to_string(),
            judge::slop::MERGED_STUB_RULE_REVISION,
        ),
        (
            judge::slop::EMPTY_IMPL_RULE.to_string(),
            judge::slop::EMPTY_IMPL_RULE_REVISION,
        ),
        (
            judge::slop::ASSERTION_FREE_TEST_RULE.to_string(),
            judge::slop::ASSERTION_FREE_TEST_RULE_REVISION,
        ),
        (
            judge::slop::TAUTOLOGICAL_TEST_RULE.to_string(),
            judge::slop::TAUTOLOGICAL_TEST_RULE_REVISION,
        ),
        (
            judge::slop::IGNORED_TEST_ACCUMULATION_RULE.to_string(),
            judge::slop::IGNORED_TEST_ACCUMULATION_RULE_REVISION,
        ),
        (
            judge::slop::CONVERSATIONAL_ARTIFACT_RULE.to_string(),
            judge::slop::CONVERSATIONAL_ARTIFACT_RULE_REVISION,
        ),
        (
            judge::slop::RESTATING_COMMENT_RULE.to_string(),
            judge::slop::RESTATING_COMMENT_RULE_REVISION,
        ),
        (
            judge::slop::STEP_COMMENT_INFLATION_RULE.to_string(),
            judge::slop::STEP_COMMENT_INFLATION_RULE_REVISION,
        ),
        (
            judge::slop::GENERIC_NAMING_RULE.to_string(),
            judge::slop::GENERIC_NAMING_RULE_REVISION,
        ),
        (
            judge::slop::DOC_RESTATES_SIGNATURE_RULE.to_string(),
            judge::slop::DOC_RESTATES_SIGNATURE_RULE_REVISION,
        ),
        (
            judge::slop_structural::COMPLEXITY_INFLATION_RULE.to_string(),
            judge::slop_structural::COMPLEXITY_INFLATION_RULE_REVISION,
        ),
        (
            judge::complexity::SIGNATURE_COMPLEXITY_RULE.to_string(),
            judge::complexity::SIGNATURE_COMPLEXITY_RULE_REVISION,
        ),
        (
            judge::slop_structural::ABSTRACTION_INFLATION_RULE.to_string(),
            judge::slop_structural::ABSTRACTION_INFLATION_RULE_REVISION,
        ),
        (
            judge::slop_structural::FRAGILE_SUBSTRING_CLASSIFICATION_RULE.to_string(),
            judge::slop_structural::FRAGILE_SUBSTRING_CLASSIFICATION_RULE_REVISION,
        ),
        (
            judge::security::UNSAFE_SURFACE_RULE.to_string(),
            judge::security::UNSAFE_SURFACE_RULE_REVISION,
        ),
        (
            judge::security::UNSAFE_DENSITY_RULE.to_string(),
            judge::security::UNSAFE_DENSITY_RULE_REVISION,
        ),
        (
            judge::security::INTEGER_CAST_RISK_RULE.to_string(),
            judge::security::INTEGER_CAST_RISK_RULE_REVISION,
        ),
        (
            judge::security::PANIC_IN_LIB_RULE.to_string(),
            judge::security::PANIC_IN_LIB_RULE_REVISION,
        ),
        (
            judge::security::HARDCODED_SECRET_RULE.to_string(),
            judge::security::HARDCODED_SECRET_RULE_REVISION,
        ),
    ])
}

fn collect_complexity_and_history(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
) {
    let complexity_source_files = super::analysis_commands::workspace_source_files(workspace);
    let complexity = judge::complexity::analyze_workspace(complexity_source_files, false);
    append_analysis_errors(analysis_errors, &complexity.errors);
    findings.extend(judge::slop_structural::complexity_inflation(
        &complexity.functions,
    ));
    findings.extend(judge::complexity::signature_complexity(
        &complexity.functions,
    ));
    findings.extend(judge::complexity::maintainability_index(
        &complexity.functions,
    ));
}

fn collect_slop(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
) -> Result<(), CliError> {
    let slop = super::analysis_commands::analyze_slop_workspace(workspace, false)?;
    append_analysis_errors(analysis_errors, &slop.errors);
    findings.extend(slop.findings);
    Ok(())
}

fn collect_duplication(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
) {
    let dupes_source_files = super::analysis_commands::workspace_source_files(workspace);
    let dupes = judge::duplication::analyze_workspace_with_options(
        dupes_source_files,
        DupeMode::Mild,
        judge::duplication::DEFAULT_MIN_TOKENS,
        false,
        false,
    );
    append_analysis_errors(analysis_errors, &dupes.errors);
    findings.extend(dupes.to_findings());
}

/// G4 structural slop (see todo.md §3.G). Shared with `cargo judge health`
/// (see `health_command::run`), which computes these same two findings sets
/// over the same whole-workspace scope.
pub(super) fn collect_structural(workspace: &judge::ingest::Workspace, findings: &mut Vec<Finding>) {
    let abstraction_source_files = super::analysis_commands::workspace_source_files(workspace);
    findings.extend(judge::slop_structural::analyze_workspace_structural(
        abstraction_source_files,
    ));

    let fragile_substring_source_files = super::analysis_commands::workspace_source_files(workspace);
    findings.extend(judge::slop_structural::fragile_substring_classification(
        fragile_substring_source_files,
    ));
}

/// Shared with `cargo judge health` (see `health_command::run`), which needs
/// `include_generated` to be a parameter rather than always-off, and needs
/// the excluded-generated count back to fold into its own total; the bare
/// combined run ignores both (bare `cargo judge`/`audit` never expose
/// `--include-generated`, so this collector's own call site below always
/// passes `false` and drops the returned count).
pub(super) fn collect_security(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
    include_generated: bool,
) -> usize {
    let security_source_files = super::analysis_commands::workspace_source_files(workspace);
    let security = judge::security::analyze_workspace(security_source_files, include_generated);
    append_analysis_errors(analysis_errors, &security.errors);
    findings.extend(security.findings);
    security.excluded_generated
}

fn collect_dependencies(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
) {
    let deps = judge::deps::analyze_workspace(workspace);
    append_analysis_errors(analysis_errors, &deps.errors);
    findings.extend(deps.findings);

    let dep_graph = judge::dep_graph::analyze_workspace(workspace);
    append_analysis_errors(analysis_errors, &dep_graph.errors);
    findings.extend(dep_graph.findings);

    // `name-collision-risk` is fully local (no network), so it runs in the
    // combined bare `cargo judge`/`audit` pass too. The other three G5
    // rules (`phantom-crate`/`phantom-version`/`fresh-low-reputation-dep`)
    // need real crates.io network access and are opt-in only via
    // `cargo judge deps --check-crates-io` (see `run_deps`).
    findings.extend(judge::slopsquat::analyze_name_collision(workspace));
}

fn collect_boundaries(
    workspace: &judge::ingest::Workspace,
    findings: &mut Vec<Finding>,
    analysis_errors: &mut Vec<String>,
    rule_revisions: &mut std::collections::HashMap<String, u32>,
) -> Result<(PathBuf, usize), CliError> {
    let boundaries_config_path = workspace.root.join("judge.toml");
    let mut boundary_rules_checked = 0;
    if boundaries_config_path.exists() {
        let config = parse_boundary_config(&boundaries_config_path)?;
        boundary_rules_checked = config.boundaries.len();
        let evaluated = judge::boundaries::evaluate(workspace, &config)?;
        findings.extend(evaluated.findings);
        rule_revisions.extend(boundaries_rule_revisions());
    }

    // `feature-graph-cycle` is always-on, unlike the `judge.toml`-gated
    // boundary rules above — see `judge::boundaries` module docs
    // "`feature-graph-cycle`" for why: a `[features]` table is either
    // cyclic or it isn't, a fact needing no project-intent config to
    // interpret.
    let feature_graph_manifest = workspace.root.join("Cargo.toml");
    match judge::boundaries::feature_graph_cycles(Some(&feature_graph_manifest)) {
        Ok(cycle_findings) => {
            findings.extend(cycle_findings);
            rule_revisions.insert(
                judge::boundaries::FEATURE_GRAPH_CYCLE_RULE.to_string(),
                judge::boundaries::FEATURE_GRAPH_CYCLE_RULE_REVISION,
            );
        }
        Err(err) => analysis_errors.push(err.to_string()),
    }
    Ok((boundaries_config_path, boundary_rules_checked))
}

fn collect_suppression(
    workspace: &judge::ingest::Workspace,
    findings: Vec<Finding>,
) -> Result<(Vec<Finding>, usize), CliError> {
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;
    Ok((findings, suppressed_inline))
}
