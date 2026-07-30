//! Fast-Tier report commands: source analysis, dependency hygiene, boundaries,
//! ownership, provenance, coverage, module graph, and API surface.

use super::*;

/// Every Fast-Tier analyzer takes a fresh iterator over the workspace's
/// source files (each one is consumed once), so this one-liner is
/// reconstructed at every call site rather than reused — shared here instead
/// of repeating `workspace.crates.iter().flat_map(...)` in every command and
/// collector.
pub(super) fn workspace_source_files(
    workspace: &judge::ingest::Workspace,
) -> impl Iterator<Item = &judge::ingest::SourceFile> {
    workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter())
}

/// Runs the slop analyzer with `judge.toml`'s `[rules]` config applied — the
/// same "fresh source-file iterator, load the config, analyze" recipe
/// `run_errors`/`run_slop` and `health_command::run`/
/// `combined_analysis::collect_slop` all need before filtering or merging
/// its findings differently.
pub(super) fn analyze_slop_workspace(
    workspace: &judge::ingest::Workspace,
    include_generated: bool,
) -> Result<judge::slop::WorkspaceSlop, CliError> {
    let source_files = workspace_source_files(workspace);
    let config = load_judge_toml(&workspace.root)?.rules;
    Ok(judge::slop::analyze_workspace(
        source_files,
        include_generated,
        config.catch_all_error.allow_anyhow_at_boundary,
    ))
}

/// Renders a `<label>: <count>` line followed by one indented line per
/// error, or nothing when `errors` is empty — the same shape every Fast-Tier
/// command's TTY view uses for its "files skipped (parse errors)"/"analysis
/// errors"/etc. block.
pub(super) fn write_error_list<E: std::fmt::Display>(
    out: &mut dyn Write,
    label: &str,
    errors: &[E],
) -> std::io::Result<()> {
    if errors.is_empty() {
        return Ok(());
    }
    writeln!(out, "{label}: {}", errors.len())?;
    for error in errors {
        writeln!(out, "  {error}")?;
    }
    Ok(())
}

/// The single "suppressed (inline judge-ignore): N" TTY line, printed only
/// when inline `judge-ignore` comments actually suppressed something.
pub(super) fn write_suppressed_inline_line(
    out: &mut dyn Write,
    suppressed_inline: usize,
) -> std::io::Result<()> {
    if suppressed_inline > 0 {
        writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
    }
    Ok(())
}

/// The "excluded (generated)"/"suppressed (inline judge-ignore)" TTY lines
/// every command that supports `--include-generated` prints the same way,
/// in the same order, when each count is nonzero.
pub(super) fn write_excluded_and_suppressed_lines(
    out: &mut dyn Write,
    excluded_generated: usize,
    suppressed_inline: usize,
) -> std::io::Result<()> {
    if excluded_generated > 0 {
        writeln!(
            out,
            "excluded (generated): {excluded_generated} (see --include-generated)"
        )?;
    }
    write_suppressed_inline_line(out, suppressed_inline)
}

/// The `--format json` report shape shared by `run_boundaries` and
/// `run_module_graph`: a plain [`Report`] with only the inline-suppression
/// count added on top (unlike `dupes`/`deps`/`coverage`/`api-surface`, which
/// each embed their own extra JSON fields).
pub(super) fn write_json_with_suppressed(
    out: &mut dyn Write,
    findings: Vec<Finding>,
    analysis_errors: Vec<String>,
    suppressed_inline: usize,
) -> Result<(), CliError> {
    let report =
        Report::with_errors(findings, analysis_errors).with_suppressed_inline(suppressed_inline);
    write_json(out, &report)?;
    Ok(())
}

/// The non-`deep`-build arm of every Deep-Tier-gated `#[cfg(feature =
/// "deep")]`/`#[cfg(not(feature = "deep"))]` split: unreachable because the
/// caller already checked `AnalysisTier::Deep.is_available()` (compile-time
/// `false` without the feature) before entering it.
#[cfg(not(feature = "deep"))]
pub(super) fn deep_tier_unreachable() -> ! {
    unreachable!("AnalysisTier::Deep.is_available() is compile-time false without the deep feature")
}

/// matching the GitHub Action's default report-only mode).
pub(super) fn run_dupes(
    options: DupesOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let DupesOptions {
        mode,
        min_tokens,
        baseline_args,
        include_generated,
        include_tests,
    } = options;
    let format = baseline_args.format;
    let workspace = judge::ingest::load(None)?;

    let source_files = workspace_source_files(&workspace);
    let report = judge::duplication::analyze_workspace_with_options(
        source_files,
        mode.into(),
        min_tokens,
        include_generated,
        include_tests,
    );
    // TTY gets a compact top-5 ranked summary; JSON is the documented "full
    // list" escape hatch for the TTY family trailer below, so it must not
    // truncate — an agent or script consuming `--format json` needs every
    // family's members, not just the highest-priority handful.
    let refactoring_summary_limit = match format {
        OutputFormat::Json => report.families.len(),
        OutputFormat::Tty | OutputFormat::Sarif | OutputFormat::Markdown => 5,
    };
    let refactoring_summary = report.refactoring_summary(&workspace.root, refactoring_summary_limit);
    let analysis_errors = analysis_errors(&report.errors);

    let (findings, suppressed_inline) = match suppress_and_baseline(
        report.to_findings(),
        &workspace,
        &analysis_errors,
        &baseline_args,
        std::collections::HashMap::from([(
            judge::duplication::DUPLICATE_RULE.to_string(),
            judge::duplication::DUPLICATE_RULE_REVISION,
        )]),
        Path::new(DEFAULT_BASELINE_DUPES),
        out,
    )? {
        std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
        std::ops::ControlFlow::Continue(rest) => rest,
    };

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline);
            let mut envelope = serde_json::to_value(&report)?;
            envelope["refactoring_summary"] = serde_json::to_value(refactoring_summary)?;
            write_json(out, &envelope)?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`dupes`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(
                out,
                "mode: {}",
                match mode {
                    DupeModeArg::Strict => "strict",
                    DupeModeArg::Mild => "mild",
                    DupeModeArg::Weak => "weak",
                    DupeModeArg::Semantic => "semantic",
                }
            )?;
            writeln!(out, "min tokens: {min_tokens}")?;
            writeln!(out, "clone families: {}", report.families.len())?;
            print_duplication_refactoring_summary(out, &refactoring_summary)?;
            write_error_list(out, "files skipped (parse errors)", &report.errors)?;
            write_excluded_and_suppressed_lines(out, report.excluded_generated, suppressed_inline)?;

            for (index, family) in report
                .refactoring_order(&workspace.root)
                .into_iter()
                .take(DUPE_FAMILY_TTY_LIMIT)
                .enumerate()
            {
                writeln!(out)?;
                writeln!(
                    out,
                    "family #{} — {} members",
                    index + 1,
                    family.members.len()
                )?;
                for member in &family.members {
                    writeln!(
                        out,
                        "  {:>4} tokens  {}:{}-{}  {}",
                        member.token_count,
                        member.file.display(),
                        member.start_line,
                        member.end_line,
                        member.qualified_name
                    )?;
                }
            }
            if report.families.len() > DUPE_FAMILY_TTY_LIMIT {
                writeln!(
                    out,
                    "\n... and {} more families (see --format json for the full list)",
                    report.families.len() - DUPE_FAMILY_TTY_LIMIT
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

fn print_duplication_refactoring_summary(
    out: &mut dyn Write,
    summary: &judge::duplication::RefactoringSummary,
) -> std::io::Result<()> {
    writeln!(
        out,
        "refactoring summary: {} clone families, {} members (repeated tokens, not an automatic merge recommendation)",
        summary.clone_families, summary.clone_members
    )?;
    for family in &summary.top_families {
        writeln!(
            out,
            "  #{}  {} members × {} tokens = {} repeated tokens across {} files  {}",
            family.rank,
            family.members,
            family.tokens_per_member,
            family.duplicated_token_mass,
            family.files.len(),
            family.representative_items.join(", ")
        )?;
    }
    Ok(())
}

/// `cargo judge deps`: dependency-hygiene findings (`misplaced-dependency-kind`)
/// plus the G5 slopsquatting rules (see todo.md §14.2 G5). `name-collision-risk`
/// is fully local and always runs; `phantom-crate`/`phantom-version`/
/// `fresh-low-reputation-dep` need real crates.io network access and only run
/// when `--check-crates-io` is passed — judge makes no network calls by
/// default (see todo.md §1 "kein SaaS, keine Telemetrie, lokal deterministisch").
pub(super) fn run_deps(
    options: DepsOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let DepsOptions {
        baseline_args,
        check_crates_io,
        check_rustc_lints,
        audit_json,
    } = options;
    let format = baseline_args.format;
    let workspace = judge::ingest::load(None)?;

    let report = judge::deps::analyze_workspace(&workspace);
    let mut analysis_errors = analysis_errors(&report.errors);
    let mut findings = report.findings;

    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut rule_revisions = super::combined_analysis::deps_rule_revisions();
    findings.extend(judge::slopsquat::analyze_name_collision(&workspace));

    let dep_graph_report = judge::dep_graph::analyze_workspace(&workspace);
    append_analysis_errors(&mut analysis_errors, &dep_graph_report.errors);
    findings.extend(dep_graph_report.findings);

    if check_crates_io {
        let slopsquat_config = load_judge_toml(&workspace.root)?.slopsquat;
        let cache_root = workspace.root.join("target/judge/slopsquat-cache");

        let index_client = judge::slopsquat::SparseIndexClient::new(cache_root.clone());
        let phantom_report =
            judge::slopsquat::analyze_phantom_dependencies(&workspace, &index_client);
        findings.extend(phantom_report.findings);
        analysis_errors.extend(phantom_report.errors);
        rule_revisions.insert(
            judge::slopsquat::PHANTOM_CRATE_RULE.to_string(),
            judge::slopsquat::PHANTOM_CRATE_RULE_REVISION,
        );
        rule_revisions.insert(
            judge::slopsquat::PHANTOM_VERSION_RULE.to_string(),
            judge::slopsquat::PHANTOM_VERSION_RULE_REVISION,
        );

        let metadata_client = judge::slopsquat::RestMetadataClient::new(cache_root.clone());
        let fresh_report = judge::slopsquat::analyze_fresh_low_reputation(
            &workspace,
            &metadata_client,
            &slopsquat_config,
        );
        findings.extend(fresh_report.findings);
        analysis_errors.extend(fresh_report.errors);
        rule_revisions.insert(
            judge::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE.to_string(),
            judge::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE_REVISION,
        );

        let yanked_report =
            judge::slopsquat::analyze_yanked_dependencies(&workspace, &index_client);
        findings.extend(yanked_report.findings);
        analysis_errors.extend(yanked_report.errors);
        rule_revisions.insert(
            judge::slopsquat::YANKED_DEPENDENCY_RULE.to_string(),
            judge::slopsquat::YANKED_DEPENDENCY_RULE_REVISION,
        );

        let owners_client = judge::slopsquat::RestOwnersClient::new(cache_root);
        let single_maintainer_report =
            judge::slopsquat::analyze_single_maintainer_dependencies(&workspace, &owners_client);
        findings.extend(single_maintainer_report.findings);
        analysis_errors.extend(single_maintainer_report.errors);
        rule_revisions.insert(
            judge::slopsquat::DEP_SINGLE_MAINTAINER_RULE.to_string(),
            judge::slopsquat::DEP_SINGLE_MAINTAINER_RULE_REVISION,
        );
    }

    if check_rustc_lints {
        let rustc_lint_report = judge::deps::analyze_rustc_unused_dependencies(&workspace);
        findings.extend(rustc_lint_report.findings);
        append_analysis_errors(&mut analysis_errors, &rustc_lint_report.errors);
        rule_revisions.insert(
            judge::deps::UNUSED_DEPENDENCY_RULE.to_string(),
            judge::deps::UNUSED_DEPENDENCY_RULE_REVISION,
        );
    }

    if let Some(audit_json_path) = audit_json {
        let vulnerabilities = judge::advisories::read_audit_report(&audit_json_path)?;
        let advisory_report =
            judge::advisories::analyze_vulnerabilities(&workspace, &vulnerabilities);
        findings.extend(advisory_report.findings);
        analysis_errors.extend(advisory_report.errors);
        rule_revisions.insert(
            judge::advisories::KNOWN_VULNERABILITY_RULE.to_string(),
            judge::advisories::KNOWN_VULNERABILITY_RULE_REVISION,
        );
    }

    let (findings, suppressed_inline) = match suppress_and_baseline(
        findings,
        &workspace,
        &analysis_errors,
        &baseline_args,
        rule_revisions,
        Path::new(DEFAULT_BASELINE_DEPS),
        out,
    )? {
        std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
        std::ops::ControlFlow::Continue(rest) => rest,
    };

    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "findings": findings,
                "feature_only_candidates": report.feature_only_candidates,
                "errors": analysis_errors,
                "suppressed_inline": suppressed_inline,
            });
            write_json(out, &envelope)?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`deps`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(out, "dependency findings: {}", findings.len())?;
            write_error_list(out, "errors", &analysis_errors)?;
            write_suppressed_inline_line(out, suppressed_inline)?;

            for finding in &findings {
                let krate = workspace
                    .crates
                    .iter()
                    .find(|krate| krate.manifest_path == finding.location.file);
                let crate_name = krate.map_or("?", |krate| krate.name.as_str());
                if finding.rule == judge::deps::MISPLACED_DEPENDENCY_KIND_RULE {
                    let is_build_dep = krate.is_some_and(|krate| {
                        krate.dependencies.iter().any(|dep| {
                            dep.name == finding.location.item_path
                                && dep.kind == judge::ingest::DependencyKind::Build
                        })
                    });
                    let direction = if is_build_dep {
                        "build-dependency appears unused by build.rs"
                    } else {
                        "should probably be a dev-dependency"
                    };
                    writeln!(
                        out,
                        "  {}  {} — {direction}",
                        crate_name, finding.location.item_path
                    )?;
                } else {
                    writeln!(
                        out,
                        "  [{}] {}  {}",
                        finding.rule, crate_name, finding.location.item_path
                    )?;
                }
            }

            if !report.feature_only_candidates.is_empty() {
                writeln!(out)?;
                writeln!(
                    out,
                    "feature-only candidates (no code usage found; see unused-feature-flag findings above for detail): {}",
                    report.feature_only_candidates.join(", ")
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

pub(super) fn run_coverage(
    options: CoverageOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let CoverageOptions {
        lcov,
        mutants_json,
        baseline_args,
    } = options;
    let format = baseline_args.format;
    let workspace = judge::ingest::load(None)?;

    let coverage = judge::coverage::read_lcov(&lcov, &workspace.root)?;

    let complexity_source_files = workspace_source_files(&workspace);
    let complexity_report = judge::complexity::analyze_workspace(complexity_source_files, false);
    let mut analysis_errors = analysis_errors(&complexity_report.errors);
    for missing in &coverage.missing_files {
        analysis_errors.push(format!(
            "{}: coverage data references this file, but it no longer exists in the workspace",
            missing.display()
        ));
    }

    let mut findings = judge::coverage::untested_hotspots(
        &complexity_report.functions,
        &std::collections::HashMap::new(),
        &coverage,
        &workspace.root,
    );

    let mut rule_revisions = std::collections::HashMap::from([(
        judge::coverage::UNTESTED_HOTSPOT_RULE.to_string(),
        judge::coverage::UNTESTED_HOTSPOT_RULE_REVISION,
    )]);

    if let Some(mutants_json_path) = mutants_json {
        let mutants_report = judge::mutants::read_mutants_report(&mutants_json_path)?;
        findings.extend(mutants_report.findings);
        analysis_errors.extend(mutants_report.errors);
        rule_revisions.insert(
            judge::mutants::MUTATION_SURVIVOR_RULE.to_string(),
            judge::mutants::MUTATION_SURVIVOR_RULE_REVISION,
        );
    }

    let no_coverage_data_source_files = workspace_source_files(&workspace);
    let no_coverage_data = coverage.files_without_coverage_data(
        &workspace.root,
        no_coverage_data_source_files.map(|file| file.path.as_path()),
    );

    let test_ratios = judge::coverage::test_ratios(&workspace);

    let (findings, _suppressed_inline) = match suppress_and_baseline(
        findings,
        &workspace,
        &analysis_errors,
        &baseline_args,
        rule_revisions,
        Path::new(DEFAULT_BASELINE_COVERAGE),
        out,
    )? {
        std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
        std::ops::ControlFlow::Continue(rest) => rest,
    };

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors);
            let mut value = serde_json::to_value(&report)?;
            value["files_without_coverage_data"] = serde_json::to_value(
                no_coverage_data
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>(),
            )?;
            value["test_ratios"] = serde_json::to_value(
                test_ratios
                    .iter()
                    .map(|ratio| {
                        serde_json::json!({
                            "crate": ratio.crate_name,
                            "production_loc": ratio.production_loc,
                            "test_loc": ratio.test_loc,
                            "ratio": ratio.ratio(),
                        })
                    })
                    .collect::<Vec<_>>(),
            )?;
            write_json(out, &value)?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`coverage`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(out, "untested hotspots: {}", findings.len())?;
            write_error_list(out, "errors", &analysis_errors)?;
            for finding in &findings {
                writeln!(
                    out,
                    "  {}:{}  {}",
                    finding.location.file.display(),
                    finding.location.line,
                    finding.location.item_path
                )?;
            }
            if !no_coverage_data.is_empty() {
                writeln!(out)?;
                writeln!(
                    out,
                    "no coverage data (not asserted as 0%): {}",
                    no_coverage_data.len()
                )?;
                for file in &no_coverage_data {
                    writeln!(out, "  {}", file.display())?;
                }
            }
            if !test_ratios.is_empty() {
                writeln!(out)?;
                writeln!(out, "test-to-code LOC ratio (metric only, no verdict):")?;
                for ratio in &test_ratios {
                    match ratio.ratio() {
                        Some(value) => writeln!(
                            out,
                            "  {}: {:.2} (test {} / production {})",
                            ratio.crate_name, value, ratio.test_loc, ratio.production_loc
                        )?,
                        None => writeln!(
                            out,
                            "  {}: undefined (test {} / production 0)",
                            ratio.crate_name, ratio.test_loc
                        )?,
                    }
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

pub(super) fn run_boundaries(
    options: BoundariesOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let BoundariesOptions {
        config: config_path,
        baseline_args,
        graph,
    } = options;
    let format = baseline_args.format;

    if let Some(graph_format) = graph {
        let crate_graph = judge::boundaries::build_crate_graph(None)?;
        let rendered = match graph_format {
            GraphFormat::Dot => crate_graph.to_dot(),
            GraphFormat::Mermaid => crate_graph.to_mermaid(),
        };
        write!(out, "{rendered}")?;
        return Ok(CommandOutcome::Clean);
    }

    let workspace = judge::ingest::load(None)?;

    let config_path = config_path.unwrap_or_else(|| workspace.root.join("judge.toml"));
    if !config_path.exists() {
        writeln!(
            out,
            "no judge.toml found — boundaries are opt-in, nothing to check"
        )?;
        return Ok(CommandOutcome::Clean);
    }

    let config: judge::boundaries::BoundaryConfig = parse_boundary_config(&config_path)?;

    let boundaries = judge::boundaries::evaluate(&workspace, &config)?;
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut findings = boundaries.findings;
    // `evaluate()` itself has no per-file soft-error channel (its
    // `--no-deps` `cargo_metadata` resolve either succeeds outright or
    // fails via `?` above) — this only ever gets entries from the Deep-Tier
    // pass below.
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut analysis_errors: Vec<String> = Vec::new();

    // Deep-Tier upgrade to `[[module_boundary]]`: real symbol reference
    // resolution instead of the Fast Tier's `syn`-based text scan — see
    // `judge::boundaries_deep` module docs. Only available in a build
    // compiled with `--features deep`; a Fast Tier build silently skips it
    // (the Fast-Tier `module-boundary-violation` check above already ran),
    // matching `run_api_surface`'s same precedent for `semver-hazard`'s
    // Deep-Tier sub-case.
    if judge::AnalysisTier::Deep.is_available() {
        #[cfg(feature = "deep")]
        {
            let deep_report = judge::boundaries_deep::analyze_workspace(&workspace, &config)
                .map_err(|err| CliError::Analyzer(err.to_string()))?;
            findings.extend(deep_report.findings);
            append_analysis_errors(&mut analysis_errors, &deep_report.errors);
        }
        #[cfg(not(feature = "deep"))]
        {
            deep_tier_unreachable();
        }
    }

    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut rule_revisions = super::combined_analysis::boundaries_rule_revisions();
    rule_revisions.insert(
        judge::boundaries::MODULE_BOUNDARY_VIOLATION_RULE.to_string(),
        judge::boundaries::MODULE_BOUNDARY_VIOLATION_RULE_REVISION,
    );
    #[cfg(feature = "deep")]
    if judge::AnalysisTier::Deep.is_available() {
        rule_revisions.insert(
            judge::boundaries_deep::MODULE_BOUNDARY_VIOLATION_DEEP_RULE.to_string(),
            judge::boundaries_deep::MODULE_BOUNDARY_VIOLATION_DEEP_RULE_REVISION,
        );
    }
    let (findings, suppressed_inline) = match suppress_and_baseline(
        findings,
        &workspace,
        &analysis_errors,
        &baseline_args,
        rule_revisions,
        Path::new(DEFAULT_BASELINE_BOUNDARIES),
        out,
    )? {
        std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
        std::ops::ControlFlow::Continue(rest) => rest,
    };

    match format {
        OutputFormat::Json => {
            write_json_with_suppressed(out, findings, analysis_errors, suppressed_inline)?
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`boundaries`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            writeln!(out, "boundary rules: {}", config.boundaries.len())?;
            writeln!(out, "findings: {}", findings.len())?;
            write_error_list(out, "analysis errors", &analysis_errors)?;
            write_suppressed_inline_line(out, suppressed_inline)?;
            for finding in &findings {
                writeln!(
                    out,
                    "  [{}] {} — {}",
                    severity_label(finding.severity),
                    finding.rule,
                    finding.location.item_path
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// `unlinked-file`/`orphan-module` findings from resolving each crate's real
/// `mod` tree (see `judge::module_graph`). Subcommand-only, matching
/// `Distribution`/`Provenance`/`ApiSurface`'s own opt-in precedent — no
/// config needed, but not part of bare `cargo judge`/`audit`/`health`.
pub(super) fn run_module_graph(
    options: ModuleGraphOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ModuleGraphOptions {
        baseline_args,
        include_generated,
    } = options;
    let format = baseline_args.format;
    let workspace = judge::ingest::load(None)?;

    let report = judge::module_graph::analyze_workspace(&workspace, include_generated);
    let analysis_errors = analysis_errors(&report.errors);
    let excluded_generated = report.excluded_generated;

    let (findings, suppressed_inline) = match suppress_and_baseline(
        report.findings,
        &workspace,
        &analysis_errors,
        &baseline_args,
        std::collections::HashMap::from([
            (
                judge::module_graph::UNLINKED_FILE_RULE.to_string(),
                judge::module_graph::UNLINKED_FILE_RULE_REVISION,
            ),
            (
                judge::module_graph::ORPHAN_MODULE_RULE.to_string(),
                judge::module_graph::ORPHAN_MODULE_RULE_REVISION,
            ),
        ]),
        Path::new(DEFAULT_BASELINE_MODULE_GRAPH),
        out,
    )? {
        std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
        std::ops::ControlFlow::Continue(rest) => rest,
    };

    match format {
        OutputFormat::Json => {
            write_json_with_suppressed(out, findings, analysis_errors, suppressed_inline)?
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`module-graph`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            let (unlinked, orphaned): (Vec<&Finding>, Vec<&Finding>) = findings
                .iter()
                .partition(|finding| finding.rule == judge::module_graph::UNLINKED_FILE_RULE);
            write_error_list(out, "files skipped (parse errors)", &analysis_errors)?;
            write_excluded_and_suppressed_lines(out, excluded_generated, suppressed_inline)?;
            writeln!(out, "unlinked-file findings: {}", unlinked.len())?;
            for finding in &unlinked {
                writeln!(
                    out,
                    "  [{}] {}",
                    severity_label(finding.severity),
                    finding.location.item_path
                )?;
            }
            writeln!(out)?;
            writeln!(out, "orphan-module findings: {}", orphaned.len())?;
            for finding in &orphaned {
                writeln!(
                    out,
                    "  [{}] {}",
                    severity_label(finding.severity),
                    finding.location.item_path
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Focused unsafe-code review. The result is a projection of concrete syntax
/// findings, not a claim that a particular author introduced unsafe code.
pub(super) fn run_unsafe(
    options: FocusedAnalysisOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let source_files = workspace_source_files(&workspace);
    let report = judge::security::analyze_workspace(source_files, options.include_generated);
    let findings = findings_matching(
        report.findings,
        &[
            judge::security::UNSAFE_SURFACE_RULE,
            judge::security::UNSAFE_DENSITY_RULE,
        ],
    );
    render_focused(
        "unsafe",
        options.format,
        &workspace,
        findings,
        analysis_errors(&report.errors),
        out,
    )
}

/// Focused error-handling review built from existing evidence-backed syntax
/// rules. Type-dependent conclusions remain a Deep-Tier follow-up.
pub(super) fn run_errors(
    options: FocusedAnalysisOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let report = analyze_slop_workspace(&workspace, options.include_generated)?;
    let findings = findings_matching(
        report.findings,
        &[
            judge::slop::SWALLOWED_RESULT_RULE,
            judge::slop::EMPTY_ERROR_ARM_RULE,
            judge::slop::CATCH_ALL_ERROR_RULE,
            judge::slop::CONTEXT_FREE_PROPAGATION_RULE,
            judge::slop::SILENT_DEFAULT_RULE,
        ],
    );
    render_focused(
        "errors",
        options.format,
        &workspace,
        findings,
        analysis_errors(&report.errors),
        out,
    )
}

/// Test-structure review. It reports relationships judge can actually see and
/// never turns an absent syntactic relation into a coverage claim.
pub(super) fn run_tests(
    options: FocusedAnalysisOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let source_files = workspace_source_files(&workspace);
    let report = judge::slop::analyze_workspace(source_files, options.include_generated, false);
    let findings = findings_matching(
        report.findings,
        &[
            judge::slop::ASSERTION_FREE_TEST_RULE,
            judge::slop::TAUTOLOGICAL_TEST_RULE,
            judge::slop::IGNORED_TEST_ACCUMULATION_RULE,
        ],
    );
    render_focused(
        "tests",
        options.format,
        &workspace,
        findings,
        analysis_errors(&report.errors),
        out,
    )
}

/// Current-state mechanical code smells. The report deliberately contains no
/// author, model, or provenance classification.
pub(super) fn run_slop(
    options: FocusedAnalysisOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let report = analyze_slop_workspace(&workspace, options.include_generated)?;
    render_focused(
        "slop",
        options.format,
        &workspace,
        report.findings,
        analysis_errors(&report.errors),
        out,
    )
}

/// Keeps only the findings whose rule is one of `rules` — the shared
/// "project this analyzer's full report down to one focused command's rule
/// subset" step behind `run_unsafe`/`run_errors`/`run_tests`.
fn findings_matching(findings: Vec<Finding>, rules: &[&str]) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| rules.contains(&finding.rule.as_str()))
        .collect()
}

fn render_focused(
    label: &str,
    format: OutputFormat,
    workspace: &judge::ingest::Workspace,
    mut findings: Vec<Finding>,
    errors: Vec<String>,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    judge::finding::sort_by_severity_desc(&mut findings);
    match format {
        OutputFormat::Json => write_json(
            out,
            &serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "analysis": label,
                "scope": {
                    "tier": "fast",
                    "claim": "Findings are current-state syntax and workspace facts. Absence of a finding is not proof of absence in unanalysed generated or semantic code."
                },
                "report": Report::with_errors(findings, errors),
            }),
        )?,
        OutputFormat::Sarif => write_sarif(out, &workspace.root, findings, errors, None)?,
        OutputFormat::Tty => judge::report::write_findings_tty(
            out,
            &workspace.root,
            format!("Judge {label}"),
            &findings,
            &errors,
        )?,
        OutputFormat::Markdown => {
            return Err(unsupported_format(label, format, "tty, json, sarif"));
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Public-API-surface findings (`undocumented-public-item` and
/// `semver-hazard` — see todo.md §I). Subcommand-only: deliberately not
/// wired into `collect_findings`/`run_all`/`SLOP_RULES`, matching
/// `Distribution`/`Provenance`/`DeadCode`'s own opt-in precedent. In a build
/// compiled with `--features deep`, also runs `semver-hazard`'s
/// `leaked_dependency_type` sub-case (see `judge::api_surface_deep`) on top
/// of the two Fast-Tier sub-cases — unlike `dead-code`, this command still
/// produces useful output without the Deep Tier, so it degrades rather than
/// erroring when built without it.
pub(super) fn run_api_surface(
    options: ApiSurfaceOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ApiSurfaceOptions {
        baseline_args:
            BaselineArgs {
                format,
                save_baseline,
                baseline,
            },
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;
    let boundary_config = load_judge_toml(&workspace.root)?;
    judge::boundaries::validate_internal_crates(&workspace, &boundary_config)?;

    let report = judge::api_surface::analyze_workspace(workspace.crates.iter(), include_generated);
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut findings = report.findings;
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut analysis_errors = analysis_errors(&report.errors);

    // The third `semver-hazard` sub-case (`leaked_dependency_type`) needs
    // the Deep Tier's type resolution — see `judge::api_surface_deep`'s
    // module docs. Only available in a build compiled with `--features
    // deep`; a Fast Tier build silently skips it rather than erroring,
    // unlike `dead-code` (whose *entire* subcommand needs the Deep Tier),
    // because the other two `semver-hazard` sub-cases and
    // `undocumented-public-item` are useful on their own.
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut deep_errors: Vec<String> = Vec::new();
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut deep_checked: Option<usize> = None;
    if judge::AnalysisTier::Deep.is_available() {
        #[cfg(feature = "deep")]
        {
            let deep_report = judge::api_surface_deep::analyze_workspace(
                &workspace,
                &boundary_config.internal_crates,
            )
            .map_err(|err| CliError::Analyzer(err.to_string()))?;
            deep_checked = Some(deep_report.checked);
            findings.extend(deep_report.findings);
            deep_errors = super::baseline_output::analysis_errors(&deep_report.errors);
            analysis_errors.extend(deep_errors.iter().cloned());
        }
        #[cfg(not(feature = "deep"))]
        {
            deep_tier_unreachable();
        }
    }

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    // API-surface-size trend against a saved baseline (see todo.md §I
    // "API-Surface-Größe pro Crate, Trend gegen Baseline") — computed before
    // `handle_baseline`/`handle_baseline_with_trend` run below, same "trend
    // vor Absolutwert" ordering `run_health` uses for the health-score
    // trend, since a failing findings-delta verdict there ends the run
    // before reaching any code after it. `baseline_size` stays `None` for a
    // plain run and for `--save-baseline` — every crate's `delta` is then
    // `None` too, which is exactly what a save needs (only `item_count`
    // matters there).
    let baseline_size = if !save_baseline && let Some(path) = &baseline {
        judge::baseline::load(path)?.api_surface_size
    } else {
        None
    };
    let size_trend =
        judge::api_surface::size_trend(&report.api_surface_size, baseline_size.as_ref());
    if matches!(format, OutputFormat::Tty) {
        print_api_surface_size(out, &size_trend, baseline.is_some() && !save_baseline)?;
    }

    if save_baseline || baseline.is_some() {
        #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
        let mut rule_revisions = std::collections::HashMap::from([
            (
                judge::api_surface::UNDOCUMENTED_PUBLIC_ITEM_RULE.to_string(),
                judge::api_surface::UNDOCUMENTED_PUBLIC_ITEM_RULE_REVISION,
            ),
            (
                judge::api_surface::SEMVER_HAZARD_RULE.to_string(),
                judge::api_surface::SEMVER_HAZARD_RULE_REVISION,
            ),
        ]);
        #[cfg(feature = "deep")]
        rule_revisions.insert(
            judge::api_surface_deep::INTERNAL_LEAK_RULE.to_string(),
            judge::api_surface_deep::INTERNAL_LEAK_RULE_REVISION,
        );
        #[cfg(feature = "deep")]
        rule_revisions.insert(
            judge::api_surface_deep::RE_EXPORT_CHAIN_RULE.to_string(),
            judge::api_surface_deep::RE_EXPORT_CHAIN_RULE_REVISION,
        );
        let current_size: std::collections::HashMap<String, usize> = size_trend
            .iter()
            .map(|trend| (trend.crate_name.clone(), trend.item_count))
            .collect();
        return handle_baseline_with_trend(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_API_SURFACE),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            None,
            Some(&current_size),
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline)
                .with_api_surface_size(
                    size_trend
                        .iter()
                        .map(|trend| (trend.crate_name.clone(), trend.item_count))
                        .collect(),
                );
            write_json(out, &report)?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`api-surface`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            writeln!(out, "undocumented public items: {}", findings.len())?;
            if let Some(checked) = deep_checked {
                writeln!(out, "pub fns checked (leaked_dependency_type): {checked}")?;
            }
            write_error_list(out, "files skipped (parse errors)", &report.errors)?;
            write_error_list(out, "leaked-dependency-type analysis errors", &deep_errors)?;
            write_excluded_and_suppressed_lines(out, report.excluded_generated, suppressed_inline)?;
            for finding in &findings {
                writeln!(
                    out,
                    "  [{}] {}:{}  {}",
                    severity_label(finding.severity),
                    finding.location.file.display(),
                    finding.location.line,
                    finding.location.item_path
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// One `api surface: <crate> <count> items` line per crate (see todo.md §I
/// "API-Surface-Größe pro Crate, Trend gegen Baseline"). Appends `(Δ<delta>
/// vs baseline)` when [`judge::api_surface::CrateSizeTrend::delta`] is
/// comparable; when `--baseline` was given but the loaded baseline recorded
/// no `api_surface_size` (older schema, or a baseline saved by a different
/// command) or lacks that particular crate, `baseline_requested` makes this
/// say so explicitly instead of silently printing a plain count as if no
/// baseline had been given (mirrors [`print_score_trend`]'s "explicit reason
/// instead of a false delta" rule).
fn print_api_surface_size(
    out: &mut dyn Write,
    trend: &[judge::api_surface::CrateSizeTrend],
    baseline_requested: bool,
) -> std::io::Result<()> {
    for crate_trend in trend {
        match crate_trend.delta {
            Some(delta) => writeln!(
                out,
                "api surface: {} {} items (\u{394}{delta:+} vs baseline)",
                crate_trend.crate_name, crate_trend.item_count
            )?,
            None if baseline_requested => writeln!(
                out,
                "api surface: {} {} items (not comparable to baseline)",
                crate_trend.crate_name, crate_trend.item_count
            )?,
            None => writeln!(
                out,
                "api surface: {} {} items",
                crate_trend.crate_name, crate_trend.item_count
            )?,
        }
    }
    Ok(())
}

fn suppress_and_baseline(
    findings: Vec<Finding>,
    workspace: &judge::ingest::Workspace,
    analysis_errors: &[String],
    baseline_args: &BaselineArgs,
    rule_revisions: std::collections::HashMap<String, u32>,
    default_save_path: &Path,
    out: &mut dyn Write,
) -> Result<std::ops::ControlFlow<CommandOutcome, (Vec<Finding>, usize)>, CliError> {
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    let baseline_request = BaselineRequest::new(
        baseline_args.save_baseline,
        baseline_args.baseline.as_deref(),
        baseline_args.format,
    );

    if let Some(result) = baseline_request.handle(
        BaselineInput {
            workspace_root: &workspace.root,
            findings: &findings,
            analysis_errors,
            rule_revisions,
            default_save_path,
            total_loc: judge::health_score::total_authored_loc(workspace),
        },
        out,
    ) {
        return result.map(std::ops::ControlFlow::Break);
    }

    Ok(std::ops::ControlFlow::Continue((
        findings,
        suppressed_inline,
    )))
}
