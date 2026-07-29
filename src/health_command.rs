//! `cargo judge health`: health aggregation, score, and report selection.

use super::*;

pub(super) fn run(options: HealthOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let HealthOptions {
        score: show_score,
        show_cascades,
        baseline_args:
            BaselineArgs {
                format,
                save_baseline,
                baseline,
            },
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let report = judge::complexity::analyze_workspace(source_files, include_generated);
    let mut analysis_errors = analysis_errors(&report.errors);
    let mut functions = report.functions;
    functions.sort_by_key(|function| std::cmp::Reverse(function.cyclomatic));

    let (hotspots, hotspot_error) =
        match judge::git::hotspots(&workspace.root, &functions, judge::git::DEFAULT_WINDOW_DAYS) {
            Ok(hotspots) => (hotspots, None),
            Err(err) => {
                let error = err.to_string();
                analysis_errors.push(error.clone());
                (Vec::new(), Some(error))
            }
        };
    let mut findings: Vec<_> = hotspots
        .iter()
        .take(HOTSPOT_LIMIT)
        .map(judge::git::Hotspot::to_finding)
        .collect();

    // AI-slop signals (see todo.md §G "AI-Slop-Signale", §12 "Entscheidungen":
    // "Der Slop-Block ist Teil von `health`, kein eigener Sub-Command") — a
    // second, fresh iterator over the same source files, since the first one
    // was consumed by `complexity::analyze_workspace` above.
    let slop_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let rules_config = load_judge_toml(&workspace.root)?.rules;
    let slop = judge::slop::analyze_workspace(
        slop_source_files,
        include_generated,
        rules_config.catch_all_error.allow_anyhow_at_boundary,
    );
    append_analysis_errors(&mut analysis_errors, &slop.errors);
    findings.extend(slop.findings);

    // G4 structural slop (see todo.md §3.G): same whole-workspace scope as
    // the analyzers above, so it's wired in here too rather than left
    // `health`-only-missing.
    findings.extend(judge::slop_structural::complexity_inflation(&functions));
    findings.extend(judge::complexity::signature_complexity(&functions));
    findings.extend(judge::complexity::maintainability_index(&functions));
    match judge::git::churn(&workspace.root, 14) {
        Ok(two_week_churn) => {
            findings.extend(judge::slop_structural::churn_hotspots(&two_week_churn));
        }
        Err(err) => analysis_errors.push(err.to_string()),
    }
    let abstraction_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    findings.extend(judge::slop_structural::analyze_workspace_structural(
        abstraction_source_files,
    ));

    let fragile_substring_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    findings.extend(judge::slop_structural::fragile_substring_classification(
        fragile_substring_source_files,
    ));

    let security_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let security = judge::security::analyze_workspace(security_source_files, include_generated);
    append_analysis_errors(&mut analysis_errors, &security.errors);
    findings.extend(security.findings);

    // Inline `judge-ignore` suppression (todo.md §5): applied after every
    // detector above has merged its findings in, so a suppressed finding
    // never reaches score, baseline diff, or verdict below.
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    let excluded_generated =
        report.excluded_generated + slop.excluded_generated + security.excluded_generated;

    // The LOC denominator is only computed — and an unreadable file only
    // fatal — where a score or a saved baseline depends on it (see todo.md
    // §15.1: no score on an incomplete basis). Plain `health` keeps
    // reporting per-file read problems as analysis errors instead.
    let total_loc = if show_score || save_baseline || baseline.is_some() {
        judge::health_score::total_authored_loc_checked(&workspace)?
    } else {
        0 // unused: every consumer below sits behind one of the flags above
    };

    // Compute the score trend before `handle_baseline` runs below, since a
    // failing verdict there ends the run before reaching any code after it
    // (see todo.md §4 point 4, "Trend vor Absolutwert" — the score is
    // never shown without this). Written here for TTY; JSON gets it embedded
    // in the delta envelope by `handle_baseline_with_trend`.
    let score_trend = if show_score
        && !save_baseline
        && let Some(path) = &baseline
    {
        Some(compute_score_trend(&workspace, &findings, total_loc, path)?)
    } else {
        None
    };
    if matches!(format, OutputFormat::Tty)
        && let Some(trend) = &score_trend
    {
        print_score_trend(out, trend)?;
    }

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::git::HOTSPOT_RULE.to_string(),
                judge::git::HOTSPOT_RULE_REVISION,
            ),
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
                judge::slop_structural::CHURN_HOTSPOT_RULE.to_string(),
                judge::slop_structural::CHURN_HOTSPOT_RULE_REVISION,
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
        ]);
        return handle_baseline_with_trend(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_HEALTH),
                format,
                total_loc,
            },
            score_trend.as_ref(),
            None,
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            // With `--score`, the score is embedded next to the report
            // fields (additive, so the plain report shape stays intact) —
            // an unavailable score is already an error above instead of
            // being silently omitted (see todo.md §15.1).
            let score = if show_score {
                let config = load_judge_toml(&workspace.root)?;
                Some(require_score(judge::health_score::compute(
                    &findings,
                    total_loc,
                    &workspace,
                    &config.crate_profiles,
                ))?)
            } else {
                None
            };
            let report = Report::with_errors(findings, analysis_errors)
                .with_universe(judge::finding::AnalysisUniverse::fast(
                    &workspace,
                    include_generated,
                ))
                .with_suppressed_inline(suppressed_inline);
            let mut value = serde_json::to_value(&report).unwrap();
            if let Some(score) = score {
                value["score"] = serde_json::to_value(&score).unwrap();
            }
            write_json(out, &value)?;
        }
        OutputFormat::Sarif => {
            if show_score {
                // SARIF has no result slot a numeric score would surface in
                // — rejected rather than silently dropped.
                return Err(CliError::Config(
                    "--score is not supported with --format sarif; use --format json".to_string(),
                ));
            }
            write_sarif(
                out,
                &workspace.root,
                findings,
                analysis_errors,
                Some(judge::finding::AnalysisUniverse::fast(
                    &workspace,
                    include_generated,
                )),
            )?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`health`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(out, "functions analyzed: {}", functions.len())?;
            if !analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", analysis_errors.len())?;
                for error in &analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
            if excluded_generated > 0 {
                writeln!(
                    out,
                    "excluded (generated): {excluded_generated} (see --include-generated)"
                )?;
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }

            writeln!(out)?;
            writeln!(out, "top complexity (cyclomatic):")?;
            for function in functions.iter().take(15) {
                writeln!(
                    out,
                    "  {:>3}  {}:{}  {}",
                    function.cyclomatic,
                    function.file.display(),
                    function.line,
                    function.qualified_name
                )?;
            }

            writeln!(out)?;
            if let Some(error) = hotspot_error {
                writeln!(out, "hotspots: unavailable ({error})")?;
            } else {
                print_hotspots(out, &hotspots, &findings, show_cascades)?;
            }

            writeln!(out)?;
            print_slop(out, &findings, show_cascades)?;

            if show_score {
                writeln!(out)?;
                let config = load_judge_toml(&workspace.root)?;
                let score = require_score(judge::health_score::compute(
                    &findings,
                    total_loc,
                    &workspace,
                    &config.crate_profiles,
                ))?;
                let advisory_count = findings
                    .iter()
                    .filter(|finding| !finding.is_gating())
                    .count();
                writeln!(
                    out,
                    "health score: {:.1} ({}) — {} authored LOC, {} fail, {} warn, {} advisory (not scored)",
                    score.score,
                    score.grade.label(),
                    score.total_loc,
                    score.fail_count,
                    score.warn_count,
                    advisory_count,
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}
