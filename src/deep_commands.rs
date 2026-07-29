//! Commands that optionally use judge's rust-analyzer-backed Deep Tier.

use super::*;

#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
pub(super) fn run_dead_code(
    options: DeadCodeOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    if !judge::AnalysisTier::Deep.is_available() {
        return Err(CliError::Analyzer(
            "dead-code analysis needs the Deep Tier — rebuild with `cargo install --path . --features deep` (see todo.md §2.1)".to_string(),
        ));
    }

    #[cfg(feature = "deep")]
    {
        run_dead_code_deep(options, out)
    }
    #[cfg(not(feature = "deep"))]
    {
        unreachable!(
            "AnalysisTier::Deep.is_available() is compile-time false without the deep feature"
        )
    }
}

#[cfg(feature = "deep")]
fn run_dead_code_deep(
    options: DeadCodeOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let DeadCodeOptions {
        include_tests,
        baseline_args:
            BaselineArgs {
                format,
                save_baseline,
                baseline,
            },
    } = options;
    let workspace = judge::ingest::load(None)?;

    let dead_code_report = judge::dead_code::analyze_workspace(&workspace, include_tests)?;

    // `feature-gated-dead-code` is opt-in via `judge.toml` `[feature_matrix]`
    // — with `combinations` absent or empty (the default), this performs no
    // analysis at all (see `judge::feature_matrix` module docs).
    let feature_matrix_config = load_judge_toml(&workspace.root)?.feature_matrix;
    let feature_matrix_report = judge::feature_matrix::analyze_workspace(
        &workspace,
        &feature_matrix_config.combinations,
        include_tests,
    )?;

    let dead_trait_impl_report = judge::dead_trait_impl::analyze_workspace(&workspace)?;

    // `duplicative-reinvention` needs clone-family membership — cheap,
    // Fast Tier, same defaults `cargo judge health`/`dupes` already use.
    let dupes_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let dupes = judge::duplication::analyze_workspace(
        dupes_source_files,
        DupeMode::Mild,
        judge::duplication::DEFAULT_MIN_TOKENS,
        false,
    );

    // `monomorphization-load` needs each function's `generic_param_count` —
    // cheap, Fast Tier, the same `Vec<FunctionInfo>` `signature-complexity`
    // already computes.
    let monomorphization_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity = judge::complexity::analyze_workspace(monomorphization_source_files, false);

    let structural_report = judge::slop_structural_deep::analyze_workspace(
        &workspace,
        &dupes,
        include_tests,
        &complexity.functions,
    )?;

    let mut findings = dead_code_report.findings;
    findings.extend(feature_matrix_report.findings);
    findings.extend(dead_trait_impl_report.findings);
    findings.extend(structural_report.findings);

    let mut analysis_errors = analysis_errors(&dead_code_report.errors);
    append_analysis_errors(&mut analysis_errors, &feature_matrix_report.errors);
    append_analysis_errors(&mut analysis_errors, &dead_trait_impl_report.errors);
    append_analysis_errors(&mut analysis_errors, &dupes.errors);
    append_analysis_errors(&mut analysis_errors, &complexity.errors);
    append_analysis_errors(&mut analysis_errors, &structural_report.errors);

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    let baseline_request = BaselineRequest::new(save_baseline, baseline.as_deref(), format);
    if baseline_request.is_requested() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::dead_code::UNUSED_PUB_WORKSPACE_RULE.to_string(),
                judge::dead_code::UNUSED_PUB_WORKSPACE_RULE_REVISION,
            ),
            (
                judge::dead_code::UNUSED_PUB_API_RULE.to_string(),
                judge::dead_code::UNUSED_PUB_API_RULE_REVISION,
            ),
            (
                judge::dead_code::DEAD_ENUM_VARIANT_RULE.to_string(),
                judge::dead_code::DEAD_ENUM_VARIANT_RULE_REVISION,
            ),
            (
                judge::dead_code::TEST_ONLY_PUB_RULE.to_string(),
                judge::dead_code::TEST_ONLY_PUB_RULE_REVISION,
            ),
            (
                judge::dead_code::UNREACHABLE_FROM_ENTRY_RULE.to_string(),
                judge::dead_code::UNREACHABLE_FROM_ENTRY_RULE_REVISION,
            ),
            (
                judge::dead_code::CRATE_COUPLING_RULE.to_string(),
                judge::dead_code::CRATE_COUPLING_RULE_REVISION,
            ),
            (
                judge::dead_code::MODULE_COUPLING_RULE.to_string(),
                judge::dead_code::MODULE_COUPLING_RULE_REVISION,
            ),
            (
                judge::feature_matrix::FEATURE_GATED_DEAD_CODE_RULE.to_string(),
                judge::feature_matrix::FEATURE_GATED_DEAD_CODE_RULE_REVISION,
            ),
            (
                judge::dead_trait_impl::DEAD_TRAIT_IMPL_RULE.to_string(),
                judge::dead_trait_impl::DEAD_TRAIT_IMPL_RULE_REVISION,
            ),
            (
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE.to_string(),
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE_REVISION,
            ),
            (
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE.to_string(),
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE_REVISION,
            ),
            (
                judge::slop_structural_deep::MONOMORPHIZATION_LOAD_RULE.to_string(),
                judge::slop_structural_deep::MONOMORPHIZATION_LOAD_RULE_REVISION,
            ),
        ]);
        return baseline_request
            .handle(
                BaselineInput {
                    workspace_root: &workspace.root,
                    findings: &findings,
                    analysis_errors: &analysis_errors,
                    rule_revisions,
                    default_save_path: Path::new(DEFAULT_BASELINE_DEAD_CODE),
                    total_loc: judge::health_score::total_authored_loc(&workspace),
                },
                out,
            )
            .expect("baseline request was checked above");
    }

    // §0 demands the Deep Tier fully describes what its claims are
    // about — JSON carries the structured universe, TTY a compact echo.
    let universe = judge::finding::AnalysisUniverse::deep(&workspace, include_tests);
    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_universe(universe)
                .with_suppressed_inline(suppressed_inline);
            write_json(out, &report)?;
        }
        OutputFormat::Sarif => {
            write_sarif(
                out,
                &workspace.root,
                findings,
                analysis_errors,
                Some(universe),
            )?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`dead-code`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            print_universe_tty(out, &universe)?;
            writeln!(out, "pub items checked: {}", dead_code_report.checked)?;
            writeln!(
                out,
                "functions checked (connectivity-drop): {}",
                structural_report.checked
            )?;
            if !analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", analysis_errors.len())?;
                for error in &analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }
            for rule in [
                judge::dead_code::UNUSED_PUB_WORKSPACE_RULE,
                judge::dead_code::UNUSED_PUB_API_RULE,
                judge::dead_code::DEAD_ENUM_VARIANT_RULE,
                judge::dead_code::TEST_ONLY_PUB_RULE,
                judge::dead_code::UNREACHABLE_FROM_ENTRY_RULE,
                judge::dead_code::CRATE_COUPLING_RULE,
                judge::dead_code::MODULE_COUPLING_RULE,
                judge::feature_matrix::FEATURE_GATED_DEAD_CODE_RULE,
                judge::dead_trait_impl::DEAD_TRAIT_IMPL_RULE,
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE,
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE,
                judge::slop_structural_deep::MONOMORPHIZATION_LOAD_RULE,
            ] {
                let rule_findings: Vec<&Finding> = findings
                    .iter()
                    .filter(|finding| finding.rule == rule)
                    .collect();
                writeln!(out, "{rule} findings: {}", rule_findings.len())?;
                for finding in rule_findings {
                    writeln!(
                        out,
                        "  [{}] {}:{}  {}",
                        severity_label(finding.severity),
                        finding.location.file.display(),
                        finding.location.line,
                        finding.location.item_path
                    )?;
                    if let Some(limitations) = &finding.limitations {
                        writeln!(out, "    limitations: {limitations:?}")?;
                    }
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Compact TTY rendering of the deep analysis universe. JSON carries the
/// same facts structurally; this keeps the terminal report equally explicit.
#[cfg(feature = "deep")]
fn print_universe_tty(
    out: &mut dyn Write,
    universe: &judge::finding::AnalysisUniverse,
) -> std::io::Result<()> {
    let fidelity = |status: judge::finding::FidelityStatus| match status {
        judge::finding::FidelityStatus::Enabled => "enabled",
        judge::finding::FidelityStatus::Disabled => "disabled",
        judge::finding::FidelityStatus::NotApplicable => "not applicable",
    };
    writeln!(
        out,
        "analysis universe: {} tier, judge {}, {}, commit {}",
        universe.tier,
        universe.judge_version,
        universe.platform,
        universe
            .commit
            .as_deref()
            .unwrap_or("none (no git repository)")
    )?;
    writeln!(
        out,
        "  targets: {}; features: {}; entry points: {}",
        universe.targets.join(", "),
        universe.features.join(", "),
        universe.entry_points.join(", ")
    )?;
    writeln!(
        out,
        "  include tests: {}; include generated: {}; proc-macro expansion: {}; build scripts: {}",
        universe.include_tests,
        universe.include_generated,
        fidelity(universe.proc_macro_expansion),
        fidelity(universe.build_scripts)
    )
}

/// `judge explain <item-path> --why-live` (see todo.md §7, §14.2 P1).
/// Only `--why-live` is implemented; other explain modes (e.g. explaining a
/// finding id) don't exist yet.
#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
pub(super) fn run_explain(
    options: ExplainOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    // Checked before the tier/mode gates so `explain --format sarif` is the
    // same clean config error (exit 2) in Fast and Deep Tier builds alike.
    if matches!(options.format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`explain`", options.format, "tty, json"));
    }
    if !options.why_live {
        return Err(CliError::Analyzer(
            "`judge explain` currently only supports `--why-live`".to_string(),
        ));
    }
    if !judge::AnalysisTier::Deep.is_available() {
        return Err(CliError::Analyzer(
            "--why-live needs the Deep Tier — rebuild with `cargo install --path . --features deep` (see todo.md §2.1)".to_string(),
        ));
    }

    #[cfg(feature = "deep")]
    {
        run_explain_deep(options, out)
    }
    #[cfg(not(feature = "deep"))]
    {
        unreachable!(
            "AnalysisTier::Deep.is_available() is compile-time false without the deep feature"
        )
    }
}

#[cfg(feature = "deep")]
fn run_explain_deep(
    options: ExplainOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainOptions {
        item_path,
        why_live: _,
        include_tests,
        format,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let result = judge::reachability::why_live(&workspace, &item_path, include_tests)?;

    match format {
        OutputFormat::Json => {
            // Not a `Report` (no findings), but the same §0 obligation
            // applies: a Deep Tier answer states what it is a claim
            // about (see `judge::finding::AnalysisUniverse`).
            let universe = judge::finding::AnalysisUniverse::deep(&workspace, include_tests);
            let json = match &result {
                judge::reachability::WhyLive::Path(path) => serde_json::json!({
                    "item_path": item_path,
                    "reachable": true,
                    "path": path.iter().map(|step| serde_json::json!({
                        "qualified_name": step.qualified_name,
                        "file": step.file,
                        "line": step.line,
                        "call_kind": step.kind.map(|kind| kind.as_str()),
                    })).collect::<Vec<_>>(),
                    "analysis_universe": universe,
                }),
                judge::reachability::WhyLive::NotReachable => serde_json::json!({
                    "item_path": item_path,
                    "reachable": false,
                    "path": [],
                    "analysis_universe": universe,
                }),
            };
            write_json(out, &json)?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected in run_explain before the Deep Tier runs")
        }
        OutputFormat::Tty => match &result {
            judge::reachability::WhyLive::Path(path) => {
                writeln!(out, "{item_path} is live:")?;
                for (index, step) in path.iter().enumerate() {
                    let prefix = if index == 0 { "  " } else { "  called by " };
                    let kind_suffix = step.kind.map_or(String::new(), |kind| format!(" [{kind}]"));
                    writeln!(
                        out,
                        "{prefix}{} ({}:{}){kind_suffix}",
                        step.qualified_name,
                        step.file.display(),
                        step.line
                    )?;
                }
            }
            judge::reachability::WhyLive::NotReachable => {
                writeln!(
                    out,
                    "{item_path}: not reachable from any recognized entry point (`fn main` in a [[bin]]/[[example]] target, #[test]/#[bench] with --include-tests, or #[no_mangle]/#[export_name]/#[wasm_bindgen])"
                )?;
            }
        },
    }
    Ok(CommandOutcome::Clean)
}
