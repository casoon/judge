//! Shared baseline persistence, comparison, and delta rendering.

use serde::Serialize;

use crate::*;

/// The baseline-related portion of a command invocation. Keeping this
/// separate from the individual command options lets ordinary report commands
/// share the exact save/compare decision without flattening their distinct
/// analyses into one handler.
pub(crate) struct BaselineRequest<'a> {
    save: bool,
    compare_path: Option<&'a Path>,
    format: OutputFormat,
}

/// Data produced by a report command before the shared baseline decision is
/// applied. Keeping it together makes the baseline hand-off an explicit
/// boundary instead of a long positional argument list.
pub(crate) struct BaselineInput<'a> {
    pub(crate) workspace_root: &'a Path,
    pub(crate) findings: &'a [Finding],
    pub(crate) analysis_errors: &'a [String],
    pub(crate) rule_revisions: std::collections::HashMap<String, u32>,
    pub(crate) default_save_path: &'a Path,
    pub(crate) total_loc: usize,
}

impl<'a> BaselineRequest<'a> {
    pub(crate) fn new(save: bool, compare_path: Option<&'a Path>, format: OutputFormat) -> Self {
        Self {
            save,
            compare_path,
            format,
        }
    }

    pub(crate) fn is_requested(&self) -> bool {
        self.save || self.compare_path.is_some()
    }

    /// Handles the standard baseline path and returns `None` when the command
    /// should continue with its normal report rendering.
    pub(crate) fn handle(
        &self,
        input: BaselineInput<'_>,
        out: &mut dyn Write,
    ) -> Option<Result<CommandOutcome, CliError>> {
        let BaselineInput {
            workspace_root,
            findings,
            analysis_errors,
            rule_revisions,
            default_save_path,
            total_loc,
        } = input;
        self.is_requested().then(|| {
            handle_baseline(
                workspace_root,
                findings,
                analysis_errors,
                BaselineOptions {
                    rule_revisions,
                    save: self.save,
                    compare_path: self.compare_path,
                    default_save_path,
                    format: self.format,
                    total_loc,
                },
                out,
            )
        })
    }
}

/// Converts analyzer-specific errors to the stable command-report form.
pub(crate) fn analysis_errors<E>(errors: impl IntoIterator<Item = E>) -> Vec<String>
where
    E: std::fmt::Display,
{
    errors.into_iter().map(|error| error.to_string()).collect()
}

/// Appends analyzer-specific errors without making command handlers repeat
/// their display conversion.
pub(crate) fn append_analysis_errors<E>(
    target: &mut Vec<String>,
    errors: impl IntoIterator<Item = E>,
) where
    E: std::fmt::Display,
{
    target.extend(analysis_errors(errors));
}

/// Writes the established pretty JSON representation and its trailing newline.
/// All report commands use this path so serialization failures have one CLI
/// error mapping and JSON artifacts keep a byte-stable layout.
pub(crate) fn write_json<T: Serialize + ?Sized>(
    out: &mut dyn Write,
    value: &T,
) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *out, value)
        .map_err(|error| CliError::Analyzer(format!("failed to render JSON report: {error}")))?;
    writeln!(out)?;
    Ok(())
}

/// Saves `findings` as a new baseline, or compares them against one and
/// writes the delta (see todo.md §5, §14.2 P0#5). Only called when one of
/// the two applies (`--save-baseline`/`--baseline`); a failing compare
/// verdict becomes [`CommandOutcome::FindingsFound`].
pub(crate) struct BaselineOptions<'a> {
    pub(crate) rule_revisions: std::collections::HashMap<String, u32>,
    pub(crate) save: bool,
    pub(crate) compare_path: Option<&'a Path>,
    pub(crate) default_save_path: &'a Path,
    pub(crate) format: OutputFormat,
    /// Authored LOC analyzed this run (see `judge::health_score`) — stored on
    /// a saved baseline so a later run can recompute its historical score.
    pub(crate) total_loc: usize,
}

pub(crate) fn handle_baseline(
    workspace_root: &Path,
    findings: &[Finding],
    analysis_errors: &[String],
    options: BaselineOptions<'_>,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    handle_baseline_with_trend(
        workspace_root,
        findings,
        analysis_errors,
        options,
        None,
        None,
        out,
    )
}

/// Like [`handle_baseline`], but embeds the health score and its trend into
/// the JSON delta envelope when `score_trend` is given (only `health --score
/// --baseline` computes one — see todo.md §15.1: the trend is emitted in
/// JSON too, with an explicit `comparable: false` reason instead of a false
/// delta). TTY trend output stays in `run_health`, written before this runs.
///
/// `api_surface_size` is `Some` only for `cargo judge api-surface
/// --save-baseline` — it's attached to the saved [`judge::baseline::Baseline`]
/// (see [`judge::baseline::Baseline::with_api_surface_size`]). The
/// api-surface-size *trend* against a compared baseline is computed and
/// printed by `run_api_surface` itself, before this runs, the same way
/// `run_health` handles the health-score trend for TTY.
pub(crate) fn handle_baseline_with_trend(
    workspace_root: &Path,
    findings: &[Finding],
    analysis_errors: &[String],
    options: BaselineOptions<'_>,
    score_trend: Option<&judge::health_score::Trend>,
    api_surface_size: Option<&std::collections::HashMap<String, usize>>,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let BaselineOptions {
        rule_revisions,
        save,
        compare_path,
        default_save_path,
        format,
        total_loc,
    } = options;
    let mut findings = findings.to_vec();
    judge::finding::relativize_paths(&mut findings, workspace_root);

    if !analysis_errors.is_empty() {
        return match format {
            OutputFormat::Json => {
                let report = Report::with_errors(findings, analysis_errors.to_vec());
                write_json(out, &report)?;
                Err(CliError::Reported)
            }
            OutputFormat::Tty | OutputFormat::Sarif | OutputFormat::Markdown => {
                Err(CliError::AnalysisIncomplete {
                    context: "baseline was not evaluated",
                    errors: analysis_errors.to_vec(),
                })
            }
        };
    }

    if save {
        let config = load_judge_toml(workspace_root)?;
        let mut baseline = judge::baseline::Baseline::new(
            &findings,
            String::new(),
            rule_revisions,
            total_loc,
            judge::health_score::ScoreContext::from_profiles(&config.crate_profiles),
        );
        if let Some(size) = api_surface_size {
            baseline = baseline.with_api_surface_size(size.clone());
        }
        let save_path = workspace_root.join(default_save_path);
        judge::baseline::save(&save_path, &baseline)?;
        writeln!(
            out,
            "baseline saved: {} ({} findings)",
            save_path.display(),
            findings.len()
        )?;
        return Ok(CommandOutcome::Clean);
    }

    let Some(path) = compare_path else {
        // Callers only invoke baseline handling when saving or comparing.
        return Ok(CommandOutcome::Clean);
    };
    let mut baseline = judge::baseline::load(path)?;
    baseline.relativize_paths(workspace_root);
    let delta = judge::baseline::diff(
        &findings,
        &baseline,
        &std::collections::HashSet::new(),
        &rule_revisions,
    );
    let verdict = delta.verdict();
    match format {
        OutputFormat::Json => {
            let mut envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "verdict": verdict,
                "delta": delta,
            });
            if let Some(trend) = score_trend {
                envelope["score"] = serde_json::to_value(trend.current()).unwrap();
                envelope["trend"] = trend_json(trend);
            }
            write_json(out, &envelope)?;
        }
        OutputFormat::Markdown => {
            write!(out, "{}", judge::markdown::render_delta(&delta, verdict))?;
        }
        OutputFormat::Sarif => {
            return Err(unsupported_format(
                "baseline comparison",
                format,
                "tty, json, markdown",
            ));
        }
        OutputFormat::Tty => print_delta(out, &delta, verdict)?,
    }

    if verdict == Verdict::Fail {
        return Ok(CommandOutcome::FindingsFound);
    }
    Ok(CommandOutcome::Clean)
}

/// The `unchanged`/`resolved` count header shared by [`print_delta`] and
/// [`print_pattern_delta_tty`], before either lists its own resolved items.
fn write_unchanged_resolved(
    out: &mut dyn Write,
    unchanged_count: usize,
    resolved_count: usize,
) -> std::io::Result<()> {
    writeln!(out, "unchanged: {unchanged_count}")?;
    writeln!(out, "resolved: {resolved_count}")?;
    Ok(())
}

/// One `rule  file:line` finding line, shared by [`print_delta`]'s gating and
/// advisory sections.
fn write_finding_line(out: &mut dyn Write, finding: &Finding) -> std::io::Result<()> {
    writeln!(
        out,
        "  {}  {}:{}",
        finding.rule,
        finding.location.file.display(),
        finding.location.line
    )
}

fn print_delta(
    out: &mut dyn Write,
    delta: &judge::baseline::Delta,
    verdict: Verdict,
) -> std::io::Result<()> {
    writeln!(out, "verdict: {}", verdict.label())?;
    write_unchanged_resolved(out, delta.unchanged_count, delta.resolved.len())?;
    for finding in &delta.resolved {
        writeln!(out, "  {}  {}", finding.rule, finding.file.display())?;
    }

    let (gating, advisory) = judge::baseline::partition_gating(&delta.introduced);
    writeln!(out, "introduced: {}", gating.len())?;
    for finding in &gating {
        write_finding_line(out, finding)?;
    }

    writeln!(
        out,
        "introduced advisory (heuristic — no verdict effect): {}",
        advisory.len()
    )?;
    for finding in &advisory {
        write_finding_line(out, finding)?;
    }

    writeln!(out, "severity changed: {}", delta.severity_changed.len())?;
    for change in &delta.severity_changed {
        let (rule, before, after) = change.transition();
        writeln!(
            out,
            "  {}  {} -> {}  {}:{}",
            rule,
            severity_label(before),
            severity_label(after),
            change.after.location.file.display(),
            change.after.location.line
        )?;
    }
    Ok(())
}

/// TTY rendering of a [`judge::pattern_baseline::PatternDelta`] — the
/// pattern-candidate analog of [`print_delta`], but without a verdict line
/// (pattern candidates never gate — see `judge::pattern_baseline`'s module
/// docs) and without the `code_introduced`/`rule_introduced` split (patterns
/// use a flat new/resolved/unchanged classification instead).
pub(crate) fn print_pattern_delta_tty(
    out: &mut dyn Write,
    delta: &judge::pattern_baseline::PatternDelta,
) -> std::io::Result<()> {
    write_unchanged_resolved(out, delta.unchanged_count, delta.resolved.len())?;
    for candidate in &delta.resolved {
        writeln!(
            out,
            "  [{}] {}  crate: {}",
            candidate.id, candidate.pattern, candidate.krate
        )?;
    }
    writeln!(out, "new: {}", delta.new.len())?;
    for candidate in &delta.new {
        writeln!(
            out,
            "  [{}] {}  crate: {}",
            candidate.id, candidate.pattern, candidate.scope.krate
        )?;
    }
    Ok(())
}
