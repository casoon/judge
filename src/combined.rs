//! Rendering and baseline handling for the bare combined `cargo judge` run.

use serde::Serialize;

use super::*;

/// Schema version for `cargo judge --progress PATH` JSON Lines records.
const PROGRESS_SCHEMA_VERSION: u32 = 1;

/// One lifecycle notification emitted by the Fast-Tier collector.
#[derive(Clone, Copy)]
pub(super) enum ProgressEvent {
    Started(&'static str),
    Completed(&'static str),
}

impl ProgressEvent {
    pub(super) const fn started(phase: &'static str) -> Self {
        Self::Started(phase)
    }

    pub(super) const fn completed(phase: &'static str) -> Self {
        Self::Completed(phase)
    }

    fn phase(self) -> &'static str {
        match self {
            Self::Started(phase) | Self::Completed(phase) => phase,
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::Started(_) => "phase_started",
            Self::Completed(_) => "phase_completed",
        }
    }
}

#[derive(Serialize)]
struct ProgressRecord {
    schema_version: u32,
    sequence: u64,
    event: &'static str,
    phase: &'static str,
}

/// Separate, line-buffered event writer. It never shares stdout with the
/// final report, preserving JSON/SARIF consumers' existing contracts.
struct ProgressWriter {
    out: std::fs::File,
    sequence: u64,
}

impl ProgressWriter {
    fn create(path: &Path) -> Result<Self, CliError> {
        Ok(Self {
            out: std::fs::File::create(path)?,
            sequence: 0,
        })
    }

    fn emit(&mut self, event: ProgressEvent) -> Result<(), CliError> {
        self.sequence += 1;
        let record = ProgressRecord {
            schema_version: PROGRESS_SCHEMA_VERSION,
            sequence: self.sequence,
            event: event.event(),
            phase: event.phase(),
        };
        writeln!(self.out, "{}", serde_json::to_string(&record).unwrap())?;
        self.out.flush()?;
        Ok(())
    }
}

/// Bare `cargo judge` (see todo.md §4 "Decision Surface", §8 "Vollanalyse"):
/// runs [`collect_findings`], sorts the result worst-first, then either
/// saves/compares a baseline or prints the merged report.
pub(super) fn run(
    format: OutputFormat,
    save_baseline: bool,
    baseline: Option<PathBuf>,
    progress_path: Option<&Path>,
    details: bool,
    color: bool,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let progress_path = progress_path.map(|path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace.root.join(path)
        }
    });
    let mut progress = progress_path
        .as_deref()
        .map(ProgressWriter::create)
        .transpose()?;

    let mut collected = collect_findings_with_progress(&workspace, &mut |event| {
        if let Some(progress) = &mut progress {
            progress.emit(event)?;
        }
        Ok(())
    })?;
    judge::finding::sort_by_severity_desc(&mut collected.findings);

    let baseline_request = BaselineRequest::new(save_baseline, baseline.as_deref(), format);
    if let Some(result) = baseline_request.handle(
        BaselineInput {
            workspace_root: &workspace.root,
            findings: &collected.findings,
            analysis_errors: &collected.analysis_errors,
            rule_revisions: collected.rule_revisions,
            default_save_path: Path::new(DEFAULT_BASELINE_ALL),
            total_loc: judge::health_score::total_authored_loc(&workspace),
        },
        out,
    ) {
        return result;
    }

    match format {
        OutputFormat::Json => {
            // Bare `cargo judge` analyzes with the generated-code default
            // (excluded — see `collect_findings`), so the universe says so.
            let report = Report::with_errors(collected.findings, collected.analysis_errors)
                .with_universe(judge::finding::AnalysisUniverse::fast(&workspace, false))
                .with_suppressed_inline(collected.suppressed_inline);
            write_json(out, &report)?;
        }
        OutputFormat::Sarif => {
            write_sarif(
                out,
                &workspace.root,
                collected.findings,
                collected.analysis_errors,
                Some(judge::finding::AnalysisUniverse::fast(&workspace, false)),
            )?;
        }
        OutputFormat::Markdown => {
            let (gating, advisory) = judge::baseline::partition_gating(&collected.findings);
            let markdown = build_report(
                &gating,
                &advisory,
                &collected.analysis_errors,
                collected.boundary_rules_checked,
                collected.boundaries_config_path.exists(),
                collected.suppressed_inline,
                &workspace.root,
            )
            .write_markdown(&workspace.root);
            write!(out, "{markdown}")?;
        }
        OutputFormat::Tty => {
            let (gating, advisory) = judge::baseline::partition_gating(&collected.findings);
            build_report(
                &gating,
                &advisory,
                &collected.analysis_errors,
                collected.boundary_rules_checked,
                collected.boundaries_config_path.exists(),
                collected.suppressed_inline,
                &workspace.root,
            )
            .write_tty_colored(out, &workspace.root, details, color)?;
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Builds the shared presentation model (issue #12) for the combined
/// command's terminal view. The previous exhaustive listing remains
/// available through `--details`; JSON is always exhaustive and therefore
/// remains the automation contract.
#[allow(clippy::too_many_arguments)]
fn build_report<'a>(
    gating: &[&'a Finding],
    advisory: &[&'a Finding],
    analysis_errors: &'a [String],
    boundary_rules_checked: usize,
    boundaries_config_exists: bool,
    suppressed_inline: usize,
    _workspace_root: &Path,
) -> judge::report::Report<'a> {
    let mut status_lines = vec![
        "Judge summary".to_string(),
        format!(
            "  {} evidence-backed findings · {} advisory heuristics",
            gating.len(),
            advisory.len()
        ),
        format!(
            "  boundary rules: {}{}",
            boundary_rules_checked,
            if boundaries_config_exists {
                " checked"
            } else {
                " not checked (no judge.toml)"
            }
        ),
    ];
    if suppressed_inline > 0 {
        status_lines.push(format!("  inline suppressions: {suppressed_inline}"));
    }

    let analysis_error_items = analysis_errors
        .iter()
        .map(|error| std::borrow::Cow::Borrowed(error.as_str()))
        .collect();
    judge::report::Report::new(status_lines)
        .with_scope_note(
            format!("Analysis incomplete: {} error(s)", analysis_errors.len()),
            analysis_error_items,
        )
        .with_group("Evidence-backed findings", gating.to_vec(), false)
        .with_group(
            "Advisory heuristics (no verdict or score effect)",
            advisory.to_vec(),
            true,
        )
        .with_next_steps(vec![
            "cargo judge dupes              clone families, grouped and prioritized".to_string(),
            "cargo judge --details          every finding and location".to_string(),
            "cargo judge --format json      full machine-readable report in .judge/judge.json"
                .to_string(),
        ])
}
