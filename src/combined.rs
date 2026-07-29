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
        &workspace.root,
        &collected.findings,
        &collected.analysis_errors,
        collected.rule_revisions,
        Path::new(DEFAULT_BASELINE_ALL),
        judge::health_score::total_authored_loc(&workspace),
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
                .with_suppressed_inline(collected.suppressed_inline)
                .with_history_unavailable(collected.history_unavailable);
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
            return Err(unsupported_format(
                "`cargo judge`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            let (gating, advisory): (Vec<&Finding>, Vec<&Finding>) = collected
                .findings
                .iter()
                .partition(|finding| finding.is_gating());
            writeln!(
                out,
                "findings: {} (worst first), {} advisory",
                gating.len(),
                advisory.len()
            )?;
            if !collected.analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", collected.analysis_errors.len())?;
                for error in &collected.analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
            if !collected.history_unavailable.is_empty() {
                writeln!(
                    out,
                    "history unavailable for {} uncommitted files:",
                    collected.history_unavailable.len()
                )?;
                for file in &collected.history_unavailable {
                    writeln!(out, "  {}", file.display())?;
                }
            }
            writeln!(
                out,
                "boundary rules checked: {}{}",
                collected.boundary_rules_checked,
                if collected.boundaries_config_path.exists() {
                    ""
                } else {
                    " (no judge.toml — boundaries skipped)"
                }
            )?;
            if collected.suppressed_inline > 0 {
                writeln!(
                    out,
                    "suppressed (inline judge-ignore): {}",
                    collected.suppressed_inline
                )?;
            }
            writeln!(out)?;
            for finding in &gating {
                write_finding(out, finding)?;
            }
            if !advisory.is_empty() {
                writeln!(out)?;
                writeln!(
                    out,
                    "advisory (heuristic) — no verdict effect: {}",
                    advisory.len()
                )?;
                for finding in &advisory {
                    write_finding(out, finding)?;
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// One finding line of the bare `cargo judge` TTY report.
fn write_finding(out: &mut dyn Write, finding: &Finding) -> std::io::Result<()> {
    writeln!(
        out,
        "  [{}] {:<28} {}:{}  {}",
        severity_label(finding.severity),
        finding.rule,
        finding.location.file.display(),
        finding.location.line,
        finding.location.item_path
    )
}
