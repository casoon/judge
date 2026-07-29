use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, ValueEnum};
use judge::AnalysisTier;
#[cfg(test)]
use judge::baseline::TriVerdict;
use judge::baseline::Verdict;
use judge::duplication::DupeMode;
use judge::finding::{Finding, Report};
use serde::Serialize;
use serde::ser::SerializeMap;

mod advisory_commands;
mod analysis_commands;
mod baseline_output;
mod combined;
mod combined_analysis;
mod commands;
mod deep_commands;
mod health_command;
mod workspace_commands;

use advisory_commands::{
    run_explain_pattern, run_explain_principle, run_explain_rule, run_fix_preview, run_patterns,
    run_principles,
};
use analysis_commands::{
    run_api_surface, run_boundaries, run_coverage, run_deps, run_dupes, run_errors,
    run_module_graph, run_slop, run_tests, run_unsafe,
};
use baseline_output::{
    BaselineInput, BaselineOptions, BaselineRequest, analysis_errors, append_analysis_errors,
    handle_baseline_with_trend, print_pattern_delta_tty, write_json,
};
#[cfg(test)]
use combined_analysis::collect_findings;
use combined_analysis::collect_findings_with_progress;
use commands::{BaselineArgs, Command};
use deep_commands::{run_dead_code, run_explain};
use health_command::run as run_health;
use workspace_commands::{
    run_complexity, run_impact, run_inspect, run_map, run_refactor, run_structure,
};

const DEFAULT_BASELINE_HEALTH: &str = ".judge/baseline-health.json";
const DEFAULT_BASELINE_DUPES: &str = ".judge/baseline-dupes.json";
const DEFAULT_BASELINE_DEPS: &str = ".judge/baseline-deps.json";
const DEFAULT_BASELINE_BOUNDARIES: &str = ".judge/baseline-boundaries.json";
const DEFAULT_BASELINE_ALL: &str = ".judge/baseline.json";
const DEFAULT_BASELINE_COVERAGE: &str = ".judge/baseline-coverage.json";
const DEFAULT_BASELINE_API_SURFACE: &str = ".judge/baseline-api-surface.json";
const DEFAULT_BASELINE_MODULE_GRAPH: &str = ".judge/baseline-module-graph.json";
const DEFAULT_PATTERN_BASELINE: &str = ".judge/baseline-patterns.json";
#[cfg(feature = "deep")]
const DEFAULT_BASELINE_DEAD_CODE: &str = ".judge/baseline-dead-code.json";

/// `cargo judge dupes`'s TTY view prints at most this many clone families
/// (GitHub issue #7: on a large workspace the unindicated truncation reads
/// as a complete list — grepping the TTY output for a just-touched file and
/// finding nothing looked like "no duplication" when the full graph, only
/// visible via `--format json`, told a different story). The header's
/// `clone families: N` line already gives the true total; the loop below
/// additionally prints an explicit "... and N more" trailer whenever the
/// list is actually truncated, so the TTY view can't be mistaken for the
/// full picture on its own.
const DUPE_FAMILY_TTY_LIMIT: usize = 15;

#[derive(Debug, Parser)]
#[command(
    name = "cargo judge",
    version,
    about = "Deterministic post-refactoring analysis for Rust workspaces",
    long_about = "Deterministic post-refactoring analysis for Rust workspaces. Analyses the current source tree, workspace structure, public APIs, and dependency graph without Git history or code provenance."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Output format (bare `cargo judge` only — a combined run across every
    /// detector; see todo.md §4 "Decision Surface", §8).
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Write versioned JSON Lines progress events for a bare combined run.
    /// The final report remains on stdout; this separate file is flushed
    /// after every phase event so agents can observe long-running analysis.
    #[arg(long, value_name = "PATH")]
    progress: Option<PathBuf>,
    /// Show every finding in the bare combined TTY report instead of the
    /// default rule-grouped decision summary.
    #[arg(long)]
    details: bool,
    /// Terminal color policy for the bare combined report. `auto` uses color
    /// only on a terminal and honours `NO_COLOR`; use `always` to force it.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
    /// Write the artifact to this path. With `--format json`, the default is
    /// `.judge/<command>.json`; with the bare `cargo judge --format
    /// markdown`, the default is `.judge/judge.md`. This option selects a
    /// different artifact path.
    #[arg(long, global = true, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DupesOptions {
    /// How aggressively token spans must match to count as duplicates.
    #[arg(long, value_enum, default_value = "mild")]
    mode: DupeModeArg,
    /// Minimum span length, in tokens — spans shorter than this are
    /// ignored so trivial one-liners don't dominate every family.
    #[arg(long, default_value_t = judge::duplication::DEFAULT_MIN_TOKENS)]
    min_tokens: usize,
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Analyze generated files too (see todo.md §3.A). Off by default —
    /// duplication in generated code isn't actionable the way it is in
    /// authored code.
    #[arg(long)]
    include_generated: bool,
    /// Include test-only functions and integration-test targets. Off by
    /// default so fixture duplication does not dominate refactoring signals.
    #[arg(long)]
    include_tests: bool,
}

#[derive(Debug, Args)]
struct HealthOptions {
    /// Include the numeric health score.
    #[arg(long)]
    score: bool,
    /// Show findings caused by another finding, not just root findings.
    #[arg(long)]
    show_cascades: bool,
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Analyze generated files too (see todo.md §3.A).
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct DepsOptions {
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Opt-in: also check declared dependencies against the real
    /// crates.io sparse index and REST API (`phantom-crate`,
    /// `phantom-version`, `fresh-low-reputation-dep`). Off by default —
    /// judge makes no network calls unless explicitly asked to (see
    /// todo.md §1 "kein SaaS, keine Telemetrie, lokal deterministisch").
    /// `name-collision-risk` always runs; it's fully local.
    #[arg(long)]
    check_crates_io: bool,
    /// Opt-in: also run a full `cargo check --workspace --all-targets` with
    /// rustc's stable `unused_crate_dependencies` lint enabled and import
    /// its result as `unused-dependency` findings. Off by default — unlike
    /// this command's other detectors, a full compile is a different order
    /// of cost (see `judge::deps` module docs "Importing rustc's
    /// `unused_crate_dependencies` lint").
    #[arg(long)]
    check_rustc_lints: bool,
    /// Opt-in: cross-reference an already-generated `cargo audit --json`
    /// report against the resolved dependency graph (`known-vulnerability`).
    /// judge never runs `cargo-audit` itself — generate the report with
    /// `cargo audit --json > PATH` first (see `judge::advisories` module
    /// docs).
    #[arg(long, value_name = "PATH")]
    audit_json: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct BoundariesOptions {
    /// Path to the boundary config. Defaults to `judge.toml` in the
    /// workspace root.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Print the workspace's crate dependency graph in this format instead
    /// of checking boundary rules, and exit — a pure projection of the
    /// existing architecture graph (todo.md §H), not a new rule engine.
    /// Ignores every other flag above; does not require `judge.toml`.
    #[arg(long, value_enum)]
    graph: Option<GraphFormat>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum GraphFormat {
    /// Graphviz DOT (see `judge::boundaries::CrateGraph::to_dot`).
    Dot,
    /// Mermaid `flowchart` (see `judge::boundaries::CrateGraph::to_mermaid`).
    Mermaid,
}

#[derive(Debug, Args)]
struct DeadCodeOptions {
    /// Count a `#[test]`-only reference as usage. Off by default: a
    /// `pub` item only reachable from tests is still dead in production
    /// (see todo.md §3.A "Reachability-Modi").
    #[arg(long)]
    include_tests: bool,
    #[command(flatten)]
    baseline_args: BaselineArgs,
}

#[derive(Debug, Args)]
struct CoverageOptions {
    /// Path to a `cargo-llvm-cov` LCOV report (see todo.md §J). judge never
    /// measures coverage itself, only imports an already-generated snapshot.
    #[arg(long, value_name = "PATH")]
    lcov: PathBuf,
    /// Opt-in: also import an externally generated `cargo-mutants`
    /// `outcomes.json` report and flag `mutation-survivor` findings (see
    /// `judge::mutants` module docs). judge never runs `cargo-mutants`
    /// itself — generate the report with `cargo mutants` first (writes
    /// `mutants.out/outcomes.json`), then pass that path here.
    #[arg(long, value_name = "PATH")]
    mutants_json: Option<PathBuf>,
    #[command(flatten)]
    baseline_args: BaselineArgs,
}

#[derive(Debug, Args)]
struct ExplainOptions {
    /// The qualified item path (e.g. `core::retry::backoff`) to explain.
    item_path: String,
    /// Show the shortest evidenced call path from a recognized entry
    /// point. Needs the Deep Tier — build with `--features deep`.
    #[arg(long)]
    why_live: bool,
    /// Count a `#[test]`-only call as reaching the item.
    #[arg(long)]
    include_tests: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct CompareOptions {
    /// Baseline artifact produced by `cargo judge --save-baseline`.
    baseline: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct PatternsOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Opt-in: cross-reference an already-generated `cargo clippy
    /// --message-format=json` report, strengthening `boolean-state-cluster`
    /// candidates with a third, cross-call-site corroborating evidence
    /// signal (`clippy::fn_params_excessive_bools`) when clippy
    /// independently flags the same function. judge never runs `cargo
    /// clippy` itself — generate the report with `cargo clippy
    /// --message-format=json > PATH` first (see `judge::clippy_import`
    /// module docs).
    #[arg(long, value_name = "PATH")]
    clippy_json: Option<PathBuf>,
    /// Save the current pattern candidates as a pattern baseline — a
    /// separate, simpler mechanism from `Finding` baselines (see
    /// `judge::pattern_baseline`: pattern candidates never gate, so their
    /// baseline carries no rule revisions, LOC, or score context).
    #[arg(long)]
    save_pattern_baseline: bool,
    /// Compare pattern candidates against a previously saved pattern
    /// baseline.
    #[arg(long, value_name = "PATH")]
    pattern_baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PrinciplesOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ExplainPatternOptions {
    /// The pattern candidate id (see `cargo judge patterns`).
    id: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ExplainPrincipleOptions {
    /// The principle heuristic id (see `cargo judge principles`).
    id: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct FixPreviewOptions {
    /// The pattern candidate id (see `cargo judge patterns`).
    id: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ExplainRuleOptions {
    /// The rule id (e.g. `catch-all-error`) — see `judge::rule_registry`.
    id: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ApiSurfaceOptions {
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Analyze generated files too (see todo.md §3.A). Off by default —
    /// documentation completeness on generated code isn't actionable the way
    /// it is on authored code.
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct ModuleGraphOptions {
    #[command(flatten)]
    baseline_args: BaselineArgs,
    /// Analyze generated files too (see todo.md §3.A). Off by default — an
    /// unlinked/orphaned generated file isn't actionable the way it is in
    /// authored code.
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct MapOptions {
    /// Output format. JSON is intended for tooling; TTY shows the highest
    /// complexity-ranked authored files with their measured facts.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Include test-only functions in the complexity attention ranking.
    /// Production and test metrics remain separate in every output format.
    #[arg(long)]
    include_tests: bool,
}

#[derive(Debug, Args)]
struct ImpactOptions {
    /// Workspace-relative or absolute path to a discovered Rust source file.
    target: PathBuf,
    /// Output format. JSON is intended for deterministic agent tooling.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct StructureOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ComplexityOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Include test-only functions in the ranking while keeping their metrics separate.
    #[arg(long)]
    include_tests: bool,
}

#[derive(Debug, Args)]
struct RefactorOptions {
    /// Optional workspace-relative source file to focus the queue on.
    target: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct FocusedAnalysisOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Include generated source files in the analysis.
    #[arg(long)]
    include_generated: bool,
}

/// Output format shared by commands that emit findings (see todo.md §7).
/// Not every command supports every format: SARIF exists for the
/// report-producing commands; Markdown exists for the baseline delta
/// and the bare `cargo judge` review report (the PR-comment use cases) —
/// anything else is rejected as a config error instead of producing
/// half-baked output.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable, reduced to root findings by default.
    Tty,
    /// Versioned JSON, always the full finding graph.
    Json,
    /// SARIF 2.1.0 (report-producing commands only — see `judge::sarif`).
    Sarif,
    /// Markdown: a delta table for baseline comparisons
    /// (see `judge::markdown`), or the shared-model review report for the
    /// bare `cargo judge` combined run (see `judge::report`).
    Markdown,
}

/// Color policy for the bare human-readable combined report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    fn is_enabled(self) -> bool {
        match self {
            Self::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
            Self::Always => true,
            Self::Never => false,
        }
    }
}

impl OutputFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Tty => "tty",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Markdown => "markdown",
        }
    }
}

/// The config error (exit 2) for a format a command has no meaningful
/// rendering for (see todo.md §7: no half-baked outputs).
fn unsupported_format(context: &str, format: OutputFormat, supported: &str) -> CliError {
    CliError::Config(format!(
        "--format {} is not supported for {context}; supported formats: {supported}",
        format.label()
    ))
}

/// Renders `findings` as a SARIF 2.1.0 log (see `judge::sarif`). Findings
/// are relativized to the workspace root first — SARIF artifact URIs are
/// relative, forward-slash paths.
fn write_sarif(
    out: &mut dyn Write,
    workspace_root: &Path,
    mut findings: Vec<Finding>,
    analysis_errors: Vec<String>,
    universe: Option<judge::finding::AnalysisUniverse>,
) -> Result<(), CliError> {
    judge::finding::relativize_paths(&mut findings, workspace_root);
    let mut report = Report::with_errors(findings, analysis_errors);
    if let Some(universe) = universe {
        report = report.with_universe(universe);
    }
    writeln!(
        out,
        "{}",
        serde_json::to_string_pretty(&judge::sarif::render(&report)).unwrap()
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DupeModeArg {
    Strict,
    Mild,
    Weak,
    Semantic,
}

impl From<DupeModeArg> for DupeMode {
    fn from(value: DupeModeArg) -> Self {
        match value {
            DupeModeArg::Strict => Self::Strict,
            DupeModeArg::Mild => Self::Mild,
            DupeModeArg::Weak => Self::Weak,
            DupeModeArg::Semantic => Self::Semantic,
        }
    }
}

/// What a successfully executed command concluded — [`main`] translates this
/// (and [`CliError`]) into the documented exit-code convention: `0` clean,
/// `1` a failing findings verdict, `2` a real error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandOutcome {
    /// No verdict-failing findings: exit 0. Commands without a verdict
    /// (plain reports, `inspect`, …) are always `Clean`.
    Clean,
    /// A baseline verdict failed on introduced findings: exit 1.
    FindingsFound,
}

/// A real error — always exit 2, never a findings verdict (see todo.md §5).
#[derive(Debug)]
enum CliError {
    /// A configuration input is broken: `judge.toml`, a baseline file
    /// (including an unsupported `schema_version`), or a stale baseline.
    Config(String),
    /// An analyzer/toolchain failure: cargo metadata, git, the Deep Tier,
    /// an unavailable score, or an unsupported invocation.
    Analyzer(String),
    /// Analysis produced errors, so a baseline verdict was withheld
    /// (see todo.md §15.1: no verdict on an incomplete basis).
    AnalysisIncomplete {
        context: &'static str,
        errors: Vec<String>,
    },
    /// The error was already fully rendered to the output stream (the JSON
    /// error envelope) — nothing further goes to stderr.
    Reported,
    /// Writing to the output stream failed. `BrokenPipe` gets special
    /// treatment in [`exit_code`].
    Io(std::io::Error),
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<judge::ingest::IngestError> for CliError {
    fn from(err: judge::ingest::IngestError) -> Self {
        Self::Analyzer(err.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        Self::Analyzer(err.to_string())
    }
}

impl From<judge::health_score::LocError> for CliError {
    fn from(err: judge::health_score::LocError) -> Self {
        Self::Analyzer(err.to_string())
    }
}

impl From<judge::baseline::BaselineError> for CliError {
    fn from(err: judge::baseline::BaselineError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::pattern_baseline::PatternBaselineError> for CliError {
    fn from(err: judge::pattern_baseline::PatternBaselineError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::boundaries::BoundaryConfigError> for CliError {
    fn from(err: judge::boundaries::BoundaryConfigError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::coverage::LcovError> for CliError {
    fn from(err: judge::coverage::LcovError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::advisories::AuditImportError> for CliError {
    fn from(err: judge::advisories::AuditImportError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::clippy_import::ClippyImportError> for CliError {
    fn from(err: judge::clippy_import::ClippyImportError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::mutants::MutantsImportError> for CliError {
    fn from(err: judge::mutants::MutantsImportError) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<judge::suppression::SuppressionError> for CliError {
    fn from(err: judge::suppression::SuppressionError) -> Self {
        Self::Config(err.to_string())
    }
}

#[cfg(feature = "deep")]
impl From<judge::dead_code::DeadCodeError> for CliError {
    fn from(err: judge::dead_code::DeadCodeError) -> Self {
        Self::Analyzer(err.to_string())
    }
}

#[cfg(feature = "deep")]
impl From<judge::slop_structural_deep::SlopStructuralDeepError> for CliError {
    fn from(err: judge::slop_structural_deep::SlopStructuralDeepError) -> Self {
        Self::Analyzer(err.to_string())
    }
}

#[cfg(feature = "deep")]
impl From<judge::reachability::ReachabilityError> for CliError {
    fn from(err: judge::reachability::ReachabilityError) -> Self {
        Self::Analyzer(err.to_string())
    }
}

/// Renders `err` to stderr, matching the exact shapes the pre-refactor
/// `eprintln!`-then-`exit(2)` call sites produced.
fn report_error(err: &CliError) {
    match err {
        CliError::Config(message) | CliError::Analyzer(message) => eprintln!("error: {message}"),
        CliError::AnalysisIncomplete { context, errors } => {
            eprintln!("error: analysis incomplete; {context}");
            for error in errors {
                eprintln!("  {error}");
            }
        }
        CliError::Reported => {}
        CliError::Io(err) => eprintln!("error: {err}"),
    }
}

/// The documented exit-code convention: `0` clean, `1` findings verdict
/// failed, `2` real error. Broken pipe is the deliberate exception: before
/// this refactor a closed stdout (e.g. `cargo judge health --format json |
/// head`) made `println!` panic (exit 101); now it is a silent exit 0 — the
/// consumer chose to stop reading, and the verdict for the aborted render
/// was never delivered, so neither 1 nor 2 would be truthful.
fn exit_code(result: &Result<CommandOutcome, CliError>) -> u8 {
    match result {
        Ok(CommandOutcome::Clean) => 0,
        Ok(CommandOutcome::FindingsFound) => 1,
        Err(CliError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(_) => 2,
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "judge") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let result = run_with_artifact_output(cli, &mut out).and_then(|outcome| {
        out.flush()?;
        Ok(outcome)
    });
    if let Err(err) = &result {
        report_error(err);
    }
    ExitCode::from(exit_code(&result))
}

/// The functional core's entry: executes the parsed command, writing every
/// report to `out` and returning an outcome/error instead of exiting — only
/// [`main`] translates the result into a process exit code.
fn run(cli: Cli, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    match cli.command {
        None => combined::run(
            cli.baseline_args.format,
            cli.baseline_args.save_baseline,
            cli.baseline_args.baseline,
            cli.progress.as_deref(),
            cli.details,
            cli.color.is_enabled(),
            out,
        ),
        Some(command) => {
            if cli.progress.is_some() {
                return Err(CliError::Config(
                    "--progress is available only for the bare `cargo judge` combined run"
                        .to_string(),
                ));
            }
            if cli.details {
                return Err(CliError::Config(
                    "--details is available only for the bare `cargo judge` combined run"
                        .to_string(),
                ));
            }
            if cli.color != ColorChoice::Auto {
                return Err(CliError::Config(
                    "--color is available only for the bare `cargo judge` combined run".to_string(),
                ));
            }
            command.run(out)
        }
    }
}

/// Runs a JSON-formatted command, or the bare `cargo judge --format
/// markdown` review report (issue #14), into its artifact file while
/// keeping the internal command handlers stream-oriented. Every other
/// format/command combination keeps its existing stdout behavior;
/// `--output` is deliberately rejected for them so a file extension never
/// silently changes a rendering contract.
fn run_with_artifact_output(cli: Cli, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let Some((path, command, format)) = cli.output_artifact()? else {
        return run(cli, out);
    };

    let mut rendered = Vec::new();
    let result = run(cli, &mut rendered);
    if !rendered.is_empty() {
        match format {
            OutputFormat::Json => {
                let artifact = add_json_header(&rendered, &path, command, &result)?;
                write_artifact_file(&path, &artifact)?;
                writeln!(out, "JSON written to {}", path.display())?;
            }
            OutputFormat::Markdown => {
                write_artifact_file(&path, &rendered)?;
                writeln!(out, "Markdown written to {}", path.display())?;
            }
            OutputFormat::Tty | OutputFormat::Sarif => {
                unreachable!("output_artifact only returns Json or Markdown")
            }
        }
    }
    result
}

impl Cli {
    /// The command's default output-artifact naming for `--format json`, or
    /// (bare command only) `--format markdown` — the two formats that
    /// support `--output` and a default `.judge/` artifact path.
    fn output_artifact(&self) -> Result<Option<(PathBuf, &'static str, OutputFormat)>, CliError> {
        let format_and_name = match &self.command {
            Some(command) => command.json_artifact(),
            None => Some((self.baseline_args.format, "judge")),
        };
        let supports_artifact = matches!(
            (&self.command, format_and_name),
            (_, Some((OutputFormat::Json, _))) | (None, Some((OutputFormat::Markdown, _)))
        );
        if !supports_artifact {
            return self.output.is_none().then_some(None).ok_or_else(|| {
                CliError::Config(
                    "--output requires a command using `--format json`, or the bare `cargo judge --format markdown` run"
                        .to_string(),
                )
            });
        }
        let (format, name) = format_and_name.expect("checked by supports_artifact above");
        let extension = match format {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
            OutputFormat::Tty | OutputFormat::Sarif => {
                unreachable!("checked by supports_artifact above")
            }
        };
        let path = self
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from(".judge").join(format!("{name}.{extension}")));
        Ok(Some((path, name, format)))
    }
}

fn write_artifact_file(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

/// Adds artifact metadata without moving the command's established JSON
/// payload. Consumers can keep reading existing root fields while people and
/// agents get enough context to decide whether a follow-up is warranted.
fn add_json_header(
    contents: &[u8],
    output_path: &Path,
    command: &str,
    result: &Result<CommandOutcome, CliError>,
) -> Result<Vec<u8>, CliError> {
    let mut document: serde_json::Value = serde_json::from_slice(contents).map_err(|err| {
        CliError::Analyzer(format!("JSON renderer produced an invalid artifact: {err}"))
    })?;
    let Some(root) = document.as_object_mut() else {
        return Err(CliError::Analyzer(
            "JSON renderer produced a non-object artifact".to_string(),
        ));
    };

    let findings = root
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let candidates = ["candidates", "heuristics"]
        .into_iter()
        .filter_map(|key| root.get(key).and_then(serde_json::Value::as_array))
        .map(Vec::len)
        .sum::<usize>();
    let errors = root
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let blocking = matches!(result, Ok(CommandOutcome::FindingsFound));
    let (assessment, action_required, summary) = if errors > 0 {
        (
            "analysis_incomplete",
            true,
            format!("Resolve {errors} analysis error(s) before relying on this artifact."),
        )
    } else if blocking {
        (
            "blocking_findings",
            true,
            "The command returned a failing verdict; action is required.".to_string(),
        )
    } else if findings + candidates > 0 {
        (
            "review_recommended",
            true,
            format!(
                "Review {findings} finding(s) and {candidates} advisory candidate(s); this is not an automatic refactoring instruction."
            ),
        )
    } else {
        (
            "informational",
            false,
            "No findings or advisory candidates require follow-up.".to_string(),
        )
    };

    let generated_at_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| CliError::Analyzer(format!("system clock is before Unix epoch: {err}")))?
        .as_secs();
    let generated_at_utc = format_utc_timestamp(generated_at_unix_seconds)?;
    let analysis_universe = root
        .get("analysis_universe")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let header = serde_json::json!({
        "schema_version": 1,
        "generated_at_utc": generated_at_utc,
        "generated_at_unix_seconds": generated_at_unix_seconds,
        "working_directory": std::env::current_dir()?.display().to_string(),
        "output_path": output_path.display().to_string(),
        "command": command,
        "description": json_artifact_description(command),
        "contains": "The command's normal versioned JSON payload plus this artifact header.",
        "context": {
            "analysis_universe": analysis_universe,
            "evidence_contract": {
                "finding_identity": "id, rule, severity, location, and origin are stable references within this artifact.",
                "evidence": "A finding's evidence and limitations state the observed facts and the boundary of the claim.",
                "recommendations": "Next actions are review order only; they are not automatic refactoring instructions.",
            },
            "next_actions": json_next_actions(command, findings, errors),
        },
        "assessment": {
            "kind": assessment,
            "action_required": action_required,
            "blocking": blocking,
            "findings": findings,
            "advisory_candidates": candidates,
            "analysis_errors": errors,
            "summary": summary,
        },
    });
    serde_json::to_vec_pretty(&HeaderFirstJson {
        header: &header,
        payload: root,
    })
    .map_err(|err| CliError::Analyzer(err.to_string()))
}

/// Small, stable navigation hints for humans and agents. These are derived
/// solely from the selected report and never claim a code change is required.
fn json_next_actions(command: &str, findings: usize, errors: usize) -> Vec<serde_json::Value> {
    if errors > 0 {
        return vec![serde_json::json!({
            "id": "resolve-analysis-errors",
            "reason": "The report is incomplete; inspect the errors array before acting on findings."
        })];
    }
    if findings == 0 {
        return Vec::new();
    }
    let mut actions = vec![serde_json::json!({
        "id": "inspect-findings",
        "reason": "Start with each finding's location, evidence, limitations, and causal links."
    })];
    match command {
        "judge" | "compare" => actions.push(serde_json::json!({
            "id": "refactoring-context",
            "command": "cargo judge dupes --format json",
            "reason": "Inspect duplicate families before deciding whether a shared extraction is justified."
        })),
        "deps" => actions.push(serde_json::json!({
            "id": "dependency-context",
            "command": "cargo judge deps --format json",
            "reason": "Use the dependency findings and their source locations to verify actual usage."
        })),
        _ => {}
    }
    actions
}

/// Serializes an artifact's context before its established command payload.
/// JSON object order is semantically irrelevant, but leading with the header
/// makes the file practical to inspect without scrolling past large findings.
struct HeaderFirstJson<'a> {
    header: &'a serde_json::Value,
    payload: &'a serde_json::Map<String, serde_json::Value>,
}

impl Serialize for HeaderFirstJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let has_existing_header = self.payload.contains_key("header");
        let mut object = serializer
            .serialize_map(Some(self.payload.len() + usize::from(!has_existing_header)))?;
        object.serialize_entry("header", self.header)?;
        for (key, value) in self.payload {
            if key != "header" {
                object.serialize_entry(key, value)?;
            }
        }
        object.end()
    }
}

fn format_utc_timestamp(unix_seconds: u64) -> Result<String, CliError> {
    let seconds = i64::try_from(unix_seconds)
        .map_err(|_| CliError::Analyzer("system timestamp exceeds supported range".to_string()))?;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_date_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Gregorian civil date for a Unix-day offset, using the public-domain
/// civil-date algorithm by Howard Hinnant. Kept dependency-free because the
/// artifact header only needs a stable UTC rendering of `SystemTime`.
fn civil_date_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn json_artifact_description(command: &str) -> &'static str {
    match command {
        "dupes" => "Duplicated token spans grouped into clone families and refactoring priorities.",
        "map" => "Workspace facts and refactoring attention ranked from measured source metrics.",
        "impact" => "Direct analysis and Cargo-target context for one source file.",
        "patterns" => "Advisory Rust pattern candidates aggregated from project evidence.",
        "principles" => "Advisory design-principle heuristics aggregated from project evidence.",
        "judge" => "Combined Judge findings across the enabled default analyzers.",
        _ => "Versioned Judge analysis output for the selected command.",
    }
}

/// Loads `judge.toml`'s `[[boundary]]`/`[[crate_profile]]` config, if
/// present. Both are opt-in — a missing file is the default (empty) config,
/// not an error.
fn load_judge_toml(workspace_root: &Path) -> Result<judge::boundaries::BoundaryConfig, CliError> {
    let config_path = workspace_root.join("judge.toml");
    if !config_path.exists() {
        return Ok(judge::boundaries::BoundaryConfig::default());
    }
    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|err| CliError::Config(format!("{}: {err}", config_path.display())))?;
    toml::from_str(&config_text).map_err(|err| {
        CliError::Config(format!("{}: failed to parse: {err}", config_path.display()))
    })
}

/// Treats an unavailable score as the analyzer error it is — exit 2,
/// matching `IngestError`/`GitError`/`BaselineError` (see todo.md §15.1).
fn require_score(
    outcome: judge::health_score::ScoreOutcome,
) -> Result<judge::health_score::HealthScore, CliError> {
    match outcome {
        judge::health_score::ScoreOutcome::Available(score) => Ok(score),
        judge::health_score::ScoreOutcome::Unavailable(reason) => Err(CliError::Analyzer(format!(
            "health score unavailable: {reason}"
        ))),
    }
}

/// Computes the current health score and its trend against the baseline at
/// `baseline_path` (see todo.md §4 point 4, "Trend vor Absolutwert").
fn compute_score_trend(
    workspace: &judge::ingest::Workspace,
    findings: &[Finding],
    total_loc: usize,
    baseline_path: &Path,
) -> Result<judge::health_score::Trend, CliError> {
    let baseline = judge::baseline::load(baseline_path)?;
    let config = load_judge_toml(&workspace.root)?;
    let current = require_score(judge::health_score::compute(
        findings,
        total_loc,
        workspace,
        &config.crate_profiles,
    ))?;
    Ok(judge::health_score::trend(
        current,
        &baseline,
        workspace,
        &config.crate_profiles,
    ))
}

/// Writes the current health score alongside the score a saved baseline
/// represents — or the explicit reason the two aren't directly comparable
/// (see todo.md §15.1), instead of a delta across different formulas.
fn print_score_trend(
    out: &mut dyn Write,
    trend: &judge::health_score::Trend,
) -> std::io::Result<()> {
    match trend {
        judge::health_score::Trend::Comparable {
            current,
            baseline_score,
            baseline_grade,
        } => writeln!(
            out,
            "health score: {:.1} ({}) — {:+.1} since baseline ({:.1} {})",
            current.score,
            current.grade.label(),
            current.score - baseline_score,
            baseline_score,
            baseline_grade.label(),
        ),
        judge::health_score::Trend::NotComparable { current, reason } => writeln!(
            out,
            "health score: {:.1} ({}) — baseline not directly comparable: {reason}",
            current.score,
            current.grade.label(),
        ),
    }
}

/// The `trend` JSON shape: `comparable` plus either the baseline score and
/// delta, or the explicit reason no delta can be computed.
fn trend_json(trend: &judge::health_score::Trend) -> serde_json::Value {
    match trend {
        judge::health_score::Trend::Comparable {
            current,
            baseline_score,
            baseline_grade,
        } => serde_json::json!({
            "comparable": true,
            "baseline_score": baseline_score,
            "baseline_grade": baseline_grade,
            "delta": current.score - baseline_score,
        }),
        judge::health_score::Trend::NotComparable { reason, .. } => serde_json::json!({
            "comparable": false,
            "reason": reason.code(),
            "message": reason.to_string(),
        }),
    }
}

/// AI-slop signals (see todo.md §G "AI-Slop-Signale", §12 "Entscheidungen":
/// "Der Slop-Block ist Teil von `health`, kein eigener Sub-Command"). Grouped
/// by rule with a per-rule count, then listed root-findings-first unless
/// `show_cascades` is set (see todo.md §14.2 P0#2), same convention as
/// `print_hotspots`.
const SLOP_RULES: [&str; 25] = [
    judge::slop::SWALLOWED_RESULT_RULE,
    judge::slop::EMPTY_ERROR_ARM_RULE,
    judge::slop::CATCH_ALL_ERROR_RULE,
    judge::slop::SUPPRESSION_DEBT_RULE,
    judge::slop::MERGED_STUB_RULE,
    judge::slop::EMPTY_IMPL_RULE,
    judge::slop::ASSERTION_FREE_TEST_RULE,
    judge::slop::TAUTOLOGICAL_TEST_RULE,
    judge::slop::IGNORED_TEST_ACCUMULATION_RULE,
    judge::slop::CONVERSATIONAL_ARTIFACT_RULE,
    judge::slop::RESTATING_COMMENT_RULE,
    judge::slop::STEP_COMMENT_INFLATION_RULE,
    judge::slop::GENERIC_NAMING_RULE,
    judge::slop::DOC_RESTATES_SIGNATURE_RULE,
    judge::slop_structural::CHURN_HOTSPOT_RULE,
    judge::slop_structural::COMPLEXITY_INFLATION_RULE,
    judge::complexity::SIGNATURE_COMPLEXITY_RULE,
    judge::complexity::MAINTAINABILITY_INDEX_RULE,
    judge::slop_structural::ABSTRACTION_INFLATION_RULE,
    judge::slop_structural::FRAGILE_SUBSTRING_CLASSIFICATION_RULE,
    judge::security::UNSAFE_SURFACE_RULE,
    judge::security::UNSAFE_DENSITY_RULE,
    judge::security::INTEGER_CAST_RISK_RULE,
    judge::security::PANIC_IN_LIB_RULE,
    judge::security::HARDCODED_SECRET_RULE,
];

fn print_slop(
    out: &mut dyn Write,
    findings: &[judge::finding::Finding],
    show_cascades: bool,
) -> std::io::Result<()> {
    let shown: Vec<&judge::finding::Finding> = if show_cascades {
        findings
            .iter()
            .filter(|finding| SLOP_RULES.contains(&finding.rule.as_str()))
            .collect()
    } else {
        judge::finding::root_findings(findings)
            .into_iter()
            .filter(|finding| SLOP_RULES.contains(&finding.rule.as_str()))
            .collect()
    };

    if shown.is_empty() {
        writeln!(out, "slop signals: none")?;
        return Ok(());
    }

    let (gating, advisory): (Vec<&Finding>, Vec<&Finding>) =
        shown.iter().partition(|finding| finding.is_gating());
    writeln!(
        out,
        "slop signals: {} ({} advisory)",
        gating.len(),
        advisory.len()
    )?;
    for rule in SLOP_RULES {
        let count = shown.iter().filter(|finding| finding.rule == rule).count();
        if count > 0 {
            writeln!(out, "  {rule}: {count}")?;
        }
    }
    writeln!(out)?;
    for finding in &gating {
        write_slop_finding(out, finding)?;
    }
    if !advisory.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "advisory (heuristic) — no verdict effect: {}",
            advisory.len()
        )?;
        for finding in &advisory {
            write_slop_finding(out, finding)?;
        }
    }
    Ok(())
}

/// One finding line of the slop block in the `health` TTY report.
fn write_slop_finding(out: &mut dyn Write, finding: &Finding) -> std::io::Result<()> {
    writeln!(
        out,
        "  [{}] {:<20} {}:{}  {}",
        severity_label(finding.severity),
        finding.rule,
        finding.location.file.display(),
        finding.location.line,
        finding.location.item_path
    )
}

fn severity_label(severity: judge::finding::Severity) -> &'static str {
    match severity {
        judge::finding::Severity::Fail => "fail",
        judge::finding::Severity::Warn => "warn",
        judge::finding::Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp directory unique to one test, removed when it goes out of
    /// scope. Duplicated from `judge::test_util::TempDir` rather than
    /// reused, since that module is private to the `judge` library crate's
    /// own test builds and isn't reachable from this binary crate's tests
    /// (mirrors how `git.rs`'s tests build their own `git()` fixture helper
    /// rather than shelling out to the production code path).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "judge-main-test-{name}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self(path)
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Runs `git` in `dir` with a fixed test identity — fixture setup only,
    /// never the production code path (see `git.rs`'s own tests).
    fn git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=judge-test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .status()
            .expect("failed to run git — required for these fixtures");
        assert!(status.success(), "git {args:?} failed");
    }

    /// The `judge-ignore` marker text, assembled at runtime rather than
    /// written as one literal in this file — a fixture string containing it
    /// verbatim (especially the deliberately-malformed, missing-reason
    /// cases below) would itself read as a real directive when `judge`
    /// analyzes its own `main.rs`, wherever a `duplicate-code`/
    /// `churn-hotspot`/etc. finding happens to land on or next to that line.
    fn ignore_marker() -> String {
        ["judge", "-ignore:"].concat()
    }

    fn commit_sha(dir: &Path, rev: &str) -> String {
        let output = std::process::Command::new("git")
            .args(["rev-parse", rev])
            .current_dir(dir)
            .output()
            .expect("failed to run git rev-parse");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn write_fixture_crate(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
    }

    /// `cargo judge api-surface` end-to-end: a `pub fn` with a `///` doc
    /// comment produces no finding.
    #[test]
    fn run_api_surface_reports_clean_on_a_documented_fixture() {
        let dir = TempDir::new("api-surface-clean");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "/// Says hello.\npub fn hello() {}\n",
        )
        .unwrap();

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            api_surface_cli(OutputFormat::Tty, false, None),
            &mut out,
        )
        .expect("clean fixture must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("undocumented public items: 0"),
            "unexpected output: {text}"
        );
    }

    /// `cargo judge api-surface` end-to-end: an undocumented `pub fn`
    /// produces one `undocumented-public-item` finding, listed in the TTY
    /// output.
    #[test]
    fn run_api_surface_reports_undocumented_public_items() {
        let dir = TempDir::new("api-surface-findings");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            api_surface_cli(OutputFormat::Tty, false, None),
            &mut out,
        )
        .expect("fixture must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("undocumented public items: 1"),
            "unexpected output: {text}"
        );
        assert!(text.contains("hello"), "unexpected output: {text}");
    }

    /// (c) `--save-baseline` records each crate's api-surface-size count; a
    /// later run with 2 more `pub fn`s shows the delta against it (see
    /// todo.md §I "API-Surface-Größe pro Crate, Trend gegen Baseline").
    #[test]
    fn api_surface_baseline_shows_a_size_delta() {
        let dir = TempDir::new("api-surface-baseline-delta");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            api_surface_cli(OutputFormat::Tty, true, None),
            &mut out,
        )
        .expect("saving a baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("api surface: fixture 1 items"),
            "unexpected output: {text}"
        );

        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn hello() {}\n\npub fn a() {}\n\npub fn b() {}\n",
        )
        .unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add two more pub fns"]);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            api_surface_cli(
                OutputFormat::Tty,
                false,
                Some(PathBuf::from(DEFAULT_BASELINE_API_SURFACE)),
            ),
            &mut out,
        )
        .expect("comparing against the baseline must not error");
        // The two new items are `undocumented-public-item` findings, but
        // that rule is `Severity::Info` — informational findings never fail
        // the verdict (see `judge::baseline::Delta::verdict`).
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("api surface: fixture 3 items (\u{394}+2 vs baseline)"),
            "unexpected output: {text}"
        );
    }

    /// (d) A baseline saved before `api_surface_size` existed — or by some
    /// other command's `--save-baseline` — still loads; the trend line says
    /// "not comparable" instead of crashing or showing a false delta (see
    /// todo.md §I, and `judge::baseline`'s own
    /// `baseline_without_api_surface_size_still_loads` unit test for the same
    /// backward-compatibility rule at the schema level).
    #[test]
    fn api_surface_baseline_without_size_field_is_not_comparable() {
        let dir = TempDir::new("api-surface-baseline-old-schema");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let commit = commit_sha(&dir, "HEAD");

        let baseline_path = dir.join("old-baseline.json");
        std::fs::write(
            &baseline_path,
            format!(
                r#"{{
                    "schema_version": 2,
                    "judge_version": "0.1.0",
                    "commit": "{commit}",
                    "rule_revisions": {{}},
                    "total_loc": 1,
                    "findings": []
                }}"#
            ),
        )
        .unwrap();

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            api_surface_cli(OutputFormat::Tty, false, Some(baseline_path)),
            &mut out,
        )
        .expect("comparing against an old-schema baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("api surface: fixture 1 items (not comparable to baseline)"),
            "unexpected output: {text}"
        );
    }

    /// A fixture crate with two `catch-all-error` boundary functions and a
    /// crate-local typed error — corroborated evidence for exactly one
    /// `stringly-error-boundary` pattern candidate (see `judge::pattern`).
    fn write_pattern_candidate_fixture_crate(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> {\n\
             \x20   std::fs::read_to_string(\"x\").map_err(|_| \"failed\".into())?;\n\
             \x20   Ok(())\n\
             }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> {\n\
             \x20   std::fs::read_to_string(\"y\").map_err(|_| \"failed\".into())?;\n\
             \x20   Ok(())\n\
             }\n\
             enum FixtureError { Bad }\n",
        )
        .unwrap();
    }

    /// A fixture crate combining fixtures for all five §16.3 MVP pattern
    /// rules at once: `stringly-error-boundary` (two `catch-all-error`
    /// boundary functions plus a crate-local typed error),
    /// `primitive-domain-value` (two `pub fn` signatures sharing a
    /// `threshold: u32` parameter, one of them guarded),
    /// `boolean-state-cluster` (a function with three bool parameters, two of
    /// which are combined in one condition), `public-invariant-bypass` (a
    /// `pub struct` with two `pub` fields and a constructor jointly
    /// validating both), and `manual-resource-lifecycle` (a function calling
    /// both an acquire- and a release-shaped operation, with no `impl Drop`
    /// anywhere in the crate) — corroborated evidence for five candidates of
    /// different patterns at once.
    fn write_multi_rule_pattern_candidate_fixture_crate(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> {\n\
             \x20   std::fs::read_to_string(\"x\").map_err(|_| \"failed\".into())?;\n\
             \x20   Ok(())\n\
             }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> {\n\
             \x20   std::fs::read_to_string(\"y\").map_err(|_| \"failed\".into())?;\n\
             \x20   Ok(())\n\
             }\n\
             enum FixtureError { Bad }\n\
             pub fn set_a(threshold: u32) {}\n\
             pub fn set_b(threshold: u32) -> Result<(), String> {\n\
             \x20   if threshold > 100 {\n\
             \x20       return Err(\"too big\".to_string());\n\
             \x20   }\n\
             \x20   Ok(())\n\
             }\n\
             pub fn configure(verbose: bool, strict: bool, dry_run: bool) {\n\
             \x20   if verbose && strict {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             \x20   let _ = dry_run;\n\
             }\n\
             fn do_thing() {}\n\
             pub struct Range {\n\
             \x20   pub low: u32,\n\
             \x20   pub high: u32,\n\
             }\n\
             impl Range {\n\
             \x20   pub fn new(low: u32, high: u32) -> Result<Self, String> {\n\
             \x20       if low >= high {\n\
             \x20           return Err(\"low must be less than high\".to_string());\n\
             \x20       }\n\
             \x20       Ok(Self { low, high })\n\
             \x20   }\n\
             }\n\
             pub fn manage(handle: u32) {\n\
             \x20   connect();\n\
             \x20   let _ = handle;\n\
             \x20   disconnect();\n\
             }\n\
             fn connect() {}\n\
             fn disconnect() {}\n",
        )
        .unwrap();
    }

    /// A fixture crate with one function satisfying both
    /// `functional-core-imperative-shell` signals: an `std::fs::read_to_string`
    /// call plus nine sequential `if`s (cyclomatic complexity 10, at
    /// [`judge::principle::FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD`]).
    fn write_principle_heuristic_fixture_crate(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn read_and_branch(path: &str) -> i32 {\n\
             \x20   let contents = std::fs::read_to_string(path).unwrap();\n\
             \x20   let mut total = contents.len() as i32;\n\
             \x20   if total > 0 { total += 1; }\n\
             \x20   if total > 1 { total += 1; }\n\
             \x20   if total > 2 { total += 1; }\n\
             \x20   if total > 3 { total += 1; }\n\
             \x20   if total > 4 { total += 1; }\n\
             \x20   if total > 5 { total += 1; }\n\
             \x20   if total > 6 { total += 1; }\n\
             \x20   if total > 7 { total += 1; }\n\
             \x20   if total > 8 { total += 1; }\n\
             \x20   total\n\
             }\n",
        )
        .unwrap();
    }

    /// A pair of duplicated function bodies (well over
    /// `judge::duplication::DEFAULT_MIN_TOKENS`), both in one new file — a
    /// self-contained `code_introduced` duplication finding once that file
    /// is committed.
    const DUPE_FILE_CONTENT: &str = r#"
fn dup_one(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}

fn dup_two(x: i32) -> i32 {
    let mut total = 0;
    for i in 0..x {
        total += i;
    }
    total
}
"#;

    /// Serializes every test that depends on the process working directory:
    /// [`run_in_dir`] points it at a fixture workspace (because
    /// `judge::ingest::load(None)` resolves the manifest from the current
    /// directory), and any test spawning `cargo metadata` — even with an
    /// explicit manifest path — needs it to *exist* while the child process
    /// starts. Both are process-global concerns, so they must not interleave.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_cwd() -> std::sync::MutexGuard<'static, ()> {
        CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn run_in_dir(dir: &Path, cli: Cli, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
        let _guard = lock_cwd();
        run_in_dir_locked(dir, cli, out)
    }

    /// [`run_in_dir`] for tests that already hold the [`CWD_LOCK`] guard —
    /// e.g. because their fixture setup itself spawns `cargo metadata` and
    /// must not interleave with another test's cwd change.
    fn run_in_dir_locked(
        dir: &Path,
        cli: Cli,
        out: &mut dyn Write,
    ) -> Result<CommandOutcome, CliError> {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = run(cli, out);
        std::env::set_current_dir(original).unwrap();
        result
    }

    fn run_json_in_dir(
        dir: &Path,
        cli: Cli,
        out: &mut dyn Write,
    ) -> Result<CommandOutcome, CliError> {
        let _guard = lock_cwd();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = run_with_artifact_output(cli, out);
        std::env::set_current_dir(original).unwrap();
        result
    }

    fn cli_with(command: Command) -> Cli {
        Cli {
            command: Some(command),
            baseline_args: baseline_args(OutputFormat::Tty, false, None),
            progress: None,
            details: false,
            color: ColorChoice::Auto,
            output: None,
        }
    }

    fn baseline_args(
        format: OutputFormat,
        save_baseline: bool,
        baseline: Option<PathBuf>,
    ) -> BaselineArgs {
        BaselineArgs {
            format,
            save_baseline,
            baseline,
        }
    }

    fn dupes_cli(format: OutputFormat, save_baseline: bool, baseline: Option<PathBuf>) -> Cli {
        cli_with(Command::Dupes(DupesOptions {
            mode: DupeModeArg::Mild,
            min_tokens: judge::duplication::DEFAULT_MIN_TOKENS,
            baseline_args: baseline_args(format, save_baseline, baseline),
            include_generated: false,
            include_tests: false,
        }))
    }

    fn api_surface_cli(
        format: OutputFormat,
        save_baseline: bool,
        baseline: Option<PathBuf>,
    ) -> Cli {
        cli_with(Command::ApiSurface(ApiSurfaceOptions {
            baseline_args: baseline_args(format, save_baseline, baseline),
            include_generated: false,
        }))
    }

    /// Bare `cargo judge` (no subcommand — `Cli::command` is `None`).
    fn all_cli(save_baseline: bool, baseline: Option<PathBuf>) -> Cli {
        Cli {
            command: None,
            baseline_args: baseline_args(OutputFormat::Tty, save_baseline, baseline),
            progress: None,
            details: false,
            color: ColorChoice::Auto,
            output: None,
        }
    }

    fn all_cli_markdown() -> Cli {
        Cli {
            baseline_args: baseline_args(OutputFormat::Markdown, false, None),
            ..all_cli(false, None)
        }
    }

    #[test]
    fn compare_works_from_an_artifact_in_a_workspace_without_git() {
        let dir = TempDir::new("compare-without-git");
        write_fixture_crate(&dir);

        let mut save_out = Vec::new();
        run_in_dir(&dir, all_cli(true, None), &mut save_out)
            .expect("saving a baseline must not require Git");
        let baseline_path = dir.join(DEFAULT_BASELINE_ALL);
        let baseline: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&baseline_path).unwrap()).unwrap();
        assert!(baseline.get("commit").is_none(), "baseline: {baseline}");

        let mut compare_out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Compare(CompareOptions {
                baseline: baseline_path,
                format: OutputFormat::Json,
            })),
            &mut compare_out,
        )
        .expect("comparison must not require Git");
        assert_eq!(outcome, CommandOutcome::Clean);
        let compare: serde_json::Value = serde_json::from_slice(&compare_out).unwrap();
        assert_eq!(compare["delta"]["introduced"], serde_json::json!([]));
        assert_eq!(compare["delta"]["resolved"], serde_json::json!([]));

        let mut structure_out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::Structure(StructureOptions {
                format: OutputFormat::Json,
            })),
            &mut structure_out,
        )
        .expect("structure must not require Git");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&structure_out).unwrap()["crates"]
                .is_array()
        );

        let mut refactor_out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::Refactor(RefactorOptions {
                target: None,
                format: OutputFormat::Json,
            })),
            &mut refactor_out,
        )
        .expect("refactor must not require Git");
        let refactor: serde_json::Value = serde_json::from_slice(&refactor_out).unwrap();
        assert!(refactor["candidates"].is_array());
        assert!(refactor["findings"].is_array());
    }

    #[test]
    fn flattened_baseline_arguments_remain_available_to_root_and_subcommands() {
        let root = Cli::try_parse_from(["judge", "--format", "json", "--save-baseline"])
            .expect("root baseline arguments must parse");
        assert!(root.command.is_none());
        assert!(matches!(root.baseline_args.format, OutputFormat::Json));
        assert!(root.baseline_args.save_baseline);

        let cli = Cli::try_parse_from([
            "judge",
            "dupes",
            "--format",
            "sarif",
            "--baseline",
            "saved.json",
        ])
        .expect("subcommand baseline arguments must parse");
        let Some(Command::Dupes(options)) = cli.command else {
            panic!("expected dupes command");
        };
        assert!(matches!(options.baseline_args.format, OutputFormat::Sarif));
        assert_eq!(
            options.baseline_args.baseline,
            Some(PathBuf::from("saved.json"))
        );

        let root_details =
            Cli::try_parse_from(["judge", "--details"]).expect("combined details flag must parse");
        assert!(root_details.details);
    }

    #[test]
    fn combined_tty_defaults_to_a_grouped_summary_and_keeps_details_available() {
        let dir = TempDir::new("combined-tty-summary");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        std::fs::write(dir.join("src/lib.rs"), DUPE_FILE_CONTENT).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut summary_out = Vec::new();
        run_in_dir(&dir, all_cli(false, None), &mut summary_out)
            .expect("combined summary must run");
        let summary = String::from_utf8(summary_out).unwrap();
        assert!(
            summary.starts_with("[WARN] Judge summary\n"),
            "unexpected output: {summary}"
        );
        assert!(
            summary.contains("duplicate-code"),
            "unexpected output: {summary}"
        );
        assert!(
            summary.contains("Next steps"),
            "unexpected output: {summary}"
        );
        assert!(
            !summary.contains("[warn] duplicate-code"),
            "the default must not print every clone member: {summary}"
        );

        let mut detailed_cli = all_cli(false, None);
        detailed_cli.details = true;
        let mut details_out = Vec::new();
        run_in_dir(&dir, detailed_cli, &mut details_out).expect("detailed report must run");
        let details = String::from_utf8(details_out).unwrap();
        assert!(
            details.contains("duplicate-code in dup_one"),
            "details must retain the exhaustive list: {details}"
        );
        assert!(
            details.contains("src/lib.rs:2"),
            "details must use workspace-relative paths: {details}"
        );
    }

    /// Success path: a clean fixture workspace runs through `run` to
    /// `CommandOutcome::Clean`, with the TTY report in the writer.
    #[test]
    fn run_reports_clean_on_a_fixture_without_findings() {
        let dir = TempDir::new("run-clean");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, dupes_cli(OutputFormat::Tty, false, None), &mut out)
            .expect("clean fixture must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("clone families: 0"),
            "unexpected output: {text}"
        );
    }

    #[test]
    fn dupes_json_includes_a_compact_refactoring_summary() {
        let dir = TempDir::new("dupes-refactoring-summary");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        run_in_dir(&dir, dupes_cli(OutputFormat::Json, false, None), &mut out)
            .expect("dupes must run");
        let json: serde_json::Value = serde_json::from_slice(&out).expect("dupes JSON");

        assert_eq!(json["refactoring_summary"]["schema_version"], 1);
        assert_eq!(json["refactoring_summary"]["clone_families"], 0);
        assert_eq!(json["refactoring_summary"]["clone_members"], 0);
        assert_eq!(
            json["refactoring_summary"]["top_families"],
            serde_json::json!([])
        );
    }

    /// GitHub issue #7: with more than [`DUPE_FAMILY_TTY_LIMIT`] clone
    /// families, the TTY view must say so explicitly instead of silently
    /// stopping after the cap — the header count alone isn't enough,
    /// grepping the (apparently complete) family list for a touched file
    /// and finding nothing must not read as "no duplication".
    #[test]
    fn run_dupes_tty_reports_a_trailer_when_families_exceed_the_cap() {
        let dir = TempDir::new("dupes-truncation-trailer");
        write_n_duplicate_clone_families(&dir, 16);

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, dupes_cli(OutputFormat::Tty, false, None), &mut out)
            .expect("fixture must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("clone families: 16"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("... and 1 more families (see --format json for the full list)"),
            "missing truncation trailer: {text}"
        );
    }

    /// The TTY trailer above promises "the full list" in `--format json` —
    /// `refactoring_summary.top_families` must actually carry every family in
    /// that format, not just the TTY's own top-5 ranked summary slice.
    #[test]
    fn dupes_json_refactoring_summary_is_not_truncated_to_the_tty_summary_cap() {
        let dir = TempDir::new("dupes-json-full-family-list");
        write_n_duplicate_clone_families(&dir, 16);

        let mut out = Vec::new();
        run_in_dir(&dir, dupes_cli(OutputFormat::Json, false, None), &mut out)
            .expect("dupes must run");
        let json: serde_json::Value = serde_json::from_slice(&out).expect("dupes JSON");

        assert_eq!(json["refactoring_summary"]["clone_families"], 16);
        assert_eq!(
            json["refactoring_summary"]["top_families"]
                .as_array()
                .expect("top_families array")
                .len(),
            16,
            "JSON top_families must list every family, not just the TTY's top 5"
        );
    }

    /// `count` distinct clone families (each a duplicated pair) — every pair
    /// has unique literals so Mild mode doesn't merge them into one family,
    /// and each body is well over `DEFAULT_MIN_TOKENS` (20).
    fn write_n_duplicate_clone_families(dir: &Path, count: usize) {
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let mut source = String::new();
        for i in 0..count {
            for suffix in ["a", "b"] {
                source.push_str(&format!(
                    "pub fn dup_{i}_{suffix}() -> i32 {{ let v0 = {i}; let v1 = {i}; \
                     let v2 = {i}; let v3 = {i}; let v4 = {i}; let v5 = {i}; \
                     let v6 = {i}; v0 + v1 + v2 + v3 + v4 + v5 + v6 }}\n"
                ));
            }
        }
        std::fs::write(dir.join("src/lib.rs"), source).unwrap();
    }

    /// Findings path: a failing baseline-compare verdict becomes
    /// `CommandOutcome::FindingsFound` (exit 1), never an error.
    #[test]
    fn run_maps_a_failing_baseline_verdict_to_findings_found() {
        let dir = TempDir::new("run-findings-found");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, dupes_cli(OutputFormat::Tty, true, None), &mut out)
            .expect("saving a baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("baseline saved:"),
            "unexpected output: {text}"
        );

        std::fs::write(dir.join("src/dupe.rs"), DUPE_FILE_CONTENT).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add duplicated code"]);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            dupes_cli(
                OutputFormat::Tty,
                false,
                Some(PathBuf::from(DEFAULT_BASELINE_DUPES)),
            ),
            &mut out,
        )
        .expect("a failing verdict is an outcome, not an error");
        assert_eq!(outcome, CommandOutcome::FindingsFound);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: fail"), "unexpected output: {text}");
    }

    /// (f) End-to-end (todo.md §5): a `// judge-ignore: <rule> — <reason>`
    /// comment on an otherwise-`Fail`-triggering finding (`swallowed-result`
    /// — `slop.rs`'s own tests cover that it fires without suppression)
    /// removes it before the baseline diff, so the verdict is
    /// `CommandOutcome::Clean`/`pass` instead of `FindingsFound`/`fail`.
    #[test]
    fn judge_ignore_suppresses_a_finding_so_it_does_not_fail_the_verdict() {
        let dir = TempDir::new("judge-ignore-verdict");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, all_cli(true, None), &mut out)
            .expect("saving a baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);

        std::fs::write(
            dir.join("src/risky.rs"),
            format!(
                "pub fn call_it() {{\n    let _ = std::fs::remove_file(\"x\"); // {} swallowed-result — best-effort cleanup\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();
        git(&dir, &["add", "."]);
        git(
            &dir,
            &["commit", "-q", "-m", "add suppressed swallowed-result"],
        );

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            all_cli(false, Some(PathBuf::from(DEFAULT_BASELINE_ALL))),
            &mut out,
        )
        .expect("a suppressed finding must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: pass"), "unexpected output: {text}");
    }

    /// (d) End-to-end (todo.md §5): a `judge-ignore` comment with no reason
    /// is a hard config error (exit 2), analogous to `judge-dupe-off`
    /// without a reason (`duplication::tests::judge_dupe_off_without_a_reason_is_a_hard_error`).
    #[test]
    fn judge_ignore_without_a_reason_is_a_config_error_end_to_end() {
        let dir = TempDir::new("judge-ignore-missing-reason");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        std::fs::write(
            dir.join("src/risky.rs"),
            format!(
                "pub fn call_it() {{\n    let _ = std::fs::remove_file(\"x\"); // {} swallowed-result\n}}\n",
                ignore_marker()
            ),
        )
        .unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut out = Vec::new();
        let err = run_in_dir(&dir, all_cli(false, None), &mut out)
            .expect_err("a judge-ignore comment with no reason must be a config error");
        match err {
            CliError::Config(message) => {
                assert!(message.contains("requires a reason"), "message: {message}");
            }
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// Config-error path: an unparseable `judge.toml` is a `CliError::Config`
    /// (exit 2), not a panic or a silent pass.
    #[test]
    fn run_reports_a_broken_judge_toml_as_a_config_error() {
        let dir = TempDir::new("run-broken-config");
        write_fixture_crate(&dir);
        std::fs::write(dir.join("judge.toml"), "this is { not toml").unwrap();

        let mut out = Vec::new();
        let err = run_in_dir(
            &dir,
            cli_with(Command::Boundaries(BoundariesOptions {
                config: None,
                baseline_args: baseline_args(OutputFormat::Tty, false, None),
                graph: None,
            })),
            &mut out,
        )
        .expect_err("a broken judge.toml must be an error");
        match err {
            CliError::Config(message) => {
                assert!(message.contains("failed to parse"), "message: {message}");
            }
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// `cargo judge boundaries --graph dot` is a pure projection of the
    /// crate graph (todo.md §H) — it must work without a `judge.toml`
    /// (boundaries proper are opt-in and require one; the graph does not),
    /// and must not touch findings/baseline machinery at all.
    #[test]
    fn run_boundaries_graph_dot_renders_the_crate_graph_without_a_judge_toml() {
        let dir = TempDir::new("boundaries-graph-dot");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Boundaries(BoundariesOptions {
                config: None,
                baseline_args: baseline_args(OutputFormat::Tty, false, None),
                graph: Some(GraphFormat::Dot),
            })),
            &mut out,
        )
        .expect("graph projection must not require judge.toml");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "digraph crates {\n  \"fixture\";\n}\n");
    }

    /// Same fixture, Mermaid format — todo.md §H names both `dot` and
    /// `mermaid` as the two graph output formats.
    #[test]
    fn run_boundaries_graph_mermaid_renders_the_crate_graph() {
        let dir = TempDir::new("boundaries-graph-mermaid");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::Boundaries(BoundariesOptions {
                config: None,
                baseline_args: baseline_args(OutputFormat::Tty, false, None),
                graph: Some(GraphFormat::Mermaid),
            })),
            &mut out,
        )
        .expect("graph projection must not require judge.toml");
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "flowchart TD\n  fixture[\"fixture\"]\n");
    }

    /// Config-error path: a baseline with an unknown `schema_version` is a
    /// `CliError::Config` (exit 2) with the library's guidance message.
    #[test]
    fn run_reports_an_unsupported_baseline_schema_version_as_a_config_error() {
        let dir = TempDir::new("run-baseline-schema");
        write_fixture_crate(&dir);
        let baseline_path = dir.join("baseline.json");
        std::fs::write(&baseline_path, r#"{"schema_version": 999}"#).unwrap();

        let mut out = Vec::new();
        let err = run_in_dir(
            &dir,
            dupes_cli(OutputFormat::Tty, false, Some(baseline_path)),
            &mut out,
        )
        .expect_err("an unsupported baseline schema version must be an error");
        match err {
            CliError::Config(message) => {
                assert!(
                    message.contains("unsupported baseline schema_version 999"),
                    "message: {message}"
                );
            }
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// Analyzer-error path: no workspace at all is a `CliError::Analyzer`
    /// (exit 2) — `cargo metadata` cannot run.
    #[test]
    fn run_reports_a_missing_workspace_as_an_analyzer_error() {
        let dir = TempDir::new("run-no-workspace");

        let mut out = Vec::new();
        let err = run_in_dir(&dir, dupes_cli(OutputFormat::Tty, false, None), &mut out)
            .expect_err("a directory without a Cargo.toml must be an error");
        assert!(
            matches!(err, CliError::Analyzer(_)),
            "expected CliError::Analyzer, got {err:?}"
        );
    }

    /// JSON rendering goes to the writer handed to `run`, not to a global
    /// stream — the report envelope must parse from the captured bytes.
    #[test]
    fn run_writes_the_json_report_into_the_given_writer() {
        let dir = TempDir::new("run-json-writer");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, dupes_cli(OutputFormat::Json, false, None), &mut out)
            .expect("json report must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let value: serde_json::Value =
            serde_json::from_slice(&out).expect("writer must contain valid JSON");
        assert_eq!(value["schema_version"], judge::finding::SCHEMA_VERSION);
        assert!(value.get("findings").is_some());
    }

    /// `--format sarif` renders a SARIF 2.1.0 log with workspace-relative,
    /// forward-slash artifact URIs (see `judge::sarif`).
    #[test]
    fn run_writes_a_sarif_log_into_the_given_writer() {
        let dir = TempDir::new("run-sarif-writer");
        write_fixture_crate(&dir);
        std::fs::write(dir.join("src/dupe.rs"), DUPE_FILE_CONTENT).unwrap();

        let mut out = Vec::new();
        let outcome = run_in_dir(&dir, dupes_cli(OutputFormat::Sarif, false, None), &mut out)
            .expect("sarif report must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let value: serde_json::Value =
            serde_json::from_slice(&out).expect("writer must contain valid JSON");
        assert_eq!(value["version"], "2.1.0");
        let run = &value["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "judge");
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "duplicate-code");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "duplicate-code");
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/dupe.rs"
        );
        assert_eq!(result["properties"]["evidence_class"], "derived_fact");
    }

    /// Markdown is delta-only (see todo.md §7): a plain report command must
    /// reject it as a config error (exit 2) instead of printing half-baked
    /// output.
    #[test]
    fn health_format_markdown_is_a_config_error() {
        let dir = TempDir::new("health-format-markdown");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let err = run_in_dir(
            &dir,
            cli_with(Command::Health(HealthOptions {
                score: false,
                show_cascades: false,
                baseline_args: baseline_args(OutputFormat::Markdown, false, None),
                include_generated: false,
            })),
            &mut out,
        )
        .expect_err("`health --format markdown` must be a config error");
        match err {
            CliError::Config(message) => {
                assert!(
                    message.contains("--format markdown is not supported"),
                    "message: {message}"
                );
            }
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// `explain` supports neither SARIF nor Markdown — a clean config error
    /// (exit 2) in Fast and Deep Tier builds alike.
    #[test]
    fn explain_format_sarif_is_a_config_error() {
        let mut out = Vec::new();
        let err = run(
            cli_with(Command::Explain(ExplainOptions {
                item_path: "core::retry::backoff".to_string(),
                why_live: true,
                include_tests: false,
                format: OutputFormat::Sarif,
            })),
            &mut out,
        )
        .expect_err("`explain --format sarif` must be a config error");
        match err {
            CliError::Config(message) => {
                assert!(
                    message.contains("--format sarif is not supported"),
                    "message: {message}"
                );
            }
            other => panic!("expected CliError::Config, got {other:?}"),
        }
    }

    /// (d) `patterns` never fails the verdict, even with a real corroborated
    /// candidate (todo.md §16.6: "Kein Pattern-Kandidat allein führt zu
    /// Exitcode 1").
    #[test]
    fn patterns_command_is_clean_even_with_a_real_candidate() {
        let dir = TempDir::new("patterns-clean");
        write_pattern_candidate_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Patterns(PatternsOptions {
                format: OutputFormat::Json,
                clippy_json: None,
                save_pattern_baseline: false,
                pattern_baseline: None,
            })),
            &mut out,
        )
        .expect("`patterns` must not error on a valid fixture");
        assert_eq!(outcome, CommandOutcome::Clean);

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let candidates = json["candidates"].as_array().expect("candidates array");
        assert_eq!(
            candidates.len(),
            1,
            "expected one corroborated candidate: {json}"
        );
    }

    /// (d.2) Several pattern rules can produce candidates in the same run —
    /// here all five §16.3 MVP rules fire together on one fixture — and
    /// `patterns` still stays clean (exit 0).
    #[test]
    fn patterns_command_reports_candidates_from_multiple_rules_and_stays_clean() {
        let dir = TempDir::new("patterns-multi-rule");
        write_multi_rule_pattern_candidate_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Patterns(PatternsOptions {
                format: OutputFormat::Json,
                clippy_json: None,
                save_pattern_baseline: false,
                pattern_baseline: None,
            })),
            &mut out,
        )
        .expect("`patterns` must not error on a valid fixture");
        assert_eq!(outcome, CommandOutcome::Clean);

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let candidates = json["candidates"].as_array().expect("candidates array");
        assert_eq!(
            candidates.len(),
            5,
            "expected one candidate per rule: {json}"
        );
        let patterns: std::collections::BTreeSet<&str> = candidates
            .iter()
            .map(|candidate| candidate["pattern"].as_str().unwrap())
            .collect();
        assert_eq!(
            patterns,
            std::collections::BTreeSet::from([
                "domain_error",
                "validated_newtype",
                "options_struct",
                "smart_constructor",
                "raii_guard",
            ]),
            "expected candidates from five different rules: {json}"
        );
    }

    /// (d.3) `--save-pattern-baseline` writes a `PatternBaseline` JSON file
    /// — a separate mechanism from `Finding` baselines (see
    /// `judge::pattern_baseline`) — and `--pattern-baseline` reads it back,
    /// classifying candidates into new/resolved/unchanged with no verdict
    /// (pattern candidates never gate).
    #[test]
    fn pattern_baseline_flags_save_and_diff_candidates() {
        let dir = TempDir::new("patterns-baseline-flags");
        write_pattern_candidate_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Patterns(PatternsOptions {
                format: OutputFormat::Tty,
                clippy_json: None,
                save_pattern_baseline: true,
                pattern_baseline: None,
            })),
            &mut out,
        )
        .expect("saving a pattern baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("pattern baseline saved:") && text.contains("(1 candidates)"),
            "unexpected output: {text}"
        );
        assert!(
            dir.join(DEFAULT_PATTERN_BASELINE).exists(),
            "expected {} to exist",
            DEFAULT_PATTERN_BASELINE
        );

        // The multi-rule fixture keeps `fn a`/`fn b`/`FixtureError` verbatim
        // (see its doc comment) and adds four more pattern-triggering
        // shapes, so the `domain-error` candidate saved above keeps the same
        // id (unchanged) while the other four are new.
        write_multi_rule_pattern_candidate_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Patterns(PatternsOptions {
                format: OutputFormat::Tty,
                clippy_json: None,
                save_pattern_baseline: false,
                pattern_baseline: Some(PathBuf::from(DEFAULT_PATTERN_BASELINE)),
            })),
            &mut out,
        )
        .expect("comparing against a pattern baseline must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("unchanged: 1"), "unexpected output: {text}");
        assert!(text.contains("resolved: 0"), "unexpected output: {text}");
        assert!(text.contains("new: 4"), "unexpected output: {text}");
    }

    /// (e) `principles` reports the corroborated `functional-core-
    /// imperative-shell` heuristic and never fails the verdict (todo.md
    /// §16.7: advisory only, same as `patterns`).
    #[test]
    fn principles_command_reports_a_heuristic_and_stays_clean() {
        let dir = TempDir::new("principles-clean");
        write_principle_heuristic_fixture_crate(&dir);

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::Principles(PrinciplesOptions {
                format: OutputFormat::Json,
            })),
            &mut out,
        )
        .expect("`principles` must not error on a valid fixture");
        assert_eq!(outcome, CommandOutcome::Clean);

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let heuristics = json["heuristics"].as_array().expect("heuristics array");
        assert_eq!(
            heuristics.len(),
            1,
            "expected one corroborated heuristic: {json}"
        );
        assert_eq!(
            heuristics[0]["principle"].as_str(),
            Some("functional_core_imperative_shell")
        );
    }

    /// (e) `explain-pattern` with an unknown id is a usage error (exit 2),
    /// not a findings verdict.
    #[test]
    fn explain_pattern_unknown_id_is_an_analyzer_error() {
        let dir = TempDir::new("explain-pattern-unknown");
        write_fixture_crate(&dir);

        let mut out = Vec::new();
        let err = run_in_dir(
            &dir,
            cli_with(Command::ExplainPattern(ExplainPatternOptions {
                id: "pattern:domain-error:doesnotexist".to_string(),
                format: OutputFormat::Tty,
            })),
            &mut out,
        )
        .expect_err("unknown pattern candidate id must be an error");
        match err {
            CliError::Analyzer(message) => {
                assert!(
                    message.contains("unknown pattern candidate id"),
                    "message: {message}"
                );
            }
            other => panic!("expected CliError::Analyzer, got {other:?}"),
        }
    }

    /// (e) `explain-principle` with an unknown id is a usage error (exit 2),
    /// not a findings verdict — same convention as `explain-pattern`.
    #[test]
    fn explain_principle_unknown_id_is_an_analyzer_error() {
        let dir = TempDir::new("explain-principle-unknown");
        write_principle_heuristic_fixture_crate(&dir);

        let mut out = Vec::new();
        let err = run_in_dir(
            &dir,
            cli_with(Command::ExplainPrinciple(ExplainPrincipleOptions {
                id: "principle:cohesion:doesnotexist".to_string(),
                format: OutputFormat::Tty,
            })),
            &mut out,
        )
        .expect_err("unknown principle heuristic id must be an error");
        match err {
            CliError::Analyzer(message) => {
                assert!(
                    message.contains("unknown principle heuristic id"),
                    "message: {message}"
                );
            }
            other => panic!("expected CliError::Analyzer, got {other:?}"),
        }
    }

    /// (e) `explain-principle` on a known id returns the same heuristic
    /// `principles` reports, rendered with its full evidence and
    /// interpretation.
    #[test]
    fn explain_principle_known_id_matches_principles_output() {
        let dir = TempDir::new("explain-principle-known");
        write_principle_heuristic_fixture_crate(&dir);

        let mut json_out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::Principles(PrinciplesOptions {
                format: OutputFormat::Json,
            })),
            &mut json_out,
        )
        .expect("`principles` must not error");
        let json: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
        let id = json["heuristics"][0]["id"]
            .as_str()
            .expect("heuristic id")
            .to_string();

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::ExplainPrinciple(ExplainPrincipleOptions {
                id: id.clone(),
                format: OutputFormat::Json,
            })),
            &mut out,
        )
        .expect("`explain-principle` must not error for a known id");
        assert_eq!(outcome, CommandOutcome::Clean);
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(json["id"].as_str(), Some(id.as_str()));
        assert_eq!(
            json["principle"].as_str(),
            Some("functional_core_imperative_shell")
        );

        let mut tty_out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::ExplainPrinciple(ExplainPrincipleOptions {
                id,
                format: OutputFormat::Tty,
            })),
            &mut tty_out,
        )
        .expect("`explain-principle` must not error for a known id");
        let text = String::from_utf8(tty_out).unwrap();
        assert!(text.contains("principle heuristic:"), "output: {text}");
        assert!(text.contains("interpretation:"), "output: {text}");
    }

    /// `explain-rule` is a pure static lookup — no workspace/cwd needed, so
    /// these tests call `run` directly instead of `run_in_dir`.
    ///
    /// (a) A known rule id resolves with every field rendered in TTY output.
    #[test]
    fn explain_rule_known_id_renders_all_fields_in_tty() {
        let mut out = Vec::new();
        let outcome = run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "catch-all-error".to_string(),
                format: OutputFormat::Tty,
            })),
            &mut out,
        )
        .expect("known rule id must not error");
        assert_eq!(outcome, CommandOutcome::Clean);

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("rule: catch-all-error"), "{text}");
        assert!(text.contains("evidence class: derived_fact"), "{text}");
        assert!(text.contains("verdict effect: gating"), "{text}");
        assert!(text.contains("preconditions:"), "{text}");
        assert!(text.contains("exclusions:"), "{text}");
        assert!(text.contains("allowed wording:"), "{text}");
    }

    /// (a) Same known rule id, rendered as JSON — same field values, an
    /// unambiguous shape.
    #[test]
    fn explain_rule_known_id_renders_all_fields_in_json() {
        let mut out = Vec::new();
        let outcome = run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "catch-all-error".to_string(),
                format: OutputFormat::Json,
            })),
            &mut out,
        )
        .expect("known rule id must not error");
        assert_eq!(outcome, CommandOutcome::Clean);

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(json["id"], "catch-all-error");
        assert_eq!(json["evidence_class"], "derived_fact");
        assert_eq!(json["verdict_effect"], "gating");
        assert!(
            !json["preconditions"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
        );
        assert!(!json["exclusions"].as_str().unwrap_or_default().is_empty());
        assert!(
            !json["allowed_wording"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
        );
    }

    /// (c) A rule id with a curated registry example renders it in both TTY
    /// and JSON; a rule id without one (`catch-all-error`, above) omits the
    /// section/field entirely rather than printing an empty placeholder.
    #[test]
    fn explain_rule_with_a_curated_example_renders_it_in_tty_and_json() {
        let mut tty_out = Vec::new();
        run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "swallowed-result".to_string(),
                format: OutputFormat::Tty,
            })),
            &mut tty_out,
        )
        .expect("known rule id must not error");
        let tty_text = String::from_utf8(tty_out).unwrap();
        assert!(tty_text.contains("  example:"), "{tty_text}");
        assert!(tty_text.contains("let _ ="), "{tty_text}");
        assert!(tty_text.contains("why it matters:"), "{tty_text}");

        let mut json_out = Vec::new();
        run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "swallowed-result".to_string(),
                format: OutputFormat::Json,
            })),
            &mut json_out,
        )
        .expect("known rule id must not error");
        let json: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
        assert!(
            json["example"]["before"]
                .as_str()
                .unwrap()
                .contains("let _ =")
        );
        assert!(
            !json["example"]["why_it_matters"]
                .as_str()
                .unwrap()
                .is_empty()
        );

        let mut no_example_out = Vec::new();
        run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "crate-boundary-violation".to_string(),
                format: OutputFormat::Json,
            })),
            &mut no_example_out,
        )
        .expect("known rule id must not error");
        let json: serde_json::Value = serde_json::from_slice(&no_example_out).unwrap();
        assert!(json["example"].is_null());
    }

    /// (b) An unknown rule id is a usage error (exit 2), not a findings
    /// verdict — same convention as `explain-pattern`.
    #[test]
    fn explain_rule_unknown_id_is_an_analyzer_error() {
        let mut out = Vec::new();
        let err = run(
            cli_with(Command::ExplainRule(ExplainRuleOptions {
                id: "not-a-real-rule".to_string(),
                format: OutputFormat::Tty,
            })),
            &mut out,
        )
        .expect_err("unknown rule id must be an error");
        match &err {
            CliError::Analyzer(message) => {
                assert!(message.contains("unknown rule id"), "message: {message}");
            }
            other => panic!("expected CliError::Analyzer, got {other:?}"),
        }
        assert_eq!(exit_code(&Err(err)), 2);
    }

    /// (f) `fix-preview` returns only the migration plan and related
    /// findings — no patch.
    #[test]
    fn fix_preview_lists_migration_steps_without_a_patch() {
        let dir = TempDir::new("fix-preview");
        write_pattern_candidate_fixture_crate(&dir);

        let mut json_out = Vec::new();
        run_in_dir(
            &dir,
            cli_with(Command::Patterns(PatternsOptions {
                format: OutputFormat::Json,
                clippy_json: None,
                save_pattern_baseline: false,
                pattern_baseline: None,
            })),
            &mut json_out,
        )
        .expect("`patterns` must not error");
        let json: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
        let id = json["candidates"][0]["id"]
            .as_str()
            .expect("candidate id")
            .to_string();

        let mut out = Vec::new();
        let outcome = run_in_dir(
            &dir,
            cli_with(Command::FixPreview(FixPreviewOptions {
                id,
                format: OutputFormat::Json,
            })),
            &mut out,
        )
        .expect("`fix-preview` must not error for a known id");
        assert_eq!(outcome, CommandOutcome::Clean);

        let preview: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(preview["patch"].is_null(), "preview: {preview}");
        assert!(
            !preview["migration"]
                .as_array()
                .expect("migration array")
                .is_empty()
        );
        assert!(
            !preview["related_findings"]
                .as_array()
                .expect("related_findings array")
                .is_empty()
        );
    }

    /// A writer that fails like a closed pipe (`cargo judge … | head`).
    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Broken pipe: the render aborts with `CliError::Io(BrokenPipe)`, which
    /// [`exit_code`] maps to a silent exit 0 — before the refactor this was
    /// a `println!` panic (exit 101).
    #[test]
    fn a_broken_pipe_while_rendering_maps_to_exit_zero() {
        let dir = TempDir::new("run-broken-pipe");
        write_fixture_crate(&dir);

        let result = run_in_dir(&dir, cli_with(Command::Inspect), &mut BrokenPipeWriter);
        let err = result.expect_err("writes to a broken pipe must surface as an error");
        match &err {
            CliError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected CliError::Io, got {other:?}"),
        }
        assert_eq!(exit_code(&Err(err)), 0);
    }

    /// The exit-code convention `main` applies: 0 clean, 1 findings verdict
    /// failed, 2 real error — broken pipe being the documented exception.
    #[test]
    fn exit_codes_follow_the_documented_convention() {
        assert_eq!(exit_code(&Ok(CommandOutcome::Clean)), 0);
        assert_eq!(exit_code(&Ok(CommandOutcome::FindingsFound)), 1);
        assert_eq!(exit_code(&Err(CliError::Config("x".to_string()))), 2);
        assert_eq!(exit_code(&Err(CliError::Analyzer("x".to_string()))), 2);
        assert_eq!(exit_code(&Err(CliError::Reported)), 2);
        assert_eq!(
            exit_code(&Err(CliError::AnalysisIncomplete {
                context: "x",
                errors: Vec::new(),
            })),
            2
        );
        assert_eq!(
            exit_code(&Err(CliError::Io(std::io::Error::other("disk")))),
            2
        );
    }

    /// Artifact comparison classifies newly added source findings without
    /// consulting repository history.
    #[test]
    fn baseline_diff_classifies_a_new_files_duplication_as_introduced() {
        let _guard = lock_cwd();
        let dir = TempDir::new("audit-code-introduced");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base_commit = commit_sha(&dir, "HEAD");

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let baseline_collected = collect_findings(&workspace).unwrap();
        assert!(baseline_collected.analysis_errors.is_empty());
        let baseline = judge::baseline::Baseline::new(
            &baseline_collected.findings,
            base_commit.clone(),
            baseline_collected.rule_revisions,
            judge::health_score::total_authored_loc(&workspace),
            judge::health_score::ScoreContext::from_profiles(&[]),
        );

        // `judge::ingest::collect_source_files` walks the directory tree
        // rather than following `mod` declarations, so a new file is picked
        // up without needing to be wired into `lib.rs`.
        std::fs::write(dir.join("src/dupe.rs"), DUPE_FILE_CONTENT).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add duplicated code"]);
        // Source file lists are captured at `ingest::load` time, not
        // re-scanned dynamically — reload to see the file added above.
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let mut collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

        let delta = judge::baseline::diff(
            &collected.findings,
            &baseline,
            &std::collections::HashSet::new(),
            &collected.rule_revisions,
        );

        let dupe_introduced: Vec<_> = delta
            .introduced
            .iter()
            .filter(|finding| finding.rule == judge::duplication::DUPLICATE_RULE)
            .collect();
        assert_eq!(dupe_introduced.len(), 2);
        for finding in &dupe_introduced {
            assert_eq!(finding.location.file, PathBuf::from("src/dupe.rs"));
            assert_eq!(finding.severity, judge::finding::Severity::Warn);
        }
        assert_eq!(delta.tri_verdict(), TriVerdict::Warn);
    }

    /// Artifact comparisons retain an identical finding even when the rule
    /// revision changed; Git history is irrelevant to the comparison.
    #[test]
    fn artifact_comparison_keeps_an_identical_finding_unchanged() {
        let dir = TempDir::new("audit-rule-introduced");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base_commit = commit_sha(&dir, "HEAD");

        // Second commit touches an unrelated file only — `src/lib.rs` (the
        // file the simulated pre-existing finding lives in) is untouched.
        std::fs::write(dir.join("src/other.rs"), "pub fn other() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "unrelated change"]);

        let pre_existing = judge::finding::Finding::new(
            "duplicate-code:src/lib.rs:hello:0-20".to_string(),
            judge::duplication::DUPLICATE_RULE.to_string(),
            judge::finding::Severity::Warn,
            judge::finding::Location {
                file: PathBuf::from("src/lib.rs"),
                line: judge::finding::OneBasedLine::FIRST,
                item_path: "hello".to_string(),
            },
            judge::finding::EvidenceClass::DerivedFact,
            judge::finding::Origin::Code,
            None,
        );
        let baseline = judge::baseline::Baseline::new(
            std::slice::from_ref(&pre_existing),
            base_commit,
            std::collections::HashMap::from([(judge::duplication::DUPLICATE_RULE.to_string(), 1)]),
            0,
            judge::health_score::ScoreContext::from_profiles(&[]),
        );
        let bumped_revisions =
            std::collections::HashMap::from([(judge::duplication::DUPLICATE_RULE.to_string(), 2)]);

        let delta = judge::baseline::diff(
            &[pre_existing],
            &baseline,
            &std::collections::HashSet::new(),
            &bumped_revisions,
        );

        assert_eq!(delta.unchanged_count, 1);
        assert!(delta.introduced.is_empty());
        assert!(delta.rule_introduced.is_empty());
        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);
    }

    /// Tests todo.md §17.2/§17.5's advisory default at the wiring level: a
    /// workspace whose only findings are heuristic (here: `churn-hotspot`)
    /// (a) scores without deductions and reports an advisory count, and
    /// (c) never breaks the delta/audit verdict with newly introduced
    /// heuristic findings.
    #[test]
    fn heuristic_only_findings_pass_the_verdict_and_score_without_deductions() {
        let _guard = lock_cwd();
        let dir = TempDir::new("advisory-heuristics-only");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base_commit = commit_sha(&dir, "HEAD");

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let baseline_collected = collect_findings(&workspace).unwrap();
        assert!(baseline_collected.analysis_errors.is_empty());
        let baseline = judge::baseline::Baseline::new(
            &baseline_collected.findings,
            base_commit.clone(),
            baseline_collected.rule_revisions,
            judge::health_score::total_authored_loc(&workspace),
            judge::health_score::ScoreContext::from_profiles(&[]),
        );

        // Five more commits to the same file, all inside `churn-hotspot`'s
        // 14-day window — enough churn for the (heuristic) rule to fire,
        // without introducing any derived-fact (G1–G3) pattern.
        for revision in 1..=5 {
            std::fs::write(
                dir.join("src/lib.rs"),
                format!("pub fn hello() -> u32 {{ {revision} }}\n"),
            )
            .unwrap();
            git(&dir, &["add", "."]);
            git(&dir, &["commit", "-q", "-m", &format!("rev {revision}")]);
        }

        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let mut collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

        collected.findings.push(judge::finding::Finding::new(
            "synthetic-advisory:src/lib.rs".to_string(),
            "synthetic-advisory".to_string(),
            judge::finding::Severity::Info,
            judge::finding::Location {
                file: PathBuf::from("src/lib.rs"),
                line: judge::finding::OneBasedLine::FIRST,
                item_path: "hello".to_string(),
            },
            judge::finding::EvidenceClass::Heuristic,
            judge::finding::Origin::Code,
            None,
        ));
        let gating_rules: Vec<&judge::finding::RuleId> = collected
            .findings
            .iter()
            .filter(|finding| finding.is_gating())
            .map(|finding| &finding.rule)
            .collect();
        assert!(
            gating_rules.is_empty(),
            "fixture should only produce heuristic (advisory) findings, got gating: {gating_rules:?}"
        );

        // (c) Newly introduced heuristic findings stay visible in the delta
        // but never break the verdict.
        let delta = judge::baseline::diff(
            &collected.findings,
            &baseline,
            &std::collections::HashSet::new(),
            &collected.rule_revisions,
        );
        assert!(!delta.introduced.is_empty());
        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);

        // (a) The score takes no deductions from advisory findings, and the
        // report envelope records them as advisory.
        let total_loc = judge::health_score::total_authored_loc(&workspace);
        let score =
            match judge::health_score::compute(&collected.findings, total_loc, &workspace, &[]) {
                judge::health_score::ScoreOutcome::Available(score) => score,
                judge::health_score::ScoreOutcome::Unavailable(reason) => {
                    panic!("score unavailable: {reason}")
                }
            };
        assert_eq!(score.score, 100.0);
        assert_eq!(score.fail_count, 0);
        assert_eq!(score.warn_count, 0);

        let report = Report::new(collected.findings);
        assert_eq!(report.counts.gating, 0);
        assert!(report.counts.advisory > 0);
    }

    /// The default current-state pass does not derive historical hotspots,
    /// even when its workspace happens to be a Git repository.
    #[test]
    fn collect_findings_omits_historical_hotspots() {
        let _guard = lock_cwd();
        let dir = TempDir::new("hotspot-limit");
        write_fixture_crate(&dir);

        const FILE_COUNT: usize = 20;
        for branches in 1..=FILE_COUNT {
            let mut body = String::from("pub fn f(x: i32) -> i32 {\n    let mut total = x;\n");
            for i in 0..branches {
                body.push_str(&format!("    if x > {i} {{ total += {i}; }}\n"));
            }
            body.push_str("    total\n}\n");
            std::fs::write(dir.join(format!("src/hotspot_{branches:02}.rs")), body).unwrap();
        }

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let mut collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

        let hotspot_files: std::collections::HashSet<&Path> = collected
            .findings
            .iter()
            .filter(|finding| finding.rule == "hotspot")
            .map(|finding| finding.location.file.as_path())
            .collect();
        assert!(hotspot_files.is_empty());
    }

    #[test]
    fn refactoring_commands_keep_their_cli_contracts() {
        let map = Cli::try_parse_from(["judge", "map", "--format", "json", "--include-tests"])
            .expect("map arguments must parse");
        let Some(Command::Map(options)) = map.command else {
            panic!("expected map command");
        };
        assert!(matches!(options.format, OutputFormat::Json));
        assert!(options.include_tests);

        let impact = Cli::try_parse_from(["judge", "impact", "src/lib.rs", "--format", "json"])
            .expect("impact arguments must parse");
        let Some(Command::Impact(options)) = impact.command else {
            panic!("expected impact command");
        };
        assert_eq!(options.target, PathBuf::from("src/lib.rs"));
        assert!(matches!(options.format, OutputFormat::Json));

        let structure = Cli::try_parse_from(["judge", "structure", "--format", "json"])
            .expect("structure arguments must parse");
        assert!(matches!(structure.command, Some(Command::Structure(_))));

        let complexity = Cli::try_parse_from(["judge", "complexity", "--include-tests"])
            .expect("complexity arguments must parse");
        let Some(Command::Complexity(options)) = complexity.command else {
            panic!("expected complexity command");
        };
        assert!(options.include_tests);

        let refactor = Cli::try_parse_from(["judge", "refactor", "src/lib.rs", "--format", "json"])
            .expect("refactor arguments must parse");
        let Some(Command::Refactor(options)) = refactor.command else {
            panic!("expected refactor command");
        };
        assert_eq!(options.target, Some(PathBuf::from("src/lib.rs")));

        let combined = Cli::try_parse_from(["judge", "--progress", "progress.jsonl"])
            .expect("combined progress arguments must parse");
        assert_eq!(combined.progress, Some(PathBuf::from("progress.jsonl")));

        let output = Cli::try_parse_from([
            "judge",
            "dupes",
            "--format",
            "json",
            "--output",
            "report.json",
        ])
        .expect("JSON output arguments must parse");
        assert_eq!(output.output, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn json_artifacts_use_a_command_default_or_an_explicit_output_path() {
        let dir = TempDir::new("json-artifacts");
        write_fixture_crate(&dir);

        let mut default_out = Vec::new();
        let outcome = run_json_in_dir(
            &dir,
            dupes_cli(OutputFormat::Json, false, None),
            &mut default_out,
        )
        .expect("default JSON artifact must be written");
        assert_eq!(outcome, CommandOutcome::Clean);
        assert_eq!(
            String::from_utf8(default_out).unwrap(),
            "JSON written to .judge/dupes.json\n"
        );
        let default_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(".judge/dupes.json")).unwrap())
                .expect("default artifact JSON");
        let default_json_text = std::fs::read_to_string(dir.join(".judge/dupes.json")).unwrap();
        assert!(
            default_json_text.starts_with("{\n  \"header\": "),
            "artifact context must be the first root field"
        );
        assert!(default_json["findings"].is_array());
        assert_eq!(default_json["header"]["schema_version"], 1);
        assert_eq!(default_json["header"]["command"], "dupes");
        assert!(default_json["header"]["context"]["analysis_universe"].is_null());
        assert!(default_json["header"]["context"]["evidence_contract"].is_object());
        assert!(default_json["header"]["context"]["next_actions"].is_array());
        assert!(default_json["header"]["working_directory"].is_string());
        assert!(
            default_json["header"]["generated_at_utc"]
                .as_str()
                .is_some_and(|timestamp| timestamp.ends_with('Z'))
        );
        assert!(default_json["header"]["generated_at_unix_seconds"].is_u64());
        assert_eq!(
            default_json["header"]["assessment"]["kind"],
            "informational"
        );

        let custom_path = dir.join("reports/custom.json");
        let mut custom_cli = dupes_cli(OutputFormat::Json, false, None);
        custom_cli.output = Some(custom_path.clone());
        let mut custom_out = Vec::new();
        run_json_in_dir(&dir, custom_cli, &mut custom_out)
            .expect("explicit JSON artifact must be written");
        assert!(custom_path.is_file());

        let mut invalid_cli = dupes_cli(OutputFormat::Tty, false, None);
        invalid_cli.output = Some(PathBuf::from("report.json"));
        let error = run_with_artifact_output(invalid_cli, &mut Vec::new())
            .expect_err("--output without JSON must be rejected");
        assert!(matches!(error, CliError::Config(message) if message.contains("--format json")));
    }

    #[test]
    fn markdown_review_reports_use_a_default_or_explicit_judge_artifact_path() {
        let dir = TempDir::new("markdown-artifacts");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        std::fs::write(dir.join("src/lib.rs"), DUPE_FILE_CONTENT).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut default_out = Vec::new();
        let outcome = run_json_in_dir(&dir, all_cli_markdown(), &mut default_out)
            .expect("default Markdown artifact must be written");
        assert_eq!(outcome, CommandOutcome::Clean);
        assert_eq!(
            String::from_utf8(default_out).unwrap(),
            "Markdown written to .judge/judge.md\n"
        );
        let default_markdown = std::fs::read_to_string(dir.join(".judge/judge.md")).unwrap();
        assert!(
            default_markdown.starts_with("# Judge summary\n"),
            "unexpected artifact: {default_markdown}"
        );
        assert!(
            default_markdown.contains("## Evidence-backed findings"),
            "unexpected artifact: {default_markdown}"
        );
        assert!(
            default_markdown.contains("## Next steps"),
            "unexpected artifact: {default_markdown}"
        );

        let custom_path = dir.join("reports/review.md");
        let mut custom_cli = all_cli_markdown();
        custom_cli.output = Some(custom_path.clone());
        let mut custom_out = Vec::new();
        run_json_in_dir(&dir, custom_cli, &mut custom_out)
            .expect("explicit Markdown artifact must be written");
        assert!(custom_path.is_file());

        let mut invalid_cli = all_cli(false, None);
        invalid_cli.output = Some(PathBuf::from("report.md"));
        let error = run_with_artifact_output(invalid_cli, &mut Vec::new())
            .expect_err("--output on the bare tty run must be rejected");
        assert!(matches!(error, CliError::Config(message) if message.contains("--format json")));
    }

    #[test]
    fn root_help_states_the_post_refactoring_purpose() {
        use clap::CommandFactory;

        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("Deterministic post-refactoring analysis for Rust workspaces"));
        assert!(help.contains("--progress <PATH>"));
    }

    #[test]
    fn map_and_impact_json_keep_refactoring_facts_machine_readable() {
        let dir = TempDir::new("refactoring-command-contracts");
        write_fixture_crate(&dir);

        let mut map_out = Vec::new();
        let map = cli_with(Command::Map(MapOptions {
            format: OutputFormat::Json,
            include_tests: false,
        }));
        let outcome = run_in_dir(&dir, map, &mut map_out).expect("map must run");
        assert_eq!(outcome, CommandOutcome::Clean);
        let map: serde_json::Value = serde_json::from_slice(&map_out).expect("map JSON");
        assert_eq!(map["schema_version"], judge::refactor_map::SCHEMA_VERSION);
        assert_eq!(map["includes_tests"], false);
        assert_eq!(map["crates"][0]["name"], "fixture");
        assert_eq!(map["files"][0]["production"]["functions"], 1);
        assert_eq!(map["duplication"]["schema_version"], 1);
        assert_eq!(map["duplication"]["clone_families"], 0);

        let mut impact_out = Vec::new();
        let impact = cli_with(Command::Impact(ImpactOptions {
            target: PathBuf::from("src/lib.rs"),
            format: OutputFormat::Json,
        }));
        let outcome = run_in_dir(&dir, impact, &mut impact_out).expect("impact must run");
        assert_eq!(outcome, CommandOutcome::Clean);
        let impact: serde_json::Value = serde_json::from_slice(&impact_out).expect("impact JSON");
        assert_eq!(impact["schema_version"], judge::impact::SCHEMA_VERSION);
        assert_eq!(impact["target"], "src/lib.rs");
        assert_eq!(impact["crate_name"], "fixture");
        assert!(impact["direct_analysis"].as_array().is_some_and(|effects| {
            effects
                .iter()
                .any(|effect| effect["command"] == "cargo judge map")
        }));
    }

    #[test]
    fn map_include_tests_changes_ranking_scope_without_merging_metrics() {
        let dir = TempDir::new("map-include-tests-contract");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn production() {}\n\n#[cfg(test)]\nmod tests { fn helper(value: bool) { if value {} } }\n",
        )
        .unwrap();

        let mut out = Vec::new();
        let cli = cli_with(Command::Map(MapOptions {
            format: OutputFormat::Json,
            include_tests: true,
        }));
        run_in_dir(&dir, cli, &mut out).expect("map with tests must run");
        let map: serde_json::Value = serde_json::from_slice(&out).expect("map JSON");
        assert_eq!(map["includes_tests"], true);
        let file = map["files"]
            .as_array()
            .and_then(|files| files.iter().find(|file| file["file"] == "src/lib.rs"))
            .expect("lib.rs must appear in the map");
        assert_eq!(file["production"]["functions"], 1);
        assert_eq!(file["tests"]["functions"], 1);
        assert_eq!(file["complexity_rank"], 1);
    }

    #[test]
    fn combined_progress_is_separate_versioned_jsonl_and_subcommands_reject_it() {
        let dir = TempDir::new("combined-progress-contract");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let mut out = Vec::new();
        let mut cli = all_cli(false, None);
        cli.progress = Some(PathBuf::from("judge-progress.jsonl"));
        run_in_dir(&dir, cli, &mut out).expect("combined run with progress must succeed");

        let progress = std::fs::read_to_string(dir.join("judge-progress.jsonl"))
            .expect("progress file must be written");
        let records: Vec<serde_json::Value> = progress
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON record per line"))
            .collect();
        assert!(!records.is_empty());
        assert_eq!(records[0]["schema_version"], 1);
        assert_eq!(records[0]["event"], "phase_started");
        assert!(records.iter().all(|record| record["phase"].is_string()));

        let error = run(
            Cli {
                command: Some(Command::Init),
                baseline_args: baseline_args(OutputFormat::Tty, false, None),
                progress: Some(PathBuf::from("not-allowed.jsonl")),
                details: false,
                color: ColorChoice::Auto,
                output: None,
            },
            &mut Vec::new(),
        )
        .expect_err("subcommands must not share the combined progress channel");
        let CliError::Config(message) = error else {
            panic!("progress misuse must be a configuration error");
        };
        assert!(message.contains("bare `cargo judge` combined run"));
    }
}
