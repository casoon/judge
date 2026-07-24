use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use judge::AnalysisTier;
use judge::baseline::{TriVerdict, Verdict};
use judge::duplication::DupeMode;
use judge::finding::{Finding, Report};

const DEFAULT_BASELINE_HEALTH: &str = ".judge/baseline-health.json";
const DEFAULT_BASELINE_DUPES: &str = ".judge/baseline-dupes.json";
const DEFAULT_BASELINE_DEPS: &str = ".judge/baseline-deps.json";
const DEFAULT_BASELINE_BOUNDARIES: &str = ".judge/baseline-boundaries.json";
const DEFAULT_BASELINE_ALL: &str = ".judge/baseline.json";
const DEFAULT_BASELINE_DISTRIBUTION: &str = ".judge/baseline-distribution.json";
const DEFAULT_BASELINE_PROVENANCE: &str = ".judge/baseline-provenance.json";
const DEFAULT_BASELINE_COVERAGE: &str = ".judge/baseline-coverage.json";
const DEFAULT_BASELINE_API_SURFACE: &str = ".judge/baseline-api-surface.json";
const DEFAULT_BASELINE_MODULE_GRAPH: &str = ".judge/baseline-module-graph.json";
#[cfg(feature = "deep")]
const DEFAULT_BASELINE_DEAD_CODE: &str = ".judge/baseline-dead-code.json";

/// Top-N cap on git hotspot findings — shared by the dedicated `health`
/// hotspot print path and every combined findings list `git::hotspots`
/// feeds into. `git::hotspots` already sorts by score (complexity ×
/// recency-weighted changes) descending, so `.take(HOTSPOT_LIMIT)` keeps
/// the highest-score files, not an arbitrary prefix. Without this cap a
/// repo where every file crosses
/// both complexity and churn thresholds floods the findings list with one
/// hotspot per file instead of surfacing genuine outliers.
const HOTSPOT_LIMIT: usize = 15;

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
#[command(name = "cargo judge", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Output format (bare `cargo judge` only — a combined run across every
    /// detector; see todo.md §4 "Decision Surface", §8).
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the combined findings as the baseline (bare `cargo judge` only).
    #[arg(long)]
    save_baseline: bool,
    /// Compare the combined findings against a previously saved baseline
    /// (bare `cargo judge` only).
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Find duplicated token spans (clone families).
    Dupes(DupesOptions),
    /// Show the repository health summary, including slop signals.
    Health(HealthOptions),
    /// Show dependency-hygiene findings (misplaced dependency kinds,
    /// slopsquatting signals — see todo.md §14.2 G5).
    Deps(DepsOptions),
    /// Check crate-level architecture boundaries declared in `judge.toml`
    /// (see todo.md §3.H, §14.2 P1/P2). Opt-in: does nothing if no config is
    /// found.
    Boundaries(BoundariesOptions),
    /// Show ownership/bus-factor findings (see todo.md §3.E, §8).
    Distribution(DistributionOptions),
    /// Show heuristic author-class breakdowns (churn, duplication rate,
    /// suppression debt) from commit trailers/markers and optional
    /// configured labels (see todo.md §3.G G6). A distribution trend, never
    /// a per-commit or per-person judgement — see the printed caveat.
    /// Subcommand-only: not part of bare `cargo judge`.
    Provenance(ProvenanceOptions),
    /// Find `pub` items no other workspace crate references (see todo.md
    /// §3.A, §14.2 P1). Needs the Deep Tier — build with `--features deep`.
    DeadCode(DeadCodeOptions),
    /// Explains a specific item (see todo.md §7). Currently only
    /// `--why-live` is implemented.
    Explain(ExplainOptions),
    /// Combined pass/warn/fail PR verdict reflecting only findings
    /// introduced since `<ref>` (see todo.md §5 "audit --since"). Reuses the
    /// already-saved `.judge/baseline.json` (or `--baseline`) the same way
    /// `--baseline` works today — `<ref>` is only the boundary for "what
    /// changed since then", not a second analysis target. This is
    /// verdict-incremental, not analysis-incremental: cross-file analyzers
    /// like duplication still run over the full corpus, only the delta
    /// classification is scoped to touched files.
    Audit(AuditOptions),
    /// Initialize judge configuration in a workspace.
    Init,
    /// Show detected entry points, tiers, and cache status.
    Inspect,
    /// Imports an externally generated `cargo-llvm-cov` LCOV report and
    /// flags `untested-hotspot` functions: high complexity, high churn, and
    /// mostly uncovered lines (see todo.md §J). judge never measures
    /// coverage itself — only an already-generated snapshot is read.
    Coverage(CoverageOptions),
    /// Heuristic Rust design-pattern recommendations aggregated from
    /// projectwide evidence (see todo.md §16). Advisory only — never
    /// affects the verdict/exit code (todo.md §16.6).
    Patterns(PatternsOptions),
    /// Heuristic abstract-design-principle interpretations (cohesion,
    /// functional core/imperative shell, ...) aggregated from at least two
    /// independent evidence classes per finding (see todo.md §16.7).
    /// Advisory only — never affects the verdict/exit code, and a
    /// deliberately separate assertion class from `patterns`.
    Principles(PrinciplesOptions),
    /// Shows one pattern candidate's full evidence, preconditions,
    /// contraindications, and migration plan (see todo.md §16.5).
    ExplainPattern(ExplainPatternOptions),
    /// Shows only a pattern candidate's migration plan and affected call
    /// sites — deliberately no patch (see todo.md §16.5).
    FixPreview(FixPreviewOptions),
    /// Shows one rule's evidence class, preconditions, exclusions, allowed
    /// wording, and verdict effect from the static rule registry (see
    /// todo.md §17.5). A pure documentation lookup — never runs analysis and
    /// never produces exit code 1.
    ExplainRule(ExplainRuleOptions),
    /// Shows public-API-surface findings (`undocumented-public-item` and
    /// `semver-hazard` — see todo.md §I). Subcommand-only: not part of bare
    /// `cargo judge`, `audit`, or `health`, matching
    /// `Distribution`/`Provenance`/`DeadCode`'s own opt-in precedent. A
    /// build compiled with `--features deep` additionally checks
    /// `semver-hazard`'s `leaked_dependency_type` sub-case.
    ApiSurface(ApiSurfaceOptions),
    /// Shows `unlinked-file`/`orphan-module` findings from resolving each
    /// crate's real `mod` tree (see `judge::module_graph`). Subcommand-only:
    /// not part of bare `cargo judge`, `audit`, or `health`, matching
    /// `Distribution`/`Provenance`/`ApiSurface`'s own opt-in precedent.
    ModuleGraph(ModuleGraphOptions),
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
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// Analyze generated files too (see todo.md §3.A). Off by default —
    /// duplication in generated code isn't actionable the way it is in
    /// authored code.
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct HealthOptions {
    /// Include the numeric health score.
    #[arg(long)]
    score: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Show findings caused by another finding, not just root findings.
    #[arg(long)]
    show_cascades: bool,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// Analyze generated files too (see todo.md §3.A).
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct DepsOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
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
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
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
struct DistributionOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ProvenanceOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DeadCodeOptions {
    /// Count a `#[test]`-only reference as usage. Off by default: a
    /// `pub` item only reachable from tests is still dead in production
    /// (see todo.md §3.A "Reachability-Modi").
    #[arg(long)]
    include_tests: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CoverageOptions {
    /// Path to a `cargo-llvm-cov` LCOV report (see todo.md §J). judge never
    /// measures coverage itself, only imports an already-generated snapshot.
    #[arg(long, value_name = "PATH")]
    lcov: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
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
struct AuditOptions {
    /// Commit-ish boundary findings are classified against (see
    /// `judge::git::changed_files_since`). Requires a baseline already
    /// saved via `cargo judge --save-baseline`.
    #[arg(long)]
    since: String,
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Baseline file to compare against. Defaults to
    /// `.judge/baseline.json` (the file `cargo judge --save-baseline`
    /// writes).
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// Minimum touched authored LOC before a ratio gate is evaluated.
    /// Shared by both ratio gates; a gate additionally needs its own
    /// threshold flag (`--max-duplication-ratio` /
    /// `--max-suppression-ratio`) — without both, that gate is skipped
    /// and reported as not evaluated rather than assuming a threshold
    /// (see todo.md §6, §11 "nicht optimierbar": a fixed ratio is a
    /// policy decision judge deliberately doesn't invent a default for).
    #[arg(long, value_name = "N")]
    audit_min_sample: Option<u64>,
    /// Maximum allowed ratio of duplicated tokens (falling back to a
    /// raw finding count if no token count is available) to touched
    /// authored LOC before the duplication gate fails.
    #[arg(long, value_name = "RATIO")]
    max_duplication_ratio: Option<f64>,
    /// Maximum allowed ratio of code-introduced `suppression-debt`
    /// findings (one per `#[allow]`/`#[expect]` occurrence, see
    /// `judge::slop`) to touched authored LOC before the
    /// suppression-debt gate fails.
    #[arg(long, value_name = "RATIO")]
    max_suppression_ratio: Option<f64>,
}

#[derive(Debug, Args)]
struct PatternsOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
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
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// Analyze generated files too (see todo.md §3.A). Off by default —
    /// documentation completeness on generated code isn't actionable the way
    /// it is on authored code.
    #[arg(long)]
    include_generated: bool,
}

#[derive(Debug, Args)]
struct ModuleGraphOptions {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,
    /// Analyze generated files too (see todo.md §3.A). Off by default — an
    /// unlinked/orphaned generated file isn't actionable the way it is in
    /// authored code.
    #[arg(long)]
    include_generated: bool,
}

/// Output format shared by commands that emit findings (see todo.md §7).
/// Not every command supports every format: SARIF exists for the
/// report-producing commands, Markdown only for the audit/baseline delta
/// (the PR-comment use case) — anything else is rejected as a config error
/// instead of producing half-baked output.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable, reduced to root findings by default.
    Tty,
    /// Versioned JSON, always the full finding graph.
    Json,
    /// SARIF 2.1.0 (report-producing commands only — see `judge::sarif`).
    Sarif,
    /// Markdown delta table (`audit --since` and `--baseline` comparison
    /// only — see `judge::markdown`).
    Markdown,
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
    /// A baseline/audit verdict failed on introduced findings: exit 1.
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
    /// Analysis produced errors, so a baseline/audit verdict was withheld
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

impl From<judge::git::GitError> for CliError {
    fn from(err: judge::git::GitError) -> Self {
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
    let result = run(cli, &mut out).and_then(|outcome| {
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
        None => run_all(cli.format, cli.save_baseline, cli.baseline, out),
        Some(Command::Dupes(options)) => run_dupes(options, out),
        Some(Command::Health(options)) => run_health(options, out),
        Some(Command::Deps(options)) => run_deps(options, out),
        Some(Command::Boundaries(options)) => run_boundaries(options, out),
        Some(Command::Distribution(options)) => run_distribution(options, out),
        Some(Command::Provenance(options)) => run_provenance(options, out),
        Some(Command::DeadCode(options)) => run_dead_code(options, out),
        Some(Command::Explain(options)) => run_explain(options, out),
        Some(Command::Audit(options)) => run_audit(options, out),
        Some(Command::Init) => {
            writeln!(out, "judge init is not implemented yet")?;
            Ok(CommandOutcome::Clean)
        }
        Some(Command::Inspect) => run_inspect(out),
        Some(Command::Coverage(options)) => run_coverage(options, out),
        Some(Command::Patterns(options)) => run_patterns(options, out),
        Some(Command::Principles(options)) => run_principles(options, out),
        Some(Command::ExplainPattern(options)) => run_explain_pattern(options, out),
        Some(Command::FixPreview(options)) => run_fix_preview(options, out),
        Some(Command::ExplainRule(options)) => run_explain_rule(options, out),
        Some(Command::ApiSurface(options)) => run_api_surface(options, out),
        Some(Command::ModuleGraph(options)) => run_module_graph(options, out),
    }
}

/// Everything [`collect_findings`] produces — the analyzer set shared by
/// bare `cargo judge` ([`run_all`]) and `cargo judge audit --since`
/// ([`run_audit`]), so the latter's analyzer set stays mechanically
/// identical to the former's (see todo.md §5 "audit --since").
struct CollectedFindings {
    findings: Vec<Finding>,
    analysis_errors: Vec<String>,
    rule_revisions: std::collections::HashMap<String, u32>,
    boundary_rules_checked: usize,
    boundaries_config_path: PathBuf,
    /// How many findings an inline `// judge-ignore: <rule> — <reason>`
    /// comment dropped (see [`judge::suppression::apply_inline_suppressions`]).
    suppressed_inline: usize,
}

/// Runs every detector that doesn't need extra opt-in config (complexity +
/// hotspots, duplication, dependency hygiene, ownership) plus boundaries if
/// a `judge.toml` exists, and merges their findings. This is deliberately
/// *not* the numeric 0-100 health score from §4 — that needs crate-type
/// profiles and a weighting scheme that don't exist yet; merging findings
/// doesn't require either. Findings are returned unsorted; callers that show
/// them worst-first must sort explicitly (see [`judge::finding::sort_by_severity_desc`]).
fn collect_findings(workspace: &judge::ingest::Workspace) -> Result<CollectedFindings, CliError> {
    let mut findings = Vec::new();
    let mut analysis_errors = Vec::new();
    let mut rule_revisions = std::collections::HashMap::from([
        (
            judge::git::HOTSPOT_RULE.to_string(),
            judge::git::HOTSPOT_RULE_REVISION,
        ),
        (
            judge::git::SIZE_DISTRIBUTION_RULE.to_string(),
            judge::git::SIZE_DISTRIBUTION_RULE_REVISION,
        ),
        (
            judge::duplication::DUPLICATE_RULE.to_string(),
            judge::duplication::DUPLICATE_RULE_REVISION,
        ),
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
            judge::ownership::LOW_BUS_FACTOR_RULE.to_string(),
            judge::ownership::LOW_BUS_FACTOR_RULE_REVISION,
        ),
        (
            judge::slopsquat::NAME_COLLISION_RISK_RULE.to_string(),
            judge::slopsquat::NAME_COLLISION_RISK_RULE_REVISION,
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
            judge::slop_structural::LEGACY_FREEZE_RULE.to_string(),
            judge::slop_structural::LEGACY_FREEZE_RULE_REVISION,
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

    let complexity_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity = judge::complexity::analyze_workspace(complexity_source_files, false);
    analysis_errors.extend(complexity.errors.iter().map(ToString::to_string));
    match judge::git::hotspots(
        &workspace.root,
        &complexity.functions,
        judge::git::DEFAULT_WINDOW_DAYS,
    ) {
        Ok(hotspots) => findings.extend(
            hotspots
                .iter()
                .take(HOTSPOT_LIMIT)
                .map(judge::git::Hotspot::to_finding),
        ),
        Err(err) => analysis_errors.push(err.to_string()),
    }
    findings.extend(
        judge::git::size_distribution(workspace)
            .iter()
            .map(judge::git::SizeDistributionOutlier::to_finding),
    );
    findings.extend(judge::slop_structural::complexity_inflation(
        &complexity.functions,
    ));

    // G4 structural slop: `churn-hotspot` (2-week window) and `legacy-freeze`
    // (12-month window) each need their own [`judge::git::churn`] call at a
    // different window than [`judge::git::hotspots`]'s internal one above —
    // matching the precedent set by `churn-hotspot`'s own additional call.
    match judge::git::churn(&workspace.root, 14) {
        Ok(two_week_churn) => {
            findings.extend(judge::slop_structural::churn_hotspots(&two_week_churn));
        }
        Err(err) => analysis_errors.push(err.to_string()),
    }
    match judge::git::churn(&workspace.root, judge::git::DEFAULT_WINDOW_DAYS) {
        Ok(year_churn) => {
            let all_files: Vec<PathBuf> = workspace
                .crates
                .iter()
                .flat_map(|krate| krate.source_files.iter())
                .filter_map(|file| {
                    file.path
                        .strip_prefix(&workspace.root)
                        .ok()
                        .map(Path::to_path_buf)
                })
                .collect();
            findings.extend(judge::slop_structural::legacy_freeze(
                &year_churn,
                &all_files,
            ));
        }
        Err(err) => analysis_errors.push(err.to_string()),
    }

    let slop_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let rules_config = load_judge_toml(&workspace.root)?.rules;
    let slop = judge::slop::analyze_workspace(
        slop_source_files,
        false,
        rules_config.catch_all_error.allow_anyhow_at_boundary,
    );
    analysis_errors.extend(slop.errors.iter().map(ToString::to_string));
    findings.extend(slop.findings);

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
    analysis_errors.extend(dupes.errors.iter().map(ToString::to_string));
    findings.extend(dupes.to_findings());

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
    let security = judge::security::analyze_workspace(security_source_files, false);
    analysis_errors.extend(security.errors.iter().map(ToString::to_string));
    findings.extend(security.findings);

    let deps = judge::deps::analyze_workspace(workspace);
    analysis_errors.extend(deps.errors.iter().map(ToString::to_string));
    findings.extend(deps.findings);

    let dep_graph = judge::dep_graph::analyze_workspace(workspace);
    analysis_errors.extend(dep_graph.errors.iter().map(ToString::to_string));
    findings.extend(dep_graph.findings);

    // `name-collision-risk` is fully local (no network), so it runs in the
    // combined bare `cargo judge`/`audit` pass too. The other three G5
    // rules (`phantom-crate`/`phantom-version`/`fresh-low-reputation-dep`)
    // need real crates.io network access and are opt-in only via
    // `cargo judge deps --check-crates-io` (see `run_deps`).
    findings.extend(judge::slopsquat::analyze_name_collision(workspace));

    let ownership =
        judge::ownership::analyze_workspace(workspace, judge::git::DEFAULT_WINDOW_DAYS)?;
    analysis_errors.extend(ownership.errors.iter().map(ToString::to_string));
    findings.extend(ownership.findings);

    let boundaries_config_path = workspace.root.join("judge.toml");
    let mut boundary_rules_checked = 0;
    if boundaries_config_path.exists() {
        let config_text = std::fs::read_to_string(&boundaries_config_path).map_err(|err| {
            CliError::Config(format!("{}: {err}", boundaries_config_path.display()))
        })?;
        let config: judge::boundaries::BoundaryConfig =
            toml::from_str(&config_text).map_err(|err| {
                CliError::Config(format!(
                    "{}: failed to parse: {err}",
                    boundaries_config_path.display()
                ))
            })?;
        boundary_rules_checked = config.boundaries.len();
        let evaluated = judge::boundaries::evaluate(workspace, &config)?;
        findings.extend(evaluated.findings);
        rule_revisions.insert(
            judge::boundaries::BOUNDARY_VIOLATION_RULE.to_string(),
            judge::boundaries::BOUNDARY_VIOLATION_RULE_REVISION,
        );
        rule_revisions.insert(
            judge::boundaries::DEPENDENCY_CYCLE_RULE.to_string(),
            judge::boundaries::DEPENDENCY_CYCLE_RULE_REVISION,
        );

        match judge::boundaries::change_coupling_signals(
            workspace,
            &config,
            judge::git::DEFAULT_WINDOW_DAYS,
        ) {
            Ok(coupling_findings) => {
                findings.extend(coupling_findings);
                rule_revisions.insert(
                    judge::boundaries::CHANGE_COUPLING_SIGNAL_RULE.to_string(),
                    judge::boundaries::CHANGE_COUPLING_SIGNAL_RULE_REVISION,
                );
            }
            Err(err) => analysis_errors.push(err.to_string()),
        }
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

    // Inline `judge-ignore` suppression (todo.md §5): a generic, per-rule
    // post-filter applied after every detector above has merged its
    // findings in, so a suppressed finding never reaches baseline diff,
    // verdict, or score computation for either of this function's callers
    // (bare `cargo judge` and `audit`).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    Ok(CollectedFindings {
        findings,
        analysis_errors,
        rule_revisions,
        boundary_rules_checked,
        boundaries_config_path,
        suppressed_inline,
    })
}

/// Bare `cargo judge` (see todo.md §4 "Decision Surface", §8 "Vollanalyse"):
/// runs [`collect_findings`], sorts the result worst-first, then either
/// saves/compares a baseline or prints the merged report.
fn run_all(
    format: OutputFormat,
    save_baseline: bool,
    baseline: Option<PathBuf>,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;

    let mut collected = collect_findings(&workspace)?;
    judge::finding::sort_by_severity_desc(&mut collected.findings);

    if save_baseline || baseline.is_some() {
        return handle_baseline(
            &workspace.root,
            &collected.findings,
            &collected.analysis_errors,
            BaselineOptions {
                rule_revisions: collected.rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_ALL),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            // Bare `cargo judge` analyzes with the generated-code default
            // (excluded — see `collect_findings`), so the universe says so.
            let report = Report::with_errors(collected.findings, collected.analysis_errors)
                .with_universe(judge::finding::AnalysisUniverse::fast(&workspace, false))
                .with_suppressed_inline(collected.suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
                write_combined_finding(out, finding)?;
            }
            if !advisory.is_empty() {
                writeln!(out)?;
                writeln!(
                    out,
                    "advisory (heuristic) — no verdict effect: {}",
                    advisory.len()
                )?;
                for finding in &advisory {
                    write_combined_finding(out, finding)?;
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// One finding line of the bare `cargo judge` TTY report.
fn write_combined_finding(out: &mut dyn Write, finding: &Finding) -> std::io::Result<()> {
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

/// Saves `findings` as a new baseline, or compares them against one and
/// writes the delta (see todo.md §5, §14.2 P0#5). Only called when one of
/// the two applies (`--save-baseline`/`--baseline`); a failing compare
/// verdict becomes [`CommandOutcome::FindingsFound`].
struct BaselineOptions<'a> {
    rule_revisions: std::collections::HashMap<String, u32>,
    save: bool,
    compare_path: Option<&'a Path>,
    default_save_path: &'a Path,
    format: OutputFormat,
    /// Authored LOC analyzed this run (see `judge::health_score`) — stored on
    /// a saved baseline so a later run can recompute its historical score.
    total_loc: usize,
}

fn handle_baseline(
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
fn handle_baseline_with_trend(
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
                writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
        let commit = judge::git::head_commit(workspace_root)?;
        let config = load_judge_toml(workspace_root)?;
        let mut baseline = judge::baseline::Baseline::new(
            &findings,
            commit,
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
    let touched: std::collections::HashSet<PathBuf> =
        judge::git::changed_files_since(workspace_root, &baseline.commit)?;

    let delta = judge::baseline::diff(&findings, &baseline, &touched, &rule_revisions);
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
            writeln!(out, "{}", serde_json::to_string_pretty(&envelope).unwrap())?;
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

fn print_delta(
    out: &mut dyn Write,
    delta: &judge::baseline::Delta,
    verdict: Verdict,
) -> std::io::Result<()> {
    writeln!(
        out,
        "verdict: {}",
        match verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        }
    )?;
    writeln!(out, "unchanged: {}", delta.unchanged_count)?;
    writeln!(out, "resolved: {}", delta.resolved.len())?;
    for finding in &delta.resolved {
        writeln!(out, "  {}  {}", finding.rule, finding.file.display())?;
    }

    let (gating, advisory): (Vec<&Finding>, Vec<&Finding>) = delta
        .code_introduced
        .iter()
        .partition(|finding| finding.is_gating());
    writeln!(out, "code-introduced: {}", gating.len())?;
    for finding in &gating {
        writeln!(
            out,
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        )?;
    }

    writeln!(
        out,
        "code-introduced advisory (heuristic — no verdict effect): {}",
        advisory.len()
    )?;
    for finding in &advisory {
        writeln!(
            out,
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        )?;
    }

    writeln!(
        out,
        "rule-introduced (protected, does not fail): {}",
        delta.rule_introduced.len()
    )?;
    for finding in &delta.rule_introduced {
        writeln!(
            out,
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        )?;
    }
    Ok(())
}

/// `cargo judge audit --since <ref>` (see todo.md §5 "audit --since"): one
/// combined pass/warn/fail PR verdict reflecting only findings introduced
/// since `<ref>`. Reuses the already-persisted `.judge/baseline.json` the
/// same way `--baseline <path>` works for every other command — `<ref>` is
/// only the boundary [`judge::git::changed_files_since`] measures "what
/// changed" against, not a second analysis target this re-runs analysis on.
/// Exit codes: `2` for any config/parse/toolchain/ref-resolution/staleness
/// error, `1` for a `fail` verdict, `0` for `pass`/`warn` (report-only,
/// matching the GitHub Action's default report-only mode).
fn run_audit(options: AuditOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let AuditOptions {
        since,
        format,
        baseline: baseline_path,
        audit_min_sample,
        max_duplication_ratio,
        max_suppression_ratio,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let resolved_since = judge::git::resolve_commit(&workspace.root, &since)?;

    let path = baseline_path.unwrap_or_else(|| workspace.root.join(DEFAULT_BASELINE_ALL));
    if !path.exists() {
        return Err(CliError::Config(format!(
            "{} not found — run `cargo judge --save-baseline` first",
            path.display()
        )));
    }
    let mut baseline = judge::baseline::load(&path)?;
    baseline.relativize_paths(&workspace.root);

    if !judge::git::is_ancestor(&workspace.root, &baseline.commit, &resolved_since)? {
        return Err(CliError::Config(format!(
            "baseline commit {} is not an ancestor of `{since}` ({resolved_since}) — the baseline has diverged; re-run `cargo judge --save-baseline`",
            baseline.commit
        )));
    }

    let touched = judge::git::changed_files_since(&workspace.root, &resolved_since)?;

    let mut collected = collect_findings(&workspace)?;
    if !collected.analysis_errors.is_empty() {
        return Err(CliError::AnalysisIncomplete {
            context: "audit was not evaluated",
            errors: collected.analysis_errors,
        });
    }
    judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

    let delta = judge::baseline::diff(
        &collected.findings,
        &baseline,
        &touched,
        &collected.rule_revisions,
    );

    // Duplication ratio gate (see todo.md §6 "Kleine Stichproben"): opt-in,
    // since a fixed ratio threshold is a policy decision judge deliberately
    // doesn't invent a default for. Numerator prefers duplicated-token count
    // (carried through `Finding.evidence` by `CloneMember::to_finding`) over
    // a raw finding count, since it's a more faithful density measure; falls
    // back to counting findings if a finding's evidence doesn't carry it.
    let duplication_gate = match (audit_min_sample, max_duplication_ratio) {
        (Some(minimum_sample), Some(max_ratio)) => {
            let numerator: u64 = delta
                .code_introduced
                .iter()
                .filter(|finding| finding.rule == judge::duplication::DUPLICATE_RULE)
                .map(|finding| {
                    finding
                        .evidence
                        .as_ref()
                        .and_then(|evidence| evidence.get("token_count"))
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(1)
                })
                .sum();
            let sample_size = judge::health_score::authored_loc_in(&workspace, &touched) as u64;
            Some(judge::gate::ratio_gate(
                "duplication-ratio",
                numerator,
                sample_size,
                minimum_sample,
                max_ratio,
            ))
        }
        _ => None,
    };

    // Suppression-debt ratio gate (todo.md §0/§6): same opt-in shape as the
    // duplication gate — no invented default threshold, shared
    // `--audit-min-sample` minimum — and the same denominator, touched
    // authored LOC (the size of the change under judgement), so both gate
    // ratios are densities over one sample. Numerator: code-introduced
    // `suppression-debt` findings, one per `#[allow]`/`#[expect]` occurrence
    // (see `judge::slop`) — unlike duplication there is no token-count
    // evidence to prefer, the attribute itself is the unit of debt.
    let suppression_gate = match (audit_min_sample, max_suppression_ratio) {
        (Some(minimum_sample), Some(max_ratio)) => {
            let numerator = delta
                .code_introduced
                .iter()
                .filter(|finding| finding.rule == judge::slop::SUPPRESSION_DEBT_RULE)
                .count() as u64;
            let sample_size = judge::health_score::authored_loc_in(&workspace, &touched) as u64;
            Some(judge::gate::ratio_gate(
                "suppression-debt-ratio",
                numerator,
                sample_size,
                minimum_sample,
                max_ratio,
            ))
        }
        _ => None,
    };

    let verdict = combine_verdict(
        combine_verdict(
            delta.tri_verdict(),
            duplication_gate.as_ref().map(|gate| gate.verdict),
        ),
        suppression_gate.as_ref().map(|gate| gate.verdict),
    );

    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "verdict": verdict,
                "delta": delta,
                "gates": duplication_gate
                    .iter()
                    .chain(suppression_gate.iter())
                    .collect::<Vec<_>>(),
                "suppressed_inline": collected.suppressed_inline,
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&envelope).unwrap())?;
        }
        OutputFormat::Markdown => {
            let gates = [
                judge::markdown::GateSlot {
                    name: "duplication-ratio",
                    threshold_flag: "--max-duplication-ratio",
                    gate: duplication_gate.as_ref(),
                },
                judge::markdown::GateSlot {
                    name: "suppression-debt-ratio",
                    threshold_flag: "--max-suppression-ratio",
                    gate: suppression_gate.as_ref(),
                },
            ];
            write!(
                out,
                "{}",
                judge::markdown::render_audit(&delta, verdict, &gates)
            )?;
        }
        OutputFormat::Sarif => {
            return Err(unsupported_format("`audit`", format, "tty, json, markdown"));
        }
        OutputFormat::Tty => print_audit(
            out,
            &delta,
            verdict,
            duplication_gate.as_ref(),
            suppression_gate.as_ref(),
            collected.suppressed_inline,
        )?,
    }

    if verdict == TriVerdict::Fail {
        return Ok(CommandOutcome::FindingsFound);
    }
    Ok(CommandOutcome::Clean)
}

/// Combines the delta's tri-state verdict with a ratio gate's verdict (if
/// evaluated) into one final verdict: `Fail` wins over everything, `Warn`
/// wins over `Pass`. With several gates, [`run_audit`] folds this over each
/// in turn. A gate result of `NotEvaluatedSmallSample` is purely
/// informational and never forces `Warn`/`Fail` on its own (see todo.md §6).
fn combine_verdict(tri: TriVerdict, gate: Option<judge::gate::GateVerdict>) -> TriVerdict {
    let gate_failed = matches!(gate, Some(judge::gate::GateVerdict::Fail));
    if tri == TriVerdict::Fail || gate_failed {
        TriVerdict::Fail
    } else if tri == TriVerdict::Warn {
        TriVerdict::Warn
    } else {
        TriVerdict::Pass
    }
}

fn print_audit(
    out: &mut dyn Write,
    delta: &judge::baseline::Delta,
    verdict: TriVerdict,
    duplication_gate: Option<&judge::gate::RatioGate>,
    suppression_gate: Option<&judge::gate::RatioGate>,
    suppressed_inline: usize,
) -> std::io::Result<()> {
    writeln!(
        out,
        "verdict: {}",
        match verdict {
            TriVerdict::Pass => "pass",
            TriVerdict::Warn => "warn",
            TriVerdict::Fail => "fail",
        }
    )?;
    if suppressed_inline > 0 {
        writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
    }
    writeln!(out, "unchanged: {}", delta.unchanged_count)?;
    writeln!(out, "resolved: {}", delta.resolved.len())?;
    for finding in &delta.resolved {
        writeln!(out, "  {}  {}", finding.rule, finding.file.display())?;
    }

    let (gating, advisory): (Vec<&Finding>, Vec<&Finding>) = delta
        .code_introduced
        .iter()
        .partition(|finding| finding.is_gating());
    writeln!(out, "code-introduced: {}", gating.len())?;
    for finding in &gating {
        write_introduced_finding(out, finding)?;
    }

    writeln!(
        out,
        "code-introduced advisory (heuristic — no verdict effect): {}",
        advisory.len()
    )?;
    for finding in &advisory {
        write_introduced_finding(out, finding)?;
    }

    writeln!(
        out,
        "rule-introduced (protected, does not fail): {}",
        delta.rule_introduced.len()
    )?;
    for finding in &delta.rule_introduced {
        writeln!(
            out,
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        )?;
    }

    writeln!(out)?;
    print_gate(
        out,
        duplication_gate,
        "duplication-ratio",
        "--max-duplication-ratio",
    )?;
    print_gate(
        out,
        suppression_gate,
        "suppression-debt-ratio",
        "--max-suppression-ratio",
    )?;
    Ok(())
}

/// One gate line of the audit TTY report: either the evaluated gate
/// (including an explicit `not_evaluated_small_sample`, see todo.md §6) or
/// the hint naming the flags that would enable it — a skipped gate stays
/// visible either way, never a silent pass.
fn print_gate(
    out: &mut dyn Write,
    gate: Option<&judge::gate::RatioGate>,
    name: &str,
    threshold_flag: &str,
) -> std::io::Result<()> {
    match gate {
        Some(gate) => {
            let gate_verdict = match gate.verdict {
                judge::gate::GateVerdict::Pass => "pass",
                judge::gate::GateVerdict::Fail => "fail",
                judge::gate::GateVerdict::NotEvaluatedSmallSample => "not_evaluated_small_sample",
            };
            writeln!(
                out,
                "gate: {} — {}/{} ({gate_verdict}, min sample {}, max ratio {})",
                gate.name, gate.numerator, gate.sample_size, gate.minimum_sample, gate.max_ratio
            )
        }
        None => writeln!(
            out,
            "gate: {name} not evaluated (pass --audit-min-sample and {threshold_flag} to enable)"
        ),
    }
}

/// One `code-introduced` finding line of the audit TTY report.
fn write_introduced_finding(out: &mut dyn Write, finding: &Finding) -> std::io::Result<()> {
    writeln!(
        out,
        "  [{}] {}  {}:{}",
        severity_label(finding.severity),
        finding.rule,
        finding.location.file.display(),
        finding.location.line
    )
}

fn run_dupes(options: DupesOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let DupesOptions {
        mode,
        min_tokens,
        format,
        save_baseline,
        baseline,
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let report = judge::duplication::analyze_workspace(
        source_files,
        mode.into(),
        min_tokens,
        include_generated,
    );
    let analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();

    // Inline `judge-ignore` suppression (todo.md §5): dropped here, before
    // baseline diff/verdict or JSON/SARIF output — the TTY clone-family
    // preview below still lists every family member (see `run_dupes`'s own
    // scope note at its `Tty` arm), but nothing suppressed reaches a verdict.
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(report.to_findings(), &workspace.root)?;

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([(
            judge::duplication::DUPLICATE_RULE.to_string(),
            judge::duplication::DUPLICATE_RULE_REVISION,
        )]);
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_DUPES),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
            if !report.errors.is_empty() {
                writeln!(out, "files skipped (parse errors): {}", report.errors.len())?;
                for err in &report.errors {
                    writeln!(out, "  {err}")?;
                }
            }
            if report.excluded_generated > 0 {
                writeln!(
                    out,
                    "excluded (generated): {} (see --include-generated)",
                    report.excluded_generated
                )?;
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }

            for (index, family) in report
                .families
                .iter()
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

/// `cargo judge deps`: dependency-hygiene findings (`misplaced-dependency-kind`)
/// plus the G5 slopsquatting rules (see todo.md §14.2 G5). `name-collision-risk`
/// is fully local and always runs; `phantom-crate`/`phantom-version`/
/// `fresh-low-reputation-dep` need real crates.io network access and only run
/// when `--check-crates-io` is passed — judge makes no network calls by
/// default (see todo.md §1 "kein SaaS, keine Telemetrie, lokal deterministisch").
fn run_deps(options: DepsOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let DepsOptions {
        format,
        save_baseline,
        baseline,
        check_crates_io,
        check_rustc_lints,
        audit_json,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let report = judge::deps::analyze_workspace(&workspace);
    let mut analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
    let mut findings = report.findings;

    let mut rule_revisions = std::collections::HashMap::from([
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
    ]);
    findings.extend(judge::slopsquat::analyze_name_collision(&workspace));

    let dep_graph_report = judge::dep_graph::analyze_workspace(&workspace);
    analysis_errors.extend(dep_graph_report.errors.iter().map(ToString::to_string));
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
        analysis_errors.extend(rustc_lint_report.errors.iter().map(ToString::to_string));
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

    // Inline `judge-ignore` suppression (todo.md §5), applied after every
    // detector above has merged its findings in.
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    if save_baseline || baseline.is_some() {
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_DEPS),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "findings": findings,
                "feature_only_candidates": report.feature_only_candidates,
                "errors": analysis_errors,
                "suppressed_inline": suppressed_inline,
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&envelope).unwrap())?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`deps`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(out, "dependency findings: {}", findings.len())?;
            if !analysis_errors.is_empty() {
                writeln!(out, "errors: {}", analysis_errors.len())?;
                for err in &analysis_errors {
                    writeln!(out, "  {err}")?;
                }
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }

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

fn run_coverage(options: CoverageOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let CoverageOptions {
        lcov,
        format,
        save_baseline,
        baseline,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let coverage = judge::coverage::read_lcov(&lcov, &workspace.root)?;

    let complexity_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity_report = judge::complexity::analyze_workspace(complexity_source_files, false);
    let mut analysis_errors: Vec<String> = complexity_report
        .errors
        .iter()
        .map(ToString::to_string)
        .collect();
    for missing in &coverage.missing_files {
        analysis_errors.push(format!(
            "{}: coverage data references this file, but it no longer exists in the workspace",
            missing.display()
        ));
    }

    let churn = match judge::git::churn(
        &workspace.root,
        judge::coverage::UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS,
    ) {
        Ok(churn) => churn,
        Err(err) => {
            analysis_errors.push(err.to_string());
            std::collections::HashMap::new()
        }
    };

    let findings = judge::coverage::untested_hotspots(
        &complexity_report.functions,
        &churn,
        &coverage,
        &workspace.root,
    );

    let no_coverage_data_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let no_coverage_data = coverage.files_without_coverage_data(
        &workspace.root,
        no_coverage_data_source_files.map(|file| file.path.as_path()),
    );

    let test_ratios = judge::coverage::test_ratios(&workspace);

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([(
            judge::coverage::UNTESTED_HOTSPOT_RULE.to_string(),
            judge::coverage::UNTESTED_HOTSPOT_RULE_REVISION,
        )]);
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_COVERAGE),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors);
            let mut value = serde_json::to_value(&report).unwrap();
            value["files_without_coverage_data"] = serde_json::to_value(
                no_coverage_data
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
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
            )
            .unwrap();
            writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format("`coverage`", format, "tty, json, sarif"));
        }
        OutputFormat::Tty => {
            writeln!(out, "untested hotspots: {}", findings.len())?;
            if !analysis_errors.is_empty() {
                writeln!(out, "errors: {}", analysis_errors.len())?;
                for err in &analysis_errors {
                    writeln!(out, "  {err}")?;
                }
            }
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

fn run_boundaries(
    options: BoundariesOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let BoundariesOptions {
        config: config_path,
        format,
        save_baseline,
        baseline,
        graph,
    } = options;

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

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|err| CliError::Config(format!("{}: {err}", config_path.display())))?;
    let config: judge::boundaries::BoundaryConfig =
        toml::from_str(&config_text).map_err(|err| {
            CliError::Config(format!("{}: failed to parse: {err}", config_path.display()))
        })?;

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
            analysis_errors.extend(deep_report.errors.iter().map(ToString::to_string));
        }
        #[cfg(not(feature = "deep"))]
        {
            unreachable!(
                "AnalysisTier::Deep.is_available() is compile-time false without the deep feature"
            );
        }
    }

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    if save_baseline || baseline.is_some() {
        #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
        let mut rule_revisions = std::collections::HashMap::from([
            (
                judge::boundaries::BOUNDARY_VIOLATION_RULE.to_string(),
                judge::boundaries::BOUNDARY_VIOLATION_RULE_REVISION,
            ),
            (
                judge::boundaries::DEPENDENCY_CYCLE_RULE.to_string(),
                judge::boundaries::DEPENDENCY_CYCLE_RULE_REVISION,
            ),
            (
                judge::boundaries::MODULE_BOUNDARY_VIOLATION_RULE.to_string(),
                judge::boundaries::MODULE_BOUNDARY_VIOLATION_RULE_REVISION,
            ),
        ]);
        #[cfg(feature = "deep")]
        if judge::AnalysisTier::Deep.is_available() {
            rule_revisions.insert(
                judge::boundaries_deep::MODULE_BOUNDARY_VIOLATION_DEEP_RULE.to_string(),
                judge::boundaries_deep::MODULE_BOUNDARY_VIOLATION_DEEP_RULE_REVISION,
            );
        }
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_BOUNDARIES),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
            if !analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", analysis_errors.len())?;
                for error in &analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }
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

/// Ownership/bus-factor findings (see todo.md §3.E, §8). Window is the same
/// `judge::git::DEFAULT_WINDOW_DAYS` used by hotspots — not a separate CLI
/// flag, matching how hotspots hardcodes it today.
fn run_distribution(
    options: DistributionOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let DistributionOptions {
        format,
        save_baseline,
        baseline,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let report = judge::ownership::analyze_workspace(&workspace, judge::git::DEFAULT_WINDOW_DAYS)?;
    let analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
    let files_analyzed = report.files.len();
    let blame_errors = report.errors.len();

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(report.findings, &workspace.root)?;

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::ownership::LOW_BUS_FACTOR_RULE.to_string(),
                judge::ownership::LOW_BUS_FACTOR_RULE_REVISION,
            ),
            (
                judge::ownership::OWNERSHIP_FRAGMENTATION_RULE.to_string(),
                judge::ownership::OWNERSHIP_FRAGMENTATION_RULE_REVISION,
            ),
        ]);
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_DISTRIBUTION),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
        }
        OutputFormat::Sarif => {
            write_sarif(out, &workspace.root, findings, analysis_errors, None)?;
        }
        OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`distribution`",
                format,
                "tty, json, sarif",
            ));
        }
        OutputFormat::Tty => {
            writeln!(out, "files analyzed: {files_analyzed}")?;
            if blame_errors > 0 {
                writeln!(out, "files skipped (blame errors): {blame_errors}")?;
                for err in &analysis_errors {
                    writeln!(out, "  {err}")?;
                }
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }

            let (bus_factor, fragmentation): (Vec<&Finding>, Vec<&Finding>) = findings
                .iter()
                .partition(|finding| finding.rule == judge::ownership::LOW_BUS_FACTOR_RULE);

            writeln!(out)?;
            writeln!(out, "low-bus-factor findings: {}", bus_factor.len())?;
            for finding in &bus_factor {
                writeln!(
                    out,
                    "  [{}] {}  primary author: {}",
                    severity_label(finding.severity),
                    finding.location.file.display(),
                    finding.location.item_path
                )?;
            }

            writeln!(out)?;
            writeln!(
                out,
                "ownership-fragmentation findings (advisory, no verdict effect): {}",
                fragmentation.len()
            )?;
            for finding in &fragmentation {
                writeln!(
                    out,
                    "  [{}] {}  {}",
                    severity_label(finding.severity),
                    finding.location.file.display(),
                    finding.location.item_path
                )?;
            }
            if !fragmentation.is_empty() {
                writeln!(
                    out,
                    "  note: {}",
                    judge::ownership::OWNERSHIP_FRAGMENTATION_NOTE
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
fn run_module_graph(
    options: ModuleGraphOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ModuleGraphOptions {
        format,
        save_baseline,
        baseline,
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let report = judge::module_graph::analyze_workspace(&workspace, include_generated);
    let analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
    let excluded_generated = report.excluded_generated;

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(report.findings, &workspace.root)?;

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::module_graph::UNLINKED_FILE_RULE.to_string(),
                judge::module_graph::UNLINKED_FILE_RULE_REVISION,
            ),
            (
                judge::module_graph::ORPHAN_MODULE_RULE.to_string(),
                judge::module_graph::ORPHAN_MODULE_RULE_REVISION,
            ),
        ]);
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_MODULE_GRAPH),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_suppressed_inline(suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
            if !analysis_errors.is_empty() {
                writeln!(
                    out,
                    "files skipped (parse errors): {}",
                    analysis_errors.len()
                )?;
                for err in &analysis_errors {
                    writeln!(out, "  {err}")?;
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

/// Public-API-surface findings (`undocumented-public-item` and
/// `semver-hazard` — see todo.md §I). Subcommand-only: deliberately not
/// wired into `collect_findings`/`run_all`/`SLOP_RULES`, matching
/// `Distribution`/`Provenance`/`DeadCode`'s own opt-in precedent. In a build
/// compiled with `--features deep`, also runs `semver-hazard`'s
/// `leaked_dependency_type` sub-case (see `judge::api_surface_deep`) on top
/// of the two Fast-Tier sub-cases — unlike `dead-code`, this command still
/// produces useful output without the Deep Tier, so it degrades rather than
/// erroring when built without it.
fn run_api_surface(
    options: ApiSurfaceOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ApiSurfaceOptions {
        format,
        save_baseline,
        baseline,
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;
    let boundary_config = load_judge_toml(&workspace.root)?;
    judge::boundaries::validate_internal_crates(&workspace, &boundary_config)?;

    let report = judge::api_surface::analyze_workspace(workspace.crates.iter(), include_generated);
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut findings = report.findings;
    #[cfg_attr(not(feature = "deep"), allow(unused_mut))]
    let mut analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();

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
            deep_errors = deep_report.errors.iter().map(ToString::to_string).collect();
            analysis_errors.extend(deep_errors.iter().cloned());
        }
        #[cfg(not(feature = "deep"))]
        {
            unreachable!(
                "AnalysisTier::Deep.is_available() is compile-time false without the deep feature"
            );
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
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
            if !report.errors.is_empty() {
                writeln!(out, "files skipped (parse errors): {}", report.errors.len())?;
                for err in report.errors.iter().map(ToString::to_string) {
                    writeln!(out, "  {err}")?;
                }
            }
            if !deep_errors.is_empty() {
                writeln!(
                    out,
                    "leaked-dependency-type analysis errors: {}",
                    deep_errors.len()
                )?;
                for err in &deep_errors {
                    writeln!(out, "  {err}")?;
                }
            }
            if report.excluded_generated > 0 {
                writeln!(
                    out,
                    "excluded (generated): {} (see --include-generated)",
                    report.excluded_generated
                )?;
            }
            if suppressed_inline > 0 {
                writeln!(out, "suppressed (inline judge-ignore): {suppressed_inline}")?;
            }
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

/// Heuristic author-class breakdowns of churn, duplication, and suppression
/// debt (see todo.md §3.G G6). Subcommand-only: deliberately not wired into
/// `collect_findings`/`run_all`/`SLOP_RULES`, matching `Distribution`/
/// `DeadCode`'s own opt-in precedent. Reuses `git::DEFAULT_WINDOW_DAYS`, same
/// as `run_distribution`.
fn run_provenance(
    options: ProvenanceOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ProvenanceOptions {
        format,
        save_baseline,
        baseline,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let config = load_judge_toml(&workspace.root)?;

    let breakdown = judge::provenance::analyze_workspace(
        &workspace,
        judge::git::DEFAULT_WINDOW_DAYS,
        &config.provenance.labels,
    );
    let analysis_errors: Vec<String> = breakdown.errors.iter().map(ToString::to_string).collect();

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::provenance::PROVENANCE_CHURN_RULE.to_string(),
                judge::provenance::PROVENANCE_CHURN_RULE_REVISION,
            ),
            (
                judge::provenance::PROVENANCE_DUPLICATION_RATE_RULE.to_string(),
                judge::provenance::PROVENANCE_DUPLICATION_RATE_RULE_REVISION,
            ),
            (
                judge::provenance::PROVENANCE_SUPPRESSION_DEBT_RULE.to_string(),
                judge::provenance::PROVENANCE_SUPPRESSION_DEBT_RULE_REVISION,
            ),
            (
                judge::provenance::DEP_ADDED_BY_AGENT_RULE.to_string(),
                judge::provenance::DEP_ADDED_BY_AGENT_RULE_REVISION,
            ),
        ]);
        return handle_baseline(
            &workspace.root,
            &breakdown.findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_PROVENANCE),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(breakdown.findings, analysis_errors);
            let mut envelope = serde_json::to_value(&report).unwrap();
            envelope["caveat"] =
                serde_json::Value::String(judge::provenance::PROVENANCE_CAVEAT.to_string());
            writeln!(out, "{}", serde_json::to_string_pretty(&envelope).unwrap())?;
        }
        // No SARIF: provenance output is inseparable from its caveat (a
        // distribution trend, never a per-person judgement), and SARIF has
        // no slot that CI annotators would surface it in.
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format("`provenance`", format, "tty, json"));
        }
        OutputFormat::Tty => {
            writeln!(out, "{}", judge::provenance::PROVENANCE_CAVEAT)?;
            writeln!(out)?;
            if !analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", analysis_errors.len())?;
                for error in &analysis_errors {
                    writeln!(out, "  {error}")?;
                }
                writeln!(out)?;
            }
            writeln!(
                out,
                "{:<24} {:>8} {:>12} {:>12}",
                "class", "churn", "duplication", "suppression"
            )?;
            for summary in &breakdown.by_class {
                writeln!(
                    out,
                    "{:<24} {:>8} {:>12} {:>12}",
                    summary.class.key(),
                    summary.churn,
                    summary.duplication,
                    summary.suppression_debt
                )?;
            }

            // `dep-added-by-agent` findings are per-instance, not part of
            // the `by_class` aggregate table above (see `ClassSummary`'s
            // doc comment: it's a count model, this rule isn't a count).
            let dep_added_findings: Vec<&Finding> = breakdown
                .findings
                .iter()
                .filter(|finding| finding.rule == judge::provenance::DEP_ADDED_BY_AGENT_RULE)
                .collect();
            if !dep_added_findings.is_empty() {
                writeln!(out)?;
                writeln!(
                    out,
                    "dependencies added in an agent-classified commit, with no same-commit usage found:"
                )?;
                for finding in dep_added_findings {
                    let evidence = finding.evidence.as_ref().expect("always set");
                    writeln!(
                        out,
                        "  {} (commit {}, {})",
                        evidence["dependency"].as_str().unwrap_or("?"),
                        evidence["commit"].as_str().unwrap_or("?"),
                        evidence["author_class"].as_str().unwrap_or("?")
                    )?;
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Loads the workspace's `catch-all-error` findings (same slop pass and
/// `judge.toml` config `run_all`/`run_health` use) and runs the pattern
/// aggregator (`judge::pattern`) over them. Shared by `patterns`,
/// `explain-pattern`, and `fix-preview` — all three re-run the same
/// analysis and then match by id, mirroring how `cargo judge explain`
/// re-runs its own analysis rather than caching a prior run.
fn collect_pattern_candidates(
    workspace: &judge::ingest::Workspace,
) -> Result<Vec<judge::pattern::PatternCandidate>, CliError> {
    let slop_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let rules_config = load_judge_toml(&workspace.root)?.rules;
    let slop = judge::slop::analyze_workspace(
        slop_source_files,
        false,
        rules_config.catch_all_error.allow_anyhow_at_boundary,
    );
    Ok(judge::pattern::analyze_workspace(workspace, &slop.findings))
}

/// `cargo judge patterns` (todo.md §16.5, §16.6): heuristic Rust
/// design-pattern recommendations aggregated from projectwide evidence.
/// Always `CommandOutcome::Clean` — a pattern candidate never fails the
/// verdict on its own; a real analyzer/config failure still surfaces as a
/// `CliError` (exit 2), same as every other command.
fn run_patterns(options: PatternsOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let PatternsOptions { format } = options;
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`patterns`", format, "tty, json"));
    }
    let workspace = judge::ingest::load(None)?;
    let candidates = collect_pattern_candidates(&workspace)?;

    match format {
        OutputFormat::Json => {
            let json = serde_json::json!({ "candidates": candidates });
            writeln!(out, "{}", serde_json::to_string_pretty(&json).unwrap())?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before loading the workspace")
        }
        OutputFormat::Tty => {
            writeln!(
                out,
                "heuristic pattern suggestions — advisory, no verdict effect: {}",
                candidates.len()
            )?;
            for candidate in &candidates {
                writeln!(
                    out,
                    "  [{}] {}  crate: {}",
                    candidate.id, candidate.pattern, candidate.scope.krate
                )?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// `cargo judge principles` (todo.md §16.7): heuristic abstract-design-
/// principle interpretations aggregated from at least two independent
/// evidence classes per finding. Always `CommandOutcome::Clean` — a
/// principle heuristic never fails the verdict on its own; a real
/// analyzer/config failure still surfaces as a `CliError` (exit 2), same as
/// every other command. Deliberately a separate, standalone output block
/// from `patterns`, even though both are advisory: todo.md §16.7 treats
/// concrete pattern recommendations and abstract design-principle
/// interpretations as different assertion classes.
fn run_principles(
    options: PrinciplesOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let PrinciplesOptions { format } = options;
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`principles`", format, "tty, json"));
    }
    let workspace = judge::ingest::load(None)?;
    let boundary_config = load_judge_toml(&workspace.root)?;
    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity = judge::complexity::analyze_workspace(source_files, false);
    let heuristics =
        judge::principle::analyze_workspace(&workspace, &complexity, Some(&boundary_config))?;

    match format {
        OutputFormat::Json => {
            let json = serde_json::json!({ "heuristics": heuristics });
            writeln!(out, "{}", serde_json::to_string_pretty(&json).unwrap())?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before loading the workspace")
        }
        OutputFormat::Tty => {
            writeln!(
                out,
                "design principle heuristics — advisory, no verdict effect, always a judgment \
                 call: {}",
                heuristics.len()
            )?;
            for heuristic in &heuristics {
                writeln!(
                    out,
                    "  [{}] {}  crate: {}",
                    heuristic.id, heuristic.principle, heuristic.scope.krate
                )?;
                for module in &heuristic.scope.modules {
                    writeln!(out, "    - {module}")?;
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Finds the pattern candidate `id` refers to, re-running the same analysis
/// [`collect_pattern_candidates`] does. Unknown id ⇒ [`CliError::Analyzer`]
/// (exit 2) — a usage error, not a findings verdict (todo.md §16.6's
/// `explain-pattern` acceptance criterion).
fn find_pattern_candidate(
    workspace: &judge::ingest::Workspace,
    id: &str,
) -> Result<judge::pattern::PatternCandidate, CliError> {
    collect_pattern_candidates(workspace)?
        .into_iter()
        .find(|candidate| candidate.id.as_str() == id)
        .ok_or_else(|| CliError::Analyzer(format!("unknown pattern candidate id: {id}")))
}

/// One [`judge::pattern::Evidence`] entry, TTY-rendered under `label`.
fn print_evidence_tty(
    out: &mut dyn Write,
    label: &str,
    evidence: &judge::pattern::Evidence,
) -> std::io::Result<()> {
    writeln!(out, "  evidence ({label}): {}", evidence.description)?;
    for location in &evidence.locations {
        match &location.item_path {
            Some(item_path) => writeln!(out, "    - {}  {item_path}", location.file.display())?,
            None => writeln!(out, "    - {}", location.file.display())?,
        }
    }
    Ok(())
}

/// Full TTY rendering of one pattern candidate: scope, evidence,
/// preconditions, contraindications, migration plan, and related findings
/// (todo.md §16.6: `explain-pattern` always shows contraindications, and
/// generic text without concrete fundstellen is unacceptable).
fn print_pattern_candidate_tty(
    out: &mut dyn Write,
    candidate: &judge::pattern::PatternCandidate,
) -> std::io::Result<()> {
    writeln!(out, "pattern candidate: {}", candidate.id)?;
    writeln!(out, "  pattern: {}", candidate.pattern)?;
    writeln!(out, "  scope: crate `{}`", candidate.scope.krate)?;
    if !candidate.scope.modules.is_empty() {
        writeln!(out, "    modules:")?;
        for module in &candidate.scope.modules {
            writeln!(out, "      - {module}")?;
        }
    }
    print_evidence_tty(out, "primary", &candidate.evidence.primary)?;
    print_evidence_tty(out, "independent", &candidate.evidence.independent)?;
    for extra in &candidate.evidence.additional {
        print_evidence_tty(out, "additional", extra)?;
    }
    writeln!(out, "  preconditions:")?;
    for precondition in &candidate.preconditions {
        writeln!(out, "    - {}", precondition.description)?;
    }
    writeln!(out, "  contraindications:")?;
    for contraindication in &candidate.contraindications {
        writeln!(out, "    - {}", contraindication.description)?;
    }
    writeln!(out, "  migration plan (no patch — text only):")?;
    for step in &candidate.migration {
        writeln!(out, "    {}. {}", step.step, step.description)?;
        for path in &step.affected_paths {
            writeln!(out, "       - {}", path.display())?;
        }
    }
    writeln!(out, "  related findings:")?;
    for finding_id in &candidate.related_findings {
        writeln!(out, "    - {finding_id}")?;
    }
    Ok(())
}

/// `cargo judge explain-pattern <id>` (todo.md §16.5, §16.6): the full
/// evidence, preconditions, contraindications, and migration plan behind
/// one pattern candidate.
fn run_explain_pattern(
    options: ExplainPatternOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainPatternOptions { id, format } = options;
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`explain-pattern`", format, "tty, json"));
    }
    let workspace = judge::ingest::load(None)?;
    let candidate = find_pattern_candidate(&workspace, &id)?;

    match format {
        OutputFormat::Json => {
            writeln!(out, "{}", serde_json::to_string_pretty(&candidate).unwrap())?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before loading the workspace")
        }
        OutputFormat::Tty => print_pattern_candidate_tty(out, &candidate)?,
    }
    Ok(CommandOutcome::Clean)
}

/// `cargo judge fix-preview <id>` (todo.md §16.5): only the migration plan
/// and the affected call sites (`related_findings`) — deliberately no
/// patch is generated or applied.
fn run_fix_preview(
    options: FixPreviewOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let FixPreviewOptions { id, format } = options;
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`fix-preview`", format, "tty, json"));
    }
    let workspace = judge::ingest::load(None)?;
    let candidate = find_pattern_candidate(&workspace, &id)?;

    match format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "id": candidate.id,
                "pattern": candidate.pattern,
                "migration": candidate.migration,
                "related_findings": candidate.related_findings,
                "patch": serde_json::Value::Null,
                "note": "migration plan only — no patch is generated (see todo.md §16.5)",
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&json).unwrap())?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before loading the workspace")
        }
        OutputFormat::Tty => {
            writeln!(
                out,
                "fix preview for {} ({}) — no patch is generated, migration plan only:",
                candidate.id, candidate.pattern
            )?;
            for step in &candidate.migration {
                writeln!(out, "  {}. {}", step.step, step.description)?;
                for path in &step.affected_paths {
                    writeln!(out, "     - {}", path.display())?;
                }
            }
            writeln!(out)?;
            writeln!(
                out,
                "related findings (call sites): {}",
                candidate.related_findings.len()
            )?;
            for finding_id in &candidate.related_findings {
                writeln!(out, "  {finding_id}")?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// `cargo judge explain-rule <id>` (todo.md §17.5): a rule's fixed
/// documentation from [`judge::rule_registry`] — evidence class,
/// preconditions, exclusions, allowed wording, and verdict effect. A pure
/// static lookup: unlike `explain-pattern`/`fix-preview` it never loads the
/// workspace or runs analysis, so it never fails for an analyzer reason and
/// never produces `CommandOutcome::FindingsFound`.
fn run_explain_rule(
    options: ExplainRuleOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainRuleOptions { id, format } = options;
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format("`explain-rule`", format, "tty, json"));
    }
    let entry = judge::rule_registry::lookup(&id)
        .ok_or_else(|| CliError::Analyzer(format!("unknown rule id: {id}")))?;

    match format {
        OutputFormat::Json => {
            let example = entry.example.map(|example| {
                serde_json::json!({
                    "before": example.before,
                    "why_it_matters": example.why_it_matters,
                })
            });
            let json = serde_json::json!({
                "id": entry.id,
                "evidence_class": entry.evidence_class,
                "verdict_effect": entry.verdict_effect.label(),
                "preconditions": entry.preconditions,
                "exclusions": entry.exclusions,
                "allowed_wording": entry.allowed_wording,
                "example": example,
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&json).unwrap())?;
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before looking up the rule")
        }
        OutputFormat::Tty => {
            let evidence_class = serde_json::to_value(entry.evidence_class).unwrap();
            writeln!(out, "rule: {}", entry.id)?;
            writeln!(
                out,
                "  evidence class: {}",
                evidence_class.as_str().unwrap_or_default()
            )?;
            writeln!(out, "  verdict effect: {}", entry.verdict_effect.label())?;
            writeln!(out, "  preconditions: {}", entry.preconditions)?;
            writeln!(out, "  exclusions: {}", entry.exclusions)?;
            writeln!(out, "  allowed wording: {}", entry.allowed_wording)?;
            if let Some(example) = entry.example {
                writeln!(out, "  example:")?;
                for line in example.before.lines() {
                    writeln!(out, "    {line}")?;
                }
                writeln!(out, "  why it matters: {}", example.why_it_matters)?;
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// Compact TTY rendering of the analysis universe (see
/// [`judge::finding::AnalysisUniverse`]) — the JSON report carries the same
/// data structured; TTY gets the human-readable echo so the Deep Tier's
/// output always states what it makes a claim about (todo.md §0, §17.5).
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

/// `unused-pub-workspace` via the Deep Tier (see todo.md §3.A, §14.2 P1).
/// Only available in a build compiled with `--features deep` — a Fast Tier
/// build returns a clear error instead of silently doing nothing.
#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
fn run_dead_code(
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
        format,
        save_baseline,
        baseline,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let dead_code_report = judge::dead_code::analyze_workspace(&workspace, include_tests)?;

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

    // `connectivity-drop`/`duplicative-reinvention` load their own
    // second `DeepContext` here rather than sharing `dead_code`'s —
    // `dead_code::analyze_workspace` doesn't expose the `RootDatabase`
    // it loads internally, and threading one through would widen that
    // module's public API for a performance-only concern. Accepted,
    // documented extra cost (a second full workspace load; see
    // `judge::deep`'s own cost note), not a correctness one.
    let structural_report =
        judge::slop_structural_deep::analyze_workspace(&workspace, &dupes, include_tests)?;

    let mut findings = dead_code_report.findings;
    findings.extend(structural_report.findings);

    let mut analysis_errors: Vec<String> = dead_code_report
        .errors
        .iter()
        .map(ToString::to_string)
        .collect();
    analysis_errors.extend(dupes.errors.iter().map(ToString::to_string));
    analysis_errors.extend(structural_report.errors.iter().map(ToString::to_string));

    // Inline `judge-ignore` suppression (todo.md §5).
    let (findings, suppressed_inline) =
        judge::suppression::apply_inline_suppressions(findings, &workspace.root)?;

    if save_baseline || baseline.is_some() {
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
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE.to_string(),
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE_REVISION,
            ),
            (
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE.to_string(),
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE_REVISION,
            ),
        ]);
        return handle_baseline(
            &workspace.root,
            &findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_DEAD_CODE),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
            out,
        );
    }

    // §0 demands the Deep Tier fully describes what its claims are
    // about — JSON carries the structured universe, TTY a compact echo.
    let universe = judge::finding::AnalysisUniverse::deep(&workspace, include_tests);
    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors)
                .with_universe(universe)
                .with_suppressed_inline(suppressed_inline);
            writeln!(out, "{}", serde_json::to_string_pretty(&report).unwrap())?;
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
                judge::slop_structural_deep::CONNECTIVITY_DROP_RULE,
                judge::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE,
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
                    if let Some(limitations) =
                        finding.evidence.as_ref().and_then(|e| e.get("limitations"))
                    {
                        writeln!(out, "    limitations: {limitations}")?;
                    }
                }
            }
        }
    }
    Ok(CommandOutcome::Clean)
}

/// `judge explain <item-path> --why-live` (see todo.md §7, §14.2 P1).
/// Only `--why-live` is implemented; other explain modes (e.g. explaining a
/// finding id) don't exist yet.
#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
fn run_explain(options: ExplainOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
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
            writeln!(out, "{}", serde_json::to_string_pretty(&json).unwrap())?;
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

fn run_health(options: HealthOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let HealthOptions {
        score: show_score,
        format,
        show_cascades,
        save_baseline,
        baseline,
        include_generated,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let report = judge::complexity::analyze_workspace(source_files, include_generated);
    let mut analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
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
    analysis_errors.extend(slop.errors.iter().map(ToString::to_string));
    findings.extend(slop.findings);

    // G4 structural slop (see todo.md §3.G): same whole-workspace scope as
    // the analyzers above, so it's wired in here too rather than left
    // `health`-only-missing.
    findings.extend(judge::slop_structural::complexity_inflation(&functions));
    match judge::git::churn(&workspace.root, 14) {
        Ok(two_week_churn) => {
            findings.extend(judge::slop_structural::churn_hotspots(&two_week_churn));
        }
        Err(err) => analysis_errors.push(err.to_string()),
    }
    match judge::git::churn(&workspace.root, judge::git::DEFAULT_WINDOW_DAYS) {
        Ok(year_churn) => {
            let all_files: Vec<PathBuf> = workspace
                .crates
                .iter()
                .flat_map(|krate| krate.source_files.iter())
                .filter_map(|file| {
                    file.path
                        .strip_prefix(&workspace.root)
                        .ok()
                        .map(Path::to_path_buf)
                })
                .collect();
            findings.extend(judge::slop_structural::legacy_freeze(
                &year_churn,
                &all_files,
            ));
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
    analysis_errors.extend(security.errors.iter().map(ToString::to_string));
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
                judge::slop_structural::LEGACY_FREEZE_RULE.to_string(),
                judge::slop_structural::LEGACY_FREEZE_RULE_REVISION,
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
            writeln!(out, "{}", serde_json::to_string_pretty(&value).unwrap())?;
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

/// Hotspot = complexity × recency-weighted change frequency (see todo.md
/// §3.E). Files with no recorded churn (or no git history at all) are left
/// out rather than shown as zero-risk. Reduced to root findings unless
/// `show_cascades` is set (see todo.md §14.2 P0#2) — currently a no-op,
/// since nothing yet populates `caused_by` for hotspot findings, but the
/// mechanism is exercised here so future detectors that do can rely on it.
fn print_hotspots(
    out: &mut dyn Write,
    hotspots: &[judge::git::Hotspot],
    findings: &[judge::finding::Finding],
    show_cascades: bool,
) -> std::io::Result<()> {
    if hotspots.is_empty() {
        writeln!(
            out,
            "hotspots: none in the last {} days (no git history, or no file crosses both complexity and churn)",
            judge::git::DEFAULT_WINDOW_DAYS
        )?;
        return Ok(());
    }

    let shown_ids: std::collections::HashSet<&str> = if show_cascades {
        findings.iter().map(|f| f.id.as_str()).collect()
    } else {
        judge::finding::root_findings(findings)
            .into_iter()
            .map(|f| f.id.as_str())
            .collect()
    };

    writeln!(
        out,
        "hotspots (complexity × recency-weighted changes in the last {} days — advisory, no verdict effect):",
        judge::git::DEFAULT_WINDOW_DAYS
    )?;
    for hotspot in hotspots.iter().take(HOTSPOT_LIMIT) {
        let id = format!("{}:{}", judge::git::HOTSPOT_RULE, hotspot.file.display());
        if !shown_ids.contains(id.as_str()) {
            continue;
        }
        writeln!(
            out,
            "  {:>6}  {} × {:.1} weighted ({} raw) changes  {}",
            hotspot.score(),
            hotspot.complexity,
            hotspot.recency_weight,
            hotspot.changes,
            hotspot.file.display()
        )?;
    }
    Ok(())
}

/// AI-slop signals (see todo.md §G "AI-Slop-Signale", §12 "Entscheidungen":
/// "Der Slop-Block ist Teil von `health`, kein eigener Sub-Command"). Grouped
/// by rule with a per-rule count, then listed root-findings-first unless
/// `show_cascades` is set (see todo.md §14.2 P0#2), same convention as
/// `print_hotspots`.
const SLOP_RULES: [&str; 23] = [
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
    judge::slop_structural::LEGACY_FREEZE_RULE,
    judge::slop_structural::ABSTRACTION_INFLATION_RULE,
    judge::slop_structural::FRAGILE_SUBSTRING_CLASSIFICATION_RULE,
    judge::security::UNSAFE_SURFACE_RULE,
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

fn run_inspect(out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;

    writeln!(out, "workspace root: {}", workspace.root.display())?;
    writeln!(out, "crates: {}", workspace.crates.len())?;
    for krate in &workspace.crates {
        writeln!(out)?;
        writeln!(out, "  {} {}", krate.name, krate.version)?;
        writeln!(out, "    manifest: {}", krate.manifest_path.display())?;
        writeln!(out, "    source files: {}", krate.source_files.len())?;
        if krate.entry_points.is_empty() {
            writeln!(out, "    entry points: none")?;
        } else {
            writeln!(out, "    entry points:")?;
            for entry in &krate.entry_points {
                writeln!(
                    out,
                    "      [{}] {} — {}",
                    entry.kind.label(),
                    entry.name,
                    entry.path.display()
                )?;
            }
        }
    }

    writeln!(out)?;
    writeln!(out, "tiers:")?;
    writeln!(out, "  fast: available")?;
    writeln!(
        out,
        "  deep: {}",
        if AnalysisTier::Deep.is_available() {
            "available"
        } else {
            "not available (build with --features deep)"
        }
    )?;
    writeln!(out)?;
    writeln!(out, "cache: not implemented yet")?;
    Ok(CommandOutcome::Clean)
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
    /// `legacy-freeze`/etc. finding happens to land on or next to that line.
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
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
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
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
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

    fn cli_with(command: Command) -> Cli {
        Cli {
            command: Some(command),
            format: OutputFormat::Tty,
            save_baseline: false,
            baseline: None,
        }
    }

    fn dupes_cli(format: OutputFormat, save_baseline: bool, baseline: Option<PathBuf>) -> Cli {
        cli_with(Command::Dupes(DupesOptions {
            mode: DupeModeArg::Mild,
            min_tokens: judge::duplication::DEFAULT_MIN_TOKENS,
            format,
            save_baseline,
            baseline,
            include_generated: false,
        }))
    }

    fn api_surface_cli(
        format: OutputFormat,
        save_baseline: bool,
        baseline: Option<PathBuf>,
    ) -> Cli {
        cli_with(Command::ApiSurface(ApiSurfaceOptions {
            format,
            save_baseline,
            baseline,
            include_generated: false,
        }))
    }

    /// Bare `cargo judge` (no subcommand — `Cli::command` is `None`).
    fn all_cli(save_baseline: bool, baseline: Option<PathBuf>) -> Cli {
        Cli {
            command: None,
            format: OutputFormat::Tty,
            save_baseline,
            baseline,
        }
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

    /// GitHub issue #7: with more than [`DUPE_FAMILY_TTY_LIMIT`] clone
    /// families, the TTY view must say so explicitly instead of silently
    /// stopping after the cap — the header count alone isn't enough,
    /// grepping the (apparently complete) family list for a touched file
    /// and finding nothing must not read as "no duplication".
    #[test]
    fn run_dupes_tty_reports_a_trailer_when_families_exceed_the_cap() {
        let dir = TempDir::new("dupes-truncation-trailer");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // 16 distinct clone families (one over the 15-family TTY cap) — each
        // pair has unique literals so Mild mode doesn't merge them into one
        // family, and each body is well over `DEFAULT_MIN_TOKENS` (20).
        let mut source = String::new();
        for i in 0..16 {
            for suffix in ["a", "b"] {
                source.push_str(&format!(
                    "pub fn dup_{i}_{suffix}() -> i32 {{ let v0 = {i}; let v1 = {i}; \
                     let v2 = {i}; let v3 = {i}; let v4 = {i}; let v5 = {i}; \
                     let v6 = {i}; v0 + v1 + v2 + v3 + v4 + v5 + v6 }}\n"
                ));
            }
        }
        std::fs::write(dir.join("src/lib.rs"), source).unwrap();

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
                format: OutputFormat::Tty,
                save_baseline: false,
                baseline: None,
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
                format: OutputFormat::Tty,
                save_baseline: false,
                baseline: None,
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
                format: OutputFormat::Tty,
                save_baseline: false,
                baseline: None,
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
                format: OutputFormat::Markdown,
                show_cascades: false,
                save_baseline: false,
                baseline: None,
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
                id: "catch-all-error".to_string(),
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

    /// `audit --format markdown` renders the PR-comment delta table,
    /// including the not-evaluated gate lines (see `judge::markdown`).
    #[test]
    fn audit_format_markdown_renders_the_delta_table() {
        let _guard = lock_cwd();
        let (dir, base_commit) = suppression_audit_fixture("audit-markdown");

        let mut out = Vec::new();
        let outcome = run_in_dir_locked(
            &dir,
            cli_with(Command::Audit(AuditOptions {
                since: base_commit,
                format: OutputFormat::Markdown,
                baseline: None,
                audit_min_sample: None,
                max_duplication_ratio: None,
                max_suppression_ratio: None,
            })),
            &mut out,
        )
        .expect("audit markdown must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("**verdict: pass**"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains(
                "- gate `suppression-debt-ratio`: not evaluated (pass --audit-min-sample and --max-suppression-ratio to enable)"
            ),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("### code-introduced: 3"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("| rule | severity | location | item |"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("| suppression-debt | info | src/suppressed.rs:1 |"),
            "unexpected output: {text}"
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

    /// Exercises the wiring `run_audit` performs — `collect_findings`,
    /// `judge::git::changed_files_since`, `judge::baseline::diff`, the
    /// duplication ratio gate, and `combine_verdict` — without invoking the
    /// CLI's exit-code translation directly (see todo.md §5 "audit
    /// --since"). A new file's duplication finding must classify as
    /// `code_introduced`.
    #[test]
    fn audit_wiring_classifies_a_new_files_duplication_as_code_introduced() {
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
        let head_commit = commit_sha(&dir, "HEAD");

        assert!(judge::git::is_ancestor(&dir, &base_commit, &head_commit).unwrap());

        let touched = judge::git::changed_files_since(&dir, &base_commit).unwrap();
        assert!(touched.contains(&PathBuf::from("src/dupe.rs")));

        // Source file lists are captured at `ingest::load` time, not
        // re-scanned dynamically — reload to see the file added above.
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let mut collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

        let delta = judge::baseline::diff(
            &collected.findings,
            &baseline,
            &touched,
            &collected.rule_revisions,
        );

        let dupe_introduced: Vec<_> = delta
            .code_introduced
            .iter()
            .filter(|finding| finding.rule == judge::duplication::DUPLICATE_RULE)
            .collect();
        assert_eq!(dupe_introduced.len(), 2);
        for finding in &dupe_introduced {
            assert_eq!(finding.location.file, PathBuf::from("src/dupe.rs"));
            assert_eq!(finding.severity, judge::finding::Severity::Warn);
        }
        assert_eq!(delta.tri_verdict(), TriVerdict::Warn);

        // A high `--audit-min-sample` withholds judgement even though the
        // duplicated-token ratio would fail any reasonable threshold —
        // `NotEvaluatedSmallSample` must not force `Warn`/`Fail` on its own.
        let numerator: u64 = dupe_introduced
            .iter()
            .map(|finding| {
                finding
                    .evidence
                    .as_ref()
                    .and_then(|evidence| evidence.get("token_count"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1)
            })
            .sum();
        assert!(numerator > 0);
        let sample_size = judge::health_score::authored_loc_in(&workspace, &touched) as u64;

        let small_sample_gate =
            judge::gate::ratio_gate("duplication-ratio", numerator, sample_size, 1_000_000, 0.0);
        assert_eq!(
            small_sample_gate.verdict,
            judge::gate::GateVerdict::NotEvaluatedSmallSample
        );
        assert_eq!(
            combine_verdict(delta.tri_verdict(), Some(small_sample_gate.verdict)),
            TriVerdict::Warn
        );

        // A low minimum sample lets the same (bad) ratio actually fail the
        // gate, which then escalates the combined verdict past `Warn`.
        let evaluated_gate =
            judge::gate::ratio_gate("duplication-ratio", numerator, sample_size, 1, 0.0);
        assert_eq!(evaluated_gate.verdict, judge::gate::GateVerdict::Fail);
        assert_eq!(
            combine_verdict(delta.tri_verdict(), Some(evaluated_gate.verdict)),
            TriVerdict::Fail
        );
    }

    /// An untouched file's finding that only appears because a rule
    /// revision changed must classify as `rule_introduced`, not
    /// `code_introduced` — and must not fail the verdict (see todo.md §5
    /// "Regelversions-Schutz"). `judge::baseline::diff` itself already has
    /// dedicated coverage for this; this test only confirms `run_audit`'s
    /// own verdict combination (`tri_verdict` + `combine_verdict`) respects
    /// it once wired together.
    #[test]
    fn audit_wiring_does_not_fail_on_a_rule_introduced_finding() {
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
        let head_commit = commit_sha(&dir, "HEAD");

        let touched = judge::git::changed_files_since(&dir, &base_commit).unwrap();
        assert!(!touched.contains(&PathBuf::from("src/lib.rs")));
        assert!(judge::git::is_ancestor(&dir, &base_commit, &head_commit).unwrap());

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

        let delta = judge::baseline::diff(&[pre_existing], &baseline, &touched, &bumped_revisions);

        assert!(delta.code_introduced.is_empty());
        assert_eq!(delta.rule_introduced.len(), 1);
        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);
        assert_eq!(combine_verdict(delta.tri_verdict(), None), TriVerdict::Pass);
    }

    /// A new file whose only findings are `suppression-debt` (Info severity,
    /// derived fact): visible as gating code-introduced findings, but never
    /// moving the tri-verdict past `pass` — so the suppression-debt ratio
    /// gate alone decides whether the audit fails.
    const SUPPRESSED_FILE_CONTENT: &str = r#"#[allow(dead_code)]
pub fn quiet_one() -> u32 {
    1
}

#[allow(unused_variables)]
pub fn quiet_two() -> u32 {
    2
}

#[allow(unreachable_code)]
pub fn quiet_three() -> u32 {
    3
}
"#;

    /// Builds a git fixture whose saved `.judge/baseline.json` predates a
    /// commit adding [`SUPPRESSED_FILE_CONTENT`], so `audit --since <base>`
    /// classifies its three `suppression-debt` findings as code-introduced.
    /// Returns the fixture dir and the baseline commit. The caller must hold
    /// the [`CWD_LOCK`] guard — the baseline pass spawns `cargo metadata`.
    fn suppression_audit_fixture(name: &str) -> (TempDir, String) {
        let dir = TempDir::new(name);
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base_commit = commit_sha(&dir, "HEAD");

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        let baseline = judge::baseline::Baseline::new(
            &collected.findings,
            base_commit.clone(),
            collected.rule_revisions,
            judge::health_score::total_authored_loc(&workspace),
            judge::health_score::ScoreContext::from_profiles(&[]),
        );
        judge::baseline::save(&dir.join(DEFAULT_BASELINE_ALL), &baseline).unwrap();

        std::fs::write(dir.join("src/suppressed.rs"), SUPPRESSED_FILE_CONTENT).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add suppressions"]);
        (dir, base_commit)
    }

    fn audit_cli(
        since: &str,
        audit_min_sample: Option<u64>,
        max_suppression_ratio: Option<f64>,
    ) -> Cli {
        cli_with(Command::Audit(AuditOptions {
            since: since.to_string(),
            format: OutputFormat::Tty,
            baseline: None,
            audit_min_sample,
            max_duplication_ratio: None,
            max_suppression_ratio,
        }))
    }

    /// Without gate flags both ratio gates are skipped but stay visible as
    /// not evaluated, and the verdict is untouched — Info-severity
    /// `suppression-debt` findings alone never fail an audit.
    #[test]
    fn audit_without_gate_flags_reports_the_suppression_gate_as_not_evaluated() {
        let _guard = lock_cwd();
        let (dir, base_commit) = suppression_audit_fixture("audit-suppression-no-flags");

        let mut out = Vec::new();
        let outcome = run_in_dir_locked(&dir, audit_cli(&base_commit, None, None), &mut out)
            .expect("audit without gate flags must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: pass"), "unexpected output: {text}");
        assert!(
            text.contains("code-introduced: 3"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("gate: suppression-debt-ratio not evaluated"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("gate: duplication-ratio not evaluated"),
            "unexpected output: {text}"
        );
    }

    /// Over the threshold with a sufficient sample, the suppression gate
    /// fails the audit (`CommandOutcome::FindingsFound`, exit 1), even
    /// though the findings themselves are Info-severity.
    #[test]
    fn audit_fails_when_the_suppression_ratio_exceeds_the_threshold() {
        let _guard = lock_cwd();
        let (dir, base_commit) = suppression_audit_fixture("audit-suppression-over-threshold");

        let mut out = Vec::new();
        let outcome =
            run_in_dir_locked(&dir, audit_cli(&base_commit, Some(1), Some(0.0)), &mut out)
                .expect("a failing gate is an outcome, not an error");
        assert_eq!(outcome, CommandOutcome::FindingsFound);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: fail"), "unexpected output: {text}");
        assert!(
            text.contains("gate: suppression-debt-ratio — 3/"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("(fail, min sample 1, max ratio 0)"),
            "unexpected output: {text}"
        );
    }

    /// Below `--audit-min-sample` the gate withholds judgement — the report
    /// must say `not_evaluated_small_sample` explicitly (todo.md §6), and
    /// the verdict stays untouched instead of silently passing or failing.
    #[test]
    fn audit_reports_a_small_sample_suppression_gate_explicitly() {
        let _guard = lock_cwd();
        let (dir, base_commit) = suppression_audit_fixture("audit-suppression-small-sample");

        let mut out = Vec::new();
        let outcome = run_in_dir_locked(
            &dir,
            audit_cli(&base_commit, Some(1_000_000), Some(0.0)),
            &mut out,
        )
        .expect("a small-sample gate must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: pass"), "unexpected output: {text}");
        assert!(
            text.contains("not_evaluated_small_sample"),
            "unexpected output: {text}"
        );
    }

    /// Below the threshold with a sufficient sample the gate passes — three
    /// suppressions over the new file's LOC stay under a ratio of 1.
    #[test]
    fn audit_passes_when_the_suppression_ratio_is_within_the_threshold() {
        let _guard = lock_cwd();
        let (dir, base_commit) = suppression_audit_fixture("audit-suppression-under-threshold");

        let mut out = Vec::new();
        let outcome =
            run_in_dir_locked(&dir, audit_cli(&base_commit, Some(1), Some(1.0)), &mut out)
                .expect("a passing gate must not error");
        assert_eq!(outcome, CommandOutcome::Clean);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("verdict: pass"), "unexpected output: {text}");
        assert!(
            text.contains("gate: suppression-debt-ratio — 3/"),
            "unexpected output: {text}"
        );
        assert!(
            text.contains("(pass, min sample 1, max ratio 1)"),
            "unexpected output: {text}"
        );
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

        assert!(
            collected
                .findings
                .iter()
                .any(|finding| finding.rule == judge::slop_structural::CHURN_HOTSPOT_RULE),
            "fixture should provoke a churn-hotspot finding"
        );
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
        let touched = judge::git::changed_files_since(&dir, &base_commit).unwrap();
        let delta = judge::baseline::diff(
            &collected.findings,
            &baseline,
            &touched,
            &collected.rule_revisions,
        );
        assert!(!delta.code_introduced.is_empty());
        assert_eq!(delta.verdict(), Verdict::Pass);
        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);
        assert_eq!(combine_verdict(delta.tri_verdict(), None), TriVerdict::Pass);

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

    /// A repo where every file crosses both the complexity and churn
    /// thresholds must not flood the combined findings list with one
    /// `hotspot` finding per file (see `HOTSPOT_LIMIT`'s doc comment: 317/317
    /// files flagged in a real repo, no "outlier" signal left). `collect_findings`
    /// caps at `HOTSPOT_LIMIT`, and — since `git::hotspots` already sorts by
    /// score (complexity × recency-weighted changes) descending — keeps the
    /// *highest*-score files, not an arbitrary prefix.
    #[test]
    fn collect_findings_caps_hotspots_at_the_shared_limit_keeping_the_highest_scores() {
        let _guard = lock_cwd();
        let dir = TempDir::new("hotspot-limit");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);

        // 20 more files, each with a distinct, strictly increasing cyclomatic
        // complexity (one more `if` branch than the last) — together with
        // `write_fixture_crate`'s `src/lib.rs` (complexity 1, the unambiguous
        // minimum), that's 21 hotspot candidates once all are committed
        // together (one commit = one churn count each), well past
        // `HOTSPOT_LIMIT`, with a strict score ranking so "top N by score"
        // has one unambiguous answer.
        const FILE_COUNT: usize = 20;
        for branches in 1..=FILE_COUNT {
            let mut body = String::from("pub fn f(x: i32) -> i32 {\n    let mut total = x;\n");
            for i in 0..branches {
                body.push_str(&format!("    if x > {i} {{ total += {i}; }}\n"));
            }
            body.push_str("    total\n}\n");
            std::fs::write(dir.join(format!("src/hotspot_{branches:02}.rs")), body).unwrap();
        }
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let mut collected = collect_findings(&workspace).unwrap();
        assert!(collected.analysis_errors.is_empty());
        judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

        let hotspot_files: std::collections::HashSet<&Path> = collected
            .findings
            .iter()
            .filter(|finding| finding.rule == judge::git::HOTSPOT_RULE)
            .map(|finding| finding.location.file.as_path())
            .collect();
        assert_eq!(
            hotspot_files.len(),
            HOTSPOT_LIMIT,
            "expected exactly {HOTSPOT_LIMIT} hotspot findings out of 21 candidates, got {}",
            hotspot_files.len()
        );

        // Bottom 6 by score (`src/lib.rs` at complexity 1, then branches
        // 1..=5) must be dropped; top 15 (branches 6..=20) must survive.
        assert!(!hotspot_files.contains(Path::new("src/lib.rs")));
        for branches in 1..=5 {
            let file = PathBuf::from(format!("src/hotspot_{branches:02}.rs"));
            assert!(
                !hotspot_files.contains(file.as_path()),
                "expected the lower-complexity {file:?} to be dropped by the cap"
            );
        }
        for branches in 6..=FILE_COUNT {
            let file = PathBuf::from(format!("src/hotspot_{branches:02}.rs"));
            assert!(
                hotspot_files.contains(file.as_path()),
                "expected the higher-complexity {file:?} to survive the cap"
            );
        }
    }

    #[test]
    fn combine_verdict_prefers_fail_over_everything() {
        assert_eq!(
            combine_verdict(TriVerdict::Warn, Some(judge::gate::GateVerdict::Fail)),
            TriVerdict::Fail
        );
        assert_eq!(
            combine_verdict(TriVerdict::Fail, Some(judge::gate::GateVerdict::Pass)),
            TriVerdict::Fail
        );
    }

    #[test]
    fn combine_verdict_small_sample_gate_is_purely_informational() {
        assert_eq!(
            combine_verdict(
                TriVerdict::Pass,
                Some(judge::gate::GateVerdict::NotEvaluatedSmallSample)
            ),
            TriVerdict::Pass
        );
        assert_eq!(
            combine_verdict(
                TriVerdict::Warn,
                Some(judge::gate::GateVerdict::NotEvaluatedSmallSample)
            ),
            TriVerdict::Warn
        );
    }

    #[test]
    fn combine_verdict_without_a_gate_is_just_the_tri_verdict() {
        assert_eq!(combine_verdict(TriVerdict::Pass, None), TriVerdict::Pass);
        assert_eq!(combine_verdict(TriVerdict::Warn, None), TriVerdict::Warn);
        assert_eq!(combine_verdict(TriVerdict::Fail, None), TriVerdict::Fail);
    }
}
