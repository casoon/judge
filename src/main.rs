use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
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
#[cfg(feature = "deep")]
const DEFAULT_BASELINE_DEAD_CODE: &str = ".judge/baseline-dead-code.json";

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
    Dupes {
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
    },
    /// Show the repository health summary, including slop signals.
    Health {
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
    },
    /// Show dependency-hygiene findings (misplaced dependency kinds,
    /// slopsquatting signals — see todo.md §14.2 G5).
    Deps {
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
    },
    /// Check crate-level architecture boundaries declared in `judge.toml`
    /// (see todo.md §3.H, §14.2 P1/P2). Opt-in: does nothing if no config is
    /// found.
    Boundaries {
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
    },
    /// Show ownership/bus-factor findings (see todo.md §3.E, §8).
    Distribution {
        /// Output format.
        #[arg(long, value_enum, default_value = "tty")]
        format: OutputFormat,
        /// Save the current findings as the baseline (see todo.md §5).
        #[arg(long)]
        save_baseline: bool,
        /// Compare findings against a previously saved baseline.
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,
    },
    /// Find `pub` items no other workspace crate references (see todo.md
    /// §3.A, §14.2 P1). Needs the Deep Tier — build with `--features deep`.
    DeadCode {
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
    },
    /// Explains a specific item (see todo.md §7). Currently only
    /// `--why-live` is implemented.
    Explain {
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
    },
    /// Combined pass/warn/fail PR verdict reflecting only findings
    /// introduced since `<ref>` (see todo.md §5 "audit --since"). Reuses the
    /// already-saved `.judge/baseline.json` (or `--baseline`) the same way
    /// `--baseline` works today — `<ref>` is only the boundary for "what
    /// changed since then", not a second analysis target. This is
    /// verdict-incremental, not analysis-incremental: cross-file analyzers
    /// like duplication still run over the full corpus, only the delta
    /// classification is scoped to touched files.
    Audit {
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
        /// Minimum touched authored LOC before the duplication ratio gate is
        /// evaluated. Must be given together with `--max-duplication-ratio`
        /// — without both, the gate is skipped and reported as not
        /// evaluated rather than assuming a threshold (see todo.md §6, §11
        /// "nicht optimierbar": a fixed ratio is a policy decision judge
        /// deliberately doesn't invent a default for).
        #[arg(long, value_name = "N")]
        audit_min_sample: Option<u64>,
        /// Maximum allowed ratio of duplicated tokens (falling back to a
        /// raw finding count if no token count is available) to touched
        /// authored LOC before the duplication gate fails.
        #[arg(long, value_name = "RATIO")]
        max_duplication_ratio: Option<f64>,
    },
    /// Initialize judge configuration in a workspace.
    Init,
    /// Show detected entry points, tiers, and cache status.
    Inspect,
}

/// Output format shared by commands that emit findings (see todo.md §7).
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable, reduced to root findings by default.
    Tty,
    /// Versioned JSON, always the full finding graph.
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DupeModeArg {
    Strict,
    Mild,
}

impl From<DupeModeArg> for DupeMode {
    fn from(value: DupeModeArg) -> Self {
        match value {
            DupeModeArg::Strict => Self::Strict,
            DupeModeArg::Mild => Self::Mild,
        }
    }
}

fn main() {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "judge") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    match cli.command {
        None => run_all(cli.format, cli.save_baseline, cli.baseline),
        Some(Command::Dupes {
            mode,
            min_tokens,
            format,
            save_baseline,
            baseline,
            include_generated,
        }) => run_dupes(
            mode,
            min_tokens,
            format,
            save_baseline,
            baseline,
            include_generated,
        ),
        Some(Command::Health {
            score,
            format,
            show_cascades,
            save_baseline,
            baseline,
            include_generated,
        }) => run_health(
            score,
            format,
            show_cascades,
            save_baseline,
            baseline,
            include_generated,
        ),
        Some(Command::Deps {
            format,
            save_baseline,
            baseline,
            check_crates_io,
        }) => run_deps(format, save_baseline, baseline, check_crates_io),
        Some(Command::Boundaries {
            config,
            format,
            save_baseline,
            baseline,
        }) => run_boundaries(config, format, save_baseline, baseline),
        Some(Command::Distribution {
            format,
            save_baseline,
            baseline,
        }) => run_distribution(format, save_baseline, baseline),
        Some(Command::DeadCode {
            include_tests,
            format,
            save_baseline,
            baseline,
        }) => run_dead_code(include_tests, format, save_baseline, baseline),
        Some(Command::Explain {
            item_path,
            why_live,
            include_tests,
            format,
        }) => run_explain(item_path, why_live, include_tests, format),
        Some(Command::Audit {
            since,
            format,
            baseline,
            audit_min_sample,
            max_duplication_ratio,
        }) => run_audit(
            since,
            format,
            baseline,
            audit_min_sample,
            max_duplication_ratio,
        ),
        Some(Command::Init) => println!("judge init is not implemented yet"),
        Some(Command::Inspect) => run_inspect(),
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
}

/// Runs every detector that doesn't need extra opt-in config (complexity +
/// hotspots, duplication, dependency hygiene, ownership) plus boundaries if
/// a `judge.toml` exists, and merges their findings. This is deliberately
/// *not* the numeric 0-100 health score from §4 — that needs crate-type
/// profiles and a weighting scheme that don't exist yet; merging findings
/// doesn't require either. Findings are returned unsorted; callers that show
/// them worst-first must sort explicitly (see [`judge::finding::sort_by_severity_desc`]).
fn collect_findings(workspace: &judge::ingest::Workspace) -> CollectedFindings {
    let mut findings = Vec::new();
    let mut analysis_errors = Vec::new();
    let mut rule_revisions = std::collections::HashMap::from([
        (
            judge::git::HOTSPOT_RULE.to_string(),
            judge::git::HOTSPOT_RULE_REVISION,
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
        Ok(hotspots) => findings.extend(hotspots.iter().map(judge::git::Hotspot::to_finding)),
        Err(err) => analysis_errors.push(err.to_string()),
    }
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
    let slop = judge::slop::analyze_workspace(slop_source_files, false);
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

    let deps = judge::deps::analyze_workspace(workspace);
    analysis_errors.extend(deps.errors.iter().map(ToString::to_string));
    findings.extend(deps.findings);

    // `name-collision-risk` is fully local (no network), so it runs in the
    // combined bare `cargo judge`/`audit` pass too. The other three G5
    // rules (`phantom-crate`/`phantom-version`/`fresh-low-reputation-dep`)
    // need real crates.io network access and are opt-in only via
    // `cargo judge deps --check-crates-io` (see `run_deps`).
    findings.extend(judge::slopsquat::analyze_name_collision(workspace));

    match judge::ownership::analyze_workspace(workspace, judge::git::DEFAULT_WINDOW_DAYS) {
        Ok(ownership) => {
            analysis_errors.extend(ownership.errors.iter().map(ToString::to_string));
            findings.extend(ownership.findings);
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    }

    let boundaries_config_path = workspace.root.join("judge.toml");
    let mut boundary_rules_checked = 0;
    if boundaries_config_path.exists() {
        let config_text = match std::fs::read_to_string(&boundaries_config_path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("error: {}: {err}", boundaries_config_path.display());
                std::process::exit(2);
            }
        };
        let config: judge::boundaries::BoundaryConfig = match toml::from_str(&config_text) {
            Ok(config) => config,
            Err(err) => {
                eprintln!(
                    "error: {}: failed to parse: {err}",
                    boundaries_config_path.display()
                );
                std::process::exit(2);
            }
        };
        boundary_rules_checked = config.boundaries.len();
        match judge::boundaries::evaluate(workspace, &config) {
            Ok(evaluated) => {
                findings.extend(evaluated.findings);
                rule_revisions.insert(
                    judge::boundaries::BOUNDARY_VIOLATION_RULE.to_string(),
                    judge::boundaries::BOUNDARY_VIOLATION_RULE_REVISION,
                );
                rule_revisions.insert(
                    judge::boundaries::DEPENDENCY_CYCLE_RULE.to_string(),
                    judge::boundaries::DEPENDENCY_CYCLE_RULE_REVISION,
                );
            }
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        }
    }

    CollectedFindings {
        findings,
        analysis_errors,
        rule_revisions,
        boundary_rules_checked,
        boundaries_config_path,
    }
}

/// Bare `cargo judge` (see todo.md §4 "Decision Surface", §8 "Vollanalyse"):
/// runs [`collect_findings`], sorts the result worst-first, then either
/// saves/compares a baseline or prints the merged report.
fn run_all(format: OutputFormat, save_baseline: bool, baseline: Option<PathBuf>) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let mut collected = collect_findings(&workspace);
    judge::finding::sort_by_severity_desc(&mut collected.findings);

    if save_baseline || baseline.is_some() {
        handle_baseline(
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
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(collected.findings, collected.analysis_errors);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Tty => {
            println!("findings: {} (worst first)", collected.findings.len());
            if !collected.analysis_errors.is_empty() {
                println!("analysis errors: {}", collected.analysis_errors.len());
                for error in &collected.analysis_errors {
                    println!("  {error}");
                }
            }
            println!(
                "boundary rules checked: {}{}",
                collected.boundary_rules_checked,
                if collected.boundaries_config_path.exists() {
                    ""
                } else {
                    " (no judge.toml — boundaries skipped)"
                }
            );
            println!();
            for finding in &collected.findings {
                let severity = match finding.severity {
                    judge::finding::Severity::Fail => "fail",
                    judge::finding::Severity::Warn => "warn",
                    judge::finding::Severity::Info => "info",
                };
                println!(
                    "  [{severity}] {:<28} {}:{}  {}",
                    finding.rule,
                    finding.location.file.display(),
                    finding.location.line,
                    finding.location.item_path
                );
            }
        }
    }
}

/// Saves `findings` as a new baseline, or compares them against one and
/// prints the delta (see todo.md §5, §14.2 P0#5). Returns `true` if baseline
/// handling ran and the caller's normal report should be skipped.
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
) -> bool {
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
        match format {
            OutputFormat::Json => {
                let report = Report::with_errors(findings, analysis_errors.to_vec());
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
            OutputFormat::Tty => {
                eprintln!("error: analysis incomplete; baseline was not evaluated");
                for error in analysis_errors {
                    eprintln!("  {error}");
                }
            }
        }
        std::process::exit(2);
    }

    if save {
        let commit = match judge::git::head_commit(workspace_root) {
            Ok(commit) => commit,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };
        let baseline = judge::baseline::Baseline::new(&findings, commit, rule_revisions, total_loc);
        let save_path = workspace_root.join(default_save_path);
        match judge::baseline::save(&save_path, &baseline) {
            Ok(()) => println!(
                "baseline saved: {} ({} findings)",
                save_path.display(),
                findings.len()
            ),
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        }
        return true;
    }

    let Some(path) = compare_path else {
        return false;
    };
    let mut baseline = match judge::baseline::load(path) {
        Ok(baseline) => baseline,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };
    baseline.relativize_paths(workspace_root);
    let touched: std::collections::HashSet<PathBuf> =
        match judge::git::changed_files_since(workspace_root, &baseline.commit) {
            Ok(relative) => relative,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };

    let delta = judge::baseline::diff(&findings, &baseline, &touched, &rule_revisions);
    let verdict = delta.verdict();
    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "verdict": verdict,
                "delta": delta,
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        }
        OutputFormat::Tty => print_delta(&delta, verdict),
    }

    if verdict == Verdict::Fail {
        std::process::exit(1);
    }
    true
}

fn print_delta(delta: &judge::baseline::Delta, verdict: Verdict) {
    println!(
        "verdict: {}",
        match verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        }
    );
    println!("unchanged: {}", delta.unchanged_count);
    println!("resolved: {}", delta.resolved.len());
    for finding in &delta.resolved {
        println!("  {}  {}", finding.rule, finding.file.display());
    }

    println!("code-introduced: {}", delta.code_introduced.len());
    for finding in &delta.code_introduced {
        println!(
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        );
    }

    println!(
        "rule-introduced (protected, does not fail): {}",
        delta.rule_introduced.len()
    );
    for finding in &delta.rule_introduced {
        println!(
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        );
    }
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
fn run_audit(
    since: String,
    format: OutputFormat,
    baseline_path: Option<PathBuf>,
    audit_min_sample: Option<u64>,
    max_duplication_ratio: Option<f64>,
) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let resolved_since = match judge::git::resolve_commit(&workspace.root, &since) {
        Ok(commit) => commit,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let path = baseline_path.unwrap_or_else(|| workspace.root.join(DEFAULT_BASELINE_ALL));
    if !path.exists() {
        eprintln!(
            "error: {} not found — run `cargo judge --save-baseline` first",
            path.display()
        );
        std::process::exit(2);
    }
    let mut baseline = match judge::baseline::load(&path) {
        Ok(baseline) => baseline,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };
    baseline.relativize_paths(&workspace.root);

    match judge::git::is_ancestor(&workspace.root, &baseline.commit, &resolved_since) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "error: baseline commit {} is not an ancestor of `{since}` ({resolved_since}) — the baseline has diverged; re-run `cargo judge --save-baseline`",
                baseline.commit
            );
            std::process::exit(2);
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    }

    let touched = match judge::git::changed_files_since(&workspace.root, &resolved_since) {
        Ok(touched) => touched,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let mut collected = collect_findings(&workspace);
    if !collected.analysis_errors.is_empty() {
        eprintln!("error: analysis incomplete; audit was not evaluated");
        for error in &collected.analysis_errors {
            eprintln!("  {error}");
        }
        std::process::exit(2);
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
    let gate = match (audit_min_sample, max_duplication_ratio) {
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

    let verdict = combine_verdict(delta.tri_verdict(), gate.as_ref().map(|gate| gate.verdict));

    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "verdict": verdict,
                "delta": delta,
                "gates": gate.iter().collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        }
        OutputFormat::Tty => print_audit(&delta, verdict, gate.as_ref()),
    }

    if verdict == TriVerdict::Fail {
        std::process::exit(1);
    }
}

/// Combines the delta's tri-state verdict with the duplication ratio gate's
/// verdict (if evaluated) into one final verdict: `Fail` wins over
/// everything, `Warn` wins over `Pass`. A gate result of
/// `NotEvaluatedSmallSample` is purely informational and never forces
/// `Warn`/`Fail` on its own (see todo.md §6).
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
    delta: &judge::baseline::Delta,
    verdict: TriVerdict,
    gate: Option<&judge::gate::RatioGate>,
) {
    println!(
        "verdict: {}",
        match verdict {
            TriVerdict::Pass => "pass",
            TriVerdict::Warn => "warn",
            TriVerdict::Fail => "fail",
        }
    );
    println!("unchanged: {}", delta.unchanged_count);
    println!("resolved: {}", delta.resolved.len());
    for finding in &delta.resolved {
        println!("  {}  {}", finding.rule, finding.file.display());
    }

    println!("code-introduced: {}", delta.code_introduced.len());
    for finding in &delta.code_introduced {
        let severity = match finding.severity {
            judge::finding::Severity::Fail => "fail",
            judge::finding::Severity::Warn => "warn",
            judge::finding::Severity::Info => "info",
        };
        println!(
            "  [{severity}] {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        );
    }

    println!(
        "rule-introduced (protected, does not fail): {}",
        delta.rule_introduced.len()
    );
    for finding in &delta.rule_introduced {
        println!(
            "  {}  {}:{}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line
        );
    }

    println!();
    match gate {
        Some(gate) => {
            let gate_verdict = match gate.verdict {
                judge::gate::GateVerdict::Pass => "pass",
                judge::gate::GateVerdict::Fail => "fail",
                judge::gate::GateVerdict::NotEvaluatedSmallSample => "not_evaluated_small_sample",
            };
            println!(
                "gate: {} — {}/{} ({gate_verdict}, min sample {}, max ratio {})",
                gate.name, gate.numerator, gate.sample_size, gate.minimum_sample, gate.max_ratio
            );
        }
        None => println!(
            "gate: duplication-ratio not evaluated (pass --audit-min-sample and --max-duplication-ratio to enable)"
        ),
    }
}

fn run_dupes(
    mode: DupeModeArg,
    min_tokens: usize,
    format: OutputFormat,
    save_baseline: bool,
    baseline: Option<PathBuf>,
    include_generated: bool,
) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

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

    if save_baseline || baseline.is_some() {
        let findings = report.to_findings();
        let rule_revisions = std::collections::HashMap::from([(
            judge::duplication::DUPLICATE_RULE.to_string(),
            judge::duplication::DUPLICATE_RULE_REVISION,
        )]);
        handle_baseline(
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
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(report.to_findings(), analysis_errors);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Tty => {
            println!(
                "mode: {}",
                match mode {
                    DupeModeArg::Strict => "strict",
                    DupeModeArg::Mild => "mild",
                }
            );
            println!("min tokens: {min_tokens}");
            println!("clone families: {}", report.families.len());
            if !report.errors.is_empty() {
                println!("files skipped (parse errors): {}", report.errors.len());
                for err in &report.errors {
                    println!("  {err}");
                }
            }
            if report.excluded_generated > 0 {
                println!(
                    "excluded (generated): {} (see --include-generated)",
                    report.excluded_generated
                );
            }

            for (index, family) in report.families.iter().take(15).enumerate() {
                println!();
                println!("family #{} — {} members", index + 1, family.members.len());
                for member in &family.members {
                    println!(
                        "  {:>4} tokens  {}:{}-{}  {}",
                        member.token_count,
                        member.file.display(),
                        member.start_line,
                        member.end_line,
                        member.qualified_name
                    );
                }
            }
        }
    }
}

/// `cargo judge deps`: dependency-hygiene findings (`misplaced-dependency-kind`)
/// plus the G5 slopsquatting rules (see todo.md §14.2 G5). `name-collision-risk`
/// is fully local and always runs; `phantom-crate`/`phantom-version`/
/// `fresh-low-reputation-dep` need real crates.io network access and only run
/// when `--check-crates-io` is passed — judge makes no network calls by
/// default (see todo.md §1 "kein SaaS, keine Telemetrie, lokal deterministisch").
fn run_deps(format: OutputFormat, save_baseline: bool, baseline: Option<PathBuf>, check_crates_io: bool) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let report = judge::deps::analyze_workspace(&workspace);
    let mut analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();
    let mut findings = report.findings;

    let mut rule_revisions = std::collections::HashMap::from([
        (
            judge::deps::MISPLACED_DEPENDENCY_KIND_RULE.to_string(),
            judge::deps::MISPLACED_DEPENDENCY_KIND_RULE_REVISION,
        ),
        (
            judge::slopsquat::NAME_COLLISION_RISK_RULE.to_string(),
            judge::slopsquat::NAME_COLLISION_RISK_RULE_REVISION,
        ),
    ]);
    findings.extend(judge::slopsquat::analyze_name_collision(&workspace));

    if check_crates_io {
        let slopsquat_config = load_judge_toml(&workspace.root).slopsquat;
        let cache_root = workspace.root.join("target/judge/slopsquat-cache");

        let index_client = judge::slopsquat::SparseIndexClient::new(cache_root.clone());
        let phantom_report = judge::slopsquat::analyze_phantom_dependencies(&workspace, &index_client);
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

        let metadata_client = judge::slopsquat::RestMetadataClient::new(cache_root);
        let fresh_report =
            judge::slopsquat::analyze_fresh_low_reputation(&workspace, &metadata_client, &slopsquat_config);
        findings.extend(fresh_report.findings);
        analysis_errors.extend(fresh_report.errors);
        rule_revisions.insert(
            judge::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE.to_string(),
            judge::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE_REVISION,
        );
    }

    if save_baseline || baseline.is_some() {
        handle_baseline(
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
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let envelope = serde_json::json!({
                "schema_version": judge::finding::SCHEMA_VERSION,
                "findings": findings,
                "feature_only_candidates": report.feature_only_candidates,
                "errors": analysis_errors,
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        }
        OutputFormat::Tty => {
            println!("dependency findings: {}", findings.len());
            if !analysis_errors.is_empty() {
                println!("errors: {}", analysis_errors.len());
                for err in &analysis_errors {
                    println!("  {err}");
                }
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
                    println!(
                        "  {}  {} — {direction}",
                        crate_name, finding.location.item_path
                    );
                } else {
                    println!(
                        "  [{}] {}  {}",
                        finding.rule, crate_name, finding.location.item_path
                    );
                }
            }

            if !report.feature_only_candidates.is_empty() {
                println!();
                println!(
                    "feature-only candidates (no code usage found, kept as evidence, not asserted): {}",
                    report.feature_only_candidates.join(", ")
                );
            }
        }
    }
}

fn run_boundaries(
    config_path: Option<PathBuf>,
    format: OutputFormat,
    save_baseline: bool,
    baseline: Option<PathBuf>,
) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let config_path = config_path.unwrap_or_else(|| workspace.root.join("judge.toml"));
    if !config_path.exists() {
        println!("no judge.toml found — boundaries are opt-in, nothing to check");
        return;
    }

    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: {}: {err}", config_path.display());
            std::process::exit(2);
        }
    };
    let config: judge::boundaries::BoundaryConfig = match toml::from_str(&config_text) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}: failed to parse: {err}", config_path.display());
            std::process::exit(2);
        }
    };

    let boundaries = match judge::boundaries::evaluate(&workspace, &config) {
        Ok(boundaries) => boundaries,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([
            (
                judge::boundaries::BOUNDARY_VIOLATION_RULE.to_string(),
                judge::boundaries::BOUNDARY_VIOLATION_RULE_REVISION,
            ),
            (
                judge::boundaries::DEPENDENCY_CYCLE_RULE.to_string(),
                judge::boundaries::DEPENDENCY_CYCLE_RULE_REVISION,
            ),
        ]);
        handle_baseline(
            &workspace.root,
            &boundaries.findings,
            &[],
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_BOUNDARIES),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let report = Report::new(boundaries.findings);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Tty => {
            println!("boundary rules: {}", config.boundaries.len());
            println!("findings: {}", boundaries.findings.len());
            for finding in &boundaries.findings {
                let severity = match finding.severity {
                    judge::finding::Severity::Fail => "fail",
                    judge::finding::Severity::Warn => "warn",
                    judge::finding::Severity::Info => "info",
                };
                println!(
                    "  [{severity}] {} — {}",
                    finding.rule, finding.location.item_path
                );
            }
        }
    }
}

/// Ownership/bus-factor findings (see todo.md §3.E, §8). Window is the same
/// `judge::git::DEFAULT_WINDOW_DAYS` used by hotspots — not a separate CLI
/// flag, matching how hotspots hardcodes it today.
fn run_distribution(format: OutputFormat, save_baseline: bool, baseline: Option<PathBuf>) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let report =
        match judge::ownership::analyze_workspace(&workspace, judge::git::DEFAULT_WINDOW_DAYS) {
            Ok(report) => report,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };
    let analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();

    if save_baseline || baseline.is_some() {
        let rule_revisions = std::collections::HashMap::from([(
            judge::ownership::LOW_BUS_FACTOR_RULE.to_string(),
            judge::ownership::LOW_BUS_FACTOR_RULE_REVISION,
        )]);
        handle_baseline(
            &workspace.root,
            &report.findings,
            &analysis_errors,
            BaselineOptions {
                rule_revisions,
                save: save_baseline,
                compare_path: baseline.as_deref(),
                default_save_path: Path::new(DEFAULT_BASELINE_DISTRIBUTION),
                format,
                total_loc: judge::health_score::total_authored_loc(&workspace),
            },
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(report.findings, analysis_errors);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Tty => {
            println!("files analyzed: {}", report.files.len());
            if !report.errors.is_empty() {
                println!("files skipped (blame errors): {}", report.errors.len());
                for err in &report.errors {
                    println!("  {err}");
                }
            }

            println!();
            println!("low-bus-factor findings: {}", report.findings.len());
            for finding in &report.findings {
                let severity = match finding.severity {
                    judge::finding::Severity::Fail => "fail",
                    judge::finding::Severity::Warn => "warn",
                    judge::finding::Severity::Info => "info",
                };
                println!(
                    "  [{severity}] {}  primary author: {}",
                    finding.location.file.display(),
                    finding.location.item_path
                );
            }
        }
    }
}

/// `unused-pub-workspace` via the Deep Tier (see todo.md §3.A, §14.2 P1).
/// Only available in a build compiled with `--features deep` — a Fast Tier
/// build prints a clear error instead of silently doing nothing.
#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
fn run_dead_code(
    include_tests: bool,
    format: OutputFormat,
    save_baseline: bool,
    baseline: Option<PathBuf>,
) {
    if !judge::AnalysisTier::Deep.is_available() {
        eprintln!(
            "error: dead-code analysis needs the Deep Tier — rebuild with `cargo install --path . --features deep` (see todo.md §2.1)"
        );
        std::process::exit(2);
    }

    #[cfg(feature = "deep")]
    {
        let workspace = match judge::ingest::load(None) {
            Ok(workspace) => workspace,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };

        let report = match judge::dead_code::analyze_workspace(&workspace, include_tests) {
            Ok(report) => report,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };
        let analysis_errors: Vec<String> = report.errors.iter().map(ToString::to_string).collect();

        if save_baseline || baseline.is_some() {
            let rule_revisions = std::collections::HashMap::from([(
                judge::dead_code::UNUSED_PUB_WORKSPACE_RULE.to_string(),
                judge::dead_code::UNUSED_PUB_WORKSPACE_RULE_REVISION,
            )]);
            handle_baseline(
                &workspace.root,
                &report.findings,
                &analysis_errors,
                BaselineOptions {
                    rule_revisions,
                    save: save_baseline,
                    compare_path: baseline.as_deref(),
                    default_save_path: Path::new(DEFAULT_BASELINE_DEAD_CODE),
                    format,
                    total_loc: judge::health_score::total_authored_loc(&workspace),
                },
            );
            return;
        }

        match format {
            OutputFormat::Json => {
                let report = Report::with_errors(report.findings, analysis_errors);
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
            OutputFormat::Tty => {
                println!("pub items checked: {}", report.checked);
                if !analysis_errors.is_empty() {
                    println!("analysis errors: {}", analysis_errors.len());
                    for error in &analysis_errors {
                        println!("  {error}");
                    }
                }
                println!("unused-pub-workspace findings: {}", report.findings.len());
                for finding in &report.findings {
                    println!(
                        "  [warn] {}:{}  {}",
                        finding.location.file.display(),
                        finding.location.line,
                        finding.location.item_path
                    );
                }
            }
        }
    }
}

/// `judge explain <item-path> --why-live` (see todo.md §7, §14.2 P1).
/// Only `--why-live` is implemented; other explain modes (e.g. explaining a
/// finding id) don't exist yet.
#[cfg_attr(not(feature = "deep"), allow(unused_variables))]
fn run_explain(item_path: String, why_live: bool, include_tests: bool, format: OutputFormat) {
    if !why_live {
        eprintln!("error: `judge explain` currently only supports `--why-live`");
        std::process::exit(2);
    }
    if !judge::AnalysisTier::Deep.is_available() {
        eprintln!(
            "error: --why-live needs the Deep Tier — rebuild with `cargo install --path . --features deep` (see todo.md §2.1)"
        );
        std::process::exit(2);
    }

    #[cfg(feature = "deep")]
    {
        let workspace = match judge::ingest::load(None) {
            Ok(workspace) => workspace,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };

        let result = match judge::reachability::why_live(&workspace, &item_path, include_tests) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
        };

        match format {
            OutputFormat::Json => {
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
                    }),
                    judge::reachability::WhyLive::NotReachable => serde_json::json!({
                        "item_path": item_path,
                        "reachable": false,
                        "path": [],
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            OutputFormat::Tty => match &result {
                judge::reachability::WhyLive::Path(path) => {
                    println!("{item_path} is live:");
                    for (index, step) in path.iter().enumerate() {
                        let prefix = if index == 0 { "  " } else { "  called by " };
                        let kind_suffix =
                            step.kind.map_or(String::new(), |kind| format!(" [{kind}]"));
                        println!(
                            "{prefix}{} ({}:{}){kind_suffix}",
                            step.qualified_name,
                            step.file.display(),
                            step.line
                        );
                    }
                }
                judge::reachability::WhyLive::NotReachable => {
                    println!(
                        "{item_path}: not reachable from any recognized entry point (`fn main` in a [[bin]]/[[example]] target, #[test]/#[bench] with --include-tests, or #[no_mangle]/#[export_name]/#[wasm_bindgen])"
                    );
                }
            },
        }
    }
}

fn run_health(
    show_score: bool,
    format: OutputFormat,
    show_cascades: bool,
    save_baseline: bool,
    baseline: Option<PathBuf>,
    include_generated: bool,
) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

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
    let slop = judge::slop::analyze_workspace(slop_source_files, include_generated);
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

    let excluded_generated = report.excluded_generated + slop.excluded_generated;
    let total_loc = judge::health_score::total_authored_loc(&workspace);

    // Print the score trend before `handle_baseline` runs below, since a
    // failing verdict there exits the process before reaching any code after
    // it (see todo.md §4 point 4, "Trend vor Absolutwert" — the score is
    // never shown without this). TTY only, matching the current-score
    // display further down.
    if show_score
        && !save_baseline
        && matches!(format, OutputFormat::Tty)
        && let Some(path) = &baseline
    {
        print_score_trend(&workspace, &findings, total_loc, path);
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
        ]);
        handle_baseline(
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
        );
        return;
    }

    match format {
        OutputFormat::Json => {
            let report = Report::with_errors(findings, analysis_errors);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Tty => {
            println!("functions analyzed: {}", functions.len());
            if !analysis_errors.is_empty() {
                println!("analysis errors: {}", analysis_errors.len());
                for error in &analysis_errors {
                    println!("  {error}");
                }
            }
            if excluded_generated > 0 {
                println!("excluded (generated): {excluded_generated} (see --include-generated)");
            }

            println!();
            println!("top complexity (cyclomatic):");
            for function in functions.iter().take(15) {
                println!(
                    "  {:>3}  {}:{}  {}",
                    function.cyclomatic,
                    function.file.display(),
                    function.line,
                    function.qualified_name
                );
            }

            println!();
            if let Some(error) = hotspot_error {
                println!("hotspots: unavailable ({error})");
            } else {
                print_hotspots(&hotspots, &findings, show_cascades);
            }

            println!();
            print_slop(&findings, show_cascades);

            if show_score {
                println!();
                let config = load_judge_toml(&workspace.root);
                let score = judge::health_score::compute(
                    &findings,
                    total_loc,
                    &workspace,
                    &config.crate_profiles,
                );
                println!(
                    "health score: {:.1} ({}) — {} authored LOC, {} fail, {} warn",
                    score.score,
                    score.grade.label(),
                    score.total_loc,
                    score.fail_count,
                    score.warn_count,
                );
            }
        }
    }
}

/// Loads `judge.toml`'s `[[boundary]]`/`[[crate_profile]]` config, if
/// present. Both are opt-in — a missing file is the default (empty) config,
/// not an error.
fn load_judge_toml(workspace_root: &Path) -> judge::boundaries::BoundaryConfig {
    let config_path = workspace_root.join("judge.toml");
    if !config_path.exists() {
        return judge::boundaries::BoundaryConfig::default();
    }
    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: {}: {err}", config_path.display());
            std::process::exit(2);
        }
    };
    match toml::from_str(&config_text) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}: failed to parse: {err}", config_path.display());
            std::process::exit(2);
        }
    }
}

/// Prints the current health score alongside the score a saved baseline
/// represents (see todo.md §4 point 4, "Trend vor Absolutwert").
fn print_score_trend(
    workspace: &judge::ingest::Workspace,
    findings: &[Finding],
    total_loc: usize,
    baseline_path: &Path,
) {
    let baseline = match judge::baseline::load(baseline_path) {
        Ok(baseline) => baseline,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };
    let config = load_judge_toml(&workspace.root);
    let current =
        judge::health_score::compute(findings, total_loc, workspace, &config.crate_profiles);
    let baseline_score = judge::health_score::baseline_score(&baseline);
    let trend = judge::health_score::Trend {
        current,
        baseline_score: baseline_score.score,
        baseline_grade: baseline_score.grade,
    };

    println!(
        "health score: {:.1} ({}) — {:+.1} since baseline ({:.1} {})",
        trend.current.score,
        trend.current.grade.label(),
        trend.delta(),
        trend.baseline_score,
        trend.baseline_grade.label(),
    );
}

/// Hotspot = complexity × change frequency (see todo.md §3.E). Files with no
/// recorded churn (or no git history at all) are left out rather than shown
/// as zero-risk. Reduced to root findings unless `show_cascades` is set (see
/// todo.md §14.2 P0#2) — currently a no-op, since nothing yet populates
/// `caused_by` for hotspot findings, but the mechanism is exercised here so
/// future detectors that do can rely on it.
fn print_hotspots(
    hotspots: &[judge::git::Hotspot],
    findings: &[judge::finding::Finding],
    show_cascades: bool,
) {
    if hotspots.is_empty() {
        println!(
            "hotspots: none in the last {} days (no git history, or no file crosses both complexity and churn)",
            judge::git::DEFAULT_WINDOW_DAYS
        );
        return;
    }

    let shown_ids: std::collections::HashSet<&str> = if show_cascades {
        findings.iter().map(|f| f.id.as_str()).collect()
    } else {
        judge::finding::root_findings(findings)
            .into_iter()
            .map(|f| f.id.as_str())
            .collect()
    };

    println!(
        "hotspots (complexity × changes in the last {} days):",
        judge::git::DEFAULT_WINDOW_DAYS
    );
    for hotspot in hotspots.iter().take(15) {
        let id = format!("{}:{}", judge::git::HOTSPOT_RULE, hotspot.file.display());
        if !shown_ids.contains(id.as_str()) {
            continue;
        }
        println!(
            "  {:>6}  {} × {} changes  {}",
            hotspot.score(),
            hotspot.complexity,
            hotspot.changes,
            hotspot.file.display()
        );
    }
}

/// AI-slop signals (see todo.md §G "AI-Slop-Signale", §12 "Entscheidungen":
/// "Der Slop-Block ist Teil von `health`, kein eigener Sub-Command"). Grouped
/// by rule with a per-rule count, then listed root-findings-first unless
/// `show_cascades` is set (see todo.md §14.2 P0#2), same convention as
/// `print_hotspots`.
const SLOP_RULES: [&str; 18] = [
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
];

fn print_slop(findings: &[judge::finding::Finding], show_cascades: bool) {
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
        println!("slop signals: none");
        return;
    }

    println!("slop signals: {}", shown.len());
    for rule in SLOP_RULES {
        let count = shown.iter().filter(|finding| finding.rule == rule).count();
        if count > 0 {
            println!("  {rule}: {count}");
        }
    }
    println!();
    for finding in &shown {
        let severity = match finding.severity {
            judge::finding::Severity::Fail => "fail",
            judge::finding::Severity::Warn => "warn",
            judge::finding::Severity::Info => "info",
        };
        println!(
            "  [{severity}] {:<20} {}:{}  {}",
            finding.rule,
            finding.location.file.display(),
            finding.location.line,
            finding.location.item_path
        );
    }
}

fn run_inspect() {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    println!("workspace root: {}", workspace.root.display());
    println!("crates: {}", workspace.crates.len());
    for krate in &workspace.crates {
        println!();
        println!("  {} {}", krate.name, krate.version);
        println!("    manifest: {}", krate.manifest_path.display());
        println!("    source files: {}", krate.source_files.len());
        if krate.entry_points.is_empty() {
            println!("    entry points: none");
        } else {
            println!("    entry points:");
            for entry in &krate.entry_points {
                println!(
                    "      [{}] {} — {}",
                    entry.kind.label(),
                    entry.name,
                    entry.path.display()
                );
            }
        }
    }

    println!();
    println!("tiers:");
    println!("  fast: available");
    println!(
        "  deep: {}",
        if AnalysisTier::Deep.is_available() {
            "available"
        } else {
            "not available (build with --features deep)"
        }
    );
    println!();
    println!("cache: not implemented yet");
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

    /// Exercises the wiring `run_audit` performs — `collect_findings`,
    /// `judge::git::changed_files_since`, `judge::baseline::diff`, the
    /// duplication ratio gate, and `combine_verdict` — without invoking the
    /// CLI's `std::process::exit` paths directly (see todo.md §5 "audit
    /// --since"). A new file's duplication finding must classify as
    /// `code_introduced`.
    #[test]
    fn audit_wiring_classifies_a_new_files_duplication_as_code_introduced() {
        let dir = TempDir::new("audit-code-introduced");
        git(&dir, &["init", "-q", "-b", "main"]);
        write_fixture_crate(&dir);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base_commit = commit_sha(&dir, "HEAD");

        let manifest = dir.join("Cargo.toml");
        let workspace = judge::ingest::load(Some(&manifest)).unwrap();
        let baseline_collected = collect_findings(&workspace);
        assert!(baseline_collected.analysis_errors.is_empty());
        let baseline = judge::baseline::Baseline::new(
            &baseline_collected.findings,
            base_commit.clone(),
            baseline_collected.rule_revisions,
            judge::health_score::total_authored_loc(&workspace),
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
        let mut collected = collect_findings(&workspace);
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

        let pre_existing = judge::finding::Finding {
            id: "duplicate-code:src/lib.rs:hello:0-20".to_string(),
            rule: judge::duplication::DUPLICATE_RULE.to_string(),
            severity: judge::finding::Severity::Warn,
            location: judge::finding::Location {
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                item_path: "hello".to_string(),
            },
            confidence: 1.0,
            origin: judge::finding::Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        };
        let baseline = judge::baseline::Baseline::new(
            &[pre_existing.clone()],
            base_commit,
            std::collections::HashMap::from([(judge::duplication::DUPLICATE_RULE.to_string(), 1)]),
            0,
        );
        let bumped_revisions =
            std::collections::HashMap::from([(judge::duplication::DUPLICATE_RULE.to_string(), 2)]);

        let delta = judge::baseline::diff(&[pre_existing], &baseline, &touched, &bumped_revisions);

        assert!(delta.code_introduced.is_empty());
        assert_eq!(delta.rule_introduced.len(), 1);
        assert_eq!(delta.tri_verdict(), TriVerdict::Pass);
        assert_eq!(combine_verdict(delta.tri_verdict(), None), TriVerdict::Pass);
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
