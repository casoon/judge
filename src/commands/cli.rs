//! Command routing and arguments shared by baseline-aware subcommands.

use crate::ApiSurfaceOptions;
use crate::BoundariesOptions;
use crate::CliError;
use crate::CommandOutcome;
use crate::CompareOptions;
use crate::ComplexityOptions;
use crate::CoverageOptions;
use crate::DeadCodeOptions;
use crate::DepsOptions;
use crate::DupesOptions;
use crate::ExplainOptions;
use crate::ExplainPatternOptions;
use crate::ExplainPrincipleOptions;
use crate::ExplainRuleOptions;
use crate::FixPreviewOptions;
use crate::FocusedAnalysisOptions;
use crate::HealthOptions;
use crate::ImpactOptions;
use crate::MapOptions;
use crate::ModuleGraphOptions;
use crate::OutputFormat;
use crate::PatternsOptions;
use crate::PrinciplesOptions;
use crate::RefactorOptions;
use crate::StructureOptions;
use crate::run_api_surface;
use crate::run_boundaries;
use crate::run_complexity;
use crate::run_coverage;
use crate::run_dead_code;
use crate::run_deps;
use crate::run_dupes;
use crate::run_errors;
use crate::run_explain;
use crate::run_explain_pattern;
use crate::run_explain_principle;
use crate::run_explain_rule;
use crate::run_fix_preview;
use crate::run_health;
use crate::run_impact;
use crate::run_inspect;
use crate::run_map;
use crate::run_module_graph;
use crate::run_patterns;
use crate::run_principles;
use crate::run_refactor;
use crate::run_slop;
use crate::run_structure;
use crate::run_tests;
use crate::run_unsafe;
use clap::{Args, Subcommand};
use std::io::Write;
use std::path::PathBuf;

use super::combined;

/// Arguments shared by commands that can save or compare finding baselines.
///
/// Flattening this type keeps the command-line interface unchanged while
/// ensuring every baseline-aware command exposes the same option semantics.
#[derive(Debug, Args)]
pub(crate) struct BaselineArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    pub(crate) format: OutputFormat,
    /// Save the current findings as the baseline.
    #[arg(long)]
    pub(crate) save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    pub(crate) baseline: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Find duplicated token spans (clone families).
    Dupes(DupesOptions),
    /// Show the repository health summary, including slop signals.
    Health(HealthOptions),
    /// Show dependency-hygiene findings (misplaced dependency kinds,
    /// slopsquatting signals).
    Deps(DepsOptions),
    /// Check crate-level architecture boundaries declared in `judge.toml`
    /// Opt-in: does nothing if no config is
    /// found.
    Boundaries(BoundariesOptions),
    /// Find `pub` items no other workspace crate references. Needs the Deep Tier — build with `--features deep`.
    DeadCode(DeadCodeOptions),
    /// Explains a specific item. Currently only
    /// `--why-live` is implemented.
    Explain(ExplainOptions),
    /// Compare the current project state with a recorded baseline artifact.
    /// This command never reads Git history.
    Compare(CompareOptions),
    /// Initialize judge configuration in a workspace.
    Init,
    /// Show detected entry points, tiers, and cache status.
    Inspect,
    /// Show a compact, deterministic map of refactoring-relevant workspace facts.
    Map(MapOptions),
    /// Diagnose the current workspace structure: crates, targets, dependency edges,
    /// modules, complexity concentration, and duplicate-code context.
    Structure(StructureOptions),
    /// Show current-state complexity facts without historical hotspot signals.
    Complexity(ComplexityOptions),
    /// Show the analysis and Cargo-target context of one workspace source file.
    Impact(ImpactOptions),
    /// Build a deterministic, evidence-backed queue of refactoring candidates.
    Refactor(RefactorOptions),
    /// Review unsafe-code structure and safety documentation.
    Unsafe(FocusedAnalysisOptions),
    /// Review current error-handling patterns and architecture signals.
    Errors(FocusedAnalysisOptions),
    /// Review test-structure signals without making coverage claims.
    Tests(FocusedAnalysisOptions),
    /// Review mechanical code smells without inferring authorship.
    Slop(FocusedAnalysisOptions),
    /// Imports an externally generated `cargo-llvm-cov` LCOV report and
    /// flags `untested-hotspot` functions: high complexity, high churn, and
    /// mostly uncovered lines. judge never measures
    /// coverage itself — only an already-generated snapshot is read.
    Coverage(CoverageOptions),
    /// Heuristic Rust design-pattern recommendations aggregated from
    /// projectwide evidence. Advisory only — never
    /// affects the verdict/exit code.
    Patterns(PatternsOptions),
    /// Heuristic abstract-design-principle interpretations (cohesion,
    /// functional core/imperative shell, ...) aggregated from at least two
    /// independent evidence classes per finding.
    /// Advisory only — never affects the verdict/exit code, and a
    /// deliberately separate assertion class from `patterns`.
    Principles(PrinciplesOptions),
    /// Shows one pattern candidate's full evidence, preconditions,
    /// contraindications, and migration plan.
    ExplainPattern(ExplainPatternOptions),
    /// Shows one design-principle heuristic's full evidence, interpretation,
    /// contraindications, missing evidence, and alternatives, analogous to `explain-pattern`.
    ExplainPrinciple(ExplainPrincipleOptions),
    /// Shows only a pattern candidate's migration plan and affected call
    /// sites — deliberately no patch.
    FixPreview(FixPreviewOptions),
    /// Shows one rule's evidence class, preconditions, exclusions, allowed
    /// wording, and verdict effect from the static rule registry. A pure documentation lookup — never runs analysis and never
    /// produces exit code 1.
    ExplainRule(ExplainRuleOptions),
    /// Shows public-API-surface findings (`undocumented-public-item` and
    /// `semver-hazard`). Subcommand-only: not part of bare
    /// `cargo judge` or `health`. A
    /// build compiled with `--features deep` additionally checks
    /// `semver-hazard`'s `leaked_dependency_type` sub-case.
    ApiSurface(ApiSurfaceOptions),
    /// Focused public API analysis.
    Api(ApiSurfaceOptions),
    /// Shows `unlinked-file`/`orphan-module` findings from resolving each
    /// crate's real `mod` tree (see `judge::rules::module_graph`). Subcommand-only:
    /// not part of bare `cargo judge` or `health`.
    ModuleGraph(ModuleGraphOptions),
}

impl Command {
    /// Returns the selected JSON format and its stable default artifact name.
    /// Commands that render a non-JSON projection regardless of `--format`
    /// (currently `boundaries --graph`) deliberately have no JSON artifact.
    pub(crate) fn json_artifact(&self) -> Option<(OutputFormat, &'static str)> {
        match self {
            Self::Dupes(options) => Some((options.baseline_args.format, "dupes")),
            Self::Health(options) => Some((options.baseline_args.format, "health")),
            Self::Deps(options) => Some((options.baseline_args.format, "deps")),
            Self::Boundaries(options) => Some((options.baseline_args.format, "boundaries")),
            Self::DeadCode(options) => Some((options.baseline_args.format, "dead-code")),
            Self::Explain(options) => Some((options.format, "explain")),
            Self::Compare(options) => Some((options.format, "compare")),
            Self::Coverage(options) => Some((options.baseline_args.format, "coverage")),
            Self::Patterns(options) => Some((options.format, "patterns")),
            Self::Principles(options) => Some((options.format, "principles")),
            Self::ExplainPattern(options) => Some((options.format, "explain-pattern")),
            Self::ExplainPrinciple(options) => Some((options.format, "explain-principle")),
            Self::FixPreview(options) => Some((options.format, "fix-preview")),
            Self::ExplainRule(options) => Some((options.format, "explain-rule")),
            Self::ApiSurface(options) => Some((options.baseline_args.format, "api-surface")),
            Self::Api(options) => Some((options.baseline_args.format, "api")),
            Self::ModuleGraph(options) => Some((options.baseline_args.format, "module-graph")),
            Self::Map(options) => Some((options.format, "map")),
            Self::Structure(options) => Some((options.format, "structure")),
            Self::Complexity(options) => Some((options.format, "complexity")),
            Self::Impact(options) => Some((options.format, "impact")),
            Self::Refactor(options) => Some((options.format, "refactor")),
            Self::Unsafe(options) => Some((options.format, "unsafe")),
            Self::Errors(options) => Some((options.format, "errors")),
            Self::Tests(options) => Some((options.format, "tests")),
            Self::Slop(options) => Some((options.format, "slop")),
            Self::Init | Self::Inspect => None,
        }
    }

    /// Dispatches a parsed subcommand to its handler.
    pub(crate) fn run(self, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
        match self {
            Self::Dupes(options) => run_dupes(options, out),
            Self::Health(options) => run_health(options, out),
            Self::Deps(options) => run_deps(options, out),
            Self::Boundaries(options) => run_boundaries(options, out),
            Self::DeadCode(options) => run_dead_code(options, out),
            Self::Explain(options) => run_explain(options, out),
            Self::Compare(options) => combined::run(
                combined::CombinedOptions::compare(options.format, options.baseline),
                out,
            ),
            Self::Init => run_init(out),
            Self::Inspect => run_inspect(out),
            Self::Map(options) => run_map(options, out),
            Self::Structure(options) => run_structure(options, out),
            Self::Complexity(options) => run_complexity(options, out),
            Self::Impact(options) => run_impact(options, out),
            Self::Refactor(options) => run_refactor(options, out),
            Self::Unsafe(options) => run_unsafe(options, out),
            Self::Errors(options) => run_errors(options, out),
            Self::Tests(options) => run_tests(options, out),
            Self::Slop(options) => run_slop(options, out),
            Self::Coverage(options) => run_coverage(options, out),
            Self::Patterns(options) => run_patterns(options, out),
            Self::Principles(options) => run_principles(options, out),
            Self::ExplainPattern(options) => run_explain_pattern(options, out),
            Self::ExplainPrinciple(options) => run_explain_principle(options, out),
            Self::FixPreview(options) => run_fix_preview(options, out),
            Self::ExplainRule(options) => run_explain_rule(options, out),
            Self::ApiSurface(options) => run_api_surface(options, out),
            Self::Api(options) => run_api_surface(options, out),
            Self::ModuleGraph(options) => run_module_graph(options, out),
        }
    }
}

/// Starter `judge.toml`: every table is commented out, so a fresh file
/// changes nothing until a rule is opted into.
const JUDGE_TOML_TEMPLATE: &str = r#"# judge configuration. Everything below is opt-in: with no active table,
# judge runs its defaults. Uncomment and adapt what you need.
# Reference: https://casoon.github.io/judge/docs/

# Crate-level architecture rules (`cargo judge boundaries`).
# [[boundary]]
# name = "domain-stays-pure"
# from = ["my-domain"]
# forbidden = ["my-infra"]
# reach = "transitive"   # or "direct"

# Module-level rules inside one crate.
# [[module_boundary]]
# name = "domain-no-db"
# crate = "my-app"
# from = "domain"
# forbidden = ["db"]

# Weigh findings of some crates differently in `health --score`.
# [[crate_profile]]
# name = "parsers"
# crates = ["my-parser"]
# deduction_multiplier = 0.5

# Allow `anyhow` at public boundaries for `catch-all-error`.
# [rules.catch-all-error]
# allow-anyhow-at-boundary = true
"#;

/// `cargo judge init`: writes a commented starter `judge.toml` into the
/// workspace root. Never overwrites an existing file.
fn run_init(out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let path = workspace.root.join("judge.toml");
    if path.exists() {
        return Err(CliError::Config(format!(
            "{} already exists; judge init does not overwrite it",
            path.display()
        )));
    }
    std::fs::write(&path, JUDGE_TOML_TEMPLATE)?;
    writeln!(out, "wrote {}", path.display())?;
    writeln!(
        out,
        "Next: uncomment a table, then run `cargo judge boundaries`."
    )?;
    Ok(CommandOutcome::Clean)
}
