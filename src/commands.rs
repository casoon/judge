//! Command routing and arguments shared by baseline-aware subcommands.

use super::*;
use clap::{Args, Subcommand};

/// Arguments shared by commands that can save or compare finding baselines.
///
/// Flattening this type keeps the command-line interface unchanged while
/// ensuring every baseline-aware command exposes the same option semantics.
#[derive(Debug, Args)]
pub(super) struct BaselineArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "tty")]
    pub(super) format: OutputFormat,
    /// Save the current findings as the baseline (see todo.md §5).
    #[arg(long)]
    pub(super) save_baseline: bool,
    /// Compare findings against a previously saved baseline.
    #[arg(long, value_name = "PATH")]
    pub(super) baseline: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
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
    /// Find `pub` items no other workspace crate references (see todo.md
    /// §3.A, §14.2 P1). Needs the Deep Tier — build with `--features deep`.
    DeadCode(DeadCodeOptions),
    /// Explains a specific item (see todo.md §7). Currently only
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
    /// Shows one design-principle heuristic's full evidence, interpretation,
    /// contraindications, missing evidence, and alternatives (see todo.md
    /// §16.7), analogous to `explain-pattern`.
    ExplainPrinciple(ExplainPrincipleOptions),
    /// Shows only a pattern candidate's migration plan and affected call
    /// sites — deliberately no patch (see todo.md §16.5).
    FixPreview(FixPreviewOptions),
    /// Shows one rule's evidence class, preconditions, exclusions, allowed
    /// wording, and verdict effect from the static rule registry (see todo.md
    /// §17.5). A pure documentation lookup — never runs analysis and never
    /// produces exit code 1.
    ExplainRule(ExplainRuleOptions),
    /// Shows public-API-surface findings (`undocumented-public-item` and
    /// `semver-hazard` — see todo.md §I). Subcommand-only: not part of bare
    /// `cargo judge` or `health`. A
    /// build compiled with `--features deep` additionally checks
    /// `semver-hazard`'s `leaked_dependency_type` sub-case.
    ApiSurface(ApiSurfaceOptions),
    /// Focused public API analysis.
    Api(ApiSurfaceOptions),
    /// Shows `unlinked-file`/`orphan-module` findings from resolving each
    /// crate's real `mod` tree (see `judge::module_graph`). Subcommand-only:
    /// not part of bare `cargo judge` or `health`.
    ModuleGraph(ModuleGraphOptions),
}

impl Command {
    /// Returns the selected JSON format and its stable default artifact name.
    /// Commands that render a non-JSON projection regardless of `--format`
    /// (currently `boundaries --graph`) deliberately have no JSON artifact.
    pub(super) fn json_artifact(&self) -> Option<(OutputFormat, &'static str)> {
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
    pub(super) fn run(self, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
        match self {
            Self::Dupes(options) => run_dupes(options, out),
            Self::Health(options) => run_health(options, out),
            Self::Deps(options) => run_deps(options, out),
            Self::Boundaries(options) => run_boundaries(options, out),
            Self::DeadCode(options) => run_dead_code(options, out),
            Self::Explain(options) => run_explain(options, out),
            Self::Compare(options) => combined::run(
                options.format,
                false,
                Some(options.baseline),
                None,
                false,
                false,
                out,
            ),
            Self::Init => {
                writeln!(out, "judge init is not implemented yet")?;
                Ok(CommandOutcome::Clean)
            }
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
