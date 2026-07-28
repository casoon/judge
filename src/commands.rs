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

impl Command {
    /// Dispatches a parsed subcommand to its handler.
    pub(super) fn run(self, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
        match self {
            Self::Dupes(options) => run_dupes(options, out),
            Self::Health(options) => run_health(options, out),
            Self::Deps(options) => run_deps(options, out),
            Self::Boundaries(options) => run_boundaries(options, out),
            Self::Distribution(options) => run_distribution(options, out),
            Self::Provenance(options) => run_provenance(options, out),
            Self::DeadCode(options) => run_dead_code(options, out),
            Self::Explain(options) => run_explain(options, out),
            Self::Audit(options) => run_audit(options, out),
            Self::Init => {
                writeln!(out, "judge init is not implemented yet")?;
                Ok(CommandOutcome::Clean)
            }
            Self::Inspect => run_inspect(out),
            Self::Coverage(options) => run_coverage(options, out),
            Self::Patterns(options) => run_patterns(options, out),
            Self::Principles(options) => run_principles(options, out),
            Self::ExplainPattern(options) => run_explain_pattern(options, out),
            Self::ExplainPrinciple(options) => run_explain_principle(options, out),
            Self::FixPreview(options) => run_fix_preview(options, out),
            Self::ExplainRule(options) => run_explain_rule(options, out),
            Self::ApiSurface(options) => run_api_surface(options, out),
            Self::ModuleGraph(options) => run_module_graph(options, out),
        }
    }
}
