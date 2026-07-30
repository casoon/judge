//! Advisory pattern and design-principle commands and their focused rendering.

use super::*;

/// Rejects `sarif`/`markdown` up front; every advisory command in this
/// module only supports `tty`/`json`. Shared so the supported-format list is
/// stated once instead of duplicated per command.
fn reject_unsupported_advisory_format(
    format: OutputFormat,
    command_name: &str,
) -> Result<(), CliError> {
    if matches!(format, OutputFormat::Sarif | OutputFormat::Markdown) {
        return Err(unsupported_format(command_name, format, "tty, json"));
    }
    Ok(())
}

/// Pretty-prints `value` as the `json` closure every [`render_advisory`]
/// caller passes — factored out so the call sites don't each repeat the same
/// `Ok(serde_json::to_string_pretty(..)?)` wrapper.
fn to_json_string<T: Serialize + ?Sized>(value: &T) -> Result<String, CliError> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Converts a TTY renderer's `std::io::Result` into this module's
/// `CliError`, as the `tty` closure every [`render_advisory`] caller passes
/// — factored out so the call sites don't each repeat the same
/// `Ok(print_..(..)?)` wrapper.
fn to_cli_result(result: std::io::Result<()>) -> Result<(), CliError> {
    Ok(result?)
}

/// Dispatches an advisory command's final `tty`/`json` rendering. Every
/// advisory command in this module rejects `sarif`/`markdown` up front (via
/// [`reject_unsupported_advisory_format`]) before reaching here, so the
/// `sarif`/`markdown` arm is unreachable by construction. `json` is a
/// closure (not an already-built value) so the json serialization work is
/// only ever paid for `--format json`, matching the original per-command
/// match arms this replaces.
fn render_advisory(
    out: &mut dyn Write,
    format: OutputFormat,
    json: impl FnOnce() -> Result<String, CliError>,
    tty: impl FnOnce(&mut dyn Write) -> Result<(), CliError>,
) -> Result<CommandOutcome, CliError> {
    match format {
        OutputFormat::Json => writeln!(out, "{}", json()?)?,
        OutputFormat::Sarif | OutputFormat::Markdown => {
            unreachable!("rejected above before dispatch")
        }
        OutputFormat::Tty => tty(out)?,
    }
    Ok(CommandOutcome::Clean)
}

/// Runs the shared slop and optional Clippy evidence pass for the pattern
/// commands. Keeping it local prevents standalone commands from duplicating
/// their analysis inputs.
fn collect_pattern_candidates(
    workspace: &judge::ingest::Workspace,
    clippy_json: Option<&Path>,
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
    let clippy_hits = match clippy_json {
        Some(path) => judge::clippy_import::read_clippy_report(path)?,
        None => Vec::new(),
    };
    Ok(judge::pattern::analyze_workspace_with_clippy(
        workspace,
        &slop.findings,
        &clippy_hits,
    ))
}

/// `CliError` (exit 2), same as every other command.
pub(super) fn run_patterns(
    options: PatternsOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let PatternsOptions {
        format,
        clippy_json,
        save_pattern_baseline,
        pattern_baseline,
    } = options;
    reject_unsupported_advisory_format(format, "`patterns`")?;
    let workspace = judge::ingest::load(None)?;
    let candidates = collect_pattern_candidates(&workspace, clippy_json.as_deref())?;

    if save_pattern_baseline {
        let baseline = judge::pattern_baseline::PatternBaseline::new(&candidates);
        let save_path = workspace.root.join(DEFAULT_PATTERN_BASELINE);
        judge::pattern_baseline::save(&save_path, &baseline)?;
        writeln!(
            out,
            "pattern baseline saved: {} ({} candidates)",
            save_path.display(),
            candidates.len()
        )?;
        return Ok(CommandOutcome::Clean);
    }

    if let Some(path) = &pattern_baseline {
        let baseline = judge::pattern_baseline::load(path)?;
        let delta = judge::pattern_baseline::diff_patterns(&candidates, &baseline);
        return render_advisory(
            out,
            format,
            || to_json_string(&serde_json::json!({ "delta": delta })),
            |out| to_cli_result(print_pattern_delta_tty(out, &delta)),
        );
    }

    render_advisory(
        out,
        format,
        || to_json_string(&serde_json::json!({ "candidates": candidates })),
        |out| {
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
            Ok(())
        },
    )
}

/// Loads the workspace's complexity metrics (same complexity pass
/// `run_health` uses) and `judge.toml` boundary config, then runs the
/// principle-heuristic aggregator (`judge::principle`) over them. Shared by
/// `principles` and `explain-principle`, mirroring how
/// [`collect_pattern_candidates`] is shared by `patterns`/`explain-
/// pattern`/`fix-preview`.
fn collect_principle_heuristics(
    workspace: &judge::ingest::Workspace,
) -> Result<Vec<judge::principle::PrincipleHeuristic>, CliError> {
    let boundary_config = load_judge_toml(&workspace.root)?;
    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let complexity = judge::complexity::analyze_workspace(source_files, false);
    Ok(judge::principle::analyze_workspace(
        workspace,
        &complexity,
        Some(&boundary_config),
    )?)
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
pub(super) fn run_principles(
    options: PrinciplesOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let PrinciplesOptions { format } = options;
    reject_unsupported_advisory_format(format, "`principles`")?;
    let workspace = judge::ingest::load(None)?;
    let heuristics = collect_principle_heuristics(&workspace)?;

    render_advisory(
        out,
        format,
        || to_json_string(&serde_json::json!({ "heuristics": heuristics })),
        |out| {
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
            Ok(())
        },
    )
}

/// Finds the pattern candidate `id` refers to, re-running the same analysis
/// [`collect_pattern_candidates`] does. Unknown id ⇒ [`CliError::Analyzer`]
/// (exit 2) — a usage error, not a findings verdict (todo.md §16.6's
/// `explain-pattern` acceptance criterion).
fn find_pattern_candidate(
    workspace: &judge::ingest::Workspace,
    id: &str,
) -> Result<judge::pattern::PatternCandidate, CliError> {
    collect_pattern_candidates(workspace, None)?
        .into_iter()
        .find(|candidate| candidate.id.as_str() == id)
        .ok_or_else(|| CliError::Analyzer(format!("unknown pattern candidate id: {id}")))
}

/// Rejects unsupported formats, loads the workspace, and resolves the
/// pattern candidate `id` refers to — the identical setup shared by
/// `explain-pattern` and `fix-preview` before they diverge on rendering.
fn load_pattern_candidate(
    id: &str,
    format: OutputFormat,
    command_name: &str,
) -> Result<judge::pattern::PatternCandidate, CliError> {
    reject_unsupported_advisory_format(format, command_name)?;
    let workspace = judge::ingest::load(None)?;
    find_pattern_candidate(&workspace, id)
}

/// Finds the principle heuristic `id` refers to, re-running the same
/// analysis [`collect_principle_heuristics`] does. Unknown id ⇒
/// [`CliError::Analyzer`] (exit 2) — a usage error, not a findings verdict,
/// mirroring [`find_pattern_candidate`]'s convention.
fn find_principle_heuristic(
    workspace: &judge::ingest::Workspace,
    id: &str,
) -> Result<judge::principle::PrincipleHeuristic, CliError> {
    collect_principle_heuristics(workspace)?
        .into_iter()
        .find(|heuristic| heuristic.id.as_str() == id)
        .ok_or_else(|| CliError::Analyzer(format!("unknown principle heuristic id: {id}")))
}

/// Renders a [`judge::pattern::CodeScope`]'s crate and modules. Shared by
/// [`print_pattern_candidate_tty`] and [`print_principle_heuristic_tty`],
/// whose `PatternCandidate`/`PrincipleHeuristic` types both scope themselves
/// with the same `CodeScope`.
fn print_scope_tty(
    out: &mut dyn Write,
    scope: &judge::pattern::CodeScope,
) -> std::io::Result<()> {
    writeln!(out, "  scope: crate `{}`", scope.krate)?;
    if !scope.modules.is_empty() {
        writeln!(out, "    modules:")?;
        for module in &scope.modules {
            writeln!(out, "      - {module}")?;
        }
    }
    Ok(())
}

/// Renders one [`judge::pattern::MigrationStep`] and its affected paths,
/// indented by `indent`. Shared by [`print_pattern_candidate_tty`] (nested
/// further under its own section indentation) and `run_fix_preview` (a
/// top-level rendering) — the affected-paths line is always three spaces
/// deeper than the step line in both callers.
fn print_migration_step_tty(
    out: &mut dyn Write,
    step: &judge::pattern::MigrationStep,
    indent: &str,
) -> std::io::Result<()> {
    writeln!(out, "{indent}{}. {}", step.step, step.description)?;
    for path in &step.affected_paths {
        writeln!(out, "{indent}   - {}", path.display())?;
    }
    Ok(())
}

/// Renders the `contraindications:` section — shared by
/// [`print_pattern_candidate_tty`] and [`print_principle_heuristic_tty`],
/// both of which list a `Vec<Contraindication>` the same way.
fn print_contraindications_tty(
    out: &mut dyn Write,
    contraindications: &[judge::pattern::Contraindication],
) -> std::io::Result<()> {
    writeln!(out, "  contraindications:")?;
    for contraindication in contraindications {
        writeln!(out, "    - {}", contraindication.description)?;
    }
    Ok(())
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
    print_scope_tty(out, &candidate.scope)?;
    print_evidence_tty(out, "primary", &candidate.evidence.primary)?;
    print_evidence_tty(out, "independent", &candidate.evidence.independent)?;
    for extra in &candidate.evidence.additional {
        print_evidence_tty(out, "additional", extra)?;
    }
    writeln!(out, "  preconditions:")?;
    for precondition in &candidate.preconditions {
        writeln!(out, "    - {}", precondition.description)?;
    }
    print_contraindications_tty(out, &candidate.contraindications)?;
    writeln!(out, "  migration plan (no patch — text only):")?;
    for step in &candidate.migration {
        print_migration_step_tty(out, step, "    ")?;
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
pub(super) fn run_explain_pattern(
    options: ExplainPatternOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainPatternOptions { id, format } = options;
    let candidate = load_pattern_candidate(&id, format, "`explain-pattern`")?;

    render_advisory(
        out,
        format,
        || to_json_string(&candidate),
        |out| to_cli_result(print_pattern_candidate_tty(out, &candidate)),
    )
}

/// Full TTY rendering of one principle heuristic: scope, evidence,
/// interpretation, contraindications, missing evidence, alternatives, and
/// related findings — mirrors [`print_pattern_candidate_tty`], adapted for
/// [`judge::principle::PrincipleHeuristic`]'s fields (no preconditions or
/// migration plan; those are `PatternCandidate`-only).
fn print_principle_heuristic_tty(
    out: &mut dyn Write,
    heuristic: &judge::principle::PrincipleHeuristic,
) -> std::io::Result<()> {
    writeln!(out, "principle heuristic: {}", heuristic.id)?;
    writeln!(out, "  principle: {}", heuristic.principle)?;
    print_scope_tty(out, &heuristic.scope)?;
    for (index, evidence) in heuristic.evidence.iter().enumerate() {
        print_evidence_tty(out, &(index + 1).to_string(), evidence)?;
    }
    writeln!(out, "  interpretation: {}", heuristic.interpretation)?;
    print_contraindications_tty(out, &heuristic.contraindications)?;
    writeln!(out, "  missing evidence:")?;
    for missing in &heuristic.missing_evidence {
        writeln!(out, "    - {}", missing.description)?;
    }
    writeln!(out, "  alternatives:")?;
    for alternative in &heuristic.alternatives {
        writeln!(out, "    - {}", alternative.description)?;
    }
    writeln!(out, "  related findings:")?;
    for finding_id in &heuristic.related_findings {
        writeln!(out, "    - {finding_id}")?;
    }
    Ok(())
}

/// `cargo judge explain-principle <id>` (todo.md §16.7, analogous to
/// `explain-pattern` todo.md §16.5/§16.6): the full evidence, interpretation,
/// contraindications, missing evidence, and alternatives behind one
/// principle heuristic.
pub(super) fn run_explain_principle(
    options: ExplainPrincipleOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainPrincipleOptions { id, format } = options;
    reject_unsupported_advisory_format(format, "`explain-principle`")?;
    let workspace = judge::ingest::load(None)?;
    let heuristic = find_principle_heuristic(&workspace, &id)?;

    render_advisory(
        out,
        format,
        || to_json_string(&heuristic),
        |out| to_cli_result(print_principle_heuristic_tty(out, &heuristic)),
    )
}

/// `cargo judge fix-preview <id>` (todo.md §16.5): only the migration plan
/// and the affected call sites (`related_findings`) — deliberately no
/// patch is generated or applied.
pub(super) fn run_fix_preview(
    options: FixPreviewOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let FixPreviewOptions { id, format } = options;
    let candidate = load_pattern_candidate(&id, format, "`fix-preview`")?;

    render_advisory(
        out,
        format,
        || {
            let json = serde_json::json!({
                "id": candidate.id,
                "pattern": candidate.pattern,
                "migration": candidate.migration,
                "related_findings": candidate.related_findings,
                "patch": serde_json::Value::Null,
                "note": "migration plan only — no patch is generated (see todo.md §16.5)",
            });
            to_json_string(&json)
        },
        |out| {
            writeln!(
                out,
                "fix preview for {} ({}) — no patch is generated, migration plan only:",
                candidate.id, candidate.pattern
            )?;
            for step in &candidate.migration {
                print_migration_step_tty(out, step, "  ")?;
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
            Ok(())
        },
    )
}

/// `cargo judge explain-rule <id>` (todo.md §17.5): a rule's fixed
/// documentation from [`judge::rule_registry`] — evidence class,
/// preconditions, exclusions, allowed wording, and verdict effect. A pure
/// static lookup: unlike `explain-pattern`/`fix-preview` it never loads the
/// workspace or runs analysis, so it never fails for an analyzer reason and
/// never produces `CommandOutcome::FindingsFound`.
pub(super) fn run_explain_rule(
    options: ExplainRuleOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let ExplainRuleOptions { id, format } = options;
    reject_unsupported_advisory_format(format, "`explain-rule`")?;
    let entry = judge::rule_registry::lookup(&id)
        .ok_or_else(|| CliError::Analyzer(format!("unknown rule id: {id}")))?;

    render_advisory(
        out,
        format,
        || {
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
            to_json_string(&json)
        },
        |out| {
            let evidence_class = serde_json::to_value(entry.evidence_class)?;
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
            Ok(())
        },
    )
}
