//! Lightweight workspace projections: inspection, refactoring map, and impact.

use super::*;

pub(super) fn run_inspect(out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
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

/// `cargo judge map`: concise workspace facts ordered by measured aggregate
/// cyclomatic complexity. This is a planning aid, not a verdict or an
/// automatic refactoring recommendation.
pub(super) fn run_map(
    options: MapOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let map = judge::refactor_map::analyze(&workspace, options.include_tests);

    match options.format {
        OutputFormat::Json => {
            writeln!(out, "{}", serde_json::to_string_pretty(&map).unwrap())?;
        }
        OutputFormat::Tty => {
            let authored_files = map
                .files
                .iter()
                .filter(|file| file.source_kind == "authored")
                .count();
            writeln!(
                out,
                "workspace map: {} crates, {authored_files} authored files",
                map.crates.len()
            )?;
            if !map.analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", map.analysis_errors.len())?;
                for error in &map.analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
            writeln!(out)?;
            writeln!(
                out,
                "complexity attention ({}, measured total cyclomatic, not a verdict):",
                if map.includes_tests {
                    "production + test code"
                } else {
                    "production code"
                }
            )?;
            for file in map
                .files
                .iter()
                .filter(|file| file.complexity_rank.is_some())
                .take(15)
            {
                let metrics = file.complexity_in_scope(map.includes_tests);
                writeln!(
                    out,
                    "  #{:<2} {:>4} total, {:>3} max, {:>3} functions  {}",
                    file.complexity_rank.unwrap(),
                    metrics.total_cyclomatic,
                    metrics.max_cyclomatic,
                    metrics.functions,
                    file.file.display()
                )?;
            }
            writeln!(out)?;
            writeln!(
                out,
                "duplication attention (repeated tokens, not an automatic merge recommendation):"
            )?;
            if map.duplication.top_families.is_empty() {
                writeln!(out, "  none at the configured threshold")?;
            }
            for family in &map.duplication.top_families {
                writeln!(
                    out,
                    "  #{}  {} members × {} tokens across {} files  {}",
                    family.rank,
                    family.members,
                    family.tokens_per_member,
                    family.files.len(),
                    family.representative_items.join(", ")
                )?;
            }
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format("`map`", options.format, "tty, json"));
        }
    }
    Ok(CommandOutcome::Clean)
}

/// `cargo judge impact <PATH>`: metadata-backed context for planning a change
/// to one source file. It identifies direct analysis inputs; it intentionally
/// does not guess which individual findings will result from an edit.
pub(super) fn run_impact(
    options: ImpactOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let impact = judge::impact::analyze(&workspace, &options.target)
        .map_err(|err| CliError::Config(err.to_string()))?;

    match options.format {
        OutputFormat::Json => {
            writeln!(out, "{}", serde_json::to_string_pretty(&impact).unwrap())?;
        }
        OutputFormat::Tty => {
            writeln!(out, "impact: {}", impact.target.display())?;
            writeln!(out, "crate: {}", impact.crate_name)?;
            writeln!(
                out,
                "source: {} ({})",
                impact.source_kind, impact.source_domain
            )?;
            writeln!(out)?;
            writeln!(
                out,
                "Cargo targets in this crate (shared crate, not reachability proof):"
            )?;
            for target in &impact.crate_targets {
                writeln!(
                    out,
                    "  {}:{}  {}{}",
                    target.kind,
                    target.name,
                    target.source.display(),
                    if target.is_target_root {
                        " (this file)"
                    } else {
                        ""
                    }
                )?;
            }
            writeln!(out)?;
            writeln!(out, "direct analysis inputs (not a finding prediction):")?;
            for effect in &impact.direct_analysis {
                if effect.included_by_default {
                    writeln!(out, "  included  {:<30} {}", effect.command, effect.input)?;
                } else {
                    writeln!(
                        out,
                        "  excluded  {:<30} {} ({})",
                        effect.command,
                        effect.input,
                        effect.required_opt_in.unwrap_or("opt-in required")
                    )?;
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format("`impact`", options.format, "tty, json"));
        }
    }
    Ok(CommandOutcome::Clean)
}
