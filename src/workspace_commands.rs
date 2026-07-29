//! Lightweight workspace projections: inspection, refactoring map, and impact.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Current-state workspace architecture, deliberately independent of Git.
pub(super) fn run_structure(
    options: StructureOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let map = judge::refactor_map::analyze(&workspace, false);
    let graph = judge::boundaries::build_crate_graph(Some(&workspace.root.join("Cargo.toml")))?;

    match options.format {
        OutputFormat::Json => write_json(
            out,
            &serde_json::json!({
                "schema_version": 1,
                "workspace_root": workspace.root,
                "crates": workspace.crates.iter().map(|krate| serde_json::json!({
                    "name": krate.name,
                    "version": krate.version,
                    "manifest": krate.manifest_path,
                    "source_files": krate.source_files.len(),
                    "entry_points": krate.entry_points.iter().map(|entry| serde_json::json!({
                        "kind": entry.kind.label(),
                        "name": entry.name,
                        "path": entry.path,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "internal_dependency_edges": graph.edges,
                "complexity": map.crates,
                "files": map.files,
                "duplication": map.duplication,
                "analysis_errors": map.analysis_errors,
            }),
        )?,
        OutputFormat::Tty => {
            writeln!(
                out,
                "workspace structure: {} crates",
                workspace.crates.len()
            )?;
            for krate in &workspace.crates {
                writeln!(
                    out,
                    "  {} {} — {} source files",
                    krate.name,
                    krate.version,
                    krate.source_files.len()
                )?;
                for entry in &krate.entry_points {
                    writeln!(
                        out,
                        "    [{}] {}  {}",
                        entry.kind.label(),
                        entry.name,
                        entry.path.display()
                    )?;
                }
            }
            writeln!(out, "\ninternal dependency edges:")?;
            let mut names: Vec<_> = graph.edges.keys().collect();
            names.sort();
            for name in names {
                let dependencies = &graph.edges[name];
                if dependencies.is_empty() {
                    writeln!(out, "  {name} -> none")?;
                } else {
                    writeln!(out, "  {name} -> {}", dependencies.join(", "))?;
                }
            }
            writeln!(out, "\ncomplexity concentration (production code):")?;
            for krate in &map.crates {
                writeln!(
                    out,
                    "  {}  {} functions, {} total cyclomatic, {} max",
                    krate.name,
                    krate.production.functions,
                    krate.production.total_cyclomatic,
                    krate.production.max_cyclomatic
                )?;
            }
            if !map.analysis_errors.is_empty() {
                writeln!(out, "\nanalysis errors:")?;
                for error in map.analysis_errors {
                    writeln!(out, "  {error}")?;
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`structure`",
                options.format,
                "tty, json",
            ));
        }
    }
    Ok(CommandOutcome::Clean)
}

/// A focused projection of the measured complexity data already used by map.
pub(super) fn run_complexity(
    options: ComplexityOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let map = judge::refactor_map::analyze(&workspace, options.include_tests);
    match options.format {
        OutputFormat::Json => write_json(
            out,
            &serde_json::json!({
                "schema_version": 1,
                "includes_tests": map.includes_tests,
                "crates": map.crates,
                "files": map.files,
                "analysis_errors": map.analysis_errors,
            }),
        )?,
        OutputFormat::Tty => {
            writeln!(
                out,
                "complexity: {}",
                if map.includes_tests {
                    "production + tests"
                } else {
                    "production"
                }
            )?;
            for file in map
                .files
                .iter()
                .filter(|file| file.complexity_rank.is_some())
                .take(20)
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
            if !map.analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", map.analysis_errors.len())?;
            }
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`complexity`",
                options.format,
                "tty, json",
            ));
        }
    }
    Ok(CommandOutcome::Clean)
}

#[derive(Serialize)]
struct RefactorCandidate {
    file: PathBuf,
    severity: judge::finding::Severity,
    rules: Vec<String>,
    finding_ids: Vec<String>,
    items: Vec<String>,
    reason_count: usize,
}

/// Aggregates existing Fast-Tier findings into an inspection queue. It does
/// not invent a fix: every reason is a stable finding id supplied in output.
pub(super) fn run_refactor(
    options: RefactorOptions,
    out: &mut dyn Write,
) -> Result<CommandOutcome, CliError> {
    let workspace = judge::ingest::load(None)?;
    let mut collected = super::combined_analysis::collect_findings(&workspace)?;
    judge::finding::sort_by_severity_desc(&mut collected.findings);
    judge::finding::relativize_paths(&mut collected.findings, &workspace.root);

    let target = options.target.as_ref().map(|path| {
        path.strip_prefix(&workspace.root)
            .unwrap_or(path)
            .to_path_buf()
    });
    let mut grouped: BTreeMap<PathBuf, Vec<&Finding>> = BTreeMap::new();
    for finding in &collected.findings {
        if target
            .as_ref()
            .is_some_and(|target| &finding.location.file != target)
        {
            continue;
        }
        grouped
            .entry(finding.location.file.clone())
            .or_default()
            .push(finding);
    }
    let mut candidates = grouped
        .into_iter()
        .map(|(file, findings)| {
            let severity = findings
                .iter()
                .map(|finding| finding.severity)
                .max()
                .expect("a candidate contains at least one finding");
            let rules = findings
                .iter()
                .map(|finding| finding.rule.to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let items = findings
                .iter()
                .map(|finding| finding.location.item_path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            RefactorCandidate {
                file,
                severity,
                rules,
                finding_ids: findings
                    .iter()
                    .map(|finding| finding.id.to_string())
                    .collect(),
                items,
                reason_count: findings.len(),
            }
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.severity),
            std::cmp::Reverse(candidate.reason_count),
            candidate.file.clone(),
        )
    });
    let context_findings = collected
        .findings
        .iter()
        .filter(|finding| {
            target
                .as_ref()
                .is_none_or(|target| &finding.location.file == target)
        })
        .cloned()
        .collect::<Vec<_>>();

    match options.format {
        OutputFormat::Json => write_json(
            out,
            &serde_json::json!({
                "schema_version": 1,
                "scope": { "tier": "fast", "target": target },
                "analysis_errors": collected.analysis_errors,
                "candidates": candidates,
                "findings": context_findings,
                "contract": "Each candidate aggregates only the included findings. finding_ids resolve within this artifact to locations, evidence, limitations, and causal links; no candidate is an automatic refactoring instruction."
            }),
        )?,
        OutputFormat::Tty => {
            writeln!(out, "refactoring candidates: {}", candidates.len())?;
            for (index, candidate) in candidates.iter().enumerate() {
                writeln!(
                    out,
                    "  {}. [{}] {} — {} reasons: {}",
                    index + 1,
                    severity_label(candidate.severity),
                    candidate.file.display(),
                    candidate.reason_count,
                    candidate.rules.join(", ")
                )?;
            }
            if !collected.analysis_errors.is_empty() {
                writeln!(out, "analysis errors: {}", collected.analysis_errors.len())?;
            }
        }
        OutputFormat::Sarif | OutputFormat::Markdown => {
            return Err(unsupported_format(
                "`refactor`",
                options.format,
                "tty, json",
            ));
        }
    }
    Ok(CommandOutcome::Clean)
}

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
