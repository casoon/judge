//! `cargo judge audit`: baseline-delta gating and its focused rendering.

use super::*;

pub(super) fn run(options: AuditOptions, out: &mut dyn Write) -> Result<CommandOutcome, CliError> {
    let AuditOptions {
        since,
        format,
        baseline: baseline_path,
        audit_min_sample,
        max_duplication_ratio,
        max_suppression_ratio,
    } = options;
    let workspace = judge::ingest::load(None)?;

    let path = baseline_path.unwrap_or_else(|| workspace.root.join(DEFAULT_BASELINE_ALL));
    if !path.exists() {
        return Err(CliError::Config(format!(
            "{} not found — run `cargo judge --save-baseline` first",
            path.display()
        )));
    }
    let mut baseline = judge::baseline::load(&path)?;
    baseline.relativize_paths(&workspace.root);

    let _ = since;

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
        &std::collections::HashSet::new(),
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
                .introduced
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
            let sample_size = judge::health_score::total_authored_loc(&workspace) as u64;
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
                .introduced
                .iter()
                .filter(|finding| finding.rule == judge::slop::SUPPRESSION_DEBT_RULE)
                .count() as u64;
            let sample_size = judge::health_score::total_authored_loc(&workspace) as u64;
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
pub(super) fn combine_verdict(
    tri: TriVerdict,
    gate: Option<judge::gate::GateVerdict>,
) -> TriVerdict {
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
        .introduced
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
