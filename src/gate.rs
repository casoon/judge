//! Small-sample guard for ratio/density gates (see todo.md §6 "Kleine
//! Stichproben", §14.2 P0#6).
//!
//! A percentage-based gate (duplication ratio, coverage, suppression rate,
//! …) is meaningless on a tiny sample: a single duplicated line in a 10-line
//! PR is a disproportionate 10%, while the same line in a 10,000-line change
//! is noise. [`evaluate_ratio_gate`] withholds judgement below a configured
//! `minimum_sample` instead of forcing a pass or fail on too little data.
//!
//! Two concrete gates are wired to opt-in CLI thresholds on `cargo judge
//! audit --since` (`--max-duplication-ratio` and `--max-suppression-ratio`,
//! sharing `--audit-min-sample`) — todo.md deliberately avoids prescribing a
//! default (§4 "nicht optimierbar", §11 "Score-Gaming"), so each gate stays
//! off until its threshold is given explicitly. This module provides the
//! primitive; a gate only supplies its own numerator, sample size, and
//! threshold.

use serde::Serialize;

/// Outcome of a ratio-based gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Fail,
    /// `sample_size` was below `minimum_sample` — the gate did not run.
    NotEvaluatedSmallSample,
}

/// Evaluates `numerator / sample_size` against `max_ratio`, but only once
/// `sample_size` reaches `minimum_sample`. A `sample_size` of zero is always
/// too small to judge, regardless of `minimum_sample`.
pub fn evaluate_ratio_gate(
    numerator: u64,
    sample_size: u64,
    minimum_sample: u64,
    max_ratio: f64,
) -> GateVerdict {
    if sample_size == 0 || sample_size < minimum_sample {
        return GateVerdict::NotEvaluatedSmallSample;
    }
    let ratio = numerator as f64 / sample_size as f64;
    if ratio > max_ratio {
        GateVerdict::Fail
    } else {
        GateVerdict::Pass
    }
}

/// A named ratio gate together with its inputs and verdict, suitable for
/// inclusion in a report so the guard is visible, not just its outcome.
#[derive(Debug, Clone, Serialize)]
pub struct RatioGate {
    pub name: String,
    pub numerator: u64,
    pub sample_size: u64,
    pub minimum_sample: u64,
    pub max_ratio: f64,
    pub verdict: GateVerdict,
}

pub fn ratio_gate(
    name: &str,
    numerator: u64,
    sample_size: u64,
    minimum_sample: u64,
    max_ratio: f64,
) -> RatioGate {
    RatioGate {
        name: name.to_string(),
        numerator,
        sample_size,
        minimum_sample,
        max_ratio,
        verdict: evaluate_ratio_gate(numerator, sample_size, minimum_sample, max_ratio),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_minimum_sample_is_not_evaluated_regardless_of_ratio() {
        // 5/10 = 50%, would fail any reasonable threshold, but the sample is
        // too small (minimum 100) to judge.
        let verdict = evaluate_ratio_gate(5, 10, 100, 0.05);
        assert_eq!(verdict, GateVerdict::NotEvaluatedSmallSample);
    }

    #[test]
    fn zero_sample_is_not_evaluated_even_with_zero_minimum() {
        let verdict = evaluate_ratio_gate(0, 0, 0, 0.05);
        assert_eq!(verdict, GateVerdict::NotEvaluatedSmallSample);
    }

    #[test]
    fn at_minimum_sample_with_ratio_within_threshold_passes() {
        // 4/100 = 4% <= 5% threshold.
        let verdict = evaluate_ratio_gate(4, 100, 100, 0.05);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn at_minimum_sample_with_ratio_over_threshold_fails() {
        // 6/100 = 6% > 5% threshold.
        let verdict = evaluate_ratio_gate(6, 100, 100, 0.05);
        assert_eq!(verdict, GateVerdict::Fail);
    }

    #[test]
    fn ratio_gate_carries_its_inputs_alongside_the_verdict() {
        let gate = ratio_gate("duplication-ratio", 6, 100, 100, 0.05);

        assert_eq!(gate.name, "duplication-ratio");
        assert_eq!(gate.verdict, GateVerdict::Fail);
    }
}
