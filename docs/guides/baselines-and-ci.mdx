---
title: Baselines and CI
description: Save findings as an artifact, compare later trees with it, and turn the verdict into a CI gate.
order: 1
---

A baseline is a JSON snapshot of the findings of one tree. judge compares later trees with it
without reading Git history, so it works the same on a laptop, in CI and on an unpacked archive.

## Save a baseline

```sh
cargo judge --save-baseline
# baseline saved: .judge/baseline.json (N findings)
```

## Compare

```sh
cargo judge compare .judge/baseline.json
```

The report lists `unchanged`, `resolved` and `introduced` findings and a verdict. Introduced
advisory findings are listed separately and have no verdict effect. The
[baseline compare example](../../../showcase/baseline-compare/) shows a real run: judge 0.7.0
compared with a baseline saved right after its own source reorganisation.

For a pull-request comment, render the delta as Markdown:

```sh
cargo judge compare .judge/baseline.json --format markdown
```

## The verdict

The verdict fails when the comparison introduces gating findings with warning or failure
severity. Heuristic (advisory) findings never fail it.

| Exit code | Meaning |
| --- | --- |
| `0` | Verdict passes. |
| `1` | Verdict fails on introduced gating findings. |
| `2` | Error: unreadable or unsupported baseline, broken `judge.toml`, analyzer failure. No verdict is given on incomplete analysis. |

## In CI

Commit the baseline (or restore it as a CI artifact) and let a job compare against it. A GitHub
Actions step could look like this:

```yaml
- name: judge
  run: |
    cargo install cargo-judge --locked
    cargo judge compare .judge/baseline.json
```

Refresh the baseline deliberately, with `cargo judge --save-baseline`, when you accept the new
state.

## Health score trends

`cargo judge health --score` prints a score from 0 to 100 and a letter grade (A ≥ 90, B ≥ 80,
C ≥ 70, D ≥ 60, F below). Deductions are severity-weighted and normalised by authored-LOC density;
advisory findings are not scored.

- The score is a configurable trend index, not an objective quality ranking. The delta against a
  baseline is the message, not the absolute number.
- A trend is shown only with `--baseline PATH`, and only when the baseline used the same score
  formula version and the same crate profiles. Anything else is reported as not comparable.
- Without a basis for a score, for example no authored lines of code, the score is reported as
  unavailable and judge exits with 2 — never a fake perfect score.

Per-crate weighting profiles are opt-in in `judge.toml`:

```toml
[[crate_profile]]
name = "parsers"
crates = ["my-parser"]
deduction_multiplier = 0.5
```
