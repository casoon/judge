---
title: Quickstart
description: Run judge on a workspace, read the grouped report, drill into details and save a first baseline.
order: 2
---

Run every command from the workspace root.

## Run the combined report

```sh
cargo judge
```

The bare command runs every detector that needs no opt-in configuration. The terminal view is
deliberately compact: findings are grouped by rule, split into **evidence-backed findings** and
**advisory heuristics** (no verdict or score effect), each with a representative location, and
followed by the next commands to run. The [showcase](../../../showcase/combined-report/) shows the
report for judge's own source tree.

Colour is used only on an interactive terminal and honours `NO_COLOR`; `--color always` or
`--color never` overrides that.

## Drill down

```sh
cargo judge --details          # every finding and location
cargo judge dupes              # clone families, grouped and prioritised
cargo judge refactor           # ranked, evidence-backed review queue
cargo judge health --score     # complexity, slop signals and a 0–100 score
cargo judge explain-rule swallowed-result   # what a rule checks and where it stops
```

## Keep the results

```sh
cargo judge --format json      # writes .judge/judge.json
cargo judge --format markdown  # writes .judge/judge.md for a pull request
cargo judge --save-baseline    # writes .judge/baseline.json
```

Consider adding `.judge/` to `.gitignore` unless you want to commit a baseline.

## Compare later

```sh
cargo judge compare .judge/baseline.json
```

`compare` reports unchanged, resolved and introduced findings and a verdict. See
[Baselines and CI](../../guides/baselines-and-ci/) for exit codes and a CI setup.
