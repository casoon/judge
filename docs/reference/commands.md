---
title: Commands
description: Every cargo judge subcommand in 0.7.0, the global options and the exit-code convention.
order: 1
---

Run `cargo judge --help` or `cargo judge <command> --help` for the complete option list of the
installed version.

## Combined report

| Command | What it does |
| --- | --- |
| `cargo judge` | Combined findings from every detector that needs no opt-in configuration, grouped for triage. `--details` lists every finding. `--progress PATH` writes JSON Lines phase events. |

## Workspace context

| Command | What it does |
| --- | --- |
| `inspect` | Crates, source files, entry points and available tiers, via `cargo metadata`. |
| `structure` | Crates, targets, internal dependency edges and measured structural concentration. |
| `complexity` | Production and test complexity rankings from the checked-out tree. |
| `map` | Compact facts for refactoring plans: files by aggregate cyclomatic complexity and the largest clone families. `--include-tests` adds test-only code. |
| `impact PATH` | Crate targets and judge commands that read one Rust source file directly. It does not predict findings. |

## Focused analyses

| Command | What it does |
| --- | --- |
| `health [--score]` | Complexity, syntax-level slop signals and an optional 0–100 health score with letter grade. |
| `dupes --mode strict\|mild\|weak\|semantic` | Duplicated token spans grouped into clone families. Default `mild`, minimum 20 tokens; test code with `--include-tests`. |
| `deps` | Dependency-kind hygiene and local name-collision checks. Opt-in: `--check-crates-io`, `--check-rustc-lints`, `--audit-json PATH`. `--why CRATE` explains one dependency instead. |
| `api` | Focused public API surface analysis (`api-surface` remains available). |
| `boundaries` | Crate boundaries from `judge.toml` plus dependency cycles. `--graph dot\|mermaid` prints the crate graph instead. |
| `module-graph` | `unlinked-file` and `orphan-module` findings from each crate's real `mod` tree. |
| `errors`, `tests`, `unsafe`, `slop` | Focused current-state views with concrete locations and stated Fast-Tier limits. |
| `coverage` | Imports an existing `cargo-llvm-cov` LCOV report and flags `untested-hotspot` functions. judge never measures coverage itself. |

## Refactoring support

| Command | What it does |
| --- | --- |
| `refactor [PATH]` | Deterministic, evidence-backed review queue. With `--format json` it adds a ranked `next_actions` summary (top 10). It never writes a patch. |
| `patterns`, `principles` | Heuristic design-pattern and design-principle readings. Advisory only; they never affect the verdict or exit code. |
| `explain-pattern`, `explain-principle` | Full evidence, preconditions and contraindications of one candidate. |
| `fix-preview` | The migration plan and affected call sites of a pattern candidate — deliberately no patch. |
| `explain-rule ID` | Documentation of one rule from the static registry. See [Rules](../rules/). |

## Baselines

| Command | What it does |
| --- | --- |
| `--save-baseline` | Saves the current findings to `.judge/baseline.json`. |
| `--baseline PATH` | Compares a report with a saved baseline. |
| `compare BASELINE` | Compares the current project state with a saved baseline artifact. Never reads Git history. |

## Deep Tier (`--features deep`)

| Command | What it does |
| --- | --- |
| `dead-code [--include-tests]` | `pub` items with no reference from another workspace crate and no reachability from an entry point of their own crate. |
| `explain <item-path> --why-live` | The shortest evidenced call path from an entry point to the item. |

## Global options

| Option | Effect |
| --- | --- |
| `--format tty\|json\|sarif\|markdown` | Output format. See [Output formats](../../guides/output-formats/). |
| `--output PATH` | Artifact path instead of the default `.judge/<command>.json` or `.judge/judge.md`. |
| `--color auto\|always\|never` | Colour policy of the combined report. `auto` honours `NO_COLOR`. |
| `--details` | Every finding in the combined terminal report. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean. Commands without a verdict always exit 0. A closed stdout (broken pipe) also exits 0. |
| `1` | A baseline verdict failed on introduced gating findings. |
| `2` | A real error: broken `judge.toml` or baseline, analyzer or toolchain failure, an unavailable health score, or incomplete analysis. |
