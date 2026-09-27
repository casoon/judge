---
title: Migrating to 0.6
description: 0.6.0 repositioned judge as a purely deterministic current-state analyzer. What was removed and what replaces it.
order: 3
---

Since 0.6.0, judge analyses the checked-out source tree, workspace structure, public APIs and
dependency graph only. It no longer inspects Git authorship, commit history, churn, bus factor or
code provenance, and it needs neither a `.git` directory nor network access.

## Removed and replaced

| Before (0.5.x) | Since 0.6.0 | Use instead |
| --- | --- | --- |
| `cargo judge distribution` | removed | `cargo judge structure` for crate and target metrics |
| `cargo judge provenance` | removed | `cargo judge slop` for mechanical code smells |
| `cargo judge audit --since <REF>` | removed | `cargo judge compare <BASELINE.json>` |
| Commit-bound baselines | deprecated | Artifact-based JSON baselines |
| `gix` dependency and `.git` check | removed | Works in archives, CI artifacts and vendored code |
| `ureq` HTTP dependency | optional | `--features network` |

`cargo judge refactor` gives a prioritised inspection queue where `distribution` was used for
triage.

## Baselines

A baseline no longer records a commit hash. It is a deterministic snapshot of findings, LOC
density and API surface sizes:

```sh
cargo judge --save-baseline               # writes .judge/baseline.json
cargo judge compare .judge/baseline.json  # introduced, resolved and changed findings
```

## crates.io checks

The network-backed rules of `deps --check-crates-io` need a build with the `network` feature:

```sh
cargo install cargo-judge                     # offline, no HTTP client compiled in
cargo install cargo-judge --features network  # enables crates.io lookups
```

## 0.7.0: library paths

0.7.0 moved the source into `rules/`, `advisory/` and `commands/`. Code that uses judge as a
library changes paths from `judge::X` to `judge::rules::X` or `judge::advisory::X`. The CLI is
unaffected.
