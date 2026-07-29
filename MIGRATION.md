# Migration Guide: cargo-judge 0.6.0 (Post-Refactoring Architecture)

## Overview

Starting with version `0.6.0`, `cargo-judge` has been repositioned as a **purely deterministic, post-refactoring analysis tool for Rust workspaces**.

It analyzes the checked-out source tree, workspace structure, public APIs, and dependency graph. It does **not** inspect Git authorship, commit history, churn, bus factor, or code provenance.

> **Guiding Principle**: Anything the compiler or Clippy already tells you, `judge` doesn't repeat. `judge` covers structural, architectural, and cross-crate concerns without requiring a `.git` repository or network access.

---

## Breaking Changes Summary

| Old Feature / Command | Status in 0.6.0+ | Replacement / Alternative |
|---|---|---|
| `cargo judge distribution` | **Removed** | Use `cargo judge structure` for workspace crate & target metrics |
| `cargo judge provenance` | **Removed** | Use `cargo judge slop` for mechanical code smells |
| `cargo judge audit --since <REF>` | **Removed** | Use `cargo judge compare <BASELINE.json>` for artifact deltas |
| Git commit-bound baselines | **Deprecated** | All baselines are artifact-based JSON snapshots |
| `gix` dependency & `.git` check | **Removed** | Works in archives, CI artifacts, and vendored code |
| `ureq` HTTP dependency | **Optional** | Network calls gated behind `cargo build --features network` |

---

## Subcommand Changes

### 1. `distribution` and `provenance` Removal
The `distribution` (bus factor, ownership fragmentation) and `provenance` (author class classification, agent attribution) subcommands have been permanently removed.

* **Before (0.5.x)**: `cargo judge distribution`, `cargo judge provenance`
* **After (0.6.0+)**: Use `cargo judge structure` for current-state structural concentration and `cargo judge refactor` for a prioritized inspection queue.

---

### 2. Baseline Comparison (`compare`)
Baselines no longer record or require a Git commit hash. A baseline artifact is a deterministic snapshot of project findings, LOC density, and API surface sizes.

* **Saving a Baseline**:
  ```bash
  cargo judge --save-baseline
  # Writes .judge/baseline.json
  ```

* **Comparing Current State against Baseline**:
  ```bash
  cargo judge compare .judge/baseline.json
  ```
  Reports introduced, resolved, and severity-changed findings without reading Git logs or diffs.

---

### 3. Optional Network Feature for Crates.io Checks
Network operations (`phantom-crate`, `phantom-version`, `fresh-low-reputation-dep`) in `cargo judge deps --check-crates-io` now require building with the `network` feature flag:

```bash
# Offline build (default, no network code compiled):
cargo build --release

# Network-enabled build:
cargo build --release --features network
```

---

## Output Formats & Contracts

* **TTY (Default)**: Uses `runemark` for compact, representative findings grouped by rule with actionable next steps.
* **JSON (`--format json`)**: Exhaustive machine contract saved by default to `.judge/<command>.json` (or `--output PATH`).
* **SARIF (`--format sarif`)**: Standard SARIF 2.1.0 log for CI/CD code scanning integrations.
* **Markdown (`--format markdown`)**: Review-ready PR summary saved to `.judge/judge.md`.
