---
title: Overview
description: What judge analyses, what it deliberately leaves out, and how this documentation is organised.
order: 0
---

judge is a Cargo subcommand (binary `cargo-judge`) for Rust workspaces. It reads the checked-out
source tree, the workspace structure from `cargo metadata`, the public APIs and the dependency
graph, and turns repeatable post-refactoring checks into deterministic, evidence-backed findings.
It runs as `cargo judge` or standalone as `cargo-judge`.

The guiding rule: anything the compiler or Clippy already tells you, judge does not repeat. It
covers structural and cross-file concerns that only become visible across a workspace:
duplication, complexity concentration, dependency hygiene, crate boundaries, public API surface,
error handling, unsafe structure and mechanical code smells.

## What it does not do

- It does not read Git history, authorship, churn or code provenance. Results apply equally to
  code written by people, generated or refactored by agents, and it works in archives, CI
  artifacts and vendored code.
- It is not a linter, formatter or security scanner. It complements Clippy and cargo-audit; an
  existing `cargo audit --json` report can be cross-referenced, but judge never runs cargo-audit.
- It makes no network calls unless it is built with the `network` feature and asked for
  crates.io lookups. There is no SaaS, account or telemetry.
- It never writes a patch. `refactor` and `fix-preview` rank candidates and describe migrations;
  changing the code stays with you.

## Two tiers

- **Fast Tier** — no build required. Based on `syn`, Cargo metadata and the manifests. This is
  what `cargo judge` and most subcommands run.
- **Deep Tier** — loads the workspace into rust-analyzer. Compiled only with `--features deep`;
  it powers `dead-code` and `explain --why-live`. See [Deep Tier](guides/deep-tier/).

## Status

judge is early-stage software. Module-level boundaries exist only in a first form, and several
planned maintainability and dependency-hygiene rules are not implemented yet.

## How the docs are organised

- **Getting started**: install judge and run a first analysis.
- **Guides**: baselines and CI, output formats, crate boundaries, duplicate code, the Deep Tier
  and the MCP adapter.
- **Reference**: commands, the rule registry and the 0.6.0 migration. Item-level documentation
  of the library crate lives on [docs.rs](https://docs.rs/cargo-judge).
