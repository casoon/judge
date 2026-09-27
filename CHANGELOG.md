# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release dates are the dates the
versions were published on crates.io.

## [0.7.0] - 2026-08-29

### Added

- `cargo judge deps --why CRATE` shows one dependency's source usages, enabled features,
  dependency kind and resolved graph paths.
- `cargo judge refactor --format json` includes a ranked `next_actions` summary (top 10),
  derived from the same candidate ranking as the full list.

### Changed

- Source reorganised into `rules/`, `advisory/` and `commands/`. Library paths moved from
  `judge::X` to `judge::rules::X` and `judge::advisory::X`.

### Removed

- The dead `audit` tool of judge-mcp.

### Fixed

- `cargo judge dupes --format json` no longer truncates the family list to 5.
- Four false positives in the slop and structural rules, found by running judge on itself.

## [0.6.0] - 2026-07-29

### Breaking

- judge is now a purely deterministic current-state analyzer. It no longer reads Git history,
  authorship or churn.
- Removed `cargo judge distribution`, `cargo judge provenance` and `cargo judge audit --since`.
  Use `structure`, `slop` and `compare` instead; see MIGRATION.md.
- Baselines no longer record a commit hash; they are artifact-based JSON snapshots.

### Changed

- The `gix` dependency is gone, so judge works in archives, CI artifacts and vendored code.
- HTTP lookups against crates.io are compiled only with `--features network`.

## [0.5.2] - 2026-07-29

### Added

- `structure`, `complexity`, `refactor`, `api`, `errors`, `tests`, `unsafe` and `slop` as
  focused views of the current project state.
- `cargo judge compare` compares a saved baseline artifact with the current workspace.
- The bare `cargo judge` report groups findings by rule with a representative location;
  `--details` keeps the complete list.
- `cargo judge --format markdown` writes a review-ready summary to `.judge/judge.md`.

### Changed

- Terminal reports use a shared renderer for verdicts, evidence groups, source locations,
  colour policy and next steps.

## [0.2.0] - 2026-07-29

### Added

- JSON reports are written to `.judge/<command>.json` by default (`--output PATH` to override).
  Every artifact starts with a header and a non-binding triage assessment.
- `map` and `impact` expose workspace and change context for refactoring work.
- Duplicate-code output includes a prioritised refactoring summary.

## [0.1.0] - 2026-07-16

### Added

- First release: Fast Tier with `inspect`, `health` and `dupes`.
