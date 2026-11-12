# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release dates are the dates the
versions were published on crates.io.

## [Unreleased]

### Changed

- **Pages:** the project site uses the current shared theme (0.12.12).
- **`untested-hotspot`:** flags high-complexity, mostly uncovered functions without a churn
  criterion (judge reads no Git history). Before, `cargo judge coverage` could never report it.

### Fixed

- **Baselines:** a finding that only moved because of an edit above it is no longer reported as
  resolved plus introduced; `--baseline` matches the rest per rule and file.
- **`dupes --mode strict`:** no longer panics on a doc comment inside a duplicated body.
- **`dupes`:** a checkout below a `tests/` or `benches/` directory is no longer skipped; only
  directories inside the package count.
- **`panic-in-lib`:** detects `panic!(..);` written as a statement.
- **JSON output:** `--format json --save-baseline` and `boundaries --format json` without a
  `judge.toml` print their status line instead of failing with exit 2.
- **JSON header:** the assessment counts findings of `slop`, `errors`, `tests` and `unsafe`, and
  the `analysis_errors` of `map`, `structure`, `complexity` and `refactor`.
- **`unreachable-from-entry` (deep tier):** no longer reports non-`pub` types, trait-impl methods,
  tests, proc-macro or build-script functions and functions named in a same-file `const`/`static`;
  a publishable library's public API counts as entry points. Findings state the macro limit.
- **`connectivity-drop` (deep tier):** no longer reports `fn main`, test helpers, FFI exports and
  proc-macro entry points.
- **`deps --check-crates-io`:** path, git and alternate-registry dependencies are no longer looked
  up on crates.io, so internal crates are not reported as phantom crates and their names are not
  sent out.
- **Dependencies:** a renamed dependency (`package = ".."`) with a `-` in its alias is matched
  against its `_` identifier in code.
- **`deps --audit-json`:** a file that is not a `cargo audit --json` report is an error instead of
  "no vulnerabilities".
- **`judge.toml`:** a misspelled key in `[[boundary]]` or `[[module_boundary]]` is rejected, and a
  `[[boundary]]` with neither `forbidden` nor `required` is an error instead of a rule that never
  fires.
- **CLI help and README:** removed remaining `todo.md` references and the outdated note that
  module-level boundaries are missing.
- **`module-graph`:** `mod x;` inside an inline `mod { .. }` resolves below it, and
  `pub use self::x::Y` counts as a reference to `x`.

## [0.7.1] - 2026-10-31

### Changed

- **CLI help and `explain-rule`:** removed references to the internal, unpublished `todo.md`.
- **README:** lists every subcommand and the `network` feature.
- **Project site:** the start page shows an animated terminal scene from real judge output and
  a diagram of the baseline-to-verdict flow; install variants, `judge.toml`, the CI step and the
  deep tier are covered in the [documentation](https://casoon.github.io/judge/docs/).
- **Docs:** the [Baselines and CI](https://casoon.github.io/judge/docs/guides/baselines-and-ci/)
  guide shows how `cargo judge compare` reaches its verdict and exit code as a diagram.
- **Project site:** the start page now carries a release teaser and an FAQ (theme 0.11.1).

### Fixed

- **Docs:** the library API docs build without warnings, with and without `--all-features`;
  links to private, feature-gated or removed items are now plain code spans.

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
