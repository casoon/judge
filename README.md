# judge

> Deterministic post-refactoring analysis for Rust workspaces.

## Overview

`judge` analyzes the current Rust source tree, workspace structure, public APIs,
and dependency graph. It turns repeatable post-refactoring checks into
deterministic, evidence-backed findings. It is built as a Cargo subcommand
(binary `cargo-judge`), runnable both as `cargo judge` and standalone as
`cargo-judge`.

The guiding rule: anything the compiler or Clippy already tells you, `judge`
doesn't repeat. It covers structural and cross-file concerns that only become
visible across a workspace.

judge does not inspect authorship, commit history, telemetry, or code
provenance. Its results apply equally to human-written, generated, and
agent-refactored code.

Human-readable TTY reports use [runemark](https://github.com/casoon/runemark)
for consistent verdicts, evidence groups, source locations, color policy, and
next steps. JSON, SARIF, and Markdown remain explicit machine or handoff
contracts owned by judge.

See [MIGRATION.md](file:///Users/jseidel/GitHub/judge/MIGRATION.md) for breaking changes and CLI migration details.

## Status

Early stage. The Fast Tier (no build required, `syn`-, Cargo-metadata-, and manifest-based) and a first slice of the Deep Tier (rust-analyzer-based, behind the `deep` Cargo feature) are implemented:

- `cargo judge` — combined findings from every detector that does not require opt-in configuration; the default view is grouped for triage and `--details` lists every finding
- `cargo judge inspect` — crates, source files, and entry points detected via `cargo metadata`
- `cargo judge structure` — crates, targets, internal dependency edges, and measured structural concentration
- `cargo judge complexity` — current production/test complexity rankings from the checked-out source tree
- `cargo judge map` — compact workspace facts for refactoring plans: crates and
  files ordered by measured aggregate cyclomatic complexity; production and
  test-only code stay separate, and `--include-tests` opts tests into the
  ranking; it also lists the highest-volume clone families as inspection
  candidates; JSON is versioned for tooling, not an automatic recommendation
- `cargo judge impact PATH` — deterministic change context for one discovered
  Rust source file: crate targets and judge commands that read it directly;
  it does not predict individual findings or reachability
- `cargo judge health [--score]` — current-state complexity, syntax-level slop signals, and an optional health score (see below)
- `cargo judge dupes --mode strict|mild|weak|semantic [--include-tests]` — duplicated token spans grouped into clone families; test-only code is opt-in
- `cargo judge deps [--check-crates-io] [--audit-json PATH]` — dependency-kind hygiene plus local name-collision checks; the crates.io lookups (`phantom-crate`, `phantom-version`, `fresh-low-reputation-dep`, `yanked-dependency`, `dep-single-maintainer`) are opt-in because judge makes no network calls otherwise; `--audit-json` cross-references an already-generated `cargo audit --json` report against the resolved dependency graph (`known-vulnerability`) — judge never runs `cargo-audit` itself
- `cargo judge api` — focused public API surface analysis (the existing `api-surface` name remains available during migration)
- `cargo judge boundaries` — opt-in crate boundaries from `judge.toml`, plus dependency cycles; `--graph dot|mermaid` prints the crate dependency graph itself instead of checking rules
- `cargo judge errors`, `tests`, `unsafe`, `slop` — focused current-state projections with concrete locations and stated Fast-Tier limits
- `cargo judge refactor [PATH]` — deterministic, evidence-backed refactoring review queue; it never invents a patch
- `cargo judge compare BASELINE` — compares the current project state with a saved findings artifact; works without Git
- `cargo judge dead-code [--include-tests]` — Deep Tier, needs `--features deep` (see below)
- `cargo judge explain <item-path> --why-live` — Deep Tier, needs `--features deep` (see below)
- `--format json|sarif|markdown` — versioned JSON on every report command (written by default to `.judge/<command>.json`, or to `--output PATH`), SARIF 2.1.0 on the report-producing commands, and Markdown for the combined review summary and baseline delta
- `--save-baseline` / `--baseline PATH` — save or compare findings against a baseline

Every written JSON artifact starts with a `header`, followed by the command payload. It
records the working directory, output path, generation timestamp, a short
command description, and an assessment (`informational`, `review_recommended`,
`analysis_incomplete`, or `blocking_findings`). The assessment is a triage
hint, not an automatic refactoring instruction.

Not yet implemented: module-level boundaries (only crate-level exists), several planned maintainability and dependency-hygiene rules, and the MCP server.

## Health Score

`cargo judge health --score` prints a score from 0–100 plus a letter grade (A ≥90, B ≥80, C ≥70, D ≥60, F below). Deductions are severity-weighted and normalized by authored-LOC density; per-crate weighting profiles are opt-in via `judge.toml`.

Honest limits:

- The score is a configurable trend index, not an objective quality ranking. The delta against a baseline is the message, not the absolute number.
- A trend is only shown with `--baseline PATH`, and only when the baseline was produced with the same score formula version and the same crate profiles. Anything else is explicitly reported as not comparable instead of showing a false delta.
- When there is no basis to compute a score (e.g. no authored lines of code), the score is reported as unavailable and judge exits with code 2 — never a fake perfect score.

## Deep Tier (`--features deep`)

The Deep Tier loads the workspace into rust-analyzer (`ra_ap_ide`, `ra_ap_load-cargo`) to work with real reference data instead of syntax-level guesses. Building it compiles the `ra_ap_*` crates, which takes noticeably longer than the default build.

- `cargo judge dead-code [--include-tests]` — reports `unused-pub-workspace`: `pub` items with no reference from another workspace crate **and** no reachability from a recognized entry point of their own crate. This means "no use found in the examined view", not proven dead. `--include-tests` counts `#[test]`-only references as usage (off by default). Findings carry evidence (root-set size, searched crates, confidence reason) so you can judge the confidence yourself.
- `cargo judge explain <item-path> --why-live` — the shortest evidenced call path from a recognized entry point (`fn main` in bins/examples; tests and benches with `--include-tests`; `#[no_mangle]`/`#[export_name]`/`#[wasm_bindgen]` always) to the item. Each edge is classified as `static`/`dynamic`/`macro`/`generated`/`unknown`.

Known limits: the workspace is loaded without a proc-macro server and without running build scripts, so code produced by proc macros or `build.rs` is invisible to the analysis. Generic registration macros are not recognized either — an item that is only reached through one can be reported as unused.

## Why judge

- Deterministic findings, meant to be as readable for coding agents as for humans
- No linter, no formatter, no security scanner — it complements Clippy/cargo-audit, not replaces them
- No SaaS, no telemetry, no account

## Install

Requires Rust 1.95+ (edition 2024).

### Build from source

```bash
git clone https://github.com/casoon/judge.git
cd judge
cargo build --release
./target/release/cargo-judge --help
```

### crates.io

```bash
cargo install cargo-judge
```

### cargo install (local path)

```bash
cargo install --path . --force
```

## Usage

```bash
cargo judge                    # compact, structured combined triage report
cargo judge --color always     # force terminal colors (even with NO_COLOR set)
cargo judge --details          # every combined finding and source location
cargo judge --format markdown  # review report, written to .judge/judge.md
cargo judge inspect            # crates, entry points, detected tiers
cargo judge structure          # current workspace architecture
cargo judge complexity         # measured complexity concentrations
cargo judge refactor           # ranked evidence-backed review queue
cargo judge map --format json  # writes compact facts to .judge/map.json
cargo judge dupes --format json --output reports/dupes.json
cargo judge map --include-tests # include test-only code in map ranking
cargo judge impact src/lib.rs  # direct analysis and Cargo-target context
cargo judge --progress judge-progress.jsonl  # live, versioned JSONL phases
cargo judge dupes --mode mild  # production duplicate spans (test code: --include-tests)
cargo judge deps --format json # dependency findings as JSON
cargo judge health --score     # health score, 0-100 + letter grade
cargo judge --save-baseline    # save .judge/baseline.json
cargo judge --baseline .judge/baseline.json
cargo judge compare .judge/baseline.json  # current project state versus saved baseline
cargo judge dead-code          # Deep Tier — binary must be built with --features deep
```

`cargo judge --progress PATH` is available for the bare combined run. It
writes a flushed JSON Lines event stream to `PATH`; JSON reports are written
to `.judge/judge.json` by default (or `--output PATH`), while TTY/SARIF stay
on stdout. Each record has `schema_version`, `sequence`,
`event` (`phase_started`/`phase_completed`), and `phase`; it reports analysis
lifecycle only, never provisional findings.

The normal `cargo judge` terminal view is deliberately compact: it groups
evidence-backed findings and advisory heuristics by rule and shows a
representative location for each group. Use `cargo judge --details` for every
location, or `cargo judge --format json` for the complete versioned artifact.
Its TTY view uses color only on an interactive terminal and honours `NO_COLOR`;
use `--color always` or `--color never` to override that policy.

`cargo judge --format markdown` renders the same grouped summary as Markdown
for pull-request descriptions, issue comments, or other review handoffs: an
executive summary, evidence-backed and advisory groups with counts and
representative locations, and a next-steps section — never a raw per-finding
dump. It is written to `.judge/judge.md` by default, or to `--output PATH`.

## Intentional Duplicate Code

For a clearly intentional duplicate — for example an externally specified
protocol adapter or a deliberately parallel implementation — put a reasoned
comment immediately before each affected function:

```rust
// judge-dupe-ignore: required external protocol shape; keeping variants parallel
fn encode_v2(/* … */) { /* … */ }
```

The directive suppresses only that next function body. It requires a
non-empty reason and fails if it is not directly followed by a function, so a
stale comment cannot silently suppress unrelated code. Use it sparingly: it
documents an intentional exception; it is not a replacement for extracting a
shared abstraction. `// judge-dupe-off: <reason>` … `// judge-dupe-on` remains
available for a deliberately scoped multi-item range.

`dupes` treats a brace-delimited macro call with named fields (for example
`candidate! { evidence: ..., migration: ... }`) as declarative configuration,
not duplicated executable code. Ordinary macro calls remain part of the token
analysis.

The `map`, `impact`, and progress JSON contracts are covered by CLI tests, so
tooling can rely on their schema versions and their separation from stdout.

## Development

```bash
cargo build
cargo test
cargo test --features deep   # includes the Deep Tier (slow first build)
```

Optional Cargo feature:

| Feature | What it adds | Build command |
|---|---|---|
| `deep` | rust-analyzer-based deep tier (`ra_ap_ide`, `ra_ap_load-cargo`) | `cargo build --features deep` |

## License

Business Source License 1.1, see [LICENSE](LICENSE). Free for any use,
including production, except offering `cargo-judge` (or a modified version)
to third parties as a hosted/managed service or a competing product.
Converts to Apache License 2.0 four years after each version's release.
