# judge

> Codebase intelligence for Rust workspaces — deterministic findings, no server, no telemetry.

## Overview

`judge` analyzes Rust workspaces for complexity, duplication, dependency hygiene, architecture boundaries, ownership, slop signals, and git-derived hotspots. It's built as a Cargo subcommand (binary `cargo-judge`), runnable both as `cargo judge` and standalone as `cargo-judge`.

The guiding rule: anything the compiler or Clippy already tells you, `judge` doesn't repeat. It covers what sits above the crate boundary, across git history, or aggregated over multiple tools.

## Status

Early stage. The Fast Tier (no build required, `syn`- and `gix`-based) and a first slice of the Deep Tier (rust-analyzer-based, behind the `deep` Cargo feature) are implemented:

- `cargo judge` — combined findings from every detector that does not require opt-in configuration, worst first
- `cargo judge inspect` — crates, source files, and entry points detected via `cargo metadata`
- `cargo judge health [--score]` — cyclomatic complexity, git hotspots, syntax-level slop signals, and an optional health score (see below)
- `cargo judge dupes --mode strict|mild|weak|semantic` — duplicated token spans grouped into clone families
- `cargo judge deps [--check-crates-io]` — dependency-kind hygiene plus local name-collision checks; the crates.io lookups (`phantom-crate`, `phantom-version`, `fresh-low-reputation-dep`) are opt-in because judge makes no network calls otherwise
- `cargo judge boundaries` — opt-in crate boundaries from `judge.toml`, plus dependency cycles
- `cargo judge distribution` — ownership and bus-factor findings from git blame
- `cargo judge audit --since REF` — pass/warn/fail verdict scoped to findings introduced since a commit; requires a previously saved baseline
- `cargo judge dead-code [--include-tests]` — Deep Tier, needs `--features deep` (see below)
- `cargo judge explain <item-path> --why-live` — Deep Tier, needs `--features deep` (see below)
- `--format json` — versioned machine-readable output
- `--save-baseline` / `--baseline PATH` — save or compare findings against a baseline

Not yet implemented: SARIF/Markdown output, module-level boundaries (only crate-level exists), several planned maintainability and dependency-hygiene rules, and the MCP server.

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

### cargo install (local path)

```bash
cargo install --path . --force
```

## Usage

```bash
cargo judge                    # combined findings, worst first
cargo judge inspect            # crates, entry points, detected tiers
cargo judge dupes --mode mild  # duplicated token spans (clone families)
cargo judge deps --format json # dependency findings as JSON
cargo judge health --score     # health score, 0-100 + letter grade
cargo judge --save-baseline    # save .judge/baseline.json
cargo judge --baseline .judge/baseline.json
cargo judge audit --since origin/main  # pass/warn/fail verdict for a PR
cargo judge dead-code          # Deep Tier — binary must be built with --features deep
```

## Provenance Attribution

`cargo judge provenance` breaks churn, duplication, and suppression debt down
by heuristically classified author class (commit trailers/markers like
`Co-authored-by: Claude`, or a configured `[[provenance_label]]`). It is
opt-in — not part of bare `cargo judge` — and always prints this caveat:

> Provenance labels are a distribution trend, not a judgment on any single
> commit or person. Trailers and metadata are incomplete and can be
> manipulated; the heuristics are weak. Valid as a trend, not valid as a
> gate. Using this to evaluate individual people is a misuse of this tool.

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

MIT, see [LICENSE](LICENSE).
