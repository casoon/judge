# judge

> Codebase intelligence for Rust workspaces — deterministic findings, no server, no telemetry.

## Overview

`judge` analyzes Rust workspaces for complexity, duplication, dependency hygiene, architecture boundaries, ownership, slop signals, and git-derived hotspots. It's built as a Cargo subcommand (binary `cargo-judge`), runnable both as `cargo judge` and standalone as `cargo-judge`.

The guiding rule: anything the compiler or Clippy already tells you, `judge` doesn't repeat. It covers what sits above the crate boundary, across git history, or aggregated over multiple tools.

## Status

Early stage — only the Fast Tier (no build required, `syn`-based) is implemented:

- `cargo judge inspect` — crates, source files, and entry points detected via `cargo metadata`
- `cargo judge` — combined findings from every detector that does not require opt-in configuration
- `cargo judge health` — cyclomatic complexity, git hotspots, and syntax-level slop signals
- `cargo judge dupes --mode strict|mild` — duplicated token spans grouped into clone families
- `cargo judge deps` — dependency-kind hygiene
- `cargo judge boundaries` — opt-in crate boundaries from `judge.toml`, plus dependency cycles
- `cargo judge distribution` — ownership and bus-factor findings from git blame
- `--format json` — versioned machine-readable output
- `--save-baseline` / `--baseline PATH` — save or compare findings against a baseline

Not yet implemented: health score, semantic duplicate detection, SARIF output, the Deep Tier (rust-analyzer-based reachability), and MCP server.

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
cargo judge --save-baseline    # save .judge/baseline.json
cargo judge --baseline .judge/baseline.json
cargo judge health --score     # health score (not implemented yet)
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
```

Optional Cargo feature:

| Feature | What it adds | Build command |
|---|---|---|
| `deep` | rust-analyzer-based deep tier (`ra_ap_ide`, `ra_ap_load-cargo`) | `cargo build --features deep` |

## License

MIT, see [LICENSE](LICENSE).
