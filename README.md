# judge

> Codebase intelligence for Rust workspaces — deterministic findings, no server, no telemetry.

## Overview

`judge` analyzes Rust workspaces for complexity, duplication, and git-derived hotspots. It's built as a Cargo subcommand (binary `cargo-judge`), runnable both as `cargo judge` and standalone as `judge`.

The guiding rule: anything the compiler or Clippy already tells you, `judge` doesn't repeat. It covers what sits above the crate boundary, across git history, or aggregated over multiple tools.

## Status

Early stage — only the Fast Tier (no build required, `syn`-based) is implemented:

- `cargo judge inspect` — crates, source files, and entry points detected via `cargo metadata`
- `cargo judge health` — cyclomatic complexity per function, plus git hotspots (complexity × change frequency, via `gix`)
- `cargo judge dupes --mode strict|mild` — duplicated function bodies grouped into clone families

Not yet implemented: health score, ownership/bus-factor analysis, semantic duplicate detection, JSON/SARIF output, baselines, the Deep Tier (rust-analyzer-based reachability), dependency hygiene checks, AI-slop signals, MCP server.

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
cargo judge                    # health summary: complexity + hotspots
cargo judge inspect            # crates, entry points, detected tiers
cargo judge dupes --mode mild  # duplicated function bodies (clone families)
cargo judge health --score     # health score (not implemented yet)
```

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
