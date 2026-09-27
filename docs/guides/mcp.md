---
title: MCP adapter
description: judge-mcp exposes cargo-judge's JSON output to MCP clients over stdio. It computes nothing itself.
order: 6
---

`judge-mcp` lives in the [`judge-mcp/`](https://github.com/casoon/judge/tree/main/judge-mcp)
directory of the repository. It is a thin stdio adapter: every tool call runs an already-built
`cargo-judge` binary and returns its `--format json` output to the MCP client. No state, no
cloud, no network beyond that local subprocess. It is not published to a registry, and it is not
a requirement of judge.

## Build

```sh
cd judge-mcp
npm install
npm run build   # produces dist/index.js
```

It needs Node.js 18 or newer and the `cargo-judge` binary. `JUDGE_BINARY` sets the path to the
binary; by default `cargo-judge` must be on `PATH`. If the binary cannot be started, the affected
tool call returns an error explaining how to fix it; the server itself still starts.

## Client configuration

```json
{
  "mcpServers": {
    "judge": {
      "command": "node",
      "args": ["/absolute/path/to/judge-mcp/dist/index.js"],
      "env": {
        "JUDGE_BINARY": "/absolute/path/to/cargo-judge"
      }
    }
  }
}
```

## Tools

| Tool | Runs |
| --- | --- |
| `analyze` | `cargo-judge --format json` |
| `health` | `cargo-judge health --format json [--score]` |
| `dupes` | `cargo-judge dupes --format json [--mode ...]` |
| `dead_code` | `cargo-judge dead-code --format json` (needs a `--features deep` build) |
| `explain_finding` | `cargo-judge explain-rule <rule-id> --format json` |
| `inspect_symbol` | `cargo-judge explain <item-path> --why-live --format json` (needs a `--features deep` build) |
| `fix_preview` | `cargo-judge fix-preview <pattern-id> --format json` |

All tools are read-only; cargo-judge never modifies code. `explain_finding` explains the **rule**
behind a finding (evidence class, preconditions, exclusions, verdict effect), not the individual
occurrence, because the CLI has no per-finding explain command.
