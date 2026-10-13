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

## In practice

<figure>
<video controls preload="none" playsinline width="1920" height="1080" poster="../../../videos/judge-mcp-poster.webp" aria-label="Five questions about a Rust workspace to judge, as a chat with tool calls" style="width:100%;height:auto">
<source src="../../../videos/judge-mcp.mp4" type="video/mp4">
</video>
<figcaption>Five requests to an assistant with the judge MCP server, run against a real multi-crate Rust/Tauri workspace, 1:53, no sound. The chat is staged; every tool call and result is real output of the server, shortened.</figcaption>
</figure>

1. **Health check:** "How healthy is this workspace before the release?" `health` with `score: true` reports a score of 90.0 (grade A) for 20,493 lines, no failing findings and 68 warnings, with 72 gating and 54 advisory findings. The most frequent rules are `swallowed-result` (33), `panic-in-lib` (32) and `silent-default` (20). The lowest maintainability index (1.0) is in `origin-xtask/src/validate.rs`.
2. **Duplicates:** "Where do we have duplicated code?" `dupes` reports 62 clone families with 126 members. The largest is `SyncEngine::sync_if_due` (engine.rs:253) and `SyncEngine::sync_now` (engine.rs:286), 108 tokens each. One family crosses crates: `proxy_streams` (origin-mcp-http/src/proxy.rs:39) and `serve_streams` (origin-mcp-stdio/src/lib.rs:37), 63 tokens each.
3. **Delete or keep?** "Can I delete `demo_refresh` in the demo app, or is it still used?" `dead_code` reports it as `unused-pub-workspace` with 0 references, and lists the limitation `proc_macro_expansion_disabled`. `inspect_symbol` finds no path to `demo_refresh` (`reachable: false`). For `origin-demo::run` it shows a static call from `main` (main.rs:5). Because `run` registers the command inside a macro, which judge does not expand, the assistant keeps the function.
4. **Explain a finding:** "What does the silent-default finding in origin-auth/src/token.rs:91 mean?" `explain_finding` describes the rule as a heuristic with the verdict effect `advisory_only`, to be stated "as a hint or possible reading, never as proof". It also gives its exclusions: a syntax-only proxy, not a taint proof.
5. **Refactoring plan:** "`cargo judge patterns` suggests pattern:raii-guard:51769d26d9a7fc5e. How would I refactor that?" `fix_preview` returns a four-step migration plan for `raii_guard`. Step 1 is a manual check, and step 4 points to `crates/origin-platform/src/shortcut.rs`. The plan comes with `patch: null`, because judge generates no patch.

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
