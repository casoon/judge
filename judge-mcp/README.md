# judge-mcp

A thin [MCP](https://modelcontextprotocol.io) adapter over the `cargo-judge`
CLI. It **berechnet keine eigenen Befunde und ist weder Installations- noch
Laufzeitvoraussetzung von judge.** Every tool call shells out to an
already-built `cargo-judge` binary and returns its `--format json` output
structured for an MCP client — no state, no cloud, no network beyond that
local subprocess call.

## Installation

```bash
npm install
npm run build
```

This produces `dist/index.js`, the server entry point.

## Configuration

judge-mcp needs the `cargo-judge` binary. It does not install or build it
for you.

- `JUDGE_BINARY` (optional): path to the `cargo-judge` executable. Defaults
  to `cargo-judge`, i.e. it must be on `PATH` (e.g. after
  `cargo install --path .` in the judge repo, or a `--features deep` build
  for `dead_code`/`inspect_symbol`).

If the binary cannot be started (e.g. `ENOENT`), the affected tool call
returns a clear MCP tool error explaining how to fix it — the server itself
still starts.

## Running

```bash
node dist/index.js
```

The server speaks MCP over stdio.

## Example client config

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

| Tool | Maps to |
|---|---|
| `analyze` | bare `cargo-judge --format json` |
| `health` | `cargo-judge health --format json [--score]` |
| `dupes` | `cargo-judge dupes --format json [--mode ...]` |
| `dead_code` | `cargo-judge dead-code --format json` (needs a `--features deep` build) |
| `audit` | `cargo-judge audit --since <ref> --format json` |
| `explain_finding` | `cargo-judge explain-rule <rule-id> --format json` |
| `inspect_symbol` | `cargo-judge explain <item-path> --why-live --format json` (needs a `--features deep` build) |
| `fix_preview` | `cargo-judge fix-preview <pattern-id> --format json` |

All tools are read-only (`readOnlyHint: true`, `destructiveHint: false`) —
`cargo-judge` never modifies code.

### Naming deviation: `explain_finding`

judge's CLI has no `explain <finding-id>` command that explains one specific
finding instance — only `explain <item-path> --why-live`,
`explain-rule <rule-id>`, and `explain-pattern <id>`. `explain_finding` is
mapped onto `explain-rule`: it explains the **rule** behind a finding
(evidence class, preconditions, exclusions, verdict effect), not the
individual finding occurrence. This is documented in the tool's description
as well.

## Exit code handling

`cargo-judge` has a specific exit code convention this adapter respects:

- **0** (clean) and **1** (findings present) are both normal tool
  successes — exit 1 is judge's way of reporting "there are findings", not
  an error. The JSON report is returned either way.
- **2** (a real analyzer/config error) becomes an MCP tool error carrying
  judge's stderr text.
- Unparsable JSON output also becomes an MCP tool error, with a diagnostic
  hint (start of stdout + stderr).
