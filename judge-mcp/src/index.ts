#!/usr/bin/env node
/**
 * judge-mcp: a thin MCP adapter over the `cargo-judge` CLI.
 *
 * It computes no findings of its own. Every tool below shells out to the
 * already-built `cargo-judge` binary and returns its `--format json` output
 * structured for an MCP client. It is an optional adapter on the stable
 * CLI/JSON interface, not part of the analysis, and neither an install nor a
 * runtime requirement of judge.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { JudgeExecutionError, runJudgeJson } from "./judge.js";

const server = new McpServer(
  {
    name: "judge-mcp",
    version: "0.1.0",
  },
  {
    instructions:
      "Thin adapter over the cargo-judge CLI. Computes no findings itself; " +
      "every tool call runs cargo-judge as a subprocess and returns its --format json " +
      "output. All tools are read-only except save_baseline, which writes a baseline " +
      "file into the analyzed workspace. cargo-judge's exit code convention: 0 = clean, 1 = findings present " +
      "(a normal result, not an error), 2 = real analyzer/config error (surfaced as a " +
      "tool error). judge-mcp is optional: it is neither an install nor a runtime " +
      "requirement of judge itself.",
  },
);

const workspaceRootField = z
  .string()
  .optional()
  .describe(
    "Absolute or relative path to the Cargo workspace root to analyze. Defaults to the " +
      "MCP server process's current working directory if omitted.",
  );

function jsonResult(data: unknown): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

function errorResult(err: unknown): CallToolResult {
  const message = err instanceof JudgeExecutionError ? err.message : String(err);
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

async function callJudge(args: string[], cwd: string | undefined): Promise<CallToolResult> {
  try {
    const data = await runJudgeJson({ args, cwd });
    return jsonResult(data);
  } catch (err) {
    return errorResult(err);
  }
}

// ---------------------------------------------------------------------------
// analyze -> bare `cargo-judge --format json` (combined decision surface)
// ---------------------------------------------------------------------------
const AnalyzeInputSchema = {
  workspace_root: workspaceRootField,
  baseline: z
    .string()
    .optional()
    .describe("Path to a saved baseline to compare against (--baseline <path>)."),
};

server.registerTool(
  "analyze",
  {
    title: "Full judge analysis",
    description:
      "Runs bare `cargo-judge` (--format json): the combined decision surface across " +
      "complexity, slop, duplication, structure, security, dependency hygiene and (if " +
      "judge.toml exists) boundaries, merged and worst-first sorted. Read-only; computes nothing itself, " +
      "only forwards judge's own JSON report.",
    inputSchema: AnalyzeInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, baseline }) => {
    const args: string[] = [];
    if (baseline) args.push("--baseline", baseline);
    args.push("--format", "json");
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// health -> `cargo-judge health --format json [--score]`
// ---------------------------------------------------------------------------
const HealthInputSchema = {
  workspace_root: workspaceRootField,
  score: z.boolean().optional().describe("Include the numeric health score (--score)."),
  show_cascades: z
    .boolean()
    .optional()
    .describe("Show findings caused by another finding, not just root findings (--show-cascades)."),
  baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
  include_generated: z.boolean().optional().describe("Analyze generated files too."),
};

server.registerTool(
  "health",
  {
    title: "judge health summary",
    description:
      "Runs `cargo-judge health --format json`: complexity and " +
      "maintainability/slop findings, optionally with the 0-100 health score " +
      "(--score). Read-only; computes nothing itself, only forwards judge's own " +
      "JSON report.",
    inputSchema: HealthInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, score, show_cascades, baseline, include_generated }) => {
    const args: string[] = ["health"];
    if (score) args.push("--score");
    if (show_cascades) args.push("--show-cascades");
    if (baseline) args.push("--baseline", baseline);
    if (include_generated) args.push("--include-generated");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// dupes -> `cargo-judge dupes --format json [--mode ...]`
// ---------------------------------------------------------------------------
const DupesInputSchema = {
  workspace_root: workspaceRootField,
  mode: z
    .enum(["strict", "mild", "weak", "semantic"])
    .optional()
    .describe("How aggressively token spans must match to count as duplicates (default: mild)."),
  min_tokens: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Minimum span length in tokens for a clone family (--min-tokens)."),
  baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
  include_generated: z.boolean().optional().describe("Analyze generated files too."),
};

server.registerTool(
  "dupes",
  {
    title: "judge duplication findings",
    description:
      "Runs `cargo-judge dupes --format json`: duplicated token spans (clone families). " +
      "Read-only; computes nothing itself, only forwards judge's own JSON report.",
    inputSchema: DupesInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, mode, min_tokens, baseline, include_generated }) => {
    const args: string[] = ["dupes"];
    if (mode) args.push("--mode", mode);
    if (min_tokens !== undefined) args.push("--min-tokens", String(min_tokens));
    if (baseline) args.push("--baseline", baseline);
    if (include_generated) args.push("--include-generated");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// dead_code -> `cargo-judge dead-code --format json`
// ---------------------------------------------------------------------------
const DeadCodeInputSchema = {
  workspace_root: workspaceRootField,
  include_tests: z
    .boolean()
    .optional()
    .describe("Count a #[test]-only reference as usage (--include-tests)."),
  baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
};

server.registerTool(
  "dead_code",
  {
    title: "judge dead-code findings",
    description:
      "Runs `cargo-judge dead-code --format json`: `pub` items no other workspace crate " +
      "references, unreachable from any detected entry point. Requires a cargo-judge " +
      "binary built with `--features deep` (the Deep Tier); if the configured " +
      "JUDGE_BINARY was built without that feature, judge itself reports an error and " +
      "this tool passes that error through unchanged. Read-only; computes nothing " +
      "itself, only forwards judge's own JSON report.",
    inputSchema: DeadCodeInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, include_tests, baseline }) => {
    const args: string[] = ["dead-code"];
    if (include_tests) args.push("--include-tests");
    if (baseline) args.push("--baseline", baseline);
    args.push("--format", "json");
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// explain_finding -> `cargo-judge explain-rule <rule-id> --format json`
//
// judge's CLI has no
// `explain <finding-id>` command that explains one specific finding
// instance. The closest real capability is `explain-rule <rule-id>`, which
// explains the RULE behind a finding (evidence class, preconditions,
// exclusions, verdict effect) rather than that one finding occurrence. This
// tool is mapped onto that command; `rule_id` is the `rule` field found on
// any finding in `health`/`dupes`/etc. output.
// ---------------------------------------------------------------------------
const ExplainFindingInputSchema = {
  workspace_root: workspaceRootField,
  rule_id: z
    .string()
    .describe(
      "The rule id to explain (e.g. 'catch-all-error'), taken from a finding's `rule` field.",
    ),
};

server.registerTool(
  "explain_finding",
  {
    title: "judge explain-rule (rule behind a finding)",
    description:
      "Runs `cargo-judge explain-rule <rule_id> --format json`. NOTE: judge's CLI has " +
      "no command that explains one specific finding instance (no `explain <finding-id>`). " +
      "This tool maps onto `explain-rule`, the closest real capability: it explains the RULE " +
      "behind a finding (evidence class, preconditions, exclusions, allowed wording, " +
      "verdict effect) via judge's static rule registry, not the individual finding " +
      "occurrence. A pure documentation lookup; never runs analysis, never affects any " +
      "verdict. Read-only; computes nothing itself, only forwards judge's own JSON " +
      "output.",
    inputSchema: ExplainFindingInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, rule_id }) => {
    const args = ["explain-rule", rule_id, "--format", "json"];
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// inspect_symbol -> `cargo-judge explain <item-path> --why-live --format json`
// ---------------------------------------------------------------------------
const InspectSymbolInputSchema = {
  workspace_root: workspaceRootField,
  item_path: z
    .string()
    .describe("The qualified item path to inspect, e.g. 'core::retry::backoff'."),
  why_live: z
    .boolean()
    .default(true)
    .describe(
      "Show the shortest evidenced call path from a recognized entry point (--why-live). " +
        "Needs a cargo-judge binary built with --features deep (the Deep Tier).",
    ),
  include_tests: z
    .boolean()
    .optional()
    .describe("Count a #[test]-only call as reaching the item (--include-tests)."),
};

server.registerTool(
  "inspect_symbol",
  {
    title: "judge inspect symbol (why-live explain)",
    description:
      "Runs `cargo-judge explain <item_path> --why-live --format json`, the closest real " +
      "capability to a symbol inspection: the shortest evidenced call path from a " +
      "recognized entry point to the given item, with each edge classified " +
      "static/dynamic/macro/generated/unknown. Requires a cargo-judge binary built with " +
      "`--features deep`; if unavailable, judge itself reports an error and this tool " +
      "passes it through unchanged. Read-only; computes nothing itself, only forwards " +
      "judge's own JSON output.",
    inputSchema: InspectSymbolInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, item_path, why_live, include_tests }) => {
    const args: string[] = ["explain", item_path];
    if (why_live) args.push("--why-live");
    if (include_tests) args.push("--include-tests");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// fix_preview -> `cargo-judge fix-preview <pattern-id> --format json`
// ---------------------------------------------------------------------------
const FixPreviewInputSchema = {
  workspace_root: workspaceRootField,
  pattern_id: z
    .string()
    .describe("The pattern candidate id to preview a fix for (see judge's `patterns` command)."),
};

server.registerTool(
  "fix_preview",
  {
    title: "judge fix preview",
    description:
      "Runs `cargo-judge fix-preview <pattern_id> --format json`: a pattern candidate's " +
      "migration plan and affected call sites, deliberately no patch. Read-only; " +
      "computes nothing itself, only forwards judge's own JSON output.",
    inputSchema: FixPreviewInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, pattern_id }) => {
    const args = ["fix-preview", pattern_id, "--format", "json"];
    return callJudge(args, workspace_root);
  },
);

// ---------------------------------------------------------------------------
// review -> `cargo-judge <command> --format json` for the focused read-only views
// ---------------------------------------------------------------------------
const REVIEW_COMMANDS = [
  "structure",
  "complexity",
  "refactor",
  "api",
  "api-surface",
  "errors",
  "tests",
  "unsafe",
  "slop",
  "deps",
  "boundaries",
  "module-graph",
  "map",
] as const;

server.registerTool(
  "review",
  {
    title: "judge focused review",
    description:
      "Runs one focused, read-only judge view as `cargo-judge <command> --format json`: " +
      REVIEW_COMMANDS.join(", ") +
      ". `boundaries` does nothing without a judge.toml. Computes nothing itself, only " +
      "forwards judge's own JSON report.",
    inputSchema: {
      workspace_root: workspaceRootField,
      command: z.enum(REVIEW_COMMANDS).describe("Which focused view to run."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, command }) => callJudge([command, "--format", "json"], workspace_root),
);

// ---------------------------------------------------------------------------
// compare -> `cargo-judge compare --baseline <path> --format json`
// ---------------------------------------------------------------------------
server.registerTool(
  "compare",
  {
    title: "judge compare with baseline",
    description:
      "Runs `cargo-judge compare --baseline <path> --format json`: compares the current " +
      "project state with a saved baseline artifact and reports introduced, resolved and " +
      "unchanged findings plus the verdict. Read-only.",
    inputSchema: {
      workspace_root: workspaceRootField,
      baseline: z.string().describe("Path to a saved baseline artifact."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async ({ workspace_root, baseline }) =>
    callJudge(["compare", "--baseline", baseline, "--format", "json"], workspace_root),
);

// ---------------------------------------------------------------------------
// save_baseline -> the only tool that writes into the analyzed workspace
// ---------------------------------------------------------------------------
server.registerTool(
  "save_baseline",
  {
    title: "judge save baseline",
    description:
      "Saves the current findings as the baseline (`--save-baseline`). WRITES a baseline " +
      "file under `.judge/` in the analyzed workspace, replacing an earlier baseline of " +
      "the same scope. `scope` picks the baseline: `all` (bare run), `health`, `dupes` or " +
      "`dead-code`.",
    inputSchema: {
      workspace_root: workspaceRootField,
      scope: z.enum(["all", "health", "dupes", "dead-code"]).describe("Which baseline to save."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
  },
  async ({ workspace_root, scope }) => {
    const args: string[] = scope === "all" ? [] : [scope];
    args.push("--save-baseline", "--format", "json");
    return callJudge(args, workspace_root);
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("judge-mcp running on stdio");
}

main().catch((err) => {
  console.error("judge-mcp fatal error:", err);
  process.exit(1);
});
