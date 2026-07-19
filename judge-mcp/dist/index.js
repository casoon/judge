#!/usr/bin/env node
/**
 * judge-mcp: a thin MCP adapter over the `cargo-judge` CLI.
 *
 * It computes no findings of its own. Every tool below shells out to the
 * already-built `cargo-judge` binary and returns its `--format json` output
 * structured for an MCP client. See todo.md §1 / §7 in the judge repo:
 * "MCP, Editor-Plugins und Agent-Skills sind optionale Adapter auf dieselbe
 * stabile CLI-/JSON-Schnittstelle, nicht Teil der fachlichen Berechnung." /
 * "Er berechnet keine eigenen Befunde und ist weder Installations- noch
 * Laufzeitvoraussetzung."
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { JudgeExecutionError, runJudgeJson } from "./judge.js";
const server = new McpServer({
    name: "judge-mcp",
    version: "0.1.0",
}, {
    instructions: "Thin, read-only adapter over the cargo-judge CLI. Computes no findings itself; " +
        "every tool call runs cargo-judge as a subprocess and returns its --format json " +
        "output. cargo-judge's exit code convention: 0 = clean, 1 = findings present " +
        "(a normal result, not an error), 2 = real analyzer/config error (surfaced as a " +
        "tool error). judge-mcp is optional: it is neither an install nor a runtime " +
        "requirement of judge itself.",
});
const workspaceRootField = z
    .string()
    .optional()
    .describe("Absolute or relative path to the Cargo workspace root to analyze. Defaults to the " +
    "MCP server process's current working directory if omitted.");
function jsonResult(data) {
    return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
}
function errorResult(err) {
    const message = err instanceof JudgeExecutionError ? err.message : String(err);
    return {
        content: [{ type: "text", text: message }],
        isError: true,
    };
}
async function callJudge(args, cwd) {
    try {
        const data = await runJudgeJson({ args, cwd });
        return jsonResult(data);
    }
    catch (err) {
        return errorResult(err);
    }
}
// ---------------------------------------------------------------------------
// analyze -> bare `cargo-judge --format json` (combined decision surface)
// ---------------------------------------------------------------------------
const AnalyzeInputSchema = {
    workspace_root: workspaceRootField,
    save_baseline: z
        .boolean()
        .optional()
        .describe("Save the combined findings as the baseline (--save-baseline)."),
    baseline: z
        .string()
        .optional()
        .describe("Path to a saved baseline to compare against (--baseline <path>)."),
};
server.registerTool("analyze", {
    title: "Full judge analysis",
    description: "Runs bare `cargo-judge` (--format json): the combined decision surface across " +
        "hotspots, duplication, dependency hygiene, ownership and (if judge.toml exists) " +
        "boundaries, merged and worst-first sorted. Read-only; computes nothing itself, " +
        "only forwards judge's own JSON report.",
    inputSchema: AnalyzeInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, save_baseline, baseline }) => {
    const args = [];
    if (save_baseline)
        args.push("--save-baseline");
    if (baseline)
        args.push("--baseline", baseline);
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
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
    save_baseline: z.boolean().optional().describe("Save the current findings as the baseline."),
    baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
    include_generated: z.boolean().optional().describe("Analyze generated files too."),
};
server.registerTool("health", {
    title: "judge health summary",
    description: "Runs `cargo-judge health --format json`: complexity, git hotspots, and " +
        "maintainability/slop findings, optionally with the 0-100 health score " +
        "(--score). Read-only; computes nothing itself, only forwards judge's own " +
        "JSON report.",
    inputSchema: HealthInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, score, show_cascades, save_baseline, baseline, include_generated }) => {
    const args = ["health"];
    if (score)
        args.push("--score");
    if (show_cascades)
        args.push("--show-cascades");
    if (save_baseline)
        args.push("--save-baseline");
    if (baseline)
        args.push("--baseline", baseline);
    if (include_generated)
        args.push("--include-generated");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
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
    save_baseline: z.boolean().optional().describe("Save the current findings as the baseline."),
    baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
    include_generated: z.boolean().optional().describe("Analyze generated files too."),
};
server.registerTool("dupes", {
    title: "judge duplication findings",
    description: "Runs `cargo-judge dupes --format json`: duplicated token spans (clone families). " +
        "Read-only; computes nothing itself, only forwards judge's own JSON report.",
    inputSchema: DupesInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, mode, min_tokens, save_baseline, baseline, include_generated }) => {
    const args = ["dupes"];
    if (mode)
        args.push("--mode", mode);
    if (min_tokens !== undefined)
        args.push("--min-tokens", String(min_tokens));
    if (save_baseline)
        args.push("--save-baseline");
    if (baseline)
        args.push("--baseline", baseline);
    if (include_generated)
        args.push("--include-generated");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
// ---------------------------------------------------------------------------
// dead_code -> `cargo-judge dead-code --format json`
// ---------------------------------------------------------------------------
const DeadCodeInputSchema = {
    workspace_root: workspaceRootField,
    include_tests: z
        .boolean()
        .optional()
        .describe("Count a #[test]-only reference as usage (--include-tests)."),
    save_baseline: z.boolean().optional().describe("Save the current findings as the baseline."),
    baseline: z.string().optional().describe("Path to a saved baseline to compare against."),
};
server.registerTool("dead_code", {
    title: "judge dead-code findings",
    description: "Runs `cargo-judge dead-code --format json`: `pub` items no other workspace crate " +
        "references, unreachable from any detected entry point. Requires a cargo-judge " +
        "binary built with `--features deep` (the Deep Tier); if the configured " +
        "JUDGE_BINARY was built without that feature, judge itself reports an error and " +
        "this tool passes that error through unchanged. Read-only; computes nothing " +
        "itself, only forwards judge's own JSON report.",
    inputSchema: DeadCodeInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, include_tests, save_baseline, baseline }) => {
    const args = ["dead-code"];
    if (include_tests)
        args.push("--include-tests");
    if (save_baseline)
        args.push("--save-baseline");
    if (baseline)
        args.push("--baseline", baseline);
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
// ---------------------------------------------------------------------------
// audit -> `cargo-judge audit --since <ref> --format json`
// ---------------------------------------------------------------------------
const AuditInputSchema = {
    workspace_root: workspaceRootField,
    since: z
        .string()
        .describe("Commit-ish boundary findings are classified against (--since <ref>)."),
    baseline: z
        .string()
        .optional()
        .describe("Baseline file to compare against. Defaults to .judge/baseline.json, which must " +
        "already exist (written by `analyze` with save_baseline)."),
    audit_min_sample: z
        .number()
        .int()
        .optional()
        .describe("Minimum touched authored LOC before a ratio gate is evaluated (--audit-min-sample)."),
    max_duplication_ratio: z
        .number()
        .optional()
        .describe("Maximum allowed duplicated-token ratio before the duplication gate fails."),
    max_suppression_ratio: z
        .number()
        .optional()
        .describe("Maximum allowed suppression-debt ratio before the suppression-debt gate fails."),
};
server.registerTool("audit", {
    title: "judge PR audit verdict",
    description: "Runs `cargo-judge audit --since <ref> --format json`: a pass/warn/fail verdict " +
        "scoped to findings introduced since <ref>, against an already-saved baseline. " +
        "Read-only; computes nothing itself, only forwards judge's own JSON report.",
    inputSchema: AuditInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, since, baseline, audit_min_sample, max_duplication_ratio, max_suppression_ratio, }) => {
    const args = ["audit", "--since", since];
    if (baseline)
        args.push("--baseline", baseline);
    if (audit_min_sample !== undefined)
        args.push("--audit-min-sample", String(audit_min_sample));
    if (max_duplication_ratio !== undefined) {
        args.push("--max-duplication-ratio", String(max_duplication_ratio));
    }
    if (max_suppression_ratio !== undefined) {
        args.push("--max-suppression-ratio", String(max_suppression_ratio));
    }
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
// ---------------------------------------------------------------------------
// explain_finding -> `cargo-judge explain-rule <rule-id> --format json`
//
// Deviation from todo.md §7's naming: judge's CLI has no
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
        .describe("The rule id to explain (e.g. 'catch-all-error'), taken from a finding's `rule` field."),
};
server.registerTool("explain_finding", {
    title: "judge explain-rule (rule behind a finding)",
    description: "Runs `cargo-judge explain-rule <rule_id> --format json`. NOTE: this deviates from " +
        "the `explain_finding` naming in todo.md §7 — judge's CLI has no command that " +
        "explains one specific finding instance (no `explain <finding-id>`). This tool " +
        "maps onto `explain-rule`, the closest real capability: it explains the RULE " +
        "behind a finding (evidence class, preconditions, exclusions, allowed wording, " +
        "verdict effect) via judge's static rule registry, not the individual finding " +
        "occurrence. A pure documentation lookup; never runs analysis, never affects any " +
        "verdict. Read-only; computes nothing itself, only forwards judge's own JSON " +
        "output.",
    inputSchema: ExplainFindingInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, rule_id }) => {
    const args = ["explain-rule", rule_id, "--format", "json"];
    return callJudge(args, workspace_root);
});
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
        .describe("Show the shortest evidenced call path from a recognized entry point (--why-live). " +
        "Needs a cargo-judge binary built with --features deep (the Deep Tier)."),
    include_tests: z
        .boolean()
        .optional()
        .describe("Count a #[test]-only call as reaching the item (--include-tests)."),
};
server.registerTool("inspect_symbol", {
    title: "judge inspect symbol (why-live explain)",
    description: "Runs `cargo-judge explain <item_path> --why-live --format json`, the closest real " +
        "capability to a symbol inspection: the shortest evidenced call path from a " +
        "recognized entry point to the given item, with each edge classified " +
        "static/dynamic/macro/generated/unknown. Requires a cargo-judge binary built with " +
        "`--features deep`; if unavailable, judge itself reports an error and this tool " +
        "passes it through unchanged. Read-only; computes nothing itself, only forwards " +
        "judge's own JSON output.",
    inputSchema: InspectSymbolInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, item_path, why_live, include_tests }) => {
    const args = ["explain", item_path];
    if (why_live)
        args.push("--why-live");
    if (include_tests)
        args.push("--include-tests");
    args.push("--format", "json");
    return callJudge(args, workspace_root);
});
// ---------------------------------------------------------------------------
// fix_preview -> `cargo-judge fix-preview <pattern-id> --format json`
// ---------------------------------------------------------------------------
const FixPreviewInputSchema = {
    workspace_root: workspaceRootField,
    pattern_id: z
        .string()
        .describe("The pattern candidate id to preview a fix for (see judge's `patterns` command)."),
};
server.registerTool("fix_preview", {
    title: "judge fix preview",
    description: "Runs `cargo-judge fix-preview <pattern_id> --format json`: a pattern candidate's " +
        "migration plan and affected call sites, deliberately no patch. Read-only; " +
        "computes nothing itself, only forwards judge's own JSON output.",
    inputSchema: FixPreviewInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false },
}, async ({ workspace_root, pattern_id }) => {
    const args = ["fix-preview", pattern_id, "--format", "json"];
    return callJudge(args, workspace_root);
});
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("judge-mcp running on stdio");
}
main().catch((err) => {
    console.error("judge-mcp fatal error:", err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map