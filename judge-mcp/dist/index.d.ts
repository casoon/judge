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
export {};
//# sourceMappingURL=index.d.ts.map