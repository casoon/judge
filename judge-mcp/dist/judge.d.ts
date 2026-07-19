export interface JudgeRunOptions {
    /** CLI arguments after the binary name, e.g. ["health", "--format", "json"]. */
    args: string[];
    /** Working directory for the subprocess (maps to a tool's `workspace_root`). */
    cwd?: string;
}
/** Error thrown for any failure while invoking cargo-judge: process launch
 * failure, exit code 2 (real analyzer/config error), or unparsable output.
 * Callers report this back to the MCP client as a tool error. */
export declare class JudgeExecutionError extends Error {
}
/**
 * Runs cargo-judge and returns its parsed `--format json` output.
 *
 * Exit code convention (judge's own CLI contract, see src/main.rs `exit_code`):
 *   - 0: clean, no findings.
 *   - 1: findings present. This is NOT an error state for judge — a normal
 *     analysis result — so it is returned like exit 0, not thrown.
 *   - 2: a real analyzer/config error. Thrown as a `JudgeExecutionError`
 *     carrying judge's stderr text.
 */
export declare function runJudgeJson(options: JudgeRunOptions): Promise<unknown>;
//# sourceMappingURL=judge.d.ts.map