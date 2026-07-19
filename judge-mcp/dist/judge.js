import { spawn } from "node:child_process";
/** Path to the `cargo-judge` binary. judge-mcp never installs or builds it. */
const JUDGE_BINARY = process.env.JUDGE_BINARY ?? "cargo-judge";
/** Error thrown for any failure while invoking cargo-judge: process launch
 * failure, exit code 2 (real analyzer/config error), or unparsable output.
 * Callers report this back to the MCP client as a tool error. */
export class JudgeExecutionError extends Error {
}
function runJudgeProcess({ args, cwd }) {
    return new Promise((resolve, reject) => {
        const child = spawn(JUDGE_BINARY, args, {
            cwd,
            stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => {
            stdout += chunk.toString("utf8");
        });
        child.stderr.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });
        child.on("error", (err) => {
            if (err.code === "ENOENT") {
                reject(new JudgeExecutionError(`Could not start '${JUDGE_BINARY}': not found. judge-mcp is a thin adapter and ` +
                    `does not install or build cargo-judge itself. Install it first (e.g. ` +
                    `'cargo install --path .' in the judge repo) so it is on PATH, or set the ` +
                    `JUDGE_BINARY environment variable to its full path.`));
                return;
            }
            reject(new JudgeExecutionError(`Failed to start '${JUDGE_BINARY}': ${err.message}`));
        });
        child.on("close", (code, signal) => {
            if (signal) {
                reject(new JudgeExecutionError(`'${JUDGE_BINARY}' was terminated by signal ${signal}`));
                return;
            }
            resolve({ exitCode: code ?? 0, stdout, stderr });
        });
    });
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
export async function runJudgeJson(options) {
    const result = await runJudgeProcess(options);
    if (result.exitCode === 2) {
        throw new JudgeExecutionError(`cargo-judge reported a config/analyzer error (exit 2): ${result.stderr.trim() || "(no stderr output)"}`);
    }
    if (result.exitCode !== 0 && result.exitCode !== 1) {
        throw new JudgeExecutionError(`cargo-judge exited with unexpected code ${result.exitCode}. stderr: ${result.stderr.trim() || "(none)"}`);
    }
    try {
        return JSON.parse(result.stdout);
    }
    catch (err) {
        throw new JudgeExecutionError(`Failed to parse cargo-judge JSON output: ${err instanceof Error ? err.message : String(err)}. ` +
            `First 500 chars of stdout: ${JSON.stringify(result.stdout.slice(0, 500))}. ` +
            `stderr: ${result.stderr.trim() || "(none)"}`);
    }
}
//# sourceMappingURL=judge.js.map