import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Path to the `cargo-judge` binary. judge-mcp never installs or builds it. */
const JUDGE_BINARY = process.env.JUDGE_BINARY ?? "cargo-judge";

export interface JudgeRunOptions {
  /** CLI arguments after the binary name, e.g. ["health", "--format", "json"]. */
  args: string[];
  /** Working directory for the subprocess (maps to a tool's `workspace_root`). */
  cwd?: string;
}

interface JudgeRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** Error thrown for any failure while invoking cargo-judge: process launch
 * failure, exit code 2 (real analyzer/config error), or unparsable output.
 * Callers report this back to the MCP client as a tool error. */
export class JudgeExecutionError extends Error {}

function runJudgeProcess({ args, cwd }: JudgeRunOptions): Promise<JudgeRunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(JUDGE_BINARY, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") {
        reject(
          new JudgeExecutionError(
            `Could not start '${JUDGE_BINARY}': not found. judge-mcp is a thin adapter and ` +
              `does not install or build cargo-judge itself. Install it first (e.g. ` +
              `'cargo install --path .' in the judge repo) so it is on PATH, or set the ` +
              `JUDGE_BINARY environment variable to its full path.`,
          ),
        );
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
 * cargo-judge writes `--format json` output to an artifact file (default
 * `.judge/<command>.json` in the workspace) and only prints "JSON written to
 * <path>" on stdout. To keep the analyzed workspace untouched, the artifact is
 * written to a unique temp file via `--output`, read back and always deleted.
 * judge adds a `header` object (artifact path, timestamp, assessment) in front
 * of the command's normal versioned payload; it is dropped here, so the tool
 * returns that payload as before.
 *
 * Exit code convention (judge's own CLI contract, see src/main.rs `exit_code`):
 *   - 0: clean, no findings.
 *   - 1: findings present. This is NOT an error state for judge — a normal
 *     analysis result — so it is returned like exit 0, not thrown.
 *   - 2: a real analyzer/config error. Thrown as a `JudgeExecutionError`
 *     carrying judge's stderr text.
 */
export async function runJudgeJson(options: JudgeRunOptions): Promise<unknown> {
  const outputPath = join(tmpdir(), `judge-mcp-${randomUUID()}.json`);
  try {
    const result = await runJudgeProcess({ ...options, args: [...options.args, "--output", outputPath] });

    if (result.exitCode === 2) {
      throw new JudgeExecutionError(
        `cargo-judge reported a config/analyzer error (exit 2): ${
          result.stderr.trim() || "(no stderr output)"
        }`,
      );
    }
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new JudgeExecutionError(
        `cargo-judge exited with unexpected code ${result.exitCode}. stderr: ${
          result.stderr.trim() || "(none)"
        }`,
      );
    }

    let artifact: string;
    try {
      artifact = await readFile(outputPath, "utf8");
    } catch (err) {
      throw new JudgeExecutionError(
        `cargo-judge wrote no JSON artifact: ${err instanceof Error ? err.message : String(err)}. ` +
          `First 500 chars of stdout: ${JSON.stringify(result.stdout.slice(0, 500))}. ` +
          `stderr: ${result.stderr.trim() || "(none)"}`,
      );
    }
    try {
      const { header: _header, ...payload } = JSON.parse(artifact) as Record<string, unknown>;
      return payload;
    } catch (err) {
      throw new JudgeExecutionError(
        `Failed to parse cargo-judge JSON output: ${err instanceof Error ? err.message : String(err)}. ` +
          `First 500 chars of the artifact: ${JSON.stringify(artifact.slice(0, 500))}. ` +
          `stderr: ${result.stderr.trim() || "(none)"}`,
      );
    }
  } finally {
    await rm(outputPath, { force: true });
  }
}
