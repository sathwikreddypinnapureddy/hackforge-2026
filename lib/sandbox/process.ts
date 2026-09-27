import { spawn } from "node:child_process";
import { AnalysisError, LIMITS, processEnvironment } from "./policy.ts";
import type { AnalysisErrorCode } from "./policy.ts";

export interface CommandOptions {
  cwd: string;
  timeoutMs?: number;
  maxBytes?: number;
  timeoutCode?: AnalysisErrorCode;
  failureCode?: AnalysisErrorCode;
  env?: NodeJS.ProcessEnv;
  input?: string;
  signal?: AbortSignal;
  detached?: boolean;
}
export function runCommand(executable: "git" | "docker" | "node", args: readonly string[], options: CommandOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable === "node" ? process.execPath : executable, [...args], {
      cwd: options.cwd, env: options.env ?? processEnvironment(), shell: false,
      detached: options.detached ?? true, stdio: ["pipe", "pipe", "ignore"],
    });
    let size = 0;
    const chunks: Buffer[] = [];
    let failure: AnalysisError | undefined;
    const kill = (code: AnalysisErrorCode) => {
      failure ??= new AnalysisError(code);
      if (child.pid) {
        if (options.detached === false) child.kill("SIGKILL");
        else { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
      }
    };
    const abort = () => kill("ANALYSIS_FAILED");
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    const timer = setTimeout(() => kill(options.timeoutCode ?? "SCAN_TIMEOUT"), options.timeoutMs ?? LIMITS.scanMs);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > (options.maxBytes ?? LIMITS.outputBytes)) kill("REPOSITORY_LIMIT");
      else chunks.push(chunk);
    });
    child.stdin.on("error", () => {});
    child.stdin.end(options.input);
    child.on("error", () => { clearTimeout(timer); options.signal?.removeEventListener("abort", abort); reject(new AnalysisError(options.failureCode ?? "ANALYSIS_FAILED")); });
    child.on("close", (code) => {
      clearTimeout(timer); options.signal?.removeEventListener("abort", abort);
      if (failure) reject(failure);
      else if (code !== 0) reject(new AnalysisError(options.failureCode ?? "ANALYSIS_FAILED"));
      else resolve(Buffer.concat(chunks));
    });
  });
}
