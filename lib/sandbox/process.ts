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
}
export function runCommand(executable: "git" | "docker", args: readonly string[], options: CommandOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], {
      cwd: options.cwd, env: options.env ?? processEnvironment(), shell: false,
      detached: true, stdio: ["pipe", "pipe", "ignore"],
    });
    let size = 0;
    const chunks: Buffer[] = [];
    let failure: AnalysisError | undefined;
    const kill = (code: AnalysisErrorCode) => {
      failure ??= new AnalysisError(code);
      if (child.pid) { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
    };
    const timer = setTimeout(() => kill(options.timeoutCode ?? "SCAN_TIMEOUT"), options.timeoutMs ?? LIMITS.scanMs);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > (options.maxBytes ?? LIMITS.outputBytes)) kill("REPOSITORY_LIMIT");
      else chunks.push(chunk);
    });
    child.stdin.on("error", () => {});
    child.stdin.end(options.input);
    child.on("error", () => { clearTimeout(timer); reject(new AnalysisError(options.failureCode ?? "ANALYSIS_FAILED")); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else if (code !== 0) reject(new AnalysisError(options.failureCode ?? "ANALYSIS_FAILED"));
      else resolve(Buffer.concat(chunks));
    });
  });
}
