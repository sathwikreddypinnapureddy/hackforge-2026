import "server-only";
import { randomUUID } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { runCommand } from "./process.ts";
import { AnalysisError, ERROR_MESSAGES, LIMITS, SANDBOX_IMAGE } from "./policy.ts";
import type { AnalysisErrorCode } from "./policy.ts";
import { PublicGitHubAcquisition } from "./acquisition.ts";
import type { RepositoryAcquisition } from "./acquisition.ts";
import type { RepositoryScan } from "../projects/types.ts";

export interface AnalysisSandbox {
  create(): Promise<void>;
  cloneRepository(url: string): Promise<void>;
  getWorkspacePath(): string;
  scan(): Promise<Omit<RepositoryScan, "projectId" | "scanType">>;
  destroy(): Promise<void>;
}

export function dockerScanArguments(name: string, root: string, imageId: string): string[] {
  return ["run", "--rm", "--pull=never", "--name", name, "--label", "hackforge.sandbox=true",
    "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--user=65532:65532", "--cpus=1", "--memory=768m", "--memory-swap=768m", "--pids-limit=64",
    "--ulimit", "nofile=128:128", "--log-driver=none",
    "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=320m,uid=65532,gid=65532,mode=0700",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700",
    "--mount", `type=bind,source=${root},target=/input,readonly`, imageId];
}

export class DockerAnalysisSandbox implements AnalysisSandbox {
  private workspace?: string;
  private repository?: string;
  private imageId?: string;
  private attemptedRun = false;
  private readonly name = `hackforge-${randomUUID()}`;
  private readonly acquisition: RepositoryAcquisition;
  constructor(acquisition: RepositoryAcquisition = new PublicGitHubAcquisition()) { this.acquisition = acquisition; }
  async create() {
    try {
      const info = JSON.parse((await runCommand("docker", ["info", "--format", "{{json .}}"], { cwd: os.tmpdir(), timeoutMs: 5000 })).toString());
      if (!info.MemoryLimit || !info.CpuCfsQuota || !info.PidsLimit || info.CgroupDriver === "none") throw new Error("Resource limits required");
      const id = (await runCommand("docker", ["image", "inspect", "--format", "{{.Id}}", SANDBOX_IMAGE], { cwd: os.tmpdir(), timeoutMs: 5000 })).toString().trim();
      if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error("Image unavailable");
      this.imageId = id;
    } catch { throw new AnalysisError("DOCKER_UNAVAILABLE"); }
    this.workspace = await mkdtemp(path.join(await realpath(os.tmpdir()), "hackforge-analysis-"));
  }
  async cloneRepository(url: string) {
    this.repository = await this.acquisition.clone(url, this.getWorkspacePath());
    // Discard origin/branch configuration. There are no remote helpers, includes,
    // filters, hooks, alternates or credentials available to the offline worker.
    await writeFile(path.join(this.repository, ".git/config"), "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = false\n");
  }
  getWorkspacePath() {
    if (!this.workspace) throw new AnalysisError("ANALYSIS_FAILED");
    return this.workspace;
  }
  async scan() {
    if (!this.repository || !this.imageId) throw new AnalysisError("ANALYSIS_FAILED");
    this.attemptedRun = true;
    const output = await runCommand("docker", dockerScanArguments(this.name, this.repository, this.imageId), {
      cwd: this.getWorkspacePath(), timeoutMs: LIMITS.scanMs, timeoutCode: "SCAN_TIMEOUT", maxBytes: LIMITS.outputBytes,
    });
    let result;
    try { result = JSON.parse(output.toString("utf8")); }
    catch { throw new AnalysisError("ANALYSIS_FAILED"); }
    if (result?.error) throw new AnalysisError(Object.hasOwn(ERROR_MESSAGES, result.error) ? result.error as AnalysisErrorCode : "ANALYSIS_FAILED");
    return result as Omit<RepositoryScan, "projectId" | "scanType">;
  }
  async destroy() {
    let cleanupFailed = false;
    if (this.attemptedRun) {
      try {
        // --rm handles normal exit. Force-remove also handles timeouts and killed
        // Docker clients. Confirm absence; a daemon outage is not success.
        await runCommand("docker", ["rm", "--force", this.name], { cwd: os.tmpdir(), timeoutMs: 5000 }).catch(() => undefined);
        const remaining = await runCommand("docker", ["ps", "--all", "--quiet", "--filter", `name=^/${this.name}$`], { cwd: os.tmpdir(), timeoutMs: 5000 });
        cleanupFailed = remaining.toString().trim().length !== 0;
      } catch { cleanupFailed = true; }
    }
    if (this.workspace) {
      await rm(this.workspace, { recursive: true, force: true }).catch(() => { cleanupFailed = true; });
      this.workspace = undefined;
    }
    if (cleanupFailed) throw new AnalysisError("CLEANUP_FAILED");
  }
}

// Only this factory is used by the server. There is deliberately no host-scan
// fallback when Docker is missing. Tests inject a fixture sandbox explicitly.
export const sandboxFactory = { create: (): AnalysisSandbox => new DockerAnalysisSandbox() };
