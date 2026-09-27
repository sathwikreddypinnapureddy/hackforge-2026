import "server-only";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PublicGitHubAcquisition, validateAcquiredTree } from "./acquisition.ts";
import type { RepositoryAcquisition } from "./acquisition.ts";
import type { AnalysisSandbox } from "./docker.ts";
import type { RepositoryScan } from "../projects/types.ts";
import { validateRepositoryUrl } from "../projects/url.ts";
import { AnalysisError, ERROR_MESSAGES, LIMITS } from "./policy.ts";
import type { AnalysisErrorCode } from "./policy.ts";
import { runCommand } from "./process.ts";

// This is a static-only workspace, not a container or a VM. The executable
// and worker are HackForge-controlled; target blobs are only read as data.
export class LocalStaticSandbox implements AnalysisSandbox {
  private workspace?: string;
  private repository?: string;
  private readonly acquisition: RepositoryAcquisition;
  private readonly signal?: AbortSignal;
  private readonly scanMs: number;
  constructor(acquisition: RepositoryAcquisition = new PublicGitHubAcquisition(),
    signal?: AbortSignal, scanMs: number = LIMITS.scanMs) {
    this.acquisition = acquisition; this.signal = signal; this.scanMs = scanMs;
  }
  async create() {
    if (this.signal?.aborted) throw new AnalysisError("ANALYSIS_FAILED");
    this.workspace = await mkdtemp(path.join(await realpath(os.tmpdir()), "hackforge-local-static-"));
  }
  getWorkspacePath() {
    if (!this.workspace) throw new AnalysisError("ANALYSIS_FAILED");
    return this.workspace;
  }
  async cloneRepository(url: string) {
    validateRepositoryUrl(url);
    const workspace = this.getWorkspacePath();
    const repository = await this.acquisition.clone(url, workspace, this.signal);
    // Acquisition cannot redirect the worker to an arbitrary host directory.
    if (repository !== path.join(workspace, "repository") || await realpath(repository) !== repository) {
      throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    }
    await validateAcquiredTree(repository);
    await writeFile(path.join(repository, ".git/config"), "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = false\n");
    this.repository = repository;
  }
  async scan() {
    if (!this.repository) throw new AnalysisError("ANALYSIS_FAILED");
    const workspace = this.getWorkspacePath();
    const output = await runCommand("node", ["--disable-warning=MODULE_TYPELESS_PACKAGE_JSON",
      "--max-old-space-size=512", path.join(process.cwd(), "scripts/local-static-worker.ts"), workspace], {
      cwd: workspace, timeoutMs: this.scanMs, timeoutCode: "SCAN_TIMEOUT", signal: this.signal,
    });
    let result;
    try { result = JSON.parse(output.toString("utf8")); }
    catch { throw new AnalysisError("ANALYSIS_FAILED"); }
    if (result?.error) throw new AnalysisError(Object.hasOwn(ERROR_MESSAGES, result.error)
      ? result.error as AnalysisErrorCode : "ANALYSIS_FAILED");
    return { ...result, sandboxMode: "LOCAL_STATIC" } as Omit<RepositoryScan, "projectId" | "scanType">;
  }
  async destroy() {
    if (this.workspace) {
      try { await rm(this.workspace, { recursive: true, force: true }); }
      catch { throw new AnalysisError("CLEANUP_FAILED"); }
      this.workspace = undefined;
      this.repository = undefined;
    }
  }
}
