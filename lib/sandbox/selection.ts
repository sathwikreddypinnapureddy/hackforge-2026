import "server-only";
import { DockerAnalysisSandbox } from "./docker.ts";
import type { AnalysisSandbox } from "./docker.ts";
import { LocalStaticSandbox } from "./local.ts";
import { AnalysisError } from "./policy.ts";

export class AutomaticSandbox implements AnalysisSandbox {
  private selected: AnalysisSandbox;
  private readonly preferDocker: boolean;
  private readonly docker: () => AnalysisSandbox;
  constructor(preferDocker: boolean, signal?: AbortSignal,
    docker: () => AnalysisSandbox = () => new DockerAnalysisSandbox()) {
    this.preferDocker = preferDocker; this.docker = docker;
    this.selected = new LocalStaticSandbox(undefined, signal);
  }
  async create() {
    if (this.preferDocker) {
      const candidate = this.docker();
      try { await candidate.create(); this.selected = candidate; return; }
      catch (error) {
        await candidate.destroy();
        if (!(error instanceof AnalysisError) || error.code !== "DOCKER_UNAVAILABLE") throw error;
      }
    }
    await this.selected.create();
  }
  cloneRepository(url: string) { return this.selected.cloneRepository(url); }
  getWorkspacePath() { return this.selected.getWorkspacePath(); }
  scan() { return this.selected.scan(); }
  destroy() { return this.selected.destroy(); }
}

// Docker is opt-in. Unconfigured installations never invoke Docker at all.
export const sandboxFactory = { create: (signal?: AbortSignal): AnalysisSandbox =>
  new AutomaticSandbox(process.env.HACKFORGE_SANDBOX === "DOCKER", signal) };
