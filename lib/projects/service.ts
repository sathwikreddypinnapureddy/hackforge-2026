import "server-only";
import type { ProjectRepository, RepositoryScan } from "./types.ts";
import { projectStore } from "./store.ts";
import { sandboxFactory } from "../sandbox/docker.ts";
import type { AnalysisSandbox } from "../sandbox/docker.ts";
import { AnalysisError } from "../sandbox/policy.ts";
import { sanitizeRepositoryEvidence } from "./evidence.ts";

const state = globalThis as typeof globalThis & { hackforgeAnalysisBusy?: boolean; hackforgeCleanupBlocked?: boolean };
export async function analyzeProject(id: string, scanType: "RESCAN" | "FINAL" = "RESCAN",
  store: ProjectRepository = projectStore, create: () => AnalysisSandbox = sandboxFactory.create) {
  if (state.hackforgeCleanupBlocked) throw new AnalysisError("CLEANUP_FAILED");
  if (state.hackforgeAnalysisBusy) throw new AnalysisError("BUSY");
  state.hackforgeAnalysisBusy = true;
  let sandbox: AnalysisSandbox | undefined;
  let previous;
  try {
    previous = await store.get(id);
    await store.setStatus(id, "SCANNING");
    sandbox = create();
    let scan: RepositoryScan;
    try {
      await sandbox.create();
      await sandbox.cloneRepository(previous.project.repositoryUrl);
      scan = sanitizeRepositoryEvidence({ ...await sandbox.scan(), projectId: id, scanType: previous.scans.length ? scanType : "BASELINE" });
    } finally {
      // No result is committed until cleanup is confirmed, even after failure.
      try { await sandbox.destroy(); }
      catch { state.hackforgeCleanupBlocked = true; throw new AnalysisError("CLEANUP_FAILED"); }
    }
    return await store.appendScan(id, scan);
  } catch (error) {
    if (previous) await store.setStatus(id, previous.scans.length ? "READY_FOR_RESCAN" : "NOT_SCANNED").catch(() => undefined);
    throw error instanceof AnalysisError ? error : new AnalysisError("ANALYSIS_FAILED");
  } finally { state.hackforgeAnalysisBusy = false; }
}
