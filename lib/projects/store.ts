import "server-only";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rename, rm } from "node:fs/promises";
import path from "node:path";
import { validateProjectId, validateRepositoryUrl } from "./url.ts";
import type { Project, ProjectDetail, ProjectRepository, ProjectStatus, RepositoryScan } from "./types.ts";
import { sanitizeRepositoryEvidence } from "./evidence.ts";
import { AnalysisError } from "../sandbox/policy.ts";

const MAX_STORE_BYTES = 16 * 1024 * 1024;
interface Database { version: 1; projects: ProjectDetail[] }
export class LocalProjectRepository implements ProjectRepository {
  private readonly directory: string;
  private queue: Promise<unknown> = Promise.resolve();
  private recovered = false;
  constructor(directory = path.join(process.cwd(), ".hackforge-data")) { this.directory = directory; }
  private async load(): Promise<Database> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const directoryStat = await lstat(this.directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || await realpath(this.directory) !== this.directory) throw new AnalysisError("ANALYSIS_FAILED");
    let handle;
    try { handle = await open(path.join(this.directory, "projects.json"), constants.O_RDONLY | constants.O_NOFOLLOW); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, projects: [] }; throw error; }
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_STORE_BYTES) throw new AnalysisError("STORE_LIMIT");
      const db = JSON.parse(await handle.readFile("utf8")) as Database;
      if (db.version !== 1 || !Array.isArray(db.projects) || db.projects.length > 25) throw new AnalysisError("ANALYSIS_FAILED");
      for (const detail of db.projects) {
        validateProjectId(detail.project.id);
        validateRepositoryUrl(detail.project.repositoryUrl);
        detail.scans = detail.scans.map(sanitizeRepositoryEvidence);
        if (detail.scans.some((scan) => scan.projectId !== detail.project.id)) throw new AnalysisError("ANALYSIS_FAILED");
        // A process restart cannot leave a project permanently SCANNING.
        if (!this.recovered && detail.project.status === "SCANNING") detail.project.status = detail.scans.length ? "READY_FOR_RESCAN" : "NOT_SCANNED";
      }
      return db;
    } finally { await handle.close(); }
  }
  private transaction<T>(operation: (db: Database) => T): Promise<T> {
    const result = this.queue.then(async () => {
      const db = await this.load();
      const value = operation(db);
      const serialized = JSON.stringify(db);
      if (Buffer.byteLength(serialized) > MAX_STORE_BYTES) throw new AnalysisError("STORE_LIMIT");
      const temporary = path.join(this.directory, `write-${randomUUID()}.json`);
      try {
        const handle = await open(temporary, "wx", 0o600);
        try { await handle.writeFile(serialized); await handle.sync(); } finally { await handle.close(); }
        await rename(temporary, path.join(this.directory, "projects.json"));
        this.recovered = true;
      } finally { await rm(temporary, { force: true }); }
      return structuredClone(value);
    });
    this.queue = result.catch(() => undefined);
    return result;
  }
  list(): Promise<Project[]> { return this.transaction((db) => db.projects.map((detail) => detail.project)); }
  get(id: string): Promise<ProjectDetail> {
    validateProjectId(id);
    return this.transaction((db) => { const detail = db.projects.find((x) => x.project.id === id); if (!detail) throw new Error("Unknown project"); return detail; });
  }
  create(url: string): Promise<ProjectDetail> {
    const repository = validateRepositoryUrl(url);
    return this.transaction((db) => {
      const existing = db.projects.find((x) => x.project.repositoryUrl.toLowerCase() === repository.repositoryUrl.toLowerCase());
      if (existing) return existing;
      if (db.projects.length >= 25) throw new AnalysisError("STORE_LIMIT");
      const detail: ProjectDetail = { project: { id: randomUUID(), name: repository.repositoryName, ...repository,
        createdAt: new Date().toISOString(), lastScannedAt: null, status: "NOT_SCANNED" }, scans: [] };
      db.projects.push(detail); return detail;
    });
  }
  setStatus(id: string, status: ProjectStatus) {
    return this.transaction((db) => { const detail = db.projects.find((x) => x.project.id === id); if (!detail) throw new Error("Unknown project"); detail.project.status = status; });
  }
  appendScan(id: string, input: RepositoryScan) {
    const scan = sanitizeRepositoryEvidence(input);
    return this.transaction((db) => {
      const detail = db.projects.find((x) => x.project.id === id);
      if (!detail || scan.projectId !== id || detail.scans.some((s) => s.scanId === scan.scanId)
        || (detail.scans.length === 0) !== (scan.scanType === "BASELINE")) throw new AnalysisError("ANALYSIS_FAILED");
      detail.scans.push(scan);
      // Keep the original baseline and most recent 49 scans.
      if (detail.scans.length > 50) detail.scans.splice(1, detail.scans.length - 50);
      detail.project.lastScannedAt = scan.scannedAt;
      detail.project.status = scan.findings.length ? "NEEDS_ATTENTION" : detail.scans.length > 1 ? "VERIFIED" : "READY_FOR_RESCAN";
      return detail;
    });
  }
}
const state = globalThis as typeof globalThis & { hackforgeProjects?: LocalProjectRepository };
export const projectStore = state.hackforgeProjects ??= new LocalProjectRepository();
