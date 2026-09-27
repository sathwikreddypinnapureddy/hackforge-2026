import type { ScanResult } from "../scanner/types.ts";

export type ProjectStatus = "NOT_SCANNED" | "SCANNING" | "NEEDS_ATTENTION" | "READY_FOR_RESCAN" | "VERIFIED";
export interface Project {
  id: string;
  name: string;
  repositoryUrl: string;
  repositoryOwner: string;
  repositoryName: string;
  createdAt: string;
  lastScannedAt: string | null;
  status: ProjectStatus;
}
export interface RepositoryScan extends ScanResult {
  target: "repository";
  projectId: string;
  commitSha: string;
  scanType: "BASELINE" | "RESCAN" | "FINAL";
  scannerVersion: string;
  coverage: { filesScanned: number; binaryFilesSkipped: number; generatedFilesSkipped: number };
}
export interface ProjectDetail { project: Project; scans: RepositoryScan[] }

// Implement this interface with a database when moving beyond one local process.
export interface ProjectRepository {
  list(): Promise<Project[]>;
  get(id: string): Promise<ProjectDetail>;
  create(repositoryUrl: string): Promise<ProjectDetail>;
  setStatus(id: string, status: ProjectStatus): Promise<void>;
  appendScan(id: string, scan: RepositoryScan): Promise<ProjectDetail>;
}
