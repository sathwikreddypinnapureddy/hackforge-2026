import type { Finding, Severity } from "../scanner/types.ts";
export type EventType = "REMEDIATION_REQUESTED" | "FIX_PROPOSED" | "FIX_APPROVED" | "BRANCH_CREATED" | "FILE_CHANGED" | "COMMIT_CREATED" | "RESCAN_STARTED" | "RESCAN_COMPLETED" | "FINDING_RESOLVED" | "FINDING_REMAINING" | "NEW_FINDING_DETECTED" | "BRANCH_READY_FOR_REVIEW";
export interface CommitRecord {
  branchName: string; commitSha: string; commitSubject: string; findingIds: string[];
  filesChanged: string[]; authorTimestamp: string; committerTimestamp: string; sanitizedSummary: string;
}
export interface TimelineEvent {
  eventId: string; timestamp: string; type: EventType; projectId: string; remediationSessionId: string;
  scanId: string; findingIds: string[]; repository: string; sourceCommitSha: string;
  branchName?: string; commitSha?: string; description: string;
}
export interface FixProposal {
  findingId: string; severity: Severity; file: string; remediation: string; filesToModify: string[];
  patchPreview: string; commitMessage: string;
}
export interface RemediationSession {
  id: string; projectId: string; scanId: string; findingIds: string[]; repository: string; sourceCommitSha: string;
  status: "PROPOSED" | "APPLYING" | "READY_FOR_REVIEW" | "FAILED" | "CANCELLED";
  proposal?: FixProposal; branchName?: string; reviewDirectory?: string; commit?: CommitRecord; beforeScore: number;
  afterScore?: number; resolved?: Finding[]; remaining?: Finding[]; newFindings?: Finding[]; timeline: TimelineEvent[];
}
export type PatchOperation = { kind: "replace"; path: string; before: string; after: string }
  | { kind: "remove"; path: string; before: string }
  | { kind: "write"; path: string; before: string | null; after: string };
