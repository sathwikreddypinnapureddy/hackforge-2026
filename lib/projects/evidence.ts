import type { Finding, Severity } from "../scanner/types.ts";
import { SEVERITIES } from "../scanner/types.ts";
import { calculateScore, PENALTIES } from "../scanner/scoring.ts";
import { SECRET_RULE_TEMPLATES } from "../scanner/secrets.ts";
import { GIT_RULE_TEMPLATES } from "../scanner/git.ts";
import { LIMITS, SCANNER_VERSION, AnalysisError } from "../sandbox/policy.ts";
import type { RepositoryScan } from "./types.ts";
import { PROJECT_ID, validateProjectId } from "./url.ts";

function integer(value: unknown, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max) throw new AnalysisError("ANALYSIS_FAILED");
  return value as number;
}
function text(value: unknown, max: number): string {
  if (typeof value !== "string" || !value.length || value.length > max || /[\u0000-\u001f]/.test(value)) throw new AnalysisError("ANALYSIS_FAILED");
  return value;
}
const canonical = new Map([...SECRET_RULE_TEMPLATES, ...Object.values(GIT_RULE_TEMPLATES)].map((entry) => [entry.title, entry]));
// Only worker-authored evidence is accepted here, never a request body. Rebuild
// fields explicitly so accidental source/config fields cannot reach disk/HTML.
export function sanitizeRepositoryEvidence(input: unknown): RepositoryScan {
  if (!input || typeof input !== "object") throw new AnalysisError("ANALYSIS_FAILED");
  const value = input as RepositoryScan;
  if (value.target !== "repository" || !PROJECT_ID.test(value.scanId) || !/^[a-f0-9]{40}$/.test(value.commitSha)
    || value.scannerVersion !== SCANNER_VERSION || !["BASELINE", "RESCAN", "FINAL"].includes(value.scanType)
    || !Number.isFinite(Date.parse(value.scannedAt)) || !Array.isArray(value.findings) || value.findings.length > LIMITS.findings) throw new AnalysisError("ANALYSIS_FAILED");
  validateProjectId(value.projectId);
  // Older Phase 5 scans were exclusively Docker scans.
  const sandboxMode = value.sandboxMode ?? "DOCKER";
  if (sandboxMode !== "DOCKER" && sandboxMode !== "LOCAL_STATIC") throw new AnalysisError("ANALYSIS_FAILED");
  const seen = new Set<string>();
  const findings = value.findings.map((f): Finding => {
    if (!/^[a-f0-9]{24}$/.test(f.id) || seen.has(f.id) || !/^\[path:[a-f0-9]{16}\]$/.test(f.filePath)
      || !SEVERITIES.includes(f.severity) || !["SECRET", "GIT_HYGIENE"].includes(f.category) || f.status !== "OPEN") throw new AnalysisError("ANALYSIS_FAILED");
    seen.add(f.id);
    const trusted = canonical.get(f.title);
    if (!trusted || trusted.category !== f.category || trusted.severity !== f.severity
      || trusted.description !== f.description || trusted.remediation !== f.remediation
      || (f.maskedSample !== undefined && (f.category !== "SECRET" || f.maskedSample !== "[REDACTED]"))) {
      throw new AnalysisError("ANALYSIS_FAILED");
    }
    if (f.lineNumber !== undefined && (!Number.isInteger(f.lineNumber) || f.lineNumber < 1)) throw new AnalysisError("ANALYSIS_FAILED");
    return { id: f.id, category: f.category, severity: f.severity, filePath: f.filePath,
      title: text(trusted.title, 150), description: text(trusted.description, 1000), remediation: text(trusted.remediation, 2000),
      status: "OPEN", penalty: PENALTIES[f.severity],
      ...(f.lineNumber === undefined ? {} : { lineNumber: integer(f.lineNumber, LIMITS.fileBytes) }),
      ...(f.maskedSample === undefined ? {} : { maskedSample: "[REDACTED]" }),
    };
  });
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((f) => counts[f.severity]++);
  const score = calculateScore(findings);
  if (score !== value.score || SEVERITIES.some((s) => counts[s] !== value.counts?.[s])) throw new AnalysisError("ANALYSIS_FAILED");
  return { scanId: value.scanId, target: "repository", projectId: value.projectId, commitSha: value.commitSha,
    sandboxMode, scanType: value.scanType, scannerVersion: SCANNER_VERSION, scannedAt: new Date(value.scannedAt).toISOString(), score, findings, counts,
    coverage: { filesScanned: integer(value.coverage?.filesScanned, LIMITS.files),
      binaryFilesSkipped: integer(value.coverage?.binaryFilesSkipped, LIMITS.files),
      generatedFilesSkipped: integer(value.coverage?.generatedFilesSkipped, LIMITS.files) } };
}
