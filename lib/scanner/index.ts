import { randomUUID } from "node:crypto";
import { readSourceFiles } from "./files.ts";
import { inspectGit } from "./git.ts";
import { detectSecrets } from "./secrets.ts";
import { calculateScore } from "./scoring.ts";
import { InvalidTargetError, resolveTarget, ScanUnavailableError } from "./targets.ts";
import { SEVERITIES } from "./types.ts";
import type { ScanResult } from "./types.ts";

export async function scanProject(target: unknown): Promise<ScanResult> {
  try {
    const resolved = await resolveTarget(target);
    const files = await readSourceFiles(resolved.root);
    const findings = files.flatMap((file) => detectSecrets(file.content, file.filePath));
    findings.push(...await inspectGit(resolved.root, resolved.gitDir, files));
    findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
      || a.filePath.localeCompare(b.filePath, "en")
      || (a.lineNumber ?? 0) - (b.lineNumber ?? 0) || a.id.localeCompare(b.id, "en"));
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of findings) counts[finding.severity]++;
    return {
      scanId: randomUUID(), target: resolved.target, score: calculateScore(findings),
      counts, findings, scannedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error instanceof InvalidTargetError) throw error;
    // Errors may contain paths/content. Only the fixed sanitized error escapes.
    throw new ScanUnavailableError();
  }
}
