import { randomUUID } from "node:crypto";
import { readSourceFiles } from "./files.ts";
import type { SourceReadPolicy } from "./files.ts";
import { inspectGit } from "./git.ts";
import { detectSecrets } from "./secrets.ts";
import { calculateScore } from "./scoring.ts";
import { SEVERITIES } from "./types.ts";
import type { DemoTarget, ScanResult } from "./types.ts";

// Internal paths only. APIs accept demo IDs or project IDs, never this type.
export type TrustedScanTarget =
  | { kind: "demo"; target: DemoTarget; root: string; gitDir: string }
  | { kind: "repository"; target: "repository"; root: string; gitDir: string; indexPath: string; policy: SourceReadPolicy };

export async function scanTrustedTarget(target: TrustedScanTarget): Promise<ScanResult> {
  const files = await readSourceFiles(target.root, target.kind === "repository" ? target.policy : undefined);
  const findings = files.flatMap((file) => detectSecrets(file.content, file.filePath));
  findings.push(...await inspectGit(target.root, target.gitDir, files, target.kind === "repository" ? target.indexPath : undefined));
  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.filePath.localeCompare(b.filePath, "en")
    || (a.lineNumber ?? 0) - (b.lineNumber ?? 0) || a.id.localeCompare(b.id, "en"));
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const finding of findings) counts[finding.severity]++;
  return { scanId: randomUUID(), target: target.target, score: calculateScore(findings), counts, findings, scannedAt: new Date().toISOString() };
}
