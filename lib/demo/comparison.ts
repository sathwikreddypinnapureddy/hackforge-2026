import type { ScanResult } from "../scanner/types.ts";

export function compareScans(before: ScanResult, after: ScanResult) {
  if (before.target !== after.target || before.scanId === after.scanId
    || Date.parse(after.scannedAt) < Date.parse(before.scannedAt)) {
    throw new Error("Comparison requires a later scan of the same target.");
  }
  const emittedIds = new Set(after.findings.map((finding) => finding.id));
  return {
    previousScore: before.score, newScore: after.score,
    improvement: after.score - before.score,
    previousCount: before.findings.length, newCount: after.findings.length,
    disappeared: before.findings.filter((finding) => !emittedIds.has(finding.id)),
    remaining: after.findings,
  };
}
