import type { Finding, Severity } from "./types.ts";

export const PENALTIES: Readonly<Record<Severity, number>> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
};

// Trusted server evidence only. Phase 1 has no status mutation or waiver endpoint.
export interface ScoringEvidence {
  verifiedResolvedIds?: ReadonlySet<string>;
  explicitlyDismissedIds?: ReadonlySet<string>;
}

export function calculateScore(
  findings: readonly Finding[],
  evidence: ScoringEvidence = {},
): number {
  const penalties = findings.reduce((sum, finding) => {
    if (finding.status === "RESOLVED" && evidence.verifiedResolvedIds?.has(finding.id)) return sum;
    if (finding.status === "FALSE_POSITIVE" && evidence.explicitlyDismissedIds?.has(finding.id)) return sum;
    // A status label alone cannot improve the score. Recompute penalties from severity.
    return sum + PENALTIES[finding.severity];
  }, 0);
  return Math.max(0, 100 - penalties);
}
