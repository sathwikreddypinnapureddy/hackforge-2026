export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type Severity = (typeof SEVERITIES)[number];
export type FindingStatus = "OPEN" | "RESOLVED" | "ACCEPTED_RISK" | "FALSE_POSITIVE";
export type FindingCategory = "SECRET" | "GIT_HYGIENE";
export type ScanTarget = "vulnerable-demo" | "clean-demo";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  lineNumber?: number;
  maskedSample?: string;
  remediation: string;
  status: FindingStatus;
  penalty: number;
}

export interface ScanResult {
  scanId: string;
  target: ScanTarget;
  score: number;
  counts: Record<Severity, number>;
  findings: Finding[];
  scannedAt: string;
}
