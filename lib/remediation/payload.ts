import "server-only";
import type { Finding } from "../scanner/types.ts";

// Only call with findings produced by scanProject, never browser-supplied objects.
// The scanner's title, description and remediation are fixed rule-authored text.
export function buildSanitizedPayload(finding: Finding) {
  return Object.freeze({
    category: finding.category,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    // File names are untrusted too: fully redact, including directories/extensions.
    filePath: "[REDACTED PATH]",
    maskedSample: finding.maskedSample === undefined ? undefined : "[REDACTED]",
    remediation: finding.remediation,
  });
}

export type SanitizedFinding = ReturnType<typeof buildSanitizedPayload>;
