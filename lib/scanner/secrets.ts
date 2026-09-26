import { createFinding } from "./findings.ts";
import { maskSecret } from "./masking.ts";
import type { Finding, Severity } from "./types.ts";

interface SecretRule {
  id: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

const PROVIDER_RULES: readonly SecretRule[] = [
  {
    id: "openai-key",
    pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b/g,
    severity: "CRITICAL",
    title: "OpenAI-style key exposed",
    description: "A literal matches the OpenAI-style key format. Format matching does not verify credential validity.",
  },
  {
    id: "github-token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b/g,
    severity: "CRITICAL",
    title: "GitHub-style token exposed",
    description: "A literal matches a GitHub-style token format. Format matching does not verify credential validity.",
  },
  {
    id: "aws-access-key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    severity: "HIGH",
    title: "AWS access key ID exposed",
    description: "A literal matches an AWS access key ID format. The paired secret is not required for this finding.",
  },
];

const REMEDIATION = "Remove the literal from source and tracked configuration. Load it from an environment variable. If a real credential was exposed, revoke or rotate it and remove it from repository history.";

function isReference(value: string, quoted: boolean): boolean {
  if (/^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$/.test(value)) return true;
  if (quoted) return false; // A quoted "process.env.KEY" is a literal, not a reference.
  return /^(?:process\.env(?:\.|\[)|(?:import\.meta\.)?env\.|(?:os\.)?(?:getenv|environ)\b|(?:System\.)?getenv\b|(?:Deno\.)?env\.get\b|(?:undefined|null|true|false|None)\b)/i.test(value);
}

function assignmentRule(name: string): Pick<SecretRule, "id" | "title" | "severity" | "description"> | null {
  // Normalize camelCase and separators so apiKey, API_KEY, and api-key agree.
  const normalized = name.replace(/([a-z])([A-Z])/g, "$1_$2").replace(/[-.]/g, "_").toLowerCase();
  if (/(?:^|_)(?:password|passwd|pwd)(?:_|$)/.test(normalized)) {
    return { id: "password-assignment", title: "Hardcoded password", severity: "HIGH", description: "A password-named assignment contains a literal value." };
  }
  if (/(?:^|_)api_?key(?:_|$)/.test(normalized)) {
    return { id: "generic-api-key", title: "Hardcoded API key", severity: "HIGH", description: "An API-key-named assignment contains a literal value." };
  }
  if (/(?:^|_)(?:secret|token)(?:_|$)/.test(normalized)) {
    return { id: "secret-assignment", title: "Hardcoded secret or token", severity: "HIGH", description: "A secret- or token-named assignment contains a literal value." };
  }
  return null;
}

export function detectSecrets(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((line, index) => {
    const providerSpans: { start: number; end: number }[] = [];
    for (const rule of PROVIDER_RULES) {
      // A fresh regex prevents state leaking between lines and scans.
      for (const match of line.matchAll(new RegExp(rule.pattern))) {
        const start = match.index;
        providerSpans.push({ start, end: start + match[0].length });
        const maskedSample = maskSecret(match[0]); // Redact before constructing a finding.
        findings.push(createFinding(rule.id, {
          category: "SECRET", severity: rule.severity, title: rule.title,
          description: rule.description, filePath, lineNumber: index + 1,
          maskedSample, remediation: REMEDIATION,
        }, start));
      }
    }

    // Literal assignments in env, JS/TS, Python, YAML, JSON, and simple config.
    // No source lines or captured values ever enter a finding.
    const assignments = /["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|`([^`\r\n]*)`|([^\s,;#}\]]+))/g;
    for (const match of line.matchAll(assignments)) {
      const rule = assignmentRule(match[1]);
      if (!rule) continue;
      const value = match[2] ?? match[3] ?? match[4] ?? match[5] ?? "";
      const quoted = match[2] !== undefined || match[3] !== undefined || match[4] !== undefined;
      if (!value || isReference(value, quoted)) continue;
      if (!quoted && !/^[A-Za-z0-9_./+@!$%*-]+$/.test(value)) continue;
      if (value.includes("${")) continue;
      const end = match.index + match[0].length;
      // One occurrence gets one penalty: prefer the more specific provider rule.
      if (providerSpans.some((span) => span.start >= match.index && span.end <= end)) continue;
      const maskedSample = maskSecret(value);
      findings.push(createFinding(rule.id, {
        category: "SECRET", severity: rule.severity, title: rule.title,
        description: rule.description, filePath, lineNumber: index + 1,
        maskedSample, remediation: REMEDIATION,
      }, match.index));
    }
  });

  return findings;
}
