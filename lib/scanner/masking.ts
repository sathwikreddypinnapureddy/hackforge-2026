// Full redaction deliberately reveals neither prefix, suffix, nor secret length.
export function maskSecret(value: string): string {
  return value.length ? "[REDACTED]" : "";
}

export function sanitizeFilePath(filePath: string): string {
  return filePath
    .replace(/\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/g, "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f]/g, "?");
}
