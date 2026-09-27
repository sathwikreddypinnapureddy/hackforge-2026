export const LIMITS = Object.freeze({
  transferBytes: 100 * 1024 * 1024,
  repositoryBytes: 250 * 1024 * 1024,
  sourceBytes: 32 * 1024 * 1024,
  fileBytes: 1024 * 1024,
  files: 10_000,
  depth: 30,
  cloneMs: 45_000,
  scanMs: 60_000,
  outputBytes: 2 * 1024 * 1024,
  findings: 1500,
});
export const SCANNER_VERSION = "sai-phase5-v1";
export const SANDBOX_IMAGE = "hackforge-scanner:phase5";
export const ERROR_MESSAGES = {
  DOCKER_UNAVAILABLE: "Docker or the HackForge scanner image is unavailable. Start Docker and run npm run sandbox:build.",
  REPOSITORY_UNAVAILABLE: "Public repository unavailable. Check the URL; private, renamed, and missing repositories are not supported.",
  NETWORK_UNAVAILABLE: "GitHub is unavailable. Try again later.",
  REPOSITORY_LIMIT: "Repository exceeds the analysis limits. Use a smaller repository.",
  CLONE_TIMEOUT: "Repository acquisition timed out. Try a smaller repository.",
  SCAN_TIMEOUT: "Repository analysis timed out. No result was recorded.",
  UNSUPPORTED_REPOSITORY: "Repository contains unsupported files, links, submodules, or malformed data. No score was recorded.",
  ANALYSIS_FAILED: "Repository analysis could not be completed.",
  CLEANUP_FAILED: "Analysis workspace cleanup could not be confirmed. Check temporary analysis workspaces (and containers labeled hackforge.sandbox=true when using Docker) before restarting HackForge.",
  BUSY: "Another repository analysis is running. Try again when it finishes.",
  STORE_LIMIT: "Local project storage is full. No new scan was saved.",
} as const;
export type AnalysisErrorCode = keyof typeof ERROR_MESSAGES;
export class AnalysisError extends Error {
  readonly code: AnalysisErrorCode;
  constructor(code: AnalysisErrorCode) { super(ERROR_MESSAGES[code]); this.code = code; }
}
export const GENERATED = new Set(["node_modules", ".next", "dist", "build", "coverage", "vendor"]);

// No inherited credentials, NODE_OPTIONS, proxy settings, GIT_CONFIG_COUNT,
// SSH agents, or application environment. The Docker socket stays on the host.
export function processEnvironment(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/nonexistent", LANG: "C.UTF-8",
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0",
    GIT_LFS_SKIP_SMUDGE: "1", GIT_ATTR_NOSYSTEM: "1",
  };
}
export const SAFE_GIT = [
  "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
  "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null",
  "-c", "credential.helper=", "-c", "http.followRedirects=false",
  "-c", "protocol.allow=never", "-c", "protocol.http.allow=always",
  "-c", "protocol.file.allow=never", "-c", "submodule.recurse=false",
  "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "fetch.fsckObjects=true",
] as const;
