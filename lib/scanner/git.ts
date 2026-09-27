import { execFile } from "node:child_process";
import { createFinding } from "./findings.ts";
import { ScanUnavailableError } from "./targets.ts";
import type { Finding } from "./types.ts";
import type { SourceFile } from "./files.ts";
import { processEnvironment } from "../sandbox/policy.ts";

const ENV_PROBES = [".env", ".env.local", ".env.development", ".env.production", ".env.development.local", "nested/.env", "nested/.env.local"] as const;
export const GIT_RULE_TEMPLATES = Object.freeze({
  trackedEnv: { category: "GIT_HYGIENE" as const, severity: "HIGH" as const, title: "Environment file tracked by Git",
    description: "The Git index includes an environment file that can expose local credentials.",
    remediation: "Remove the environment file from tracking, add environment ignore rules, and commit a secret-free .env.example instead. Rotate real exposed credentials." },
  sensitiveConfig: { category: "GIT_HYGIENE" as const, severity: "MEDIUM" as const, title: "Sensitive configuration tracked by Git",
    description: "The Git index includes a configuration or key file commonly used to store credentials. This check is based on the filename.",
    remediation: "Review this file, move credentials into environment variables, and ignore private configuration and key files. Keep only sanitized templates in Git." },
  missingGitignore: { category: "GIT_HYGIENE" as const, severity: "MEDIUM" as const, title: "Missing .gitignore",
    description: "The project root has no .gitignore file.",
    remediation: "Create a .gitignore with .env, .env.*, node_modules/, and build-output patterns. Allow only secret-free environment templates." },
  missingEnvIgnore: { category: "GIT_HYGIENE" as const, severity: "MEDIUM" as const, title: "Incomplete environment ignore rules",
    description: "Common root or nested environment filenames are not all protected by Git ignore rules.",
    remediation: "Add .env and .env.* patterns that cover root and nested environment files. Use !.env.example only for a secret-free template." },
});

function readGit(root: string, gitDir: string, args: readonly string[], allowNoMatch = false, indexPath?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // Fixed executable, argument array, no shell, no user-provided arguments.
    const env = processEnvironment();
    execFile("git", [
      "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
      "-c", "core.excludesFile=/dev/null", "-c", "core.attributesFile=/dev/null",
      "-c", "core.hooksPath=/dev/null", "-c", `safe.directory=${root}`,
      `--git-dir=${gitDir}`, `--work-tree=${root}`, ...args,
    ], {
      cwd: root, encoding: "utf8", timeout: 5000, maxBuffer: indexPath ? 12 * 1024 * 1024 : 1024 * 1024,
      env: { ...env, ...(indexPath ? { GIT_INDEX_FILE: indexPath } : {}) },
    }, (error, stdout) => {
      if (error && !(allowNoMatch && error.code === 1)) {
        // Never propagate git stderr or underlying errors to callers or logs.
        reject(new ScanUnavailableError());
      } else resolve(stdout);
    });
  });
}

export async function inspectGit(root: string, gitDir: string, files: readonly SourceFile[], indexPath?: string): Promise<Finding[]> {
  const tracked = (await readGit(root, gitDir, ["ls-files", "--cached", "-z"], false, indexPath))
    .split("\0").filter(Boolean).sort();
  const findings: Finding[] = [];
  for (const filePath of tracked) {
    if (/(?:^|\/)\.env(?:\.local)?$/.test(filePath)) {
      findings.push(createFinding("tracked-env", {
        ...GIT_RULE_TEMPLATES.trackedEnv, filePath,
      }));
    } else if (/(?:^|\/)(?:\.env\.(?!example$|sample$|template$)[^/]+|\.npmrc|\.pypirc|\.netrc|credentials(?:\.json)?|(?:service[-_]account|secrets)[^/]*\.(?:json|ya?ml|toml)|id_rsa|id_ed25519)$|\.(?:pem|key|p12|pfx)$|(?:^|\/)\.docker\/config\.json$/i.test(filePath)) {
      findings.push(createFinding("tracked-sensitive-config", {
        ...GIT_RULE_TEMPLATES.sensitiveConfig, filePath,
      }));
    }
  }

  if (!files.some((file) => file.filePath === ".gitignore")) {
    findings.push(createFinding("missing-gitignore", {
      ...GIT_RULE_TEMPLATES.missingGitignore, filePath: ".gitignore",
    }));
    return findings;
  }

  // Ask Git to evaluate real ignore semantics, including negations and nested rules.
  const ignored = new Set((await readGit(root, gitDir,
    ["check-ignore", "--no-index", "--", ...ENV_PROBES], true, indexPath)).split(/\r?\n/).filter(Boolean));
  if (ENV_PROBES.some((probe) => !ignored.has(probe))) {
    findings.push(createFinding("missing-env-ignore", {
      ...GIT_RULE_TEMPLATES.missingEnvIgnore, filePath: ".gitignore",
    }));
  }
  return findings;
}
