import { execFile } from "node:child_process";
import { createFinding } from "./findings.ts";
import { ScanUnavailableError } from "./targets.ts";
import type { Finding } from "./types.ts";
import type { SourceFile } from "./files.ts";

const ENV_PROBES = [".env", ".env.local", ".env.development", ".env.production", ".env.development.local", "nested/.env", "nested/.env.local"] as const;

function readGit(root: string, gitDir: string, args: readonly string[], allowNoMatch = false): Promise<string> {
  return new Promise((resolve, reject) => {
    // Fixed executable, argument array, no shell, no user-provided arguments.
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
    execFile("git", [
      "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
      "-c", "core.excludesFile=/dev/null", "-c", "core.attributesFile=/dev/null",
      `--git-dir=${gitDir}`, `--work-tree=${root}`, ...args,
    ], {
      cwd: root, encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024,
      env: { ...env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_OPTIONAL_LOCKS: "0" },
    }, (error, stdout) => {
      if (error && !(allowNoMatch && error.code === 1)) {
        // Never propagate git stderr or underlying errors to callers or logs.
        reject(new ScanUnavailableError());
      } else resolve(stdout);
    });
  });
}

export async function inspectGit(root: string, gitDir: string, files: readonly SourceFile[]): Promise<Finding[]> {
  const tracked = (await readGit(root, gitDir, ["ls-files", "--cached", "-z"]))
    .split("\0").filter(Boolean).sort();
  const findings: Finding[] = [];
  for (const filePath of tracked) {
    if (/(?:^|\/)\.env(?:\.local)?$/.test(filePath)) {
      findings.push(createFinding("tracked-env", {
        category: "GIT_HYGIENE", severity: "HIGH", title: "Environment file tracked by Git",
        description: "The Git index includes an environment file that can expose local credentials.", filePath,
        remediation: "Remove the environment file from tracking, add environment ignore rules, and commit a secret-free .env.example instead. Rotate real exposed credentials.",
      }));
    } else if (/(?:^|\/)(?:\.env\.(?!example$|sample$|template$)[^/]+|\.npmrc|\.pypirc|\.netrc|credentials(?:\.json)?|(?:service[-_]account|secrets)[^/]*\.(?:json|ya?ml|toml)|id_rsa|id_ed25519)$|\.(?:pem|key|p12|pfx)$|(?:^|\/)\.docker\/config\.json$/i.test(filePath)) {
      findings.push(createFinding("tracked-sensitive-config", {
        category: "GIT_HYGIENE", severity: "MEDIUM", title: "Sensitive configuration tracked by Git",
        description: "The Git index includes a configuration or key file commonly used to store credentials. This check is based on the filename.", filePath,
        remediation: "Review this file, move credentials into environment variables, and ignore private configuration and key files. Keep only sanitized templates in Git.",
      }));
    }
  }

  if (!files.some((file) => file.filePath === ".gitignore")) {
    findings.push(createFinding("missing-gitignore", {
      category: "GIT_HYGIENE", severity: "MEDIUM", title: "Missing .gitignore",
      description: "The project root has no .gitignore file.", filePath: ".gitignore",
      remediation: "Create a .gitignore with .env, .env.*, node_modules/, and build-output patterns. Allow only secret-free environment templates.",
    }));
    return findings;
  }

  // Ask Git to evaluate real ignore semantics, including negations and nested rules.
  const ignored = new Set((await readGit(root, gitDir,
    ["check-ignore", "--no-index", "--", ...ENV_PROBES], true)).split(/\r?\n/).filter(Boolean));
  if (ENV_PROBES.some((probe) => !ignored.has(probe))) {
    findings.push(createFinding("missing-env-ignore", {
      category: "GIT_HYGIENE", severity: "MEDIUM", title: "Incomplete environment ignore rules",
      description: "Common root or nested environment filenames are not all protected by Git ignore rules.", filePath: ".gitignore",
      remediation: "Add .env and .env.* patterns that cover root and nested environment files. Use !.env.example only for a secret-free template.",
    }));
  }
  return findings;
}
