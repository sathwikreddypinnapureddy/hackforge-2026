import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import type { ScanTarget } from "./types.ts";

export class InvalidTargetError extends Error {
  constructor() { super("Choose vulnerable-demo or clean-demo."); }
}

export class ScanUnavailableError extends Error {
  constructor() { super("The controlled demo could not be scanned safely. Run npm run setup:demos and try again."); }
}

export function validateTarget(target: unknown): ScanTarget {
  if (target !== "vulnerable-demo" && target !== "clean-demo") throw new InvalidTargetError();
  return target;
}

export function validateScanInput(input: unknown): ScanTarget {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new InvalidTargetError();
  const values = input as Record<string, unknown>;
  if (Object.keys(values).length !== 1 || !("target" in values)) throw new InvalidTargetError();
  return validateTarget(values.target);
}

export function isContained(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

export async function resolveTarget(target: unknown): Promise<{ target: ScanTarget; root: string; gitDir: string }> {
  const validated = validateTarget(target); // Before ANY filesystem access.
  const workspace = await realpath(process.cwd());
  const demoBase = path.join(workspace, "demo-repos");
  const root = path.join(demoBase, validated);
  const metadataBase = path.join(demoBase, ".git-data");
  const gitDir = path.join(metadataBase, validated);
  // Reject redirected roots/metadata rather than following symlinks out of the allowlist.
  for (const directory of [demoBase, root, metadataBase, gitDir]) {
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(directory) !== directory) {
      throw new ScanUnavailableError();
    }
  }
  // Git's index/metadata must also remain inside the fixed fixture.
  let metadataEntries = 0;
  async function checkMetadata(directory: string, depth = 0): Promise<void> {
    if (depth > 10) throw new ScanUnavailableError();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (++metadataEntries > 1000) throw new ScanUnavailableError();
      if (entry.isSymbolicLink()) throw new ScanUnavailableError();
      if (entry.isDirectory()) await checkMetadata(path.join(directory, entry.name), depth + 1);
      else if (!entry.isFile()) throw new ScanUnavailableError();
    }
  }
  await checkMetadata(gitDir);
  // Phase 1 accepts only controlled fixture config: no includes, alternate paths,
  // or executable helpers from repository-controlled Git configuration.
  const expectedConfig = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = false\n";
  const configPath = path.join(gitDir, "config");
  if ((await lstat(configPath)).size > 1024 || await readFile(configPath, "utf8") !== expectedConfig) {
    throw new ScanUnavailableError();
  }
  return { target: validated, root, gitDir };
}
