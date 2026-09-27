import { createHash } from "node:crypto";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { scanTrustedTarget } from "../scanner/core.ts";
import { AnalysisError, LIMITS, SAFE_GIT, SCANNER_VERSION, processEnvironment } from "./policy.ts";
import { runCommand } from "./process.ts";
import { parseTree } from "./tree.ts";
import { isContained } from "../scanner/targets.ts";

export async function scanAcquiredRepository(acquiredRoot: string, work: string) {
  const gitDir = path.join(acquiredRoot, ".git");
  const root = path.join(work, "source");
  const indexPath = path.join(work, "index");
  await mkdir(root, { recursive: true });
  const args = [...SAFE_GIT, "-c", `safe.directory=${acquiredRoot}`, `--git-dir=${gitDir}`, `--work-tree=${root}`];
  const git = (extra: string[], maxBytes = LIMITS.outputBytes) => runCommand("git", [...args, ...extra], {
    cwd: work, maxBytes, detached: false, env: { ...processEnvironment(), GIT_INDEX_FILE: indexPath }, failureCode: "UNSUPPORTED_REPOSITORY",
  });
  const commitSha = (await git(["rev-parse", "--verify", "HEAD^{commit}"])).toString("ascii").trim();
  if (!/^[0-9a-f]{40}$/.test(commitSha)) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
  const entries = parseTree(await git(["ls-tree", "-r", "-l", "-z", "--full-tree", commitSha], 12 * 1024 * 1024));
  let sourceBytes = 0;
  let binaryFilesSkipped = 0;
  for (const entry of entries) {
    if (entry.generated) continue;
    // Only blob IDs from a validated Git tree are passed to cat-file. Nothing
    // from package.json, attributes, hooks, Makefiles, or scripts is executed.
    const content = await git(["cat-file", "blob", entry.objectId], LIMITS.fileBytes + 1);
    if (content.length !== entry.size) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    if (content.subarray(0, 100).toString().startsWith("version https://git-lfs.github.com/spec/v1")) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    try {
      if (/\.(?:png|jpe?g|gif|ico|webp|pdf|zip|gz|jar|wasm|exe|bin|mp[34]|mov|class)$/i.test(entry.filePath) || content.includes(0)) throw new Error("Binary");
      new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch { binaryFilesSkipped++; continue; }
    sourceBytes += content.length;
    if (sourceBytes > LIMITS.sourceBytes) throw new AnalysisError("REPOSITORY_LIMIT");
    const filename = path.resolve(root, entry.filePath);
    if (!isContained(root, filename)) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    await mkdir(path.dirname(filename), { recursive: true });
    if (!isContained(root, await realpath(path.dirname(filename)))) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    await writeFile(filename, content, { flag: "wx", mode: 0o600 });
  }
  // Build the index for the existing Git hygiene checks without checkout.
  await git(["read-tree", commitSha]);
  const result = await scanTrustedTarget({ kind: "repository", target: "repository", root, gitDir, indexPath,
    policy: { fileBytes: LIMITS.fileBytes, totalBytes: LIMITS.sourceBytes, files: LIMITS.files * 2,
      depth: LIMITS.depth, skipBinary: false, excludeVendor: true } });
  if (result.findings.length > LIMITS.findings) throw new AnalysisError("REPOSITORY_LIMIT");
  // Preserve location/rule IDs; never use captured credential values as IDs.
  // Filenames can themselves contain secrets. Keep only opaque path references.
  result.findings = result.findings.map((finding) => ({ ...finding,
    filePath: `[path:${createHash("sha256").update(finding.filePath).digest("hex").slice(0, 16)}]`,
    ...(finding.maskedSample !== undefined ? { maskedSample: "[REDACTED]" } : {}),
  }));
  const generatedFilesSkipped = entries.filter((entry) => entry.generated).length;
  return { ...result, target: "repository" as const, commitSha, scannerVersion: SCANNER_VERSION,
    coverage: { filesScanned: entries.length - generatedFilesSkipped - binaryFilesSkipped, binaryFilesSkipped, generatedFilesSkipped } };
}
