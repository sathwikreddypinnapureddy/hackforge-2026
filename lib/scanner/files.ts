import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { isContained, ScanUnavailableError } from "./targets.ts";

const EXCLUDED_DIRECTORIES = new Set([".git", "node_modules", ".next", "dist", "build", "coverage"]);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 500;

export interface SourceFile { filePath: string; content: string }
export interface SourceReadPolicy {
  fileBytes: number; totalBytes: number; files: number; depth: number;
  skipBinary: boolean; excludeVendor: boolean;
  onBinary?: () => void;
}
const DEMO_POLICY: SourceReadPolicy = {
  fileBytes: MAX_FILE_BYTES, totalBytes: MAX_TOTAL_BYTES, files: MAX_FILES, depth: 20,
  skipBinary: false, excludeVendor: false,
};

export async function readSourceFiles(root: string, policy = DEMO_POLICY): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  let totalBytes = 0;
  let entriesSeen = 0;

  async function visit(directory: string, depth: number): Promise<void> {
    if (depth > policy.depth) throw new ScanUnavailableError();
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      if (++entriesSeen > policy.files) throw new ScanUnavailableError();
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new ScanUnavailableError();
      const stat = await lstat(absolutePath);
      if (stat.isSymbolicLink()) throw new ScanUnavailableError();
      if (!isContained(root, await realpath(absolutePath))) throw new ScanUnavailableError();
      if (stat.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name) && !(policy.excludeVendor && entry.name === "vendor")) await visit(absolutePath, depth + 1);
        continue;
      }
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > policy.fileBytes) throw new ScanUnavailableError();
      totalBytes += stat.size;
      if (totalBytes > policy.totalBytes) throw new ScanUnavailableError();
      const handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const openedStat = await handle.stat();
        if (!openedStat.isFile() || openedStat.dev !== stat.dev || openedStat.ino !== stat.ino) {
          throw new ScanUnavailableError();
        }
        const buffer = Buffer.alloc(policy.fileBytes + 1);
        let bytesRead = 0;
        while (bytesRead < buffer.length) {
          const chunk = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
          if (!chunk.bytesRead) break;
          bytesRead += chunk.bytesRead;
        }
        if (bytesRead > policy.fileBytes) throw new ScanUnavailableError();
        const bytes = buffer.subarray(0, bytesRead);
        // Fail closed instead of presenting an incomplete scan as clean.
        let content: string;
        try {
          if (bytes.includes(0)) throw new Error("Binary");
          content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        } catch {
          if (!policy.skipBinary) throw new ScanUnavailableError();
          policy.onBinary?.(); continue;
        }
        files.push({ filePath: path.relative(root, absolutePath).split(path.sep).join("/"), content });
      } finally { await handle.close(); }
    }
  }

  await visit(root, 0);
  return files;
}
