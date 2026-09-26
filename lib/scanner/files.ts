import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { isContained, ScanUnavailableError } from "./targets.ts";

const EXCLUDED_DIRECTORIES = new Set([".git", "node_modules", ".next", "dist", "build", "coverage"]);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 500;

export interface SourceFile { filePath: string; content: string }

export async function readSourceFiles(root: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];
  let totalBytes = 0;
  let entriesSeen = 0;

  async function visit(directory: string, depth: number): Promise<void> {
    if (depth > 20) throw new ScanUnavailableError();
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      if (++entriesSeen > MAX_FILES) throw new ScanUnavailableError();
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new ScanUnavailableError();
      const stat = await lstat(absolutePath);
      if (stat.isSymbolicLink()) throw new ScanUnavailableError();
      if (!isContained(root, await realpath(absolutePath))) throw new ScanUnavailableError();
      if (stat.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) await visit(absolutePath, depth + 1);
        continue;
      }
      if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new ScanUnavailableError();
      totalBytes += stat.size;
      if (totalBytes > MAX_TOTAL_BYTES) throw new ScanUnavailableError();
      const handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const openedStat = await handle.stat();
        if (!openedStat.isFile() || openedStat.dev !== stat.dev || openedStat.ino !== stat.ino) {
          throw new ScanUnavailableError();
        }
        const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
        let bytesRead = 0;
        while (bytesRead < buffer.length) {
          const chunk = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
          if (!chunk.bytesRead) break;
          bytesRead += chunk.bytesRead;
        }
        if (bytesRead > MAX_FILE_BYTES) throw new ScanUnavailableError();
        const bytes = buffer.subarray(0, bytesRead);
        // Fail closed instead of presenting an incomplete scan as clean.
        if (bytes.includes(0)) throw new ScanUnavailableError();
        const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        files.push({ filePath: path.relative(root, absolutePath).split(path.sep).join("/"), content });
      } finally { await handle.close(); }
    }
  }

  await visit(root, 0);
  return files;
}
