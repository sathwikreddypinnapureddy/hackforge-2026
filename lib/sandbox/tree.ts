import { AnalysisError, GENERATED, LIMITS } from "./policy.ts";

export interface TreeEntry { filePath: string; objectId: string; size: number; generated: boolean }
export function parseTree(buffer: Buffer): TreeEntry[] {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  const entries: TreeEntry[] = [];
  let bytes = 0;
  const paths = new Set<string>();
  for (const row of text.split("\0").filter(Boolean)) {
    const match = /^(100644|100755) blob ([a-f0-9]{40}) +([0-9]+)\t([^\0]+)$/.exec(row);
    // Symlinks, gitlinks (submodules), and special modes fail closed.
    if (!match) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    const filePath = match[4];
    const parts = filePath.split("/");
    if (filePath.length > 1024 || /[\\\u0000-\u001f\u007f]/.test(filePath)
      || parts.some((part) => !part || part === "." || part === ".." || part.toLowerCase() === ".git") || paths.has(filePath)) {
      throw new AnalysisError("UNSUPPORTED_REPOSITORY");
    }
    paths.add(filePath);
    const size = Number(match[3]);
    bytes += size;
    if (parts.length > LIMITS.depth || size > LIMITS.fileBytes || bytes > LIMITS.repositoryBytes || entries.length >= LIMITS.files) {
      throw new AnalysisError("REPOSITORY_LIMIT");
    }
    entries.push({ filePath, objectId: match[2], size, generated: parts.slice(0, -1).some((part) => GENERATED.has(part)) });
  }
  if (!entries.length) throw new AnalysisError("UNSUPPORTED_REPOSITORY");
  return entries;
}
