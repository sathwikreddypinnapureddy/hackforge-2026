import "server-only";
import { lstat, readFile, realpath, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import type { PatchOperation } from "./workflow-types.ts";

export const PATCH_LIMITS = { files: 5, bytes: 64 * 1024, fileBytes: 32 * 1024 } as const;
export function validatePatch(operations: readonly PatchOperation[]) {
  if (!Array.isArray(operations) || !operations.length || operations.length > PATCH_LIMITS.files) throw new Error("Invalid patch");
  const seen = new Set<string>(); let bytes = 0;
  for (const op of operations) {
    if (!op || !["replace", "remove", "write"].includes(op.kind) || typeof op.path !== "string"
      || !op.path || op.path.length > 512 || /[\\\u0000-\u001f\u007f:]/.test(op.path) || path.isAbsolute(op.path)
      || op.path.split("/").some((p: string) => !p || p === "." || p === ".." || p.toLowerCase() === ".git") || seen.has(op.path)) throw new Error("Unsafe patch path");
    seen.add(op.path);
    const allowed = op.kind === "remove" ? ["kind", "path", "before"] : ["kind", "path", "before", "after"];
    if (Object.keys(op).some((key) => !allowed.includes(key)) || (op.before !== null && typeof op.before !== "string")
      || (op.kind !== "write" && (typeof op.before !== "string" || !op.before.length))
      || (op.kind !== "remove" && typeof op.after !== "string")) throw new Error("Invalid patch operation");
    for (const value of [op.before, "after" in op ? op.after : ""]) {
      if (value !== null) { const size = Buffer.byteLength(value); if (size > PATCH_LIMITS.fileBytes || value.includes("\0")) throw new Error("Patch limit"); bytes += size; }
    }
  }
  if (bytes > PATCH_LIMITS.bytes) throw new Error("Patch limit");
}
export async function safePatchPath(root: string, relative: string) {
  validatePatch([{ kind: "write", path: relative, before: null, after: "" }]);
  if (await realpath(root) !== root || root === process.cwd() || root.startsWith(process.cwd() + path.sep)) throw new Error("Unsafe repository root");
  const parts = relative.split("/");
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink() || (i < parts.length - 1 ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1)) throw new Error("Unsafe patch target");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT" || i !== parts.length - 1) throw error;
    }
  }
  return current;
}
// Private workspace, preflight every operation before writing any of them.
export async function applyApprovedPatch(root: string, operations: readonly PatchOperation[], approved: boolean) {
  if (approved !== true) throw new Error("Explicit approval required");
  validatePatch(operations);
  const planned = [];
  for (const op of operations) {
    const filename = await safePatchPath(root, op.path);
    let content: string | null = null;
    try { content = await readFile(filename, "utf8"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (op.kind === "replace") {
      if (content === null || content.split(op.before).length !== 2) throw new Error("Exact replacement must match once");
      const next = content.replace(op.before, op.after);
      if (Buffer.byteLength(next) > PATCH_LIMITS.fileBytes) throw new Error("Generated file limit");
      planned.push({ filename, next });
    } else {
      if (content !== op.before) throw new Error("File changed since proposal");
      planned.push({ filename, next: op.kind === "remove" ? null : op.after });
    }
  }
  for (const entry of planned) {
    if (entry.next === null) await unlink(entry.filename);
    else await writeFile(entry.filename, entry.next, { mode: 0o600 });
  }
}
