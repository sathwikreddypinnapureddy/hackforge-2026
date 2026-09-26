import "server-only";
import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { readSourceFiles } from "../scanner/files.ts";
import { resolveTarget } from "../scanner/targets.ts";
import { withDemoLock } from "./lock.ts";

export const HISTORY_NOTICE = "Credential rotation and Git history review recommended.";
export type DemoAction = "apply-safe-fixes" | "reset-vulnerable-demo";

export function validateDemoInput(input: unknown): DemoAction {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid action");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== 3 || value.target !== "vulnerable-demo"
    || value.confirmed !== true
    || (value.action !== "apply-safe-fixes" && value.action !== "reset-vulnerable-demo")) {
    throw new Error("Invalid action");
  }
  return value.action;
}

// Fixed fake templates only. No request content ever reaches the filesystem.
const INITIAL_CONFIG = '// Every credential in this fixture is fake and nonfunctional.\nexport const config = {\n  apiKey: "fake-testonly-api-key-00000000",\n};\n';
const INITIAL_ENV = '# Deliberately fake, nonfunctional demo credential.\nOPENAI_API_KEY=sk-testonly000000000000000000000000\n';
const SAFE_CONFIG = '// Demo credentials are supplied through the environment.\nexport const config = {\n  apiKey: process.env.API_KEY,\n};\n';
const SAFE_ENV = '# Demo credentials removed. Supply values through your environment.\n';
const IGNORE = '.env\n.env.*\n!.env.example\nnode_modules/\n.next/\ndist/\nbuild/\n';
const EXAMPLE = '# Secret-free demo template.\nAPI_KEY=\nOPENAI_API_KEY=\n';
const MANIFEST = new Set([".env", "README.md", "src/app.ts", "src/config.ts", ".gitignore", ".env.example"]);

async function checkFile(filename: string): Promise<void> {
  try {
    const stat = await lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("Unsafe fixture");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function replaceFile(filename: string, content: string | Buffer): Promise<void> {
  await checkFile(filename);
  const temporary = `${filename}.hackforge-${randomUUID()}`;
  try {
    await writeFile(temporary, content, { flag: "wx", mode: 0o600 });
    await rename(temporary, filename);
  } finally { await unlink(temporary).catch(() => undefined); }
}

// Edit only the controlled v2 index. Preserve other entries and all Git objects,
// refs, HEAD, and history. There are no executable commands or Git hooks here.
function updatedIndex(index: Buffer, reset: boolean): Buffer {
  if (index.length < 32 || index.toString("ascii", 0, 4) !== "DIRC" || index.readUInt32BE(4) !== 2
    || !createHash("sha1").update(index.subarray(0, -20)).digest().equals(index.subarray(-20))) {
    throw new Error("Unsafe index");
  }
  const entries: { name: string; bytes: Buffer }[] = [];
  let offset = 12;
  const count = index.readUInt32BE(8);
  if (count > MANIFEST.size) throw new Error("Unsafe index");
  for (let i = 0; i < count; i++) {
    const end = index.indexOf(0, offset + 62);
    if (end < 0 || end >= index.length - 20) throw new Error("Unsafe index");
    const length = Math.ceil((end - offset + 1) / 8) * 8;
    const name = index.toString("utf8", offset + 62, end);
    if (!MANIFEST.has(name)) throw new Error("Unsafe index");
    if (name !== ".env") entries.push({ name, bytes: index.subarray(offset, offset + length) });
    offset += length;
  }
  if (offset !== index.length - 20) throw new Error("Unsupported index extensions");
  if (reset) {
    const content = Buffer.from(INITIAL_ENV);
    const digest = createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest();
    const bytes = Buffer.alloc(72);
    bytes.writeUInt32BE(0o100644, 24);
    bytes.writeUInt32BE(content.length, 36);
    digest.copy(bytes, 40);
    bytes.writeUInt16BE(4, 60);
    bytes.write(".env", 62);
    entries.push({ name: ".env", bytes });
  }
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const header = Buffer.from(index.subarray(0, 12));
  header.writeUInt32BE(entries.length, 8);
  const body = Buffer.concat([header, ...entries.map((entry) => entry.bytes)]);
  return Buffer.concat([body, createHash("sha1").update(body).digest()]);
}

export function mutateDemo(input: unknown): Promise<{ action: DemoAction; notice: string }> {
  const action = validateDemoInput(input); // Validate before filesystem access.
  return withDemoLock(async () => {
    const { root, gitDir } = await resolveTarget("vulnerable-demo");
    const files = await readSourceFiles(root);
    if (files.some((file) => !MANIFEST.has(file.filePath))) throw new Error("Unexpected fixture state");
    const contents = new Map(files.map((file) => [file.filePath, file.content]));
    const allowed: Record<string, (string | undefined)[]> = {
      "src/config.ts": [INITIAL_CONFIG, SAFE_CONFIG], ".env": [INITIAL_ENV, SAFE_ENV],
      ".gitignore": [undefined, IGNORE], ".env.example": [undefined, EXAMPLE],
    };
    // Refuse unexpected contents, including real credentials, before ANY mutation.
    for (const [filename, versions] of Object.entries(allowed)) {
      if (!versions.includes(contents.get(filename))) throw new Error("Unexpected fixture state");
      await checkFile(path.join(root, filename));
    }
    const indexPath = path.join(gitDir, "index");
    await checkFile(indexPath);
    const reset = action === "reset-vulnerable-demo";
    const index = updatedIndex(await readFile(indexPath), reset);
    await replaceFile(path.join(root, "src/config.ts"), reset ? INITIAL_CONFIG : SAFE_CONFIG);
    await replaceFile(path.join(root, ".env"), reset ? INITIAL_ENV : SAFE_ENV);
    for (const [filename, content] of [[".gitignore", IGNORE], [".env.example", EXAMPLE]]) {
      if (reset) {
        if (contents.has(filename)) await unlink(path.join(root, filename));
      } else await replaceFile(path.join(root, filename), content);
    }
    await replaceFile(indexPath, index);
    return { action, notice: HISTORY_NOTICE };
  });
}
