import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

// Fixture preparation only; never imported or called by the scanner/API.
// Generate real Git indexes with Node built-ins, without any mutating git command.
// Fixed manifests keep tracked .env checks reproducible after a fresh clone.
const repository = fileURLToPath(new URL("../", import.meta.url));
const manifests = {
  "vulnerable-demo": [".env", "README.md", "src/app.ts", "src/config.ts"],
  "clean-demo": [".env.example", ".gitignore", "README.md", "src/app.ts", "src/config.ts"],
};

async function safeDirectory(directory) {
  await mkdir(directory, { recursive: true });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(directory) !== directory) {
    throw new Error("Demo setup requires ordinary directories.");
  }
}

async function safeWrite(filename, content) {
  try {
    const stat = await lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Unsafe fixture metadata.");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await writeFile(filename, content);
}

for (const [target, manifest] of Object.entries(manifests)) {
  const root = path.join(repository, "demo-repos", target);
  // Separate metadata keeps worktree files commit-able in the parent project.
  const metadataBase = path.join(repository, "demo-repos", ".git-data");
  const gitDir = path.join(metadataBase, target);
  await safeDirectory(root);
  await safeDirectory(metadataBase);
  await safeDirectory(gitDir);
  // Preserve current remediation state across dev/test/build restarts.
  // Reset is an explicit confirmed API action, never an automatic lifecycle step.
  try {
    const existing = await lstat(path.join(gitDir, "index"));
    if (!existing.isFile() || existing.isSymbolicLink()) throw new Error("Unsafe fixture index.");
    continue;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await safeDirectory(path.join(gitDir, "objects"));
  await safeDirectory(path.join(gitDir, "refs"));
  await safeDirectory(path.join(gitDir, "refs", "heads"));
  await safeWrite(path.join(gitDir, "HEAD"), "ref: refs/heads/main\n");
  await safeWrite(path.join(gitDir, "config"), "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = false\n");

  const entries = [];
  for (const filename of manifest.toSorted()) {
    const content = await readFile(path.join(root, filename));
    const blob = Buffer.concat([Buffer.from(`blob ${content.length}\0`), content]);
    const digest = createHash("sha1").update(blob).digest();
    const hex = digest.toString("hex");
    const objectDirectory = path.join(gitDir, "objects", hex.slice(0, 2));
    await safeDirectory(objectDirectory);
    await safeWrite(path.join(objectDirectory, hex.slice(2)), deflateSync(blob));

    // Git index v2: 62-byte fixed stat/hash/flags section, NUL path, 8-byte padding.
    const name = Buffer.from(filename);
    const length = Math.ceil((62 + name.length + 1) / 8) * 8;
    const entry = Buffer.alloc(length);
    entry.writeUInt32BE(0o100644, 24);
    entry.writeUInt32BE(content.length, 36);
    digest.copy(entry, 40);
    entry.writeUInt16BE(name.length, 60);
    name.copy(entry, 62);
    entries.push(entry);
  }
  const header = Buffer.alloc(12);
  header.write("DIRC", 0);
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(entries.length, 8);
  const index = Buffer.concat([header, ...entries]);
  await safeWrite(path.join(gitDir, "index"), Buffer.concat([index, createHash("sha1").update(index).digest()]));
}

console.log("Controlled demo Git indexes are ready. No credential contents were logged.");
