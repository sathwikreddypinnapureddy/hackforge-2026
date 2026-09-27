import { mkdtemp, mkdir, cp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const project = fileURLToPath(new URL("../", import.meta.url));
const context = await mkdtemp(path.join(os.tmpdir(), "hackforge-image-"));
try {
  // Build from an allowlisted context. No .env.local, host Git metadata,
  // application configuration, credentials, or demo data enters the image.
  await mkdir(path.join(context, "lib/sandbox"), { recursive: true });
  await mkdir(path.join(context, "scripts"));
  await cp(path.join(project, "lib/scanner"), path.join(context, "lib/scanner"), { recursive: true });
  for (const file of ["worker.ts", "tree.ts", "policy.ts", "process.ts"]) {
    await cp(path.join(project, "lib/sandbox", file), path.join(context, "lib/sandbox", file));
  }
  await cp(path.join(project, "scripts/sandbox-worker.ts"), path.join(context, "scripts/sandbox-worker.ts"));
  await cp(path.join(project, "sandbox/Dockerfile"), path.join(context, "Dockerfile"));
  await new Promise((resolve, reject) => {
    const child = spawn("docker", ["build", "--tag", "hackforge-scanner:phase5", context], { stdio: "inherit", shell: false });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error("Scanner image build failed")));
  });
} finally { await rm(context, { recursive: true, force: true }); }
