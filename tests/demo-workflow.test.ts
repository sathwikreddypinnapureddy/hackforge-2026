import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, link, lstat, mkdtemp, readFile, readdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { mock, test } from "node:test";
import { POST as fix } from "../app/api/fix-demo/route.ts";
import { POST as scan } from "../app/api/scan/route.ts";
import { POST as explain } from "../app/api/explain/route.ts";
import { compareScans } from "../lib/demo/comparison.ts";
import { HISTORY_NOTICE, mutateDemo, validateDemoInput } from "../lib/demo/workflow.ts";
import { scanProject } from "../lib/scanner/index.ts";
import { geminiTransport } from "../lib/remediation/service.ts";
import type { ScanResult } from "../lib/scanner/types.ts";

const apply = { target: "vulnerable-demo", action: "apply-safe-fixes", confirmed: true };
const reset = { ...apply, action: "reset-vulnerable-demo" };
function request(input: unknown, headers: Record<string, string> = {}) {
  return new Request("http://localhost/api/fix-demo", {
    method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(input),
  });
}

async function snapshot(directory: string, excluded: Set<string> = new Set()): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function visit(current: string) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const filename = path.join(current, entry.name);
      const relative = path.relative(directory, filename).split(path.sep).join("/");
      if (excluded.has(relative)) continue;
      if (entry.isDirectory()) await visit(filename);
      else if (entry.isFile()) result[relative] = createHash("sha256").update(await readFile(filename)).digest("hex");
    }
  }
  await visit(directory);
  return result;
}

test("fix API rejects arbitrary targets/fields, missing confirmation, cross-origin requests and oversized input", async () => {
  for (const input of [null, [], {}, { ...apply, target: "clean-demo" }, { ...apply, target: "/etc/passwd" },
    { ...apply, target: "vulnerable-demo/../clean-demo" }, { ...apply, confirmed: false }, { ...apply, confirmed: "true" },
    { target: apply.target, action: apply.action }, { ...apply, action: "git reset --hard" },
    ...["path", "command", "content", "prompt", "findingId"].map((field) => ({ ...apply, [field]: "arbitrary" }))]) {
    assert.throws(() => validateDemoInput(input));
    assert.equal((await fix(request(input))).status, 400);
  }
  assert.equal((await fix(request({ ...apply, padding: "x".repeat(2000) }))).status, 400);
  assert.equal((await fix(new Request("http://localhost/api/fix-demo", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" }))).status, 400);
  assert.equal((await fix(request(apply, { Origin: "https://attacker.example" }))).status, 403);
  assert.equal((await fix(request(reset, { "Sec-Fetch-Site": "cross-site" }))).status, 403);
  assert.equal((await fix(request(apply, { "Content-Type": "text/plain" }))).status, 403);
});

test("confirmed cycles change only the controlled fixture and verify actual scans; Gemini remains explanation-only", async () => {
  const workspace = process.cwd();
  const excluded = new Set(["node_modules", ".next"]);
  const realBefore = await snapshot(workspace, excluded);
  const temporary = await mkdtemp(path.join(os.tmpdir(), "hackforge-phase3-"));
  await cp(path.join(workspace, "demo-repos"), path.join(temporary, "demo-repos"), { recursive: true });
  // Sentinel stands in for a real application's config; values are never logged.
  await writeFile(path.join(temporary, ".env.local"), "GEMINI_API_KEY=private-sentinel\n");
  const allowed = new Set(["demo-repos/vulnerable-demo", "demo-repos/.git-data/vulnerable-demo/index"]);
  const outsideBefore = await snapshot(temporary, allowed);
  const metadata = path.join(temporary, "demo-repos/.git-data/vulnerable-demo");
  const historyBefore = await snapshot(metadata, new Set(["index"]));
  const cwd = mock.method(process, "cwd", () => temporary);
  const logs: unknown[][] = [];
  const spies = ["log", "warn", "error", "info", "debug"].map((method) => mock.method(console, method as "log", (...values: unknown[]) => { logs.push(values); }));
  const oldKey = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "fake-gemini-test-key";
  const transport = mock.method(geminiTransport, "generate", async () => JSON.stringify({
    explanation: "CyberBot emitted this finding.", impact: "Review exposed configuration.",
    remediationSteps: ["Use environment references and rescan."], priorityReason: "Use the scanner severity.",
  }));
  try {
    assert.equal((await fix(request(reset))).status, 200);
    const initialFiles = await snapshot(path.join(temporary, "demo-repos/vulnerable-demo"));
    const initialIndex = await readFile(path.join(metadata, "index"));
    let baseline: ScanResult | undefined;
    for (let cycle = 0; cycle < 3; cycle++) {
      const response = await scan(new Request("http://localhost/api/scan", { method: "POST", body: JSON.stringify({ target: "vulnerable-demo" }) }));
      const before = await response.json() as ScanResult;
      assert.equal(before.score, 37);
      assert.equal(before.findings.length, 4);
      if (baseline) assert.deepEqual(before.findings, baseline.findings);
      baseline = before;
      const cookie = response.headers.get("set-cookie")!.split(";")[0];
      const explanationRequest = (result: ScanResult) => new Request("http://localhost/api/explain", {
        method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify({ scanId: result.scanId, findingId: result.findings[0].id }),
      });
      const guidance = await explain(explanationRequest(before));
      assert.equal(guidance.status, 200);
      assert.equal((await guidance.json()).source, "gemini");
      const fixed = await fix(request(apply));
      assert.equal(fixed.status, 200);
      assert.equal(fixed.headers.get("cache-control"), "no-store");
      const fixedResult = await fixed.json();
      assert.deepEqual(fixedResult, { action: apply.action, notice: HISTORY_NOTICE });
      assert.ok(!("resolved" in fixedResult) && !("score" in fixedResult));
      const root = path.join(temporary, "demo-repos/vulnerable-demo");
      assert.match(await readFile(path.join(root, "src/config.ts"), "utf8"), /process\.env\.API_KEY/);
      assert.ok(!(await readFile(path.join(root, ".env"), "utf8")).includes("sk-testonly"));
      assert.match(await readFile(path.join(root, ".env.example"), "utf8"), /OPENAI_API_KEY=\n/);
      assert.equal((await fix(request(apply))).status, 200); // Idempotent safe fix.
      const afterResponse = await scan(new Request("http://localhost/api/scan", {
        method: "POST", headers: { Cookie: cookie }, body: JSON.stringify({ target: "vulnerable-demo" }),
      }));
      const after = await afterResponse.json() as ScanResult;
      assert.equal(after.score, 100);
      assert.equal(after.findings.length, 0);
      const comparison = compareScans(before, after);
      assert.equal(comparison.previousScore, before.score);
      assert.equal(comparison.newScore, after.score);
      assert.equal(comparison.improvement, 63);
      assert.equal(comparison.previousCount, before.findings.length);
      assert.equal(comparison.newCount, after.findings.length);
      assert.deepEqual(comparison.disappeared.map((finding) => finding.id), before.findings.map((finding) => finding.id));
      assert.deepEqual(comparison.remaining, []);
      assert.equal((await explain(explanationRequest(before))).status, 404); // Rescan invalidates old explanations.
      assert.deepEqual(await snapshot(temporary, allowed), outsideBefore);
      assert.deepEqual(await snapshot(metadata, new Set(["index"])), historyBefore);
      assert.equal((await fix(request(reset))).status, 200);
      assert.deepEqual(await snapshot(root), initialFiles);
      assert.deepEqual(await readFile(path.join(metadata, "index")), initialIndex);
      const [, restored] = await Promise.all([
        mutateDemo(reset), scanProject("vulnerable-demo"),
      ]); // The scan must wait for the full mutation, never observe intermediate files.
      assert.deepEqual(restored.findings, before.findings);
      const restoredResponse = await scan(new Request("http://localhost/api/scan", {
        method: "POST", headers: { Cookie: cookie }, body: JSON.stringify({ target: "vulnerable-demo" }),
      }));
      assert.equal((await explain(explanationRequest(await restoredResponse.json() as ScanResult))).status, 200);
      assert.ok(!JSON.stringify({ before, after, fixedResult }).includes("sk-testonly"));
    }
    assert.equal(logs.length, 0);
  } finally {
    transport.mock.restore();
    if (oldKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = oldKey;
    for (const spy of spies) spy.mock.restore();
    cwd.mock.restore();
    await rm(temporary, { recursive: true, force: true });
  }
  assert.deepEqual(await snapshot(workspace, excluded), realBefore);
});

test("demo mutations refuse unexpected credentials, symlinks, hardlinks and redirected roots", async () => {
  const workspace = process.cwd();
  const temporary = await mkdtemp(path.join(os.tmpdir(), "hackforge-phase3-boundary-"));
  await cp(path.join(workspace, "demo-repos"), path.join(temporary, "demo-repos"), { recursive: true });
  const cwd = mock.method(process, "cwd", () => temporary);
  const root = path.join(temporary, "demo-repos/vulnerable-demo");
  const envPath = path.join(root, ".env");
  const env = await readFile(envPath);
  try {
    await writeFile(envPath, "OPENAI_API_KEY=unexpected-private-value\n");
    const before = await snapshot(temporary);
    for (const input of [apply, reset]) assert.equal((await fix(request(input))).status, 503);
    assert.deepEqual(await snapshot(temporary), before);
    await unlink(envPath);
    const outside = path.join(temporary, ".env.local");
    await writeFile(outside, "DO_NOT_CHANGE\n");
    await symlink(outside, envPath);
    assert.equal((await fix(request(apply))).status, 503);
    assert.equal((await fix(request(reset))).status, 503);
    assert.equal(await readFile(outside, "utf8"), "DO_NOT_CHANGE\n");
    await unlink(envPath);
    await writeFile(envPath, env);
    // Even known fake contents cannot redirect a write through a hardlink.
    await unlink(envPath);
    await writeFile(outside, env);
    await link(outside, envPath);
    assert.equal((await fix(request(apply))).status, 503);
    assert.equal((await fix(request(reset))).status, 503);
    assert.deepEqual(await readFile(outside), env);
    await unlink(envPath);
    await writeFile(envPath, env);
    await writeFile(outside, "DO_NOT_CHANGE\n");
    // Metadata symlinks also fail closed before any file changes.
    const index = path.join(temporary, "demo-repos/.git-data/vulnerable-demo/index");
    await unlink(index);
    await symlink(outside, index);
    assert.equal((await fix(request(reset))).status, 503);
    assert.equal(await readFile(outside, "utf8"), "DO_NOT_CHANGE\n");
    assert.ok((await lstat(index)).isSymbolicLink());
    await rm(root, { recursive: true, force: true });
    await symlink(path.join(workspace, "demo-repos/vulnerable-demo"), root);
    assert.equal((await fix(request(apply))).status, 503);
    assert.equal((await fix(request(reset))).status, 503);
  } finally {
    cwd.mock.restore();
    await rm(temporary, { recursive: true, force: true });
  }
});

test("comparison retains remaining findings, uses actual data and requires a later matching scan", async () => {
  const before = await scanProject("vulnerable-demo");
  const after = await scanProject("vulnerable-demo");
  const same = compareScans(before, after);
  assert.equal(same.improvement, 0);
  assert.deepEqual(same.disappeared, []);
  assert.deepEqual(same.remaining, after.findings);
  assert.throws(() => compareScans(before, before));
  assert.throws(() => compareScans(before, { ...after, target: "clean-demo" }));
  assert.throws(() => compareScans(before, { ...after, scannedAt: "2000-01-01T00:00:00Z" }));
});
