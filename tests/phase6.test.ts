import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { RemediationWorkflow, remediationBranchName } from "../lib/remediation/workflow.ts";
import { RemediationJournal } from "../lib/remediation/journal.ts";
import { applyApprovedPatch, safePatchPath, validatePatch } from "../lib/remediation/patch.ts";
import { LocalProjectRepository } from "../lib/projects/store.ts";
import { scanAcquiredRepository } from "../lib/sandbox/worker.ts";
import { sanitizeRepositoryEvidence } from "../lib/projects/evidence.ts";
import { processEnvironment } from "../lib/sandbox/policy.ts";
import { compareRepositoryScans } from "../lib/projects/report.ts";
import type { PatchOperation } from "../lib/remediation/workflow-types.ts";

const fake = "sk-" + "proj-NONFUNCTIONALPHASE6FAKE123456";
async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "hackforge-phase6-test-"));
  const repo = path.join(root, "fixture"); const empty = path.join(root, "empty");
  await mkdir(repo); await mkdir(empty);
  const git = (...args: string[]) => execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "filter.attack.clean=cat", "-c", "filter.attack.smudge=cat", ...args], { cwd: repo,
    env: processEnvironment(), stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  git("init", "--quiet", "--initial-branch=main", `--template=${empty}`);
  await writeFile(path.join(repo, ".env"), `OPENAI_API_KEY=${fake}\n`);
  await writeFile(path.join(repo, "config.js"), 'const apiKey = "NONFUNCTIONAL_CREDENTIAL";\n');
  const marker = path.join(root, "EXECUTED");
  await writeFile(path.join(repo, "package.json"), JSON.stringify({ scripts: { preinstall: `touch ${marker}`, postinstall: `touch ${marker}`, prepare: `touch ${marker}` } }));
  for (const filename of ["attack.sh", "Makefile", "Dockerfile", "attack.py", "attack.ps1"]) await writeFile(path.join(repo, filename), `touch ${marker}\n`);
  await writeFile(path.join(repo, ".gitattributes"), "* filter=attack\n");
  git("add", "."); git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "controlled fake baseline");
  await mkdir(path.join(repo, ".git/hooks"));
  await writeFile(path.join(repo, ".git/hooks/pre-commit"), `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o755 });
  git("config", "filter.attack.clean", `touch ${marker}`); git("config", "filter.attack.smudge", `touch ${marker}`);
  const store = new LocalProjectRepository(path.join(root, "projects"));
  const created = await store.create("https://github.com/controlled/phase6-fixture");
  const scan = sanitizeRepositoryEvidence({ ...await scanAcquiredRepository(repo, path.join(root, "scan")), projectId: created.project.id, scanType: "BASELINE", sandboxMode: "LOCAL_STATIC" });
  await store.appendScan(created.project.id, scan);
  let workspace = "";
  const acquisition = { async clone(_url: string, destination: string) {
    workspace = destination;
    const acquired = path.join(destination, "repository"); await cp(repo, acquired, { recursive: true }); return acquired;
  } };
  const journal = new RemediationJournal(path.join(root, "journal"));
  const workflow = new RemediationWorkflow(store, acquisition, journal);
  return { root, repo, git, store, scan, workflow, journal, marker, workspace: () => workspace };
}

test("approval gates writes; real branch and focused commit leave source main intact, rescan verifies resolution and appends sanitized chronological evidence", async () => {
  const f = await fixture();
  let workspace = "";
  try {
    const start = Date.now();
    const finding = f.scan.findings.find((x) => x.title === "Environment file tracked by Git")!;
    const source = f.git("rev-parse", "main");
    const before = await readFile(path.join(f.repo, ".env"), "utf8");
    const proposal = await f.workflow.propose(f.scan.projectId, f.scan.scanId, finding.id, "owner");
    workspace = f.workspace();
    assert.equal(proposal.status, "PROPOSED");
    assert.equal(proposal.branchName, undefined);
    assert.equal(await readFile(path.join(workspace, "baseline/source/.env"), "utf8"), before);
    assert.equal(await readFile(path.join(f.repo, ".env"), "utf8"), before);
    const acquiredGit = (...args: string[]) => execFileSync("git", args, { cwd: path.join(workspace, "repository"), env: processEnvironment() }).toString().trim();
    assert.equal(acquiredGit("branch", "--list", "hackforge/remediation/*"), "");
    await assert.rejects(() => f.workflow.approve(proposal.id, "owner", false), /Explicit approval/);
    await assert.rejects(() => f.workflow.approve(proposal.id, "other-owner", true), /unavailable/);
    assert.equal(await readFile(path.join(workspace, "baseline/source/.env"), "utf8"), before);
    const ready = await f.workflow.approve(proposal.id, "owner", true);
    assert.equal(ready.status, "READY_FOR_REVIEW");
    assert.match(ready.branchName!, /^hackforge\/remediation\/[a-f0-9]{24}-\d{8}T\d{6}Z$/);
    assert.equal(acquiredGit("rev-parse", ready.branchName!), ready.commit!.commitSha);
    assert.equal(acquiredGit("rev-parse", "main"), source);
    assert.equal(f.git("rev-parse", "main"), source);
    assert.equal(f.git("branch", "--show-current"), "main");
    assert.equal(f.git("status", "--porcelain"), "");
    assert.equal(await readFile(path.join(f.repo, ".env"), "utf8"), before);
    assert.equal(acquiredGit("rev-parse", `${ready.commit!.commitSha}^`), source);
    assert.equal(ready.sourceCommitSha, source);
    assert.deepEqual(acquiredGit("diff-tree", "--no-commit-id", "--name-only", "-r", ready.commit!.commitSha).split("\n"), [".env"]);
    assert.equal(ready.commit!.commitSubject, "chore(security): stop tracking environment file");
    const metadata = acquiredGit("show", "-s", "--format=%aI%n%cI", ready.commit!.commitSha).split("\n");
    assert.equal(ready.commit!.authorTimestamp, new Date(metadata[0]).toISOString());
    assert.equal(ready.commit!.committerTimestamp, new Date(metadata[1]).toISOString());
    assert.equal(ready.commit!.branchName, ready.branchName);
    assert.deepEqual(ready.commit!.findingIds, [finding.id]);
    assert.equal(ready.commit!.filesChanged.length, 1);
    assert.ok(ready.resolved!.some((x) => x.id === finding.id));
    assert.ok(ready.remaining!.length > 0);
    assert.equal(ready.newFindings!.length, 0);
    assert.ok(ready.afterScore! > ready.beforeScore);
    const types = ready.timeline.map((event) => event.type);
    for (const required of ["REMEDIATION_REQUESTED", "FIX_PROPOSED", "FIX_APPROVED", "BRANCH_CREATED", "FILE_CHANGED", "COMMIT_CREATED", "RESCAN_STARTED", "RESCAN_COMPLETED", "FINDING_RESOLVED", "FINDING_REMAINING", "BRANCH_READY_FOR_REVIEW"]) assert.ok(types.includes(required as typeof types[number]), required);
    assert.ok(types.indexOf("COMMIT_CREATED") < types.indexOf("RESCAN_STARTED"));
    assert.ok(types.indexOf("RESCAN_COMPLETED") < types.indexOf("FINDING_RESOLVED"));
    const end = Date.now();
    for (const event of ready.timeline) {
      assert.ok(Date.parse(event.timestamp) >= start && Date.parse(event.timestamp) <= end);
      assert.match(event.timestamp, /Z$/);
      assert.equal(event.projectId, f.scan.projectId); assert.equal(event.remediationSessionId, ready.id);
      assert.equal(event.sourceCommitSha, source); assert.equal(event.repository, "https://github.com/controlled/phase6-fixture.git");
    }
    assert.deepEqual(ready.timeline.map((e) => e.timestamp), ready.timeline.map((e) => e.timestamp).sort());
    const persisted = await readFile(path.join(f.root, "journal/timeline.jsonl"), "utf8");
    const records = persisted.trim().split("\n").map((line) => JSON.parse(line));
    for (let i = 1; i < records.length; i++) assert.deepEqual(records[i].timeline.slice(0, records[i - 1].timeline.length), records[i - 1].timeline);
    const reopened = new RemediationJournal(path.join(f.root, "journal"));
    assert.deepEqual((await reopened.list(f.scan.projectId))[0], ready);
    for (const output of [persisted, JSON.stringify(proposal), JSON.stringify(ready)]) {
      assert.ok(!output.includes(fake)); assert.ok(!output.includes("NONFUNCTIONAL_CREDENTIAL")); assert.ok(!output.includes(f.root));
    }
    assert.equal(acquiredGit("remote"), "");
    assert.equal(f.git("rev-list", "--count", "main"), "1");
    assert.equal(acquiredGit("rev-list", "--count", ready.branchName!), "2");
    await assert.rejects(() => readFile(f.marker));
    await assert.rejects(() => f.workflow.approve(proposal.id, "owner", true), /unavailable/);
  } finally { if (workspace) await rm(workspace, { recursive: true, force: true }); await rm(f.root, { recursive: true, force: true }); }
});

test("bounded SAI templates fix missing ignore rules and a simple JS assignment using scanner verification", async () => {
  const f = await fixture(); const workspaces: string[] = [];
  try {
    for (const title of ["Missing .gitignore", "Hardcoded API key"]) {
      const finding = f.scan.findings.find((x) => x.title === title)!;
      const proposal = await f.workflow.propose(f.scan.projectId, f.scan.scanId, finding.id, "owner"); workspaces.push(f.workspace());
      assert.ok(proposal.proposal?.patchPreview);
      const ready = await f.workflow.approve(proposal.id, "owner", true);
      assert.equal(ready.status, "READY_FOR_REVIEW");
      assert.ok(ready.resolved!.some((x) => x.id === finding.id));
      assert.ok(ready.remaining!.length > 0);
      assert.equal(ready.newFindings!.length, 0);
    }
  } finally { for (const workspace of workspaces) await rm(workspace, { recursive: true, force: true }); await rm(f.root, { recursive: true, force: true }); }
});

test("cancel and baseline drift prevent commits and cancel cleans the workspace", async () => {
  const f = await fixture(); let workspace = "";
  try {
    const finding = f.scan.findings[0];
    const proposed = await f.workflow.propose(f.scan.projectId, f.scan.scanId, finding.id, "owner"); workspace = f.workspace();
    const cancelled = await f.workflow.cancel(proposed.id, "owner");
    assert.equal(cancelled.status, "CANCELLED");
    await assert.rejects(() => readdir(workspace));
    await assert.rejects(() => f.workflow.approve(proposed.id, "owner", true));
    f.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "new source commit");
    await assert.rejects(() => f.workflow.propose(f.scan.projectId, f.scan.scanId, finding.id, "owner"), /Repository changed/);
    await assert.rejects(() => readdir(f.workspace()));
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("branch naming sanitizes IDs and Git validates refs; timestamps come from the clock", () => {
  for (const id of ["HF-SEC-001", "../../main; touch /tmp/evil", "-c core.hooksPath=evil", "master", "scan$(echo evil)"]) {
    const branch = remediationBranchName(id);
    assert.match(branch, /^hackforge\/remediation\/[A-Za-z0-9-]+-\d{8}T\d{6}Z$/);
    assert.ok(!["main", "master"].includes(branch));
    execFileSync("git", ["check-ref-format", "--branch", branch], { stdio: ["ignore", "pipe", "ignore"] });
    const stamp = branch.slice(-16); const now = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
    assert.equal(stamp, now);
  }
  assert.throws(() => remediationBranchName("../../"));
});

test("patch boundary rejects traversal, absolute paths, Git metadata, shell-shaped operations, duplicates and oversized data", () => {
  for (const filename of ["../escape", "nested/../../escape", "/etc/passwd", ".git/config", "nested/.GiT/hooks/post-commit", "C:/Windows/system.ini", "a\\b", "a/./b", "a//b"]) {
    assert.throws(() => validatePatch([{ kind: "write", path: filename, before: null, after: "safe" }]));
  }
  assert.throws(() => validatePatch([{ kind: "shell", command: "touch evil" }] as unknown as PatchOperation[]));
  assert.throws(() => validatePatch([{ kind: "write", path: "safe", before: null, after: "safe", resolved: true }] as unknown as PatchOperation[]));
  assert.throws(() => validatePatch(Array.from({ length: 6 }, (_, i) => ({ kind: "write" as const, path: `file${i}`, before: null, after: "safe" }))));
  assert.throws(() => validatePatch([{ kind: "write", path: "safe", before: null, after: "x".repeat(32 * 1024 + 1) }]));
  assert.throws(() => validatePatch([{ kind: "write", path: "safe", before: null, after: "safe" }, { kind: "write", path: "safe", before: null, after: "safe" }]));
});

test("symlinks, hardlinks and protected HackForge paths are rejected; preflight failures and missing approval write nothing", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hackforge-patch-test-"));
  try {
    await writeFile(path.join(root, "safe.txt"), "original");
    await symlink("/etc", path.join(root, "escape"));
    await symlink(path.join(root, "safe.txt"), path.join(root, "alias"));
    await import("node:fs/promises").then((fs) => fs.link(path.join(root, "safe.txt"), path.join(root, "hardlink")));
    for (const filename of ["escape/passwd", "alias", "hardlink"]) await assert.rejects(() => safePatchPath(root, filename));
    await assert.rejects(() => safePatchPath(process.cwd(), "package.json"));
    await writeFile(path.join(root, "one.txt"), "original");
    const op: PatchOperation = { kind: "replace", path: "one.txt", before: "original", after: "approved" };
    await assert.rejects(() => applyApprovedPatch(root, [op], false), /approval/);
    await assert.rejects(() => applyApprovedPatch(root, [op, { kind: "remove", path: "missing", before: "mismatch" }], true));
    assert.equal(await readFile(path.join(root, "one.txt"), "utf8"), "original");
    await applyApprovedPatch(root, [op], true);
    assert.equal(await readFile(path.join(root, "one.txt"), "utf8"), "approved");
    await assert.rejects(() => applyApprovedPatch(root, [op], true));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("remaining and new findings come only from stable scanner ID comparison", async () => {
  const f = await fixture();
  try {
    await writeFile(path.join(f.repo, "new.js"), 'const password = "NONFUNCTIONAL_NEW_PASSWORD";\n');
    f.git("-c", "filter.attack.clean=cat", "add", "new.js");
    f.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "new fake finding");
    const after = sanitizeRepositoryEvidence({ ...await scanAcquiredRepository(f.repo, path.join(f.root, "new-scan")), projectId: f.scan.projectId, scanType: "RESCAN", sandboxMode: "LOCAL_STATIC" });
    const result = compareRepositoryScans(f.scan, after);
    assert.equal(result.disappeared.length, 0);
    assert.equal(result.remaining.length, f.scan.findings.length);
    assert.equal(result.newFindings.length, 1);
    assert.equal(result.newFindings[0].title, "Hardcoded password");
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("remediation API rejects implicit approvals, supplied patches, scanner authority fields, commands and cross-origin requests", async () => {
  const { POST } = await import("../app/api/projects/[id]/remediation/route.ts");
  const context = { params: Promise.resolve({ id: "a926133d-25a9-4625-81c8-af9160b4c574" }) };
  for (const body of [
    { action: "approve", sessionId: "a926133d-25a9-4625-81c8-af9160b4c574" },
    { action: "approve", sessionId: "a926133d-25a9-4625-81c8-af9160b4c574", approved: true, resolved: true },
    { action: "propose", scanId: "a926133d-25a9-4625-81c8-af9160b4c574", findingId: "a".repeat(24), operations: [{ kind: "write", path: ".git/config" }] },
    { action: "shell", command: "git push --force" },
    { score: 100, severity: "LOW", status: "RESOLVED" },
  ]) {
    const response = await POST(new Request("http://localhost/api/projects/test/remediation", {
      method: "POST", headers: { "Content-Type": "application/json", cookie: "hackforge-scan-session=a926133d-25a9-4625-81c8-af9160b4c574" }, body: JSON.stringify(body),
    }), context);
    assert.equal(response.status, 400);
    const data = await response.json(); assert.ok(!JSON.stringify(data).includes("git push"));
  }
  const cross = await POST(new Request("http://localhost/api/projects/test/remediation", { method: "POST",
    headers: { "Content-Type": "application/json", origin: "https://evil.invalid" }, body: "{}" }), context);
  assert.equal(cross.status, 403);
});

test("file drift after proposal fails closed without a commit, rescan, or ready status", async () => {
  const f = await fixture();
  try {
    const finding = f.scan.findings.find((x) => x.title === "Hardcoded API key")!;
    const proposal = await f.workflow.propose(f.scan.projectId, f.scan.scanId, finding.id, "owner");
    const filename = path.join(f.workspace(), "baseline/source/config.js");
    await writeFile(filename, (await readFile(filename, "utf8")) + "// unapproved drift\n");
    await assert.rejects(() => f.workflow.approve(proposal.id, "owner", true), /failed safely/);
    const failed = (await f.journal.list(f.scan.projectId))[0];
    assert.equal(failed.status, "FAILED");
    assert.ok(!failed.timeline.some((event) => ["COMMIT_CREATED", "RESCAN_STARTED", "BRANCH_READY_FOR_REVIEW"].includes(event.type)));
    await assert.rejects(() => readdir(f.workspace()));
    assert.equal(f.git("rev-parse", "main"), f.scan.commitSha);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
