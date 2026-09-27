import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { validateRepositoryUrl } from "../lib/projects/url.ts";
import { TransferBudget } from "../lib/sandbox/acquisition.ts";
import { parseTree } from "../lib/sandbox/tree.ts";
import { dockerScanArguments } from "../lib/sandbox/docker.ts";
import { processEnvironment, SCANNER_VERSION } from "../lib/sandbox/policy.ts";
import { scanAcquiredRepository } from "../lib/sandbox/worker.ts";
import { LocalProjectRepository } from "../lib/projects/store.ts";
import { analyzeProject } from "../lib/projects/service.ts";
import { createSecurityReport, compareRepositoryScans, renderSecurityReport } from "../lib/projects/report.ts";
import type { AnalysisSandbox } from "../lib/sandbox/docker.ts";
import type { RepositoryScan } from "../lib/projects/types.ts";
import { sanitizeRepositoryEvidence } from "../lib/projects/evidence.ts";

test("GitHub URL validation rejects credentials, redirects, local/private targets, paths and query tricks", () => {
  assert.deepEqual(validateRepositoryUrl("https://github.com/Owner/repo.git"), {
    repositoryUrl: "https://github.com/Owner/repo.git", repositoryOwner: "Owner", repositoryName: "repo",
  });
  assert.equal(validateRepositoryUrl("https://github.com/Owner/repo").repositoryUrl, "https://github.com/Owner/repo.git");
  for (const value of ["file:///etc/passwd", "ssh://github.com/owner/repo", "git@github.com:o/r",
    "http://github.com/owner/repo", "https://github.com.evil.test/owner/repo", "https://github.com@localhost/owner/repo",
    "https://u:p@github.com/owner/repo", "https://127.0.0.1/owner/repo", "https://[::1]/owner/repo",
    "https://github.com:443/owner/repo", "https://github.com/owner/repo/evil", "https://github.com/owner/%2e%2e",
    "https://github.com/owner/repo?download=1", "https://github.com/owner/repo#x", "https://github.com/owner/..",
    "https://github.com/owner/-repo", "/tmp/project", "../project", "https://github.com/owner/repo/"]) {
    assert.throws(() => validateRepositoryUrl(value), value);
  }
});

test("bounded transfer and strict Git tree reject limits, traversal, symlinks and submodules", () => {
  const budget = new TransferBudget(100);
  budget.take(70); budget.take(30);
  assert.throws(() => budget.take(1), /REPOSITORY_LIMIT|exceeds the analysis limits/);
  const row = (mode: string, size: number, filename: string) => `${mode} blob ${"a".repeat(40)} ${size}\t${filename}\0`;
  assert.equal(parseTree(Buffer.from(row("100644", 10, "safe/file.ts")))[0].size, 10);
  for (const input of [row("120000", 10, "escape"), row("160000", 10, "module"), row("100644", 10, "../escape"),
    row("100644", 10, "dir/../../escape"), row("100644", 10, "a\\b"), row("100644", 10, ".git/config"),
    row("100644", 1024 * 1024 + 1, "large"), row("100644", 10, "dup") + row("100644", 10, "dup")]) {
    assert.throws(() => parseTree(Buffer.from(input)));
  }
});

test("container specification is offline, capped, nonroot, source readonly, and inherits no secrets", () => {
  const args = dockerScanArguments("hackforge-test", "/tmp/controlled", "sha256:" + "f".repeat(64)).join(" ");
  for (const mandatory of ["--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--user=65532:65532", "--cpus=1", "--memory=768m", "--memory-swap=768m", "--pids-limit=64",
    "target=/input,readonly", "--rm", "--pull=never"]) assert.ok(args.includes(mandatory));
  for (const forbidden of ["--privileged", "/var/run/docker.sock", "--network=host", ".env.local", "GEMINI_API_KEY"]) assert.ok(!args.includes(forbidden));
  const prior = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "never-pass-private-test-value";
  try { assert.ok(!JSON.stringify(processEnvironment()).includes("never-pass-private-test-value")); }
  finally { if (prior === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = prior; }
});

const credential = "sk-proj-FAKEONLY1234567890SAFE";
async function trustedFixture(root: string) {
  const empty = path.join(root, "empty-template");
  const repo = path.join(root, "source-repository");
  await mkdir(empty); await mkdir(repo);
  const git = (...args: string[]) => execFileSync("git", args, {
    cwd: repo, env: { ...processEnvironment(), HOME: root }, stdio: ["ignore", "pipe", "ignore"],
  }).toString().trim();
  git("init", "--quiet", `--template=${empty}`);
  await mkdir(path.join(repo, "src"));
  await writeFile(path.join(repo, ".env"), `OPENAI_API_KEY=${credential}\n`);
  await writeFile(path.join(repo, "src/config.ts"), 'const apiKey = "fake-hardcoded-demo";\n');
  await writeFile(path.join(repo, "package.json"), JSON.stringify({ scripts: { postinstall: "touch /tmp/NEVER_RUN_HACKFORGE_TEST" } }));
  await writeFile(path.join(repo, "Makefile"), "all:\n\ttouch /tmp/NEVER_RUN_HACKFORGE_TEST\n");
  git("add", ".");
  git("-c", "user.email=test@example.invalid", "-c", "user.name=Fixture", "commit", "-qm", "baseline");
  return { repo, git };
}

test("trusted synthetic Git snapshots use the existing scanner, record SHAs, and never run repository scripts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hackforge-phase5-test-"));
  try {
    const { repo, git } = await trustedFixture(root);
    const baseline = await scanAcquiredRepository(repo, path.join(root, "first-scan"));
    assert.equal(baseline.commitSha, git("rev-parse", "HEAD"));
    assert.equal(baseline.scannerVersion, SCANNER_VERSION);
    assert.ok(baseline.findings.some((finding) => finding.title === "Environment file tracked by Git"));
    assert.ok(baseline.findings.some((finding) => finding.title === "OpenAI-style key exposed"));
    assert.ok(baseline.score < 100);
    assert.ok(!JSON.stringify(baseline).includes(credential));
    assert.ok(!JSON.stringify(baseline).includes("fake-hardcoded-demo"));
    assert.ok(baseline.findings.every((finding) => /^\[path:[a-f0-9]{16}\]$/.test(finding.filePath)));
    const hostile = { ...baseline, projectId: "d926133d-25a9-4625-81c8-af9160b4c574", scanType: "BASELINE" as const,
      findings: baseline.findings.map((finding) => ({ ...finding })) };
    hostile.findings[0].description = credential;
    assert.throws(() => sanitizeRepositoryEvidence(hostile));
    hostile.findings[0].description = baseline.findings[0].description;
    hostile.findings[0].filePath = `/source/${credential}.txt`;
    assert.throws(() => sanitizeRepositoryEvidence(hostile));
    assert.rejects(() => readFile("/tmp/NEVER_RUN_HACKFORGE_TEST"));

    await writeFile(path.join(repo, "src/config.ts"), "const apiKey = process.env.API_KEY;\n");
    await writeFile(path.join(repo, ".gitignore"), ".env\n.env.*\nnode_modules/\n");
    await writeFile(path.join(repo, ".env"), "# placeholder only\n");
    git("rm", "--cached", ".env"); git("add", ".gitignore", "src/config.ts");
    git("-c", "user.email=test@example.invalid", "-c", "user.name=Fixture", "commit", "-qm", "fixed");
    const final = await scanAcquiredRepository(repo, path.join(root, "second-scan"));
    assert.equal(final.commitSha, git("rev-parse", "HEAD"));
    assert.notEqual(final.commitSha, baseline.commitSha);
    assert.equal(final.score, 100);
    assert.equal(final.findings.length, 0);

    const storage = new LocalProjectRepository(path.join(root, "project-store"));
    const created = await storage.create("https://github.com/fixture/security-demo");
    let destroyed = 0;
    let index = 0;
    const fake = (): AnalysisSandbox => ({
      async create() {}, async cloneRepository(url) { assert.equal(url, created.project.repositoryUrl); },
      getWorkspacePath: () => path.join(root, "analysis"),
      async scan() { return [baseline, final][index++] as Omit<RepositoryScan, "projectId" | "scanType">; },
      async destroy() { destroyed++; },
    });
    const first = await analyzeProject(created.project.id, "RESCAN", storage, fake);
    const second = await analyzeProject(created.project.id, "FINAL", storage, fake);
    assert.equal(first.scans[0].scanType, "BASELINE");
    assert.equal(second.scans[1].scanType, "FINAL");
    assert.equal(second.project.status, "VERIFIED");
    assert.equal(destroyed, 2);
    const comparison = compareRepositoryScans(second.scans[0], second.scans[1]);
    assert.equal(comparison.improvement, final.score - baseline.score);
    assert.equal(comparison.disappeared.length, baseline.findings.length);
    assert.equal(comparison.remaining.length, 0);
    assert.equal(comparison.newFindings.length, 0);
    const report = createSecurityReport(await storage.get(created.project.id));
    const html = renderSecurityReport(second);
    const persisted = await readFile(path.join(root, "project-store/projects.json"), "utf8");
    for (const serialized of [JSON.stringify(report), html, persisted]) {
      assert.ok(!serialized.includes(credential));
      assert.ok(!serialized.includes("fake-hardcoded-demo"));
      assert.ok(!serialized.includes("/src/config.ts"));
    }
    assert.equal(report.evidence.baselineCommitSha, baseline.commitSha);
    assert.equal(report.evidence.finalCommitSha, final.commitSha);
    assert.equal(report.verifiedResolutions.length, baseline.findings.length);
    assert.match(html, /Print \/ Save PDF/);
    assert.ok(report.methodology.includes("AI assistance is used only to explain"));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("unsupported symlinks fail closed; analysis failure destroys sandbox and saves no scan", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hackforge-phase5-test-"));
  try {
    const { repo, git } = await trustedFixture(root);
    await symlink("/etc/passwd", path.join(repo, "escape"));
    git("add", "escape");
    git("-c", "user.email=test@example.invalid", "-c", "user.name=Fixture", "commit", "-qm", "link");
    await assert.rejects(() => scanAcquiredRepository(repo, path.join(root, "work")));
    const storage = new LocalProjectRepository(path.join(root, "store"));
    const created = await storage.create("https://github.com/fixture/unsafe");
    let destroyed = false;
    await assert.rejects(() => analyzeProject(created.project.id, "RESCAN", storage, () => ({
      async create() {}, async cloneRepository() {}, getWorkspacePath: () => root,
      async scan() { throw new Error("raw remote content"); }, async destroy() { destroyed = true; },
    })));
    assert.equal(destroyed, true);
    assert.equal((await storage.get(created.project.id)).scans.length, 0);
    assert.equal((await storage.get(created.project.id)).project.status, "NOT_SCANNED");
  } finally { await rm(root, { recursive: true, force: true }); }
});
