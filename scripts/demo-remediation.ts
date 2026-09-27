// HackForge-controlled interactive demo: only a fresh synthetic Git fixture is modified.
import { cp, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { runCommand } from "../lib/sandbox/process.ts";
import { SAFE_GIT } from "../lib/sandbox/policy.ts";
import { scanAcquiredRepository } from "../lib/sandbox/worker.ts";
import { sanitizeRepositoryEvidence } from "../lib/projects/evidence.ts";
import { LocalProjectRepository } from "../lib/projects/store.ts";
import { RemediationJournal } from "../lib/remediation/journal.ts";
import { RemediationWorkflow } from "../lib/remediation/workflow.ts";

const root = await mkdtemp(path.join(await realpath(os.tmpdir()), "hackforge-phase6-demo-"));
const repo = path.join(root, "fixture");
let approved = false;
try {
  await mkdir(repo); await mkdir(path.join(root, "empty-template"));
  const git = (args: string[]) => runCommand("git", [...SAFE_GIT, ...args], { cwd: repo });
  await git(["init", "--quiet", "--initial-branch=main", `--template=${path.join(root, "empty-template")}`]);
  await writeFile(path.join(repo, "config.js"), 'const apiKey = "NONFUNCTIONAL_PHASE6_DEMO_VALUE";\n');
  await writeFile(path.join(repo, ".gitignore"), ".env\n.env.*\n");
  await git(["add", "--", "config.js", ".gitignore"]);
  await git(["-c", "user.name=Controlled Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", "controlled fake baseline"]);
  const projects = new LocalProjectRepository(path.join(root, "projects"));
  const project = await projects.create("https://github.com/hackforge-controlled/phase6-fixture");
  const baseline = sanitizeRepositoryEvidence({ ...await scanAcquiredRepository(repo, path.join(root, "baseline")),
    projectId: project.project.id, scanType: "BASELINE", sandboxMode: "LOCAL_STATIC" });
  await projects.appendScan(project.project.id, baseline);
  const journal = new RemediationJournal(path.join(root, "audit"));
  const workflow = new RemediationWorkflow(projects, { async clone(url, workspace) {
    if (url !== project.project.repositoryUrl) throw new Error("Controlled fixture only");
    const acquired = path.join(workspace, "repository"); await cp(repo, acquired, { recursive: true }); return acquired;
  } }, journal);
  const proposal = await workflow.propose(project.project.id, baseline.scanId, baseline.findings[0].id, "interactive-demo");
  console.log(JSON.stringify(proposal.proposal, null, 2));
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  let answer;
  try { answer = await terminal.question("Type APPROVE to create the local fix branch, or Enter to cancel: "); }
  finally { terminal.close(); }
  if (answer !== "APPROVE") {
    await workflow.cancel(proposal.id, "interactive-demo"); console.log("Cancelled. No fix branch or commit created.");
  } else {
    const ready = await workflow.approve(proposal.id, "interactive-demo", true);
    approved = true;
    console.log(JSON.stringify(ready, null, 2));
    console.log(`Audit journal: ${path.join(root, "audit/timeline.jsonl")}`);
    console.log(`Review directory: ${ready.reviewDirectory}`);
  }
} catch {
  console.error("Controlled remediation demo could not complete. No public repository was modified.");
  process.exitCode = 1;
} finally { if (!approved) await rm(root, { recursive: true, force: true }); }
