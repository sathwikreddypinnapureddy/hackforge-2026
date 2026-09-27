import "server-only";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PublicGitHubAcquisition, validateAcquiredTree } from "../sandbox/acquisition.ts";
import type { RepositoryAcquisition } from "../sandbox/acquisition.ts";
import { runCommand } from "../sandbox/process.ts";
import { SAFE_GIT, processEnvironment } from "../sandbox/policy.ts";
import { scanAcquiredRepository } from "../sandbox/worker.ts";
import { parseTree } from "../sandbox/tree.ts";
import { sanitizeRepositoryEvidence } from "../projects/evidence.ts";
import { compareRepositoryScans } from "../projects/report.ts";
import { projectStore } from "../projects/store.ts";
import type { ProjectRepository, RepositoryScan } from "../projects/types.ts";
import { applyApprovedPatch, safePatchPath, validatePatch } from "./patch.ts";
import { RemediationJournal } from "./journal.ts";
import type { EventType, PatchOperation, RemediationSession } from "./workflow-types.ts";

export function remediationBranchName(id: string) {
  const safe = id.replace(/[^A-Za-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 64);
  if (!safe) throw new Error("Invalid branch identifier");
  return `hackforge/remediation/${safe}-${new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")}`;
}
function pathReference(value: string) { return `[path:${createHash("sha256").update(value).digest("hex").slice(0, 16)}]`; }
interface Pending { session: RemediationSession; workspace: string; repository: string; source: string; index: string;
  operations: PatchOperation[]; fileDigests: Map<string, string | null>; baseline: RepositoryScan; owner: string; expires: number; busy: boolean }
export class RemediationWorkflow {
  private proposals = new Map<string, Promise<RemediationSession>>();
  private pending = new Map<string, Pending>();
  private projects: ProjectRepository;
  private acquisition: RepositoryAcquisition;
  readonly journal: RemediationJournal;
  constructor(projects: ProjectRepository = projectStore, acquisition: RepositoryAcquisition = new PublicGitHubAcquisition(),
    journal = new RemediationJournal()) { this.projects = projects; this.acquisition = acquisition; this.journal = journal; }
  private git(repository: string, args: string[], source = repository, index?: string) {
    return runCommand("git", [...SAFE_GIT, "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
      "-c", `safe.directory=${repository}`, `--git-dir=${path.join(repository, ".git")}`, `--work-tree=${source}`, ...args], {
      cwd: repository, env: { ...processEnvironment(), GIT_LITERAL_PATHSPECS: "1", ...(index ? { GIT_INDEX_FILE: index } : {}) },
    });
  }
  private async event(p: Pending, type: EventType, description: string, findingIds = p.session.findingIds, scanId = p.session.scanId) {
    const s = p.session;
    s.timeline.push({ eventId: randomUUID(), timestamp: new Date().toISOString(), type, description,
      projectId: s.projectId, remediationSessionId: s.id, scanId, findingIds,
      repository: s.repository, sourceCommitSha: s.sourceCommitSha,
      ...(s.branchName ? { branchName: s.branchName } : {}), ...(s.commit ? { commitSha: s.commit.commitSha } : {}) });
    await this.journal.append(s);
  }
  private async expire() {
    for (const [id, p] of this.pending) if (!p.busy && p.expires < Date.now()) {
      p.session.status = "CANCELLED"; await this.journal.append(p.session);
      await rm(p.workspace, { recursive: true, force: true }); this.pending.delete(id);
    }
  }
  async propose(projectId: string, scanId: string, findingId: string, owner: string): Promise<RemediationSession> {
    const key = JSON.stringify([projectId, scanId, findingId]);
    const running = this.proposals.get(key);
    if (running) { await running; return this.propose(projectId, scanId, findingId, owner); }
    const task = this.prepareProposal(projectId, scanId, findingId, owner);
    this.proposals.set(key, task);
    try { return await task; } finally { this.proposals.delete(key); }
  }
  private async prepareProposal(projectId: string, scanId: string, findingId: string, owner: string) {
    const ready = (await this.journal.list(projectId)).reverse().find((s) => s.scanId === scanId && s.findingIds.includes(findingId) && s.status === "READY_FOR_REVIEW");
    if (ready) return structuredClone(ready);
    const existing = [...this.pending.values()].find((p) => p.session.projectId === projectId && p.session.scanId === scanId && p.session.findingIds.includes(findingId) && p.expires > Date.now());
    if (existing) {
      if (existing.owner !== owner) throw new Error("Proposal unavailable; another review is in progress");
      return structuredClone(existing.session);
    }
    await this.expire();
    if (this.pending.size >= 10) throw new Error("Too many proposals");
    const detail = await this.projects.get(projectId);
    const baseline = detail.scans.at(-1);
    const finding = baseline?.findings.find((f) => f.id === findingId);
    if (!baseline || baseline.scanId !== scanId || !finding) throw new Error("Verified finding required");
    const workspace = await mkdtemp(path.join(await realpath(os.tmpdir()), "hackforge-remediation-"));
    const s: RemediationSession = { id: randomUUID(), projectId, scanId, findingIds: [findingId], repository: detail.project.repositoryUrl,
      sourceCommitSha: baseline.commitSha, status: "PROPOSED", beforeScore: baseline.score, timeline: [] };
    const p: Pending = { session: s, workspace, repository: "", source: path.join(workspace, "baseline", "source"),
      index: path.join(workspace, "baseline", "index"), operations: [], fileDigests: new Map(), baseline, owner, expires: Date.now() + 15 * 60_000, busy: false };
    try {
      await this.event(p, "REMEDIATION_REQUESTED", "Remediation requested for a verified scanner finding.");
      p.repository = await this.acquisition.clone(s.repository, workspace);
      if (p.repository !== path.join(workspace, "repository") || await realpath(p.repository) !== p.repository) throw new Error("Unsafe acquisition");
      await validateAcquiredTree(p.repository);
      // Strip remote/filter/hook configuration. Never checkout untrusted attributes.
      await writeFile(path.join(p.repository, ".git/config"), "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = false\n");
      const head = (await this.git(p.repository, ["rev-parse", "--verify", "HEAD^{commit}"])).toString().trim();
      if (head !== baseline.commitSha) throw new Error("Repository changed; refresh the baseline scan");
      const check = sanitizeRepositoryEvidence({ ...await scanAcquiredRepository(p.repository, path.join(workspace, "baseline")), projectId, scanType: "RESCAN", sandboxMode: "LOCAL_STATIC" });
      if (check.score !== baseline.score || JSON.stringify(check.findings) !== JSON.stringify(baseline.findings)) throw new Error("Baseline evidence mismatch");
      const entries = parseTree(await this.git(p.repository, ["ls-tree", "-r", "-l", "-z", "--full-tree", head]));
      const file = finding.title === "Missing .gitignore" ? ".gitignore" : entries.find((entry) => pathReference(entry.filePath) === finding.filePath)?.filePath;
      if (!file) throw new Error("Finding file unavailable");
      const ignores = ".env\n.env.*\n!.env.example\nnode_modules/\n.next/\ndist/\nbuild/\n";
      let subject: string;
      let description: string;
      let preview: string;
      if (finding.title === "Missing .gitignore" || finding.title === "Incomplete environment ignore rules") {
        let before: string | null = null;
        try { before = await readFile(await safePatchPath(p.source, ".gitignore"), "utf8"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        p.operations = [{ kind: "write", path: ".gitignore", before, after: (before ? before + "\n" : "") + ignores }];
        subject = "chore(security): add environment ignore rules";
        description = "Append root and nested environment ignore rules; keep the secret-free example exception. Review nested overrides after rescanning.";
        preview = `--- .gitignore\n+++ .gitignore\n[Existing content redacted and preserved]\n${ignores.split("\n").filter(Boolean).map((line) => "+ " + line).join("\n")}`;
      } else if (/^Environment file tracked by Git$/.test(finding.title) || (finding.category === "SECRET" && /(?:^|\/)\.env(?:\.[^/]+)?$/.test(file) && !/\.(example|sample|template)$/.test(file))) {
        const before = await readFile(await safePatchPath(p.source, file), "utf8");
        p.operations = [{ kind: "remove", path: file, before }];
        subject = "chore(security): stop tracking environment file";
        description = "Remove this entire tracked environment file from the branch snapshot. Configure environment values outside Git and rotate real exposed credentials. Historical commits still contain the original data.";
        preview = `--- ${finding.filePath}\n+++ /dev/null\n- [Entire environment file removed; contents redacted]`;
      } else if (finding.category === "SECRET" && /\.[cm]?[jt]sx?$/.test(file) && finding.lineNumber) {
        const content = await readFile(await safePatchPath(p.source, file), "utf8");
        const line = content.split("\n")[finding.lineNumber - 1];
        const match = /^(\s*)((?:export\s+)?(?:const|let|var))\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(["'])[^"'\r\n]*\4;?\s*$/.exec(line);
        if (!match) throw new Error("This finding requires manual remediation");
        const after = `${match[1]}${match[2]} ${match[3]} = process.env.HACKFORGE_CREDENTIAL;`;
        p.operations = [{ kind: "replace", path: file, before: line, after }];
        subject = "fix(security): remove exposed API credential";
        description = "Replace the single credential assignment with process.env.HACKFORGE_CREDENTIAL. Configure that variable outside Git and rotate real exposed credentials. Review runtime behavior before merging.";
        preview = `--- ${finding.filePath}\n+++ ${finding.filePath}\n@@ line ${finding.lineNumber} @@\n- [Credential assignment redacted]\n+ [Same binding] = process.env.HACKFORGE_CREDENTIAL;`;
      } else throw new Error("This finding requires manual remediation");
      validatePatch(p.operations);
      for (const op of p.operations) {
        let content: Buffer | null = null;
        try { content = await readFile(await safePatchPath(p.source, op.path)); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        p.fileDigests.set(op.path, content === null ? null : createHash("sha256").update(content).digest("hex"));
      }
      s.proposal = { findingId, severity: finding.severity, file: finding.filePath, remediation: description,
        filesToModify: p.operations.map((op) => pathReference(op.path)), patchPreview: preview, commitMessage: subject };
      await this.event(p, "FIX_PROPOSED", "SAI Assistant proposed a bounded change for explicit user review.");
      this.pending.set(s.id, p); return structuredClone(s);
    } catch (error) {
      s.status = "FAILED"; await this.journal.append(s); await rm(workspace, { recursive: true, force: true });
      if (error instanceof Error && /^(Repository changed|This finding requires)/.test(error.message)) throw error;
      throw new Error("Safe remediation proposal could not be prepared");
    }
  }
  async cancel(id: string, owner: string) {
    const p = this.pending.get(id);
    if (!p || p.owner !== owner || p.busy) throw new Error("Proposal unavailable");
    p.busy = true; p.session.status = "CANCELLED";
    await this.journal.append(p.session); await rm(p.workspace, { recursive: true, force: true }); this.pending.delete(id);
    return structuredClone(p.session);
  }
  async approve(id: string, owner: string, approved: boolean) {
    if (approved !== true) throw new Error("Explicit approval required");
    await this.expire();
    const p = this.pending.get(id);
    if (!p || p.owner !== owner || p.busy || p.session.status !== "PROPOSED") throw new Error("Proposal unavailable or already approved");
    p.busy = true;
    const s = p.session;
    const git = (args: string[]) => this.git(p.repository, args, p.source, p.index);
    try {
      s.status = "APPLYING";
      await this.event(p, "FIX_APPROVED", "User explicitly approved the displayed patch and commit subject.");
      for (const op of p.operations) {
        let content: Buffer | null = null;
        try { content = await readFile(await safePatchPath(p.source, op.path)); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        const digest = content === null ? null : createHash("sha256").update(content).digest("hex");
        if (digest !== p.fileDigests.get(op.path)) throw new Error("File drift since proposal");
      }
      const working = `hackforge/working/${s.id}`;
      s.branchName = remediationBranchName(s.findingIds.length === 1 ? s.findingIds[0] : s.scanId);
      await git(["check-ref-format", "--branch", s.branchName]);
      await git(["branch", working, s.sourceCommitSha]);
      await git(["symbolic-ref", "HEAD", `refs/heads/${working}`]);
      await git(["branch", s.branchName, s.sourceCommitSha]);
      await git(["symbolic-ref", "HEAD", `refs/heads/${s.branchName}`]);
      await this.event(p, "BRANCH_CREATED", "Local remediation branch created from the exact source commit.");
      await applyApprovedPatch(p.source, p.operations, true);
      for (const op of p.operations) await this.event(p, "FILE_CHANGED", `Approved ${op.kind} operation applied to ${pathReference(op.path)}.`);
      await git(["add", "--force", "--", ...p.operations.map((op) => op.path)]);
      const changed = (await git(["diff", "--cached", "--name-only", "-z"])).toString().split("\0").filter(Boolean);
      if (!changed.length || changed.length !== p.operations.length || changed.some((file) => !p.operations.some((op) => op.path === file))) throw new Error("Unexpected changed files");
      await git(["-c", "user.name=HackForge", "-c", "user.email=remediation@hackforge.invalid", "commit", "--no-gpg-sign", "-m", s.proposal!.commitMessage]);
      const metadata = (await git(["show", "-s", "--format=%H%n%s%n%aI%n%cI", "HEAD"])).toString().trim().split("\n");
      if (!/^[a-f0-9]{40}$/.test(metadata[0]) || metadata[1] !== s.proposal!.commitMessage || metadata.slice(2).some((time) => !Number.isFinite(Date.parse(time)))) throw new Error("Invalid commit metadata");
      const parent = (await git(["rev-parse", "HEAD^"])).toString().trim();
      if (parent !== s.sourceCommitSha) throw new Error("Source commit mismatch");
      s.commit = { branchName: s.branchName, commitSha: metadata[0], commitSubject: metadata[1], findingIds: s.findingIds,
        filesChanged: changed.map(pathReference), authorTimestamp: new Date(metadata[2]).toISOString(), committerTimestamp: new Date(metadata[3]).toISOString(), sanitizedSummary: s.proposal!.remediation };
      await this.event(p, "COMMIT_CREATED", "Focused remediation commit created; Git author and committer times captured.");
      s.status = "RESCANNING";
      await this.event(p, "RESCAN_STARTED", "Deterministic scanner started against the remediation commit.");
      await mkdir(path.join(p.workspace, "rescan"));
      const after = sanitizeRepositoryEvidence({ ...await scanAcquiredRepository(p.repository, path.join(p.workspace, "rescan")), projectId: s.projectId, scanType: "RESCAN", sandboxMode: "LOCAL_STATIC" });
      if (after.commitSha !== s.commit.commitSha) throw new Error("Rescan commit mismatch");
      const comparison = compareRepositoryScans(p.baseline, after);
      s.afterScore = after.score; s.resolved = comparison.disappeared; s.remaining = comparison.remaining; s.newFindings = comparison.newFindings;
      await this.event(p, "RESCAN_COMPLETED", "Deterministic rescan completed; findings compared by stable ID.", s.findingIds, after.scanId);
      for (const [type, findings] of [["FINDING_RESOLVED", s.resolved], ["FINDING_REMAINING", s.remaining], ["NEW_FINDING_DETECTED", s.newFindings]] as const) {
        for (const finding of findings) await this.event(p, type, `Scanner comparison: ${finding.title}.`, [finding.id], after.scanId);
      }
      await git(["config", "core.worktree", p.source]);
      s.reviewDirectory = p.repository;
      s.status = "READY_FOR_REVIEW";
      await this.event(p, "BRANCH_READY_FOR_REVIEW", "Local branch ready for human review. No push or merge performed.", s.findingIds, after.scanId);
      // Keep the real local Git branch for review. Never expose workspace paths in API evidence.
      this.pending.delete(id); return structuredClone(s);
    } catch {
      s.status = "FAILED"; await this.journal.append(s); this.pending.delete(id);
      await rm(p.workspace, { recursive: true, force: true });
      throw new Error("Remediation failed safely; no ready status was recorded");
    }
  }
}
const state = globalThis as typeof globalThis & { hackforgeRemediation?: RemediationWorkflow };
export const remediationWorkflow = state.hackforgeRemediation ??= new RemediationWorkflow();
