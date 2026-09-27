"use client";

import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { Project, ProjectDetail, RepositoryScan } from "../../lib/projects/types.ts";
import { SEVERITIES } from "../../lib/scanner/types.ts";
import { compareRepositoryScans } from "../../lib/projects/report.ts";
import { RemediationPanel, RemediationTimeline, RemediationResult, useRemediationSessions } from "./remediation-panel.tsx";
import { findingSession } from "../../lib/remediation/view.ts";
import { FindingExplanation } from "./finding-explanation.tsx";

function latest(detail: ProjectDetail): RepositoryScan | undefined { return detail.scans.at(-1); }

export function ProjectWorkspace() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [detail, setDetail] = useState<ProjectDetail | null>(null);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch("/api/projects", { cache: "no-store" }).then(async (response) => {
      if (!response.ok) return;
      const rows = await response.json() as Project[];
      if (!cancelled) setProjects(rows);
    }).catch(() => { if (!cancelled) setError("Could not load local projects."); });
    return () => { cancelled = true; };
  }, []);

  async function parse(response: Response) {
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "Repository analysis could not be completed.");
    return data as ProjectDetail;
  }
  async function showProject(id: string) {
    setBusy(true); setError(""); setNotice("");
    try { setDetail(await parse(await fetch(`/api/projects/${id}`, { cache: "no-store" }))); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not load project."); }
    finally { setBusy(false); }
  }
  async function analyze(id: string, scanType?: "RESCAN" | "FINAL") {
    setBusy(true); setError(""); setNotice("");
    try {
      const updated = await parse(await fetch(`/api/projects/${id}/scan`, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(scanType ? { scanType } : {}), cache: "no-store" }));
      setDetail(updated);
      setProjects((current) => current.map((project) => project.id === id ? updated.project : project));
      setNotice("Scan completed against the recorded commit. Findings and score are from the deterministic scanner.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Repository analysis could not be completed."); }
    finally { setBusy(false); }
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const created = await parse(await fetch("/api/projects", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repositoryUrl: url.trim() }), cache: "no-store" }));
      setDetail(created); setProjects((current) => current.some((p) => p.id === created.project.id) ? current : [...current, created.project]);
      setUrl("");
      await analyze(created.project.id);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not create project."); }
    finally { setBusy(false); }
  }

  const remediation = useRemediationSessions(detail?.project.id);
  const verified = remediation.sessions.find((s) => s.status === "READY_FOR_REVIEW" && s.scanId === detail?.scans.at(-1)?.scanId);
  const scan = detail && latest(detail);
  const comparison = detail && detail.scans.length > 1 ? compareRepositoryScans(detail.scans[0], detail.scans.at(-1)!) : null;
  return <section id="projects" className="projects-workspace panel" aria-labelledby="projects-heading">
    <div className="projects-heading"><div><p className="eyebrow">Real repository workspace</p><h2 id="projects-heading">Scan a public GitHub project</h2>
      <p>HackForge reads a repository snapshot in an isolated scanner. No repository scripts are run.</p></div>
      <span className="ready-badge"><span className="status-dot" />SAI Ready</span></div>
    <form onSubmit={(event) => void create(event)} className="project-input">
      <label htmlFor="repository-url">Repository URL</label>
      <div><input id="repository-url" type="url" required placeholder="https://github.com/owner/repository"
        value={url} disabled={busy} onChange={(event) => setUrl(event.target.value)} />
        <button disabled={busy} type="submit">Analyze Repository →</button></div>
    </form>
    <p className="helper">Public GitHub repositories only. Keep your source and credentials out of the URL. Analysis uses a temporary workspace and static checks only.</p>
    <div className="project-layout">
    {projects.length > 0 && <div className="project-list"><h3>Projects</h3><div>{projects.map((project) => (
      <button type="button" className={detail?.project.id === project.id ? "project-item active" : "project-item"}
        onClick={() => void showProject(project.id)} disabled={busy} key={project.id}>
        <strong>{project.repositoryOwner}/{project.repositoryName}</strong>
        <small>{project.status.replaceAll("_", " ")} · {project.lastScannedAt ? new Date(project.lastScannedAt).toLocaleString() : "Not scanned"}</small>
      </button>
    ))}</div></div>}
    <div className="project-main">
    {busy && <p role="status" className="notice">{detail ? "Acquiring and scanning the repository. This may take up to two minutes…" : "Loading project…"}</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {notice && <p role="status" className="notice">{notice}</p>}
    {detail && <div className="project-detail">
      <div className="project-title"><div><p className="eyebrow">{detail.project.status.replaceAll("_", " ")}</p><h3>{detail.project.name}</h3>
        <p>{detail.project.repositoryOwner}/{detail.project.repositoryName}</p></div>
        <div className="project-actions"><button type="button" disabled={busy} onClick={() => void analyze(detail.project.id)}>{scan ? "Refresh Repository & Rescan" : "Analyze Repository"}</button>
          {scan && <button type="button" className="secondary-button" disabled={busy} onClick={() => void analyze(detail.project.id, "FINAL")}>Run Final Scan</button>}</div></div>
      {scan ? <>
        <p className="eyebrow">Source repository snapshot · {scan.findings.length ? "OPEN ON SOURCE" : "No supported source findings"}</p>
        <div className="project-stats" id="project-security"><div>Source commit <code>{scan.commitSha.slice(0, 12)}</code></div><div>Source security score <strong>{scan.score} / 100</strong></div>
          <div>Verified findings <strong>{scan.findings.length}</strong></div><div>Scanned <span>{new Date(scan.scannedAt).toLocaleString()}</span></div></div>
        <p className="helper">Score covers supported secret and Git hygiene checks. {scan.coverage.filesScanned} source files analyzed; {scan.coverage.binaryFilesSkipped} binary files and {scan.coverage.generatedFilesSkipped} generated files skipped. A 100 / 100 score does not guarantee security.</p>
        <div className="severity-grid">{SEVERITIES.map((severity) => <div key={severity} className="severity-count panel"><span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span><strong>{scan.counts[severity]}</strong></div>)}</div>
        <h3>Findings</h3>{!scan.findings.length && <p className="clean-state panel empty-state">No supported issues detected in this snapshot.</p>}
        {scan.findings.map((finding) => <details className="finding panel" key={`${scan.scanId}:${finding.id}`}><summary className="finding-summary"><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
          <span className="finding-heading"><strong>{finding.title}</strong><code>{finding.filePath}{finding.lineNumber ? `:${finding.lineNumber}` : ""}</code></span><span className="finding-status">OPEN ON SOURCE{findingSession(remediation.sessions, scan.scanId, finding.id)?.resolved?.some((f) => f.id === finding.id) && <small className="branch-resolved">✓ RESOLVED ON FIX BRANCH</small>}</span><span className="expand-label">Details ⌄</span></summary>
          <div className="finding-body"><p>{finding.description}</p><h3>How to fix it</h3><p>{finding.remediation}</p>
            <FindingExplanation scanId={scan.scanId} findingId={finding.id} /><RemediationPanel key={`${scan.scanId}:${finding.id}`} sessions={remediation.sessions} loaded={remediation.loaded} projectId={detail.project.id} scanId={scan.scanId} findingId={finding.id} /><details className="technical-details"><summary>Technical details</summary><dl><dt>Category</dt><dd>{finding.category}</dd><dt>Finding ID</dt><dd>{finding.id}</dd><dt>Path reference</dt><dd>{finding.filePath}</dd><dt>Score penalty</dt><dd>{finding.penalty}</dd></dl></details>
          </div></details>)}
        {remediation.error && <p role="alert">{remediation.error}</p>}
        {verified && <RemediationResult session={verified} />}
        {comparison && <div className="comparison project-comparison"><p className="eyebrow">Repository scan comparison · SOURCE REPOSITORY</p><h2>{comparison.previousScore} → {comparison.newScore} / 100</h2><p>{comparison.improvement >= 0 ? "+" : ""}{comparison.improvement} points · {comparison.disappeared.length} resolved on source · {comparison.remaining.length} remaining · {comparison.newFindings.length} new</p>
          <p>{detail.scans[0].commitSha === scan.commitSha ? "No source commit change" : "Source commit changed"} · {detail.scans[0].commitSha.slice(0, 12)} → {scan.commitSha.slice(0, 12)}</p></div>}
        <RemediationTimeline titles={Object.fromEntries(detail.scans.flatMap((entry) => entry.findings.map((f) => [f.id, f.title])))} sessions={remediation.sessions} /><details className="project-history"><summary>Scan history</summary><ol>{detail.scans.map((entry) => <li key={entry.scanId}><strong>{entry.scanType}</strong> · {entry.score} / 100 · {entry.findings.length} findings · <code>{entry.commitSha.slice(0, 12)}</code> · {new Date(entry.scannedAt).toLocaleString()}</li>)}</ol></details>
        <details id="reports" className="project-reports"><summary>Reports · Security improvement report</summary><p>Uses stored deterministic scans and their exact commit IDs.</p><div>
          <a href={`/api/projects/${detail.project.id}/report?format=html`} target="_blank" rel="noopener noreferrer">Open printable report / Save PDF</a>
          <a href={`/api/projects/${detail.project.id}/report?format=json`} download>Download JSON report</a></div></details>
      </> : <p className="helper">No baseline scan yet. Analyze this repository to get started.</p>}
    </div>}
    </div></div>
  </section>;
}
