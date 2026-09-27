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
  const [activity, setActivity] = useState("");
  const [analyzeOpen, setAnalyzeOpen] = useState(false);
  const [snapshots, setSnapshots] = useState<Record<string, ProjectDetail>>({});
  const [projectsLoaded, setProjectsLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/projects", { cache: "no-store" }).then(async (response) => {
      if (!response.ok) throw new Error("Projects unavailable");
      const rows = await response.json() as Project[];
      if (!cancelled) { setProjects(rows); setProjectsLoaded(true); }
      const details = await Promise.all(rows.map(async (project) => {
        const response = await fetch(`/api/projects/${project.id}`, { cache: "no-store" });
        return response.ok ? await response.json() as ProjectDetail : null;
      }));
      if (!cancelled) setSnapshots((current) => ({ ...Object.fromEntries(details.filter((entry) => entry !== null).map((entry) => [entry.project.id, entry])), ...current }));
    }).catch(() => { if (!cancelled) { setProjectsLoaded(true); setError("Could not load local projects. Refresh to try again."); } });
    return () => { cancelled = true; };
  }, []);

  async function parse(response: Response) {
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "Repository analysis could not be completed.");
    return data as ProjectDetail;
  }
  async function showProject(id: string) {
    setBusy(true); setActivity("Loading project…"); setError(""); setNotice("");
    try {
      const updated = await parse(await fetch(`/api/projects/${id}`, { cache: "no-store" }));
      setDetail(updated); setSnapshots((current) => ({ ...current, [id]: updated })); setAnalyzeOpen(false);
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not load project."); }
    finally { setBusy(false); }
  }
  async function analyze(id: string, scanType?: "RESCAN" | "FINAL") {
    setBusy(true); setActivity("Analyzing repository… Running deterministic static checks."); setError(""); setNotice("");
    try {
      const updated = await parse(await fetch(`/api/projects/${id}/scan`, { method: "POST",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(scanType ? { scanType } : {}), cache: "no-store" }));
      setDetail(updated);
      setSnapshots((current) => ({ ...current, [id]: updated }));
      setProjects((current) => current.map((project) => project.id === id ? updated.project : project));
      setNotice("Scan completed against the recorded commit. Findings and score are from the deterministic scanner.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Repository analysis could not be completed."); }
    finally { setBusy(false); }
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setActivity("Analyzing repository… Preparing the source snapshot."); setError(""); setNotice("");
    try {
      const created = await parse(await fetch("/api/projects", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repositoryUrl: url.trim() }), cache: "no-store" }));
      setDetail(created); setProjects((current) => current.some((p) => p.id === created.project.id) ? current : [...current, created.project]);
      setUrl("");
      setAnalyzeOpen(false);
      await analyze(created.project.id);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not create project."); }
    finally { setBusy(false); }
  }

  const remediation = useRemediationSessions(detail?.project.id);
  const verified = remediation.sessions.find((s) => s.status === "READY_FOR_REVIEW" && s.scanId === detail?.scans.at(-1)?.scanId);
  const scan = detail && latest(detail);
  const comparison = detail && detail.scans.length > 1 ? compareRepositoryScans(detail.scans[0], detail.scans.at(-1)!) : null;
  return <section id="projects" className="projects-workspace" aria-label="Projects workspace">
    <div className="project-layout">
      <aside className="project-list" aria-label="Project selector">
        <div className="sidebar-heading"><h2>Projects</h2><span className="count-badge">{projects.length}</span></div>
        <button type="button" className="analyze-button secondary-button" disabled={busy} aria-expanded={analyzeOpen} aria-controls="analyze-repository" onClick={() => setAnalyzeOpen(!analyzeOpen)}>+ Analyze repository</button>
        <div className="project-items">{projects.map((project) => {
          const recent = snapshots[project.id]?.scans.at(-1);
          const label = recent ? recent.findings.length ? "Needs attention" : "Verified" : "Not scanned";
          return <button type="button" className={detail?.project.id === project.id ? "project-item active" : "project-item"}
            aria-pressed={detail?.project.id === project.id} onClick={() => void showProject(project.id)} disabled={busy} key={project.id}>
            <span className={`project-indicator ${recent && !recent.findings.length ? "healthy" : ""}`} aria-hidden="true" />
            <span className="project-item-text"><strong title={project.repositoryName}>{project.repositoryName}</strong><small>{project.repositoryOwner}</small>
              <span className="project-item-state">{recent ? `${recent.score} / 100 · ${label}` : project.status === "SCANNING" ? "Scanning…" : label}</span></span>
          </button>;
        })}</div>
        {!projectsLoaded && <p className="helper" role="status">Loading projects…</p>}
        {projectsLoaded && !projects.length && <p className="helper sidebar-empty">Your analyzed repositories will appear here.</p>}
        <div className="sidebar-note"><span className="local-label">◎ Local workspace</span><p>Source snapshots. Deterministic checks. Verified fix branches.</p></div>
      </aside>
      <div className="project-main">
        <div className="workspace-context"><span>Projects{detail && <> / <strong>{detail.project.repositoryName}</strong></>}</span><span className="local-label">Static analysis</span></div>
        {analyzeOpen && <section id="analyze-repository" className="scan-card panel" aria-labelledby="analyze-heading">
          <div className="section-heading"><div><p className="eyebrow">New project</p><h2 id="analyze-heading">Analyze a repository</h2></div><button type="button" className="tertiary-button" disabled={busy} onClick={() => setAnalyzeOpen(false)}>Close</button></div>
          <p>Start with a public GitHub repository. HackForge scans a source snapshot without running repository code.</p>
          <form onSubmit={(event) => void create(event)} className="project-input">
            <label htmlFor="repository-url">Repository URL</label>
            <div><input id="repository-url" type="url" required placeholder="https://github.com/owner/repository"
              autoFocus value={url} disabled={busy} onChange={(event) => setUrl(event.target.value)} aria-describedby="repository-url-help" />
              <button disabled={busy} type="submit">{busy ? "Analyzing…" : "Analyze repository →"}</button></div>
          </form><p id="repository-url-help" className="helper">Public repositories only. Keep credentials out of the URL.</p>
        </section>}
        <div className="workspace-feedback" aria-live="polite">
          {busy && <p role="status" className="notice loading-notice"><span className="spinner" aria-hidden="true" />{activity}</p>}
          {error && <p role="alert" className="error-message">{error}</p>}
          {notice && <p role="status" className="notice">✓ {notice}</p>}
        </div>
        {!detail && !analyzeOpen && !busy && <section className="project-welcome" aria-labelledby="welcome-heading">
          <span className="welcome-symbol" aria-hidden="true">⌘</span><p className="eyebrow">Your security workspace</p>
          <h1 id="welcome-heading">Build fast.<br />Ship with confidence.</h1>
          <p>Select a project or analyze a public GitHub repository to understand your security posture.</p>
          <button type="button" onClick={() => setAnalyzeOpen(true)}>+ Analyze repository</button>
          <div className="welcome-workflow"><span><strong>01</strong> Scan</span><span><strong>02</strong> Understand</span><span><strong>03</strong> Fix</span><span><strong>04</strong> Verify</span></div>
          <p className="helper">SAI Scanner finds it. SAI Assistant explains it. HackForge verifies the fix.</p>
        </section>}
        {detail && <div className="project-detail">
          <header className="project-header">
            <div className="project-title"><div><p className="eyebrow">Source repository</p><h1>{detail.project.repositoryOwner}<span className="repo-slash"> / </span>{detail.project.repositoryName}</h1>
              <span className={`state-label ${scan && !scan.findings.length ? "state-healthy" : ""}`}>{scan ? scan.findings.length ? "Needs attention" : "Verified" : "Not scanned"}</span></div>
              <div className="project-actions"><button type="button" className="tertiary-button" disabled={busy} onClick={() => void analyze(detail.project.id)}>{scan ? "↻ Rescan" : "Analyze repository"}</button>
                {scan && <button type="button" disabled={busy} onClick={() => void analyze(detail.project.id, "FINAL")}>Final Scan</button>}</div></div>
            {scan && <dl className="project-metadata"><div><dt>Commit</dt><dd><code>{scan.commitSha.slice(0, 12)}</code></dd></div><div><dt>Analysis</dt><dd>{scan.sandboxMode === "LOCAL_STATIC" ? "Local static" : "Docker static"}</dd></div><div><dt>Last scanned</dt><dd><time dateTime={scan.scannedAt}>{new Date(scan.scannedAt).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}</time></dd></div></dl>}
          </header>
          {scan ? <>
            <section className="score-grid" id="project-security" aria-label="Source security overview">
              <div className="posture panel"><p className="eyebrow">Source security score</p><div className={`score ${scan.score < 100 ? "score-warning" : ""}`}>{scan.score}<span>/100</span></div>
                <p className="score-status">{scan.findings.length ? "Needs attention" : "✓ No supported issues detected"}</p></div>
              <div className="severity-summary"><div className="section-heading"><h2>Security overview</h2><span>{scan.findings.length} finding{scan.findings.length === 1 ? "" : "s"}</span></div>
                <div className="severity-grid">{SEVERITIES.map((severity) => <div key={severity} className="severity-count panel"><span className={`severity severity-${severity.toLowerCase()}`}>{severity[0] + severity.slice(1).toLowerCase()}</span><strong>{scan.counts[severity]}</strong></div>)}</div>
                <p className="helper">Supported secret and Git hygiene checks only. A 100 / 100 score does not guarantee security.</p></div>
            </section>
            {comparison && <section className="source-progress panel" aria-label="Source security progress">
              <div className="section-heading"><div><p className="eyebrow">Source repository</p><h2>Security progress</h2></div><span className="progress-change">{comparison.improvement >= 0 ? "+" : ""}{comparison.improvement} verified point{Math.abs(comparison.improvement) === 1 ? "" : "s"}</span></div>
              <ol className="scan-progress">{detail.scans.filter((entry, index, entries) => index === 0 || index === entries.length - 1 || entry.score !== entries[index - 1].score).map((entry, index) => <li key={entry.scanId}><strong>{entry.score}</strong><span className={`progress-node ${entry.findings.length === 0 ? "healthy" : ""}`} /><span>{index === 0 ? "Baseline" : entry.findings.length === 0 ? "Verified" : entry.scanType === "FINAL" ? "Final scan" : "Rescan"}</span><small>{entry.findings.length} finding{entry.findings.length === 1 ? "" : "s"}</small></li>)}</ol>
              <p className="helper"><strong>{comparison.previousScore} → {comparison.newScore}</strong> · {detail.scans[0].commitSha === scan.commitSha ? "No source commit change" : "Source commit changed"} · {comparison.disappeared.length} resolved on source · {comparison.remaining.length} remaining · {comparison.newFindings.length} new</p>
            </section>}
            <section className="findings-section" aria-labelledby="project-findings-heading">
              <div className="section-heading"><h2 id="project-findings-heading">Findings <span className="count-badge">{scan.findings.length}</span></h2><span>Source snapshot</span></div>
              {!scan.findings.length && <p className="clean-state panel empty-state">✓ No supported issues detected</p>}
              {scan.findings.map((finding) => <details className="finding panel" key={`${scan.scanId}:${finding.id}`}><summary className="finding-summary"><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                <span className="finding-heading"><strong>{finding.title}</strong><code>{finding.filePath}{finding.lineNumber ? `:${finding.lineNumber}` : ""}</code></span><span className="finding-status">OPEN ON SOURCE{findingSession(remediation.sessions, scan.scanId, finding.id)?.resolved?.some((f) => f.id === finding.id) && <small className="branch-resolved">✓ RESOLVED ON FIX BRANCH</small>}</span><span className="expand-label" aria-hidden="true">›</span></summary>
                <div className="finding-body"><h3>What happened</h3><p>{finding.description}</p><h3>Why it matters</h3><p>{finding.category === "SECRET" ? "Exposed credentials can give others access to the account or service they belong to. Removing a secret from source does not rotate it or erase prior exposure." : "Without safe Git hygiene, sensitive configuration and generated files can accidentally be included when sharing or pushing a project."}</p><h3>How to fix</h3><p>{finding.remediation}</p>
                  <FindingExplanation scanId={scan.scanId} findingId={finding.id} /><RemediationPanel key={`${scan.scanId}:${finding.id}`} findingTitle={finding.title} sessions={remediation.sessions} loaded={remediation.loaded} projectId={detail.project.id} scanId={scan.scanId} findingId={finding.id} /><details className="technical-details"><summary>Technical details</summary><dl><dt>Category</dt><dd>{finding.category}</dd><dt>Finding ID</dt><dd><code>{finding.id}</code></dd><dt>Path reference</dt><dd><code>{finding.filePath}</code></dd><dt>Score penalty</dt><dd>{finding.penalty}</dd>{finding.maskedSample && <><dt>Masked sample</dt><dd><code>{finding.maskedSample}</code></dd></>}</dl></details>
                </div></details>)}
            </section>
            {remediation.error && <p className="error-message" role="alert">{remediation.error}</p>}
            {verified && <RemediationResult session={verified} />}
            <RemediationTimeline titles={Object.fromEntries(detail.scans.flatMap((entry) => entry.findings.map((f) => [f.id, f.title])))} sessions={remediation.sessions} />
            <details className="project-history scan-history panel"><summary>Scan history <span className="count-badge">{detail.scans.length}</span></summary><div className="scan-table"><table><caption className="sr-only">Source repository scan history</caption><thead><tr><th>Type</th><th>Score</th><th>Findings</th><th>Commit</th><th>Time</th></tr></thead><tbody>{detail.scans.map((entry) => <tr key={entry.scanId}><td>{entry.scanType[0] + entry.scanType.slice(1).toLowerCase()}</td><td><strong>{entry.score}</strong><span className="table-score-denominator"> / 100</span></td><td>{entry.findings.length}</td><td><code title={entry.commitSha}>{entry.commitSha.slice(0, 7)}</code></td><td><time dateTime={entry.scannedAt} title={new Date(entry.scannedAt).toLocaleString()}>{new Date(entry.scannedAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time></td></tr>)}</tbody></table></div><p className="helper scan-coverage">{scan.coverage.filesScanned} files analyzed · {scan.coverage.binaryFilesSkipped} binary files skipped · {scan.coverage.generatedFilesSkipped} generated files skipped</p></details>
            <section id="reports" className="project-reports panel" aria-labelledby="report-heading"><div><h2 id="report-heading">Security Report</h2><p>Deterministic findings · Exact commit evidence · Before/after comparison</p><p className="helper">Source repository scans. Fix branch verification appears above.</p></div><div className="report-actions">
              <a className="secondary-button" href={`/api/projects/${detail.project.id}/report?format=html`} target="_blank" rel="noopener noreferrer">Open Report ↗</a>
              <a className="tertiary-button" href={`/api/projects/${detail.project.id}/report?format=json`} download>Download JSON</a></div></section>
          </> : <p className="empty-state panel">No baseline scan yet. Analyze this repository to get started.</p>}
        </div>}
      </div>
    </div>
  </section>;
}
