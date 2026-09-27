"use client";
import { useEffect, useState } from "react";
import type { RemediationView } from "../../lib/remediation/workflow-types.ts";
import { findingSession, newestSessions } from "../../lib/remediation/view.ts";

export function useRemediationSessions(projectId?: string) {
  const [state, setState] = useState<{ projectId?: string; sessions: RemediationView[]; loaded: boolean; error: string }>({ sessions: [], loaded: false, error: "" });
  useEffect(() => {
    if (!projectId) return;
    let active = true;
    let requested = 0;
    let applied = 0;
    const load = async () => {
      const sequence = ++requested;
      try {
        const response = await fetch(`/api/projects/${projectId}/remediation`, { cache: "no-store" });
        if (!response.ok) throw new Error("Could not load remediation history. Refresh before proposing a fix.");
        const sessions = await response.json() as RemediationView[];
        if (active && sequence > applied) { applied = sequence; setState({ projectId, sessions: newestSessions(sessions), loaded: true, error: "" }); }
      } catch (cause) { if (active && sequence > applied) setState({ projectId, sessions: [], loaded: false, error: cause instanceof Error ? cause.message : "Remediation unavailable." }); }
    };
    void load();
    window.addEventListener("hackforge-remediation-updated", load);
    return () => { active = false; window.removeEventListener("hackforge-remediation-updated", load); };
  }, [projectId]);
  return state.projectId === projectId ? state : { sessions: [], loaded: false, error: "" };
}

export function RemediationPanel({ projectId, scanId, findingId, findingTitle, sessions, loaded }: {
  projectId: string; scanId: string; findingId: string; findingTitle: string; sessions: RemediationView[]; loaded: boolean;
}) {
  const [local, setLocal] = useState<RemediationView | null>(null);
  const [busy, setBusy] = useState<"propose" | "approve" | "cancel" | null>(null);
  const [error, setError] = useState("");
  const persisted = findingSession(sessions, scanId, findingId);
  const session = persisted && (!local || persisted.status === "READY_FOR_REVIEW" || (persisted.timeline.length >= local.timeline.length && persisted.id === local.id)) ? persisted : local;
  async function action(action: "propose" | "approve" | "cancel") {
    setBusy(action); setError("");
    const refresh = () => window.dispatchEvent(new Event("hackforge-remediation-updated"));
    const timer = action === "approve" ? window.setInterval(refresh, 100) : undefined;
    try {
      const input = action === "propose" ? { action, scanId, findingId } : { action, sessionId: session?.id, ...(action === "approve" ? { approved: true } : {}) };
      const response = await fetch(`/api/projects/${projectId}/remediation`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Remediation unavailable.");
      setLocal(data); refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Remediation unavailable."); refresh(); }
    finally { window.clearInterval(timer); setBusy(null); }
  }
  const inProgress = busy === "approve" || session?.status === "APPLYING" || session?.status === "RESCANNING";
  return <div className="remediation-panel" aria-live="polite">
    {!loaded && <p role="status">Loading persisted remediation state…</p>}
    {loaded && (!session || session.status === "CANCELLED" || session.status === "FAILED") && <button type="button" disabled={!!busy} onClick={() => void action("propose")}>{busy === "propose" ? "Preparing remediation…" : "Propose Fix"}</button>}
    {busy === "propose" && <p role="status">Preparing remediation for review…</p>}
    {session && !["FAILED", "CANCELLED"].includes(session.status) && <ol className="remediation-progress" aria-label="Remediation workflow">
      {[["Review", "FIX_PROPOSED"], ["Apply", "COMMIT_CREATED"], ["Rescan", "RESCAN_COMPLETED"], ["Ready for review", "BRANCH_READY_FOR_REVIEW"]].map(([label, event]) => <li className={session.timeline.some((entry) => entry.type === event) ? "complete" : ""} key={label}>{session.timeline.some((entry) => entry.type === event) ? "✓ " : "○ "}{label}</li>)}
    </ol>}
    {inProgress && <p role="status" className="notice loading-notice"><span className="spinner" aria-hidden="true" />{session?.status === "RESCANNING" ? "Running deterministic rescan…" : session?.timeline.some((event) => event.type === "BRANCH_CREATED") ? "Applying approved patch… Creating the fix commit." : "Creating fix branch… Applying the approved patch."}</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {session?.status === "FAILED" && <p role="alert">Remediation failed safely. Review and propose again.</p>}
    {session?.status === "PROPOSED" && session.proposal && !inProgress && <section aria-label="Review remediation" className="proposal-card panel">
      <p className="eyebrow">SAI Remediation</p><h3>Review remediation</h3>
      <dl><dt>Finding</dt><dd><strong>{findingTitle}</strong></dd><dt>Proposed change</dt><dd>{session.proposal.remediation}</dd><dt>Files</dt><dd>{session.proposal.filesToModify.map((file) => <code className="proposal-file" key={file}>{file}</code>)}</dd><dt>Commit</dt><dd><code>{session.proposal.commitMessage}</code></dd></dl>
      <div className="patch-preview"><h4>Sanitized patch</h4><pre>{session.proposal.patchPreview}</pre></div>
      <p className="helper">Approval creates an isolated local branch from commit <code>{session.sourceCommitSha.slice(0, 12)}</code>. The scanner verifies the result.</p>
      <div className="proposal-actions"><button type="button" disabled={!!busy} onClick={() => void action("approve")}>Approve &amp; Create Fix Branch</button>
      <button className="tertiary-button" type="button" disabled={!!busy} onClick={() => void action("cancel")}>{busy === "cancel" ? "Cancelling…" : "Cancel"}</button></div>
    </section>}
    {session?.status === "READY_FOR_REVIEW" && <p role="status" className="notice">✓ Verified fix branch ready for review. See the verified remediation result below.</p>}
  </div>;
}
export function RemediationResult({ session: s }: { session: RemediationView }) {
  const resolved = s.resolved?.length ?? 0;
  const remaining = s.remaining?.length ?? 0;
  const added = s.newFindings?.length ?? 0;
  return <section className="comparison project-comparison" aria-label="Verified remediation branch">
    <div className="section-heading"><p className="eyebrow">✓ Verified remediation</p><span className="review-state">READY FOR REVIEW</span></div>
    <div className="remediation-scores"><div><p className="comparison-label">Source repository</p><strong>{s.beforeScore}<span> / 100</span></strong><p>{resolved + remaining} finding{resolved + remaining === 1 ? "" : "s"}</p></div>
      <span className="comparison-arrow" aria-hidden="true">→</span><div><p className="comparison-label">Verified fix branch</p><strong>{s.afterScore ?? "—"}<span> / 100</span></strong><p>{remaining + added} finding{remaining + added === 1 ? "" : "s"}</p></div></div>
    <div className="comparison-totals"><p>Resolved <strong>{resolved}</strong></p><p>Remaining <strong>{remaining}</strong></p><p>New <strong>{added}</strong></p></div>
    <dl className="branch-evidence"><dt>Branch</dt><dd><code>{s.branchName}</code></dd><dt>Commit</dt><dd><code>{s.commit?.commitSha.slice(0, 12)}</code></dd></dl>
    <p className="isolation-note">The source repository remains unchanged. HackForge verified this remediation on an isolated local branch.</p>
  </section>;
}
const EVENT_LABELS: Record<string, string> = {
  REMEDIATION_REQUESTED: "Remediation requested", FIX_PROPOSED: "Fix proposed", FIX_APPROVED: "Fix approved",
  BRANCH_CREATED: "Branch created", FILE_CHANGED: "Patch applied", COMMIT_CREATED: "Commit created",
  RESCAN_STARTED: "Rescan started", RESCAN_COMPLETED: "Rescan completed", FINDING_RESOLVED: "Finding resolved",
  FINDING_REMAINING: "Finding remains", NEW_FINDING_DETECTED: "New finding detected", BRANCH_READY_FOR_REVIEW: "Ready for review",
};
export function RemediationTimeline({ sessions, titles = {} }: { sessions: RemediationView[]; titles?: Record<string, string> }) {
  const [showAll, setShowAll] = useState(false);
  const ordered = newestSessions(sessions);
  const visible = showAll ? ordered : ordered.slice(0, 3);
  return <section className="project-history remediation-activity" aria-labelledby="activity-heading"><div className="section-heading"><h2 id="activity-heading">Remediation Activity</h2><span>{sessions.length} session{sessions.length === 1 ? "" : "s"}</span></div>
    {!sessions.length && <p className="helper">No remediation sessions yet.</p>}
    {visible.map((s) => <details key={s.id} className="remediation-row panel"><summary>
      <span className="activity-finding"><span className={`activity-state ${s.status === "READY_FOR_REVIEW" ? "state-healthy" : ""}`}>{s.status.replaceAll("_", " ")}</span><strong>{s.resolved?.find((f) => s.findingIds.includes(f.id))?.title ?? s.remaining?.find((f) => s.findingIds.includes(f.id))?.title ?? titles[s.findingIds[0]] ?? "Finding remediation"}</strong></span>
      <span className="activity-score">{s.beforeScore} → {s.afterScore ?? "pending"}<small>Source → fix branch</small></span>
      <span className="activity-meta">{s.commit && <code>{s.commit.commitSha.slice(0, 7)}</code>}{s.timeline.at(-1) && <time dateTime={s.timeline.at(-1)!.timestamp}>{new Date(s.timeline.at(-1)!.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time>}</span><span className="expand-label" aria-hidden="true">›</span>
    </summary><ol className="event-timeline">{s.timeline.map((event) => <li key={event.eventId}><div><strong>{EVENT_LABELS[event.type] ?? event.type.replaceAll("_", " ")}</strong><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</time></div><p>{event.description}</p></li>)}</ol></details>)}
    {sessions.length > 3 && <button type="button" className="tertiary-button activity-toggle" aria-expanded={showAll} onClick={() => setShowAll(!showAll)}>{showAll ? "Show recent sessions" : `View all ${sessions.length} sessions`}</button>}
  </section>;
}
