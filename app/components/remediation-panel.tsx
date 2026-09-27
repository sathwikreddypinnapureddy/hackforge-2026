"use client";
import { useEffect, useState } from "react";
import type { RemediationSession } from "../../lib/remediation/workflow-types.ts";
export function RemediationPanel({ projectId, scanId, findingId }: { projectId: string; scanId: string; findingId: string }) {
  const [session, setSession] = useState<RemediationSession | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function action(input: object) {
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/projects/${projectId}/remediation`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Remediation unavailable.");
      setSession(data); window.dispatchEvent(new Event("hackforge-remediation-updated"));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Remediation unavailable."); }
    finally { setBusy(false); }
  }
  return <div className="technical-details">
    <button type="button" disabled={busy || session?.status === "APPLYING"} onClick={() => void action({ action: "propose", scanId, findingId })}>Propose Fix</button>
    {busy && <p role="status">Preparing or applying the bounded remediation…</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {session?.status === "PROPOSED" && session.proposal && <section aria-label="Review proposed remediation" className="panel finding-body">
      <h3>Review proposed remediation</h3><dl><dt>Finding</dt><dd>{session.proposal.findingId}</dd>
        <dt>Severity</dt><dd>{session.proposal.severity}</dd><dt>File</dt><dd>{session.proposal.file}</dd>
        <dt>Proposed remediation</dt><dd>{session.proposal.remediation}</dd><dt>Files to modify</dt><dd>{session.proposal.filesToModify.join(", ")}</dd>
        <dt>Commit message</dt><dd>{session.proposal.commitMessage}</dd></dl>
      <h4>Sanitized patch preview</h4><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{session.proposal.patchPreview}</pre>
      <p>Approval creates a local branch at {session.sourceCommitSha.slice(0, 12)}. Scanner results determine resolution.</p>
      <button type="button" disabled={busy} onClick={() => void action({ action: "approve", sessionId: session.id, approved: true })}>Approve &amp; Create Fix Branch</button>{" "}
      <button type="button" disabled={busy} onClick={() => void action({ action: "cancel", sessionId: session.id })}>Cancel</button>
    </section>}
    {session?.status === "READY_FOR_REVIEW" && <RemediationResult session={session} />}
  </div>;
}
function RemediationResult({ session: s }: { session: RemediationSession }) {
  return <div className="panel finding-body"><h3>Ready for review</h3>
    <p>Remediation Branch: <code>{s.branchName}</code></p><p>Commit SHA: <code>{s.commit?.commitSha}</code></p>
    <p>Commit time: {s.commit && new Date(s.commit.committerTimestamp).toLocaleString()}</p>
    <p>Before score: {s.beforeScore} · After score: {s.afterScore} · Resolved: {s.resolved?.length} · Remaining: {s.remaining?.length} · New: {s.newFindings?.length}</p>
    <p>Local review directory: <code>{s.reviewDirectory}</code></p><p>The local branch is retained for review. No push or merge is performed.</p>
  </div>;
}
export function RemediationTimeline({ projectId }: { projectId: string }) {
  const [sessions, setSessions] = useState<RemediationSession[]>([]);
  useEffect(() => {
    let active = true;
    const load = () => { void fetch(`/api/projects/${projectId}/remediation`, { cache: "no-store" }).then(async (r) => {
      if (r.ok && active) setSessions(await r.json());
    }).catch(() => {}); };
    load(); window.addEventListener("hackforge-remediation-updated", load);
    return () => { active = false; window.removeEventListener("hackforge-remediation-updated", load); };
  }, [projectId]);
  if (!sessions.length) return null;
  return <details className="project-history"><summary>Remediation Timeline</summary>
    {sessions.map((s) => <section key={s.id}><h4>{s.status.replaceAll("_", " ")} · {s.id.slice(0, 8)}</h4>
      {s.status === "READY_FOR_REVIEW" && <RemediationResult session={s} />}
      <ol>{s.timeline.map((event) => <li key={event.eventId}><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>{" "}
        <strong>{event.type.replaceAll("_", " ")}</strong> · {event.description}
        {event.branchName && <div><code>{event.branchName}</code></div>}{event.commitSha && <div><code>{event.commitSha.slice(0, 12)}</code></div>}
      </li>)}</ol></section>)}
  </details>;
}
