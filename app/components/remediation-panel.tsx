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

export function RemediationPanel({ projectId, scanId, findingId, sessions, loaded }: {
  projectId: string; scanId: string; findingId: string; sessions: RemediationView[]; loaded: boolean;
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
  return <div className="technical-details">
    {!loaded && <p role="status">Loading persisted remediation state…</p>}
    {loaded && (!session || session.status === "CANCELLED" || session.status === "FAILED") && <button type="button" disabled={!!busy} onClick={() => void action("propose")}>Propose Fix</button>}
    {busy === "propose" && <p role="status">Preparing remediation for review…</p>}
    {session && !["FAILED", "CANCELLED"].includes(session.status) && <ol className="remediation-progress" aria-label="Remediation workflow">
      {[["Review remediation", "FIX_PROPOSED"], ["Applying", "COMMIT_CREATED"], ["Rescanning", "RESCAN_COMPLETED"], ["Verified", "RESCAN_COMPLETED"], ["Ready for Review", "BRANCH_READY_FOR_REVIEW"]].map(([label, event]) => <li key={label}>{session.timeline.some((entry) => entry.type === event) ? "✓ " : ""}{label}</li>)}
    </ol>}
    {inProgress && <p role="status" className="notice">{session?.status === "RESCANNING" ? "Rescanning… Deterministic branch verification in progress." : "Applying… Creating the isolated fix branch and commit."}</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {session?.status === "FAILED" && <p role="alert">Remediation failed safely. Review and propose again.</p>}
    {session?.status === "PROPOSED" && session.proposal && !inProgress && <section aria-label="Review remediation" className="panel finding-body">
      <h3>Review remediation</h3><p>{session.proposal.remediation}</p>
      <dl><dt>Severity</dt><dd>{session.proposal.severity}</dd><dt>File</dt><dd>{session.proposal.file}</dd><dt>Commit message</dt><dd>{session.proposal.commitMessage}</dd></dl>
      <details><summary>Sanitized patch preview and files</summary><p>{session.proposal.filesToModify.join(", ")}</p><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{session.proposal.patchPreview}</pre></details>
      <p>Approval creates a local branch from source commit {session.sourceCommitSha.slice(0, 12)}. Scanner results determine resolution.</p>
      <button type="button" disabled={!!busy} onClick={() => void action("approve")}>Approve &amp; Create Fix Branch</button>{" "}
      <button type="button" disabled={!!busy} onClick={() => void action("cancel")}>Cancel</button>
    </section>}
    {session?.status === "READY_FOR_REVIEW" && <p role="status" className="notice">✓ Verified fix branch ready for review. See the verified remediation result below.</p>}
  </div>;
}
export function RemediationResult({ session: s }: { session: RemediationView }) {
  return <section className="comparison project-comparison" aria-label="Verified remediation branch">
    <p className="eyebrow">Verified remediation branch</p><h3>Verified branch remediation · READY FOR REVIEW</h3>
    <h2>{s.beforeScore} → {s.afterScore} / 100</h2>
    <p>{s.resolved?.length ?? 0} verified resolution{ s.resolved?.length === 1 ? "" : "s"} · {s.remaining?.length ?? 0} remaining · {s.newFindings?.length ?? 0} new</p>
    <p>Branch: <code>{s.branchName}</code></p><p>Commit: <code>{s.commit?.commitSha.slice(0, 12)}</code></p>
    <p>Verified remediation branch retained locally for review.</p>
    <p>HackForge prepares and verifies an isolated remediation branch. It does not push or merge security changes without developer authorization.</p>
    <p>The source repository snapshot remains unchanged.</p>
  </section>;
}
export function RemediationTimeline({ sessions, titles = {} }: { sessions: RemediationView[]; titles?: Record<string, string> }) {
  return <section className="project-history"><h3>Remediation activity</h3><p>{sessions.length} sessions</p>
    {newestSessions(sessions).map((s) => <details key={s.id} className="remediation-row"><summary>
      <strong>{s.status.replaceAll("_", " ")}</strong> · {s.resolved?.find((f) => s.findingIds.includes(f.id))?.title ?? s.remaining?.find((f) => s.findingIds.includes(f.id))?.title ?? titles[s.findingIds[0]] ?? "Finding remediation"} · {s.beforeScore} → {s.afterScore ?? "pending"}
      {s.branchName && <> · <code title={s.branchName}>{s.branchName.split("/").at(-1)?.slice(0, 20)}…</code></>}
      {s.commit && <> · commit <code>{s.commit.commitSha.slice(0, 7)}</code></>}
      {s.timeline.at(-1) && <> · {new Date(s.timeline.at(-1)!.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</>}
    </summary><ol>{s.timeline.map((event) => <li key={event.eventId}><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>{" "}<strong>{event.type.replaceAll("_", " ")}</strong> · {event.description}</li>)}</ol></details>)}
  </section>;
}
