import type { RemediationSession, RemediationView } from "./workflow-types.ts";

// Local retention metadata stays in the server journal, including legacy records.
export function remediationView(session: RemediationSession): RemediationView {
  const copy = structuredClone(session);
  delete copy.reviewDirectory;
  return copy;
}

export function newestSessions(sessions: RemediationView[]) {
  return [...sessions].sort((a, b) => (b.timeline.at(-1)?.timestamp ?? "").localeCompare(a.timeline.at(-1)?.timestamp ?? ""));
}

export function findingSession(sessions: RemediationView[], scanId: string, findingId: string) {
  const matching = newestSessions(sessions).filter((s) => s.scanId === scanId && s.findingIds.includes(findingId));
  return matching.find((s) => s.status === "READY_FOR_REVIEW") ?? matching[0];
}
