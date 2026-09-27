import { JSON_HEADERS, sameOrigin } from "../../../../../lib/projects/http.ts";
import { validateProjectId } from "../../../../../lib/projects/url.ts";
import { readBoundedJson } from "../../../../../lib/http.ts";
import { scanSession, scanStore, validateExplainInput } from "../../../../../lib/remediation/scan-store.ts";
import { remediationWorkflow } from "../../../../../lib/remediation/workflow.ts";
export const runtime = "nodejs";
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(request)) return Response.json({ error: "Use same-origin requests." }, { status: 403, headers: JSON_HEADERS });
  try {
    return Response.json(await remediationWorkflow.journal.list(validateProjectId((await context.params).id)), { headers: JSON_HEADERS });
  } catch { return Response.json({ error: "Timeline unavailable." }, { status: 503, headers: JSON_HEADERS }); }
}
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(request) || request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") {
    return Response.json({ error: "Use same-origin JSON." }, { status: 403, headers: JSON_HEADERS });
  }
  try {
    const projectId = validateProjectId((await context.params).id);
    const owner = scanSession(request);
    if (!owner) throw new Error("Refresh the repository scan before proposing a fix.");
    const input = await readBoundedJson(request) as Record<string, unknown>;
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid remediation request");
    let result;
    if (input.action === "propose" && Object.keys(input).length === 3) {
      const selection = validateExplainInput({ scanId: input.scanId, findingId: input.findingId });
      if (!scanStore.get(owner, selection.scanId)?.findings.has(selection.findingId)) throw new Error("Refresh the repository scan before proposing a fix.");
      result = await remediationWorkflow.propose(projectId, selection.scanId, selection.findingId, owner);
    } else if ((input.action === "approve" || input.action === "cancel") && typeof input.sessionId === "string"
      && /^[a-f0-9-]{36}$/.test(input.sessionId) && Object.keys(input).length === (input.action === "approve" ? 3 : 2)) {
      const sessions = await remediationWorkflow.journal.list(projectId);
      if (!sessions.some((session) => session.id === input.sessionId)) throw new Error("Proposal unavailable");
      result = input.action === "cancel" ? await remediationWorkflow.cancel(input.sessionId, owner)
        : await remediationWorkflow.approve(input.sessionId, owner, input.approved === true);
    } else throw new Error("Invalid remediation request");
    return Response.json(result, { headers: JSON_HEADERS });
  } catch (cause) {
    // Workflow errors are fixed HackForge copy, never Git stderr or repository text.
    const allowed = /^(Refresh the repository scan|This finding requires manual|Repository changed;|Explicit approval required|Proposal unavailable|Safe remediation proposal|Remediation failed safely|Invalid remediation request|Too many proposals)/;
    const message = cause instanceof Error && allowed.test(cause.message) ? cause.message : "Remediation unavailable.";
    return Response.json({ error: message }, { status: 400, headers: JSON_HEADERS });
  }
}
