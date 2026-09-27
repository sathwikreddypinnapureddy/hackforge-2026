import { JSON_HEADERS, sameOrigin, projectError } from "../../../../../lib/projects/http.ts";
import { validateProjectId } from "../../../../../lib/projects/url.ts";
import { readBoundedJson } from "../../../../../lib/http.ts";
import { analyzeProject } from "../../../../../lib/projects/service.ts";
import { scanSession, scanStore, sessionCookie } from "../../../../../lib/remediation/scan-store.ts";

export const runtime = "nodejs";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(request) || request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") {
    return Response.json({ error: "Use same-origin JSON." }, { status: 403, headers: JSON_HEADERS });
  }
  let type: "RESCAN" | "FINAL" = "RESCAN";
  try {
    const input = await readBoundedJson(request);
    if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => key !== "scanType")) throw new Error();
    const proposed = (input as { scanType?: unknown }).scanType;
    if (proposed !== undefined && proposed !== "RESCAN" && proposed !== "FINAL") throw new Error();
    if (proposed) type = proposed;
  } catch { return Response.json({ error: "Provide only an optional RESCAN or FINAL scan type." }, { status: 400, headers: JSON_HEADERS }); }
  try {
    const detail = await analyzeProject(validateProjectId((await context.params).id), type, undefined, undefined, request.signal);
    const latest = detail.scans.at(-1)!;
    const session = scanStore.register(latest, scanSession(request));
    return Response.json(detail, { headers: { ...JSON_HEADERS, "Set-Cookie": sessionCookie(session, request) } });
  }
  catch (error) { return projectError(error); }
}
