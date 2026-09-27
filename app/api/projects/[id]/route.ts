import { JSON_HEADERS, sameOrigin, projectError } from "../../../../lib/projects/http.ts";
import { validateProjectId } from "../../../../lib/projects/url.ts";
import { projectStore } from "../../../../lib/projects/store.ts";
import { scanSession, scanStore, sessionCookie } from "../../../../lib/remediation/scan-store.ts";

export const runtime = "nodejs";
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(request)) return Response.json({ error: "Invalid request." }, { status: 403, headers: JSON_HEADERS });
  try {
    const detail = await projectStore.get(validateProjectId((await context.params).id));
    const latest = detail.scans.at(-1);
    const session = latest ? scanStore.register(latest, scanSession(request)) : undefined;
    return Response.json(detail, { headers: { ...JSON_HEADERS, ...(session ? { "Set-Cookie": sessionCookie(session, request) } : {}) } });
  }
  catch (error) { return projectError(error); }
}
