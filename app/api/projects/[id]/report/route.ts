import { PRIVATE_HEADERS, sameOrigin } from "../../../../../lib/http.ts";
import { projectError } from "../../../../../lib/projects/http.ts";
import { validateProjectId } from "../../../../../lib/projects/url.ts";
import { projectStore } from "../../../../../lib/projects/store.ts";
import { createSecurityReport, renderSecurityReport } from "../../../../../lib/projects/report.ts";

export const runtime = "nodejs";
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const url = new URL(request.url);
  if (!sameOrigin(request)
    || [...url.searchParams.keys()].some((key) => key !== "format") || url.searchParams.size > 1) {
    return Response.json({ error: "Invalid report request." }, { status: 403, headers: PRIVATE_HEADERS });
  }
  const format = url.searchParams.get("format") ?? "html";
  if (format !== "json" && format !== "html") return Response.json({ error: "Use html or json." }, { status: 400, headers: PRIVATE_HEADERS });
  try {
    const id = validateProjectId((await context.params).id);
    const detail = await projectStore.get(id);
    if (!detail.scans.length) return Response.json({ error: "Run a baseline scan first." }, { status: 409, headers: PRIVATE_HEADERS });
    if (format === "json") return new Response(JSON.stringify(createSecurityReport(detail), null, 2), {
      headers: { ...PRIVATE_HEADERS, "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="hackforge-report-${id}.json"`, "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'" },
    });
    return new Response(renderSecurityReport(detail), { headers: { ...PRIVATE_HEADERS, "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" } });
  } catch (error) { return projectError(error); }
}
