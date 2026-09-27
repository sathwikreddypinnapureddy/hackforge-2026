import { PRIVATE_HEADERS, readBoundedJson, sameOrigin } from "../../../lib/http.ts";
import { scanSession, scanStore, validateExplainInput } from "../../../lib/remediation/scan-store.ts";
import { explainFinding } from "../../../lib/remediation/service.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  if (!sameOrigin(request)) {
    return Response.json({ error: "Use the HackForge workspace to request an explanation." }, { status: 403, headers: PRIVATE_HEADERS });
  }
  let input;
  try {
    if (request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") throw new Error("Invalid content type");
    input = validateExplainInput(await readBoundedJson(request));
  } catch {
    return Response.json({ error: "Provide only scanId and findingId from your current SAI Security Scanner scan." }, { status: 400, headers: PRIVATE_HEADERS });
  }
  const session = scanSession(request);
  const scan = scanStore.get(session, input.scanId);
  const finding = scan?.findings.get(input.findingId);
  const unavailable = () => Response.json({ error: "Finding unavailable. Run a new SAI Security Scanner scan and try again." }, { status: 404, headers: PRIVATE_HEADERS });
  if (!scan || !finding) return unavailable();
  // Coalesce repeated clicks and cache guidance for this scan's lifetime.
  let pending = scan.explanations.get(input.findingId);
  if (!pending) {
    pending = explainFinding(finding);
    scan.explanations.set(input.findingId, pending);
  }
  const result = await pending;
  // A rescan or expiry while Gemini was working invalidates the response too.
  if (scanStore.get(session, input.scanId) !== scan) return unavailable();
  return Response.json(result, { headers: PRIVATE_HEADERS });
}
