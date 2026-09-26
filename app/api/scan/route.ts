import { scanProject } from "../../../lib/scanner/index.ts";
import { validateScanInput } from "../../../lib/scanner/targets.ts";
import { PRIVATE_HEADERS as HEADERS, readBoundedJson } from "../../../lib/http.ts";
import { scanSession, scanStore, sessionCookie } from "../../../lib/remediation/scan-store.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  let target;
  try {
    target = validateScanInput(await readBoundedJson(request));
  } catch {
    return Response.json({ error: "Provide only a target: vulnerable-demo or clean-demo." }, { status: 400, headers: HEADERS });
  }
  try {
    const result = await scanProject(target);
    const session = scanStore.register(result, scanSession(request));
    return Response.json(result, { headers: { ...HEADERS, "Set-Cookie": sessionCookie(session, request) } });
  } catch {
    // Never log source, git output, request bodies, or raw exception details.
    return Response.json({ error: "Demo scan unavailable. Run npm run setup:demos and try again." }, { status: 503, headers: HEADERS });
  }
}
