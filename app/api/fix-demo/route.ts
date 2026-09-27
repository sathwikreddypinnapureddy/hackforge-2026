import { mutateDemo, validateDemoInput } from "../../../lib/demo/workflow.ts";
import { PRIVATE_HEADERS, readBoundedJson, sameOrigin } from "../../../lib/http.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  // Block cross-origin mutations, including browser form submissions.
  if (!sameOrigin(request)
    || request.headers.get("content-type")?.split(";")[0].trim() !== "application/json"
    || new URL(request.url).search) {
    return Response.json({ error: "Demo actions require same-origin JSON." }, { status: 403, headers: PRIVATE_HEADERS });
  }
  let input;
  try {
    input = await readBoundedJson(request);
    validateDemoInput(input);
  } catch {
    return Response.json({ error: "Confirm an allowlisted vulnerable-demo action. No extra fields are accepted." }, { status: 400, headers: PRIVATE_HEADERS });
  }
  try {
    return Response.json(await mutateDemo(input), { headers: PRIVATE_HEADERS });
  } catch {
    // No paths, source, credentials, request data, or exception details escape.
    return Response.json({ error: "Demo action unavailable: fixture must contain only known controlled files. No verification has been performed; rescan before trusting results." }, { status: 503, headers: PRIVATE_HEADERS });
  }
}
