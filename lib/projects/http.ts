import { PRIVATE_HEADERS, sameOrigin as hasSameOrigin } from "../http.ts";
import { AnalysisError, ERROR_MESSAGES } from "../sandbox/policy.ts";

export const JSON_HEADERS = { ...PRIVATE_HEADERS, "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" };
export function sameOrigin(request: Request) {
  return hasSameOrigin(request) && !new URL(request.url).search;
}
export function projectError(error: unknown) {
  if (error instanceof AnalysisError) {
    const status = error.code === "BUSY" ? 409 : error.code === "REPOSITORY_LIMIT" || error.code === "UNSUPPORTED_REPOSITORY" ? 422 : 503;
    return Response.json({ error: ERROR_MESSAGES[error.code], code: error.code }, { status, headers: JSON_HEADERS });
  }
  return Response.json({ error: "Project unavailable." }, { status: 404, headers: JSON_HEADERS });
}
