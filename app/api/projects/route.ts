import { readBoundedJson } from "../../../lib/http.ts";
import { JSON_HEADERS, sameOrigin, projectError } from "../../../lib/projects/http.ts";
import { validateRepositoryUrl } from "../../../lib/projects/url.ts";
import { projectStore } from "../../../lib/projects/store.ts";

export const runtime = "nodejs";
export async function GET(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: "Invalid request." }, { status: 403, headers: JSON_HEADERS });
  try { return Response.json(await projectStore.list(), { headers: JSON_HEADERS }); }
  catch (error) { return projectError(error); }
}
export async function POST(request: Request) {
  if (!sameOrigin(request) || request.headers.get("content-type")?.split(";")[0].trim() !== "application/json") {
    return Response.json({ error: "Use same-origin JSON." }, { status: 403, headers: JSON_HEADERS });
  }
  let repositoryUrl: string;
  try {
    const body = await readBoundedJson(request);
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 1) throw new Error();
    repositoryUrl = validateRepositoryUrl((body as { repositoryUrl?: unknown }).repositoryUrl).repositoryUrl;
  } catch { return Response.json({ error: "Enter a public https://github.com/owner/repo URL." }, { status: 400, headers: JSON_HEADERS }); }
  try { return Response.json(await projectStore.create(repositoryUrl), { status: 201, headers: JSON_HEADERS }); }
  catch (error) { return projectError(error); }
}
