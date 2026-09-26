import { scanProject } from "../../../lib/scanner/index.ts";
import { validateScanInput } from "../../../lib/scanner/targets.ts";

export const runtime = "nodejs";

const HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
const MAX_BODY_BYTES = 1024;

async function readInput(request: Request): Promise<unknown> {
  if (!request.body) throw new Error("Missing input");
  const reader = request.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error("Input too large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const buffer = Buffer.concat(chunks);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
}

export async function POST(request: Request): Promise<Response> {
  let target;
  try {
    target = validateScanInput(await readInput(request));
  } catch {
    return Response.json({ error: "Provide only a target: vulnerable-demo or clean-demo." }, { status: 400, headers: HEADERS });
  }
  try {
    return Response.json(await scanProject(target), { headers: HEADERS });
  } catch {
    // Never log source, git output, request bodies, or raw exception details.
    return Response.json({ error: "Demo scan unavailable. Run npm run setup:demos and try again." }, { status: 503, headers: HEADERS });
  }
}
