export const PRIVATE_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

function normalizedHost(value: string): string | undefined {
  // Validate the authority before URL parsing can discard credentials or paths.
  const match = /^(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([0-9]+))?$/i.exec(value);
  if (!match || (match[2] && Number(match[2]) > 65535)) return undefined;
  if (!match[1].startsWith("[") && match[1].split(".").some((label) =>
    !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) return undefined;
  try {
    const url = new URL(`http://${value}`);
    return url.hostname.toLowerCase() + (match[2] ? `:${Number(match[2])}` : "");
  } catch { return undefined; }
}

export function sameOrigin(request: Request): boolean {
  if (request.headers.get("sec-fetch-site") === "cross-site") return false;
  const origin = request.headers.get("origin");
  if (origin === null) return true;
  // Origin must be one HTTP(S) origin, without credentials, paths or opaque values.
  const match = /^https?:\/\/([^/?#]+)$/i.exec(origin);
  const originHost = match && normalizedHost(match[1]);
  if (!originHost) return false;
  // Forwarded headers are supplied by the trusted reverse proxy. Fail closed
  // on malformed supplied hosts rather than falling back to another authority.
  const forwardedHost = request.headers.get("x-forwarded-host");
  const host = forwardedHost !== null ? forwardedHost.split(",")[0].trim()
    : request.headers.get("host") ?? new URL(request.url).host;
  return originHost === normalizedHost(host);
}

export function externallyVisibleHttps(request: Request): boolean {
  const forwardedProto = request.headers.get("x-forwarded-proto");
  return forwardedProto !== null ? forwardedProto.split(",")[0].trim().toLowerCase() === "https"
    : new URL(request.url).protocol === "https:";
}

export async function readBoundedJson(request: Request, maxBytes = 1024): Promise<unknown> {
  if (!request.body) throw new Error("Missing input");
  const reader = request.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error("Input too large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
}
