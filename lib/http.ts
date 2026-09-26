export const PRIVATE_HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

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
