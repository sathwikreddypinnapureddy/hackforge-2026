import "server-only";
import { randomUUID } from "node:crypto";
import { externallyVisibleHttps } from "../http.ts";
import type { ScanResult } from "../scanner/types.ts";
import { buildSanitizedPayload } from "./payload.ts";
import type { SanitizedFinding } from "./payload.ts";
import type { ExplanationResult } from "./types.ts";

const COOKIE = "hackforge-scan-session";
export const SCAN_TTL_MS = 15 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

interface StoredScan {
  scanId: string;
  expiresAt: number;
  findings: Map<string, SanitizedFinding>;
  explanations: Map<string, Promise<ExplanationResult>>;
}

export class ScanStore {
  private readonly sessions = new Map<string, StoredScan>();

  register(scan: ScanResult, session: string | undefined, now = Date.now()): string {
    for (const [key, value] of this.sessions) if (value.expiresAt <= now) this.sessions.delete(key);
    const token = session && this.sessions.has(session) ? session : randomUUID();
    this.sessions.delete(token);
    while (this.sessions.size >= 100) this.sessions.delete(this.sessions.keys().next().value!);
    this.sessions.set(token, {
      scanId: scan.scanId, expiresAt: now + SCAN_TTL_MS,
      findings: new Map(scan.findings.map((finding) => [finding.id, buildSanitizedPayload(finding)])),
      explanations: new Map(),
    });
    return token;
  }

  get(session: string | undefined, scanId: string, now = Date.now()): StoredScan | undefined {
    if (!session) return undefined;
    const scan = this.sessions.get(session);
    if (scan && scan.expiresAt <= now) { this.sessions.delete(session); return undefined; }
    return scan?.scanId === scanId ? scan : undefined;
  }
}

// Share state across route bundles and development reloads in this Node process.
const state = globalThis as typeof globalThis & { hackforgeScanStore?: ScanStore };
export const scanStore = state.hackforgeScanStore ??= new ScanStore();

export function scanSession(request: Request): string | undefined {
  const token = request.headers.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
  return token && UUID.test(token) ? token : undefined;
}

export function sessionCookie(token: string, request: Request): string {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SCAN_TTL_MS / 1000}${externallyVisibleHttps(request) ? "; Secure" : ""}`;
}

export function validateExplainInput(input: unknown): { scanId: string; findingId: string } {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid input");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== 2 || typeof value.scanId !== "string" || !UUID.test(value.scanId)
    || typeof value.findingId !== "string" || !/^[0-9a-f]{24}$/.test(value.findingId)) throw new Error("Invalid input");
  return { scanId: value.scanId, findingId: value.findingId };
}
