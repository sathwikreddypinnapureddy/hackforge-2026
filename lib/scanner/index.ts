import { withDemoLock } from "../demo/lock.ts";
import { scanTrustedTarget } from "./core.ts";
import { InvalidTargetError, resolveTarget, ScanUnavailableError } from "./targets.ts";
import type { ScanResult } from "./types.ts";

export function scanProject(target: unknown): Promise<ScanResult> {
  return withDemoLock(() => scanUnlocked(target));
}

async function scanUnlocked(target: unknown): Promise<ScanResult> {
  try {
    const resolved = await resolveTarget(target);
    return await scanTrustedTarget({ kind: "demo", ...resolved });
  } catch (error) {
    if (error instanceof InvalidTargetError) throw error;
    // Errors may contain paths/content. Only the fixed sanitized error escapes.
    throw new ScanUnavailableError();
  }
}
