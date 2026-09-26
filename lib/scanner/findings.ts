import { createHash } from "node:crypto";
import { sanitizeFilePath } from "./masking.ts";
import { PENALTIES } from "./scoring.ts";
import type { Finding } from "./types.ts";

type FindingInput = Omit<Finding, "id" | "status" | "penalty">;

export function createFinding(ruleId: string, input: FindingInput, occurrence = 0): Finding {
  // Identity uses location and rule, never secret contents; stable across rescans.
  const id = createHash("sha256")
    .update(`${ruleId}:${input.filePath}:${input.lineNumber ?? 0}:${occurrence}`)
    .digest("hex")
    .slice(0, 24);
  return {
    ...input,
    filePath: sanitizeFilePath(input.filePath),
    id,
    status: "OPEN",
    penalty: PENALTIES[input.severity],
  };
}
