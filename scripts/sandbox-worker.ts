import { scanAcquiredRepository } from "../lib/sandbox/worker.ts";
import { AnalysisError, LIMITS } from "../lib/sandbox/policy.ts";

try {
  const result = JSON.stringify(await scanAcquiredRepository("/input", "/work"));
  if (Buffer.byteLength(result) > LIMITS.outputBytes) throw new AnalysisError("REPOSITORY_LIMIT");
  process.stdout.write(result);
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error instanceof AnalysisError ? error.code : "UNSUPPORTED_REPOSITORY" }));
}
