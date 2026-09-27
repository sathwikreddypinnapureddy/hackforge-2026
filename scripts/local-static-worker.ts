import path from "node:path";
import { scanAcquiredRepository } from "../lib/sandbox/worker.ts";
import { AnalysisError, LIMITS } from "../lib/sandbox/policy.ts";

// The parent supplies its own mkdtemp workspace; this is never an API input.
try {
  const workspace = process.argv[2];
  if (!workspace) throw new AnalysisError("ANALYSIS_FAILED");
  const result = JSON.stringify(await scanAcquiredRepository(path.join(workspace, "repository"), path.join(workspace, "work")));
  if (Buffer.byteLength(result) > LIMITS.outputBytes) throw new AnalysisError("REPOSITORY_LIMIT");
  process.stdout.write(result);
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error instanceof AnalysisError ? error.code : "UNSUPPORTED_REPOSITORY" }));
}
