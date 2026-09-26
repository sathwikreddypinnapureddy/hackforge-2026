import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { mock, test } from "node:test";
import { POST } from "../app/api/scan/route.ts";
import { readSourceFiles } from "../lib/scanner/files.ts";
import { createFinding } from "../lib/scanner/findings.ts";
import { inspectGit } from "../lib/scanner/git.ts";
import { scanProject } from "../lib/scanner/index.ts";
import { maskSecret, sanitizeFilePath } from "../lib/scanner/masking.ts";
import { calculateScore, PENALTIES } from "../lib/scanner/scoring.ts";
import { detectSecrets } from "../lib/scanner/secrets.ts";
import { InvalidTargetError, isContained, resolveTarget, ScanUnavailableError, validateScanInput, validateTarget } from "../lib/scanner/targets.ts";
import type { Finding, ScanResult, Severity } from "../lib/scanner/types.ts";

// All samples here are intentionally fake, nonfunctional detection strings.
const SAMPLES = {
  openai: "sk-testonly000000000000000000000000",
  openaiProject: "sk-proj-testonly000000000000000000000000",
  github: "ghp_testonly0000000000000000000000000000",
  githubFineGrained: "github_pat_testonly000000000000000000000000",
  aws: "AKIATESTONLY00000000",
  api: "fake-testonly-api-key-00000000",
  password: "fake-testonly-password",
  secret: "fake-testonly-signing-secret",
  token: "fake-testonly-service-token-0000",
  session: "fake-testonly-session-token-0000",
};

function assertSanitized(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const secret of Object.values(SAMPLES)) {
    assert.ok(!serialized.includes(secret), "A raw test credential escaped redaction.");
  }
}

function finding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return { ...createFinding(`test-${severity}`, {
    category: "SECRET", severity, title: "Test finding", description: "Test finding",
    filePath: "test.ts", remediation: "Remove credential",
  }), ...overrides };
}

test("masking fully redacts both short and long secret values", () => {
  for (const value of ["x", "short", ...Object.values(SAMPLES)]) assert.equal(maskSecret(value), "[REDACTED]");
  assert.equal(maskSecret(""), "");
});

test("provider-like credentials and control characters are sanitized in file paths", () => {
  const sanitized = sanitizeFilePath(`src/${SAMPLES.openai}/config\n.ts`);
  assertSanitized(sanitized);
  assert.equal(sanitized, "src/[REDACTED]/config?.ts");
});

test("all requested secret families are detected without emitting source or credential contents", () => {
  const source = [
    `OPENAI_API_KEY=${SAMPLES.openai}`,
    `const key = '${SAMPLES.openaiProject}';`,
    `GITHUB_TOKEN=${SAMPLES.github}`,
    `const key2 = '${SAMPLES.githubFineGrained}';`,
    `AWS_ACCESS_KEY_ID=${SAMPLES.aws}`,
    `apiKey: '${SAMPLES.api}',`,
    `DATABASE_PASSWORD=${SAMPLES.password}`,
    `signingSecret = '${SAMPLES.secret}';`,
    `"service_token": "${SAMPLES.token}"`,
  ].join("\n");
  const results = detectSecrets(source, "config.ts");
  assert.equal(results.length, 9);
  assert.equal(results.filter((f) => f.severity === "CRITICAL").length, 4);
  assert.deepEqual(results.map((f) => f.lineNumber).sort((a, b) => a! - b!), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.ok(results.every((f) => f.maskedSample === "[REDACTED]" && f.status === "OPEN" && f.penalty === PENALTIES[f.severity]));
  assertSanitized(results);
});

test("provider assignments are not double-counted and rescans have stable IDs", () => {
  const source = `OPENAI_API_KEY=${SAMPLES.openai}\r\nGITHUB_TOKEN=${SAMPLES.github}`;
  const first = detectSecrets(source, ".env");
  assert.equal(first.length, 2);
  assert.deepEqual(first, detectSecrets(source, ".env"));
  const rotated = detectSecrets("OPENAI_API_KEY=sk-testonly111111111111111111111111", ".env");
  assert.equal(rotated[0].id, first[0].id);
});

test("distinct occurrences on one line get distinct finding IDs", () => {
  const results = detectSecrets(`const a = '${SAMPLES.openai}'; const b = '${SAMPLES.openai}';`, "test.ts");
  assert.equal(results.length, 2);
  assert.equal(new Set(results.map((f) => f.id)).size, 2);
});

test("password, token, and generic API assignments redact even short values", () => {
  const results = detectSecrets("PASSWORD=x\napi_key=1234\ntoken='abc'", ".env");
  assert.equal(results.length, 3);
  assert.ok(results.every((f) => f.maskedSample === "[REDACTED]"));
  assert.ok(!JSON.stringify(results).includes("1234"));
});

test("environment references, empty templates, and normal code do not create secrets", () => {
  const source = [
    "apiKey: process.env.API_KEY,",
    "password = process.env['PASSWORD'];",
    "token = os.environ['TOKEN']",
    "secret = os.getenv('SECRET')",
    "api_key: import.meta.env.API_KEY,",
    "TOKEN=${TOKEN}", "TOKEN=$TOKEN", "PASSWORD=", 'secret: ""',
    "password = getPassword();", "const welcome = 'hello';",
    'token = `${process.env.TOKEN}`;',
  ].join("\n");
  assert.deepEqual(detectSecrets(source, "safe.ts"), []);
});

test("quoted reference-shaped strings are still literal credentials", () => {
  const results = detectSecrets('password = "process.env.PASSWORD"\nsecret = "your_testonly_secret"', "config.ts");
  assert.equal(results.length, 2);
  assert.ok(results.every((f) => f.maskedSample === "[REDACTED]"));
});

test("scoring applies exact severity weights and clamps at zero", () => {
  assert.equal(calculateScore([]), 100);
  for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const) {
    assert.equal(calculateScore([finding(severity)]), 100 - PENALTIES[severity]);
  }
  assert.equal(calculateScore([finding("CRITICAL"), finding("HIGH"), finding("MEDIUM"), finding("LOW")]), 49);
  assert.equal(calculateScore(Array.from({ length: 5 }, () => finding("CRITICAL"))), 0);
});

test("accepted risks still apply penalties; caller-provided penalty values cannot bypass scoring", () => {
  assert.equal(calculateScore([finding("HIGH", { status: "ACCEPTED_RISK", penalty: 0 })]), 85);
});

test("resolution and false-positive labels require trusted evidence to waive penalties", () => {
  const resolved = finding("HIGH", { status: "RESOLVED", id: "resolved" });
  const dismissed = finding("MEDIUM", { status: "FALSE_POSITIVE", id: "dismissed" });
  assert.equal(calculateScore([resolved, dismissed]), 77);
  assert.equal(calculateScore([resolved, dismissed], {
    verifiedResolvedIds: new Set([resolved.id]), explicitlyDismissedIds: new Set([dismissed.id]),
  }), 100);
  assert.equal(calculateScore([finding("HIGH", { status: "OPEN", id: "open" })], {
    verifiedResolvedIds: new Set(["open"]), explicitlyDismissedIds: new Set(["open"]),
  }), 85);
});

test("only the two literal targets and exact input schema are accepted", async () => {
  assert.equal(validateTarget("vulnerable-demo"), "vulnerable-demo");
  assert.equal(validateScanInput({ target: "clean-demo" }), "clean-demo");
  for (const invalid of ["../clean-demo", "clean-demo/../vulnerable-demo", "/etc/passwd", "clean-demo/", "clean-demo%2f..", "clean-demo\0", "clean-demo;pwd", "__proto__", "", null, 1, {}, ["clean-demo"]]) {
    assert.throws(() => validateTarget(invalid), InvalidTargetError);
    await assert.rejects(scanProject(invalid), InvalidTargetError);
  }
  for (const invalid of [null, [], {}, { target: "clean-demo", path: "/etc/passwd" }, { target: "../clean-demo" }]) {
    assert.throws(() => validateScanInput(invalid), InvalidTargetError);
  }
});

test("containment checks reject sibling-prefix and parent paths", () => {
  assert.ok(isContained("/tmp/demo", "/tmp/demo/src/config.ts"));
  assert.ok(isContained("/tmp/demo", "/tmp/demo"));
  assert.ok(!isContained("/tmp/demo", "/tmp/demo-other/file"));
  assert.ok(!isContained("/tmp/demo", "/tmp/demo/../outside"));
});

test("vulnerable demo detects secrets, tracked env files, sensitive config, and missing ignores", async () => {
  const result = await scanProject("vulnerable-demo");
  assert.equal(result.score, 0);
  assert.deepEqual(result.counts, { CRITICAL: 2, HIGH: 8, MEDIUM: 3, LOW: 0 });
  assert.equal(result.findings.length, 13);
  assert.equal(result.findings.filter((f) => f.title === "Environment file tracked by Git").length, 2);
  for (const title of ["Missing .gitignore", "Incomplete environment ignore rules", "Sensitive configuration tracked by Git", "Hardcoded API key", "Hardcoded password", "Hardcoded secret or token", "AWS access key ID exposed", "GitHub-style token exposed", "OpenAI-style key exposed"]) {
    assert.ok(result.findings.some((f) => f.title === title), `Missing rule: ${title}`);
  }
  assert.ok(result.findings.every((f) => f.status === "OPEN" && !f.filePath.startsWith("/")));
  assert.ok(!result.findings.some((f) => f.filePath === "src/app.ts" || f.filePath === "README.md"));
  assertSanitized(result);
});

test("clean demo has no findings and a score of 100", async () => {
  const result = await scanProject("clean-demo");
  assert.equal(result.score, 100);
  assert.deepEqual(result.counts, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  assert.deepEqual(result.findings, []);
});

async function snapshot(directory: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function visit(current: string): Promise<void> {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const filename = path.join(current, entry.name);
      if (entry.isDirectory()) await visit(filename);
      else result[path.relative(directory, filename)] = createHash("sha256").update(await readFile(filename)).digest("hex");
    }
  }
  await visit(directory);
  return result;
}

test("rescans are deterministic and never alter source files or Git metadata", async () => {
  const root = path.join(process.cwd(), "demo-repos");
  const before = await snapshot(root);
  const first = await scanProject("vulnerable-demo");
  const second = await scanProject("vulnerable-demo");
  assert.deepEqual(first.findings, second.findings);
  assert.deepEqual(first.counts, second.counts);
  assert.equal(first.score, second.score);
  assert.notEqual(first.scanId, second.scanId);
  assert.deepEqual(await snapshot(root), before);
});

test("POST returns sanitized results for both demos and no-store headers", async () => {
  for (const target of ["vulnerable-demo", "clean-demo"]) {
    const response = await POST(new Request("http://localhost/api/scan", { method: "POST", body: JSON.stringify({ target }) }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const result = await response.json() as ScanResult;
    assert.deepEqual(Object.keys(result).sort(), ["counts", "findings", "scanId", "scannedAt", "score", "target"]);
    assert.equal(result.target, target);
    assert.ok(!Number.isNaN(Date.parse(result.scannedAt)));
    assertSanitized(result);
  }
});

test("POST rejects traversal, extra fields, malformed JSON, and oversized bodies without echoing input", async () => {
  for (const body of [
    JSON.stringify({ target: "../../etc/passwd" }), JSON.stringify({ target: "clean-demo", command: "pwd" }),
    "{}", "null", "[]", "not JSON", JSON.stringify({ target: SAMPLES.openai }),
    JSON.stringify({ target: "clean-demo", padding: "x".repeat(2000) }),
  ]) {
    const response = await POST(new Request("http://localhost/api/scan", { method: "POST", body }));
    assert.equal(response.status, 400);
    const result = await response.json();
    assert.deepEqual(result, { error: "Provide only a target: vulnerable-demo or clean-demo." });
    assertSanitized(result);
  }
});

test("Git ignore evaluation detects ineffective negated rules", async () => {
  const root = path.join(process.cwd(), "demo-repos", "clean-demo");
  const gitDir = path.join(process.cwd(), "demo-repos", ".git-data", "clean-demo");
  const ignoredFiles = await readSourceFiles(root);
  assert.deepEqual(await inspectGit(root, gitDir, ignoredFiles), []);
  // An isolated work tree reuses the controlled index using read-only git operations.
  const temp = await mkdtemp(path.join(os.tmpdir(), "hackforge-ignore-"));
  try {
    await writeFile(path.join(temp, ".gitignore"), ".env\n.env.*\n!.env.local\n");
    const findings = await inspectGit(temp, gitDir, await readSourceFiles(temp));
    assert.ok(findings.some((f) => f.title === "Incomplete environment ignore rules"));
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test("file scanning rejects symlinks, binary files, and oversized files instead of reporting clean", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "hackforge-files-"));
  try {
    for (const name of ["link", "binary", "large"]) {
      const directory = path.join(temp, name);
      await mkdir(directory);
      if (name === "link") await symlink("/etc/passwd", path.join(directory, "outside"));
      if (name === "binary") await writeFile(path.join(directory, "data"), Buffer.from([0, 1, 2]));
      if (name === "large") await writeFile(path.join(directory, "data"), Buffer.alloc(512 * 1024 + 1, "a"));
      await assert.rejects(readSourceFiles(directory), ScanUnavailableError);
    }
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test("root and Git metadata symlinks cannot redirect the allowlisted target", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "hackforge-roots-"));
  const originalWorkspace = process.cwd();
  const cwd = mock.method(process, "cwd", () => temp);
  try {
    const demos = path.join(temp, "demo-repos");
    await mkdir(demos);
    const metadataBase = path.join(demos, ".git-data");
    await mkdir(metadataBase);
    await symlink(path.join(originalWorkspace, "demo-repos", "clean-demo"), path.join(demos, "clean-demo"));
    await assert.rejects(resolveTarget("clean-demo"), ScanUnavailableError);
    const vulnerable = path.join(demos, "vulnerable-demo");
    await mkdir(vulnerable);
    await symlink(path.join(originalWorkspace, "demo-repos", ".git-data", "vulnerable-demo"), path.join(metadataBase, "vulnerable-demo"));
    await assert.rejects(resolveTarget("vulnerable-demo"), ScanUnavailableError);
  } finally {
    cwd.mock.restore();
    await rm(temp, { recursive: true, force: true });
  }
});

test("successful and unavailable scans emit no logs; API errors contain no internal paths or credentials", async () => {
  const logs: unknown[][] = [];
  const spies = ["log", "warn", "error", "info", "debug"].map((method) =>
    mock.method(console, method as "log", (...values: unknown[]) => { logs.push(values); }));
  try {
    await scanProject("vulnerable-demo");
    const cwd = mock.method(process, "cwd", () => path.join(os.tmpdir(), "hackforge-no-such-project"));
    try {
      const response = await POST(new Request("http://localhost/api/scan", { method: "POST", body: JSON.stringify({ target: "clean-demo" }) }));
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { error: "Demo scan unavailable. Run npm run setup:demos and try again." });
    } finally { cwd.mock.restore(); }
    assert.equal(logs.length, 0, "Scanner unexpectedly emitted log output.");
  } finally { for (const spy of spies) spy.mock.restore(); }
});
