# HackForge · SAI Phase 5

HackForge is a security-first development workspace for hackathon teams, built
during hackUMBC 2026. **The deterministic scanner determines what exists.**
The controlled demo remains available. Phase 5 adds local projects, read-only
public GitHub intake, a disposable offline Docker scanner, baseline/rescan
history, and printable HTML / downloadable JSON reports. Gemini never discovers
findings or controls severity, scores, or status. There is no authentication or
database; the real repository workflow is intended for a single local user.

**SAI Scanner finds it. SAI Assistant explains it.** SAI Security Scanner is the
deterministic scanning engine. SAI Assistant provides AI guidance based on a
security issue already verified by HackForge. Gemini remains the underlying AI API.

## Run the demo

Requires Node.js 22.18+ and Git on PATH. Run from this project directory.

```bash
npm ci
npm run sandbox:build
npm run dev
```

`predev` prepares the two controlled Git fixtures automatically. Open
[localhost:3000](http://localhost:3000), select **Vulnerable Demo**, and click
**SCAN PROJECT**. Expect a score of **37** and **4 OPEN findings**: 1 critical,
2 high, and 1 medium. The findings are a masked fake OpenAI-style key, a tracked
`.env`, a masked hardcoded API key, and a missing `.gitignore`.

Select **Clean Demo** and scan again. Expect **100** and **0 findings**. This demo
uses environment references and a secret-free `.env.example`, with working
ignore rules for root and nested environment files.

Click **Explain with SAI** on any finding for an explanation, potential
impact, remediation steps, and a reason for its existing priority. The server
uses the existing `GEMINI_API_KEY` environment variable (or an ignored root
`.env.local`). Never prefix this key with `NEXT_PUBLIC_`. No key is required to
scan: missing keys, API failures, and invalid responses return clearly labeled
deterministic local guidance. Restart the server after changing its environment.

All credentials inside the vulnerable fixture are deliberately fake and
nonfunctional. The top-level `.gitignore` allows only the specific demo
environment files so they survive a fresh clone; normal environment files stay
ignored. Nothing is copied into `public/` or imported into the client bundle.

For a production demo:

```bash
npm run build
npm start
```

The dev/build scripts use Next.js's supported `--webpack` mode because the
constrained build runner blocks the local worker ports used by Turbopack's CSS
processing. Fonts use the system stack and require no external download.

## Architecture

| File | Responsibility |
| --- | --- |
| `lib/scanner/types.ts` | Shared finding, severity, status, target, and response types. |
| `lib/scanner/targets.ts` | Exact target/schema allowlist, canonical roots, symlink and fixture Git configuration checks. |
| `lib/scanner/files.ts` | Bounded, read-only UTF-8 source traversal; no symlink following. |
| `lib/scanner/secrets.ts` | Provider-format checks and literal API key, password, secret, and token assignments. |
| `lib/scanner/masking.ts` | Full `[REDACTED]` samples and sanitized paths. |
| `lib/scanner/findings.ts` | Stable rule/location IDs, OPEN defaults, and severity penalties. |
| `lib/scanner/git.ts` | Read-only Git index and effective ignore-rule checks. |
| `lib/scanner/scoring.ts` | Severity weights and trusted evidence requirements for penalty waivers. |
| `lib/scanner/index.ts` | Orchestration, deterministic ordering, counts, score, and scan metadata. |
| `app/api/scan/route.ts` | Bounded POST input, sanitized response/errors, and no-store caching. |
| `lib/http.ts` | Shared bounded JSON reader and private response headers. |
| `lib/remediation/scan-store.ts` | Session-bound current scan metadata, expiry, bounded storage, and explanation cache. |
| `lib/remediation/payload.ts` | Explicit metadata allowlist and full sample/path redaction at the Gemini boundary. |
| `lib/remediation/service.ts` | Official `@google/genai` SDK, structured output validation, timeout, and local fallback. |
| `lib/remediation/types.ts` | Client-safe explanation response types, separate from finding authority. |
| `app/api/explain/route.ts` | Exact ID-only request validation and server-side verified finding lookup. |
| `app/components/finding-explanation.tsx` | Per-finding explanation request and labeled plain-text guidance. |
| `app/page.tsx` | Demo selector, scan action, score, counts, and actionable findings. |
| `scripts/setup-demos.mjs` | Reproducible fixture Git metadata, separate from scanning. |

The request flows through target validation, source reading, deterministic
detection, Git checks, and scoring. Secrets are fully redacted **before** findings
are created; source lines and raw credential values are never returned or logged.
Provider/assignment overlap is deduplicated within one occurrence. A tracked
environment file and a literal within that file are separate verified risks.
Missing `.gitignore` produces one finding; incomplete environment ignore rules
are checked only when the root `.gitignore` exists.

Only Git `ls-files --cached` and `check-ignore --no-index` run during a scan.
Commands use a fixed executable with argument arrays, no shell, disabled optional
locks and filesystem monitors, sanitized Git environment/configuration, output
limits, and a timeout. The scanner never writes, deletes, stages, or edits files.

The setup script uses Node built-ins to generate fixture blob objects and Git v2
indexes from fixed manifests; it uses **no mutating Git commands**. These are
controlled repositories with staged files and an unborn main branch. They are
not nested submodules and need no commits. Generated `.git` metadata is local
only, stored under the ignored `demo-repos/.git-data/<target>/` directories.
The scanner supplies Git's directory and worktree explicitly; the source
fixtures remain ordinary files that can be committed in HackForge. Preparation
runs before dev, build, and test, or explicitly with
`npm run setup:demos`. Existing indexes are preserved, so restarting or building
does not undo remediation. Setup is not called by the API or scanner.

## Real repository workflow (Phase 5)

Requires Docker Desktop/Engine running with memory, CPU and PID limits supported,
Node.js 24+ and Git. Build the trusted scanner image after source changes:

```bash
npm ci
npm run sandbox:build
npm run dev
```

Open **Projects**, enter `https://github.com/owner/repo`, and click **Analyze
Repository**. Only public GitHub HTTPS URLs are accepted, with an optional
`.git` suffix. A fresh shallow, no-checkout acquisition obtains the latest
default-branch commit using a fixed HTTPS Git read proxy with a 100 MiB byte
budget, no redirects or credentials, a 45-second timeout, no repository
templates or submodules, and no script execution. It first checks Docker and
the image; Docker unavailability stops the scan safely. Git's object pack is
stored under a disposable system temp directory, never in the HackForge source.

The Docker worker has a read-only mount of the acquired Git objects, no network,
no privileges/capabilities, a nonroot user, a read-only root filesystem, a
bounded temporary filesystem, and CPU/memory/PID/time limits. It validates the
tree, rejects symlinks, submodules, special modes, unsafe paths and oversize
files, then extracts blobs as data. It does not run checkout filters, Git hooks,
package scripts, Makefiles, Dockerfiles or any repository instructions. The
existing deterministic detection and scoring modules run on the isolated
snapshot. The worker sees no `GEMINI_API_KEY` or `.env.local`.

Maximum transfer is 100 MiB; total tree bytes 250 MiB; files 10,000; one file
1 MiB; depth 30; source text 32 MiB; scan 60 seconds. Generated directories
and recognized binaries are skipped; the remaining source limit fails closed
instead of issuing a score for a partial scan. Git index checks still include
all tracked paths. LFS pointer files and submodules are unsupported. Paths in
findings become stable opaque `[path:...]` references because filenames can
contain credentials or repository-authored instructions. Raw source and secrets
are never saved or sent to Gemini. Scores cover only secret and Git hygiene
rules; dependency analysis has not been implemented.

Use **Refresh Repository & Rescan** after changing and pushing the public repo.
Each scan clones a new snapshot and records its SHA. **Run Final Scan** marks
the latest scan as FINAL; baseline versus latest computes disappeared,
remaining, and new finding IDs from actual results. Changes in score or status
never come from SAI Assistant. **Reports** provides printable HTML (use the
browser's Print / Save PDF) and downloadable JSON. A baseline-only report
clearly shows no verified improvement yet.

Projects and sanitized scans persist in `.hackforge-data/projects.json` via a
bounded atomic JSON write. The directory is ignored by Git; records are local
and have no credentials, source code or raw paths. The `ProjectRepository`
interface can later be replaced with PostgreSQL. A single Node process handles
one repository scan at a time; concurrent attempts get a busy response. Without
authentication, use only on your own machine, not as a public multiuser service.
The existing 15-minute session-bound SAI explanation service can explain a
stored verified scan when its project is opened; it receives only fixed rule
metadata with full path/sample redaction. Repository instructions never become
prompts.

API: `GET/POST /api/projects`, `GET /api/projects/:id`, `POST
/api/projects/:id/scan`, `GET /api/projects/:id/report?format=html|json`.
Creation accepts only `{ "repositoryUrl": "https://github.com/owner/repo" }`;
scan accepts only `{}` or `{ "scanType": "FINAL" }`. Existing demo APIs remain.
No API accepts a filesystem path, commands, prompts, source, or credentials.

## Controlled demo API

```bash
curl -s http://localhost:3000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"vulnerable-demo"}'
```

Only `{"target":"vulnerable-demo"}` and `{"target":"clean-demo"}` are accepted.
Extra fields, arbitrary paths, traversal, malformed JSON, and bodies over 1 KiB
return 400. Unavailable or unsafe fixtures return 503 with a fixed error message.

A successful response contains `scanId`, `target`, `score`, severity `counts`
(`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `findings`, and ISO `scannedAt`. Each finding
has a stable ID, category, severity, title, description, relative file path,
optional 1-based line number, optional masked sample, remediation, status, and
penalty. Scan IDs and timestamps change on each scan; identical inputs produce
identical findings and scores.

`POST /api/fix-demo` accepts exactly three fields:

```json
{ "target": "vulnerable-demo", "action": "apply-safe-fixes", "confirmed": true }
```

The only other action is `reset-vulnerable-demo`, also requiring `confirmed: true`.
Content type must be JSON; cross-origin requests and URL query parameters are
rejected. No paths, commands, arbitrary content, prompts, or additional fields
are accepted. Missing confirmation or invalid input returns 400; unsafe or
unexpected fixture states return a sanitized 503. Mutation responses contain no
scores or resolved finding IDs. Run `/api/scan` afterward to verify.


`POST /api/scan` also sets a random `HttpOnly; SameSite=Strict` session cookie
(`Secure` on HTTPS). The latest successful scan for that session is eligible for
explanations for 15 minutes. A new successful scan replaces the previous one,
including across browser tabs. Only server-authored metadata is retained, with
at most 100 session records in the Node process; older records may be evicted.

`POST /api/explain` requires `Content-Type: application/json`, that session
cookie, and exactly `{"scanId":"<current scan UUID>","findingId":"<finding ID>"}`.
It accepts no prompts, finding objects, severity overrides, source, or secrets.
Invalid bodies return 400, cross-origin requests 403, and unknown, stale,
expired, or other-session findings 404. Bodies are bounded to 1 KiB. Responses
are never cached by the browser. The server coalesces and caches explanation
requests per finding for the scan lifetime, including fallback responses.

A successful explanation returns:

```json
{
  "source": "gemini",
  "guidance": {
    "explanation": "Plain-English description of the verified finding.",
    "impact": "Potential security impact without asserting compromise.",
    "remediationSteps": ["A practical step based on the scanner remediation."],
    "priorityReason": "Why the existing scanner severity warrants attention."
  }
}
```

The deterministic fallback uses the same shape with `source: "local"`.

## Gemini security boundary

The request flow is: browser IDs → session-bound server lookup → sanitized
metadata → Gemini → runtime JSON validation → separately labeled guidance.
The service and store use Next.js's `server-only` import guard. The browser
imports only response types and never the SDK or key. The scan handler has no
dependency on the Gemini service, so scanning cannot trigger a model call.

Gemini receives only category, fixed severity, scanner-authored title,
description and remediation, a fully redacted sample, and `[REDACTED PATH]`.
Full path redaction also removes arbitrary credentials or prompt injections in
filenames. IDs, score, status, penalty, source lines, entire files, raw secrets,
and session cookies are excluded. Metadata text is trusted only because it comes
from the current scanner's fixed rule strings; new scanner rules must preserve
that invariant. Request bodies never supply this metadata.

The official SDK calls `gemini-3.8-flash` with a fixed instruction, JSON Schema,
no tools, and a 40-second deadline. Requests are not retried. Validation rejects
missing or extra fields, wrong types, blank or oversized text, and invalid step
arrays. Missing configuration, SDK errors, timeouts, blocked output, malformed
JSON, and schema failures fall back locally. Exceptions and request payloads
are never logged or echoed. SDK usage follows the
[official structured-output API](https://googleapis.github.io/js-genai/release_docs/interfaces/types.GenerateContentConfig.html).

Guidance is rendered as escaped React text, without HTML or Markdown execution.
It has no write path to findings, severity, scores, resolution, or false-positive
state. Gemini is instructed to explain only the verified finding and existing
priority; schema validation cannot prove the factual correctness of prose.
Review the advice before acting. A deterministic rescan remains necessary.

## Scoring and statuses

Score is `max(0, 100 - active penalties)`: CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3.
All emitted findings default to OPEN. OPEN and ACCEPTED_RISK always apply their
penalties. A RESOLVED label alone cannot waive a penalty: trusted verified-rescan
evidence is required. A FALSE_POSITIVE label requires evidence of explicit user
action. There is no status mutation endpoint or waiver UI. The API accepts no
status or scoring-evidence input. Before/after comparison uses separate actual
scan responses of the same target, requires a later scan, and identifies
disappeared IDs by set difference. Findings emitted in the new scan remain OPEN.
The current scan score is calculated from its actual findings; clicking a fix
or reading Gemini guidance cannot change it.

## Validation

```bash
npm test
npm run build
npm run lint
```

Tests use Node's built-in test runner without additional dependencies. Coverage
includes full masking, every requested secret family, environment-reference
handling, overlap deduplication, line numbers and stable IDs, scoring and waiver
rules, vulnerable/clean detection, API response sanitization, input/path
validation, effective Git ignore negations, symlink rejection, size/binary
failures, no console logs, and unchanged source and Git metadata after rescans.

Phase 2 tests add sanitized payload construction, mocked SDK HTTP requests,
arbitrary-prompt rejection, strict API/output validation, session ownership,
expiry and eviction, rescan invalidation (including in-flight requests), cached
requests, missing-key/invalid-output/error/timeout fallback, and unchanged scan
results after Gemini failure. All Gemini calls are mocked; a test network guard
prevents real HTTP calls. `--conditions=react-server` enables the server-only
modules in the Node test runner. Existing scanner and Gemini tests remain in place.

## Judge demo sequence (Phase 3)

1. Select **Vulnerable Demo**. Click **Reset Vulnerable Demo** and confirm to
   establish the known initial state, then **SCAN PROJECT**: 37 / 100, 4 findings.
2. Click **Explain with SAI** on a finding. Guidance must leave the score and
   findings unchanged; missing Gemini configuration uses the existing fallback.
3. Click **Apply Safe Demo Fixes** and confirm. The previous scan still shows
   37 and 4 findings; the UI says verification is pending.
4. Click **Rescan & Verify**. The new deterministic scan shows 100 and 0 findings.
   Before vs After shows **+63**, the four disappeared IDs, and no remaining
   findings. Scores and counts come from the two actual scan responses.
5. Click **Reset Vulnerable Demo**, confirm, and scan again. The same 37, four
   finding IDs, and severities return. Gemini explanations work for the new scan.
   Repeat steps 2–5 for each judge.

The fix writes only four allowlisted files inside the vulnerable fixture:
`src/config.ts` uses `process.env.API_KEY`; `.env` retains a comment with no
credential literal; `.gitignore` protects root and nested environment files;
`.env.example` has empty credential values. It removes only `.env` from the
controlled fixture's separate Git v2 index. Reset restores the known fake config
and environment file, removes only the known generated ignore/template files,
and restores the fake `.env` index entry. No shell or mutating Git command runs.

Unexpected file contents (including real credentials), extra fixture files,
symlinks, hardlinked mutation files, redirected directories/metadata, or an
unsupported index fail closed. HackForge source/config, its `.env.local`, its
Git index/history, and Clean Demo are outside the mutation boundary. The only
metadata mutation is `demo-repos/.git-data/vulnerable-demo/index`. Git objects,
refs, HEAD, and all history remain untouched. The fixture starts with staged fake
files and an unborn branch; it does not require an actual credential commit.

**Credential rotation and Git history review recommended.** Verification describes
only the current fixture; it does not certify historical credential removal.
The UI requires explicit browser confirmation for both fixes and reset. Scans
and mutations share an in-process queue so scans cannot observe intermediate
API mutations. This requires a single Node process and stable local filesystem.

Phase 3 tests perform three reset/fix/rescan cycles in isolated fixture copies,
check file and metadata hashes outside the allowlist (including real HackForge),
verify actual scores and stable IDs, reject unsafe input and redirected files,
check no console logging, and exercise mocked Gemini before and after scans.

## Manual Gemini checks

1. Run `npm run dev` with the existing server-side `GEMINI_API_KEY`. Scan
   Vulnerable Demo: confirm 4 OPEN findings and score 37.
2. Click **Explain with SAI** on each finding. Check all four guidance fields
   and the label “SAI Assistant” with the description
   “AI guidance based on a security issue already verified by HackForge.”
   The browser request must contain only scan/finding IDs and target `/api/explain`.
   Verify the browser does not call Google directly and scores/statuses stay fixed.
3. Restart with `GEMINI_API_KEY` unset or empty (also disable any `.env.local`
   value), rescan, and explain. Expect the local-guidance label and useful steps.
   Both demos must still scan normally; Clean Demo remains 100 with no findings.
4. Send `/api/explain` JSON containing `prompt` or an extra `finding` field:
   expect 400. Send valid IDs without the session cookie: expect 404. Rescan and
   replay the previous IDs with the cookie: expect 404. Repeat after 15 minutes.
5. Inspect browser network responses: no raw credential or API key should appear.
   Change demo selection or rescan during an explanation: old guidance must not
   appear on the new scan's findings.

## Known limitations

- Only public GitHub repositories and the two controlled demos can be scanned.
  No private repositories, uploads, arbitrary Git hosts, full Git history,
  dependency vulnerabilities, or service-side credential validation.
- Secret rules are format and assignment heuristics, not a full language parser.
  They may flag harmless literals, including fake demo values and comments, and
  may miss obfuscated, split, multiline, encoded, or unfamiliar credentials.
  Generic keys require a credential-named assignment; there is no entropy scan.
- Sensitive configuration checks use filenames and can flag sanitized files.
  Common environment ignore probes test a fixed representative set of paths.
- Dependency/build directories (`.git`, `node_modules`, `.next`, `dist`, `build`,
  `coverage`) are excluded from source detection. Other binary/non-UTF-8 files,
  symlinks, files over 512 KiB, more than 500 visited source entries, depth over
  20, or total source size over 8 MiB fail the scan instead of returning a clean
  score. Git metadata traversal is also bounded.
- Explanation sessions and their cached guidance are in-memory and process-local.
  Restarts, worker changes, eviction, and expiry require a rescan. This demo needs
  a single Node process; multi-instance deployments need a shared verified-scan
  store. The random session cookie provides scan ownership, not user authentication.
- There is no deployment-wide rate limiter. Per-scan caching limits repeated
  clicks, but the unauthenticated demo should not be exposed as a public paid API.
- Model availability, quota, network access, and key permissions can force fallback.
  Automated validation uses mocks, not a live Gemini account. Fallback is cached
  until the next scan. AI prose may be inaccurate despite shape validation and
  cannot constitute a new finding or a verification of remediation.
- Results are fresh, in-memory snapshots. Concurrent local edits are not a
  transactional filesystem snapshot; demo files and their Git metadata should
  remain stable during scans. Scores describe only the Phase 1 checks and are
  not proof that a project is secure.

Phase 3 ends here. Tiger Data, Backboard, DigitalOcean, and other integrations
are intentionally absent.

## Judge sequence for Phase 5

1. Reset Vulnerable Demo and scan: 37 / 100, four verified findings. Apply Safe
   Demo Fixes, then Rescan & Verify: 100 / 100. Repeatable offline, no Docker.
2. With Docker running and `npm run sandbox:build` complete, paste your own
   public GitHub test repository containing **only fake, nonfunctional** demo
   credentials. The UI labels the controlled demo credentials nonfunctional;
   the public test repository must also explicitly say so in its README.
3. Show the actual baseline commit SHA, score, sanitized findings, and an SAI
   explanation (Gemini if configured, labeled local guidance otherwise).
4. Open the initial report. Edit and push the public test repository yourself;
   HackForge does not push or mutate GitHub.
5. Click Refresh Repository & Rescan or Run Final Scan. Show the second actual
   commit SHA, timeline, verified disappeared/remaining/new IDs, score delta,
   and printable HTML / JSON report. Verify `hackforge-analysis-*` temporary
   directories were removed and no Docker container remains.

The runner used for this implementation lacked Docker, so the container build
and a live GitHub-to-Docker demonstration require validation on the local
Docker-equipped machine. The synthetic two-commit tests exercise scanner,
redaction, SHA evidence, persistence, comparison, cleanup and reports; they
do not substitute for running Docker and GitHub on the judge machine.
