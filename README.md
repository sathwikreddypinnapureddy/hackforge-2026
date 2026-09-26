# HackForge · CyberBot Phase 2

HackForge is a security-first development workspace for hackathon teams, built
during hackUMBC 2026. **The deterministic scanner determines what exists.** This
phase adds Gemini explanations of verified findings. Gemini never discovers
findings or controls severity, scores, or status. There is no authentication,
database, or other sponsor integration.

## Run the demo

Requires Node.js 22.18+ and Git on PATH. Run from this project directory.

```bash
npm ci
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

Click **Explain with Gemini** on any finding for an explanation, potential
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
`npm run setup:demos`. Setup is not called by the API or scanner.

## API

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

The official SDK calls `gemini-2.5-flash` with a fixed instruction, JSON Schema,
no tools, and a 10-second deadline. Requests are not retried. Validation rejects
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
All Phase 1 findings default to OPEN. OPEN and ACCEPTED_RISK always apply their
penalties. A RESOLVED label alone cannot waive a penalty: trusted verified-rescan
evidence is required. A FALSE_POSITIVE label requires evidence of explicit user
action. There is no status mutation endpoint, waiver UI, or persistence in Phase
2. The API accepts no status or scoring-evidence input.

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
modules in the Node test runner. Existing Phase 1 tests are unchanged.

## Manual Phase 2 checks

1. Run `npm run dev` with the existing server-side `GEMINI_API_KEY`. Scan
   Vulnerable Demo: confirm 4 OPEN findings and score 37.
2. Click **Explain with Gemini** on each finding. Check all four guidance fields
   and the label “AI-generated explanation based on a verified CyberBot finding.”
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

- Only the two local, controlled demos can be scanned. No remote URLs, uploads,
  arbitrary projects, repository history, or service-side credential validation.
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

Phase 2 ends here. Tiger Data, Backboard, DigitalOcean, and other integrations
are intentionally absent.
