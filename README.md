# HackForge · CyberBot Phase 1.5

HackForge is a security-first development workspace for hackathon teams, built
during hackUMBC 2026. **The deterministic scanner determines what exists.** This
phase has no AI, authentication, database, or sponsor integrations.

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

## Scoring and statuses

Score is `max(0, 100 - active penalties)`: CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3.
All Phase 1 findings default to OPEN. OPEN and ACCEPTED_RISK always apply their
penalties. A RESOLVED label alone cannot waive a penalty: trusted verified-rescan
evidence is required. A FALSE_POSITIVE label requires evidence of explicit user
action. There is no status mutation endpoint, waiver UI, or persistence in Phase
1. The API accepts no status or scoring-evidence input.

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
- Results are fresh, in-memory snapshots. Concurrent local edits are not a
  transactional filesystem snapshot; demo files and their Git metadata should
  remain stable during scans. Scores describe only the Phase 1 checks and are
  not proof that a project is secure.

Phase 1.5 ends here. Gemini and other integrations are intentionally absent.
