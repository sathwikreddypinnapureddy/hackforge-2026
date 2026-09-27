# Phase 6 local remediation

Remediation uses a new isolated acquisition through the Phase 5 public GitHub read proxy. The acquired HEAD must equal the latest stored scan commit exactly. A fresh deterministic scan must reproduce the stored baseline. Repository files are materialized as validated blobs, without checkout, filters, target execution or dependency installation.

SAI's existing explanation can use Gemini with sanitized scanner metadata. Fix proposals use bounded local SAI templates: append environment ignore rules, remove an entire tracked environment file, or replace one simple JS/TS credential assignment with `process.env.HACKFORGE_CREDENTIAL`. The assistant never receives raw secrets, executes commands or controls scanner evidence. Other syntax and sensitive configurations require manual remediation. An environment-file removal removes all of that file's settings; the review panel says this explicitly. Real credential rotation and historical secret cleanup remain manual.

A proposal owns server-only structured operations with a 15-minute expiry, bound to the scan-session cookie. Opening an explanation is never approval. The API accepts only finding IDs or a session ID and explicit approval; it accepts no patches, commands, scores or resolution fields. Review displays the finding ID, severity, opaque file references, remediation, affected files, sanitized patch and fixed commit subject. Cancel deletes the temporary proposal workspace.

Approval creates a local working branch and then `hackforge/remediation/<sanitized-id>-<UTC timestamp>` at the exact baseline SHA. Branches use only safe characters and pass Git `check-ref-format`. No repository text selects a name. Structured operations reject absolute paths, traversal, `.git`, symlinks, hardlinks and HackForge source roots. Limits are five files, 64 KiB of patch text and 32 KiB per generated file. All operations are preflighted before writing. Git uses fixed argument arrays, a stripped environment, literal pathspecs, disabled hooks/signing, no inherited filter/remote configuration and a scanner-built index that preserves untouched blobs.

One focused commit is created per session. The commit record includes the actual SHA, subject, finding IDs, opaque changed-file references, sanitized summary and author/committer times read from Git and normalized to ISO UTC. A new static scan reads that committed branch, verifies its SHA and compares stable finding IDs. Only scanner comparison emits resolved/remaining/new events. Ready for review does not mean every finding resolved or that runtime behavior was tested.

The append-only JSONL journal stores projections with immutable event prefixes, UUID event IDs and actual ISO UTC timestamps. Every event carries project/session/scan/finding IDs, repository and source SHA, plus branch/commit metadata when available. The UI reads chronological persisted evidence, including after a restart. No update/delete API exists. This is a single-process local store, not a tamper-evident or multi-user audit database.

Ready branches are retained in private OS temporary workspaces. The result displays the local Git review directory. Inspect the committed diff with `git -C <review-directory> show <commit-sha>`; source files live in the explicitly configured private worktree. Pending proposals cannot resume after a server restart; create a fresh proposal. Failed operations never reach ready status and clean their workspace. Abandoned process-crash workspaces and retained ready workspaces need manual lifecycle management. The OS may remove temporary artifacts; the persisted audit remains. Remediation scans are session evidence, separate from the project’s public-default-branch scan history and Phase 5 reports. A rescan of the public project still reads its unchanged default branch.

## Safe controlled demo

Run `npm run demo:remediation` from the HackForge directory. It creates a fresh temporary Git fixture containing one nonfunctional fake credential. Review the sanitized proposal; type `APPROVE` explicitly. The demo creates a local branch, one commit, a deterministic rescan, and prints ready status, scores, commit metadata, timeline and local review directory. Enter cancels. No public repository is acquired or changed. The audit journal and ready Git branch are retained for inspection.

## Browser workflow

Run `npm run dev`. Use an expendable public fixture you own (never an important repository or the public hackforge-validation-target). Analyze it in the real repository workspace. Expand a finding, select **Explain with SAI**, then **Propose Fix**. Review the panel, select **Approve & Create Fix Branch**, and inspect branch/commit/time, before/after scores and resolved/remaining/new counts. Expand **Remediation Timeline** for the chronological audit. **Cancel** creates no branch. The browser workflow only acquires public snapshots; the remediation branch remains local. No push, merge or force-push exists in the automated workflow.

## Validation

`npm test`, `npm run lint`, `npm run build`. Phase 6 tests use fresh temporary fake Git fixtures. Existing Phase 5 and controlled-demo tests run unchanged.
