"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { SEVERITIES } from "../lib/scanner/types.ts";
import type { DemoTarget, ScanResult } from "../lib/scanner/types.ts";
import { compareScans } from "../lib/demo/comparison.ts";
import { FindingExplanation } from "./components/finding-explanation.tsx";
import { ProjectWorkspace } from "./components/project-workspace.tsx";

const TARGET_LABELS: Record<DemoTarget, string> = {
  "vulnerable-demo": "Vulnerable Demo",
  "clean-demo": "Clean Demo",
};

export default function Home() {
  const [mode, setMode] = useState<"projects" | "demo">("projects");
  const [target, setTarget] = useState<DemoTarget>("vulnerable-demo");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [activity, setActivity] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [before, setBefore] = useState<ScanResult | null>(null);
  const [comparison, setComparison] = useState<ReturnType<typeof compareScans> | null>(null);
  const [fixed, setFixed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function scan(event?: FormEvent<HTMLFormElement>, verify = false) {
    event?.preventDefault();
    setScanning(true);
    setActivity(verify || fixed ? "SAI is verifying the fixes..." : "SAI is checking your project...");
    setNotice(null);
    setError(null);
    setComparison(null);
    try {
      const response = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }), cache: "no-store",
      });
      if (!response.ok) {
        setError(response.status === 503
          ? "Demo unavailable. Run npm run setup:demos in the project, then try again."
          : "The scan could not be completed. Try again.");
        return;
      }
      const next = await response.json() as ScanResult;
      if ((verify || fixed) && (before ?? result)) {
        setComparison(compareScans((before ?? result)!, next));
        setNotice("Verification complete.");
      } else setBefore(null);
      setResult(next);
    } catch {
      setError("Cannot reach SAI Security Scanner. Check that the development server is running and try again.");
    } finally { setScanning(false); setActivity(null); }
  }

  async function demoAction(action: "apply-safe-fixes" | "reset-vulnerable-demo") {
    const reset = action === "reset-vulnerable-demo";
    const confirmation = reset
      ? "Reset only Vulnerable Demo to its known fake-vulnerable state? This removes the generated demo ignore rules and template."
      : "Apply safe fixes only inside Vulnerable Demo? This replaces fake credentials, clears the demo .env, untracks it from the controlled index, and adds ignore rules and a secret-free template. Git history will remain unchanged.";
    if (!window.confirm(confirmation)) return;
    setScanning(true);
    setActivity(reset ? "Resetting the demo..." : "Applying safe demo fixes...");
    setNotice(null);
    setError(null);
    setComparison(null);
    try {
      const response = await fetch("/api/fix-demo", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "vulnerable-demo", action, confirmed: true }),
      });
      if (!response.ok) {
        setError("Demo action unavailable. Only known controlled fixture states can be changed. Rescan to check the current state.");
        return;
      }
      setNotice(reset
        ? "Vulnerable Demo restored. Scan again to start a new demonstration."
        : "Fixes applied. Rescan to verify the result.");
      setBefore(reset ? null : result);
      setFixed(!reset);
      if (reset) setResult(null);
    } catch {
      setError("Cannot reach SAI Security Scanner. Rescan before trusting the fixture state.");
    } finally { setScanning(false); setActivity(null); }
  }

  return (
    <main className="workspace">
      <a className="skip-link" href={mode === "projects" ? "#projects" : "#scan-project"}>Skip to workspace</a>
      <header className="workspace-header">
        <div className="brand"><span className="brand-mark" aria-hidden="true">H</span><div>
          <p className="brand-name">HackForge<span className="brand-dot">.</span></p>
          <p className="tagline">Build Fast. Ship Secure.</p>
        </div></div>
        <nav className="app-navigation" aria-label="Application mode">
          <button type="button" aria-pressed={mode === "projects"} onClick={() => setMode("projects")}>Projects</button>
          <button type="button" aria-pressed={mode === "demo"} onClick={() => setMode("demo")}>Demo Lab</button>
        </nav>
        <span className="ready-badge"><span aria-hidden="true" className="status-dot" />{scanning ? "SAI Working…" : "SAI Ready"}</span>
      </header>

      <div hidden={mode !== "projects"}><ProjectWorkspace /></div>
      {mode === "demo" && <div className="demo-lab">

      <section className="intro">
        <p className="eyebrow">Controlled judge demonstration</p>
        <h1>Demo Lab<span className="demo-tag">Synthetic fixtures</span></h1>
        <p>Uses intentionally vulnerable synthetic fixtures. All credential-like values are fake and nonfunctional.</p>
      </section>

      <nav className="progress-flow" aria-label="Security workflow">
        <ol>{["Scan", "Understand", "Fix", "Verify"].map((step, index) => (
          <li className={index === (comparison ? 3 : fixed ? 2 : result ? 1 : 0) ? "current-step" : ""} key={step}><span className="step-number" aria-hidden="true">{index + 1}</span><span>{step}</span></li>
        ))}</ol>
        <p>SAI Scanner finds it. SAI Assistant explains it. HackForge verifies the fix.</p>
      </nav>

      <section className="scan-card panel" id="scan-project" aria-labelledby="scan-heading">
        <h2 id="scan-heading">Scan a demo fixture</h2>
        <p>Explore the scan, explanation, and verification flow in a controlled environment.</p>
        <form className="scan-controls" onSubmit={(event) => { void scan(event); }}>
          <div className="target-control">
            <label htmlFor="target">Demo fixture</label>
            <select id="target" value={target} disabled={scanning} onChange={(event) => {
              setTarget(event.target.value as DemoTarget);
              setResult(null); setError(null); setBefore(null); setComparison(null); setFixed(false); setNotice(null);
            }}>
              <option value="vulnerable-demo">Vulnerable Demo</option>
              <option value="clean-demo">Clean Demo</option>
            </select>
          </div>
          <button type="submit" disabled={scanning}>{scanning ? "Working…" : "Scan Project"} <span aria-hidden="true">→</span></button>
        </form>
        <p className="helper">Two controlled demo projects. All demo credentials are nonfunctional.</p>
        <div role="status" aria-live="polite" className="scan-status">
          {activity || (result ? `SAI found ${result.findings.length} verified security ${result.findings.length === 1 ? "issue" : "issues"} in ${TARGET_LABELS[result.target as DemoTarget]}.` : "Choose a project to get started.")}
        </div>
      </section>
      {error && <p role="alert" className="error-message">{error}</p>}

      {result && <><section className="score-grid" id="security" aria-label="Demo security overview" aria-busy={scanning}>
        <div className="posture panel">
          <h2>Project Security Score</h2>
          <div className={`score ${result && result.score < 100 ? "score-warning" : ""}`}>
            {result ? result.score : "—"}<span>/ 100</span>
          </div>
          <p className="score-status">{result ? (result.findings.length === 0 ? "No supported issues found" : "Needs attention") : "Awaiting your first scan"}</p>
          <p className="helper">Score reflects only checks currently supported by HackForge.</p>
        </div>
        <div className="severity-summary">
          <h2>Severity summary</h2>
          <div className="severity-grid">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="severity-count panel">
                <span className={`severity severity-${severity.toLowerCase()}`}>{severity.charAt(0) + severity.slice(1).toLowerCase()}</span>
                <strong>{result ? result.counts[severity] : "—"}</strong>
              </div>
            ))}
          </div>
          <p className="helper">Verified findings, grouped by severity.</p>
        </div>
      </section>

      <section className="findings-section" aria-labelledby="findings-heading">
        <div className="section-heading"><h2 id="findings-heading">Findings</h2>{result && <span>{result.findings.length} open</span>}</div>
        {!result && <div className="empty-state panel">Your results will appear here. Start with Scan Project above.</div>}
        {result && result.findings.length === 0 && <div className="empty-state panel clean-state"><strong>✓ No supported issues detected</strong><p>Your latest scan is clear for the supported checks.</p></div>}
        {result?.findings.map((finding) => (
          <details className="finding panel" key={`${result.scanId}:${finding.id}`}>
            <summary className="finding-summary">
              <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
              <span className="finding-heading"><strong>{finding.title}</strong><code>{finding.filePath}{finding.lineNumber ? `:${finding.lineNumber}` : ""}</code></span>
              <span className="finding-status">{finding.status} ON FIXTURE</span>
              <span className="expand-label" aria-hidden="true">›</span>
            </summary>
            <div className="finding-body">
              <h3>What happened?</h3><p>{finding.description}</p>
              <h3>Why it matters</h3><p>{finding.category === "SECRET"
                ? "If a credential is real, someone who can read the project may be able to access the account or service it belongs to."
                : "Sensitive files can accidentally be included when you share your project or push it to Git."}</p>
              <h3>How to fix it</h3><p>{finding.remediation}</p>
              <FindingExplanation scanId={result.scanId} findingId={finding.id} />
              <details className="technical-details"><summary>Technical details</summary>
                <dl><dt>Category</dt><dd>{finding.category}</dd><dt>Finding ID</dt><dd>{finding.id}</dd><dt>Score penalty</dt><dd>{finding.penalty} points</dd>
                  {finding.lineNumber && <><dt>Line number</dt><dd>{finding.lineNumber}</dd></>}
                  {finding.maskedSample && <><dt>Masked sample</dt><dd><code>{finding.maskedSample}</code></dd></>}
                  <dt>Path reference</dt><dd><code>{finding.filePath}</code></dd><dt>Scan ID</dt><dd>{result.scanId}</dd><dt>Scanned at</dt><dd>{result.scannedAt}</dd></dl>
              </details>
            </div>
          </details>
        ))}
      </section></>}

      {target === "vulnerable-demo" && result && <>
        <section className="demo-workflow panel" aria-labelledby="fix-heading">
          <div><p className="eyebrow">Next step · Fix</p><h2 id="fix-heading">Ready to fix these issues?</h2>
            <p>HackForge can safely repair the controlled demo project.</p><p className="helper">You’ll confirm the changes before they are applied.</p>
            {activity === "Applying safe demo fixes..." && <p role="status">{activity}</p>}</div>
          <button className="secondary-button" disabled={scanning || !result || fixed} onClick={() => void demoAction("apply-safe-fixes")}>Apply Safe Demo Fixes</button>
        </section>
        <section className="verify-workflow panel" aria-labelledby="verify-heading">
          <div><p className="eyebrow">Next step · Verify</p><h2 id="verify-heading">Check that your fixes worked.</h2><p>A new scan verifies the result and compares your scores.</p>
            {activity === "SAI is verifying the fixes..." && <p role="status">{activity}</p>}</div>
          <button disabled={scanning || !result} onClick={() => void scan(undefined, true)}>Rescan &amp; Verify <span aria-hidden="true">→</span></button>
        </section>
      </>}
      {notice && <p className="notice" role="status">{notice}</p>}

      {comparison && (
        <section className="comparison" aria-labelledby="comparison-heading" aria-live="polite">
          <p className="eyebrow">Security improvement</p><h2 id="comparison-heading">Before vs After</h2>
          <div className="comparison-grid">
            <div className="comparison-card"><p className="comparison-label">Before</p><strong>{comparison.previousScore}<span> / 100</span></strong><p>{comparison.previousCount} {comparison.previousCount === 1 ? "finding" : "findings"}</p></div>
            <span className="comparison-arrow" aria-hidden="true">→</span>
            <div className="comparison-card after-card"><p className="comparison-label">After</p><strong>{comparison.newScore}<span> / 100</span></strong><p>{comparison.newCount} {comparison.newCount === 1 ? "finding" : "findings"}</p></div>
            <div className="improvement"><strong>{comparison.improvement >= 0 ? "+" : ""}{comparison.improvement}</strong><p>Verified improvement</p></div>
          </div>
          <p className="verification-label">Fixes verified by SAI Security Scanner</p>
          <div className="comparison-totals"><p>Resolved after rescan: <strong>{comparison.disappeared.length}</strong></p><p>Remaining: <strong>{comparison.remaining.length}</strong></p></div>
          <details className="comparison-details"><summary>Verification details</summary>
            <h3>Resolved after rescan</h3>{comparison.disappeared.length ? <ul>{comparison.disappeared.map((finding) => <li key={finding.id}>{finding.title} · <code>{finding.id}</code></li>)}</ul> : <p>No finding IDs disappeared.</p>}
            <h3>Remaining findings</h3>{comparison.remaining.length ? <ul>{comparison.remaining.map((finding) => <li key={finding.id}>{finding.title} · {finding.status}</li>)}</ul> : <p>No findings remain in the current scan.</p>}
            <p>Verification compares current project scans. Credential rotation and Git history review are still recommended; this does not certify Git history is clean.</p>
          </details>
        </section>
      )}

      {target === "vulnerable-demo" && <section className="reset-demo" aria-label="Repeat the demo">
        <div><h2>Demo again?</h2><p>Restore the controlled vulnerable project so the demo can be repeated.</p></div>
        <button className="tertiary-button" disabled={scanning} onClick={() => void demoAction("reset-vulnerable-demo")}>Reset Demo</button>
      </section>}
      </div>}
      <footer><strong>HackForge</strong><span>Build Fast. Ship Secure.</span><p>SAI Scanner finds it. SAI Assistant explains it. HackForge verifies the fix.</p></footer>
    </main>
  );
}
