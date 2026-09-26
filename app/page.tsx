"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { SEVERITIES } from "../lib/scanner/types.ts";
import type { ScanResult, ScanTarget } from "../lib/scanner/types.ts";
import { compareScans } from "../lib/demo/comparison.ts";
import { FindingExplanation } from "./components/finding-explanation.tsx";

const TARGET_LABELS: Record<ScanTarget, string> = {
  "vulnerable-demo": "Vulnerable Demo",
  "clean-demo": "Clean Demo",
};

export default function Home() {
  const [target, setTarget] = useState<ScanTarget>("vulnerable-demo");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [before, setBefore] = useState<ScanResult | null>(null);
  const [comparison, setComparison] = useState<ReturnType<typeof compareScans> | null>(null);
  const [fixed, setFixed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function scan(event?: FormEvent<HTMLFormElement>, verify = false) {
    event?.preventDefault();
    setScanning(true);
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
        setNotice("Rescan complete. CyberBot verified the comparison below from deterministic findings.");
      } else setBefore(null);
      setResult(next);
    } catch {
      setError("Cannot reach CyberBot. Check that the development server is running and try again.");
    } finally { setScanning(false); }
  }

  async function demoAction(action: "apply-safe-fixes" | "reset-vulnerable-demo") {
    const reset = action === "reset-vulnerable-demo";
    const confirmation = reset
      ? "Reset only Vulnerable Demo to its known fake-vulnerable state? This removes the generated demo ignore rules and template."
      : "Apply safe fixes only inside Vulnerable Demo? This replaces fake credentials, clears the demo .env, untracks it from the controlled index, and adds ignore rules and a secret-free template. Git history will remain unchanged.";
    if (!window.confirm(confirmation)) return;
    setScanning(true);
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
        : "Safe demo fixes applied. Findings remain unverified until Rescan & Verify completes.");
      setBefore(reset ? null : result);
      setFixed(!reset);
      if (reset) setResult(null);
    } catch {
      setError("Cannot reach CyberBot. Rescan before trusting the fixture state.");
    } finally { setScanning(false); }
  }

  return (
    <main className="workspace">
      <header className="workspace-header">
        <div>
          <p className="eyebrow">hackUMBC 2026 · Phase 3</p>
          <h1>HackForge<span className="brand-dot">.</span></h1>
        </div>
        <span className="phase-badge">CyberBot / deterministic scanner</span>
      </header>

      <section className="intro">
        <h2>Know what&apos;s in your project.</h2>
        <p>Scan a controlled demo for exposed credentials and Git hygiene issues.
          Findings come from deterministic rules. Credential values are masked on the server.
          Ask Gemini to explain a verified finding and its remediation.</p>
      </section>

      <form className="scan-controls panel" onSubmit={(event) => { void scan(event); }}>
        <div className="target-control">
          <label htmlFor="target">Project</label>
          <select id="target" value={target} disabled={scanning} onChange={(event) => {
            setTarget(event.target.value as ScanTarget);
            setResult(null);
            setError(null);
            setBefore(null);
            setComparison(null);
            setFixed(false);
            setNotice(null);
          }}>
            <option value="vulnerable-demo">Vulnerable Demo</option>
            <option value="clean-demo">Clean Demo</option>
          </select>
        </div>
        <button type="submit" disabled={scanning}>{scanning ? "SCANNING…" : "SCAN PROJECT"}</button>
      </form>

      {target === "vulnerable-demo" && (
        <section className="demo-workflow panel" aria-label="Verified demo remediation">
          <h2>Fix, rescan, verify.</h2>
          <p>Only the controlled fake fixture can be changed. Confirmation is required.
            Credential rotation and Git history review recommended.</p>
          <div className="demo-actions">
            <button disabled={scanning || !result || fixed} onClick={() => void demoAction("apply-safe-fixes")}>Apply Safe Demo Fixes</button>
            <button disabled={scanning || !result} onClick={() => void scan(undefined, true)}>Rescan &amp; Verify</button>
            <button className="secondary-button" disabled={scanning} onClick={() => void demoAction("reset-vulnerable-demo")}>Reset Vulnerable Demo</button>
          </div>
          {notice && <p role="status">{notice}</p>}
        </section>
      )}

      {comparison && (
        <section className="comparison panel" aria-label="Before versus after verification" aria-live="polite">
          <h2>Before vs After</h2>
          <div className="comparison-grid">
            <div><p className="eyebrow">BEFORE</p><strong>Score: {comparison.previousScore}</strong><p>{comparison.previousCount} findings</p></div>
            <div><p className="eyebrow">AFTER</p><strong>Score: {comparison.newScore}</strong><p>{comparison.newCount} findings</p></div>
          </div>
          <p className="verified-improvement">Verified improvement: {comparison.improvement >= 0 ? "+" : ""}{comparison.improvement}</p>
          <p>CyberBot compared deterministic scans. Disappeared IDs are verified resolved in the current fixture state.</p>
          <h3>Disappeared finding IDs ({comparison.disappeared.length})</h3>
          {comparison.disappeared.length === 0 ? <p>None.</p> : <ul>{comparison.disappeared.map((finding) => <li key={finding.id}>{finding.title} · <code>{finding.id}</code></li>)}</ul>}
          <h3>Findings in the new scan ({comparison.remaining.length})</h3>
          {comparison.remaining.length === 0 ? <p>None remain.</p> : <ul>{comparison.remaining.map((finding) => <li key={finding.id}>{finding.title} · <code>{finding.id}</code> · OPEN</li>)}</ul>}
          <p>Credential rotation and Git history review recommended. Current-state verification does not certify Git history is clean.</p>
        </section>
      )}

      {error && <p role="alert" className="error-message">{error}</p>}

      <div aria-live="polite" aria-busy={scanning}>
        <section className="score-grid" aria-label="Security posture">
          <div className="posture panel">
            <p className="eyebrow">Security posture score</p>
            <div className={`score ${result && result.score < 70 ? "score-warning" : ""}`}>
              {result ? result.score : "—"}<span>/ 100</span>
            </div>
            <p>{result ? `${TARGET_LABELS[result.target]} · ${result.findings.length} findings` : "Run a scan to see verified findings."}</p>
          </div>
          <div className="severity-grid">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="severity-count panel">
                <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>
                <strong>{result ? result.counts[severity] : "—"}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="findings-section" aria-label="Scan findings">
          <div className="section-heading">
            <h2>Findings</h2>
            {result && <span>{result.findings.length} open</span>}
          </div>
          {scanning && <div className="empty-state panel" role="status">Checking files and Git tracking…</div>}
          {!scanning && !result && <div className="empty-state panel">Select a demo and scan to get started. Both demos use only nonfunctional test credentials.</div>}
          {result && result.findings.length === 0 && (
            <div className="empty-state panel clean-state">No findings detected by deterministic rules. Score: {result.score} / 100.</div>
          )}
          {result?.findings.map((finding) => (
            <article className="finding panel" key={`${result.scanId}:${finding.id}`}>
              <div className="finding-header">
                <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                <span className="finding-category">{finding.category === "SECRET" ? "Secret detection" : "Git hygiene"}</span>
                <span className="finding-status">{finding.status} · −{finding.penalty} pts</span>
              </div>
              <h3>{finding.title}</h3>
              <p>{finding.description}</p>
              <div className="finding-evidence">
                <code>{finding.filePath}{finding.lineNumber ? `:${finding.lineNumber}` : ""}</code>
                {finding.maskedSample && <code className="masked-sample">{finding.maskedSample}</code>}
              </div>
              <div className="remediation"><strong>Remediation</strong><p>{finding.remediation}</p></div>
              <FindingExplanation scanId={result.scanId} findingId={finding.id} />
            </article>
          ))}
          {result && <p className="scan-meta">Scanned at {result.scannedAt} · Scan {result.scanId}</p>}
        </section>
      </div>

      <footer>Score starts at 100. Critical −25 · High −15 · Medium −8 · Low −3.
        Emitted findings stay OPEN. Only a later deterministic scan can verify disappearance.</footer>
    </main>
  );
}
