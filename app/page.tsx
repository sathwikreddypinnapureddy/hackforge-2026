"use client";

import { useState } from "react";
import type { FormEvent } from "react";
import { SEVERITIES } from "../lib/scanner/types.ts";
import type { ScanResult, ScanTarget } from "../lib/scanner/types.ts";

const TARGET_LABELS: Record<ScanTarget, string> = {
  "vulnerable-demo": "Vulnerable Demo",
  "clean-demo": "Clean Demo",
};

export default function Home() {
  const [target, setTarget] = useState<ScanTarget>("vulnerable-demo");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function scan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScanning(true);
    setError(null);
    setResult(null);
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
      setResult(await response.json() as ScanResult);
    } catch {
      setError("Cannot reach CyberBot. Check that the development server is running and try again.");
    } finally { setScanning(false); }
  }

  return (
    <main className="workspace">
      <header className="workspace-header">
        <div>
          <p className="eyebrow">hackUMBC 2026 · Phase 1</p>
          <h1>HackForge<span className="brand-dot">.</span></h1>
        </div>
        <span className="phase-badge">CyberBot / deterministic scanner</span>
      </header>

      <section className="intro">
        <h2>Know what&apos;s in your project.</h2>
        <p>Scan a controlled demo for exposed credentials and Git hygiene issues.
          Findings come from deterministic rules. Credential values are masked on the server.</p>
      </section>

      <form className="scan-controls panel" onSubmit={scan}>
        <div className="target-control">
          <label htmlFor="target">Project</label>
          <select id="target" value={target} disabled={scanning} onChange={(event) => {
            setTarget(event.target.value as ScanTarget);
            setResult(null);
            setError(null);
          }}>
            <option value="vulnerable-demo">Vulnerable Demo</option>
            <option value="clean-demo">Clean Demo</option>
          </select>
        </div>
        <button type="submit" disabled={scanning}>{scanning ? "SCANNING…" : "SCAN PROJECT"}</button>
      </form>

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
            <div className="empty-state panel clean-state">No findings detected by Phase 1 rules. Score: 100 / 100.</div>
          )}
          {result?.findings.map((finding) => (
            <article className="finding panel" key={finding.id}>
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
            </article>
          ))}
          {result && <p className="scan-meta">Scanned at {result.scannedAt} · Scan {result.scanId}</p>}
        </section>
      </div>

      <footer>Score starts at 100. Critical −25 · High −15 · Medium −8 · Low −3.
        All Phase 1 findings are OPEN. Accepting a risk keeps its penalty.</footer>
    </main>
  );
}
