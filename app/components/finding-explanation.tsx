"use client";

import { useState } from "react";
import type { ExplanationResult } from "../../lib/remediation/types.ts";

export function FindingExplanation({ scanId, findingId }: { scanId: string; findingId: string }) {
  const [result, setResult] = useState<ExplanationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  async function explain() {
    if (result) { setExpanded(!expanded); return; }
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/explain", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, findingId }), cache: "no-store",
      });
      if (!response.ok) {
        setError(response.status === 404
          ? "This scan is no longer available. Run a new scan, then try again."
          : "Explanation unavailable. The SAI Security Scanner remediation above is still available.");
        return;
      }
      setResult(await response.json() as ExplanationResult);
      setExpanded(true);
    } catch {
      setError("Cannot reach the explanation service. The SAI Security Scanner remediation above is still available.");
    } finally { setLoading(false); }
  }

  return (
    <div className="finding-explanation">
      <button className="secondary-button" type="button" onClick={explain} disabled={loading}
        aria-expanded={expanded} aria-controls={`explanation-${scanId}-${findingId}`}>
        {loading ? "Explaining…" : expanded ? "Close SAI explanation" : "Explain with SAI"}
      </button>
      <div id={`explanation-${scanId}-${findingId}`} aria-live="polite" aria-busy={loading}>
        {error && <p role="alert" className="error-message">{error}</p>}
        {result && expanded && (
          <section className="explanation-content" aria-label="SAI Assistant explanation">
            <div className="assistant-heading"><span className="assistant-mark" aria-hidden="true">✦</span><div><p className="explanation-label">SAI Assistant</p><span className="assistant-source">{result.source === "gemini" ? "Powered by Gemini" : "Scanner-backed local guidance"}</span></div></div>
            <p>{result.source === "gemini"
              ? "AI guidance based on a security issue already verified by HackForge."
              : "SAI Assistant unavailable. Deterministic local guidance based on a security issue already verified by HackForge."}</p>
            <h4>What this means</h4>
            <p>{result.guidance.explanation}</p>
            <h4>Why it matters</h4>
            <p>{result.guidance.impact}</p>
            <h4>Recommended remediation</h4>
            <ol>{result.guidance.remediationSteps.map((step, index) => <li key={index}>{step}</li>)}</ol>
            <details className="assistant-priority"><summary>Remediation context</summary><p>{result.guidance.priorityReason}</p></details>
            <p className="explanation-note">SAI explains verified scanner findings. It does not determine severity, score, or resolution.</p>
          </section>
        )}
      </div>
    </div>
  );
}
