"use client";

import { useState } from "react";
import type { ExplanationResult } from "../../lib/remediation/types.ts";

export function FindingExplanation({ scanId, findingId }: { scanId: string; findingId: string }) {
  const [result, setResult] = useState<ExplanationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function explain() {
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
          : "Explanation unavailable. The CyberBot remediation above is still available.");
        return;
      }
      setResult(await response.json() as ExplanationResult);
    } catch {
      setError("Cannot reach the explanation service. The CyberBot remediation above is still available.");
    } finally { setLoading(false); }
  }

  return (
    <div className="finding-explanation">
      <button type="button" onClick={explain} disabled={loading || result !== null}
        aria-expanded={result !== null} aria-controls={`explanation-${findingId}`}>
        {loading ? "Explaining…" : "Explain with Gemini"}
      </button>
      <div id={`explanation-${findingId}`} aria-live="polite" aria-busy={loading}>
        {error && <p role="alert" className="error-message">{error}</p>}
        {result && (
          <div className="explanation-content">
            <p className="explanation-label">{result.source === "gemini"
              ? "AI-generated explanation based on a verified CyberBot finding."
              : "Gemini unavailable. Deterministic local guidance based on a verified CyberBot finding."}</p>
            <h4>Plain-English explanation</h4>
            <p>{result.guidance.explanation}</p>
            <h4>Security impact</h4>
            <p>{result.guidance.impact}</p>
            <h4>Remediation steps</h4>
            <ol>{result.guidance.remediationSteps.map((step, index) => <li key={index}>{step}</li>)}</ol>
            <h4>Priority explanation</h4>
            <p>{result.guidance.priorityReason}</p>
            <p className="explanation-note">Review guidance before making changes. CyberBot controls findings, severity, score, and status.</p>
          </div>
        )}
      </div>
    </div>
  );
}
