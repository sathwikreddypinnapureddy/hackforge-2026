export interface RemediationExplanation {
  explanation: string;
  impact: string;
  remediationSteps: string[];
  priorityReason: string;
}

export interface ExplanationResult {
  source: "gemini" | "local";
  guidance: RemediationExplanation;
}
