/**
 * Map validated assessment data to the labels the popup renders.
 *
 * The wording keeps the three concepts separate: a heuristic risk band, the
 * evidence coverage, and an unavailable assessment. There is deliberately no
 * "safe" state. A low band with incomplete coverage still says coverage is
 * incomplete.
 */

import type {
  AssessmentData,
  RiskBand,
  RiskFactorStatus,
  Severity,
} from "./assessment.ts";

export type AssessmentState =
  | "high_risk"
  | "suspicious"
  | "caution"
  | "low"
  | "incomplete";

export interface AssessmentView {
  state: AssessmentState;
  headline: string;
  bandLabel: string;
  score: number | null;
  verdict: string;
  reasons: string[];
  missing: string[];
  coverageLabel: string;
  partial: boolean;
  likelihoodLabel: string;
  postureLabel: string;
  heuristicNotice: string;
}

export const HEURISTIC_NOTICE =
  "This is an assessment aid, not a guarantee of safety. Scores are heuristic, not probabilities.";

const BAND_LABELS: Record<RiskBand, string> = {
  low: "Low",
  guarded: "Guarded",
  suspicious: "Suspicious",
  high: "High",
  critical: "Critical",
  insufficient_evidence: "Insufficient evidence",
};

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const COUNTABLE_FACTOR_STATUSES: readonly RiskFactorStatus[] = ["applied", "evaluated"];

export function bandLabel(band: RiskBand): string {
  return BAND_LABELS[band];
}

function stateForBand(band: RiskBand): AssessmentState {
  switch (band) {
    case "high":
    case "critical":
      return "high_risk";
    case "suspicious":
      return "suspicious";
    case "guarded":
      return "caution";
    case "low":
      return "low";
    case "insufficient_evidence":
      return "incomplete";
  }
}

function headlineForState(state: AssessmentState): string {
  switch (state) {
    case "high_risk":
      return "High-risk evidence";
    case "suspicious":
      return "Suspicious characteristics";
    case "caution":
      return "Some caution indicators";
    case "low":
      return "Low observed risk";
    case "incomplete":
      return "Incomplete assessment";
  }
}

function buildReasons(data: AssessmentData, state: AssessmentState): string[] {
  const factors = data.factors
    .filter(
      (factor) =>
        factor.direction === "increases_risk" &&
        COUNTABLE_FACTOR_STATUSES.includes(factor.status),
    )
    .sort(
      (left, right) =>
        right.contribution - left.contribution ||
        SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity],
    );

  const reasons: string[] = [];
  for (const factor of factors) {
    if (!reasons.includes(factor.explanation)) {
      reasons.push(factor.explanation);
    }
    if (reasons.length >= 4) {
      break;
    }
  }

  if (reasons.length === 0) {
    if (state === "incomplete") {
      reasons.push("PHISHGUARD did not have enough usable evidence to produce a risk score.");
    } else if (state === "low") {
      reasons.push("No high-risk indicators were found in the evidence that was assessed.");
    } else {
      reasons.push("No individual risk factors were reported by the assessment.");
    }
  }

  return reasons;
}

export function buildAssessmentView(data: AssessmentData): AssessmentView {
  const state = stateForBand(data.band);
  const partial =
    data.incomplete ||
    data.confidence.incomplete ||
    data.status !== "complete" ||
    data.band === "insufficient_evidence";

  const covered = Math.round(data.confidence.coveredWeight);
  const total = Math.round(data.confidence.totalWeight);
  let coverageLabel = `Evidence coverage: ${covered}/${total} weighted points.`;
  if (data.confidence.incomplete || data.band === "insufficient_evidence") {
    coverageLabel += " Some configured checks did not run; missing evidence is not safe.";
  }
  if (data.status === "partial") {
    coverageLabel += " Scan status: partial.";
  }

  const likelihoodPercent = Math.round(data.likelihood.score * 100);
  const likelihoodLabel = `${bandLabel(data.likelihood.band)} (${likelihoodPercent}% heuristic likelihood)`;
  const postureStatus =
    data.posture.status === "ok" ? "" : `, ${data.posture.status} evidence`;
  const postureLabel = `Grade ${data.posture.grade} (${data.posture.score}/100 configuration score${postureStatus})`;

  const headline = headlineForState(state);
  return {
    state,
    headline,
    bandLabel: bandLabel(data.band),
    score: data.score,
    verdict: data.verdict === "" ? headline : data.verdict,
    reasons: buildReasons(data, state),
    missing: data.confidence.missingEvidence.slice(0, 5),
    coverageLabel,
    partial,
    likelihoodLabel,
    postureLabel,
    heuristicNotice: HEURISTIC_NOTICE,
  };
}
