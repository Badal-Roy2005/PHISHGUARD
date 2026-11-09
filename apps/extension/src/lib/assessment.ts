/**
 * Runtime validation of the PHISHGUARD scan response.
 *
 * The extension does not import the contracts package at runtime (there is no
 * bundler and the extension must be self-contained). Instead this module keeps
 * a small duplicate of the contract enums and validates every field it renders.
 * `tests/contract-parity.test.ts` fails if these drift from
 * `@phishguard/contracts`.
 *
 * Backend responses are untrusted input: unknown fields are ignored, required
 * fields are checked, and text is length/control-character normalized before it
 * reaches the DOM. The extension never renders backend HTML.
 */

export const SUPPORTED_CONTRACT_VERSION = "2026-11-09.2";

export const SCAN_STATUSES = ["queued", "running", "complete", "partial", "failed"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const RISK_BANDS = [
  "low",
  "guarded",
  "suspicious",
  "high",
  "critical",
  "insufficient_evidence",
] as const;
export type RiskBand = (typeof RISK_BANDS)[number];

export const ENGINE_STATUSES = ["ok", "partial", "skipped", "unknown", "error"] as const;
export type EngineStatus = (typeof ENGINE_STATUSES)[number];

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const RISK_FACTOR_CATEGORIES = [
  "intel",
  "url",
  "brand",
  "redirect",
  "tls",
  "http",
  "ml",
] as const;
export type RiskFactorCategory = (typeof RISK_FACTOR_CATEGORIES)[number];

export const RISK_FACTOR_STATUSES = [
  "applied",
  "evaluated",
  "no_match",
  "unavailable",
  "error",
] as const;
export type RiskFactorStatus = (typeof RISK_FACTOR_STATUSES)[number];

export const RISK_DIRECTIONS = [
  "increases_risk",
  "decreases_risk",
  "informational",
] as const;
export type RiskDirection = (typeof RISK_DIRECTIONS)[number];

export const ERROR_CODES = [
  "invalid_request",
  "invalid_url",
  "blocked_target",
  "rate_limited",
  "not_found",
  "unauthorized",
  "payload_too_large",
  "upstream_unavailable",
  "timeout",
  "internal",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export const ASSESSMENT_FAILURE_KINDS = [
  "timeout",
  "offline",
  "rate_limited",
  "backend_error",
  "malformed",
  "unsupported_url",
  "config_error",
  "rejected",
  "blocked_target",
  "not_ready",
  "failed",
  "no_risk",
] as const;
export type AssessmentFailureKind = (typeof ASSESSMENT_FAILURE_KINDS)[number];

export interface ConfidenceView {
  score: number;
  incomplete: boolean;
  coveredWeight: number;
  totalWeight: number;
  missingEvidence: string[];
}

export interface FactorView {
  reasonCode: string;
  category: RiskFactorCategory;
  severity: Severity;
  contribution: number;
  direction: RiskDirection;
  status: RiskFactorStatus;
  explanation: string;
}

export interface AssessmentData {
  status: ScanStatus;
  scanId: string;
  band: RiskBand;
  score: number | null;
  verdict: string;
  incomplete: boolean;
  confidence: ConfidenceView;
  likelihood: { score: number; band: RiskBand };
  posture: { score: number; grade: string; status: EngineStatus };
  factors: FactorView[];
}

export interface AssessmentFailure {
  kind: AssessmentFailureKind;
  message: string;
  retryable: boolean;
  status?: number;
  code?: ErrorCode;
}

export type AssessmentResult =
  | { ok: true; data: AssessmentData }
  | { ok: false; error: AssessmentFailure };

const POSTURE_GRADES = ["A", "B", "C", "D", "F", "unknown"] as const;
const MAX_FACTORS = 50;
const MAX_MISSING_EVIDENCE = 20;
const MAX_VERDICT_LENGTH = 280;
const MAX_REASON_LENGTH = 240;
const MAX_MISSING_ITEM_LENGTH = 120;
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOneOf<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}

function isNumberInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;
}

function cleanText(value: string, maxLength: number): string | null {
  const text = value
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (text === "") {
    return null;
  }
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

export function failure(
  kind: AssessmentFailureKind,
  message: string,
  retryable: boolean,
  status?: number,
  code?: ErrorCode,
): AssessmentFailure {
  const error: AssessmentFailure = { kind, message, retryable };
  if (status !== undefined) {
    error.status = status;
  }
  if (code !== undefined) {
    error.code = code;
  }
  return error;
}

function malformed(message: string): AssessmentResult {
  return { ok: false, error: failure("malformed", message, false) };
}

function parseConfidence(value: unknown): ConfidenceView | null {
  if (!isRecord(value)) {
    return null;
  }
  const score = value.score;
  const coveredWeight = value.covered_weight;
  const totalWeight = value.total_weight;
  const incomplete = value.incomplete;
  if (
    !isNumberInRange(score, 0, 1) ||
    !isNumberInRange(coveredWeight, 0, 100) ||
    !isNumberInRange(totalWeight, 0, 100) ||
    typeof incomplete !== "boolean"
  ) {
    return null;
  }
  if (coveredWeight > totalWeight + 0.001) {
    return null;
  }

  const missingEvidence: string[] = [];
  if (value.missing_evidence !== undefined) {
    if (!Array.isArray(value.missing_evidence)) {
      return null;
    }
    for (const item of value.missing_evidence) {
      if (typeof item !== "string") {
        continue;
      }
      const cleaned = cleanText(item, MAX_MISSING_ITEM_LENGTH);
      if (cleaned !== null) {
        missingEvidence.push(cleaned);
      }
      if (missingEvidence.length >= MAX_MISSING_EVIDENCE) {
        break;
      }
    }
  }

  return { score, incomplete, coveredWeight, totalWeight, missingEvidence };
}

function parseLikelihood(value: unknown): { score: number; band: RiskBand } | null {
  if (!isRecord(value)) {
    return null;
  }
  const score = value.score;
  const band = value.band;
  if (!isNumberInRange(score, 0, 1) || !isOneOf(RISK_BANDS, band)) {
    return null;
  }
  if (band === "insufficient_evidence") {
    return null;
  }
  return { score, band };
}

function parsePosture(
  value: unknown,
): { score: number; grade: string; status: EngineStatus } | null {
  if (!isRecord(value)) {
    return null;
  }
  const score = value.score;
  const grade = value.grade;
  const status = value.status;
  if (
    !isNumberInRange(score, 0, 100) ||
    !isOneOf(POSTURE_GRADES, grade) ||
    !isOneOf(ENGINE_STATUSES, status)
  ) {
    return null;
  }
  return { score, grade, status };
}

function parseFactor(value: unknown): FactorView | null {
  if (!isRecord(value)) {
    return null;
  }
  const reasonCode = value.reason_code;
  const category = value.category;
  const severity = value.severity;
  const contribution = value.contribution;
  const direction = value.direction;
  const status = value.status;
  const rawExplanation = value.explanation;
  if (
    typeof reasonCode !== "string" ||
    reasonCode.length === 0 ||
    reasonCode.length > 100 ||
    !isOneOf(RISK_FACTOR_CATEGORIES, category) ||
    !isOneOf(SEVERITIES, severity) ||
    !isNumberInRange(contribution, 0, 100) ||
    !isOneOf(RISK_DIRECTIONS, direction) ||
    !isOneOf(RISK_FACTOR_STATUSES, status) ||
    typeof rawExplanation !== "string"
  ) {
    return null;
  }
  const explanation = cleanText(rawExplanation, MAX_REASON_LENGTH);
  if (explanation === null) {
    return null;
  }
  return {
    reasonCode,
    category,
    severity,
    contribution,
    direction,
    status,
    explanation,
  };
}

function parseFactors(value: unknown): FactorView[] | null {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    return null;
  }
  const factors: FactorView[] = [];
  for (const item of value) {
    const factor = parseFactor(item);
    if (factor !== null) {
      factors.push(factor);
    }
    if (factors.length >= MAX_FACTORS) {
      break;
    }
  }
  return factors;
}

function parseRisk(value: unknown, status: ScanStatus, scanId: string): AssessmentResult {
  if (!isRecord(value)) {
    return malformed("The assessment did not include a risk object.");
  }

  const rawScore = value.score;
  let score: number | null;
  if (rawScore === null) {
    score = null;
  } else if (isNumberInRange(rawScore, 0, 100)) {
    score = rawScore;
  } else {
    return malformed("The risk score was not a number between 0 and 100.");
  }

  const band = value.band;
  if (!isOneOf(RISK_BANDS, band)) {
    return malformed("The risk band was not recognized.");
  }
  if (score === null && band !== "insufficient_evidence") {
    return malformed("A missing risk score must use the insufficient_evidence band.");
  }
  if (score !== null && band === "insufficient_evidence") {
    return malformed("The insufficient_evidence band must not include a risk score.");
  }

  if (typeof value.verdict !== "string") {
    return malformed("The assessment did not include a verdict.");
  }
  const verdict = cleanText(value.verdict, MAX_VERDICT_LENGTH) ?? "";
  const rawIncomplete = value.incomplete;
  if (typeof rawIncomplete !== "boolean") {
    return malformed("The assessment did not include its coverage state.");
  }

  const confidence = parseConfidence(value.confidence);
  if (confidence === null) {
    return malformed("The assessment coverage was malformed.");
  }
  const likelihood = parseLikelihood(value.likelihood);
  if (likelihood === null) {
    return malformed("The assessment likelihood was malformed.");
  }
  const posture = parsePosture(value.posture);
  if (posture === null) {
    return malformed("The assessment posture was malformed.");
  }
  const factors = parseFactors(value.factors);
  if (factors === null) {
    return malformed("The assessment factors were malformed.");
  }

  return {
    ok: true,
    data: {
      status,
      scanId,
      band,
      score,
      verdict,
      incomplete: rawIncomplete || confidence.incomplete || band === "insufficient_evidence",
      confidence,
      likelihood,
      posture,
      factors,
    },
  };
}

export function parseScanResponse(value: unknown): AssessmentResult {
  if (!isRecord(value)) {
    return malformed("The backend response was not a JSON object.");
  }
  const status = value.status;
  if (!isOneOf(SCAN_STATUSES, status)) {
    return malformed("The backend response had an unrecognized scan status.");
  }
  if (status === "queued" || status === "running") {
    return {
      ok: false,
      error: failure(
        "not_ready",
        "PHISHGUARD did not finish the assessment in time. The page was not assessed.",
        true,
      ),
    };
  }
  if (status === "failed") {
    return {
      ok: false,
      error: failure(
        "failed",
        "PHISHGUARD could not complete the assessment. The page was not assessed.",
        false,
      ),
    };
  }
  const scanId = value.scan_id;
  if (typeof scanId !== "string" || scanId.length === 0) {
    return malformed("The backend response had no scan identifier.");
  }
  if (scanId.length > 128) {
    return malformed("The backend response scan identifier was too long.");
  }
  if (value.risk === null || value.risk === undefined) {
    return {
      ok: false,
      error: failure(
        "no_risk",
        "PHISHGUARD returned no risk assessment for this page. It was not assessed.",
        false,
      ),
    };
  }
  return parseRisk(value.risk, status, scanId);
}

export function isAssessmentData(value: unknown): value is AssessmentData {
  if (!isRecord(value)) {
    return false;
  }
  if (
    !isOneOf(SCAN_STATUSES, value.status) ||
    typeof value.scanId !== "string" ||
    !isOneOf(RISK_BANDS, value.band) ||
    (value.score !== null && !isNumberInRange(value.score, 0, 100)) ||
    typeof value.verdict !== "string" ||
    typeof value.incomplete !== "boolean" ||
    !Array.isArray(value.factors)
  ) {
    return false;
  }

  const confidence = value.confidence;
  if (
    !isRecord(confidence) ||
    !isNumberInRange(confidence.score, 0, 1) ||
    !isNumberInRange(confidence.coveredWeight, 0, 100) ||
    !isNumberInRange(confidence.totalWeight, 0, 100) ||
    typeof confidence.incomplete !== "boolean" ||
    !Array.isArray(confidence.missingEvidence)
  ) {
    return false;
  }

  const likelihood = value.likelihood;
  if (
    !isRecord(likelihood) ||
    !isNumberInRange(likelihood.score, 0, 1) ||
    !isOneOf(RISK_BANDS, likelihood.band) ||
    likelihood.band === "insufficient_evidence"
  ) {
    return false;
  }

  const posture = value.posture;
  if (
    !isRecord(posture) ||
    !isNumberInRange(posture.score, 0, 100) ||
    !isOneOf(POSTURE_GRADES, posture.grade) ||
    !isOneOf(ENGINE_STATUSES, posture.status)
  ) {
    return false;
  }

  return true;
}

export function isAssessmentFailure(value: unknown): value is AssessmentFailure {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isOneOf(ASSESSMENT_FAILURE_KINDS, value.kind) &&
    typeof value.message === "string" &&
    value.message.length > 0 &&
    value.message.length <= 500 &&
    typeof value.retryable === "boolean" &&
    (value.status === undefined || typeof value.status === "number") &&
    (value.code === undefined || isOneOf(ERROR_CODES, value.code))
  );
}
