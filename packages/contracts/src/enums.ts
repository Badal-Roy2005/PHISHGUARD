/**
 * Contract enums. Declared as const objects + union types so Node's native
 * TypeScript type-stripping can run these files without a build step.
 */

export const SCAN_STATUSES = ["queued", "running", "complete", "partial", "failed"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const ENGINE_STATUSES = ["ok", "partial", "skipped", "unknown", "error"] as const;
export type EngineStatus = (typeof ENGINE_STATUSES)[number];

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const RISK_BANDS = [
  "low",
  "guarded",
  "suspicious",
  "high",
  "critical",
  "insufficient_evidence",
] as const;
export type RiskBand = (typeof RISK_BANDS)[number];

export const ENGINE_NAMES = ["ml", "url", "tls", "http", "intel", "community"] as const;
export type EngineName = (typeof ENGINE_NAMES)[number];

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

export const REPORT_CATEGORIES = [
  "phishing",
  "malware",
  "scam",
  "credential_theft",
  "impersonation",
  "other",
] as const;
export type ReportCategory = (typeof REPORT_CATEGORIES)[number];

export const REPORT_STATUSES = ["pending", "verified", "rejected"] as const;
export type ReportStatus = (typeof REPORT_STATUSES)[number];

/**
 * A status that means "no usable verdict". These values must never be rendered
 * or scored as safe.
 */
export const NON_SAFE_STATUSES: readonly EngineStatus[] = [
  "unknown",
  "error",
  "skipped",
  "partial",
];

export function isUsableVerdict(status: EngineStatus): boolean {
  return status === "ok";
}
