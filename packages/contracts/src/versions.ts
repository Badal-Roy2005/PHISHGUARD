/**
 * Version constants shared by every service.
 * Bump CONTRACT_VERSION on any breaking wire change and update docs/api-contracts.md.
 */
export const SERVICE_VERSION = "0.1.0";
export const CONTRACT_VERSION = "2026-11-09.1";
export const SCHEMA_VERSION = 1;
export const FEATURE_SCHEMA_VERSION = "2";

/** PhiUSIIL label mapping. 0 = phishing, 1 = legitimate. Never invert. */
export const LABEL_MAP = { "0": "phishing", "1": "legitimate" } as const;
