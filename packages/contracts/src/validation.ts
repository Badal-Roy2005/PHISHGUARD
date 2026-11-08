import { ERROR_CODES, REPORT_CATEGORIES } from "./enums.ts";
import type { CreateReportRequest, ScanRequest } from "./types.ts";

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; errors: string[] };

const MAX_URL_LENGTH = 2048;
const MIN_URL_LENGTH = 8;

/**
 * Structural URL validation only. This performs NO DNS resolution and NO fetch.
 * Rejecting private addresses is the scanner's job (M4), not the API's: the API
 * must stay cheap and must never trigger egress.
 */
export function validateUrl(raw: unknown): ValidationResult<string> {
  if (typeof raw !== "string") {
    return { ok: false, errors: ["url must be a string"] };
  }
  if (raw.length < MIN_URL_LENGTH) {
    return { ok: false, errors: [`url must be at least ${MIN_URL_LENGTH} characters`] };
  }
  if (raw.length > MAX_URL_LENGTH) {
    return { ok: false, errors: [`url must be at most ${MAX_URL_LENGTH} characters`] };
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, errors: ["url is not a valid absolute URL"] };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, errors: ["url scheme must be http or https"] };
  }
  if (parsed.hostname.length === 0) {
    return { ok: false, errors: ["url must include a hostname"] };
  }
  if (parsed.username !== "" || parsed.password !== "") {
    return { ok: false, errors: ["url must not contain credentials"] };
  }
  if (parsed.hostname === "localhost" || parsed.hostname.endsWith(".localhost")) {
    return { ok: false, errors: ["url host is not permitted"] };
  }

  return { ok: true, value: parsed.toString() };
}

export function validateScanRequest(input: unknown): ValidationResult<ScanRequest> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, errors: ["request body must be an object"] };
  }

  const body = input as Record<string, unknown>;
  const errors: string[] = [];

  for (const key of Object.keys(body)) {
    if (key !== "url" && key !== "options") {
      errors.push(`unknown field: ${key}`);
    }
  }

  const urlResult = validateUrl(body["url"]);
  if (!urlResult.ok) {
    return urlResult;
  }

  const options: ScanRequest["options"] = {};
  if (body["options"] !== undefined) {
    const raw = body["options"];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return { ok: false, errors: ["options must be an object"] };
    }
    const opts = raw as Record<string, unknown>;
    if (opts["include_intel"] !== undefined) {
      if (typeof opts["include_intel"] !== "boolean") {
        errors.push("options.include_intel must be a boolean");
      } else {
        options.include_intel = opts["include_intel"];
      }
    }
    if (opts["include_ct"] !== undefined) {
      if (typeof opts["include_ct"] !== "boolean") {
        errors.push("options.include_ct must be a boolean");
      } else {
        options.include_ct = opts["include_ct"];
      }
    }
    if (opts["timeout_ms"] !== undefined) {
      const t = opts["timeout_ms"];
      if (typeof t !== "number" || !Number.isInteger(t) || t < 1000 || t > 15000) {
        errors.push("options.timeout_ms must be an integer between 1000 and 15000");
      } else {
        options.timeout_ms = t;
      }
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, value: { url: urlResult.value, options } };
}

export function validateCreateReportRequest(
  input: unknown,
): ValidationResult<CreateReportRequest> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, errors: ["request body must be an object"] };
  }
  const body = input as Record<string, unknown>;
  const errors: string[] = [];

  const urlResult = validateUrl(body["url"]);
  if (!urlResult.ok) {
    return urlResult;
  }

  const category = body["category"];
  if (
    typeof category !== "string" ||
    !(REPORT_CATEGORIES as readonly string[]).includes(category)
  ) {
    errors.push(`category must be one of: ${REPORT_CATEGORIES.join(", ")}`);
  }

  const description = body["description"];
  if (typeof description !== "string" || description.length < 10) {
    errors.push("description must be a string of at least 10 characters");
  } else if (description.length > 2000) {
    errors.push("description must be at most 2000 characters");
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    value: {
      url: urlResult.value,
      category: category as CreateReportRequest["category"],
      description: description as string,
      ...(body["evidence"] !== undefined
        ? { evidence: body["evidence"] as Record<string, unknown> }
        : {}),
    },
  };
}

export function isKnownErrorCode(value: unknown): boolean {
  return typeof value === "string" && (ERROR_CODES as readonly string[]).includes(value);
}
