/**
 * Bounded backend client for `POST /api/scan`.
 *
 * - The endpoint is derived from the single manifest host permission.
 * - Requests are anonymous: `credentials: "omit"`, no Authorization header, no
 *   cookies, and no referrer.
 * - Redirects are refused, the response body is size-limited, and the parse
 *   step validates the response before anything is rendered.
 * - There are no retries and no polling. A failure or timeout is reported as an
 *   unavailable assessment, never as a safe verdict.
 */

import { scanEndpoint } from "./api-origin.ts";
import {
  ERROR_CODES,
  failure,
  parseScanResponse,
  type AssessmentResult,
  type ErrorCode,
} from "./assessment.ts";
import { sanitizeUrl } from "./url.ts";

const DEFAULT_TIMEOUT_MS = 20_000;
export const SCAN_TIMEOUT_MS = 12_000;
export const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_REQUEST_TIMEOUT_MS = 60_000;

export interface RequestDeps {
  origin: string | null;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxBytes?: number;
  isOffline?: () => boolean;
}

class TimeoutError extends Error {
  constructor() {
    super("timeout");
    this.name = "TimeoutError";
  }
}

class BodyTooLargeError extends Error {
  constructor() {
    super("body_too_large");
    this.name = "BodyTooLargeError";
  }
}

function failureResult(
  kind: Parameters<typeof failure>[0],
  message: string,
  retryable: boolean,
  status?: number,
  code?: ErrorCode,
): AssessmentResult {
  return { ok: false, error: failure(kind, message, retryable, status, code) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === "string" && (ERROR_CODES as readonly string[]).includes(value);
}

function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  if (text.trim() === "") {
    return { ok: false };
  }
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function extractErrorCode(text: string): ErrorCode | null {
  const parsed = parseJson(text);
  if (!parsed.ok || !isRecord(parsed.value)) {
    return null;
  }
  const error = parsed.value.error;
  if (!isRecord(error) || !isErrorCode(error.code)) {
    return null;
  }
  return error.code;
}

function defaultIsOffline(): boolean {
  return typeof navigator !== "undefined" && navigator.onLine === false;
}

function boundedTimeout(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) {
    return DEFAULT_TIMEOUT_MS;
  }
  return Math.min(MAX_REQUEST_TIMEOUT_MS, Math.max(10, Math.round(value)));
}

async function readBounded(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";

  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      received += chunk.value.byteLength;
      if (received > maxBytes) {
        throw new BodyTooLargeError();
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    try {
      await reader.cancel();
    } catch {
      // The stream may already be closed or errored.
    }
    reader.releaseLock();
  }
}

export async function requestAssessment(
  rawUrl: string,
  deps: RequestDeps,
): Promise<AssessmentResult> {
  const sanitized = sanitizeUrl(rawUrl);
  if (!sanitized.ok) {
    return failureResult("unsupported_url", sanitized.message, false);
  }

  if (deps.origin === null) {
    return failureResult(
      "config_error",
      "The PHISHGUARD backend origin is not configured in this build.",
      false,
    );
  }
  const endpoint = scanEndpoint(deps.origin);
  if (endpoint === null) {
    return failureResult(
      "config_error",
      "The configured PHISHGUARD backend origin is invalid.",
      false,
    );
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const isOffline = deps.isOffline ?? defaultIsOffline;
  const timeoutMs = boundedTimeout(deps.timeoutMs);
  const maxBytes =
    deps.maxBytes !== undefined && Number.isFinite(deps.maxBytes) && deps.maxBytes > 0
      ? Math.floor(deps.maxBytes)
      : MAX_RESPONSE_BYTES;

  const controller = new AbortController();
  let timedOut = false;
  let rejectDeadline: ((reason: unknown) => void) | null = null;
  const deadline = new Promise<never>((_resolve, reject) => {
    rejectDeadline = reject;
  });

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
    rejectDeadline?.(new TimeoutError());
  }, timeoutMs);

  try {
    const init: RequestInit = {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: sanitized.url,
        options: {
          include_intel: true,
          include_ct: false,
          timeout_ms: SCAN_TIMEOUT_MS,
        },
      }),
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    };

    let response: Response;
    const fetchPromise = fetchImpl(endpoint, init);
    // Avoid an unhandled rejection if the deadline wins the race first.
    fetchPromise.catch(() => undefined);
    try {
      response = await Promise.race([fetchPromise, deadline]);
    } catch (error) {
      if (error instanceof TimeoutError || timedOut || controller.signal.aborted) {
        return failureResult(
          "timeout",
          "PHISHGUARD took too long to respond. The page was not assessed.",
          true,
        );
      }
      if (isOffline()) {
        return failureResult(
          "offline",
          "You appear to be offline. The page was not assessed.",
          true,
        );
      }
      return failureResult(
        "backend_error",
        "Could not reach PHISHGUARD. The page was not assessed.",
        true,
      );
    }

    let text: string;
    try {
      text = await Promise.race([readBounded(response, maxBytes), deadline]);
    } catch (error) {
      if (error instanceof TimeoutError || timedOut || controller.signal.aborted) {
        return failureResult(
          "timeout",
          "PHISHGUARD took too long to respond. The page was not assessed.",
          true,
        );
      }
      if (error instanceof BodyTooLargeError) {
        return failureResult(
          "malformed",
          "PHISHGUARD returned an unexpectedly large response. The page was not assessed.",
          false,
        );
      }
      return failureResult(
        "backend_error",
        "The response from PHISHGUARD could not be read. The page was not assessed.",
        true,
      );
    }

    if (response.status === 200) {
      const parsed = parseJson(text);
      if (!parsed.ok) {
        return failureResult(
          "malformed",
          "PHISHGUARD returned a response that was not valid JSON. The page was not assessed.",
          false,
        );
      }
      return parseScanResponse(parsed.value);
    }

    const code = extractErrorCode(text) ?? undefined;

    if (response.status === 429) {
      return failureResult(
        "rate_limited",
        "PHISHGUARD is rate limiting requests. Wait before trying again; the page was not assessed.",
        true,
        response.status,
        code,
      );
    }

    if (response.status === 400 || response.status === 413) {
      if (code === "blocked_target") {
        return failureResult(
          "blocked_target",
          "PHISHGUARD blocked this target, so it was not assessed.",
          false,
          response.status,
          code,
        );
      }
      return failureResult(
        "rejected",
        "PHISHGUARD rejected this request, so the page was not assessed.",
        false,
        response.status,
        code,
      );
    }

    if (response.status === 401 || response.status === 403) {
      return failureResult(
        "rejected",
        "PHISHGUARD refused the request. The page was not assessed.",
        false,
        response.status,
        code,
      );
    }

    if (response.status === 503) {
      return failureResult(
        "backend_error",
        "The PHISHGUARD analysis service is temporarily unavailable. The page was not assessed.",
        true,
        response.status,
        code,
      );
    }

    return failureResult(
      "backend_error",
      "PHISHGUARD returned an unexpected error. The page was not assessed.",
      true,
      response.status,
      code,
    );
  } finally {
    clearTimeout(timer);
  }
}
