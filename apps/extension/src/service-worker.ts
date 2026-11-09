/**
 * MV3 background service worker.
 *
 * It does no polling, no tab monitoring, and no page inspection. The popup asks
 * for one assessment after a user action. The approved backend origin comes
 * from the manifest's single host permission, and responses are cached in
 * memory by a hash of the normalized URL.
 */

import { resolveApiOrigin } from "./lib/api-origin.ts";
import {
  failure,
  type AssessmentData,
  type AssessmentResult,
} from "./lib/assessment.ts";
import { requestAssessment } from "./lib/backend.ts";
import { SingleFlight, TtlCache } from "./lib/cache.ts";
import {
  isTrustedSender,
  parseExtensionMessage,
  type AssessMessage,
  type AssessResponse,
  type ClearCacheResponse,
  type ExtensionMessage,
} from "./lib/messages.ts";
import { hashUrl, sanitizeUrl } from "./lib/url.ts";

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX_ENTRIES = 32;

const cache = new TtlCache<AssessmentData>(CACHE_TTL_MS, CACHE_MAX_ENTRIES);
const inFlight = new SingleFlight<string, AssessmentResult>();
const apiOrigin = resolveApiOrigin(chrome.runtime.getManifest().host_permissions);

function configError(message: string): AssessResponse {
  return { ok: false, error: failure("config_error", message, false) };
}

async function assess(message: AssessMessage): Promise<AssessResponse> {
  const sanitized = sanitizeUrl(message.url);
  if (!sanitized.ok) {
    return {
      ok: false,
      error: failure("unsupported_url", sanitized.message, false),
    };
  }

  let key: string;
  try {
    key = await hashUrl(sanitized.url);
  } catch {
    return configError("The extension could not prepare a cache key for this page.");
  }

  if (!message.force) {
    const cached = cache.get(key);
    if (cached !== undefined) {
      return { ok: true, cached: true, data: cached };
    }
  }

  if (apiOrigin === null) {
    return configError("The PHISHGUARD backend origin is not configured in this build.");
  }

  const epoch = cache.epoch;
  const result = await inFlight.run(key, () =>
    requestAssessment(sanitized.url, { origin: apiOrigin }),
  );

  if (result.ok) {
    cache.set(key, result.data, epoch);
    return { ok: true, cached: false, data: result.data };
  }
  return { ok: false, error: result.error };
}

async function handleMessage(
  message: ExtensionMessage,
): Promise<AssessResponse | ClearCacheResponse> {
  if (message.type === "clear-cache") {
    cache.clear();
    return { ok: true };
  }
  return assess(message);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isTrustedSender(sender, chrome.runtime.id)) {
    return false;
  }

  const parsed = parseExtensionMessage(message);
  if (parsed === null) {
    sendResponse({
      ok: false,
      error: failure("malformed", "The extension received an invalid request.", false),
    });
    return false;
  }

  void handleMessage(parsed)
    .then(sendResponse)
    .catch(() => {
      sendResponse({
        ok: false,
        error: failure(
          "backend_error",
          "An unexpected extension error occurred. The page was not assessed.",
          true,
        ),
      });
    });
  return true;
});
