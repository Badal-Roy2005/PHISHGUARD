import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { parseScanResponse, type AssessmentData } from "../src/lib/assessment.ts";
import {
  isTrustedSender,
  parseAssessResponse,
  parseClearCacheResponse,
  parseExtensionMessage,
} from "../src/lib/messages.ts";

const FIXTURES = new URL("../../../packages/contracts/fixtures/", import.meta.url);
const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";

function completeAssessment(): AssessmentData {
  const parsed: unknown = JSON.parse(
    readFileSync(new URL("scan-result.complete.json", FIXTURES), "utf8"),
  );
  const result = parseScanResponse(parsed);
  if (!result.ok) {
    assert.fail(result.error.message);
  }
  return result.data;
}

test("parses valid popup messages", () => {
  assert.deepEqual(parseExtensionMessage({ type: "assess", url: "https://example.com/" }), {
    type: "assess",
    url: "https://example.com/",
    force: false,
  });
  assert.deepEqual(
    parseExtensionMessage({ type: "assess", url: "https://example.com/", force: true }),
    { type: "assess", url: "https://example.com/", force: true },
  );
  assert.deepEqual(parseExtensionMessage({ type: "clear-cache" }), { type: "clear-cache" });
});

test("rejects malformed popup messages", () => {
  const invalid: unknown[] = [
    null,
    [],
    "assess",
    {},
    { type: "unknown" },
    { type: "assess" },
    { type: "assess", url: 42 },
    { type: "assess", url: "short" },
    { type: "assess", url: `https://example.com/${"a".repeat(9000)}` },
    { type: "assess", url: "https://example.com/", force: "yes" },
    { type: "clear-cache", extra: true },
  ];

  for (const value of invalid) {
    assert.equal(parseExtensionMessage(value), null, JSON.stringify(value));
  }
});

test("accepts only this extension's own pages as message senders", () => {
  const origin = `chrome-extension://${EXTENSION_ID}`;

  assert.equal(isTrustedSender({ id: EXTENSION_ID, origin }, EXTENSION_ID), true);
  assert.equal(
    isTrustedSender({ id: EXTENSION_ID, url: `${origin}/popup.html` }, EXTENSION_ID),
    true,
  );
  assert.equal(isTrustedSender({ id: EXTENSION_ID }, EXTENSION_ID), false);
  assert.equal(
    isTrustedSender({ id: "other", url: `${origin}/popup.html` }, EXTENSION_ID),
    false,
  );
  assert.equal(
    isTrustedSender({ id: EXTENSION_ID, url: "https://example.com/" }, EXTENSION_ID),
    false,
  );
  assert.equal(
    isTrustedSender({ id: EXTENSION_ID, origin: "https://example.com" }, EXTENSION_ID),
    false,
  );
  assert.equal(isTrustedSender(undefined, EXTENSION_ID), false);
  assert.equal(isTrustedSender({ id: "", origin: "chrome-extension://" }, ""), false);
});

test("parses worker assessment responses", () => {
  const data = completeAssessment();

  assert.deepEqual(parseAssessResponse({ ok: true, cached: false, data }), {
    ok: true,
    cached: false,
    data,
  });
  assert.deepEqual(
    parseAssessResponse({
      ok: false,
      error: { kind: "timeout", message: "timed out", retryable: true },
    }),
    { ok: false, error: { kind: "timeout", message: "timed out", retryable: true } },
  );

  assert.equal(parseAssessResponse(null), null);
  assert.equal(parseAssessResponse({ ok: true, cached: "no", data }), null);
  assert.equal(parseAssessResponse({ ok: true, cached: false, data: { band: "high" } }), null);
  assert.equal(
    parseAssessResponse({ ok: false, error: { kind: "nope", message: "x", retryable: true } }),
    null,
  );
  assert.equal(parseAssessResponse({ ok: "yes" }), null);
});

test("parses worker cache responses", () => {
  assert.deepEqual(parseClearCacheResponse({ ok: true }), { ok: true });
  assert.deepEqual(
    parseClearCacheResponse({
      ok: false,
      error: { kind: "malformed", message: "invalid request", retryable: false },
    }),
    { ok: false, error: { kind: "malformed", message: "invalid request", retryable: false } },
  );
  assert.equal(parseClearCacheResponse(null), null);
  assert.equal(parseClearCacheResponse({ ok: false, error: null }), null);
});
