import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CONTRACT_VERSION,
  FEATURE_SCHEMA_VERSION,
  LABEL_MAP,
  SCAN_STATUSES,
  validateCreateReportRequest,
  validateScanRequest,
  validateUrl,
} from "../src/index.ts";

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8"));

test("accepts the canonical scan request fixture", () => {
  const result = validateScanRequest(fixture("scan-request.json"));
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.value.url, "https://secure-update-login.example.com/verify");
    assert.equal(result.value.options?.timeout_ms, 8000);
  }
});

test("normalizes the URL through the WHATWG parser", () => {
  const result = validateUrl("HTTPS://Example.COM/a b");
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.value, "https://example.com/a%20b");
  }
});

test("rejects non-http(s) schemes", () => {
  for (const url of [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "ftp://example.com/x",
    "data:text/html,<script>",
  ]) {
    const result = validateScanRequest({ url });
    assert.equal(result.ok, false, `should reject ${url}`);
  }
});

test("rejects credentials in the URL", () => {
  const result = validateScanRequest({ url: "https://user:pass@example.com/" });
  assert.equal(result.ok, false);
});

test("rejects localhost before any DNS work happens", () => {
  assert.equal(validateScanRequest({ url: "http://localhost:3000/x" }).ok, false);
  assert.equal(validateScanRequest({ url: "http://app.localhost/x" }).ok, false);
});

test("rejects oversized and malformed URLs", () => {
  assert.equal(validateScanRequest({ url: "https://a.co/" + "x".repeat(3000) }).ok, false);
  assert.equal(validateScanRequest({ url: "not a url" }).ok, false);
  assert.equal(validateScanRequest({ url: 42 }).ok, false);
});

test("rejects unknown fields and bad options", () => {
  assert.equal(
    validateScanRequest({ url: "https://example.com", extra: true }).ok,
    false,
  );
  assert.equal(
    validateScanRequest({ url: "https://example.com", options: { timeout_ms: 999999 } }).ok,
    false,
  );
  assert.equal(
    validateScanRequest({ url: "https://example.com", options: { include_ct: "yes" } }).ok,
    false,
  );
});

test("validates community report requests", () => {
  assert.equal(validateCreateReportRequest(fixture("report-create-request.json")).ok, true);
  assert.equal(
    validateCreateReportRequest({
      url: "https://example.com",
      category: "phishing",
      description: "short",
    }).ok,
    false,
  );
  assert.equal(
    validateCreateReportRequest({
      url: "https://example.com",
      category: "not-a-category",
      description: "long enough description",
    }).ok,
    false,
  );
});

test("contract versions and label map are pinned", () => {
  assert.equal(CONTRACT_VERSION, "2026-11-09.2");
  assert.equal(FEATURE_SCHEMA_VERSION, "2");
  assert.deepEqual(LABEL_MAP, { "0": "phishing", "1": "legitimate" });
  assert.deepEqual(SCAN_STATUSES, [
    "queued",
    "running",
    "complete",
    "partial",
    "failed",
  ]);
});
