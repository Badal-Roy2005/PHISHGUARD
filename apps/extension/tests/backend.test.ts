import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { requestAssessment, type RequestDeps } from "../src/lib/backend.ts";

const FIXTURES = new URL("../../../packages/contracts/fixtures/", import.meta.url);
const COMPLETE_BODY = readFileSync(new URL("scan-result.complete.json", FIXTURES), "utf8");
const ORIGIN = "https://phishguard.example.test";

interface Call {
  url: string;
  init: RequestInit;
}

function mockFetch(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): { deps: RequestDeps; calls: Call[] } {
  const calls: Call[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const requestInit = init ?? {};
    calls.push({ url, init: requestInit });
    return handler(url, requestInit);
  }) as typeof fetch;
  return { deps: { origin: ORIGIN, fetchImpl: impl }, calls };
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function errorBody(code: string): string {
  return JSON.stringify({ error: { code, message: "test error" } });
}

test("sends one anonymous, non-redirecting POST to the approved endpoint", async () => {
  const { deps, calls } = mockFetch(() => jsonResponse(COMPLETE_BODY));
  const result = await requestAssessment(
    "https://example.com/page?token=secret&keep=1#fragment",
    deps,
  );

  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.ok(call);
  assert.equal(call.url, `${ORIGIN}/api/scan`);
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.cache, "no-store");
  assert.equal(call.init.credentials, "omit");
  assert.equal(call.init.redirect, "error");
  assert.equal(call.init.referrerPolicy, "no-referrer");
  assert.ok(call.init.signal instanceof AbortSignal);

  const headers = call.init.headers as Record<string, string>;
  assert.deepEqual(Object.keys(headers).sort(), ["Accept", "Content-Type"]);
  assert.equal(headers.Authorization, undefined);
  assert.equal(headers.Cookie, undefined);

  const body = JSON.parse(String(call.init.body)) as {
    url: string;
    options: Record<string, unknown>;
  };
  assert.equal(body.url, "https://example.com/page?keep=1");
  assert.equal(body.options.include_intel, true);
  assert.equal(body.options.include_ct, false);
  assert.equal(body.options.timeout_ms, 12_000);
});

test("maps a successful response through the strict parser", async () => {
  const { deps } = mockFetch(() => jsonResponse(COMPLETE_BODY));
  const result = await requestAssessment("https://example.com/", deps);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.band, "high");
    assert.equal(result.data.score, 83);
  }
});

test("maps 429 to a retryable rate_limited failure", async () => {
  const { deps } = mockFetch(() => jsonResponse(errorBody("rate_limited"), 429));
  const result = await requestAssessment("https://example.com/", deps);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.kind, "rate_limited");
    assert.equal(result.error.retryable, true);
    assert.equal(result.error.status, 429);
    assert.equal(result.error.code, "rate_limited");
  }
});

test("maps 503 and 500 to backend_error without retrying", async () => {
  for (const status of [503, 500]) {
    const { deps, calls } = mockFetch(() => jsonResponse(errorBody("upstream_unavailable"), status));
    const result = await requestAssessment("https://example.com/", deps);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.error.kind, "backend_error");
      assert.equal(result.error.retryable, true);
      assert.equal(result.error.status, status);
    }
    assert.equal(calls.length, 1, "must not retry or poll");
  }
});

test("maps blocked_target and rejection statuses without claiming an assessment", async () => {
  const blocked = mockFetch(() => jsonResponse(errorBody("blocked_target"), 400));
  const blockedResult = await requestAssessment("https://example.com/", blocked.deps);
  assert.equal(blockedResult.ok, false);
  if (!blockedResult.ok) {
    assert.equal(blockedResult.error.kind, "blocked_target");
    assert.equal(blockedResult.error.retryable, false);
    assert.equal(blockedResult.error.code, "blocked_target");
  }

  const cases: Array<[number, string]> = [
    [400, "invalid_request"],
    [413, "payload_too_large"],
    [401, "unauthorized"],
    [403, "unauthorized"],
  ];
  for (const [status, code] of cases) {
    const mock = mockFetch(() => jsonResponse(errorBody(code), status));
    const result = await requestAssessment("https://example.com/", mock.deps);
    assert.equal(result.ok, false, `${status}`);
    if (!result.ok) {
      assert.equal(result.error.kind, "rejected", `${status}`);
      assert.equal(result.error.retryable, false, `${status}`);
    }
  }
});

test("distinguishes offline from an unreachable backend", async () => {
  const offline = mockFetch(() => {
    throw new TypeError("Failed to fetch");
  });
  const offlineResult = await requestAssessment("https://example.com/", {
    ...offline.deps,
    isOffline: () => true,
  });
  assert.equal(offlineResult.ok, false);
  if (!offlineResult.ok) {
    assert.equal(offlineResult.error.kind, "offline");
    assert.equal(offlineResult.error.retryable, true);
  }

  const online = mockFetch(() => {
    throw new TypeError("Failed to fetch");
  });
  const onlineResult = await requestAssessment("https://example.com/", {
    ...online.deps,
    isOffline: () => false,
  });
  assert.equal(onlineResult.ok, false);
  if (!onlineResult.ok) {
    assert.equal(onlineResult.error.kind, "backend_error");
  }
});

test("bounds requests with a timeout", async () => {
  const calls: Call[] = [];
  const deps: RequestDeps = {
    origin: ORIGIN,
    timeoutMs: 25,
    fetchImpl: (async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(_input), init: init ?? {} });
      return new Promise<Response>(() => undefined);
    }) as typeof fetch,
  };

  const result = await requestAssessment("https://example.com/", deps);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.kind, "timeout");
    assert.equal(result.error.retryable, true);
  }
  assert.equal(calls.length, 1);
});

test("rejects oversized, empty, non-JSON, and non-object bodies", async () => {
  const oversized = mockFetch(() => new Response("x".repeat(200)));
  const oversizedResult = await requestAssessment("https://example.com/", {
    ...oversized.deps,
    maxBytes: 16,
  });
  assert.equal(oversizedResult.ok, false);
  if (!oversizedResult.ok) {
    assert.equal(oversizedResult.error.kind, "malformed");
  }

  for (const body of ["", "not json", "null", "[]", '"ok"']) {
    const mock = mockFetch(() => jsonResponse(body));
    const result = await requestAssessment("https://example.com/", mock.deps);
    assert.equal(result.ok, false, JSON.stringify(body));
    if (!result.ok) {
      assert.equal(result.error.kind, "malformed");
    }
  }
});

test("rejects local targets before any network call", async () => {
  for (const url of [
    "http://127.0.0.1/admin",
    "http://localhost:3000/",
    "ftp://example.com/file",
    "https://example.com:8443/",
  ]) {
    const { deps, calls } = mockFetch(() => jsonResponse(COMPLETE_BODY));
    const result = await requestAssessment(url, deps);
    assert.equal(result.ok, false, url);
    if (!result.ok) {
      assert.equal(result.error.kind, "unsupported_url", url);
      assert.equal(result.error.retryable, false);
    }
    assert.equal(calls.length, 0, url);
  }
});

test("refuses to run without a valid approved origin", async () => {
  for (const origin of [null, "not a url", "ftp://example.com"]) {
    const { deps, calls } = mockFetch(() => jsonResponse(COMPLETE_BODY));
    const result = await requestAssessment("https://example.com/", { ...deps, origin });
    assert.equal(result.ok, false, String(origin));
    if (!result.ok) {
      assert.equal(result.error.kind, "config_error");
    }
    assert.equal(calls.length, 0);
  }
});
