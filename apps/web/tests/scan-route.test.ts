import assert from "node:assert/strict";
import { test } from "node:test";

import type { ScanRequest } from "@phishguard/contracts";

import { createScanResponse } from "../lib/api/scan.ts";

const USER_A = "11111111-1111-4111-8111-111111111111";
const USER_B = "22222222-2222-4222-8222-222222222222";

const VALID_BODY = {
  url: "https://example.com/login",
  options: { include_intel: false, include_ct: false, timeout_ms: 5000 },
} as const;

function errorCode(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null || !("error" in body)) {
    return undefined;
  }
  const err = (body as { error?: unknown }).error;
  if (typeof err !== "object" || err === null || !("code" in err)) {
    return undefined;
  }
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

test("anonymous scan runs without a user id (no persistence owner)", async () => {
  const seen: Array<string | null> = [];
  const result = await createScanResponse({
    body: VALID_BODY,
    getUser: async () => ({ user: null }),
    analyze: async (_payload: ScanRequest, userId: string | null) => {
      seen.push(userId);
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 200);
  assert.deepEqual(seen, [null]);
});

test("authenticated scan passes the verified user id", async () => {
  const seen: Array<string | null> = [];
  const result = await createScanResponse({
    body: VALID_BODY,
    getUser: async () => ({ user: { id: USER_A } }),
    analyze: async (_payload: ScanRequest, userId: string | null) => {
      seen.push(userId);
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 200);
  assert.deepEqual(seen, [USER_A]);
});

test("invalid or expired session is anonymous, never authenticated", async () => {
  const seen: Array<string | null> = [];
  const result = await createScanResponse({
    body: VALID_BODY,
    // An expired/invalid session verifies to no user.
    getUser: async () => ({ user: null }),
    analyze: async (_payload: ScanRequest, userId: string | null) => {
      seen.push(userId);
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 200);
  assert.deepEqual(seen, [null]);
});

test("a user id smuggled in the request body is rejected, not trusted", async () => {
  let analyzed = false;
  const result = await createScanResponse({
    body: { ...VALID_BODY, user_id: USER_B },
    getUser: async () => ({ user: { id: USER_A } }),
    analyze: async () => {
      analyzed = true;
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 400);
  assert.equal(errorCode(result.body), "invalid_request");
  assert.equal(analyzed, false);
});

test("a camelCase forged identity field is rejected, not trusted", async () => {
  let analyzed = false;
  const result = await createScanResponse({
    body: { ...VALID_BODY, userId: USER_B },
    getUser: async () => ({ user: { id: USER_A } }),
    analyze: async () => {
      analyzed = true;
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 400);
  assert.equal(errorCode(result.body), "invalid_request");
  assert.equal(analyzed, false);
});

test("unverifiable session fails safely without running the scan", async () => {
  let analyzed = false;
  const result = await createScanResponse({
    body: VALID_BODY,
    getUser: async () => {
      throw new Error("auth backend unavailable");
    },
    analyze: async () => {
      analyzed = true;
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 503);
  assert.equal(errorCode(result.body), "upstream_unavailable");
  assert.equal(analyzed, false);
});

test("validated options are forwarded to the analysis service", async () => {
  let received: ScanRequest | undefined;
  const result = await createScanResponse({
    body: VALID_BODY,
    getUser: async () => ({ user: { id: USER_A } }),
    analyze: async (payload: ScanRequest) => {
      received = payload;
      return { status: 200, body: { ok: true } };
    },
  });

  assert.equal(result.status, 200);
  assert.deepEqual(received?.options, VALID_BODY.options);
  assert.equal(received?.url, "https://example.com/login");
});
