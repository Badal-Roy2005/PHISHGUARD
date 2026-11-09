import assert from "node:assert/strict";
import { test } from "node:test";

import { hashUrl, sanitizeUrl, type UrlSanitization } from "../src/lib/url.ts";

function ok(result: UrlSanitization) {
  assert.equal(result.ok, true, result.ok ? "unexpected failure" : result.message);
  if (!result.ok) {
    throw new Error("unreachable");
  }
  return result;
}

function rejected(result: UrlSanitization) {
  assert.equal(result.ok, false, "expected the URL to be rejected");
  if (result.ok) {
    throw new Error("unreachable");
  }
  return result;
}

test("keeps ordinary HTTP(S) URLs and non-sensitive query parameters", () => {
  const result = ok(sanitizeUrl("https://example.com/account?page=2&lang=en"));
  assert.equal(result.url, "https://example.com/account?page=2&lang=en");
  assert.equal(result.display, "https://example.com/account");
  assert.deepEqual(result.redactedParams, []);
  assert.equal(result.removedCredentials, false);
  assert.equal(result.removedFragment, false);

  const http = ok(sanitizeUrl("http://example.com/"));
  assert.equal(http.url, "http://example.com/");
});

test("removes fragment, credentials, and sensitive query parameters", () => {
  const result = ok(
    sanitizeUrl(
      "https://user:pass@example.com/login?token=abc&access_token=def&PHPSESSID=ghi&next=%2Fhome&email=a%40b.test#section",
    ),
  );

  assert.equal(result.removedCredentials, true);
  assert.equal(result.removedFragment, true);
  assert.equal(result.url, "https://example.com/login?next=%2Fhome");
  assert.deepEqual(
    [...result.redactedParams].sort(),
    ["PHPSESSID", "access_token", "email", "token"].sort(),
  );
  assert.equal(result.display.includes("token"), false);
  assert.equal(result.display.includes("?"), false);
});

test("matches sensitive parameter names case-insensitively and with separators", () => {
  const result = ok(
    sanitizeUrl(
      "https://example.com/x?Session-Id=1&API_KEY=2&clientSecret=3&password=4&otp=5&jwt=6&sig=7&state=8&code=9&keep=yes",
    ),
  );
  assert.equal(result.url, "https://example.com/x?keep=yes");
  assert.deepEqual(
    [...result.redactedParams].sort(),
    ["API_KEY", "Session-Id", "clientSecret", "code", "jwt", "otp", "password", "sig", "state"].sort(),
  );
});

test("rejects unsupported schemes and ports", () => {
  assert.equal(rejected(sanitizeUrl("ftp://example.com/file")).reason, "unsupported_scheme");
  assert.equal(rejected(sanitizeUrl("javascript:alert(1)")).reason, "unsupported_scheme");
  assert.equal(
    rejected(sanitizeUrl("data:text/html,<script>alert(1)</script>")).reason,
    "unsupported_scheme",
  );
  assert.equal(
    rejected(sanitizeUrl("https://example.com:8443/x")).reason,
    "unsupported_port",
  );
});

test("rejects local, private, reserved, and internal hosts", () => {
  const blocked = [
    "http://localhost/",
    "http://localhost:3000/",
    "http://service.localhost/",
    "http://printer.local/",
    "http://intranet/",
    "http://host.internal/",
    "http://router.home.arpa/",
    "http://127.0.0.1/",
    "http://127.1.2.3/",
    "http://0.0.0.0/",
    "http://10.0.0.7/",
    "http://172.16.4.2/",
    "http://172.31.255.255/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",
    "http://198.18.0.1/",
    "http://192.0.2.10/",
    "http://224.0.0.1/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[::ffff:127.0.0.1]/",
  ];

  for (const url of blocked) {
    assert.equal(rejected(sanitizeUrl(url)).reason, "blocked_host", url);
  }
});

test("normalizes a trailing root dot on public hosts", () => {
  const result = ok(sanitizeUrl("https://example.com./path"));
  assert.equal(result.url, "https://example.com/path");
});

test("rejects malformed, too-short, and over-long URLs", () => {
  assert.equal(rejected(sanitizeUrl("not a url")).reason, "invalid_url");
  assert.equal(rejected(sanitizeUrl("http://")).reason, "invalid_url");
  assert.equal(rejected(sanitizeUrl("")).reason, "invalid_url");
  assert.equal(rejected(sanitizeUrl("http://999.999.999.999/")).reason, "invalid_url");

  const longPath = `https://example.com/${"a".repeat(2200)}`;
  assert.equal(rejected(sanitizeUrl(longPath)).reason, "too_long");
});

test("produces deterministic SHA-256 cache keys without retaining the URL", async () => {
  const one = await hashUrl("https://example.com/a");
  const two = await hashUrl("https://example.com/a");
  const other = await hashUrl("https://example.com/b");

  assert.match(one, /^[0-9a-f]{64}$/);
  assert.equal(one, two);
  assert.notEqual(one, other);
  assert.equal(one.includes("example.com"), false);
});
