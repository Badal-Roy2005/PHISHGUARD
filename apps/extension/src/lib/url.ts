/**
 * URL normalization and privacy filtering.
 *
 * The extension only ever sends a public HTTP(S) URL to the PHISHGUARD backend.
 * Before that happens this module:
 *   - rejects non-HTTP(S), local/private/reserved hosts, and non-default ports;
 *   - strips embedded credentials;
 *   - removes the fragment;
 *   - removes query parameters whose names commonly carry secrets or PII.
 *
 * This is defense in depth, not a replacement for the backend's own validation
 * or the scanner's SSRF controls.
 */

export type UrlRejectionReason =
  | "invalid_url"
  | "unsupported_scheme"
  | "unsupported_port"
  | "blocked_host"
  | "too_long";

export interface UrlSanitizationOk {
  ok: true;
  /** Canonical URL sent to the backend. */
  url: string;
  /** Origin and path only; safe to show in the popup (no query). */
  display: string;
  /** Names of query parameters that were removed. */
  redactedParams: string[];
  removedCredentials: boolean;
  removedFragment: boolean;
}

export interface UrlSanitizationError {
  ok: false;
  reason: UrlRejectionReason;
  message: string;
}

export type UrlSanitization = UrlSanitizationOk | UrlSanitizationError;

const MIN_URL_LENGTH = 8;
const MAX_URL_LENGTH = 2048;
const MAX_DISPLAY_LENGTH = 120;

/**
 * Parameter names that carry credentials, session material, one-time codes,
 * signatures, or direct identifiers. Matching is case-insensitive and also
 * catches separator variants such as `access_token` and `PHPSESSID`.
 */
const SENSITIVE_EXACT = new Set([
  "access_token",
  "accesstoken",
  "api_key",
  "apikey",
  "assertion",
  "auth",
  "auth_token",
  "authtoken",
  "authorization",
  "bearer",
  "client_secret",
  "clientsecret",
  "code",
  "connectsid",
  "csrf",
  "csrftoken",
  "email",
  "id_token",
  "idtoken",
  "jwt",
  "mail",
  "nonce",
  "otp",
  "password",
  "passwd",
  "phpsessid",
  "phone",
  "pwd",
  "refresh_token",
  "refreshtoken",
  "saml",
  "secret",
  "session",
  "session_id",
  "sessionid",
  "sid",
  "sig",
  "signature",
  "state",
  "ticket",
  "token",
  "user",
  "username",
]);

const SENSITIVE_SUFFIXES = [
  "apikey",
  "auth",
  "csrf",
  "password",
  "secret",
  "sessionid",
  "token",
];

const LOCAL_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];

const IPV4_LIKE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

type Ipv4 = [number, number, number, number];

function toOctet(part: string): number | null {
  if (!/^\d{1,3}$/.test(part)) {
    return null;
  }
  const value = Number(part);
  return value <= 255 ? value : null;
}

function parseIpv4(host: string): Ipv4 | null {
  if (!IPV4_LIKE.test(host)) {
    return null;
  }
  const parts = host.split(".");
  const first = parts[0];
  const second = parts[1];
  const third = parts[2];
  const fourth = parts[3];
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
  ) {
    return null;
  }
  const a = toOctet(first);
  const b = toOctet(second);
  const c = toOctet(third);
  const d = toOctet(fourth);
  if (a === null || b === null || c === null || d === null) {
    return null;
  }
  return [a, b, c, d];
}

function isBlockedIpv4([a, b, c]: Ipv4): boolean {
  if (a === 0 || a === 10 || a === 127) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true; // carrier-grade NAT
  }
  if (a === 169 && b === 254) {
    return true; // link-local, including cloud metadata
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 192 && b === 0 && (c === 0 || c === 2)) {
    return true; // reserved / documentation
  }
  if (a === 192 && b === 88 && c === 99) {
    return true; // 6to4 relay anycast
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return true; // benchmarking
  }
  if (a === 198 && b === 51 && c === 100) {
    return true; // documentation
  }
  if (a === 203 && b === 0 && c === 113) {
    return true; // documentation
  }
  if (a >= 224) {
    return true; // multicast / reserved / broadcast
  }
  return false;
}

function isBlockedIpv6(rawHost: string): boolean {
  let host = rawHost.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }

  if (host === "::" || host === "::1") {
    return true;
  }
  if (
    host.startsWith("fe8") ||
    host.startsWith("fe9") ||
    host.startsWith("fea") ||
    host.startsWith("feb")
  ) {
    return true; // fe80::/10 link-local
  }
  if (host.startsWith("fc") || host.startsWith("fd")) {
    return true; // fc00::/7 unique-local
  }
  if (host.startsWith("ff")) {
    return true; // multicast
  }
  if (host.startsWith("100:") || host.startsWith("100::")) {
    return true; // discard-only
  }
  if (
    host.startsWith("2001:db8") ||
    host.startsWith("2001:2:") ||
    host.startsWith("2001:10") ||
    host.startsWith("2001::") ||
    host.startsWith("2002:") ||
    host.startsWith("64:ff9b:")
  ) {
    return true; // documentation, benchmarking, ORCHID, Teredo, 6to4, NAT64
  }

  // IPv4-mapped/compatible forms: block private/loopback embedded addresses.
  const mappedIndex = host.lastIndexOf("::ffff:");
  if (mappedIndex >= 0) {
    const suffix = host.slice(mappedIndex + "::ffff:".length);
    const embedded = parseIpv4(suffix);
    if (embedded === null || isBlockedIpv4(embedded)) {
      return true;
    }
  }

  return false;
}

function isBlockedHostname(host: string): boolean {
  if (host === "localhost") {
    return true;
  }
  for (const suffix of LOCAL_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return true;
    }
  }

  const ipv4 = parseIpv4(host);
  if (ipv4 !== null) {
    return isBlockedIpv4(ipv4);
  }
  if (host.includes(":")) {
    return isBlockedIpv6(host);
  }

  // A single-label host resolves through local search domains; do not send it.
  if (!host.includes(".")) {
    return true;
  }

  // Fail closed for anything that looks numeric but did not parse as IPv4.
  if (/^[0-9.]+$/.test(host)) {
    return true;
  }

  return false;
}

function normalizedParamName(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, "");
}

function isSensitiveParam(name: string): boolean {
  const lower = name.toLowerCase();
  if (SENSITIVE_EXACT.has(lower)) {
    return true;
  }
  const normalized = normalizedParamName(lower);
  if (SENSITIVE_EXACT.has(normalized)) {
    return true;
  }
  return SENSITIVE_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

function reject(reason: UrlRejectionReason, message: string): UrlSanitizationError {
  return { ok: false, reason, message };
}

export function sanitizeUrl(raw: string): UrlSanitization {
  const trimmed = raw.trim();
  if (trimmed.length < MIN_URL_LENGTH) {
    return reject("invalid_url", "The page address is too short to assess.");
  }
  if (trimmed.length > MAX_URL_LENGTH) {
    return reject("too_long", "The page address is too long to assess.");
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return reject("invalid_url", "The page address could not be parsed.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return reject("unsupported_scheme", "Only HTTP and HTTPS pages can be assessed.");
  }

  let host = parsed.hostname.toLowerCase();
  if (!host.startsWith("[") && host.endsWith(".")) {
    host = host.slice(0, -1);
    parsed.hostname = host;
  }
  if (host === "" || isBlockedHostname(host)) {
    return reject(
      "blocked_host",
      "Local, private, internal, and reserved addresses are not assessed.",
    );
  }

  if (parsed.port !== "") {
    return reject(
      "unsupported_port",
      "Only pages on the default HTTP or HTTPS port can be assessed.",
    );
  }

  const removedCredentials = parsed.username !== "" || parsed.password !== "";
  if (removedCredentials) {
    parsed.username = "";
    parsed.password = "";
  }

  const removedFragment = parsed.hash !== "";
  if (removedFragment) {
    parsed.hash = "";
  }

  const redacted = new Set<string>();
  for (const name of parsed.searchParams.keys()) {
    if (isSensitiveParam(name)) {
      redacted.add(name);
    }
  }
  for (const name of redacted) {
    parsed.searchParams.delete(name);
  }

  const url = parsed.toString();
  if (url.length < MIN_URL_LENGTH || url.length > MAX_URL_LENGTH) {
    return reject("too_long", "The normalized page address is too long to assess.");
  }

  let display = `${parsed.origin}${parsed.pathname}`;
  if (display.length > MAX_DISPLAY_LENGTH) {
    display = `${display.slice(0, MAX_DISPLAY_LENGTH - 3)}...`;
  }

  return {
    ok: true,
    url,
    display,
    redactedParams: [...redacted].sort(),
    removedCredentials,
    removedFragment,
  };
}

/**
 * Hash the normalized URL for cache keying. The raw URL never becomes a cache
 * key, so a cache dump cannot reveal browsing history.
 */
export async function hashUrl(url: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
