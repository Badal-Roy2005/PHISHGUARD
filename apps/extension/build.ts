/**
 * Production build for the PHISHGUARD MV3 extension.
 *
 * There is no bundler in this repository, so the build uses the existing
 * TypeScript compiler to emit native ES modules, copies the static popup
 * assets, and generates the final `manifest.json` with the configured backend
 * origin. The origin is injected at build time; the extension has no runtime
 * endpoint configuration.
 */

import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));

export const DEFAULT_API_ORIGIN = "http://localhost:3000";

const ALLOWED_MANIFEST_KEYS = [
  "action",
  "background",
  "content_security_policy",
  "description",
  "host_permissions",
  "manifest_version",
  "minimum_chrome_version",
  "name",
  "permissions",
  "version",
];

const FORBIDDEN_MANIFEST_KEYS = [
  "chrome_url_overrides",
  "content_scripts",
  "devtools_page",
  "externally_connectable",
  "optional_host_permissions",
  "optional_permissions",
  "side_panel",
  "update_url",
  "web_accessible_resources",
];

const REQUIRED_OUTPUT_FILES = [
  "manifest.json",
  "popup.css",
  "popup.html",
  "popup.js",
  "service-worker.js",
];

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Validate and normalize the API origin used for the single host permission.
 *
 * Plaintext HTTP is only accepted for loopback development; a remote deployment
 * must use HTTPS because the extension sends the assessed URL to this origin.
 */
export function parseApiOrigin(raw: string): string {
  const trimmed = raw.trim();
  assert(trimmed.length > 0, "PHISHGUARD_API_ORIGIN must not be empty.");

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error(`PHISHGUARD_API_ORIGIN is not a valid URL: ${trimmed}`);
  }

  assert(
    url.protocol === "http:" || url.protocol === "https:",
    "PHISHGUARD_API_ORIGIN must use http or https.",
  );
  assert(
    url.username === "" && url.password === "",
    "PHISHGUARD_API_ORIGIN must not contain credentials.",
  );
  assert(
    url.pathname === "/" && url.search === "" && url.hash === "",
    "PHISHGUARD_API_ORIGIN must be an origin without a path, query, or fragment.",
  );
  assert(!url.hostname.includes("*"), "PHISHGUARD_API_ORIGIN must not use a wildcard host.");

  if (url.protocol === "http:") {
    const host = url.hostname;
    const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
    assert(
      loopback,
      "Plaintext HTTP is only allowed for loopback development hosts; use HTTPS.",
    );
  }

  return url.origin;
}

/**
 * Replace the build-time placeholder in the manifest template.
 *
 * All placeholder occurrences (host permission and CSP connect-src) receive the
 * same validated origin, so the network capability cannot drift from the
 * injected endpoint.
 */
export function buildManifest(
  template: unknown,
  apiOrigin: string,
  version?: string,
): Record<string, unknown> {
  const origin = parseApiOrigin(apiOrigin);
  assert(isRecord(template), "Manifest template must be a JSON object.");

  const manifest = JSON.parse(
    JSON.stringify(template).replaceAll("__API_ORIGIN__", origin),
  ) as unknown;
  assert(isRecord(manifest), "Manifest template must be a JSON object.");

  if (version !== undefined) {
    assert(/^\d+\.\d+\.\d+$/.test(version), "Package version must be semver.");
    manifest.version = version;
  }

  return manifest;
}

/** Enforce the deliberately small permission and capability surface. */
export function validateManifest(manifest: Record<string, unknown>, apiOrigin: string): void {
  const origin = parseApiOrigin(apiOrigin);

  assert(manifest.manifest_version === 3, "manifest_version must be 3.");
  assert(typeof manifest.name === "string" && manifest.name.length > 0, "name is required.");
  assert(
    typeof manifest.version === "string" && /^\d+\.\d+\.\d+$/.test(manifest.version),
    "version must be semver.",
  );

  for (const key of FORBIDDEN_MANIFEST_KEYS) {
    assert(!(key in manifest), `Manifest must not contain ${key}.`);
  }

  const keys = Object.keys(manifest).sort();
  assert(
    deepEqual(keys, [...ALLOWED_MANIFEST_KEYS].sort()),
    `Manifest contains unexpected keys: ${keys.join(", ")}`,
  );

  assert(
    deepEqual(manifest.permissions, ["activeTab"]),
    "Manifest permissions must be exactly [\"activeTab\"].",
  );
  assert(
    deepEqual(manifest.host_permissions, [`${origin}/*`]),
    `host_permissions must be exactly ["${origin}/*"]`,
  );

  const background = manifest.background;
  assert(
    isRecord(background) &&
      background.service_worker === "service-worker.js" &&
      background.type === "module",
    "background must be the module service worker service-worker.js.",
  );

  const action = manifest.action;
  assert(
    isRecord(action) && action.default_popup === "popup.html",
    "action.default_popup must be popup.html.",
  );

  const cspRoot = manifest.content_security_policy;
  assert(isRecord(cspRoot), "content_security_policy is required.");
  const csp = cspRoot.extension_pages;
  assert(typeof csp === "string" && csp.length > 0, "extension_pages CSP is required.");
  assert(csp.includes("script-src 'self'"), "CSP must restrict scripts to 'self'.");
  assert(csp.includes("object-src 'none'"), "CSP must disable plugins.");
  assert(csp.includes("base-uri 'none'"), "CSP must disable base URI changes.");
  assert(csp.includes("form-action 'none'"), "CSP must disable form submissions.");
  assert(csp.includes(`connect-src ${origin}`), "CSP connect-src must be the API origin.");
  assert(!csp.includes("'unsafe-eval'"), "CSP must not allow unsafe-eval.");
  assert(!csp.includes("'unsafe-inline'"), "CSP must not allow unsafe-inline.");
  assert(!csp.includes("*"), "CSP must not use wildcard sources.");

  const manifestText = JSON.stringify(manifest);
  assert(
    !manifestText.includes("<all_urls>") && !manifestText.includes("*://"),
    "Manifest must not request broad host access.",
  );
  assert(!manifestText.includes("__API_ORIGIN__"), "API origin placeholder was not replaced.");
}

function emitTypeScript(outDir: string): void {
  const require = createRequire(import.meta.url);
  const tsc = require.resolve("typescript/lib/tsc.js");
  const result = spawnSync(
    process.execPath,
    [tsc, "-p", join(ROOT, "tsconfig.build.json"), "--outDir", outDir],
    { cwd: ROOT, stdio: "inherit" },
  );
  if (result.status !== 0) {
    throw new Error(`TypeScript build failed with status ${String(result.status)}.`);
  }
}

async function main(): Promise<void> {
  const outDir = resolve(ROOT, process.env.EXTENSION_OUT_DIR?.trim() || "dist");
  const apiOrigin = parseApiOrigin(
    process.env.PHISHGUARD_API_ORIGIN?.trim() || DEFAULT_API_ORIGIN,
  );

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  emitTypeScript(outDir);

  copyFileSync(join(ROOT, "src/popup.html"), join(outDir, "popup.html"));
  copyFileSync(join(ROOT, "src/popup.css"), join(outDir, "popup.css"));

  const template = JSON.parse(
    readFileSync(join(ROOT, "src/manifest.template.json"), "utf8"),
  ) as unknown;
  const packageJson = JSON.parse(
    readFileSync(join(ROOT, "package.json"), "utf8"),
  ) as unknown;
  assert(isRecord(packageJson), "package.json must be a JSON object.");
  const version = typeof packageJson.version === "string" ? packageJson.version : undefined;

  const manifest = buildManifest(template, apiOrigin, version);
  validateManifest(manifest, apiOrigin);

  writeFileSync(join(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

  for (const file of REQUIRED_OUTPUT_FILES) {
    assert(existsSync(join(outDir, file)), `Build output is missing ${file}.`);
  }

  process.stdout.write(
    `[extension] built ${outDir} for ${apiOrigin} (permissions: activeTab)\n`,
  );
}

const entry = process.argv[1];
if (entry && pathToFileURL(resolve(entry)).href === import.meta.url) {
  // TypeScript target is ES2022, so top-level await is available.
  await main();
}
