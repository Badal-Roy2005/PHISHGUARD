import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  buildManifest,
  DEFAULT_API_ORIGIN,
  parseApiOrigin,
  validateManifest,
} from "../build.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TEMPLATE = JSON.parse(
  readFileSync(new URL("../src/manifest.template.json", import.meta.url), "utf8"),
) as Record<string, unknown>;
const ORIGIN = "https://phishguard.example.test";

test("normalizes valid backend origins", () => {
  assert.equal(parseApiOrigin("https://phishguard.example.test"), ORIGIN);
  assert.equal(parseApiOrigin("  https://phishguard.example.test/  "), ORIGIN);
  assert.equal(parseApiOrigin("http://localhost:3000"), "http://localhost:3000");
  assert.equal(parseApiOrigin("http://127.0.0.1:8000"), "http://127.0.0.1:8000");
  assert.equal(parseApiOrigin("http://[::1]:3000"), "http://[::1]:3000");
  assert.equal(DEFAULT_API_ORIGIN, "http://localhost:3000");
});

test("rejects unsafe or ambiguous backend origins", () => {
  const invalid = [
    "",
    "not a url",
    "ftp://phishguard.example.test",
    "http://phishguard.example.test",
    "https://user:pass@phishguard.example.test",
    "https://phishguard.example.test/api",
    "https://phishguard.example.test?x=1",
    "https://phishguard.example.test#x",
  ];

  for (const origin of invalid) {
    assert.throws(() => parseApiOrigin(origin), `expected ${origin} to be rejected`);
  }
});

test("injects the origin and package version into the manifest", () => {
  const manifest = buildManifest(TEMPLATE, ORIGIN, "1.2.3");
  assert.equal(manifest.version, "1.2.3");
  assert.deepEqual(manifest.host_permissions, [`${ORIGIN}/*`]);

  const csp = manifest.content_security_policy as Record<string, string>;
  assert.ok(csp.extension_pages?.includes(`connect-src ${ORIGIN}`));

  const text = JSON.stringify(manifest);
  assert.equal(text.includes("__API_ORIGIN__"), false);
  assert.equal(text.includes("localhost"), false);

  validateManifest(manifest, ORIGIN);
});

test("manifest validation rejects broadened capability", () => {
  const valid = buildManifest(TEMPLATE, ORIGIN, "1.2.3");
  const mutations: Array<[string, (manifest: Record<string, unknown>) => void]> = [
    ["tabs permission", (m) => (m.permissions = ["activeTab", "tabs"])],
    ["storage permission", (m) => (m.permissions = ["activeTab", "storage"])],
    ["broad host permission", (m) => (m.host_permissions = ["<all_urls>"])],
    ["content scripts", (m) => (m.content_scripts = [])],
    ["extra manifest key", (m) => (m.side_panel = {})],
    ["manifest v2", (m) => (m.manifest_version = 2)],
    ["unsafe inline CSP", (m) => {
      const csp = m.content_security_policy as Record<string, string>;
      csp.extension_pages = `${csp.extension_pages ?? ""} 'unsafe-inline'`;
    }],
    ["wildcard connect-src", (m) => {
      const csp = m.content_security_policy as Record<string, string>;
      csp.extension_pages = "default-src 'self'; connect-src *";
    }],
    ["missing popup", (m) => {
      (m.action as Record<string, unknown>).default_popup = "other.html";
    }],
    ["classic worker", (m) => {
      (m.background as Record<string, unknown>).type = "classic";
    }],
    ["non-semver version", (m) => (m.version = "1.2")],
  ];

  for (const [label, mutate] of mutations) {
    const manifest = structuredClone(valid);
    mutate(manifest);
    assert.throws(() => validateManifest(manifest, ORIGIN), label);
  }
});

test("production build emits a loadable MV3 package", () => {
  const outDir = mkdtempSync(join(tmpdir(), "phishguard-extension-"));
  try {
    const result = spawnSync(process.execPath, ["build.ts"], {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        ...process.env,
        EXTENSION_OUT_DIR: outDir,
        PHISHGUARD_API_ORIGIN: ORIGIN,
      },
    });

    assert.equal(result.status, 0, result.stderr || result.stdout);

    const required = [
      "manifest.json",
      "popup.html",
      "popup.css",
      "popup.js",
      "service-worker.js",
      "lib/url.js",
      "lib/backend.js",
      "lib/assessment.js",
      "lib/messages.js",
      "lib/cache.js",
      "lib/request-gate.js",
      "lib/view.js",
      "lib/api-origin.js",
    ];
    for (const file of required) {
      assert.equal(existsSync(join(outDir, file)), true, `missing ${file}`);
    }

    const manifest = JSON.parse(
      readFileSync(join(outDir, "manifest.json"), "utf8"),
    ) as Record<string, unknown>;
    assert.equal(manifest.manifest_version, 3);
    assert.deepEqual(manifest.permissions, ["activeTab"]);
    assert.deepEqual(manifest.host_permissions, [`${ORIGIN}/*`]);
    assert.equal((manifest.background as Record<string, unknown>).service_worker, "service-worker.js");
    assert.equal(JSON.stringify(manifest).includes("__API_ORIGIN__"), false);

    const worker = readFileSync(join(outDir, "service-worker.js"), "utf8");
    assert.ok(worker.includes('from "./lib/api-origin.js"'));
    assert.ok(worker.includes('from "./lib/backend.js"'));
    assert.equal(/\.ts["']/.test(worker), false);

    const popup = readFileSync(join(outDir, "popup.js"), "utf8");
    assert.ok(popup.includes('from "./lib/request-gate.js"'));
    assert.equal(/\.ts["']/.test(popup), false);

    const html = readFileSync(join(outDir, "popup.html"), "utf8");
    assert.ok(html.includes('src="popup.js"'));
    assert.equal(/https?:\/\//.test(html), false);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("build refuses a remote plaintext backend origin", () => {
  const outDir = mkdtempSync(join(tmpdir(), "phishguard-extension-"));
  try {
    const result = spawnSync(process.execPath, ["build.ts"], {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        ...process.env,
        EXTENSION_OUT_DIR: outDir,
        PHISHGUARD_API_ORIGIN: "http://phishguard.example.test",
      },
    });

    assert.notEqual(result.status, 0);
    assert.equal(existsSync(join(outDir, "manifest.json")), false);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});
