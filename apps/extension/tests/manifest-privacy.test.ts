import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

function sourceFiles(): Array<{ path: string; text: string }> {
  return readdirSync(SRC, { recursive: true })
    .map((entry) => String(entry))
    .filter((entry) => /\.(ts|html|json|css)$/.test(entry))
    .map((entry) => ({
      path: entry,
      text: readFileSync(join(SRC, entry), "utf8"),
    }));
}

function filesWith(pattern: RegExp): string[] {
  return sourceFiles()
    .filter((file) => pattern.test(file.text))
    .map((file) => file.path);
}

test("no page-content, credential, or browsing-history collection APIs", () => {
  const forbidden = [
    /chrome\.cookies/,
    /chrome\.history/,
    /chrome\.webRequest/,
    /chrome\.scripting/,
    /chrome\.storage/,
    /chrome\.downloads/,
    /chrome\.bookmarks/,
    /chrome\.management/,
    /localStorage/,
    /sessionStorage/,
    /indexedDB/,
    /document\.cookie/,
    /navigator\.clipboard/,
    /getUserMedia/,
    /geolocation/,
  ];

  for (const pattern of forbidden) {
    assert.deepEqual(filesWith(pattern), [], `forbidden API ${pattern}`);
  }
});

test("no HTML injection, dynamic code, or remote script loading", () => {
  const forbidden = [
    /innerHTML/,
    /outerHTML/,
    /insertAdjacentHTML/,
    /document\.write/,
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /setTimeout\s*\(\s*["'`]/,
    /setInterval\s*\(/,
    /XMLHttpRequest/,
    /WebSocket/,
    /EventSource/,
    /sendBeacon/,
  ];

  for (const pattern of forbidden) {
    assert.deepEqual(filesWith(pattern), [], `forbidden construct ${pattern}`);
  }

  for (const file of sourceFiles().filter((entry) => entry.path.endsWith(".html"))) {
    assert.doesNotMatch(file.text, /<form\b/i, `${file.path} must not contain a form`);
    assert.doesNotMatch(file.text, /<input\b/i, `${file.path} must not contain inputs`);
    assert.doesNotMatch(file.text, /type=["']password["']/i, `${file.path} must not collect passwords`);
    for (const match of file.text.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) {
      const src = match[1] ?? "";
      assert.equal(
        /^(?:https?:)?\/\//.test(src),
        false,
        `${file.path} must not load remote scripts (${src})`,
      );
    }
    for (const match of file.text.matchAll(/<link\b[^>]*\bhref=["']([^"']+)["']/gi)) {
      const href = match[1] ?? "";
      assert.equal(
        /^(?:https?:)?\/\//.test(href),
        false,
        `${file.path} must not load remote styles (${href})`,
      );
    }
  }
});

test("only the bounded backend client performs network I/O", () => {
  assert.deepEqual(filesWith(/\bfetch\b/), ["lib/backend.ts"]);
  assert.deepEqual(filesWith(/from\s+["']@phishguard\/contracts/), []);
});

test("Chrome API usage is limited to runtime messaging and active-tab reads", () => {
  const codeFiles = sourceFiles().filter((file) => file.path.endsWith(".ts"));
  for (const file of codeFiles) {
    for (const match of file.text.matchAll(/chrome\.([A-Za-z]+)(?:\.([A-Za-z]+))?/g)) {
      const namespace = match[1];
      const member = match[2];
      assert.ok(
        namespace === "runtime" || namespace === "tabs",
        `${file.path} uses chrome.${namespace ?? ""}`,
      );
      if (namespace === "tabs" && member !== "query") {
        assert.fail(`${file.path} uses chrome.tabs.${member ?? ""}`);
      }
    }
  }
});

test("manifest requests only activeTab plus the single backend origin", () => {
  const template = JSON.parse(
    readFileSync(join(SRC, "manifest.template.json"), "utf8"),
  ) as Record<string, unknown>;

  assert.deepEqual(template.permissions, ["activeTab"]);
  assert.deepEqual(template.host_permissions, ["__API_ORIGIN__/*"]);
  assert.equal("content_scripts" in template, false);
  assert.equal("web_accessible_resources" in template, false);
  assert.equal("optional_permissions" in template, false);
  assert.equal("optional_host_permissions" in template, false);

  const text = JSON.stringify(template);
  for (const forbidden of ["<all_urls>", "*://", '"tabs"', '"scripting"', '"storage"', '"cookies"']) {
    assert.equal(text.includes(forbidden), false, `manifest must not include ${forbidden}`);
  }

  const csp = template.content_security_policy as Record<string, string>;
  const extensionPages = csp.extension_pages ?? "";
  assert.ok(extensionPages.includes("script-src 'self'"));
  assert.ok(extensionPages.includes("connect-src __API_ORIGIN__"));
  assert.ok(extensionPages.includes("object-src 'none'"));
  assert.deepEqual(filesWith(/unsafe-eval|unsafe-inline/), []);
});

test("the popup renders untrusted text with textContent only", () => {
  const popup = readFileSync(join(SRC, "popup.ts"), "utf8");
  assert.ok(popup.includes("textContent"));
  assert.ok(popup.includes("replaceChildren"));
  assert.ok(popup.includes("RequestGate"));
  assert.ok(popup.includes("sanitizeUrl"));
  assert.doesNotMatch(popup, /chrome\.tabs\.(?!query)/);
});
