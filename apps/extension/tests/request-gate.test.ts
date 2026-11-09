import assert from "node:assert/strict";
import { test } from "node:test";

import { RequestGate } from "../src/lib/request-gate.ts";

test("accepts only the latest request for the active key", () => {
  const gate = new RequestGate();

  const first = gate.begin("https://example.com/a");
  assert.equal(gate.isCurrent(first, "https://example.com/a"), true);

  const second = gate.begin("https://example.com/b");
  assert.equal(gate.isCurrent(first, "https://example.com/a"), false);
  assert.equal(gate.isCurrent(second, "https://example.com/b"), true);
  assert.equal(gate.activeKey, "https://example.com/b");
});

test("a repeat request for the same key invalidates the earlier response", () => {
  const gate = new RequestGate();
  const first = gate.begin("https://example.com/a");
  const second = gate.begin("https://example.com/a");

  assert.equal(gate.isCurrent(first, "https://example.com/a"), false);
  assert.equal(gate.isCurrent(second, "https://example.com/a"), true);
});

test("rejects a key that does not match the active request", () => {
  const gate = new RequestGate();
  const token = gate.begin("https://example.com/a");
  assert.equal(gate.isCurrent(token, "https://example.com/b"), false);
});

test("cancel invalidates every outstanding response", () => {
  const gate = new RequestGate();
  const token = gate.begin("https://example.com/a");

  gate.cancel();
  assert.equal(gate.isCurrent(token, "https://example.com/a"), false);
  assert.equal(gate.activeKey, null);
});
