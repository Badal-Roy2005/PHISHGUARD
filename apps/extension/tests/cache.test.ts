import assert from "node:assert/strict";
import { test } from "node:test";

import { SingleFlight, TtlCache } from "../src/lib/cache.ts";

function clock() {
  let now = 1_000;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

test("expires cached entries after the TTL", () => {
  const time = clock();
  const cache = new TtlCache<string>(1_000, 4, time.now);

  assert.equal(cache.set("a", "value"), true);
  assert.equal(cache.get("a"), "value");

  time.advance(999);
  assert.equal(cache.get("a"), "value");

  time.advance(2);
  assert.equal(cache.get("a"), undefined);
  assert.equal(cache.size, 0);
});

test("evicts the least recently written entry beyond the maximum", () => {
  const cache = new TtlCache<number>(60_000, 2, () => 0);
  cache.set("a", 1);
  cache.set("b", 2);
  cache.set("c", 3);

  assert.equal(cache.size, 2);
  assert.equal(cache.get("a"), undefined);
  assert.equal(cache.get("b"), 2);
  assert.equal(cache.get("c"), 3);

  const reinserted = new TtlCache<number>(60_000, 2, () => 0);
  reinserted.set("a", 1);
  reinserted.set("b", 2);
  reinserted.set("a", 10);
  reinserted.set("c", 3);
  assert.equal(reinserted.get("b"), undefined);
  assert.equal(reinserted.get("a"), 10);
  assert.equal(reinserted.get("c"), 3);
});

test("clear invalidates in-flight writes from an older epoch", () => {
  const cache = new TtlCache<string>(60_000, 4, () => 0);
  const epoch = cache.epoch;

  cache.clear();
  assert.equal(cache.epoch, epoch + 1);
  assert.equal(cache.size, 0);
  assert.equal(cache.set("a", "stale", epoch), false);
  assert.equal(cache.size, 0);

  assert.equal(cache.set("a", "fresh"), true);
  assert.equal(cache.get("a"), "fresh");
});

test("rejects invalid cache configuration", () => {
  assert.throws(() => new TtlCache<string>(0));
  assert.throws(() => new TtlCache<string>(-1));
  assert.throws(() => new TtlCache<string>(Number.NaN));
  assert.throws(() => new TtlCache<string>(1_000, 0));
  assert.throws(() => new TtlCache<string>(1_000, 1.5));
});

test("deduplicates concurrent work for the same key", async () => {
  const flight = new SingleFlight<string, number>();
  let calls = 0;
  const deferred: { resolve?: (value: number) => void } = {};
  const pending = new Promise<number>((resolve) => {
    deferred.resolve = resolve;
  });

  const task = () => {
    calls += 1;
    return pending;
  };

  const first = flight.run("key", task);
  const second = flight.run("key", task);

  assert.equal(first, second);
  assert.equal(flight.size, 1);

  // The task starts on the next microtask, not synchronously.
  await Promise.resolve();
  assert.equal(calls, 1);

  deferred.resolve?.(42);
  assert.equal(await first, 42);
  assert.equal(await second, 42);
  await Promise.resolve();
  assert.equal(flight.size, 0);
  assert.equal(calls, 1);
});

test("runs independent keys separately and allows a later retry", async () => {
  const flight = new SingleFlight<string, string>();
  let calls = 0;

  const task = async (value: string) => {
    calls += 1;
    return value;
  };

  assert.equal(await flight.run("a", () => task("a")), "a");
  assert.equal(await flight.run("b", () => task("b")), "b");
  assert.equal(calls, 2);

  assert.equal(await flight.run("a", () => task("again")), "again");
  assert.equal(calls, 3);
});

test("clears a failed in-flight entry so a retry can run", async () => {
  const flight = new SingleFlight<string, number>();
  let calls = 0;

  await assert.rejects(
    flight.run("key", async () => {
      calls += 1;
      throw new Error("boom");
    }),
    /boom/,
  );
  await Promise.resolve();
  assert.equal(flight.size, 0);

  const value = await flight.run("key", async () => {
    calls += 1;
    return 7;
  });
  assert.equal(value, 7);
  assert.equal(calls, 2);
});
