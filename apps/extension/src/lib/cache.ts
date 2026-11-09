/**
 * Bounded in-memory cache and single-flight deduplication.
 *
 * The cache stores only already-validated assessment data, keyed by a SHA-256
 * hash of the normalized URL. URLs themselves are never stored. The cache lives
 * in the service worker's memory: it is discarded when the worker is suspended
 * or the browser closes, and can be cleared explicitly from the popup.
 */

interface CacheEntry<V> {
  value: V;
  expiresAt: number;
}

export class TtlCache<V> {
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #entries = new Map<string, CacheEntry<V>>();
  #epoch = 0;

  constructor(ttlMs: number, maxEntries = 32, now: () => number = Date.now) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("ttlMs must be positive");
    }
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new Error("maxEntries must be a positive integer");
    }
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
    this.#now = now;
  }

  /** Increments whenever the cache is cleared. */
  get epoch(): number {
    return this.#epoch;
  }

  get size(): number {
    return this.#entries.size;
  }

  get(key: string): V | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined) {
      return undefined;
    }
    if (entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  /**
   * Store a value unless the cache was cleared after the request started.
   * Returns false when the value belongs to an obsolete epoch.
   */
  set(key: string, value: V, epoch = this.#epoch): boolean {
    if (epoch !== this.#epoch) {
      return false;
    }

    this.#entries.delete(key);
    this.#entries.set(key, { value, expiresAt: this.#now() + this.#ttlMs });

    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.#entries.delete(oldest);
    }
    return true;
  }

  clear(): void {
    this.#entries.clear();
    this.#epoch += 1;
  }
}

export class SingleFlight<K, V> {
  readonly #inFlight = new Map<K, Promise<V>>();

  get size(): number {
    return this.#inFlight.size;
  }

  run(key: K, task: () => Promise<V>): Promise<V> {
    const existing = this.#inFlight.get(key);
    if (existing !== undefined) {
      return existing;
    }

    const promise = Promise.resolve()
      .then(task)
      .finally(() => {
        if (this.#inFlight.get(key) === promise) {
          this.#inFlight.delete(key);
        }
      });

    this.#inFlight.set(key, promise);
    return promise;
  }
}
