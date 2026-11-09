/**
 * Sequence gate for popup requests.
 *
 * Each refresh gets a token tied to the normalized URL key. When the active tab
 * changes or the user rechecks, a new token invalidates every earlier in-flight
 * response, so a slow assessment for tab A can never render on tab B.
 */

export class RequestGate {
  #sequence = 0;
  #activeKey: string | null = null;

  begin(key: string): number {
    this.#sequence += 1;
    this.#activeKey = key;
    return this.#sequence;
  }

  isCurrent(token: number, key: string): boolean {
    return token === this.#sequence && key === this.#activeKey;
  }

  cancel(): void {
    this.#sequence += 1;
    this.#activeKey = null;
  }

  get activeKey(): string | null {
    return this.#activeKey;
  }
}
