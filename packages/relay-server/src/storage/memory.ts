/**
 * In-memory `RelayStorage` — used by self-hosted dev runs and tests.
 *
 * NOT for production: no durability, no cross-process sharing. The
 * self-hosted production mode uses a RAM-only local Redis instead
 * (`--save "" --appendonly no`, ТЗ §3.4).
 */
import { RATE_LIMIT_WINDOW_SECONDS, type DropId, type RelayStorage } from './types.js';

interface Entry {
  value: string;
  /** Unix epoch ms when the entry expires. */
  expiresAtMs: number;
}

export class InMemoryRelayStorage implements RelayStorage {
  private readonly data = new Map<string, Entry>();
  private readonly counters = new Map<string, Entry>();

  private static expired(entry: Entry | undefined, nowMs: number): boolean {
    return entry === undefined || entry.expiresAtMs <= nowMs;
  }

  private static live(entry: Entry | undefined): string | null {
    const now = Date.now();
    return InMemoryRelayStorage.expired(entry, now) ? null : (entry as Entry).value;
  }

  async putDrop(id: DropId, envelope: string, ttlSeconds: number): Promise<void> {
    this.data.set(`drop:${id}`, {
      value: envelope,
      expiresAtMs: Date.now() + ttlSeconds * 1000,
    });
  }

  async getDrop(id: DropId): Promise<string | null> {
    return InMemoryRelayStorage.live(this.data.get(`drop:${id}`));
  }

  async consumeDrop(id: DropId): Promise<string | null> {
    const key = `drop:${id}`;
    const value = InMemoryRelayStorage.live(this.data.get(key));
    if (value !== null) this.data.delete(key); // GETDEL semantics (§6.4)
    return value;
  }

  async putDeleteTokenHash(id: DropId, tokenHashHex: string, ttlSeconds: number): Promise<void> {
    this.data.set(`delete:${id}`, {
      value: tokenHashHex,
      expiresAtMs: Date.now() + ttlSeconds * 1000,
    });
  }

  async getDeleteTokenHash(id: DropId): Promise<string | null> {
    return InMemoryRelayStorage.live(this.data.get(`delete:${id}`));
  }

  async putBurnMarker(id: DropId, ttlSeconds: number): Promise<void> {
    this.data.set(`burn:${id}`, {
      value: '0',
      expiresAtMs: Date.now() + ttlSeconds * 1000,
    });
  }

  async getBurnMarker(id: DropId): Promise<boolean> {
    return InMemoryRelayStorage.live(this.data.get(`burn:${id}`)) !== null;
  }

  async destroyDrop(id: DropId): Promise<void> {
    // DEL of missing keys is a no-op in Redis too — mirror that.
    for (const key of [`drop:${id}`, `delete:${id}`, `burn:${id}`]) {
      this.data.delete(key);
    }
  }

  async ping(): Promise<boolean> {
    return true; // in-process map — always alive
  }

  async hitRateLimit(bucketKey: string): Promise<number> {
    const key = `ratelimit:${bucketKey}`;
    const now = Date.now();
    const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;
    const entry = this.counters.get(key);
    if (InMemoryRelayStorage.expired(entry, now)) {
      this.counters.set(key, { value: '1', expiresAtMs: now + windowMs });
      return 1;
    }
    const next = Number((entry as Entry).value) + 1;
    (entry as Entry).value = String(next);
    return next;
  }
}
