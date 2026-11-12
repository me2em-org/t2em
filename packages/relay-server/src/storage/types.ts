/**
 * Storage abstraction for the Blind Relay (ТЗ §6.1 Redis schema).
 *
 * The relay never interprets envelope contents — every method below
 * moves opaque strings. Both deployment modes (Cloudflare Workers /
 * self-hosted Node) share this interface; only the adapter differs
 * (ТЗ §3.4).
 */

/** Drop identifier, URL-safe. */
export type DropId = string;

/** Relay storage contract. All operations are async (remote Redis). */
export interface RelayStorage {
  /**
   * Store the opaque envelope JSON for `id`, auto-expiring after
   * `ttlSeconds` (60..900, ТЗ §4). Redis: `SET drop:{id} <json> EX {ttl}`.
   */
  putDrop(id: DropId, envelope: string, ttlSeconds: number): Promise<void>;

  /** Read the envelope without consuming it. Redis: `GET drop:{id}`. */
  getDrop(id: DropId): Promise<string | null>;

  /**
   * Atomically read-and-delete the envelope (read exactly once).
   * Redis: `GETDEL drop:{id}` (Redis 6.2+, ТЗ §6.4).
   */
  consumeDrop(id: DropId): Promise<string | null>;

  /**
   * Store `sha256(delete_token)` (hex) for `id`, same TTL as the drop.
   * Redis: `SET delete:{id} <hex> EX {ttl}`.
   */
  putDeleteTokenHash(id: DropId, tokenHashHex: string, ttlSeconds: number): Promise<void>;

  /** Read the stored delete-token hash. Redis: `GET delete:{id}`. */
  getDeleteTokenHash(id: DropId): Promise<string | null>;

  /**
   * Increment the per-minute rate-limit counter for an already-hashed
   * bucket key (`ratelimit:{ip_hash}:{minute}`) and return the new
   * counter value. First increment sets EX 60 (ТЗ §6.1).
   */
  hitRateLimit(bucketKey: string): Promise<number>;
}

/** Seconds a rate-limit counter lives (ТЗ §6.1: `EX 60`). */
export const RATE_LIMIT_WINDOW_SECONDS = 60;
