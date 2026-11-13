/**
 * Upstash Redis (REST) adapter — production storage for the
 * Cloudflare Workers entry (ТЗ §3.1, §8.6).
 *
 * Wire duties carried over from the ТЗ:
 * - REST API only (no TCP sockets) — `@upstash/redis` uses fetch;
 * - server side runs RAM-only (RDB/AOF off) — configuration duty;
 * - this adapter never logs values; at most hashed keys in caller logs.
 *
 * Key layout mirrors ТЗ §6.1:
 *   drop:{id}                  → envelope JSON, EX {ttl}
 *   delete:{id}                → sha256(delete_token) hex, EX {ttl}
 *   ratelimit:{ip_hash}:{min}  → counter, EX 60 (INCR + EXPIRE)
 */
import { Redis } from '@upstash/redis';
import { RATE_LIMIT_WINDOW_SECONDS, type DropId, type RelayStorage } from './types.js';

export interface UpstashRelayStorageConfig {
  /** e.g. https://global-...upstash.io */
  url: string;
  /** Upstash REST token — inject from a secret, never hardcode. */
  token: string;
}

export class UpstashRelayStorage implements RelayStorage {
  private readonly redis: Redis;

  constructor(config: UpstashRelayStorageConfig) {
    const url = config?.url ?? '';
    const token = config?.token ?? '';
    if (!url.startsWith('https://')) {
      throw new Error('UpstashRelayStorage: url must be https:// (TLS 1.3, ТЗ §8.6)');
    }
    if (token.length === 0) {
      throw new Error('UpstashRelayStorage: token is required');
    }
    // automaticDeserialization: false — the envelope is opaque for the Blind
    // Relay (ТЗ §3.2): the SDK must not JSON.parse stored strings on read and
    // must not encode values on write; drop:{id} travels byte-for-byte.
    this.redis = new Redis({ url, token, automaticDeserialization: false });
  }

  async putDrop(id: DropId, envelope: string, ttlSeconds: number): Promise<void> {
    await this.redis.set(`drop:${id}`, envelope, { ex: ttlSeconds });
  }

  async getDrop(id: DropId): Promise<string | null> {
    const v = await this.redis.get<string>(`drop:${id}`);
    return typeof v === 'string' ? v : null;
  }

  async consumeDrop(id: DropId): Promise<string | null> {
    // GETDEL (Redis 6.2+, ТЗ §6.4): drop is read exactly once.
    const v = await this.redis.getdel<string>(`drop:${id}`);
    return typeof v === 'string' ? v : null;
  }

  async putDeleteTokenHash(id: DropId, tokenHashHex: string, ttlSeconds: number): Promise<void> {
    await this.redis.set(`delete:${id}`, tokenHashHex, { ex: ttlSeconds });
  }

  async getDeleteTokenHash(id: DropId): Promise<string | null> {
    const v = await this.redis.get<string>(`delete:${id}`);
    return typeof v === 'string' ? v : null;
  }

  async hitRateLimit(bucketKey: string): Promise<number> {
    // Single-RTT pipeline; EXPIRE refreshes within the per-minute
    // bucket, which only extends a past minute's counter lifetime —
    // the bucket key itself rotates every minute (ТЗ §6.1).
    const key = `ratelimit:${bucketKey}`;
    const pipeline = this.redis.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, RATE_LIMIT_WINDOW_SECONDS);
    const [counter] = await pipeline.exec<[number, number]>();
    return counter;
  }
}
