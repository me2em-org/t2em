/**
 * Upstash Redis (REST) adapter — production storage for the
 * Cloudflare Workers entry (ТЗ §3.1, §8.6).
 *
 * Этап 0 skeleton: the constructor validates the configuration and the
 * methods deliberately throw `NOT_IMPLEMENTED`. The real REST-backed
 * implementation (GET/SET EX/GETDEL/INCR+EXPIRE) lands in Этап 1 —
 * see `docs/TZ_t2em.md` §5, §6.1.
 *
 * Hard requirements carried over from the ТЗ (§8.6):
 * - REST API only (no TCP sockets);
 * - no persistence on the server side (RDB/AOF off) — config duty;
 * - the client never logs values, only keys' hashed forms at most.
 */
import type { DropId, RelayStorage } from './types.js';

export interface UpstashRelayStorageConfig {
  /** e.g. https://global-...upstash.io */
  url: string;
  /** Upstash REST token — inject from a secret, never hardcode. */
  token: string;
}

export class UpstashRelayStorage implements RelayStorage {
  constructor(config: UpstashRelayStorageConfig) {
    const url = config?.url ?? '';
    const token = config?.token ?? '';
    if (!url.startsWith('https://')) {
      throw new Error('UpstashRelayStorage: url must be https:// (TLS 1.3, ТЗ §8.6)');
    }
    if (token.length === 0) {
      throw new Error('UpstashRelayStorage: token is required');
    }
  }

  async putDrop(_id: DropId, _envelope: string, _ttlSeconds: number): Promise<void> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }

  async getDrop(_id: DropId): Promise<string | null> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }

  async consumeDrop(_id: DropId): Promise<string | null> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }

  async putDeleteTokenHash(_id: DropId, _tokenHashHex: string, _ttlSeconds: number): Promise<void> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }

  async getDeleteTokenHash(_id: DropId): Promise<string | null> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }

  async hitRateLimit(_bucketKey: string): Promise<number> {
    throw new Error('NOT_IMPLEMENTED: UpstashRelayStorage lands in Этап 1');
  }
}
