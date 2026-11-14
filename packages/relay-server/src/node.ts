/**
 * Self-hosted Node entry (ТЗ §3.4, deployment mode 2).
 * Same Hono app as the Workers entry — only the storage adapter differs.
 *
 * Production duty (self-hosted Redis): run RAM-only —
 * `redis-server --save "" --appendonly no` (ТЗ §3.4).
 *
 * Этап 0 skeleton: in-memory storage. Этап 1 adds the local-Redis
 * adapter behind the same `RelayStorage` interface.
 */
import { serve } from '@hono/node-server';
import { createApp, type AppDeps } from './app.js';
import { InMemoryRelayStorage } from './storage/memory.js';

const port = Number(process.env.T2EM_PORT ?? 8787);

/** Env vars are strings — parse defensively, ignore junk, keep defaults. */
function numVar(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

const limits: Partial<AppDeps> = {
  ...(numVar('RATE_LIMIT_DROP_PER_MINUTE') !== undefined
    ? { rateLimitDropPerMinute: numVar('RATE_LIMIT_DROP_PER_MINUTE') }
    : {}),
  ...(numVar('RATE_LIMIT_DROP_PER_HOUR') !== undefined
    ? { rateLimitDropPerHour: numVar('RATE_LIMIT_DROP_PER_HOUR') }
    : {}),
  ...(numVar('RATE_LIMIT_FETCH_PER_MINUTE') !== undefined
    ? { rateLimitFetchPerMinute: numVar('RATE_LIMIT_FETCH_PER_MINUTE') }
    : {}),
  ...(numVar('RATE_LIMIT_DELETE_PER_MINUTE') !== undefined
    ? { rateLimitDeletePerMinute: numVar('RATE_LIMIT_DELETE_PER_MINUTE') }
    : {}),
  ...(numVar('MAX_ENVELOPE_FIELDS') !== undefined
    ? { maxEnvelopeFields: numVar('MAX_ENVELOPE_FIELDS') }
    : {}),
  ...(numVar('GLOBAL_ACTIVE_DROPS_LIMIT') !== undefined
    ? { globalActiveDropsLimit: numVar('GLOBAL_ACTIVE_DROPS_LIMIT') }
    : {}),
};

const app = createApp({ storage: new InMemoryRelayStorage(), ...limits });

serve({ fetch: app.fetch, port }, (info) => {
  // Zero-logging: startup banner contains no request data, ever.
  console.log(`t2em-relay listening on http://localhost:${info.port}`);
});
