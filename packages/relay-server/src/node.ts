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
import { createApp } from './app.js';
import { InMemoryRelayStorage } from './storage/memory.js';

const port = Number(process.env.T2EM_PORT ?? 8787);

const app = createApp({ storage: new InMemoryRelayStorage() });

serve({ fetch: app.fetch, port }, (info) => {
  // Zero-logging: startup banner contains no request data, ever.
  console.log(`t2em-relay listening on http://localhost:${info.port}`);
});
