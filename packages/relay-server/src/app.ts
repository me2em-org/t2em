/**
 * Shared Hono application of the Blind Relay (ТЗ §3.4):
 * both the Cloudflare Workers entry (`worker.ts`) and the self-hosted
 * Node entry (`node.ts`) mount exactly this app; only the storage
 * adapter differs.
 *
 * Этап 0 skeleton: security headers, `/healthz`, JSON 404/500.
 * The drop API (`POST /api/v1/drop`, `GET /s/:id`,
 * `DELETE /api/v1/drop/:id` — ТЗ §5) lands in Этап 1.
 */
import { Hono } from 'hono';
import { T2EM_PROTOCOL_VERSION } from '@t2em/protocol';
import type { RelayStorage } from './storage/types.js';
import { T2EM_RELAY_VERSION } from './version.js';

export interface AppDeps {
  storage: RelayStorage;
}

/** Headers applied to every response (ТЗ §3.1, §8.6). */
function applySecurityHeaders(c: Parameters<Parameters<Hono['use']>[1]>[0]): void {
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  // Zero-Knowledge transport hygiene: nothing dynamic is cacheable.
  c.header('Cache-Control', 'no-store, no-cache, private');
}

export function createApp(_deps: AppDeps): Hono {
  // TODO(Этап 1): register drop API routes using _deps.storage
  // (POST /api/v1/drop, GET /s/:id, DELETE /api/v1/drop/:id — ТЗ §5).
  const app = new Hono();

  app.use('*', async (c, next) => {
    applySecurityHeaders(c);
    await next();
  });

  // Liveness probe — no secrets, no PII, cacheable nowhere.
  app.get('/healthz', (c) =>
    c.json({
      ok: true,
      service: 't2em-relay',
      version: T2EM_RELAY_VERSION,
      protocol: T2EM_PROTOCOL_VERSION,
    }),
  );

  app.notFound((c) =>
    c.json({ error: { code: 'NOT_FOUND', message: 'Unknown route' } }, 404),
  );

  // Zero-logging: report the failure class, never request bodies.
  app.onError((err, c) => {
    if (err instanceof Error && err.message.startsWith('NOT_IMPLEMENTED')) {
      return c.json({ error: { code: 'NOT_IMPLEMENTED', message: err.message } }, 501);
    }
    return c.json({ error: { code: 'INTERNAL', message: 'Internal error' } }, 500);
  });

  return app;
}
