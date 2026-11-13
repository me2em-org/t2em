/**
 * Cloudflare Workers entry (ТЗ §3.4, deployment mode 1).
 * Same Hono app as the Node entry — only the storage adapter differs.
 *
 * Secrets (set once via `wrangler secret put`):
 *   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 */
import { createApp } from './app.js';
import { UpstashRelayStorage } from './storage/upstash.js';

export interface Env {
  /** Upstash REST endpoint (https://...upstash.io). */
  readonly UPSTASH_REDIS_REST_URL: string;
  /** Upstash REST token — injected as a Worker secret, never hardcoded. */
  readonly UPSTASH_REDIS_REST_TOKEN: string;
}

export default {
  fetch(request, env, _ctx) {
    const app = createApp({
      storage: new UpstashRelayStorage({
        url: env.UPSTASH_REDIS_REST_URL,
        token: env.UPSTASH_REDIS_REST_TOKEN,
      }),
    });
    return app.fetch(request);
  },
} satisfies ExportedHandler<Env>;
