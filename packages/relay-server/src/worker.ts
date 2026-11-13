/**
 * Cloudflare Workers entry (ТЗ §3.4, deployment mode 1).
 * Same Hono app as the Node entry — only the storage adapter differs.
 *
 * Secrets (set once via `wrangler secret put`):
 *   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 *
 * Optional var (wrangler.jsonc `[vars]`):
 *   T2EM_PUBLIC_ORIGIN — overrides the origin used in share links
 *   (§5.2 `url`). Unset = the §5.1 canonical `https://t2em.com`; useful
 *   while the custom domain is not yet attached and the worker is
 *   served from `*.workers.dev`.
 */
import { createApp } from './app.js';
import { UpstashRelayStorage } from './storage/upstash.js';

export interface Env {
  /** Upstash REST endpoint (https://...upstash.io). */
  readonly UPSTASH_REDIS_REST_URL: string;
  /** Upstash REST token — injected as a Worker secret, never hardcoded. */
  readonly UPSTASH_REDIS_REST_TOKEN: string;
  /** Optional share-link origin override (see file comment). */
  readonly T2EM_PUBLIC_ORIGIN?: string;
}

export default {
  fetch(request, env, _ctx) {
    const app = createApp({
      storage: new UpstashRelayStorage({
        url: env.UPSTASH_REDIS_REST_URL,
        token: env.UPSTASH_REDIS_REST_TOKEN,
      }),
      ...(env.T2EM_PUBLIC_ORIGIN ? { publicOrigin: env.T2EM_PUBLIC_ORIGIN } : {}),
    });
    return app.fetch(request);
  },
} satisfies ExportedHandler<Env>;
