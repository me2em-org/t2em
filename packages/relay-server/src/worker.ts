/**
 * Cloudflare Workers entry (ТЗ §3.4, deployment mode 1).
 * Same Hono app as the Node entry — only the storage adapter differs.
 *
 * Этап 0 skeleton: binds the in-memory storage. Этап 1 swaps in
 * `UpstashRelayStorage` backed by the REST credentials below.
 */
import { createApp } from './app.js';
import { InMemoryRelayStorage } from './storage/memory.js';

export interface Env {
  /** Upstash REST endpoint (https://...upstash.io). */
  readonly UPSTASH_REDIS_REST_URL: string;
  /** Upstash REST token — set via `wrangler secret put`. */
  readonly UPSTASH_REDIS_REST_TOKEN: string;
}

export default {
  fetch(request, _env, _ctx) {
    // TODO(Этап 1): create UpstashRelayStorage(env) per isolate and
    // wire rate limiting + drop API. Memory storage keeps the skeleton
    // runnable on workers.dev without external dependencies.
    const app = createApp({ storage: new InMemoryRelayStorage() });
    return app.fetch(request);
  },
} satisfies ExportedHandler<Env>;
