/**
 * Cloudflare Workers entry (ТЗ §3.4, deployment mode 1).
 * Same Hono app as the Node entry — only the storage adapter differs.
 *
 * Secrets (set once via `wrangler secret put`):
 *   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
 *
 * Optional vars (wrangler.jsonc `[vars]`, unset = app defaults):
 *   T2EM_PUBLIC_ORIGIN — share-link origin override (§5.2 `url`)
 *   RATE_LIMIT_DROP_PER_MINUTE   — POST /drop, minute bucket (default 30)
 *   RATE_LIMIT_DROP_PER_HOUR     — POST /drop, hour bucket (default 100)
 *   RATE_LIMIT_FETCH_PER_MINUTE  — GET /s/:id (default 60)
 *   RATE_LIMIT_DELETE_PER_MINUTE — DELETE /drop/:id (default 60)
 *   MAX_ENVELOPE_FIELDS          — JSON-bomb guard (default 10)
 *   GLOBAL_ACTIVE_DROPS_LIMIT    — §5.1 budget in drops (default 1 000 000)
 */
import { createApp, type AppDeps } from './app.js';
import { UpstashRelayStorage } from './storage/upstash.js';

export interface Env {
  /** Upstash REST endpoint (https://...upstash.io). */
  readonly UPSTASH_REDIS_REST_URL: string;
  /** Upstash REST token — injected as a Worker secret, never hardcoded. */
  readonly UPSTASH_REDIS_REST_TOKEN: string;
  /** Optional share-link origin override (see file comment). */
  readonly T2EM_PUBLIC_ORIGIN?: string;
  /** §5.1 tuning — see file comment; unset = built-in defaults. */
  readonly RATE_LIMIT_DROP_PER_MINUTE?: string;
  readonly RATE_LIMIT_DROP_PER_HOUR?: string;
  readonly RATE_LIMIT_FETCH_PER_MINUTE?: string;
  readonly RATE_LIMIT_DELETE_PER_MINUTE?: string;
  readonly MAX_ENVELOPE_FIELDS?: string;
  readonly GLOBAL_ACTIVE_DROPS_LIMIT?: string;
}

/** Env vars are strings — parse defensively, ignore junk, keep defaults. */
function numVar(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

export default {
  fetch(request, env, _ctx) {
    const limits: Partial<AppDeps> = {
      ...(numVar(env.RATE_LIMIT_DROP_PER_MINUTE) !== undefined
        ? { rateLimitDropPerMinute: numVar(env.RATE_LIMIT_DROP_PER_MINUTE) }
        : {}),
      ...(numVar(env.RATE_LIMIT_DROP_PER_HOUR) !== undefined
        ? { rateLimitDropPerHour: numVar(env.RATE_LIMIT_DROP_PER_HOUR) }
        : {}),
      ...(numVar(env.RATE_LIMIT_FETCH_PER_MINUTE) !== undefined
        ? { rateLimitFetchPerMinute: numVar(env.RATE_LIMIT_FETCH_PER_MINUTE) }
        : {}),
      ...(numVar(env.RATE_LIMIT_DELETE_PER_MINUTE) !== undefined
        ? { rateLimitDeletePerMinute: numVar(env.RATE_LIMIT_DELETE_PER_MINUTE) }
        : {}),
      ...(numVar(env.MAX_ENVELOPE_FIELDS) !== undefined
        ? { maxEnvelopeFields: numVar(env.MAX_ENVELOPE_FIELDS) }
        : {}),
      ...(numVar(env.GLOBAL_ACTIVE_DROPS_LIMIT) !== undefined
        ? { globalActiveDropsLimit: numVar(env.GLOBAL_ACTIVE_DROPS_LIMIT) }
        : {}),
    };
    const app = createApp({
      storage: new UpstashRelayStorage({
        url: env.UPSTASH_REDIS_REST_URL,
        token: env.UPSTASH_REDIS_REST_TOKEN,
      }),
      ...(env.T2EM_PUBLIC_ORIGIN ? { publicOrigin: env.T2EM_PUBLIC_ORIGIN } : {}),
      ...limits,
    });
    return app.fetch(request);
  },
} satisfies ExportedHandler<Env>;
