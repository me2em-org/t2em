# infra

Deployment configuration for the t2em relay (ТЗ §3.4, §8.6).

## Deployment modes

1. **Cloudflare Workers (managed, $0/мес)** — entry
   `packages/relay-server/src/worker.ts`, storage Upstash Redis (REST),
   deploy via GitHub Actions + `wrangler-action`. Wrangler config and
   secrets wiring land here in Этап 1 (`wrangler.jsonc`,
   `wrangler secret put UPSTASH_REDIS_REST_TOKEN`).
2. **Self-hosted Docker** — entry
   `packages/relay-server/src/node.ts` (`@hono/node-server`), storage
   local Redis **RAM-only**: `redis-server --save "" --appendonly no`.
   `docker-compose.yml` lands here in Этап 1.

## Edge duties (Cloudflare, ТЗ §8.6)

DNSSEC · HSTS `max-age=63072000; includeSubDomains; preload` · TLS 1.3
only · WAF (Managed + OWASP CRS) · bot management with an allowlist for
known AI agents · Cache-Control `no-store` on all API responses.

## Status

Этап 0: directory contract only. Этап 1 adds the wrangler/Docker
configuration and CI deploy job.
