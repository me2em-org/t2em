# @t2em/relay-server

Blind Relay of [t2em.com](https://t2em.com) — the server that stores
opaque envelopes without ever seeing plaintext (ТЗ §3, §6).

One Hono app (`src/app.ts`), two deployment entries (ТЗ §3.4):

| Entry | Target | Storage |
|---|---|---|
| `src/worker.ts` | Cloudflare Workers (`@cloudflare/workers-types` `ExportedHandler`) | Upstash Redis REST |
| `src/node.ts` | Self-hosted Docker (`@hono/node-server`) | local Redis / RAM |

Storage backends implement `RelayStorage` (`src/storage/types.ts`) and
mirror the Redis schema from ТЗ §6.1:

```
drop:{id}          → envelope JSON      EX {ttl}
delete:{id}        → sha256(delete_token) EX {ttl}
ratelimit:{ip_hash}:{minute} → counter EX 60
```

## Zero-Knowledge guarantees (ТЗ §6.3–6.4)

- No request-body logging, no User-Agent logging, no plaintext IP.
- `GETDEL` semantics (`consumeDrop`) — a drop is read exactly once
  when `burn_after_reading` is set.
- `Cache-Control: no-store` on all dynamic routes.

## Status

Skeleton (Этап 0): shared app + storage interface + in-memory backend +
health endpoint. The API surface (`POST /api/v1/drop`, `GET /s/:id`,
`DELETE /api/v1/drop/:id`, rate limiting, Upstash adapter) lands in
Этап 1 per `docs/TZ_t2em.md` §5.
