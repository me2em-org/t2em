# @t2em/mcp-server

MCP server for [t2em.com](https://t2em.com) — lets Claude Code / Cursor /
Windsurf push and pull zero-knowledge drops without exposing secrets to
the LLM context (ТЗ `docs/TZ_t2em.md` §8.4).

## Tools (fixed by the ТЗ, 6 total)

| Tool | Notes |
|---|---|
| `t2em_keygen` | privkey stays in the in-process vault |
| `t2em_push` | `{ secret, ttl?, recipient_pubkey? }` → `{ url, delete_token? }` |
| `t2em_pull` | returns a `secret_handle` (`sec_<uuid>`), never the secret itself |
| `t2em_http_request` | `{{secret_handle}}` substitution; **SSRF-guard** mandatory |
| `t2em_wipe_secret` | two-pass `secureWipe` |
| `t2em_list_secrets` | handles only |

## SSRF-guard (§8.4, blocking in CodeQL)

- HTTPS only; credentials in URLs rejected;
- RFC1918 / loopback / link-local (cloud metadata 169.254.169.254) /
  CGNAT / ULA / multicast / documentation ranges denied — IPv4,
  IPv6 and IPv4-mapped forms;
- DNS pinning against rebinding (connect uses a validated address);
- redirects re-validated hop by hop (max 3), response capped at 1 MiB.

## Install / wire into the agent

```bash
npm install -g @t2em/mcp-server
```

```json
{ "mcpServers": { "t2em": { "command": "t2em-mcp" } } }
```

Environment: `T2EM_BASE_URL` (default `https://t2em.com`).
Zero-logging: no secret value is ever printed; stdout belongs to the
MCP JSON-RPC transport only.

## Status

**Implemented (Этап 5 done)** on the official MCP SDK
(`@modelcontextprotocol/sdk`, stdio transport). Full journeys are
tested in-process against the real Hono relay app via
`InMemoryTransport` (62 tests).
