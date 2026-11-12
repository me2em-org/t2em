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

- HTTPS only; RFC1918/loopback/link-local/CGNAT/metadata ranges denied;
- DNS pinning against rebinding; redirects re-validated hop by hop.

## Status

Skeleton (Этап 0): tool registry + version constants. Implementation on
the MCP SDK lands in Этап 5 (see `docs/TZ_t2em.md` §14).
