# @t2em/cli

`t2em-cli` — command-line client for [t2em.com](https://t2em.com)
(ТЗ `docs/TZ_t2em.md` §8.2).

## Contract (fixed in the ТЗ)

- **UNIX pipes:** secrets go through stdin, never through arguments
  (`--secret` is forbidden). Diagnostics (fingerprints, progress) go to
  **stderr** only.
- **Exit codes:** `0` success · `1` error · `2` invalid arguments.
- **Env:** `T2EM_BASE_URL` (default `https://t2em.com`).
- **Keyfiles:** permission `0600`, `secureWipe` after use.

## Commands (Этап 3)

```
echo "secret" | t2em-cli push --ttl 300          # Mode B
echo "secret" | t2em-cli push --to <pubkey>      # Mode A (+ fingerprint on stderr)
t2em-cli pull "https://t2em.com/s/abc123#xyz789"
t2em-cli pull "https://t2em.com/s/abc123" --key ./agent.key
t2em-cli keygen --out ./agent.key
t2em-cli delete "https://t2em.com/s/abc123" --token <delete_token>
```

## Status

**Implemented (Этап 3).** All four commands, Mode A and Mode B, keyfile
handling (0600 + `secureWipe`), injectable transport — the command
suite is integration-tested against the real relay Hono app
(`packages/cli/test/commands.test.ts`).

## Development

```bash
pnpm install && pnpm -r build
echo "secret" | node packages/cli/dist/main.js push --ttl 120   # T2EM_BASE_URL to override the host
```
