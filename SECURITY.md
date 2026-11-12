# Security Policy

## Supported versions

t2em packages are pre-1.0 (roadmap in `docs/TZ_t2em.md` §14); security
fixes ship on `main` and in the latest release of every package.

| Package | Supported |
|---------|-----------|
| latest `main` / latest release of each `@t2em/*` | Yes |
| older releases | No |

## Reporting a vulnerability

Use **GitHub Security Advisories** ("Report a vulnerability" on the
[repository security tab](https://github.com/me2em-org/t2em/security/advisories/new)).
Do not open public issues for vulnerabilities.

Please include: affected package, reproduction steps or PoC, impact
assessment, and whether the finding affects the Zero-Knowledge
guarantees (ТЗ §6.3) — those are the core invariant of the product.

## Scope notes for this product

- The relay stores only opaque AES-GCM envelopes; reports claiming
  plaintext exposure via the relay must include a concrete vector.
- `@t2em/mcp-server`: SSRF-guard bypasses (ТЗ §8.4) are in scope,
  including DNS rebinding and redirect-based bypasses.
- Out of scope: automated scanners without reproduction steps, missing
  security headers on third-party CDNs.

## Hardening commitments carried from the ТЗ

- Zero-logging: no request bodies, no plaintext IP (only in-memory
  `sha256(ip)` rate-limit key, TTL 60 s), no User-Agent.
- `pnpm audit --prod --audit-level high` is a blocking CI gate.
- gitleaks scans the full git history on every push.
