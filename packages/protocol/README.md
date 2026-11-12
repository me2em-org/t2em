# @t2em/protocol

Cryptographic core of [t2em.com](https://t2em.com) — Zero-Knowledge
Token Transfer (Blind Relay).

Implements the envelope formats of the ТЗ (`docs/TZ_t2em.md` §4) on top
of `@me2em/crypto` primitives only (`@noble/*` is forbidden in
application code — ТЗ §4.1).

## Scope (v1, Этап 1–2)

- **Mode A** — asymmetric E2EE on X25519 (ephemeral sender key +
  recipient public key, UKS-safe HKDF salt `eph_pub || recipient_pub`,
  HKDF info `me2em/crypto/v1/t2em-drop`, AES-256-GCM).
- **Mode B** — symmetric `#fragment` bootstrap (`sym_key` never leaves
  the URL fragment, RFC 3986).
- Recipient key fingerprint: `base64url(sha256(pubkey))[0..8]`.
- Memory hygiene: two-pass `secureWipe` on every secret buffer.
- Test vectors: `vectors/t2em-drop.v1.json`, bit-compatible between the
  TypeScript and Python implementations.

## Freeze rule (ТЗ §4.5)

`HKDF_INFO_DROP_V1`, the `envelope.v` field and every string that feeds
key derivation change **only** through a new `/v2` (new info string,
new `v`, separate `mode`). Editing existing strings is a breaking
change and is forbidden.

## Status

Skeleton (Этап 0). Envelope implementation lands in Этап 1–2 per the
roadmap in `docs/TZ_t2em.md` §14.
