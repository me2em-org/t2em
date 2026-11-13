# t2em — Python SDK (PyPI)

Python client for [t2em.com](https://t2em.com) for LangGraph / CrewAI /
AutoGen pipelines (ТЗ `docs/TZ_t2em.md` §8.3).

**Status: implemented (Этап 4 done).** Zero-knowledge secret drops —
the relay stores only an AES-256-GCM envelope and can never derive the
key.

## Install

```bash
pip install t2em          # from PyPI (when published)
pip install -e .          # from this repo (editable, dev)
```

## Usage (the ТЗ §8.3 contract)

```python
from t2em import T2emClient, generate_x25519_keypair

client = T2emClient("https://t2em.com")

# Mode B (symmetric — key rides in the URL #fragment, never sent to the server)
drop = client.push(secret="sk-live-...", ttl=300)
print(drop.url)        # https://t2em.com/s/abc123#xyz789
print(drop.delete_token)
secret = client.pull_text(drop.url)

# Mode A (asymmetric — sealed to the recipient's X25519 pubkey)
keys = generate_x25519_keypair()
drop = client.push(secret="sk-live-...", recipient_pubkey=keys.public_key, ttl=300)
secret = client.pull_text(drop.url, recipient_privkey=keys.private_key)

# Delete before TTL expiry
client.delete(drop.id, drop.delete_token)

# Keyfile — same JSON format as the TS CLI (`t2em-cli keygen`)
from t2em import write_keyfile, load_keyfile
pubkey = write_keyfile("./agent.key")            # 0600, returns b64url pubkey
key = load_keyfile("./agent.key")                # LoadedKey(private_key, public_key)
```

## Guarantees

- Python ≥ 3.10, full type hints (`py.typed`).
- Networking: stdlib `urllib` only (no `requests`/`httpx`) — §8.3.
- Crypto: PyCA `cryptography` as the single crypto dependency
  (hand-rolled crypto is forbidden, §11.2); HKDF strictly per RFC 5869.
- Bit-compatible with the TypeScript protocol `@t2em/protocol`:
  verified against `vectors/t2em-drop.v1.json` (unpack AND deterministic
  re-encryption, both modes) plus TS↔Python cross-pack/unpack checks.
- Transport is injectable (`T2emClient(base_url, transport=...)`) for
  testing without sockets.
- Error taxonomy mirrors §4.5: branch on `ProtocolError.code`
  (`MALFORMED` / `UNSUPPORTED_VERSION` / `DECRYPT_FAILED`), `UsageError`,
  `HttpError` (status / code / retry_after).

## Layout

```
python-sdk/
├── src/t2em/           # package (py.typed)
│   ├── protocol.py     # constants: version, TTL bounds, HKDF info (freeze §4.5)
│   ├── base64url.py    # strict RFC 4648 §5 unpadded codec
│   ├── envelope.py     # v1 envelope validation (mirror of @t2em/protocol)
│   ├── mode_b.py       # pack/unpack sym (AES-256-GCM, 12B IV)
│   ├── mode_a.py       # pack/unpack X25519 ECDH + HKDF-SHA256
│   ├── fingerprint.py  # 8-char pubkey fingerprint (§4.2.1)
│   ├── keyfile.py      # t2em-x25519-key-v1 JSON keyfile (0600)
│   └── client.py       # T2emClient: push / pull_text / pull_bytes / delete
└── tests/              # pytest: vectors bit-compat, client journeys, keyfile
```
