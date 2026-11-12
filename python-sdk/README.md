# t2em — Python SDK (PyPI)

Python client for [t2em.com](https://t2em.com) for LangGraph / CrewAI /
AutoGen pipelines (ТЗ `docs/TZ_t2em.md` §8.3).

**Status: planned, Этап 4 of the roadmap.** This directory currently
holds only the contract summary; the package lands in Этап 4.

## Contract fixed by the ТЗ

```python
from t2em import T2emClient, generate_x25519_keypair

client = T2emClient("https://t2em.com")
drop = client.push(secret="sk-live-...", ttl=300)          # Mode B
secret = client.pull_text(drop.url)

keys = generate_x25519_keypair()                            # Mode A
drop = client.push(secret="...", recipient_pubkey=keys.public_key, ttl=300)
secret = client.pull_text(drop.url, recipient_privkey=keys.private_key)
```

- Python ≥ 3.10, full type hints.
- Networking: stdlib `urllib` only (no `requests`/`httpx`).
- Crypto: PyCA `cryptography` as the single crypto dependency
  (hand-rolled crypto is forbidden, §11.2); HKDF strictly per RFC 5869.
- Bit-compatible with the TypeScript protocol: verified against
  `vectors/t2em-drop.v1.json` from `@t2em/protocol`.
