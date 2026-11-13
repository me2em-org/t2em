"""t2em — Python SDK for t2em.com (ТЗ docs/TZ_t2em.md §8.3).

Zero-knowledge secret drops over a Blind Relay: the server stores only
an AES-256-GCM envelope and can never derive the key. Bit-compatible
with the TypeScript protocol `@t2em/protocol` — verified against
`vectors/t2em-drop.v1.json`.

Typical use::

    from t2em import T2emClient, generate_x25519_keypair

    client = T2emClient("https://t2em.com")

    # Mode B (symmetric, key lives in the URL #fragment)
    drop = client.push(secret="sk-live-...", ttl=300)
    secret = client.pull_text(drop.url)

    # Mode A (asymmetric, sealed to the recipient's X25519 pubkey)
    keys = generate_x25519_keypair()
    drop = client.push(secret="sk-live-...", recipient_pubkey=keys.public_key, ttl=300)
    secret = client.pull_text(drop.url, recipient_privkey=keys.private_key)
"""

from .base64url import b64u_decode, b64u_encode, is_b64u_of_length
from ._meta import SDK_VERSION, SDK_USER_AGENT
from .client import CreatedDrop, ShareUrl, T2emClient
from .envelope import Envelope, ModeAEnvelope, ModeBEnvelope, validate_envelope
from .exceptions import HttpError, ProtocolError, T2emError, UsageError
from .fingerprint import fingerprint_pubkey
from .keyfile import KEYFILE_KIND, load_keyfile, write_keyfile
from .keys import X25519KeyPair, generate_x25519_keypair
from .protocol import (
    HKDF_INFO_DROP_V1,
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    T2EM_PROTOCOL_VERSION,
)

__version__ = SDK_VERSION

__all__ = [
    "CreatedDrop",
    "Envelope",
    "HKDF_INFO_DROP_V1",
    "KEYFILE_KIND",
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "ModeAEnvelope",
    "ModeBEnvelope",
    "ProtocolError",
    "HttpError",
    "SDK_USER_AGENT",
    "SDK_VERSION",
    "ShareUrl",
    "T2EM_PROTOCOL_VERSION",
    "T2emClient",
    "T2emError",
    "UsageError",
    "X25519KeyPair",
    "b64u_decode",
    "b64u_encode",
    "fingerprint_pubkey",
    "generate_x25519_keypair",
    "is_b64u_of_length",
    "load_keyfile",
    "validate_envelope",
    "write_keyfile",
]
