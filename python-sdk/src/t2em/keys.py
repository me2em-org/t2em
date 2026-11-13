"""X25519 keypair generation (ТЗ §8.3, §4.2.1).

`generate_x25519_keypair()` returns b64url string fields, matching the
ТЗ §8.3 API contract (`keys.public_key` / `keys.private_key` feed
`push(recipient_pubkey=...)` and `pull_text(recipient_privkey=...)`
directly).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .base64url import b64u_encode
from .protocol import X25519_KEY_BYTES


@dataclass(frozen=True)
class X25519KeyPair:
    """X25519 keypair with base64url string fields (ТЗ §8.3 shape)."""

    public_key: str
    private_key: str

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key."""
        from .base64url import b64u_decode

        return b64u_decode(self.public_key)

    @property
    def private_key_bytes(self) -> bytes:
        """Raw 32-byte private key."""
        from .base64url import b64u_decode

        return b64u_decode(self.private_key)


def generate_x25519_keypair() -> X25519KeyPair:
    """Generate a fresh X25519 keypair (RFC 7748) via PyCA cryptography."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    if len(priv_raw) != X25519_KEY_BYTES or len(pub_raw) != X25519_KEY_BYTES:  # pragma: no cover
        raise RuntimeError("X25519 key derivation produced wrong length")
    return X25519KeyPair(public_key=b64u_encode(pub_raw), private_key=b64u_encode(priv_raw))


def os_random(n: int) -> bytes:
    """CSPRNG bytes (exposed for tests that patch entropy sources)."""
    return os.urandom(n)
