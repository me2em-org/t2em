"""Fingerprint — 16-char key verification token (ТЗ §4.2.1, v2.1 fix #4).

fingerprint = base64url(sha256(pubkey))[0:16]

16 base64url chars = 96 bits: collision at ~2**48 keys (birthday
paradox). The previous 8-char form (48 bits) collided at ~16M keys —
the length was raised to 16 in ТЗ v2.1 §4.2.1.

Used by CLI/SDK/MCP to protect against key substitution (MITM): the
parties compare fingerprints out-of-band before Mode A use.
"""

from __future__ import annotations

import hashlib
import base64

from .exceptions import UsageError
from .protocol import X25519_KEY_BYTES

FINGERPRINT_LENGTH: int = 16


def fingerprint_pubkey(pubkey: bytes | bytearray | str) -> str:
    """Compute the 16-char fingerprint of a raw 32-byte public key.

    Accepts raw bytes or a base64url-encoded public key string.
    """
    if isinstance(pubkey, str):
        pad = "=" * (-len(pubkey) % 4)
        try:
            pubkey = base64.urlsafe_b64decode(pubkey + pad)
        except Exception as exc:
            raise UsageError(f"pubkey is not valid base64url: {exc}") from exc
    if len(pubkey) != X25519_KEY_BYTES:
        raise UsageError(f"pubkey must be {X25519_KEY_BYTES} bytes, got {len(pubkey)}")
    digest = hashlib.sha256(bytes(pubkey)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:FINGERPRINT_LENGTH]


# §3.6 fixed public-API name (alias of fingerprint_pubkey).
generate_fingerprint = fingerprint_pubkey
