"""Fingerprint — 8-char key verification token (ТЗ §4.2.1, §2.1).

fingerprint = base64url(sha256(pubkey))[0:8]

Used by CLI/SDK/MCP to protect against key substitution (MITM): the
parties compare fingerprints out-of-band before Mode A use.
"""

from __future__ import annotations

import hashlib
import base64

from .exceptions import UsageError
from .protocol import X25519_KEY_BYTES

FINGERPRINT_LENGTH: int = 8


def fingerprint_pubkey(pubkey: bytes | bytearray | str) -> str:
    """Compute the 8-char fingerprint of a raw 32-byte public key.

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
