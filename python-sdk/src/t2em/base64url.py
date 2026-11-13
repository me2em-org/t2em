"""Base64URL helpers (RFC 4648 §5, no padding) — ТЗ §4.1.

Strict mirror of `@t2em/protocol` `base64url.ts`: the same alphabet,
the same rejection rules, so every wire string produced here is
byte-identical to the TypeScript implementation.
"""

from __future__ import annotations

import base64
import re

from .exceptions import ProtocolError

_B64URL_ALPHABET = re.compile(r"^[A-Za-z0-9\-_]+$")


def b64u_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Throwing strict decoder: rejects any non-base64url alphabet or padding."""
    if not isinstance(text, str) or len(text) == 0:
        raise ProtocolError("MALFORMED", "base64url string must be non-empty")
    if not _B64URL_ALPHABET.match(text):
        raise ProtocolError("MALFORMED", "not base64url (RFC 4648 §5, unpadded)")
    if len(text) % 4 == 1:
        raise ProtocolError("MALFORMED", "invalid base64url length")
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # binascii.Error and friends
        raise ProtocolError("MALFORMED", f"invalid base64url: {exc}") from exc


def is_b64u_of_length(text: object, byte_length: int) -> bool:
    """True when `text` is valid base64url decoding to exactly `byte_length` bytes."""
    if not isinstance(text, str):
        return False
    try:
        return len(b64u_decode(text)) == byte_length
    except ProtocolError:
        return False
