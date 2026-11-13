"""Mode B — Zero-Key Bootstrap (ТЗ §4.3).

`sym_key` never touches the relay: it travels to the recipient inside
the URL `#fragment` (RFC 3986 — fragments are not sent to servers).
Secret byte buffers are best-effort wiped two-pass (random then zeros,
§4.4) — a mitigation, not a guarantee (immutable `bytes` copies made
by the interpreter cannot be scrubbed).
"""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base64url import b64u_decode, b64u_encode
from .envelope import ModeBEnvelope
from .exceptions import ProtocolError
from .protocol import IV_BYTES, SYM_KEY_BYTES


def _wipe(buf: bytearray) -> None:
    """Two-pass wipe (§4.4): random noise first, then zeros."""
    if len(buf) == 0:
        return
    buf[:] = os.urandom(len(buf))
    buf[:] = bytes(len(buf))


def pack_drop_sym(plaintext: bytes) -> Tuple[ModeBEnvelope, str]:
    """Encrypt `plaintext` under a fresh random symmetric key (Mode B).

    Returns the envelope plus the base64url(32B) `sym_key` that goes
    into the URL `#fragment`, never to the server.
    """
    sym_key = bytearray(os.urandom(SYM_KEY_BYTES))
    try:
        iv = os.urandom(IV_BYTES)
        ciphertext = AESGCM(bytes(sym_key)).encrypt(iv, plaintext, None)
        return ModeBEnvelope(ciphertext=b64u_encode(ciphertext), iv=b64u_encode(iv)), b64u_encode(
            bytes(sym_key)
        )
    finally:
        _wipe(sym_key)


def unpack_drop_sym(envelope: ModeBEnvelope, sym_key: str) -> bytes:
    """Decrypt a Mode B envelope with the key taken from the URL fragment."""
    sym_key_bytes = bytearray(b64u_decode(sym_key))
    try:
        if len(sym_key_bytes) != SYM_KEY_BYTES:
            raise ProtocolError("MALFORMED", f"sym key must be {SYM_KEY_BYTES} bytes")
        return AESGCM(bytes(sym_key_bytes)).decrypt(
            b64u_decode(envelope.iv), b64u_decode(envelope.ciphertext), None
        )
    finally:
        _wipe(sym_key_bytes)
