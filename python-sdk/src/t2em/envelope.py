"""Envelope shapes and validation — mirror of `@t2em/protocol` `envelope.ts`.

The relay validates envelopes on write; the SDK validates envelopes it
pulls before decrypting, so a hostile/broken relay cannot feed the
crypto layer arbitrary bytes (§11.4 injection protection).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Union

from .base64url import b64u_decode, is_b64u_of_length
from .exceptions import ProtocolError
from .protocol import GCM_TAG_BYTES, IV_BYTES, T2EM_PROTOCOL_VERSION, X25519_KEY_BYTES

MAX_IV_BYTES = IV_BYTES
MAX_EPHEMERAL_PUBKEY_BYTES = X25519_KEY_BYTES


@dataclass(frozen=True)
class ModeBEnvelope:
    """Mode B — symmetric #fragment bootstrap (ТЗ §4.3)."""

    ciphertext: str
    iv: str
    mode: str = "sym"
    v: int = T2EM_PROTOCOL_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {"v": self.v, "mode": self.mode, "ciphertext": self.ciphertext, "iv": self.iv}


@dataclass(frozen=True)
class ModeAEnvelope:
    """Mode A — asymmetric E2EE on X25519 (ТЗ §4.2)."""

    ephemeral_pubkey: str
    ciphertext: str
    iv: str
    mode: str = "x25519"
    v: int = T2EM_PROTOCOL_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.v,
            "mode": self.mode,
            "ephemeralPubKey": self.ephemeral_pubkey,
            "ciphertext": self.ciphertext,
            "iv": self.iv,
        }


Envelope = Union[ModeAEnvelope, ModeBEnvelope]

_FORBIDDEN_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _safe_json(value: Any) -> Dict[str, Any]:
    """Prototype-safe parse guard (§11.4): reject poisoned keys outright."""
    if not isinstance(value, dict):
        raise ProtocolError("MALFORMED", "envelope must be a JSON object")
    if any(k in _FORBIDDEN_KEYS for k in value):
        raise ProtocolError("MALFORMED", "forbidden key in envelope")
    return value


def validate_envelope(value: Any) -> Envelope:
    """Validate an unknown value as a protocol-v1 envelope.

    Raises `ProtocolError` with code ``UNSUPPORTED_VERSION`` or
    ``MALFORMED`` on any deviation; returns the narrowed envelope
    otherwise.
    """
    v = _safe_json(value)

    if v.get("v") != T2EM_PROTOCOL_VERSION:
        if isinstance(v.get("v"), int):
            raise ProtocolError("UNSUPPORTED_VERSION", f"envelope.v={v.get('v')}")
        raise ProtocolError("MALFORMED", "envelope.v must be a number")

    ciphertext = v.get("ciphertext")
    if not isinstance(ciphertext, str) or len(ciphertext) == 0:
        raise ProtocolError("MALFORMED", "ciphertext must be a non-empty base64url string")
    iv = v.get("iv")
    if not isinstance(iv, str) or not is_b64u_of_length(iv, MAX_IV_BYTES):
        raise ProtocolError("MALFORMED", f"iv must be base64url of exactly {MAX_IV_BYTES} bytes")
    try:
        ct_len = len(b64u_decode(ciphertext))
    except ProtocolError:
        raise ProtocolError("MALFORMED", "ciphertext is not valid base64url") from None
    if ct_len < GCM_TAG_BYTES:
        raise ProtocolError("MALFORMED", f"ciphertext shorter than GCM tag ({GCM_TAG_BYTES} bytes)")

    mode = v.get("mode")
    if mode == "sym":
        return ModeBEnvelope(ciphertext=ciphertext, iv=iv)

    if mode == "x25519":
        eph = v.get("ephemeralPubKey")
        if not isinstance(eph, str) or not is_b64u_of_length(eph, MAX_EPHEMERAL_PUBKEY_BYTES):
            raise ProtocolError(
                "MALFORMED",
                f"ephemeralPubKey must be base64url of exactly {MAX_EPHEMERAL_PUBKEY_BYTES} bytes",
            )
        return ModeAEnvelope(ephemeral_pubkey=eph, ciphertext=ciphertext, iv=iv)

    raise ProtocolError("MALFORMED", f"unknown envelope.mode: {mode!r}")


def parse_envelope_json(text: str) -> Envelope:
    """Parse + validate an envelope from relay JSON (safe re-raise)."""
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("MALFORMED", f"relay response is not valid JSON: {exc}") from exc
    return validate_envelope(raw)
