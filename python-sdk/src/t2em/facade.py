"""Fixed public-API facade (ТЗ v2.1 §3.6): ``pack_drop`` / ``unpack_drop``.

§3.6 pins the public API — integrators dispatch through exactly these
functions instead of touching the per-mode primitives directly. The
facade also enforces the §4.5 cross-mode contract: an envelope passed
with the WRONG mode option fails closed (``MALFORMED``) — Mode A bytes
can never be opened as Mode B and vice versa.

The §3.6 sketch types ``sym_key`` as raw 32 bytes; the per-mode
``pack_drop_sym`` returns the base64url fragment string, which the
facade decodes — callers b64u-encode it into the URL ``#fragment``.
"""

from __future__ import annotations

from typing import TypedDict, Union

from .base64url import b64u_decode, b64u_encode
from .envelope import Envelope
from .exceptions import ProtocolError
from .mode_a import pack_drop_asym, unpack_drop_asym
from .mode_b import pack_drop_sym, unpack_drop_sym


class PackSymOptions(TypedDict):
    mode: str  # literal "sym"


class PackAsymOptions(TypedDict):
    mode: str  # literal "x25519"
    recipient_pubkey: bytes | str  # raw 32B or base64url (§8.3 key shape)


PackOptions = Union[PackSymOptions, PackAsymOptions]


class UnpackSymOptions(TypedDict):
    mode: str  # literal "sym"
    sym_key: bytes | str  # raw 32B or base64url


class UnpackAsymOptions(TypedDict):
    mode: str  # literal "x25519"
    recipient_privkey: bytes | str  # raw 32B or base64url (§8.3 key shape)


UnpackOptions = Union[UnpackSymOptions, UnpackAsymOptions]


class PackedDrop(TypedDict, total=False):
    envelope: Envelope
    sym_key: bytes


def _to_b64u(value: bytes | bytearray | str, what: str) -> str:
    """Accept raw bytes or a base64url key string; return base64url."""
    if isinstance(value, (bytes, bytearray)):
        return b64u_encode(bytes(value))
    if isinstance(value, str):
        return value
    raise ProtocolError("MALFORMED", f"{what} must be raw bytes or a base64url string")


def pack_drop(plaintext: bytes, options: PackOptions) -> PackedDrop:
    """Encrypt ``plaintext`` into an Envelope v1 (§3.6 ``packDrop``)."""
    if options["mode"] == "sym":
        envelope, sym_key = pack_drop_sym(plaintext)
        return {"envelope": envelope, "sym_key": b64u_decode(sym_key)}
    recipient_pubkey = options.get("recipient_pubkey")
    if recipient_pubkey is None:
        raise ProtocolError("MALFORMED", "x25519 pack options require recipient_pubkey")
    envelope = pack_drop_asym(plaintext, _to_b64u(recipient_pubkey, "recipient_pubkey"))
    return {"envelope": envelope}


def unpack_drop(envelope: Envelope, options: UnpackOptions) -> bytes:
    """Decrypt an Envelope v1 to the exact plaintext (§3.6 ``unpackDrop``)."""
    envelope_mode = getattr(envelope, "mode", None)
    if options["mode"] != envelope_mode:
        # §4.5 cross-mode: fail closed on mode mismatch (MALFORMED).
        raise ProtocolError(
            "MALFORMED",
            f"envelope mode '{envelope_mode}' does not match options mode '{options['mode']}'",
        )
    if options["mode"] == "sym":
        sym_key = options.get("sym_key")
        if sym_key is None:
            raise ProtocolError("MALFORMED", "sym unpack options require sym_key")
        return unpack_drop_sym(envelope, _to_b64u(sym_key, "sym_key"))
    recipient_privkey = options.get("recipient_privkey")
    if recipient_privkey is None:
        raise ProtocolError("MALFORMED", "x25519 unpack options require recipient_privkey")
    return unpack_drop_asym(envelope, _to_b64u(recipient_privkey, "recipient_privkey"))
