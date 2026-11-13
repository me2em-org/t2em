"""Mode A — asymmetric E2EE on X25519 (ТЗ §4.2).

The sender holds the recipient's static X25519 public key out of band
(keyfile / fingerprint check / we2em registry in v2.0). The relay sees
only the sealed envelope — it can never derive the AES key (§6.3
zero-knowledge).

Key schedule (§4.2, freeze rule §4.5) — bit-compatible with
`@t2em/protocol` `mode-a.ts`::

    shared   = X25519(eph_priv, recipient_pub)          — 32B, full
    salt     = eph_pub || recipient_pub                 — 64B, UKS-safe
    aes_key  = HKDF-SHA256(shared, salt, HKDF_INFO_DROP_V1, 32)
    iv       = random 12B
    ct       = AES-256-GCM(aes_key, iv, plaintext)      — includes 16B tag
"""

from __future__ import annotations

import os
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .base64url import b64u_decode, b64u_encode
from .envelope import ModeAEnvelope
from .exceptions import ProtocolError, UsageError
from .protocol import HKDF_INFO_DROP_V1, IV_BYTES, X25519_KEY_BYTES

PubKeyInput = Union[str, bytes, bytearray]
PrivKeyInput = Union[str, bytes, bytearray]


def _as_bytes(data: PubKeyInput | PrivKeyInput, what: str) -> bytes:
    if isinstance(data, str):
        try:
            return b64u_decode(data)
        except ProtocolError:
            raise UsageError(f"{what} is not valid base64url") from None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise UsageError(f"{what} must be base64url str or raw bytes")


def _pubkey_raw(recipient_pubkey: PubKeyInput) -> bytes:
    raw = _as_bytes(recipient_pubkey, "recipient pubkey")
    if len(raw) != X25519_KEY_BYTES:
        raise UsageError(f"recipient pubkey must be {X25519_KEY_BYTES} bytes")
    return raw


def _privkey_raw(recipient_privkey: PrivKeyInput) -> bytes:
    raw = _as_bytes(recipient_privkey, "recipient privkey")
    if len(raw) != X25519_KEY_BYTES:
        raise UsageError(f"recipient privkey must be {X25519_KEY_BYTES} bytes")
    return raw


def _hkdf_drop_key(shared: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO_DROP_V1,
    ).derive(shared)


def _wipe(buf: bytearray) -> None:
    if len(buf) == 0:
        return
    buf[:] = os.urandom(len(buf))
    buf[:] = bytes(len(buf))


def _x25519_shared(priv_raw: bytes, pub_raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv_raw).exchange(
        X25519PublicKey.from_public_bytes(pub_raw)
    )


def derive_pubkey(priv_raw: bytes) -> bytes:
    """Derive the raw 32-byte X25519 public key from a raw private key."""
    return (
        X25519PrivateKey.from_private_bytes(priv_raw)
        .public_key()
        .public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )


def pack_drop_asym(plaintext: bytes, recipient_pubkey: PubKeyInput) -> ModeAEnvelope:
    """Seal `plaintext` to a static X25519 `recipient_pubkey` (§4.2 steps 1-7).

    Returns the envelope for `POST /api/v1/drop`; the share URL carries
    NO secret fragment in Mode A. The ephemeral private key never
    leaves this function alive (wiped in `finally`).
    """
    recip_raw = _pubkey_raw(recipient_pubkey)
    eph_priv = bytearray(
        X25519PrivateKey.generate()
        .private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
    )
    shared = bytearray()
    aes_key = bytearray()
    try:
        eph_pub = bytes(derive_pubkey(bytes(eph_priv)))
        shared = bytearray(_x25519_shared(bytes(eph_priv), recip_raw))
        aes_key = bytearray(_hkdf_drop_key(bytes(shared), eph_pub + recip_raw))
        iv = os.urandom(IV_BYTES)
        ciphertext = AESGCM(bytes(aes_key)).encrypt(iv, plaintext, None)
        return ModeAEnvelope(
            ephemeral_pubkey=b64u_encode(eph_pub),
            ciphertext=b64u_encode(ciphertext),
            iv=b64u_encode(iv),
        )
    finally:
        _wipe(eph_priv)
        _wipe(shared)
        _wipe(aes_key)


def unpack_drop_asym(envelope: ModeAEnvelope, recipient_privkey: PrivKeyInput) -> bytes:
    """Open a Mode A envelope with the recipient's static X25519 private key."""
    priv_raw = bytearray(_privkey_raw(recipient_privkey))
    shared = bytearray()
    aes_key = bytearray()
    try:
        eph_pub = b64u_decode(envelope.ephemeral_pubkey)
        if len(eph_pub) != X25519_KEY_BYTES:
            raise ProtocolError("MALFORMED", f"ephemeralPubKey must be {X25519_KEY_BYTES} bytes")
        recip_pub = bytes(derive_pubkey(bytes(priv_raw)))
        shared = bytearray(_x25519_shared(bytes(priv_raw), eph_pub))
        aes_key = bytearray(_hkdf_drop_key(bytes(shared), eph_pub + recip_pub))
        try:
            return AESGCM(bytes(aes_key)).decrypt(
                b64u_decode(envelope.iv), b64u_decode(envelope.ciphertext), None
            )
        except Exception as exc:
            raise ProtocolError("DECRYPT_FAILED", f"AES-256-GCM decryption failed: {type(exc).__name__}") from None
    finally:
        _wipe(priv_raw)
        _wipe(shared)
        _wipe(aes_key)
