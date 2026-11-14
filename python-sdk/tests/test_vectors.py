"""Bit-compatibility tests against `vectors/t2em-drop.v1.json` (ТЗ §4.5,
extended set per ТЗ v2.1 fix #23: negative, edge, cross-mode,
senderSignature/Ed25519 vectors + fingerprint pins).

The vectors are the TS<->Python contract: generated deterministically
by `vectors/generate.mjs` with fixed keys/IVs. Each positive vector is
checked in BOTH directions:

1. **unpack** — Python decrypts the TS-produced envelope to the
   expected plaintext (interop pull), through the §3.6 `unpack_drop`
   facade.
2. **key-schedule re-derivation** — Python re-encrypts deterministically
   (fixed keys + fixed IV → AES-GCM is deterministic) and must produce
   the very ciphertext bytes the TypeScript generator produced
   (interop push, bit-exact).

Negative and cross-mode vectors must fail with the pinned taxonomy
code; fingerprint pins must reproduce bit-exactly.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from t2em.base64url import b64u_decode, b64u_encode
from t2em.envelope import validate_envelope
from t2em.exceptions import ProtocolError
from t2em.facade import pack_drop, unpack_drop
from t2em.fingerprint import FINGERPRINT_LENGTH, fingerprint_pubkey
from t2em.mode_a import pack_drop_asym, unpack_drop_asym, derive_pubkey
from t2em.mode_b import pack_drop_sym, unpack_drop_sym
from t2em.protocol import HKDF_INFO_DROP_V1

VECTORS_PATH = Path(__file__).resolve().parents[2] / "vectors" / "t2em-drop.v1.json"


def _load() -> Dict[str, Any]:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _params() -> Dict[str, Any]:
    data = _load()
    assert data["protocol"] == 1
    assert data["hkdf_info"] == HKDF_INFO_DROP_V1.decode("ascii")
    assert data["fingerprint_length"] == 16
    return data


def _ok_vectors() -> List[Dict[str, Any]]:
    return [v for v in _load()["vectors"] if v["expected"] == "ok"]


def _error_vectors() -> List[Dict[str, Any]]:
    return [v for v in _load()["vectors"] if v["expected"] == "error"]


def _pt(raw: Dict[str, Any]) -> bytes:
    if "plaintext_b64u" in raw:
        return b64u_decode(raw["plaintext_b64u"])
    return raw["plaintext_utf8"].encode("utf-8")


def _unpack_options(raw: Dict[str, Any]) -> Dict[str, Any]:
    # Options follow the key material present in the vector: sym_key ⇒
    # sym attempt, recipient_privkey ⇒ x25519 attempt. For cross-mode
    # vectors this is deliberately the WRONG mode for the envelope —
    # that is exactly what must fail closed (§4.5).
    if "sym_key" in raw:
        return {"mode": "sym", "sym_key": b64u_decode(raw["sym_key"])}
    return {"mode": "x25519", "recipient_privkey": b64u_decode(raw["recipient_privkey"])}


def test_file_shape_contract() -> None:
    """Vector file contract: names, modes, hkdf_info, fingerprint pins."""
    data = _params()
    ok = _ok_vectors()
    errors = _error_vectors()
    names = [v["name"] for v in data["vectors"]]
    assert names[:6] == [
        "mode-a-ascii",
        "mode-b-ascii",
        "mode-a-utf8",
        "mode-b-utf8",
        "mode-a-empty",
        "mode-b-empty",
    ]
    assert len(errors) >= 10
    assert {"sym", "x25519"} == {v["envelope"]["mode"] for v in ok}
    assert any(v["name"] == "mode-a-ed25519-recv" for v in ok)
    assert any(v["name"] == "mode-a-sender-signed" for v in ok)
    assert any(v["name"] == "mode-a-64k" for v in ok)
    assert len(data["fingerprint_vectors"]) >= 2


@pytest.mark.parametrize("index", range(len(_load()["vectors"])))
def test_vector_by_index(index: int) -> None:
    """Every vector: ok → exact plaintext via facade; error → pinned code."""
    vec = _load()["vectors"][index]
    if vec["expected"] == "ok":
        envelope = validate_envelope(vec["envelope"])
        plaintext = unpack_drop(envelope, _unpack_options(vec))
        assert plaintext == _pt(vec)
        return

    # Error vector: validation itself, or the §3.6 facade, must fail
    # with the pinned taxonomy code.
    code = vec["error_code"]
    envelope: Any = None
    validation_error: ProtocolError | None = None
    try:
        envelope = validate_envelope(vec["envelope"])
    except ProtocolError as exc:
        validation_error = exc
    if validation_error is not None:
        assert validation_error.code == code
        return
    with pytest.raises(ProtocolError) as excinfo:
        unpack_drop(envelope, _unpack_options(vec))
    assert excinfo.value.code == code


@pytest.mark.parametrize("index", range(len([v for v in _load()["vectors"] if v["expected"] == "ok"])))
def test_reencrypt_is_bit_exact(index: int) -> None:
    """Python key schedule re-derivation reproduces the TS ciphertext bytes."""
    vec = _ok_vectors()[index]
    envelope = vec["envelope"]
    iv = b64u_decode(envelope["iv"])
    expected_ct = b64u_decode(envelope["ciphertext"])
    plaintext = _pt(vec)

    if envelope["mode"] == "sym":
        key = b64u_decode(vec["sym_key"])
        assert len(key) == 32
        assert AESGCM(key).encrypt(iv, plaintext, None) == expected_ct
    else:
        eph_priv = b64u_decode(vec["ephemeral_privkey"])
        if "recipient_pubkey" in vec:
            recip_pub = b64u_decode(vec["recipient_pubkey"])
        else:
            # Ed25519-converted recipient: the X25519 pubkey of the
            # converted private scalar (pinned in the vector).
            recip_pub = derive_pubkey(b64u_decode(vec["recipient_privkey"]))

        # eph_pub derived from eph_priv must equal the envelope field (bit-exact).
        assert b64u_encode(derive_pubkey(eph_priv)) == envelope["ephemeralPubKey"]

        shared = X25519PrivateKey.from_private_bytes(eph_priv).exchange(
            X25519PublicKey.from_public_bytes(recip_pub)
        )
        salt = b64u_decode(envelope["ephemeralPubKey"]) + recip_pub
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO_DROP_V1).derive(
            shared
        )
        assert AESGCM(key).encrypt(iv, plaintext, None) == expected_ct


def test_ed25519_conversion_pin() -> None:
    """mode-a-ed25519-recv pins the Ed25519→X25519 conversion bit-exactly.

    Conversion formula (noble `toMontgomerySecret`, mirrored by
    `@me2em/crypto ed25519PrivToX25519`): x25519_scalar =
    clamp(sha512(seed)[0:32]) — RFC 7748 clamping of the SHA-512
    prefix, NOT a clamp of the raw seed.
    """
    vec = next(v for v in _ok_vectors() if v["name"] == "mode-a-ed25519-recv")
    seed = b64u_decode(vec["recipient_ed25519_privkey"])
    scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    assert bytes(scalar) == b64u_decode(vec["recipient_privkey"])

    # The Ed25519 pubkey matches the seed (RFC 8032 determinism).
    ed_priv = Ed25519PrivateKey.from_private_bytes(seed)
    assert ed_priv.public_key().public_bytes_raw() == b64u_decode(vec["recipient_ed25519_pubkey"])

    # Full journey: seal with the converted pubkey, open with the converted priv.
    converted_pub = X25519PrivateKey.from_private_bytes(bytes(scalar)).public_key().public_bytes_raw()
    envelope = pack_drop_asym(b"ed25519 conversion", converted_pub)
    assert unpack_drop_asym(envelope, bytes(scalar)) == b"ed25519 conversion"


def test_sender_signed_vector_verifies() -> None:
    """senderSignature verifies against the pinned signature convention."""
    vec = next(v for v in _ok_vectors() if v["name"] == "mode-a-sender-signed")
    env = validate_envelope(vec["envelope"])
    assert env.sender_signature is not None
    assert env.sender_pubkey is not None
    message = (
        f"{env.ephemeral_pubkey}.{env.ciphertext}.{env.iv}".encode("utf-8")
    )
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(env.sender_pubkey))
    pub.verify(b64u_decode(env.sender_signature), message)  # raises on mismatch
    with pytest.raises(Exception):
        pub.verify(b64u_decode(env.sender_signature), b"tampered")


def test_fingerprint_pins() -> None:
    """Fingerprint pins: 16 chars, bit-exact in both implementations."""
    data = _params()
    for pin in data["fingerprint_vectors"]:
        fp = fingerprint_pubkey(b64u_decode(pin["pubkey_b64u"]))
        assert fp == pin["fingerprint"]
        assert len(fp) == FINGERPRINT_LENGTH


def test_python_pack_is_unpackable_by_python_roundtrip() -> None:
    """Fresh random Mode A + Mode B roundtrips through the Python stack."""
    for secret in ("sk-live-abc123", "пароль с юникодом 🤖", ""):
        plaintext = secret.encode("utf-8")

        packed = pack_drop(plaintext, {"mode": "sym"})
        assert len(packed["sym_key"]) == 32  # type: ignore[typeddict-item]
        assert unpack_drop(packed["envelope"], {"mode": "sym", "sym_key": packed["sym_key"]}) == plaintext

        from t2em.keys import generate_x25519_keypair

        kp = generate_x25519_keypair()
        packed_a = pack_drop(plaintext, {"mode": "x25519", "recipient_pubkey": kp.public_key})
        assert "sym_key" not in packed_a
        assert unpack_drop(packed_a["envelope"], {"mode": "x25519", "recipient_privkey": kp.private_key}) == plaintext


def test_high_order_dummy_key_rejected_or_consistent() -> None:
    """bytes(range(32)) sanity guard: real keypairs roundtrip; low-order fails closed."""
    from t2em.keys import generate_x25519_keypair

    kp = generate_x25519_keypair()
    env = pack_drop_asym(b"x", kp.public_key)
    with pytest.raises(ProtocolError):
        unpack_drop_asym(env, b"\x00" * 32)  # wrong key must fail closed


def test_b64u_strict_rejects_padding_and_std_alphabet() -> None:
    """Strict decoder: '+'/'/' and '=' are rejected (RFC 4648 §5 unpadded)."""
    raw = bytes(range(0, 250, 7))[:31]  # 31 bytes ⇒ standard base64 carries '=' padding
    enc = b64u_encode(raw)
    assert "+" not in enc and "/" not in enc and "=" not in enc
    assert b64u_decode(enc) == raw
    padded = base64.urlsafe_b64encode(raw).decode()
    assert padded.endswith("=")
    with pytest.raises(ProtocolError):
        b64u_decode(padded)  # '=' padding rejected
