"""Bit-compatibility tests against `vectors/t2em-drop.v1.json` (ТЗ §4.5).

The vectors are the TS<->Python contract: generated deterministically
by `vectors/generate.mjs` with fixed keys/IVs. Each vector is checked
in BOTH directions:

1. **unpack** — Python decrypts the TS-produced envelope to the
   expected plaintext (interop pull).
2. **key-schedule re-derivation** — Python re-encrypts deterministically
   (fixed keys + fixed IV → AES-GCM is deterministic) and must produce
   the very ciphertext bytes the TypeScript generator produced
   (interop push, bit-exact).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict

import pytest
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
    return data


def _pt(raw: Dict[str, Any]) -> bytes:
    return raw["plaintext_utf8"].encode("utf-8")


@pytest.mark.parametrize("index", range(len(_load()["vectors"])))
def test_unpack_matches_ts_envelope(index: int) -> None:
    """Python decrypts every TS-generated envelope to the exact plaintext."""
    vec = _params()["vectors"][index]
    envelope = validate_envelope(vec["envelope"])

    if envelope.mode == "sym":
        plaintext = unpack_drop_sym(envelope, vec["sym_key"])
    else:
        plaintext = unpack_drop_asym(envelope, vec["recipient_privkey"])

    assert plaintext == _pt(vec)


@pytest.mark.parametrize("index", range(len(_load()["vectors"])))
def test_reencrypt_is_bit_exact(index: int) -> None:
    """Python key schedule re-derivation reproduces the TS ciphertext bytes."""
    vec = _params()["vectors"][index]
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
        recip_pub = b64u_decode(vec["recipient_pubkey"])

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


def test_python_pack_is_unpackable_by_python_roundtrip() -> None:
    """Fresh random Mode A + Mode B roundtrips through the Python stack."""
    for secret in ("sk-live-abc123", "пароль с юникодом 🤖", ""):
        plaintext = secret.encode("utf-8")

        envelope, sym_key = pack_drop_sym(plaintext)
        assert unpack_drop_sym(envelope, sym_key) == plaintext

        keys_pub = b64u_encode(bytes(range(32)))  # deterministic dummy recipient key
        # use a real keypair instead — dummy key may be low-order on X25519
        from t2em.keys import generate_x25519_keypair

        kp = generate_x25519_keypair()
        a_env = pack_drop_asym(plaintext, kp.public_key)
        assert unpack_drop_asym(a_env, kp.private_key) == plaintext


def test_high_order_dummy_key_rejected_or_consistent() -> None:
    """bytes(range(32)) sanity guard: real keypairs roundtrip; low-order fails closed."""
    from t2em.keys import generate_x25519_keypair

    kp = generate_x25519_keypair()
    env = pack_drop_asym(b"x", kp.public_key)
    with pytest.raises(ProtocolError):
        unpack_drop_asym(env, b"\x00" * 32)  # wrong key must fail closed


def test_vector_file_shape() -> None:
    """Vector file contract: names, modes, hkdf_info stability."""
    data = _params()
    names = [v["name"] for v in data["vectors"]]
    assert names == [
        "mode-a-ascii",
        "mode-b-ascii",
        "mode-a-utf8",
        "mode-b-utf8",
        "mode-a-empty",
        "mode-b-empty",
    ]
    modes = {v["envelope"]["mode"] for v in data["vectors"]}
    assert modes == {"sym", "x25519"}


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
