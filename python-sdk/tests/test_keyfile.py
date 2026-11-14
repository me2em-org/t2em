"""Keyfile tests — format parity with the TS CLI (`packages/cli/src/keys.ts`).

Covers the §8.2 v2.1 format (version/type/createdAt/fingerprint, with
fingerprint self-verification) and backward compatibility with the
pre-v2.1 legacy format (v/kind).
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from t2em import UsageError, load_keyfile, write_keyfile
from t2em.fingerprint import fingerprint_pubkey
from t2em.keyfile import KEYFILE_TYPE, KEYFILE_VERSION
from t2em.mode_a import derive_pubkey


def test_write_and_load_roundtrip(tmp_path) -> None:
    path = str(tmp_path / "agent.key")
    pub_b64u = write_keyfile(path)

    payload = json.loads(open(path, encoding="utf-8").read())
    assert payload["version"] == KEYFILE_VERSION
    assert payload["type"] == KEYFILE_TYPE
    assert payload["publicKey"] == pub_b64u
    assert payload["createdAt"].endswith("Z")
    assert payload["fingerprint"] == fingerprint_pubkey(pub_b64u)
    assert len(payload["fingerprint"]) == 16  # §4.2.1

    loaded = load_keyfile(path)
    assert loaded.format == "current"
    assert len(loaded.private_key) == 32
    assert len(loaded.public_key) == 32
    from t2em.base64url import b64u_encode

    assert b64u_encode(derive_pubkey(loaded.private_key)) == pub_b64u
    assert b64u_encode(loaded.public_key) == pub_b64u


def test_written_with_0600(tmp_path) -> None:
    path = str(tmp_path / "agent.key")
    write_keyfile(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0, f"keyfile too wide: {mode:03o}"


def test_wide_permissions_warn(tmp_path) -> None:
    path = str(tmp_path / "agent.key")
    write_keyfile(path)
    os.chmod(path, 0o644)
    warnings = []
    load_keyfile(path, warn=warnings.append)
    assert warnings and "chmod 600" in warnings[0]

    os.chmod(path, 0o600)
    warnings2 = []
    load_keyfile(path, warn=warnings2.append)
    assert warnings2 == []


def test_fingerprint_mismatch_rejected(tmp_path) -> None:
    """A spliced/corrupted keyfile must fail closed (§8.2 self-verification)."""
    path = str(tmp_path / "spliced.key")
    write_keyfile(path)
    payload = json.loads(open(path, encoding="utf-8").read())
    payload["fingerprint"] = "0" * 16
    path2 = tmp_path / "spliced2.key"
    path2.write_text(json.dumps(payload))
    with pytest.raises(UsageError, match="fingerprint mismatch"):
        load_keyfile(str(path2))


def test_legacy_format_still_loads(tmp_path) -> None:
    """Pre-v2.1 keyfiles (v/kind) load without the fingerprint check."""
    legacy = {
        "v": 1,
        "kind": "t2em-x25519-key-v1",
        "privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }
    path = tmp_path / "legacy.key"
    path.write_text(json.dumps(legacy))
    loaded = load_keyfile(str(path))
    assert loaded.format == "legacy"
    assert len(loaded.private_key) == 32


def test_bad_kind_rejected(tmp_path) -> None:
    path = tmp_path / "weird.key"
    path.write_text(json.dumps({"v": 1, "kind": "other-kind", "privateKey": "", "publicKey": ""}))
    with pytest.raises(UsageError, match="kind"):
        load_keyfile(str(path))


def test_not_json_rejected(tmp_path) -> None:
    path = tmp_path / "garbage.key"
    path.write_text("not json at all")
    with pytest.raises(UsageError, match="not valid JSON"):
        load_keyfile(str(path))


def test_wrong_lengths_rejected(tmp_path) -> None:
    path = tmp_path / "short.key"
    path.write_text(
        json.dumps({"version": 1, "type": KEYFILE_TYPE, "privateKey": "AAAA", "publicKey": "AAAA"})
    )
    with pytest.raises(UsageError, match="32 bytes"):
        load_keyfile(str(path))


def test_python_and_node_keyfiles_are_interchangeable(tmp_path) -> None:
    """The JSON shape matches the TS §8.2 keyfile field-for-field."""
    path = str(tmp_path / "agent.key")
    write_keyfile(path)
    payload = json.loads(open(path, encoding="utf-8").read())
    assert set(payload.keys()) == {"version", "type", "privateKey", "publicKey", "createdAt", "fingerprint"}
