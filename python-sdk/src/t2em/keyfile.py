"""X25519 keyfile for Mode A — TS-CLI-compatible (ТЗ §8.2, v2.1 format).

Current (§8.2) file format — JSON, UTF-8, written with 0600::

    { "version": 1, "type": "x25519",
      "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>",
      "createdAt": "<ISO-8601 Z, seconds precision>",
      "fingerprint": "<16-char base64url, §4.2.1>" }

Legacy format (pre-v2.1) is still READ for backward compatibility::

    { "v": 1, "kind": "t2em-x25519-key-v1", privateKey, publicKey }

The new format self-verifies: on load, the stored ``fingerprint`` is
recomputed from ``publicKey`` and must match — a corrupted or spliced
keyfile fails closed. Python and Node keyfiles are interchangeable.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .base64url import b64u_decode, b64u_encode
from .exceptions import UsageError
from .fingerprint import fingerprint_pubkey
from .keys import generate_x25519_keypair
from .protocol import X25519_KEY_BYTES

KEYFILE_VERSION = 1
KEYFILE_TYPE = "x25519"
# Legacy (pre-v2.1) kind marker — read for compatibility, never written.
KEYFILE_KIND = "t2em-x25519-key-v1"

WarnFn = Callable[[str], None]


@dataclass(frozen=True)
class LoadedKey:
    """Raw key material loaded from a keyfile."""

    private_key: bytes
    public_key: bytes
    format: str  # 'current' (§8.2) or 'legacy' (pre-v2.1)


def _warn_wider_permissions(path: str, warn: Optional[WarnFn]) -> None:
    if warn is None:
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return
    if mode & 0o077:
        warn(
            f"warning: keyfile permissions are {mode:03o}, expected 600 — "
            f"run: chmod 600 {path}"
        )


def _now_iso_seconds() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_keyfile(out_path: str, warn: Optional[WarnFn] = None) -> str:
    """Generate a keypair, write the §8.2 keyfile with 0600, return the public key b64u."""
    pair = generate_x25519_keypair()
    payload = {
        "version": KEYFILE_VERSION,
        "type": KEYFILE_TYPE,
        "privateKey": pair.private_key,
        "publicKey": pair.public_key,
        "createdAt": _now_iso_seconds(),
        "fingerprint": fingerprint_pubkey(pair.public_key),
    }
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.chmod(out_path, 0o600)
    _warn_wider_permissions(out_path, warn)
    return pair.public_key


def load_keyfile(path: str, warn: Optional[WarnFn] = None) -> LoadedKey:
    """Load a keyfile, validate shape, warn if permissions are too wide."""
    _warn_wider_permissions(path, warn)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageError(f"keyfile is not valid JSON: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise UsageError(f"unsupported keyfile kind: {type(payload).__name__}")

    if payload.get("version") == KEYFILE_VERSION and payload.get("type") == KEYFILE_TYPE:
        try:
            private_key = b64u_decode(payload["privateKey"])
            public_key = b64u_decode(payload["publicKey"])
        except (KeyError, TypeError) as exc:
            raise UsageError(f"keyfile is missing key material: {exc}") from exc
        if len(private_key) != X25519_KEY_BYTES or len(public_key) != X25519_KEY_BYTES:
            raise UsageError(f"keyfile keys must be {X25519_KEY_BYTES} bytes")
        # Self-verification (§8.2): the stored fingerprint must match
        # the recomputed fingerprint of the public key.
        recomputed = fingerprint_pubkey(payload["publicKey"])
        if payload.get("fingerprint") != recomputed:
            raise UsageError(
                f"keyfile fingerprint mismatch: stored {payload.get('fingerprint')}, "
                f"recomputed {recomputed}"
            )
        return LoadedKey(private_key=private_key, public_key=public_key, format="current")

    if payload.get("v") == 1 and payload.get("kind") == KEYFILE_KIND:
        try:
            private_key = b64u_decode(payload["privateKey"])
            public_key = b64u_decode(payload["publicKey"])
        except (KeyError, TypeError) as exc:
            raise UsageError(f"keyfile is missing key material: {exc}") from exc
        if len(private_key) != X25519_KEY_BYTES or len(public_key) != X25519_KEY_BYTES:
            raise UsageError(f"keyfile keys must be {X25519_KEY_BYTES} bytes")
        return LoadedKey(private_key=private_key, public_key=public_key, format="legacy")

    kind = payload.get("kind", payload.get("type", "<none>"))
    raise UsageError(f"unsupported keyfile kind: {kind}")
