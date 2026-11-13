"""X25519 keyfile for Mode A — same format as the TS CLI (ТЗ §8.2, §4.2.1).

File format (JSON, UTF-8, written with 0600)::

    { "v": 1, "kind": "t2em-x25519-key-v1",
      "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>" }

Python and Node keyfiles are interchangeable.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import Callable, Optional

from .base64url import b64u_decode, b64u_encode
from .exceptions import UsageError
from .keys import generate_x25519_keypair
from .protocol import X25519_KEY_BYTES

KEYFILE_KIND = "t2em-x25519-key-v1"

WarnFn = Callable[[str], None]


@dataclass(frozen=True)
class LoadedKey:
    """Raw key material loaded from a keyfile."""

    private_key: bytes
    public_key: bytes


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


def write_keyfile(out_path: str, warn: Optional[WarnFn] = None) -> str:
    """Generate a keypair, write the keyfile with 0600, return the public key b64u."""
    pair = generate_x25519_keypair()
    payload = {
        "v": 1,
        "kind": KEYFILE_KIND,
        "privateKey": pair.private_key,
        "publicKey": pair.public_key,
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
    if not isinstance(payload, dict) or payload.get("v") != 1 or payload.get("kind") != KEYFILE_KIND:
        kind = payload.get("kind") if isinstance(payload, dict) else type(payload).__name__
        raise UsageError(f"unsupported keyfile kind: {kind}")
    try:
        private_key = b64u_decode(payload["privateKey"])
        public_key = b64u_decode(payload["publicKey"])
    except (KeyError, TypeError) as exc:
        raise UsageError(f"keyfile is missing key material: {exc}") from exc
    if len(private_key) != X25519_KEY_BYTES or len(public_key) != X25519_KEY_BYTES:
        raise UsageError(f"keyfile keys must be {X25519_KEY_BYTES} bytes")
    return LoadedKey(private_key=private_key, public_key=public_key)
