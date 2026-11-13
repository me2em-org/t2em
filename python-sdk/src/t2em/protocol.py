"""Protocol v1 wire constants (ТЗ §4) — mirror of `@t2em/protocol`.

FREEZE RULE (§4.5): `HKDF_INFO_DROP_V1` feeds HKDF key derivation. It
may never be edited in place — key rotation happens through a new
`/v2` info string and a new `envelope.v`.
"""

T2EM_PROTOCOL_VERSION: int = 1

#: Drop lifetime bounds in seconds (ТЗ §4, §6.1).
MIN_TTL_SECONDS: int = 60
MAX_TTL_SECONDS: int = 900

#: HKDF info string for drop key derivation (ТЗ §4.2 step 5).
HKDF_INFO_DROP_V1: bytes = b"me2em/crypto/v1/t2em-drop"

#: AES-256-GCM key length in bytes (§11.2).
SYM_KEY_BYTES: int = 32

#: GCM tag length appended to the ciphertext (§5.2 envelope checks).
GCM_TAG_BYTES: int = 16

#: X25519 public/private key length in bytes (RFC 7748).
X25519_KEY_BYTES: int = 32

#: 12-byte IV for every AES-GCM encryption (§4.2, §4.3).
IV_BYTES: int = 12
