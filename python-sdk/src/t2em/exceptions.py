"""Exception taxonomy (ТЗ §4.5) — mirrors the TS client errors.

Integrators branch on `ProtocolError.code`, never on message text.
"""

from __future__ import annotations

from typing import Optional


class T2emError(Exception):
    """Base class for every t2em SDK error."""


class UsageError(T2emError):
    """Invalid caller input: bad URL, TTL out of range, wrong key length."""


class ProtocolError(T2emError):
    """Envelope-level failure (shape, version, or AEAD decryption).

    Attributes:
        code: ``MALFORMED`` | ``UNSUPPORTED_VERSION`` | ``DECRYPT_FAILED``
            — the §4.5 taxonomy used by the relay and the TS SDK.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class HttpError(T2emError):
    """Non-success relay response carrying the §5.2 error JSON.

    Attributes:
        status: HTTP status code.
        code: machine-readable error code from the body, if present.
        message: human-readable message from the body or a fallback.
        retry_after: parsed ``Retry-After`` header (seconds), if present.
    """

    def __init__(
        self,
        status: int,
        code: Optional[str],
        message: str,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(f"HTTP {status}{f' ({code})' if code else ''}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after
