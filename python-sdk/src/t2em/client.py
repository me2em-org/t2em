"""Relay API client — `T2emClient` (ТЗ §5, §8.3).

Speaks only the JSON contract (`Accept: application/json`) — no HTML
parsing, ever (§8.1 API-first). Networking uses stdlib `urllib` only
(§8.3: zero external network deps); the transport is injectable so the
client is testable without sockets.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple, Union

from .envelope import Envelope, validate_envelope
from .exceptions import HttpError, ProtocolError, UsageError
from .mode_a import pack_drop_asym, unpack_drop_asym
from .mode_b import pack_drop_sym, unpack_drop_sym
from ._meta import SDK_USER_AGENT
from .protocol import MAX_TTL_SECONDS, MIN_TTL_SECONDS

DEFAULT_BASE_URL = "https://t2em.com"

_SECRET_RE = re.compile(r"^/s/([A-Za-z0-9_-]+)$")

Transport = Callable[[str, str, Sequence[Tuple[str, str]], Optional[bytes]], "TransportResponse"]


@dataclass(frozen=True)
class TransportResponse:
    """Raw HTTP response as seen by the transport."""

    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class CreatedDrop:
    """`{ id, url, expires_in, delete_token }` from `POST /api/v1/drop`."""

    id: str
    url: str
    expires_in: int
    delete_token: str


@dataclass(frozen=True)
class ShareUrl:
    """A share URL split into its relay id and the secret #fragment."""

    id: str
    #: None for Mode A URLs — they carry no fragment.
    fragment: Optional[str]

    @property
    def has_fragment(self) -> bool:
        return self.fragment is not None


def parse_share_url(raw: str) -> ShareUrl:
    """Parse `https://<host>/s/<id>[#<fragment>]` into its parts (§8.2)."""
    if not isinstance(raw, str) or not raw.strip():
        raise UsageError("url must be a non-empty string")
    from urllib.parse import urlsplit

    parts = urlsplit(raw.strip())
    if parts.scheme not in ("https", "http"):
        raise UsageError(f"unsupported url scheme: {parts.scheme!r}")
    if not parts.netloc:
        raise UsageError(f"invalid url: {raw}")
    match = _SECRET_RE.match(parts.path)
    if not match:
        raise UsageError("url must point to a drop: https://<host>/s/<id>[#<key>]")
    return ShareUrl(id=match.group(1), fragment=parts.fragment or None)


def _urllib_transport(timeout: float) -> Transport:
    """Default transport factory: stdlib urllib, no external deps (§8.3)."""

    def transport(
        method: str, url: str, headers: Sequence[Tuple[str, str]], body: Optional[bytes]
    ) -> TransportResponse:
        request = urllib.request.Request(url, data=body, method=method)
        for key, value in headers:
            request.add_header(key, value)
        # Identify the client (default urllib UA is rejected by CF 1010).
        request.add_header("user-agent", SDK_USER_AGENT)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return TransportResponse(
                    status=response.status,
                    headers={k: v for k, v in response.headers.items()},
                    body=response.read(),
                )
        except urllib.error.HTTPError as err:
            return TransportResponse(
                status=err.code,
                headers={k: v for k, v in err.headers.items()},
                body=err.read(),
            )

    return transport


class T2emClient:
    """Client for the t2em.com Blind Relay (ТЗ §5).

    Args:
        base_url: relay origin, e.g. ``https://t2em.com``.
        transport: injectable transport ``(method, url, headers, body)
            -> TransportResponse`` for tests; defaults to stdlib urllib.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        transport: Optional[Transport] = None,
        timeout: float = 15.0,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise UsageError("base_url must be a non-empty string")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        if transport is not None:
            self._transport: Transport = transport
        else:
            self._transport = _urllib_transport(timeout)

    # ------------------------------------------------------------------
    # Push / pull / delete
    # ------------------------------------------------------------------

    def push(
        self,
        *,
        secret: Union[str, bytes, bytearray],
        ttl: int = 300,
        recipient_pubkey: Optional[Union[str, bytes, bytearray]] = None,
    ) -> CreatedDrop:
        """Create a drop — Mode B by default, Mode A with `recipient_pubkey`.

        Returns `CreatedDrop` whose `url` carries the key in the
        `#fragment` (Mode B only). The delete token is returned here
        once — store it if you need `delete()`.
        """
        self._check_ttl(ttl)
        plaintext = self._as_plaintext(secret)

        if recipient_pubkey is not None:
            from .mode_a import pack_drop_asym

            envelope = pack_drop_asym(plaintext, recipient_pubkey)
            fragment: Optional[str] = None
        else:
            envelope, fragment = pack_drop_sym(plaintext)

        body = json.dumps({"envelope": envelope.to_dict(), "ttl": ttl}).encode("utf-8")
        response = self._transport(
            "POST",
            f"{self._base_url}/api/v1/drop",
            (("content-type", "application/json"), ("accept", "application/json")),
            body,
        )
        payload = self._json_body(response.status, response.body)
        if response.status != 201:
            raise self._http_error(response.status, response.headers, response.body, payload)
        try:
            drop_id = payload["id"]
            drop_url = payload["url"]
            expires_in = payload["expires_in"]
            delete_token = payload["delete_token"]
        except (KeyError, TypeError) as exc:
            raise ProtocolError("MALFORMED", f"relay 201 payload missing field: {exc}") from exc
        if not all(
            isinstance(x, str) for x in (drop_id, drop_url, delete_token)
        ) or not isinstance(expires_in, int):
            raise ProtocolError("MALFORMED", "relay 201 payload has unexpected field types")
        # Mode B: the relay never sees the key — the #fragment is appended
        # client-side, exactly like the Web UI and the CLI do (§4.3).
        url = drop_url if fragment is None else f"{drop_url}#{fragment}"
        return CreatedDrop(
            id=drop_id, url=url, expires_in=expires_in, delete_token=delete_token
        )

    def pull_bytes(
        self,
        url: str,
        *,
        recipient_privkey: Optional[Union[str, bytes, bytearray]] = None,
    ) -> bytes:
        """Fetch and decrypt a drop; the relay copy is consumed (GETDEL).

        Mode B needs the `#fragment` of the URL; Mode A needs the
        recipient's X25519 private key.
        """
        parts = parse_share_url(url)
        envelope = self._consume(parts.id)

        if envelope.mode == "sym":
            if not parts.fragment:
                raise UsageError(
                    "Mode B url carries no #fragment — the key is missing"
                )
            return unpack_drop_sym(envelope, parts.fragment)

        # Mode A
        if recipient_privkey is None:
            raise UsageError(
                "Mode A url requires recipient_privkey (e.g. from load_keyfile)"
            )
        return unpack_drop_asym(envelope, recipient_privkey)

    def pull_text(
        self,
        url: str,
        *,
        recipient_privkey: Optional[Union[str, bytes, bytearray]] = None,
    ) -> str:
        """`pull_bytes` decoded as UTF-8 text (ТЗ §8.3 `pull_text`)."""
        return self.pull_bytes(url, recipient_privkey=recipient_privkey).decode("utf-8")

    def delete(self, url_or_id: str, delete_token: str) -> None:
        """Delete a drop before TTL expiry (§5.4); idempotent 404 is NOT ok."""
        raw = url_or_id.strip()
        drop_id = parse_share_url(raw).id if "/s/" in raw else raw
        if not re.fullmatch(r"[A-Za-z0-9_-]+", drop_id):
            raise UsageError(f"invalid drop id: {drop_id!r}")
        if not delete_token:
            raise UsageError("delete_token is required")
        response = self._transport(
            "DELETE",
            f"{self._base_url}/api/v1/drop/{drop_id}",
            (("x-delete-token", delete_token), ("accept", "application/json")),
            None,
        )
        if response.status != 200:
            raise self._http_error(response.status, response.headers, response.body)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _consume(self, drop_id: str) -> Envelope:
        response = self._transport(
            "GET",
            f"{self._base_url}/s/{drop_id}",
            (("accept", "application/json"),),
            None,
        )
        payload = self._json_body(response.status, response.body)
        if response.status != 200:
            raise self._http_error(response.status, response.headers, response.body, payload)
        # §5.3 wire shape: { envelope: {...} }
        if not isinstance(payload, dict) or "envelope" not in payload:
            raise ProtocolError("MALFORMED", 'relay response missing "envelope" object')
        return validate_envelope(payload["envelope"])

    @staticmethod
    def _check_ttl(ttl: int) -> None:
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            raise UsageError("ttl must be an integer number of seconds")
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise UsageError(
                f"ttl must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS} seconds"
            )

    @staticmethod
    def _as_plaintext(secret: Union[str, bytes, bytearray]) -> bytes:
        if isinstance(secret, str):
            return secret.encode("utf-8")
        if isinstance(secret, (bytes, bytearray)):
            return bytes(secret)
        raise UsageError("secret must be str or bytes")

    @staticmethod
    def _json_body(status: int, body: bytes) -> Any:
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if 200 <= status < 300:
                raise ProtocolError("MALFORMED", f"relay response is not valid JSON: {exc}") from exc
            return None

    @staticmethod
    def _http_error(
        status: int,
        headers: Mapping[str, str],
        body: bytes,
        payload: Any = None,
    ) -> HttpError:
        retry_after: Optional[int] = None
        raw_retry = headers.get("retry-after") if headers else None
        if raw_retry is not None:
            try:
                retry_after = int(raw_retry)
            except ValueError:
                retry_after = None
        code: Optional[str] = None
        message = f"relay returned HTTP {status}"
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            err = payload["error"]
            if isinstance(err.get("code"), str):
                code = err["code"]
            if isinstance(err.get("message"), str):
                message = err["message"]
        return HttpError(status, code, message, retry_after)
