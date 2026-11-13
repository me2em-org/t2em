"""`T2emClient` tests — full journeys against a fake transport (no sockets).

The fake transport records requests and replays canned relay
responses matching the §5.2/§5.3/§5.4 wire contract, so the client
layer is verified independently of any HTTP stack.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from t2em import (
    HttpError,
    ProtocolError,
    T2emClient,
    UsageError,
    generate_x25519_keypair,
)
from t2em.client import TransportResponse, parse_share_url
from t2em.envelope import validate_envelope
from t2em.mode_b import unpack_drop_sym
from t2em.mode_a import unpack_drop_asym

BASE = "https://test.local"
UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


@dataclass
class RecordedRequest:
    method: str
    url: str
    headers: Tuple[Tuple[str, str], ...]
    body: Optional[bytes]

    def json(self) -> Any:
        assert self.body is not None
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


class FakeTransport:
    """Records every request; answers via a handler callable."""

    def __init__(self) -> None:
        self.requests: List[RecordedRequest] = []
        self.handler = self.default_handler
        self.default_status = 201
        self.default_payload: Dict[str, Any] = {}

    def __call__(
        self, method: str, url: str, headers: Sequence[Tuple[str, str]], body: Optional[bytes]
    ) -> TransportResponse:
        self.requests.append(RecordedRequest(method, url, tuple(headers), body))
        return self.handler(self.requests[-1])

    def default_handler(self, req: RecordedRequest) -> TransportResponse:
        payload = dict(self.default_payload)
        if req.method == "POST" and req.url.endswith("/api/v1/drop"):
            payload.setdefault("id", "11111111-2222-3333-4444-555555555555")
            payload.setdefault("url", f"{BASE}/s/11111111-2222-3333-4444-555555555555")
            payload.setdefault("expires_in", 300)
            payload.setdefault("delete_token", "dt-1")
            return TransportResponse(201, {}, json.dumps(payload).encode())
        return TransportResponse(self.default_status, {}, json.dumps(payload).encode())


def make_client() -> Tuple[T2emClient, FakeTransport]:
    transport = FakeTransport()
    return T2emClient(BASE, transport=transport), transport


class TestPushModeB:
    def test_push_posts_envelope_and_ttl(self) -> None:
        client, fake = make_client()
        drop = client.push(secret="sk-live-abc", ttl=300)

        req = fake.requests[0]
        assert req.method == "POST"
        assert req.url == f"{BASE}/api/v1/drop"
        assert req.header("content-type") == "application/json"
        body = req.json()
        assert body["ttl"] == 300
        env = validate_envelope(body["envelope"])
        assert env.mode == "sym"
        # SDK appends the #fragment client-side (relay never sees the key).
        assert re.fullmatch(rf"{BASE}/s/{UUID_RE}#[A-Za-z0-9_-]{{43}}", drop.url)
        assert drop.delete_token == "dt-1"
        assert drop.expires_in == 300

    def test_push_never_leaks_fragment_to_relay(self) -> None:
        """The #fragment key must never appear in any relay request body."""
        client, fake = make_client()
        client.push(secret="topsecret-value", ttl=60)
        for req in fake.requests:
            if req.body is not None:
                assert b"topsecret-value" not in req.body
                body = req.json()
                assert "sym_key" not in body and "fragment" not in body

    def test_full_roundtrip_over_fake_relay(self) -> None:
        """Push → canned relay → pull, exercising the real crypto stack."""
        fake = FakeTransport()
        stored: Dict[str, Any] = {}

        def handler(req: RecordedRequest) -> TransportResponse:
            if req.method == "POST":
                stored.update(req.json()["envelope"])
                assert req.url.endswith("/api/v1/drop")
                drop_id = "99999999-8888-7777-6666-555555555555"
                return TransportResponse(
                    201,
                    {},
                    json.dumps(
                        {
                            "id": drop_id,
                            "url": f"{BASE}/s/{drop_id}",
                            "expires_in": 60,
                            "delete_token": "tok",
                        }
                    ).encode(),
                )
            return TransportResponse(
                200, {}, json.dumps({"envelope": stored}).encode()
            )

        fake.handler = handler
        client = T2emClient(BASE, transport=fake)
        drop = client.push(secret="roundtrip", ttl=60)
        # SDK appends the #fragment client-side — the url is complete now.
        url = drop.url
        assert url.count("#") == 1
        assert client.pull_text(url) == "roundtrip"

    def test_ttl_bounds_enforced(self) -> None:
        client, fake = make_client()
        for bad in (59, 901, 0, -1):
            with pytest.raises(UsageError):
                client.push(secret="x", ttl=bad)
        assert fake.requests == []  # rejected before any network call

    def test_ttl_bounds_accept_limits(self) -> None:
        client, fake = make_client()
        client.push(secret="x", ttl=60)
        client.push(secret="x", ttl=900)
        assert len(fake.requests) == 2

    def test_secret_rejects_non_string_bytes(self) -> None:
        client, _ = make_client()
        with pytest.raises(UsageError):
            client.push(secret=123)  # type: ignore[arg-type]

    def test_bytes_secret_accepted(self) -> None:
        client, fake = make_client()
        client.push(secret=b"\x00\x01binary", ttl=300)
        sent = fake.requests[0].json()
        assert sent["envelope"]["mode"] == "sym"


class TestPull:
    def test_pull_sends_json_accept_and_parses_envelope(self) -> None:
        from t2em.mode_b import pack_drop_sym

        envelope, frag = pack_drop_sym(b"hello")
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(
            200, {}, json.dumps({"envelope": envelope.to_dict()}).encode()
        )
        client = T2emClient(BASE, transport=fake)

        out = client.pull_text(f"{BASE}/s/{'a' * 36}#{frag}")
        assert out == "hello"
        req = fake.requests[0]
        assert req.method == "GET"
        assert req.header("accept") == "application/json"
        assert req.body is None

    def test_pull_mode_b_without_fragment_is_usage_error(self) -> None:
        from t2em.mode_b import pack_drop_sym

        envelope, _ = pack_drop_sym(b"x")
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(
            200, {}, json.dumps({"envelope": envelope.to_dict()}).encode()
        )
        client = T2emClient(BASE, transport=fake)
        with pytest.raises(UsageError, match="fragment"):
            client.pull_text(f"{BASE}/s/{'a' * 36}")

    def test_pull_mode_a_requires_privkey(self) -> None:
        kp = generate_x25519_keypair()
        from t2em.mode_a import pack_drop_asym

        envelope = pack_drop_asym(b"asym secret", kp.public_key)
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(
            200, {}, json.dumps({"envelope": envelope.to_dict()}).encode()
        )
        client = T2emClient(BASE, transport=fake)
        url = f"{BASE}/s/{'a' * 36}"  # Mode A: no fragment
        with pytest.raises(UsageError, match="recipient_privkey"):
            client.pull_text(url)
        assert client.pull_text(url, recipient_privkey=kp.private_key) == "asym secret"

    def test_pull_404_maps_to_http_error(self) -> None:
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(
            404,
            {"retry-after": "7"},
            json.dumps({"error": {"code": "NOT_FOUND", "message": "no such drop"}}).encode(),
        )
        client = T2emClient(BASE, transport=fake)
        with pytest.raises(HttpError) as err:
            client.pull_text(f"{BASE}/s/{'a' * 36}#frag")
        assert err.value.status == 404
        assert err.value.code == "NOT_FOUND"
        assert err.value.retry_after == 7
        assert "no such drop" in err.value.message

    def test_pull_429_rate_limit_with_retry_after(self) -> None:
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(
            429, {"retry-after": "30"}, json.dumps({"error": {"code": "RATE_LIMITED"}}).encode()
        )
        client = T2emClient(BASE, transport=fake)
        with pytest.raises(HttpError) as err:
            client.pull_text(f"{BASE}/s/{'a' * 36}#frag")
        assert err.value.status == 429
        assert err.value.retry_after == 30

    def test_pull_non_json_body_500(self) -> None:
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(500, {}, b"<html>boom</html>")
        client = T2emClient(BASE, transport=fake)
        with pytest.raises(HttpError) as err:
            client.pull_text(f"{BASE}/s/{'a' * 36}#frag")
        assert err.value.status == 500
        assert err.value.code is None

    def test_pull_relay_sends_non_envelope_json(self) -> None:
        fake = FakeTransport()
        fake.handler = lambda req: TransportResponse(200, {}, b'{"hello": "world"}')
        client = T2emClient(BASE, transport=fake)
        with pytest.raises(ProtocolError):
            client.pull_text(f"{BASE}/s/{'a' * 36}#frag")


class TestParseShareUrl:
    def test_parses_id_and_fragment(self) -> None:
        parts = parse_share_url("https://t2em.com/s/abcDEF123-_#kYz")
        assert parts.id == "abcDEF123-_"
        assert parts.fragment == "kYz"

    def test_mode_a_url_has_no_fragment(self) -> None:
        parts = parse_share_url("https://t2em.com/s/abc123")
        assert parts.fragment is None
        assert not parts.has_fragment

    def test_rejects_non_drop_paths(self) -> None:
        for bad in (
            "https://t2em.com/",
            "https://t2em.com/s/",
            "https://t2em.com/api/v1/drop",
            "ftp://t2em.com/s/abc",
            "https://t2em.com/s/abc/extra",
            "not a url at all",
        ):
            with pytest.raises(UsageError):
                parse_share_url(bad)


class TestDelete:
    def test_delete_sends_token_header(self) -> None:
        client, fake = make_client()
        fake.default_status = 200

        client.delete(f"{BASE}/s/{'a' * 36}", "tok-123")
        req = fake.requests[0]
        assert req.method == "DELETE"
        assert req.url == f"{BASE}/api/v1/drop/{'a' * 36}"
        assert req.header("x-delete-token") == "tok-123"

    def test_delete_accepts_bare_id(self) -> None:
        client, fake = make_client()
        fake.default_status = 200
        client.delete("abc123-_x", "tok")
        assert fake.requests[0].url.endswith("/api/v1/drop/abc123-_x")

    def test_delete_requires_token(self) -> None:
        client, _ = make_client()
        with pytest.raises(UsageError):
            client.delete(f"{BASE}/s/{'a' * 36}", "")

    def test_delete_failure_raises_http_error(self) -> None:
        client, fake = make_client()
        fake.default_status = 403
        fake.default_payload = {"error": {"code": "FORBIDDEN"}}
        with pytest.raises(HttpError) as err:
            client.delete(f"{BASE}/s/{'a' * 36}", "wrong")
        assert err.value.status == 403


class TestUrlValidation:
    def test_push_rejects_bad_base_url(self) -> None:
        with pytest.raises(UsageError):
            T2emClient("   ")
