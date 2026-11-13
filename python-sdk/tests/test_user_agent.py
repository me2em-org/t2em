"""Client identity: the SDK sends a proper User-Agent (CF 1010 gate)."""

from __future__ import annotations

import json

from t2em import SDK_USER_AGENT, SDK_VERSION, T2emClient
from t2em.client import TransportResponse

BASE = "https://test.local"


def test_default_transport_sends_sdk_user_agent(monkeypatch) -> None:
    """The stdlib transport must not leak the Python-urllib default UA."""
    sent: dict = {}

    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        sent["ua"] = request.get_header("User-agent")
        sent["url"] = request.full_url

        class Response:
            status = 201
            headers = {}
            body = json.dumps(
                {
                    "id": "x",
                    "url": f"{BASE}/s/x",
                    "expires_in": 60,
                    "delete_token": "t",
                }
            ).encode()

            def read(self):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Response()

    import t2em.client as client_mod

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)
    client = T2emClient(BASE)
    client.push(secret="ua-check", ttl=60)
    assert sent["ua"] == SDK_USER_AGENT
    assert sent["ua"].startswith("t2em-python-sdk/")
    assert sent["ua"] != "Python-urllib"


def test_version_is_exported() -> None:
    import t2em

    assert t2em.__version__ == SDK_VERSION
