from __future__ import annotations

from saharo_client.config_types import ClientConfig
from saharo_client.transport import Transport


class _FakeResponse:
    status_code = 200

    def __init__(self, payload: dict):
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


class _FakeHttpxClient:
    def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        self.calls: list[dict] = []

    def close(self) -> None:
        return None

    def request(self, method: str, path: str, *, json=None, headers=None):  # noqa: ANN001
        self.calls.append({
            "method": method,
            "path": path,
            "json": json,
            "headers": dict(headers or {}),
        })
        return _FakeResponse({"ok": True})


def test_transport_sets_unique_request_id_header(monkeypatch) -> None:
    fake_client = _FakeHttpxClient()

    def _make_client(*args, **kwargs):  # noqa: ANN002, ANN003
        return fake_client

    monkeypatch.setattr("saharo_client.transport.httpx.Client", _make_client)

    cfg = ClientConfig(base_url="http://example.test", token="tkn", timeout_s=5)
    t = Transport(cfg)
    try:
        t.request("GET", "/health")
        t.request("GET", "/version")
    finally:
        t.close()

    assert len(fake_client.calls) == 2
    h1 = fake_client.calls[0]["headers"].get("X-Request-Id", "")
    h2 = fake_client.calls[1]["headers"].get("X-Request-Id", "")
    assert len(h1) == 32
    assert len(h2) == 32
    assert h1 != h2
