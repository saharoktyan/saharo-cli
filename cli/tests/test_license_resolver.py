import httpx

from saharo_cli.license_resolver import resolve_entitlements


def test_resolve_entitlements_parses_versions(monkeypatch) -> None:
    def _fake_get(_url: str, _headers=None, _timeout=None) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "allowed_major": 2,
                "resolved_versions": {
                    "host": "1.2.3",
                    "agent": "2.3.4",
                    "cli": "3.4.5",
                    "api": "0.0.1",
                },
            },
        )

    monkeypatch.setattr(httpx, "get", _fake_get)
    entitlements = resolve_entitlements("https://lic.example.test", "key")
    assert entitlements.allowed_major == 2
    assert entitlements.resolved_versions["host"] == "1.2.3"
    assert entitlements.resolved_versions["agent"] == "2.3.4"
    assert entitlements.resolved_versions["cli"] == "3.4.5"
    assert entitlements.resolved_versions["api"] == "0.0.1"
