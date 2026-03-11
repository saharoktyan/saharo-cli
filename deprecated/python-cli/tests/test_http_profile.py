from __future__ import annotations

from saharo_cli import config
from saharo_cli.http import make_client


def test_make_client_uses_profile_config(tmp_path, monkeypatch) -> None:
    def _config_dir(_: str) -> str:
        return str(tmp_path)

    monkeypatch.setattr(config, "user_config_dir", _config_dir)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '\n'.join(
            [
                'base_url = "http://default.test"',
                "",
                "[auth]",
                'token = "default-token"',
                "",
                "[profiles.dev]",
                'base_url = "http://dev.test"',
                'token = "dev-token"',
                "",
                "[profiles.prod]",
                'base_url = "http://prod.test"',
                'token = "prod-token"',
                "",
            ]
        ),
        encoding="utf-8",
    )

    cfg = config.load_config()
    captured = {}

    class _FakeClient:
        def __init__(self, client_cfg):
            captured["base_url"] = client_cfg.base_url
            captured["token"] = client_cfg.token

    monkeypatch.setattr("saharo_cli.http.SaharoClient", _FakeClient)

    make_client(cfg, profile="prod", base_url_override=None, check_compat=False)

    assert captured["base_url"] == "http://prod.test"
    assert captured["token"] == "prod-token"


def test_make_client_normalizes_base_url_override(monkeypatch) -> None:
    cfg = config.default_config()
    captured = {}

    class _FakeClient:
        def __init__(self, client_cfg):
            captured["base_url"] = client_cfg.base_url

    monkeypatch.setattr("saharo_cli.http.SaharoClient", _FakeClient)

    make_client(cfg, profile=None, base_url_override="example.com/", check_compat=False)

    assert captured["base_url"] == "https://example.com"
