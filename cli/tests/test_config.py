from saharo_cli import config


def test_save_config_omits_none_agent_id(tmp_path, monkeypatch) -> None:
    def _config_dir(_: str) -> str:
        return str(tmp_path)

    monkeypatch.setattr(config, "user_config_dir", _config_dir)
    cfg = config.AppConfig(
        base_url="http://example.com",
        auth=config.AuthConfig(token="token", token_type="bearer"),
        agents={
            "agent": config.AgentConfig(
                agent_id=None,
                agent_secret="secret",
                invite_token="invite",
                note="note",
                created_at="2024-01-01",
                expires_at="2024-02-01",
            )
        },
    )

    path = config.save_config(cfg)
    contents = tmp_path.joinpath("config.toml").read_text(encoding="utf-8")

    assert path.endswith("config.toml")
    assert "agent_id =" not in contents


def test_normalize_base_url_defaults_to_https() -> None:
    assert config.normalize_base_url("example.com") == "https://example.com"


def test_normalize_base_url_defaults_to_http_for_localhost() -> None:
    assert config.normalize_base_url("127.0.0.1:8010") == "http://127.0.0.1:8010"


def test_normalize_base_url_strips_trailing_slash() -> None:
    assert config.normalize_base_url("https://example.com/") == "https://example.com"
