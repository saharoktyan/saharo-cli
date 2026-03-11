import os
import sys
import types

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    import saharo_client  # noqa: F401
except ImportError:
    fake_client_mod = types.ModuleType("saharo_client")

    class _FakeApiError(Exception):
        def __init__(self, status_code: int, message: str, details: str | None = None) -> None:
            super().__init__(message)
            self.status_code = status_code
            self.details = details

    fake_client_mod.ApiError = _FakeApiError
    fake_client_mod.AuthError = type("AuthError", (Exception,), {})
    fake_client_mod.NetworkError = type("NetworkError", (Exception,), {})
    fake_client_mod.SaharoClient = object
    sys.modules.setdefault("saharo_client", fake_client_mod)

    fake_config_mod = types.ModuleType("saharo_client.config_types")

    class _FakeClientConfig:
        def __init__(self, base_url: str = "", token: str | None = None) -> None:
            self.base_url = base_url
            self.token = token

    fake_config_mod.ClientConfig = _FakeClientConfig
    sys.modules.setdefault("saharo_client.config_types", fake_config_mod)

sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import invite_cmd
from saharo_cli.config import AppConfig, AuthConfig


def test_prompt_password_with_confirmation_match(monkeypatch) -> None:
    responses = iter(["password123", "password123"])

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(invite_cmd.typer, "prompt", _prompt)
    monkeypatch.setattr(invite_cmd.console, "err", lambda *_args, **_kwargs: None)
    assert invite_cmd._prompt_password_with_confirmation(None) == "password123"


def test_prompt_password_with_confirmation_retries_on_mismatch(monkeypatch) -> None:
    responses = iter(["password123", "nope", "password123", "password123"])
    messages: list[str] = []

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(invite_cmd.typer, "prompt", _prompt)
    monkeypatch.setattr(invite_cmd.console, "err", lambda msg: messages.append(str(msg)))
    assert invite_cmd._prompt_password_with_confirmation(None) == "password123"
    assert any("Passwords do not match" in msg for msg in messages)


def test_prompt_password_with_confirmation_too_many_attempts(monkeypatch) -> None:
    responses = iter(["short", "short", "short", "short", "short", "short"])
    messages: list[str] = []

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(invite_cmd.typer, "prompt", _prompt)
    monkeypatch.setattr(invite_cmd.console, "err", lambda msg: messages.append(str(msg)))
    with pytest.raises(invite_cmd.typer.Exit):
        invite_cmd._prompt_password_with_confirmation(None, min_length=8)
    assert any("Too many attempts" in msg for msg in messages)


def test_accept_invite_uses_confirmed_password(monkeypatch) -> None:
    cfg = AppConfig(
        base_url="http://example.test",
        auth=AuthConfig(token="", token_type="bearer"),
        agents={},
    )
    responses = iter(["password123", "password123"])

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(invite_cmd.typer, "prompt", _prompt)
    monkeypatch.setattr(invite_cmd.console, "err", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(invite_cmd.console, "ok", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(invite_cmd.console, "info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(invite_cmd, "load_config", lambda: cfg)
    monkeypatch.setattr(invite_cmd, "save_config", lambda *_args, **_kwargs: "/tmp/config.toml")

    captured: dict[str, str] = {}

    class _FakeClient:
        def invites_claim_local(self, *, token, username, password, device_label, platform):
            captured["password"] = password
            return {"token": "jwt"}

        def close(self) -> None:
            return None

    monkeypatch.setattr(invite_cmd, "make_client", lambda *_args, **_kwargs: _FakeClient())

    invite_cmd.accept_invite(
        invite_token="invite-token",
        username="new-user",
        password=None,
        device_label="device",
        base_url=None,
    )

    assert captured["password"] == "password123"
