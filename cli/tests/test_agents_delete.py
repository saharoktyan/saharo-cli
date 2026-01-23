import os
import sys
import types

import pytest
import typer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

fake_client_mod = types.ModuleType("saharo_client")


class _FakeApiError(Exception):
    def __init__(self, status_code: int, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.details = details


fake_client_mod.ApiError = _FakeApiError
fake_client_mod.NetworkError = type("NetworkError", (Exception,), {})
fake_client_mod.SaharoClient = object
sys.modules["saharo_client"] = fake_client_mod

fake_config_mod = types.ModuleType("saharo_client.config_types")
fake_config_mod.ClientConfig = type("ClientConfig", (), {})
sys.modules["saharo_client.config_types"] = fake_config_mod
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import agents_cmd
from saharo_cli.config import AppConfig, AuthConfig


class _FakeClient:
    def __init__(self) -> None:
        self.deleted = False
        self.force = False

    def admin_agent_delete(self, agent_id: int, *, force: bool = False) -> dict:
        self.deleted = True
        self.force = force
        return {"ok": True, "agent_id": agent_id, "detached_servers": []}

    def close(self) -> None:
        return None


def _make_cfg() -> AppConfig:
    return AppConfig(base_url="http://example.test", auth=AuthConfig(token="", token_type="bearer"), agents={})


def test_delete_requires_confirmation(monkeypatch) -> None:
    client = _FakeClient()
    monkeypatch.setattr(agents_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(agents_cmd, "make_client", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(typer, "confirm", lambda *_args, **_kwargs: False)

    with pytest.raises(typer.Exit) as exc:
        agents_cmd.delete_agent(agent_id=5, yes=False, force=False, base_url=None, json_out=False)

    assert exc.value.exit_code == 0
    assert client.deleted is False


def test_delete_skips_prompt_with_yes(monkeypatch) -> None:
    client = _FakeClient()
    monkeypatch.setattr(agents_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(agents_cmd, "make_client", lambda *_args, **_kwargs: client)
    monkeypatch.setattr(typer, "confirm", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("prompted")))

    agents_cmd.delete_agent(agent_id=7, yes=True, force=True, base_url=None, json_out=True)

    assert client.deleted is True
    assert client.force is True
