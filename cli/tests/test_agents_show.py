import os
import sys
import types

import pytest
import typer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class _FakeApiError(Exception):
    def __init__(self, status_code: int, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.details = details

try:
    import saharo_client
    _FakeApiError = saharo_client.ApiError
except ImportError:
    fake_client_mod = types.ModuleType("saharo_client")

    fake_client_mod.ApiError = _FakeApiError
    fake_client_mod.AuthError = type("AuthError", (Exception,), {})
    fake_client_mod.NetworkError = type("NetworkError", (Exception,), {})
    fake_client_mod.SaharoClient = object
    sys.modules["saharo_client"] = fake_client_mod

    fake_config_mod = types.ModuleType("saharo_client.config_types")
    fake_config_mod.ClientConfig = type("ClientConfig", (), {})
    sys.modules["saharo_client.config_types"] = fake_config_mod

    fake_errors_mod = types.ModuleType("saharo_client.errors_utils")
    fake_errors_mod.parse_api_error_detail = lambda *_args, **_kwargs: None
    sys.modules["saharo_client.errors_utils"] = fake_errors_mod

    fake_resolve_mod = types.ModuleType("saharo_client.resolve")
    fake_resolve_mod.resolve_agent_id_for_agents = lambda *_args, **_kwargs: 0
    sys.modules["saharo_client.resolve"] = fake_resolve_mod
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import agents_cmd
from saharo_cli.config import AppConfig, AuthConfig


class _FakeClient:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    def agents_get(self, agent_id: int) -> dict:
        raise _FakeApiError(self.status_code, "unauthorized")

    def close(self) -> None:
        return None


def _make_cfg() -> AppConfig:
    return AppConfig(base_url="http://example.test", auth=AuthConfig(token="", token_type="bearer"), agents={})


def test_show_agent_handles_auth_error(monkeypatch) -> None:
    client = _FakeClient(403)
    monkeypatch.setattr(agents_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(agents_cmd, "make_client", lambda *_args, **_kwargs: client)

    with pytest.raises(typer.Exit) as exc:
        agents_cmd.show_agent(agent_id=5, profile=None, base_url=None, json_out=False)

    assert exc.value.exit_code == 2
