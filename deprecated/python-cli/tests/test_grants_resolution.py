import os
import sys
import types

import pytest
import typer

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
    sys.modules["saharo_client"] = fake_client_mod

    fake_config_mod = types.ModuleType("saharo_client.config_types")
    fake_config_mod.ClientConfig = type("ClientConfig", (), {})
    sys.modules["saharo_client.config_types"] = fake_config_mod

    fake_resolve_mod = types.ModuleType("saharo_client.resolve")
    fake_resolve_mod.ResolveError = type("ResolveError", (Exception,), {})
    fake_resolve_mod.resolve_protocol_for_grants = lambda *_args, **_kwargs: (0, None)
    fake_resolve_mod.resolve_user_id_for_grants = lambda *_args, **_kwargs: 0
    fake_resolve_mod.resolve_server_id_for_grants = lambda *_args, **_kwargs: 0
    fake_resolve_mod.validate_route_for_protocol = lambda *_args, **_kwargs: None
    sys.modules["saharo_client.resolve"] = fake_resolve_mod
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import grants_cmd


class _FakeClient:
    def __init__(self) -> None:
        self.users: list[dict] = []
        self.servers: list[dict] = []
        self.protocols: list[dict] = []

    def admin_users_list(self, *, q=None, limit=50, offset=0):  # noqa: ANN001
        return {"items": self.users}

    def admin_servers_list(self, *, q=None, limit=50, offset=0):  # noqa: ANN001
        return {"items": self.servers}

    def admin_protocols_list(self):  # noqa: ANN001
        return {"items": self.protocols}


def test_resolve_user_id_numeric() -> None:
    client = _FakeClient()
    assert grants_cmd._resolve_user_id(client, "42", None) == 42


def test_resolve_user_id_single_match() -> None:
    client = _FakeClient()
    client.users = [{"id": 7, "username": "alice", "telegram_id": 111}]
    assert grants_cmd._resolve_user_id(client, "alice", None) == 7


def test_resolve_user_id_multiple_matches() -> None:
    client = _FakeClient()
    client.users = [
        {"id": 1, "username": "alex", "telegram_id": 101},
        {"id": 2, "username": "alex", "telegram_id": 202},
    ]
    with pytest.raises(typer.Exit) as exc:
        grants_cmd._resolve_user_id(client, "alex", None)
    assert exc.value.exit_code == 2


def test_resolve_server_id_single_match() -> None:
    client = _FakeClient()
    client.servers = [{"id": 3, "name": "srv-1", "public_host": "srv-1.test"}]
    assert grants_cmd._resolve_server_id(client, "srv-1", None) == 3


def test_resolve_protocol_key() -> None:
    client = _FakeClient()
    client.protocols = [{"id": 9, "code": "awg", "title": "AmneziaWG"}]
    assert grants_cmd._resolve_protocol(client, "awg") == (9, "awg")


def test_resolve_protocol_numeric() -> None:
    client = _FakeClient()
    client.protocols = [{"id": 5, "code": "xray", "title": "Xray"}]
    assert grants_cmd._resolve_protocol(client, "5") == (5, "xray")


def test_validate_route_rejects_non_xray() -> None:
    with pytest.raises(typer.Exit) as exc:
        grants_cmd._validate_route_for_protocol("awg", "ws")
    assert exc.value.exit_code == 2


def test_validate_route_accepts_xray() -> None:
    assert grants_cmd._validate_route_for_protocol("xray", "ws") == "ws"
