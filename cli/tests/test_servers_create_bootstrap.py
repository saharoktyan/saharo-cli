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
fake_client_mod.SaharoClient = object
sys.modules["saharo_client"] = fake_client_mod

fake_config_mod = types.ModuleType("saharo_client.config_types")
fake_config_mod.ClientConfig = type("ClientConfig", (), {})
sys.modules["saharo_client.config_types"] = fake_config_mod
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import servers_cmd
from saharo_cli.config import AppConfig, AuthConfig


class _FakeClient:
    def __init__(self) -> None:
        self.created = False
        self.bootstrapped = False
        self.bootstrap_services: list[str] = []
        self.protocol_upserts: list[dict] = []
        self.job_response: dict = {}

    def admin_servers_list(self, *, q=None, limit=50, offset=0):  # noqa: ANN001
        return {"items": [{"id": 1, "name": "alpha"}]}

    def admin_server_create(self, *, name: str, host: str, agent_id: int, note: str | None = None) -> dict:
        self.created = True
        return {"id": 11, "name": name, "public_host": host, "agent_id": agent_id, "note": note}

    def admin_server_bootstrap(self, server_id: int, *, services: list[str]) -> dict:
        self.bootstrapped = True
        self.bootstrap_services = services
        return {"job_id": 99, "server_id": server_id, "agent_id": 1, "services": services}

    def admin_job_get(self, job_id: int) -> dict:
        return {"id": job_id, **self.job_response}

    def admin_server_protocol_upsert(self, server_id: int, *, protocol_key: str, status: str | None = None,
                                     meta=None) -> dict:
        payload = {
            "server_id": server_id,
            "protocol_key": protocol_key,
            "status": status,
            "meta": meta,
        }
        self.protocol_upserts.append(payload)
        return payload

    def admin_server_protocols_list(self, server_id: int):  # noqa: ANN001
        return []

    def close(self) -> None:
        return None


def _make_cfg() -> AppConfig:
    return AppConfig(base_url="http://example.test", auth=AuthConfig(token="", token_type="bearer"), agents={})


def test_create_server_calls_api(monkeypatch) -> None:
    client = _FakeClient()
    monkeypatch.setattr(servers_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(servers_cmd, "make_client", lambda *_args, **_kwargs: client)

    servers_cmd.create_server(
        name="alpha",
        host="example.test",
        agent_id=3,
        note="primary",
        base_url=None,
        json_out=True,
    )

    assert client.created is True


def test_bootstrap_requires_service_flags(monkeypatch) -> None:
    client = _FakeClient()
    monkeypatch.setattr(servers_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(servers_cmd, "make_client", lambda *_args, **_kwargs: client)

    with pytest.raises(typer.Exit) as exc:
        servers_cmd.bootstrap_server(
            server_ref="1",
            xray=False,
            awg=False,
            all_services=False,
            wait=False,
            base_url=None,
            json_out=True,
        )

    assert exc.value.exit_code == 2
    assert client.bootstrapped is False


def test_bootstrap_all_services(monkeypatch) -> None:
    client = _FakeClient()
    monkeypatch.setattr(servers_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(servers_cmd, "make_client", lambda *_args, **_kwargs: client)

    servers_cmd.bootstrap_server(
        server_ref="1",
        xray=False,
        awg=False,
        all_services=True,
        wait=False,
        base_url=None,
        json_out=True,
    )

    assert client.bootstrapped is True
    assert client.bootstrap_services == ["xray", "amnezia-awg"]


def test_bootstrap_reports_protocols_when_job_succeeds(monkeypatch) -> None:
    client = _FakeClient()
    client.job_response = {
        "status": "succeeded",
        "result": {"installed_services": ["xray", "amnezia-awg"]},
        "payload": {"requested_services": ["xray", "amnezia-awg"]},
    }
    monkeypatch.setattr(servers_cmd, "load_config", _make_cfg)
    monkeypatch.setattr(servers_cmd, "make_client", lambda *_args, **_kwargs: client)

    servers_cmd.bootstrap_server(
        server_ref="1",
        xray=False,
        awg=False,
        all_services=True,
        wait=True,
        wait_timeout=1,
        wait_interval=1,
        base_url=None,
        json_out=True,
    )

    assert client.protocol_upserts == [
        {
            "server_id": 1,
            "protocol_key": "xray",
            "status": "available",
            "meta": {"source": "bootstrap", "service": "xray"},
        },
        {
            "server_id": 1,
            "protocol_key": "awg",
            "status": "available",
            "meta": {"source": "bootstrap", "service": "amnezia-awg"},
        },
    ]
