from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from saharo_cli import main
from saharo_cli.auth_state import AuthContext
from saharo_cli.commands import services_cmd


class _FakeClient:
    def __init__(self):
        self.last_desired_set: dict | None = None
        self.desired_map: dict[str, int] = {"svc-a": 3, "svc-b": 1}

    def admin_servers_list(self, *, q=None, limit=None, offset=None):  # noqa: ANN001
        return {"items": [{"id": 7, "name": "srv-a", "public_host": "srv-a.local"}]}

    def admin_server_desired_custom_services_set(self, server_id: int, **kwargs):  # noqa: ANN003
        self.last_desired_set = {"server_id": server_id, **kwargs}
        desired_specs = kwargs.get("services") or [{"code": code, "replicas": 1} for code in (kwargs.get("service_codes") or [])]
        replicas_map = {str(item.get("code")): int(item.get("replicas") or 1) for item in desired_specs}
        self.desired_map = dict(replicas_map)
        return {
            "server_id": server_id,
            "desired_services": [str(item.get("code")) for item in desired_specs],
            "desired_service_replicas": replicas_map,
            "disabled_services": [],
            "job_id": 123,
        }

    def admin_server_desired_custom_services_get(self, server_id: int):
        return {
            "server_id": server_id,
            "desired_services": list(self.desired_map.keys()),
            "desired_service_replicas": dict(self.desired_map),
            "disabled_services": [],
        }

    def admin_server_custom_services_dry_run(self, server_id: int, **kwargs):  # noqa: ANN003
        return {
            "server_id": server_id,
            "rollout_strategy": kwargs.get("rollout_strategy") or "safe",
            "rollout_policy": {"batch_size": 1, "max_unavailable": 1, "pause_seconds": 0.0},
            "actions": [{"service_code": "svc-a", "action": "skip", "reason": "already_running"}],
            "rolling_batches": [],
        }

    def admin_custom_service_get_by_code(self, code: str):
        if code == "svc-a":
            return {"id": 11, "code": "svc-a", "display_name": "Svc A", "enabled": True}
        raise Exception("not used")

    def admin_custom_service_get(self, service_id: int):
        return {"id": service_id, "code": "svc-a", "display_name": "Svc A", "enabled": True}

    def admin_custom_service_create(self, *, code: str, display_name: str, yaml_definition: str):  # noqa: ARG002
        return {"id": 11, "code": code, "display_name": display_name, "enabled": True}

    def admin_custom_service_update(self, service_id: int, **kwargs):  # noqa: ANN003
        return {
            "id": service_id,
            "code": "svc-a",
            "display_name": kwargs.get("display_name") or "Svc A",
            "enabled": kwargs.get("enabled", True),
        }

    def close(self) -> None:
        return None


def test_services_group_available_for_viewer(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="viewer"))
    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "services" in result.output


def test_services_desired_set_command(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "services",
            "desired-state",
            "set",
            "7",
            "svc-a=3",
            "svc-b,svc-c:2",
            "--strategy",
            "rolling",
        ],
    )
    assert result.exit_code == 0
    assert "Desired services updated for server 7" in result.output
    assert "Replicas: svc-a=3, svc-b=1, svc-c=2" in result.output
    assert fake_client.last_desired_set is not None
    assert fake_client.last_desired_set["services"] == [
        {"code": "svc-a", "replicas": 3},
        {"code": "svc-b", "replicas": 1},
        {"code": "svc-c", "replicas": 2},
    ]
    assert fake_client.last_desired_set["service_codes"] == ["svc-a", "svc-b", "svc-c"]


def test_services_ds_alias_set_command(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "ds", "set", "7", "svc-a=2"])
    assert result.exit_code == 0
    assert "Desired services updated for server 7" in result.output
    assert fake_client.last_desired_set is not None
    assert fake_client.last_desired_set["services"] == [{"code": "svc-a", "replicas": 2}]


def test_services_desired_get_shows_replicas(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: _FakeClient())
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "desired-state", "get", "7"])
    assert result.exit_code == 0
    assert "Replicas: svc-a=3, svc-b=1" in result.output


def test_services_desired_add_merges_existing(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    fake_client.desired_map = {"svc-a": 1}
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "ds", "add", "7", "svc-b=2", "svc-a=3"])
    assert result.exit_code == 0
    assert "Desired services merged for server 7" in result.output
    assert fake_client.last_desired_set is not None
    assert fake_client.last_desired_set["services"] == [
        {"code": "svc-a", "replicas": 3},
        {"code": "svc-b", "replicas": 2},
    ]


def test_services_desired_rm_prunes_services(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    fake_client.desired_map = {"svc-a": 3, "svc-b": 1}
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "ds", "rm", "7", "svc-b"])
    assert result.exit_code == 0
    assert "Desired services pruned for server 7" in result.output
    assert fake_client.last_desired_set is not None
    assert fake_client.last_desired_set["services"] == [{"code": "svc-a", "replicas": 3}]


def test_services_desired_scale_requires_existing_without_add_missing(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    fake_client.desired_map = {"svc-a": 1}
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "ds", "scale", "7", "svc-b=2"])
    assert result.exit_code == 2
    assert "Cannot scale non-desired service(s): svc-b" in result.output


def test_services_desired_scale_with_add_missing(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    fake_client = _FakeClient()
    fake_client.desired_map = {"svc-a": 1}
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: fake_client)
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "desired-state", "scale", "7", "svc-a=3", "svc-b=2", "--add-missing"])
    assert result.exit_code == 0
    assert "Desired replicas updated for server 7" in result.output
    assert fake_client.last_desired_set is not None
    assert fake_client.last_desired_set["services"] == [
        {"code": "svc-a", "replicas": 3},
        {"code": "svc-b", "replicas": 2},
    ]


def test_services_apply_command(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    monkeypatch.setattr(services_cmd, "make_client", lambda *args, **kwargs: _FakeClient())
    monkeypatch.setattr(services_cmd, "load_config", lambda: object())

    yaml_file = tmp_path / "svc.yaml"
    yaml_file.write_text(
        "name: svc-a\n"
        "display_name: Service A\n"
        "container:\n"
        "  image: nginx:alpine\n"
        "  ports: []\n"
        "  volumes: []\n"
        "  environment: []\n"
        "  capabilities: []\n"
        "  devices: []\n",
        encoding="utf-8",
    )

    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["services", "apply", str(yaml_file)])
    assert result.exit_code == 0
    assert "Service 'svc-a' updated" in result.output
