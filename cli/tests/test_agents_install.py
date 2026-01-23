import json
import os
import subprocess
import sys
import types
from types import SimpleNamespace

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
fake_client_mod = types.ModuleType("saharo_client")


class _FakeSaharoClient:
    def __init__(self, *_args, **_kwargs) -> None:
        pass


class _FakeApiError(Exception):
    def __init__(self, status_code: int, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class _FakeNetworkError(Exception):
    pass


fake_client_mod.SaharoClient = _FakeSaharoClient
fake_client_mod.ApiError = _FakeApiError
fake_client_mod.NetworkError = _FakeNetworkError
sys.modules.setdefault("saharo_client", fake_client_mod)

fake_config_mod = types.ModuleType("saharo_client.config_types")


class _FakeClientConfig:
    def __init__(self, base_url: str = "", token: str | None = None) -> None:
        self.base_url = base_url
        self.token = token


fake_config_mod.ClientConfig = _FakeClientConfig
sys.modules.setdefault("saharo_client.config_types", fake_config_mod)
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import agents_cmd
from saharo_cli.config import AuthConfig


class _TimeController:
    def __init__(self) -> None:
        self.current = 0.0

    def time(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.current += seconds


class _FakeSession:
    def __init__(self, responses: list[subprocess.CompletedProcess]) -> None:
        self.responses = responses
        self.target = SimpleNamespace(dry_run=False)
        self.commands: list[str] = []

    def run(self, command: str) -> subprocess.CompletedProcess:
        self.commands.append(command)
        if not self.responses:
            return subprocess.CompletedProcess([], 1, "", "")
        return self.responses.pop(0)

    def run_privileged(self, command: str) -> subprocess.CompletedProcess:
        return self.run(command)


def test_cleanup_removes_existing_state_volume(monkeypatch) -> None:
    session = _FakeSession(
        [
            subprocess.CompletedProcess([], 0, "container-id\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
        ]
    )
    agents_cmd._cleanup_agent_installation(session, sudo=False, allow_existing_state=False)

    assert "docker rm -f saharo_agent" in session.commands
    assert f"docker volume rm -f {agents_cmd.AGENT_STATE_VOLUME}" in session.commands


def test_wait_for_agent_registration_times_out(monkeypatch) -> None:
    time_controller = _TimeController()
    monkeypatch.setattr(agents_cmd.time, "time", time_controller.time)
    monkeypatch.setattr(agents_cmd.time, "sleep", time_controller.sleep)
    monkeypatch.setattr(agents_cmd, "AGENT_STATE_PATHS", ("/data/agent_state.json",))
    monkeypatch.setattr(agents_cmd, "_is_agent_visible", lambda *_args, **_kwargs: False)
    prints: list[str] = []
    monkeypatch.setattr(agents_cmd.console.console, "print", lambda msg, **_kwargs: prints.append(str(msg)))

    session = _FakeSession([])
    result = agents_cmd._wait_for_agent_registration(
        session,
        SimpleNamespace(),
        sudo=False,
        timeout_s=3,
        poll_interval_s=1,
        indicator_interval_s=1,
    )

    assert result.timeout_reached is True
    assert result.registered is False
    assert result.elapsed_seconds == 3
    assert any("Waiting for agent registration" in msg for msg in prints)


def test_wait_for_agent_registration_waits_for_api(monkeypatch) -> None:
    time_controller = _TimeController()
    monkeypatch.setattr(agents_cmd.time, "time", time_controller.time)
    monkeypatch.setattr(agents_cmd.time, "sleep", time_controller.sleep)
    monkeypatch.setattr(agents_cmd, "AGENT_STATE_PATHS", ("/data/agent_state.json",))
    visible_checks = [False, True]
    events: list[str] = []

    def _visible(_cfg, _agent_id) -> bool:
        result = visible_checks.pop(0)
        events.append("visible_true" if result else "visible_false")
        return result

    monkeypatch.setattr(agents_cmd, "_is_agent_visible", _visible)
    prints: list[str] = []

    def _print(msg, **_kwargs) -> None:
        text = str(msg)
        prints.append(text)

    monkeypatch.setattr(agents_cmd.console.console, "print", _print)
    session = _FakeSession(
        [
            subprocess.CompletedProcess([], 0, '{"agent_id": 9, "agent_secret": "sekret"}', ""),
            subprocess.CompletedProcess([], 0, '{"agent_id": 9, "agent_secret": "sekret"}', ""),
        ]
    )

    result = agents_cmd._wait_for_agent_registration(
        session,
        SimpleNamespace(),
        sudo=False,
        timeout_s=5,
        poll_interval_s=1,
        indicator_interval_s=1,
    )

    assert result.registered is True
    assert result.agent_id == 9
    assert "visible_true" in events
    assert all("Agent registered successfully" not in msg for msg in prints)


def test_install_json_output_schema(capsys) -> None:
    result = agents_cmd.InstallResult(
        deployed=True,
        registered=True,
        agent_id=12,
        elapsed_seconds=9,
        timeout_reached=False,
    )
    agents_cmd._print_install_json(result)
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert payload["deployed"] is True
    assert payload["registered"] is True
    assert payload["agent_id"] == 12


def test_install_no_wait_skips_registration(monkeypatch) -> None:
    cfg = agents_cmd.AppConfig(
        base_url="http://example.test",
        auth=AuthConfig(token="", token_type="bearer"),
        agents={},
    )
    monkeypatch.setattr(agents_cmd, "load_config", lambda: cfg)

    def _wait_should_not_run(*_args, **_kwargs) -> None:
        raise AssertionError("_wait_for_agent_registration should not run")

    monkeypatch.setattr(agents_cmd, "_wait_for_agent_registration", _wait_should_not_run)

    agents_cmd.install_agent(
        ssh_target="user@example",
        port=22,
        key=None,
        password=False,
        sudo=False,
        sudo_password=False,
        with_docker=False,
        dry_run=True,
        invite="invite-token",
        api_url="http://example.test",
        force_reregister=False,
        timeout=5,
        no_wait=True,
        show=False,
        json_out=True,
        watch=False,
        follow=False,
        local=False,
        local_path=None,
        create_server=False,
    )


def test_prompt_required_field_trims_and_retries(monkeypatch) -> None:
    responses = iter(["", "   ", " example.com "])

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(agents_cmd.typer, "prompt", _prompt)
    value = agents_cmd._prompt_required_field("Host")
    assert value == "example.com"


def test_create_server_wizard_calls_api(monkeypatch) -> None:
    cfg = agents_cmd.AppConfig(
        base_url="http://example.test",
        auth=AuthConfig(token="token", token_type="bearer"),
        agents={},
    )
    responses = iter(["1.2.3.4", "My Server", ""])

    def _prompt(_text, **_kwargs):
        return next(responses)

    monkeypatch.setattr(agents_cmd.typer, "prompt", _prompt)

    created: dict = {}

    class _FakeClient:
        def admin_server_create(self, *, name: str, host: str, agent_id: int, note: str | None = None):
            created["payload"] = {
                "name": name,
                "host": host,
                "agent_id": agent_id,
                "note": note,
            }
            return {"id": 99, "name": name, "public_host": host}

        def close(self) -> None:
            return None

    monkeypatch.setattr(agents_cmd, "make_client", lambda *_args, **_kwargs: _FakeClient())
    monkeypatch.setattr(agents_cmd.console, "info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agents_cmd.console, "ok", lambda *_args, **_kwargs: None)

    agents_cmd._run_create_server_wizard(cfg, agent_id=12)
    assert created["payload"] == {
        "name": "My Server",
        "host": "1.2.3.4",
        "agent_id": 12,
        "note": None,
    }


def test_handle_registration_result_only_creates_when_requested(monkeypatch) -> None:
    cfg = agents_cmd.AppConfig(
        base_url="http://example.test",
        auth=AuthConfig(token="token", token_type="bearer"),
        agents={},
    )
    reg_result = agents_cmd.RegistrationResult(
        registered=True,
        agent_id=7,
        elapsed_seconds=1,
        timeout_reached=False,
    )
    called = {"wizard": 0}

    def _wizard(_cfg, _agent_id):
        called["wizard"] += 1

    monkeypatch.setattr(agents_cmd, "_run_create_server_wizard", _wizard)
    monkeypatch.setattr(agents_cmd.console.console, "print", lambda *_args, **_kwargs: None)

    agents_cmd._handle_registration_result(
        reg_result,
        deployed=True,
        timeout_s=5,
        json_out=False,
        show=False,
        watch=False,
        follow=False,
        cfg=cfg,
        follow_local=False,
        create_server=False,
    )
    assert called["wizard"] == 0

    agents_cmd._handle_registration_result(
        reg_result,
        deployed=True,
        timeout_s=5,
        json_out=False,
        show=False,
        watch=False,
        follow=False,
        cfg=cfg,
        follow_local=False,
        create_server=True,
    )
    assert called["wizard"] == 1
