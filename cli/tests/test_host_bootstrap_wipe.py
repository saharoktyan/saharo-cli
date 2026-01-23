import httpx
import pytest
import typer

from saharo_cli.commands.host_bootstrap import (
    BootstrapInputs,
    _ensure_wipe_confirmed,
    bootstrap_admin,
)


def _make_inputs(tmp_path) -> BootstrapInputs:
    return BootstrapInputs(
        api_url="https://example.test",
        api_url_original="https://example.test",
        x_root_secret="root-secret",
        db_password="db-pass",
        admin_username="admin",
        admin_password="admin-pass",
        admin_api_key_name="admin-key",
        jwt_secret="jwt-secret",
        install_dir=str(tmp_path),
        registry="registry.example.com",
        tag="1.2.3",
        non_interactive=True,
        assume_yes=True,
        no_docker_install=True,
        force=True,
    )


def test_bootstrap_admin_conflict_is_success(tmp_path, monkeypatch) -> None:
    inputs = _make_inputs(tmp_path)
    inputs.host_dir.mkdir(parents=True, exist_ok=True)
    inputs.env_path.write_text("ROOT_ADMIN_SECRET=root-secret\n", encoding="utf-8")
    calls = {"count": 0}

    def _fake_post(*_args, **_kwargs) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(409, text="admin already exists")

    monkeypatch.setattr(httpx, "post", _fake_post)
    bootstrap_admin(inputs)
    assert calls["count"] == 1


def test_wipe_requires_confirm_in_non_interactive(tmp_path) -> None:
    with pytest.raises(typer.Exit) as exc:
        _ensure_wipe_confirmed(
            install_dir=str(tmp_path),
            non_interactive=True,
            assume_yes=True,
            confirm_wipe=False,
        )
    assert exc.value.exit_code == 2
