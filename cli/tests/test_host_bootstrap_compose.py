import shutil
import subprocess

import pytest
from saharo_cli.commands.host_bootstrap import BootstrapInputs, render_compose, render_env


def _docker_compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    res = subprocess.run(
        ["docker", "compose", "version"], check=False, capture_output=True, text=True
    )
    return res.returncode == 0


def test_render_compose_indentation_and_config(tmp_path) -> None:
    inputs = BootstrapInputs(
        api_url="https://example.com",
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
    compose_content = render_compose(inputs)
    assert "\n  api:\n    image:" in compose_content

    inputs.host_dir.mkdir(parents=True, exist_ok=True)
    inputs.compose_path.write_text(compose_content, encoding="utf-8")
    inputs.env_path.write_text(
        render_env(inputs, include_root_secret=False), encoding="utf-8"
    )

    if not _docker_compose_available():
        pytest.skip("docker compose not available")

    res = subprocess.run(
        ["docker", "compose", "-f", str(inputs.compose_path), "config", "-q"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr


def test_render_env_includes_root_admin_secret(tmp_path) -> None:
    inputs = BootstrapInputs(
        api_url="https://example.com",
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
    env_content = render_env(inputs, include_root_secret=True)
    assert "ROOT_ADMIN_SECRET=root-secret" in env_content
