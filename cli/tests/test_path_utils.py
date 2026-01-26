from saharo_cli.commands.host_bootstrap import BootstrapInputs
from saharo_cli.path_utils import looks_like_windows_path


def test_looks_like_windows_path() -> None:
    for value in ("C:\\opt\\saharo", "C:/opt/saharo", "C:", "\\\\server\\share", "opt\\saharo"):
        assert looks_like_windows_path(value)
    for value in ("/opt/saharo", "opt/saharo", "relative/path", ""):
        assert not looks_like_windows_path(value)


def test_bootstrap_inputs_posix_paths() -> None:
    inputs = BootstrapInputs(
        api_url="https://example.test",
        api_url_original="https://example.test",
        x_root_secret="root-secret",
        db_password="db-pass",
        admin_username="admin",
        admin_password="admin-pass",
        admin_api_key_name="admin-key",
        jwt_secret="jwt-secret",
        install_dir="/opt/saharo",
        registry="registry.example.com",
        lic_url="https://lic.example.com",
        tag="1.2.3",
        non_interactive=True,
        assume_yes=True,
        no_docker_install=True,
        force=True,
    )

    assert inputs.host_dir_posix == "/opt/saharo/host"
    assert inputs.compose_path_posix == "/opt/saharo/host/docker-compose.yml"
    assert inputs.env_path_posix == "/opt/saharo/host/.env"
    assert inputs.readme_path_posix == "/opt/saharo/host/README.txt"
    assert inputs.data_dir_posix == "/opt/saharo/host/data/postgres"
    assert inputs.license_state_path_posix == "/opt/saharo/host/state/license.json"
