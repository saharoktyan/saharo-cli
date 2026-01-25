from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

import httpx
import typer
from rich.prompt import Confirm
from rich.text import Text

from .host_https import (
    HttpsSetupError,
    ensure_https,
    normalize_api_url,
    normalize_domain,
    report_https_failure,
)
from .. import console
from ..ssh import SSHSession, SshTarget, build_control_path, is_windows
from ..path_utils import looks_like_windows_path
IMAGE_COMPONENTS = {"host": "api", "agent": "agent"}

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_MISSING_FIELD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
_MISSING_MARKER_RE = re.compile(r"field required|type=missing", re.IGNORECASE)

DEFAULT_INSTALL_DIR = "/opt/saharo"
DEFAULT_REGISTRY = "registry.saharoktyan.ru"
DEFAULT_TAG = "1.0.0"
DEFAULT_API_BIND = "127.0.0.1"
DEFAULT_API_PORT = 8010
DEFAULT_HEALTH_TIMEOUT = 60.0
DEFAULT_HEALTH_INTERVAL = 2.0
DEFAULT_HEALTH_CURL_TIMEOUT = 5
DEFAULT_HEALTH_LOG_TAIL = 60
DEFAULT_API_CONTAINER = "saharo_host_api"
_TRANSIENT_CURL_EXIT_CODES = {7, 28, 52, 56}
_LAST_PULL_STDERR: str | None = None




@dataclass(frozen=True)
class BootstrapInputs:
    api_url: str
    api_url_original: str | None
    x_root_secret: str
    db_password: str
    admin_username: str
    admin_password: str
    admin_api_key_name: str
    jwt_secret: str
    install_dir: str
    registry: str
    tag: str
    non_interactive: bool
    assume_yes: bool
    no_docker_install: bool
    force: bool
    telegram_bot_token: str | None = None
    https_enabled: bool = False
    https_domain: str | None = None
    https_email: str | None = None
    https_http01: bool = True
    skip_https: bool = False

    @property
    def host_dir(self) -> Path:
        return Path(self.install_dir).expanduser().resolve() / "host"

    # Remote paths must stay POSIX to avoid Windows drive letters in SSH commands.
    @property
    def host_dir_posix(self) -> str:
        return posixpath.join(self.install_dir, "host")

    @property
    def compose_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "docker-compose.yml")

    @property
    def env_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, ".env")

    @property
    def readme_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "README.txt")

    @property
    def data_dir_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "data", "postgres")

    @property
    def compose_path(self) -> Path:
        return self.host_dir / "docker-compose.yml"

    @property
    def env_path(self) -> Path:
        return self.host_dir / ".env"

    @property
    def readme_path(self) -> Path:
        return self.host_dir / "README.txt"

    @property
    def data_dir(self) -> Path:
        return self.host_dir / "data" / "postgres"

    @property
    def api_base(self) -> str:
        return f"http://{DEFAULT_API_BIND}:{DEFAULT_API_PORT}"


@dataclass
class PrereqResult:
    docker_installed: bool
    compose_installed: bool
    docker_running: bool



def _normalize_remote_install_dir(install_dir: str) -> str:
    clean = (install_dir or "").strip()
    if not clean:
        return DEFAULT_INSTALL_DIR
    if looks_like_windows_path(clean):
        console.err("In SSH mode, --install-dir must be a Linux path like /opt/saharo.")
        raise typer.Exit(code=2)
    return clean


def host_bootstrap(
        api_url: str | None = typer.Option(None, "--api-url", help="Public base URL for users/clients."),
        x_root_secret: str | None = typer.Option(None, "--x-root-secret", help="Root secret for /admin/bootstrap."),
        db_password: str | None = typer.Option(None, "--db-password", help="Postgres password."),
        admin_username: str | None = typer.Option(None, "--admin-username", help="Admin username."),
        admin_password: str | None = typer.Option(None, "--admin-password", help="Admin password."),
        admin_api_key_name: str = typer.Option("root", "--admin-api-key-name", help="Admin API key name."),
        telegram_bot_token: str | None = typer.Option(
            None,
            "--telegram-bot-token",
            help="Telegram bot token for Telegram WebApp auth (optional).",
        ),
        install_dir: str = typer.Option(DEFAULT_INSTALL_DIR, "--install-dir", help="Installation directory."),
        registry: str = typer.Option(DEFAULT_REGISTRY, "--registry", help="Container registry for images."),
        version: str | None = typer.Option(None, "--version", help="Exact host version tag to deploy, e.g. 1.4.1"),
        tag: str = typer.Option(DEFAULT_TAG, "--tag", help="Image tag to deploy (fallback)."),
        wipe_data: bool = typer.Option(False, "--wipe-data", help="DANGEROUS: delete all host data before install."),
        confirm_wipe: bool = typer.Option(
            False,
            "--confirm-wipe",
            help="Confirm the irreversible wipe (required with --wipe-data in non-interactive mode).",
        ),
        skip_https: bool = typer.Option(False, "--skip-https", help="Skip HTTPS setup entirely."),
        non_interactive: bool = typer.Option(False, "--non-interactive", help="Fail if required flags are missing."),
        assume_yes: bool = typer.Option(False, "--yes", help="Assume yes where safe."),
        no_docker_install: bool = typer.Option(False, "--no-docker-install", help="Do not offer docker install."),
        force: bool = typer.Option(
            False,
            "--force",
            help="Overwrite generated files and recreate containers (keeps Postgres data).",
        ),
        rotate_jwt_secret: bool = typer.Option(False, "--rotate-jwt-secret", help="Rotate JWT secret on reinstall."),
        ssh_host: str | None = typer.Option(None, "--ssh-host", help="SSH target in user@host form."),
        ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port."),
        ssh_key: str | None = typer.Option(None, "--ssh-key", help="SSH private key path."),
        ssh_sudo: bool = typer.Option(True, "--ssh-sudo/--no-ssh-sudo",
                                      help="Use sudo over SSH for privileged commands."),

):
    """Interactive installation wizard for Saharo host stack.

    Examples:
      saharo host bootstrap --api-url https://api.example.com
      saharo host bootstrap --ssh-host root@203.0.113.10
    """
    console.rule("[bold]Saharo Host Bootstrap[/]")

    if ssh_key and ssh_key.endswith(".pub"):
        console.err("--ssh-key must be a private key path, not .pub")
        raise typer.Exit(code=2)

    if is_windows() and not ssh_host:
        console.err("Local host bootstrap is not supported on Windows. Use --ssh-host to connect to a Linux host.")
        raise typer.Exit(code=2)

    if ssh_host:
        install_dir = _normalize_remote_install_dir(install_dir)

    if wipe_data:
        _ensure_wipe_confirmed(
            install_dir=install_dir,
            non_interactive=non_interactive,
            assume_yes=assume_yes,
            confirm_wipe=confirm_wipe,
            remote=bool(ssh_host),
        )

    if ssh_host:
        _host_bootstrap_ssh(
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_sudo=ssh_sudo,
            api_url=api_url,
            x_root_secret=x_root_secret,
            db_password=db_password,
            admin_username=admin_username,
            admin_password=admin_password,
            admin_api_key_name=admin_api_key_name,
            telegram_bot_token=telegram_bot_token,
            install_dir=install_dir,
            registry=registry,
            tag=tag,
            non_interactive=non_interactive,
            assume_yes=assume_yes,
            no_docker_install=no_docker_install,
            force=force,
            rotate_jwt_secret=rotate_jwt_secret,
            version=version,
            wipe_data=wipe_data,
            skip_https=skip_https,
        )
        return

    if version:
        resolved_tag = version
    else:
        resolved_tag = tag

    inputs = collect_inputs(
        api_url=api_url,
        x_root_secret=x_root_secret,
        db_password=db_password,
        admin_username=admin_username,
        admin_password=admin_password,
        admin_api_key_name=admin_api_key_name,
        telegram_bot_token=telegram_bot_token,
        install_dir=install_dir,
        registry=registry,
        tag=resolved_tag,
        non_interactive=non_interactive,
        assume_yes=assume_yes,
        no_docker_install=no_docker_install,
        force=force,
        rotate_jwt_secret=rotate_jwt_secret,
        skip_https=skip_https,
    )

    prereqs = check_prereqs(inputs)
    if not prereqs.docker_installed:
        handle_missing_docker(inputs)
        prereqs = check_prereqs(inputs)
    if not prereqs.compose_installed:
        console.err("Docker Compose plugin is required (docker compose). Please install it and re-run.")
        raise typer.Exit(code=2)
    if not prereqs.docker_running:
        console.err("Docker daemon is not running. Start Docker and re-run.")
        raise typer.Exit(code=2)

    if not inputs.assume_yes:
        confirm_message = Text("Proceed with writing files and starting containers?", style="bold")
        if not Confirm.ask(confirm_message, default=True):
            console.err("Aborted by user.")
            raise typer.Exit(code=1)

    if wipe_data:
        wipe_host_data(inputs)

    write_files(inputs)
    compose_pull_up(inputs)
    verify_health(inputs)
    bootstrap_admin(inputs)
    verify_health(inputs)
    https_url = _maybe_setup_https_local(inputs)
    print_summary(inputs, public_api_url=https_url)


def _host_bootstrap_ssh(
        *,
        ssh_host: str,
        ssh_port: int,
        ssh_key: str | None,
        ssh_sudo: bool,
        api_url: str | None,
        x_root_secret: str | None,
        db_password: str | None,
        admin_username: str | None,
        admin_password: str | None,
        admin_api_key_name: str,
        telegram_bot_token: str | None,
        install_dir: str,
        registry: str,
        tag: str,
        non_interactive: bool,
        assume_yes: bool,
        no_docker_install: bool,
        force: bool,
        rotate_jwt_secret: bool,
        version: str | None,
        wipe_data: bool,
        skip_https: bool,
) -> None:
    install_dir = _normalize_remote_install_dir(install_dir)

    ssh_password = None
    if not ssh_key:
        if is_windows():
            console.err(
                "Password SSH authentication is not supported on Windows. "
                "Use --ssh-key or run bootstrap from Linux/macOS."
            )
            raise typer.Exit(code=2)
        if non_interactive:
            console.err("Missing required SSH authentication. Provide --ssh-key or allow password prompt.")
            raise typer.Exit(code=2)
        console.info("SSH password required for remote host.")
        ssh_password = typer.prompt("SSH password", hide_input=True)

    ssh_user = ssh_host.split("@", 1)[0] if "@" in ssh_host else ""
    use_sudo = ssh_sudo and ssh_user != "root"
    if ssh_sudo and ssh_user == "root":
        console.info("Remote sudo: not required (running as root).")
    elif use_sudo:
        console.info("Remote sudo: enabled.")
    else:
        console.info("Remote sudo: disabled.")

    target = SshTarget(
        host=ssh_host,
        port=ssh_port,
        key_path=ssh_key,
        password=ssh_password,
        sudo=use_sudo,
        dry_run=False,
    )
    session = SSHSession(target=target, control_path=build_control_path(dry_run=False))
    try:
        try:
            session.start()
        except RuntimeError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        if use_sudo:
            try:
                _ensure_remote_sudo(session, target, non_interactive=non_interactive)
            except RuntimeError as exc:
                console.err(str(exc))
                raise typer.Exit(code=2)

        if version:
            resolved_tag = version
        else:
            resolved_tag = tag

        existing_jwt_secret = _get_existing_jwt_secret_remote(session, install_dir, sudo=use_sudo)
        inputs = collect_inputs(
            api_url=api_url,
            x_root_secret=x_root_secret,
            db_password=db_password,
            admin_username=admin_username,
            admin_password=admin_password,
            admin_api_key_name=admin_api_key_name,
            telegram_bot_token=telegram_bot_token,
            install_dir=install_dir,
            registry=registry,
            tag=resolved_tag,
            non_interactive=non_interactive,
            assume_yes=assume_yes,
            no_docker_install=no_docker_install,
            force=force,
            rotate_jwt_secret=rotate_jwt_secret,
            skip_https=skip_https,
            existing_jwt_secret=existing_jwt_secret,
        )

        if not use_sudo:
            if not _remote_can_write_install_dir(session, inputs.install_dir):
                console.err(
                    f"Insufficient permissions to write to {inputs.install_dir}. Try --ssh-sudo or run as root."
                )
                raise typer.Exit(code=2)

        prereqs = _remote_check_prereqs(session, sudo=use_sudo)
        if not prereqs.docker_installed:
            _remote_handle_missing_docker(session, inputs, sudo=use_sudo)
            prereqs = _remote_check_prereqs(session, sudo=use_sudo)
        if not prereqs.compose_installed:
            console.err("Docker Compose plugin is required (docker compose). Please install it and re-run.")
            raise typer.Exit(code=2)
        if not prereqs.docker_running:
            console.err("Docker daemon is not running. Start Docker and re-run.")
            raise typer.Exit(code=2)

        if not inputs.assume_yes:
            confirm_message = Text("Proceed with writing files and starting containers?", style="bold")
            if not Confirm.ask(confirm_message, default=True):
                console.err("Aborted by user.")
                raise typer.Exit(code=1)

        if wipe_data:
            _remote_wipe_host_data(session, inputs, sudo=use_sudo)

        _remote_write_files(session, inputs, sudo=use_sudo)
        _remote_compose_pull_up(session, inputs, sudo=use_sudo)
        verify_health(inputs, ssh_session=session, ssh_host=ssh_host, sudo=use_sudo)
        _remote_bootstrap_admin(session, inputs, sudo=use_sudo)
        verify_health(inputs, ssh_session=session, ssh_host=ssh_host, sudo=use_sudo)
        https_url = _maybe_setup_https_remote(
            session,
            inputs,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            sudo=use_sudo,
        )
        _print_remote_summary(inputs, ssh_host=ssh_host, public_api_url=https_url)
    finally:
        session.close()


def check_prereqs(inputs: BootstrapInputs) -> PrereqResult:
    docker_installed = _command_exists("docker")
    compose_installed = False
    docker_running = False
    if docker_installed:
        compose_installed = _command_success(["docker", "compose", "version"])
        docker_running = _command_success(["docker", "info"])
    if docker_installed and compose_installed and docker_running:
        console.ok("Docker and Docker Compose are available.")
    return PrereqResult(
        docker_installed=docker_installed,
        compose_installed=compose_installed,
        docker_running=docker_running,
    )


def collect_inputs(
        *,
        api_url: str | None,
        x_root_secret: str | None,
        db_password: str | None,
        admin_username: str | None,
        admin_password: str | None,
        admin_api_key_name: str,
        telegram_bot_token: str | None,
        install_dir: str,
        registry: str,
        tag: str,
        non_interactive: bool,
        assume_yes: bool,
        no_docker_install: bool,
        force: bool,
        rotate_jwt_secret: bool,
        skip_https: bool,
        existing_jwt_secret: str | None = None,
) -> BootstrapInputs:
    missing = []
    if not api_url:
        missing.append("--api-url")
    if not x_root_secret:
        missing.append("--x-root-secret")
    if not db_password:
        missing.append("--db-password")
    if not admin_username:
        missing.append("--admin-username")
    if not admin_password:
        missing.append("--admin-password")

    if missing and non_interactive:
        console.err(f"Missing required flags: {', '.join(missing)}")
        raise typer.Exit(code=2)

    if not api_url:
        api_url = typer.prompt("Public API URL (e.g. https://api.example.com)")
    if not x_root_secret:
        x_root_secret = typer.prompt("Root secret for admin bootstrap", hide_input=True)
    if not db_password:
        db_password = typer.prompt("Postgres password", hide_input=True)
    if not admin_username:
        admin_username = typer.prompt("Admin username")
    if not admin_password:
        admin_password = typer.prompt("Admin password", hide_input=True, confirmation_prompt=True)
    if telegram_bot_token is None and not non_interactive:
        telegram_bot_token = typer.prompt(
            "Telegram bot token (optional, press Enter to skip)",
            default="",
            show_default=False,
        )

    api_url = (api_url or "").strip()
    if not api_url:
        console.err("API URL cannot be empty.")
        raise typer.Exit(code=2)
    try:
        api_url = normalize_api_url(api_url)
    except ValueError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)
    api_url_original = api_url

    https_enabled = False
    https_domain = None
    https_email = None
    https_http01 = True
    if skip_https:
        https_enabled = False
    elif not non_interactive:
        if Confirm.ask("Configure HTTPS with Nginx + Let's Encrypt?", default=True):
            https_enabled = True
            default_domain = normalize_domain(api_url)
            while True:
                domain_input = typer.prompt(
                    f"Domain for HTTPS (default: {default_domain})",
                    default=default_domain,
                    show_default=False,
                )
                try:
                    https_domain = normalize_domain(domain_input)
                    break
                except ValueError:
                    console.err("Invalid domain. Please try again.")
            while True:
                https_email = typer.prompt("Email for Let's Encrypt")
                if "@" in https_email:
                    break
                console.err("Email must include '@'.")
            https_http01 = Confirm.ask(
                "Use HTTP-01 challenge (requires port 80 open)?",
                default=True,
            )
            api_url = f"https://{https_domain}"
            api_url_original = api_url_original or api_url

    jwt_secret = existing_jwt_secret or get_existing_jwt_secret(Path(install_dir) / "host")
    if rotate_jwt_secret or not jwt_secret:
        jwt_secret = _generate_jwt_secret()

    telegram_bot_token = (telegram_bot_token or "").strip() or None

    return BootstrapInputs(
        api_url=api_url,
        api_url_original=api_url_original,
        x_root_secret=x_root_secret or "",
        db_password=db_password or "",
        admin_username=admin_username or "",
        admin_password=admin_password or "",
        admin_api_key_name=admin_api_key_name or "root",
        jwt_secret=jwt_secret,
        telegram_bot_token=telegram_bot_token,
        install_dir=install_dir,
        registry=registry,
        tag=tag,
        non_interactive=non_interactive,
        assume_yes=assume_yes,
        no_docker_install=no_docker_install,
        force=force,
        https_enabled=https_enabled,
        https_domain=https_domain,
        https_email=https_email,
        https_http01=https_http01,
        skip_https=skip_https,
    )


def handle_missing_docker(inputs: BootstrapInputs) -> None:
    console.warn("Docker is required to run the host stack.")
    if inputs.no_docker_install:
        console.err("Docker is missing. Install Docker and re-run.")
        raise typer.Exit(code=2)
    if not inputs.assume_yes:
        if not Confirm.ask("Docker is required. Install now?", default=True):
            console.err("Aborted: Docker is required.")
            raise typer.Exit(code=2)
    install_docker_linux()


def install_docker_linux() -> None:
    if is_windows():
        console.err("Docker auto-install is supported on Linux only. Install Docker manually and re-run.")
        raise typer.Exit(code=2)
    console.info("Installing Docker using the official convenience script.")
    cmd = "curl -fsSL https://get.docker.com | sh"
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        console.err("Docker installation failed. Please install Docker manually and re-run.")
        raise typer.Exit(code=2)
    console.ok("Docker installed. Ensure your user can run docker without sudo.")


def _ensure_remote_sudo(session: SSHSession, target: SshTarget, *, non_interactive: bool) -> None:
    if target.dry_run:
        target.sudo_mode = "nopass"
        return
    if session.run("command -v sudo >/dev/null 2>&1").returncode != 0:
        raise RuntimeError("Remote user does not have sufficient privileges (sudo required)")
    check = session.run("sudo -n true")
    if check.returncode == 0:
        target.sudo_mode = "nopass"
        return
    stderr = (check.stderr or "").lower()
    if "not in the sudoers file" in stderr or "is not allowed to run sudo" in stderr:
        raise RuntimeError("Remote user does not have sufficient privileges (sudo required)")
    if non_interactive:
        raise RuntimeError("Sudo requires a password. Re-run without --non-interactive.")
    console.info("Sudo password required for remote host.")
    sudo_password = typer.prompt("Sudo password", hide_input=True)
    verify = session.run_input("sudo -S -p '' true", f"{sudo_password}\n", log_label="sudo check")
    if verify.returncode != 0:
        raise RuntimeError("Sudo authentication failed.")
    target.sudo_password = sudo_password
    target.sudo_mode = "password"


def _remote_run(session: SSHSession,
                command: str,
                *,
                sudo: bool,
                cwd: str | None = None,
                ) -> subprocess.CompletedProcess:
    return session.run_privileged(command, cwd=cwd) if sudo else session.run(command, cwd=cwd)


def _remote_run_input(
        session: SSHSession,
        command: str,
        content: str,
        *,
        log_label: str,
        sudo: bool,
) -> subprocess.CompletedProcess:
    if sudo:
        return session.run_input_privileged(command, content, log_label=log_label)
    return session.run_input(command, content, log_label=log_label)


def _remote_command_success(session: SSHSession, command: str, *, sudo: bool) -> bool:
    res = _remote_run(session, command, sudo=sudo)
    return res.returncode == 0


def _remote_check_prereqs(session: SSHSession, *, sudo: bool) -> PrereqResult:
    docker_installed = session.run("command -v docker >/dev/null 2>&1").returncode == 0
    compose_installed = False
    docker_running = False
    if docker_installed:
        compose_installed = _remote_command_success(
            session, "docker compose version >/dev/null 2>&1", sudo=sudo
        )
        docker_running = _remote_command_success(session, "docker info >/dev/null 2>&1", sudo=sudo)
    if docker_installed and compose_installed and docker_running:
        console.ok("Docker and Docker Compose are available.")
    return PrereqResult(
        docker_installed=docker_installed,
        compose_installed=compose_installed,
        docker_running=docker_running,
    )


def _remote_handle_missing_docker(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    console.warn("Docker is required to run the host stack.")
    if inputs.no_docker_install:
        console.err("Docker is missing. Install Docker and re-run.")
        raise typer.Exit(code=2)
    if not inputs.assume_yes:
        if not Confirm.ask("Docker is required. Install now?", default=True):
            console.err("Aborted: Docker is required.")
            raise typer.Exit(code=2)
    _remote_install_docker_linux(session, sudo=sudo)


def _remote_install_docker_linux(session: SSHSession, *, sudo: bool) -> None:
    if not sudo:
        console.err("Docker installation requires sudo. Use --ssh-sudo or run as root.")
        raise typer.Exit(code=2)
    console.info("Installing Docker using the official convenience script.")
    cmd = "curl -fsSL https://get.docker.com | sh"
    res = _remote_run(session, cmd, sudo=True)
    if res.returncode != 0:
        console.err("Docker installation failed. Please install Docker manually and re-run.")
        raise typer.Exit(code=2)
    console.ok("Docker installed. Ensure your user can run docker without sudo.")


def _remote_can_write_install_dir(session: SSHSession, install_dir: str) -> bool:
    clean_dir = install_dir.rstrip("/") or "/"
    parent_dir = posixpath.dirname(clean_dir) or "/"
    dir_q = shlex.quote(clean_dir)
    parent_q = shlex.quote(parent_dir)
    cmd = f"if [ -d {dir_q} ]; then [ -w {dir_q} ]; else [ -w {parent_q} ]; fi"
    res = session.run(cmd)
    return res.returncode == 0


def _remote_write_files(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    host_dir = inputs.host_dir_posix
    data_dir = inputs.data_dir_posix
    compose_path = inputs.compose_path_posix
    env_path = inputs.env_path_posix
    readme_path = inputs.readme_path_posix
    host_q = shlex.quote(host_dir)
    exists_check = _remote_run(session, f"test -d {host_q}", sudo=sudo)
    if exists_check.returncode == 0 and not inputs.force:
        console.err(f"Install dir already exists: {host_dir}. Use --force to overwrite.")
        raise typer.Exit(code=2)
    if exists_check.returncode == 0 and inputs.force:
        backup_path = _remote_backup_host_dir(session, inputs, sudo=sudo)
        if backup_path:
            console.warn(f"Backed up existing host config to {backup_path}")

    res = _remote_run(session, f"mkdir -p {shlex.quote(host_dir)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to create remote host directory.")
        raise typer.Exit(code=2)
    res = _remote_run(session, f"mkdir -p {shlex.quote(data_dir)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to create remote data directory.")
        raise typer.Exit(code=2)

    compose_content = render_compose(inputs)
    env_content = render_env(inputs, include_root_secret=True)
    readme_content = render_readme(inputs)

    res = _remote_run_input(
        session,
        f"cat > {shlex.quote(compose_path)}",
        compose_content,
        log_label="write docker-compose.yml",
        sudo=sudo,
    )
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to write docker-compose.yml.")
        raise typer.Exit(code=2)

    res = _remote_run_input(
        session,
        f"cat > {shlex.quote(env_path)}",
        env_content,
        log_label="write .env",
        sudo=sudo,
    )
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to write .env.")
        raise typer.Exit(code=2)
    res = _remote_run(session, f"chmod 600 {shlex.quote(env_path)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to set .env permissions.")
        raise typer.Exit(code=2)

    _validate_compose_remote(session, inputs, sudo=sudo)

    res = _remote_run_input(
        session,
        f"cat > {shlex.quote(readme_path)}",
        readme_content,
        log_label="write README.txt",
        sudo=sudo,
    )
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to write README.txt.")
        raise typer.Exit(code=2)

    console.ok(f"Wrote compose file to {compose_path}")
    console.ok(f"Wrote env file to {env_path}")
    console.ok(f"Ensured data dir at {data_dir}")
    console.ok(f"Wrote README to {readme_path}")


def _remote_backup_host_dir(
        session: SSHSession, inputs: BootstrapInputs, *, sudo: bool
) -> str | None:
    host_dir = inputs.host_dir_posix
    data_dir = posixpath.join(inputs.host_dir_posix, "data")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{host_dir}.bak-{timestamp}"
    script = (
        f"host_dir={shlex.quote(host_dir)}; "
        f"data_dir={shlex.quote(data_dir)}; "
        f"backup_path={shlex.quote(backup_path)}; "
        "moved=0; "
        "mkdir -p \"$backup_path\"; "
        "for entry in \"$host_dir\"/*; do "
        "[ \"$entry\" = \"$data_dir\" ] && continue; "
        "[ -e \"$entry\" ] || continue; "
        "mv \"$entry\" \"$backup_path\"/; "
        "moved=1; "
        "done; "
        "if [ \"$moved\" -eq 0 ]; then rmdir \"$backup_path\"; fi"
    )
    res = _remote_run(session, f"sh -c {shlex.quote(script)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to backup existing host config.")
        raise typer.Exit(code=2)
    check = session.run(f"test -d {shlex.quote(backup_path)}")
    if check.returncode == 0:
        return backup_path
    return None


def _remote_run_compose(
        session: SSHSession,
        inputs: BootstrapInputs,
        args: Iterable[str],
        *,
        sudo: bool,
        capture_output: bool = False,
        check: bool = True,
) -> subprocess.CompletedProcess:
    compose_path = shlex.quote(inputs.compose_path_posix)
    env_path = shlex.quote(inputs.env_path_posix)
    cmd = (
            f"docker compose --env-file {env_path} -f {compose_path} "
            + " ".join(shlex.quote(arg) for arg in args)
    )

    res = _remote_run(
        session,
        cmd,
        sudo=sudo,
        cwd=inputs.host_dir_posix,
    )

    if check and res.returncode != 0:
        out = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
        raise RuntimeError(out or "Remote docker compose command failed.")
    return res


def _remote_compose_pull_up(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    global _LAST_PULL_STDERR
    console.info("Pulling images...")
    pull_res = _remote_run_compose(
        session, inputs, ["pull"], sudo=sudo, capture_output=True, check=False
    )
    _LAST_PULL_STDERR = (pull_res.stderr or "").strip()
    if pull_res.returncode != 0:
        _report_pull_failure(_LAST_PULL_STDERR)
        raise typer.Exit(code=2)
    console.info("Starting containers...")
    try:
        _remote_run_compose(session, inputs, ["up", "-d", "--force-recreate"], sudo=sudo, check=True)
    except RuntimeError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)
    _remote_verify_root_secret_env(session, inputs, sudo=sudo)
    console.ok("Containers started.")


def _remote_http_get(session: SSHSession, url: str, *, timeout: int = 5) -> tuple[int | None, str | None]:
    if session.run("command -v curl >/dev/null 2>&1").returncode == 0:
        cmd = f"curl -sS -m {timeout} -w '\\n%{{http_code}}' {shlex.quote(url)}"
        res = session.run(cmd)
        if res.returncode != 0:
            return None, None
        stdout = res.stdout or ""
        body, _, code = stdout.rpartition("\n")
        if not code.strip().isdigit():
            return None, body
        return int(code.strip()), body
    if session.run("command -v python3 >/dev/null 2>&1").returncode == 0:
        url_literal = json.dumps(url)
        script = "\n".join(
            [
                "python3 - <<'PY'",
                "import sys, urllib.request",
                f"url = {url_literal}",
                f"timeout = {timeout}",
                "try:",
                "    with urllib.request.urlopen(url, timeout=timeout) as r:",
                "        body = r.read().decode('utf-8', errors='ignore')",
                "        sys.stdout.write(body)",
                "        sys.stdout.write('\\n')",
                "        sys.stdout.write(str(r.status))",
                "except Exception as exc:",
                "    sys.stderr.write(str(exc))",
                "    sys.exit(1)",
                "PY",
            ]
        )
        res = session.run(script)
        if res.returncode != 0:
            return None, None
        stdout = res.stdout or ""
        body, _, code = stdout.rpartition("\n")
        if not code.strip().isdigit():
            return None, body
        return int(code.strip()), body
    return None, None


def _remote_verify_health(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    console.info("Verifying API availability on the remote host...")
    runner = _remote_command_runner(session, sudo=sudo)
    if not _wait_for_api_ready(
            inputs,
            runner=runner,
            timeout=DEFAULT_HEALTH_TIMEOUT,
            interval=DEFAULT_HEALTH_INTERVAL,
    ):
        console.err("Health check timed out on the remote host.")
        _remote_diagnose_unreachable(session, inputs, sudo=sudo)
        raise typer.Exit(code=2)
    console.ok("API is healthy.")


def _remote_bootstrap_admin(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    payload = {
        "username": inputs.admin_username,
        "password": inputs.admin_password,
        "api_key_name": inputs.admin_api_key_name,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Root-Secret": inputs.x_root_secret,
    }
    url = f"{inputs.api_base}/admin/bootstrap"
    console.info("Bootstrapping the first admin account...")
    with _remote_temporary_root_secret(session, inputs, sudo=sudo):
        for attempt in range(1, 6):
            status, body = _remote_http_post_json(session, url, payload, headers)
            if status is None:
                if attempt < 5:
                    console.warn("Failed to reach bootstrap endpoint. Retrying...")
                    time.sleep(1)
                    continue
                console.err("Failed to reach bootstrap endpoint.")
                raise typer.Exit(code=2)
            if status == 200:
                console.ok("Admin bootstrap completed.")
                return
            if status == 409:
                console.ok("Admin already exists; skipping bootstrap.")
                return
            if status == 400 and body and "already" in body.lower():
                console.ok("Admin already bootstrapped.")
                return
            if status == 403:
                console.err("Invalid root secret for bootstrap.")
                raise typer.Exit(code=2)
            _report_bootstrap_http_error(status, body)
            if attempt < 5:
                console.warn("Bootstrap did not succeed yet. Retrying...")
                time.sleep(1)
                continue
            console.err("Admin bootstrap failed. Check API logs for details.")
            raise typer.Exit(code=2)



def _remote_http_post_json(
        session: SSHSession, url: str, payload: dict[str, object], headers: dict[str, str]
) -> tuple[int | None, str | None]:
    payload_json = json.dumps(payload)
    if session.run("command -v curl >/dev/null 2>&1").returncode == 0:
        header_args = " ".join(
            f"-H {shlex.quote(f'{name}: {value}')}" for name, value in headers.items()
        )
        cmd = (
            f"curl -sS -m 10 -w '\\n%{{http_code}}' -X POST {header_args} "
            f"-d {shlex.quote(payload_json)} {shlex.quote(url)}"
        )
        res = session.run(cmd)
        if res.returncode != 0:
            return None, None
        stdout = res.stdout or ""
        body, _, code = stdout.rpartition("\n")
        if not code.strip().isdigit():
            return None, body
        return int(code.strip()), body
    if session.run("command -v python3 >/dev/null 2>&1").returncode == 0:
        url_literal = json.dumps(url)
        payload_literal = json.dumps(payload)
        headers_literal = json.dumps(headers)
        script = "\n".join(
            [
                "python3 - <<'PY'",
                "import json, sys, urllib.request",
                f"url = {url_literal}",
                f"payload = {payload_literal}",
                f"headers = {headers_literal}",
                "data = json.dumps(payload).encode('utf-8')",
                "req = urllib.request.Request(url, data=data, headers=headers, method='POST')",
                "try:",
                "    with urllib.request.urlopen(req, timeout=10) as r:",
                "        body = r.read().decode('utf-8', errors='ignore')",
                "        sys.stdout.write(body)",
                "        sys.stdout.write('\\n')",
                "        sys.stdout.write(str(r.status))",
                "except Exception as exc:",
                "    sys.stderr.write(str(exc))",
                "    sys.exit(1)",
                "PY",
            ]
        )
        res = session.run(script)
        if res.returncode != 0:
            return None, None
        stdout = res.stdout or ""
        body, _, code = stdout.rpartition("\n")
        if not code.strip().isdigit():
            return None, body
        return int(code.strip()), body
    return None, None


def _print_remote_summary(inputs: BootstrapInputs, *, ssh_host: str, public_api_url: str | None = None) -> None:
    console.rule("[bold]Next steps[/]")
    console.print(f"Remote host: {ssh_host}")
    console.print(f"Host install dir: {inputs.host_dir_posix}")
    console.print(f"Local API address: {inputs.api_base}")
    api_url = public_api_url or inputs.api_url
    console.print(f"Public api-url: {api_url}")
    console.print(f"Login from another machine: saharo auth login --url {api_url} ...")
    console.print(f"View logs: docker compose -f {inputs.compose_path_posix} logs -f api")


def _maybe_setup_https_local(inputs: BootstrapInputs) -> str | None:
    if inputs.skip_https:
        console.info("HTTPS setup skipped (--skip-https).")
        return None
    if not inputs.https_enabled:
        return None
    if is_windows():
        console.err(
            "HTTPS setup is not supported on Windows. Run bootstrap from Linux/macOS "
            "or use --skip-https."
        )
        return inputs.api_url_original
    domain = inputs.https_domain or normalize_domain(inputs.api_url)
    email = inputs.https_email or ""
    console.rule("[bold]HTTPS setup[/]")
    try:
        ensure_https(
            domain,
            email,
            DEFAULT_API_PORT,
            http01=inputs.https_http01,
            ssh_session=None,
            allow_sudo=os.geteuid() != 0,
        )
        return f"https://{domain}"
    except (HttpsSetupError, ValueError) as exc:
        report_https_failure(exc)
        console.warn("HTTPS setup failed; bootstrap completed without HTTPS.")
        console.warn(
            "Retry with: "
            f"saharo host https setup --domain {domain} --email {email} --api-port {DEFAULT_API_PORT}"
        )
        return inputs.api_url_original


def _maybe_setup_https_remote(
        session: SSHSession,
        inputs: BootstrapInputs,
        *,
        ssh_host: str,
        ssh_port: int,
        ssh_key: str | None,
        sudo: bool,
) -> str | None:
    if inputs.skip_https:
        console.info("HTTPS setup skipped (--skip-https).")
        return None
    if not inputs.https_enabled:
        return None
    domain = inputs.https_domain or normalize_domain(inputs.api_url)
    email = inputs.https_email or ""
    console.rule("[bold]HTTPS setup[/]")
    try:
        ensure_https(
            domain,
            email,
            DEFAULT_API_PORT,
            http01=inputs.https_http01,
            ssh_session=session,
            allow_sudo=sudo,
        )
        return f"https://{domain}"
    except (HttpsSetupError, ValueError) as exc:
        report_https_failure(exc)
        console.warn("HTTPS setup failed; bootstrap completed without HTTPS.")
        retry = [
            "saharo host https setup",
            f"--ssh-host {ssh_host}",
            f"--ssh-port {ssh_port}",
            f"--domain {domain}",
            f"--email {email}",
            f"--api-port {DEFAULT_API_PORT}",
        ]
        if ssh_key:
            retry.insert(3, f"--ssh-key {ssh_key}")
        if sudo:
            retry.append("--ssh-sudo")
        console.warn("Retry with: " + " ".join(retry))
        return inputs.api_url_original


def _get_api_logs(inputs: BootstrapInputs, *, tail: int = 30) -> str | None:
    try:
        res = _run_compose(inputs, ["logs", "--tail", str(tail), "api"], check=False, capture_output=True)
    except FileNotFoundError:
        return None
    output = (res.stdout or "").strip()
    if not output:
        output = (res.stderr or "").strip()
    return output or None


def _remote_get_api_logs(
        session: SSHSession, inputs: BootstrapInputs, *, tail: int = 30, sudo: bool
) -> str | None:
    res = _remote_run_compose(
        session, inputs, ["logs", "--tail", str(tail), "api"], sudo=sudo, check=False
    )
    output = (res.stdout or "").strip()
    if not output:
        output = (res.stderr or "").strip()
    return output or None


def _get_container_logs(*, tail: int = DEFAULT_HEALTH_LOG_TAIL) -> str | None:
    try:
        res = subprocess.run(
            ["docker", "logs", "--tail", str(tail), DEFAULT_API_CONTAINER],
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    output = (res.stdout or "").strip()
    if not output:
        output = (res.stderr or "").strip()
    return output or None


def _remote_get_container_logs(
        session: SSHSession, *, tail: int = DEFAULT_HEALTH_LOG_TAIL, sudo: bool
) -> str | None:
    cmd = f"docker logs --tail {tail} {DEFAULT_API_CONTAINER}"
    res = _remote_run(session, cmd, sudo=sudo)
    output = (res.stdout or "").strip()
    if not output:
        output = (res.stderr or "").strip()
    return output or None


def _local_command_runner() -> Callable[[list[str]], subprocess.CompletedProcess[str]]:
    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(cmd, text=True, capture_output=True)
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(cmd, 127, "", str(exc))

    return _run


def _remote_command_runner(
        session: SSHSession, *, sudo: bool
) -> Callable[[list[str]], subprocess.CompletedProcess[str]]:
    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        cmd_str = " ".join(shlex.quote(arg) for arg in cmd)
        return _remote_run(session, cmd_str, sudo=sudo)

    return _run


def _get_docker_health_status(
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]]
) -> str | None:
    res = runner(["docker", "inspect", "-f", "{{.State.Health.Status}}", DEFAULT_API_CONTAINER])
    if res.returncode != 0:
        return None
    status = (res.stdout or "").strip()
    if not status or status in {"<no value>", "null", "none"}:
        return None
    return status


def _curl_health_ok(
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]], url: str
) -> bool:
    res = runner(
        [
            "curl",
            "-sS",
            "-m",
            str(DEFAULT_HEALTH_CURL_TIMEOUT),
            "-w",
            "\n%{http_code}",
            url,
        ]
    )
    if res.returncode != 0:
        if res.returncode in _TRANSIENT_CURL_EXIT_CODES:
            return False
        return False
    stdout = res.stdout or ""
    body, _, code = stdout.rpartition("\n")
    if not code.strip().isdigit():
        return False
    if int(code.strip()) != 200:
        return False
    body = body.strip()
    if not body:
        return False
    return _health_body_ok_text(body)


def _health_body_ok_text(body: str) -> bool:
    try:
        payload = json.loads(body)
    except ValueError:
        return True
    if isinstance(payload, dict) and "ok" in payload:
        return bool(payload.get("ok"))
    return True


def _wait_for_api_ready(
        inputs: BootstrapInputs,
        *,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
        timeout: float,
        interval: float,
) -> bool:
    deadline = time.monotonic() + timeout
    url = f"{inputs.api_base}/health"
    while time.monotonic() < deadline:
        status = _get_docker_health_status(runner)
        if status == "healthy":
            return True
        if _curl_health_ok(runner, url):
            return True
        time.sleep(interval)
    return False


def _remote_diagnose_unreachable(
        session: SSHSession,
        inputs: BootstrapInputs,
        *,
        sudo: bool,
        health_cmd: str | None = None,
        health_result: subprocess.CompletedProcess | None = None,
) -> None:
    console.err("API is not reachable on the remote host.")
    if health_cmd:
        console.info("Remote health check command:")
        console.print(f"  {health_cmd}")
        stdout = (health_result.stdout or "").strip() if health_result else ""
        stderr = (health_result.stderr or "").strip() if health_result else ""
        console.info("Health check stdout:")
        console.print(stdout or "<empty>")
        console.info("Health check stderr:")
        console.print(stderr or "<empty>")
    compose_path = shlex.quote(inputs.compose_path_posix)
    console.info("Remote container status (docker compose ps):")
    console.print(f"  docker compose -f {compose_path} ps")
    ps_res = _remote_run_compose(session, inputs, ["ps"], sudo=sudo, check=False)
    ps_output = (ps_res.stdout or "").strip() or (ps_res.stderr or "").strip()
    if ps_output:
        console.print(ps_output)
    else:
        console.print("<empty>")
    console.info(f"Last {DEFAULT_HEALTH_LOG_TAIL} API log lines (docker logs):")
    console.print(f"  docker logs --tail {DEFAULT_HEALTH_LOG_TAIL} {DEFAULT_API_CONTAINER}")
    container_logs = _remote_get_container_logs(
        session,
        tail=DEFAULT_HEALTH_LOG_TAIL,
        sudo=sudo,
    )
    if container_logs:
        _print_logs_and_missing_hint(container_logs, tail=DEFAULT_HEALTH_LOG_TAIL)
    else:
        console.print("<empty>")
    console.info("Last 60 API log lines (docker compose logs api):")
    console.print(f"  docker compose -f {compose_path} logs --tail 60 api")
    logs = _remote_get_api_logs(session, inputs, tail=60, sudo=sudo)
    if logs:
        _print_logs_and_missing_hint(logs, tail=60)
    else:
        console.print("<empty>")
    if _compose_pull_failed(inputs):
        console.warn("Image pull failed. Check registry credentials and access.")


def _get_existing_jwt_secret_remote(
        session: SSHSession, install_dir: str, *, sudo: bool
) -> str | None:
    env_path = posixpath.join(install_dir, "host", ".env")
    res = _remote_run(session, f"cat {shlex.quote(env_path)}", sudo=sudo)
    if res.returncode != 0:
        return None
    env = read_env_content(res.stdout or "")
    jwt_secret = env.get("JWT_SECRET")
    return jwt_secret.strip() if jwt_secret else None


@contextmanager
def _remote_temporary_root_secret(
        session: SSHSession, inputs: BootstrapInputs, *, sudo: bool
) -> Iterator[None]:
    updated = _remote_ensure_root_secret_env(session, inputs, sudo=sudo)
    if updated:
        _remote_restart_api(session, inputs, sudo=sudo)
        _remote_wait_for_health(session, inputs, timeout=DEFAULT_HEALTH_TIMEOUT, sudo=sudo)
    yield


def _remote_ensure_root_secret_env(
        session: SSHSession, inputs: BootstrapInputs, *, sudo: bool
) -> bool:
    env_path = inputs.env_path_posix
    res = _remote_run(session, f"cat {shlex.quote(env_path)}", sudo=sudo)
    if res.returncode == 0:
        current = read_env_content(res.stdout or "").get("ROOT_ADMIN_SECRET")
        if current == inputs.x_root_secret:
            return False
    content = render_env(inputs, include_root_secret=True)
    res = _remote_run_input(
        session,
        f"cat > {shlex.quote(env_path)}",
        content,
        log_label="write .env",
        sudo=sudo,
    )
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to write .env.")
        raise typer.Exit(code=2)
    res = _remote_run(session, f"chmod 600 {shlex.quote(env_path)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to set .env permissions.")
        raise typer.Exit(code=2)
    return True


def _remote_restart_api(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    try:
        _remote_run_compose(
            session, inputs, ["up", "-d", "--force-recreate", "--no-deps", "api"], sudo=sudo, check=True
        )
    except RuntimeError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _remote_wait_for_health(
        session: SSHSession, inputs: BootstrapInputs, *, timeout: float, sudo: bool
) -> None:
    runner = _remote_command_runner(session, sudo=sudo)
    if _wait_for_api_ready(inputs, runner=runner, timeout=timeout, interval=DEFAULT_HEALTH_INTERVAL):
        return
    console.err("API did not become healthy after restart.")
    _remote_diagnose_unreachable(session, inputs, sudo=sudo)
    raise typer.Exit(code=2)


def _remote_verify_root_secret_env(
        session: SSHSession, inputs: BootstrapInputs, *, sudo: bool
) -> None:
    cmd = "docker exec saharo_host_api env | grep ROOT_ADMIN_SECRET"
    res = _remote_run(session, f"sh -c {shlex.quote(cmd)}", sudo=sudo)
    if res.returncode == 0:
        return
    console.err(
        "ROOT_ADMIN_SECRET not found in saharo_host_api env. "
        "The .env file may not have been applied; re-run with --force-recreate."
    )
    raise typer.Exit(code=2)


def write_files(inputs: BootstrapInputs) -> None:
    host_dir = inputs.host_dir
    if host_dir.exists() and not inputs.force:
        console.err(f"Install dir already exists: {host_dir}. Use --force to overwrite.")
        raise typer.Exit(code=2)
    if host_dir.exists() and inputs.force:
        backup_path = backup_host_dir(host_dir)
        if backup_path:
            console.warn(f"Backed up existing host config to {backup_path}")

    host_dir.mkdir(parents=True, exist_ok=True)
    inputs.data_dir.mkdir(parents=True, exist_ok=True)

    compose_content = render_compose(inputs)
    env_content = render_env(inputs, include_root_secret=True)
    readme_content = render_readme(inputs)

    inputs.compose_path.write_text(compose_content, encoding="utf-8")
    inputs.env_path.write_text(env_content, encoding="utf-8")
    os.chmod(inputs.env_path, 0o600)

    _validate_compose_local(inputs)

    inputs.readme_path.write_text(readme_content, encoding="utf-8")

    console.ok(f"Wrote compose file to {inputs.compose_path}")
    console.ok(f"Wrote env file to {inputs.env_path}")
    console.ok(f"Ensured data dir at {inputs.data_dir}")
    console.ok(f"Wrote README to {inputs.readme_path}")


def _ensure_wipe_confirmed(
        *,
        install_dir: str,
        non_interactive: bool,
        assume_yes: bool,
        confirm_wipe: bool,
        remote: bool = False,
) -> None:
    if remote:
        data_dir = posixpath.join(install_dir, "host", "data", "postgres")
    else:
        data_dir = Path(install_dir).expanduser().resolve() / "host" / "data" / "postgres"
    console.warn("DANGEROUS: you are about to delete all host data.")
    console.warn(f"Postgres data directory will be removed: {data_dir}")
    if non_interactive:
        if not (assume_yes and confirm_wipe):
            console.err("--wipe-data requires --yes and --confirm-wipe in non-interactive mode.")
            raise typer.Exit(code=2)
        return
    typed = typer.prompt("Type WIPE to confirm", default="", show_default=False)
    if typed != "WIPE":
        console.err("Wipe aborted. Type WIPE to proceed.")
        raise typer.Exit(code=1)


def wipe_host_data(inputs: BootstrapInputs) -> None:
    data_dir = inputs.data_dir
    console.warn("Wiping host data (irreversible).")
    console.info(f"Deleting data directory: {data_dir}")
    if inputs.compose_path.exists():
        console.info("Stopping containers before data wipe...")
        try:
            res = _run_compose(inputs, ["down"], check=False, capture_output=True)
        except FileNotFoundError:
            res = None
        if res and res.returncode != 0:
            console.warn((res.stderr or "").strip() or "Failed to stop containers before wipe.")
    if data_dir.exists():
        shutil.rmtree(data_dir)
        console.ok(f"Deleted {data_dir}")
    else:
        console.warn(f"No data directory found at {data_dir}")


def _remote_wipe_host_data(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    data_dir = inputs.data_dir_posix
    compose_path = shlex.quote(inputs.compose_path_posix)
    console.warn("Wiping host data on remote (irreversible).")
    console.info(f"Deleting data directory: {data_dir}")
    exists_check = _remote_run(session, f"test -f {compose_path}", sudo=sudo)
    if exists_check.returncode == 0:
        console.info("Stopping containers before data wipe...")
        try:
            _remote_run_compose(session, inputs, ["down"], sudo=sudo, check=False)
        except RuntimeError as exc:
            console.warn(str(exc))
    res = _remote_run(session, f"rm -rf {shlex.quote(data_dir)}", sudo=sudo)
    if res.returncode != 0:
        console.err(res.stderr.strip() or f"Failed to delete {data_dir}.")
        raise typer.Exit(code=2)
    console.ok(f"Deleted {data_dir}")


def compose_pull_up(inputs: BootstrapInputs) -> None:
    global _LAST_PULL_STDERR
    console.info("Pulling images...")
    pull_res = _run_compose(inputs, ["pull"], check=False, capture_output=True)
    _LAST_PULL_STDERR = (pull_res.stderr or "").strip()
    if pull_res.returncode != 0:
        _report_pull_failure(_LAST_PULL_STDERR)
        raise typer.Exit(code=2)
    console.info("Starting containers...")
    _run_compose(inputs, ["up", "-d", "--force-recreate"])
    _verify_root_secret_env(inputs)
    console.ok("Containers started.")


def _verify_root_secret_env(inputs: BootstrapInputs) -> None:
    cmd = "docker exec saharo_host_api env | grep ROOT_ADMIN_SECRET"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode == 0:
        return
    console.err(
        "ROOT_ADMIN_SECRET not found in saharo_host_api env. "
        "The .env file may not have been applied; re-run with --force-recreate."
    )
    raise typer.Exit(code=2)


def bootstrap_admin(inputs: BootstrapInputs) -> None:
    payload = {
        "username": inputs.admin_username,
        "password": inputs.admin_password,
        "api_key_name": inputs.admin_api_key_name,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Root-Secret": inputs.x_root_secret,
    }
    url = f"{inputs.api_base}/admin/bootstrap"
    console.info("Bootstrapping the first admin account...")
    with _temporary_root_secret(inputs):
        for attempt in range(1, 6):
            try:
                response = httpx.post(url, headers=headers, json=payload, timeout=10.0)
            except httpx.RequestError:
                if attempt < 5:
                    console.warn("Failed to reach bootstrap endpoint. Retrying...")
                    time.sleep(1)
                    continue
                console.err("Failed to reach bootstrap endpoint.")
                raise typer.Exit(code=2)

            if response.status_code == 200:
                console.ok("Admin bootstrap completed.")
                return
            if response.status_code == 409:
                console.ok("Admin already exists; skipping bootstrap.")
                return
            if response.status_code == 400 and "already" in response.text.lower():
                console.ok("Admin already bootstrapped.")
                return
            if response.status_code == 403:
                console.err("Invalid root secret for bootstrap.")
                raise typer.Exit(code=2)
            _report_bootstrap_http_error(response.status_code, response.text, response)
            if attempt < 5:
                console.warn("Bootstrap did not succeed yet. Retrying...")
                time.sleep(1)
                continue
            console.err("Admin bootstrap failed. Check API logs for details.")
            raise typer.Exit(code=2)


def verify_health(
        inputs: BootstrapInputs,
        *,
        ssh_session: SSHSession | None = None,
        ssh_host: str | None = None,
        sudo: bool = False,
) -> None:
    if ssh_session is not None or ssh_host is not None:
        if ssh_session is None:
            raise RuntimeError("SSH session is required for remote health checks.")
        _remote_verify_health(ssh_session, inputs, sudo=sudo)
        return
    console.info("Verifying API availability...")
    runner = _local_command_runner()
    if not _wait_for_api_ready(
            inputs,
            runner=runner,
            timeout=DEFAULT_HEALTH_TIMEOUT,
            interval=DEFAULT_HEALTH_INTERVAL,
    ):
        _diagnose_unreachable(inputs)
        raise typer.Exit(code=2)
    console.ok("API is healthy.")


def _report_bootstrap_http_error(
        status: int,
        body: str | None,
        response: httpx.Response | None = None,
) -> None:
    console.err(f"Admin bootstrap failed with HTTP {status}.")
    if body:
        console.err(f"Response body: {body}")
    if status == 422:
        data = None
        if response is not None:
            try:
                data = response.json()
            except ValueError:
                data = None
        elif body:
            try:
                data = json.loads(body)
            except ValueError:
                data = None
        if data is not None:
            console.print_json(data=data)


def print_summary(inputs: BootstrapInputs, public_api_url: str | None = None) -> None:
    console.rule("[bold]Next steps[/]")
    console.print(f"Host install dir: {inputs.host_dir}")
    console.print(f"Local API address: {inputs.api_base}")
    api_url = public_api_url or inputs.api_url
    console.print(f"Public api-url: {api_url}")
    console.print(f"Login from another machine: saharo auth login --url {api_url} ...")
    console.print(
        f"View logs: docker compose -f {inputs.compose_path} logs -f api"
    )


def render_compose(inputs: BootstrapInputs) -> str:
    api_image = f"{inputs.registry}/saharo/v1/{IMAGE_COMPONENTS['host']}:{inputs.tag}"
    compose = {
        "services": {
            "db": {
                "image": "postgres:16-alpine",
                "container_name": "saharo_host_db",
                "restart": "unless-stopped",
                "environment": {
                    "POSTGRES_DB": "${POSTGRES_DB}",
                    "POSTGRES_USER": "${POSTGRES_USER}",
                    "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}",
                },
                "volumes": ["./data/postgres:/var/lib/postgresql/data"],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}",
                    ],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 5,
                },
            },
            "api": {
                "image": api_image,
                "container_name": "saharo_host_api",
                "restart": "unless-stopped",
                "env_file": ["./.env"],
                "depends_on": {"db": {"condition": "service_healthy"}},
                "ports": [f"{DEFAULT_API_BIND}:{DEFAULT_API_PORT}:{DEFAULT_API_PORT}"],
                "volumes": ["./state:/opt/saharo/host/state"],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health').read()\"",
                    ],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 5,
                },
            },
        }
    }
    try:
        import yaml
    except Exception:
        return "\n".join(
            [
                "services:",
                "  db:",
                "    image: postgres:16-alpine",
                "    container_name: saharo_host_db",
                "    restart: unless-stopped",
                "    environment:",
                "      POSTGRES_DB: ${POSTGRES_DB}",
                "      POSTGRES_USER: ${POSTGRES_USER}",
                "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
                "    volumes:",
                "      - ./data/postgres:/var/lib/postgresql/data",
                "    healthcheck:",
                "      test: [\"CMD-SHELL\", \"pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}\"]",
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
                "  api:",
                f"    image: {api_image}",
                "    container_name: saharo_host_api",
                "    restart: unless-stopped",
                "    env_file:",
                "      - ./.env",
                "    depends_on:",
                "      db:",
                "        condition: service_healthy",
                "    ports:",
                f"      - \"{DEFAULT_API_BIND}:{DEFAULT_API_PORT}:{DEFAULT_API_PORT}\"",
                "    volumes:",
                "      - ./state:/opt/saharo/host/state",
                "    healthcheck:",
                "      test: [\"CMD-SHELL\", \"python -c \\\"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health').read()\\\"\"]",
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
            ]
        ) + "\n"
    dumped = yaml.safe_dump(compose, sort_keys=False, default_flow_style=False)
    return dumped if dumped.endswith("\n") else dumped + "\n"


def render_env(inputs: BootstrapInputs, *, include_root_secret: bool) -> str:
    database_url = f"postgresql://{_url_encode('saharo')}:{_url_encode(inputs.db_password)}@db:5432/saharo"
    lines = [
        f"APP_VERSION={inputs.tag}",
        "ENV=prod",
        "LOG_LEVEL=info",
        "POSTGRES_DB=saharo",
        "POSTGRES_USER=saharo",
        f"POSTGRES_PASSWORD={inputs.db_password}",
        f"DATABASE_URL={database_url}",
        "DB_POOL_MIN=1",
        "DB_POOL_MAX=5",
        "CORS_ALLOW_ORIGINS=" + inputs.api_url,
        "CORS_ALLOW_CREDENTIALS=true",
        f"JWT_SECRET={inputs.jwt_secret}",
    ]
    if inputs.telegram_bot_token:
        lines.append(f"TELEGRAM_BOT_TOKEN={inputs.telegram_bot_token}")
    if include_root_secret:
        lines.append(f"ROOT_ADMIN_SECRET={inputs.x_root_secret}")
    return "\n".join(lines) + "\n"


def render_readme(inputs: BootstrapInputs) -> str:
    return "\n".join(
        [
            "Saharo Host (API + Postgres)",
            "",
            "Manage services:",
            f"  docker compose -f {inputs.compose_path} ps",
            f"  docker compose -f {inputs.compose_path} logs -f api",
            f"  docker compose -f {inputs.compose_path} restart api",
            "",
            "Stop services:",
            f"  docker compose -f {inputs.compose_path} down",
            "",
            "Start services:",
            f"  docker compose -f {inputs.compose_path} up -d",
        ]
    ) + "\n"


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return read_env_content(path.read_text(encoding="utf-8"))


def read_env_content(content: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def get_existing_jwt_secret(host_dir: Path) -> str | None:
    env_path = host_dir / ".env"
    env = read_env_file(env_path)
    jwt_secret = env.get("JWT_SECRET")
    return jwt_secret.strip() if jwt_secret else None


def backup_host_dir(host_dir: Path) -> Path | None:
    if not host_dir.exists():
        return None
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = host_dir.with_name(f"{host_dir.name}.bak-{timestamp}")
    moved_any = False
    data_dir = host_dir / "data"
    backup_path.mkdir(parents=False, exist_ok=False)
    for entry in host_dir.iterdir():
        if entry == data_dir:
            continue
        shutil.move(str(entry), str(backup_path / entry.name))
        moved_any = True
    if not moved_any:
        backup_path.rmdir()
        return None
    return backup_path


def _diagnose_unreachable(inputs: BootstrapInputs) -> None:
    console.err("API is not reachable on 127.0.0.1:8010.")
    console.info("Container status (docker compose ps):")
    console.print(f"  docker compose -f {inputs.compose_path} ps")
    try:
        ps_res = _run_compose(inputs, ["ps"], check=False, capture_output=True)
    except FileNotFoundError:
        ps_res = None
    ps_output = ""
    if ps_res:
        ps_output = (ps_res.stdout or "").strip() or (ps_res.stderr or "").strip()
    if ps_output:
        console.print(ps_output)
    else:
        console.print("<empty>")
    console.info(f"Last {DEFAULT_HEALTH_LOG_TAIL} API log lines (docker logs):")
    console.print(f"  docker logs --tail {DEFAULT_HEALTH_LOG_TAIL} {DEFAULT_API_CONTAINER}")
    container_logs = _get_container_logs(tail=DEFAULT_HEALTH_LOG_TAIL)
    if container_logs:
        _print_logs_and_missing_hint(container_logs, tail=DEFAULT_HEALTH_LOG_TAIL)
    else:
        console.print("<empty>")
    console.info("Check API logs:")
    console.print(f"  docker compose -f {inputs.compose_path} logs -f api")
    logs = _get_api_logs(inputs)
    if logs:
        _print_logs_and_missing_hint(logs)

    if not _command_success(["docker", "info"]):
        console.warn("Docker daemon does not appear to be running.")
    if _port_in_use(DEFAULT_API_PORT):
        console.warn("Port 8010 is already in use on this host.")
    if _compose_pull_failed(inputs):
        console.warn("Image pull failed. Check registry credentials and access.")


def _health_body_ok(response: httpx.Response) -> bool:
    try:
        payload = response.json()
    except ValueError:
        return True
    if isinstance(payload, dict) and "ok" in payload:
        return bool(payload.get("ok"))
    return True


def _compose_pull_failed(inputs: BootstrapInputs) -> bool:
    stderr = (_LAST_PULL_STDERR or "").lower()
    return "unauthorized" in stderr or "denied" in stderr


def _run_compose(
        inputs: BootstrapInputs,
        args: Iterable[str],
        *,
        check: bool = True,
        capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "compose", "-f", str(inputs.compose_path), *args]
    if capture_output:
        return subprocess.run(cmd, check=check, text=True, capture_output=True)
    return subprocess.run(cmd, check=check)


def _validate_compose_local(inputs: BootstrapInputs) -> None:
    console.info("Validating compose file...")
    res = _run_compose(inputs, ["config", "-q"], check=False, capture_output=True)
    if res.returncode == 0:
        return
    console.err("Compose validation failed. Fix docker-compose.yml and retry.")
    stderr = (res.stderr or "").strip()
    if stderr:
        console.err("Docker/Compose stderr:")
        console.print(stderr)
    raise typer.Exit(code=2)


def _validate_compose_remote(session: SSHSession, inputs: BootstrapInputs, *, sudo: bool) -> None:
    console.info("Validating compose file...")

    compose_path = shlex.quote(inputs.compose_path_posix)
    env_path = shlex.quote(inputs.env_path_posix)
    host_dir = inputs.host_dir_posix

    cmd = f"docker compose --env-file {env_path} -f {compose_path} config -q"
    res = _remote_run(session, cmd, sudo=sudo, cwd=host_dir)

    if res.returncode == 0:
        return

    console.err("Compose validation failed on remote host. Fix docker-compose.yml and retry.")
    stderr = (res.stderr or "").strip()
    if stderr:
        console.err("Docker/Compose stderr:")
        console.print(stderr)
    raise typer.Exit(code=2)


def _remote_machine_name(session: SSHSession, *, ssh_host: str) -> str:
    hostname = ssh_host.split("@", 1)[-1]
    res = session.run("hostname")
    if res.returncode != 0:
        return hostname
    remote_name = (res.stdout or "").strip()
    return remote_name or hostname


def _report_pull_failure(stderr: str) -> None:
    console.err("Failed to pull images.")
    trimmed = stderr.strip()
    if trimmed:
        console.err("Docker/Compose stderr (last lines):")
        tail = _tail_lines(trimmed, limit=12)
        console.print("\n".join(tail))
    console.err(
        "Likely causes: missing registry login, incorrect registry URL, invalid tag/version, or network/DNS issues."
    )


def _tail_lines(text: str, *, limit: int) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-limit:] if lines else []


def _extract_missing_fields(log_text: str) -> list[str]:
    lines = log_text.splitlines()
    missing: list[str] = []
    for idx, line in enumerate(lines):
        if not _MISSING_MARKER_RE.search(line):
            continue
        for back in range(idx - 1, max(-1, idx - 4), -1):
            match = _MISSING_FIELD_RE.match(lines[back])
            if match:
                field = match.group(1)
                if field not in missing:
                    missing.append(field)
                break
    return missing


def _print_logs_and_missing_hint(log_text: str, *, tail: int = 30) -> None:
    if not log_text:
        return
    console.info(f"Last {tail} API log lines:")
    console.print(log_text)
    missing = _extract_missing_fields(log_text)
    if missing:
        console.err("Missing required settings detected in API logs: " + ", ".join(missing))


def normalize_registry_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return host
    parsed = urllib.parse.urlparse(f"//{text}")
    if parsed.netloc:
        return parsed.netloc
    return text.split("/", 1)[0]


def docker_login_local(registry_url: str, username: str, password: str) -> None:
    registry_host = normalize_registry_host(registry_url)
    if not registry_host:
        console.err("Registry URL is missing or invalid.")
        raise typer.Exit(code=2)
    try:
        result = subprocess.run(
            ["docker", "login", registry_host, "-u", username, "--password-stdin"],
            input=password.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        console.err("Docker CLI not found in PATH.")
        raise typer.Exit(code=2)
    if result.returncode == 0:
        console.ok(f"Docker login succeeded for {registry_host}.")
        return
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    console.err(f"Docker login failed: {stderr}" if stderr else "Docker login failed.")
    raise typer.Exit(code=2)


def docker_login_ssh(
        session: SSHSession,
        registry_url: str,
        username: str,
        password: str,
        *,
        sudo: bool,
) -> None:
    registry_host = normalize_registry_host(registry_url)
    if not registry_host:
        console.err("Registry URL is missing or invalid.")
        raise typer.Exit(code=2)
    cmd = (
        f"docker login {shlex.quote(registry_host)} "
        f"-u {shlex.quote(username)} --password-stdin"
    )
    res = _remote_run_input(session, cmd, password, log_label="docker login", sudo=sudo)
    if res.returncode == 0:
        console.ok(f"Docker login succeeded for {registry_host}.")
        return
    stderr = (res.stderr or "").strip()
    console.err(f"Docker login failed: {stderr}" if stderr else "Docker login failed.")
    raise typer.Exit(code=2)


def _command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _command_success(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return False
    return True


def _check_tcp(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((DEFAULT_API_BIND, port)) == 0


def _generate_jwt_secret() -> str:
    return os.urandom(32).hex()


def _url_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


@contextmanager
def _temporary_root_secret(inputs: BootstrapInputs) -> Iterator[None]:
    updated = _ensure_root_secret_env(inputs)
    if updated:
        _restart_api(inputs)
        _wait_for_health(inputs, timeout=DEFAULT_HEALTH_TIMEOUT)
    yield


def _ensure_root_secret_env(inputs: BootstrapInputs) -> bool:
    env = read_env_file(inputs.env_path)
    if env.get("ROOT_ADMIN_SECRET") == inputs.x_root_secret:
        return False
    content = render_env(inputs, include_root_secret=True)
    inputs.env_path.write_text(content, encoding="utf-8")
    os.chmod(inputs.env_path, 0o600)
    return True


def _restart_api(inputs: BootstrapInputs) -> None:
    _run_compose(inputs, ["up", "-d", "--force-recreate", "--no-deps", "api"])


def _wait_for_health(inputs: BootstrapInputs, *, timeout: float) -> None:
    runner = _local_command_runner()
    if _wait_for_api_ready(inputs, runner=runner, timeout=timeout, interval=DEFAULT_HEALTH_INTERVAL):
        return
    console.err("API did not become healthy after restart.")
    _diagnose_unreachable(inputs)
    raise typer.Exit(code=2)
