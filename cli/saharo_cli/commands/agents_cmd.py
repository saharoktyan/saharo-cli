from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass
from urllib.parse import urlparse

import typer
from rich.table import Table
from saharo_client import ApiError, NetworkError
from saharo_client.errors_utils import parse_api_error_detail
from saharo_client.resolve import resolve_agent_id_for_agents

from .host_bootstrap import DEFAULT_REGISTRY, normalize_registry_host
from .. import console
from ..config import load_config, AgentConfig, AppConfig, save_config, normalize_base_url, resolve_license_api_url
from ..formatting import format_age, format_list_timestamp
from ..http import make_client
from ..interactive import select_item, select_agent
from questionary import Choice
from ..license_resolver import (
    IMAGE_COMPONENTS,
    LicenseEntitlements,
    LicenseEntitlementsError,
    resolve_entitlements,
)
from saharo_client.registry import resolve_agent_version_from_license_payload
from ..registry_store import load_registry
from ..ssh import SshTarget, SSHSession, build_control_path, _ensure_sudo_mode, _sudo_prefix, is_windows

app = typer.Typer(help="Agents commands.")

AGENT_CONTAINER_NAME = "saharo_agent"
AGENT_STATE_VOLUME = "agent_agent_data"
AGENT_STATE_PATHS = ("/data/agent_state.json", "/data/state.json", "/data/state.toml")
REGISTRATION_TIMEOUT_S = 60
REGISTRATION_POLL_INTERVAL_S = 2
WAIT_INDICATOR_INTERVAL_S = 0.5
WATCH_POLL_INTERVAL_S = 5

DEFAULT_LIC_URL = "https://downloads.saharoktyan.ru"
DEFAULT_TAG = "1.0.0"


def _resolve_entitlements_from_license(
        lic_url: str, license_key: str
) -> LicenseEntitlements:
    try:
        return resolve_entitlements(lic_url, license_key)
    except LicenseEntitlementsError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _resolve_agent_version_from_host_api(cfg: AppConfig) -> tuple[str, str | None] | None:
    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        data = client.admin_license_versions()
    except (ApiError, NetworkError):
        return None
    finally:
        client.close()

    result = resolve_agent_version_from_license_payload(data if isinstance(data, dict) else {})
    if not result:
        return None
    tag, registry_url = result
    return tag, normalize_registry_host(registry_url) if registry_url else None


@app.command("list")
def list_agents(
        profile: str | None = typer.Option(None, "--profile", help="Config profile name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        page: int = typer.Option(1, "--page", help="Page number (1-based)."),
        page_size: int = typer.Option(50, "--page-size", help="Number of agents per page."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    if page < 1:
        console.err("--page must be >= 1.")
        raise typer.Exit(code=2)
    if page_size < 1:
        console.err("--page-size must be >= 1.")
        raise typer.Exit(code=2)
    offset = (page - 1) * page_size

    cfg = load_config()
    client = make_client(cfg, profile=profile, base_url_override=base_url)

    try:
        data = client.admin_agents_list(include_deleted=False, limit=page_size, offset=offset)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    agents = data.get("items") if isinstance(data, dict) else []
    total = data.get("total") if isinstance(data, dict) else None

    table = Table(title="Agents")
    table.add_column("id", style="bold")
    table.add_column("name")
    table.add_column("status", no_wrap=True)
    table.add_column("missed", justify="right")
    table.add_column("last_heartbeat")
    table.add_column("last_seen_at", no_wrap=True)
    table.add_column("version")

    for a in agents:
        agent_id = str(a.get("id", "-"))
        name = str(a.get("name", "-"))
        status = str(a.get("status", "-"))
        missed_val = a.get("missed_heartbeats")
        missed = "-" if missed_val is None else str(missed_val)
        age = format_age(a.get("last_seen_age_s"))
        last_seen = format_list_timestamp(a.get("last_seen_at"))
        version = str((a.get("meta") or {}).get("version", "-"))
        table.add_row(agent_id, name, status, missed, age, last_seen, version)

    console.console.print(table)
    if total is not None:
        pages = max(1, math.ceil(total / page_size))
        console.info(f"page={page}/{pages} total={total}")


@app.command("get")
def get_agent(
        agent_id: int | None = typer.Argument(None, help="Agent ID."),
        profile: str | None = typer.Option(None, "--profile", help="Config profile name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=profile, base_url_override=base_url)

    try:
        if agent_id is None:
            agent_id = select_agent(client)
        
        agent = client.agents_get(agent_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Agent {agent_id} not found")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Not authorized. Please login or use an admin token.")
            raise typer.Exit(code=2)
        raise
    finally:
        client.close()

    if json_out:
        console.print_json(agent)
        return

    # pretty-ish summary
    console.info(f"id: {agent.get('id')}")
    console.info(f"name: {agent.get('name')}")
    console.info(f"status: {agent.get('status')}")
    console.info(f"last_seen_at: {agent.get('last_seen_at')}")
    meta = agent.get("meta") or {}
    if meta:
        console.info(f"meta: {meta}")
    last_status = agent.get("last_status")
    if last_status is not None:
        console.info(f"last_status: {last_status}")


@app.command("delete")
def delete_agent(
        agent_id: int | None = typer.Argument(None, help="Agent ID."),
        yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt."),
        force: bool = typer.Option(False, "--force", help="Detach servers before deleting the agent."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    
    try:
        if agent_id is None:
            agent_id = select_agent(client)
        
        if not yes:
            if not typer.confirm(f"Delete agent {agent_id}?", default=False):
                console.info("Aborted.")
                raise typer.Exit(code=0)

        data = client.admin_agent_delete(agent_id, force=force)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Agent {agent_id} not found.")
            raise typer.Exit(code=2)
        if e.status_code == 409:
            detail = _parse_api_error_detail(e.details)
            if detail and detail.get("servers"):
                servers = ", ".join(f"{s.get('id')}:{s.get('name')}" for s in detail["servers"])
                console.err(f"Agent is attached to server(s): {servers}. Use --force to detach.")
            else:
                console.err("Agent is attached to server(s). Use --force to detach.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to delete agent: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return
    console.console.print("✓ Agent deleted.")


@app.command("uninstall", help="Run remote uninstall on an agent-managed server.")
def uninstall_agent(
        agent_name_or_id: str | None = typer.Argument(None, help="Agent name or numeric id."),
        force: bool = typer.Option(False, "--force", help="Proceed even if the agent is attached to servers."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed without deleting anything."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        if agent_name_or_id is None:
            agent_id = select_agent(client)
        else:
            agent_id = _resolve_agent_id(client, agent_name_or_id)
        data = client.admin_agent_uninstall(agent_id, force=force, dry_run=dry_run)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Agent {agent_name_or_id} not found.")
            raise typer.Exit(code=2)
        if e.status_code == 409:
            detail = _parse_api_error_detail(e.details)
            if detail and detail.get("servers"):
                servers = ", ".join(f"{s.get('id')}:{s.get('name')}" for s in detail["servers"])
                console.err(f"Agent is attached to server(s): {servers}. Use --force to detach after uninstall.")
            else:
                console.err("Agent is attached to server(s). Use --force to detach after uninstall.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to uninstall agent: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    job_id = data.get("job_id")
    console.console.print(f"✓ Uninstall job queued (job_id={job_id}).")
    console.info(f"Check status: saharo jobs get {job_id}")


@app.command("purge", help="Destroy all saharo assets on a remote host.")
def purge_agent(
        agent_name_or_id: str | None = typer.Argument(None, help="Agent name or numeric id."),
        yes_i_really_want_to_delete_everything: bool = typer.Option(
            False,
            "--yes-i-really-want-to-delete-everything",
            help="Confirm destructive cleanup of all saharo assets on the remote host.",
        ),
        force: bool = typer.Option(False, "--force", help="Proceed even if the agent is attached to servers."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed without deleting anything."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        if agent_name_or_id is None:
            agent_id = select_agent(client)
        else:
            agent_id = _resolve_agent_id(client, agent_name_or_id)
        data = client.admin_agent_purge(agent_id, force=force, dry_run=dry_run)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Agent {agent_name_or_id} not found.")
            raise typer.Exit(code=2)
        if e.status_code == 409:
            detail = _parse_api_error_detail(e.details)
            if detail and detail.get("servers"):
                servers = ", ".join(f"{s.get('id')}:{s.get('name')}" for s in detail["servers"])
                console.err(f"Agent is attached to server(s): {servers}. Use --force to detach after purge.")
            else:
                console.err("Agent is attached to server(s). Use --force to detach after purge.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to purge agent: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    job_id = data.get("job_id")
    console.console.print(f"✓ Purge job queued (job_id={job_id}).")
    console.info(f"Check status: saharo jobs get {job_id}")


def _create_agent_invite(
        name: str = typer.Option(..., "--name", help="Agent name."),
        note: str | None = typer.Option(None, "--note", help="Optional note."),
        expires_minutes: int | None = typer.Option(None, "--expires-minutes", help="Invite expiration in minutes."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.admin_agent_invite_create(name=name, note=note, expires_minutes=expires_minutes)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create invite: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    invite_id = data.get("id") or data.get("invite_id") or data.get("agent_invite_id")
    token = data.get("token")
    expires_at = data.get("expires_at")
    created_at = data.get("created_at")

    cfg.agents[name] = AgentConfig(
        agent_id=None,
        agent_secret="",
        invite_token=str(token or ""),
        note=note,
        created_at=str(created_at) if created_at else None,
        expires_at=str(expires_at) if expires_at else None,
    )
    save_config(cfg)

    table = Table(title="Bootstrap Invite")
    table.add_column("invite_id", style="bold")
    table.add_column("token")
    table.add_column("expires_at")
    table.add_row(str(invite_id or "-"), str(token or "-"), str(expires_at or "-"))
    console.console.print(table)
    install_hint = (
        "saharo servers bootstrap --name <server-name> --host <server-host> "
        f"--ssh user@ip --password --sudo"
    )
    if _is_local_base_url(cfg.base_url):
        install_hint += " --api-url http://<reachable-host>:8010"
    console.info(f"Install hint: {install_hint}")


@app.command("create")
def create_agent(
        name: str = typer.Option(..., "--name", help="Agent name."),
        note: str | None = typer.Option(None, "--note", help="Optional note."),
        expires_minutes: int | None = typer.Option(None, "--expires-minutes", help="Invite expiration in minutes."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    _create_agent_invite(name=name, note=note, expires_minutes=expires_minutes, base_url=base_url)


@app.command("install")
def install_agent(
        ssh_target: str | None = typer.Option(None, "--ssh", help="SSH target in user@host form."),
        port: int = typer.Option(22, "--port", help="SSH port."),
        key: str | None = typer.Option(None, "--key", help="SSH private key path."),
        password: bool = typer.Option(False, "--password", help="Prompt for SSH password."),
        sudo: bool = typer.Option(False, "--sudo", help="Use sudo -n for privileged commands."),
        sudo_password: bool = typer.Option(False, "--sudo-password", help="Prompt for sudo password."),
        with_docker: bool = typer.Option(False, "--with-docker", help="Bootstrap Docker if missing."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print actions without executing."),
        invite: str = typer.Option(..., "--invite", help="Invite token."),
        api_url: str | None = typer.Option(None, "--api-url", help="Override API base URL for agent."),
        force_reregister: bool = typer.Option(False, "--force-reregister",
                                              help="Force agent to re-register even if state exists."),
        timeout: int = typer.Option(REGISTRATION_TIMEOUT_S, "--timeout", help="Registration wait timeout in seconds."),
        no_wait: bool = typer.Option(False, "--no-wait", help="Skip waiting for agent registration."),
        show: bool = typer.Option(False, "--show", help="Show agent details after registration."),
        json_out: bool = typer.Option(False, "--json", help="Output machine-readable JSON only."),
        watch: bool = typer.Option(False, "--watch", help="Watch agent status after registration."),
        follow: bool = typer.Option(False, "--follow", help="Follow agent logs after registration."),
        local: bool = typer.Option(False, "--local", help="Install agent on the current machine using deploy/agent."),
        local_path: str | None = typer.Option(None, "--local-path", help="Path to local deploy/agent directory."),
        create_server: bool = typer.Option(False, "--create-server", help="Create a server record after registration."),
        version: str | None = typer.Option(None, "--version", help="Exact agent version tag to deploy, e.g. 1.4.1"),
        lic_url: str = typer.Option(DEFAULT_LIC_URL, "--lic-url",
                                    help="License API base URL used to resolve versions."),
        no_license: bool = typer.Option(False, "--no-license",
                                        help="Do not query license API; use --tag or --version."),
        tag: str = typer.Option(DEFAULT_TAG, "--tag", help="Image tag to deploy (fallback)."),
):
    cfg = load_config()
    invite_token = invite.strip()
    if not invite_token:
        console.err("Invite token is required. Use --invite or create an invite.")
        raise typer.Exit(code=2)
    if json_out and (show or watch or follow):
        console.err("--json cannot be combined with --show, --watch, or --follow.")
        raise typer.Exit(code=2)
    if no_wait and (show or watch or follow):
        console.err("--no-wait cannot be combined with --show, --watch, or --follow.")
        raise typer.Exit(code=2)
    if timeout <= 0:
        console.err("--timeout must be a positive integer.")
        raise typer.Exit(code=2)

    registry = DEFAULT_REGISTRY
    resolved_tag = None

    if version:
        resolved_tag = version
    elif not no_license:
        host_result = _resolve_agent_version_from_host_api(cfg)
        if host_result:
            resolved_tag, registry_override = host_result
            if registry_override:
                registry = registry_override
            console.ok(f"Resolved agent version from host license cache: {resolved_tag}")
        else:
            lic_url = resolve_license_api_url(cfg) or lic_url
            registry_creds = load_registry()
            license_key = registry_creds.license_key if registry_creds else None
            if not license_key:
                console.err(
                    "License key not found. Re-run `saharo host bootstrap --license-key <key>` "
                    "or pass --no-license."
                )
                raise typer.Exit(code=2)
            entitlements = _resolve_entitlements_from_license(lic_url, license_key)
            resolved_tag = entitlements.agent
            if registry_creds and registry_creds.url:
                registry = registry_creds.url
            console.ok(
                "Resolved versions from license entitlements: "
                f"host={entitlements.host} agent={entitlements.agent} cli={entitlements.cli} "
                f"(allowed major={entitlements.allowed_major if entitlements.allowed_major is not None else 'unknown'})"
            )
    else:
        resolved_tag = tag

    pwd = None
    if password:
        if is_windows():
            console.err(
                "Password SSH authentication is not supported on Windows. "
                "Use --key or run from Linux/macOS."
            )
            raise typer.Exit(code=2)
        if dry_run:
            pwd = None
        else:
            pwd = typer.prompt("SSH password (input hidden)", hide_input=True)
    sudo_pwd = None
    if sudo_password and not dry_run:
        sudo_pwd = typer.prompt("Sudo password (input hidden)", hide_input=True)

    if local:
        if is_windows():
            console.err("Local agent install is not supported on Windows. Use --ssh to connect to a Linux host.")
            raise typer.Exit(code=2)
        if ssh_target:
            console.err("--local cannot be combined with --ssh.")
            raise typer.Exit(code=2)
        if dry_run:
            console.err("--dry-run is not supported with --local.")
            raise typer.Exit(code=2)
        agent_api_url = _resolve_local_agent_api_url(cfg.base_url, api_url)
        compose_dir = _resolve_local_agent_dir(local_path)
        compose_cmd = _detect_compose_command_local()

        _check_local_api_health(agent_api_url)
        _cleanup_agent_installation_local(allow_existing_state=False)
        env_path = os.path.join(compose_dir, ".env")
        env_content = (
            f"AGENT_API_BASE={agent_api_url}\n"
            f"SAHARO_AGENT_INVITE={invite_token}\n"
        )
        if force_reregister:
            env_content += "SAHARO_AGENT_FORCE_REREGISTER=1\n"
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
        os.chmod(env_path, 0o600)
        res = _run_local_command(f"cd {compose_dir} && {compose_cmd} up -d --build")
        if res.returncode != 0:
            console.err((res.stderr or "").strip() or "Failed to start local agent container.")
            raise typer.Exit(code=2)

        deployed = True
        if not json_out:
            console.console.print("✓ Agent deployed")

        if no_wait:
            if json_out:
                _print_install_json(
                    InstallResult(
                        deployed=deployed,
                        registered=False,
                        agent_id=None,
                        elapsed_seconds=0,
                        timeout_reached=False,
                    )
                )
            else:
                console.console.print("✓ Done.")
            return

        reg_result = _wait_for_agent_registration_with_runner(
            _run_local_command,
            cfg,
            timeout_s=timeout,
            emit_output=not json_out,
        )
        _handle_registration_result(
            reg_result,
            deployed=deployed,
            timeout_s=timeout,
            json_out=json_out,
            show=show,
            watch=watch,
            follow=follow,
            cfg=cfg,
            follow_local=True,
            create_server=create_server,
        )
        return

    if not ssh_target:
        console.err("--ssh is required unless --local is set.")
        raise typer.Exit(code=2)

    agent_api_url = _resolve_agent_api_url(cfg.base_url, api_url)
    target = SshTarget(host=ssh_target, port=port, key_path=key, password=pwd, sudo=sudo, sudo_password=sudo_pwd,
                       dry_run=dry_run)
    base_dir = "/opt/saharo/agent"
    compose_path = f"{base_dir}/docker-compose.yml"
    env_path = f"{base_dir}/.env"
    ssh_user = ssh_target.split("@", 1)[0] if "@" in ssh_target else ""

    session = SSHSession(target=target, control_path=build_control_path(dry_run=dry_run))
    try:
        try:
            session.start()
        except RuntimeError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        if with_docker:
            res = session.run("command -v docker >/dev/null 2>&1 || echo missing")
            if res.returncode != 0:
                console.err(res.stderr.strip() or "Failed to check docker.")
                raise typer.Exit(code=2)
            if "missing" in (res.stdout or ""):
                try:
                    if not sudo:
                        console.err("Docker bootstrap requires sudo. Re-run with --sudo.")
                        raise typer.Exit(code=2)
                    _bootstrap_docker(session, ssh_user=ssh_user)
                except RuntimeError as e:
                    console.err(str(e))
                    raise typer.Exit(code=2)
        else:
            res = session.run("command -v docker >/dev/null 2>&1")
            if res.returncode != 0:
                console.err("Docker is missing. Use `saharo host bootstrap` or pass --with-docker.")
                raise typer.Exit(code=2)

        if with_docker:
            try:
                _ensure_compose_installed(session)
            except RuntimeError as e:
                console.err(str(e))
                raise typer.Exit(code=2)

        res = session.run_privileged(f"mkdir -p {base_dir}") if sudo else session.run(f"mkdir -p {base_dir}")
        if res.returncode != 0:
            console.err(res.stderr.strip() or "Failed to create remote directory.")
            raise typer.Exit(code=2)

        local_agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "http-agent"))
        upload_res = session.put_dir_tar(local_agent_dir, f"{base_dir}/http-agent")
        if upload_res.returncode != 0:
            console.err((upload_res.stderr or "").strip() or "Failed to upload agent sources.")
            raise typer.Exit(code=2)

        if sudo and ssh_user and ssh_user != "root":
            res = session.run_privileged(f"chown -R {ssh_user}:{ssh_user} {base_dir}")
            if res.returncode != 0:
                console.err(res.stderr.strip() or "Failed to set agent file ownership.")
                raise typer.Exit(code=2)

        compose_content = _render_agent_compose(registry, resolved_tag)
        if sudo:
            res = session.run_input_privileged(f"cat > {compose_path}", compose_content,
                                               log_label="write docker-compose.yml")
        else:
            res = session.run_input(f"cat > {compose_path}", compose_content, log_label="write docker-compose.yml")
        if res.returncode != 0:
            console.err(res.stderr.strip() or "Failed to write docker-compose.yml.")
            raise typer.Exit(code=2)

        env_content = (
            f"AGENT_API_BASE={agent_api_url}\n"
            f"SAHARO_AGENT_INVITE={invite_token}\n"
        )
        if force_reregister:
            env_content += "SAHARO_AGENT_FORCE_REREGISTER=1\n"
        if sudo:
            res = session.run_input_privileged(f"cat > {env_path}", env_content, log_label="write .env")
        else:
            res = session.run_input(f"cat > {env_path}", env_content, log_label="write .env")
        if res.returncode != 0:
            console.err(res.stderr.strip() or "Failed to write .env.")
            raise typer.Exit(code=2)
        chmod_cmd = f"chmod 600 {env_path}"
        res = session.run_privileged(chmod_cmd) if sudo else session.run(chmod_cmd)
        if res.returncode != 0:
            console.err(res.stderr.strip() or "Failed to set .env permissions.")
            raise typer.Exit(code=2)

        _check_remote_api_health(session, agent_api_url, sudo=sudo)
        _cleanup_agent_installation(session, sudo=sudo, allow_existing_state=False)
        compose_check = session.run(
            "docker compose version >/dev/null 2>&1 && echo docker-compose-plugin || echo docker-compose")
        compose_cmd = "docker compose" if "docker-compose-plugin" in (compose_check.stdout or "") else "docker-compose"
        up_cmd = f"cd {base_dir} && {compose_cmd} up -d --build"
        res = session.run_privileged(up_cmd) if sudo else session.run(up_cmd)
        if res.returncode != 0:
            console.err(res.stderr.strip() or "Failed to start agent container.")
            raise typer.Exit(code=2)

        deployed = True
        if not json_out:
            console.console.print("✓ Agent deployed")

        if no_wait:
            if json_out:
                _print_install_json(
                    InstallResult(
                        deployed=deployed,
                        registered=False,
                        agent_id=None,
                        elapsed_seconds=0,
                        timeout_reached=False,
                    )
                )
            else:
                console.console.print("✓ Done.")
            return

        reg_result = _wait_for_agent_registration(
            session,
            cfg,
            sudo=sudo,
            timeout_s=timeout,
            emit_output=not json_out,
        )
        _handle_registration_result(
            reg_result,
            deployed=deployed,
            timeout_s=timeout,
            json_out=json_out,
            show=show,
            watch=watch,
            follow=follow,
            cfg=cfg,
            follow_local=False,
            session=session,
            sudo=sudo,
            create_server=create_server,
        )
    finally:
        session.close()


def _is_local_base_url(url: str) -> bool:
    parsed = urlparse(normalize_base_url(url))
    host = parsed.hostname or ""
    return host in {"localhost", "127.0.0.1"}


def _resolve_agent_api_url(base_url: str, api_url_override: str | None) -> str:
    if api_url_override:
        return normalize_base_url(api_url_override, warn=True)
    base_url = normalize_base_url(base_url, warn=True)
    if _is_local_base_url(base_url):
        console.err(
            "API base_url points to localhost and is not reachable from remote host. "
            "Please pass --api-url http://<reachable-host>:8010"
        )
        raise typer.Exit(code=2)
    return base_url


def _resolve_local_agent_api_url(base_url: str, api_url_override: str | None) -> str:
    if api_url_override:
        return normalize_base_url(api_url_override, warn=True)
    base_url = normalize_base_url(base_url, warn=True)
    if _is_local_base_url(base_url):
        return "http://host.docker.internal:8010"
    return base_url


def _parse_api_error_detail(details: str | None) -> dict | None:
    return parse_api_error_detail(details)


def _resolve_agent_id(client, agent_name_or_id: str) -> int:
    return resolve_agent_id_for_agents(client, agent_name_or_id)


@dataclass
class RegistrationResult:
    registered: bool
    agent_id: int | None
    elapsed_seconds: int
    timeout_reached: bool
    state: dict | None = None
    invalid_state_path: str | None = None
    invalid_state_reason: str | None = None


@dataclass
class InstallResult:
    deployed: bool
    registered: bool
    agent_id: int | None
    elapsed_seconds: int
    timeout_reached: bool


def _print_install_json(result: InstallResult) -> None:
    payload = {
        "deployed": result.deployed,
        "registered": result.registered,
        "agent_id": result.agent_id,
        "elapsed_seconds": result.elapsed_seconds,
        "timeout_reached": result.timeout_reached,
    }
    print(json.dumps(payload))


def _check_remote_api_health(session: SSHSession, api_url: str, *, sudo: bool) -> None:
    if session.target.dry_run:
        console.info(f"[dry-run] would check API health at {api_url}/health")
        return
    cmd = f"curl -fsS {api_url}/health"
    runner = session.run_privileged if sudo else session.run
    res = runner(cmd)
    if res.returncode != 0:
        console.err(
            "Remote host cannot reach API health endpoint. "
            "Ensure the API URL is reachable from the remote host and try again."
        )
        raise typer.Exit(code=2)


def _check_local_api_health(api_url: str) -> None:
    res = _run_local_command(f"curl -fsS {api_url}/health")
    if res.returncode != 0:
        console.err(
            "Local host cannot reach API health endpoint. "
            "Ensure the API URL is reachable and try again."
        )
        raise typer.Exit(code=2)


def _parse_agent_state(content: str, path: str) -> dict | None:
    try:
        if path.endswith(".toml"):
            return tomllib.loads(content)
        return json.loads(content)
    except Exception:
        return None


def _state_has_credentials(state: dict) -> bool:
    agent_id = state.get("agent_id")
    agent_secret = state.get("agent_secret")
    return bool(agent_id) and bool(agent_secret)


def _fetch_agent_state(runner, path: str) -> tuple[dict | None, str | None]:
    res = runner(f"docker exec {AGENT_CONTAINER_NAME} sh -c 'test -f {path} && cat {path}'")
    if res.returncode != 0:
        return None, None
    content = (res.stdout or "").strip()
    if not content:
        return None, None
    state = _parse_agent_state(content, path)
    if state is None:
        return None, "state file is not valid JSON/TOML"
    return state, None


def _is_agent_visible(cfg: AppConfig, agent_id: str | int) -> bool:
    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        client.agents_get(agent_id)
        return True
    except (ApiError, NetworkError, Exception):
        return False
    finally:
        client.close()


def _find_agent_state(runner) -> tuple[dict | None, str | None, str | None]:
    last_invalid_path = None
    last_invalid_reason = None
    for path in AGENT_STATE_PATHS:
        state, error = _fetch_agent_state(runner, path)
        if state is None:
            if error:
                last_invalid_path = path
                last_invalid_reason = error
            continue
        if _state_has_credentials(state):
            return state, None, None
        last_invalid_path = path
        last_invalid_reason = "state missing agent_id/agent_secret"
    return None, last_invalid_path, last_invalid_reason


def _terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).columns


def _clear_wait_line(width: int | None = None) -> None:
    if width is None:
        width = _terminal_width()
    console.console.print("\r" + (" " * width) + "\r", end="")


def _render_wait_line(message: str, dots: str, elapsed: int, timeout_s: int, width: int) -> str:
    timer = f"({elapsed}s / {timeout_s}s)"
    base = f"{message}{dots}"
    min_gap = 1
    if width <= len(base) + len(timer) + min_gap:
        return f"{base} {timer}"
    gap = width - len(base) - len(timer)
    return f"{base}{' ' * gap}{timer}"


def _wait_for_agent_registration_with_runner(
        runner,
        cfg: AppConfig,
        *,
        timeout_s: int = REGISTRATION_TIMEOUT_S,
        poll_interval_s: int = REGISTRATION_POLL_INTERVAL_S,
        indicator_interval_s: float = WAIT_INDICATOR_INTERVAL_S,
        emit_output: bool = True,
) -> RegistrationResult:
    start = time.time()
    deadline = start + timeout_s
    next_poll = start
    next_indicator = start
    dot_states = (".", "..", "...")
    dot_index = 0
    last_invalid_path = None
    last_invalid_reason = None
    last_agent_id = None
    width = _terminal_width()

    if emit_output:
        console.console.print("Waiting for agent registration", end="\r")
    try:
        while True:
            now = time.time()
            if now >= next_poll:
                state, invalid_path, invalid_reason = _find_agent_state(runner)
                if state is not None:
                    agent_id = state.get("agent_id")
                    last_agent_id = agent_id
                    if agent_id and _is_agent_visible(cfg, agent_id):
                        if emit_output:
                            _clear_wait_line(width)
                        elapsed = int(now - start)
                        return RegistrationResult(
                            registered=True,
                            agent_id=int(agent_id),
                            elapsed_seconds=elapsed,
                            timeout_reached=False,
                            state=state,
                        )
                if invalid_path:
                    last_invalid_path = invalid_path
                    last_invalid_reason = invalid_reason
                next_poll = now + poll_interval_s

            if now >= deadline:
                break

            if now >= next_indicator:
                elapsed = int(now - start)
                dots = dot_states[dot_index]
                dot_index = (dot_index + 1) % len(dot_states)
                if emit_output:
                    width = _terminal_width()
                    line = _render_wait_line("Waiting for agent registration", dots, elapsed, timeout_s, width)
                    console.console.print(line, end="\r")
                next_indicator = now + indicator_interval_s

            sleep_for = min(
                max(0.0, next_poll - now),
                max(0.0, next_indicator - now),
                max(0.0, deadline - now),
            )
            if sleep_for > 0:
                time.sleep(sleep_for)
    except KeyboardInterrupt:
        if emit_output:
            _clear_wait_line(width)
        raise

    if emit_output:
        _clear_wait_line(width)
    elapsed = int(time.time() - start)
    return RegistrationResult(
        registered=False,
        agent_id=int(last_agent_id) if last_agent_id else None,
        elapsed_seconds=elapsed,
        timeout_reached=True,
        invalid_state_path=last_invalid_path,
        invalid_state_reason=last_invalid_reason,
    )


def _wait_for_agent_registration(
        session: SSHSession,
        cfg: AppConfig,
        *,
        sudo: bool,
        timeout_s: int = REGISTRATION_TIMEOUT_S,
        poll_interval_s: int = REGISTRATION_POLL_INTERVAL_S,
        indicator_interval_s: float = WAIT_INDICATOR_INTERVAL_S,
        emit_output: bool = True,
) -> RegistrationResult:
    if session.target.dry_run:
        console.info("[dry-run] would wait for agent registration")
        return RegistrationResult(
            registered=False,
            agent_id=None,
            elapsed_seconds=0,
            timeout_reached=False,
        )
    runner = session.run_privileged if sudo else session.run
    return _wait_for_agent_registration_with_runner(
        runner,
        cfg,
        timeout_s=timeout_s,
        poll_interval_s=poll_interval_s,
        indicator_interval_s=indicator_interval_s,
        emit_output=emit_output,
    )


def _watch_agent_status(cfg: AppConfig, agent_id: int, *, poll_interval_s: int = WATCH_POLL_INTERVAL_S) -> None:
    client = make_client(cfg, profile=None, base_url_override=None)
    last_snapshot: dict | None = None
    console.info("Watching agent status. Press Ctrl+C to stop.")
    try:
        while True:
            try:
                agent = client.agents_get(agent_id)
            except (ApiError, NetworkError, Exception) as e:
                console.warn(f"Failed to fetch agent status: {e}")
                time.sleep(poll_interval_s)
                continue

            snapshot = {
                "status": agent.get("status"),
                "last_seen_at": agent.get("last_seen_at"),
                "version": (agent.get("meta") or {}).get("version"),
            }
            if snapshot != last_snapshot:
                console.info(
                    f"status={snapshot.get('status')} last_seen_at={snapshot.get('last_seen_at')} "
                    f"version={snapshot.get('version')}"
                )
                last_snapshot = snapshot
            time.sleep(poll_interval_s)
    except KeyboardInterrupt:
        return
    finally:
        client.close()


def _follow_agent_logs(session: SSHSession, *, sudo: bool) -> None:
    console.info("Streaming agent logs. Press Ctrl+C to stop.")
    cmd = f"docker logs -f {AGENT_CONTAINER_NAME}"
    if session.target.dry_run:
        console.info(f"[dry-run] would run: {cmd}")
        return
    if sudo:
        _ensure_sudo_mode(session.target)
        cmd = f"{_sudo_prefix(session.target)} {cmd}"
    ssh_cmd = session._ssh_base_cmd(control_master=False) + [session.target.host, cmd]
    try:
        if sudo and session.target.sudo_mode == "password":
            proc = subprocess.Popen(ssh_cmd, text=True, stdin=subprocess.PIPE)
            if proc.stdin:
                proc.stdin.write(f"{session.target.sudo_password}\n")
                proc.stdin.flush()
            proc.wait()
        else:
            subprocess.run(ssh_cmd, text=True)
    except KeyboardInterrupt:
        return


def _follow_agent_logs_local() -> None:
    console.info("Streaming agent logs. Press Ctrl+C to stop.")
    try:
        subprocess.run(f"docker logs -f {AGENT_CONTAINER_NAME}", shell=True, text=True)
    except KeyboardInterrupt:
        return


def _cleanup_agent_installation_with_runner(
        runner,
        *,
        allow_existing_state: bool,
        label: str = "agent",
) -> None:
    res = runner(f"docker ps -a --filter name=^/{AGENT_CONTAINER_NAME}$ -q")
    if res.returncode != 0:
        console.err(res.stderr.strip() or f"Failed to check existing {label} container.")
        raise typer.Exit(code=2)
    if (res.stdout or "").strip():
        console.info(f"Removing existing {label} container...")
        rm_res = runner(f"docker rm -f {AGENT_CONTAINER_NAME}")
        if rm_res.returncode != 0:
            console.err(rm_res.stderr.strip() or f"Failed to remove existing {label} container.")
            raise typer.Exit(code=2)

    res = runner(f"docker volume inspect {AGENT_STATE_VOLUME} >/dev/null 2>&1")
    if res.returncode == 0:
        console.info(f"Removing existing {label} state volume {AGENT_STATE_VOLUME}...")
        rm_res = runner(f"docker volume rm -f {AGENT_STATE_VOLUME}")
        if rm_res.returncode != 0:
            console.err(rm_res.stderr.strip() or f"Failed to remove existing {label} state volume.")
            raise typer.Exit(code=2)

    res = runner(f"docker volume inspect {AGENT_STATE_VOLUME} >/dev/null 2>&1")
    if res.returncode == 0 and not allow_existing_state:
        console.err(
            f"Existing {label} state volume {AGENT_STATE_VOLUME} detected. "
            "Refusing to reuse state; re-run with --force-reregister to proceed."
        )
        raise typer.Exit(code=2)


def _cleanup_agent_installation(
        session: SSHSession,
        *,
        sudo: bool,
        allow_existing_state: bool,
        label: str = "agent",
) -> None:
    if session.target.dry_run:
        console.info(f"[dry-run] would remove existing {label} container")
        console.info(f"[dry-run] would remove existing {label} state volume {AGENT_STATE_VOLUME}")
        return
    runner = session.run_privileged if sudo else session.run
    _cleanup_agent_installation_with_runner(runner, allow_existing_state=allow_existing_state, label=label)


def _cleanup_agent_installation_local(*, allow_existing_state: bool, label: str = "agent") -> None:
    _cleanup_agent_installation_with_runner(_run_local_command, allow_existing_state=allow_existing_state, label=label)


def _resolve_local_agent_dir(local_path: str | None) -> str:
    if local_path:
        compose_dir = os.path.abspath(local_path)
    else:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        compose_dir = os.path.join(repo_root, "deploy", "agent")
    compose_file = os.path.join(compose_dir, "docker-compose.yml")
    if not os.path.exists(compose_file):
        console.err(f"docker-compose.yml not found at {compose_file}")
        raise typer.Exit(code=2)
    return compose_dir


def _handle_registration_result(
        reg_result: RegistrationResult,
        *,
        deployed: bool,
        timeout_s: int,
        json_out: bool,
        show: bool,
        watch: bool,
        follow: bool,
        cfg: AppConfig,
        follow_local: bool,
        session: SSHSession | None = None,
        sudo: bool = False,
        create_server: bool = False,
) -> None:
    if reg_result.timeout_reached or not reg_result.registered:
        if json_out:
            _print_install_json(
                InstallResult(
                    deployed=deployed,
                    registered=False,
                    agent_id=None,
                    elapsed_seconds=reg_result.elapsed_seconds,
                    timeout_reached=True,
                )
            )
        else:
            console.err(f"✗ Agent did not register within {timeout_s} seconds")
            if reg_result.invalid_state_path:
                console.err(
                    f"Agent state file at {reg_result.invalid_state_path} is invalid: {reg_result.invalid_state_reason}"
                )
            elif reg_result.agent_id:
                console.err("Agent state found but agent is not visible in API.")
        raise typer.Exit(code=2)

    agent_id = reg_result.agent_id
    if not agent_id:
        if json_out:
            _print_install_json(
                InstallResult(
                    deployed=deployed,
                    registered=False,
                    agent_id=None,
                    elapsed_seconds=reg_result.elapsed_seconds,
                    timeout_reached=False,
                )
            )
        else:
            console.err("Agent registration did not produce an agent_id.")
        raise typer.Exit(code=2)
    if json_out:
        _print_install_json(
            InstallResult(
                deployed=deployed,
                registered=True,
                agent_id=agent_id,
                elapsed_seconds=reg_result.elapsed_seconds,
                timeout_reached=False,
            )
        )
        return

    console.console.print(f"✓ Agent registered successfully (id={agent_id})")
    if create_server:
        _run_create_server_wizard(cfg, agent_id)
    if show and agent_id:
        show_agent(agent_id, base_url=cfg.base_url, json_out=False)
    if watch and agent_id:
        _watch_agent_status(cfg, agent_id)
    if follow:
        if follow_local:
            _follow_agent_logs_local()
        elif session:
            _follow_agent_logs(session, sudo=sudo)
    console.console.print("✓ Done.")


def _prompt_required_field(prompt_text: str) -> str:
    while True:
        value = typer.prompt(prompt_text)
        trimmed = value.strip()
        if trimmed:
            return trimmed
        console.err("Value cannot be empty.")


def _run_create_server_wizard(cfg: AppConfig, agent_id: int) -> None:
    try:
        host = _prompt_required_field("Host/IP (example: 1.2.3.4 or my-vps.example.com)")
        name = _prompt_required_field("Server name")
        console.info(f"Agent id: {agent_id}")
        note = typer.prompt("Note (optional)", default="", show_default=False)
    except KeyboardInterrupt:
        console.info("Server creation canceled.")
        return

    note_value = note.strip() if isinstance(note, str) else ""
    note_payload = note_value or None

    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        server = client.admin_server_create(name=name, host=host, agent_id=agent_id, note=note_payload)
    except ApiError as e:
        if e.status_code == 404:
            console.err("Agent not found.")
            raise typer.Exit(code=2)
        if e.status_code == 409:
            console.err("Server name already exists.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create server: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    server_id = server.get("id")
    server_name = server.get("name") or name
    server_host = server.get("public_host") or host
    console.ok(f"Created server {server_id}: {server_name} ({server_host})")


# -----------------------------
# Local / remote helper utilities
# -----------------------------


def _run_local_command(cmd: str, *, timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run a shell command locally.

    This is used by --local agent installation flow.
    """
    return subprocess.run(
        cmd,
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _detect_compose_command_local() -> str:
    """Return the docker compose command available on the current machine."""
    # Prefer Compose v2 plugin: `docker compose`
    if shutil.which("docker"):
        try:
            res = _run_local_command("docker compose version")
            if res.returncode == 0:
                return "docker compose"
        except Exception:
            pass

    # Fallback to legacy docker-compose binary
    if shutil.which("docker-compose"):
        return "docker-compose"

    console.err("Docker Compose is not installed. Install Docker Compose v2 or docker-compose.")
    raise typer.Exit(code=2)


def _ensure_compose_installed(session: SSHSession, *, sudo: bool = True) -> str:
    """Ensure docker compose exists on remote host and return the command string."""

    # helper: run a command with/without sudo
    def _run(cmd: str):
        return session.run_privileged(cmd) if sudo else session.run(cmd)

    # Try docker compose (v2 plugin)
    res = _run("docker compose version >/dev/null 2>&1")
    if getattr(res, "returncode", 1) == 0:
        return "docker compose"

    # Try docker-compose (v1)
    res = _run("docker-compose version >/dev/null 2>&1")
    if getattr(res, "returncode", 1) == 0:
        return "docker-compose"

    # If neither exists, attempt to install compose plugin (best effort)
    # NOTE: keep it simple; if you already have an installer function, call it here instead.
    # For Debian/Ubuntu:
    #   apt-get update && apt-get install -y docker-compose-plugin
    install_cmds = [
        "command -v apt-get >/dev/null 2>&1 && (apt-get update -y >/dev/null 2>&1 || true) && apt-get install -y docker-compose-plugin >/dev/null 2>&1",
        "command -v yum >/dev/null 2>&1 && yum install -y docker-compose-plugin >/dev/null 2>&1",
        "command -v dnf >/dev/null 2>&1 && dnf install -y docker-compose-plugin >/dev/null 2>&1",
    ]
    for cmd in install_cmds:
        _run(cmd)

    res = _run("docker compose version >/dev/null 2>&1")
    if getattr(res, "returncode", 1) == 0:
        return "docker compose"

    raise RuntimeError(
        "Docker Compose not found on remote host. Install docker compose plugin (docker-compose-plugin) and re-run."
    )


def _bootstrap_docker(session: SSHSession, *, ssh_user: str | None = None) -> None:
    """Best-effort docker bootstrap.

    Historically this project had a more opinionated installer. For now, we keep a
    lightweight check to avoid crashing the CLI when --ssh flow is used.
    """
    # Validate docker is present
    res = session.run("docker version", check=False, sudo=True)
    if not res.ok:
        raise RuntimeError(
            "Docker is not installed or not accessible. Install Docker on the target host first."
        )


def _render_agent_compose(registry: str, tag: str) -> str:
    agent_image = f"{registry}/saharo/v1/{IMAGE_COMPONENTS['agent']}:{tag}"

    return "\n".join([
        "services:",
        "  http-agent:",
        f"    image: {agent_image}",
        "    container_name: saharo_agent",
        "    restart: unless-stopped",
        "    env_file:",
        "      - ./.env",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock",
        "      - agent_data:/data",
        "      - /opt/saharo/services/amnezia-awg/conf:/opt/saharo/services/amnezia-awg/conf",
        "      - /opt/saharo/services:/opt/saharo/services",
        "",
        "volumes:",
        "  agent_data:",
        "",
    ]) + "\n"
