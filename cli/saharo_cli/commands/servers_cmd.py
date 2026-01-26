from __future__ import annotations

import json
import math
import os
import posixpath
import shlex
from datetime import datetime, timezone

import typer
from rich import box
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text
from saharo_client import ApiError, AuthError, NetworkError
from saharo_client.jobs import job_status_hint, wait_job
from saharo_client.registry import (
    extract_registry_creds_from_snapshot,
    resolve_agent_version_from_license_payload,
)
from saharo_client.polling import wait_for_server_heartbeat
from saharo_client.resolve import ResolveError, find_server_by_name, resolve_server_id_for_servers

from . import agents_cmd
from .host_bootstrap import DEFAULT_REGISTRY, docker_login_ssh, normalize_registry_host
from .. import console
from ..config import load_config, normalize_base_url
from ..formatting import format_age, format_list_timestamp
from ..http import make_client
from ..ssh import is_windows

app = typer.Typer(help="Servers commands.")

protocol_app = typer.Typer(help="Manage server protocols (install, validate, apply config).")
app.add_typer(protocol_app, name="protocol")

protocol_awg_app = typer.Typer(help="AWG protocol commands.")
protocol_app.add_typer(protocol_awg_app, name="awg")

SERVICE_PROTOCOL_MAP = {
    "xray": "xray",
    "amnezia-awg": "awg",
}

PROTOCOL_SERVICE_MAP = {
    "awg": "amnezia-awg",
    "xray": "xray",
}

DEFAULT_AGENT_HEARTBEAT_INTERVAL_S = 30
DEFAULT_AGENT_POLL_INTERVAL_S = 10


def _validate_ssh_key_path(raw_path: str) -> str:
    path = os.path.expanduser(raw_path.strip())
    if not path:
        raise RuntimeError("SSH key path is empty.")
    if path.endswith(".pub"):
        raise RuntimeError("SSH key must be a private key, not a .pub file.")
    if not os.path.exists(path):
        raise RuntimeError(f"SSH key not found: {path}")
    return path


def _resolve_agent_version_from_host_api(cfg, base_url_override: str | None) -> tuple[str, str | None]:
    client = make_client(cfg, profile=None, base_url_override=base_url_override)
    try:
        data = client.admin_license_versions()
    except AuthError as exc:
        console.err(f"Host API auth failed: {exc}")
        raise typer.Exit(code=2)
    except NetworkError as exc:
        console.err(f"Host API request failed: {exc}")
        raise typer.Exit(code=2)
    except ApiError as exc:
        if exc.status_code == 503:
            console.err(str(exc))
        else:
            console.err(f"Failed to resolve license versions: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()
    result = resolve_agent_version_from_license_payload(data if isinstance(data, dict) else {})
    if not result:
        console.err("Invalid license cache response: missing resolved_versions.agent.")
        raise typer.Exit(code=2)
    agent_tag, registry_url = result
    if registry_url:
        registry_url = normalize_registry_host(registry_url) or None
    return agent_tag.strip(), registry_url


def _render_agent_env(
        *,
        agent_api_url: str,
        invite_token: str,
        registry_url: str,
        registry_username: str,
        registry_password: str,
        agent_version: str,
        heartbeat_interval_s: int,
        poll_interval_s: int,
        force_reregister: bool,
) -> str:
    lines = [
        f"AGENT_API_BASE={agent_api_url}",
        f"SAHARO_AGENT_INVITE={invite_token}",
        f"REGISTRY_URL={registry_url}",
        f"REGISTRY_USERNAME={registry_username}",
        f"REGISTRY_PASSWORD={registry_password}",
        f"AGENT_VERSION={agent_version}",
        f"AGENT_HEARTBEAT_INTERVAL_S={heartbeat_interval_s}",
        f"AGENT_POLL_INTERVAL_S={poll_interval_s}",
    ]
    if force_reregister:
        lines.append("SAHARO_AGENT_FORCE_REREGISTER=1")
    return "\n".join(lines) + "\n"


def _render_agent_readme(*, compose_path: str) -> str:
    return "\n".join(
        [
            "Saharo Agent (runtime)",
            "",
            "Manage services:",
            f"  docker compose -f {compose_path} ps",
            f"  docker compose -f {compose_path} logs -f http-agent",
            f"  docker compose -f {compose_path} restart http-agent",
            "",
            "Stop services:",
            f"  docker compose -f {compose_path} down",
            "",
            "Start services:",
            f"  docker compose -f {compose_path} up -d",
        ]
    ) + "\n"


def _fetch_registry_creds_from_host_api(
        cfg,
        base_url_override: str | None,
) -> tuple[str, str, str] | None:
    client = make_client(cfg, profile=None, base_url_override=base_url_override)
    try:
        snapshot = client.admin_license_snapshot()
    except (ApiError, AuthError, NetworkError):
        return None
    finally:
        client.close()

    return extract_registry_creds_from_snapshot(snapshot if isinstance(snapshot, dict) else {})


def _require_registry_activation(cfg, base_url_override: str | None) -> tuple[str, str, str]:
    host_creds = _fetch_registry_creds_from_host_api(cfg, base_url_override)
    if host_creds:
        return host_creds
    console.err(
        "Registry credentials are unavailable from the host API. "
        "Re-run `saharo host bootstrap` with a valid license key or restore host licensing."
    )
    raise typer.Exit(code=2)


def _is_registry_auth_error(text: str) -> bool:
    lowered = (text or "").lower()
    return (
            "unauthorized" in lowered
            or "authentication required" in lowered
            or "access denied" in lowered
            or "requested access to the resource is denied" in lowered
            or "forbidden" in lowered
            or "401" in lowered
            or "403" in lowered
    )


def _protocol_to_service(proto: str) -> str:
    p = (proto or "").strip().lower()
    svc = PROTOCOL_SERVICE_MAP.get(p)
    if not svc:
        console.err(f"Unsupported protocol: {proto}")
        raise typer.Exit(code=2)
    return svc


def _job_status_hint(job_id: int | None) -> str:
    return job_status_hint(job_id)


def _wait_job(client, job_id: int, *, timeout_s: int = 900, interval_s: int = 5) -> dict:
    def _on_status(jid: int, status: str) -> None:
        console.info(f"job {jid}: {status}")

    def _on_timeout(jid: int) -> None:
        console.err("Job did not finish before timeout.")

    return wait_job(
        client,
        job_id,
        timeout_s=timeout_s,
        interval_s=interval_s,
        on_status=_on_status,
        on_timeout=_on_timeout,
    )


def _resolve_server_id_or_exit(client, server_ref: str) -> int:
    try:
        return _resolve_server_id(client, server_ref)
    except typer.Exit:
        raise
    except Exception:
        console.err(f"Failed to resolve server: {server_ref}")
        raise typer.Exit(code=2)


@protocol_app.command("list")
def protocol_list(
        server_ref: str = typer.Option(..., "--server", help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """List protocols registered for a server (what API thinks is installed/available)."""
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id_or_exit(client, server_ref)

        data = client.admin_server_protocols_list(server_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err("Server not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to list server protocols: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    table = Table(title=f"Server {server_ref} protocols")
    table.add_column("protocol", style="bold")
    table.add_column("status", no_wrap=True)
    table.add_column("meta")

    for p in data or []:
        code = str(p.get("code") or p.get("protocol") or p.get("key") or "-")
        status = str(p.get("status") or "-")
        meta = p.get("meta")
        meta_s = json.dumps(meta) if isinstance(meta, dict) else (str(meta) if meta is not None else "")
        table.add_row(code, status, meta_s)

    console.console.print(table)


@protocol_app.command("bootstrap")
def protocol_bootstrap(
        protocol: str = typer.Argument(..., help="Protocol to bootstrap (awg, xray, etc)."),
        server_ref: str = typer.Option(..., "--server", help="Server ID or exact name."),
        force: bool = typer.Option(False, "--force", help="Reinstall even if container exists."),
        wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for bootstrap job to finish."),
        wait_timeout: int = typer.Option(900, "--wait-timeout", help="Max seconds to wait for bootstrap."),
        wait_interval: int = typer.Option(5, "--wait-interval", help="Poll interval in seconds."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """Bootstrap (install) a protocol on a server."""
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id_or_exit(client, server_ref)

        svc = _protocol_to_service(protocol)
        data = client.admin_server_bootstrap(server_id, services=[svc], force=force)
        if wait:
            job_id = int(data.get("job_id") or 0)
            if job_id:
                job = _wait_job(client, job_id, timeout_s=wait_timeout, interval_s=wait_interval)
                # record protocol availability in DB
                status = str(job.get("status") or "").lower()
                proto_key = SERVICE_PROTOCOL_MAP.get(svc)
                if proto_key:
                    if status == "succeeded":
                        client.admin_server_protocol_upsert(server_id, protocol_key=proto_key, status="available",
                                                            meta={"source": "bootstrap", "service": svc})
                    elif status == "failed":
                        client.admin_server_protocol_upsert(server_id, protocol_key=proto_key, status="unavailable",
                                                            meta={"source": "bootstrap", "service": svc})
    except ApiError as e:
        if e.status_code == 404:
            console.err("Server not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to bootstrap protocol: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    job_id = data.get("job_id")
    console.ok(f"Bootstrap job queued (id={job_id}).")
    console.info(f"services: {', '.join(data.get('services') or [])}")
    console.info(_job_status_hint(job_id))


def bootstrap_server(
        server_ref: str,
        *,
        xray: bool,
        awg: bool,
        all_services: bool,
        wait: bool,
        wait_timeout: int = 900,
        wait_interval: int = 5,
        base_url: str | None,
        json_out: bool,
) -> None:
    services: list[str] = []
    if all_services:
        services = ["xray", "amnezia-awg"]
    else:
        if xray:
            services.append("xray")
        if awg:
            services.append("amnezia-awg")

    if not services:
        console.err("Select at least one service to bootstrap.")
        raise typer.Exit(code=2)

    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id_or_exit(client, server_ref)
        data = client.admin_server_bootstrap(server_id, services=services)
        if wait:
            job_id = int(data.get("job_id") or 0)
            if job_id:
                job = _wait_job(client, job_id, timeout_s=wait_timeout, interval_s=wait_interval)
                status = str(job.get("status") or "").lower()
                installed = (
                    (job.get("result") or {}).get("installed_services")
                    or (job.get("payload") or {}).get("requested_services")
                    or services
                )
                if isinstance(installed, list):
                    for svc in installed:
                        proto_key = SERVICE_PROTOCOL_MAP.get(str(svc))
                        if not proto_key:
                            continue
                        if status == "succeeded":
                            client.admin_server_protocol_upsert(
                                server_id,
                                protocol_key=proto_key,
                                status="available",
                                meta={"source": "bootstrap", "service": str(svc)},
                            )
                        elif status == "failed":
                            client.admin_server_protocol_upsert(
                                server_id,
                                protocol_key=proto_key,
                                status="unavailable",
                                meta={"source": "bootstrap", "service": str(svc)},
                            )
    except ApiError as e:
        if e.status_code == 404:
            console.err("Server not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to bootstrap server: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return
    job_id = data.get("job_id")
    console.ok(f"Bootstrap job queued (id={job_id}).")
    console.info(f"services: {', '.join(data.get('services') or [])}")
    console.info(_job_status_hint(job_id))


@protocol_app.command("validate")
def protocol_validate(
        protocol: str = typer.Argument(..., help="Protocol to validate (awg, xray, etc)."),
        server_ref: str = typer.Option(..., "--server", help="Server ID or exact name."),
        wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for validate job to finish."),
        wait_timeout: int = typer.Option(300, "--wait-timeout", help="Max seconds to wait for validate."),
        wait_interval: int = typer.Option(5, "--wait-interval", help="Poll interval in seconds."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """Validate that server-side protocol config matches what API expects."""
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id_or_exit(client, server_ref)

        proto = (protocol or '').strip().lower()
        data = client.admin_server_protocol_validate(server_id, protocol_key=proto)
        if wait:
            job_id = int(data.get("job_id") or 0)
            if job_id:
                job = _wait_job(client, job_id, timeout_s=wait_timeout, interval_s=wait_interval)
                data = {"job_id": job_id, "job": job}

    except ApiError as e:
        if e.status_code == 409:
            console.err(f"Protocol '{protocol}' is not installed on this server.")
            raise typer.Exit(code=2)
        if e.status_code == 404:
            console.err("Server not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to validate protocol: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    # Pretty-print basic validate result
    job = (data or {}).get("job") if isinstance(data, dict) else None
    if isinstance(job, dict):
        status = str(job.get("status") or "").lower()
        if status == "succeeded":
            console.ok("Validation succeeded.")
        elif status:
            console.err(f"Validation finished with status: {status}")
        result = job.get("result")
        if result is not None:
            console.print_json(result)
    else:
        job_id = data.get("job_id")
        console.ok(f"Validate job queued (id={job_id}).")
        console.info(_job_status_hint(job_id))


@protocol_awg_app.command("params")
def protocol_awg_params(
        server_ref: str = typer.Option(..., "--server", help="Server ID or exact name."),
        show: bool = typer.Option(False, "--show", help="Show current AWG params for server (no changes)."),
        jc: str | None = typer.Option(None, "--jc"),
        jmin: str | None = typer.Option(None, "--jmin"),
        jmax: str | None = typer.Option(None, "--jmax"),
        s1: str | None = typer.Option(None, "--s1"),
        s2: str | None = typer.Option(None, "--s2"),
        h1: str | None = typer.Option(None, "--h1"),
        h2: str | None = typer.Option(None, "--h2"),
        h3: str | None = typer.Option(None, "--h3"),
        h4: str | None = typer.Option(None, "--h4"),
        mtu: int | None = typer.Option(None, "--mtu"),
        apply: bool = typer.Option(False, "--apply", help="Apply config on server after saving."),
        wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for apply job to finish."),
        wait_timeout: int = typer.Option(300, "--wait-timeout", help="Max seconds to wait for apply."),
        wait_interval: int = typer.Option(5, "--wait-interval", help="Poll interval in seconds."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """Set AWG AmneziaWG params (J*/S*/H*) and MTU for a server."""
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id_or_exit(client, server_ref)
        if show:
            if apply or any(
                    v is not None
                    for v in (jc, jmin, jmax, s1, s2, h1, h2, h3, h4)
            ) or (mtu is not None):
                console.err("--show cannot be combined with param flags or --apply.")
                raise typer.Exit(code=2)

            data = client.admin_server_awg_params_get(server_id)
            if json_out:
                console.print_json(data)
                return

            params = data.get("params_json") if isinstance(data, dict) else None
            if not isinstance(params, dict):
                params = {}
            params.pop("server_public_key", None)

            table = Table(title=f"AWG params (server {server_id})", box=box.SIMPLE)
            table.add_column("Param")
            table.add_column("Value", justify="right")
            for k in sorted(params.keys()):
                table.add_row(k, str(params[k]))
            console.print(table)
            return

        patch: dict[str, object] = {}
        for k, v in {
            "jc": jc, "jmin": jmin, "jmax": jmax,
            "s1": s1, "s2": s2,
            "h1": h1, "h2": h2, "h3": h3, "h4": h4,
        }.items():
            if v is not None:
                patch[k] = v
        if mtu is not None:
            patch["mtu"] = int(mtu)

        if not patch:
            console.err("No params provided.")
            raise typer.Exit(code=2)

        data = client.admin_server_awg_params_set(server_id, patch)

        apply_job = None
        if apply:
            apply_data = client.admin_server_protocol_apply(server_id, protocol_key="awg")
            job_id = int(apply_data.get("job_id") or 0)
            if wait and job_id:
                apply_job = _wait_job(client, job_id, timeout_s=wait_timeout, interval_s=wait_interval)
            else:
                apply_job = {"job_id": job_id, "queued": True}

        if json_out:
            out = {"updated": data, "apply": apply_job}
            console.print_json(out)
            return

        console.ok(f"OK AWG params updated for server {server_id}.")
        if apply:
            if isinstance(apply_job, dict) and apply_job.get("status") == "succeeded":
                console.ok("Apply succeeded.")
            elif isinstance(apply_job, dict) and apply_job.get("status"):
                console.err(f"Apply finished with status: {apply_job.get('status')}")
            else:
                job_id = apply_job.get("job_id") if isinstance(apply_job, dict) else None
                console.info(f"Apply job queued (id={job_id}).")
                console.info(_job_status_hint(job_id))
    except ApiError as e:
        if e.status_code == 409:
            console.err("Protocol 'awg' is not installed on this server.")
            raise typer.Exit(code=2)
        if e.status_code == 404:
            console.err("Server not found.")
            raise typer.Exit(code=2)
        console.err(f"Failed to set AWG params: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()


def _age_from_iso(ts: str | None) -> str:
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        s = int((now - dt).total_seconds())
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m{s % 60:02d}s"
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    except Exception:
        return "-"


def _resolve_server_id(client, server_ref: str) -> int:
    try:
        return resolve_server_id_for_servers(client, server_ref)
    except ResolveError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _find_server_by_name(client, name: str) -> dict | None:
    try:
        return find_server_by_name(client, name)
    except ResolveError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _create_bootstrap_invite(
        *,
        cfg,
        name: str,
        note: str | None,
        expires_minutes: int | None,
        base_url_override: str | None,
) -> str:
    client = make_client(cfg, profile=None, base_url_override=base_url_override)
    try:
        data = client.admin_agent_invite_create(name=name, note=note, expires_minutes=expires_minutes)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create bootstrap invite: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()
    token = data.get("token")
    if not token:
        console.err("Invite token missing from API response.")
        raise typer.Exit(code=2)
    return str(token)


def _resolve_existing_registration(runner, cfg) -> int | None:
    state, _, _ = agents_cmd._find_agent_state(runner)
    if not state:
        return None
    agent_id = state.get("agent_id")
    if not agent_id:
        return None
    if agents_cmd._is_agent_visible(cfg, agent_id):
        try:
            return int(agent_id)
        except (TypeError, ValueError):
            return None
    return None


def _wait_for_registration(runner, cfg, *, timeout_s: int, json_out: bool) -> agents_cmd.RegistrationResult:
    if not json_out:
        console.info("Waiting for server registration...")
    return agents_cmd._wait_for_agent_registration_with_runner(
        runner,
        cfg,
        timeout_s=timeout_s,
        emit_output=False,
    )


def _require_registration(reg_result: agents_cmd.RegistrationResult, *, timeout_s: int) -> int:
    if reg_result.timeout_reached or not reg_result.registered or not reg_result.agent_id:
        console.err(f"Server did not register within {timeout_s} seconds.")
        if reg_result.invalid_state_path:
            console.err(
                f"State file at {reg_result.invalid_state_path} is invalid: {reg_result.invalid_state_reason}"
            )
        raise typer.Exit(code=2)
    return int(reg_result.agent_id)


def _ensure_server_record(client, *, name: str, host: str, agent_id: int, note: str | None) -> dict:
    try:
        return client.admin_server_create(name=name, host=host, agent_id=agent_id, note=note)
    except ApiError as e:
        if e.status_code == 409:
            existing = _find_server_by_name(client, name)
            if not existing:
                console.err("Server already exists but could not be resolved by name.")
                raise typer.Exit(code=2)
            existing_host = existing.get("public_host")
            if existing_host and existing_host != host:
                console.warn(
                    f"Server '{name}' already exists with host {existing_host}; keeping existing record."
                )
            return existing
        if e.status_code == 404:
            console.err("Server runtime was not found during registration.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create server: {e}")
        raise typer.Exit(code=2)


def _wait_for_server_heartbeat(
        client,
        server_id: int,
        *,
        timeout_s: int,
        interval_s: int,
        json_out: bool,
) -> dict:
    def _on_status(sid: int, status: str) -> None:
        if not json_out:
            console.info(f"server {sid}: {status}")

    def _on_timeout(sid: int) -> None:
        if not json_out:
            console.err("No heartbeat detected before timeout.")

    return wait_for_server_heartbeat(
        client,
        server_id,
        timeout_s=timeout_s,
        interval_s=interval_s,
        on_status=_on_status,
        on_timeout=_on_timeout,
    )


@app.command("list")
def list_servers(
        q: str | None = typer.Option(None, "--q", help="Search by name or public_host."),
        page: int = typer.Option(1, "--page", help="Page number (1-based)."),
        page_size: int = typer.Option(50, "--page-size", help="Number of servers per page."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
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
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.admin_servers_list(q=q, limit=page_size, offset=offset)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to list servers: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    items = data.get("items") if isinstance(data, dict) else []
    total = data.get("total") if isinstance(data, dict) else None

    table = Table(title="Servers")
    table.add_column("id", style="bold")
    table.add_column("name")
    table.add_column("host")
    table.add_column("status", no_wrap=True)
    table.add_column("missed", justify="right")
    table.add_column("last_heartbeat")
    table.add_column("last_seen_at", no_wrap=True)

    for s in items or []:
        server_id = str(s.get("id", "-"))
        name = str(s.get("name", "-"))
        host = str(s.get("public_host") or "-")
        status = str(s.get("status") or "-")
        missed_val = s.get("missed_heartbeats")
        missed = "-" if missed_val is None else str(missed_val)
        age = format_age(s.get("last_seen_age_s"))
        last_seen = format_list_timestamp(s.get("last_seen_at"))
        table.add_row(server_id, name, host, status, missed, age, last_seen)

    console.console.print(table)
    if total is not None:
        pages = max(1, math.ceil(total / page_size))
        console.info(f"page={page}/{pages} total={total}")


@app.command("create", hidden=True)
def create_server(
        name: str = typer.Option(..., "--name", help="Server name."),
        host: str = typer.Option(..., "--host", help="Server host (IP or DNS)."),
        agent_id: int = typer.Option(..., "--agent-id", help="Runtime ID (internal)."),
        note: str | None = typer.Option(None, "--note", help="Optional note."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.admin_server_create(name=name, host=host, agent_id=agent_id, note=note)
    except ApiError as e:
        if e.status_code == 404:
            console.err("Runtime not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create server: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    table = Table(title="Server Created")
    table.add_column("id", style="bold")
    table.add_column("name")
    table.add_column("host")
    table.add_column("runtime_id")
    table.add_column("note")
    table.add_row(
        str(data.get("id", "-")),
        str(data.get("name", "-")),
        str(data.get("public_host") or "-"),
        str(data.get("agent_id") or "-"),
        str(data.get("note") or "-"),
    )
    console.console.print(table)


def _show_server_impl(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id(client, server_ref)
        data = client.admin_server_get(server_id)
        protocols = client.admin_server_protocols_list(server_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Server '{server_ref}' not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to fetch server: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        data = dict(data)
        data["protocols"] = protocols
        console.print_json(data)
        return

    hidden_keys = {"agent_id"}
    for key in sorted(data.keys()):
        if key in hidden_keys:
            continue
        console.info(f"{key}: {data.get(key)}")
    if protocols:
        rendered = ", ".join(
            f"{p.get('code')}:{p.get('status') or 'unknown'}" for p in protocols if p.get("code")
        )
        console.info(f"protocols: {rendered}")


@app.command("get")
def get_server(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    _show_server_impl(server_ref=server_ref, base_url=base_url, json_out=json_out)


@app.command("show", hidden=True)
def show_server(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    _show_server_impl(server_ref=server_ref, base_url=base_url, json_out=json_out)


@app.command("status")
def server_status(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
        raw: bool = typer.Option(False, "--raw", help="Show raw last_status JSON (debug)."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id(client, server_ref)
        data = client.admin_server_status(server_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Server '{server_ref}' not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to fetch server status: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    server_id = data.get("server_id")
    online = bool(data.get("online"))
    status = data.get("status") or ("online" if online else "offline")

    last_seen_at = data.get("last_seen_at")
    age_s = data.get("last_seen_age_s")
    # ---- Header line (one красивый заголовок вместо кучи строчек)
    hdr = Text()
    hdr.append(f"Server {server_id}", style="bold")
    hdr.append(" — ")
    hdr.append(status.upper(), style="green" if online else "red")

    hb = data.get("last_heartbeat")
    if hb is not None:
        hdr.append(f"  •  last heartbeat {hb} ago", style="dim")
    elif isinstance(age_s, int):
        hdr.append(f"  •  last seen {format_age(age_s)} ago", style="dim")

    console.print(hdr)

    # ---- Services table
    last_status = data.get("last_status") or {}
    services = last_status.get("services") or []

    if services:
        t = Table(
            title="Services",
            box=box.SQUARE,  # <- как в agents list: рамка + вертикальные разделители
            show_header=True,
            header_style="bold",
            show_lines=False,
            pad_edge=True,  # <- чтобы рамка выглядела “как таблица”, а не как текст
        )
        t.add_column("NAME", no_wrap=True)
        t.add_column("STATE", no_wrap=True)
        t.add_column("STARTED", overflow="fold")
        t.add_column("AGE", justify="right", no_wrap=True)

        for s in services:
            name = str(s.get("container") or s.get("name") or "unknown")
            up = bool(s.get("up"))
            started_at = s.get("started_at")
            state = Text("UP" if up else "DOWN", style="green" if up else "magenta")
            started = str(started_at) if started_at else "-"
            age = _age_from_iso(started_at)
            t.add_row(name, state, started, age)

        console.console.print(t)
    else:
        console.console.print(Panel("No service status reported yet.", title="Services", style="dim"))

    checked_at = last_status.get("checked_at")
    if checked_at:
        console.console.print(Text(f"Checked at: {checked_at}", style="dim"))

    # ---- Recent jobs
    jobs = data.get("jobs") or []
    if jobs:
        jt = Table(
            title="Recent jobs",
            box=box.SQUARE,
            show_header=True,
            header_style="bold",
            pad_edge=True,
        )
        jt.add_column("ID", justify="right", no_wrap=True)
        jt.add_column("TYPE", no_wrap=True)
        jt.add_column("STATUS", no_wrap=True)
        jt.add_column("CREATED", overflow="fold")
        jt.add_column("FINISHED", overflow="fold")

        for j in jobs:
            jid = str(j.get("id") or "-")
            jtype = str(j.get("type") or "-")
            st = str(j.get("status") or "-")

            if st == "succeeded":
                st_cell = Text(st, style="green")
            elif st == "failed":
                st_cell = Text(st, style="magenta")
            elif st == "running":
                st_cell = Text(st, style="yellow")
            else:
                st_cell = Text(st, style="dim")

            created = str(j.get("created_at") or "-")
            finished = str(j.get("finished_at") or "-")

            jt.add_row(jid, jtype, st_cell, created, finished)

        console.console.print(jt)

    if raw and last_status:
        pretty = json.dumps(last_status, ensure_ascii=False, indent=2, sort_keys=True)
        console.console.print(Panel(pretty, title="last_status (raw)", border_style="dim"))


def _detach_server_impl(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id(client, server_ref)
        data = client.admin_server_detach_agent(server_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Server '{server_ref}' not found.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to detach server runtime: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return
    console.ok(f"Detached server runtime from server {server_id}.")


@app.command("detach")
def detach_server(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    _detach_server_impl(server_ref=server_ref, base_url=base_url, json_out=json_out)


@app.command("detach-agent", hidden=True)
def detach_server_agent(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    _detach_server_impl(server_ref=server_ref, base_url=base_url, json_out=json_out)


@app.command("delete")
def delete_server(
        server_ref: str = typer.Argument(..., help="Server ID or exact name."),
        force: bool = typer.Option(False, "--force", help="Detach runtime before deleting the server."),
        yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server_id = _resolve_server_id(client, server_ref)
        if not yes:
            confirmed = typer.confirm(f"Delete server {server_id}?", default=False)
            if not confirmed:
                console.info("Aborted.")
                raise typer.Exit(code=0)
        data = client.admin_server_delete(server_id, force=force)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Server '{server_ref}' not found.")
            raise typer.Exit(code=2)
        if e.status_code == 409:
            console.err("Server is attached to a runtime. Detach it first or use --force.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to delete server: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return
    console.ok(f"Deleted server {server_id}.")


@app.command("bootstrap")
def bootstrap(
        protocol: str | None = typer.Argument(None, help="Legacy: protocol to bootstrap (awg, xray, etc)."),
        server_ref: str | None = typer.Option(None, "--server", help="Legacy: server ID or exact name."),
        name: str | None = typer.Option(None, "--name", help="Server name."),
        host: str | None = typer.Option(None, "--host", help="Server host (IP or DNS)."),
        note: str | None = typer.Option(None, "--note", help="Optional note."),
        invite_expires_minutes: int | None = typer.Option(None, "--invite-expires-minutes",
                                                          help="Invite expiration in minutes."),
        ssh_target: str | None = typer.Option(None, "--ssh", help="SSH target in user@host form."),
        port: int = typer.Option(22, "--port", help="SSH port."),
        key: str | None = typer.Option(None, "--key", help="SSH private key path."),
        password: bool = typer.Option(False, "--password", help="Prompt for SSH password."),
        sudo: bool = typer.Option(False, "--sudo", help="Use sudo -n for privileged commands."),
        sudo_password: bool = typer.Option(False, "--sudo-password", help="Prompt for sudo password."),
        no_remote_login: bool = typer.Option(False, "--no-remote-login", help="Skip docker login on the remote host."),
        with_docker: bool = typer.Option(False, "--with-docker", help="Bootstrap Docker if missing."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print actions without executing."),
        api_url: str | None = typer.Option(None, "--api-url", help="Override API base URL for the runtime."),
        force_reregister: bool = typer.Option(False, "--force-reregister",
                                              help="Force re-register even if state exists."),
        heartbeat_interval_s: int = typer.Option(
            DEFAULT_AGENT_HEARTBEAT_INTERVAL_S,
            "--heartbeat-interval",
            help="Agent heartbeat interval in seconds.",
        ),
        poll_interval_s: int = typer.Option(
            DEFAULT_AGENT_POLL_INTERVAL_S,
            "--poll-interval",
            help="Agent job poll interval in seconds.",
        ),
        force: bool = typer.Option(False, "--force", help="Legacy: reinstall protocol even if container exists."),
        register_timeout: int = typer.Option(agents_cmd.REGISTRATION_TIMEOUT_S, "--register-timeout",
                                             help="Registration wait timeout in seconds."),
        wait: bool = typer.Option(True, "--wait/--no-wait",
                                  help="Wait for protocol job completion or server heartbeat."),
        wait_timeout: int = typer.Option(300, "--wait-timeout",
                                         help="Max seconds to wait for completion or heartbeat."),
        wait_interval: int = typer.Option(5, "--wait-interval", help="Poll interval in seconds."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
        local: bool = typer.Option(False, "--local", help="Install locally using the bundled runtime deploy files."),
        local_path: str | None = typer.Option(None, "--local-path", help="Path to local runtime deploy directory."),
        lic_url: str = typer.Option(agents_cmd.DEFAULT_LIC_URL, "--lic-url",
                                    help="License API base URL used to resolve versions."),
        no_license: bool = typer.Option(False, "--no-license", help="Do not query license API for agent version."),
        agent_version: str | None = typer.Option(None, "--agent-version",
                                                 help="Exact agent version tag to deploy, e.g. 1.4.1"),
        registry: str = typer.Option(DEFAULT_REGISTRY, "--registry", help="Container registry for agent images."),
):
    """Bootstrap a new server runtime and register the server.

    Example:
      saharo servers bootstrap --name my-vps --host 203.0.113.10 --ssh root@203.0.113.10 --sudo
    """
    ssh_password_value = None
    sudo_password_value = None

    if protocol:
        if not server_ref:
            console.err("--server is required when using protocol bootstrap.")
            raise typer.Exit(code=2)
        if any([name, host, note, ssh_target, local]):
            console.err("Server bootstrap flags cannot be combined with protocol bootstrap.")
            raise typer.Exit(code=2)
        return protocol_bootstrap(
            protocol=protocol,
            server_ref=server_ref,
            force=force,
            wait=wait,
            wait_timeout=wait_timeout,
            wait_interval=wait_interval,
            base_url=base_url,
            json_out=json_out,
        )
    if server_ref:
        console.err("--server is only valid with protocol bootstrap.")
        raise typer.Exit(code=2)

    if key:
        try:
            key = _validate_ssh_key_path(key)
        except RuntimeError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)

    use_wizard = not name or not host or (not local and not ssh_target)
    if use_wizard:
        console.rule("[bold]Saharo Server Bootstrap[/]")
    if local and ssh_target:
        console.err("--local cannot be combined with --ssh.")
        raise typer.Exit(code=2)
    if not local and not ssh_target:
        if is_windows():
            console.info("Local server bootstrap is not supported on Windows.")
            ssh_host = typer.prompt("SSH host (e.g. 203.0.113.10)")
            ssh_user = typer.prompt("SSH user", default="root")
            ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        elif Confirm.ask("Install on a remote host via SSH?", default=False):
            ssh_host = typer.prompt("SSH host (e.g. 203.0.113.10)")
            ssh_user = typer.prompt("SSH user", default="root")
            ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        else:
            local = True
    if local and is_windows():
        console.err("Local server bootstrap is not supported on Windows. Use SSH to connect to a Linux host.")
        raise typer.Exit(code=2)
    if not local and not ssh_target:
        console.err("--ssh is required unless --local is set.")
        raise typer.Exit(code=2)
    if not local and use_wizard:
        port = typer.prompt("SSH port", default=port)
    if not local:
        if not key and not password:
            if Confirm.ask("Use an SSH private key for authentication?", default=True):
                key_input = typer.prompt(
                    "SSH private key path",
33                    default="~/.ssh/id_ed25519",
                )
                try:
                    key = _validate_ssh_key_path(key_input)
                except RuntimeError as exc:
                    console.err(str(exc))
                    raise typer.Exit(code=2)
            else:
                ssh_password_value = typer.prompt("SSH password (input hidden)", hide_input=True)
        if password and not dry_run:
            ssh_password_value = typer.prompt("SSH password (input hidden)", hide_input=True)
            password = False
        ssh_user = ssh_target.split("@", 1)[0] if "@" in ssh_target else ""
        if ssh_user and ssh_user != "root" and not sudo:
            if not Confirm.ask(
                "Remote user is not root. Use sudo privileges (required)?",
                default=True,
            ):
                console.err("Sudo privileges are required to install the agent.")
                raise typer.Exit(code=2)
            sudo = True
        if sudo and not dry_run and not sudo_password:
            sudo_password_value = typer.prompt(
                "Sudo password (input hidden, leave blank if none)",
                default="",
                show_default=False,
                hide_input=True,
            )
            if sudo_password_value and sudo_password_value.strip():
                sudo_password = False
            else:
                sudo_password_value = None
    if not name:
        name = typer.prompt("Server name")
    if not host:
        host = typer.prompt("Server host (IP or DNS)")
    if heartbeat_interval_s <= 0:
        console.err("--heartbeat-interval must be a positive integer.")
        raise typer.Exit(code=2)
    if poll_interval_s <= 0:
        console.err("--poll-interval must be a positive integer.")
        raise typer.Exit(code=2)
    if use_wizard:
        heartbeat_interval_s = typer.prompt(
            "Agent heartbeat interval (seconds)",
            default=DEFAULT_AGENT_HEARTBEAT_INTERVAL_S,
        )
        poll_interval_s = typer.prompt(
            "Agent job poll interval (seconds)",
            default=DEFAULT_AGENT_POLL_INTERVAL_S,
        )
        if heartbeat_interval_s <= 0:
            console.err("Heartbeat interval must be a positive integer.")
            raise typer.Exit(code=2)
        if poll_interval_s <= 0:
            console.err("Poll interval must be a positive integer.")
            raise typer.Exit(code=2)
    if register_timeout <= 0:
        console.err("--register-timeout must be a positive integer.")
        raise typer.Exit(code=2)
    if dry_run:
        if json_out:
            console.print_json({"dry_run": True, "deployed": False})
        else:
            console.info("Dry run: no changes applied.")
        return

    cfg = load_config()
    effective_base_url = normalize_base_url(base_url or cfg.base_url, warn=True)
    invite_token = _create_bootstrap_invite(
        cfg=cfg,
        name=name,
        note=note,
        expires_minutes=invite_expires_minutes,
        base_url_override=base_url,
    )

    if agent_version:
        resolved_tag = agent_version
    elif not no_license:
        resolved_tag, registry_override = _resolve_agent_version_from_host_api(cfg, base_url_override=base_url)
        if registry_override:
            registry = registry_override
    else:
        resolved_tag = agents_cmd.DEFAULT_TAG
    registry = normalize_registry_host(registry)
    if not registry:
        console.err("Registry URL is missing or invalid.")
        raise typer.Exit(code=2)
    console.info(f"Resolved agent version: {resolved_tag}")

    agent_id = None
    deployed = False
    if local:
        agent_api_url = agents_cmd._resolve_local_agent_api_url(effective_base_url, api_url)
        compose_dir = agents_cmd._resolve_local_agent_dir(local_path)
        compose_cmd = agents_cmd._detect_compose_command_local()
        agents_cmd._check_local_api_health(agent_api_url)

        runner = agents_cmd._run_local_command
        if not force_reregister:
            agent_id = _resolve_existing_registration(runner, cfg)
            if agent_id is not None and not json_out:
                console.info("Existing registration detected; reusing runtime state.")
            if agent_id is not None:
                deployed = True

        if agent_id is None:
            agents_cmd._cleanup_agent_installation_local(allow_existing_state=False, label="bootstrap")
            env_path = f"{compose_dir}/.env"
            registry_url, registry_username, registry_password = _require_registry_activation(cfg, base_url)
            env_content = _render_agent_env(
                agent_api_url=agent_api_url,
                invite_token=invite_token,
                registry_url=registry_url,
                registry_username=registry_username,
                registry_password=registry_password,
                agent_version=resolved_tag,
                heartbeat_interval_s=heartbeat_interval_s,
                poll_interval_s=poll_interval_s,
                force_reregister=force_reregister,
            )
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(env_content)
            os.chmod(env_path, 0o600)
            compose_content = agents_cmd._render_agent_compose(registry, resolved_tag)
            compose_path = os.path.join(compose_dir, "docker-compose.yml")
            with open(compose_path, "w", encoding="utf-8") as f:
                f.write(compose_content)
            readme_path = os.path.join(compose_dir, "README.txt")
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(_render_agent_readme(compose_path=compose_path))
            res = runner(f"cd {compose_dir} && {compose_cmd} pull")
            if res.returncode != 0:
                console.err((res.stderr or "").strip() or "Failed to pull bootstrap container.")
                raise typer.Exit(code=2)
            res = runner(f"cd {compose_dir} && {compose_cmd} up -d")
            if res.returncode != 0:
                console.err((res.stderr or "").strip() or "Failed to start bootstrap container.")
                raise typer.Exit(code=2)
            deployed = True
            if not json_out:
                console.ok("Bootstrap runtime deployed.")

            reg_result = _wait_for_registration(runner, cfg, timeout_s=register_timeout, json_out=json_out)
            agent_id = _require_registration(reg_result, timeout_s=register_timeout)
    else:
        pwd = None
        if ssh_password_value is not None:
            pwd = ssh_password_value
        elif password:
            if is_windows():
                console.err(
                    "Password SSH authentication is not supported on Windows. "
                    "Use --key or run from Linux/macOS."
                )
                raise typer.Exit(code=2)
            if not dry_run:
                pwd = typer.prompt("SSH password (input hidden)", hide_input=True)
        sudo_pwd = None
        if sudo_password_value is not None:
            sudo_pwd = sudo_password_value
        elif sudo_password and not dry_run:
            sudo_pwd = typer.prompt("Sudo password (input hidden)", hide_input=True)

        agent_api_url = agents_cmd._resolve_agent_api_url(effective_base_url, api_url)
        target = agents_cmd.SshTarget(
            host=ssh_target,
            port=port,
            key_path=key,
            password=pwd,
            sudo=sudo,
            sudo_password=sudo_pwd,
            dry_run=dry_run,
        )
        base_dir = posixpath.join("/opt", "saharo", "agent")
        compose_path = posixpath.join(base_dir, "docker-compose.yml")
        env_path = posixpath.join(base_dir, ".env")
        base_dir_q = shlex.quote(base_dir)
        compose_path_q = shlex.quote(compose_path)
        env_path_q = shlex.quote(env_path)
        ssh_user = ssh_target.split("@", 1)[0] if "@" in ssh_target else ""

        session = agents_cmd.SSHSession(target=target, control_path=agents_cmd.build_control_path(dry_run=dry_run))
        try:
            try:
                session.start()
            except RuntimeError as exc:
                console.err(str(exc))
                raise typer.Exit(code=2)
            runner = session.run_privileged if sudo else session.run
            if not force_reregister:
                agent_id = _resolve_existing_registration(runner, cfg)
                if agent_id is not None and not json_out:
                    console.info("Existing registration detected; reusing runtime state.")
                if agent_id is not None:
                    deployed = True

            if agent_id is None:
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
                            agents_cmd._bootstrap_docker(session, ssh_user=ssh_user)
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
                        agents_cmd._ensure_compose_installed(session)
                    except RuntimeError as e:
                        console.err(str(e))
                        raise typer.Exit(code=2)

                res = session.run_privileged(f"mkdir -p {base_dir_q}") if sudo else session.run(
                    f"mkdir -p {base_dir_q}")
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to create remote directory.")
                    raise typer.Exit(code=2)

                registry_url, registry_username, registry_password = _require_registry_activation(cfg, base_url)
                compose_content = agents_cmd._render_agent_compose(registry, resolved_tag)
                if sudo:
                    res = session.run_input_privileged(
                        f"cat > {compose_path_q}",
                        compose_content,
                        log_label="write docker-compose.yml",
                    )
                else:
                    res = session.run_input(
                        f"cat > {compose_path_q}",
                        compose_content,
                        log_label="write docker-compose.yml",
                    )
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to write docker-compose.yml.")
                    raise typer.Exit(code=2)

                env_content = _render_agent_env(
                    agent_api_url=agent_api_url,
                    invite_token=invite_token,
                    registry_url=registry_url,
                    registry_username=registry_username,
                    registry_password=registry_password,
                    agent_version=resolved_tag,
                    heartbeat_interval_s=heartbeat_interval_s,
                    poll_interval_s=poll_interval_s,
                    force_reregister=force_reregister,
                )
                if sudo:
                    res = session.run_input_privileged(f"cat > {env_path_q}", env_content, log_label="write .env")
                else:
                    res = session.run_input(f"cat > {env_path_q}", env_content, log_label="write .env")
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to write .env.")
                    raise typer.Exit(code=2)
                chmod_cmd = f"chmod 600 {env_path_q}"
                res = session.run_privileged(chmod_cmd) if sudo else session.run(chmod_cmd)
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to set .env permissions.")
                    raise typer.Exit(code=2)
                readme_content = _render_agent_readme(compose_path=compose_path)
                readme_path = posixpath.join(base_dir, "README.txt")
                readme_path_q = shlex.quote(readme_path)
                if sudo:
                    res = session.run_input_privileged(
                        f"cat > {readme_path_q}",
                        readme_content,
                        log_label="write README.txt",
                    )
                else:
                    res = session.run_input(
                        f"cat > {readme_path_q}",
                        readme_content,
                        log_label="write README.txt",
                    )
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to write README.txt.")
                    raise typer.Exit(code=2)

                agents_cmd._check_remote_api_health(session, agent_api_url, sudo=sudo)
                agents_cmd._cleanup_agent_installation(session, sudo=sudo, allow_existing_state=False,
                                                       label="bootstrap")

                agent_image = f"{registry}/saharo/v1/agent:{resolved_tag}"
                pull_image_cmd = f"docker pull {agent_image}"
                pull_runner = session.run_privileged if sudo else session.run
                pre_pull = pull_runner(pull_image_cmd)
                pre_pull_output = f"{pre_pull.stdout or ''}\n{pre_pull.stderr or ''}"
                if pre_pull.returncode == 0:
                    console.info("Remote registry pull succeeded; skipping docker login.")
                else:
                    if _is_registry_auth_error(pre_pull_output):
                        console.info("Remote registry requires authentication.")
                        if no_remote_login:
                            console.err("Remote docker login skipped (--no-remote-login); cannot pull agent image.")
                            raise typer.Exit(code=2)
                        console.info("Attempting docker login on remote host...")
                        login_ok = True
                        try:
                            docker_login_ssh(
                                session,
                                registry_url,
                                registry_username,
                                registry_password,
                                sudo=sudo,
                            )
                        except typer.Exit:
                            login_ok = False
                        retry_pull = pull_runner(pull_image_cmd)
                        retry_output = f"{retry_pull.stdout or ''}\n{retry_pull.stderr or ''}"
                        if retry_pull.returncode != 0:
                            if _is_registry_auth_error(retry_output):
                                console.err(
                                    "Remote docker is not authenticated to registry; re-run `saharo host bootstrap` with a valid "
                                    "license key or login to the registry on the remote host."
                                )
                            console.err(retry_pull.stderr.strip() or "Failed to pull bootstrap container.")
                            raise typer.Exit(code=2)
                        if login_ok:
                            console.info("Remote registry pull succeeded after login.")
                        else:
                            console.warn("Docker login failed, but pull succeeded; continuing.")
                    else:
                        console.err(pre_pull.stderr.strip() or "Failed to pull bootstrap container.")
                        raise typer.Exit(code=2)

                compose_check = session.run(
                    "docker compose version >/dev/null 2>&1 && echo docker-compose-plugin || echo docker-compose")
                compose_cmd = "docker compose" if "docker-compose-plugin" in (
                        compose_check.stdout or "") else "docker-compose"
                pull_cmd = f"cd {base_dir_q} && {compose_cmd} pull"
                res = session.run_privileged(pull_cmd) if sudo else session.run(pull_cmd)
                if res.returncode != 0:
                    auth_output = f"{res.stdout or ''}\n{res.stderr or ''}"
                    if _is_registry_auth_error(auth_output):
                        console.err(
                            "Remote docker is not authenticated to registry; re-run `saharo host bootstrap` with a valid "
                            "license key or login to the registry on the remote host."
                        )
                    console.err(res.stderr.strip() or "Failed to pull bootstrap container.")
                    raise typer.Exit(code=2)
                up_cmd = f"cd {base_dir_q} && {compose_cmd} up -d"
                res = session.run_privileged(up_cmd) if sudo else session.run(up_cmd)
                if res.returncode != 0:
                    console.err(res.stderr.strip() or "Failed to start bootstrap container.")
                    raise typer.Exit(code=2)

                deployed = True
                if not json_out:
                    console.ok("Bootstrap runtime deployed.")

                if not json_out:
                    console.info("Waiting for server registration...")
                reg_result = agents_cmd._wait_for_agent_registration(
                    session,
                    cfg,
                    sudo=sudo,
                    timeout_s=register_timeout,
                    emit_output=False,
                )
                agent_id = _require_registration(reg_result, timeout_s=register_timeout)
        finally:
            session.close()

    if agent_id is None:
        console.err("Registration did not return an id.")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        server = _ensure_server_record(client, name=name, host=host, agent_id=agent_id, note=note)
        server_id = server.get("id")
        server_name = server.get("name") or name
        server_host = server.get("public_host") or host
        status_payload = None
        if wait and server_id:
            status_payload = _wait_for_server_heartbeat(
                client,
                int(server_id),
                timeout_s=wait_timeout,
                interval_s=wait_interval,
                json_out=json_out,
            )
    finally:
        client.close()

    if json_out:
        console.print_json(
            {
                "deployed": deployed,
                "server_id": server_id,
                "server_name": server_name,
                "server_host": server_host,
                "status": status_payload,
            }
        )
        return

    console.ok(f"Server registered: {server_id} ({server_name})")
    console.info(f"Host: {server_host}")
    if wait and status_payload:
        status = status_payload.get("status") or ("online" if status_payload.get("online") else "offline")
        console.info(f"Heartbeat status: {status}")
    console.info(f"Next: saharo servers status {server_id}")
