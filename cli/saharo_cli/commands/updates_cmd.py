from __future__ import annotations

from datetime import datetime
from typing import Any

import typer
from saharo_client import ApiError
from saharo_client.updates import (
    clean_versions,
    coerce_int,
    extract_installations,
    extract_latest_versions,
    extract_linked,
    extract_outdated_agents,
    extract_status,
    format_api_error,
    format_limit,
    platform_id,
)

from .. import console
from ..compat import cli_version
from ..config import load_config
from ..http import make_client
from saharo_client.jobs import wait_job, job_status_hint
from saharo_client.resolve import resolve_server_id_for_jobs
from ..interactive import select_server, select_items_search

app = typer.Typer(help="Check CLI updates (users) or license cache status (admins).")

_ACTION_NEEDED_STATUSES = {"outdated_host", "outdated_agents", "limit_exceeded", "not_linked"}


def _coerce_int(value: Any) -> int | None:
    return coerce_int(value)


def _clean_versions(data: dict) -> dict[str, str]:
    return clean_versions(data)


def _extract_latest_versions(entitlements: dict | list | None, versions: dict | None) -> dict[str, str]:
    return extract_latest_versions(entitlements, versions)


def _extract_status(entitlements: dict | list | None) -> str | None:
    return extract_status(entitlements)


def _extract_linked(entitlements: dict | list | None, status: str | None) -> bool | None:
    return extract_linked(entitlements, status)


def _extract_installations(entitlements: dict | list | None) -> tuple[int | None, int | None]:
    return extract_installations(entitlements)


def _extract_outdated_agents(entitlements: dict | list | None) -> tuple[int | None, int | None]:
    return extract_outdated_agents(entitlements)


def _format_limit(limit: int | None) -> str:
    return format_limit(limit)


def _platform_id() -> str:
    return platform_id()


def _format_api_error(exc: ApiError) -> str:
    return format_api_error(exc)


def _resolve_latest_agent_version(client, *, refresh: bool = True) -> str:
    try:
        data = client.admin_license_refresh() if refresh else client.admin_license_snapshot()
    except ApiError as exc:
        console.err(f"License snapshot failed: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    if not isinstance(data, dict) or not data.get("ok"):
        console.err("License snapshot failed: invalid response from host API.")
        raise typer.Exit(code=2)

    entitlements = data.get("entitlements")
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    latest_versions = _extract_latest_versions(entitlements, versions)
    agent_version = latest_versions.get("agent")
    if not agent_version:
        console.err("Unable to resolve latest agent version from license snapshot.")
        raise typer.Exit(code=2)
    return agent_version


def _list_all_servers(client) -> list[dict]:
    items: list[dict] = []
    offset = 0
    limit = 200
    while True:
        data = client.admin_servers_list(limit=limit, offset=offset)
        batch = data.get("items") if isinstance(data, dict) else []
        if batch:
            items.extend(batch)
        total = data.get("total") if isinstance(data, dict) else None
        if not batch or (total is not None and len(items) >= int(total)):
            break
        offset += limit
    return items


def _select_servers_multi(client) -> list[int]:
    servers = _list_all_servers(client)
    if not servers:
        console.err("No servers found.")
        raise typer.Exit(code=2)
    choices = []
    for item in servers:
        sid = item.get("id")
        name = item.get("name") or "-"
        host = item.get("public_host") or "-"
        if sid is None:
            continue
        label = f"{name} ({host}) [id={sid}]"
        choices.append(Choice(title=label, value=str(sid)))
    selected = select_items_search("Select servers to update", choices)
    if not selected:
        console.err("No servers selected.")
        raise typer.Exit(code=1)
    return [int(s) for s in selected]


@app.command("check", help="Show CLI update status (users) or full license cache info (admins).")
def check(
        base_url: str | None = typer.Option(None, "--base-url", help="Override hub API base URL."),
) -> None:
    cfg = load_config()
    base_url_value = (base_url or cfg.base_url or "").strip()
    if not base_url_value:
        console.err("No host URL configured. Run: saharo auth login --base-url https://<your-host>")
        raise typer.Exit(code=2)
    if not (cfg.auth.token or "").strip():
        console.err("Not authenticated. Run: saharo auth login")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        me = client.me()
    except ApiError as exc:
        client.close()
        if exc.status_code in (401, 403):
            console.err("Not authenticated.")
            console.info("Run: saharo auth login --base-url https://<your-host>")
        else:
            console.err(f"Failed to fetch /me: {_format_api_error(exc)}")
        raise typer.Exit(code=2)

    is_admin = isinstance(me, dict) and me.get("role") == "admin"
    if not is_admin:
        current_version = cli_version()
        try:
            data = client.updates_cli(current=current_version, platform=_platform_id())
        except ApiError as exc:
            if exc.status_code in (401, 403):
                console.err("Not authenticated.")
                console.info("Run: saharo auth login --base-url https://<your-host>")
            else:
                console.err(f"Update check failed: {_format_api_error(exc)}")
            raise typer.Exit(code=2)
        finally:
            client.close()

        if not isinstance(data, dict) or not data.get("ok"):
            console.err("Update check failed: invalid response from host API.")
            raise typer.Exit(code=2)

        latest_cli = data.get("latest") if isinstance(data.get("latest"), str) else "unknown"
        update_available = bool(data.get("update_available"))

        if update_available:
            console.print(f"CLI: update available ({current_version} -> {latest_cli})")
            console.info("Run: saharo updates self")
        else:
            console.print(f"CLI: up to date ({current_version})")
        raise typer.Exit(code=0)

    try:
        data = client.admin_license_refresh()
    except ApiError as exc:
        client.close()
        console.err(f"License refresh failed: {_format_api_error(exc)}")
        raise typer.Exit(code=2)

    if not isinstance(data, dict) or not data.get("ok"):
        console.err("License refresh failed: invalid response from host API.")
        raise typer.Exit(code=2)

    entitlements = data.get("entitlements")
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    fetched_at = data.get("fetched_at")

    status = _extract_status(entitlements)
    linked = _extract_linked(entitlements, status)
    linked_label = "linked" if linked is True else "not_linked" if linked is False else "unknown"
    status_label = status or "unknown"

    latest_versions = _extract_latest_versions(entitlements, versions)
    latest_host = latest_versions.get("host") or "-"
    latest_agent = latest_versions.get("agent") or "-"
    latest_cli = latest_versions.get("cli") or "-"

    console.print(f"License: {linked_label} (status={status_label})")
    console.print(f"Latest versions: host={latest_host} agent={latest_agent} cli={latest_cli}")

    install_count, install_limit = _extract_installations(entitlements)
    if install_count is not None or install_limit is not None:
        count_label = str(install_count or 0)
        limit_label = _format_limit(install_limit)
        console.print(f"Installations: {count_label} / {limit_label}")

    outdated_count, outdated_total = _extract_outdated_agents(entitlements)
    outdated_reported = False
    if outdated_count is not None and outdated_total is not None:
        console.print(f"Outdated agents: {outdated_count} / {outdated_total}")
        outdated_reported = True

    summary = None
    try:
        summary = client.admin_agents_summary()
    except Exception:
        summary = None

    if isinstance(summary, dict):
        agents_summary = summary.get("agents") if isinstance(summary.get("agents"), dict) else None
        if agents_summary:
            agent_outdated = agents_summary.get("outdated")
            agent_total = agents_summary.get("total")
            last_seen = agents_summary.get("last_seen_at")
            if agent_outdated is not None and agent_total is not None:
                if not outdated_reported:
                    console.print(f"Outdated agents: {agent_outdated} / {agent_total}")
                    outdated_reported = True
            if last_seen:
                console.print(f"Last agent seen: {last_seen}")

    version_info = None
    try:
        version_info = client.version()
    except Exception:
        version_info = None

    if isinstance(version_info, dict):
        cli_range = version_info.get("supported_cli_range")
        agent_range = version_info.get("supported_agent_range")
        compat_parts: list[str] = []
        if isinstance(cli_range, str) and cli_range:
            compat_parts.append(f"cli {cli_range}")
        if isinstance(agent_range, str) and agent_range:
            compat_parts.append(f"agent {agent_range}")
        if compat_parts:
            console.print(f"Compatibility: {', '.join(compat_parts)}")

    if isinstance(fetched_at, datetime):
        fetched_at_label = fetched_at.isoformat()
    else:
        fetched_at_label = str(fetched_at) if fetched_at else "unknown"
    console.print(f"Cache updated: {fetched_at_label}")

    if status_label in _ACTION_NEEDED_STATUSES:
        client.close()
        raise typer.Exit(code=10)
    client.close()
    raise typer.Exit(code=0)


@app.command("self", help="Update the CLI from the connected host.")
def update_self_cmd() -> None:
    from .self_cmd import update_self

    update_self()


@app.command("cli", help="Update the CLI from the connected host.")
def update_cli_cmd() -> None:
    from .self_cmd import update_self

    update_self()


@app.command("servers", help="Create update jobs for server runtimes (agents).")
def update_servers(
        server: list[str] | None = typer.Option(
            None,
            "--server",
            "-s",
            help="Server ID or exact name. Repeatable.",
        ),
        all_servers: bool = typer.Option(False, "--all", help="Update all servers."),
        version: str | None = typer.Option(None, "--version", help="Agent version to deploy (default: latest)."),
        refresh: bool = typer.Option(True, "--refresh/--no-refresh", help="Refresh license snapshot first."),
        wait: bool = typer.Option(False, "--wait/--no-wait", help="Wait for job completion."),
        wait_timeout: int = typer.Option(900, "--wait-timeout", help="Max seconds to wait."),
        wait_interval: int = typer.Option(5, "--wait-interval", help="Poll interval in seconds."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
) -> None:
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        agent_version = version or _resolve_latest_agent_version(client, refresh=refresh)
        if not json_out:
            console.info(f"Resolved agent version: {agent_version}")

        server_ids: list[int] = []
        if all_servers:
            servers = _list_all_servers(client)
            if not servers:
                console.err("No servers found.")
                raise typer.Exit(code=2)
            for item in servers:
                sid = item.get("id")
                if sid is not None:
                    server_ids.append(int(sid))
        elif not server:
            server_ids = _select_servers_multi(client)
        else:
            for ref in server or []:
                server_ids.append(resolve_server_id_for_jobs(client, ref))

        results: list[dict] = []
        for sid in server_ids:
            data = client.admin_job_create(
                server_id=sid,
                agent_id=None,
                job_type="agent_update",
                payload={"target_version": agent_version},
            )
            if wait and isinstance(data, dict) and data.get("id"):
                data = wait_job(
                    client,
                    int(data["id"]),
                    timeout_s=wait_timeout,
                    interval_s=wait_interval,
                )
            results.append(data if isinstance(data, dict) else {"raw": data})
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
        else:
            console.err(f"Failed to create update job: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json({"jobs": results})
        return

    for item in results:
        job_id = item.get("id")
        status = item.get("status") or "unknown"
        console.ok(f"Job created: id={job_id} status={status}")
    if results:
        console.info(job_status_hint(results[-1].get("id")))


@app.command("hosts", help="Request host API update (docker compose).")
def update_hosts(
        pull_only: bool = typer.Option(False, "--pull-only", help="Only pull images; do not restart services."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
) -> None:
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.admin_host_update(pull_only=pull_only)
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
        else:
            console.err(f"Failed to update host: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    if data.get("ok"):
        if data.get("scheduled"):
            console.ok("Host update scheduled.")
        else:
            console.ok("Host update triggered.")
    else:
        console.err("Host update failed.")
    if data.get("stderr"):
        console.warn(str(data.get("stderr")))
