from __future__ import annotations

import typer
from saharo_client import ApiError
from questionary import Choice
from saharo_client.servers import list_all_servers
from saharo_client.updates import (
    check_updates,
    create_agent_update_jobs,
    format_api_error,
    host_update,
    platform_id,
    resolve_latest_agent_version,
)

from .. import console
from ..compat import cli_version
from ..config import load_config
from ..http import make_client
from saharo_client.jobs import job_status_hint
from saharo_client.resolve import resolve_server_id_for_jobs
from ..interactive import select_items_search

app = typer.Typer(help="Check CLI updates (users) or license cache status (admins).")

_ACTION_NEEDED_STATUSES = {"outdated_host", "outdated_agents", "limit_exceeded", "not_linked"}


def _format_api_error(exc: ApiError) -> str:
    return format_api_error(exc)


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
        result = check_updates(
            client,
            current_version=cli_version(),
            platform=platform_id(),
            refresh_admin=True,
        )
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Not authenticated.")
            console.info("Run: saharo auth login --base-url https://<your-host>")
        else:
            console.err(f"Update check failed: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    except ValueError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)
    finally:
        client.close()

    if result.mode == "user" and result.cli:
        latest_cli = result.cli.latest or "unknown"
        if result.cli.update_available:
            console.print(f"CLI: update available ({result.cli.current} -> {latest_cli})")
            console.info("Run: saharo updates self")
        else:
            console.print(f"CLI: up to date ({result.cli.current})")
        raise typer.Exit(code=0)

    admin = result.admin
    if not admin:
        console.err("Update check failed: missing admin data.")
        raise typer.Exit(code=2)

    linked_label = "linked" if admin.linked is True else "not_linked" if admin.linked is False else "unknown"
    status_label = admin.status or "unknown"

    latest_host = admin.latest_versions.get("host") or "-"
    latest_agent = admin.latest_versions.get("agent") or "-"
    latest_cli = admin.latest_versions.get("cli") or "-"

    console.print(f"License: {linked_label} (status={status_label})")
    console.print(f"Latest versions: host={latest_host} agent={latest_agent} cli={latest_cli}")

    install_count, install_limit = admin.installations
    if install_count is not None or install_limit is not None:
        limit_label = "∞" if not install_limit or install_limit <= 0 else str(install_limit)
        console.print(f"Installations: {install_count or 0} / {limit_label}")

    outdated_count, outdated_total = admin.outdated_agents
    outdated_reported = False
    if outdated_count is not None and outdated_total is not None:
        console.print(f"Outdated agents: {outdated_count} / {outdated_total}")
        outdated_reported = True

    if isinstance(admin.agents_summary, dict):
        agent_outdated = admin.agents_summary.get("outdated")
        agent_total = admin.agents_summary.get("total")
        last_seen = admin.agents_summary.get("last_seen_at")
        if agent_outdated is not None and agent_total is not None:
            if not outdated_reported:
                console.print(f"Outdated agents: {agent_outdated} / {agent_total}")
                outdated_reported = True
        if last_seen:
            console.print(f"Last agent seen: {last_seen}")

    if admin.compatibility:
        compat_parts = []
        cli_range = admin.compatibility.get("cli")
        agent_range = admin.compatibility.get("agent")
        if cli_range:
            compat_parts.append(f"cli {cli_range}")
        if agent_range:
            compat_parts.append(f"agent {agent_range}")
        if compat_parts:
            console.print(f"Compatibility: {', '.join(compat_parts)}")

    console.print(f"Cache updated: {admin.fetched_at or 'unknown'}")

    if status_label in _ACTION_NEEDED_STATUSES:
        raise typer.Exit(code=10)
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
        agent_version = version or resolve_latest_agent_version(client, refresh=refresh)
        if not json_out:
            console.info(f"Resolved agent version: {agent_version}")

        server_ids: list[int] = []
        if all_servers:
            servers = list_all_servers(client)
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

        results = create_agent_update_jobs(
            client,
            server_ids=server_ids,
            target_version=agent_version,
            wait=wait,
            timeout_s=wait_timeout,
            interval_s=wait_interval,
        )
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
        else:
            console.err(f"Failed to create update job: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    except ValueError as exc:
        console.err(str(exc))
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
        data = host_update(client, pull_only=pull_only)
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
        else:
            console.err(f"Failed to update host: {_format_api_error(exc)}")
        raise typer.Exit(code=2)
    except ValueError as exc:
        console.err(str(exc))
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
