from __future__ import annotations

import subprocess
import time
from typing import Iterable

import typer

from saharo_client import ApiError
from .. import console
from ..config import load_config
from ..http import make_client

LOGS_USAGE = """\
Usage:
  saharo logs api [--follow] [--lines N]
  saharo logs server <server> [--follow] [--lines N]
"""

app = typer.Typer(
    help="View saharo service logs.\n\n" + LOGS_USAGE,
    no_args_is_help=True,
)

DEFAULT_LINES = 200
FOLLOW_POLL_S = 2.0


def _docker_available() -> bool:
    res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return res.returncode == 0


def _resolve_container_by_name(name: str) -> str | None:
    res = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True)
    if res.returncode != 0:
        return None
    names = [line.strip() for line in (res.stdout or "").splitlines() if line.strip()]
    return name if name in names else None


def _docker_logs(container: str, *, lines: int, follow: bool) -> None:
    args = ["docker", "logs", "--tail", str(lines)]
    if follow:
        args.append("--follow")
    args.append(container)
    if follow:
        subprocess.call(args)
        return
    res = subprocess.run(args, text=True, capture_output=True)
    if res.returncode != 0:
        console.err(res.stderr.strip() or "Failed to fetch logs.")
        raise typer.Exit(code=2)
    if res.stdout:
        print(res.stdout.rstrip())


def _diff_lines(previous: list[str], current: list[str]) -> list[str]:
    if not previous:
        return current
    last = previous[-1]
    for idx in range(len(current) - 1, -1, -1):
        if current[idx] == last:
            return current[idx + 1 :]
    return current


def _print_container_logs(title: str, lines: Iterable[str]) -> None:
    console.console.print(f"[bold]{title}[/bold]")
    if not lines:
        console.console.print("(no logs)")
        return
    for line in lines:
        print(line)


@app.command("api", help="Show API logs from local docker container saharo_api.")
def logs_api(
    follow: bool = typer.Option(False, "--follow", help="Follow logs."),
    lines: int = typer.Option(DEFAULT_LINES, "--lines", min=1, help="Number of lines to show."),
):
    if not _docker_available():
        console.err("Docker is unavailable. Install Docker or run on the API host.")
        raise typer.Exit(code=2)
    container = _resolve_container_by_name("saharo_api")
    if not container:
        console.err("API container not found (expected container name: saharo_api).")
        raise typer.Exit(code=2)
    _docker_logs(container, lines=lines, follow=follow)


@app.command("agent", help="Show logs from a remote runtime via the API.", hidden=True)
def logs_agent(
    agent_name_or_id: str = typer.Argument(..., help="Runtime name or numeric id."),
    follow: bool = typer.Option(False, "--follow", help="Follow logs by polling."),
    lines: int = typer.Option(DEFAULT_LINES, "--lines", min=1, help="Number of lines to show."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        agent_id = _resolve_agent_id(client, agent_name_or_id)
        _tail_remote_logs(
            client,
            agent_id=agent_id,
            containers=["saharo_agent"],
            follow=follow,
            lines=lines,
            title_prefix="runtime",
        )
    except ApiError as exc:
        _render_api_error(exc, target=f"runtime {agent_name_or_id}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("server", help="Show logs for server services via the attached runtime.")
def logs_server(
    server_name_or_id: str = typer.Argument(..., help="Server name or numeric id."),
    follow: bool = typer.Option(False, "--follow", help="Follow logs by polling."),
    lines: int = typer.Option(DEFAULT_LINES, "--lines", min=1, help="Number of lines to show."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        server_id = _resolve_server_id(client, server_name_or_id)
        _tail_server_logs(client, server_id=server_id, follow=follow, lines=lines)
    except ApiError as exc:
        _render_api_error(exc, target=f"server {server_name_or_id}")
        raise typer.Exit(code=2)
    finally:
        client.close()


def _resolve_agent_id(client, agent_name_or_id: str) -> int:
    value = str(agent_name_or_id).strip()
    if value.isdigit():
        return int(value)
    page_size = 200
    offset = 0
    while True:
        data = client.admin_agents_list(include_deleted=False, limit=page_size, offset=offset)
        items = data.get("items") if isinstance(data, dict) else []
        matches = [a for a in (items or []) if str(a.get("name") or "").strip() == value]
        if matches:
            if len(matches) > 1:
                raise ApiError(409, f"multiple runtimes named {value}")
            return int(matches[0]["id"])
        total = data.get("total") if isinstance(data, dict) else None
        if total is None:
            break
        offset += page_size
        if offset >= total:
            break
    raise ApiError(404, f"runtime {value} not found")


def _resolve_server_id(client, server_name_or_id: str) -> int:
    value = str(server_name_or_id).strip()
    if value.isdigit():
        return int(value)
    data = client.admin_servers_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [s for s in (items or []) if str(s.get("name") or "").strip() == value]
    if not matches:
        raise ApiError(404, f"server {value} not found")
    if len(matches) > 1:
        raise ApiError(409, f"multiple servers named {value}")
    return int(matches[0]["id"])


def _tail_remote_logs(
    client,
    *,
    agent_id: int,
    containers: list[str],
    follow: bool,
    lines: int,
    title_prefix: str,
):
    last_lines: dict[str, list[str]] = {c: [] for c in containers}
    while True:
        result = client.admin_agent_logs(agent_id, containers=containers, lines=lines)
        logs = result.get("logs") or {}
        warnings = result.get("warnings") or []
        for warning in warnings:
            console.warn(str(warning))
        for container in containers:
            content = str(logs.get(container) or "")
            new_lines = content.splitlines()
            delta = _diff_lines(last_lines.get(container, []), new_lines)
            _print_container_logs(f"{title_prefix}:{container}", delta if follow else new_lines)
            last_lines[container] = new_lines
        if not follow:
            return
        time.sleep(FOLLOW_POLL_S)


def _tail_server_logs(client, *, server_id: int, follow: bool, lines: int) -> None:
    last_lines: dict[str, list[str]] = {}
    while True:
        result = client.admin_server_logs(server_id, lines=lines)
        logs = result.get("logs") or {}
        warnings = result.get("warnings") or []
        for warning in warnings:
            console.warn(str(warning))
        for container, content in logs.items():
            new_lines = str(content or "").splitlines()
            delta = _diff_lines(last_lines.get(container, []), new_lines)
            _print_container_logs(f"server:{container}", delta if follow else new_lines)
            last_lines[container] = new_lines
        if not follow:
            return
        time.sleep(FOLLOW_POLL_S)


def _render_api_error(exc: ApiError, *, target: str) -> None:
    if exc.status_code == 404:
        console.err(f"{target} not found.")
        return
    if exc.status_code == 400:
        console.err(str(exc) or "Bad request.")
        return
    if exc.status_code in (401, 403):
        console.err("Unauthorized. Admin access is required.")
        return
    console.err(f"Failed to fetch logs: {exc}")
