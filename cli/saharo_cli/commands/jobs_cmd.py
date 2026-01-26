from __future__ import annotations

import math

import typer
from rich.table import Table
from saharo_client import ApiError
from saharo_client.jobs import normalize_job_type
from saharo_client.resolve import ResolveError, resolve_server_id_for_jobs

from .. import console
from ..config import load_config
from ..http import make_client

JOBS_USAGE = """\
Usage:
  saharo jobs get <id>
  saharo jobs list [--status STATUS] [--server ID|NAME] [--agent-id ID]
  saharo jobs create --type <type> [--server ID|NAME | --agent-id ID] [--service NAME | --container NAME]
  saharo jobs clear [--older-than DAYS] [--status finished|failed|claimed|queued] [--dry-run] [--yes]
"""

app = typer.Typer(help="Jobs commands.\n\n" + JOBS_USAGE)


def _resolve_server_id(client, server_ref: str) -> int:
    try:
        return resolve_server_id_for_jobs(client, server_ref)
    except ResolveError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _normalize_job_type(value: str) -> str:
    return normalize_job_type(value)


@app.command("create")
def create_job(
        job_type: str = typer.Option(
            ...,
            "--type",
            help="Job type: restart-service, start-service, stop-service, restart-container, collect-status.",
        ),
        server: str | None = typer.Option(None, "--server", help="Server ID or exact name."),
        agent_id: int | None = typer.Option(None, "--agent-id", help="Agent ID (if no server)."),
        service: str | None = typer.Option(None, "--service", help="Service name for *-service jobs."),
        container: str | None = typer.Option(None, "--container", help="Container name for restart-container."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    def _norm_job_type(s: str) -> str:
        # accept stop_service and stop-service
        return (s or "").strip().lower().replace("_", "-")

    def _norm_service(s: str) -> str:
        # accept amnezia_awg and amnezia-awg
        return (s or "").strip().lower().replace("_", "-")

    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    jt = _norm_job_type(job_type)

    job_type_map = {
        "restart-service": "restart_service",
        "start-service": "start_service",
        "stop-service": "stop_service",
        "restart-container": "restart_container",
        "collect-status": "collect_status",
    }
    job_key = _normalize_job_type(job_type)
    if job_key not in job_type_map:
        console.err(
            "Invalid job type. Use restart-service, start-service, stop-service, restart-container, or collect-status."
        )
        raise typer.Exit(code=2)

    payload: dict[str, str] = {}
    if job_key in {"restart-service", "start-service", "stop-service"}:
        if not service:
            console.err("--service is required for service jobs.")
            raise typer.Exit(code=2)
        payload["service"] = service
    elif job_key == "restart-container":
        if not container:
            console.err("--container is required for restart-container.")
            raise typer.Exit(code=2)
        payload["container"] = container.strip()

    # collect-status -> payload stays empty

    server_id = None
    if server:
        server_id = _resolve_server_id(client, server)

    if not server_id and not agent_id:
        console.err("Either --server or --agent-id must be provided.")
        raise typer.Exit(code=2)

    if server_id and agent_id:
        console.err("Use either --server or --agent-id, not both.")
        raise typer.Exit(code=2)

    try:
        data = client.admin_job_create(
            server_id=server_id,
            agent_id=agent_id,
            job_type=job_type_map[job_key],
            payload=payload,
        )
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create job: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    console.ok(f"Job created: id={data.get('id')} status={data.get('status')}")


@app.command("list")
def list_jobs(
        status: str | None = typer.Option(None, "--status", help="Filter by status."),
        server: str | None = typer.Option(None, "--server", help="Server ID or exact name."),
        agent_id: int | None = typer.Option(None, "--agent-id", help="Filter by agent ID."),
        page: int = typer.Option(1, "--page", help="Page number (1-based)."),
        page_size: int = typer.Option(50, "--page-size", help="Number of jobs per page."),
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

    server_id = None
    if server:
        server_id = _resolve_server_id(client, server)

    try:
        data = client.admin_jobs_list(
            status=status,
            agent_id=agent_id,
            server_id=server_id,
            limit=page_size,
            offset=offset,
        )
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to list jobs: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    items = data.get("items") if isinstance(data, dict) else []
    total = data.get("total") if isinstance(data, dict) else None

    table = Table(title="Jobs")
    table.add_column("id", style="bold")
    table.add_column("type")
    table.add_column("status")
    table.add_column("agent_id")
    table.add_column("server_id")
    table.add_column("created_at")
    table.add_column("started_at")
    table.add_column("finished_at")

    for j in items or []:
        payload = j.get("payload") or {}
        table.add_row(
            str(j.get("id", "-")),
            str(j.get("type", "-")),
            str(j.get("status", "-")),
            str(j.get("agent_id", "-")),
            str(payload.get("server_id") or "-"),
            str(j.get("created_at") or "-"),
            str(j.get("started_at") or "-"),
            str(j.get("finished_at") or "-"),
        )

    console.console.print(table)
    if total is not None:
        pages = max(1, math.ceil(total / page_size))
        console.info(f"page={page}/{pages} total={total}")


def _get_job(
        job_id: int = typer.Argument(...),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.admin_job_get(job_id)
    except ApiError as e:
        if e.status_code == 404:
            console.err(f"Job {job_id} not found. Use `saharo jobs get <id>`.")
            raise typer.Exit(code=2)
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to fetch job: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    for key in sorted(data.keys()):
        console.info(f"{key}: {data.get(key)}")


@app.command("get", help="Fetch a job by id.")
def get_job(
        job_id: int = typer.Argument(...),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    _get_job(job_id=job_id, base_url=base_url, json_out=json_out)


@app.command("show", hidden=True)
def show_job(
        job_id: int = typer.Argument(...),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    console.warn("Deprecated: use `saharo jobs get` instead.")
    _get_job(job_id=job_id, base_url=base_url, json_out=json_out)


@app.command("clear", help="Prune old jobs with safety prompts.")
def clear_jobs(
        older_than_days: int | None = typer.Option(
            None,
            "--older-than",
            help="Delete jobs older than N days (default: 30).",
        ),
        status: str | None = typer.Option(
            None,
            "--status",
            help="Status filter: finished, failed, claimed, queued.",
        ),
        server_id: int | None = typer.Option(None, "--server-id", help="Filter by server ID."),
        agent_id: int | None = typer.Option(None, "--agent-id", help="Filter by agent ID."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted."),
        yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    if not yes:
        confirmed = typer.confirm("Delete matching jobs?", default=False)
        if not confirmed:
            console.info("Aborted.")
            raise typer.Exit(code=0)

    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        data = client.admin_jobs_cleanup(
            older_than_days=older_than_days,
            status=status,
            server_id=server_id,
            agent_id=agent_id,
            dry_run=dry_run,
        )
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to clear jobs: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    console.ok(f"Matched={data.get('matched')} Deleted={data.get('deleted')}")
