"""Services CLI commands."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml as pyyaml
from rich.table import Table
from saharo_client import ApiError

from .. import console
from ..config import load_config
from ..formatting import format_list_timestamp
from ..http import make_client
from ..interactive import confirm_choice, select_custom_service, select_server

app = typer.Typer(help="Manage custom services and desired-state operations.")
desired_state_app = typer.Typer(help="Desired-state operations for custom services.")
app.add_typer(desired_state_app, name="desired-state")
app.add_typer(desired_state_app, name="ds")


def _client(base_url: str | None):
    cfg = load_config()
    return make_client(cfg, profile=None, base_url_override=base_url)


def _read_yaml_file(yaml_file: Path) -> str:
    try:
        return yaml_file.read_text(encoding="utf-8")
    except Exception as exc:
        console.err(f"Failed to read file: {exc}")
        raise typer.Exit(code=2)


def _parse_yaml_identity(yaml_content: str) -> tuple[str, str]:
    try:
        data = pyyaml.safe_load(yaml_content) or {}
    except Exception as exc:
        console.err(f"Invalid YAML: {exc}")
        raise typer.Exit(code=2)

    code = str(data.get("name") or "").strip()
    display_name = str(data.get("display_name") or code).strip() or code
    if not code:
        console.err("YAML must include 'name'.")
        raise typer.Exit(code=2)
    return code, display_name


def _resolve_server_id(client, server_ref: str | None) -> int:
    if not server_ref:
        return int(select_server(client))
    if server_ref.isdigit():
        return int(server_ref)
    try:
        data = client.admin_servers_list(q=server_ref, limit=50)
    except ApiError as exc:
        console.err(f"Failed to resolve server: {exc}")
        raise typer.Exit(code=2)
    items = data.get("items") if isinstance(data, dict) else []
    exact = [s for s in items if str(s.get("name") or "").strip().lower() == server_ref.strip().lower()]
    if exact:
        return int(exact[0]["id"])
    if len(items) == 1:
        return int(items[0]["id"])
    console.err(f"Server '{server_ref}' not found.")
    raise typer.Exit(code=2)


def _resolve_service(client, code_or_id: str | None) -> dict[str, Any]:
    try:
        if not code_or_id:
            service_id = select_custom_service(client)
            return client.admin_custom_service_get(int(service_id))
        if code_or_id.isdigit():
            return client.admin_custom_service_get(int(code_or_id))
        return client.admin_custom_service_get_by_code(code_or_id)
    except ApiError as exc:
        if exc.status_code == 404:
            console.err(f"Service '{code_or_id}' not found.")
            raise typer.Exit(code=2)
        console.err(f"Failed to resolve service: {exc}")
        raise typer.Exit(code=2)


def _parse_service_codes(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in str(raw).split(","):
            code = part.strip().lower()
            if not code or code in seen:
                continue
            seen.add(code)
            out.append(code)
    return out


def _parse_desired_service_specs(values: list[str]) -> tuple[list[str], list[dict[str, int]]]:
    order: list[str] = []
    replicas_by_code: dict[str, int] = {}
    for raw in values:
        for part in str(raw).split(","):
            token = part.strip().lower()
            if not token:
                continue
            code_part = token
            replicas_part: str | None = None
            if "=" in token:
                code_part, replicas_part = token.split("=", 1)
            elif ":" in token:
                code_part, replicas_part = token.split(":", 1)
            code = code_part.strip()
            if not code:
                raise ValueError(f"Invalid service spec '{part}'. Expected '<code>' or '<code>=<replicas>'.")
            replicas = 1
            if replicas_part is not None:
                try:
                    replicas = int(replicas_part.strip())
                except Exception as exc:
                    raise ValueError(
                        f"Invalid replicas in '{part}'. Expected positive integer in '<code>=<replicas>'."
                    ) from exc
                if replicas <= 0:
                    raise ValueError(f"Invalid replicas in '{part}'. Replicas must be >= 1.")
            if code not in replicas_by_code:
                order.append(code)
            replicas_by_code[code] = replicas
    services = [{"code": code, "replicas": int(replicas_by_code[code])} for code in order]
    return order, services


def _desired_replicas_map(state: dict[str, Any]) -> tuple[list[str], dict[str, int]]:
    desired_raw = state.get("desired_services") if isinstance(state, dict) else []
    replicas_raw = state.get("desired_service_replicas") if isinstance(state, dict) else {}
    order: list[str] = []
    replicas: dict[str, int] = {}
    if isinstance(desired_raw, list):
        for raw in desired_raw:
            code = str(raw or "").strip().lower()
            if not code or code in replicas:
                continue
            order.append(code)
            replicas[code] = 1
    if isinstance(replicas_raw, dict):
        for key, value in replicas_raw.items():
            code = str(key or "").strip().lower()
            if not code:
                continue
            try:
                rep = int(value)
            except Exception:
                rep = 1
            replicas[code] = max(1, rep)
            if code not in order:
                order.append(code)
    return order, replicas


def _render_desired_replicas_line(replicas_map: dict[str, int]) -> str:
    return ", ".join(f"{code}={int(replicas_map.get(code) or 1)}" for code in sorted(replicas_map))


def _print_service_summary(service: dict[str, Any]) -> None:
    console.rule(f"Service: {service.get('display_name')}")
    console.info(f"ID: {service.get('id')}")
    console.info(f"Code: {service.get('code')}")
    console.info(f"Status: {'enabled' if service.get('enabled') else 'disabled'}")
    console.info(f"Created: {service.get('created_at')}")
    console.info(f"Updated: {service.get('updated_at')}")
    console.console.print("\n[bold]YAML Definition:[/bold]")
    console.console.print(f"[dim]{service.get('yaml_definition', '')}[/dim]\n")


@app.command("add")
def add_service(
    yaml_file: Path = typer.Argument(..., exists=True, help="YAML definition file."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    yaml_content = _read_yaml_file(yaml_file)
    code, display_name = _parse_yaml_identity(yaml_content)

    client = _client(base_url)
    try:
        service = client.admin_custom_service_create(
            code=code,
            display_name=display_name,
            yaml_definition=yaml_content,
        )
        console.ok(f"Service '{code}' added (id={service.get('id')}).")
    except ApiError as exc:
        if exc.status_code == 409:
            console.err(f"Service '{code}' already exists. Use 'services apply'.")
        else:
            console.err(f"Failed to add service: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("apply")
def apply_service(
    yaml_file: Path = typer.Argument(..., exists=True, help="YAML definition file."),
    enable: bool | None = typer.Option(None, "--enable/--disable", help="Optionally set enabled flag."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    """Create or update service from YAML (idempotent CLI flow)."""
    yaml_content = _read_yaml_file(yaml_file)
    code, display_name = _parse_yaml_identity(yaml_content)

    client = _client(base_url)
    try:
        existing = None
        try:
            existing = client.admin_custom_service_get_by_code(code)
        except ApiError as exc:
            if exc.status_code != 404:
                raise

        if existing:
            service = client.admin_custom_service_update(
                int(existing["id"]),
                display_name=display_name,
                yaml_definition=yaml_content,
                enabled=enable,
            )
            action = "updated"
        else:
            service = client.admin_custom_service_create(
                code=code,
                display_name=display_name,
                yaml_definition=yaml_content,
            )
            action = "created"
            if enable is not None and bool(service.get("enabled")) != bool(enable):
                service = client.admin_custom_service_update(int(service["id"]), enabled=enable)

        if json_out:
            console.print_json({"action": action, "service": service})
            return
        console.ok(f"Service '{code}' {action} (id={service.get('id')}).")
    except ApiError as exc:
        console.err(f"Failed to apply service: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("list")
def list_services(
    enabled_only: bool = typer.Option(False, "--enabled-only", help="Show only enabled services."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    client = _client(base_url)
    try:
        services = client.admin_custom_services_list(enabled_only=enabled_only)
        if json_out:
            console.print_json(services)
            return
        if not services:
            console.info("No custom services found.")
            return

        table = Table(title="Custom Services")
        table.add_column("id", style="bold")
        table.add_column("code")
        table.add_column("display name")
        table.add_column("status")
        table.add_column("created", no_wrap=True)
        for svc in services:
            status = "enabled" if svc.get("enabled") else "disabled"
            table.add_row(
                str(svc.get("id")),
                str(svc.get("code") or ""),
                str(svc.get("display_name") or ""),
                status,
                format_list_timestamp(svc.get("created_at")),
            )
        console.console.print(table)
    except ApiError as exc:
        console.err(f"Failed to list services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("get")
def get_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    client = _client(base_url)
    try:
        service = _resolve_service(client, code_or_id)
        if json_out:
            console.print_json(service)
            return
        _print_service_summary(service)
    finally:
        client.close()


@app.command("delete")
def delete_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    client = _client(base_url)
    try:
        service = _resolve_service(client, code_or_id)
        service_id = int(service["id"])
        code = str(service.get("code") or service_id)

        if not force and not confirm_choice(f"Remove service '{code}' ({service.get('display_name')})?", default=False):
            console.info("Aborted.")
            return

        client.admin_custom_service_delete(service_id)
        console.ok(f"Service '{code}' removed.")
    except ApiError as exc:
        console.err(f"Failed to remove service: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("remove", hidden=True)
def remove_service(
    code_or_id: str | None = typer.Argument(None, help="Service code or ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    delete_service(code_or_id=code_or_id, force=force, base_url=base_url)


@app.command("validate")
def validate_service(
    yaml_file: Path = typer.Argument(..., exists=True, help="YAML definition file."),
):
    yaml_content = _read_yaml_file(yaml_file)
    try:
        import os
        import sys

        script_dir = os.path.dirname(os.path.abspath(__file__))
        agent_path = os.path.normpath(os.path.join(script_dir, "../../../../saharo-host-monorepo/http-agent"))
        if os.path.exists(agent_path) and agent_path not in sys.path:
            sys.path.insert(0, agent_path)

        from agent.services.yaml_parser import parse_service_yaml

        definition = parse_service_yaml(yaml_content)
        console.ok("YAML is valid")
        console.info(f"Service name: {definition.name}")
        console.info(f"Display name: {definition.display_name}")
        console.info(f"Container image: {definition.container.image}")
    except ImportError:
        try:
            data = pyyaml.safe_load(yaml_content) or {}
            if not data.get("name"):
                raise ValueError("Missing 'name' field")
            console.ok("Basic YAML structure is valid.")
        except Exception as exc:
            console.err(f"Validation failed: {exc}")
            raise typer.Exit(code=2)
    except Exception as exc:
        console.err(f"Validation failed: {exc}")
        raise typer.Exit(code=2)


@app.command("instances")
def list_instances(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        rows = client.admin_server_custom_service_instances(server_id)
        if json_out:
            console.print_json(rows)
            return
        table = Table(title=f"Service Instances (server={server_id})")
        table.add_column("service")
        table.add_column("status")
        table.add_column("updated")
        for row in rows:
            table.add_row(str(row.get("code") or ""), str(row.get("status") or ""), format_list_timestamp(row.get("updated_at")))
        console.console.print(table)
    except ApiError as exc:
        console.err(f"Failed to list instances: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("set")
def desired_set(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    services: list[str] = typer.Argument(
        ...,
        help="Service specs (space/comma separated): '<code>' or '<code>=<replicas>'.",
    ),
    reconcile: bool = typer.Option(True, "--reconcile/--no-reconcile", help="Enqueue reconcile job."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        try:
            codes, service_specs = _parse_desired_service_specs(services)
        except ValueError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        if not codes:
            console.err("At least one service code is required.")
            raise typer.Exit(code=2)
        out = client.admin_server_desired_custom_services_set(
            server_id,
            service_codes=codes,
            services=service_specs,
            enqueue_reconcile=reconcile,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Desired services updated for server {server_id}.")
        replicas_map = out.get("desired_service_replicas") if isinstance(out, dict) else {}
        if isinstance(replicas_map, dict) and replicas_map:
            console.info(f"Replicas: {_render_desired_replicas_line(replicas_map)}")
        if out.get("job_id"):
            console.info(f"Job queued: {out['job_id']}")
    except ApiError as exc:
        console.err(f"Failed to set desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("clear")
def desired_clear(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    reconcile: bool = typer.Option(True, "--reconcile/--no-reconcile", help="Enqueue reconcile job."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_desired_custom_services_set(
            server_id,
            service_codes=[],
            services=[],
            enqueue_reconcile=reconcile,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Desired services cleared for server {server_id}.")
        if out.get("job_id"):
            console.info(f"Job queued: {out['job_id']}")
    except ApiError as exc:
        console.err(f"Failed to clear desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("get")
def desired_get(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_desired_custom_services_get(server_id)
        if json_out:
            console.print_json(out)
            return
        console.rule(f"Desired Services (server={server_id})")
        console.info(f"Desired: {', '.join(out.get('desired_services') or []) or '-'}")
        replicas_map = out.get("desired_service_replicas") if isinstance(out, dict) else {}
        if isinstance(replicas_map, dict) and replicas_map:
            console.info(f"Replicas: {_render_desired_replicas_line(replicas_map)}")
        console.info(f"Disabled: {', '.join(out.get('disabled_services') or []) or '-'}")
    except ApiError as exc:
        console.err(f"Failed to get desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("add")
def desired_add(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    services: list[str] = typer.Argument(
        ...,
        help="Service specs to add/update: '<code>' or '<code>=<replicas>'.",
    ),
    reconcile: bool = typer.Option(True, "--reconcile/--no-reconcile", help="Enqueue reconcile job."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        try:
            add_order, add_specs = _parse_desired_service_specs(services)
        except ValueError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        current = client.admin_server_desired_custom_services_get(server_id)
        order, replicas = _desired_replicas_map(current)
        for item in add_specs:
            code = str(item.get("code") or "").strip().lower()
            rep = max(1, int(item.get("replicas") or 1))
            if code not in order:
                order.append(code)
            replicas[code] = rep
        for code in add_order:
            if code not in order:
                order.append(code)
                replicas[code] = 1
        payload_specs = [{"code": code, "replicas": int(replicas[code])} for code in order if code in replicas]
        out = client.admin_server_desired_custom_services_set(
            server_id,
            service_codes=[item["code"] for item in payload_specs],
            services=payload_specs,
            enqueue_reconcile=reconcile,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Desired services merged for server {server_id}.")
        replicas_map = out.get("desired_service_replicas") if isinstance(out, dict) else {}
        if isinstance(replicas_map, dict) and replicas_map:
            console.info(f"Replicas: {_render_desired_replicas_line(replicas_map)}")
        if out.get("job_id"):
            console.info(f"Job queued: {out['job_id']}")
    except ApiError as exc:
        console.err(f"Failed to merge desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("rm")
def desired_rm(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    services: list[str] = typer.Argument(..., help="Service codes to remove from desired-state."),
    reconcile: bool = typer.Option(True, "--reconcile/--no-reconcile", help="Enqueue reconcile job."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        remove_codes = set(_parse_service_codes(services))
        if not remove_codes:
            console.err("At least one service code is required.")
            raise typer.Exit(code=2)
        current = client.admin_server_desired_custom_services_get(server_id)
        order, replicas = _desired_replicas_map(current)
        next_order = [code for code in order if code not in remove_codes]
        payload_specs = [{"code": code, "replicas": int(replicas.get(code) or 1)} for code in next_order]
        out = client.admin_server_desired_custom_services_set(
            server_id,
            service_codes=[item["code"] for item in payload_specs],
            services=payload_specs,
            enqueue_reconcile=reconcile,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Desired services pruned for server {server_id}.")
        replicas_map = out.get("desired_service_replicas") if isinstance(out, dict) else {}
        if isinstance(replicas_map, dict) and replicas_map:
            console.info(f"Replicas: {_render_desired_replicas_line(replicas_map)}")
        if out.get("job_id"):
            console.info(f"Job queued: {out['job_id']}")
    except ApiError as exc:
        console.err(f"Failed to remove desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@desired_state_app.command("scale")
def desired_scale(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    services: list[str] = typer.Argument(..., help="Scale specs: '<code>=<replicas>' or '<code>:<replicas>'."),
    add_missing: bool = typer.Option(False, "--add-missing", help="Add service to desired-state if it is absent."),
    reconcile: bool = typer.Option(True, "--reconcile/--no-reconcile", help="Enqueue reconcile job."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    for raw in services:
        for part in str(raw).split(","):
            token = part.strip()
            if token and ("=" not in token and ":" not in token):
                console.err(f"Invalid scale spec '{part}'. Use '<code>=<replicas>'.")
                raise typer.Exit(code=2)
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        try:
            _, scale_specs = _parse_desired_service_specs(services)
        except ValueError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        current = client.admin_server_desired_custom_services_get(server_id)
        order, replicas = _desired_replicas_map(current)
        missing: list[str] = []
        for item in scale_specs:
            code = str(item.get("code") or "").strip().lower()
            rep = max(1, int(item.get("replicas") or 1))
            if code not in replicas:
                if not add_missing:
                    missing.append(code)
                    continue
                order.append(code)
            replicas[code] = rep
        if missing:
            console.err(
                "Cannot scale non-desired service(s): "
                + ", ".join(sorted(missing))
                + ". Use --add-missing or 'desired-state add' (alias: 'ds add')."
            )
            raise typer.Exit(code=2)
        payload_specs = [{"code": code, "replicas": int(replicas.get(code) or 1)} for code in order if code in replicas]
        out = client.admin_server_desired_custom_services_set(
            server_id,
            service_codes=[item["code"] for item in payload_specs],
            services=payload_specs,
            enqueue_reconcile=reconcile,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Desired replicas updated for server {server_id}.")
        replicas_map = out.get("desired_service_replicas") if isinstance(out, dict) else {}
        if isinstance(replicas_map, dict) and replicas_map:
            console.info(f"Replicas: {_render_desired_replicas_line(replicas_map)}")
        if out.get("job_id"):
            console.info(f"Job queued: {out['job_id']}")
    except ApiError as exc:
        console.err(f"Failed to scale desired services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("known-get")
def known_get(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_known_custom_services_get(server_id)
        if json_out:
            console.print_json(out)
            return
        console.rule(f"Known Services (server={server_id})")
        console.info(f"Known: {', '.join(out.get('known_services') or []) or '-'}")
    except ApiError as exc:
        console.err(f"Failed to get known services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("known-set")
def known_set(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    services: list[str] = typer.Argument(..., help="Service codes (space/comma separated)."),
    append: bool = typer.Option(False, "--append", help="Append to known list instead of replacing."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        codes = _parse_service_codes(services)
        out = client.admin_server_known_custom_services_set(
            server_id,
            service_codes=codes,
            append=append,
        )
        if json_out:
            console.print_json(out)
            return
        action = "appended" if append else "updated"
        console.ok(f"Known services {action} for server {server_id}.")
        console.info(f"Known: {', '.join(out.get('known_services') or []) or '-'}")
    except ApiError as exc:
        console.err(f"Failed to set known services: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("dry-run")
def dry_run(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int | None = typer.Option(None, "--batch-size", min=1),
    max_unavailable: int | None = typer.Option(None, "--max-unavailable", min=0),
    pause_seconds: float | None = typer.Option(None, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_custom_services_dry_run(
            server_id,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return

        console.rule(f"Dry Run (server={server_id})")
        policy = out.get("rollout_policy") or {}
        console.info(f"Strategy: {out.get('rollout_strategy')}")
        console.info(
            "Policy: "
            f"batch_size={policy.get('batch_size')} "
            f"max_unavailable={policy.get('max_unavailable')} "
            f"pause_seconds={policy.get('pause_seconds')}"
        )
        actions = out.get("actions") or []
        if actions:
            table = Table(title="Actions")
            table.add_column("service")
            table.add_column("action")
            table.add_column("reason")
            for item in actions:
                table.add_row(str(item.get("service_code") or ""), str(item.get("action") or ""), str(item.get("reason") or ""))
            console.console.print(table)
        batches = out.get("rolling_batches") or []
        if batches:
            bt = Table(title="Rolling Batches")
            bt.add_column("service")
            bt.add_column("batch")
            bt.add_column("containers")
            for b in batches:
                bt.add_row(
                    str(b.get("service_code") or ""),
                    str(b.get("batch_index") or ""),
                    ", ".join([str(x) for x in (b.get("containers") or [])]),
                )
            console.console.print(bt)
    except ApiError as exc:
        console.err(f"Dry-run failed: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("reconcile")
def reconcile_now(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    strategy: str = typer.Option("safe", "--strategy", help="safe|rolling|recreate"),
    batch_size: int = typer.Option(1, "--batch-size", min=1),
    max_unavailable: int = typer.Option(1, "--max-unavailable", min=0),
    pause_seconds: float = typer.Option(0.0, "--pause-seconds", min=0.0),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_custom_services_reconcile_now(
            server_id,
            rollout_strategy=strategy,
            rollout_batch_size=batch_size,
            rollout_max_unavailable=max_unavailable,
            rollout_pause_seconds=pause_seconds,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Reconcile requested for server {server_id}.")
        console.info(f"Job: {out.get('job_id')} status={out.get('status')} reused_pending={out.get('reused_pending')}")
    except ApiError as exc:
        console.err(f"Failed to reconcile: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("drift")
def drift(
    server: str | None = typer.Argument(None, help="Server ID or name."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        server_id = _resolve_server_id(client, server)
        out = client.admin_server_custom_services_drift(server_id)
        if json_out:
            console.print_json(out)
            return
        console.rule(f"Drift (server={server_id})")
        console.info(f"Desired: {', '.join(out.get('desired_services') or []) or '-'}")
        console.info(f"Running: {', '.join(out.get('running_services') or []) or '-'}")
        console.info(f"Known: {', '.join(out.get('known_services') or []) or '-'}")
        console.info(f"Missing: {', '.join(out.get('missing_services') or []) or '-'}")
        console.info(f"Extra: {', '.join(out.get('extra_running_services') or []) or '-'}")
        console.info(f"Disabled but running: {', '.join(out.get('disabled_but_running_services') or []) or '-'}")
    except ApiError as exc:
        console.err(f"Failed to get drift: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("revisions")
def revisions(
    service: str | None = typer.Argument(None, help="Service code or ID."),
    limit: int = typer.Option(50, "--limit", min=1, max=200),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        svc = _resolve_service(client, service)
        rows = client.admin_custom_service_revisions(int(svc["id"]), limit=limit)
        if json_out:
            console.print_json(rows)
            return
        table = Table(title=f"Revisions: {svc.get('code')}")
        table.add_column("revision")
        table.add_column("created")
        table.add_column("note")
        for row in rows:
            table.add_row(str(row.get("revision")), format_list_timestamp(row.get("created_at")), str(row.get("note") or ""))
        console.console.print(table)
    except ApiError as exc:
        console.err(f"Failed to list revisions: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("rollback")
def rollback(
    service: str | None = typer.Argument(None, help="Service code or ID."),
    revision: int = typer.Option(..., "--revision", min=1),
    note: str | None = typer.Option(None, "--note"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        svc = _resolve_service(client, service)
        if not force and not confirm_choice(
            f"Rollback service '{svc.get('code')}' to revision {revision}?",
            default=False,
        ):
            console.info("Aborted.")
            return
        out = client.admin_custom_service_rollback(int(svc["id"]), revision=revision, note=note)
        if json_out:
            console.print_json(out)
            return
        console.ok(f"Rollback completed for {svc.get('code')} to revision {revision}.")
    except ApiError as exc:
        console.err(f"Rollback failed: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("events")
def events(
    limit: int = typer.Option(200, "--limit", min=1, max=1000),
    service_code: str | None = typer.Option(None, "--service"),
    server_id: int | None = typer.Option(None, "--server-id"),
    event_type: str | None = typer.Option(None, "--event-type"),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    client = _client(base_url)
    try:
        rows = client.admin_custom_services_events(
            limit=limit,
            service_code=service_code,
            server_id=server_id,
            event_type=event_type,
        )
        if json_out:
            console.print_json(rows)
            return
        table = Table(title="Custom Service Events")
        table.add_column("time")
        table.add_column("event")
        table.add_column("service")
        table.add_column("server")
        table.add_column("level")
        for row in rows:
            table.add_row(
                format_list_timestamp(row.get("created_at")),
                str(row.get("event_type") or ""),
                str(row.get("service_code") or ""),
                str(row.get("server_id") or ""),
                str(row.get("level") or ""),
            )
        console.console.print(table)
    except ApiError as exc:
        console.err(f"Failed to list events: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("state-export")
def state_export(
    out_file: Path | None = typer.Option(None, "--out", help="Output file (JSON)."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON to stdout."),
):
    client = _client(base_url)
    try:
        out = client.admin_custom_services_state_export()
        if out_file:
            out_file.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
            console.ok(f"State exported to {out_file}")
            return
        if json_out or not out_file:
            console.print_json(out)
    except ApiError as exc:
        console.err(f"State export failed: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()


@app.command("state-import")
def state_import(
    in_file: Path = typer.Argument(..., exists=True, help="Input JSON or YAML file."),
    merge: bool = typer.Option(True, "--merge/--no-merge", help="Merge mode."),
    base_url: str | None = typer.Option(None, "--base-url"),
    json_out: bool = typer.Option(False, "--json"),
):
    try:
        content = in_file.read_text(encoding="utf-8")
        if in_file.suffix.lower() in {".yaml", ".yml"}:
            data = pyyaml.safe_load(content) or {}
        else:
            data = json.loads(content)
    except Exception as exc:
        console.err(f"Failed to read import file: {exc}")
        raise typer.Exit(code=2)

    services = data.get("services") if isinstance(data, dict) else None
    revisions = data.get("revisions") if isinstance(data, dict) else None
    instances = data.get("instances") if isinstance(data, dict) else None
    if not isinstance(services, list) or not isinstance(revisions, list) or not isinstance(instances, list):
        console.err("Import file must contain list fields: services, revisions, instances.")
        raise typer.Exit(code=2)

    client = _client(base_url)
    try:
        out = client.admin_custom_services_state_import(
            services=services,
            revisions=revisions,
            instances=instances,
            merge=merge,
        )
        if json_out:
            console.print_json(out)
            return
        console.ok("State import completed.")
        console.info(
            f"created={out.get('created_services')} "
            f"updated={out.get('updated_services')} "
            f"revisions={out.get('imported_revisions')} "
            f"instances={out.get('upserted_instances')}"
        )
    except ApiError as exc:
        console.err(f"State import failed: {exc}")
        raise typer.Exit(code=2)
    finally:
        client.close()
