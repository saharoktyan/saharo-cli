from __future__ import annotations

import typer
from rich.table import Table
from saharo_client import ApiError
from saharo_client.resolve import (
    ResolveError,
    resolve_protocol_for_grants,
    resolve_server_id_for_grants,
    resolve_user_id_for_grants,
    validate_route_for_protocol,
)

from .. import console
from ..config import load_config
from ..http import make_client
from ..interactive import select_user, select_server, select_protocol

app = typer.Typer(help="Grants commands (admin only).")


def _print_candidates(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_header=True, header_style="bold")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.console.print(table)


def _resolve_user_id(client, user: str | None, user_id: int | None) -> int:
    if user is None and user_id is None:
        return select_user(client)
    try:
        return resolve_user_id_for_grants(client, user, user_id)
    except ResolveError as exc:
        console.err(str(exc))
        if exc.candidates and exc.candidate_headers:
            _print_candidates("Users", exc.candidate_headers, exc.candidates)
        raise typer.Exit(code=2)


def _resolve_server_id(client, server: str | None, server_id: int | None) -> int:
    if server is None and server_id is None:
        return select_server(client)
    try:
        return resolve_server_id_for_grants(client, server, server_id)
    except ResolveError as exc:
        console.err(str(exc))
        if exc.candidates and exc.candidate_headers:
            _print_candidates("Servers", exc.candidate_headers, exc.candidates)
        raise typer.Exit(code=2)


def _resolve_protocol(client, server_id: int, protocol: str | None) -> tuple[int, str | None]:
    if protocol is None:
        code = select_protocol(client, server_id)
        id_val, _ = resolve_protocol_for_grants(client, code)
        return id_val, code
    try:
        return resolve_protocol_for_grants(client, protocol)
    except ResolveError as exc:
        console.err(str(exc))
        if exc.info_label and exc.info_value:
            console.info(f"{exc.info_label}: {exc.info_value}")
        if exc.candidates and exc.candidate_headers:
            _print_candidates("Protocols", exc.candidate_headers, exc.candidates)
        raise typer.Exit(code=2)


def _validate_route_for_protocol(protocol_code: str | None, route: str | None) -> str | None:
    try:
        return validate_route_for_protocol(protocol_code, route)
    except ResolveError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


@app.command("list")
def list_grants(
        user_id: int | None = typer.Option(None, "--user-id", help="Filter by user ID."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        data = client.admin_grants_list(user_id=user_id)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to list grants: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    items = data.get("items") if isinstance(data, dict) else []
    protocol_map = {}
    if items:
        cfg = load_config()
        client = make_client(cfg, profile=None, base_url_override=base_url)
        try:
            proto_data = client.admin_protocols_list()
            for p in proto_data.get("items", []) if isinstance(proto_data, dict) else []:
                protocol_map[int(p["id"])] = p.get("code") or p.get("title") or str(p.get("id"))
        except ApiError:
            protocol_map = {}
        finally:
            client.close()

    table = Table(title="Grants")
    table.add_column("id", style="bold")
    table.add_column("user_id")
    table.add_column("server_id")
    table.add_column("protocol")
    table.add_column("status")
    table.add_column("expires_at")
    table.add_column("revoked_at")

    for g in items or []:
        protocol_id = g.get("protocol_id")
        protocol_label = protocol_map.get(int(protocol_id)) if protocol_id is not None else None
        protocol_display = protocol_label or str(protocol_id or "-")
        table.add_row(
            str(g.get("id", "-")),
            str(g.get("user_id", "-")),
            str(g.get("server_id", "-")),
            protocol_display,
            str(g.get("status") or "-"),
            str(g.get("expires_at") or "-"),
            str(g.get("revoked_at") or "-"),
        )

    console.console.print(table)


@app.command("create")
def create_grant(
        user: str | None = typer.Option(None, "--user", help="Target user (id, username, or telegram id)."),
        user_id: int | None = typer.Option(None, "--user-id", help="Target user ID."),
        server: str | None = typer.Option(None, "--server", help="Server (id or name)."),
        server_id: int | None = typer.Option(None, "--server-id", help="Server ID."),
        protocol: str | None = typer.Argument(None, help="Protocol code (awg, xray, ...)"),
        route: str | None = typer.Option(None, "--route", help="Route for xray grants (e.g. tcp, ws)."),
        device_limit: int | None = typer.Option(None, "--device-limit", help="Device limit."),
        note: str | None = typer.Option(None, "--note", help="Grant note."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        resolved_user_id = _resolve_user_id(client, user, user_id)
        resolved_server_id = _resolve_server_id(client, server, server_id)
        protocol_id, protocol_code = _resolve_protocol(client, resolved_server_id, protocol)
        resolved_route = _validate_route_for_protocol(protocol_code, route)
        grant = client.admin_grant_create(
            user_id=resolved_user_id,
            server_id=resolved_server_id,
            protocol_id=protocol_id,
            route=resolved_route,
            device_limit=device_limit,
            note=note,
        )
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to create grant: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok(f"Grant {grant.get('id')} created for user {resolved_user_id}.")


@app.command("delete")
def delete_grant(
        grant_id: int | None = typer.Option(None, "--id", help="Grant ID."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        if grant_id is None:
            # For deletion, we could list all grants, but it might be too many.
            # Usually users delete specific grants. But for unification:
            data = client.admin_grants_list()
            items = data.get("items") if isinstance(data, dict) else []
            if not items:
                console.err("No grants found.")
                raise typer.Exit(code=2)
            
            from questionary import Choice
            choices = []
            for g in items:
                label = f"ID {g['id']}: User {g['user_id']} -> Server {g['server_id']} ({g['status']})"
                choices.append(Choice(title=label, value=str(g["id"])))
            
            from ..interactive import select_item
            sel = select_item("Select a grant to delete", choices)
            if not sel:
                raise typer.Exit(code=1)
            grant_id = int(sel)

        grant = client.admin_grant_revoke(grant_id)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to revoke grant: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok(f"Grant {grant.get('id', grant_id)} revoked.")
