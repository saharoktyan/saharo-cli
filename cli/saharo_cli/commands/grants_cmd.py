from __future__ import annotations

import typer
from rich.table import Table
from saharo_client import ApiError

from .. import console
from ..config import load_config
from ..http import make_client

app = typer.Typer(help="Grants commands (admin only).")


def _print_candidates(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_header=True, header_style="bold")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.console.print(table)


def _resolve_protocol(client, protocol: str) -> tuple[int, str | None]:
    protocol = (protocol or "").strip()
    if not protocol:
        console.err("Protocol is required.")
        raise typer.Exit(code=2)
    data = client.admin_protocols_list()
    items = data.get("items") if isinstance(data, dict) else []
    if protocol.isdigit():
        protocol_id = int(protocol)
        match = next((p for p in items or [] if int(p.get("id", -1)) == protocol_id), None)
        return protocol_id, match.get("code") if match else None
    matches = [
        p
        for p in items or []
        if str(p.get("code", "")).lower() == protocol.lower()
    ]
    if not matches:
        choices = ", ".join(sorted({str(p.get("code")) for p in items or [] if p.get("code")}))
        console.err(f"Protocol '{protocol}' not found.")
        if choices:
            console.info(f"Available: {choices}")
        raise typer.Exit(code=2)
    if len(matches) > 1:
        console.err(f"Protocol '{protocol}' is ambiguous. Matches:")
        rows = [
            [str(p.get("id", "-")), str(p.get("code", "-")), str(p.get("title", "-"))]
            for p in matches
        ]
        _print_candidates("Protocols", ["id", "code", "title"], rows)
        raise typer.Exit(code=2)
    return int(matches[0]["id"]), matches[0].get("code")


def _resolve_user_id(client, user: str | None, user_id: int | None) -> int:
    if user_id is not None:
        return int(user_id)
    value = (user or "").strip()
    if not value:
        console.err("User is required. Provide --user or --user-id.")
        raise typer.Exit(code=2)
    if value.isdigit():
        return int(value)

    data = client.admin_users_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        console.err(f"User '{value}' not found.")
        raise typer.Exit(code=2)
    if len(items) > 1:
        console.err("Multiple users matched. Use --user-id to disambiguate.")
        rows = [
            [
                str(u.get("id", "-")),
                str(u.get("username") or "-"),
                str(u.get("telegram_id") or "-"),
            ]
            for u in items
        ]
        _print_candidates("Users", ["id", "username", "telegram_id"], rows)
        raise typer.Exit(code=2)
    return int(items[0]["id"])


def _resolve_server_id(client, server: str | None, server_id: int | None) -> int:
    if server_id is not None:
        return int(server_id)
    value = (server or "").strip()
    if not value:
        console.err("Server is required. Provide --server or --server-id.")
        raise typer.Exit(code=2)
    if value.isdigit():
        return int(value)

    data = client.admin_servers_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        console.err(f"Server '{value}' not found.")
        raise typer.Exit(code=2)
    if len(items) > 1:
        console.err("Multiple servers matched. Use --server-id to disambiguate.")
        rows = [
            [
                str(s.get("id", "-")),
                str(s.get("name") or "-"),
                str(s.get("public_host") or "-"),
            ]
            for s in items
        ]
        _print_candidates("Servers", ["id", "name", "host"], rows)
        raise typer.Exit(code=2)
    return int(items[0]["id"])


def _validate_route_for_protocol(protocol_code: str | None, route: str | None) -> str | None:
    if route is None:
        return None
    normalized = route.strip()
    if not normalized:
        return None
    if protocol_code != "xray":
        console.err("Route is only supported for xray grants.")
        raise typer.Exit(code=2)
    return normalized


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
        protocol_id, protocol_code = _resolve_protocol(client, protocol)
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


@app.command("revoke")
def revoke_grant(
        grant_id: int = typer.Option(..., "--id", help="Grant ID."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
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
