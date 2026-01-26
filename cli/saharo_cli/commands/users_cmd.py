from __future__ import annotations

import typer
from rich.table import Table
from saharo_client import ApiError
from saharo_client.resolve import ResolveError, resolve_user_id_for_users

from .invite_cmd import create_invite
from .. import console
from ..config import load_config
from ..http import make_client

app = typer.Typer(help="Users commands (admin only).")

app.command("invite")(create_invite)


def _resolve_user_id(client, user_id: int | None, username: str | None) -> int:
    try:
        return resolve_user_id_for_users(client, user_id, username)
    except ResolveError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _print_subscription(sub: dict | None) -> None:
    if not sub:
        console.console.print("  subscription: -")
        return
    status = sub.get("status") or "-"
    ends_at = sub.get("ends_at")
    days_left = sub.get("days_left")
    if ends_at is None:
        ends_at_display = "perpetual"
    else:
        ends_at_display = str(ends_at)
    console.console.print(f"  subscription_status: {status}")
    console.console.print(f"  subscription_ends_at: {ends_at_display}")
    console.console.print(f"  subscription_days_left: {days_left if days_left is not None else '-'}")


@app.command("list")
def list_users(
        q: str | None = typer.Option(None, "--q", help="Search by username or telegram_id."),
        limit: int = typer.Option(50, "--limit", help="Max users to return."),
        offset: int = typer.Option(0, "--offset", help="Offset for listing."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
        json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        data = client.admin_users_list(q=q, limit=limit, offset=offset)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to list users: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    items = data.get("items") if isinstance(data, dict) else []
    total = data.get("total") if isinstance(data, dict) else None
    if total is not None:
        console.info(f"total={total} limit={limit} offset={offset}")

    table = Table(title="Users")
    table.add_column("id", style="bold")
    table.add_column("username")
    table.add_column("role")
    table.add_column("telegram_id")

    for u in items or []:
        user_id = str(u.get("id", "-"))
        username = str(u.get("username") or "-")
        role = str(u.get("role") or "-")
        telegram_id = str(u.get("telegram_id") or "-")
        table.add_row(user_id, username, role, telegram_id)

    console.console.print(table)


@app.command("show")
def show_user(
        user_id: int | None = typer.Argument(None, help="User ID."),
        username: str | None = typer.Option(None, "--u", help="Username."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        resolved_id = _resolve_user_id(client, user_id, username)
        user = client.admin_user_get(resolved_id)
        try:
            sub = client.admin_user_subscription_get(resolved_id)
        except ApiError as e:
            if e.status_code == 404:
                sub = None
            else:
                raise
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to fetch user: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok("User:")
    console.console.print(f"  id: {user.get('id')}")
    console.console.print(f"  username: {user.get('username')}")
    console.console.print(f"  role: {user.get('role')}")
    console.console.print(f"  telegram_id: {user.get('telegram_id')}")
    _print_subscription(sub)


@app.command("freeze")
def freeze_user(
        user_id: int | None = typer.Argument(None, help="User ID."),
        username: str | None = typer.Option(None, "--u", help="Username."),
        reason: str | None = typer.Option(None, "--reason", help="Freeze reason."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        resolved_id = _resolve_user_id(client, user_id, username)
        sub = client.admin_user_freeze(resolved_id, reason=reason)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to freeze user: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok(f"User {resolved_id} frozen.")
    _print_subscription(sub)


@app.command("unfreeze")
def unfreeze_user(
        user_id: int | None = typer.Argument(None, help="User ID."),
        username: str | None = typer.Option(None, "--u", help="Username."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        resolved_id = _resolve_user_id(client, user_id, username)
        sub = client.admin_user_unfreeze(resolved_id)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to unfreeze user: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok(f"User {resolved_id} unfrozen.")
    _print_subscription(sub)


@app.command("extend")
def extend_user(
        user_id: int | None = typer.Argument(None, help="User ID."),
        username: str | None = typer.Option(None, "--u", help="Username."),
        days: int = typer.Option(..., "--days", help="Days to extend."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)

    try:
        resolved_id = _resolve_user_id(client, user_id, username)
        sub = client.admin_user_extend(resolved_id, days=days)
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
            raise typer.Exit(code=2)
        console.err(f"Failed to extend user: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    console.ok(f"User {resolved_id} extended by {days} days.")
    _print_subscription(sub)
