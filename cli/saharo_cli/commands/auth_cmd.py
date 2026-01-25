from __future__ import annotations

import typer
from rich.table import Table
from saharo_client import ApiError

from .invite_cmd import accept_invite
from .. import console
from ..config import load_config, save_config
from ..http import make_client

app = typer.Typer(help="Auth commands.")


@app.command("login")
def login(
        username: str = typer.Option(..., "--username", prompt=True, help="Username for login."),
        password: str = typer.Option(..., "--password", prompt=True, hide_input=True, help="Password for login."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        token = client.auth_login(username=username, password=password)
    except ApiError as e:
        console.err(f"Login failed: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    cfg.auth.token = token
    cfg.auth.token_type = "bearer"
    save_path = save_config(cfg)
    console.ok(f"Login successful. Token saved to {save_path}.")


@app.command("login-api-key")
def login_api_key(
        api_key: str = typer.Option(..., "--api-key", prompt=True, hide_input=True, help="API key for login."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        token = client.auth_api_key(api_key=api_key)
    except ApiError as e:
        console.err(f"Login failed: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    cfg.auth.token = token
    cfg.auth.token_type = "bearer"
    save_path = save_config(cfg)
    console.ok(f"Login successful. Token saved to {save_path}.")


@app.command("logout", help="Clear API token.")
def logout():
    cfg = load_config()
    cfg.auth.token = ""
    save_path = save_config(cfg)
    console.ok(f"Token cleared from {save_path}.")


app.command("register")(accept_invite)


def whoami_impl(
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
        verbose: bool = typer.Option(False, "--verbose", help="Print raw /me JSON."),
):
    """
    Show current authenticated user.
    """
    from ..http import make_client
    from saharo_client import ApiError

    cfg = load_config()
    if not (cfg.auth.token or "").strip():
        console.err("Not authenticated. No token found.")
        console.info("Run: saharo auth login")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        me = client.me()
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Not authenticated.")
            console.info("Your token is invalid or expired.")
            console.info("Run: saharo auth login")
        else:
            console.err(f"Failed to fetch /me: HTTP {e.status_code}")
            try:
                console.print_json(e.body)
            except Exception:
                console.err(str(e))
        raise typer.Exit(code=2)
    finally:
        client.close()

    username = me.get("username") or "-"
    role = me.get("role") or "-"
    console.rule("Whoami")
    console.console.print(f"[bold]Username:[/] {username}")
    console.console.print(f"[bold]Role:[/] {role}")
    sub = me.get("subscription") or {}
    if sub:
        status = sub.get("status") or "active"
        ends_at = sub.get("ends_at")
        days_left = sub.get("days_left")
        details: list[str] = []
        if days_left is not None:
            details.append(f"{days_left} days left")
        elif ends_at is None:
            details.append("perpetual")
        if details:
            sub_display = f"{status} ({', '.join(details)})"
        else:
            sub_display = status
    else:
        sub_display = "none"
        ends_at = None
    console.console.print(f"[bold]Subscription:[/] {sub_display}")

    access = me.get("access") or []
    rows: list[dict[str, str]] = []
    for server in access:
        server_id = server.get("id")
        server_name = server.get("name")
        server_label = server_name or (f"id={server_id}" if server_id is not None else "-")
        for protocol in server.get("protocols") or []:
            protocol_key = protocol.get("key") or protocol.get("name") or "-"
            status = protocol.get("status") or "active"
            expires_at = protocol.get("expires_at") or ends_at or "—"
            rows.append(
                {
                    "server": server_label,
                    "protocol": str(protocol_key),
                    "status": str(status),
                    "expires": str(expires_at),
                }
            )

    if rows:
        rows_sorted = sorted(rows, key=lambda r: (r["server"], r["protocol"]))
        table = Table(title="Access (Grants)")
        table.add_column("Server", style="bold")
        table.add_column("Protocol")
        table.add_column("Status")
        table.add_column("Expires")
        for row in rows_sorted:
            table.add_row(row["server"], row["protocol"], row["status"], row["expires"])
        console.console.print(table)
    else:
        console.info("No access grants yet. Ask admin to enable a server/protocol for your account.")

    if verbose:
        console.rule("Raw /me")
        console.print_json(me)


@app.command("whoami")
def whoami(
        base_url: str | None = typer.Option(None, "--base-url", help="Override API base URL."),
        verbose: bool = typer.Option(False, "--verbose", help="Print raw /me JSON."),
):
    console.warn("Deprecated: use `saharo whoami` instead.")
    whoami_impl(base_url=base_url, verbose=verbose)
