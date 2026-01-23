from __future__ import annotations

import typer

from .. import console
from ..config import load_config, save_config
from ..http import make_client
from saharo_client import ApiError

app_user = typer.Typer(help="Invite commands (user).")
app_admin = typer.Typer(help="Invite commands (admin).")


def _default_device_label() -> str:
    import socket
    return socket.gethostname() or "device"


def _default_platform() -> str:
    import platform as _p
    # nice readable string
    return f"{_p.system()} {_p.release()}".strip()


@app_user.command("accept")
def accept_invite(
    invite_token: str = typer.Argument(..., help="Invite token."),
    username: str = typer.Option(..., "--username", prompt=True, help="New username."),
    password: str | None = typer.Option(None, "--password", help="New password."),
    device_label: str = typer.Option(
        None,
        "--device",
        help="Device label. Defaults to hostname.",
    ),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    cfg = load_config()
    token = (invite_token or "").strip()
    if not token:
        console.err("Invite token cannot be empty.")
        raise typer.Exit(code=2)

    label = (device_label or _default_device_label()).strip()
    if not label:
        console.err("Device label cannot be empty.")
        raise typer.Exit(code=2)

    password = _prompt_password_with_confirmation(password)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.invites_claim_local(
            token=token,
            username=username,
            password=password,
            device_label=label,
            platform=_default_platform(),
        )
    except ApiError as e:
        # make errors friendly
        if e.status_code == 404:
            console.err("Invite not found.")
        elif e.status_code == 409:
            console.err("Username or device label already exists.")
        elif e.status_code in (400, 401, 403):
            console.err(f"Invite claim failed: {e}")
        else:
            console.err(f"Invite claim failed: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    jwt = data.get("token") if isinstance(data, dict) else None
    if not isinstance(jwt, str) or not jwt:
        console.err("Unexpected response: token missing.")
        raise typer.Exit(code=2)

    cfg.auth.token = jwt
    cfg.auth.token_type = "bearer"
    save_path = save_config(cfg)

    console.ok("Invite accepted. You are now logged in.")
    console.info(f"Token saved to {save_path}.")


def _prompt_password_with_confirmation(
    initial_password: str | None,
    *,
    max_attempts: int = 3,
    min_length: int = 8,
) -> str:
    attempts = 0
    password = initial_password
    while attempts < max_attempts:
        if password is None:
            password = typer.prompt("Password", hide_input=True)
        confirm = typer.prompt("Confirm password", hide_input=True)
        if not password or not password.strip():
            console.err("Password cannot be empty.")
            attempts += 1
            password = None
            continue
        if len(password) < min_length:
            console.err(f"Password must be at least {min_length} characters.")
            attempts += 1
            password = None
            continue
        if password != confirm:
            console.err("Passwords do not match.")
            attempts += 1
            password = None
            continue
        return password
    console.err("Too many attempts.")
    raise typer.Exit(code=2)


@app_admin.command("create")
def create_invite(
    duration_days: int | None = typer.Option(None, "--duration-days", help="Subscription duration template (days)."),
    perpetual: bool = typer.Option(False, "--perpetual", help="Perpetual subscription template."),
    note: str | None = typer.Option(None, "--note", help="Note stored with invite/subscription."),
    max_uses: int = typer.Option(1, "--max-uses", help="Maximum uses for this invite."),
    expires_in_days: int | None = typer.Option(30, "--expires-in-days", help="Invite expiry in days."),
    base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
    json_out: bool = typer.Option(False, "--json", help="Print raw JSON."),
):
    cfg = load_config()
    if not (cfg.auth.token or "").strip():
        console.err("Auth token missing. Run `saharo auth login` first.")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        data = client.invites_create(
            duration_days=duration_days,
            perpetual=perpetual,
            note=note,
            max_uses=max_uses,
            expires_in_days=expires_in_days,
        )
    except ApiError as e:
        if e.status_code in (401, 403):
            console.err("Unauthorized. Admin access is required.")
        else:
            console.err(f"Failed to create invite: {e}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if json_out:
        console.print_json(data)
        return

    token = data.get("token") if isinstance(data, dict) else None
    if token:
        console.ok("Invite created:")
        console.console.print(token)
    else:
        console.err("Invite created but token missing in response.")
        console.print_json(data)
