from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

import httpx
import typer
from rich.table import Table
from .. import console
from ..auth_state import resolve_auth_context
from ..config import load_config, resolve_license_api_url, save_config
from ..http import make_client
from ..registry_store import delete_registry, load_registry, save_registry, registry_path
from saharo_client import ApiError
from .invite_cmd import accept_invite

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


@app.command("logout", help="Clear API token and registry credentials.")
def logout(
    docker: bool = typer.Option(
        True,
        "--docker/--no-docker",
        help="Log out of the Docker registry as well.",
    ),
):
    cfg = load_config()
    ctx = resolve_auth_context()
    cfg.auth.token = ""
    save_path = save_config(cfg)
    console.ok(f"Token cleared from {save_path}.")
    if ctx.role == "admin":
        creds = load_registry()
        if creds and docker:
            _docker_logout(creds.url)
        if creds:
            delete_registry()
            console.ok("Registry credentials removed.")


@dataclass
class _ActivateResponse:
    registry_url: str
    registry_username: str
    registry_password: str | None
    resolved_versions: dict[str, str]


def _parse_activate_response(payload: dict[str, Any]) -> _ActivateResponse:
    registry = payload.get("registry")
    if not isinstance(registry, dict):
        raise ValueError("Missing registry data in response.")
    registry_url = str(registry.get("url") or "").strip()
    registry_username = str(registry.get("username") or "").strip()
    registry_password = registry.get("password")
    if registry_password is not None and not isinstance(registry_password, str):
        registry_password = None
    resolved_versions = payload.get("resolved_versions")
    if not isinstance(resolved_versions, dict):
        resolved_versions = {}
    versions: dict[str, str] = {}
    for key, value in resolved_versions.items():
        if isinstance(value, str) and value.strip():
            versions[str(key)] = value
    if not registry_url or not registry_username:
        raise ValueError("Registry credentials are incomplete.")
    return _ActivateResponse(
        registry_url=registry_url,
        registry_username=registry_username,
        registry_password=registry_password,
        resolved_versions=versions,
    )


def _docker_login(url: str, username: str, password: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "login", url, "-u", username, "--password-stdin"],
            input=password.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        console.err("Docker CLI not found in PATH.")
        return False
    if result.returncode == 0:
        return True
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    if stderr:
        console.err(f"Docker login failed: {stderr}")
    else:
        console.err("Docker login failed.")
    return False


def _docker_logout(url: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "logout", url],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        console.err("Docker CLI not found in PATH.")
        return False
    if result.returncode == 0:
        return True
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    if stderr:
        console.err(f"Docker logout failed: {stderr}")
    else:
        console.err("Docker logout failed.")
    return False


@app.command(
    "activate",
    help="Admin-only: activate a license during host bootstrap.",
    hidden=True,
)
def activate(
    license_key: str = typer.Option(
        ...,
        "--license-key",
        prompt="License key",
        hide_input=True,
        help="License key for activation.",
    ),
    machine_name: str | None = typer.Option(
        None,
        "--machine-name",
        help="Optional machine name to attach to the activation.",
    ),
    note: str | None = typer.Option(
        None,
        "--note",
        help="Optional activation note.",
    ),
    login: bool = typer.Option(
        True,
        "--login/--no-login",
        help="Log into the registry with the returned credentials.",
    ),
):
    ctx = resolve_auth_context()
    if ctx.role != "admin":
        console.err("This is an admin-only command used during host bootstrap.")
        console.info("Run: saharo host bootstrap")
        raise typer.Exit(code=2)

    cfg = load_config()
    api_url = resolve_license_api_url(cfg)
    payload: dict[str, str] = {}
    if machine_name is not None:
        machine_name = machine_name.strip()
        if machine_name:
            payload["machine_name"] = machine_name
    if note is not None:
        note = note.strip()
        if note:
            payload["note"] = note

    try:
        response = httpx.post(
            f"{api_url}/v1/activate",
            headers={"X-License-Key": license_key},
            json=payload,
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.RequestError as exc:
        console.err(f"License API request failed: {exc}")
        raise typer.Exit(code=2)
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        body = exc.response.text.strip()
        detail = f": {body}" if body else ""
        console.err(f"Activation failed: HTTP {status}{detail}")
        raise typer.Exit(code=2)

    try:
        data = response.json()
    except ValueError:
        console.err("Activation failed: invalid JSON response.")
        raise typer.Exit(code=2)

    try:
        activation = _parse_activate_response(data)
    except ValueError as exc:
        console.err(f"Activation failed: {exc}")
        raise typer.Exit(code=2)

    existing = load_registry()
    password = activation.registry_password
    if password is None and existing and existing.password:
        password = existing.password
        console.warn("Registry password not returned; keeping existing credentials.")
    elif password is None:
        console.warn("Registry password not returned; credentials were not rotated.")

    save_registry(
        url=activation.registry_url,
        username=activation.registry_username,
        password=password,
    )

    console.ok("License activated.")
    console.console.print(f"[bold]Registry user:[/] {activation.registry_username}")
    if activation.resolved_versions:
        versions = ", ".join(
            f"{k}={v}" for k, v in sorted(activation.resolved_versions.items(), key=lambda item: item[0])
        )
        console.console.print(f"[bold]Resolved versions:[/] {versions}")
    else:
        console.console.print("[bold]Resolved versions:[/] (none)")

    if login:
        if password:
            if _docker_login(activation.registry_url, activation.registry_username, password):
                console.ok(f"Docker login succeeded for {activation.registry_url}.")
        else:
            console.warn("Docker login skipped: no registry password available.")


@app.command("status", help="Show current registry activation status.")
def status(
    verbose: bool = typer.Option(False, "--verbose", help="Show extra activation details."),
):
    creds = load_registry()
    if not creds:
        console.info("Not activated.")
        return
    issued_at = creds.issued_at or "-"
    console.console.print(f"[bold]Registry:[/] {creds.url}")
    console.console.print(f"[bold]Username:[/] {creds.username}")
    console.console.print(f"[bold]Issued at:[/] {issued_at}")
    if verbose:
        console.console.print(f"[bold]Registry file:[/] {registry_path()}")
        console.console.print(f"[bold]Password stored:[/] {'yes' if creds.password else 'no'}")




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
