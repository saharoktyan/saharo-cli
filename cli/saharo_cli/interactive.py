from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import Iterable

import questionary
import typer
from questionary import Choice, Style

from saharo_client import ApiError, AuthError, NetworkError

from . import console
from .config import AppConfig, load_config, save_config
from .http import make_client


# Use questionary for inline, non-fullscreen selections that feel like gh/codex prompts.

_SELECT_STYLE = Style(
    [
        ("pointer", "ansiyellow bold"),
        ("selected", "ansicyan bold"),
        ("highlighted", "ansicyan bold"),
        ("instruction", "ansiblack"),
        ("star_on", "ansigreen bold"),
        ("star_off", "ansiblack"),
    ]
)

@dataclass(frozen=True)
class PortalLicense:
    key: str
    name: str
    expires_at: str | None = None


def fetch_portal_licenses(cfg: AppConfig, *, base_url_override: str | None = None) -> list[PortalLicense]:
    try:
        client = make_client(cfg, profile=None, base_url_override=base_url_override, check_compat=False)
    except Exception:
        return []
    try:
        raw = client.portal_licenses() if hasattr(client, "portal_licenses") else []
    except (ApiError, AuthError, NetworkError):
        return []
    finally:
        client.close()

    if not isinstance(raw, list):
        return []
    licenses: list[PortalLicense] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        key = str(item.get("license_key") or item.get("key") or item.get("id") or "").strip()
        if not key:
            continue
        name = str(item.get("name") or item.get("title") or key).strip() or key
        expires_at = item.get("expires_at") or item.get("expires") or item.get("expiry")
        expires = str(expires_at).strip() if isinstance(expires_at, str) and expires_at else None
        licenses.append(PortalLicense(key=key, name=name, expires_at=expires))
    return licenses


def select_license(licenses: Iterable[PortalLicense]) -> str | None:
    license_list = list(licenses)
    if not license_list:
        return ""

    choices: list[Choice] = []
    for lic in license_list:
        if lic.expires_at:
            title = f"{lic.name} (expires {lic.expires_at})"
        else:
            title = lic.name
        choices.append(Choice(title=title, value=lic.key))
    choices.append(Choice(title="Enter license key manually", value=""))

    try:
        result = questionary.select(
            "Select a license",
            choices=choices,
            default=None,
            use_shortcuts=False,
            pointer="▶",
            style=_SELECT_STYLE,
        ).ask()
    except KeyboardInterrupt:
        _abort_interactive()
    if result is None:
        _abort_interactive()
    return str(result)


def confirm_telemetry(*, default: bool = False) -> bool:
    return confirm_choice("Enable telemetry for this host?", default=default)


def confirm_choice(message: object, *, default: bool = True) -> bool:
    prompt = str(getattr(message, "plain", message))
    choices = [
        Choice(title="Yes", value=True),
        Choice(title="No", value=False),
    ]
    try:
        result = questionary.select(
            prompt,
            choices=choices,
            default=None,
            use_shortcuts=False,
            pointer="▶",
            style=_SELECT_STYLE,
        ).ask()
    except KeyboardInterrupt:
        _abort_interactive()
    if result is None:
        _abort_interactive()
    return bool(result)


def select_toggle(message: str, *, default_enabled: bool | None = None) -> bool:
    enable_title = "Enable"
    disable_title = "Disable"
    if default_enabled is True:
        enable_title = [
            ("class:star_on", "★ "),
            ("", "Enable"),
        ]
        disable_title = [
            ("class:star_off", "  "),
            ("", "Disable"),
        ]
    elif default_enabled is False:
        enable_title = [
            ("class:star_off", "  "),
            ("", "Enable"),
        ]
        disable_title = [
            ("class:star_on", "★ "),
            ("", "Disable"),
        ]

    choices = [
        Choice(title=enable_title, value=True),
        Choice(title=disable_title, value=False),
    ]
    default_value = None if default_enabled is None else default_enabled
    try:
        result = questionary.select(
            message,
            choices=choices,
            default=default_value,
            use_shortcuts=False,
            pointer="▶",
            style=_SELECT_STYLE,
        ).ask()
    except KeyboardInterrupt:
        _abort_interactive()
    if result is None:
        _abort_interactive()
    return bool(result)


def select_item(message: str, choices: list[Choice], *, clear_after: bool = False) -> str | None:
    try:
        result = questionary.select(
            message,
            choices=choices,
            default=None,
            use_shortcuts=False,
            pointer="▶",
            style=_SELECT_STYLE,
        ).ask()
    except KeyboardInterrupt:
        _abort_interactive()
    if result is None:
        _abort_interactive()
    if clear_after:
        _clear_prompt(len(choices) + 1)
    return str(result)


def persist_telemetry_choice(host_key: str, enabled: bool) -> None:
    cfg = load_config()
    cfg.telemetry[host_key] = enabled
    save_config(cfg)


def _abort_interactive() -> None:
    console.err("Aborted by user.")
    raise typer.Exit(code=1)


def _clear_prompt(lines: int) -> None:
    if not sys.stdout.isatty() or lines <= 0:
        return
    # Clear the prompt block so nested menus don't spam scrollback.
    for _ in range(lines):
        sys.stdout.write("\x1b[2K\x1b[1A")
    sys.stdout.write("\x1b[2K\r")
    sys.stdout.flush()
def select_user(client) -> int:
    try:
        data = client.admin_users_list(limit=100)
    except ApiError as e:
        console.err(f"Failed to list users: {e}")
        raise typer.Exit(code=2)
    
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        console.err("No users found.")
        raise typer.Exit(code=2)
    
    choices = []
    for u in items:
        username = u.get("username") or "unnamed"
        label = f"{username} (id={u.get('id')}) - {u.get('role')}"
        choices.append(Choice(title=label, value=str(u.get("id"))))
    
    selected_id = select_item("Select a user", choices)
    if not selected_id:
        raise typer.Exit(code=1)
    return int(selected_id)


def select_server(client) -> int:
    try:
        data = client.admin_servers_list(limit=100)
    except ApiError as e:
        console.err(f"Failed to list servers: {e}")
        raise typer.Exit(code=2)
    
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        console.err("No servers found.")
        raise typer.Exit(code=2)
    
    choices = []
    for s in items:
        name = s.get("name") or "unnamed"
        label = f"{name} (id={s.get('id')}) - {s.get('public_host') or 'no host'}"
        choices.append(Choice(title=label, value=str(s.get("id"))))
    
    selected_id = select_item("Select a server", choices)
    if not selected_id:
        raise typer.Exit(code=1)
    return int(selected_id)


def select_agent(client) -> int:
    try:
        data = client.admin_agents_list(include_deleted=False, limit=100)
    except ApiError as e:
        console.err(f"Failed to list agents: {e}")
        raise typer.Exit(code=2)
    
    agents = data.get("items") if isinstance(data, dict) else []
    if not agents:
        console.err("No agents found.")
        raise typer.Exit(code=2)
    
    choices = []
    for a in agents:
        name = a.get("name") or "unnamed"
        label = f"{name} (id={a.get('id')}) - {a.get('status')}"
        choices.append(Choice(title=label, value=str(a.get("id"))))
    
    selected_id = select_item("Select an agent", choices)
    if not selected_id:
        raise typer.Exit(code=1)
    return int(selected_id)


def select_protocol(client, server_id: int) -> str:
    try:
        data = client.admin_server_protocols_list(server_id)
    except ApiError as e:
        console.err(f"Failed to list server protocols: {e}")
        raise typer.Exit(code=2)
    
    if not data:
        console.err("No protocols available on this server.")
        raise typer.Exit(code=2)
    
    choices = []
    for p in data:
        code = p.get("code") or p.get("protocol") or p.get("key")
        label = f"{code} ({p.get('status', 'unknown')})"
        choices.append(Choice(title=label, value=str(code)))
    
    selected = select_item("Select a protocol", choices)
    if not selected:
        raise typer.Exit(code=1)
    return selected


def select_custom_service(client) -> int:
    try:
        data = client.admin_custom_services_list()
    except ApiError as e:
        console.err(f"Failed to list custom services: {e}")
        raise typer.Exit(code=2)
    
    if not data:
        console.err("No custom services found.")
        raise typer.Exit(code=2)
    
    choices = []
    for s in data:
        label = f"{s.get('display_name') or s.get('code')} (id={s.get('id')})"
        choices.append(Choice(title=label, value=str(s.get("id"))))
    
    selected_id = select_item("Select a custom service", choices)
    if not selected_id:
        raise typer.Exit(code=1)
    return int(selected_id)
