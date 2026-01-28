from __future__ import annotations

from dataclasses import dataclass
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


def persist_telemetry_choice(host_key: str, enabled: bool) -> None:
    cfg = load_config()
    cfg.telemetry[host_key] = enabled
    save_config(cfg)


def _abort_interactive() -> None:
    console.err("Aborted by user.")
    raise typer.Exit(code=1)
