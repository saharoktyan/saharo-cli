from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from typing import Any

import tomli_w
from platformdirs import user_config_dir

from . import console

APP_NAME = "saharo"
CONFIG_FILENAME = "config.toml"
LICENSE_API_URL_DEFAULT = "https://downloads.saharoktyan.ru"
ENV_LICENSE_API_URL = "SAHARO_LICENSE_API_URL"

_WARNED_BASE_URL_SCHEME = False


@dataclass
class AuthConfig:
    token: str = ""
    token_type: str = "bearer"


@dataclass
class AgentConfig:
    agent_id: int | None = None
    agent_secret: str = ""
    invite_token: str = ""
    note: str | None = None
    created_at: str | None = None
    expires_at: str | None = None


@dataclass
class AppConfig:
    base_url: str
    auth: AuthConfig
    agents: dict[str, AgentConfig]
    license_api_url: str = LICENSE_API_URL_DEFAULT
    telemetry: dict[str, bool] = field(default_factory=dict)
    portal_session_token: str = ""
    portal_csrf_token: str = ""


def config_path() -> str:
    return f"{user_config_dir(APP_NAME)}/{CONFIG_FILENAME}"


def default_config() -> AppConfig:
    return AppConfig(
        base_url="http://127.0.0.1:8010",
        auth=AuthConfig(token="", token_type="bearer"),
        agents={},
        license_api_url=LICENSE_API_URL_DEFAULT,
        telemetry={},
        portal_session_token="",
        portal_csrf_token="",
    )


def normalize_base_url(raw: str | None, *, warn: bool = False) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    value = value.rstrip("/")
    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return value

    host = value.split("/", 1)[0]
    host = host.split(":", 1)[0].lower()
    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        scheme = "http://"
    else:
        scheme = "https://"

    normalized = f"{scheme}{value}"
    if warn:
        _warn_missing_scheme(normalized)
    return normalized


def _warn_missing_scheme(normalized: str) -> None:
    global _WARNED_BASE_URL_SCHEME
    if _WARNED_BASE_URL_SCHEME:
        return
    if not _is_interactive():
        return
    console.warn(f"base_url missing scheme, assuming {normalized}")
    _WARNED_BASE_URL_SCHEME = True


def _is_interactive() -> bool:
    import sys
    return bool(sys.stderr.isatty() or sys.stdout.isatty())


def ensure_parent_dir(path: str) -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)


def to_toml(cfg: AppConfig) -> dict[str, Any]:
    return _prune_none(
        {
            "base_url": cfg.base_url,
            "license_api_url": cfg.license_api_url,
            "telemetry": cfg.telemetry,
            "portal_session_token": cfg.portal_session_token,
            "portal_csrf_token": cfg.portal_csrf_token,
            "auth": {
                "token": cfg.auth.token,
                "token_type": cfg.auth.token_type,
            },
            "agents": {
                name: {
                    "agent_id": a.agent_id,
                    "agent_secret": a.agent_secret,
                    "invite_token": a.invite_token,
                    "note": a.note,
                    "created_at": a.created_at,
                    "expires_at": a.expires_at,
                }
                for name, a in cfg.agents.items()
            },
        }
    )


def _prune_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _prune_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_prune_none(item) for item in value if item is not None]
    return value


def from_toml(data: dict[str, Any]) -> AppConfig:
    base_url = normalize_base_url(str(data.get("base_url") or ""), warn=True)
    license_api_url = str(data.get("license_api_url") or "").strip()
    portal_session_token = str(data.get("portal_session_token") or "").strip()
    portal_csrf_token = str(data.get("portal_csrf_token") or "").strip()
    telemetry_raw = data.get("telemetry") or {}
    telemetry: dict[str, bool] = {}
    if isinstance(telemetry_raw, dict):
        for key, value in telemetry_raw.items():
            if isinstance(value, bool):
                telemetry[str(key)] = value
    auth_raw = data.get("auth") or {}
    token = ""
    token_type = "bearer"
    if isinstance(auth_raw, dict):
        token = str(auth_raw.get("token") or "")
        token_type = str(auth_raw.get("token_type") or "bearer")
    agents_raw = data.get("agents") or {}
    agents: dict[str, AgentConfig] = {}
    if isinstance(agents_raw, dict):
        for name, v in agents_raw.items():
            if not isinstance(v, dict):
                continue
            agent_id = v.get("agent_id")
            agent_secret = str(v.get("agent_secret") or "")
            invite_token = str(v.get("invite_token") or "")
            note = v.get("note")
            created_at = v.get("created_at")
            expires_at = v.get("expires_at")
            if agent_id is not None:
                try:
                    agent_id = int(agent_id)
                except Exception:
                    agent_id = None
            agents[str(name)] = AgentConfig(
                agent_id=agent_id,
                agent_secret=agent_secret,
                invite_token=invite_token,
                note=note if isinstance(note, str) else None,
                created_at=created_at if isinstance(created_at, str) else None,
                expires_at=expires_at if isinstance(expires_at, str) else None,
            )

    if base_url:
        return AppConfig(
            base_url=base_url,
            auth=AuthConfig(token=token, token_type=token_type),
            agents=agents,
            license_api_url=license_api_url or LICENSE_API_URL_DEFAULT,
            telemetry=telemetry,
            portal_session_token=portal_session_token,
            portal_csrf_token=portal_csrf_token,
        )

    # Backward compatibility: profiles-based config
    active = str(data.get("active_profile") or "dev")
    profiles_raw = data.get("profiles") or {}
    if isinstance(profiles_raw, dict):
        prof = profiles_raw.get(active)
        if not isinstance(prof, dict):
            # fallback to first profile
            for v in profiles_raw.values():
                if isinstance(v, dict):
                    prof = v
                    break
        if isinstance(prof, dict):
            base_url = normalize_base_url(str(prof.get("base_url") or ""), warn=True)
            token = str(prof.get("token") or "")
            if not license_api_url:
                license_api_url = str(prof.get("license_api_url") or "").strip()
            if base_url:
                return AppConfig(
                    base_url=base_url,
                    auth=AuthConfig(token=token, token_type="bearer"),
                    agents=agents,
                    license_api_url=license_api_url or LICENSE_API_URL_DEFAULT,
                    telemetry=telemetry,
                    portal_session_token=portal_session_token,
                    portal_csrf_token=portal_csrf_token,
                )

    cfg = default_config()
    cfg.agents = agents
    if license_api_url:
        cfg.license_api_url = license_api_url
    cfg.telemetry = telemetry
    cfg.portal_session_token = portal_session_token
    cfg.portal_csrf_token = portal_csrf_token
    return cfg


def load_config() -> AppConfig:
    path = config_path()
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return from_toml(data)
    except FileNotFoundError:
        return default_config()


def apply_profile(cfg: AppConfig, profile: str | None) -> AppConfig:
    if not profile:
        return cfg
    path = config_path()
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return cfg

    profiles_raw = data.get("profiles") or {}
    if not isinstance(profiles_raw, dict):
        return cfg
    prof = profiles_raw.get(profile)
    if not isinstance(prof, dict):
        return cfg

    base_url = normalize_base_url(str(prof.get("base_url") or cfg.base_url), warn=True)
    auth_raw = prof.get("auth") if isinstance(prof.get("auth"), dict) else {}
    token = str(prof.get("token") or auth_raw.get("token") or cfg.auth.token)
    token_type = str(prof.get("token_type") or auth_raw.get("token_type") or cfg.auth.token_type)
    license_api_url = str(prof.get("license_api_url") or cfg.license_api_url).strip()
    return AppConfig(
        base_url=base_url or cfg.base_url,
        auth=AuthConfig(token=token, token_type=token_type),
        agents=cfg.agents,
        license_api_url=license_api_url or cfg.license_api_url,
        telemetry=cfg.telemetry,
        portal_session_token=cfg.portal_session_token,
        portal_csrf_token=cfg.portal_csrf_token,
    )


def resolve_license_api_url(cfg: AppConfig) -> str:
    env_value = os.getenv(ENV_LICENSE_API_URL, "").strip()
    if env_value:
        return env_value.rstrip("/")
    return (cfg.license_api_url or LICENSE_API_URL_DEFAULT).strip().rstrip("/")


def save_config(cfg: AppConfig) -> str:
    path = config_path()
    ensure_parent_dir(path)
    with open(path, "wb") as f:
        f.write(tomli_w.dumps(to_toml(cfg)).encode("utf-8"))
    import os
    os.chmod(path, 0o600)
    return path
