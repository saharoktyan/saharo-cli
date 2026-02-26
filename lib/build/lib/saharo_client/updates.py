from __future__ import annotations

import platform as platform_mod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .errors import ApiError
from .jobs import wait_job


def coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            try:
                return int(text)
            except Exception:
                return None
    return None


def clean_versions(data: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(key, str) and isinstance(value, str) and key and value:
            out[key] = value
    return out


def extract_latest_versions(entitlements: dict | list | None, versions: dict | None) -> dict[str, str]:
    for source in (entitlements, versions):
        if not isinstance(source, dict):
            continue
        latest = source.get("latest_versions")
        if isinstance(latest, dict):
            return clean_versions(latest)
        resolved = source.get("resolved_versions")
        if isinstance(resolved, dict):
            return clean_versions(resolved)
    return {}


def extract_status(entitlements: dict | list | None) -> str | None:
    if not isinstance(entitlements, dict):
        return None
    status = entitlements.get("status")
    return status if isinstance(status, str) and status else None


def extract_linked(entitlements: dict | list | None, status: str | None) -> bool | None:
    if isinstance(entitlements, dict):
        telemetry = entitlements.get("telemetry")
        if isinstance(telemetry, dict):
            linked = telemetry.get("linked")
            if isinstance(linked, bool):
                return linked
        linked = entitlements.get("linked")
        if isinstance(linked, bool):
            return linked
    if status == "not_linked":
        return False
    if status:
        return True
    return None


def extract_installations(entitlements: dict | list | None) -> tuple[int | None, int | None]:
    if not isinstance(entitlements, dict):
        return None, None
    count = coerce_int(entitlements.get("installations_count"))
    limit = coerce_int(entitlements.get("installations_limit"))
    if count is not None or limit is not None:
        return count, limit
    installations = entitlements.get("installations")
    if isinstance(installations, dict):
        count = coerce_int(installations.get("count") or installations.get("installed"))
        limit = coerce_int(installations.get("limit") or installations.get("max"))
    return count, limit


def extract_outdated_agents(entitlements: dict | list | None) -> tuple[int | None, int | None]:
    if not isinstance(entitlements, dict):
        return None, None
    for key in ("installations_summary", "installation_summary", "installations"):
        summary = entitlements.get(key)
        if not isinstance(summary, dict):
            continue
        count = coerce_int(summary.get("outdated_agents") or summary.get("outdated_agents_count"))
        total = coerce_int(summary.get("agents_total") or summary.get("total_agents") or summary.get("agents_count"))
        if count is not None and total is not None:
            return count, total
    return None, None


def format_limit(limit: int | None) -> str:
    if limit is None or limit <= 0:
        return "∞"
    return str(limit)


def platform_id() -> str:
    return f"{platform_mod.system().lower()}-{platform_mod.machine().lower()}"


def format_api_error(exc: ApiError) -> str:
    if exc.details:
        return exc.details
    return str(exc.status_code)


@dataclass(frozen=True)
class CliUpdateStatus:
    current: str
    latest: str | None
    update_available: bool
    raw: dict[str, Any]


@dataclass(frozen=True)
class AdminUpdateStatus:
    status: str | None
    linked: bool | None
    latest_versions: dict[str, str]
    installations: tuple[int | None, int | None]
    outdated_agents: tuple[int | None, int | None]
    agents_summary: dict[str, Any] | None
    compatibility: dict[str, str] | None
    fetched_at: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class UpdateCheckResult:
    mode: str
    cli: CliUpdateStatus | None
    admin: AdminUpdateStatus | None


def check_updates(
    client,
    *,
    current_version: str,
    platform: str | None = None,
    refresh_admin: bool = True,
) -> UpdateCheckResult:
    me = client.me()
    is_admin = isinstance(me, dict) and me.get("role") == "admin"

    if not is_admin:
        data = client.updates_cli(current=current_version, platform=platform)
        if not isinstance(data, dict) or not data.get("ok"):
            raise ValueError("Update check failed: invalid response from host API.")
        latest_cli = data.get("latest") if isinstance(data.get("latest"), str) else None
        update_available = bool(data.get("update_available"))
        return UpdateCheckResult(
            mode="user",
            cli=CliUpdateStatus(
                current=current_version,
                latest=latest_cli,
                update_available=update_available,
                raw=data,
            ),
            admin=None,
        )

    data = client.admin_license_refresh() if refresh_admin else client.admin_license_snapshot()
    if not isinstance(data, dict) or not data.get("ok"):
        raise ValueError("License refresh failed: invalid response from host API.")

    entitlements = data.get("entitlements")
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    fetched_at = data.get("fetched_at")

    status = extract_status(entitlements)
    linked = extract_linked(entitlements, status)
    latest_versions = extract_latest_versions(entitlements, versions)
    installations = extract_installations(entitlements)
    outdated_agents = extract_outdated_agents(entitlements)

    summary = None
    try:
        summary = client.admin_agents_summary()
    except Exception:
        summary = None

    agents_summary = None
    if isinstance(summary, dict):
        agents_summary = summary.get("agents") if isinstance(summary.get("agents"), dict) else None

    version_info = None
    try:
        version_info = client.version()
    except Exception:
        version_info = None

    compatibility = None
    if isinstance(version_info, dict):
        compat: dict[str, str] = {}
        cli_range = version_info.get("supported_cli_range")
        agent_range = version_info.get("supported_agent_range")
        if isinstance(cli_range, str) and cli_range:
            compat["cli"] = cli_range
        if isinstance(agent_range, str) and agent_range:
            compat["agent"] = agent_range
        compatibility = compat or None

    if isinstance(fetched_at, datetime):
        fetched_at_label = fetched_at.isoformat()
    else:
        fetched_at_label = str(fetched_at) if fetched_at else None

    return UpdateCheckResult(
        mode="admin",
        cli=None,
        admin=AdminUpdateStatus(
            status=status,
            linked=linked,
            latest_versions=latest_versions,
            installations=installations,
            outdated_agents=outdated_agents,
            agents_summary=agents_summary,
            compatibility=compatibility,
            fetched_at=fetched_at_label,
            raw=data,
        ),
    )


def resolve_latest_agent_version(client, *, refresh: bool = True) -> str:
    data = client.admin_license_refresh() if refresh else client.admin_license_snapshot()
    if not isinstance(data, dict) or not data.get("ok"):
        raise ValueError("License snapshot failed: invalid response from host API.")
    entitlements = data.get("entitlements")
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    latest_versions = extract_latest_versions(entitlements, versions)
    agent_version = latest_versions.get("agent")
    if not agent_version:
        raise ValueError("Unable to resolve latest agent version from license snapshot.")
    return agent_version


def create_agent_update_jobs(
    client,
    *,
    server_ids: list[int],
    target_version: str,
    wait: bool = False,
    timeout_s: int = 900,
    interval_s: int = 5,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for sid in server_ids:
        data = client.admin_job_create(
            server_id=sid,
            agent_id=None,
            job_type="agent_update",
            payload={"target_version": target_version},
        )
        if wait and isinstance(data, dict) and data.get("id"):
            data = wait_job(
                client,
                int(data["id"]),
                timeout_s=timeout_s,
                interval_s=interval_s,
            )
        results.append(data if isinstance(data, dict) else {"raw": data})
    return results


def host_update(client, *, pull_only: bool = False) -> dict[str, Any]:
    data = client.admin_host_update(pull_only=pull_only)
    return data if isinstance(data, dict) else {"raw": data}
