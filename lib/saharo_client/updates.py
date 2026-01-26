from __future__ import annotations

import platform as platform_mod
from typing import Any

from .errors import ApiError


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
