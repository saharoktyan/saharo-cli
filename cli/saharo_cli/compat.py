from __future__ import annotations

import os
from importlib import metadata
from typing import Any

import httpx

from .console import err, warn
from .semver import is_version_in_range

_CHECK_CACHE: dict[str, dict[str, Any]] = {}


def cli_version() -> str:
    try:
        return metadata.version("saharo-cli")
    except Exception:
        return "0.0.0"


def cli_protocol() -> int:
    try:
        return int(os.getenv("SAHARO_CLI_PROTOCOL") or "1")
    except Exception:
        return 1


def ensure_hub_compatibility(base_url: str, *, warn_only: bool = False) -> dict[str, Any] | None:
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        return None
    if base_url in _CHECK_CACHE:
        return _CHECK_CACHE[base_url]

    url = f"{base_url}/version"
    try:
        resp = httpx.get(url, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        warn(f"Compatibility check skipped: failed to reach {url} ({exc})")
        return None

    if not isinstance(data, dict):
        warn("Compatibility check skipped: invalid /version response.")
        return None

    supported_range = str(data.get("supported_cli_range") or "").strip()
    api_protocol = data.get("api_protocol")
    api_version = str(data.get("api_version") or data.get("version") or "").strip()
    current_version = cli_version()
    current_protocol = cli_protocol()

    incompatible = False
    if supported_range and not is_version_in_range(current_version, supported_range):
        incompatible = True
        err(
            f"Incompatible CLI version: requires {supported_range}, current {current_version}."
        )
    if api_protocol is not None and int(api_protocol) != int(current_protocol):
        incompatible = True
        err(
            f"Incompatible CLI protocol: requires {api_protocol}, current {current_protocol}."
        )
    if incompatible and not warn_only:
        err(f"Hub API version {api_version} expects a compatible CLI. Update and retry.")
        raise SystemExit(1)

    _CHECK_CACHE[base_url] = data
    return data
