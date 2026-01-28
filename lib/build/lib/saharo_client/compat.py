from __future__ import annotations

from typing import Any

from .semver import is_version_in_range


def evaluate_compatibility(
        data: dict[str, Any],
        *,
        current_version: str,
        current_protocol: int,
) -> dict[str, Any]:
    supported_range = str(data.get("supported_cli_range") or "").strip()
    api_protocol = data.get("api_protocol")
    api_version = str(data.get("api_version") or data.get("version") or "").strip()

    reasons: list[str] = []
    if supported_range and not is_version_in_range(current_version, supported_range):
        reasons.append("cli_version_incompatible")
    if api_protocol is not None and int(api_protocol) != int(current_protocol):
        reasons.append("cli_protocol_incompatible")

    return {
        "supported_range": supported_range or None,
        "api_protocol": api_protocol,
        "api_version": api_version or None,
        "reasons": reasons,
    }
