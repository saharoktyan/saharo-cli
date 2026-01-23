from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ENV_VERSION_KEYS = {
    "host": "SAHARO_BOOTSTRAP_VERSION_HOST",
    "agent": "SAHARO_BOOTSTRAP_VERSION_AGENT",
    "cli": "SAHARO_BOOTSTRAP_VERSION_CLI",
}

IMAGE_COMPONENTS = {"host": "api", "agent": "agent"}


class LicenseEntitlementsError(RuntimeError):
    pass


@dataclass(frozen=True)
class LicenseEntitlements:
    allowed_major: int | None
    resolved_versions: dict[str, str]
    from_fallback: bool = False

    @property
    def host(self) -> str:
        return self.resolved_versions["host"]

    @property
    def agent(self) -> str:
        return self.resolved_versions["agent"]

    @property
    def cli(self) -> str:
        return self.resolved_versions["cli"]


def resolve_entitlements(
    license_api_base_url: str,
    license_key: str,
    *,
    timeout_s: float = 10.0,
) -> LicenseEntitlements:
    base = (license_api_base_url or "").strip().rstrip("/")
    if not base:
        raise LicenseEntitlementsError("License API base URL is not configured.")
    if not (license_key or "").strip():
        raise LicenseEntitlementsError("License key is required to resolve entitlements.")
    url = f"{base}/v1/entitlements"
    headers = {"X-License-Key": license_key}
    try:
        response = httpx.get(url, headers=headers, timeout=timeout_s)
    except httpx.RequestError as exc:
        return _resolve_from_env_or_raise(url, exc)

    if response.status_code >= 400:
        detail = _extract_detail(url, response)
        detail_msg = f" detail={detail!r}" if detail else ""
        raise LicenseEntitlementsError(
            "License entitlements request failed "
            f"(status={response.status_code}, url={url}){detail_msg}"
        )

    payload = _parse_json_or_raise(url, response)
    if not isinstance(payload, dict):
        raise LicenseEntitlementsError(
            f"License entitlements response is not an object: url={url}"
        )

    allowed_major = payload.get("allowed_major")
    if not isinstance(allowed_major, int):
        allowed_major = None

    resolved = payload.get("resolved_versions")
    if not isinstance(resolved, dict):
        raise LicenseEntitlementsError(
            f"License entitlements response missing resolved_versions: url={url}"
        )

    versions = _extract_required_versions(resolved, url)
    api_version = resolved.get("api")
    if isinstance(api_version, str) and _SEMVER_RE.match(api_version.strip()):
        versions["api"] = api_version.strip()

    return LicenseEntitlements(
        allowed_major=allowed_major,
        resolved_versions=versions,
        from_fallback=False,
    )


def _extract_required_versions(resolved: dict[str, object], url: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for key in ("host", "agent", "cli"):
        raw = resolved.get(key)
        value = raw.strip() if isinstance(raw, str) else ""
        if not value or not _SEMVER_RE.match(value):
            raise LicenseEntitlementsError(
                f"License entitlements missing resolved_versions.{key}: url={url}, value={raw!r}"
            )
        versions[key] = value
    return versions


def _parse_json_or_raise(url: str, response: httpx.Response) -> object:
    try:
        return response.json()
    except ValueError:
        content_type = response.headers.get("content-type", "(missing)")
        preview = response.content[:160]
        body_text = preview.decode("utf-8", errors="replace")
        raise LicenseEntitlementsError(
            "License entitlements response is not JSON "
            f"(status={response.status_code}, content-type={content_type}, url={url}, body={body_text!r})"
        )


def _extract_detail(url: str, response: httpx.Response) -> object | None:
    data = _parse_json_or_raise(url, response)
    if isinstance(data, dict):
        return data.get("detail")
    return None


def _resolve_from_env_or_raise(url: str, exc: Exception) -> LicenseEntitlements:
    versions: dict[str, str] = {}
    missing: list[str] = []
    for key, env_var in _ENV_VERSION_KEYS.items():
        value = (os.getenv(env_var) or "").strip()
        if not value:
            missing.append(env_var)
            continue
        if not _SEMVER_RE.match(value):
            raise LicenseEntitlementsError(
                f"Invalid {env_var}={value!r} (expected semver like 1.2.3). "
                f"License API unreachable at {url}: {exc}"
            )
        versions[key] = value
    if missing:
        raise LicenseEntitlementsError(
            f"License API unreachable at {url}: {exc}. "
            f"Set {', '.join(missing)} to proceed offline."
        )
    return LicenseEntitlements(
        allowed_major=None, resolved_versions=versions, from_fallback=True
    )
