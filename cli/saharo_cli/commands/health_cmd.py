from __future__ import annotations

import platform as platform_mod
from datetime import datetime, timezone

import httpx
import typer

from ..compat import cli_protocol, cli_version
from ..config import load_config, resolve_license_api_url
from ..console import err, info, ok, print_json, warn
from ..registry_store import load_registry
from ..semver import is_version_in_range

app = typer.Typer(help="Diagnostics for hub compatibility and updates.")


def _platform_id() -> str:
    return f"{platform_mod.system().lower()}-{platform_mod.machine().lower()}"


def _emit(level: str, msg: str, *, json_mode: bool) -> None:
    if json_mode:
        return
    if level == "ok":
        ok(msg)
    elif level == "warn":
        warn(msg)
    elif level == "err":
        err(msg)
    else:
        info(msg)


@app.command("health")
def health(
        json_output: bool = typer.Option(False, "--json", help="Output JSON only."),
        verbose: bool = typer.Option(False, "--verbose", help="Show extra details."),
) -> None:
    cfg = load_config()
    base_url = (cfg.base_url or "").strip()
    current_version = cli_version()
    current_protocol = cli_protocol()

    result: dict[str, object] = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "hub": {
            "ok": None,
            "base_url": base_url or None,
            "cli_version": current_version,
            "cli_protocol": current_protocol,
            "errors": [],
        },
        "license": {
            "ok": None,
            "license_api_url": None,
            "entitlements": None,
            "updates": None,
            "errors": [],
        },
    }

    hub = result["hub"]
    hub_errors: list[str] = hub["errors"]  # type: ignore[assignment]

    if not base_url:
        hub_errors.append("base_url_not_configured")
        _emit("warn", "Base URL is not configured. Run `saharo settings set base_url ...` first.",
              json_mode=json_output)
    else:
        endpoint = f"{base_url.rstrip('/')}/version"
        try:
            resp = httpx.get(endpoint, timeout=5.0)
            if resp.status_code != 200:
                hub_errors.append(f"hub_version_http_{resp.status_code}")
                _emit("warn", f"Hub /version check failed ({resp.status_code}).", json_mode=json_output)
            else:
                data = resp.json()
                api_protocol = data.get("api_protocol")
                supported_range = str(data.get("supported_cli_range") or "").strip()
                api_version = str(data.get("api_version") or data.get("version") or "").strip()
                hub.update(
                    {
                        "api_version": api_version or None,
                        "api_protocol": api_protocol,
                        "supported_cli_range": supported_range or None,
                    }
                )
                incompatible = False
                if api_protocol is not None and int(api_protocol) != int(current_protocol):
                    hub_errors.append("cli_protocol_incompatible")
                    incompatible = True
                    _emit(
                        "err",
                        f"Incompatible CLI protocol: requires {api_protocol}, current {current_protocol}.",
                        json_mode=json_output,
                    )
                if supported_range and not is_version_in_range(current_version, supported_range):
                    hub_errors.append("cli_version_incompatible")
                    incompatible = True
                    _emit(
                        "err",
                        f"Incompatible CLI version: requires {supported_range}, current {current_version}.",
                        json_mode=json_output,
                    )
                if not incompatible:
                    _emit("ok", "Hub API compatibility check passed.", json_mode=json_output)
                if verbose and not json_output:
                    _emit(
                        "info",
                        f"Hub /version: api_version={api_version} api_protocol={api_protocol} "
                        f"supported_cli_range={supported_range}",
                        json_mode=json_output,
                    )
                if verbose:
                    hub["endpoint"] = endpoint
                hub["ok"] = not incompatible
        except Exception as exc:
            hub_errors.append("hub_version_request_failed")
            _emit("warn", f"Hub /version check failed: {exc}", json_mode=json_output)

    registry = load_registry()
    license_key = registry.license_key if registry else None
    lic_url = resolve_license_api_url(cfg)
    license_result = result["license"]
    license_errors: list[str] = license_result["errors"]  # type: ignore[assignment]
    license_result["license_api_url"] = lic_url or None

    if not license_key:
        license_errors.append("license_key_missing")
        _emit("warn", "License key not found in registry store; skipping license checks.", json_mode=json_output)
    elif lic_url:
        entitlements_endpoint = f"{lic_url.rstrip('/')}/v1/entitlements"
        try:
            resp = httpx.get(
                entitlements_endpoint,
                headers={"X-License-Key": license_key},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                allowed_major = data.get("allowed_major")
                resolved = data.get("resolved_versions") or {}
                entitlements = {
                    "allowed_major": allowed_major,
                    "resolved_versions": resolved,
                    "strategy": data.get("strategy"),
                    "source": data.get("source"),
                }
                license_result["entitlements"] = entitlements
                _emit(
                    "ok",
                    f"License OK. Allowed major: {allowed_major}; resolved: {resolved}.",
                    json_mode=json_output,
                )
            else:
                license_errors.append(f"entitlements_http_{resp.status_code}")
                _emit("warn", f"License API error ({resp.status_code}).", json_mode=json_output)
        except Exception as exc:
            license_errors.append("entitlements_request_failed")
            _emit("warn", f"License API check failed: {exc}", json_mode=json_output)

        updates_endpoint = f"{lic_url.rstrip('/')}/v1/updates/cli"
        try:
            resp = httpx.get(
                updates_endpoint,
                params={"current": current_version, "platform": _platform_id()},
                headers={"X-License-Key": license_key},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                updates = {
                    "update_available": data.get("update_available"),
                    "current": data.get("current"),
                    "latest": data.get("latest"),
                }
                license_result["updates"] = updates
                if data.get("update_available"):
                    _emit(
                        "warn",
                        f"CLI update available: {data.get('latest')} (current {data.get('current')}).",
                        json_mode=json_output,
                    )
                else:
                    _emit("ok", "CLI is up to date.", json_mode=json_output)
            else:
                license_errors.append(f"updates_http_{resp.status_code}")
                _emit("info", f"Update check skipped ({resp.status_code}).", json_mode=json_output)
        except Exception as exc:
            license_errors.append("updates_request_failed")
            _emit("warn", f"Update check failed: {exc}", json_mode=json_output)

        if verbose:
            license_result["endpoints"] = {
                "entitlements": entitlements_endpoint,
                "updates": updates_endpoint,
            }

        license_result["ok"] = not license_errors

    if hub.get("ok") is None:
        hub["ok"] = False if hub_errors else None
    if license_result.get("ok") is None:
        license_result["ok"] = False if license_errors else None

    if json_output:
        print_json(result)
