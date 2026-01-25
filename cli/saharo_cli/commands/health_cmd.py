from __future__ import annotations

from datetime import datetime, timezone

import typer

from ..compat import cli_protocol, cli_version
from ..config import load_config
from ..console import err, info, ok, print_json, warn
from ..semver import is_version_in_range

app = typer.Typer(help="Diagnostics for hub compatibility and updates.")


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

    if hub.get("ok") is None:
        hub["ok"] = False if hub_errors else None

    if json_output:
        print_json(result)
