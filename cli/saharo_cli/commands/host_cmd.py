from __future__ import annotations

import httpx
import typer

from .host_bootstrap import host_bootstrap
from .host_https import app as https_app
from .. import console
from ..config import load_config, resolve_license_api_url

app = typer.Typer(help="Host bootstrap commands.")

app.command("bootstrap")(host_bootstrap)
app.add_typer(https_app, name="https")


@app.command("purge", help="Purge all host installations for a license (immediate detach).")
def host_purge(
    lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    token = (cfg.portal_session_token or "").strip()
    csrf = (cfg.portal_csrf_token or "").strip()
    if not token:
        console.err("Not authenticated with portal. Run: saharo portal auth")
        raise typer.Exit(code=2)
    if not csrf:
        console.err("Portal CSRF token missing. Re-authenticate: saharo portal auth")
        raise typer.Exit(code=2)

    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        if csrf:
            client.cookies.set("saharo_csrf", csrf)
            client.headers["X-CSRF-Token"] = csrf
        licenses_resp = client.get("/v1/account/licenses")
        if licenses_resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            raise typer.Exit(code=2)
        if licenses_resp.status_code >= 400:
            console.err(f"Failed to list licenses: HTTP {licenses_resp.status_code}")
            raise typer.Exit(code=2)
        licenses = licenses_resp.json() if licenses_resp.content else []

    if not isinstance(licenses, list) or not licenses:
        console.err("No licenses available for this account.")
        raise typer.Exit(code=2)

    choices = []
    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        lic_id = str(lic.get("id") or "").strip()
        last4 = str(lic.get("key_last4") or "----")
        status = str(lic.get("status") or "unknown")
        name = str(lic.get("notes") or "-")
        if lic_id:
            choices.append((f"****{last4} | {status} | {name}", lic_id))

    if not choices:
        console.err("No valid licenses found.")
        raise typer.Exit(code=2)

    from questionary import select
    selected = select(
        "Select license to purge:",
        choices=[c[0] for c in choices],
        use_shortcuts=False,
        pointer="▶",
    ).ask()
    if selected is None:
        console.err("Aborted by user.")
        raise typer.Exit(code=1)

    license_id = next((lid for title, lid in choices if title == selected), None)
    if not license_id:
        console.err("Invalid selection.")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        client.cookies.set("saharo_csrf", csrf)
        client.headers["X-CSRF-Token"] = csrf
        telemetry_resp = client.get("/v1/account/telemetry")
        installations = []
        if telemetry_resp.status_code < 400:
            payload = telemetry_resp.json() if telemetry_resp.content else {}
            installations = payload.get("installations") if isinstance(payload, dict) else []

    if installations:
        console.info("Installations to be deleted:")
        for item in installations:
            if not isinstance(item, dict):
                continue
            if str(item.get("license_id") or "") != license_id:
                continue
            inst_id = item.get("installation_id") or "unknown"
            host_name = item.get("host_name") or "-"
            status = item.get("status") or "unknown"
            console.info(f"  - {inst_id} | {status} | {host_name}")

    console.warn("This will delete ALL host installations for the selected license.")
    confirm = typer.prompt("Type DELETE to confirm")
    if confirm != "DELETE":
        console.err("Confirmation failed. Aborted.")
        raise typer.Exit(code=1)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        if csrf:
            client.cookies.set("saharo_csrf", csrf)
            client.headers["X-CSRF-Token"] = csrf
        resp = client.post(f"/v1/licenses/{license_id}/hosts/purge")
        if resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            raise typer.Exit(code=2)
        if resp.status_code >= 400:
            console.err(f"Purge failed: HTTP {resp.status_code}")
            raise typer.Exit(code=2)

    console.ok("Purge completed. License detach is immediate.")
