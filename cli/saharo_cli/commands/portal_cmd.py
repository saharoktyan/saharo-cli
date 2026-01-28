from __future__ import annotations

import httpx
import typer

from .. import console
from ..config import load_config, resolve_license_api_url, save_config
from ..interactive import confirm_choice, select_toggle

app = typer.Typer(help="Manage portal access and telemetry.")


@app.command("telemetry", help="Enable or disable portal telemetry for your account.")
def telemetry(
        enabled: bool | None = typer.Option(None, "--enable/--disable", help="Enable or disable portal telemetry."),
        lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    token = (cfg.portal_session_token or "").strip()
    csrf = (cfg.portal_csrf_token or "").strip()
    if not token:
        console.err("Not authenticated with portal. Run: saharo portal auth")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        status_resp = client.get("/v1/account/telemetry")
        if status_resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            raise typer.Exit(code=2)
        if status_resp.status_code >= 400:
            console.err(f"Portal telemetry status failed: HTTP {status_resp.status_code}")
            raise typer.Exit(code=2)
        status_data = status_resp.json() if status_resp.content else {}
        telemetry = status_data.get("telemetry") if isinstance(status_data, dict) else None
        current_state = telemetry.get("enabled") if isinstance(telemetry, dict) else None
    if enabled is None:
        enabled = select_toggle("Telemetry:", default_enabled=current_state)

    if not csrf:
        console.err("Portal CSRF token missing. Re-authenticate: saharo portal auth")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        client.cookies.set("saharo_csrf", csrf)
        client.headers["X-CSRF-Token"] = csrf
        resp = client.post("/v1/account/telemetry", json={"enabled": bool(enabled)})
        if resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            raise typer.Exit(code=2)
        if resp.status_code >= 400:
            console.err(f"Portal telemetry change failed: HTTP {resp.status_code}")
            raise typer.Exit(code=2)

    if enabled:
        console.ok("Telemetry enabled.")
    else:
        console.ok("Telemetry disabled.")


@app.command("auth", help="Authenticate with the Saharo portal (stores session token).")
def auth(
        lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    has_account = confirm_choice("Do you already have an account?", default=True)
    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        if has_account:
            _login_flow(client, cfg)
        else:
            _register_flow(client, cfg)


def _extract_error_message(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return ""
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            message = err.get("message")
            if isinstance(message, str):
                return message
    return ""


@app.command("status", help="Show current portal session status.")
def status(
        lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    token = (cfg.portal_session_token or "").strip()
    if not token:
        console.info("Portal status: not authenticated.")
        console.info("Run: saharo portal auth")
        return

    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        resp = client.get("/v1/auth/me")
        if resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            return
        if resp.status_code >= 400:
            console.err(f"Portal status failed: HTTP {resp.status_code}")
            raise typer.Exit(code=2)
        data = resp.json() if resp.content else {}

        telemetry_payload = {}
        licenses_payload = []
        csrf = (cfg.portal_csrf_token or "").strip()
        if csrf:
            client.cookies.set("saharo_csrf", csrf)
            client.headers["X-CSRF-Token"] = csrf
            telemetry_resp = client.get("/v1/account/telemetry")
            if telemetry_resp.status_code < 400:
                telemetry_payload = telemetry_resp.json() if telemetry_resp.content else {}
            licenses_resp = client.get("/v1/account/licenses")
            if licenses_resp.status_code < 400:
                licenses_payload = licenses_resp.json() if licenses_resp.content else []
        else:
            console.warn("CSRF missing: re-authenticate to see telemetry and licenses.")

    username = data.get("username") or "unknown"
    email = data.get("email") or "unknown"
    providers = data.get("linked_providers") or []
    if not isinstance(providers, list):
        providers = []
    github = "enabled" if "github" in providers else "disabled"
    google = "enabled" if "google" in providers else "disabled"
    two_fa = "enabled" if data.get("is_2fa_enabled") else "disabled"
    licenses_count = len(licenses_payload) if isinstance(licenses_payload, list) else 0

    console.print("• Profile info")
    console.print(f"  Username: {username}")
    console.print(f"  Email: {email}")
    console.print(f"  2FA: {two_fa}")
    github_label = f"[green]github[/]" if github == "enabled" else f"[red]github[/]"
    google_label = f"[green]google[/]" if google == "enabled" else f"[red]google[/]"
    console.print(f"  Social integrations: {github_label}, {google_label}")
    console.print("")
    console.print(f"• Provisioned licenses: {licenses_count}")
    if isinstance(licenses_payload, list) and licenses_payload:
        for lic in licenses_payload:
            if not isinstance(lic, dict):
                continue
            last4 = str(lic.get("key_last4") or "----")
            status = str(lic.get("status") or "unknown")
            name = str(lic.get("name") or lic.get("notes") or "-")
            console.print(f"  - ****{last4} | {status} | {name}")
    console.print("")

    telemetry = telemetry_payload.get("telemetry") if isinstance(telemetry_payload, dict) else None
    enabled = telemetry.get("enabled") if isinstance(telemetry, dict) else None
    if enabled is True:
        telemetry_status = "enabled"
    elif enabled is False:
        telemetry_status = "disabled"
    else:
        telemetry_status = "unknown"
    console.print(f"• Telemetry: {telemetry_status}")


@app.command("logout", help="Revoke local portal session token.")
def logout(
        lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    token = (cfg.portal_session_token or "").strip()
    if not token:
        console.info("Portal session: already logged out.")
        return

    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    csrf = (cfg.portal_csrf_token or "").strip()
    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        if csrf:
            client.cookies.set("saharo_csrf", csrf)
            client.headers["X-CSRF-Token"] = csrf
        resp = client.post("/v1/auth/logout")
        if resp.status_code not in (200, 204, 401, 403) and resp.status_code >= 400:
            console.err(f"Portal logout failed: HTTP {resp.status_code}")
            raise typer.Exit(code=2)

    cfg.portal_session_token = ""
    cfg.portal_csrf_token = ""
    save_config(cfg)
    console.ok("Portal session cleared.")


def _login_flow(client: httpx.Client, cfg) -> None:
    login = typer.prompt("Email or username").strip()
    password = typer.prompt("Password (input hidden)", hide_input=True)
    if not login or not password:
        console.err("Email/username and password are required.")
        raise typer.Exit(code=2)

    resp = client.post("/v1/auth/login", json={"login": login, "password": password})
    if resp.status_code == 401:
        console.err("Username/email or password does not match.")
        raise typer.Exit(code=2)
    if resp.status_code == 403:
        message = _extract_error_message(resp)
        console.err(message or "Email not verified.")
        raise typer.Exit(code=2)
    if resp.status_code >= 400:
        console.err(f"Portal auth failed: HTTP {resp.status_code}")
        raise typer.Exit(code=2)

    token, csrf = _extract_session(resp)
    _verify_2fa_if_needed(client, token, csrf)
    _save_portal_session(cfg, token, csrf)


def _register_flow(client: httpx.Client, cfg) -> None:
    email = typer.prompt("Email").strip()
    username = typer.prompt("Username").strip()
    password = typer.prompt("Password (input hidden)", hide_input=True)
    password_confirm = typer.prompt("Confirm password (input hidden)", hide_input=True)
    if password != password_confirm:
        console.err("Passwords do not match.")
        raise typer.Exit(code=2)

    resp = client.post(
        "/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "password_confirm": password_confirm,
        },
    )
    if resp.status_code == 409:
        message = _extract_error_message(resp) or "Email or username already exists."
        console.err(message)
        raise typer.Exit(code=2)
    if resp.status_code >= 400:
        message = _extract_error_message(resp)
        console.err(message or f"Registration failed: HTTP {resp.status_code}")
        raise typer.Exit(code=2)

    console.ok("Verification code sent to your email.")
    otp = typer.prompt("Email confirmation code")
    verify = client.post("/v1/auth/verify-email", json={"login": email, "otp": otp})
    if verify.status_code == 401:
        console.err("Invalid or expired confirmation code.")
        raise typer.Exit(code=2)
    if verify.status_code >= 400:
        message = _extract_error_message(verify)
        console.err(message or "Email verification failed.")
        raise typer.Exit(code=2)

    token, csrf = _extract_session(verify)
    _save_portal_session(cfg, token, csrf)
    console.ok("Account verified and session saved.")


def _extract_session(resp: httpx.Response) -> tuple[str, str]:
    data = resp.json() if resp.content else {}
    token = str(data.get("token") or "").strip()
    if not token:
        console.err("Portal auth failed: missing session token.")
        raise typer.Exit(code=2)
    csrf = resp.cookies.get("saharo_csrf") or ""
    return token, csrf


def _save_portal_session(cfg, token: str, csrf: str) -> None:
    cfg.portal_session_token = token
    cfg.portal_csrf_token = csrf or ""
    save_config(cfg)
    console.ok("Portal session saved.")


def _verify_2fa_if_needed(client: httpx.Client, token: str, csrf: str) -> None:
    client.headers["X-Session-Token"] = token
    if csrf:
        client.cookies.set("saharo_csrf", csrf)

    me_resp = client.get("/v1/auth/me")
    if me_resp.status_code >= 400:
        console.err("Portal auth failed: unable to validate session.")
        raise typer.Exit(code=2)
    me = me_resp.json() if me_resp.content else {}
    if not bool(me.get("is_2fa_enabled")):
        return

    if not csrf:
        console.err("Portal auth failed: CSRF token missing.")
        raise typer.Exit(code=2)
    headers = {"X-CSRF-Token": csrf}
    start = client.post("/v1/auth/admin/2fa/start", headers=headers)
    if start.status_code == 403:
        console.err("Admin access required for 2FA verification.")
        raise typer.Exit(code=2)
    if start.status_code >= 400:
        console.err("Failed to send 2FA code to email.")
        raise typer.Exit(code=2)
    otp = typer.prompt("Email confirmation code")
    verify = client.post("/v1/auth/admin/2fa/verify", headers=headers, json={"otp": otp})
    if verify.status_code == 401:
        console.err("Invalid or expired confirmation code.")
        raise typer.Exit(code=2)
    if verify.status_code >= 400:
        console.err("2FA verification failed.")
        raise typer.Exit(code=2)
