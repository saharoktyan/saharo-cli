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
    console.info("Portal: https://portal.saharoktyan.ru")


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

    username = data.get("username") or data.get("email") or "unknown"
    console.ok(f"Portal session: authenticated as {username}.")
    if data.get("is_2fa_enabled"):
        console.info("2FA: enabled")


@app.command("telemetry-status", help="Show current portal telemetry status.")
def telemetry_status(
        lic_url: str | None = typer.Option(None, "--lic-url", help="License API base URL used for portal auth."),
) -> None:
    cfg = load_config()
    token = (cfg.portal_session_token or "").strip()
    if not token:
        console.info("Portal telemetry: not authenticated.")
        console.info("Run: saharo portal auth")
        return

    lic_url_value = (lic_url or resolve_license_api_url(cfg)).strip().rstrip("/")
    if not lic_url_value:
        console.err("License API URL is not configured.")
        raise typer.Exit(code=2)

    with httpx.Client(base_url=lic_url_value, timeout=10.0) as client:
        client.headers["X-Session-Token"] = token
        resp = client.get("/v1/account/telemetry")
        if resp.status_code in (401, 403):
            console.err("Portal session is invalid or expired.")
            return
        if resp.status_code >= 400:
            console.err(f"Portal telemetry status failed: HTTP {resp.status_code}")
            raise typer.Exit(code=2)
        payload = resp.json() if resp.content else {}
        telemetry = payload.get("telemetry") if isinstance(payload, dict) else None
        enabled = telemetry.get("enabled") if isinstance(telemetry, dict) else None

    if enabled is True:
        console.ok("Telemetry status: enabled")
    elif enabled is False:
        console.ok("Telemetry status: disabled")
    else:
        console.info("Telemetry status: unknown")


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
