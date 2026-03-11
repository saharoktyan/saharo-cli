from __future__ import annotations

import httpx
import os
import shlex
import subprocess
import typer

from saharo_client import HostError, purge_hosts, normalize_remote_install_dir

from .host_bootstrap import host_bootstrap
from .host_https import app as https_app
from .. import console
from ..config import load_config, resolve_license_api_url
from ..ssh import SSHSession, SshTarget, build_control_path, is_windows

app = typer.Typer(help="Host bootstrap commands.")

app.command("bootstrap")(host_bootstrap)
app.add_typer(https_app, name="https")


@app.command("vpn-lockdown", help="Restrict host API/web ports to localhost + VPN CIDR (local or SSH).")
def host_vpn_lockdown(
    vpn_cidr: str = typer.Option(..., "--vpn-cidr", help="VPN CIDR to allow (e.g. 10.8.0.0/24)."),
    install_dir: str = typer.Option("/opt/saharo", "--install-dir", help="Installation directory."),
    ssh_host: str | None = typer.Option(None, "--ssh-host", help="SSH target in user@host form."),
    ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port."),
    ssh_key: str | None = typer.Option(None, "--ssh-key", help="SSH private key path."),
    ssh_password: str | None = typer.Option(None, "--ssh-password", help="SSH password (insecure)."),
    ssh_sudo: bool = typer.Option(True, "--ssh-sudo/--no-ssh-sudo", help="Use sudo over SSH."),
) -> None:
    try:
        script_path = f"{normalize_remote_install_dir(install_dir)}/host/apply-vpn-lockdown.sh"
    except HostError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)
    if ssh_host:
        target = SshTarget(
            host=ssh_host,
            port=ssh_port,
            key_path=ssh_key,
            password=ssh_password,
            sudo=bool(ssh_sudo and (ssh_host.split("@", 1)[0] if "@" in ssh_host else "") != "root"),
            dry_run=False,
        )
        session = SSHSession(target=target, control_path=build_control_path(dry_run=False))
        try:
            session.start()
            cmd = f"sh {shlex.quote(script_path)} {shlex.quote(vpn_cidr)}"
            res = session.run_privileged(cmd) if target.sudo else session.run(cmd)
            if res.returncode != 0:
                console.err((res.stderr or "").strip() or "Failed to apply remote VPN lockdown.")
                raise typer.Exit(code=2)
            console.ok("Remote VPN lockdown applied.")
            return
        finally:
            session.close()

    if is_windows():
        console.err("Local VPN lockdown command is supported on Linux only.")
        raise typer.Exit(code=2)
    cmd = ["sh", script_path, vpn_cidr]
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        console.err((res.stderr or "").strip() or (res.stdout or "").strip() or "Failed to apply VPN lockdown.")
        raise typer.Exit(code=2)
    console.ok("VPN lockdown applied.")


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

    try:
        purge_hosts(
            lic_url=lic_url_value,
            license_id=license_id,
            session_token=token,
            csrf_token=csrf,
        )
    except HostError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)

    console.ok("Purge completed. License detach is immediate.")
