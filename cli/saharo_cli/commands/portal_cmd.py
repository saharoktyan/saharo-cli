from __future__ import annotations

import typer
from saharo_client import ApiError

from .. import console
from ..config import load_config
from ..http import make_client

app = typer.Typer(help="Manage portal linking (admin-only).")


@app.command("link", help="Enable or disable portal linking (admin-only).")
def link(
        enabled: bool = typer.Option(True, "--enable/--disable", help="Enable or disable portal linking."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override hub API base URL."),
) -> None:
    cfg = load_config()
    base_url_value = (base_url or cfg.base_url or "").strip()
    if not base_url_value:
        console.err("No host URL configured. Run: saharo auth login --base-url https://<your-host>")
        raise typer.Exit(code=2)
    if not (cfg.auth.token or "").strip():
        console.err("Not authenticated. Run: saharo auth login")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        me = client.me()
        if not (isinstance(me, dict) and me.get("role") == "admin"):
            console.err("This is an admin-only command.")
            raise typer.Exit(code=2)
        data = client.portal_link(enabled=enabled)
    except ApiError as exc:
        if exc.status_code in (401, 403):
            console.err("Not authenticated.")
            console.info("Run: saharo auth login --base-url https://<your-host>")
        else:
            detail = exc.details or exc.status_code
            console.err(f"Portal link failed: HTTP {detail}")
        raise typer.Exit(code=2)
    finally:
        client.close()

    if not isinstance(data, dict) or not data.get("ok"):
        console.err("Portal link failed: invalid response from host API.")
        raise typer.Exit(code=2)

    if enabled:
        console.ok("Portal linking enabled.")
    else:
        console.ok("Portal linking disabled.")
        console.info("Portal is not linked.")
        console.info("Telemetry is disabled. Enable it via: saharo portal link")
    console.info("Portal: https://portal.saharoktyan.ru")
