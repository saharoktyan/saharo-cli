from __future__ import annotations

import os

import typer

from .. import console
from ..config import load_config, save_config, default_config, config_path, normalize_base_url

app = typer.Typer(help="Manage local CLI settings (~/.config/saharo/config.toml).")


@app.command("init")
def init_settings(
        force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
        base_url: str = typer.Option(
            ...,
            "--base-url",
            prompt="API base URL",
            help="API base URL like http://127.0.0.1:8010",
        ),
):
    path = config_path()
    if os.path.exists(path) and not force:
        console.info(f"Config already exists: {path}")
        console.info("Use --force to overwrite.")
        return

    cfg = default_config()
    cfg.base_url = normalize_base_url(base_url, warn=True)
    if not cfg.base_url:
        console.err("Base URL cannot be empty.")
        raise typer.Exit(code=2)
    saved = save_config(cfg)
    console.ok(f"Config written: {saved}")


@app.command("show")
def show_settings():
    cfg = load_config()
    token_state = "(set)" if (cfg.auth.token or "").strip() else "(empty)"
    console.console.print(
        f"base_url={cfg.base_url} license_api_url={cfg.license_api_url} token={token_state} token_type={cfg.auth.token_type}"
    )


@app.command("get")
def get_setting(
        key: str = typer.Argument(..., help="Setting key (base_url, license_api_url)."),
):
    cfg = load_config()
    k = key.strip().lower()
    if k == "base_url":
        console.console.print(cfg.base_url)
        return
    if k == "license_api_url":
        console.console.print(cfg.license_api_url)
        return
    console.err(f"Unknown setting: {key}")
    raise typer.Exit(code=2)


@app.command("set")
def set_setting(
        base_url: str | None = typer.Option(None, "--base-url", help="Set API base URL."),
        license_api_url: str | None = typer.Option(None, "--license-api-url", help="Set license API URL."),
):
    cfg = load_config()
    if base_url is not None:
        cfg.base_url = normalize_base_url(base_url, warn=True)
    if license_api_url is not None:
        cfg.license_api_url = license_api_url.strip().rstrip("/")
    saved = save_config(cfg)
    console.ok(f"Settings updated: {saved}")
