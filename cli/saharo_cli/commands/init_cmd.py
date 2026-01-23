from __future__ import annotations

import typer

from .. import console
from ..config import load_config, save_config, default_config, config_path, normalize_base_url


def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
    base_url: str = typer.Option(
        ...,
        "--base-url",
        prompt="API base URL",
        help="Example: https://api.example.com or http://127.0.0.1:8010",
    ),
):
    """
    Initialize local saharo CLI config and set API base URL.
    """
    import os

    path = config_path()

    if os.path.exists(path) and not force:
        cfg = load_config()
    else:
        cfg = default_config()

    bu = normalize_base_url(base_url, warn=True)
    if not bu:
        console.err("Base URL cannot be empty.")
        raise typer.Exit(code=2)

    cfg.base_url = bu

    saved = save_config(cfg)
    console.ok(f"Config written: {saved}")
    console.info("Next: `saharo auth register <token>` or `saharo auth login`.")


def init_deprecated(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
    base_url: str = typer.Option(
        ...,
        "--base-url",
        prompt="API base URL",
        help="Example: https://api.example.com or http://127.0.0.1:8010",
    ),
):
    """
    Deprecated: use `saharo settings init`.
    """
    console.warn("Deprecated: use `saharo settings init` instead.")
    init(force=force, base_url=base_url)
