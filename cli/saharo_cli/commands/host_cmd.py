from __future__ import annotations

import typer

from .host_bootstrap import host_bootstrap
from .host_https import app as https_app

app = typer.Typer(help="Host bootstrap commands.")

app.command("bootstrap")(host_bootstrap)
app.add_typer(https_app, name="https")
