from __future__ import annotations

import os

from rich.console import Console
from rich.markup import escape

console = Console()


def print_json(data) -> None:
    console.print_json(data=data)


def info(msg: str) -> None:
    console.print(f"[bold cyan]•[/] {escape(msg)}")


def ok(msg: str) -> None:
    console.print(f"[bold green]OK[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold yellow]WARN[/] {msg}")


def err(msg: str) -> None:
    console.print(f"[bold red]ERR[/] {msg}")


def print(*args, **kwargs):
    """Proxy to underlying rich Console.print()."""
    console.print(*args, **kwargs)


def rule(*args, **kwargs):
    """Proxy to underlying rich Console.rule()."""
    console.rule(*args, **kwargs)


def clear() -> None:
    """Clear the terminal when running interactive flows."""
    if os.getenv("SAHARO_INTERACTIVE") == "1":
        try:
            console.file.write("\x1b]999;SAHARO_CLEAR\x07")
            console.file.flush()
        except Exception:
            pass
    console.clear()
