from __future__ import annotations

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
