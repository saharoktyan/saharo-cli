from __future__ import annotations

import sys

from .interactive_menu import run_interactive_menu
from .main import app


def main() -> None:
    if len(sys.argv) == 1:
        tokens = run_interactive_menu(app)
        if not tokens:
            raise SystemExit(0)
        sys.argv = [sys.argv[0], *tokens]
    app()


if __name__ == "__main__":
    main()
