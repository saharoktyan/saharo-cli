from __future__ import annotations

import logging


def setup_logging(verbose: bool) -> None:
    # базовый уровень
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    # подавляем шум httpx по умолчанию
    logging.getLogger("httpx").setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.DEBUG if verbose else logging.WARNING)
