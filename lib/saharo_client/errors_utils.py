from __future__ import annotations

import json


def parse_api_error_detail(details: str | None) -> dict | None:
    if not details:
        return None
    try:
        return json.loads(details)
    except Exception:
        return None
