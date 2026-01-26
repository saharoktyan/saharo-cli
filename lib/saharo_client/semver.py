from __future__ import annotations

import re

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse_semver(text: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match((text or "").strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def is_version_in_range(version: str, range_expr: str) -> bool:
    v = parse_semver(version)
    if not v:
        return False
    expr = (range_expr or "").strip()
    if not expr:
        return True
    parts = [p.strip() for p in expr.split(",") if p.strip()]
    for part in parts:
        if part.startswith(">="):
            target = parse_semver(part[2:].strip())
            if not target or v < target:
                return False
        elif part.startswith("<="):
            target = parse_semver(part[2:].strip())
            if not target or v > target:
                return False
        elif part.startswith(">"):
            target = parse_semver(part[1:].strip())
            if not target or v <= target:
                return False
        elif part.startswith("<"):
            target = parse_semver(part[1:].strip())
            if not target or v >= target:
                return False
        elif part.startswith("=="):
            target = parse_semver(part[2:].strip())
            if not target or v != target:
                return False
        else:
            target = parse_semver(part)
            if not target or v != target:
                return False
    return True
