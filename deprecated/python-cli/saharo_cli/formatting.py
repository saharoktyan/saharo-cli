from __future__ import annotations

from datetime import datetime, timezone


def format_age(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m{secs:02d}s"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h{minutes:02d}m"


def format_list_timestamp(value: datetime | str | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value)
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    ms = dt.microsecond // 1000
    if ms:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
