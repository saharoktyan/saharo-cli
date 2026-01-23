import re

_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:([\\/]|$)")


def looks_like_windows_path(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    return bool(_WINDOWS_PATH_RE.match(value)) or ("\\" in value)
