from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import tomllib
import tomli_w

from .config import config_path


REGISTRY_FILENAME = "registry.toml"


@dataclass
class RegistryCredentials:
    url: str
    username: str
    password: str | None
    issued_at: str | None
    license_key: str | None = None


def registry_path() -> Path:
    return Path(config_path()).expanduser().parent / REGISTRY_FILENAME


def load_registry() -> RegistryCredentials | None:
    path = registry_path()
    if not path.exists():
        return None
    with path.open("rb") as f:
        data = tomllib.load(f)
    registry = data.get("registry") if isinstance(data, dict) else None
    if not isinstance(registry, dict):
        return None
    url = str(registry.get("url") or "").strip()
    username = str(registry.get("username") or "").strip()
    password = registry.get("password")
    if not url or not username:
        return None
    issued_at = data.get("issued_at")
    if issued_at is not None and not isinstance(issued_at, str):
        issued_at = None
    return RegistryCredentials(
        url=url,
        username=username,
        password=str(password) if isinstance(password, str) else None,
        issued_at=issued_at,
    )


def save_registry(
    url: str,
    username: str,
    password: str | None,
    issued_at: str | None = None,
) -> Path:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    registry_data: dict[str, str] = {"url": url, "username": username}
    if password is not None:
        registry_data["password"] = password
    payload: dict[str, object] = {"registry": registry_data}
    if issued_at is None:
        issued_at = datetime.now(timezone.utc).isoformat()
    payload["issued_at"] = issued_at
    path.write_bytes(tomli_w.dumps(payload).encode("utf-8"))
    import os
    os.chmod(path, 0o600)
    return path


def delete_registry() -> None:
    path = registry_path()
    if path.exists():
        path.unlink()
