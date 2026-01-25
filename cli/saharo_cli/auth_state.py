from __future__ import annotations

from dataclasses import dataclass

from saharo_client import ApiError, AuthError, NetworkError

from .config import load_config, config_path
from .http import make_client


@dataclass
class AuthContext:
    state: str
    role: str | None = None


def resolve_auth_context() -> AuthContext:
    import os

    if not os.path.exists(config_path()):
        return AuthContext(state="no_base_url")
    cfg = load_config()
    base_url = (cfg.base_url or "").strip()
    if not base_url:
        return AuthContext(state="no_base_url")

    token = (cfg.auth.token or "").strip()
    if not token:
        return AuthContext(state="no_token")

    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        data = client._t.request("GET", "/me")
    except AuthError:
        return AuthContext(state="invalid_token")
    except (ApiError, NetworkError):
        return AuthContext(state="unreachable")
    finally:
        client.close()

    role = None
    if isinstance(data, dict):
        role = data.get("role")
    return AuthContext(state="authed", role=str(role) if role else None)
