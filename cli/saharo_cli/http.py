from __future__ import annotations

from saharo_client import SaharoClient
from saharo_client.config_types import ClientConfig

from .compat import cli_protocol, cli_version, ensure_hub_compatibility
from .config import AppConfig, apply_profile, normalize_base_url


def make_client(
    cfg: AppConfig,
    *,
    profile: str | None,
    base_url_override: str | None,
    check_compat: bool = True,
) -> SaharoClient:
    effective_cfg = apply_profile(cfg, profile)
    base_url = normalize_base_url(base_url_override or effective_cfg.base_url, warn=True)
    token = effective_cfg.auth.token or None

    if check_compat:
        ensure_hub_compatibility(base_url, warn_only=False)
    return SaharoClient(
        ClientConfig(
            base_url=base_url,
            token=token,
            client_version=cli_version(),
            client_protocol=cli_protocol(),
        )
    )
