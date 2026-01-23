from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    token: str | None = None
    timeout_s: float = 15.0
    client_version: str | None = None
    client_protocol: int | None = None
