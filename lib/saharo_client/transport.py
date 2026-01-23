from __future__ import annotations

import json
from typing import Any

import httpx

from .errors import ApiError, AuthError, NetworkError
from .config_types import ClientConfig


class Transport:
    def __init__(self, cfg: ClientConfig):
        self._cfg = cfg
        headers = {"User-Agent": "saharo-client/0.1.0"}
        if cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"
        if cfg.client_version:
            headers["X-CLI-Version"] = cfg.client_version
        if cfg.client_protocol is not None:
            headers["X-CLI-Protocol"] = str(cfg.client_protocol)

        self._client = httpx.Client(
            base_url=cfg.base_url.rstrip("/"),
            timeout=cfg.timeout_s,
            headers=headers,
            follow_redirects=True,
        )
    def close(self) -> None:
        self._client.close()

    def request(self, method: str, path: str, *, json_body: Any | None = None) -> Any:
        try:
            r = self._client.request(method, path, json=json_body)
        except httpx.RequestError as e:
            raise NetworkError(str(e)) from e

        # Try parse body as json for better errors / output
        data: Any = None
        text = None
        try:
            data = r.json()
        except Exception:
            text = r.text


        if r.status_code >= 400:
            msg = f"{method} {path} failed with {r.status_code}"
            details = None

            if isinstance(data, dict) and "detail" in data:
                details = json.dumps(data, ensure_ascii=False)
                msg = str(data.get("detail") or msg)
            elif text:
                details = text[:1000]

            if r.status_code in (401, 403):
                raise AuthError(r.status_code, msg, details)
            raise ApiError(r.status_code, msg, details)

        return data if data is not None else r.text
