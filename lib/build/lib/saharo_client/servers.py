from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .resolve import resolve_server_id_for_servers


@dataclass(frozen=True)
class ServerListPage:
    items: list[dict[str, Any]]
    total: int | None
    page: int
    page_size: int
    pages: int | None
    raw: dict[str, Any]


def list_servers_page(
    client,
    *,
    q: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> ServerListPage:
    if page < 1:
        raise ValueError("--page must be >= 1.")
    if page_size < 1:
        raise ValueError("--page-size must be >= 1.")
    offset = (page - 1) * page_size

    data = client.admin_servers_list(q=q, limit=page_size, offset=offset)
    items = data.get("items") if isinstance(data, dict) else []
    total = data.get("total") if isinstance(data, dict) else None
    pages = None
    if isinstance(total, int) and total >= 0:
        pages = max(1, (total + page_size - 1) // page_size)
    raw = data if isinstance(data, dict) else {"items": items, "total": total}
    return ServerListPage(
        items=items or [],
        total=total if isinstance(total, int) else None,
        page=page,
        page_size=page_size,
        pages=pages,
        raw=raw,
    )


def list_all_servers(client, *, page_size: int = 200) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = 1
    while True:
        page_data = list_servers_page(client, page=page, page_size=page_size)
        if page_data.items:
            items.extend(page_data.items)
        if not page_data.items:
            break
        if page_data.pages is not None and page >= page_data.pages:
            break
        page += 1
    return items


def get_server(client, server_ref: str | int) -> dict[str, Any]:
    value = str(server_ref or "").strip()
    if not value:
        raise ValueError("Server ID or exact name is required.")
    server_id = resolve_server_id_for_servers(client, value)
    data = client.admin_server_get(server_id)
    return data if isinstance(data, dict) else {"raw": data}


def get_server_with_protocols(client, server_ref: str | int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value = str(server_ref or "").strip()
    if not value:
        raise ValueError("Server ID or exact name is required.")
    server_id = resolve_server_id_for_servers(client, value)
    data = client.admin_server_get(server_id)
    protocols = client.admin_server_protocols_list(server_id)
    server = data if isinstance(data, dict) else {"raw": data}
    return server, protocols or []


def get_server_status(client, server_ref: str | int) -> dict[str, Any]:
    value = str(server_ref or "").strip()
    if not value:
        raise ValueError("Server ID or exact name is required.")
    server_id = resolve_server_id_for_servers(client, value)
    data = client.admin_server_status(server_id)
    return data if isinstance(data, dict) else {"raw": data}


def resolve_server_id(client, server_ref: str | int) -> int:
    value = str(server_ref or "").strip()
    if not value:
        raise ValueError("Server ID or exact name is required.")
    return resolve_server_id_for_servers(client, value)


def detach_server_runtime(client, server_ref: str | int) -> tuple[int, dict[str, Any]]:
    server_id = resolve_server_id(client, server_ref)
    data = client.admin_server_detach_agent(server_id)
    return server_id, data if isinstance(data, dict) else {"raw": data}


def delete_server(
    client,
    server_ref: str | int,
    *,
    force: bool = False,
) -> tuple[int, dict[str, Any]]:
    server_id = resolve_server_id(client, server_ref)
    data = client.admin_server_delete(server_id, force=force)
    return server_id, data if isinstance(data, dict) else {"raw": data}


def fetch_server_logs(
    client,
    server_ref: str | int,
    *,
    lines: int = 50,
) -> dict[str, Any]:
    server_id = resolve_server_id(client, server_ref)
    data = client.admin_server_logs(server_id, lines=lines)
    return data if isinstance(data, dict) else {"raw": data}
