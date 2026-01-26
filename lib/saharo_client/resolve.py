from __future__ import annotations

from dataclasses import dataclass

from .errors import ApiError


@dataclass
class ResolveError(ValueError):
    message: str
    info_label: str | None = None
    info_value: str | None = None
    candidates: list[list[str]] | None = None
    candidate_headers: list[str] | None = None

    def __str__(self) -> str:
        return self.message


def resolve_user_id_for_users(client, user_id: int | None, username: str | None) -> int:
    if user_id is not None:
        return int(user_id)
    username = (username or "").strip()
    if not username:
        raise ResolveError("User id or --u username is required.")
    data = client.admin_users_list(q=username, limit=10, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [u for u in items or [] if str(u.get("username") or "") == username]
    if not matches:
        raise ResolveError(f"User not found for username '{username}'.")
    if len(matches) > 1:
        ids = ", ".join(str(u.get("id")) for u in matches)
        raise ResolveError(f"Multiple users matched '{username}': {ids}")
    return int(matches[0]["id"])


def resolve_protocol_for_grants(client, protocol: str) -> tuple[int, str | None]:
    protocol = (protocol or "").strip()
    if not protocol:
        raise ResolveError("Protocol is required.")
    data = client.admin_protocols_list()
    items = data.get("items") if isinstance(data, dict) else []
    if protocol.isdigit():
        protocol_id = int(protocol)
        match = next((p for p in items or [] if int(p.get("id", -1)) == protocol_id), None)
        return protocol_id, match.get("code") if match else None
    matches = [
        p
        for p in items or []
        if str(p.get("code", "")).lower() == protocol.lower()
    ]
    if not matches:
        choices = ", ".join(sorted({str(p.get("code")) for p in items or [] if p.get("code")}))
        raise ResolveError(
            f"Protocol '{protocol}' not found.",
            info_label="Available",
            info_value=choices or None,
        )
    if len(matches) > 1:
        rows = [
            [str(p.get("id", "-")), str(p.get("code", "-")), str(p.get("title", "-"))]
            for p in matches
        ]
        raise ResolveError(
            f"Protocol '{protocol}' is ambiguous. Matches:",
            candidates=rows,
            candidate_headers=["id", "code", "title"],
        )
    return int(matches[0]["id"]), matches[0].get("code")


def resolve_user_id_for_grants(client, user: str | None, user_id: int | None) -> int:
    if user_id is not None:
        return int(user_id)
    value = (user or "").strip()
    if not value:
        raise ResolveError("User is required. Provide --user or --user-id.")
    if value.isdigit():
        return int(value)

    data = client.admin_users_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        raise ResolveError(f"User '{value}' not found.")
    if len(items) > 1:
        rows = [
            [
                str(u.get("id", "-")),
                str(u.get("username") or "-"),
                str(u.get("telegram_id") or "-"),
            ]
            for u in items
        ]
        raise ResolveError(
            "Multiple users matched. Use --user-id to disambiguate.",
            candidates=rows,
            candidate_headers=["id", "username", "telegram_id"],
        )
    return int(items[0]["id"])


def resolve_server_id_for_grants(client, server: str | None, server_id: int | None) -> int:
    if server_id is not None:
        return int(server_id)
    value = (server or "").strip()
    if not value:
        raise ResolveError("Server is required. Provide --server or --server-id.")
    if value.isdigit():
        return int(value)

    data = client.admin_servers_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    if not items:
        raise ResolveError(f"Server '{value}' not found.")
    if len(items) > 1:
        rows = [
            [
                str(s.get("id", "-")),
                str(s.get("name") or "-"),
                str(s.get("public_host") or "-"),
            ]
            for s in items
        ]
        raise ResolveError(
            "Multiple servers matched. Use --server-id to disambiguate.",
            candidates=rows,
            candidate_headers=["id", "name", "host"],
        )
    return int(items[0]["id"])


def validate_route_for_protocol(protocol_code: str | None, route: str | None) -> str | None:
    if route is None:
        return None
    normalized = route.strip()
    if not normalized:
        return None
    if protocol_code != "xray":
        raise ResolveError("Route is only supported for xray grants.")
    return normalized


def resolve_server_id_for_jobs(client, server_ref: str) -> int:
    if server_ref.isdigit():
        return int(server_ref)

    data = client.admin_servers_list(q=server_ref, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [s for s in items if str(s.get("name")) == server_ref]
    if not matches:
        raise ResolveError(f"Server '{server_ref}' not found.")
    if len(matches) > 1:
        names = ", ".join(str(s.get("id")) for s in matches)
        raise ResolveError(f"Multiple servers matched '{server_ref}': {names}")
    return int(matches[0]["id"])


def resolve_server_id_for_servers(client, server_ref: str) -> int:
    if server_ref.isdigit():
        return int(server_ref)

    data = client.admin_servers_list(q=server_ref, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [s for s in items if str(s.get("name")) == server_ref]
    if not matches:
        raise ResolveError(f"Server '{server_ref}' not found.")
    if len(matches) > 1:
        names = ", ".join(str(s.get("id")) for s in matches)
        raise ResolveError(f"Multiple servers matched '{server_ref}': {names}")
    return int(matches[0]["id"])


def find_server_by_name(client, name: str) -> dict | None:
    data = client.admin_servers_list(q=name, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [s for s in items if str(s.get("name")) == name]
    if not matches:
        return None
    if len(matches) > 1:
        names = ", ".join(str(s.get("id")) for s in matches)
        raise ResolveError(f"Multiple servers matched '{name}': {names}")
    return matches[0]


def resolve_agent_id_for_logs(client, agent_name_or_id: str) -> int:
    value = str(agent_name_or_id).strip()
    if value.isdigit():
        return int(value)
    page_size = 200
    offset = 0
    while True:
        data = client.admin_agents_list(include_deleted=False, limit=page_size, offset=offset)
        items = data.get("items") if isinstance(data, dict) else []
        matches = [a for a in (items or []) if str(a.get("name") or "").strip() == value]
        if matches:
            if len(matches) > 1:
                raise ApiError(409, f"multiple runtimes named {value}")
            return int(matches[0]["id"])
        total = data.get("total") if isinstance(data, dict) else None
        if total is None:
            break
        offset += page_size
        if offset >= total:
            break
    raise ApiError(404, f"runtime {value} not found")


def resolve_server_id_for_logs(client, server_name_or_id: str) -> int:
    value = str(server_name_or_id).strip()
    if value.isdigit():
        return int(value)
    data = client.admin_servers_list(q=value, limit=50, offset=0)
    items = data.get("items") if isinstance(data, dict) else []
    matches = [s for s in (items or []) if str(s.get("name") or "").strip() == value]
    if not matches:
        raise ApiError(404, f"server {value} not found")
    if len(matches) > 1:
        raise ApiError(409, f"multiple servers named {value}")
    return int(matches[0]["id"])


def resolve_agent_id_for_agents(client, agent_name_or_id: str) -> int:
    value = str(agent_name_or_id).strip()
    if value.isdigit():
        return int(value)
    page_size = 200
    offset = 0
    while True:
        data = client.admin_agents_list(include_deleted=False, limit=page_size, offset=offset)
        items = data.get("items") if isinstance(data, dict) else []
        matches = [a for a in (items or []) if str(a.get("name") or "").strip() == value]
        if matches:
            if len(matches) > 1:
                raise ApiError(409, f"multiple agents named {value}")
            return int(matches[0]["id"])
        total = data.get("total") if isinstance(data, dict) else None
        if total is None:
            break
        offset += page_size
        if offset >= total:
            break
    raise ApiError(404, f"agent {value} not found")
