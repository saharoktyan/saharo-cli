from __future__ import annotations

import urllib.parse


def normalize_registry_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return host
    parsed = urllib.parse.urlparse(f"//{text}")
    if parsed.netloc:
        return parsed.netloc
    return text.split("/", 1)[0]


def resolve_agent_version_from_license_payload(payload: dict) -> tuple[str, str | None] | None:
    versions = payload.get("versions") if isinstance(payload, dict) else {}
    if not isinstance(versions, dict):
        return None

    resolved_versions = versions.get("resolved_versions")
    if not isinstance(resolved_versions, dict):
        resolved_versions = versions
    agent_tag = resolved_versions.get("agent")
    if not isinstance(agent_tag, str) or not agent_tag.strip():
        return None

    registry_url = None
    registry = versions.get("registry")
    if isinstance(registry, dict):
        reg_url = str(registry.get("url") or "").strip()
        if reg_url:
            registry_url = normalize_registry_host(reg_url) or None

    return agent_tag.strip(), registry_url


def extract_registry_creds_from_snapshot(snapshot: dict) -> tuple[str, str, str] | None:
    versions = snapshot.get("versions") if isinstance(snapshot, dict) else None
    if not isinstance(versions, dict):
        return None
    registry = versions.get("registry")
    if not isinstance(registry, dict):
        return None
    registry_url = str(registry.get("url") or "").strip()
    registry_username = str(registry.get("username") or "").strip()
    registry_password = registry.get("password")
    if registry_password is not None and not isinstance(registry_password, str):
        registry_password = None
    if not registry_url or not registry_username or not registry_password:
        return None
    registry_url = normalize_registry_host(registry_url)
    if not registry_url:
        return None
    return registry_url, registry_username, registry_password
