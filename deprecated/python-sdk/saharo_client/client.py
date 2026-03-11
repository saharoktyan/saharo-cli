from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from .config_types import ClientConfig
from .errors import ApiError
from .transport import Transport


class SaharoClient:
    def __init__(self, cfg: ClientConfig):
        self._t = Transport(cfg)

    def _request_json(
            self,
            method: str,
            path: str,
            *,
            json_body: dict | None = None,
    ):
        """Internal helper for endpoints that should return JSON."""
        data = self._t.request(method, path, json_body=json_body)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"items": data}
        return {"raw": data}

    def close(self) -> None:
        self._t.close()

    # --- API methods (MVP) ---
    def auth_login(self, *, username: str, password: str) -> str:
        data = self._t.request("POST", "/auth/login", json_body={"username": username, "password": password})
        if isinstance(data, dict):
            token = data.get("token") or data.get("access_token")
            if isinstance(token, str) and token:
                return token
        raise ApiError(500, "auth login returned no token", None)

    def auth_api_key(self, *, api_key: str) -> str:
        data = self._t.request("POST", "/auth/api-key", json_body={"api_key": api_key})
        if isinstance(data, dict):
            token = data.get("token") or data.get("access_token")
            if isinstance(token, str) and token:
                return token
        raise ApiError(500, "auth api-key returned no token", None)

    def admin_users_list(self, *, q: str | None = None, limit: int | None = None, offset: int | None = None) -> dict[
        str, Any]:
        params: dict[str, Any] = {}
        if q:
            params["q"] = q
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        query = urlencode(params) if params else ""
        path = "/admin/users" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, dict) else {"items": data}

    def admin_user_get(self, user_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/users/{int(user_id)}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_user_subscription_get(self, user_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/users/{int(user_id)}/subscription")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_user_freeze(self, user_id: int, *, reason: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason
        data = self._t.request("POST", f"/admin/users/{int(user_id)}/freeze", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_user_unfreeze(self, user_id: int) -> dict[str, Any]:
        data = self._t.request("POST", f"/admin/users/{int(user_id)}/unfreeze", json_body={})
        return data if isinstance(data, dict) else {"raw": data}

    def admin_user_extend(self, user_id: int, *, days: int) -> dict[str, Any]:
        body = {"days": int(days)}
        data = self._t.request("POST", f"/admin/users/{int(user_id)}/extend", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_grants_list(self, *, user_id: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if user_id is not None:
            params["user_id"] = int(user_id)
        query = urlencode(params) if params else ""
        path = "/admin/grants" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, dict) else {"items": data}

    def admin_grant_create(
            self,
            *,
            user_id: int,
            server_id: int,
            protocol_id: int,
            route: str | None = None,
            device_limit: int | None = None,
            note: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "server_id": int(server_id),
            "protocol_id": int(protocol_id),
        }
        if route:
            body["route"] = route
        if device_limit is not None:
            body["device_limit"] = int(device_limit)
        if note:
            body["note"] = note
        data = self._t.request("POST", f"/admin/users/{int(user_id)}/grants", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_grant_revoke(self, grant_id: int) -> dict[str, Any]:
        data = self._t.request("PATCH", f"/admin/grants/{int(grant_id)}", json_body={"revoke": True})
        return data if isinstance(data, dict) else {"raw": data}

    def admin_protocols_list(self) -> dict[str, Any]:
        data = self._t.request("GET", "/admin/protocols")
        return data if isinstance(data, dict) else {"items": data}

    def admin_license_versions(self) -> dict[str, Any]:
        data = self._t.request("GET", "/admin/license/versions")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_license_snapshot(self) -> dict[str, Any]:
        data = self._t.request("GET", "/admin/license/snapshot")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_license_refresh(self) -> dict[str, Any]:
        data = self._t.request("POST", "/admin/license/sync")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_servers_list(self, *, q: str | None = None, limit: int | None = None, offset: int | None = None) -> dict[
        str, Any]:
        params: dict[str, Any] = {}
        if q:
            params["q"] = q
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        query = urlencode(params) if params else ""
        path = "/admin/servers" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, dict) else {"items": data}

    def admin_server_get(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/servers/{server_id}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_status(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/servers/{server_id}/status")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_detach_agent(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("DELETE", f"/admin/servers/{server_id}/agent")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_delete(self, server_id: int, *, force: bool = False) -> dict[str, Any]:
        query = "?force=true" if force else ""
        data = self._t.request("DELETE", f"/admin/servers/{server_id}{query}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agent_invite_create(self, *, name: str, note: str | None = None, expires_minutes: int | None = None) -> \
            dict[str, Any]:
        body: dict[str, Any] = {"name": name, "note": note}
        if expires_minutes is not None:
            body["ttl_seconds"] = int(expires_minutes) * 60
        paths = [
            "/admin/agent-invites",
            "/admin/agents/invites",  # legacy compatibility fallback
        ]
        last_not_found: ApiError | None = None
        data: Any = None
        for path in paths:
            try:
                data = self._t.request("POST", path, json_body=body)
                last_not_found = None
                break
            except ApiError as exc:
                if exc.status_code == 404:
                    last_not_found = exc
                    continue
                raise
        if last_not_found is not None:
            raise ApiError(
                404,
                "Agent invite endpoint is missing on Host API. Upgrade Host API or use a compatible CLI version.",
                last_not_found.details,
            )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agent_delete(self, agent_id: int, *, force: bool = False) -> dict[str, Any]:
        query = "?force=true" if force else ""
        data = self._t.request("DELETE", f"/admin/agents/{agent_id}{query}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agents_list(
            self,
            *,
            include_deleted: bool = False,
            limit: int | None = None,
            offset: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if include_deleted:
            params["include_deleted"] = "true"
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        query = urlencode(params) if params else ""
        path = "/admin/agents" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, dict) else {"items": data}

    def admin_agent_uninstall(self, agent_id: int, *, force: bool = False, dry_run: bool = False) -> dict[str, Any]:
        params = []
        if force:
            params.append("force=true")
        if dry_run:
            params.append("dry_run=true")
        query = f"?{'&'.join(params)}" if params else ""
        data = self._t.request("POST", f"/admin/agents/{agent_id}/uninstall{query}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agent_purge(self, agent_id: int, *, force: bool = False, dry_run: bool = False) -> dict[str, Any]:
        params = []
        if force:
            params.append("force=true")
        if dry_run:
            params.append("dry_run=true")
        query = f"?{'&'.join(params)}" if params else ""
        data = self._t.request("POST", f"/admin/agents/{agent_id}/purge{query}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agent_logs(self, agent_id: int, *, containers: list[str], lines: int) -> dict[str, Any]:
        body = {"containers": containers, "lines": int(lines)}
        data = self._t.request("POST", f"/admin/agents/{agent_id}/logs", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_logs(self, server_id: int, *, lines: int) -> dict[str, Any]:
        body = {"lines": int(lines)}
        data = self._t.request("POST", f"/admin/servers/{server_id}/logs", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_jobs_cleanup(
            self,
            *,
            older_than_days: int | None = None,
            status: str | None = None,
            server_id: int | None = None,
            agent_id: int | None = None,
            dry_run: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"dry-run": "true" if dry_run else "false"}
        if older_than_days is not None:
            params["older-than-days"] = int(older_than_days)
        if status:
            params["status"] = status
        if server_id is not None:
            params["server-id"] = int(server_id)
        if agent_id is not None:
            params["agent-id"] = int(agent_id)
        query = urlencode(params) if params else ""
        path = "/admin/jobs" + (f"?{query}" if query else "")
        data = self._t.request("DELETE", path)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_job_create(self, *, server_id: int | None, agent_id: int | None, job_type: str,
                         payload: dict[str, Any]) -> dict[str, Any]:
        body: dict[str, Any] = {"type": job_type, "payload": payload}
        if server_id is not None:
            body["server_id"] = int(server_id)
        if agent_id is not None:
            body["agent_id"] = int(agent_id)
        data = self._t.request("POST", "/admin/jobs", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_jobs_list(
            self,
            *,
            status: str | None = None,
            agent_id: int | None = None,
            server_id: int | None = None,
            limit: int | None = None,
            offset: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        if agent_id is not None:
            params["agent_id"] = int(agent_id)
        if server_id is not None:
            params["server_id"] = int(server_id)
        if limit is not None:
            params["limit"] = int(limit)
        if offset is not None:
            params["offset"] = int(offset)
        query = urlencode(params) if params else ""
        path = "/admin/jobs" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, dict) else {"items": data}

    def admin_host_update(self, *, pull_only: bool = False) -> dict[str, Any]:
        data = self._t.request("POST", "/admin/host/update", json_body={"pull_only": bool(pull_only)})
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_create(
            self,
            *,
            name: str,
            host: str,
            agent_id: int,
            note: str | None = None,
    ) -> dict[str, Any]:
        body = {"name": name, "host": host, "agent_id": agent_id, "note": note}
        data = self._t.request("POST", "/admin/servers", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_bootstrap(self, server_id: int, *, services: list[str], force: bool = False) -> dict[str, Any]:
        body = {"services": services, "force": bool(force)}
        data = self._t.request("POST", f"/admin/servers/{server_id}/bootstrap", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_protocols_list(self, server_id: int) -> list[dict[str, Any]]:
        data = self._t.request("GET", f"/admin/servers/{server_id}/protocols")
        return data if isinstance(data, list) else []

    def admin_server_protocol_upsert(
            self,
            server_id: int,
            *,
            protocol_key: str,
            status: str | None = None,
            meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = {"protocol_key": protocol_key, "status": status, "meta": meta}
        data = self._t.request("POST", f"/admin/servers/{server_id}/protocols", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_protocol_patch(
            self,
            server_id: int,
            *,
            protocol_key: str,
            status: str | None = None,
    ) -> dict[str, Any]:
        body = {"status": status}
        data = self._t.request("PATCH", f"/admin/servers/{server_id}/protocols/{protocol_key}", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_protocol_apply(self, server_id: int, *, protocol_key: str) -> dict[str, Any]:
        data = self._t.request("POST", f"/admin/servers/{server_id}/protocols/{protocol_key}/apply-config",
                               json_body={})
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_protocol_validate(self, server_id: int, *, protocol_key: str) -> dict[str, Any]:
        data = self._t.request("POST", f"/admin/servers/{server_id}/protocols/{protocol_key}/validate", json_body={})
        return data if isinstance(data, dict) else {"raw": data}

    def admin_job_get(self, job_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/jobs/{job_id}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_job_cancel(self, job_id: int) -> dict[str, Any]:
        data = self._t.request("POST", f"/admin/jobs/{job_id}/cancel")
        return data if isinstance(data, dict) else {"raw": data}

    def invites_create(
            self,
            *,
            duration_days: int | None = None,
            perpetual: bool = False,
            note: str | None = None,
            max_uses: int = 1,
            expires_in_days: int | None = 30,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "perpetual": bool(perpetual),
            "note": note,
            "max_uses": int(max_uses),
            "expires_in_days": expires_in_days,
            "duration_days": duration_days,
        }
        data = self._t.request("POST", "/invites/", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def invites_list(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        from urllib.parse import urlencode
        query = urlencode({"limit": int(limit), "offset": int(offset)})
        data = self._t.request("GET", f"/invites/?{query}")
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def invites_claim_local(
            self,
            *,
            token: str,
            username: str,
            password: str,
            device_label: str,
            platform: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "token": token,
            "username": username,
            "password": password,
            "device_label": device_label,
            "platform": platform,
        }
        data = self._t.request("POST", "/invites/claim-local", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def health(self) -> dict[str, Any]:
        # expected /health response: {"status":"ok", ...}
        data = self._t.request("GET", "/health")
        if isinstance(data, dict):
            return data
        return {"raw": data}

    def agents_list(self) -> list[dict]:
        data = self._t.request("GET", "/agents")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data["items"]
        return data if isinstance(data, list) else []

    def agents_get(self, agent_id: int) -> dict:
        data = self._t.request("GET", f"/agents/{agent_id}")
        return data if isinstance(data, dict) else {"raw": data}

    def server_set_agent(self, server_id: int, agent_id: int | None) -> dict:
        return self._t.request("POST", f"/servers/{server_id}/agent", json_body={"agent_id": agent_id})

    def credentials_ensure(
            self,
            *,
            server_id: int,
            protocol: str,
            device_label: str,
            route: str | None = None,
            client_public_key: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "server_id": int(server_id),
            "protocol": protocol,
            "device_label": device_label,
        }
        if route:
            body["route"] = route
        if client_public_key:
            body["client_public_key"] = client_public_key
        data = self._t.request("POST", "/credentials/ensure", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def me(self) -> dict[str, Any]:
        data = self._t.request("GET", "/me")
        if not isinstance(data, dict):
            raise ApiError(500, "Invalid /me response")
        return data

    def version(self) -> dict[str, Any]:
        data = self._t.request("GET", "/version")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_agents_summary(self) -> dict[str, Any]:
        data = self._t.request("GET", "/admin/agents/summary")
        return data if isinstance(data, dict) else {"raw": data}

    def updates_cli(self, *, current: str, platform: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"current": current}
        if platform:
            params["platform"] = platform
        query = urlencode(params)
        data = self._t.request("GET", f"/updates/cli?{query}")
        return data if isinstance(data, dict) else {"raw": data}

    def portal_link(self, *, enabled: bool) -> dict[str, Any]:
        path = "/portal/link" if enabled else "/portal/unlink"
        data = self._t.request("POST", path, json_body=None)
        return data if isinstance(data, dict) else {"raw": data}

    def portal_licenses(self) -> list[dict[str, Any]]:
        data = self._t.request("GET", "/portal/licenses")
        return data if isinstance(data, list) else []

    def admin_server_awg_params_get(self, server_id: int) -> dict[str, Any]:
        return self._request_json(
            "GET",
            f"/admin/servers/{server_id}/protocols/awg/params",
        )

    def admin_server_awg_params_set(self, server_id: int, patch: dict[str, Any]) -> dict[str, Any]:
        data = self._t.request(
            "POST",
            f"/admin/servers/{int(server_id)}/protocols/awg/params",
            json_body=patch,
        )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_apply_protocol_config(self, server_id: int, protocol_key: str) -> dict[str, Any]:
        data = self._t.request(
            "POST",
            f"/admin/servers/{int(server_id)}/protocols/{protocol_key}/apply-config",
            json_body=None,
        )
        return data if isinstance(data, dict) else {"raw": data}

    # --- Custom Services ---
    def admin_custom_services_list(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        params = {"enabled_only": "true"} if enabled_only else {}
        query = urlencode(params) if params else ""
        path = f"/admin/custom-services{f'?{query}' if query else ''}"
        data = self._t.request("GET", path)
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def admin_custom_service_get(self, service_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/custom-services/{int(service_id)}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_service_get_by_code(self, code: str) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/custom-services/by-code/{code}")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_service_create(self, *, code: str, display_name: str, yaml_definition: str) -> dict[str, Any]:
        body = {
            "code": code,
            "display_name": display_name,
            "yaml_definition": yaml_definition,
        }
        data = self._t.request("POST", "/admin/custom-services", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_service_update(
            self,
            service_id: int,
            *,
            display_name: str | None = None,
            yaml_definition: str | None = None,
            enabled: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if display_name is not None:
            body["display_name"] = display_name
        if yaml_definition is not None:
            body["yaml_definition"] = yaml_definition
        if enabled is not None:
            body["enabled"] = enabled
        data = self._t.request("PATCH", f"/admin/custom-services/{int(service_id)}", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_service_delete(self, service_id: int) -> None:
        self._t.request("DELETE", f"/admin/custom-services/{int(service_id)}")

    def admin_server_custom_service_instances(self, server_id: int) -> list[dict[str, Any]]:
        data = self._t.request("GET", f"/admin/custom-services/servers/{int(server_id)}/instances")
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def admin_agent_custom_services(self, agent_id: int) -> list[dict[str, Any]]:
        data = self._t.request("GET", f"/admin/custom-services/agents/{int(agent_id)}/services")
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def admin_custom_service_revisions(self, service_id: int, *, limit: int = 50) -> list[dict[str, Any]]:
        query = urlencode({"limit": int(limit)})
        data = self._t.request("GET", f"/admin/custom-services/{int(service_id)}/revisions?{query}")
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def admin_custom_service_rollback(self, service_id: int, *, revision: int, note: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"revision": int(revision)}
        if note:
            body["note"] = note
        data = self._t.request("POST", f"/admin/custom-services/{int(service_id)}/rollback", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_desired_custom_services_get(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/custom-services/servers/{int(server_id)}/desired-services")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_known_custom_services_get(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/custom-services/servers/{int(server_id)}/known-services")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_known_custom_services_set(
            self,
            server_id: int,
            *,
            service_codes: list[str],
            append: bool = False,
    ) -> dict[str, Any]:
        body = {
            "service_codes": service_codes,
            "append": bool(append),
        }
        data = self._t.request(
            "PUT",
            f"/admin/custom-services/servers/{int(server_id)}/known-services",
            json_body=body,
        )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_desired_custom_services_set(
            self,
            server_id: int,
            *,
            service_codes: list[str],
            services: list[dict[str, Any]] | None = None,
            enqueue_reconcile: bool = True,
            rollout_strategy: str = "safe",
            rollout_batch_size: int = 1,
            rollout_max_unavailable: int = 1,
            rollout_pause_seconds: float = 0.0,
    ) -> dict[str, Any]:
        body = {
            "service_codes": service_codes,
            "enqueue_reconcile": bool(enqueue_reconcile),
            "rollout_strategy": rollout_strategy,
            "rollout_batch_size": int(rollout_batch_size),
            "rollout_max_unavailable": int(rollout_max_unavailable),
            "rollout_pause_seconds": float(rollout_pause_seconds),
        }
        if services is not None:
            body["services"] = services
        data = self._t.request(
            "PUT",
            f"/admin/custom-services/servers/{int(server_id)}/desired-services",
            json_body=body,
        )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_custom_services_dry_run(
            self,
            server_id: int,
            *,
            rollout_strategy: str = "safe",
            rollout_batch_size: int | None = None,
            rollout_max_unavailable: int | None = None,
            rollout_pause_seconds: float | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"rollout_strategy": rollout_strategy}
        if rollout_batch_size is not None:
            body["rollout_batch_size"] = int(rollout_batch_size)
        if rollout_max_unavailable is not None:
            body["rollout_max_unavailable"] = int(rollout_max_unavailable)
        if rollout_pause_seconds is not None:
            body["rollout_pause_seconds"] = float(rollout_pause_seconds)
        data = self._t.request(
            "POST",
            f"/admin/custom-services/servers/{int(server_id)}/desired-services/dry-run",
            json_body=body,
        )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_custom_services_reconcile_now(
            self,
            server_id: int,
            *,
            rollout_strategy: str = "safe",
            rollout_batch_size: int = 1,
            rollout_max_unavailable: int = 1,
            rollout_pause_seconds: float = 0.0,
    ) -> dict[str, Any]:
        body = {
            "rollout_strategy": rollout_strategy,
            "rollout_batch_size": int(rollout_batch_size),
            "rollout_max_unavailable": int(rollout_max_unavailable),
            "rollout_pause_seconds": float(rollout_pause_seconds),
        }
        data = self._t.request(
            "POST",
            f"/admin/custom-services/servers/{int(server_id)}/reconcile-now",
            json_body=body,
        )
        return data if isinstance(data, dict) else {"raw": data}

    def admin_server_custom_services_drift(self, server_id: int) -> dict[str, Any]:
        data = self._t.request("GET", f"/admin/custom-services/servers/{int(server_id)}/drift")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_services_events(
            self,
            *,
            limit: int = 200,
            service_code: str | None = None,
            server_id: int | None = None,
            event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": int(limit)}
        if service_code:
            params["service_code"] = service_code
        if server_id is not None:
            params["server_id"] = int(server_id)
        if event_type:
            params["event_type"] = event_type
        query = urlencode(params) if params else ""
        path = "/admin/custom-services/stream/events" + (f"?{query}" if query else "")
        data = self._t.request("GET", path)
        return data if isinstance(data, list) else (data.get("items") if isinstance(data, dict) else [])

    def admin_custom_services_state_export(self) -> dict[str, Any]:
        data = self._t.request("GET", "/admin/custom-services/state/export")
        return data if isinstance(data, dict) else {"raw": data}

    def admin_custom_services_state_import(
            self,
            *,
            services: list[dict[str, Any]],
            revisions: list[dict[str, Any]],
            instances: list[dict[str, Any]],
            merge: bool = True,
    ) -> dict[str, Any]:
        body = {
            "services": services,
            "revisions": revisions,
            "instances": instances,
            "merge": bool(merge),
        }
        data = self._t.request("POST", "/admin/custom-services/state/import", json_body=body)
        return data if isinstance(data, dict) else {"raw": data}
