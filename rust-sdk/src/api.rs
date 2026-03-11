use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::JoinNodeRequest;

#[derive(Debug)]
pub struct ApiError {
    pub status_code: u16,
    pub message: String,
    pub details: Option<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

pub struct ApiClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

#[allow(dead_code)]
impl ApiClient {
    pub fn new(base_url: &str, token: Option<&str>) -> Result<Self, ApiError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ApiError {
                status_code: 0,
                message: format!("failed to create HTTP client: {e}"),
                details: None,
            })?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            token: token.map(|s| s.to_string()),
        })
    }

    pub fn auth_login(&self, username: &str, password: &str) -> Result<String, ApiError> {
        let body = json!({ "username": username, "password": password });
        let data = self.request_json("POST", "/auth/login", Some(body), false)?;
        extract_token(&data).ok_or(ApiError {
            status_code: 500,
            message: "auth login returned no token".to_string(),
            details: None,
        })
    }

    pub fn auth_api_key(&self, api_key: &str) -> Result<String, ApiError> {
        let body = json!({ "api_key": api_key });
        let data = self.request_json("POST", "/auth/api-key", Some(body), false)?;
        extract_token(&data).ok_or(ApiError {
            status_code: 500,
            message: "auth api-key returned no token".to_string(),
            details: None,
        })
    }

    pub fn me(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/me", None, true)
    }

    pub fn version(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/version", None, false)
    }

    pub fn credentials_ensure(&self, payload: Value) -> Result<Value, ApiError> {
        self.request_json("POST", "/credentials/ensure", Some(payload), true)
    }

    pub fn admin_nodes_list(
        &self,
        q: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        let mut query = Vec::new();
        if let Some(v) = q {
            if !v.trim().is_empty() {
                query.push(("q", v.to_string()));
            }
        }
        if let Some(v) = limit {
            query.push(("limit", v.to_string()));
        }
        if let Some(v) = offset {
            query.push(("offset", v.to_string()));
        }
        self.request_json_with_query("GET", "/admin/nodes", None, true, &query)
    }

    pub fn admin_node_get(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/nodes/{node_id}"), None, true)
    }

    pub fn admin_node_status(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/nodes/{node_id}/status"), None, true)
    }

    pub fn admin_node_protocols_list(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/nodes/{node_id}/protocols"),
            None,
            true,
        )
    }

    pub fn admin_node_detach_agent(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "DELETE",
            &format!("/admin/nodes/{node_id}/agent"),
            None,
            true,
        )
    }

    pub fn admin_node_delete(&self, node_id: i64, force: bool) -> Result<Value, ApiError> {
        let path = if force {
            format!("/admin/nodes/{node_id}?force=true")
        } else {
            format!("/admin/nodes/{node_id}")
        };
        self.request_json("DELETE", &path, None, true)
    }

    pub fn admin_node_logs(&self, node_id: i64, lines: i64) -> Result<Value, ApiError> {
        let body = json!({ "lines": lines });
        self.request_json(
            "POST",
            &format!("/admin/nodes/{node_id}/logs"),
            Some(body),
            true,
        )
    }

    pub fn admin_agent_logs(
        &self,
        agent_id: i64,
        containers: &[String],
        lines: i64,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "containers": containers,
            "lines": lines,
        });
        self.request_json(
            "POST",
            &format!("/admin/agents/{agent_id}/logs"),
            Some(body),
            true,
        )
    }

    pub fn admin_node_create(
        &self,
        name: &str,
        host: &str,
        agent_id: i64,
        note: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert("name".to_string(), Value::String(name.to_string()));
        body.insert("host".to_string(), Value::String(host.to_string()));
        body.insert("agent_id".to_string(), Value::Number(agent_id.into()));
        if let Some(v) = note {
            if !v.trim().is_empty() {
                body.insert("note".to_string(), Value::String(v.to_string()));
            }
        }
        self.request_json("POST", "/admin/nodes", Some(Value::Object(body)), true)
    }

    pub fn admin_node_bootstrap(
        &self,
        node_id: i64,
        services: &[String],
        force: bool,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "services": services,
            "force": force,
        });
        self.request_json(
            "POST",
            &format!("/admin/nodes/{node_id}/bootstrap"),
            Some(body),
            true,
        )
    }

    pub fn join_node(&self, payload: &JoinNodeRequest) -> Result<Value, ApiError> {
        let body = serde_json::to_value(payload).map_err(|e| ApiError {
            status_code: 0,
            message: format!("failed to serialize join payload: {e}"),
            details: None,
        })?;
        self.request_json("POST", "/admin/nodes/join", Some(body), true)
    }

    pub fn admin_jobs_list(
        &self,
        status: Option<&str>,
        agent_id: Option<i64>,
        node_id: Option<i64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        let mut query = Vec::new();
        if let Some(v) = status {
            if !v.trim().is_empty() {
                query.push(("status", v.to_string()));
            }
        }
        if let Some(v) = agent_id {
            query.push(("agent_id", v.to_string()));
        }
        if let Some(v) = node_id {
            query.push(("node_id", v.to_string()));
        }
        if let Some(v) = limit {
            query.push(("limit", v.to_string()));
        }
        if let Some(v) = offset {
            query.push(("offset", v.to_string()));
        }
        self.request_json_with_query("GET", "/admin/jobs", None, true, &query)
    }

    pub fn admin_job_get(&self, job_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/jobs/{job_id}"), None, true)
    }

    pub fn admin_job_create(
        &self,
        node_id: Option<i64>,
        agent_id: Option<i64>,
        job_type: &str,
        payload: Value,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert("type".to_string(), Value::String(job_type.to_string()));
        body.insert("payload".to_string(), payload);
        if let Some(v) = node_id {
            body.insert("node_id".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = agent_id {
            body.insert("agent_id".to_string(), Value::Number(v.into()));
        }
        self.request_json("POST", "/admin/jobs", Some(Value::Object(body)), true)
    }

    pub fn admin_jobs_cleanup(
        &self,
        older_than_days: Option<i64>,
        status: Option<&str>,
        node_id: Option<i64>,
        agent_id: Option<i64>,
        dry_run: bool,
    ) -> Result<Value, ApiError> {
        let mut query = vec![(
            "dry-run",
            if dry_run { "true" } else { "false" }.to_string(),
        )];
        if let Some(v) = older_than_days {
            query.push(("older-than-days", v.to_string()));
        }
        if let Some(v) = status {
            if !v.trim().is_empty() {
                query.push(("status", v.to_string()));
            }
        }
        if let Some(v) = node_id {
            query.push(("node-id", v.to_string()));
        }
        if let Some(v) = agent_id {
            query.push(("agent-id", v.to_string()));
        }
        self.request_json_with_query("DELETE", "/admin/jobs", None, true, &query)
    }

    pub fn admin_host_update(&self, pull_only: bool) -> Result<Value, ApiError> {
        let body = json!({ "pull_only": pull_only });
        self.request_json("POST", "/admin/host/update", Some(body), true)
    }

    pub fn admin_license_snapshot(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/admin/license/snapshot", None, true)
    }

    pub fn admin_license_refresh(&self) -> Result<Value, ApiError> {
        self.request_json("POST", "/admin/license/sync", None, true)
    }

    pub fn admin_deployments_list(&self, enabled_only: bool) -> Result<Value, ApiError> {
        let query = if enabled_only {
            "?enabled_only=true"
        } else {
            ""
        };
        self.request_json("GET", &format!("/admin/deployments{query}"), None, true)
    }

    pub fn admin_pod_get_by_name(&self, name: &str) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/pods/by-name/{}", name.trim()),
            None,
            true,
        )
    }

    pub fn admin_pods_list(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/admin/pods", None, true)
    }

    pub fn admin_pod_get(&self, pod_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/pods/{pod_id}"), None, true)
    }

    pub fn admin_pod_create(
        &self,
        name: &str,
        display_name: &str,
        yaml_definition: &str,
        workspace: Option<&str>,
        project: Option<&str>,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "name": name.trim(),
            "display_name": display_name.trim(),
            "yaml_definition": yaml_definition,
            "workspace": workspace.map(|v| v.trim()).filter(|v| !v.is_empty()),
            "project": project.map(|v| v.trim()).filter(|v| !v.is_empty()),
        });
        self.request_json("POST", "/admin/pods", Some(body), true)
    }

    pub fn admin_pod_update(
        &self,
        pod_id: i64,
        display_name: Option<&str>,
        yaml_definition: Option<&str>,
        workspace: Option<&str>,
        project: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = display_name {
            body.insert("display_name".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = yaml_definition {
            body.insert("yaml_definition".to_string(), Value::String(v.to_string()));
        }
        if let Some(v) = workspace {
            body.insert("workspace".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = project {
            body.insert("project".to_string(), Value::String(v.trim().to_string()));
        }
        self.request_json(
            "PATCH",
            &format!("/admin/pods/{pod_id}"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_users_list(
        &self,
        q: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        let mut query = Vec::new();
        if let Some(v) = q {
            if !v.trim().is_empty() {
                query.push(("q", v.to_string()));
            }
        }
        if let Some(v) = limit {
            query.push(("limit", v.to_string()));
        }
        if let Some(v) = offset {
            query.push(("offset", v.to_string()));
        }
        self.request_json_with_query("GET", "/admin/users", None, true, &query)
    }

    pub fn admin_user_get(&self, user_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/users/{user_id}"), None, true)
    }

    pub fn admin_user_update_role(&self, user_id: i64, role: &str) -> Result<Value, ApiError> {
        let body = json!({ "role": role.trim() });
        self.request_json("PATCH", &format!("/admin/users/{user_id}"), Some(body), true)
    }

    pub fn admin_roles_list(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/admin/roles", None, true)
    }

    pub fn admin_role_get(&self, role_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/roles/{role_id}"), None, true)
    }

    pub fn admin_role_get_by_name(&self, name: &str) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/roles/by-name/{name}"), None, true)
    }

    pub fn admin_role_create(&self, name: &str, yaml_definition: &str) -> Result<Value, ApiError> {
        let body = json!({
            "name": name.trim(),
            "yaml_definition": yaml_definition,
        });
        self.request_json("POST", "/admin/roles", Some(body), true)
    }

    pub fn admin_role_update(
        &self,
        role_id: i64,
        yaml_definition: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = yaml_definition {
            body.insert("yaml_definition".to_string(), Value::String(v.to_string()));
        }
        self.request_json(
            "PATCH",
            &format!("/admin/roles/{role_id}"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_role_binding_get(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/role-bindings/{binding_id}"), None, true)
    }

    pub fn admin_role_bindings_list(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/admin/role-bindings", None, true)
    }

    pub fn admin_role_binding_get_by_name(&self, name: &str) -> Result<Value, ApiError> {
        self.request_json("GET", &format!("/admin/role-bindings/by-name/{name}"), None, true)
    }

    pub fn admin_role_binding_create(
        &self,
        name: &str,
        yaml_definition: &str,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "name": name.trim(),
            "yaml_definition": yaml_definition,
        });
        self.request_json("POST", "/admin/role-bindings", Some(body), true)
    }

    pub fn admin_role_binding_update(
        &self,
        binding_id: i64,
        yaml_definition: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = yaml_definition {
            body.insert("yaml_definition".to_string(), Value::String(v.to_string()));
        }
        self.request_json(
            "PATCH",
            &format!("/admin/role-bindings/{binding_id}"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_grants_list(&self, user_id: Option<i64>) -> Result<Value, ApiError> {
        let mut query = Vec::new();
        if let Some(v) = user_id {
            query.push(("user_id", v.to_string()));
        }
        self.request_json_with_query("GET", "/admin/grants", None, true, &query)
    }

    pub fn admin_grant_create(
        &self,
        user_id: i64,
        server_id: i64,
        protocol_id: i64,
        route: Option<&str>,
        device_limit: Option<i64>,
        note: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert("server_id".to_string(), Value::Number(server_id.into()));
        body.insert("protocol_id".to_string(), Value::Number(protocol_id.into()));
        if let Some(v) = route {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert("route".to_string(), Value::String(trimmed.to_string()));
            }
        }
        if let Some(v) = device_limit {
            body.insert("device_limit".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = note {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert("note".to_string(), Value::String(trimmed.to_string()));
            }
        }
        self.request_json(
            "POST",
            &format!("/admin/users/{user_id}/grants"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_grant_revoke(&self, grant_id: i64) -> Result<Value, ApiError> {
        let body = json!({ "revoke": true });
        self.request_json(
            "PATCH",
            &format!("/admin/grants/{grant_id}"),
            Some(body),
            true,
        )
    }

    pub fn invites_list(&self, limit: i64, offset: i64) -> Result<Value, ApiError> {
        let query = vec![("limit", limit.to_string()), ("offset", offset.to_string())];
        self.request_json_with_query("GET", "/invites/", None, true, &query)
    }

    pub fn invites_create(
        &self,
        duration_days: Option<i64>,
        perpetual: bool,
        note: Option<&str>,
        max_uses: i64,
        expires_in_days: Option<i64>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert("perpetual".to_string(), Value::Bool(perpetual));
        body.insert("max_uses".to_string(), Value::Number(max_uses.into()));
        body.insert(
            "expires_in_days".to_string(),
            expires_in_days
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
        );
        body.insert(
            "duration_days".to_string(),
            duration_days
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
        );
        body.insert(
            "note".to_string(),
            note.map(|v| Value::String(v.to_string()))
                .unwrap_or(Value::Null),
        );
        self.request_json("POST", "/invites/", Some(Value::Object(body)), true)
    }

    pub fn invites_claim_local(
        &self,
        token: &str,
        username: &str,
        password: &str,
        device_label: &str,
        platform: Option<&str>,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "token": token,
            "username": username,
            "password": password,
            "device_label": device_label,
            "platform": platform
        });
        self.request_json("POST", "/invites/claim-local", Some(body), false)
    }

    pub fn updates_cli(&self, current: &str, platform: Option<&str>) -> Result<Value, ApiError> {
        let mut query = vec![("current", current.trim().to_string())];
        if let Some(v) = platform {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                query.push(("platform", trimmed.to_string()));
            }
        }
        self.request_json_with_query("GET", "/updates/cli", None, true, &query)
    }

    pub fn admin_deployment_get(&self, deployment_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/deployments/{deployment_id}"),
            None,
            true,
        )
    }

    pub fn admin_deployment_get_by_name(&self, name: &str) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/deployments/by-name/{}", name.trim()),
            None,
            true,
        )
    }

    pub fn admin_deployment_create(
        &self,
        name: &str,
        display_name: &str,
        yaml_definition: &str,
        workspace: Option<&str>,
        project: Option<&str>,
        enabled: bool,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "name": name.trim(),
            "display_name": display_name.trim(),
            "yaml_definition": yaml_definition,
            "workspace": workspace.map(|v| v.trim()).filter(|v| !v.is_empty()),
            "project": project.map(|v| v.trim()).filter(|v| !v.is_empty()),
            "enabled": enabled,
        });
        self.request_json("POST", "/admin/deployments", Some(body), true)
    }

    pub fn admin_deployment_update(
        &self,
        deployment_id: i64,
        display_name: Option<&str>,
        yaml_definition: Option<&str>,
        workspace: Option<&str>,
        project: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = display_name {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert("display_name".to_string(), Value::String(trimmed.to_string()));
            }
        }
        if let Some(v) = yaml_definition {
            body.insert("yaml_definition".to_string(), Value::String(v.to_string()));
        }
        if let Some(v) = workspace {
            body.insert("workspace".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = project {
            body.insert("project".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = enabled {
            body.insert("enabled".to_string(), Value::Bool(v));
        }
        self.request_json(
            "PATCH",
            &format!("/admin/deployments/{deployment_id}"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_deployment_delete(&self, deployment_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "DELETE",
            &format!("/admin/deployments/{deployment_id}"),
            None,
            true,
        )
    }

    pub fn admin_deployment_revisions(&self, name: &str, limit: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/deployments/{}/revisions?limit={}", name.trim(), limit),
            None,
            true,
        )
    }

    pub fn admin_bindings_list(
        &self,
        binding_kind: Option<&str>,
        server_id: Option<i64>,
    ) -> Result<Value, ApiError> {
        let mut query = Vec::new();
        if let Some(v) = binding_kind {
            if !v.trim().is_empty() {
                query.push(format!("binding_kind={}", v.trim()));
            }
        }
        if let Some(v) = server_id {
            query.push(format!("server_id={v}"));
        }
        let suffix = if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.join("&"))
        };
        self.request_json("GET", &format!("/admin/bindings{suffix}"), None, true)
    }

    pub fn admin_binding_get(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/bindings/{binding_id}"),
            None,
            true,
        )
    }

    pub fn admin_binding_get_by_name(&self, name: &str) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/bindings/by-name/{}", name.trim()),
            None,
            true,
        )
    }

    pub fn admin_binding_create(
        &self,
        name: &str,
        server_id: i64,
        deployment_name: &str,
        binding_kind: &str,
        state: &str,
        replicas: i64,
        source: Option<&str>,
        meta: Option<Value>,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "name": name.trim(),
            "server_id": server_id,
            "deployment_name": deployment_name.trim(),
            "binding_kind": binding_kind.trim(),
            "state": state.trim(),
            "replicas": replicas,
            "source": source.map(|v| v.trim()).filter(|v| !v.is_empty()),
            "meta": meta.unwrap_or_else(|| json!({})),
        });
        self.request_json("POST", "/admin/bindings", Some(body), true)
    }

    pub fn admin_binding_update(
        &self,
        binding_id: i64,
        server_id: Option<i64>,
        deployment_name: Option<&str>,
        binding_kind: Option<&str>,
        state: Option<&str>,
        replicas: Option<i64>,
        source: Option<&str>,
        meta: Option<Value>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = server_id {
            body.insert("server_id".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = deployment_name {
            body.insert("deployment_name".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = binding_kind {
            body.insert("binding_kind".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = state {
            body.insert("state".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = replicas {
            body.insert("replicas".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = source {
            body.insert("source".to_string(), Value::String(v.trim().to_string()));
        }
        if let Some(v) = meta {
            body.insert("meta".to_string(), v);
        }
        self.request_json(
            "PATCH",
            &format!("/admin/bindings/{binding_id}"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_binding_delete(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "DELETE",
            &format!("/admin/bindings/{binding_id}"),
            None,
            true,
        )
    }

    pub fn admin_node_bindings_reconcile(
        &self,
        node_id: i64,
        rollout_strategy: Option<&str>,
        rollout_batch_size: Option<i64>,
        rollout_max_unavailable: Option<i64>,
        rollout_pause_seconds: Option<f64>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = rollout_strategy {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert(
                    "rollout_strategy".to_string(),
                    Value::String(trimmed.to_string()),
                );
            }
        }
        if let Some(v) = rollout_batch_size {
            body.insert("rollout_batch_size".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = rollout_max_unavailable {
            body.insert(
                "rollout_max_unavailable".to_string(),
                Value::Number(v.into()),
            );
        }
        if let Some(v) = rollout_pause_seconds {
            if let Some(num) = serde_json::Number::from_f64(v) {
                body.insert("rollout_pause_seconds".to_string(), Value::Number(num));
            }
        }
        self.request_json(
            "POST",
            &format!("/admin/nodes/{node_id}/bindings/reconcile"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_node_binding_instances(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/nodes/{node_id}/bindings/instances"),
            None,
            true,
        )
    }

    pub fn admin_node_binding_catalog_get(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/nodes/{node_id}/bindings/catalog"),
            None,
            true,
        )
    }

    pub fn admin_node_binding_catalog_set(
        &self,
        node_id: i64,
        service_codes: &[String],
        append: bool,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "service_codes": service_codes,
            "append": append,
        });
        self.request_json(
            "PUT",
            &format!("/admin/nodes/{node_id}/bindings/catalog"),
            Some(body),
            true,
        )
    }

    pub fn admin_node_bindings_get(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/nodes/{node_id}/bindings"),
            None,
            true,
        )
    }

    pub fn admin_node_bindings_set(
        &self,
        node_id: i64,
        service_codes: &[String],
        services: Option<Value>,
        enqueue_reconcile: bool,
        rollout_strategy: Option<&str>,
        rollout_batch_size: Option<i64>,
        rollout_max_unavailable: Option<i64>,
        rollout_pause_seconds: Option<f64>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "service_codes".to_string(),
            Value::Array(
                service_codes
                    .iter()
                    .map(|code| Value::String(code.clone()))
                    .collect(),
            ),
        );
        body.insert(
            "enqueue_reconcile".to_string(),
            Value::Bool(enqueue_reconcile),
        );
        if let Some(v) = services {
            body.insert("services".to_string(), v);
        }
        if let Some(v) = rollout_strategy {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert(
                    "rollout_strategy".to_string(),
                    Value::String(trimmed.to_string()),
                );
            }
        }
        if let Some(v) = rollout_batch_size {
            body.insert("rollout_batch_size".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = rollout_max_unavailable {
            body.insert(
                "rollout_max_unavailable".to_string(),
                Value::Number(v.into()),
            );
        }
        if let Some(v) = rollout_pause_seconds {
            if let Some(num) = serde_json::Number::from_f64(v) {
                body.insert("rollout_pause_seconds".to_string(), Value::Number(num));
            }
        }
        self.request_json(
            "PUT",
            &format!("/admin/nodes/{node_id}/bindings"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_node_bindings_dry_run(
        &self,
        node_id: i64,
        rollout_strategy: Option<&str>,
        rollout_batch_size: Option<i64>,
        rollout_max_unavailable: Option<i64>,
        rollout_pause_seconds: Option<f64>,
    ) -> Result<Value, ApiError> {
        let mut body = serde_json::Map::new();
        if let Some(v) = rollout_strategy {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                body.insert(
                    "rollout_strategy".to_string(),
                    Value::String(trimmed.to_string()),
                );
            }
        }
        if let Some(v) = rollout_batch_size {
            body.insert("rollout_batch_size".to_string(), Value::Number(v.into()));
        }
        if let Some(v) = rollout_max_unavailable {
            body.insert(
                "rollout_max_unavailable".to_string(),
                Value::Number(v.into()),
            );
        }
        if let Some(v) = rollout_pause_seconds {
            if let Some(num) = serde_json::Number::from_f64(v) {
                body.insert("rollout_pause_seconds".to_string(), Value::Number(num));
            }
        }
        self.request_json(
            "POST",
            &format!("/admin/nodes/{node_id}/bindings/dry-run"),
            Some(Value::Object(body)),
            true,
        )
    }

    pub fn admin_node_bindings_drift(&self, node_id: i64) -> Result<Value, ApiError> {
        self.request_json(
            "GET",
            &format!("/admin/nodes/{node_id}/bindings/drift"),
            None,
            true,
        )
    }

    pub fn admin_deployment_events(
        &self,
        limit: i64,
        service_code: Option<&str>,
        node_id: Option<i64>,
        event_type: Option<&str>,
    ) -> Result<Value, ApiError> {
        let mut query = vec![("limit", limit.max(1).to_string())];
        if let Some(v) = service_code {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                query.push(("service_code", trimmed.to_string()));
            }
        }
        if let Some(v) = node_id {
            query.push(("server_id", v.to_string()));
        }
        if let Some(v) = event_type {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                query.push(("event_type", trimmed.to_string()));
            }
        }
        self.request_json_with_query(
            "GET",
            "/admin/nodes/deployments/events",
            None,
            true,
            &query,
        )
    }

    pub fn admin_deployments_state_export(&self) -> Result<Value, ApiError> {
        self.request_json("GET", "/admin/nodes/deployments/export", None, true)
    }

    pub fn admin_deployments_state_import(
        &self,
        services: Value,
        revisions: Value,
        instances: Value,
        merge: bool,
    ) -> Result<Value, ApiError> {
        let body = json!({
            "services": services,
            "revisions": revisions,
            "instances": instances,
            "merge": merge,
        });
        self.request_json(
            "POST",
            "/admin/nodes/deployments/import",
            Some(body),
            true,
        )
    }

    fn request_json(
        &self,
        method: &str,
        path: &str,
        json_body: Option<Value>,
        with_auth: bool,
    ) -> Result<Value, ApiError> {
        let url = format!("{}{}", self.base_url, path);
        self.request_json_raw(method, &url, json_body, with_auth)
    }

    fn request_json_with_query(
        &self,
        method: &str,
        path: &str,
        json_body: Option<Value>,
        with_auth: bool,
        query: &[(&str, String)],
    ) -> Result<Value, ApiError> {
        let mut url =
            reqwest::Url::parse(&format!("{}{}", self.base_url, path)).map_err(|e| ApiError {
                status_code: 0,
                message: format!("invalid URL: {e}"),
                details: None,
            })?;
        if !query.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
            drop(qp);
        }
        self.request_json_raw(method, url.as_str(), json_body, with_auth)
    }

    fn request_json_raw(
        &self,
        method: &str,
        url: &str,
        json_body: Option<Value>,
        with_auth: bool,
    ) -> Result<Value, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Request-Id",
            HeaderValue::from_str(&Uuid::new_v4().to_string()).map_err(|e| ApiError {
                status_code: 0,
                message: format!("failed to create request id: {e}"),
                details: None,
            })?,
        );
        headers.insert(
            "X-CLI-Version",
            HeaderValue::from_str(&cli_version()).map_err(|e| ApiError {
                status_code: 0,
                message: format!("failed to set cli version header: {e}"),
                details: None,
            })?,
        );
        headers.insert(
            "X-CLI-Protocol",
            HeaderValue::from_str(&cli_protocol().to_string()).map_err(|e| ApiError {
                status_code: 0,
                message: format!("failed to set cli protocol header: {e}"),
                details: None,
            })?,
        );
        if with_auth {
            if let Some(token) = self.token.as_deref() {
                let auth = format!("Bearer {token}");
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&auth).map_err(|e| ApiError {
                        status_code: 0,
                        message: format!("failed to set auth header: {e}"),
                        details: None,
                    })?,
                );
            }
        }

        let request = match method {
            "POST" => self.client.post(url),
            "GET" => self.client.get(url),
            "DELETE" => self.client.delete(url),
            "PATCH" => self.client.patch(url),
            "PUT" => self.client.put(url),
            _ => {
                return Err(ApiError {
                    status_code: 0,
                    message: format!("unsupported method: {method}"),
                    details: None,
                });
            }
        }
        .headers(headers);

        let request = if let Some(body) = json_body {
            request.json(&body)
        } else {
            request
        };

        let response = request.send().map_err(|e| ApiError {
            status_code: 0,
            message: e.to_string(),
            details: None,
        })?;
        let status = response.status().as_u16();
        let text = response.text().map_err(|e| ApiError {
            status_code: status,
            message: format!("failed reading response body: {e}"),
            details: None,
        })?;
        let parsed = serde_json::from_str::<Value>(&text).ok();

        if status >= 400 {
            let (message, details) = if let Some(Value::Object(obj)) = parsed.as_ref() {
                let detail = obj
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if detail.is_empty() {
                    (
                        format!("{method} {url} failed with {status}"),
                        Some(text.chars().take(1000).collect()),
                    )
                } else {
                    (detail, Some(text.chars().take(1000).collect()))
                }
            } else {
                (
                    format!("{method} {url} failed with {status}"),
                    if text.is_empty() {
                        None
                    } else {
                        Some(text.chars().take(1000).collect())
                    },
                )
            };
            return Err(ApiError {
                status_code: status,
                message,
                details,
            });
        }

        Ok(parsed.unwrap_or(Value::String(text)))
    }
}

fn extract_token(value: &Value) -> Option<String> {
    let obj = value.as_object()?;
    let token = obj
        .get("token")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("access_token").and_then(|v| v.as_str()))?;
    if token.trim().is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

pub fn cli_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn cli_protocol() -> i64 {
    std::env::var("SAHARO_CLI_PROTOCOL")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
}
