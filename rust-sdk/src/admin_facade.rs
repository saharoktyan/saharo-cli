use serde_json::Value;

use crate::admin_ops::{
    execute_join, parse_job_details, parse_jobs_list, parse_node_details, parse_nodes_list,
    resolve_node_id, JoinExecutionOptions, JoinExecutionResult,
};
use crate::models::{JobDetails, JobSummary, NodeDetails, NodeSummary};
use crate::{ApiClient, ApiError, JoinNodeRequest};

pub struct AdminFacade<'a> {
    api: &'a ApiClient,
}

impl<'a> AdminFacade<'a> {
    pub fn new(api: &'a ApiClient) -> Self {
        Self { api }
    }

    pub fn resolve_node_id(&self, node_ref: &str) -> Result<i64, String> {
        resolve_node_id(self.api, node_ref)
    }

    pub fn list_nodes_raw(
        &self,
        q: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        self.api.admin_nodes_list(q, limit, offset)
    }

    pub fn list_nodes(
        &self,
        q: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<NodeSummary>, ApiError> {
        let raw = self.list_nodes_raw(q, limit, offset)?;
        Ok(parse_nodes_list(&raw))
    }

    pub fn get_node_raw(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_get(node_id)
    }

    pub fn get_node(&self, node_id: i64) -> Result<NodeDetails, ApiError> {
        let raw = self.get_node_raw(node_id)?;
        Ok(parse_node_details(&raw))
    }

    pub fn delete_node(&self, node_id: i64, force: bool) -> Result<Value, ApiError> {
        self.api.admin_node_delete(node_id, force)
    }

    pub fn node_logs(&self, node_id: i64, lines: i64) -> Result<Value, ApiError> {
        self.api.admin_node_logs(node_id, lines)
    }

    pub fn join_node<F>(
        &self,
        payload: &JoinNodeRequest,
        options: JoinExecutionOptions,
        on_status_change: F,
    ) -> Result<JoinExecutionResult, ApiError>
    where
        F: FnMut(i64, &str, std::time::Duration),
    {
        execute_join(self.api, payload, options, on_status_change)
    }

    pub fn list_jobs_raw(
        &self,
        status: Option<&str>,
        agent_id: Option<i64>,
        node_id: Option<i64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_jobs_list(status, agent_id, node_id, limit, offset)
    }

    pub fn list_jobs(
        &self,
        status: Option<&str>,
        agent_id: Option<i64>,
        node_id: Option<i64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<JobSummary>, ApiError> {
        let raw = self.list_jobs_raw(status, agent_id, node_id, limit, offset)?;
        Ok(parse_jobs_list(&raw))
    }

    pub fn get_job_raw(&self, job_id: i64) -> Result<Value, ApiError> {
        self.api.admin_job_get(job_id)
    }

    pub fn get_job(&self, job_id: i64) -> Result<JobDetails, ApiError> {
        let raw = self.get_job_raw(job_id)?;
        Ok(parse_job_details(&raw))
    }

    pub fn list_deployments_raw(&self, enabled_only: bool) -> Result<Value, ApiError> {
        self.api.admin_deployments_list(enabled_only)
    }

    pub fn get_deployment_raw(&self, deployment_id: i64) -> Result<Value, ApiError> {
        self.api.admin_deployment_get(deployment_id)
    }

    pub fn get_deployment_by_name_raw(&self, name: &str) -> Result<Value, ApiError> {
        self.api.admin_deployment_get_by_name(name)
    }

    pub fn get_pod_by_name_raw(&self, name: &str) -> Result<Value, ApiError> {
        self.api.admin_pod_get_by_name(name)
    }

    pub fn list_pods_raw(&self) -> Result<Value, ApiError> {
        self.api.admin_pods_list()
    }

    pub fn get_pod_raw(&self, pod_id: i64) -> Result<Value, ApiError> {
        self.api.admin_pod_get(pod_id)
    }

    pub fn create_pod(
        &self,
        name: &str,
        display_name: &str,
        yaml_definition: &str,
        workspace: Option<&str>,
        project: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_pod_create(name, display_name, yaml_definition, workspace, project)
    }

    pub fn update_pod(
        &self,
        pod_id: i64,
        display_name: Option<&str>,
        yaml_definition: Option<&str>,
        workspace: Option<&str>,
        project: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_pod_update(pod_id, display_name, yaml_definition, workspace, project)
    }

    pub fn resolve_pod_id(&self, pod_ref: &str) -> Result<i64, String> {
        let trimmed = pod_ref.trim();
        if trimmed.is_empty() {
            return Err("Pod id or name is required.".to_string());
        }
        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return trimmed
                .parse::<i64>()
                .map_err(|_| "Invalid pod id.".to_string());
        }
        let raw = self.get_pod_by_name_raw(trimmed).map_err(|e| e.message)?;
        raw.get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| "Invalid pod id in response.".to_string())
    }

    pub fn create_deployment(
        &self,
        name: &str,
        display_name: &str,
        yaml_definition: &str,
        workspace: Option<&str>,
        project: Option<&str>,
        enabled: bool,
    ) -> Result<Value, ApiError> {
        self.api.admin_deployment_create(
            name,
            display_name,
            yaml_definition,
            workspace,
            project,
            enabled,
        )
    }

    pub fn update_deployment(
        &self,
        deployment_id: i64,
        display_name: Option<&str>,
        yaml_definition: Option<&str>,
        workspace: Option<&str>,
        project: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<Value, ApiError> {
        self.api.admin_deployment_update(
            deployment_id,
            display_name,
            yaml_definition,
            workspace,
            project,
            enabled,
        )
    }

    pub fn delete_deployment(&self, deployment_id: i64) -> Result<Value, ApiError> {
        self.api.admin_deployment_delete(deployment_id)
    }

    pub fn resolve_deployment_id(&self, deployment_ref: &str) -> Result<i64, String> {
        let trimmed = deployment_ref.trim();
        if trimmed.is_empty() {
            return Err("Deployment id or name is required.".to_string());
        }
        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return trimmed
                .parse::<i64>()
                .map_err(|_| "Invalid deployment id.".to_string());
        }
        let raw = self
            .get_deployment_by_name_raw(trimmed)
            .map_err(|e| e.message)?;
        raw.get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| "Invalid deployment id in response.".to_string())
    }

    pub fn list_deployment_revisions_raw(&self, deployment_name: &str, limit: i64) -> Result<Value, ApiError> {
        self.api.admin_deployment_revisions(deployment_name, limit)
    }

    pub fn list_bindings_raw(
        &self,
        binding_kind: Option<&str>,
        server_id: Option<i64>,
    ) -> Result<Value, ApiError> {
        self.api.admin_bindings_list(binding_kind, server_id)
    }

    pub fn get_binding_raw(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.api.admin_binding_get(binding_id)
    }

    pub fn get_binding_by_name_raw(&self, name: &str) -> Result<Value, ApiError> {
        self.api.admin_binding_get_by_name(name)
    }

    pub fn create_binding(
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
        self.api.admin_binding_create(
            name,
            server_id,
            deployment_name,
            binding_kind,
            state,
            replicas,
            source,
            meta,
        )
    }

    pub fn update_binding(
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
        self.api.admin_binding_update(
            binding_id,
            server_id,
            deployment_name,
            binding_kind,
            state,
            replicas,
            source,
            meta,
        )
    }

    pub fn delete_binding(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.api.admin_binding_delete(binding_id)
    }

    pub fn reconcile_bindings_now(
        &self,
        node_id: i64,
        rollout_strategy: Option<&str>,
        rollout_batch_size: Option<i64>,
        rollout_max_unavailable: Option<i64>,
        rollout_pause_seconds: Option<f64>,
    ) -> Result<Value, ApiError> {
        self.api.admin_node_bindings_reconcile(
            node_id,
            rollout_strategy,
            rollout_batch_size,
            rollout_max_unavailable,
            rollout_pause_seconds,
        )
    }

    pub fn list_users_raw(
        &self,
        q: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Value, ApiError> {
        self.api.admin_users_list(q, limit, offset)
    }

    pub fn get_user_raw(&self, user_id: i64) -> Result<Value, ApiError> {
        self.api.admin_user_get(user_id)
    }

    pub fn update_user_role(&self, user_id: i64, role: &str) -> Result<Value, ApiError> {
        self.api.admin_user_update_role(user_id, role)
    }

    pub fn list_roles_raw(&self) -> Result<Value, ApiError> {
        self.api.admin_roles_list()
    }

    pub fn get_role_raw(&self, role_id: i64) -> Result<Value, ApiError> {
        self.api.admin_role_get(role_id)
    }

    pub fn get_role_by_name_raw(&self, name: &str) -> Result<Value, ApiError> {
        self.api.admin_role_get_by_name(name)
    }

    pub fn resolve_role_id(&self, role_ref: &str) -> Result<i64, String> {
        let trimmed = role_ref.trim();
        if trimmed.is_empty() {
            return Err("Role id or name is required.".to_string());
        }
        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return trimmed
                .parse::<i64>()
                .map_err(|_| "Invalid role id.".to_string());
        }
        let raw = self
            .get_role_by_name_raw(trimmed)
            .map_err(|e| e.message)?;
        raw.get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| "Invalid role id in response.".to_string())
    }

    pub fn create_role(&self, name: &str, yaml_definition: &str) -> Result<Value, ApiError> {
        self.api.admin_role_create(name, yaml_definition)
    }

    pub fn update_role(
        &self,
        role_id: i64,
        yaml_definition: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api.admin_role_update(role_id, yaml_definition)
    }

    pub fn get_role_binding_raw(&self, binding_id: i64) -> Result<Value, ApiError> {
        self.api.admin_role_binding_get(binding_id)
    }

    pub fn list_role_bindings_raw(&self) -> Result<Value, ApiError> {
        self.api.admin_role_bindings_list()
    }

    pub fn get_role_binding_by_name_raw(&self, name: &str) -> Result<Value, ApiError> {
        self.api.admin_role_binding_get_by_name(name)
    }

    pub fn create_role_binding(
        &self,
        name: &str,
        yaml_definition: &str,
    ) -> Result<Value, ApiError> {
        self.api.admin_role_binding_create(name, yaml_definition)
    }

    pub fn update_role_binding(
        &self,
        binding_id: i64,
        yaml_definition: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api.admin_role_binding_update(binding_id, yaml_definition)
    }

    pub fn list_grants_raw(&self, user_id: Option<i64>) -> Result<Value, ApiError> {
        self.api.admin_grants_list(user_id)
    }

    pub fn create_grant(
        &self,
        user_id: i64,
        server_id: i64,
        protocol_id: i64,
        route: Option<&str>,
        device_limit: Option<i64>,
        note: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_grant_create(user_id, server_id, protocol_id, route, device_limit, note)
    }

    pub fn revoke_grant(&self, grant_id: i64) -> Result<Value, ApiError> {
        self.api.admin_grant_revoke(grant_id)
    }

    pub fn list_node_protocols_raw(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_protocols_list(node_id)
    }

    pub fn list_invites_raw(&self, limit: i64, offset: i64) -> Result<Value, ApiError> {
        self.api.invites_list(limit, offset)
    }

    pub fn create_invite(
        &self,
        duration_days: Option<i64>,
        perpetual: bool,
        note: Option<&str>,
        max_uses: i64,
        expires_in_days: Option<i64>,
    ) -> Result<Value, ApiError> {
        self.api
            .invites_create(duration_days, perpetual, note, max_uses, expires_in_days)
    }

    pub fn claim_invite_local(
        &self,
        token: &str,
        username: &str,
        password: &str,
        device_label: &str,
        platform: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api
            .invites_claim_local(token, username, password, device_label, platform)
    }

    pub fn update_host(&self, pull_only: bool) -> Result<Value, ApiError> {
        self.api.admin_host_update(pull_only)
    }

    pub fn check_cli_updates(
        &self,
        current: &str,
        platform: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api.updates_cli(current, platform)
    }

    pub fn get_agent_logs(
        &self,
        agent_id: i64,
        containers: &[String],
        lines: i64,
    ) -> Result<Value, ApiError> {
        self.api.admin_agent_logs(agent_id, containers, lines)
    }

    pub fn license_snapshot(&self) -> Result<Value, ApiError> {
        self.api.admin_license_snapshot()
    }

    pub fn license_refresh(&self) -> Result<Value, ApiError> {
        self.api.admin_license_refresh()
    }

    pub fn list_binding_instances_raw(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_binding_instances(node_id)
    }

    pub fn get_binding_catalog_raw(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_binding_catalog_get(node_id)
    }

    pub fn set_binding_catalog(
        &self,
        node_id: i64,
        service_codes: &[String],
        append: bool,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_node_binding_catalog_set(node_id, service_codes, append)
    }

    pub fn dry_run_bindings(
        &self,
        node_id: i64,
        rollout_strategy: Option<&str>,
        rollout_batch_size: Option<i64>,
        rollout_max_unavailable: Option<i64>,
        rollout_pause_seconds: Option<f64>,
    ) -> Result<Value, ApiError> {
        self.api.admin_node_bindings_dry_run(
            node_id,
            rollout_strategy,
            rollout_batch_size,
            rollout_max_unavailable,
            rollout_pause_seconds,
        )
    }

    pub fn get_bindings_runtime_raw(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_bindings_get(node_id)
    }

    pub fn set_bindings_runtime(
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
        self.api.admin_node_bindings_set(
            node_id,
            service_codes,
            services,
            enqueue_reconcile,
            rollout_strategy,
            rollout_batch_size,
            rollout_max_unavailable,
            rollout_pause_seconds,
        )
    }

    pub fn bindings_drift(&self, node_id: i64) -> Result<Value, ApiError> {
        self.api.admin_node_bindings_drift(node_id)
    }

    pub fn list_deployment_events_raw(
        &self,
        limit: i64,
        service_code: Option<&str>,
        node_id: Option<i64>,
        event_type: Option<&str>,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_deployment_events(limit, service_code, node_id, event_type)
    }

    pub fn export_deployments_state(&self) -> Result<Value, ApiError> {
        self.api.admin_deployments_state_export()
    }

    pub fn import_deployments_state(
        &self,
        services: Value,
        revisions: Value,
        instances: Value,
        merge: bool,
    ) -> Result<Value, ApiError> {
        self.api
            .admin_deployments_state_import(services, revisions, instances, merge)
    }
}
