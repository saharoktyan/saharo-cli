use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::models::{JobDetails, JobSummary, JoinRequestInput, NodeDetails, NodeSummary};
use crate::{ApiClient, ApiError, JoinNodeRequest};

pub struct WaitJobResult {
    pub job: Value,
    pub timed_out: bool,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct JoinExecutionOptions {
    pub wait: bool,
    pub timeout: Duration,
    pub interval: Duration,
}

pub struct JoinExecutionResult {
    pub response: Value,
    pub job_id: Option<i64>,
    pub job_status: Option<String>,
    pub timed_out: bool,
}

pub fn format_admin_error(err: &ApiError, action: &str) -> String {
    if err.status_code == 401 || err.status_code == 403 {
        "Unauthorized. Admin access is required.".to_string()
    } else {
        format!("Failed to {action}: {}", err.message)
    }
}

pub fn format_join_error(err: &ApiError) -> String {
    if err.status_code == 404 {
        "`join` endpoint is missing on Host API. Migrate API to nodes model first.".to_string()
    } else if err.status_code == 501 {
        "Host API exposes /admin/nodes/join but join orchestration is not implemented in this build yet.".to_string()
    } else {
        format_admin_error(err, "join node")
    }
}

pub fn build_join_request(input: JoinRequestInput) -> Result<JoinNodeRequest, String> {
    let name = input.name.trim().to_string();
    let host = input.host.trim().to_string();
    if name.is_empty() || host.is_empty() {
        return Err("name and host are required".to_string());
    }

    let note = input
        .note
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let ssh_target = input
        .ssh_target
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let ssh_key = input
        .ssh_key
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let ssh_password = input
        .ssh_password
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let local_path = input
        .local_path
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let sudo_password = input
        .sudo_password
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let ssh_password_prompt = input.ssh_password_prompt;
    let provision_mode = input
        .provision_mode
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    let public_api_base = input
        .public_api_base
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty());
    if let Some(mode) = provision_mode.as_deref() {
        if !matches!(mode, "auto" | "client" | "server") {
            return Err("provision_mode must be one of: auto, client, server".to_string());
        }
    }

    if input.local && (ssh_target.is_some() || ssh_key.is_some() || ssh_password_prompt) {
        return Err("cannot combine local mode with ssh options".to_string());
    }

    let port = input.ssh_port.max(1);
    let final_ssh_target = if input.local {
        None
    } else {
        Some(ssh_target.unwrap_or_else(|| host.clone()))
    };

    Ok(JoinNodeRequest {
        name,
        host,
        note,
        ssh_target: final_ssh_target,
        port,
        sudo: input.sudo,
        local: input.local,
        local_path,
        ssh_key_provided: if ssh_key.is_some() { Some(true) } else { None },
        ssh_password_prompt: if ssh_password_prompt {
            Some(true)
        } else {
            None
        },
        ssh_password,
        sudo_password_prompt: if input.sudo_password_prompt {
            Some(true)
        } else {
            None
        },
        sudo_password,
        provision_mode,
        public_api_base,
        include_bootstrap: input.include_bootstrap,
    })
}

pub fn resolve_node_id(client: &ApiClient, node_ref: &str) -> Result<i64, String> {
    if node_ref.trim().chars().all(|c| c.is_ascii_digit()) {
        return node_ref
            .trim()
            .parse::<i64>()
            .map_err(|_| "Invalid node id.".to_string());
    }
    let data = client
        .admin_nodes_list(Some(node_ref), Some(50), Some(0))
        .map_err(|e| e.message)?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let matches = items
        .iter()
        .filter(|s| s.get("name").and_then(|v| v.as_str()) == Some(node_ref))
        .cloned()
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(format!("Node '{}' not found.", node_ref));
    }
    if matches.len() > 1 {
        let ids = matches
            .iter()
            .filter_map(|s| {
                s.get("id")
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string())
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("Multiple nodes matched '{}': {}", node_ref, ids));
    }
    matches[0]
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Invalid node id in response.".to_string())
}

pub fn resolve_job_node_id_text(job: &Value) -> String {
    for key in ["node_id", "server_id"] {
        if let Some(v) = job.get(key) {
            return value_to_text(v);
        }
    }
    if let Some(payload) = job.get("payload").and_then(|v| v.as_object()) {
        for key in ["node_id", "server_id"] {
            if let Some(v) = payload.get(key) {
                return value_to_text(v);
            }
        }
    }
    "-".to_string()
}

pub fn wait_job<F>(
    client: &ApiClient,
    job_id: i64,
    timeout: Duration,
    interval: Duration,
    mut on_status_change: F,
) -> Result<WaitJobResult, ApiError>
where
    F: FnMut(i64, &str, Duration),
{
    let started = Instant::now();
    let deadline = started + timeout;
    let mut last_status = String::new();

    loop {
        let job = client.admin_job_get(job_id)?;
        let status = job
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        if status != last_status {
            on_status_change(job_id, status.as_str(), started.elapsed());
            last_status = status.clone();
        }

        if matches!(status.as_str(), "succeeded" | "failed" | "cancelled") {
            return Ok(WaitJobResult {
                job,
                timed_out: false,
                elapsed: started.elapsed(),
            });
        }

        if Instant::now() >= deadline {
            return Ok(WaitJobResult {
                job,
                timed_out: true,
                elapsed: started.elapsed(),
            });
        }

        thread::sleep(interval);
    }
}

pub fn parse_nodes_list(data: &Value) -> Vec<NodeSummary> {
    data.get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| NodeSummary {
            id: v.get("id").and_then(|x| x.as_i64()),
            name: v
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            host: v
                .get("public_host")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            status: v
                .get("status")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            missed_heartbeats: v.get("missed_heartbeats").and_then(|x| x.as_i64()),
        })
        .collect()
}

pub fn parse_jobs_list(data: &Value) -> Vec<JobSummary> {
    data.get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| JobSummary {
            id: v.get("id").and_then(|x| x.as_i64()),
            job_type: v
                .get("type")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            status: v
                .get("status")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            agent_id: v.get("agent_id").and_then(|x| x.as_i64()),
            node_id: {
                let id = resolve_job_node_id_text(&v);
                if id == "-" {
                    None
                } else {
                    Some(id)
                }
            },
            created_at: v
                .get("created_at")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            started_at: v
                .get("started_at")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            finished_at: v
                .get("finished_at")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        })
        .collect()
}

pub fn execute_join<F>(
    client: &ApiClient,
    payload: &JoinNodeRequest,
    options: JoinExecutionOptions,
    on_status_change: F,
) -> Result<JoinExecutionResult, ApiError>
where
    F: FnMut(i64, &str, Duration),
{
    let response = client.join_node(payload)?;
    let job_id = response.get("job_id").and_then(|v| v.as_i64());

    if !options.wait || job_id.is_none() {
        return Ok(JoinExecutionResult {
            response,
            job_id,
            job_status: None,
            timed_out: false,
        });
    }

    let wait_result = wait_job(
        client,
        job_id.unwrap_or_default(),
        options.timeout,
        options.interval,
        on_status_change,
    )?;
    let job_status = wait_result
        .job
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(JoinExecutionResult {
        response,
        job_id,
        job_status,
        timed_out: wait_result.timed_out,
    })
}

pub fn parse_node_details(data: &Value) -> NodeDetails {
    let mut extras: BTreeMap<String, Value> = data
        .as_object()
        .cloned()
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();
    for k in [
        "id",
        "name",
        "public_host",
        "status",
        "missed_heartbeats",
        "note",
        "created_at",
        "updated_at",
    ] {
        extras.remove(k);
    }
    NodeDetails {
        id: data.get("id").and_then(|x| x.as_i64()),
        name: data
            .get("name")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        host: data
            .get("public_host")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        status: data
            .get("status")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        missed_heartbeats: data.get("missed_heartbeats").and_then(|x| x.as_i64()),
        note: data
            .get("note")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        created_at: data
            .get("created_at")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        updated_at: data
            .get("updated_at")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        extras,
    }
}

pub fn parse_job_details(data: &Value) -> JobDetails {
    let mut extras: BTreeMap<String, Value> = data
        .as_object()
        .cloned()
        .map(|m| m.into_iter().collect())
        .unwrap_or_default();
    for k in [
        "id",
        "type",
        "status",
        "agent_id",
        "node_id",
        "server_id",
        "created_at",
        "started_at",
        "finished_at",
        "error",
        "payload",
        "result",
    ] {
        extras.remove(k);
    }
    JobDetails {
        id: data.get("id").and_then(|x| x.as_i64()),
        job_type: data
            .get("type")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        status: data
            .get("status")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        agent_id: data.get("agent_id").and_then(|x| x.as_i64()),
        node_id: {
            let id = resolve_job_node_id_text(data);
            if id == "-" {
                None
            } else {
                Some(id)
            }
        },
        created_at: data
            .get("created_at")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        started_at: data
            .get("started_at")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        finished_at: data
            .get("finished_at")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        error: data
            .get("error")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        payload: data.get("payload").cloned(),
        result: data.get("result").cloned(),
        extras,
    }
}

fn value_to_text(v: &Value) -> String {
    match v {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}
