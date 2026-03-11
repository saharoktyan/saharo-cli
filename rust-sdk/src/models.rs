use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct JoinNodeRequest {
    pub name: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ssh")]
    pub ssh_target: Option<String>,
    pub port: i64,
    pub sudo: bool,
    pub local: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_provided: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_password_prompt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_password_prompt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sudo_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provision_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_api_base: Option<String>,
    pub include_bootstrap: bool,
}

#[derive(Debug, Clone)]
pub struct JoinRequestInput {
    pub name: String,
    pub host: String,
    pub note: Option<String>,
    pub ssh_target: Option<String>,
    pub ssh_port: i64,
    pub ssh_key: Option<String>,
    pub ssh_password_prompt: bool,
    pub ssh_password: Option<String>,
    pub sudo: bool,
    pub sudo_password_prompt: bool,
    pub sudo_password: Option<String>,
    pub local: bool,
    pub local_path: Option<String>,
    pub provision_mode: Option<String>,
    pub public_api_base: Option<String>,
    pub include_bootstrap: bool,
}

#[derive(Debug, Clone)]
pub struct NodeSummary {
    pub id: Option<i64>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub status: Option<String>,
    pub missed_heartbeats: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct JobSummary {
    pub id: Option<i64>,
    pub job_type: Option<String>,
    pub status: Option<String>,
    pub agent_id: Option<i64>,
    pub node_id: Option<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeDetails {
    pub id: Option<i64>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub status: Option<String>,
    pub missed_heartbeats: Option<i64>,
    pub note: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub extras: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobDetails {
    pub id: Option<i64>,
    #[serde(rename = "type")]
    pub job_type: Option<String>,
    pub status: Option<String>,
    pub agent_id: Option<i64>,
    pub node_id: Option<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub payload: Option<Value>,
    pub result: Option<Value>,
    #[serde(flatten)]
    pub extras: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct WhoamiAccessEntry {
    pub server_label: String,
    pub protocol_key: String,
    pub status: String,
    pub expires: String,
}

#[derive(Debug, Clone)]
pub struct WhoamiInfo {
    pub username: String,
    pub role: String,
    pub subscription_display: String,
    pub access_entries: Vec<WhoamiAccessEntry>,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub api_version: Option<String>,
    pub api_protocol: Option<i64>,
    pub supported_cli_range: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CliCompatibility {
    pub protocol_compatible: bool,
    pub version_compatible: bool,
    pub is_compatible: bool,
}

#[derive(Debug, Clone)]
pub struct CredentialsEnsureInput {
    pub server_id: i64,
    pub protocol: String,
    pub device_label: String,
    pub route: Option<String>,
    pub client_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialsEnsureRequest {
    pub server_id: i64,
    pub protocol: String,
    pub device_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
}
