use serde_json::Value;

use crate::models::{CredentialsEnsureInput, CredentialsEnsureRequest};
use crate::{ApiClient, ApiError};

pub struct AccessFacade<'a> {
    api: &'a ApiClient,
}

impl<'a> AccessFacade<'a> {
    pub fn new(api: &'a ApiClient) -> Self {
        Self { api }
    }

    pub fn me(&self) -> Result<Value, ApiError> {
        self.api.me()
    }

    pub fn ensure_credentials(&self, payload: Value) -> Result<Value, ApiError> {
        self.api.credentials_ensure(payload)
    }

    pub fn ensure_credentials_request(
        &self,
        request: &CredentialsEnsureRequest,
    ) -> Result<Value, ApiError> {
        let payload = serde_json::to_value(request).map_err(|e| ApiError {
            status_code: 0,
            message: format!("failed to serialize credentials request: {e}"),
            details: None,
        })?;
        self.api.credentials_ensure(payload)
    }
}

pub fn build_credentials_ensure_request(
    input: CredentialsEnsureInput,
) -> Result<CredentialsEnsureRequest, String> {
    let protocol = input.protocol.trim().to_lowercase();
    if protocol.is_empty() {
        return Err("protocol is required".to_string());
    }
    let device_label = input.device_label.trim().to_string();
    if device_label.is_empty() {
        return Err("device label is required".to_string());
    }
    let route = input
        .route
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    if let Some(r) = route.as_deref() {
        if r != "tcp" && r != "xhttp" {
            return Err("route must be one of: tcp, xhttp".to_string());
        }
    }
    let client_public_key = input
        .client_public_key
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(CredentialsEnsureRequest {
        server_id: input.server_id,
        protocol,
        device_label,
        route,
        client_public_key,
    })
}

pub fn resolve_access_target_from_me(
    me: &Value,
    server_input: Option<&str>,
    protocol_input: Option<&str>,
) -> Result<(i64, String), String> {
    let access = me
        .get("access")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if access.is_empty() {
        return Err("No servers or protocols are available for your account.".to_string());
    }

    let server_ref = resolve_server_ref(server_input, &access)?;
    let protocol_ref = resolve_protocol_ref(protocol_input, &access, &server_ref)?;
    resolve_access_target(&access, &server_ref, &protocol_ref)
}

fn resolve_server_ref(server_input: Option<&str>, access: &[Value]) -> Result<String, String> {
    if let Some(s) = server_input {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let mut unique = access
        .iter()
        .filter_map(|v| {
            v.get("id")
                .and_then(|x| x.as_i64())
                .map(|id| id.to_string())
        })
        .collect::<Vec<_>>();
    unique.sort();
    unique.dedup();
    if unique.len() == 1 {
        return Ok(unique[0].clone());
    }
    let options = access
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(|x| x.as_i64());
            let name = v.get("name").and_then(|x| x.as_str());
            match (name, id) {
                (Some(n), Some(i)) => Some(format!("{n} (id={i})")),
                (Some(n), None) => Some(n.to_string()),
                (None, Some(i)) => Some(format!("id={i}")),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    if options.is_empty() {
        Err("Server is required when multiple servers are available.".to_string())
    } else {
        Err(format!(
            "Server is required when multiple servers are available. Available servers: {options}"
        ))
    }
}

fn resolve_protocol_ref(
    protocol_input: Option<&str>,
    access: &[Value],
    server: &str,
) -> Result<String, String> {
    if let Some(p) = protocol_input {
        let trimmed = p.trim().to_lowercase();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let server_entry = access.iter().find(|a| {
        a.get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string() == server)
            .unwrap_or(false)
            || a.get("name")
                .and_then(|v| v.as_str())
                .map(|n| n == server)
                .unwrap_or(false)
    });
    let protocols = server_entry
        .and_then(|s| s.get("protocols"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut unique = protocols
        .iter()
        .filter_map(|p| {
            p.get("key")
                .and_then(|v| v.as_str())
                .or_else(|| p.get("name").and_then(|v| v.as_str()))
                .map(|s| s.to_lowercase())
        })
        .collect::<Vec<_>>();
    unique.sort();
    unique.dedup();
    if unique.len() == 1 {
        return Ok(unique[0].clone());
    }
    if unique.is_empty() {
        Err("Protocol is required when multiple protocols are available.".to_string())
    } else {
        Err(format!(
            "Protocol is required when multiple protocols are available. Available protocols: {}",
            unique.join(", ")
        ))
    }
}

fn resolve_access_target(
    access: &[Value],
    server: &str,
    protocol: &str,
) -> Result<(i64, String), String> {
    let server_input = server.trim();
    if server_input.is_empty() {
        return Err("Server is required.".to_string());
    }
    let protocol_input = protocol.trim().to_lowercase();

    let server_match = if server_input.chars().all(|c| c.is_ascii_digit()) {
        let sid: i64 = server_input.parse().unwrap_or(-1);
        access
            .iter()
            .find(|item| item.get("id").and_then(|v| v.as_i64()) == Some(sid))
    } else {
        access.iter().find(|item| {
            item.get("name")
                .and_then(|v| v.as_str())
                .map(|n| n.eq_ignore_ascii_case(server_input))
                .unwrap_or(false)
        })
    };

    let Some(server_match) = server_match else {
        let options = access
            .iter()
            .filter_map(|item| {
                item.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        item.get("id")
                            .and_then(|v| v.as_i64())
                            .map(|id| format!("id={id}"))
                    })
            })
            .collect::<Vec<_>>();
        let mut msg = format!("Server '{server_input}' is not available for this account.");
        if !options.is_empty() {
            msg.push_str(&format!(" Available servers: {}", options.join(", ")));
        }
        return Err(msg);
    };

    let protocols = server_match
        .get("protocols")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let protocol_match = protocols.iter().find(|item| {
        let key = item
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        key == protocol_input || name == protocol_input
    });

    let Some(protocol_match) = protocol_match else {
        let choices = protocols
            .iter()
            .filter_map(|item| {
                item.get("key")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("name").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
            })
            .collect::<Vec<_>>();
        let mut msg =
            format!("Protocol '{protocol_input}' is not available for server '{server_input}'.");
        if !choices.is_empty() {
            msg.push_str(&format!(" Available protocols: {}", choices.join(", ")));
        }
        return Err(msg);
    };

    let server_id = server_match
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Selected server has invalid id.".to_string())?;
    let protocol_key = protocol_match
        .get("key")
        .or_else(|| protocol_match.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(&protocol_input)
        .to_lowercase();

    Ok((server_id, protocol_key))
}
