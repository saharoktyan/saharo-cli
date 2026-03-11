use serde_json::Value;

use crate::models::{WhoamiAccessEntry, WhoamiInfo};
use crate::{ApiClient, ApiError};

pub struct AuthFacade<'a> {
    api: &'a ApiClient,
}

impl<'a> AuthFacade<'a> {
    pub fn new(api: &'a ApiClient) -> Self {
        Self { api }
    }

    pub fn login_password(&self, username: &str, password: &str) -> Result<String, ApiError> {
        self.api.auth_login(username, password)
    }

    pub fn login_api_key(&self, api_key: &str) -> Result<String, ApiError> {
        self.api.auth_api_key(api_key)
    }

    pub fn whoami(&self) -> Result<Value, ApiError> {
        self.api.me()
    }

    pub fn register_via_invite(
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
}

pub fn parse_whoami_info(me: &Value) -> WhoamiInfo {
    let username = me
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let role = me
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();

    let sub = me.get("subscription").and_then(|v| v.as_object());
    let mut ends_at: Option<String> = None;
    let subscription_display = if let Some(sub_obj) = sub {
        let status = sub_obj
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("active")
            .to_string();
        ends_at = sub_obj
            .get("ends_at")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        let days_left = sub_obj.get("days_left").and_then(|v| v.as_i64());

        let mut details: Vec<String> = Vec::new();
        if let Some(days) = days_left {
            details.push(format!("{days} days left"));
        } else if ends_at.is_none() {
            details.push("perpetual".to_string());
        }

        if details.is_empty() {
            status
        } else {
            format!("{} ({})", status, details.join(", "))
        }
    } else {
        "none".to_string()
    };

    let mut access_entries: Vec<WhoamiAccessEntry> = Vec::new();
    if let Some(access_arr) = me.get("access").and_then(|v| v.as_array()) {
        for server in access_arr {
            let server_id = server.get("id").and_then(|v| v.as_i64());
            let server_name = server.get("name").and_then(|v| v.as_str());
            let server_label = if let Some(name) = server_name {
                name.to_string()
            } else if let Some(id) = server_id {
                format!("id={id}")
            } else {
                "-".to_string()
            };
            if let Some(protocols) = server.get("protocols").and_then(|v| v.as_array()) {
                for protocol in protocols {
                    let protocol_key = protocol
                        .get("key")
                        .and_then(|v| v.as_str())
                        .or_else(|| protocol.get("name").and_then(|v| v.as_str()))
                        .unwrap_or("-")
                        .to_string();
                    let status = protocol
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("active")
                        .to_string();
                    let expires = protocol
                        .get("expires_at")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_string())
                        .or_else(|| ends_at.clone())
                        .unwrap_or_else(|| "—".to_string());
                    access_entries.push(WhoamiAccessEntry {
                        server_label: server_label.clone(),
                        protocol_key,
                        status,
                        expires,
                    });
                }
            }
        }
    }
    access_entries.sort_by(|a, b| {
        (a.server_label.as_str(), a.protocol_key.as_str())
            .cmp(&(b.server_label.as_str(), b.protocol_key.as_str()))
    });

    WhoamiInfo {
        username,
        role,
        subscription_display,
        access_entries,
    }
}
