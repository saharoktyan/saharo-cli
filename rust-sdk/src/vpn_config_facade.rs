use std::path::Path;

use crate::access_facade::{
    build_credentials_ensure_request, resolve_access_target_from_me, AccessFacade,
};
use crate::awg::{build_awg_conf, build_awg_uri};
use crate::awg_keys::load_or_create_awg_keypair;
use crate::models::CredentialsEnsureInput;
use crate::{ApiClient, ApiError};

pub struct VpnConfigFacade<'a> {
    api: &'a ApiClient,
}

#[derive(Debug, Clone)]
pub struct VpnConfigRequest {
    pub server: Option<String>,
    pub protocol: Option<String>,
    pub route: Option<String>,
    pub device_label: String,
    pub awg_conf: bool,
    pub keys_base_dir: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub struct VpnConfigResult {
    pub server_id: i64,
    pub protocol_key: String,
    pub content: String,
}

#[derive(Debug)]
pub struct VpnConfigError {
    pub status_code: Option<u16>,
    pub message: String,
    pub hint: Option<String>,
}

impl<'a> VpnConfigFacade<'a> {
    pub fn new(api: &'a ApiClient) -> Self {
        Self { api }
    }

    pub fn build_content(&self, req: &VpnConfigRequest) -> Result<VpnConfigResult, VpnConfigError> {
        let access = AccessFacade::new(self.api);
        let me = access.me().map_err(api_err)?;

        let (server_id, protocol_key) =
            resolve_access_target_from_me(&me, req.server.as_deref(), req.protocol.as_deref())
                .map_err(|msg| VpnConfigError {
                    status_code: None,
                    hint: if msg.contains("No servers or protocols are available") {
                        Some("Please ask your admin to grant you access.".to_string())
                    } else {
                        None
                    },
                    message: msg,
                })?;

        let mut client_public_key: Option<String> = None;
        let mut awg_keypair: Option<crate::AwgKeypair> = None;
        if protocol_key == "awg" {
            let pair = load_or_create_awg_keypair(
                req.keys_base_dir.as_path(),
                server_id,
                req.device_label.as_str(),
            )
            .map_err(|e| VpnConfigError {
                status_code: None,
                message: e,
                hint: None,
            })?;
            client_public_key = Some(pair.public_key.clone());
            awg_keypair = Some(pair);
        }

        let ensure_req = build_credentials_ensure_request(CredentialsEnsureInput {
            server_id,
            protocol: protocol_key.clone(),
            device_label: req.device_label.clone(),
            route: req.route.clone(),
            client_public_key,
        })
        .map_err(|msg| VpnConfigError {
            status_code: None,
            message: msg,
            hint: None,
        })?;

        let data = access
            .ensure_credentials_request(&ensure_req)
            .map_err(api_err)?;
        let config = data.get("config").cloned().unwrap_or_default();
        if !config.is_object() {
            return Err(VpnConfigError {
                status_code: None,
                message: "Unexpected response from server.".to_string(),
                hint: None,
            });
        }

        let content = if protocol_key == "awg" {
            let wg = config.get("wg").cloned().unwrap_or_default();
            if !wg.is_object() {
                return Err(VpnConfigError {
                    status_code: None,
                    message: "Config payload missing WireGuard parts.".to_string(),
                    hint: None,
                });
            }
            let pair = awg_keypair.expect("awg keypair");
            if req.awg_conf {
                build_awg_conf(&pair.private_key, &wg).map_err(simple_err)?
            } else {
                build_awg_uri(
                    &pair.private_key,
                    &pair.public_key,
                    &wg,
                    &format!("{server_id}-{}", req.device_label),
                )
                .map_err(simple_err)?
            }
        } else {
            config
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        if content.is_empty() {
            return Err(VpnConfigError {
                status_code: None,
                message: "Config payload missing expected content.".to_string(),
                hint: None,
            });
        }

        Ok(VpnConfigResult {
            server_id,
            protocol_key,
            content,
        })
    }
}

fn api_err(err: ApiError) -> VpnConfigError {
    VpnConfigError {
        status_code: Some(err.status_code),
        message: err.message,
        hint: None,
    }
}

fn simple_err(message: String) -> VpnConfigError {
    VpnConfigError {
        status_code: None,
        message,
        hint: None,
    }
}

pub fn awg_output_path(
    base_dir: &Path,
    server_id: i64,
    device_label: &str,
    awg_conf: bool,
) -> std::path::PathBuf {
    let name = if awg_conf {
        "config.conf"
    } else {
        "config.uri"
    };
    crate::awg_key_dir(base_dir, server_id, device_label).join(name)
}
