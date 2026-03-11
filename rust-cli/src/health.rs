use std::io;

use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;

use crate::config::{load_config, resolve_license_api_url};
use crate::registry::load_registry;
use crate::HealthArgsCommand;
use saharo_sdk::{
    cli_protocol, cli_version, evaluate_cli_compatibility, parse_version_info, HealthFacade,
};

#[derive(Debug, Serialize)]
struct HealthResult {
    checked_at: String,
    hub: HubResult,
    license: LicenseResult,
}

#[derive(Debug, Serialize)]
struct HubResult {
    ok: Option<bool>,
    base_url: Option<String>,
    cli_version: String,
    cli_protocol: i64,
    api_version: Option<String>,
    api_protocol: Option<i64>,
    supported_cli_range: Option<String>,
    endpoint: Option<String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LicenseResult {
    ok: Option<bool>,
    license_api_url: Option<String>,
    entitlements: Option<Value>,
    updates: Option<Value>,
    endpoints: Option<Value>,
    errors: Vec<String>,
}

pub fn handle_health(args: HealthArgsCommand) -> io::Result<i32> {
    health(args)
}

fn health(args: HealthArgsCommand) -> io::Result<i32> {
    let cfg = load_config()?;
    let base_url = cfg.base_url.trim().to_string();
    let current_version = cli_version();
    let current_protocol = cli_protocol();

    let mut hub = HubResult {
        ok: None,
        base_url: if base_url.is_empty() {
            None
        } else {
            Some(base_url.clone())
        },
        cli_version: current_version.clone(),
        cli_protocol: current_protocol,
        api_version: None,
        api_protocol: None,
        supported_cli_range: None,
        endpoint: None,
        errors: Vec::new(),
    };

    if base_url.is_empty() {
        hub.errors.push("base_url_not_configured".to_string());
        emit(
            "warn",
            "Base URL is not configured. Run `saharoctl settings init --base-url ...` first.",
            args.json_output,
        );
    } else {
        match HealthFacade::new(&base_url).and_then(|h| h.hub_version()) {
            Ok(data) => {
                let version_info = parse_version_info(&data);
                let compatibility =
                    evaluate_cli_compatibility(&current_version, current_protocol, &version_info);

                hub.api_protocol = version_info.api_protocol;
                hub.supported_cli_range = version_info.supported_cli_range.clone();
                hub.api_version = version_info.api_version.clone();
                if args.verbose {
                    hub.endpoint = Some(format!("{}/version", base_url.trim_end_matches('/')));
                }

                let mut incompatible = false;
                if !compatibility.protocol_compatible {
                    if let Some(p) = version_info.api_protocol {
                        incompatible = true;
                        hub.errors.push("cli_protocol_incompatible".to_string());
                        emit(
                            "err",
                            &format!(
                                "Incompatible CLI protocol: requires {p}, current {current_protocol}."
                            ),
                            args.json_output,
                        );
                    }
                }
                if !compatibility.version_compatible {
                    if let Some(range) = version_info.supported_cli_range.as_deref() {
                        incompatible = true;
                        hub.errors.push("cli_version_incompatible".to_string());
                        emit(
                            "err",
                            &format!(
                                "Incompatible CLI version: requires {range}, current {current_version}."
                            ),
                            args.json_output,
                        );
                    }
                }
                if !incompatible {
                    emit(
                        "ok",
                        "Hub API compatibility check passed.",
                        args.json_output,
                    );
                }
                if args.verbose && !args.json_output {
                    emit(
                        "info",
                        &format!(
                            "Hub /version: api_version={} api_protocol={} supported_cli_range={}",
                            version_info.api_version.as_deref().unwrap_or("-"),
                            version_info
                                .api_protocol
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            version_info.supported_cli_range.as_deref().unwrap_or("-")
                        ),
                        args.json_output,
                    );
                }
                hub.ok = Some(!incompatible);
            }
            Err(err) => {
                hub.errors.push("hub_version_request_failed".to_string());
                emit(
                    "warn",
                    &format!("Hub /version check failed: {}", err.message),
                    args.json_output,
                );
                hub.ok = Some(false);
            }
        }
    }

    let license_url = resolve_license_api_url(&cfg);
    let mut license = LicenseResult {
        ok: None,
        license_api_url: if license_url.is_empty() {
            None
        } else {
            Some(license_url.clone())
        },
        entitlements: None,
        updates: None,
        endpoints: None,
        errors: Vec::new(),
    };
    let registry = load_registry()?;
    let license_key = registry.and_then(|r| r.license_key);
    if license_key.is_none() {
        license.errors.push("license_key_missing".to_string());
        emit(
            "warn",
            "License key not found in registry store; skipping license checks.",
            args.json_output,
        );
        license.ok = Some(false);
    } else {
        let lk = license_key.unwrap_or_default();
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http client error: {e}")))?;

        let entitlements_endpoint =
            format!("{}/v1/entitlements", license_url.trim_end_matches('/'));
        match http
            .get(&entitlements_endpoint)
            .header("X-License-Key", &lk)
            .send()
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    let parsed = resp.json::<Value>().unwrap_or(Value::Null);
                    license.entitlements = Some(serde_json::json!({
                        "allowed_major": parsed.get("allowed_major").cloned().unwrap_or(Value::Null),
                        "resolved_versions": parsed.get("resolved_versions").cloned().unwrap_or(serde_json::json!({})),
                        "strategy": parsed.get("strategy").cloned().unwrap_or(Value::Null),
                        "source": parsed.get("source").cloned().unwrap_or(Value::Null),
                    }));
                    emit("ok", "License entitlements check passed.", args.json_output);
                } else {
                    license.errors.push(format!("entitlements_http_{status}"));
                    emit(
                        "warn",
                        &format!("License API error ({status})."),
                        args.json_output,
                    );
                }
            }
            Err(e) => {
                license
                    .errors
                    .push("entitlements_request_failed".to_string());
                emit(
                    "warn",
                    &format!("License API check failed: {e}"),
                    args.json_output,
                );
            }
        }

        let updates_endpoint = format!("{}/v1/updates/cli", license_url.trim_end_matches('/'));
        let platform = platform_id();
        match http
            .get(&updates_endpoint)
            .query(&[
                ("current", current_version.as_str()),
                ("platform", platform.as_str()),
            ])
            .header("X-License-Key", &lk)
            .send()
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    let parsed = resp.json::<Value>().unwrap_or(Value::Null);
                    let updates = serde_json::json!({
                        "update_available": parsed.get("update_available").cloned().unwrap_or(Value::Null),
                        "current": parsed.get("current").cloned().unwrap_or(Value::Null),
                        "latest": parsed.get("latest").cloned().unwrap_or(Value::Null),
                    });
                    if updates
                        .get("update_available")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        emit(
                            "warn",
                            &format!(
                                "CLI update available: {} (current {}).",
                                updates
                                    .get("latest")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("-"),
                                updates
                                    .get("current")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("-")
                            ),
                            args.json_output,
                        );
                    } else {
                        emit("ok", "CLI is up to date.", args.json_output);
                    }
                    license.updates = Some(updates);
                } else {
                    license.errors.push(format!("updates_http_{status}"));
                    emit(
                        "info",
                        &format!("Update check skipped ({status})."),
                        args.json_output,
                    );
                }
            }
            Err(e) => {
                license.errors.push("updates_request_failed".to_string());
                emit(
                    "warn",
                    &format!("Update check failed: {e}"),
                    args.json_output,
                );
            }
        }

        if args.verbose {
            license.endpoints = Some(serde_json::json!({
                "entitlements": entitlements_endpoint,
                "updates": updates_endpoint
            }));
        }
        license.ok = Some(license.errors.is_empty());
    }

    let result = HealthResult {
        checked_at: now_rfc3339(),
        hub,
        license,
    };

    if args.json_output {
        let payload = serde_json::to_string_pretty(&result)
            .unwrap_or_else(|_| "{\"error\":\"serialization failed\"}".to_string());
        println!("{payload}");
    }

    Ok(0)
}

fn platform_id() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}

fn emit(level: &str, msg: &str, json_mode: bool) {
    if json_mode {
        return;
    }
    match level {
        "ok" => crate::console::ok(msg),
        "warn" => crate::console::warn(msg),
        "err" => crate::console::err(msg),
        _ => crate::console::info(msg),
    }
}
