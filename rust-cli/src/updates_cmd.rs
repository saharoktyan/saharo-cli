use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use directories::ProjectDirs;
use reqwest::blocking::Client;
use reqwest::Url;
use saharo_sdk::{cli_version, AdminFacade, ApiClient, ApiError};
use semver::Version;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{load_config, normalize_base_url, resolve_license_api_url};
use crate::{GetReleaseArgs, GetReleasesArgs, UpdateCliArgs, UpdateHostArgs, UpdateNodesArgs};

pub fn get_releases(args: GetReleasesArgs) -> io::Result<i32> {
    let data = fetch_releases(
        args.license_api_url.as_deref(),
        args.channel.as_str(),
        args.limit.max(1),
    )?;
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    let rows = data.as_array().cloned().unwrap_or_default();
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["version", "channel", "created_at"]);
    for row in rows {
        table.add_row(vec![
            value_text(row.get("version")),
            value_text(row.get("channel")),
            value_text(row.get("created_at").or_else(|| row.get("published_at"))),
        ]);
    }
    println!("{table}");
    Ok(0)
}

pub fn get_release(args: GetReleaseArgs, describe: bool) -> io::Result<i32> {
    let release_ref = match args.version {
        Some(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_string(),
        _ => {
            crate::console::err("Release version is required.");
            return Ok(2);
        }
    };
    let data = fetch_releases(
        args.license_api_url.as_deref(),
        args.channel.as_str(),
        args.limit.max(1),
    )?;
    let rows = data.as_array().cloned().unwrap_or_default();
    let item = rows.into_iter().find(|row| {
        row.get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().trim_start_matches('v') == release_ref)
            .unwrap_or(false)
    });
    let Some(release) = item else {
        crate::console::err(&format!("Release '{}' not found.", release_ref));
        return Ok(2);
    };
    if args.json_out {
        print_json(&release);
        return Ok(0);
    }
    if describe {
        crate::pretty_kv::print_value(&release);
    } else {
        let out = json!({
            "version": release.get("version").cloned().unwrap_or(Value::Null),
            "channel": release.get("channel").cloned().unwrap_or(Value::Null),
            "created_at": release
                .get("created_at")
                .cloned()
                .or_else(|| release.get("published_at").cloned())
                .unwrap_or(Value::Null),
        });
        crate::pretty_kv::print_value(&out);
    }
    Ok(0)
}

pub fn update_cli(args: UpdateCliArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    let base = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let admin = AdminFacade::new(&client);
    let current = args.current.unwrap_or_else(cli_version);
    let platform = args.platform.unwrap_or_else(platform_id);
    let data = match admin.check_cli_updates(current.as_str(), Some(platform.as_str())) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "check cli updates"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }

    let update_available = data
        .get("update_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let latest = data.get("latest").and_then(|v| v.as_str()).unwrap_or("-");
    let current_resp = data
        .get("current")
        .and_then(|v| v.as_str())
        .unwrap_or(current.as_str());
    if !update_available {
        crate::console::ok(&format!("CLI is up to date ({current_resp})."));
        return Ok(0);
    }

    crate::console::warn(&format!("CLI update available: {current_resp} -> {latest}"));
    let Some(download_url) = data.get("download_url").and_then(|v| v.as_str()) else {
        crate::console::err("No download URL in Host API response.");
        return Ok(2);
    };
    if args.check_only {
        crate::console::info(&format!("Download URL: {download_url}"));
        return Ok(0);
    }

    #[cfg(not(unix))]
    {
        crate::console::warn("Automatic atomic self-update is currently supported only on Unix.");
        crate::console::info(&format!("Download URL: {download_url}"));
        return Ok(0);
    }

    #[cfg(unix)]
    {
        let target = std::env::current_exe().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("cannot resolve current executable: {e}"),
            )
        })?;
        if !is_target_writable(&target) {
            crate::console::err(&format!(
                "No write permission for '{}'. Run with proper privileges or replace manually.",
                target.display()
            ));
            return Ok(2);
        }
        let cache_dir = update_cache_dir()?;
        let pending_path = cache_dir.join("saharoctl.pending");
        let helper_path = cache_dir.join("apply_update.sh");
        let expected_sha = data
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());

        crate::console::info(&format!("Downloading {download_url} ..."));
        let actual_sha = download_file(download_url, &pending_path)?;
        if let Some(expected) = expected_sha {
            if actual_sha.to_ascii_lowercase() != expected {
                let _ = fs::remove_file(&pending_path);
                crate::console::err("Checksum mismatch for downloaded CLI binary.");
                return Ok(2);
            }
        }

        write_helper_script(&helper_path)?;
        spawn_update_helper(&helper_path, &target, &pending_path)?;
        crate::console::ok(&format!(
            "CLI update to {latest} prepared. It will be applied atomically after this process exits."
        ));
        Ok(0)
    }
}

pub fn update_host(args: UpdateHostArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    let base = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let admin = AdminFacade::new(&client);
    let data = match admin.update_host(args.pull_only) {
        Ok(v) => v,
        Err(e) => return fail_admin(e, "update host"),
    };
    if args.json_out {
        print_json(&data);
        return Ok(0);
    }
    if data.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        if data
            .get("scheduled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            crate::console::ok("Host update scheduled.");
        } else {
            crate::console::ok("Host update triggered.");
        }
    } else {
        crate::console::err("Host update failed.");
    }
    if let Some(stderr) = data.get("stderr").and_then(|v| v.as_str()) {
        if !stderr.trim().is_empty() {
            crate::console::warn(stderr);
        }
    }
    Ok(0)
}

pub fn update_nodes(args: UpdateNodesArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    let base = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let admin = AdminFacade::new(&client);

    let refresh = args.refresh && !args.no_refresh;
    let target_version = match args.version {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => resolve_latest_agent_version(&admin, refresh)?,
    };
    if !args.json_out {
        crate::console::info(&format!("Resolved agent version: {target_version}"));
    }

    let node_ids: Vec<i64> = if args.all {
        list_all_node_ids(&admin)?
    } else if !args.nodes.is_empty() {
        let mut out = Vec::new();
        for node_ref in &args.nodes {
            let id = admin
                .resolve_node_id(node_ref)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            out.push(id);
        }
        out
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Provide --node <ref> (repeatable) or --all.",
        ));
    };
    if node_ids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No nodes selected.",
        ));
    }

    let mut jobs = Vec::new();
    for node_id in node_ids {
        let mut job = client
            .admin_job_create(
                Some(node_id),
                None,
                "agent_update",
                json!({ "target_version": target_version }),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        if args.wait {
            let timeout = args.wait_timeout.max(1) as u64;
            let interval = args.wait_interval.max(1) as u64;
            let started = std::time::Instant::now();
            let job_id = job.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            while started.elapsed().as_secs() < timeout {
                let latest = admin
                    .get_job_raw(job_id)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let status = latest
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                if matches!(status, "succeeded" | "failed" | "cancelled") {
                    job = latest;
                    break;
                }
                std::thread::sleep(Duration::from_secs(interval));
            }
        }
        jobs.push(job);
    }

    if args.json_out {
        print_json(&json!({ "jobs": jobs }));
        return Ok(0);
    }
    for item in &jobs {
        let job_id = item.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let status = item
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        crate::console::ok(&format!("Job created: id={job_id} status={status}"));
    }
    Ok(0)
}

fn fetch_releases(license_api_url: Option<&str>, channel: &str, limit: i64) -> io::Result<Value> {
    let cfg = load_config()?;
    let base = license_api_url
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| resolve_license_api_url(&cfg));
    let mut url =
        Url::parse(&format!("{}/v1/releases", base.trim_end_matches('/'))).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid license api url: {e}"),
            )
        })?;
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("channel", channel.trim());
        qp.append_pair("limit", &limit.to_string());
    }
    let http = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http client error: {e}")))?;
    let resp = http
        .get(url)
        .send()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("failed to fetch releases: HTTP {}", resp.status().as_u16()),
        ));
    }
    let data = resp
        .json::<Value>()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("invalid JSON: {e}")))?;
    let arr = data.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "invalid releases payload: expected array",
        )
    })?;
    let mut rows = arr.clone();
    rows.sort_by(|a, b| {
        let va = a
            .get("version")
            .and_then(|v| v.as_str())
            .and_then(parse_semver)
            .unwrap_or_else(|| Version::new(0, 0, 0));
        let vb = b
            .get("version")
            .and_then(|v| v.as_str())
            .and_then(parse_semver)
            .unwrap_or_else(|| Version::new(0, 0, 0));
        vb.cmp(&va)
    });
    Ok(Value::Array(rows))
}

fn parse_semver(value: &str) -> Option<Version> {
    Version::parse(value.trim().trim_start_matches('v')).ok()
}

fn resolve_latest_agent_version(admin: &AdminFacade<'_>, refresh: bool) -> io::Result<String> {
    let data = if refresh {
        admin.license_refresh()
    } else {
        admin.license_snapshot()
    }
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let entitlements = data.get("entitlements");
    let versions = data.get("versions");
    for source in [entitlements, versions] {
        if let Some(obj) = source.and_then(|v| v.as_object()) {
            if let Some(latest) = obj.get("latest_versions").and_then(|v| v.as_object()) {
                if let Some(agent) = latest.get("agent").and_then(|v| v.as_str()) {
                    if !agent.trim().is_empty() {
                        return Ok(agent.trim().to_string());
                    }
                }
            }
            if let Some(resolved) = obj.get("resolved_versions").and_then(|v| v.as_object()) {
                if let Some(agent) = resolved.get("agent").and_then(|v| v.as_str()) {
                    if !agent.trim().is_empty() {
                        return Ok(agent.trim().to_string());
                    }
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Unable to resolve latest agent version from license snapshot.",
    ))
}

fn list_all_node_ids(admin: &AdminFacade<'_>) -> io::Result<Vec<i64>> {
    let data = admin
        .list_nodes_raw(None, Some(1000), Some(0))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let items = data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut ids = Vec::new();
    for item in items {
        if let Some(id) = item.get("id").and_then(|v| v.as_i64()) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn platform_id() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn value_text(v: Option<&Value>) -> String {
    match v {
        None => "-".to_string(),
        Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) if s.trim().is_empty() => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn update_cache_dir() -> io::Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "saharo")
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "unable to resolve cache directory"))?;
    let dir = dirs.cache_dir().join("update");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn download_file(url: &str, destination: &Path) -> io::Result<String> {
    let http = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("http client error: {e}")))?;
    let mut response = http
        .get(url)
        .send()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("download failed: {e}")))?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("download failed: HTTP {}", response.status().as_u16()),
        ));
    }
    let mut file = fs::File::create(destination)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = response.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        file.write_all(&buf[..read])?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn write_helper_script(path: &Path) -> io::Result<()> {
    let script = r#"#!/bin/sh
set -eu
TARGET="$1"
PENDING="$2"
PID="$3"
while kill -0 "$PID" 2>/dev/null; do
  sleep 0.2
done
TMP="${TARGET}.new"
cp "$PENDING" "$TMP"
chmod +x "$TMP"
mv -f "$TMP" "$TARGET"
rm -f "$PENDING"
"#;
    fs::write(path, script)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn spawn_update_helper(helper: &Path, target: &Path, pending: &Path) -> io::Result<()> {
    Command::new("/bin/sh")
        .arg(helper)
        .arg(target)
        .arg(pending)
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to start update helper: {e}"),
            )
        })
}

fn is_target_writable(target: &Path) -> bool {
    if target.exists() {
        return OpenOptions::new().write(true).open(target).is_ok();
    }
    if let Some(parent) = target.parent() {
        let probe = parent.join(format!(".saharoctl-write-test-{}", std::process::id()));
        if OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe)
            .is_ok()
        {
            let _ = fs::remove_file(probe);
            return true;
        }
    }
    false
}

fn fail_admin(err: ApiError, action: &str) -> io::Result<i32> {
    crate::console::err(&saharo_sdk::format_admin_error(&err, action));
    Ok(2)
}

fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    } else {
        println!("{v}");
    }
}
