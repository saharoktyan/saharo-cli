use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::{config_path, load_config, normalize_base_url};
use crate::{ConfigCommand, ConfigGetArgs};
use saharo_sdk::{awg_output_path, ApiClient, VpnConfigFacade, VpnConfigRequest};

pub fn handle_config(command: ConfigCommand) -> io::Result<i32> {
    match command {
        ConfigCommand::Get(args) => get_config(args),
    }
}

fn get_config(args: ConfigGetArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    if cfg.auth.token.trim().is_empty() {
        err("Auth token missing. Run `saharoctl auth login` first.");
        return Ok(2);
    }

    let device = args
        .device
        .clone()
        .unwrap_or_else(default_device_label)
        .trim()
        .to_string();
    if device.is_empty() {
        err("Device label is required.");
        return Ok(2);
    }

    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let facade = VpnConfigFacade::new(&client);
    let result = match facade.build_content(&VpnConfigRequest {
        server: args.server.clone(),
        protocol: args.protocol.clone(),
        route: args.route.clone(),
        device_label: device.clone(),
        awg_conf: args.conf,
        keys_base_dir: keys_base_dir()?,
    }) {
        Ok(v) => v,
        Err(e) => {
            err(&e.message);
            if let Some(hint) = e.hint {
                info(&hint);
            }
            return Ok(2);
        }
    };

    let output_path = args.out.clone().map(PathBuf::from).unwrap_or_else(|| {
        default_output_path(&result.protocol_key, result.server_id, &device, args.conf)
    });

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, format!("{}\n", result.content))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))?;
    }

    if result.protocol_key == "awg" {
        let label = if args.conf {
            "WireGuard config"
        } else {
            "AmneziaWG URI"
        };
        ok(&format!("{label} saved to {}", output_path.display()));
    } else {
        ok(&format!("Config saved to {}", output_path.display()));
    }
    if !args.quiet {
        println!();
        println!("{}", result.content);
    }

    Ok(0)
}

fn keys_base_dir() -> io::Result<PathBuf> {
    let cfg = config_path()?;
    cfg.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid config path"))
}

fn default_device_label() -> String {
    if let Ok(v) = std::env::var("HOSTNAME") {
        let trimmed = v.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    "device".to_string()
}

fn default_output_path(
    protocol: &str,
    server_id: i64,
    device_label: &str,
    awg_conf: bool,
) -> PathBuf {
    if protocol == "awg" {
        if let Ok(base) = keys_base_dir() {
            return awg_output_path(&base, server_id, device_label, awg_conf);
        }
    }

    let safe_label = device_label.replace('/', "_");
    let cfg_dir = config_path()
        .ok()
        .and_then(|p| p.parent().map(|pp| pp.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    cfg_dir
        .join("configs")
        .join(protocol)
        .join(server_id.to_string())
        .join(safe_label)
        .join("config.txt")
}

fn info(msg: &str) {
    crate::console::info(msg);
}

fn ok(msg: &str) {
    crate::console::ok(msg);
}

fn err(msg: &str) {
    crate::console::err(msg);
}
