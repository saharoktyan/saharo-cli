use std::io::{self, Write};

use crate::config::{config_path, default_config, load_config, normalize_base_url, save_config};
use crate::{KeyArg, SettingsCommand, SettingsInitArgs, SettingsSetArgs};

pub fn handle_settings(command: SettingsCommand) -> io::Result<i32> {
    match command {
        SettingsCommand::Init(args) => init_settings(args),
        SettingsCommand::Show => show_settings(),
        SettingsCommand::Get(args) => get_setting(args),
        SettingsCommand::Set(args) => set_setting(args),
    }
}

fn init_settings(args: SettingsInitArgs) -> io::Result<i32> {
    let path = config_path()?;
    if path.exists() && !args.force {
        info(&format!("Config already exists: {}", path.display()));
        info("Use --force to overwrite.");
        return Ok(0);
    }

    let base_url_input = match args.base_url {
        Some(v) => v,
        None => prompt("API base URL")?,
    };

    let mut cfg = default_config();
    cfg.base_url = normalize_base_url(&base_url_input);
    if cfg.base_url.is_empty() {
        err("Base URL cannot be empty.");
        return Ok(2);
    }
    let saved = save_config(&cfg)?;
    ok(&format!("Config written: {}", saved.display()));
    Ok(0)
}

fn show_settings() -> io::Result<i32> {
    let cfg = load_config()?;
    let token_state = if cfg.auth.token.trim().is_empty() {
        "(empty)"
    } else {
        "(set)"
    };
    println!(
        "base_url={} license_api_url={} token={} token_type={}",
        cfg.base_url, cfg.license_api_url, token_state, cfg.auth.token_type
    );
    Ok(0)
}

fn get_setting(args: KeyArg) -> io::Result<i32> {
    let cfg = load_config()?;
    match args.key.trim().to_lowercase().as_str() {
        "base_url" => {
            println!("{}", cfg.base_url);
            Ok(0)
        }
        "license_api_url" => {
            println!("{}", cfg.license_api_url);
            Ok(0)
        }
        _ => {
            err(&format!("Unknown setting: {}", args.key));
            Ok(2)
        }
    }
}

fn set_setting(args: SettingsSetArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    if let Some(base_url) = args.base_url {
        cfg.base_url = normalize_base_url(&base_url);
    }
    if let Some(license_api_url) = args.license_api_url {
        cfg.license_api_url = license_api_url.trim().trim_end_matches('/').to_string();
    }
    let saved = save_config(&cfg)?;
    ok(&format!("Settings updated: {}", saved.display()));
    Ok(0)
}

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
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
