use std::io::{self, Write};
use std::process::Command;

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use serde_json::Value;

use crate::config::{load_config, normalize_base_url, save_config};
use crate::registry::{delete_registry, load_registry, registry_path};
use crate::{
    AuthCommand, AuthLoginApiKeyArgs, AuthLoginArgs, AuthLogoutArgs, AuthRegisterArgs,
    AuthStatusArgs, WhoamiArgs,
};
use saharo_sdk::{parse_whoami_info, ApiClient, ApiError, AuthFacade, WhoamiInfo};

pub fn handle_auth(command: AuthCommand) -> io::Result<i32> {
    match command {
        AuthCommand::Login(args) => login(args),
        AuthCommand::LoginApiKey(args) => login_api_key(args),
        AuthCommand::Register(args) => register(args),
        AuthCommand::Logout(args) => logout(args),
        AuthCommand::Activate => {
            err("This command was removed. License activation is handled during host bootstrap and stored on the host.");
            Ok(2)
        }
        AuthCommand::Status(args) => status(args),
        AuthCommand::Whoami(args) => {
            warn("Deprecated: use `saharoctl whoami` instead.");
            whoami(args)
        }
    }
}

pub fn whoami(args: WhoamiArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    if cfg.auth.token.trim().is_empty() {
        err("Not authenticated. No token found.");
        info("Run: saharoctl auth login");
        return Ok(2);
    }
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));
    let client = ApiClient::new(&base_url, Some(cfg.auth.token.as_str()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let auth = AuthFacade::new(&client);

    let me = match auth.whoami() {
        Ok(v) => v,
        Err(e) => {
            if e.status_code == 401 || e.status_code == 403 {
                err("Not authenticated.");
                info("Your token is invalid or expired.");
                info("Run: saharoctl auth login");
            } else {
                err(&format!("Failed to fetch /me: HTTP {}", e.status_code));
                if let Some(details) = e.details {
                    eprintln!("{details}");
                } else {
                    err(&e.to_string());
                }
            }
            return Ok(2);
        }
    };

    let info = parse_whoami_info(&me);
    print_whoami(&info, &me, args.verbose);
    Ok(0)
}

fn login(args: AuthLoginArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let username = match args.username {
        Some(v) => v,
        None => prompt("Username for login")?,
    };
    let password = match args.password {
        Some(v) => v,
        None => prompt_hidden("Password (input hidden)")?,
    };
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));

    let client = ApiClient::new(&base_url, None).map_err(io_other)?;
    let auth = AuthFacade::new(&client);
    let token = match auth.login_password(&username, &password) {
        Ok(v) => v,
        Err(e) => {
            err(&format!("Login failed: {}", format_api_error(&e)));
            return Ok(2);
        }
    };

    cfg.auth.token = token;
    cfg.auth.token_type = "bearer".to_string();
    let saved = save_config(&cfg)?;
    ok(&format!(
        "Login successful. Token saved to {}.",
        saved.display()
    ));
    Ok(0)
}

fn login_api_key(args: AuthLoginApiKeyArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let api_key = match args.api_key {
        Some(v) => v,
        None => prompt_hidden("API key (input hidden)")?,
    };
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));

    let client = ApiClient::new(&base_url, None).map_err(io_other)?;
    let auth = AuthFacade::new(&client);
    let token = match auth.login_api_key(&api_key) {
        Ok(v) => v,
        Err(e) => {
            err(&format!("Login failed: {}", format_api_error(&e)));
            return Ok(2);
        }
    };

    cfg.auth.token = token;
    cfg.auth.token_type = "bearer".to_string();
    let saved = save_config(&cfg)?;
    ok(&format!(
        "Login successful. Token saved to {}.",
        saved.display()
    ));
    Ok(0)
}

fn register(args: AuthRegisterArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let token = args.invite_token.trim().to_string();
    if token.is_empty() {
        err("Invite token cannot be empty.");
        return Ok(2);
    }

    let username = match args.username {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => prompt("New username")?,
    };
    if username.trim().is_empty() {
        err("Username cannot be empty.");
        return Ok(2);
    }
    let password = match prompt_password_with_confirmation(args.password) {
        Ok(v) => v,
        Err(e) => {
            err(&e.to_string());
            return Ok(2);
        }
    };
    let device_label = args
        .device_label
        .unwrap_or_else(default_device_label)
        .trim()
        .to_string();
    if device_label.is_empty() {
        err("Device label cannot be empty.");
        return Ok(2);
    }
    let base_url = normalize_base_url(args.base_url.as_deref().unwrap_or(&cfg.base_url));

    let client = ApiClient::new(&base_url, None).map_err(io_other)?;
    let auth = AuthFacade::new(&client);
    let platform = default_platform();
    let result = auth.register_via_invite(
        &token,
        &username,
        &password,
        &device_label,
        Some(platform.as_str()),
    );
    let data = match result {
        Ok(v) => v,
        Err(e) => {
            match e.status_code {
                404 => err("Invite not found."),
                409 => err("Username or device label already exists."),
                400 | 401 | 403 => err(&format!("Invite claim failed: {}", format_api_error(&e))),
                _ => err(&format!("Invite claim failed: {}", format_api_error(&e))),
            }
            return Ok(2);
        }
    };

    let jwt = data
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if jwt.trim().is_empty() {
        err("Unexpected response: token missing.");
        return Ok(2);
    }

    cfg.auth.token = jwt;
    cfg.auth.token_type = "bearer".to_string();
    let saved = save_config(&cfg)?;
    ok("Invite accepted. You are now logged in.");
    info(&format!("Token saved to {}.", saved.display()));
    Ok(0)
}

fn logout(args: AuthLogoutArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    cfg.auth.token = String::new();
    let save_path = save_config(&cfg)?;
    ok(&format!("Token cleared from {}.", save_path.display()));

    let docker_enabled = args.docker && !args.no_docker;
    if let Some(creds) = load_registry()? {
        if docker_enabled {
            let _ = docker_logout(&creds.url);
        }
        delete_registry()?;
        ok("Registry credentials removed.");
    }
    Ok(0)
}

fn status(args: AuthStatusArgs) -> io::Result<i32> {
    let creds = load_registry()?;
    let Some(creds) = creds else {
        info("Not activated.");
        return Ok(0);
    };

    let issued_at = creds.issued_at.unwrap_or_else(|| "-".to_string());
    let mut payload = serde_json::json!({
        "registry": creds.url,
        "username": creds.username,
        "issued_at": issued_at,
    });
    if args.verbose {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "registry_file".to_string(),
                Value::String(registry_path()?.display().to_string()),
            );
            obj.insert(
                "password_stored".to_string(),
                Value::String(
                    if creds.password.is_some() {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_string(),
                ),
            );
        }
    }
    crate::pretty_kv::print_value(&payload);
    Ok(0)
}

fn docker_logout(url: &str) -> bool {
    let output = Command::new("docker").arg("logout").arg(url).output();
    match output {
        Ok(out) => {
            if out.status.success() {
                true
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if stderr.is_empty() {
                    err("Docker logout failed.");
                } else {
                    err(&format!("Docker logout failed: {stderr}"));
                }
                false
            }
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                warn("Docker CLI not found in PATH; skipping registry logout.");
                false
            } else {
                err(&format!("Docker logout failed: {e}"));
                false
            }
        }
    }
}

fn print_whoami(who: &WhoamiInfo, me_raw: &Value, verbose: bool) {
    println!("Whoami");
    println!("Username: {}", who.username);
    println!("Role: {}", who.role);
    println!("Subscription: {}", who.subscription_display);

    if who.access_entries.is_empty() {
        info("No access grants yet. Ask admin to enable a server/protocol for your account.");
    } else {
        println!("\nAccess (Grants)");
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["Server", "Protocol", "Status", "Expires"]);
        for e in &who.access_entries {
            table.add_row(vec![
                e.server_label.clone(),
                e.protocol_key.clone(),
                e.status.clone(),
                e.expires.clone(),
            ]);
        }
        println!("{table}");
    }

    if verbose {
        println!("\nRaw /me");
        match serde_json::to_string_pretty(me_raw) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("{me_raw}"),
        }
    }
}

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_hidden(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    rpassword::read_password()
}

fn prompt_password_with_confirmation(initial_password: Option<String>) -> io::Result<String> {
    let mut password = initial_password;
    let mut attempts = 0;
    while attempts < 3 {
        let current = match password.take() {
            Some(v) => v,
            None => prompt_hidden("Password (input hidden)")?,
        };
        let confirm = prompt_hidden("Confirm password (input hidden)")?;
        if current.trim().is_empty() {
            err("Password cannot be empty.");
            attempts += 1;
            continue;
        }
        if current.chars().count() < 8 {
            err("Password must be at least 8 characters.");
            attempts += 1;
            continue;
        }
        if current != confirm {
            err("Passwords do not match.");
            attempts += 1;
            continue;
        }
        return Ok(current);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "too many attempts",
    ))
}

fn default_device_label() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "device".to_string())
}

fn default_platform() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

fn io_other(err: ApiError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn format_api_error(err: &ApiError) -> String {
    if err.message.trim().is_empty() {
        format!("HTTP {}", err.status_code)
    } else {
        err.message.clone()
    }
}

fn info(msg: &str) {
    crate::console::info(msg);
}

fn ok(msg: &str) {
    crate::console::ok(msg);
}

fn warn(msg: &str) {
    crate::console::warn(msg);
}

fn err(msg: &str) {
    crate::console::err(msg);
}
