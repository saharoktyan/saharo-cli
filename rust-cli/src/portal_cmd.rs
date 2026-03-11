use std::io::{self, IsTerminal, Write};

use dialoguer::{theme::ColorfulTheme, Input, Select};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use serde_json::{json, Value};

use crate::config::{load_config, resolve_license_api_url, save_config};
use crate::{
    DeleteHostArgs, PortalAuthArgs, PortalCommand, PortalLogoutArgs, PortalProfileArgs,
    PortalTelemetryArgs,
};

pub fn handle_portal(command: PortalCommand) -> io::Result<i32> {
    match command {
        PortalCommand::Auth(args) => portal_auth(args),
        PortalCommand::Profile(args) => portal_profile(args),
        PortalCommand::Telemetry(args) => portal_telemetry(args),
        PortalCommand::Logout(args) => portal_logout(args),
    }
}

pub fn delete_host(args: DeleteHostArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let base = resolve_lic_url(&cfg, args.lic_url.as_deref())?;
    let token = cfg.portal_session_token.trim().to_string();
    let csrf = cfg.portal_csrf_token.trim().to_string();
    if token.is_empty() || csrf.is_empty() {
        crate::console::err("Portal auth is required. Run `saharoctl portal auth`.");
        return Ok(2);
    }
    let client = portal_client()?;
    let license_id = match args.license_id {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            let licenses = account_licenses(&client, &base, &token, &csrf)?;
            if licenses.is_empty() {
                crate::console::err("No licenses available.");
                return Ok(2);
            }
            if !std::io::stdin().is_terminal() {
                crate::console::err("Use --license-id in non-interactive mode.");
                return Ok(2);
            }
            select_license_id(&licenses)?
        }
    };
    if !args.force {
        if !std::io::stdin().is_terminal() {
            crate::console::err("Use --force in non-interactive mode.");
            return Ok(2);
        }
        let confirm: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Type DELETE to confirm host purge")
            .interact_text()
            .map_err(dialoguer_err)?;
        if confirm.trim() != "DELETE" {
            crate::console::info("Aborted.");
            return Ok(0);
        }
    }
    let resp = client
        .post(format!(
            "{}/v1/licenses/{}/hosts/purge",
            base.trim_end_matches('/'),
            license_id
        ))
        .header("X-Session-Token", token.as_str())
        .header("X-CSRF-Token", csrf.as_str())
        .header(COOKIE, format!("saharo_csrf={csrf}"))
        .send()
        .map_err(io_other)?;
    if resp.status().is_success() {
        crate::console::ok("Host purge completed.");
        return Ok(0);
    }
    if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
        cfg.portal_session_token.clear();
        cfg.portal_csrf_token.clear();
        let _ = save_config(&cfg);
        crate::console::err("Portal session is invalid or expired. Run `saharoctl portal auth`.");
        return Ok(2);
    }
    crate::console::err(&format!(
        "Host purge failed: HTTP {}",
        resp.status().as_u16()
    ));
    Ok(2)
}

fn portal_auth(args: PortalAuthArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let base = resolve_lic_url(&cfg, args.lic_url.as_deref())?;
    let client = portal_client()?;
    let theme = ColorfulTheme::default();
    let has_account = Select::with_theme(&theme)
        .with_prompt("Do you already have an account?")
        .items(&["Yes", "No"])
        .default(0)
        .interact()
        .map_err(dialoguer_err)?
        == 0;
    let (token, csrf) = if has_account {
        login_flow(&client, &base)?
    } else {
        register_flow(&client, &base)?
    };
    cfg.portal_session_token = token;
    cfg.portal_csrf_token = csrf;
    save_config(&cfg)?;
    crate::console::ok("Portal session saved.");
    Ok(0)
}

fn portal_profile(args: PortalProfileArgs) -> io::Result<i32> {
    let cfg = load_config()?;
    let token = cfg.portal_session_token.trim().to_string();
    if token.is_empty() {
        crate::console::info("Portal profile: not authenticated.");
        crate::console::info("Run: saharoctl portal auth");
        return Ok(0);
    }
    let csrf = cfg.portal_csrf_token.trim().to_string();
    let base = resolve_lic_url(&cfg, args.lic_url.as_deref())?;
    let client = portal_client()?;

    let me_resp = client
        .get(format!("{}/v1/auth/me", base.trim_end_matches('/')))
        .header("X-Session-Token", token.as_str())
        .send()
        .map_err(io_other)?;
    if me_resp.status().as_u16() == 401 || me_resp.status().as_u16() == 403 {
        crate::console::err("Portal session is invalid or expired.");
        return Ok(2);
    }
    if !me_resp.status().is_success() {
        crate::console::err(&format!(
            "Portal status failed: HTTP {}",
            me_resp.status().as_u16()
        ));
        return Ok(2);
    }
    let me = parse_json(me_resp)?;

    let mut telemetry = Value::Null;
    let mut licenses = Value::Array(vec![]);
    if !csrf.is_empty() {
        let headers = portal_headers(&token, &csrf)?;
        let t_resp = client
            .get(format!(
                "{}/v1/account/telemetry",
                base.trim_end_matches('/')
            ))
            .headers(headers.clone())
            .send()
            .map_err(io_other)?;
        if t_resp.status().is_success() {
            telemetry = parse_json(t_resp).unwrap_or(Value::Null);
        }
        let l_resp = client
            .get(format!(
                "{}/v1/account/licenses",
                base.trim_end_matches('/')
            ))
            .headers(headers)
            .send()
            .map_err(io_other)?;
        if l_resp.status().is_success() {
            licenses = parse_json(l_resp).unwrap_or(Value::Array(vec![]));
        }
    }

    let out = json!({
        "profile": me,
        "telemetry": telemetry,
        "licenses": licenses,
    });
    crate::pretty_kv::print_value(&out);
    Ok(0)
}

fn portal_telemetry(args: PortalTelemetryArgs) -> io::Result<i32> {
    if args.enable && args.disable {
        crate::console::err("Use either --enable or --disable.");
        return Ok(2);
    }
    let cfg = load_config()?;
    let token = cfg.portal_session_token.trim().to_string();
    let csrf = cfg.portal_csrf_token.trim().to_string();
    if token.is_empty() || csrf.is_empty() {
        crate::console::err("Portal auth is required. Run `saharoctl portal auth`.");
        return Ok(2);
    }
    let base = resolve_lic_url(&cfg, args.lic_url.as_deref())?;
    let client = portal_client()?;
    let headers = portal_headers(&token, &csrf)?;
    let status_resp = client
        .get(format!(
            "{}/v1/account/telemetry",
            base.trim_end_matches('/')
        ))
        .headers(headers.clone())
        .send()
        .map_err(io_other)?;
    if status_resp.status().as_u16() == 401 || status_resp.status().as_u16() == 403 {
        crate::console::err("Portal session is invalid or expired.");
        return Ok(2);
    }
    if !status_resp.status().is_success() {
        crate::console::err(&format!(
            "Portal telemetry status failed: HTTP {}",
            status_resp.status().as_u16()
        ));
        return Ok(2);
    }
    let status_json = parse_json(status_resp).unwrap_or(Value::Null);
    let current = status_json
        .get("telemetry")
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enabled = if args.enable {
        true
    } else if args.disable {
        false
    } else if std::io::stdin().is_terminal() {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Telemetry")
            .items(&["Enable", "Disable"])
            .default(if current { 0 } else { 1 })
            .interact()
            .map_err(dialoguer_err)?
            == 0
    } else {
        current
    };

    let resp = client
        .post(format!(
            "{}/v1/account/telemetry",
            base.trim_end_matches('/')
        ))
        .headers(headers)
        .json(&json!({ "enabled": enabled }))
        .send()
        .map_err(io_other)?;
    if !resp.status().is_success() {
        crate::console::err(&format!(
            "Portal telemetry change failed: HTTP {}",
            resp.status().as_u16()
        ));
        return Ok(2);
    }
    if enabled {
        crate::console::ok("Telemetry enabled.");
    } else {
        crate::console::ok("Telemetry disabled.");
    }
    Ok(0)
}

fn portal_logout(args: PortalLogoutArgs) -> io::Result<i32> {
    let mut cfg = load_config()?;
    let token = cfg.portal_session_token.trim().to_string();
    if token.is_empty() {
        crate::console::info("Portal session: already logged out.");
        return Ok(0);
    }
    let csrf = cfg.portal_csrf_token.trim().to_string();
    let base = resolve_lic_url(&cfg, args.lic_url.as_deref())?;
    let client = portal_client()?;
    let mut req = client
        .post(format!("{}/v1/auth/logout", base.trim_end_matches('/')))
        .header("X-Session-Token", token.as_str());
    if !csrf.is_empty() {
        req = req
            .header("X-CSRF-Token", csrf.as_str())
            .header(COOKIE, format!("saharo_csrf={csrf}"));
    }
    let resp = req.send().map_err(io_other)?;
    let status = resp.status().as_u16();
    if !(status == 200 || status == 204 || status == 401 || status == 403) {
        crate::console::err(&format!("Portal logout failed: HTTP {status}"));
        return Ok(2);
    }
    cfg.portal_session_token.clear();
    cfg.portal_csrf_token.clear();
    save_config(&cfg)?;
    crate::console::ok("Portal session cleared.");
    Ok(0)
}

fn login_flow(client: &Client, base: &str) -> io::Result<(String, String)> {
    let login = prompt("Email or username")?;
    let password = prompt_hidden("Password (input hidden)")?;
    let resp = client
        .post(format!("{}/v1/auth/login", base.trim_end_matches('/')))
        .json(&json!({ "login": login, "password": password }))
        .send()
        .map_err(io_other)?;
    if resp.status().as_u16() == 401 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Username/email or password does not match.",
        ));
    }
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Portal auth failed: HTTP {}", resp.status().as_u16()),
        ));
    }
    extract_session(resp)
}

fn register_flow(client: &Client, base: &str) -> io::Result<(String, String)> {
    let email = prompt("Email")?;
    let username = prompt("Username")?;
    let password = prompt_hidden("Password (input hidden)")?;
    let confirm = prompt_hidden("Confirm password (input hidden)")?;
    if password != confirm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match.",
        ));
    }
    let resp = client
        .post(format!("{}/v1/auth/register", base.trim_end_matches('/')))
        .json(&json!({
            "email": email,
            "username": username,
            "password": password,
            "password_confirm": confirm
        }))
        .send()
        .map_err(io_other)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Registration failed: HTTP {}", resp.status().as_u16()),
        ));
    }
    crate::console::ok("Verification code sent to your email.");
    let otp = prompt("Email confirmation code")?;
    let verify = client
        .post(format!(
            "{}/v1/auth/verify-email",
            base.trim_end_matches('/')
        ))
        .json(&json!({ "login": email, "otp": otp }))
        .send()
        .map_err(io_other)?;
    if !verify.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Email verification failed: HTTP {}",
                verify.status().as_u16()
            ),
        ));
    }
    extract_session(verify)
}

fn extract_session(resp: Response) -> io::Result<(String, String)> {
    let csrf = extract_cookie(resp.headers(), "saharo_csrf").unwrap_or_default();
    let data: Value = resp
        .json()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("invalid auth response: {e}")))?;
    let token = data
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Portal auth failed: missing session token.",
        ));
    }
    Ok((token, csrf))
}

fn account_licenses(
    client: &Client,
    base: &str,
    token: &str,
    csrf: &str,
) -> io::Result<Vec<Value>> {
    let headers = portal_headers(token, csrf)?;
    let resp = client
        .get(format!(
            "{}/v1/account/licenses",
            base.trim_end_matches('/')
        ))
        .headers(headers)
        .send()
        .map_err(io_other)?;
    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to list licenses: HTTP {}", resp.status().as_u16()),
        ));
    }
    let value = parse_json(resp)?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

fn select_license_id(licenses: &[Value]) -> io::Result<String> {
    let mut labels = Vec::new();
    let mut ids = Vec::new();
    for lic in licenses {
        let id = lic
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let last4 = lic
            .get("key_last4")
            .and_then(|v| v.as_str())
            .unwrap_or("----");
        let status = lic
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let name = lic
            .get("notes")
            .and_then(|v| v.as_str())
            .or_else(|| lic.get("name").and_then(|v| v.as_str()))
            .unwrap_or("-");
        labels.push(format!("****{last4} | {status} | {name}"));
        ids.push(id);
    }
    if labels.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "No valid licenses found.",
        ));
    }
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select license to purge")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(dialoguer_err)?;
    Ok(ids[idx].clone())
}

fn resolve_lic_url(
    cfg: &crate::config::AppConfig,
    override_url: Option<&str>,
) -> io::Result<String> {
    let out = override_url
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| resolve_license_api_url(cfg));
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "License API URL is not configured.",
        ));
    }
    Ok(out)
}

fn portal_client() -> io::Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(io_other)
}

fn portal_headers(token: &str, csrf: &str) -> io::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Session-Token",
        HeaderValue::from_str(token)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
    );
    headers.insert(
        "X-CSRF-Token",
        HeaderValue::from_str(csrf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
    );
    headers.insert(
        COOKIE,
        HeaderValue::from_str(format!("saharo_csrf={csrf}").as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
    );
    Ok(headers)
}

fn parse_json(resp: Response) -> io::Result<Value> {
    resp.json()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("invalid JSON: {e}")))
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all("set-cookie").iter() {
        let s = value.to_str().ok()?;
        for part in s.split(';') {
            let trimmed = part.trim();
            if let Some(rest) = trimmed.strip_prefix(&format!("{name}=")) {
                return Some(rest.to_string());
            }
        }
    }
    None
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

fn dialoguer_err(err: dialoguer::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn io_other<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}
