use std::fs;
use std::io;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::blocking::Client;
use semver::Version;
use serde_json::json;

use crate::JoinHostArgs;

const DEFAULT_API_BASE: &str = "http://127.0.0.1:8010";
const DEFAULT_LICENSE_URL: &str = "https://downloads.saharoktyan.ru";
const HOST_IMAGE_COMPONENT: &str = "api";
const DEFAULT_API_PORT: i64 = 8010;

pub fn handle_join_host(args: JoinHostArgs) -> io::Result<i32> {
    let interactive = std::io::stdin().is_terminal() && !args.non_interactive;
    let theme = ColorfulTheme::default();

    if args.print_versions {
        crate::console::warn(
            "`--print-versions` is not wired yet in Rust CLI. Skipping version resolution and continuing.",
        );
    }
    let mut ssh = resolve_ssh_target(&args, interactive, &theme)?;
    let api_url = normalize_api_url(&required_value(
        args.api_url.clone(),
        "Public API URL (e.g. https://api.example.com)",
        interactive,
        &theme,
    )?)?;
    let https_http01 = args.https_http01 && !args.no_https_http01;
    let https = resolve_https_inputs(
        &api_url,
        args.skip_https,
        args.https_domain.clone(),
        args.https_email.clone(),
        https_http01,
        interactive,
        &theme,
    )?;
    let host_name = optional_prompt(
        args.host_name.clone(),
        "Host API name",
        "Host API",
        interactive,
        &theme,
    )?;

    let x_root_secret = secret_value(
        args.x_root_secret.clone(),
        "Root secret (X-Root-Secret for /admin/bootstrap)",
        interactive,
        &theme,
        args.non_interactive,
    )?;
    let db_password = secret_value(
        args.db_password.clone(),
        "Postgres password",
        interactive,
        &theme,
        args.non_interactive,
    )?;
    let admin_username = required_value(
        args.admin_username.clone(),
        "Admin username",
        interactive,
        &theme,
    )?;
    let admin_password = password_value(
        args.admin_password.clone(),
        "Admin password",
        interactive,
        &theme,
        args.non_interactive,
    )?;

    let enterprise = resolve_enterprise(args.enterprise, interactive, &theme)?;
    let vpn_cidr = resolve_vpn_cidr(args.vpn_cidr.clone(), interactive, &theme)?;
    let use_sudo = args.ssh_sudo && !args.no_ssh_sudo;
    let lic_url = if args.lic_url.trim().is_empty() {
        DEFAULT_LICENSE_URL.to_string()
    } else {
        args.lic_url.trim().trim_end_matches('/').to_string()
    };
    let tag = if let Some(v) = args.version.clone().filter(|v| !v.trim().is_empty()) {
        v.trim().to_string()
    } else {
        match resolve_latest_host_tag_from_license_api(&lic_url) {
            Ok(v) => {
                crate::console::info(&format!("Resolved host version from license API: {v}"));
                v
            }
            Err(err) => {
                crate::console::warn(&format!(
                    "Failed to resolve latest host version from license API ({}). Falling back to --tag {}",
                    err, args.tag
                ));
                args.tag.clone()
            }
        }
    };
    if args.print_versions {
        crate::console::ok(&format!("Resolved host version: {tag}"));
        return Ok(0);
    }
    let bootstrap_base = args
        .base_url
        .as_deref()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE.to_string());

    if let Some(target) = ssh.as_mut() {
        target.sudo = use_sudo && !target.is_root();
    }

    let host_dir = PathBuf::from(args.install_dir.clone()).join("host");
    if host_dir.exists() && !args.force {
        crate::console::err(&format!(
            "Install dir already exists: {}. Re-run with --force to overwrite files.",
            host_dir.display()
        ));
        return Ok(2);
    }

    if args.wipe_data {
        ensure_wipe_confirmed(
            args.confirm_wipe,
            args.yes,
            args.non_interactive,
            interactive,
            &theme,
        )?;
        if let Some(target) = ssh.as_ref() {
            remote_wipe_data(target, host_dir.as_path())?;
        } else {
            local_wipe_data(host_dir.as_path())?;
        }
    }

    let jwt_secret = if !args.rotate_jwt_secret {
        read_existing_jwt_secret(host_dir.as_path()).unwrap_or_else(generate_secret_token)
    } else {
        generate_secret_token()
    };

    let inputs = RenderInputs {
        api_url: api_url.as_str(),
        host_name: host_name.as_str(),
        x_root_secret: x_root_secret.as_str(),
        db_password: db_password.as_str(),
        jwt_secret: jwt_secret.as_str(),
        registry: args.registry.as_str(),
        tag: tag.as_str(),
        lic_url: lic_url.as_str(),
        enterprise,
        vpn_cidr: vpn_cidr.as_deref(),
        telegram_bot_token: args.telegram_bot_token.as_deref(),
    };

    if let Some(target) = ssh.as_ref() {
        check_docker_prereqs_remote(target)?;
        write_host_files_remote(target, &host_dir, &inputs)?;
        if !args.no_pull {
            remote_compose(target, &host_dir, &["pull"])?;
        }
        remote_compose(target, &host_dir, &["up", "-d", "--force-recreate"])?;
        wait_health_remote(
            target,
            Duration::from_secs(args.health_timeout.max(1) as u64),
        )?;
        let effective_api_url = maybe_setup_https_remote(target, https.as_ref())?.unwrap_or(api_url.clone());
        let status = bootstrap_admin_remote(
            target,
            &bootstrap_base,
            &x_root_secret,
            &admin_username,
            &admin_password,
            &args.admin_api_key_name,
        )?;
        return report_bootstrap_result(status, host_dir.as_path(), &effective_api_url, &admin_username);
    }

    check_docker_prereqs_local()?;
    write_host_files_local(host_dir.as_path(), &inputs)?;
    if !args.no_pull {
        local_compose(host_dir.as_path(), &["pull"])?;
    }
    local_compose(host_dir.as_path(), &["up", "-d", "--force-recreate"])?;
    wait_health_local(
        &format!("{}/health", bootstrap_base),
        Duration::from_secs(args.health_timeout.max(1) as u64),
    )?;
    let effective_api_url = maybe_setup_https_local(https.as_ref())?.unwrap_or(api_url.clone());
    let status = bootstrap_admin_local(
        &bootstrap_base,
        &x_root_secret,
        &admin_username,
        &admin_password,
        &args.admin_api_key_name,
    )?;
    report_bootstrap_result(status, host_dir.as_path(), &effective_api_url, &admin_username)
}

fn report_bootstrap_result(
    status: u16,
    host_dir: &Path,
    api_url: &str,
    admin_username: &str,
) -> io::Result<i32> {
    if status == 200 {
        crate::console::ok("Host API installed and admin bootstrap completed.");
        crate::console::info(&format!("Host dir: {}", host_dir.display()));
        crate::console::info(&format!(
            "Login: saharoctl auth login --base-url {} --username {}",
            api_url, admin_username
        ));
        return Ok(0);
    }
    if status == 409 {
        crate::console::warn("Admin already exists; Host API install completed.");
        crate::console::info(&format!("Host dir: {}", host_dir.display()));
        return Ok(0);
    }
    crate::console::err(&format!("Admin bootstrap failed with HTTP {}.", status));
    Ok(2)
}

#[derive(Debug, Clone)]
struct SshTarget {
    host: String,
    port: i64,
    key: Option<String>,
    password: Option<String>,
    sudo: bool,
}

impl SshTarget {
    fn is_root(&self) -> bool {
        self.host
            .split('@')
            .next()
            .map(|v| v == "root")
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct HttpsSetupInputs {
    domain: String,
    email: String,
    http01: bool,
}

fn resolve_https_inputs(
    api_url: &str,
    skip_https: bool,
    domain_arg: Option<String>,
    email_arg: Option<String>,
    http01: bool,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<Option<HttpsSetupInputs>> {
    if skip_https {
        crate::console::info("`--skip-https` set: HTTPS setup phase is skipped.");
        return Ok(None);
    }
    let url_is_https = api_url.starts_with("https://");
    let explicit_https = domain_arg.as_ref().is_some_and(|v| !v.trim().is_empty())
        || email_arg.as_ref().is_some_and(|v| !v.trim().is_empty());
    let mut enabled = url_is_https || explicit_https;
    if interactive {
        enabled = ask_yes_no(
            theme,
            "Install nginx + Let's Encrypt HTTPS now?",
            url_is_https,
        )?;
    }
    if !enabled {
        return Ok(None);
    }

    let mut domain = domain_arg
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| extract_host_from_url(api_url));
    if domain.is_none() && interactive {
        let picked: String = Input::with_theme(theme)
            .with_prompt("HTTPS domain")
            .interact_text()
            .map_err(dialoguer_err)?;
        let cleaned = picked.trim().to_string();
        if !cleaned.is_empty() {
            domain = Some(cleaned);
        }
    }
    let domain = domain.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPS domain is required (pass --https-domain or provide full --api-url)",
        )
    })?;

    let mut email = email_arg
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_default();
    if email.is_empty() && interactive {
        email = Input::with_theme(theme)
            .with_prompt("Let's Encrypt email")
            .interact_text()
            .map_err(dialoguer_err)?;
        email = email.trim().to_string();
    }
    if email.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPS requested but --https-email is missing",
        ));
    }

    Ok(Some(HttpsSetupInputs {
        domain,
        email,
        http01,
    }))
}

fn resolve_ssh_target(
    args: &JoinHostArgs,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<Option<SshTarget>> {
    let mut ssh_host = args.ssh_host.clone().unwrap_or_default().trim().to_string();
    let mut ssh_user = args.ssh_user.trim().to_string();
    if ssh_user.is_empty() {
        ssh_user = "root".to_string();
    }
    if ssh_host.is_empty() && interactive {
        let use_remote = ask_yes_no(theme, "Install on a remote host via SSH?", false)?;
        if use_remote {
            let host: String = Input::with_theme(theme)
                .with_prompt("SSH host (e.g. 203.0.113.10)")
                .interact_text()
                .map_err(dialoguer_err)?;
            let user: String = Input::with_theme(theme)
                .with_prompt("SSH user")
                .allow_empty(true)
                .interact_text()
                .map_err(dialoguer_err)?;
            let picked_user = if user.trim().is_empty() {
                "root"
            } else {
                user.trim()
            };
            ssh_host = format!("{}@{}", picked_user, host.trim());
        }
    } else if interactive && !ssh_host.is_empty() && !ssh_host.contains('@') {
        let user: String = Input::with_theme(theme)
            .with_prompt("SSH user (empty = root)")
            .allow_empty(true)
            .interact_text()
            .map_err(dialoguer_err)?;
        ssh_user = if user.trim().is_empty() {
            "root".to_string()
        } else {
            user.trim().to_string()
        };
    }
    if !ssh_host.is_empty() && !ssh_host.contains('@') {
        ssh_host = format!("{}@{}", ssh_user, ssh_host);
    }
    if !ssh_host.is_empty() {
        let mut split = ssh_host.splitn(2, '@');
        let user = split.next().unwrap_or_default().trim();
        let host = split.next().unwrap_or_default().trim();
        if !user.is_empty() && !host.is_empty() {
            ssh_host = format!("{}@{}", user, host);
        }
    }
    if ssh_host.is_empty() {
        return Ok(None);
    }

    let mut ssh_key = args.ssh_key.clone().filter(|v| !v.trim().is_empty());
    let mut ssh_password = args.ssh_password.clone().filter(|v| !v.trim().is_empty());
    let mut ssh_port = args.ssh_port.max(1);
    if interactive {
        let entered: String = Input::with_theme(theme)
            .with_prompt("SSH port")
            .default(ssh_port.to_string())
            .interact_text()
            .map_err(dialoguer_err)?;
        ssh_port = entered.parse::<i64>().ok().unwrap_or(22);

        if ssh_key.is_none() && ssh_password.is_none() {
            let use_key = ask_yes_no(theme, "Use an SSH private key for authentication?", true)?;
            if use_key {
                let key: String = Input::with_theme(theme)
                    .with_prompt("SSH private key path")
                    .default("~/.ssh/id_ed25519".to_string())
                    .interact_text()
                    .map_err(dialoguer_err)?;
                let trimmed = key.trim().to_string();
                if !trimmed.is_empty() {
                    ssh_key = Some(trimmed);
                }
            } else {
                let password = Password::with_theme(theme)
                    .with_prompt("SSH password")
                    .allow_empty_password(true)
                    .interact()
                    .map_err(dialoguer_err)?;
                if !password.trim().is_empty() {
                    ssh_password = Some(password);
                }
            }
        }
    }

    Ok(Some(SshTarget {
        host: ssh_host,
        port: ssh_port,
        key: ssh_key,
        password: ssh_password,
        sudo: false,
    }))
}

fn ensure_wipe_confirmed(
    confirm_wipe: bool,
    yes: bool,
    non_interactive: bool,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<()> {
    if non_interactive {
        if yes && confirm_wipe {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--wipe-data requires --yes and --confirm-wipe in non-interactive mode",
        ));
    }
    if !interactive {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interactive wipe confirmation required",
        ));
    }
    let typed: String = Input::with_theme(theme)
        .with_prompt("DANGEROUS: type WIPE to confirm data deletion")
        .interact_text()
        .map_err(dialoguer_err)?;
    if typed == "WIPE" {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "wipe aborted"))
    }
}

fn local_wipe_data(host_dir: &Path) -> io::Result<()> {
    let compose_path = host_dir.join("docker-compose.yml");
    if compose_path.exists() {
        let _ = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&compose_path)
            .arg("down")
            .status();
    }
    let data_dir = host_dir.join("data").join("postgres");
    if data_dir.exists() {
        fs::remove_dir_all(&data_dir)?;
        crate::console::warn(&format!("Deleted {}", data_dir.display()));
    }
    Ok(())
}

fn remote_wipe_data(target: &SshTarget, host_dir: &Path) -> io::Result<()> {
    let host_dir_s = host_dir.to_string_lossy();
    let compose = format!("{}/docker-compose.yml", host_dir_s);
    let data = format!("{}/data/postgres", host_dir_s);
    let down = format!("docker compose -f {} down || true", shell_quote(&compose));
    let rm = format!("rm -rf {}", shell_quote(&data));
    run_ssh(target, &with_sudo(target, &format!("{down}; {rm}")))?;
    Ok(())
}

fn required_value(
    value: Option<String>,
    prompt: &str,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<String> {
    let trimmed = value.unwrap_or_default().trim().to_string();
    if !trimmed.is_empty() {
        return Ok(trimmed);
    }
    if !interactive {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required flag for: {prompt}"),
        ));
    }
    Input::with_theme(theme)
        .with_prompt(prompt)
        .interact_text()
        .map(|s: String| s.trim().to_string())
        .map_err(dialoguer_err)
}

fn optional_prompt(
    value: Option<String>,
    prompt: &str,
    default: &str,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<String> {
    let trimmed = value.unwrap_or_default().trim().to_string();
    if !trimmed.is_empty() {
        return Ok(trimmed);
    }
    if !interactive {
        return Ok(default.to_string());
    }
    Input::with_theme(theme)
        .with_prompt(prompt)
        .default(default.to_string())
        .interact_text()
        .map(|s: String| s.trim().to_string())
        .map_err(dialoguer_err)
}

fn password_value(
    value: Option<String>,
    prompt: &str,
    interactive: bool,
    theme: &ColorfulTheme,
    non_interactive: bool,
) -> io::Result<String> {
    let trimmed = value.unwrap_or_default().trim().to_string();
    if !trimmed.is_empty() {
        return Ok(trimmed);
    }
    if non_interactive {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required flag for: {prompt}"),
        ));
    }
    if !interactive {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interactive password prompt required",
        ));
    }
    Password::with_theme(theme)
        .with_prompt(prompt)
        .with_confirmation("Repeat admin password", "Passwords do not match")
        .interact()
        .map_err(dialoguer_err)
}

fn secret_value(
    value: Option<String>,
    prompt: &str,
    interactive: bool,
    theme: &ColorfulTheme,
    non_interactive: bool,
) -> io::Result<String> {
    let trimmed = value.unwrap_or_default().trim().to_string();
    if !trimmed.is_empty() {
        return Ok(trimmed);
    }
    if non_interactive {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required flag for: {prompt}"),
        ));
    }
    if !interactive {
        return Ok(generate_secret_token());
    }
    let typed = Password::with_theme(theme)
        .with_prompt(format!("{prompt} (leave empty to auto-generate)"))
        .allow_empty_password(true)
        .interact()
        .map_err(dialoguer_err)?;
    if typed.trim().is_empty() {
        Ok(generate_secret_token())
    } else {
        Ok(typed)
    }
}

fn resolve_enterprise(
    value: Option<bool>,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<bool> {
    if let Some(v) = value {
        return Ok(v);
    }
    if !interactive {
        return Ok(false);
    }
    ask_yes_no(theme, "Enable enterprise mode?", false)
}

fn resolve_vpn_cidr(
    value: Option<String>,
    interactive: bool,
    theme: &ColorfulTheme,
) -> io::Result<Option<String>> {
    if let Some(v) = value {
        let s = v.trim().to_string();
        if s.is_empty() {
            return Ok(None);
        }
        return Ok(Some(s));
    }
    if !interactive {
        return Ok(None);
    }
    let enabled = ask_yes_no(theme, "Restrict Host API/web access to VPN CIDR?", false)?;
    if !enabled {
        return Ok(None);
    }
    let cidr: String = Input::with_theme(theme)
        .with_prompt("VPN CIDR")
        .default("10.8.0.0/24".to_string())
        .interact_text()
        .map_err(dialoguer_err)?;
    let out = cidr.trim().to_string();
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn normalize_api_url(raw: &str) -> io::Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "API URL cannot be empty",
        ));
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        return Ok(value.to_string());
    }
    Ok(format!("http://{value}"))
}

fn extract_host_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme.split('/').next().unwrap_or("").trim();
    if host_port.is_empty() {
        return None;
    }
    let host = host_port.split(':').next().unwrap_or("").trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn render_nginx_site(domain: &str) -> String {
    format!(
        "server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    location / {{
        proxy_pass http://127.0.0.1:{DEFAULT_API_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"
    )
}

fn resolve_latest_host_tag_from_license_api(lic_url: &str) -> io::Result<String> {
    let base = lic_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "license API URL is empty",
        ));
    }
    let url = format!("{base}/v1/releases?channel=stable&limit=50");
    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let response = client
        .get(&url)
        .send()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("HTTP {}", response.status().as_u16()),
        ));
    }
    let payload = response
        .json::<serde_json::Value>()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("invalid JSON: {e}")))?;
    let rows = payload.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "invalid releases payload: expected array",
        )
    })?;

    let mut best: Option<(Version, String)> = None;
    for row in rows {
        let version_raw = row
            .get("version")
            .and_then(|v| v.as_str())
            .map(|v| v.trim())
            .unwrap_or("");
        if version_raw.is_empty() {
            continue;
        }
        let normalized = version_raw.trim_start_matches('v');
        let parsed = match Version::parse(normalized) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match &best {
            Some((b, _)) if parsed <= *b => {}
            _ => best = Some((parsed, normalized.to_string())),
        }
    }

    best.map(|(_, s)| s).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "no semver release versions found in license API response",
        )
    })
}

fn generate_secret_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(43)
        .map(char::from)
        .collect()
}

fn read_existing_jwt_secret(host_dir: &Path) -> Option<String> {
    let env_path = host_dir.join(".env");
    let content = fs::read_to_string(env_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("JWT_SECRET=") {
            if !rest.trim().is_empty() {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

fn check_docker_prereqs_local() -> io::Result<()> {
    run_local(
        "docker",
        &["compose", "version"],
        "docker compose is required",
    )?;
    run_local(
        "docker",
        &["info"],
        "docker daemon is not running or not accessible",
    )?;
    Ok(())
}

fn check_docker_prereqs_remote(target: &SshTarget) -> io::Result<()> {
    run_ssh(target, "docker compose version >/dev/null 2>&1 || exit 20")?;
    run_ssh(target, "docker info >/dev/null 2>&1 || exit 21")?;
    Ok(())
}

fn maybe_setup_https_local(https: Option<&HttpsSetupInputs>) -> io::Result<Option<String>> {
    let Some(https) = https else {
        return Ok(None);
    };
    crate::console::info("Configuring HTTPS (nginx + certbot)...");
    ensure_https_local(https)?;
    Ok(Some(format!("https://{}", https.domain)))
}

fn maybe_setup_https_remote(
    target: &SshTarget,
    https: Option<&HttpsSetupInputs>,
) -> io::Result<Option<String>> {
    let Some(https) = https else {
        return Ok(None);
    };
    crate::console::info("Configuring HTTPS on remote host (nginx + certbot)...");
    ensure_https_remote(target, https)?;
    Ok(Some(format!("https://{}", https.domain)))
}

fn ensure_https_local(https: &HttpsSetupInputs) -> io::Result<()> {
    if !https.http01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only http-01 HTTPS flow is supported in Rust CLI right now",
        ));
    }
    run_local_shell("apt-get update", true)?;
    run_local_shell("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx", true)?;
    let conf = render_nginx_site(&https.domain);
    write_local_file_with_sudo("/etc/nginx/sites-available/saharo.conf", &conf)?;
    run_local_shell("ln -sf /etc/nginx/sites-available/saharo.conf /etc/nginx/sites-enabled/saharo.conf", true)?;
    run_local_shell("rm -f /etc/nginx/sites-enabled/default", true)?;
    run_local_shell("nginx -t", true)?;
    run_local_shell("systemctl reload nginx || service nginx reload || nginx -s reload", true)?;
    run_local_shell(
        &format!(
            "certbot --nginx -d {} -m {} --agree-tos --no-eff-email --redirect -n",
            shell_quote(&https.domain),
            shell_quote(&https.email)
        ),
        true,
    )?;
    Ok(())
}

fn ensure_https_remote(target: &SshTarget, https: &HttpsSetupInputs) -> io::Result<()> {
    if !https.http01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only http-01 HTTPS flow is supported in Rust CLI right now",
        ));
    }
    run_ssh(target, &with_sudo(target, "apt-get update"))?;
    run_ssh(
        target,
        &with_sudo(
            target,
            "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx",
        ),
    )?;
    write_remote_file(
        target,
        "/etc/nginx/sites-available/saharo.conf",
        &render_nginx_site(&https.domain),
        true,
    )?;
    run_ssh(
        target,
        &with_sudo(
            target,
            "ln -sf /etc/nginx/sites-available/saharo.conf /etc/nginx/sites-enabled/saharo.conf",
        ),
    )?;
    run_ssh(target, &with_sudo(target, "rm -f /etc/nginx/sites-enabled/default"))?;
    run_ssh(target, &with_sudo(target, "nginx -t"))?;
    run_ssh(
        target,
        &with_sudo(
            target,
            "systemctl reload nginx || service nginx reload || nginx -s reload",
        ),
    )?;
    run_ssh(
        target,
        &with_sudo(
            target,
            &format!(
                "certbot --nginx -d {} -m {} --agree-tos --no-eff-email --redirect -n",
                shell_quote(&https.domain),
                shell_quote(&https.email)
            ),
        ),
    )?;
    Ok(())
}

fn run_local(bin: &str, args: &[&str], fail_message: &str) -> io::Result<()> {
    let status = Command::new(bin).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            fail_message.to_string(),
        ))
    }
}

fn run_local_shell(command: &str, sudo: bool) -> io::Result<()> {
    let wrapped = if sudo {
        format!("sudo sh -lc {}", shell_quote(command))
    } else {
        command.to_string()
    };
    let status = Command::new("sh").arg("-lc").arg(wrapped).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("local command failed: {command}"),
        ))
    }
}

fn write_local_file_with_sudo(path: &str, content: &str) -> io::Result<()> {
    let encoded = BASE64.encode(content.as_bytes());
    let cmd = format!(
        "printf '%s' {} | base64 -d | sudo tee {} >/dev/null",
        shell_quote(&encoded),
        shell_quote(path)
    );
    run_local_shell(&cmd, false)
}

fn local_compose(host_dir: &Path, args: &[&str]) -> io::Result<()> {
    let compose = host_dir.join("docker-compose.yml");
    let env = host_dir.join(".env");
    let status = Command::new("docker")
        .arg("compose")
        .arg("--env-file")
        .arg(env)
        .arg("-f")
        .arg(compose)
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("docker compose {} failed", args.join(" ")),
        ))
    }
}

fn remote_compose(target: &SshTarget, host_dir: &Path, args: &[&str]) -> io::Result<()> {
    let host_dir_s = host_dir.to_string_lossy();
    let compose = format!("{}/docker-compose.yml", host_dir_s);
    let env = format!("{}/.env", host_dir_s);
    let cmd = format!(
        "docker compose --env-file {} -f {} {}",
        shell_quote(&env),
        shell_quote(&compose),
        args.join(" ")
    );
    run_ssh(target, &with_sudo(target, &cmd))
}

fn write_host_files_local(host_dir: &Path, inputs: &RenderInputs<'_>) -> io::Result<()> {
    fs::create_dir_all(host_dir.join("data").join("postgres"))?;
    let state_dir = host_dir.join("state");
    fs::create_dir_all(&state_dir)?;

    let compose = render_compose(inputs);
    let env = render_env(inputs);
    let readme = render_readme(host_dir);
    let script = render_vpn_lockdown_script(inputs);

    let compose_path = host_dir.join("docker-compose.yml");
    let env_path = host_dir.join(".env");
    let readme_path = host_dir.join("README.txt");
    let vpn_path = host_dir.join("apply-vpn-lockdown.sh");

    fs::write(&compose_path, compose)?;
    fs::write(&env_path, env)?;
    fs::write(&readme_path, readme)?;
    fs::write(&vpn_path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&vpn_path, fs::Permissions::from_mode(0o700))?;
        if let Err(err) = chown_state_dir_local(&state_dir) {
            crate::console::warn(&format!(
                "Could not set ownership on {} (10001:10001): {}",
                state_dir.display(),
                err
            ));
        }
    }
    Ok(())
}

fn write_host_files_remote(
    target: &SshTarget,
    host_dir: &Path,
    inputs: &RenderInputs<'_>,
) -> io::Result<()> {
    let host_dir_s = host_dir.to_string_lossy();
    let compose_path = format!("{}/docker-compose.yml", host_dir_s);
    let env_path = format!("{}/.env", host_dir_s);
    let readme_path = format!("{}/README.txt", host_dir_s);
    let vpn_path = format!("{}/apply-vpn-lockdown.sh", host_dir_s);
    run_ssh(
        target,
        &with_sudo(
            target,
            &format!(
                "mkdir -p {} {} {}",
                shell_quote(&(host_dir_s.to_string() + "/data/postgres")),
                shell_quote(&(host_dir_s.to_string() + "/state")),
                shell_quote(&host_dir_s)
            ),
        ),
    )?;
    write_remote_file(target, &compose_path, &render_compose(inputs), true)?;
    write_remote_file(target, &env_path, &render_env(inputs), true)?;
    write_remote_file(target, &readme_path, &render_readme(host_dir), true)?;
    write_remote_file(target, &vpn_path, &render_vpn_lockdown_script(inputs), true)?;
    run_ssh(
        target,
        &with_sudo(target, &format!("chmod 600 {}", shell_quote(&env_path))),
    )?;
    run_ssh(
        target,
        &with_sudo(target, &format!("chmod 700 {}", shell_quote(&vpn_path))),
    )?;
    let state_path = format!("{}/state", host_dir_s);
    if let Err(err) = run_ssh(
        target,
        &with_sudo(
            target,
            &format!("chown -R 10001:10001 {}", shell_quote(&state_path)),
        ),
    ) {
        crate::console::warn(&format!(
            "Could not set ownership on remote state dir {} (10001:10001): {}",
            state_path, err
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn chown_state_dir_local(state_dir: &Path) -> io::Result<()> {
    let status = Command::new("chown")
        .arg("-R")
        .arg("10001:10001")
        .arg(state_dir)
        .status()?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("chown exited with status {}", status),
    ))
}

fn write_remote_file(target: &SshTarget, path: &str, content: &str, sudo: bool) -> io::Result<()> {
    let encoded = BASE64.encode(content.as_bytes());
    let cmd = format!(
        "printf '%s' {} | base64 -d > {}",
        shell_quote(&encoded),
        shell_quote(path)
    );
    if sudo {
        let wrapped = with_sudo(target, &cmd);
        run_ssh(target, &wrapped)
    } else {
        run_ssh(target, &cmd)
    }
}

fn wait_health_local(url: &str, timeout: Duration) -> io::Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(resp) = client.get(url).send() {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("health endpoint did not become ready: {url}"),
    ))
}

fn wait_health_remote(target: &SshTarget, timeout: Duration) -> io::Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        let check = run_ssh_capture(
            target,
            "curl -fsS http://127.0.0.1:8010/health >/dev/null 2>&1; echo $?",
        )?;
        if check.trim() == "0" {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "remote health endpoint did not become ready in time",
    ))
}

fn bootstrap_admin_local(
    base_url: &str,
    root_secret: &str,
    username: &str,
    password: &str,
    api_key_name: &str,
) -> io::Result<u16> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let url = format!("{}/admin/bootstrap", base_url.trim_end_matches('/'));
    let payload = json!({
        "username": username,
        "password": password,
        "api_key_name": api_key_name,
    });
    let response = client
        .post(&url)
        .header("X-Root-Secret", root_secret)
        .json(&payload)
        .send()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("bootstrap request failed: {e}"),
            )
        })?;
    Ok(response.status().as_u16())
}

fn bootstrap_admin_remote(
    target: &SshTarget,
    base_url: &str,
    root_secret: &str,
    username: &str,
    password: &str,
    api_key_name: &str,
) -> io::Result<u16> {
    let payload = serde_json::to_string(&json!({
        "username": username,
        "password": password,
        "api_key_name": api_key_name,
    }))
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let header_secret = format!("X-Root-Secret: {root_secret}");
    let endpoint = format!("{}/admin/bootstrap", base_url.trim_end_matches('/'));
    let cmd = format!(
        "curl -sS -o /tmp/saharo_bootstrap_resp.json -w '%{{http_code}}' -X POST \
         -H {} -H {} --data {} {}",
        shell_quote("Content-Type: application/json"),
        shell_quote(&header_secret),
        shell_quote(&payload),
        shell_quote(&endpoint),
    );
    let out = run_ssh_capture(target, &with_sudo(target, &cmd))?;
    let code = out.trim().parse::<u16>().ok().unwrap_or(0);
    Ok(code)
}

fn with_sudo(target: &SshTarget, cmd: &str) -> String {
    if target.sudo {
        format!("sudo sh -lc {}", shell_quote(cmd))
    } else {
        cmd.to_string()
    }
}

fn run_ssh(target: &SshTarget, command: &str) -> io::Result<()> {
    let status = ssh_command(target, command).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("remote command failed: {command}"),
        ))
    }
}

fn run_ssh_capture(target: &SshTarget, command: &str) -> io::Result<String> {
    let output = ssh_command(target, command).output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

fn ssh_command(target: &SshTarget, command: &str) -> Command {
    if let Some(password) = target.password.as_ref() {
        let mut cmd = Command::new("sshpass");
        cmd.arg("-p").arg(password);
        cmd.arg("ssh");
        add_ssh_common_args(&mut cmd, target, command);
        return cmd;
    }
    let mut cmd = Command::new("ssh");
    add_ssh_common_args(&mut cmd, target, command);
    cmd
}

fn add_ssh_common_args(cmd: &mut Command, target: &SshTarget, command: &str) {
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-p").arg(target.port.to_string());
    if let Some(key) = target.key.as_ref() {
        cmd.arg("-i").arg(expand_home(key));
    }
    cmd.arg(&target.host);
    cmd.arg(command);
}

fn expand_home(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

struct RenderInputs<'a> {
    api_url: &'a str,
    host_name: &'a str,
    x_root_secret: &'a str,
    db_password: &'a str,
    jwt_secret: &'a str,
    registry: &'a str,
    tag: &'a str,
    lic_url: &'a str,
    enterprise: bool,
    vpn_cidr: Option<&'a str>,
    telegram_bot_token: Option<&'a str>,
}

fn render_compose(i: &RenderInputs<'_>) -> String {
    let image = format!(
        "{}/saharo/v1/{}:{}",
        i.registry, HOST_IMAGE_COMPONENT, i.tag
    );
    let node_provisioner_image = format!("{}/saharo/v1/node-provisioner:{}", i.registry, i.tag);
    let agent_control_plane_image =
        format!("{}/saharo/v1/agent-control-plane:{}", i.registry, i.tag);
    let mut out = format!(
        "services:\n  db:\n    image: postgres:16-alpine\n    container_name: saharo_host_db\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: ${{POSTGRES_DB}}\n      POSTGRES_USER: ${{POSTGRES_USER}}\n      POSTGRES_PASSWORD: ${{POSTGRES_PASSWORD}}\n    volumes:\n      - ./data/postgres:/var/lib/postgresql/data\n    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready -U $${{POSTGRES_USER}} -d $${{POSTGRES_DB}}\"]\n      interval: 10s\n      timeout: 5s\n      retries: 5\n  api:\n    image: {image}\n    container_name: saharo_host_api\n    restart: unless-stopped\n    env_file:\n      - ./.env\n    depends_on:\n      db:\n        condition: service_healthy\n    ports:\n      - \"127.0.0.1:8010:8010\"\n    volumes:\n      - ./state:/opt/saharo/host/state\n      - /var/run/docker.sock:/var/run/docker.sock\n    healthcheck:\n      test: [\"CMD-SHELL\", \"python -c \\\"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health').read()\\\"\"]\n      interval: 10s\n      timeout: 5s\n      retries: 5\n  node-provisioner:\n    image: {node_provisioner_image}\n    container_name: saharo_node_provisioner\n    restart: unless-stopped\n    env_file:\n      - ./.env\n    depends_on:\n      db:\n        condition: service_healthy\n    volumes:\n      - ./state:/opt/saharo/host/state\n  agent-control-plane:\n    image: {agent_control_plane_image}\n    container_name: saharo_agent_control_plane\n    restart: unless-stopped\n    env_file:\n      - ./.env\n    depends_on:\n      db:\n        condition: service_healthy\n    ports:\n      - \"50051:50051\"\n    volumes:\n      - ./state:/opt/saharo/host/state\n"
    );
    if i.enterprise {
        out.push_str(&format!(
            "  enterprise-policy:\n    image: {}/saharo/v1/enterprise-policy:{}\n    container_name: saharo_enterprise_policy\n    restart: unless-stopped\n    env_file:\n      - ./.env\n    ports:\n      - \"127.0.0.1:8091:8091\"\n",
            i.registry, i.tag
        ));
    }
    out
}

fn render_env(i: &RenderInputs<'_>) -> String {
    let internal_token = i.jwt_secret;
    let mut lines = vec![
        format!("APP_VERSION={}", i.tag),
        format!("HOST_NAME={}", i.host_name),
        "ENV=prod".to_string(),
        "LOG_LEVEL=info".to_string(),
        "POSTGRES_DB=saharo".to_string(),
        "POSTGRES_USER=saharo".to_string(),
        format!("POSTGRES_PASSWORD={}", i.db_password),
        format!(
            "DATABASE_URL=postgresql://saharo:{}@db:5432/saharo",
            i.db_password
        ),
        "DB_POOL_MIN=1".to_string(),
        "DB_POOL_MAX=5".to_string(),
        format!("CORS_ALLOW_ORIGINS={}", i.api_url),
        "CORS_ALLOW_CREDENTIALS=true".to_string(),
        format!("JWT_SECRET={}", i.jwt_secret),
        format!("LICENSE_API_URL={}", i.lic_url),
        "TELEMETRY_REPORT_INTERVAL_HOURS=1".to_string(),
        format!(
            "ENTERPRISE_ENABLED={}",
            if i.enterprise { "true" } else { "false" }
        ),
        format!("VPN_CIDR={}", i.vpn_cidr.unwrap_or("")),
        format!(
            "VPN_LOCKDOWN_ENABLED={}",
            if i.vpn_cidr.is_some() {
                "true"
            } else {
                "false"
            }
        ),
        format!("ROOT_ADMIN_SECRET={}", i.x_root_secret),
        "AGENT_CONTROL_PLANE_GRPC_ENABLED=true".to_string(),
        "AGENT_CONTROL_PLANE_GRPC_BIND=0.0.0.0:50051".to_string(),
        "AGENT_CONTROL_PLANE_URL=http://agent-control-plane:8091".to_string(),
        "AGENT_CONTROL_PLANE_TIMEOUT_S=20".to_string(),
        "AGENT_CONTROL_PLANE_AUTH_HEADER=X-Internal-Token".to_string(),
        format!("AGENT_CONTROL_PLANE_AUTH_TOKEN={}", internal_token),
        "AGENT_CONTROL_PLANE_BIND=0.0.0.0:8091".to_string(),
        "AGENT_CONTROL_PLANE_INTERNAL_AUTH_HEADER=X-Internal-Token".to_string(),
        format!("AGENT_CONTROL_PLANE_INTERNAL_AUTH_TOKEN={}", internal_token),
        "AGENT_CONTROL_PLANE_STATE_PATH=/opt/saharo/host/state/agent-control-plane-state.json"
            .to_string(),
        "NODE_PROVISIONER_URL=http://node-provisioner:8090".to_string(),
        "NODE_PROVISIONER_TIMEOUT_S=20".to_string(),
        "NODE_PROVISIONER_AUTH_HEADER=X-Internal-Token".to_string(),
        format!("NODE_PROVISIONER_AUTH_TOKEN={}", internal_token),
        "NODE_PROVISIONER_CALLBACK_API_BASE=http://api:8010".to_string(),
        "NODE_PROVISIONER_BIND=0.0.0.0:8090".to_string(),
        "NODE_PROVISIONER_INTERNAL_AUTH_HEADER=X-Internal-Token".to_string(),
        format!("NODE_PROVISIONER_INTERNAL_AUTH_TOKEN={}", internal_token),
        "NODE_PROVISIONER_STATE_PATH=/opt/saharo/host/state/node-provisioner-state.json"
            .to_string(),
    ];
    if let Some(v) = i.telegram_bot_token {
        lines.push(format!("TELEGRAM_BOT_TOKEN={v}"));
    }
    format!("{}\n", lines.join("\n"))
}

fn render_readme(host_dir: &Path) -> String {
    let compose = host_dir.join("docker-compose.yml").display().to_string();
    format!(
        "Saharo Host (API + Postgres)\n\nManage services:\n  docker compose -f {compose} ps\n  docker compose -f {compose} logs -f api\n  docker compose -f {compose} restart api\n\nStop services:\n  docker compose -f {compose} down\n\nStart services:\n  docker compose -f {compose} up -d\n"
    )
}

fn render_vpn_lockdown_script(i: &RenderInputs<'_>) -> String {
    let default_cidr = i.vpn_cidr.unwrap_or("");
    format!(
        "#!/usr/bin/env sh\nset -eu\nDEFAULT_CIDR=\"{default_cidr}\"\nVPN_CIDR=\"${{1:-$DEFAULT_CIDR}}\"\nif [ -z \"$VPN_CIDR\" ]; then\n  echo \"Usage: sudo sh ./apply-vpn-lockdown.sh <vpn-cidr>\"\n  exit 2\nfi\nif ! command -v iptables >/dev/null 2>&1; then\n  echo \"iptables is required\"\n  exit 2\nfi\nCHAIN=\"SAHARO_VPN_ONLY\"\nPORTS=\"${{SAHARO_LOCKDOWN_PORTS:-8010 80 443}}\"\niptables -N \"$CHAIN\" 2>/dev/null || true\niptables -F \"$CHAIN\"\niptables -A \"$CHAIN\" -s 127.0.0.1/32 -j RETURN\niptables -A \"$CHAIN\" -s \"$VPN_CIDR\" -j RETURN\niptables -A \"$CHAIN\" -j DROP\nfor port in $PORTS; do\n  iptables -C INPUT -p tcp --dport \"$port\" -j \"$CHAIN\" 2>/dev/null || iptables -I INPUT 1 -p tcp --dport \"$port\" -j \"$CHAIN\"\ndone\necho \"Saharo VPN lockdown applied for CIDR: $VPN_CIDR\"\n"
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn ask_yes_no(theme: &ColorfulTheme, prompt: &str, default_yes: bool) -> io::Result<bool> {
    let idx = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(&["Yes", "No"])
        .default(if default_yes { 0 } else { 1 })
        .interact()
        .map_err(dialoguer_err)?;
    Ok(idx == 0)
}

fn dialoguer_err(err: dialoguer::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> RenderInputs<'static> {
        RenderInputs {
            api_url: "https://example.com",
            host_name: "Host API",
            x_root_secret: "root-secret",
            db_password: "db-pass",
            jwt_secret: "jwt-secret",
            registry: "registry.example.com",
            tag: "1.2.3",
            lic_url: "https://lic.example.com",
            enterprise: false,
            vpn_cidr: None,
            telegram_bot_token: None,
        }
    }

    #[test]
    fn render_compose_includes_node_provisioner() {
        let out = render_compose(&sample_inputs());
        assert!(out.contains("node-provisioner"));
        assert!(out.contains("saharo_node_provisioner"));
        assert!(out.contains("registry.example.com/saharo/v1/node-provisioner:1.2.3"));
        assert!(out.contains("agent-control-plane"));
        assert!(out.contains("saharo_agent_control_plane"));
        assert!(out.contains("registry.example.com/saharo/v1/agent-control-plane:1.2.3"));
        assert!(out.contains("50051:50051"));
        assert!(!out.contains("127.0.0.1:8010:8010\"\n      - \"50051:50051"));
    }

    #[test]
    fn render_env_includes_node_provisioner_settings() {
        let out = render_env(&sample_inputs());
        assert!(out.contains("NODE_PROVISIONER_URL=http://node-provisioner:8090"));
        assert!(out.contains("NODE_PROVISIONER_CALLBACK_API_BASE=http://api:8010"));
        assert!(out.contains("NODE_PROVISIONER_AUTH_TOKEN=jwt-secret"));
        assert!(out.contains("NODE_PROVISIONER_INTERNAL_AUTH_TOKEN=jwt-secret"));
        assert!(out.contains(
            "NODE_PROVISIONER_STATE_PATH=/opt/saharo/host/state/node-provisioner-state.json"
        ));
        assert!(out.contains("AGENT_CONTROL_PLANE_URL=http://agent-control-plane:8091"));
        assert!(out.contains("AGENT_CONTROL_PLANE_AUTH_TOKEN=jwt-secret"));
        assert!(out.contains("AGENT_CONTROL_PLANE_INTERNAL_AUTH_TOKEN=jwt-secret"));
        assert!(out.contains(
            "AGENT_CONTROL_PLANE_STATE_PATH=/opt/saharo/host/state/agent-control-plane-state.json"
        ));
        assert!(out.contains("AGENT_CONTROL_PLANE_GRPC_ENABLED=true"));
        assert!(out.contains("AGENT_CONTROL_PLANE_GRPC_BIND=0.0.0.0:50051"));
    }

    #[test]
    fn render_compose_includes_enterprise_policy_when_enabled() {
        let mut inputs = sample_inputs();
        inputs.enterprise = true;

        let out = render_compose(&inputs);

        assert!(out.contains("enterprise-policy"));
        assert!(out.contains("saharo_enterprise_policy"));
        assert!(out.contains("registry.example.com/saharo/v1/enterprise-policy:1.2.3"));
    }
}
