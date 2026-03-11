use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

pub const LICENSE_API_URL_DEFAULT: &str = "https://downloads.saharoktyan.ru";
pub const ENV_LICENSE_API_URL: &str = "SAHARO_LICENSE_API_URL";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_token_type")]
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    pub agent_id: Option<i64>,
    #[serde(default)]
    pub agent_secret: String,
    #[serde(default)]
    pub invite_token: String,
    pub note: Option<String>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_url: String,
    pub license_api_url: String,
    pub auth: AuthConfig,
    pub agents: BTreeMap<String, AgentConfig>,
    pub telemetry: HashMap<String, bool>,
    pub portal_session_token: String,
    pub portal_csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RawConfig {
    base_url: Option<String>,
    license_api_url: Option<String>,
    auth: Option<AuthConfig>,
    agents: Option<BTreeMap<String, AgentConfig>>,
    telemetry: Option<HashMap<String, bool>>,
    portal_session_token: Option<String>,
    portal_csrf_token: Option<String>,
    active_profile: Option<String>,
    profiles: Option<HashMap<String, RawProfile>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RawProfile {
    base_url: Option<String>,
    token: Option<String>,
    token_type: Option<String>,
    license_api_url: Option<String>,
    auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutConfig {
    base_url: String,
    license_api_url: String,
    auth: AuthConfig,
    agents: BTreeMap<String, AgentConfig>,
    telemetry: HashMap<String, bool>,
    portal_session_token: String,
    portal_csrf_token: String,
}

fn default_token_type() -> String {
    "bearer".to_string()
}

pub fn config_path() -> io::Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "saharo").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "unable to resolve user config directory",
        )
    })?;
    Ok(dirs.config_dir().join("config.toml"))
}

pub fn default_config() -> AppConfig {
    AppConfig {
        base_url: "http://127.0.0.1:8010".to_string(),
        license_api_url: LICENSE_API_URL_DEFAULT.to_string(),
        auth: AuthConfig {
            token: String::new(),
            token_type: default_token_type(),
        },
        agents: BTreeMap::new(),
        telemetry: HashMap::new(),
        portal_session_token: String::new(),
        portal_csrf_token: String::new(),
    }
}

pub fn normalize_base_url(raw: &str) -> String {
    let value = raw.trim().trim_end_matches('/').to_string();
    if value.is_empty() {
        return String::new();
    }

    let lowered = value.to_lowercase();
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        return value;
    }

    let host = value
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    let scheme = if matches!(host.as_str(), "localhost" | "127.0.0.1" | "0.0.0.0") {
        "http://"
    } else {
        "https://"
    };
    format!("{scheme}{value}")
}

pub fn load_config() -> io::Result<AppConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(default_config());
    }

    let raw = fs::read_to_string(&path)?;
    let parsed: RawConfig = toml::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {}: {e}", path.display()),
        )
    })?;
    Ok(from_raw(parsed))
}

fn from_raw(raw: RawConfig) -> AppConfig {
    let mut base_url = normalize_base_url(raw.base_url.as_deref().unwrap_or(""));
    let mut license_api_url = raw
        .license_api_url
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let mut auth = raw.auth.unwrap_or_default();

    let agents = raw.agents.unwrap_or_default();
    let telemetry = raw.telemetry.unwrap_or_default();
    let portal_session_token = raw
        .portal_session_token
        .unwrap_or_default()
        .trim()
        .to_string();
    let portal_csrf_token = raw.portal_csrf_token.unwrap_or_default().trim().to_string();

    if base_url.is_empty() {
        if let Some(profiles) = raw.profiles {
            let mut selected: Option<&RawProfile> = None;
            if let Some(active) = raw.active_profile.as_deref() {
                selected = profiles.get(active);
            }
            if selected.is_none() {
                selected = profiles.values().next();
            }
            if let Some(profile) = selected {
                base_url = normalize_base_url(profile.base_url.as_deref().unwrap_or(""));
                if let Some(token) = profile.token.as_deref() {
                    auth.token = token.to_string();
                } else if let Some(profile_auth) = profile.auth.as_ref() {
                    auth.token = profile_auth.token.clone();
                    auth.token_type = profile_auth.token_type.clone();
                }
                if license_api_url.is_empty() {
                    license_api_url = profile
                        .license_api_url
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                }
            }
        }
    }

    if base_url.is_empty() {
        let mut cfg = default_config();
        cfg.agents = agents;
        cfg.telemetry = telemetry;
        cfg.portal_session_token = portal_session_token;
        cfg.portal_csrf_token = portal_csrf_token;
        if !license_api_url.is_empty() {
            cfg.license_api_url = license_api_url;
        }
        return cfg;
    }

    AppConfig {
        base_url,
        license_api_url: if license_api_url.is_empty() {
            LICENSE_API_URL_DEFAULT.to_string()
        } else {
            license_api_url
        },
        auth,
        agents,
        telemetry,
        portal_session_token,
        portal_csrf_token,
    }
}

pub fn save_config(cfg: &AppConfig) -> io::Result<PathBuf> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let out = OutConfig {
        base_url: cfg.base_url.clone(),
        license_api_url: cfg.license_api_url.clone(),
        auth: cfg.auth.clone(),
        agents: cfg.agents.clone(),
        telemetry: cfg.telemetry.clone(),
        portal_session_token: cfg.portal_session_token.clone(),
        portal_csrf_token: cfg.portal_csrf_token.clone(),
    };
    let serialized = toml::to_string(&out).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to serialize config: {e}"),
        )
    })?;
    fs::write(&path, serialized)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(path)
}

pub fn resolve_license_api_url(cfg: &AppConfig) -> String {
    if let Ok(value) = std::env::var(ENV_LICENSE_API_URL) {
        let v = value.trim().trim_end_matches('/').to_string();
        if !v.is_empty() {
            return v;
        }
    }
    let from_cfg = cfg.license_api_url.trim().trim_end_matches('/').to_string();
    if from_cfg.is_empty() {
        LICENSE_API_URL_DEFAULT.to_string()
    } else {
        from_cfg
    }
}
