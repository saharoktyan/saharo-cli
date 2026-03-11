use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::config_path;

#[derive(Debug, Clone)]
pub struct RegistryCredentials {
    pub url: String,
    pub username: String,
    pub password: Option<String>,
    pub issued_at: Option<String>,
    pub license_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryFile {
    registry: Option<RegistryData>,
    issued_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryData {
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    license_key: Option<String>,
}

pub fn registry_path() -> io::Result<PathBuf> {
    let cfg_path = config_path()?;
    let dir = cfg_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid config path"))?;
    Ok(dir.join("registry.toml"))
}

pub fn load_registry() -> io::Result<Option<RegistryCredentials>> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)?;
    let data: RegistryFile = toml::from_str(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {}: {e}", path.display()),
        )
    })?;

    let Some(registry) = data.registry else {
        return Ok(None);
    };

    let url = registry.url.unwrap_or_default().trim().to_string();
    let username = registry.username.unwrap_or_default().trim().to_string();
    if url.is_empty() || username.is_empty() {
        return Ok(None);
    }

    let password = registry.password.and_then(|p| {
        let t = p.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });

    Ok(Some(RegistryCredentials {
        url,
        username,
        password,
        issued_at: data.issued_at.and_then(|v| {
            let t = v.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }),
        license_key: registry.license_key.and_then(|v| {
            let t = v.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }),
    }))
}

pub fn delete_registry() -> io::Result<()> {
    let path = registry_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
