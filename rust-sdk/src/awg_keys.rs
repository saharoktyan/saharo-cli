use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone)]
pub struct AwgKeypair {
    pub public_key: String,
    pub private_key: String,
}

pub fn awg_key_dir(base_dir: &Path, server_id: i64, device_label: &str) -> PathBuf {
    base_dir
        .join("keys")
        .join("awg")
        .join(server_id.to_string())
        .join(sanitize_segment(device_label))
}

pub fn load_or_create_awg_keypair(
    base_dir: &Path,
    server_id: i64,
    device_label: &str,
) -> Result<AwgKeypair, String> {
    let path = awg_key_dir(base_dir, server_id, device_label);
    let pub_path = path.join("public.key");
    let priv_path = path.join("private.key");

    if pub_path.exists() && priv_path.exists() {
        let pubk = fs::read_to_string(&pub_path)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        let privk = fs::read_to_string(&priv_path)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        if !pubk.is_empty() && !privk.is_empty() {
            return Ok(AwgKeypair {
                public_key: pubk,
                private_key: privk,
            });
        }
    }

    fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(private.to_bytes());
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

    fs::write(&priv_path, format!("{priv_b64}\n")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    fs::write(&pub_path, format!("{pub_b64}\n")).map_err(|e| e.to_string())?;

    Ok(AwgKeypair {
        public_key: pub_b64,
        private_key: priv_b64,
    })
}

fn sanitize_segment(value: &str) -> String {
    let out = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        "device".to_string()
    } else {
        out
    }
}
