use semver::{Version, VersionReq};
use serde_json::Value;

use crate::models::{CliCompatibility, VersionInfo};
use crate::{ApiClient, ApiError};

pub struct HealthFacade {
    api: ApiClient,
}

impl HealthFacade {
    pub fn new(base_url: &str) -> Result<Self, ApiError> {
        let api = ApiClient::new(base_url, None)?;
        Ok(Self { api })
    }

    pub fn hub_version(&self) -> Result<Value, ApiError> {
        self.api.version()
    }
}

pub fn parse_version_info(data: &Value) -> VersionInfo {
    let obj = data.as_object();
    VersionInfo {
        api_protocol: obj
            .and_then(|o| o.get("api_protocol"))
            .and_then(|v| v.as_i64()),
        supported_cli_range: obj
            .and_then(|o| o.get("supported_cli_range"))
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        api_version: obj
            .and_then(|o| o.get("api_version").or_else(|| o.get("version")))
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    }
}

pub fn evaluate_cli_compatibility(
    current_version: &str,
    current_protocol: i64,
    info: &VersionInfo,
) -> CliCompatibility {
    let protocol_compatible = info
        .api_protocol
        .map(|p| p == current_protocol)
        .unwrap_or(true);
    let version_compatible = info
        .supported_cli_range
        .as_deref()
        .map(|r| is_version_in_range(current_version, r))
        .unwrap_or(true);
    CliCompatibility {
        protocol_compatible,
        version_compatible,
        is_compatible: protocol_compatible && version_compatible,
    }
}

fn is_version_in_range(current: &str, range: &str) -> bool {
    let Ok(v) = Version::parse(current.trim()) else {
        return true;
    };
    let Ok(req) = VersionReq::parse(range.trim()) else {
        return true;
    };
    req.matches(&v)
}
