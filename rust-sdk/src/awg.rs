use base64::Engine;
use flate2::{write::ZlibEncoder, Compression};
use serde_json::{json, Value};

const AWG_AMNEZIA_KEYMAP: &[(&str, &str)] = &[
    ("jc", "Jc"),
    ("jmin", "Jmin"),
    ("jmax", "Jmax"),
    ("s1", "S1"),
    ("s2", "S2"),
    ("h1", "H1"),
    ("h2", "H2"),
    ("h3", "H3"),
    ("h4", "H4"),
];

pub fn build_awg_conf(private_key: &str, wg_parts: &Value) -> Result<String, String> {
    let address = get_str(wg_parts, "address");
    let preshared_key = get_str(wg_parts, "preshared_key");
    let endpoint = get_str(wg_parts, "endpoint");
    let server_public_key = get_str(wg_parts, "server_public_key");
    if address.is_empty()
        || preshared_key.is_empty()
        || endpoint.is_empty()
        || server_public_key.is_empty()
    {
        return Err("Config payload missing required WireGuard fields.".to_string());
    }

    let allowed_ips = get_str(wg_parts, "allowed_ips_client");
    let allowed_ips = if allowed_ips.is_empty() {
        "0.0.0.0/0, ::/0".to_string()
    } else {
        allowed_ips
    };
    let keepalive = wg_parts
        .get("keepalive")
        .and_then(|v| v.as_i64())
        .unwrap_or(25);
    let dns = wg_parts.get("dns").cloned().unwrap_or(Value::Null);
    let mtu = wg_parts.get("mtu").cloned().unwrap_or(Value::Null);
    let amnezia = wg_parts.get("amnezia").cloned().unwrap_or(Value::Null);

    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {private_key}"),
        format!("Address = {address}/32"),
    ];

    let mtu_str = value_to_string(&mtu);
    if !mtu_str.is_empty() {
        lines.push(format!("MTU = {mtu_str}"));
    }
    for (k, mapped) in AWG_AMNEZIA_KEYMAP {
        let v = amnezia.get(*k).cloned().unwrap_or(Value::Null);
        let s = value_to_string(&v);
        if !s.is_empty() {
            lines.push(format!("{mapped} = {s}"));
        }
    }
    let dns_string = if let Some(arr) = dns.as_array() {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        value_to_string(&dns)
    };
    if !dns_string.is_empty() {
        lines.push(format!("DNS = {dns_string}"));
    }

    lines.extend([
        "".to_string(),
        "[Peer]".to_string(),
        format!("PublicKey = {server_public_key}"),
        format!("PresharedKey = {preshared_key}"),
        format!("Endpoint = {endpoint}"),
        format!("AllowedIPs = {allowed_ips}"),
        format!("PersistentKeepalive = {keepalive}"),
        "".to_string(),
    ]);

    Ok(lines.join("\n"))
}

pub fn build_awg_uri(
    private_key: &str,
    public_key: &str,
    wg_parts: &Value,
    name: &str,
) -> Result<String, String> {
    let config_text = build_awg_conf(private_key, wg_parts)?;
    let address = get_str(wg_parts, "address");
    let preshared_key = get_str(wg_parts, "preshared_key");
    let endpoint = get_str(wg_parts, "endpoint");
    let server_public_key = get_str(wg_parts, "server_public_key");
    if address.is_empty()
        || preshared_key.is_empty()
        || endpoint.is_empty()
        || server_public_key.is_empty()
    {
        return Err("Config payload missing required WireGuard fields.".to_string());
    }
    let allowed_ips = get_str(wg_parts, "allowed_ips_client");
    let allowed_ips = if allowed_ips.is_empty() {
        "0.0.0.0/0, ::/0".to_string()
    } else {
        allowed_ips
    };
    let keepalive = wg_parts
        .get("keepalive")
        .and_then(|v| v.as_i64())
        .unwrap_or(25);
    let dns = wg_parts.get("dns").cloned().unwrap_or(Value::Null);
    let mtu = wg_parts.get("mtu").cloned().unwrap_or(Value::Null);
    let amnezia = wg_parts.get("amnezia").cloned().unwrap_or(Value::Null);

    let (host_name, port) = parse_endpoint(&endpoint)?;
    let (dns1, dns2) = extract_dns(&dns);
    let allowed_ips_list = extract_allowed_ips(&allowed_ips);

    let mut amnezia_fields = serde_json::Map::new();
    for (k, mapped) in AWG_AMNEZIA_KEYMAP {
        let val = amnezia.get(*k).cloned().unwrap_or(Value::Null);
        let s = value_to_string(&val);
        amnezia_fields.insert((*mapped).to_string(), Value::String(s));
    }

    let mut last_cfg = serde_json::Map::new();
    for (k, v) in &amnezia_fields {
        last_cfg.insert(k.clone(), v.clone());
    }
    last_cfg.insert("allowed_ips".to_string(), json!(allowed_ips_list));
    last_cfg.insert("client_ip".to_string(), Value::String(address));
    last_cfg.insert(
        "client_priv_key".to_string(),
        Value::String(private_key.to_string()),
    );
    last_cfg.insert(
        "client_pub_key".to_string(),
        Value::String(public_key.to_string()),
    );
    last_cfg.insert("psk_key".to_string(), Value::String(preshared_key));
    last_cfg.insert(
        "server_pub_key".to_string(),
        Value::String(server_public_key),
    );
    last_cfg.insert("hostName".to_string(), Value::String(host_name.clone()));
    last_cfg.insert("port".to_string(), json!(port));
    last_cfg.insert("mtu".to_string(), Value::String(value_to_string(&mtu)));
    last_cfg.insert("persistent_keep_alive".to_string(), json!(keepalive));
    last_cfg.insert(
        "transport_proto".to_string(),
        Value::String("udp".to_string()),
    );
    last_cfg.insert("config".to_string(), Value::String(config_text));

    let payload = json!({
        "containers": [
            {
                "container": "amnezia-awg",
                "awg": {
                    "Jc": amnezia_fields.get("Jc").cloned().unwrap_or(Value::String(String::new())),
                    "Jmin": amnezia_fields.get("Jmin").cloned().unwrap_or(Value::String(String::new())),
                    "Jmax": amnezia_fields.get("Jmax").cloned().unwrap_or(Value::String(String::new())),
                    "S1": amnezia_fields.get("S1").cloned().unwrap_or(Value::String(String::new())),
                    "S2": amnezia_fields.get("S2").cloned().unwrap_or(Value::String(String::new())),
                    "H1": amnezia_fields.get("H1").cloned().unwrap_or(Value::String(String::new())),
                    "H2": amnezia_fields.get("H2").cloned().unwrap_or(Value::String(String::new())),
                    "H3": amnezia_fields.get("H3").cloned().unwrap_or(Value::String(String::new())),
                    "H4": amnezia_fields.get("H4").cloned().unwrap_or(Value::String(String::new())),
                    "port": port.to_string(),
                    "transport_proto": "udp",
                    "last_config": serde_json::to_string(&Value::Object(last_cfg)).unwrap_or_default(),
                }
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": name,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host_name,
        "nameOverriddenByUser": true
    });

    let raw = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let packed = qt_qcompress(&raw)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(packed);
    Ok(format!("vpn://{b64}"))
}

fn qt_qcompress(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    use std::io::Write;
    encoder.write_all(raw).map_err(|e| e.to_string())?;
    let compressed = encoder.finish().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    if endpoint.starts_with('[') {
        if let Some(end) = endpoint.find(']') {
            let host = endpoint[1..end].to_string();
            let rest = endpoint[end + 1..].trim();
            if let Some(port_str) = rest.strip_prefix(':') {
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| "Endpoint missing or invalid port.".to_string())?;
                return Ok((host, port));
            }
        }
        return Err("Endpoint missing port.".to_string());
    }
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| "Endpoint missing port.".to_string())?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| "Endpoint missing or invalid port.".to_string())?;
    Ok((host.to_string(), port))
}

fn extract_dns(dns: &Value) -> (String, String) {
    let values = if let Some(arr) = dns.as_array() {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    } else {
        split_csv(&value_to_string(dns))
    };
    let d1 = values.first().cloned().unwrap_or_default();
    let d2 = values.get(1).cloned().unwrap_or_default();
    (d1, d2)
}

fn extract_allowed_ips(allowed_ips: &str) -> Vec<String> {
    split_csv(allowed_ips)
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

fn get_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn value_to_string(v: &Value) -> String {
    if let Some(s) = v.as_str() {
        return s.trim().to_string();
    }
    if let Some(i) = v.as_i64() {
        return i.to_string();
    }
    if let Some(u) = v.as_u64() {
        return u.to_string();
    }
    if let Some(f) = v.as_f64() {
        return f.to_string();
    }
    String::new()
}
