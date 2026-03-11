# Saharo Client SDK

This SDK provides reusable building blocks for the CLI and future UI clients.
It focuses on pure logic and HTTP calls, avoiding SSH-only workflows.

## Modules

- `saharo_client.client` - HTTP API client wrapper (uses `Transport`).
- `saharo_client.errors` - API/Network/Auth error types.
- `saharo_client.transport` - low-level HTTP transport (httpx client).
- `saharo_client.config_types` - config dataclasses for the client.
- `saharo_client.compat` - compatibility evaluation helpers for `/version`.
- `saharo_client.licensing` - license entitlements resolver and helpers.
- `saharo_client.registry` - registry helpers (normalize host, parse license snapshot).
- `saharo_client.updates` - helpers for update/entitlements parsing and formatting.
- `saharo_client.semver` - semver parsing and range checks.
- `saharo_client.configs` - VPN config/URI builders (AWG).
- `saharo_client.resolve` - ID/selector resolution helpers.
- `saharo_client.jobs` - job helpers (waiter, status hint, normalization).
- `saharo_client.polling` - polling helpers (e.g., server heartbeat).
- `saharo_client.errors_utils` - error detail parsing helpers.

## Public API

The SDK re-exports a curated surface from `saharo_client` for convenience:

```python
from saharo_client import (
    SaharoClient,
    ApiError, AuthError, NetworkError,
    resolve_entitlements,
    evaluate_compatibility,
    build_awg_conf, build_awg_uri,
    resolve_access_target,
    normalize_registry_host,
)
```

For advanced use, import submodules directly:

```python
from saharo_client.registry import extract_registry_creds_from_snapshot
from saharo_client.resolve import resolve_server_id_for_servers
from saharo_client.jobs import wait_job
```

## Common Scenarios

### Authenticate and list servers

```python
from saharo_client import SaharoClient
from saharo_client.config_types import ClientConfig

client = SaharoClient(ClientConfig(base_url="https://api.example.com", token="..."))
servers = client.admin_servers_list(limit=50, offset=0)
print(servers)
client.close()
```

### Check hub compatibility

```python
from saharo_client import evaluate_compatibility

data = {"supported_cli_range": ">=1.2.0,<2.0.0", "api_protocol": 1}
result = evaluate_compatibility(data, current_version="1.3.0", current_protocol=1)
print(result["reasons"])
```

### Resolve license entitlements

```python
from saharo_client import resolve_entitlements

entitlements = resolve_entitlements("https://lic.example.com", "license-key")
print(entitlements.resolved_versions)
```

### Build AmneziaWG config/URI

```python
from saharo_client import build_awg_conf, build_awg_uri

wg_parts = {
    "address": "10.0.0.2",
    "preshared_key": "psk",
    "endpoint": "vpn.example.com:51820",
    "server_public_key": "server-pub",
}
conf = build_awg_conf(private_key="client-priv", wg_parts=wg_parts)
uri = build_awg_uri(private_key="client-priv", public_key="client-pub", wg_parts=wg_parts, name="device")
```

## Stability

- Stable:
  - `SaharoClient` and `Transport`
  - `ApiError`, `AuthError`, `NetworkError`
  - `resolve_entitlements`, `evaluate_compatibility`
  - `build_awg_conf`, `build_awg_uri`
  - `normalize_registry_host`

- Experimental:
  - ID/selector helpers in `saharo_client.resolve`
  - Polling/wait helpers in `saharo_client.jobs` and `saharo_client.polling`
  - Update parsing helpers in `saharo_client.updates`
  - Error parsing helpers in `saharo_client.errors_utils`

## Notes

- HTTP calls are made via `SaharoClient` methods.
- SSH-only workflows stay in the CLI layer.
