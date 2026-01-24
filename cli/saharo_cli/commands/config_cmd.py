from __future__ import annotations

import base64
import json
import zlib

import typer

from .. import console
from ..config import load_config, save_config, normalize_base_url
from ..http import make_client
from ..keys import load_or_create_awg_keypair, awg_key_dir

app = typer.Typer(help="Fetch VPN client config (server/protocol).")

AWG_AMNEZIA_KEYMAP = {
    "jc": "Jc",
    "jmin": "Jmin",
    "jmax": "Jmax",
    "s1": "S1",
    "s2": "S2",
    "h1": "H1",
    "h2": "H2",
    "h3": "H3",
    "h4": "H4",
}


def _show_config_impl() -> None:
    cfg = load_config()
    token_state = "(set)" if cfg.auth.token else "(empty)"
    console.console.print(f"base_url={cfg.base_url} token={token_state} token_type={cfg.auth.token_type}")


def _set_config_value_impl(
        base_url: str | None = None,
) -> None:
    cfg = load_config()

    if base_url is not None:
        cfg.base_url = normalize_base_url(base_url, warn=True)

    save_config(cfg)
    console.ok("Config updated.")


def _default_device_label() -> str:
    import socket
    return socket.gethostname() or "device"


def _default_output_path(
        protocol: str,
        server_id: int,
        device_label: str,
        *,
        awg_conf: bool = False,
) -> str:
    import os
    from platformdirs import user_config_dir
    from ..config import APP_NAME
    if protocol == "awg":
        filename = "config.conf" if awg_conf else "config.uri"
        return os.path.join(awg_key_dir(server_id, device_label), filename)
    base = os.path.join(user_config_dir(APP_NAME), "configs", protocol, str(server_id))
    safe_label = device_label.replace("/", "_")
    return os.path.join(base, safe_label, "config.txt")


def _resolve_access_target(access: list[dict] | None, server: str, protocol: str) -> tuple[int, str]:
    if not isinstance(access, list) or not access:
        console.err("No access grants found for this account.")
        raise typer.Exit(code=2)

    server_input = (server or "").strip()
    if not server_input:
        console.err("Server is required.")
        raise typer.Exit(code=2)

    server_match = None
    if server_input.isdigit():
        server_id = int(server_input)
        for item in access:
            if int(item.get("id") or -1) == server_id:
                server_match = item
                break
    else:
        for item in access:
            name = str(item.get("name") or "")
            if name.lower() == server_input.lower():
                server_match = item
                break

    if not server_match:
        options = []
        for item in access:
            name = item.get("name")
            options.append(name or f"id={item.get('id')}")
        options_display = ", ".join(sorted({opt for opt in options if opt}))
        console.err(f"Server '{server_input}' is not available for this account.")
        if options_display:
            console.info(f"Available servers: {options_display}")
        raise typer.Exit(code=2)

    protocol_input = (protocol or "").strip().lower()
    desired = {protocol_input}

    protocol_match = None
    for item in server_match.get("protocols") or []:
        key = str(item.get("key") or "").lower()
        name = str(item.get("name") or "").lower()
        if key in desired or name in desired:
            protocol_match = item
            break

    if not protocol_match:
        choices = []
        for item in server_match.get("protocols") or []:
            label = item.get("key") or item.get("name")
            if label:
                choices.append(str(label))
        choices_display = ", ".join(sorted({c for c in choices if c}))
        console.err(f"Protocol '{protocol}' is not available for server '{server_input}'.")
        if choices_display:
            console.info(f"Available protocols: {choices_display}")
        raise typer.Exit(code=2)

    server_id = int(server_match.get("id"))
    protocol_key = protocol_match.get("key") or protocol_match.get("name") or protocol_input
    return server_id, str(protocol_key).lower()


def _build_awg_conf(*, private_key: str, wg_parts: dict) -> str:
    address = wg_parts.get("address")
    preshared_key = wg_parts.get("preshared_key")
    endpoint = wg_parts.get("endpoint")
    server_public_key = wg_parts.get("server_public_key")
    if not all([address, preshared_key, endpoint, server_public_key]):
        console.err("Config payload missing required WireGuard fields.")
        raise typer.Exit(code=2)

    allowed_ips = wg_parts.get("allowed_ips_client") or "0.0.0.0/0, ::/0"
    keepalive = int(wg_parts.get("keepalive") or 25)
    dns = wg_parts.get("dns")
    mtu = wg_parts.get("mtu")
    amnezia = wg_parts.get("amnezia") if isinstance(wg_parts.get("amnezia"), dict) else {}

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}/32",
    ]

    if mtu not in (None, ""):
        lines.append(f"MTU = {mtu}")

    # AmneziaWG obfuscation params (optional)
    for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
        v = amnezia.get(k)
        if v not in (None, ""):
            lines.append(f"{AWG_AMNEZIA_KEYMAP.get(k, k)} = {v}")

    if dns:
        if isinstance(dns, list):
            dns = ", ".join(str(x) for x in dns if str(x).strip())
        lines.append(f"DNS = {dns}")
    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"PresharedKey = {preshared_key}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {allowed_ips}",
        f"PersistentKeepalive = {keepalive}",
        "",
    ])
    return "\n".join(lines)


def _qt_qcompress(raw: bytes, level: int = 9) -> bytes:
    comp = zlib.compress(raw, level)
    return len(raw).to_bytes(4, "big") + comp


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _extract_dns(dns: str | list | None) -> tuple[str, str]:
    if not dns:
        return "", ""
    if isinstance(dns, list):
        values = [str(x).strip() for x in dns if str(x).strip()]
    else:
        values = _split_csv(str(dns))
    dns1 = values[0] if values else ""
    dns2 = values[1] if len(values) > 1 else ""
    return dns1, dns2


def _extract_allowed_ips(allowed_ips: str | list | None) -> list[str]:
    if not allowed_ips:
        return []
    if isinstance(allowed_ips, list):
        return [str(x).strip() for x in allowed_ips if str(x).strip()]
    return _split_csv(str(allowed_ips))


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    if endpoint.startswith("[") and "]" in endpoint:
        host, _, rest = endpoint.partition("]")
        host = host.lstrip("[")
        if rest.startswith(":"):
            return host, int(rest[1:])
        raise ValueError("Endpoint missing port.")
    host, sep, port_str = endpoint.rpartition(":")
    if not sep:
        raise ValueError("Endpoint missing port.")
    return host, int(port_str)


def _build_awg_uri(*, private_key: str, public_key: str, wg_parts: dict, name: str) -> str:
    address = wg_parts.get("address")
    preshared_key = wg_parts.get("preshared_key")
    endpoint = wg_parts.get("endpoint")
    server_public_key = wg_parts.get("server_public_key")
    if not all([address, preshared_key, endpoint, server_public_key]):
        console.err("Config payload missing required WireGuard fields.")
        raise typer.Exit(code=2)

    allowed_ips = wg_parts.get("allowed_ips_client") or "0.0.0.0/0, ::/0"
    keepalive = int(wg_parts.get("keepalive") or 25)
    dns = wg_parts.get("dns")
    mtu = wg_parts.get("mtu")
    amnezia = wg_parts.get("amnezia") if isinstance(wg_parts.get("amnezia"), dict) else {}

    try:
        host_name, port = _parse_endpoint(str(endpoint))
    except ValueError:
        console.err("Config payload has invalid endpoint format.")
        raise typer.Exit(code=2)
    dns1, dns2 = _extract_dns(dns)
    allowed_ips_list = _extract_allowed_ips(allowed_ips)
    config_text = _build_awg_conf(private_key=private_key, wg_parts=wg_parts)

    amnezia_fields = {}
    for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
        v = amnezia.get(k)
        amnezia_fields[AWG_AMNEZIA_KEYMAP.get(k, k)] = "" if v in (None, "") else str(v)

    last_config = {
        **amnezia_fields,
        "allowed_ips": allowed_ips_list,
        "client_ip": str(address),
        "client_priv_key": private_key,
        "client_pub_key": public_key,
        "psk_key": preshared_key,
        "server_pub_key": server_public_key,
        "hostName": host_name,
        "port": port,
        "mtu": "" if mtu in (None, "") else mtu,
        "persistent_keep_alive": keepalive,
        "transport_proto": "udp",
        "config": config_text,
    }

    payload = {
        "containers": [
            {
                "container": "amnezia-awg",
                "awg": {
                    **amnezia_fields,
                    "port": str(port),
                    "transport_proto": "udp",
                    "last_config": json.dumps(last_config, ensure_ascii=False, separators=(",", ":")),
                },
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": name,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host_name,
        "nameOverriddenByUser": True,
    }

    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    packed = _qt_qcompress(raw)
    b64 = base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")
    return f"vpn://{b64}"


@app.command("get")
def get_config(
        server: str = typer.Option(..., "--server", help="Server ID or name."),
        protocol: str = typer.Option(..., "--protocol", help="Protocol (awg, xray, etc)."),
        route: str | None = typer.Option(
            None,
            "--route",
            help="Route for xray (tcp/xhttp). Default is server default (tcp).",
        ),
        device: str | None = typer.Option(None, "--device", help="Device label."),
        out: str | None = typer.Option(None, "--out", help="Output path for config."),
        conf: bool = typer.Option(False, "--conf", help="Output raw WireGuard config (AWG only)."),
        quiet: bool = typer.Option(False, "--quiet", help="Suppress config output to stdout."),
        base_url: str | None = typer.Option(None, "--base-url", help="Override base URL."),
):
    """
    Fetch VPN client config for a server/protocol you have access to.
    Example: saharo config get --server 12 --protocol awg
    """
    import os
    cfg = load_config()
    if not cfg.auth.token:
        console.err("Auth token missing. Run `saharo auth login` first.")
        raise typer.Exit(code=2)

    protocol_norm = protocol.strip().lower()
    if not protocol_norm:
        console.err("Protocol is required.")
        raise typer.Exit(code=2)

    device_label = (device or _default_device_label()).strip()
    if not device_label:
        console.err("Device label is required.")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        me = client.me()
        access = me.get("access") if isinstance(me, dict) else None
        server_id, protocol_key = _resolve_access_target(access, server, protocol_norm)

        payload = {
            "server_id": server_id,
            "protocol": protocol_key,
            "device_label": device_label,
        }
        if route is not None:
            route_value = route.strip().lower()
            if route_value not in {"tcp", "xhttp"}:
                console.err("Route must be one of: tcp, xhttp.")
                raise typer.Exit(code=2)
            payload["route"] = route_value

        if protocol_key == "awg":
            keypair = load_or_create_awg_keypair(server_id, device_label)
            payload["client_public_key"] = keypair.public_key

        data = client.credentials_ensure(**payload)
    finally:
        client.close()

    config = data.get("config") if isinstance(data, dict) else None
    if not isinstance(config, dict):
        console.err("Unexpected response from server.")
        raise typer.Exit(code=2)

    output_path = out or _default_output_path(
        protocol_key,
        server_id,
        device_label,
        awg_conf=conf if protocol_key == "awg" else False,
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    content = None
    if protocol_key == "awg":
        wg_parts = config.get("wg")
        if not isinstance(wg_parts, dict):
            console.err("Config payload missing WireGuard parts.")
            raise typer.Exit(code=2)
        if conf:
            content = _build_awg_conf(private_key=keypair.private_key, wg_parts=wg_parts)
        else:
            content = _build_awg_uri(
                private_key=keypair.private_key,
                public_key=keypair.public_key,
                wg_parts=wg_parts,
                name=f"{server_id}-{device_label}",
            )
    else:
        content = config.get("url")

    if not content:
        console.err("Config payload missing expected content.")
        raise typer.Exit(code=2)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(str(content).strip() + "\n")
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass

    if protocol_key == "awg":
        label = "WireGuard config" if conf else "AmneziaWG URI"
        console.ok(f"{label} saved to {output_path}")
        if not quiet:
            console.console.print("")
            console.console.print(str(content), markup=False)
    else:
        console.ok(f"Config saved to {output_path}")
        if not quiet:
            console.console.print("")
            console.console.print(str(content), markup=False)

# wqeqweqweqweqwe
