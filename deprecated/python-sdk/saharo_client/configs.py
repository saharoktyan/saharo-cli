from __future__ import annotations

import base64
import json
import zlib

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


def resolve_access_target(access: list[dict] | None, server: str, protocol: str) -> tuple[int, str]:
    if not isinstance(access, list) or not access:
        raise ValueError("No access grants found for this account.")

    server_input = (server or "").strip()
    if not server_input:
        raise ValueError("Server is required.")

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
        msg = f"Server '{server_input}' is not available for this account."
        if options_display:
            msg += f" Available servers: {options_display}"
        raise ValueError(msg)

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
        msg = f"Protocol '{protocol}' is not available for server '{server_input}'."
        if choices_display:
            msg += f" Available protocols: {choices_display}"
        raise ValueError(msg)

    server_id = int(server_match.get("id"))
    protocol_key = protocol_match.get("key") or protocol_match.get("name") or protocol_input
    return server_id, str(protocol_key).lower()


def build_awg_conf(*, private_key: str, wg_parts: dict) -> str:
    address = wg_parts.get("address")
    preshared_key = wg_parts.get("preshared_key")
    endpoint = wg_parts.get("endpoint")
    server_public_key = wg_parts.get("server_public_key")
    if not all([address, preshared_key, endpoint, server_public_key]):
        raise ValueError("Config payload missing required WireGuard fields.")

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


def qt_qcompress(raw: bytes, level: int = 9) -> bytes:
    comp = zlib.compress(raw, level)
    return len(raw).to_bytes(4, "big") + comp


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def extract_dns(dns: str | list | None) -> tuple[str, str]:
    if not dns:
        return "", ""
    if isinstance(dns, list):
        values = [str(x).strip() for x in dns if str(x).strip()]
    else:
        values = split_csv(str(dns))
    dns1 = values[0] if values else ""
    dns2 = values[1] if len(values) > 1 else ""
    return dns1, dns2


def extract_allowed_ips(allowed_ips: str | list | None) -> list[str]:
    if not allowed_ips:
        return []
    if isinstance(allowed_ips, list):
        return [str(x).strip() for x in allowed_ips if str(x).strip()]
    return split_csv(str(allowed_ips))


def parse_endpoint(endpoint: str) -> tuple[str, int]:
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


def build_awg_uri(*, private_key: str, public_key: str, wg_parts: dict, name: str) -> str:
    address = wg_parts.get("address")
    preshared_key = wg_parts.get("preshared_key")
    endpoint = wg_parts.get("endpoint")
    server_public_key = wg_parts.get("server_public_key")
    if not all([address, preshared_key, endpoint, server_public_key]):
        raise ValueError("Config payload missing required WireGuard fields.")

    allowed_ips = wg_parts.get("allowed_ips_client") or "0.0.0.0/0, ::/0"
    keepalive = int(wg_parts.get("keepalive") or 25)
    dns = wg_parts.get("dns")
    mtu = wg_parts.get("mtu")
    amnezia = wg_parts.get("amnezia") if isinstance(wg_parts.get("amnezia"), dict) else {}

    host_name, port = parse_endpoint(str(endpoint))
    dns1, dns2 = extract_dns(dns)
    allowed_ips_list = extract_allowed_ips(allowed_ips)
    config_text = build_awg_conf(private_key=private_key, wg_parts=wg_parts)

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
    packed = qt_qcompress(raw)
    b64 = base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")
    return f"vpn://{b64}"
