from __future__ import annotations

import typer
from saharo_client.configs import (
    build_awg_conf,
    build_awg_uri,
    extract_allowed_ips,
    extract_dns,
    parse_endpoint,
    qt_qcompress,
    resolve_access_target,
    split_csv,
)

from .. import console
from ..config import load_config, save_config, normalize_base_url
from ..http import make_client
from ..keys import load_or_create_awg_keypair, awg_key_dir
from ..interactive import select_item, select_item_search

from questionary import Choice

app = typer.Typer(help="Fetch VPN client config (server/protocol).")



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
    try:
        return resolve_access_target(access, server, protocol)
    except ValueError as exc:
        message = str(exc)
        if " Available servers: " in message:
            err_msg, info_msg = message.split(" Available servers: ", 1)
            console.err(err_msg)
            console.info(f"Available servers: {info_msg}")
        elif " Available protocols: " in message:
            err_msg, info_msg = message.split(" Available protocols: ", 1)
            console.err(err_msg)
            console.info(f"Available protocols: {info_msg}")
        else:
            console.err(message)
        raise typer.Exit(code=2)


def _build_awg_conf(*, private_key: str, wg_parts: dict) -> str:
    try:
        return build_awg_conf(private_key=private_key, wg_parts=wg_parts)
    except ValueError as exc:
        console.err(str(exc))
        raise typer.Exit(code=2)


def _qt_qcompress(raw: bytes, level: int = 9) -> bytes:
    return qt_qcompress(raw, level)


def _split_csv(value: str) -> list[str]:
    return split_csv(value)


def _extract_dns(dns: str | list | None) -> tuple[str, str]:
    return extract_dns(dns)


def _extract_allowed_ips(allowed_ips: str | list | None) -> list[str]:
    return extract_allowed_ips(allowed_ips)


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    return parse_endpoint(endpoint)


def _build_awg_uri(*, private_key: str, public_key: str, wg_parts: dict, name: str) -> str:
    try:
        return build_awg_uri(
            private_key=private_key,
            public_key=public_key,
            wg_parts=wg_parts,
            name=name,
        )
    except ValueError as exc:
        msg = str(exc)
        if "endpoint" in msg.lower():
            console.err("Config payload has invalid endpoint format.")
        else:
            console.err(msg)
        raise typer.Exit(code=2)


@app.command("get")
def get_config(
        server: str | None = typer.Option(None, "--server", help="Server ID or name."),
        protocol: str | None = typer.Option(None, "--protocol", help="Protocol (awg, xray, etc)."),
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

    device_label = (device or _default_device_label()).strip()
    if not device_label:
        console.err("Device label is required.")
        raise typer.Exit(code=2)

    client = make_client(cfg, profile=None, base_url_override=base_url)
    try:
        me = client.me()
        access = me.get("access") if isinstance(me, dict) else []
        if not access:
            console.err("No servers or protocols are available for your account.")
            console.info("Please ask your admin to grant you access.")
            raise typer.Exit(code=2)

        # Smart Selection: Server
        if not server:
            server_choices = []
            for a in access:
                label = f"{a.get('name') or f'id={a.get('id')}'}"
                server_choices.append(Choice(title=label, value=str(a.get("id"))))
            
            selected_server_id = select_item_search("Select a server", server_choices)
            if not selected_server_id:
                raise typer.Exit(code=1)
            server = selected_server_id

        # Find the selected server in access data
        server_entry = None
        for a in access:
            if str(a.get("id")) == server or a.get("name") == server:
                server_entry = a
                break
        
        if not server_entry:
            console.err(f"Server '{server}' not found in your access list.")
            raise typer.Exit(code=2)

        # Smart Selection: Protocol
        if not protocol:
            available_protocols = server_entry.get("protocols") or []
            if not available_protocols:
                console.err(f"No protocols available for server '{server}'.")
                raise typer.Exit(code=2)
            
            proto_choices = []
            for p in available_protocols:
                p_key = p.get("key") or p.get("name")
                p_label = f"{p.get('name') or p_key} ({p.get('status', 'active')})"
                proto_choices.append(Choice(title=p_label, value=p_key))
            
            selected_proto = select_item_search("Select a protocol", proto_choices)
            if not selected_proto:
                raise typer.Exit(code=1)
            protocol_norm = selected_proto
        else:
            protocol_norm = protocol.strip().lower()

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
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

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
