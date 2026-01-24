import base64
import json
import os
import sys
import types
import zlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
fake_client_mod = types.ModuleType("saharo_client")
fake_client_mod.ApiError = type("ApiError", (), {})
fake_client_mod.SaharoClient = object
sys.modules["saharo_client"] = fake_client_mod
fake_config_mod = types.ModuleType("saharo_client.config_types")
fake_config_mod.ClientConfig = type("ClientConfig", (), {})
sys.modules["saharo_client.config_types"] = fake_config_mod
sys.modules.setdefault("tomli_w", types.SimpleNamespace(dumps=lambda *_args, **_kwargs: ""))

from saharo_cli.commands import config_cmd


def _decode_uri(uri: str) -> dict:
    assert uri.startswith("vpn://")
    b64 = uri[len("vpn://"):]
    padded = b64 + "=" * (-len(b64) % 4)
    packed = base64.urlsafe_b64decode(padded)
    raw = zlib.decompress(packed[4:])
    return json.loads(raw.decode("utf-8"))


def test_build_awg_uri_emits_amnezia_container_schema() -> None:
    wg_parts = {
        "address": "10.0.0.2",
        "preshared_key": "psk-key",
        "endpoint": "vpn.example.com:51820",
        "server_public_key": "server-pub",
        "allowed_ips_client": "0.0.0.0/0, ::/0",
        "keepalive": 20,
        "dns": "1.1.1.1, 9.9.9.9",
        "mtu": 1400,
        "amnezia": {
            "jc": "3",
            "jmin": "10",
            "jmax": "20",
            "s1": "7",
            "s2": "9",
            "h1": "11",
            "h2": "12",
            "h3": "13",
            "h4": "14",
        },
    }

    uri = config_cmd._build_awg_uri(
        private_key="client-priv",
        public_key="client-pub",
        wg_parts=wg_parts,
        name="alpha-device",
    )

    payload = _decode_uri(uri)
    assert payload["defaultContainer"] == "amnezia-awg"
    assert payload["description"] == "alpha-device"
    assert payload["dns1"] == "1.1.1.1"
    assert payload["dns2"] == "9.9.9.9"
    assert payload["hostName"] == "vpn.example.com"
    assert payload["nameOverriddenByUser"] is True

    container = payload["containers"][0]
    assert container["container"] == "amnezia-awg"
    awg = container["awg"]
    assert awg["port"] == "51820"
    assert awg["transport_proto"] == "udp"
    assert awg["H1"] == "11"
    assert awg["H2"] == "12"
    assert awg["H3"] == "13"
    assert awg["H4"] == "14"
    assert awg["Jc"] == "3"
    assert awg["Jmin"] == "10"
    assert awg["Jmax"] == "20"
    assert awg["S1"] == "7"
    assert awg["S2"] == "9"

    last_config = json.loads(awg["last_config"])
    assert last_config["allowed_ips"] == ["0.0.0.0/0", "::/0"]
    assert last_config["client_ip"] == "10.0.0.2"
    assert last_config["client_priv_key"] == "client-priv"
    assert last_config["client_pub_key"] == "client-pub"
    assert last_config["psk_key"] == "psk-key"
    assert last_config["server_pub_key"] == "server-pub"
    assert last_config["hostName"] == "vpn.example.com"
    assert last_config["port"] == 51820
    assert last_config["mtu"] == 1400
    assert last_config["persistent_keep_alive"] == 20
    assert last_config["transport_proto"] == "udp"
    assert "PrivateKey = client-priv" in last_config["config"]
