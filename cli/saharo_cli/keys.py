from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from platformdirs import user_config_dir

from .config import APP_NAME


@dataclass
class AwgKeypair:
    public_key: str
    private_key: str


def _sanitize_segment(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in value.strip())


def awg_key_dir(server_id: int, device_label: str) -> str:
    base = user_config_dir(APP_NAME)
    safe_label = _sanitize_segment(device_label) or "device"
    return os.path.join(base, "keys", "awg", str(server_id), safe_label)


def load_or_create_awg_keypair(server_id: int, device_label: str) -> AwgKeypair:
    path = awg_key_dir(server_id, device_label)
    pub_path = os.path.join(path, "public.key")
    priv_path = os.path.join(path, "private.key")

    if os.path.exists(pub_path) and os.path.exists(priv_path):
        with open(pub_path, "r", encoding="utf-8") as f:
            pub = f.read().strip()
        with open(priv_path, "r", encoding="utf-8") as f:
            priv = f.read().strip()
        return AwgKeypair(public_key=pub, private_key=priv)

    os.makedirs(path, exist_ok=True)
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    with open(priv_path, "w", encoding="utf-8") as f:
        f.write(priv_b64 + "\n")
    os.chmod(priv_path, 0o600)

    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(pub_b64 + "\n")

    return AwgKeypair(public_key=pub_b64, private_key=priv_b64)
