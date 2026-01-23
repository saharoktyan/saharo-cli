from __future__ import annotations

import hashlib
import os
import platform as platform_mod
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import typer

from ..compat import cli_version
from ..config import load_config
from ..console import err, info, ok, warn
from ..http import make_client
from ..semver import parse_semver
from saharo_client import ApiError


app = typer.Typer(help="Manage CLI updates from your host.")

_CACHE_UPDATE_DIR = Path.home() / ".cache" / "saharo" / "update"
_CACHE_UPDATE_PATH = _CACHE_UPDATE_DIR / "saharo.new"
_CACHE_HELPER_PATH = _CACHE_UPDATE_DIR / "apply_update.sh"


def _platform_id() -> str:
    return f"{platform_mod.system().lower()}-{platform_mod.machine().lower()}"


def _download_file(url: str, dest: Path) -> str:
    sha = hashlib.sha256()
    with httpx.stream("GET", url, timeout=30.0) as resp:
        resp.raise_for_status()
        with dest.open("wb") as f:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                sha.update(chunk)
                f.write(chunk)
    return sha.hexdigest()


def _find_executable() -> Path | None:
    candidate = Path(sys.argv[0])
    if candidate.exists():
        try:
            if Path(sys.executable).resolve() == candidate.resolve():
                candidate = None
        except Exception:
            pass
    if candidate and candidate.exists():
        return candidate
    which = shutil.which("saharo")
    if which:
        return Path(which)
    return None


def _is_windows() -> bool:
    return platform_mod.system().lower().startswith("win")


def _is_standalone_binary(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    if path.suffix in {".py", ".pyc"}:
        return False
    try:
        with path.open("rb") as f:
            header = f.read(4)
            f.seek(0)
            first_line = f.readline(128)
    except Exception:
        return False
    if first_line.startswith(b"#!") and b"python" in first_line.lower():
        return False
    if header.startswith(b"\x7fELF"):
        return True
    if header in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        return True
    return False


def _ensure_writable(target: Path) -> bool:
    if target.exists():
        return os.access(target, os.W_OK)
    return os.access(target.parent, os.W_OK)


def _write_helper_script() -> None:
    _CACHE_UPDATE_DIR.mkdir(parents=True, exist_ok=True)
    script = """#!/bin/sh
set -e
TARGET="$1"
NEW="$2"
PID="$3"
shift 3
while kill -0 "$PID" 2>/dev/null; do
  sleep 0.2
done
TMP="${TARGET}.new"
cp "$NEW" "$TMP"
chmod +x "$TMP"
mv -f "$TMP" "$TARGET"
exec "$TARGET" "$@"
"""
    _CACHE_HELPER_PATH.write_text(script, encoding="utf-8")
    os.chmod(_CACHE_HELPER_PATH, 0o700)


def _spawn_update_helper(target: Path, restart_args: list[str]) -> None:
    _write_helper_script()
    subprocess.Popen(
        ["/bin/sh", str(_CACHE_HELPER_PATH), str(target), str(_CACHE_UPDATE_PATH), str(os.getpid()), *restart_args],
        close_fds=True,
    )


@app.command("update", help="Update the CLI from the connected host.")
def update_self() -> None:
    cfg = load_config()
    base_url = (cfg.base_url or "").strip()
    if not base_url:
        err("No host URL configured. Run: saharo auth login --base-url https://<your-host>")
        raise SystemExit(1)
    if not (cfg.auth.token or "").strip():
        err("Not authenticated. Run: saharo auth login")
        raise SystemExit(1)

    current_version = cli_version()
    client = make_client(cfg, profile=None, base_url_override=None)
    try:
        data = client.updates_cli(current=current_version, platform=_platform_id())
    except ApiError as exc:
        if exc.status_code in (401, 403):
            err("Not authenticated.")
            info("Run: saharo auth login --base-url https://<your-host>")
        else:
            err(f"Update check failed: HTTP {exc.status_code}")
        raise SystemExit(1)
    finally:
        client.close()

    if not isinstance(data, dict) or not data.get("ok"):
        err("Update check failed: invalid response from host API.")
        raise SystemExit(1)

    if not data.get("update_available"):
        ok(f"CLI is up to date ({current_version}).")
        return
    latest = data.get("latest") if isinstance(data.get("latest"), str) else "latest"
    target_semver = parse_semver(latest) if isinstance(latest, str) else None
    current_semver = parse_semver(current_version)
    if current_semver and target_semver and current_semver >= target_semver:
        ok(f"CLI is up to date ({current_version}).")
        return

    download_url = data.get("download_url")
    expected_sha = data.get("sha256") if isinstance(data.get("sha256"), str) else None
    if not isinstance(download_url, str) or not download_url:
        err("No CLI build available for your platform.")
        info("Download a supported build from the Saharo portal.")
        raise SystemExit(1)

    target = _find_executable()
    if not target:
        warn("Unable to locate saharo executable for in-place update.")
        info("Download the latest CLI binary from the Saharo portal.")
        return
    if _is_windows():
        warn("CLI auto-update is not available on Windows yet.")
        info("Please download the latest release and replace the binary manually.")
        raise SystemExit(1)
    if not _is_standalone_binary(target):
        warn("CLI was not installed as a standalone binary.")
        info("Download the standalone CLI binary from the Saharo portal.")
        raise SystemExit(1)

    info(f"Downloading {download_url}...")
    try:
        _CACHE_UPDATE_DIR.mkdir(parents=True, exist_ok=True)
        actual_sha = _download_file(download_url, _CACHE_UPDATE_PATH)
    except Exception as exc:
        err(f"Download failed: {exc}")
        raise SystemExit(1)

    if expected_sha and actual_sha.lower() != str(expected_sha).lower():
        _CACHE_UPDATE_PATH.unlink(missing_ok=True)
        err("Checksum mismatch for downloaded CLI.")
        raise SystemExit(1)

    os.chmod(_CACHE_UPDATE_PATH, 0o755)
    if not _ensure_writable(target):
        warn("Insufficient permissions to replace the CLI binary.")
        info(f"Manual update: sudo mv {_CACHE_UPDATE_PATH} {target}")
        info(f"Then: sudo chmod +x {target}")
        raise SystemExit(1)

    info("Applying update...")
    _spawn_update_helper(target, [])
    ok(f"CLI update to {latest} is in progress. Restarting...")
    raise SystemExit(0)
