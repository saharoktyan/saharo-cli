from __future__ import annotations

import ipaddress
import os
import posixpath
import re
import secrets
import shutil
import subprocess
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx

from .licensing import IMAGE_COMPONENTS


class HostError(RuntimeError):
    pass


DEFAULT_API_BIND = "127.0.0.1"
DEFAULT_API_PORT = 8010
LICENSE_STATE_RELATIVE_POSIX = posixpath.join("state", "license.json")


@dataclass(frozen=True)
class BootstrapInputs:
    api_url: str
    api_url_original: str | None
    host_name: str
    x_root_secret: str
    db_password: str
    admin_username: str
    admin_password: str
    admin_api_key_name: str
    jwt_secret: str
    install_dir: str
    registry: str
    lic_url: str
    tag: str
    non_interactive: bool
    assume_yes: bool
    no_docker_install: bool
    force: bool
    enterprise_enabled: bool = False
    telegram_bot_token: str | None = None
    https_enabled: bool = False
    https_domain: str | None = None
    https_email: str | None = None
    https_http01: bool = True
    skip_https: bool = False
    vpn_cidr: str | None = None

    @property
    def host_dir(self) -> Path:
        return Path(self.install_dir).expanduser().resolve() / "host"

    @property
    def host_dir_posix(self) -> str:
        return posixpath.join(self.install_dir, "host")

    @property
    def compose_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "docker-compose.yml")

    @property
    def env_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, ".env")

    @property
    def readme_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "README.txt")

    @property
    def data_dir_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "data", "postgres")

    @property
    def license_state_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, LICENSE_STATE_RELATIVE_POSIX)

    @property
    def compose_path(self) -> Path:
        return self.host_dir / "docker-compose.yml"

    @property
    def env_path(self) -> Path:
        return self.host_dir / ".env"

    @property
    def readme_path(self) -> Path:
        return self.host_dir / "README.txt"

    @property
    def vpn_lockdown_script_path(self) -> Path:
        return self.host_dir / "apply-vpn-lockdown.sh"

    @property
    def vpn_lockdown_script_path_posix(self) -> str:
        return posixpath.join(self.host_dir_posix, "apply-vpn-lockdown.sh")

    @property
    def data_dir(self) -> Path:
        return self.host_dir / "data" / "postgres"

    @property
    def api_base(self) -> str:
        return f"http://{DEFAULT_API_BIND}:{DEFAULT_API_PORT}"


@dataclass
class PrereqResult:
    docker_installed: bool
    compose_installed: bool
    docker_running: bool


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise HostError("Domain cannot be empty.")
    if "://" not in value:
        value = f"http://{value}"
    parsed = urllib.parse.urlparse(value)
    host = parsed.hostname or ""
    if not host:
        raise HostError("Invalid domain or URL.")
    return host


def normalize_api_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise HostError("API URL cannot be empty.")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme:
        if not parsed.netloc:
            raise HostError("Invalid API URL.")
        return value
    domain = normalize_domain(value)
    return f"http://{domain}"


def validate_ssh_key_path(raw_path: str) -> str:
    path = os.path.expanduser((raw_path or "").strip())
    if not path:
        raise HostError("SSH key path is empty.")
    if path.endswith(".pub"):
        raise HostError("SSH key must be a private key, not a .pub file.")
    if not os.path.exists(path):
        raise HostError(f"SSH key not found: {path}")
    return path


def normalize_remote_install_dir(install_dir: str, *, default_dir: str = "/opt/saharo") -> str:
    clean = (install_dir or "").strip()
    if not clean:
        return default_dir
    if _looks_like_windows_path(clean):
        raise HostError("In SSH mode, --install-dir must be a Linux path like /opt/saharo.")
    return clean


def generate_secret_token() -> str:
    return secrets.token_urlsafe(32)


def _looks_like_windows_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("\\\\"):
        return True
    if re.match(r"^[A-Za-z]:\\\\", path):
        return True
    if re.match(r"^[A-Za-z]:/", path):
        return True
    if "\\" in path:
        return True
    return False


def validate_bootstrap_params(params: dict) -> dict:
    api_url = (params.get("api_url") or "").strip()
    if not api_url:
        raise HostError("API URL is required.")
    x_root_secret = (params.get("x_root_secret") or "").strip()
    db_password = (params.get("db_password") or "").strip()
    admin_username = (params.get("admin_username") or "").strip()
    admin_password = (params.get("admin_password") or "").strip()
    if not (x_root_secret and db_password and admin_username and admin_password):
        raise HostError("Admin/db/root secrets are required.")

    normalized = dict(params)
    normalized["api_url"] = normalize_api_url(api_url)
    vpn_cidr = (normalized.get("vpn_cidr") or "").strip()
    if vpn_cidr:
        try:
            ipaddress.ip_network(vpn_cidr, strict=False)
        except ValueError as exc:
            raise HostError(f"Invalid VPN CIDR: {vpn_cidr}") from exc
        normalized["vpn_cidr"] = vpn_cidr
    if not normalized.get("host_name"):
        normalized["host_name"] = "Host API"
    if not normalized.get("admin_api_key_name"):
        normalized["admin_api_key_name"] = "root"
    return normalized


def render_compose(inputs: BootstrapInputs) -> str:
    api_image = f"{inputs.registry}/saharo/v1/{IMAGE_COMPONENTS['host']}:{inputs.tag}"
    enterprise_image = f"{inputs.registry}/saharo/v1/enterprise-policy:{inputs.tag}"
    compose = {
        "services": {
            "db": {
                "image": "postgres:16-alpine",
                "container_name": "saharo_host_db",
                "restart": "unless-stopped",
                "environment": {
                    "POSTGRES_DB": "${POSTGRES_DB}",
                    "POSTGRES_USER": "${POSTGRES_USER}",
                    "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}",
                },
                "volumes": ["./data/postgres:/var/lib/postgresql/data"],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}",
                    ],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 5,
                },
            },
            "api": {
                "image": api_image,
                "container_name": "saharo_host_api",
                "restart": "unless-stopped",
                "env_file": ["./.env"],
                "depends_on": {"db": {"condition": "service_healthy"}},
                "ports": [f"{DEFAULT_API_BIND}:{DEFAULT_API_PORT}:{DEFAULT_API_PORT}"],
                "volumes": [
                    "./state:/opt/saharo/host/state",
                    "/var/run/docker.sock:/var/run/docker.sock",
                ],
                "healthcheck": {
                    "test": [
                        "CMD-SHELL",
                        "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health').read()\"",
                    ],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 5,
                },
            },
        }
    }
    if inputs.enterprise_enabled:
        compose["services"]["enterprise-policy"] = {
            "image": enterprise_image,
            "container_name": "saharo_enterprise_policy",
            "restart": "unless-stopped",
            "env_file": ["./.env"],
            "ports": ["127.0.0.1:8091:8091"],
        }
    try:
        import yaml
    except Exception:
        lines = [
                "services:",
                "  db:",
                "    image: postgres:16-alpine",
                "    container_name: saharo_host_db",
                "    restart: unless-stopped",
                "    environment:",
                "      POSTGRES_DB: ${POSTGRES_DB}",
                "      POSTGRES_USER: ${POSTGRES_USER}",
                "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
                "    volumes:",
                "      - ./data/postgres:/var/lib/postgresql/data",
                "    healthcheck:",
                "      test: [\"CMD-SHELL\", \"pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}\"]",
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
                "  api:",
                f"    image: {api_image}",
                "    container_name: saharo_host_api",
                "    restart: unless-stopped",
                "    env_file:",
                "      - ./.env",
                "    depends_on:",
                "      db:",
                "        condition: service_healthy",
                "    ports:",
                f"      - \"{DEFAULT_API_BIND}:{DEFAULT_API_PORT}:{DEFAULT_API_PORT}\"",
                "    volumes:",
                "      - ./state:/opt/saharo/host/state",
                "      - /var/run/docker.sock:/var/run/docker.sock",
                "    healthcheck:",
                "      test: [\"CMD-SHELL\", \"python -c \\\"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health').read()\\\"\" ]",
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
        ]
        if inputs.enterprise_enabled:
            lines.extend(
                [
                    "  enterprise-policy:",
                    f"    image: {enterprise_image}",
                    "    container_name: saharo_enterprise_policy",
                    "    restart: unless-stopped",
                    "    env_file:",
                    "      - ./.env",
                    "    ports:",
                    "      - \"127.0.0.1:8091:8091\"",
                ]
            )
        return "\n".join(lines) + "\n"
    dumped = yaml.safe_dump(compose, sort_keys=False, default_flow_style=False)
    return dumped if dumped.endswith("\n") else dumped + "\n"


def _url_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def render_env(inputs: BootstrapInputs, *, include_root_secret: bool) -> str:
    database_url = f"postgresql://{_url_encode('saharo')}:{_url_encode(inputs.db_password)}@db:5432/saharo"
    lines = [
        f"APP_VERSION={inputs.tag}",
        f"HOST_NAME={inputs.host_name}",
        "ENV=prod",
        "LOG_LEVEL=info",
        "POSTGRES_DB=saharo",
        "POSTGRES_USER=saharo",
        f"POSTGRES_PASSWORD={inputs.db_password}",
        f"DATABASE_URL={database_url}",
        "DB_POOL_MIN=1",
        "DB_POOL_MAX=5",
        "CORS_ALLOW_ORIGINS=" + inputs.api_url,
        "CORS_ALLOW_CREDENTIALS=true",
        f"JWT_SECRET={inputs.jwt_secret}",
        f"LICENSE_API_URL={inputs.lic_url}",
        "TELEMETRY_REPORT_INTERVAL_HOURS=1",
        f"ENTERPRISE_ENABLED={'true' if inputs.enterprise_enabled else 'false'}",
        f"VPN_CIDR={inputs.vpn_cidr or ''}",
        f"VPN_LOCKDOWN_ENABLED={'true' if inputs.vpn_cidr else 'false'}",
    ]
    if inputs.telegram_bot_token:
        lines.append(f"TELEGRAM_BOT_TOKEN={inputs.telegram_bot_token}")
    if include_root_secret:
        lines.append(f"ROOT_ADMIN_SECRET={inputs.x_root_secret}")
    return "\n".join(lines) + "\n"


def render_readme(inputs: BootstrapInputs) -> str:
    return "\n".join(
        [
            "Saharo Host (API + Postgres)",
            "",
            "Manage services:",
            f"  docker compose -f {inputs.compose_path} ps",
            f"  docker compose -f {inputs.compose_path} logs -f api",
            f"  docker compose -f {inputs.compose_path} restart api",
            "",
            "Stop services:",
            f"  docker compose -f {inputs.compose_path} down",
            "",
            "Start services:",
            f"  docker compose -f {inputs.compose_path} up -d",
            "",
            "Optional VPN lockdown (allow only localhost + VPN CIDR to API/web ports):",
            f"  sudo sh {inputs.vpn_lockdown_script_path} <vpn-cidr>",
        ]
    ) + "\n"


def render_vpn_lockdown_script(inputs: BootstrapInputs) -> str:
    default_cidr = (inputs.vpn_cidr or "").strip()
    default_cidr_literal = default_cidr if default_cidr else ""
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            f'DEFAULT_CIDR="{default_cidr_literal}"',
            'VPN_CIDR="${1:-$DEFAULT_CIDR}"',
            'if [ -z "$VPN_CIDR" ]; then',
            '  echo "Usage: sudo sh ./apply-vpn-lockdown.sh <vpn-cidr>"',
            "  exit 2",
            "fi",
            'if ! command -v iptables >/dev/null 2>&1; then',
            '  echo "iptables is required"',
            "  exit 2",
            "fi",
            'CHAIN="SAHARO_VPN_ONLY"',
            'PORTS="${SAHARO_LOCKDOWN_PORTS:-8010 80 443}"',
            'iptables -N "$CHAIN" 2>/dev/null || true',
            'iptables -F "$CHAIN"',
            'iptables -A "$CHAIN" -s 127.0.0.1/32 -j RETURN',
            'iptables -A "$CHAIN" -s "$VPN_CIDR" -j RETURN',
            'iptables -A "$CHAIN" -j DROP',
            'for port in $PORTS; do',
            '  iptables -C INPUT -p tcp --dport "$port" -j "$CHAIN" 2>/dev/null || \\',
            '    iptables -I INPUT 1 -p tcp --dport "$port" -j "$CHAIN"',
            "done",
            'echo "Saharo VPN lockdown applied for CIDR: $VPN_CIDR (ports: $PORTS)"',
            "",
        ]
    )


def read_env_content(content: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return read_env_content(path.read_text(encoding="utf-8"))


def get_existing_jwt_secret(host_dir: Path) -> str | None:
    env_path = host_dir / ".env"
    env = read_env_file(env_path)
    jwt_secret = env.get("JWT_SECRET")
    return jwt_secret.strip() if jwt_secret else None


def backup_host_dir(host_dir: Path) -> Path | None:
    if not host_dir.exists():
        return None
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = host_dir.with_name(f"{host_dir.name}.bak-{timestamp}")
    moved_any = False
    data_dir = host_dir / "data"
    backup_path.mkdir(parents=False, exist_ok=False)
    for entry in host_dir.iterdir():
        if entry == data_dir:
            continue
        shutil.move(str(entry), str(backup_path / entry.name))
        moved_any = True
    if not moved_any:
        backup_path.rmdir()
        return None
    return backup_path


def write_files_local(inputs: BootstrapInputs) -> dict[str, str | None]:
    host_dir = inputs.host_dir
    backup_path = None
    if host_dir.exists() and not inputs.force:
        raise HostError(f"Install dir already exists: {host_dir}. Use --force to overwrite.")
    if host_dir.exists() and inputs.force:
        backup_path = backup_host_dir(host_dir)
    host_dir.mkdir(parents=True, exist_ok=True)
    inputs.data_dir.mkdir(parents=True, exist_ok=True)

    compose_content = render_compose(inputs)
    env_content = render_env(inputs, include_root_secret=True)
    readme_content = render_readme(inputs)
    vpn_script_content = render_vpn_lockdown_script(inputs)

    inputs.compose_path.write_text(compose_content, encoding="utf-8")
    inputs.env_path.write_text(env_content, encoding="utf-8")
    os.chmod(inputs.env_path, 0o600)
    inputs.readme_path.write_text(readme_content, encoding="utf-8")
    inputs.vpn_lockdown_script_path.write_text(vpn_script_content, encoding="utf-8")
    os.chmod(inputs.vpn_lockdown_script_path, 0o700)
    return {
        "compose_path": str(inputs.compose_path),
        "env_path": str(inputs.env_path),
        "readme_path": str(inputs.readme_path),
        "vpn_lockdown_script_path": str(inputs.vpn_lockdown_script_path),
        "backup_path": str(backup_path) if backup_path else None,
        "data_dir": str(inputs.data_dir),
    }


def wipe_host_data_local(inputs: BootstrapInputs) -> bool:
    data_dir = inputs.data_dir
    if inputs.compose_path.exists():
        subprocess.run(["docker", "compose", "-f", str(inputs.compose_path), "down"], check=False)
    if data_dir.exists():
        import shutil

        shutil.rmtree(data_dir)
        return True
    return False


def command_exists(command: str) -> bool:
    if not command:
        return False
    res = subprocess.run(f"command -v {command} >/dev/null 2>&1", shell=True)
    return res.returncode == 0


def command_success(args: list[str]) -> bool:
    if not args:
        return False
    res = subprocess.run(args, capture_output=True)
    return res.returncode == 0


def check_prereqs_local() -> PrereqResult:
    docker_installed = command_exists("docker")
    compose_installed = False
    docker_running = False
    if docker_installed:
        compose_installed = command_success(["docker", "compose", "version"])
        docker_running = command_success(["docker", "info"])
    return PrereqResult(
        docker_installed=docker_installed,
        compose_installed=compose_installed,
        docker_running=docker_running,
    )


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass
class HttpsContext:
    run: callable
    run_input: callable
    allow_sudo: bool
    is_root: bool
    remote: bool

    @property
    def needs_sudo(self) -> bool:
        return not self.is_root


def _sudo_requirement_message(ctx: HttpsContext) -> str:
    if ctx.remote:
        return "HTTPS setup requires root or --ssh-sudo to install nginx/certbot and write /etc/nginx."
    return "HTTPS setup requires root or sudo to install nginx/certbot and write /etc/nginx."


def ensure_https(
    domain: str,
    email: str,
    api_port: int,
    *,
    http01: bool = True,
    ctx: HttpsContext,
) -> None:
    clean_domain = normalize_domain(domain)
    if "@" not in (email or ""):
        raise HostError("Email must include '@'.")
    _ensure_sudo_ready(ctx)

    if _https_already_configured(ctx, clean_domain):
        return

    _check_dns(ctx, clean_domain, http01=http01)
    _ensure_apt_available(ctx)
    _install_packages(ctx)
    _write_nginx_config(ctx, clean_domain, api_port)
    _enable_nginx_site(ctx)
    _run_checked(ctx, "nginx -t", label="nginx config test", sudo=ctx.needs_sudo)
    _run_checked(ctx, "systemctl reload nginx", label="reload nginx", sudo=ctx.needs_sudo)
    _check_ports(ctx)
    _run_certbot(ctx, clean_domain, email, http01=http01)
    _verify_https_health(ctx, clean_domain)


def _ensure_sudo_ready(ctx: HttpsContext) -> None:
    if ctx.is_root:
        return
    if not ctx.allow_sudo:
        raise HostError(_sudo_requirement_message(ctx))
    if not ctx.remote:
        if _run_local("command -v sudo >/dev/null 2>&1", sudo=False).returncode != 0:
            raise HostError(_sudo_requirement_message(ctx))


def _https_already_configured(ctx: HttpsContext, domain: str) -> bool:
    res = ctx.run(f"test -f /etc/letsencrypt/live/{domain}/fullchain.pem")
    return res.returncode == 0


def _check_dns(ctx: HttpsContext, domain: str, *, http01: bool = True) -> None:
    if not http01:
        return
    res = ctx.run(f"getent hosts {domain}")
    if res.returncode != 0:
        raise HostError("Domain does not resolve. Check DNS records.")
    if not res.stdout:
        raise HostError("Domain does not resolve. Check DNS records.")
    ips = _IP_RE.findall(res.stdout)
    if not ips:
        raise HostError("Domain did not resolve to an IP address.")
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HostError(f"Domain resolved to invalid IP: {ip}")


def _ensure_apt_available(ctx: HttpsContext) -> None:
    res = ctx.run("command -v apt-get")
    if res.returncode != 0:
        raise HostError("apt-get is required for HTTPS setup.")


def _install_packages(ctx: HttpsContext) -> None:
    _run_checked(
        ctx,
        "apt-get update -y",
        label="apt-get update",
        sudo=ctx.needs_sudo,
    )
    _run_checked(
        ctx,
        "apt-get install -y nginx certbot python3-certbot-nginx",
        label="install nginx/certbot",
        sudo=ctx.needs_sudo,
    )


def _write_nginx_config(ctx: HttpsContext, domain: str, api_port: int) -> None:
    content = f"""
server {{
    listen 80;
    server_name {domain};

    location / {{
        proxy_pass http://127.0.0.1:{api_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
""".strip()
    ctx.run_input(
        f"tee /etc/nginx/sites-available/saharo.conf",
        content,
        sudo=ctx.needs_sudo,
    )


def _enable_nginx_site(ctx: HttpsContext) -> None:
    ctx.run(f"ln -sf /etc/nginx/sites-available/saharo.conf /etc/nginx/sites-enabled/saharo.conf", sudo=ctx.needs_sudo)


def _check_ports(ctx: HttpsContext) -> None:
    res = ctx.run("ss -tuln | grep -E ':(80|443) '")
    if res.returncode != 0:
        return


def _run_certbot(ctx: HttpsContext, domain: str, email: str, *, http01: bool = True) -> None:
    challenge = "--preferred-challenges http" if http01 else ""
    cmd = (
        "certbot certonly --nginx --agree-tos --no-eff-email "
        f"--email {email} -d {domain} {challenge}"
    )
    _run_checked(ctx, cmd, label="certbot", sudo=ctx.needs_sudo)


def _verify_https_health(ctx: HttpsContext, domain: str) -> None:
    res = ctx.run(f"curl -fsSL https://{domain}/health")
    if res.returncode != 0:
        raise HostError("HTTPS health check failed.")


def _run_checked(ctx: HttpsContext, command: str, *, label: str, sudo: bool) -> None:
    res = ctx.run(command, sudo=sudo)
    if res.returncode != 0:
        raise HostError(f"{label} failed.")


def _run_local(command: str, *, sudo: bool) -> subprocess.CompletedProcess:
    cmd = command
    if sudo and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def purge_hosts(
    *,
    lic_url: str,
    license_id: str,
    session_token: str,
    csrf_token: str,
    timeout_s: float = 10.0,
) -> None:
    base = (lic_url or "").strip().rstrip("/")
    if not base:
        raise HostError("License API URL is not configured.")
    lic_id = (license_id or "").strip()
    if not lic_id:
        raise HostError("License id is required.")
    token = (session_token or "").strip()
    csrf = (csrf_token or "").strip()
    if not token or not csrf:
        raise HostError("Portal auth is missing or incomplete.")

    with httpx.Client(base_url=base, timeout=timeout_s) as client:
        client.headers["X-Session-Token"] = token
        client.cookies.set("saharo_csrf", csrf)
        client.headers["X-CSRF-Token"] = csrf
        resp = client.post(f"/v1/licenses/{lic_id}/hosts/purge")
        if resp.status_code in (401, 403):
            raise HostError("Portal session is invalid or expired.")
        if resp.status_code >= 400:
            raise HostError(f"Purge failed: HTTP {resp.status_code}")
