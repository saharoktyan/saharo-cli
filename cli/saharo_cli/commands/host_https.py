from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass

import typer

from .. import console
from ..ssh import SSHSession, SshTarget, build_control_path, is_windows

DEFAULT_API_PORT = 8010
DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_NGINX_SITE = "/etc/nginx/sites-available/saharo.conf"
DEFAULT_NGINX_ENABLED = "/etc/nginx/sites-enabled/saharo.conf"

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class HttpsSetupError(RuntimeError):
    def __init__(self, message: str, *, stdout: str | None = None, stderr: str | None = None) -> None:
        super().__init__(message)
        self.stdout = stdout or ""
        self.stderr = stderr or ""


@dataclass
class AptFixPlan:
    codename: str
    bad_updates_lines: list[str]
    security_wrong_lines: list[str]
    security_missing: bool
    duplicate_lines: list[str]

    def has_fixable_issues(self) -> bool:
        return bool(self.bad_updates_lines or self.security_wrong_lines or self.security_missing)

    def has_warnings(self) -> bool:
        return bool(self.duplicate_lines)


@dataclass
class ExecContext:
    session: SSHSession | None
    allow_sudo: bool
    is_root: bool

    @property
    def needs_sudo(self) -> bool:
        return not self.is_root

    def run(self, command: str, *, sudo: bool | None = None) -> subprocess.CompletedProcess:
        use_sudo = self.allow_sudo if sudo is None else sudo
        if use_sudo and not self.allow_sudo:
            raise HttpsSetupError(_sudo_requirement_message(self))
        if self.is_root and use_sudo:
            use_sudo = False
        try:
            if self.session:
                return _remote_run(self.session, command, sudo=use_sudo)
            return _run_local(command, sudo=use_sudo)
        except RuntimeError as exc:
            if str(exc) == "Sudo requires --sudo.":
                raise HttpsSetupError(_sudo_requirement_message(self)) from exc
            raise

    def run_input(
            self,
            command: str,
            content: str,
            *,
            log_label: str,
            sudo: bool | None = None,
    ) -> subprocess.CompletedProcess:
        use_sudo = self.allow_sudo if sudo is None else sudo
        if use_sudo and not self.allow_sudo:
            raise HttpsSetupError(_sudo_requirement_message(self))
        if self.is_root and use_sudo:
            use_sudo = False
        try:
            if self.session:
                return _remote_run_input(self.session, command, content, log_label=log_label, sudo=use_sudo)
            return _run_local_input(command, content, sudo=use_sudo)
        except RuntimeError as exc:
            if str(exc) == "Sudo requires --sudo.":
                raise HttpsSetupError(_sudo_requirement_message(self)) from exc
            raise


app = typer.Typer(help="HTTPS setup commands.")


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("Domain cannot be empty.")
    if "://" not in value:
        value = f"http://{value}"
    parsed = urllib.parse.urlparse(value)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Invalid domain or URL.")
    return host


def normalize_api_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("API URL cannot be empty.")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme:
        if not parsed.netloc:
            raise ValueError("Invalid API URL.")
        return value
    domain = normalize_domain(value)
    return f"http://{domain}"


def _sudo_requirement_message(ctx: ExecContext) -> str:
    if ctx.session:
        return "HTTPS setup requires root or --ssh-sudo to install nginx/certbot and write /etc/nginx."
    return "HTTPS setup requires root or sudo to install nginx/certbot and write /etc/nginx."


def _detect_is_root(session: SSHSession | None) -> bool:
    if not session:
        return os.geteuid() == 0
    res = session.run("id -u")
    if res.returncode != 0:
        raise HttpsSetupError("Failed to determine remote UID.", stdout=res.stdout, stderr=res.stderr)
    value = (res.stdout or "").strip()
    if not value.isdigit():
        raise HttpsSetupError("Failed to determine remote UID.", stdout=res.stdout, stderr=res.stderr)
    return int(value) == 0


def _ensure_sudo_ready(ctx: ExecContext) -> None:
    if ctx.is_root:
        return
    if ctx.session:
        if not ctx.allow_sudo or not ctx.session.target.sudo:
            raise HttpsSetupError(_sudo_requirement_message(ctx))
        return
    if not ctx.allow_sudo:
        raise HttpsSetupError(_sudo_requirement_message(ctx))
    if _run_local("command -v sudo >/dev/null 2>&1", sudo=False).returncode != 0:
        raise HttpsSetupError(_sudo_requirement_message(ctx))


def _self_check_sudo_policy() -> None:
    if ExecContext(session=None, allow_sudo=False, is_root=True).needs_sudo:
        raise AssertionError("Root should not require sudo.")
    if not ExecContext(session=None, allow_sudo=True, is_root=False).needs_sudo:
        raise AssertionError("Non-root should require sudo.")


def ensure_https(
        domain: str,
        email: str,
        api_port: int,
        *,
        http01: bool = True,
        ssh_session: SSHSession | None = None,
        allow_sudo: bool = False,
) -> None:
    clean_domain = normalize_domain(domain)
    if "@" not in (email or ""):
        raise ValueError("Email must include '@'.")
    is_root = _detect_is_root(ssh_session)
    resolved_allow_sudo = ssh_session.target.sudo if ssh_session else allow_sudo
    ctx = ExecContext(session=ssh_session, allow_sudo=resolved_allow_sudo, is_root=is_root)
    _ensure_sudo_ready(ctx)

    if _https_already_configured(ctx, clean_domain):
        console.ok("HTTPS already configured; skipping.")
        return

    console.info("Checking DNS resolution...")
    _check_dns(ctx, clean_domain, http01=http01)

    console.info("Ensuring required packages are installed...")
    _ensure_apt_available(ctx)
    _install_packages(ctx)

    console.info("Writing Nginx configuration...")
    _write_nginx_config(ctx, clean_domain, api_port)
    _enable_nginx_site(ctx)
    _run_checked(ctx, "nginx -t", label="nginx config test", sudo=ctx.needs_sudo)
    _run_checked(ctx, "systemctl reload nginx", label="reload nginx", sudo=ctx.needs_sudo)

    console.info("Checking ports 80/443...")
    _check_ports(ctx)

    console.info("Requesting Let's Encrypt certificate...")
    _run_certbot(ctx, clean_domain, email, http01=http01)

    console.info("Verifying HTTPS health endpoint...")
    _verify_https_health(ctx, clean_domain)

    console.ok("HTTPS setup completed.")
    console.info("Renewal is handled automatically by the certbot systemd timer.")


@app.command("setup")
def https_setup(
        domain: str = typer.Option(..., "--domain", help="Domain for HTTPS (e.g. api.example.com)."),
        email: str = typer.Option(..., "--email", help="Email for Let's Encrypt registration."),
        api_port: int = typer.Option(
            DEFAULT_API_PORT,
            "--api-port",
            help="Local API port to proxy (default: 8010).",
        ),
        ssh_host: str | None = typer.Option(None, "--ssh-host", help="SSH target in user@host form."),
        ssh_port: int = typer.Option(22, "--ssh-port", help="SSH port."),
        ssh_key: str | None = typer.Option(None, "--ssh-key", help="SSH private key path."),
        ssh_sudo: bool = typer.Option(True, "--ssh-sudo/--no-ssh-sudo",
                                      help="Use sudo over SSH for privileged commands."),
):
    """Install Nginx + Let's Encrypt for the host API.

    Examples:
      saharo host https setup --domain api.example.com --email admin@example.com
      saharo host https setup --ssh-host root@203.0.113.10 --domain api.example.com --email admin@example.com
    """
    if ssh_key and ssh_key.endswith(".pub"):
        console.err("--ssh-key must be a private key path, not .pub")
        raise typer.Exit(code=2)

    if is_windows() and not ssh_host:
        console.err("Local HTTPS setup is not supported on Windows. Use --ssh-host or run from Linux/macOS.")
        raise typer.Exit(code=2)

    clean_domain = normalize_domain(domain)

    if ssh_host:
        _https_setup_remote(
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_sudo=ssh_sudo,
            domain=clean_domain,
            email=email,
            api_port=api_port,
        )
        return

    use_sudo = os.geteuid() != 0
    try:
        ensure_https(
            clean_domain,
            email,
            api_port,
            http01=True,
            ssh_session=None,
            allow_sudo=use_sudo,
        )
    except (HttpsSetupError, ValueError) as exc:
        report_https_failure(exc)
        raise typer.Exit(code=2)


def _https_setup_remote(
        *,
        ssh_host: str,
        ssh_port: int,
        ssh_key: str | None,
        ssh_sudo: bool,
        domain: str,
        email: str,
        api_port: int,
) -> None:
    ssh_password = None
    if not ssh_key:
        if is_windows():
            console.err(
                "Password SSH authentication is not supported on Windows. "
                "Use --ssh-key or run bootstrap from Linux/macOS."
            )
            raise typer.Exit(code=2)
        console.info("SSH password required for remote host.")
        ssh_password = typer.prompt("SSH password (input hidden)", hide_input=True)

    ssh_user = ssh_host.split("@", 1)[0] if "@" in ssh_host else ""
    use_sudo = ssh_sudo and ssh_user != "root"
    if ssh_user == "root":
        use_sudo = False

    target = SshTarget(
        host=ssh_host,
        port=ssh_port,
        key_path=ssh_key,
        password=ssh_password,
        sudo=use_sudo,
        dry_run=False,
    )
    session = SSHSession(target=target, control_path=build_control_path(dry_run=False))
    try:
        try:
            session.start()
        except RuntimeError as exc:
            console.err(str(exc))
            raise typer.Exit(code=2)
        if use_sudo:
            _ensure_remote_sudo(session, target)
        ensure_https(
            domain,
            email,
            api_port,
            http01=True,
            ssh_session=session,
            allow_sudo=use_sudo,
        )
    except (HttpsSetupError, ValueError, RuntimeError) as exc:
        report_https_failure(exc)
        raise typer.Exit(code=2)
    finally:
        session.close()


def _ensure_remote_sudo(session: SSHSession, target: SshTarget) -> None:
    if target.dry_run:
        target.sudo_mode = "nopass"
        return
    if session.run("command -v sudo >/dev/null 2>&1").returncode != 0:
        raise RuntimeError("Remote user does not have sufficient privileges (sudo required)")
    check = session.run("sudo -n true")
    if check.returncode == 0:
        target.sudo_mode = "nopass"
        return
    stderr = (check.stderr or "").lower()
    if "not in the sudoers file" in stderr or "is not allowed to run sudo" in stderr:
        raise RuntimeError("Remote user does not have sufficient privileges (sudo required)")
    console.info("Sudo password required for remote host.")
    sudo_password = typer.prompt("Sudo password (input hidden)", hide_input=True)
    verify = session.run_input("sudo -S -p '' true", f"{sudo_password}\n", log_label="sudo check")
    if verify.returncode != 0:
        raise RuntimeError("Sudo authentication failed.")
    target.sudo_password = sudo_password
    target.sudo_mode = "password"


def _run_local(command: str, *, sudo: bool) -> subprocess.CompletedProcess:
    cmd = command
    if sudo and os.geteuid() != 0:
        cmd = f"sudo {command}"
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def _run_local_input(command: str, content: str, *, sudo: bool) -> subprocess.CompletedProcess:
    cmd = f"sh -c {shlex.quote(command)}"
    if sudo and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    return subprocess.run(cmd, shell=True, input=content, text=True, capture_output=True)


def _remote_run(session: SSHSession, command: str, *, sudo: bool) -> subprocess.CompletedProcess:
    return session.run_privileged(command) if sudo else session.run(command)


def _remote_run_input(
        session: SSHSession,
        command: str,
        content: str,
        *,
        log_label: str,
        sudo: bool,
) -> subprocess.CompletedProcess:
    if sudo:
        return session.run_input_privileged(command, content, log_label=log_label)
    return session.run_input(command, content, log_label=log_label)


def _run_checked(ctx: ExecContext, command: str, *, label: str, sudo: bool = False) -> subprocess.CompletedProcess:
    res = ctx.run(command, sudo=sudo)
    if res.returncode != 0:
        raise HttpsSetupError(f"Failed to {label}.", stdout=res.stdout, stderr=res.stderr)
    return res


def _ensure_apt_available(ctx: ExecContext) -> None:
    if ctx.run("command -v apt-get >/dev/null 2>&1").returncode != 0:
        raise HttpsSetupError("apt-get not found. This step currently supports Debian-based hosts only.")


def _is_interactive() -> bool:
    return sys.stdin.isatty()


def _get_debian_codename(ctx: ExecContext) -> str | None:
    res = ctx.run("cat /etc/os-release")
    if res.returncode != 0:
        return None
    data: dict[str, str] = {}
    for line in (res.stdout or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"')
    if data.get("ID") != "debian":
        return None
    return data.get("VERSION_CODENAME") or None


def _apt_sources_grep(ctx: ExecContext, pattern: str) -> str:
    cmd = (
        f"grep -nH -E {shlex.quote(pattern)} "
        "/etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true"
    )
    res = ctx.run(cmd)
    return res.stdout or ""


def _split_non_empty(text: str) -> list[str]:
    return [line for line in (text or "").splitlines() if line.strip()]


def _apt_line_content(grep_line: str) -> str:
    parts = grep_line.split(":", 2)
    return parts[2] if len(parts) == 3 else grep_line


def _apt_line_file(grep_line: str) -> str:
    parts = grep_line.split(":", 2)
    return parts[0] if len(parts) >= 2 else ""


def _parse_apt_suite(line: str) -> str | None:
    tokens = line.strip().split()
    if len(tokens) < 3:
        return None
    if tokens[0] not in {"deb", "deb-src"}:
        return None
    idx = 1
    if tokens[idx].startswith("["):
        while idx < len(tokens) and not tokens[idx].endswith("]"):
            idx += 1
        idx += 1
    if idx + 1 >= len(tokens):
        return None
    return tokens[idx + 1]


def _find_duplicate_apt_lines(grep_lines: list[str]) -> list[str]:
    seen: dict[str, list[str]] = {}
    for line in grep_lines:
        content = _apt_line_content(line).strip()
        if not content or content.startswith("#"):
            continue
        normalized = " ".join(content.split())
        seen.setdefault(normalized, []).append(line)
    duplicates: list[str] = []
    for occurrences in seen.values():
        if len(occurrences) > 1:
            duplicates.extend(occurrences)
    return duplicates


def _apt_sanity_check(ctx: ExecContext) -> AptFixPlan | None:
    codename = _get_debian_codename(ctx)
    if not codename:
        return None
    updates_grep = _apt_sources_grep(
        ctx,
        r"^[[:space:]]*deb[[:space:]].*deb\.debian\.org/debian-updates",
    )
    updates_lines = _split_non_empty(updates_grep)
    bad_updates_lines = [line for line in updates_lines if f"{codename}-updates" in line]

    security_grep = _apt_sources_grep(ctx, r"^[[:space:]]*deb[[:space:]].*debian-security")
    security_lines = _split_non_empty(security_grep)
    security_wrong_lines: list[str] = []
    has_security = False
    expected_suite = f"{codename}-security"
    for line in security_lines:
        content = _apt_line_content(line)
        suite = _parse_apt_suite(content)
        if suite == expected_suite:
            has_security = True
        elif suite:
            security_wrong_lines.append(line)
    security_missing = not has_security

    all_deb_grep = _apt_sources_grep(ctx, r"^[[:space:]]*deb(-src)?[[:space:]]")
    duplicate_lines = _find_duplicate_apt_lines(_split_non_empty(all_deb_grep))

    if not (bad_updates_lines or security_wrong_lines or security_missing or duplicate_lines):
        return None
    return AptFixPlan(
        codename=codename,
        bad_updates_lines=bad_updates_lines,
        security_wrong_lines=security_wrong_lines,
        security_missing=security_missing,
        duplicate_lines=duplicate_lines,
    )


def _render_apt_issues(plan: AptFixPlan) -> None:
    console.warn("APT sources sanity check detected issues:")
    if plan.bad_updates_lines:
        console.print("Wrong debian-updates URL (should be deb.debian.org/debian):")
        console.print("\n".join(plan.bad_updates_lines))
    if plan.security_wrong_lines:
        console.print("Wrong debian-security suite:")
        console.print("\n".join(plan.security_wrong_lines))
    if plan.security_missing:
        console.print(f"Missing debian-security line for {plan.codename}-security.")
    if plan.duplicate_lines:
        console.print("Duplicate APT source lines (optional cleanup):")
        console.print("\n".join(plan.duplicate_lines))


def _prompt_apt_fix() -> str:
    while True:
        choice = typer.prompt(
            "Choose: [f] auto-fix, [s] skip (may fail), [q] abort",
            default="q",
        ).strip().lower()
        if choice in {"f", "s", "q"}:
            return choice
        console.print("Enter f, s, or q.")


def _backup_apt_files(ctx: ExecContext, files: set[str]) -> str:
    ts_res = ctx.run("date +%Y%m%d%H%M%S")
    timestamp = (ts_res.stdout or "").strip() or "backup"
    for path in sorted(files):
        if not path:
            continue
        exists = ctx.run(f"test -f {shlex.quote(path)}", sudo=ctx.needs_sudo)
        if exists.returncode != 0:
            continue
        backup = f"{path}.bak-{timestamp}"
        _run_checked(
            ctx,
            f"cp {shlex.quote(path)} {shlex.quote(backup)}",
            label=f"backup {path}",
            sudo=ctx.needs_sudo,
        )
    return timestamp


def _apply_apt_fix(ctx: ExecContext, plan: AptFixPlan) -> None:
    files_to_backup: set[str] = set()
    for line in plan.bad_updates_lines + plan.security_wrong_lines:
        path = _apt_line_file(line)
        if path:
            files_to_backup.add(path)
    if plan.security_missing:
        files_to_backup.add("/etc/apt/sources.list")

    _backup_apt_files(ctx, files_to_backup)

    if plan.bad_updates_lines:
        updates_suite = f"{plan.codename}-updates"
        for path in sorted({_apt_line_file(line) for line in plan.bad_updates_lines}):
            if not path:
                continue
            cmd = (
                f"sed -i -E "
                f"'/[[:space:]]{updates_suite}[[:space:]]/ "
                f"s|deb\\.debian\\.org/debian-updates|deb.debian.org/debian|g' "
                f"{shlex.quote(path)}"
            )
            _run_checked(ctx, cmd, label=f"fix debian-updates in {path}", sudo=ctx.needs_sudo)

    if plan.security_wrong_lines:
        expected_suite = f"{plan.codename}-security"
        for path in sorted({_apt_line_file(line) for line in plan.security_wrong_lines}):
            if not path:
                continue
            cmd = (
                "sed -i -E "
                f"'/debian-security/ s|(debian-security[[:space:]]+)[^[:space:]]+|\\1{expected_suite}|' "
                f"{shlex.quote(path)}"
            )
            _run_checked(ctx, cmd, label=f"fix debian-security suite in {path}", sudo=ctx.needs_sudo)

    if plan.security_missing:
        line = f"deb http://security.debian.org/debian-security {plan.codename}-security main"
        cmd = f"printf '%s\\n' {shlex.quote(line)} | tee -a /etc/apt/sources.list >/dev/null"
        _run_checked(ctx, cmd, label="add debian-security entry", sudo=ctx.needs_sudo)


def _ensure_apt_sanity(ctx: ExecContext) -> bool:
    plan = _apt_sanity_check(ctx)
    if not plan:
        return False
    if plan.has_warnings() or plan.has_fixable_issues():
        _render_apt_issues(plan)
    if not plan.has_fixable_issues():
        return False
    if not _is_interactive():
        details = []
        if plan.bad_updates_lines:
            details.extend(plan.bad_updates_lines)
        if plan.security_wrong_lines:
            details.extend(plan.security_wrong_lines)
        missing_note = ""
        if plan.security_missing:
            missing_note = f" Missing debian-security line for {plan.codename}-security."
        raise HttpsSetupError(
            "APT sources appear misconfigured. Fix the entries shown and re-run HTTPS setup."
            + missing_note,
            stdout="\n".join(details),
        )
    choice = _prompt_apt_fix()
    if choice == "q":
        raise HttpsSetupError("Aborted due to APT sources issues.")
    if choice == "s":
        return False
    _apply_apt_fix(ctx, plan)
    console.ok("APT sources updated.")
    return True


def _install_packages(ctx: ExecContext) -> None:
    _ensure_apt_sanity(ctx)
    _run_checked(ctx, "apt-get update", label="update apt package lists", sudo=ctx.needs_sudo)
    _run_checked(
        ctx,
        "apt-get install -y nginx certbot python3-certbot-nginx",
        label="install nginx/certbot",
        sudo=ctx.needs_sudo,
    )


def _write_nginx_config(ctx: ExecContext, domain: str, api_port: int) -> None:
    config = "\n".join(
        [
            "server {",
            "    listen 80;",
            f"    server_name {domain};",
            "",
            "    location / {",
            f"        proxy_pass http://{DEFAULT_PROXY_HOST}:{api_port};",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "    }",
            "}",
            "",
        ]
    )
    cmd = f"cat > {shlex.quote(DEFAULT_NGINX_SITE)}"
    res = ctx.run_input(cmd, config, log_label="write nginx config", sudo=ctx.needs_sudo)
    if res.returncode != 0:
        raise HttpsSetupError("Failed to write nginx config.", stdout=res.stdout, stderr=res.stderr)


def _enable_nginx_site(ctx: ExecContext) -> None:
    cmd = f"ln -sf {shlex.quote(DEFAULT_NGINX_SITE)} {shlex.quote(DEFAULT_NGINX_ENABLED)}"
    _run_checked(ctx, cmd, label="enable nginx site", sudo=ctx.needs_sudo)


def _check_ports(ctx: ExecContext) -> None:
    if ctx.run("command -v ss >/dev/null 2>&1").returncode != 0:
        console.warn("Skipping port check (ss not available).")
        return
    res = ctx.run("ss -ltnp | grep -E ':(80|443)\\b'", sudo=ctx.needs_sudo)
    output = (res.stdout or "").strip()
    if res.returncode != 0 and not output:
        stderr = (res.stderr or "").strip()
        if stderr:
            console.warn(f"Skipping port check: {stderr}")
        return
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        return
    non_nginx = [line for line in lines if "nginx" not in line]
    if non_nginx:
        raise HttpsSetupError(
            "Ports 80/443 are already in use by another process. Stop it before running certbot.",
            stdout=output,
        )


def _run_certbot(ctx: ExecContext, domain: str, email: str, *, http01: bool) -> None:
    cmd = (
        "certbot --nginx "
        f"-d {shlex.quote(domain)} "
        f"--non-interactive --agree-tos -m {shlex.quote(email)}"
    )
    if not http01:
        cmd += " --preferred-challenges tls-alpn-01"
    _run_checked(ctx, cmd, label="obtain Let's Encrypt certificate", sudo=ctx.needs_sudo)


def _verify_https_health(ctx: ExecContext, domain: str) -> None:
    url = f"https://{domain}/health"
    cmd = f"curl -fsS -m 10 {shlex.quote(url)}"
    _run_checked(ctx, cmd, label="verify HTTPS health endpoint")


def _https_already_configured(ctx: ExecContext, domain: str) -> bool:
    config_ok = ctx.run(f"test -f {shlex.quote(DEFAULT_NGINX_SITE)}", sudo=ctx.needs_sudo).returncode == 0
    enabled_ok = ctx.run(f"test -L {shlex.quote(DEFAULT_NGINX_ENABLED)}", sudo=ctx.needs_sudo).returncode == 0
    if not (config_ok and enabled_ok):
        return False
    if _has_existing_cert(ctx, domain):
        return True
    return False


def _has_existing_cert(ctx: ExecContext, domain: str) -> bool:
    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    if ctx.run(f"test -f {shlex.quote(cert_path)}", sudo=ctx.needs_sudo).returncode == 0:
        return True
    if ctx.run("command -v certbot >/dev/null 2>&1").returncode != 0:
        return False
    res = ctx.run(f"certbot certificates -d {shlex.quote(domain)}")
    if res.returncode != 0:
        return False
    output = (res.stdout or "") + (res.stderr or "")
    return domain in output


def _extract_ips(text: str) -> list[str]:
    return _IP_RE.findall(text or "")


def _check_dns(ctx: ExecContext, domain: str, *, http01: bool) -> None:
    domain_ips = _resolve_domain_ips(ctx, domain)
    public_ip, source = _get_public_ip(ctx)
    if not domain_ips:
        console.warn("Could not resolve DNS for the domain. Proceeding anyway.")
        return
    if not public_ip:
        console.warn("Could not determine host public IP. Proceeding anyway.")
        return
    cloudflare = _detect_cloudflare(ctx, domain, domain_ips)
    if cloudflare and public_ip not in domain_ips:
        console.warn(
            "Cloudflare proxy appears enabled (orange-cloud). "
            "DNS A will not match origin IP; this is expected."
        )
        console.info(f"DNS A records: {domain_ips}; origin IP: {public_ip} ({source}).")
        if http01:
            console.info(
                "Cloudflare proxy may interfere with HTTP-01 checks. "
                "Consider DNS-01 via a Cloudflare API token for best reliability."
            )
        return
    if cloudflare:
        console.info("Cloudflare proxy detected.")
        if http01:
            console.info(
                "Cloudflare proxy may interfere with HTTP-01 checks. "
                "Consider DNS-01 via a Cloudflare API token for best reliability."
            )
    if public_ip not in domain_ips:
        console.warn(
            f"DNS A record does not match host IP. Domain: {domain_ips}, host: {public_ip} ({source})."
        )
    elif source != "ifconfig.me":
        console.info(f"DNS check passed (local IP source: {source}).")


def _resolve_domain_ips(ctx: ExecContext, domain: str) -> list[str]:
    if ctx.run("command -v dig >/dev/null 2>&1").returncode == 0:
        res = ctx.run(f"dig +short {shlex.quote(domain)} A")
        return _extract_ips(res.stdout or "")
    if ctx.run("command -v getent >/dev/null 2>&1").returncode == 0:
        res = ctx.run(f"getent hosts {shlex.quote(domain)}")
        return _extract_ips(res.stdout or "")
    return []


def _get_public_ip(ctx: ExecContext) -> tuple[str | None, str]:
    if ctx.run("command -v curl >/dev/null 2>&1").returncode == 0:
        res = ctx.run("curl -s ifconfig.me")
        ips = _extract_ips(res.stdout or "")
        if ips:
            return ips[0], "ifconfig.me"
    if ctx.session:
        res = ctx.run("ip route get 1.1.1.1 | awk '{print $7; exit}'")
    else:
        res = ctx.run("hostname -I")
    ips = _extract_ips(res.stdout or "")
    if ips:
        source = "ip route" if ctx.session else "hostname -I"
        console.warn(f"Using {source} for host IP comparison; it may not be public.")
        return ips[0], source
    return None, "unknown"


def _detect_cloudflare(ctx: ExecContext, domain: str, domain_ips: list[str]) -> bool:
    if _any_cloudflare_ip(domain_ips):
        return True
    res = ctx.run(f"curl -sI -m 5 http://{shlex.quote(domain)}")
    headers = (res.stdout or "").lower()
    if "cf-ray:" in headers or "server: cloudflare" in headers:
        return True
    return False


def _any_cloudflare_ip(domain_ips: list[str]) -> bool:
    ranges = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]
    networks = [ipaddress.ip_network(cidr) for cidr in ranges]
    for ip in domain_ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for net in networks:
            if addr in net:
                return True
    return False


def _tail(text: str, *, limit: int = 8) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) <= limit:
        return text
    return "\n".join(lines[-limit:])


def report_https_failure(exc: Exception) -> None:
    console.err(f"HTTPS setup failed: {exc}")
    if isinstance(exc, HttpsSetupError):
        stdout = _tail(exc.stdout)
        stderr = _tail(exc.stderr)
        if stdout:
            console.err(f"Last stdout:\n{stdout}")
        if stderr:
            console.err(f"Last stderr:\n{stderr}")
    console.info("Useful checks:")
    console.print("- nginx -t")
    console.print("- journalctl -u nginx --no-pager -n 100")
    console.print("- certbot certificates")
    console.print("- docker compose logs -f api")
