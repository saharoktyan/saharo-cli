from __future__ import annotations

import functools
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import console


@dataclass
class SshTarget:
    host: str
    port: int = 22
    key_path: str | None = None
    password: str | None = None
    sudo: bool = False
    sudo_password: str | None = None
    dry_run: bool = False
    sudo_mode: str | None = None


@dataclass
class SSHSession:
    target: SshTarget
    control_path: str
    _started: bool = field(default=False, init=False, repr=False)
    _control_master_enabled: bool = field(default=True, init=False, repr=False)

    def __post_init__(self) -> None:
        self._control_master_enabled = supports_control_master()

    def start(self) -> None:
        if self.target.dry_run:
            return
        if not self._control_master_enabled:
            cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, "true"]
            res = subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(self.target.password))
            if res.returncode != 0:
                raise RuntimeError(res.stderr.strip() or "Failed to establish SSH connection")
            return
        cmd = self._ssh_base_cmd(control_master=True) + [self.target.host, "true"]
        res = subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(self.target.password))
        if res.returncode != 0:
            if _is_control_master_unsupported(_decode_stderr(res.stderr or res.stdout)):
                self._control_master_enabled = False
                cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, "true"]
                res = subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(self.target.password))
                if res.returncode != 0:
                    raise RuntimeError(res.stderr.strip() or "Failed to establish SSH connection")
                return
            raise RuntimeError(res.stderr.strip() or "Failed to establish SSH control connection")
        if not is_windows():
            self._started = True

    def close(self) -> None:
        if self.target.dry_run:
            return
        if not self._started:
            return
        try:
            cmd = self._ssh_base_cmd(control_master=False) + ["-O", "exit", self.target.host]
            subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(self.target.password))
        except Exception:
            return

    def run(self, command: str, *, cwd: str | None = None) -> subprocess.CompletedProcess:
        remote_cmd = _with_cwd(command, cwd)
        if self.target.dry_run:
            console.info(f"[dry-run] ssh {self.target.host}: {remote_cmd}")
            return subprocess.CompletedProcess([], 0, "", "")
        cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, remote_cmd]
        return subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env=_ssh_env(self.target.password),
        )

    def run_input(
            self,
            command: str,
            content: str,
            *,
            log_label: str,
            cwd: str | None = None,
    ) -> subprocess.CompletedProcess:
        remote_cmd = _with_cwd(command, cwd)
        if self.target.dry_run:
            console.info(f"[dry-run] ssh {self.target.host}: {log_label}")
            return subprocess.CompletedProcess([], 0, "", "")
        cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, remote_cmd]
        return subprocess.run(cmd, text=True, input=content, capture_output=True, env=_ssh_env(self.target.password))

    def run_privileged(self, command: str, *, cwd: str | None = None) -> subprocess.CompletedProcess:
        _ensure_sudo_mode(self.target)
        sudo_cmd = _sudo_command_with_cwd(self.target, command, cwd)
        if self.target.dry_run:
            console.info(f"[dry-run] ssh {self.target.host}: [sudo] {sudo_cmd}")
            return subprocess.CompletedProcess([], 0, "", "")
        cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, sudo_cmd]
        if self.target.sudo_mode == "password":
            return subprocess.run(
                cmd,
                text=True,
                input=f"{self.target.sudo_password}\n",
                capture_output=True,
                env=_ssh_env(self.target.password),
            )
        return subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env=_ssh_env(self.target.password),
        )

    def run_input_privileged(
            self,
            command: str,
            content: str,
            *,
            log_label: str,
            cwd: str | None = None,
    ) -> subprocess.CompletedProcess:
        _ensure_sudo_mode(self.target)
        sudo_cmd = _sudo_command_with_cwd(self.target, command, cwd)
        if self.target.dry_run:
            console.info(f"[dry-run] ssh {self.target.host}: [sudo] {log_label}")
            return subprocess.CompletedProcess([], 0, "", "")
        cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, sudo_cmd]
        if self.target.sudo_mode == "password":
            return subprocess.run(
                cmd,
                text=True,
                input=f"{self.target.sudo_password}\n{content}",
                capture_output=True,
                env=_ssh_env(self.target.password),
            )
        return subprocess.run(cmd, text=True, input=content, capture_output=True, env=_ssh_env(self.target.password))

    def put_dir_tar(self, local_dir: str, remote_dir: str) -> subprocess.CompletedProcess:
        if self.target.dry_run:
            console.info(f"[dry-run] upload {local_dir} -> {remote_dir}")
            return subprocess.CompletedProcess([], 0, "", "")
        if not os.path.isdir(local_dir):
            raise RuntimeError(f"Local directory not found: {local_dir}")
        if self.target.sudo:
            _ensure_sudo_mode(self.target)
        tar_cmd = ["tar", "-czf", "-", "-C", local_dir, "."]
        remote_cmd = f"mkdir -p {shlex.quote(remote_dir)} && tar -xzf - -C {shlex.quote(remote_dir)}"
        if self.target.sudo:
            remote_cmd = f"{_sudo_prefix(self.target)} sh -c {shlex.quote(remote_cmd)}"
        ssh_cmd = self._ssh_base_cmd(control_master=False) + [self.target.host, remote_cmd]
        tar_proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ssh_proc = subprocess.Popen(
            ssh_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_ssh_env(self.target.password),
        )
        if not tar_proc.stdout or not ssh_proc.stdin:
            raise RuntimeError("Failed to open tar/ssh streams for upload.")
        if self.target.sudo_mode == "password":
            ssh_proc.stdin.write(f"{self.target.sudo_password}\n".encode("utf-8"))
        shutil.copyfileobj(tar_proc.stdout, ssh_proc.stdin)
        tar_proc.stdout.close()
        ssh_proc.stdin.close()
        tar_stderr = tar_proc.stderr.read() if tar_proc.stderr else b""
        tar_proc.wait()
        stdout, stderr = ssh_proc.communicate()
        if tar_proc.returncode != 0:
            raise RuntimeError(
                f"Failed to create tar archive: {tar_stderr.decode('utf-8', errors='ignore').strip()}"
            )
        return subprocess.CompletedProcess(ssh_cmd, ssh_proc.returncode or 0, stdout, stderr)


def _decode_stderr(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore").strip()
    return str(raw).strip()


def _ssh_base_cmd(self, *, control_master: bool) -> list[str]:
    cmd = ["ssh", "-p", str(self.target.port), "-o", "StrictHostKeyChecking=yes"]
    if not is_windows() and self._control_master_enabled:
        cmd += ["-o", f"ControlPath={self.control_path}"]
        if control_master:
            cmd += ["-o", "ControlMaster=auto", "-o", "ControlPersist=10m"]
    if self.target.key_path:
        cmd += ["-i", self.target.key_path]
    if self.target.password:
        if is_windows():
            raise RuntimeError(
                "Password SSH authentication is not supported on Windows. "
                "Use --ssh-key or run bootstrap from Linux/macOS."
            )
        if not shutil.which("sshpass"):
            raise RuntimeError("sshpass is required for password authentication")
        cmd = ["sshpass", "-e"] + cmd
    return cmd


SSHSession._ssh_base_cmd = _ssh_base_cmd


def build_control_path(*, dry_run: bool) -> str:
    if dry_run:
        if is_windows():
            return str(Path(tempfile.gettempdir()) / "saharo-ctl-%C")
        return "/tmp/saharo-ctl-%C"
    base = Path(os.path.expanduser("~/.cache/saharo/ctl"))
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "%C")


def _base_ssh_cmd(target: SshTarget) -> list[str]:
    cmd = ["ssh", "-p", str(target.port), "-o", "StrictHostKeyChecking=yes"]
    if target.key_path:
        cmd += ["-i", target.key_path]
    if target.password:
        if is_windows():
            raise RuntimeError(
                "Password SSH authentication is not supported on Windows. "
                "Use --ssh-key or run bootstrap from Linux/macOS."
            )
        if not shutil.which("sshpass"):
            raise RuntimeError("sshpass is required for password authentication")
        cmd = ["sshpass", "-e"] + cmd
    return cmd


def _base_scp_cmd(target: SshTarget) -> list[str]:
    cmd = ["scp", "-P", str(target.port), "-o", "StrictHostKeyChecking=yes"]
    if target.key_path:
        cmd += ["-i", target.key_path]
    if target.password:
        if is_windows():
            raise RuntimeError(
                "Password SSH authentication is not supported on Windows. "
                "Use --ssh-key or run bootstrap from Linux/macOS."
            )
        if not shutil.which("sshpass"):
            raise RuntimeError("sshpass is required for password authentication")
        cmd = ["sshpass", "-e"] + cmd
    return cmd


def is_windows() -> bool:
    return os.name == "nt" or platform.system() == "Windows"


@functools.lru_cache(maxsize=1)
def _ssh_version() -> tuple[int, int] | None:
    try:
        res = subprocess.run(["ssh", "-V"], text=True, capture_output=True)
    except FileNotFoundError:
        return None
    output = (res.stderr or res.stdout or "").strip()
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", output)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def supports_control_master() -> bool:
    if is_windows():
        return False
    version = _ssh_version()
    if version is None:
        return True
    major, minor = version
    return (major, minor) >= (4, 0)


def _is_control_master_unsupported(stderr: str) -> bool:
    if not stderr:
        return False
    lowered = stderr.lower()
    return any(
        token in lowered
        for token in (
            "bad configuration option: controlmaster",
            "bad configuration option: controlpersist",
            "bad configuration option: controlpath",
        )
    )


def _sudo_prefix(target: SshTarget) -> str:
    if target.sudo_mode == "password":
        return "sudo -S -p ''"
    return "sudo -n"


def _maybe_sudo(target: SshTarget, command: str) -> str:
    if not target.sudo:
        return command
    return f"{_sudo_prefix(target)} {command}"


def _with_cwd(command: str, cwd: str | None) -> str:
    if not cwd:
        return command
    return f"cd {shlex.quote(cwd)} && {command}"


def _sudo_command_with_cwd(target: SshTarget, command: str, cwd: str | None) -> str:
    wrapped = _with_cwd(command, cwd)
    sudo_cmd = f"{_sudo_prefix(target)} sh -lc {shlex.quote(wrapped)}"
    if target.dry_run:
        console.info(f"[dry-run] sudo remote cmd: {sudo_cmd}")
    return sudo_cmd


def _ensure_sudo_mode(target: SshTarget) -> None:
    if not target.sudo:
        raise RuntimeError("Sudo requires --sudo.")
    if target.sudo_mode:
        return
    if target.dry_run:
        target.sudo_mode = "nopass"
        return

    check = _run_raw(target, "sudo -n true")
    if check.returncode == 0:
        target.sudo_mode = "nopass"
        return
    if target.sudo_password:
        target.sudo_mode = "password"
        return
    raise RuntimeError("Sudo requires a password. Re-run with --sudo-password or configure NOPASSWD.")


def _run_raw(target: SshTarget, command: str) -> subprocess.CompletedProcess:
    cmd = _base_ssh_cmd(target) + [target.host, command]
    if target.dry_run:
        console.info(f"[dry-run] ssh {target.host}: {command}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(target.password))


def run_remote(target: SshTarget, command: str, *, cwd: str | None = None) -> subprocess.CompletedProcess:
    remote_cmd = _with_cwd(command, cwd)
    cmd = _base_ssh_cmd(target) + [target.host, remote_cmd]
    if target.dry_run:
        console.info(f"[dry-run] ssh {target.host}: {remote_cmd}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, text=True, capture_output=True, env=_ssh_env(target.password))


def run_remote_input(
        target: SshTarget,
        command: str,
        content: str,
        *,
        log_label: str,
        cwd: str | None = None,
) -> subprocess.CompletedProcess:
    remote_cmd = _with_cwd(command, cwd)
    cmd = _base_ssh_cmd(target) + [target.host, remote_cmd]
    if target.dry_run:
        console.info(f"[dry-run] ssh {target.host}: {log_label}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, text=True, input=content, capture_output=True, env=_ssh_env(target.password))


def run_remote_privileged(target: SshTarget, command: str, *, cwd: str | None = None) -> subprocess.CompletedProcess:
    _ensure_sudo_mode(target)
    sudo_cmd = _sudo_command_with_cwd(target, command, cwd)
    if target.dry_run:
        console.info(f"[dry-run] ssh {target.host}: [sudo] {sudo_cmd}")
        return subprocess.CompletedProcess([], 0, "", "")
    if target.sudo_mode == "password":
        return run_remote_input(target, sudo_cmd, f"{target.sudo_password}\n", log_label="sudo command")
    return run_remote(target, sudo_cmd)


def run_remote_input_privileged(
        target: SshTarget,
        command: str,
        content: str,
        *,
        log_label: str,
        cwd: str | None = None,
) -> subprocess.CompletedProcess:
    _ensure_sudo_mode(target)
    sudo_cmd = _sudo_command_with_cwd(target, command, cwd)
    if target.dry_run:
        console.info(f"[dry-run] ssh {target.host}: [sudo] {log_label}")
        return subprocess.CompletedProcess([], 0, "", "")
    if target.sudo_mode == "password":
        return run_remote_input(
            target,
            sudo_cmd,
            f"{target.sudo_password}\n{content}",
            log_label=log_label,
        )
    return run_remote_input(target, sudo_cmd, content, log_label=log_label)


def upload_dir_tar(target: SshTarget, local_dir: str, remote_dir: str) -> subprocess.CompletedProcess:
    if target.dry_run:
        console.info(f"[dry-run] upload {local_dir} -> {remote_dir}")
        return subprocess.CompletedProcess(["tar"], 0, "", "")
    if not os.path.isdir(local_dir):
        raise RuntimeError(f"Local directory not found: {local_dir}")
    if target.sudo:
        _ensure_sudo_mode(target)
    tar_cmd = ["tar", "-czf", "-", "-C", local_dir, "."]
    remote_cmd = f"mkdir -p {shlex.quote(remote_dir)} && tar -xzf - -C {shlex.quote(remote_dir)}"
    if target.sudo:
        remote_cmd = f"{_sudo_prefix(target)} sh -lc {shlex.quote(remote_cmd)}"
    ssh_cmd = _base_ssh_cmd(target) + [target.host, remote_cmd]
    tar_proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ssh_proc = subprocess.Popen(
        ssh_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_ssh_env(target.password),
    )
    if not tar_proc.stdout or not ssh_proc.stdin:
        raise RuntimeError("Failed to open tar/ssh streams for upload.")
    if target.sudo_mode == "password":
        ssh_proc.stdin.write(f"{target.sudo_password}\n".encode("utf-8"))
    shutil.copyfileobj(tar_proc.stdout, ssh_proc.stdin)
    tar_proc.stdout.close()
    ssh_proc.stdin.close()
    tar_stderr = tar_proc.stderr.read() if tar_proc.stderr else b""
    tar_proc.wait()
    stdout, stderr = ssh_proc.communicate()
    if tar_proc.returncode != 0:
        raise RuntimeError(
            f"Failed to create tar archive: {tar_stderr.decode('utf-8', errors='ignore').strip()}"
        )
    return subprocess.CompletedProcess(ssh_cmd, ssh_proc.returncode or 0, stdout, stderr)


def _ssh_env(password: str | None) -> dict[str, str] | None:
    if not password:
        return None
    env = os.environ.copy()
    env["SSHPASS"] = password
    return env
