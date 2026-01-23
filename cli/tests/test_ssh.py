import pytest

from saharo_cli import ssh


def test_sudo_command_with_cwd_wraps_shell() -> None:
    target = ssh.SshTarget(host="example", sudo=True, dry_run=True)

    no_cwd_cmd = ssh._sudo_command_with_cwd(target, "echo ok", None)
    with_cwd_cmd = ssh._sudo_command_with_cwd(target, "echo ok", "/opt/app")

    assert "sh -lc" in no_cwd_cmd
    assert "sh -lc" in with_cwd_cmd
    assert "cd /opt/app" in with_cwd_cmd


def test_windows_ssh_disables_multiplexing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh, "is_windows", lambda: True)
    target = ssh.SshTarget(host="example", dry_run=True)
    session = ssh.SSHSession(target=target, control_path="ctl")

    cmd = session._ssh_base_cmd(control_master=True)

    assert not any("ControlMaster=" in part for part in cmd)
    assert not any("ControlPersist=" in part for part in cmd)
    assert not any("ControlPath=" in part for part in cmd)


def test_windows_password_auth_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh, "is_windows", lambda: True)
    target = ssh.SshTarget(host="example", password="secret", dry_run=True)

    with pytest.raises(RuntimeError, match="Password SSH authentication is not supported on Windows"):
        ssh._base_ssh_cmd(target)


def test_non_windows_ssh_uses_multiplexing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh, "is_windows", lambda: False)
    target = ssh.SshTarget(host="example", dry_run=True)
    session = ssh.SSHSession(target=target, control_path="/tmp/ctl")

    cmd = session._ssh_base_cmd(control_master=True)

    assert "ControlMaster=auto" in cmd
    assert "ControlPersist=10m" in cmd
    assert any("ControlPath=" in part for part in cmd)
