import subprocess

from saharo_cli.commands import host_bootstrap


class _FakeSession:
    def run(self, command: str) -> subprocess.CompletedProcess:
        if "command -v curl" in command:
            return subprocess.CompletedProcess([], 1, "", "")
        if "command -v python3" in command:
            return subprocess.CompletedProcess([], 0, "", "")
        return subprocess.CompletedProcess([], 0, '{"detail":"invalid root secret"}\n403', "")


def test_remote_http_post_json_python_fallback_preserves_http_error_status() -> None:
    session = _FakeSession()
    status, body = host_bootstrap._remote_http_post_json(
        session,
        "http://127.0.0.1:8010/admin/bootstrap",
        {"username": "admin"},
        {"Content-Type": "application/json"},
    )
    assert status == 403
    assert "invalid root secret" in (body or "")
