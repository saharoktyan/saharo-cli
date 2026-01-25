from __future__ import annotations

from saharo_cli import main
from saharo_cli.auth_state import AuthContext
from typer.testing import CliRunner


def test_top_level_whoami_command_available(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda **_: AuthContext(state="authed", role="admin"))
    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "whoami" in result.output
