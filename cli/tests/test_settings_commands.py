from __future__ import annotations

from saharo_cli import main
from saharo_cli.auth_state import AuthContext
from typer.testing import CliRunner


def test_settings_group_available(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda: AuthContext(state="authed", role="user"))
    app = main._build_app()
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "settings" in result.output
