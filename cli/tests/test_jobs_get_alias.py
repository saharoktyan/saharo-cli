from __future__ import annotations

from typer.testing import CliRunner

from saharo_cli import main
from saharo_cli.auth_state import AuthContext
from saharo_cli.commands import jobs_cmd


class _DummyClient:
    def admin_job_get(self, job_id: int) -> dict:
        return {"id": job_id, "status": "queued"}

    def close(self) -> None:
        return None


def test_jobs_get_and_show_alias(monkeypatch) -> None:
    monkeypatch.setattr(main, "resolve_auth_context", lambda: AuthContext(state="authed", role="admin"))
    monkeypatch.setattr(jobs_cmd, "make_client", lambda *args, **kwargs: _DummyClient())
    app = main._build_app()
    runner = CliRunner()

    result_get = runner.invoke(app, ["jobs", "get", "1"])
    assert result_get.exit_code == 0
    assert "id:" in result_get.output

    result_show = runner.invoke(app, ["jobs", "show", "1"])
    assert result_show.exit_code == 0
    assert "id:" in result_show.output
