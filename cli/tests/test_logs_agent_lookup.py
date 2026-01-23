from __future__ import annotations

from saharo_cli.commands import logs_cmd


def test_resolve_agent_id_paginates() -> None:
    class _FakeClient:
        def __init__(self):
            self.calls = 0

        def admin_agents_list(self, *, include_deleted: bool, limit: int, offset: int):  # noqa: ANN001
            self.calls += 1
            if offset == 0:
                return {"items": [{"id": 1, "name": "first"}], "total": 3}
            return {"items": [{"id": 3, "name": "target"}], "total": 3}

    client = _FakeClient()
    agent_id = logs_cmd._resolve_agent_id(client, "target")

    assert agent_id == 3
    assert client.calls == 2
