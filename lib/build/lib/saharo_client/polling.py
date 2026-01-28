from __future__ import annotations

import time


def wait_for_server_heartbeat(
        client,
        server_id: int,
        *,
        timeout_s: int,
        interval_s: int,
        on_status: callable | None = None,
        on_timeout: callable | None = None,
) -> dict:
    deadline = time.monotonic() + max(0, int(timeout_s))
    last_status = None
    while True:
        data = client.admin_server_status(server_id)
        status = data.get("status") or ("online" if data.get("online") else "offline")
        if status != last_status:
            if on_status:
                on_status(server_id, status)
            last_status = status
        if data.get("online") or data.get("last_heartbeat") or data.get("last_seen_at"):
            return data
        if time.monotonic() >= deadline:
            if on_timeout:
                on_timeout(server_id)
            return data
        time.sleep(max(1, int(interval_s)))
