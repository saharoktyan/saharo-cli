from __future__ import annotations

import time


def normalize_job_type(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def job_status_hint(job_id: int | None) -> str:
    if job_id:
        return f"Check status: saharo jobs get {job_id}"
    return "Check status: saharo jobs list"


def wait_job(
        client,
        job_id: int,
        *,
        timeout_s: int = 900,
        interval_s: int = 5,
        on_status: callable | None = None,
        on_timeout: callable | None = None,
) -> dict:
    deadline = time.monotonic() + max(0, int(timeout_s))
    last_status = ""
    while True:
        job = client.admin_job_get(int(job_id))
        status = str(job.get("status") or "").lower()
        if status and status != last_status:
            if on_status:
                on_status(job_id, status)
            last_status = status
        if status in {"succeeded", "failed", "cancelled"}:
            return job
        if time.monotonic() >= deadline:
            if on_timeout:
                on_timeout(job_id)
            return job
        time.sleep(max(1, int(interval_s)))
