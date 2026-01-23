from saharo_cli.formatting import format_list_timestamp


def test_format_list_timestamp_truncates_microseconds() -> None:
    ts = "2026-01-04T23:04:51.290171Z"
    assert format_list_timestamp(ts) == "2026-01-04T23:04:51.290Z"


def test_format_list_timestamp_normalizes_utc_offset() -> None:
    ts = "2026-01-04T23:04:51.290171+00:00"
    assert format_list_timestamp(ts) == "2026-01-04T23:04:51.290Z"
