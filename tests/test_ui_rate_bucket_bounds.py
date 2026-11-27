"""The UI server's rate-limit map cannot grow with the number of callers."""

from __future__ import annotations

from collections import deque

from one_link import server as server_module
from one_link.server import UIServer


def _limiter() -> UIServer:
    ui = UIServer.__new__(UIServer)
    ui._rate_buckets = server_module.RateBuckets()
    return ui


def test_limit_still_applies_per_key() -> None:
    ui = _limiter()
    assert [ui._rate_limited("login", "a", limit=2) for _ in range(3)] == [False, False, True]
    assert ui._rate_limited("login", "b", limit=2) is False


def test_idle_buckets_are_swept_as_new_callers_arrive(monkeypatch) -> None:
    ui = _limiter()
    clock = {"now": 1000.0}
    monkeypatch.setattr(server_module.time, "monotonic", lambda: clock["now"])
    for i in range(server_module.RATE_BUCKETS_SWEEP_MIN):
        ui._rate_limited("login", f"old-{i}", limit=5)
    assert len(ui._rate_buckets) == server_module.RATE_BUCKETS_SWEEP_MIN

    # Everyone above goes quiet for longer than the window.
    clock["now"] += server_module.RATE_LIMIT_WINDOW_SECONDS + 1
    ui._rate_limited("login", "fresh", limit=5)
    assert set(ui._rate_buckets) == {("login", "fresh")}


def test_live_buckets_survive_a_sweep(monkeypatch) -> None:
    ui = _limiter()
    clock = {"now": 1000.0}
    monkeypatch.setattr(server_module.time, "monotonic", lambda: clock["now"])
    ui._rate_limited("login", "busy", limit=1)
    for i in range(server_module.RATE_BUCKETS_SWEEP_MIN):
        ui._rate_limited("login", f"k-{i}", limit=5)
    # "busy" is still inside its window, so it is still limited.
    assert ui._rate_limited("login", "busy", limit=1) is True


def test_a_longer_window_is_respected_by_the_sweep(monkeypatch) -> None:
    ui = _limiter()
    clock = {"now": 1000.0}
    monkeypatch.setattr(server_module.time, "monotonic", lambda: clock["now"])
    ui._rate_limited("slow", "x", limit=1, window_seconds=3600.0)
    clock["now"] += 120.0
    for i in range(server_module.RATE_BUCKETS_SWEEP_MIN + 5):
        ui._rate_limited("login", f"k-{i}", limit=5)
    assert ui._rate_limited("slow", "x", limit=1, window_seconds=3600.0) is True


def test_a_full_map_of_live_buckets_refuses_new_keys(monkeypatch) -> None:
    ui = _limiter()
    monkeypatch.setattr(server_module, "RATE_BUCKETS_MAX", 8)
    monkeypatch.setattr(server_module, "RATE_BUCKETS_SWEEP_MIN", 4)
    ui._rate_buckets.sweep_at = 4
    monkeypatch.setattr(server_module.time, "monotonic", lambda: 1000.0)
    for i in range(8):
        assert ui._rate_limited("login", f"k-{i}", limit=5) is False
    assert ui._rate_limited("login", "one-more", limit=5) is True
    assert len(ui._rate_buckets) == 8
    assert isinstance(ui._rate_buckets[("login", "k-0")], deque)


def test_a_plain_dict_still_works_as_the_bucket_map() -> None:
    # Older call sites and test shims assign a bare dict.
    ui = UIServer.__new__(UIServer)
    ui._rate_buckets = {}
    assert [ui._rate_limited("login", "a", limit=1) for _ in range(2)] == [False, True]
    assert list(ui._rate_buckets) == [("login", "a")]
