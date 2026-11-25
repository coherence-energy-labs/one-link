"""Contract tests for the RUN-01 browser readiness gate (tests/e2e/browser_readiness.py).

The gate must be able to fail as well as pass. A browser whose parent process
does not answer must produce a named, bounded BrowserNotReady, never a hang
and never a pairing verdict. A startup-cache file that is still held open for
writing must keep the gate closed until the writer lets go.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import psutil
import pytest
from playwright.sync_api import Browser

from tests.e2e import browser_readiness
from tests.e2e.browser_readiness import BrowserNotReady, wait_for_browser_ready

# A same-origin-free probe target: fetch() of a data: URL needs no daemon.
_DATA_PROBE = "data:text/plain,ok"


def test_gate_passes_when_the_parent_answers(browser: Browser) -> None:
    context = browser.new_context()
    try:
        page = context.new_page()
        page.goto("about:blank")
        report = wait_for_browser_ready(
            page, browser, timeout_s=60, probe_path=_DATA_PROBE, require_startup_cache=False,
        )
        good = [p for p in report["parent_probes"] if p["offer"] == "ok" and p["fetch"] == "ok"]
        assert len(good) >= 3
    finally:
        context.close()


def test_gate_names_a_parent_that_never_answers_and_stays_bounded(browser: Browser) -> None:
    context = browser.new_context()
    try:
        page = context.new_page()
        # Simulate the RUN-01 hold: createOffer() never settles.
        page.add_init_script(
            "RTCPeerConnection.prototype.createOffer = function () { return new Promise(() => {}); };"
        )
        page.goto("about:blank")
        started = time.monotonic()
        with pytest.raises(BrowserNotReady) as caught:
            wait_for_browser_ready(
                page, browser, timeout_s=8, probe_bound_ms=500,
                probe_path=_DATA_PROBE, require_startup_cache=False,
            )
        assert time.monotonic() - started < 30, "the gate exceeded its own budget"
        message = str(caught.value)
        assert "browser not ready" in message
        assert "not a pairing failure" in message
    finally:
        context.close()


@pytest.mark.skipif(
    sys.platform != "win32" and not sys.platform.startswith("linux"),
    reason="a writer's open handle is directly observable only on Windows and Linux",
)
def test_startup_cache_stage_waits_for_the_writer_to_close(tmp_path: Path, monkeypatch) -> None:
    profile = tmp_path / "profile"
    cache = profile / "startupCache" / "startupCache.8.little"
    cache.parent.mkdir(parents=True)
    # This process stands in for the browser parent: it is the one that holds
    # the cache file open, which is what both platform checks look for.
    monkeypatch.setattr(browser_readiness, "_firefox_parents", lambda: {profile: psutil.Process()})
    writer = open(cache, "wb")
    writer.write(b"x" * 4096)
    writer.flush()

    # While the writer holds the file, the stage must not pass.
    report: dict = {}
    with pytest.raises(BrowserNotReady) as caught:
        browser_readiness._wait_for_startup_cache(time.monotonic() + 1.5, report)
    assert "startup-cache write had not finished" in str(caught.value)

    # Once the writer closes, the same stage passes.
    threading.Timer(0.5, writer.close).start()
    browser_readiness._wait_for_startup_cache(time.monotonic() + 10, report)
    assert report["startup_cache"]["bytes"] == 4096
    assert writer.closed


def test_startup_cache_stage_refuses_an_ambiguous_browser(monkeypatch) -> None:
    monkeypatch.setattr(browser_readiness, "_firefox_parents", lambda: {})
    with pytest.raises(BrowserNotReady, match="expected one Firefox profile"):
        browser_readiness._wait_for_startup_cache(time.monotonic() + 1, {})


class _UnreadableProcess:
    def open_files(self) -> list:
        raise psutil.AccessDenied(pid=1)


def test_an_unanswerable_writer_check_is_never_read_as_nobody_writing(tmp_path: Path) -> None:
    """None, not False: "could not ask" must not open the gate."""
    cache = tmp_path / "startupCache.8.little"
    cache.write_bytes(b"x")
    assert browser_readiness._held_for_write_by(cache, []) is None
    assert browser_readiness._held_for_write_by(cache, [_UnreadableProcess()]) is None  # type: ignore[list-item]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads descriptor access modes from /proc")
def test_linux_writer_check_tells_a_reader_from_a_writer(tmp_path: Path) -> None:
    cache = tmp_path / "startupCache.8.little"
    cache.write_bytes(b"x" * 64)
    me = [psutil.Process()]
    assert browser_readiness._held_for_write_by(cache, me) is False
    with open(cache, "rb"):
        assert browser_readiness._held_for_write_by(cache, me) is False, "a reader is not a writer"
    with open(cache, "ab"):
        assert browser_readiness._held_for_write_by(cache, me) is True
    with open(cache, "r+b"):
        assert browser_readiness._held_for_write_by(cache, me) is True
    assert browser_readiness._held_for_write_by(cache, me) is False


class _FakeBrowser:
    def __init__(self, name: str) -> None:
        self.browser_type = type("BrowserType", (), {"name": name})()


def test_session_stage_waits_only_for_firefox(tmp_path: Path, monkeypatch) -> None:
    """The conftest's once-per-session step: Firefox waits for the write, others do nothing."""
    calls: list[float] = []

    def stage(deadline: float, report: dict) -> None:
        calls.append(deadline)
        report["startup_cache"] = {"file": "startupCache.8.little", "bytes": 1, "waited_s": 0.0}

    monkeypatch.setattr(browser_readiness, "_wait_for_startup_cache", stage)
    chromium = browser_readiness.wait_for_startup_cache_write(_FakeBrowser("chromium"))  # type: ignore[arg-type]
    assert calls == [] and "skipped" in chromium
    started = time.monotonic()
    firefox = browser_readiness.wait_for_startup_cache_write(_FakeBrowser("firefox"), timeout_s=30)  # type: ignore[arg-type]
    assert len(calls) == 1 and 25 < calls[0] - started < 35, "the deadline must carry the timeout"
    assert firefox["startup_cache"]["bytes"] == 1


def test_session_stage_failure_is_browser_not_ready(monkeypatch) -> None:
    monkeypatch.setattr(browser_readiness, "_firefox_parents", lambda: {})
    with pytest.raises(BrowserNotReady):
        browser_readiness.wait_for_startup_cache_write(_FakeBrowser("firefox"), timeout_s=1)  # type: ignore[arg-type]


def test_this_session_ran_the_startup_cache_step_for_its_browser(browser: Browser) -> None:
    """The autouse fixture really ran for this session's browser (it cannot be a no-op by accident)."""
    from tests.e2e import conftest

    assert id(browser) in conftest._STARTUP_CACHE_SETTLED
