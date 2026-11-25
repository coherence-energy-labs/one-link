"""Contract tests for the RUN-01 browser readiness gate (tests/e2e/browser_readiness.py).

The gate must be able to fail as well as pass:

* A Firefox whose startup cache can still be written must fail stage 1 with
  a named BrowserNotReady, whether it was launched without the relocation or
  with one that does not hold.
* Every Firefox the session launches without its own ``env`` inherits the
  relocation. One launched through ``launch_settled`` must come back with its
  cache disabled and its parent answering, including across the window in
  which an enabled cache would be written.
* A parent that does not answer must produce a bounded BrowserNotReady from
  stage 2, never a hang and never a product verdict.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from playwright.sync_api import Browser, BrowserType

from tests.e2e import browser_readiness
from tests.e2e.browser_readiness import (
    STARTUP_CACHE_ENV,
    BrowserNotReady,
    launch_settled,
    startup_cache_disabled_env,
    wait_for_browser_ready,
)

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
        assert "stage 'parent answers'" in message
        assert "not a product failure" in message
    finally:
        context.close()


def test_disabled_env_points_into_a_directory_that_does_not_exist() -> None:
    env = startup_cache_disabled_env({"KEEP": "1"})
    assert env["KEEP"] == "1"
    target = Path(env[STARTUP_CACHE_ENV])
    assert not target.parent.exists()
    assert startup_cache_disabled_env({})[STARTUP_CACHE_ENV] != env[STARTUP_CACHE_ENV], "each launch is isolated"


def test_stage_one_explains_every_way_a_cache_can_stay_writable(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    (profile / "startupCache").mkdir(parents=True)
    disabled = startup_cache_disabled_env({})

    def why(environ: dict[str, str] | None) -> str:
        reason = browser_readiness._startup_cache_problem(profile, environ)
        assert reason is not None, "a writable startup cache was accepted"
        return reason

    assert browser_readiness._startup_cache_problem(profile, disabled) is None
    assert "launched without" in why({})
    assert "could not be read" in why(None)
    assert "directory that exists" in why({STARTUP_CACHE_ENV: str(tmp_path / "startupCache.8.little")})
    (profile / "startupCache" / "startupCache.8.little").write_bytes(b"x")
    assert "did not take effect" in why(disabled)


def test_stage_one_refuses_when_no_firefox_is_running(monkeypatch) -> None:
    monkeypatch.setattr(browser_readiness, "_firefox_parents", lambda: {})
    with pytest.raises(BrowserNotReady, match="found none"):
        browser_readiness._wait_for_startup_cache(time.monotonic() + 1, {})


class _FakeBrowser:
    def __init__(self, name: str) -> None:
        self.browser_type = type("BrowserType", (), {"name": name})()


def test_session_stage_runs_only_for_firefox(monkeypatch) -> None:
    calls: list[float] = []

    def stage(deadline: float, report: dict) -> None:
        calls.append(deadline)
        report["startup_cache"] = {"profile": "disabled"}

    monkeypatch.setattr(browser_readiness, "_wait_for_startup_cache", stage)
    chromium = browser_readiness.wait_for_startup_cache_write(_FakeBrowser("chromium"))  # type: ignore[arg-type]
    assert calls == [] and "skipped" in chromium
    started = time.monotonic()
    firefox = browser_readiness.wait_for_startup_cache_write(_FakeBrowser("firefox"), timeout_s=30)  # type: ignore[arg-type]
    assert len(calls) == 1 and 25 < calls[0] - started < 35, "the deadline must carry the timeout"
    assert firefox["startup_cache"] == {"profile": "disabled"}


def test_this_session_ran_the_startup_cache_step_for_its_browser(browser: Browser) -> None:
    """The autouse fixture really ran for this session's browser (it cannot be a no-op by accident)."""
    from tests.e2e import conftest

    assert id(browser) in conftest._STARTUP_CACHE_SETTLED


def _new_profiles(before: set[Path]) -> set[Path]:
    return browser_readiness._firefox_profile_dirs() - before


def test_the_session_sets_the_relocation_for_every_launch() -> None:
    target = os.environ.get(STARTUP_CACHE_ENV)
    assert target, "the e2e session default is not set"
    assert not Path(target).parent.exists()


def test_a_plain_launch_inherits_the_disabled_cache(browser_type: BrowserType) -> None:
    """A test that calls browser_type.launch() itself is covered by the session default."""
    if browser_type.name != "firefox":
        pytest.skip("only Firefox has this startup-cache write")
    before = browser_readiness._firefox_profile_dirs()
    plain = browser_type.launch()
    try:
        browser_readiness._wait_for_startup_cache(time.monotonic() + 10, {}, profiles=_new_profiles(before))
    finally:
        plain.close()


def test_a_firefox_launched_without_the_relocation_fails_stage_one(browser_type: BrowserType) -> None:
    """The negative case on a real browser: no relocation, named failure."""
    if browser_type.name != "firefox":
        pytest.skip("only Firefox has this startup-cache write")
    before = browser_readiness._firefox_profile_dirs()
    bare = browser_type.launch(env={k: v for k, v in os.environ.items() if k != STARTUP_CACHE_ENV})
    try:
        with pytest.raises(BrowserNotReady) as caught:
            browser_readiness._wait_for_startup_cache(time.monotonic() + 10, {}, profiles=_new_profiles(before))
        message = str(caught.value)
        assert "stage 'startup cache disabled'" in message and "launched without" in message
        assert "not a product failure" in message
    finally:
        bare.close()


def test_launch_settled_firefox_has_no_cache_and_answers_through_the_write_window(
    browser_type: BrowserType,
) -> None:
    """Past the first write window (2-10 s after launch) nothing is written and the parent answers."""
    if browser_type.name != "firefox":
        pytest.skip("only Firefox has this startup-cache write")
    before = browser_readiness._firefox_profile_dirs()
    launched = launch_settled(browser_type)
    launched_at = time.monotonic()
    try:
        (profile,) = _new_profiles(before)
        page = launched.new_context().new_page()
        page.set_default_timeout(15_000)
        while time.monotonic() - launched_at < 12:
            started = time.monotonic()
            page.goto("about:blank")
            assert page.evaluate("() => 1 + 1") == 2
            assert time.monotonic() - started < 5, "the parent held a navigation"
            time.sleep(0.5)
        assert not list((profile / "startupCache").glob("startupCache.*")), "a startup cache was written"
        browser_readiness._wait_for_startup_cache(time.monotonic() + 10, {}, profiles={profile})
    finally:
        launched.close()
    assert browser_readiness._firefox_profile_dirs() == before


def test_launch_settled_closes_what_it_refuses(browser_type: BrowserType, monkeypatch) -> None:
    if browser_type.name != "firefox":
        pytest.skip("only Firefox has this startup-cache write")
    before = browser_readiness._firefox_profile_dirs()
    monkeypatch.setattr(browser_readiness, "_startup_cache_problem", lambda profile, environ: "forced for the test")
    with pytest.raises(BrowserNotReady, match="forced for the test"):
        launch_settled(browser_type, timeout_s=3)
    deadline = time.monotonic() + 15
    while browser_readiness._firefox_profile_dirs() != before and time.monotonic() < deadline:
        time.sleep(0.2)
    assert browser_readiness._firefox_profile_dirs() == before, "a refused browser must not be left running"


def test_launch_settled_is_a_plain_launch_for_other_browsers(browser_type: BrowserType, monkeypatch) -> None:
    if browser_type.name == "firefox":
        pytest.skip("covered by the Firefox cases")
    monkeypatch.setattr(browser_readiness, "_wait_for_startup_cache", lambda *a, **k: pytest.fail("no stage here"))
    launched = launch_settled(browser_type)
    try:
        assert launched.new_context().new_page().evaluate("() => 2") == 2
    finally:
        launched.close()
