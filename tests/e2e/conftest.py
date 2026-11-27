"""Shared fixtures for the browser E2E suite.

The `live_daemon` fixture spawns a real one-link daemon in a temp
ONE_LINK_HOME, waits for it to write `ui.token` + `server.port`,
and yields an object with the base URL + auth token a Playwright
test can navigate to.

The `page` fixture (provided by pytest-playwright) gives each test
its own browser context + page; we add a small wrapper that
auto-navigates to the live daemon with the bearer token in the
query string.
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from tests.daemon_readiness import wait_for_owner_http


# v0.21.x: gate the browser E2E suite behind an explicit opt-in.
#
# These Playwright (chromium) tests require a real browser + a built
# UI and drive a live daemon. Playwright's sync driver runs its own
# event loop; running it in the SAME pytest process as the ~7000
# unit/integration tests leaves a loop active that pytest-asyncio's
# per-test runner then trips over ("Runner.run() cannot be called
# from a running event loop"), cascading into 500+ spurious setup
# errors on every async test that runs afterward. This is a well-
# known upstream pytest-playwright / pytest-asyncio coexistence
# limitation, not a defect in either our product or these tests.
#
# The correct architecture (used by virtually every project with a
# browser E2E layer) is to run the browser suite in its OWN session:
#
#     ONE_LINK_RUN_BROWSER_E2E=1 pytest tests/e2e/
#
# A bare ``pytest tests/`` (the unit/integration gate) skips them, so
# the unit run stays green AND fully isolated from the Playwright
# loop. The daemon_pair integration tests (tests/test_*_e2e.py) are
# NOT browser tests and continue to run in the normal suite.
_BROWSER_E2E_ENV = "ONE_LINK_RUN_BROWSER_E2E"


def pytest_collection_modifyitems(config, items):
    """Skip every test under tests/e2e/ unless the opt-in env flag is
    set. Skipping at collection time means the Playwright ``page``
    fixture never starts its event loop, so nothing leaks into the
    rest of the session."""
    if os.environ.get(_BROWSER_E2E_ENV) == "1":
        return
    skip_browser = pytest.mark.skip(
        reason=(
            "browser E2E gated; run with "
            f"{_BROWSER_E2E_ENV}=1 pytest tests/e2e/ "
            "(Playwright loop is isolated from the unit suite)"
        ),
    )
    here = Path(__file__).resolve().parent
    for item in items:
        try:
            item_path = Path(str(item.fspath)).resolve()
        except Exception:
            continue
        if here in item_path.parents or item_path.parent == here:
            item.add_marker(skip_browser)


@dataclass
class LiveDaemon:
    home: Path
    port: int
    token: str
    proc: subprocess.Popen
    log: Path

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def auth_url(self) -> str:
        """Top-level URL with bootstrap token. The daemon sets the
        ol_ui cookie on this load so subsequent requests succeed."""
        return f"{self.base_url}/?t={self.token}"


@pytest.fixture
def live_daemon(tmp_path: Path) -> Iterator[LiveDaemon]:
    """Spawn a real daemon for E2E. Each test gets its own clean
    ONE_LINK_HOME so tests can't bleed state into each other. The
    daemon binds a free port automatically; we read it back from
    `data/server.port` once the HTTP server is up."""
    home = tmp_path / "daemon_home"
    home.mkdir()
    log_path = tmp_path / "daemon.log"

    env = os.environ.copy()
    env["ONE_LINK_HOME"] = str(home)
    # Loopback-only so we don't spam the LAN with mDNS during tests.
    env["ONE_LINK_BIND_HOST"] = "127.0.0.1"
    # Disable any prompt that might open a folder picker etc.
    env["ONE_LINK_DISABLE_NATIVE_PICKER"] = "1"
    # Exercise the strict browser-owner gate in every live Chromium daemon.
    # peer.html must prove its enrolled Ed25519 key on the current DataChannel
    # before any owner request is accepted; this is identity possession, not a
    # claim of browser hardware/platform attestation.
    env["ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION"] = "required"
    # An OS-assigned UI port, read back from data/server.port once the daemon
    # is up. Left to itself the daemon auto-discovers from the product's
    # well-known 7117, so a test daemon could occupy a port a real daemon on
    # this machine expects (observed 2026-11-25). Set explicitly here as well
    # as in tests/conftest.py, so this fixture is safe however it is invoked.
    env["ONE_LINK_UI_PORT"] = "0"

    log_fh = open(log_path, "ab", buffering=0)
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parents[2]),
    )

    try:
        # Use the same configured boot budget as tests/harness.py, but one
        # monotonic deadline covers BOTH files and authenticated HTTP. The
        # old 30s + 10s + 30s stages could reject a healthy, loaded first boot
        # at the first boundary while allowing 70s in total. Never retry the
        # test itself or treat the fixture budget as a performance result.
        startup_budget = float(os.environ.get("ONE_LINK_TEST_DAEMON_BOOT_S", "45"))
        try:
            port, token, _elapsed = wait_for_owner_http(home, proc, timeout=startup_budget)
        except RuntimeError as exc:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(f"{exc}\n--- log ---\n{log_text}") from exc
        yield LiveDaemon(
            home=home, port=port, token=token, proc=proc, log=log_path,
        )
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        with contextlib.suppress(Exception):
            log_fh.close()


@pytest.fixture
def ui_page(live_daemon, page):
    """A Playwright `page` already navigated to the live daemon's
    UI with the bootstrap token applied + the first-launch
    onboarding modal pre-dismissed via seeded localStorage.

    Race-free dismissal pattern: register an init script BEFORE
    the first navigation so the page boots with the
    `onboarding_completed` localStorage flag already set. That
    short-circuits maybeShowOnboarding() at the top, the backdrop
    never opens, and no click in any subsequent test can be
    intercepted by it. The post-goto skip-button click was racy:
    if networkidle fired before the wizard reached the DOM, the
    `count()` check returned 0 and the wizard popped up a beat
    later, blocking every click in the actual test body.
    """
    # The "what's new" modal pops on every version it hasn't seen
    # yet; we'd seed it with the daemon's app_version but we don't
    # know it until after navigation, so seed a sentinel that the
    # daemon's version will never match - we don't WANT the modal
    # to appear in tests, and we CSS-hide its backdrop below as a
    # second line of defense.
    page.add_init_script("""
        try {
            localStorage.setItem('one_link.onboarding_completed', '1');
            // Seed both possible last-seen-version keys so the
            // What's New modal doesn't pop. The script later in
            // boot will compare daemon version to localStorage;
            // a non-empty value short-circuits the first-launch
            // seed branch and the subsequent !== comparison just
            // updates the value silently.
            if (!localStorage.getItem('one_link.last_seen_version')) {
                localStorage.setItem('one_link.last_seen_version', 'e2e-suppress');
            }
        } catch (_e) {}
    """)
    page.goto(live_daemon.auth_url, wait_until="networkidle")
    page.wait_for_selector("body", timeout=15000)
    # Belt-and-suspenders: if a different boot path managed to open
    # either modal anyway, neutralize their pointer interception
    # via CSS. visual_regression also hides them via add_style_tag
    # so screenshots still capture the underlying surface.
    page.add_style_tag(content="""
        #onboarding-backdrop, #whatsnew-modal, .wnm-modal,
        .wnm-backdrop {
            display: none !important;
            pointer-events: none !important;
        }
    """)
    # If the What's New modal landed before our CSS injected (race
    # with the boot path), tear it out of the DOM entirely so even
    # event delegation can't fire on it.
    page.evaluate("""() => {
        document.getElementById('whatsnew-modal')?.remove();
        document.body.classList.remove('wnm-open');
    }""")
    # Same for the one-setup modal (a second first-launch wizard)
    # if anything dispatches it after our init script ran.
    if page.locator("#one-setup-skip, #btn-one-setup-skip").count():
        try:
            page.locator("#one-setup-skip, #btn-one-setup-skip").first.click(timeout=1500)
        except Exception:
            pass
    return page


# Session browsers (by id) whose startup cache has been checked.
_STARTUP_CACHE_SETTLED: set[int] = set()


@pytest.fixture(scope="session", autouse=True)
def firefox_startup_cache_disabled_by_default():
    """Every Firefox this session launches gets a startup cache that cannot be written (RUN-01).

    A Firefox writes its startup cache about 2-10 s and again about 120 s
    after launch. While a write runs, its parent stops servicing navigation,
    createOffer() and Playwright's own commands, for as long as the write
    takes: up to minutes on a loaded host. Relocating the cache into a
    directory that does not exist makes those writes fail at once (see
    tests/e2e/browser_readiness.py).

    This is set in the test process environment before Playwright starts its
    driver, so a Firefox launched without an explicit ``env`` inherits it:
    the session ``browser`` and any ``browser_type.launch()`` in a test. Only
    Mozilla programs read the variable; other browsers ignore it.
    """
    from tests.e2e.browser_readiness import STARTUP_CACHE_ENV, startup_cache_disabled_env

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(STARTUP_CACHE_ENV, startup_cache_disabled_env({})[STARTUP_CACHE_ENV])
        yield


@pytest.fixture(autouse=True)
def firefox_past_startup_cache_write(request):
    """Check, before its first test, that the session's Firefox cannot write its startup cache.

    It checks every Firefox running under this test process, so it is also
    the proof that the session default above took effect. A test that
    launches its own browsers should use ``browser_readiness.launch_settled``
    (or ``launch_settled_many``), which checks the new processes too and keeps
    the relocation when the test passes its own ``env``. This is a no-op for
    tests without ``browser`` and for other browsers. A Firefox whose cache is
    still writable fails the test with BrowserNotReady naming the stage, never
    a pass or a skip.
    """
    if "browser" not in request.fixturenames:
        return
    browser = request.getfixturevalue("browser")
    if id(browser) in _STARTUP_CACHE_SETTLED:
        return
    from tests.e2e.browser_readiness import wait_for_startup_cache_write

    wait_for_startup_cache_write(browser)
    _STARTUP_CACHE_SETTLED.add(id(browser))


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Shared browser context tweaks. Loopback HTTP is not 'secure'
    by HTTPS standards but is treated as a secure context by
    Chromium since the daemon is on 127.0.0.1. Set viewport big
    enough that the conversation header + sidebar fit without the
    responsive-mode collapse logic firing."""
    return {
        **browser_context_args,
        "viewport": {"width": 1400, "height": 900},
        # Don't follow OS dark/light mode; pin to a known scheme so
        # screenshot diffs are stable.
        "color_scheme": "dark",
        "ignore_https_errors": True,
        # The app ships a strict script-src CSP (no unsafe-eval), and the
        # wait_for_function/evaluate polls these tests rely on execute in
        # the MAIN world -- whether the injection beats the CSP arriving
        # with the document is a Chromium race that flaked release run #5
        # after passing identically in run #4. Playwright's documented
        # answer for strict-CSP apps is bypass_csp; CSP CONTENT is pinned
        # by the JavaScript static-contract gates, not by e2e.
        "bypass_csp": True,
    }
