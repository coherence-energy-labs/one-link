"""The owner window's status line, in a real browser against a real daemon.

Why this file exists. On 2026-11-25 a daemon restarted for an update while an
owner window was open. For the next several hours that window showed two
banners printed over each other -- "Restoring One Link…" and "This tab's access
key expired. Click Retry to validate it again without exposing it in the
address bar." -- and never came back by itself. Three separate defects:

  * the session banner was a second element, fixed 56px from the top, which is
    exactly where the status line sits in the layout;
  * session recovery was attempted at most twice per page, so once the daemon
    had been unreachable for two attempts the page stopped trying for good
    and its Retry button did nothing;
  * the page called the credential "expired" when all it knew was that the
    daemon had not answered.

The rules are unit-tested with a virtual clock in tests/js/test_window_link.cjs.
These tests check what only a browser can show: that a window left open across
a real daemon restart recovers with nobody touching it, and that whatever the
line says, it is one element that takes its place in the layout.
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from tests.daemon_readiness import wait_for_owner_http

_SIGNED_OUT = (
    "This window was signed out. Open One Link from its desktop shortcut or "
    "tray icon to continue. Your data is safe."
)

# The polls the page's polling cluster owns and suspends during recovery. The
# call backfill (/api/v1/calls) runs on its own timer in the separate calls
# closure and is not part of the cluster.
_CLUSTER_POLLS = frozenset({"/api/peers", "/api/transfers", "/api/status", "/api/groups"})


def _cluster_polls(urls: list[str]) -> list[str]:
    return [url for url in urls if urlsplit(url).path in _CLUSTER_POLLS]


_STATUS_JS = """() => {
  const line = document.querySelector('#offline-banner');
  const rect = (el) => {
    const r = el.getBoundingClientRect();
    return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, height: r.height };
  };
  const shown = getComputedStyle(line).display !== 'none';
  const box = rect(line);
  const middle = shown
    ? document.elementFromPoint((box.left + box.right) / 2, (box.top + box.bottom) / 2)
    : null;
  return {
    kind: line.dataset.status || '',
    shown,
    text: (line.innerText || '').replace(/\\s+/g, ' ').trim(),
    buttons: [...line.querySelectorAll('button')].map((b) => b.textContent.trim()),
    position: getComputedStyle(line).position,
    line: box,
    header: rect(document.querySelector('.top')),
    main: rect(document.querySelector('#main')),
    middleIsTheLine: !!middle && line.contains(middle),
    lines: document.querySelectorAll('#offline-banner').length,
    strays: document.querySelectorAll(
      '#session-expired-banner, .session-expired-banner:not(#offline-banner)'
    ).length,
    pageOverflowsSideways: document.documentElement.scrollWidth > window.innerWidth + 1,
    everything: (document.body.innerText || ''),
  };
}"""


def _status(page) -> dict:
    return page.evaluate(_STATUS_JS)


def _wait_for_status(page, kind: str, *, timeout_ms: int) -> dict:
    page.wait_for_function(
        "(kind) => (document.querySelector('#offline-banner').dataset.status || '') === kind",
        arg=kind,
        timeout=timeout_ms,
    )
    return _status(page)


def _assert_one_line_in_the_layout(status: dict) -> None:
    """The line is in the flow between the header and the main pane."""
    assert status["lines"] == 1
    assert status["strays"] == 0, "a second status element exists"
    assert status["shown"]
    assert status["position"] == "static", "the status line positions itself over the layout"
    assert status["line"]["height"] > 0
    assert status["line"]["top"] >= status["header"]["bottom"] - 0.5, "the line covers the header"
    assert status["line"]["bottom"] <= status["main"]["top"] + 0.5, "the line covers the main pane"
    assert status["middleIsTheLine"], "something is drawn on top of the status line"
    assert not status["pageOverflowsSideways"]


def _stop(proc: subprocess.Popen) -> None:
    with contextlib.suppress(Exception):
        proc.terminate()
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10.0)


def _restart_on_the_same_port(live_daemon, log_path: Path) -> subprocess.Popen:
    """Start the daemon again in the same home, on the port the window knows.

    This is what an update does to a real install: same data, same address,
    new process.
    """
    env = os.environ.copy()
    env["ONE_LINK_HOME"] = str(live_daemon.home)
    env["ONE_LINK_BIND_HOST"] = "127.0.0.1"
    env["ONE_LINK_DISABLE_NATIVE_PICKER"] = "1"
    env["ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION"] = "required"
    env["ONE_LINK_UI_PORT"] = str(live_daemon.port)
    log_fh = open(log_path, "ab", buffering=0)
    try:
        return subprocess.Popen(
            [sys.executable, "-m", "one_link.cli", "daemon"],
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(Path(__file__).resolve().parents[2]),
        )
    finally:
        log_fh.close()


def test_a_window_left_open_across_a_daemon_restart_recovers_with_nobody_touching_it(
    live_daemon, ui_page, tmp_path,
):
    page = ui_page
    assert page.evaluate("() => !!localStorage.getItem('ol_persistent_session_token')"), (
        "precondition: this window holds a session that survives a daemon restart; "
        "without one, signing the window out after a restart is the designed outcome"
    )
    assert _status(page)["kind"] == ""

    api_requests: list[str] = []
    page.on("request", lambda request: "/api/" in request.url and api_requests.append(request.url))

    # The daemon goes away, and one API answer on its way out says 401 --
    # the combination the old page could not get out of. The 401 is given to
    # one of the page's own background polls, so it is certain to reach the
    # page's session handling; the call backfill uses a separate request path.
    injected: list[str] = []
    injected_at: list[int] = []

    def one_unauthorized_answer(route):
        if not injected and urlsplit(route.request.url).path in _CLUSTER_POLLS:
            injected.append(route.request.url)
            injected_at.append(len(api_requests))
            route.fulfill(status=401, content_type="application/json", body='{"error": "unauthorized"}')
        else:
            route.continue_()

    page.context.route("**/api/**", one_unauthorized_answer)
    _stop(live_daemon.proc)

    restoring = _wait_for_status(page, "restoring", timeout_ms=30000)
    assert injected, "the page never received the 401 this test injects"
    page.context.unroute("**/api/**", one_unauthorized_answer)
    assert restoring["text"] == "Restoring One Link… Try now"
    assert restoring["buttons"] == ["Try now"]
    assert "expired" not in restoring["everything"].lower()
    assert "access key" not in restoring["everything"].lower()
    _assert_one_line_in_the_layout(restoring)

    # The page that shipped asked twice and then never again. This one must
    # keep asking by itself, so it has to reach a FOURTH probe with nothing
    # prompting it.
    #
    # The probes are counted from the injected 401, not over a fixed window.
    # They back off (1, 2, 4, 8 s, each +-25%), so how many fall inside any
    # particular nine seconds depends on where the page's poll timers stood
    # when the daemon died. The first version of this test counted such a
    # window ("at least three in nine seconds after the status appears") and
    # failed once on a hosted runner with two: an instrument that measured
    # the timers' phase. The fourth probe is due at most 8.75 s after the 401.
    def probes_since_the_401() -> list[str]:
        return [url for url in api_requests[injected_at[0]:] if url.endswith("/api/me")]

    deadline = time.monotonic() + 40.0
    while len(probes_since_the_401()) < 4 and time.monotonic() < deadline:
        page.wait_for_timeout(250)
    assert len(probes_since_the_401()) >= 4, (
        "recovery stopped probing while the daemon was away: "
        f"{api_requests[injected_at[0]:]}"
    )

    # And it asks only whether its credential works: the background polls it
    # suspended at the 401 stay suspended while the daemon is away.
    mark = len(api_requests)
    page.wait_for_timeout(5000)
    polls = _cluster_polls(api_requests[mark:])
    assert not polls, f"background polls kept firing during recovery: {polls}"
    assert _status(page)["kind"] == "restoring"
    assert page.evaluate("() => !!localStorage.getItem('ol_persistent_session_token')"), (
        "an unreachable daemon made the page throw its credential away"
    )

    # The daemon comes back, as it does after an update. Nobody clicks anything.
    second = _restart_on_the_same_port(live_daemon, tmp_path / "daemon-restarted.log")
    try:
        budget = float(os.environ.get("ONE_LINK_TEST_DAEMON_BOOT_S", "45"))
        port, _token, _elapsed = wait_for_owner_http(live_daemon.home, second, timeout=budget)
        assert port == live_daemon.port
        mark = len(api_requests)
        try:
            recovered = _wait_for_status(page, "", timeout_ms=60000)
        except Exception as exc:
            # Say what the window and the daemon each believe, so a failure
            # here can be read without re-running it.
            stuck = _status(page)
            log_tail = (tmp_path / "daemon-restarted.log").read_text(
                encoding="utf-8", errors="replace",
            )[-2500:]
            exc.add_note(
                f"window status: kind={stuck['kind']!r} text={stuck['text']!r}\n"
                f"requests since restart: {api_requests[mark:][-12:]}\n"
                f"--- restarted daemon log tail ---\n{log_tail}"
            )
            raise
        assert not recovered["shown"]
        assert recovered["strays"] == 0
        assert "expired" not in recovered["everything"].lower()
        # And the page is live again: the polls it suspended are running.
        with page.expect_response(
            lambda response: "/api/peers" in response.url and response.status == 200,
            timeout=30000,
        ):
            pass
        assert _cluster_polls(api_requests[mark:]), "the suspended polls did not resume"
    finally:
        _stop(second)


def test_signed_out_is_one_line_in_the_layout_with_an_instruction_and_no_button(ui_page):
    page = ui_page

    def refuse(route):
        route.fulfill(status=401, content_type="application/json", body='{"error": "unauthorized"}')

    # The daemon answers, and refuses this window's credential every time.
    page.context.route("**/api/**", refuse)
    signed_out = _wait_for_status(page, "signed_out", timeout_ms=45000)
    assert signed_out["text"] == _SIGNED_OUT
    assert signed_out["buttons"] == [], "a signed-out window offers a button that cannot work"
    _assert_one_line_in_the_layout(signed_out)
    assert page.evaluate(
        "() => [sessionStorage.getItem('ol_session_token'),"
        " localStorage.getItem('ol_persistent_session_token')]"
    ) == [None, None]

    # A second fact about the same window must not produce a second message.
    page.context.set_offline(True)
    try:
        page.wait_for_timeout(1500)
        still = _status(page)
        assert still["kind"] == "signed_out"
        assert still["text"] == _SIGNED_OUT
        _assert_one_line_in_the_layout(still)
    finally:
        page.context.set_offline(False)

    # Narrow window: the sentence wraps inside the line instead of spilling out.
    page.set_viewport_size({"width": 420, "height": 800})
    narrow = _status(page)
    assert narrow["text"] == _SIGNED_OUT
    assert narrow["line"]["right"] <= 420.5 and narrow["line"]["left"] >= -0.5
    assert narrow["position"] == "static" and narrow["strays"] == 0
    assert not narrow["pageOverflowsSideways"]


def test_going_offline_shows_the_calm_line_and_coming_back_hides_it(ui_page):
    page = ui_page
    assert not _status(page)["shown"]
    page.context.set_offline(True)
    try:
        offline = _wait_for_status(page, "offline", timeout_ms=10000)
        assert offline["text"] == "You're offline. Messages queue and send when you're back."
        assert offline["buttons"] == []
        _assert_one_line_in_the_layout(offline)
    finally:
        page.context.set_offline(False)
    back = _wait_for_status(page, "", timeout_ms=10000)
    assert not back["shown"]
