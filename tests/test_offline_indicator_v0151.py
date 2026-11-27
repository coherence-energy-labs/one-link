"""v0.15.1 — Offline indicator banner.

Ship-spec from `docs/ARCHITECTURE.md` v0.15.x:

  Reach:  users on flaky Wi-Fi (cafes, transit, shared
          cellular) get a calm visible "offline" indicator
          instead of wondering why their messages aren't going
          through. The Service Worker queues sends and drains
          on reconnect; the banner just narrates that fact.
  Hide:   no element-cuts. The banner is purely additive UI
          above main, hidden until navigator.onLine flips false.
  Async:  on `online` event, the banner hides + an
          acknowledgement toast fires + the SW outbox-drain is
          poked. On `offline`, the banner shows.
  Depth:  the banner reads navigator.onLine at boot — not just
          on event — so a page reloaded mid-offline shows the
          banner immediately instead of waiting for an event
          that already fired.

Tests pin the banner markup, the CSS rule, and the JS handler.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── markup ───────────────────────────────────────────────────

def test_offline_banner_present(index_html: str):
    """The banner element MUST exist in the markup so the JS toggle
    has something to flip. Carries `role="status"` + `aria-live`
    so screen readers announce state changes."""
    assert 'id="offline-banner"' in index_html
    idx = index_html.find('id="offline-banner"')
    open_start = index_html.rfind("<", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert 'role="status"' in tag
    assert 'aria-live="polite"' in tag


def test_offline_banner_lives_above_main(index_html: str):
    """The banner MUST appear in the source BEFORE `<main id="main">`
    so it sits visually above the chat surface (not buried inside
    one of the panes)."""
    banner_idx = index_html.find('id="offline-banner"')
    main_idx = index_html.find('id="main"')
    assert banner_idx > 0
    assert main_idx > 0
    assert banner_idx < main_idx


def test_offline_banner_text_calm(index_html: str):
    """Copy MUST read as informational, not error. Don't let a
    refactor switch to "Connection lost" or similar alarming
    language — flaky Wi-Fi isn't a system error."""
    idx = index_html.find('id="offline-banner"')
    end = index_html.find("</div>", idx)
    body = index_html[idx:end]
    assert "offline" in body.lower()
    assert "queue" in body.lower()


# ───────── CSS rules ────────────────────────────────────────────────

def test_offline_banner_hidden_by_default(index_html: str):
    """Default `.offline-banner { display: none; }` MUST be present
    so the banner doesn't flash on page load."""
    assert ".offline-banner {" in index_html
    idx = index_html.find(".offline-banner {")
    snippet = index_html[idx:idx + 600]
    assert "display: none;" in snippet


def test_offline_banner_show_class_reveals(index_html: str):
    """The `.show` class MUST flip display to flex for the dot +
    text alignment."""
    assert ".offline-banner.show { display: flex; }" in index_html


def test_offline_dot_animates(index_html: str):
    """The pulsing dot is the visual anchor — without it the banner
    looks static and easy to miss."""
    assert "@keyframes offline-pulse" in index_html
    assert "animation: offline-pulse" in index_html


# ───────── JS handler ───────────────────────────────────────────────

def test_apply_online_state_helper_present(index_html: str):
    """Single-source-of-truth helper for the toggle. Don't rename —
    every call site uses this name."""
    assert "function _applyOnlineState(online)" in index_html


def test_apply_online_state_reports_to_the_status_line_owner(index_html: str):
    """The offline fact goes to windowLink, which owns the status line.

    Until 2026-11-25 this helper toggled ``.show`` on the element itself,
    the event socket rewrote the same element's text, and the session
    handler created a second element on top of it. Three writers of one
    line is how "Restoring One Link…" and "access key expired" came to be
    printed over each other. What the line shows for each combination of
    facts is tested in tests/js/test_window_link.cjs; that offline really
    shows and hides it in a browser, in tests/e2e/test_window_status_line.py.
    """
    idx = index_html.find("function _applyOnlineState(online)")
    end = index_html.find("\n  }", idx)
    body = index_html[idx:end]
    assert "windowLink.setOffline(!online);" in body
    assert "classList" not in body and "querySelector" not in body


def test_exactly_one_function_touches_the_status_line_element(index_html: str):
    """One reader of ``#offline-banner`` in the whole page: the renderer
    windowLink calls. A second one is a second writer of the line."""
    assert index_html.count('querySelector("#offline-banner")') == 1
    assert index_html.count('getElementById("offline-banner")') == 0
    idx = index_html.find('querySelector("#offline-banner")')
    owner = index_html.rfind("\n  function ", 0, idx)
    assert index_html[owner:idx].lstrip().startswith("function _renderWindowStatus(kind)")
    assert index_html.count('id="offline-banner"') == 1


def test_initial_state_read_at_boot(index_html: str):
    """A page reloaded while already offline MUST show the banner
    immediately. We can't wait for an event that already fired."""
    # `_applyOnlineState(navigator.onLine !== false)` is the
    # boot-time call.
    assert "_applyOnlineState(navigator.onLine !== false)" in index_html


def test_offline_event_shows_banner(index_html: str):
    """The `offline` event MUST flip the banner on."""
    idx = index_html.find('window.addEventListener("offline"')
    assert idx > 0
    snippet = index_html[idx:idx + 400]
    assert "_applyOnlineState(false)" in snippet


def test_online_event_hides_banner_and_drains(index_html: str):
    """The `online` event MUST hide the banner AND poke the SW
    outbox drain — both behaviors are coupled."""
    idx = index_html.find('window.addEventListener("online"')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "_applyOnlineState(true)" in snippet
    assert "_outboxRequestSync()" in snippet


def test_online_event_acknowledgement_toast(index_html: str):
    """A brief "back online" toast MUST fire so the user knows
    queued messages are now draining. Short duration so flapping
    connectivity doesn't spam the toast stack."""
    idx = index_html.find('window.addEventListener("online"')
    snippet = index_html[idx:idx + 800]
    assert 'toast("Back online' in snippet
    # Pin the duration shorthand so it doesn't bloat to 30s on a
    # well-meaning refactor.
    assert ", 3000)" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
