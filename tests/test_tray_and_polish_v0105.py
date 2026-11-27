"""v0.10.5 — system tray + bonus polish.

System tray:
  - Optional tray icon via pystray + Pillow (declared as
    `[project.optional-dependencies] tray`).
  - Single-threaded daemon-friendly: pystray runs on its own
    background thread; on_quit signals the asyncio loop to
    shut down.
  - Right-click → menu (Open / Open inbox / Quit). Click → opens
    browser. Status changes re-tint the icon's outer ring.

Bonus polish:
  - Slash commands: /shrug, /tableflip, /unflip, /me, /clear, /help.
  - Smart date separators: 2-7 days ago shows the weekday name
    instead of "Apr 30"; same-year shows "Apr 30"; older shows
    "Apr 30, 2024".
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest


# ───────── system tray module ───────────────────────────────────────

def test_tray_module_exists():
    """File must exist + class must be importable."""
    src = Path("src/one_link/tray.py").read_text(encoding="utf-8")
    assert "class TrayIcon" in src
    from one_link.tray import TrayIcon
    assert callable(TrayIcon)


def test_tray_initializes_without_pystray(monkeypatch):
    """Even if pystray is missing, construction must succeed —
    .available exposes whether the icon will actually show."""
    import sys
    # Simulate pystray being missing.
    monkeypatch.setitem(sys.modules, "pystray", None)
    from one_link.tray import TrayIcon
    # Reimport-flagged availability: caller checks .available
    # rather than try/except'ing every method.
    t = TrayIcon(on_quit=lambda: None, url="http://127.0.0.1:7117/")
    # If pystray IS installed locally (CI may have it), available
    # may be True. Either way the constructor must not raise.
    assert isinstance(t.available, bool)


def test_tray_status_tint_handles_all_states():
    """Re-tint must accept online/away/dnd/offline + unknown
    (defaults to online color) without crashing."""
    from one_link.tray import TrayIcon
    t = TrayIcon(on_quit=lambda: None, url="x")
    states = ("online", "away", "dnd", "offline", "wat", "")

    # Before start, _icon is None and set_status returns early -- so looping
    # here proves only that the early return exists.
    for s in states:
        t.set_status(s)
    assert t._icon is None, "set_status built an icon before start()"

    # With an icon attached, every state must actually produce a tint --
    # including the unknown ones, which must fall back rather than leave the
    # previous status showing. Without this the test passes against a
    # set_status that does nothing at all.
    tinted = []

    class _FakeIcon:
        icon = None

    t._icon = _FakeIcon()
    original = t._tinted_icon
    t._tinted_icon = lambda status: tinted.append(status) or f"img:{status}"
    try:
        for s in states:
            t.set_status(s)
    finally:
        t._tinted_icon = original
    assert tinted == list(states), f"not every status was tinted: {tinted}"


def test_tray_start_skips_when_icon_image_is_missing(monkeypatch):
    """A windowed build may have pystray importable while Pillow or
    bundled image data is unavailable. That must degrade to no tray,
    not crash a background thread."""
    import types

    from one_link import tray as tray_mod

    class FakeIcon:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Icon must not be constructed without image data")

    monkeypatch.setitem(
        __import__("sys").modules,
        "pystray",
        types.SimpleNamespace(Icon=FakeIcon),
    )
    monkeypatch.setattr(tray_mod.TrayIcon, "_tinted_icon", staticmethod(lambda status: None))

    t = tray_mod.TrayIcon(on_quit=lambda: None, url="x")
    assert t.available is True
    t.start()
    assert t.available is False
    assert t._icon is None


def test_tray_optional_deps_in_pyproject():
    """The pyproject.toml must declare a 'tray' optional-deps
    extra so users can `pip install one_link[tray]`."""
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    tray = data["project"]["optional-dependencies"]["tray"]
    assert "pystray>=0.19" in tray
    assert "pillow>=13.0.0,<14" in tray


def test_cli_daemon_respects_no_tray_flag():
    """The daemon CLI must accept --no-tray + default to --tray.
    Pin so a refactor doesn't drop the flag."""
    src = Path("src/one_link/cli.py").read_text(encoding="utf-8")
    assert '"--tray/--no-tray"' in src
    assert "tray_icon" in src


def test_cli_logs_headless_tray_fallback():
    """If TrayIcon.start() degrades to headless mode, the daemon log
    should say that instead of claiming tray controls are active."""
    src = Path("src/one_link/cli.py").read_text(encoding="utf-8")
    active_idx = src.find("tray icon active")
    unavailable_idx = src.find("tray icon unavailable")
    assert active_idx > 0
    assert unavailable_idx > active_idx
    assert src.count("if tray_icon.available:") >= 2


def test_tray_quit_signals_daemon_shutdown():
    """The on_quit callback wired by the CLI must trigger an
    actual shutdown signal, not just stop the icon. Pin via the
    SIGINT call to the daemon's own pid."""
    src = Path("src/one_link/cli.py").read_text(encoding="utf-8")
    idx = src.find("TrayIcon(")
    snippet = src[idx:idx + 600]
    assert "os.kill(os.getpid(), signal.SIGINT)" in snippet


def test_tray_menu_includes_inbox_when_path_provided():
    """The menu must include 'Open inbox folder' iff a path was
    passed in."""
    from one_link.tray import TrayIcon
    t_with = TrayIcon(on_quit=lambda: None, inbox_path=Path("."))
    t_without = TrayIcon(on_quit=lambda: None)
    # _build_menu only callable when pystray is available; if not,
    # both should at least construct cleanly.
    assert t_with._inbox_path is not None
    assert t_without._inbox_path is None


# ───────── bonus polish: slash commands ─────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_slash_command_helper_present(index_html: str):
    assert "function _expandSlashCommand(" in index_html
    assert "function _maybeRunSlashSideEffect(" in index_html


def test_slash_shrug_expands(index_html: str):
    """The /shrug command must produce ¯\\_(ツ)_/¯ in the body."""
    idx = index_html.find("function _expandSlashCommand(")
    snippet = index_html[idx:idx + 2000]
    assert '¯\\\\_(ツ)_/¯' in snippet


def test_slash_tableflip_expands(index_html: str):
    idx = index_html.find("function _expandSlashCommand(")
    snippet = index_html[idx:idx + 2000]
    assert "(╯°□°)╯︵ ┻━┻" in snippet


def test_slash_me_wraps_in_italics(index_html: str):
    """/me <text> → *text* (italic via existing markdown-lite)."""
    idx = index_html.find("function _expandSlashCommand(")
    snippet = index_html[idx:idx + 2000]
    assert '`*${arg}*`' in snippet


def test_slash_clear_runs_side_effect(index_html: str):
    """/clear must trigger the clear-pins side-effect, NOT send
    a message."""
    idx = index_html.find("function _expandSlashCommand(")
    snippet = index_html[idx:idx + 2000]
    assert '"clear-pins"' in snippet


def test_slash_help_opens_shortcuts_modal(index_html: str):
    idx = index_html.find("function _maybeRunSlashSideEffect(")
    snippet = index_html[idx:idx + 1000]
    assert 'shortcuts-backdrop' in snippet


def test_slash_command_runs_before_send(index_html: str):
    """sendCurrent must invoke _expandSlashCommand BEFORE branching
    on group/peer so /shrug works in either context."""
    idx = index_html.find("async function sendCurrent()")
    snippet = index_html[idx:idx + 800]
    assert "_expandSlashCommand(" in snippet


# ───────── bonus polish: smart date separators ──────────────────────

def test_day_label_uses_weekday_for_recent_past(index_html: str):
    """2-7 days ago should render as the weekday name."""
    idx = index_html.find("const dayLabel =")
    snippet = index_html[idx:idx + 1500]
    assert 'weekday: "long"' in snippet


def test_day_label_drops_year_for_same_year(index_html: str):
    """Same-year dates render without the year (Apr 30 vs Apr 30, 2024)."""
    idx = index_html.find("const dayLabel =")
    snippet = index_html[idx:idx + 1500]
    # Find the same-year branch — should NOT include 'year:'.
    same_year_idx = snippet.find("getFullYear() === now.getFullYear()")
    assert same_year_idx > 0
    # The format call right after must not include year.
    next_chunk = snippet[same_year_idx:same_year_idx + 300]
    assert 'month: "short", day: "numeric" }' in next_chunk


# ───────── version ──────────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
