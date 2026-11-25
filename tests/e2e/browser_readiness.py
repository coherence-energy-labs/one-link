"""Browser readiness gate for live WebRTC pairing tests (audit finding RUN-01).

Why this exists
---------------
A freshly launched Playwright Firefox writes its startup cache
(``<profile>/startupCache/startupCache.<word>.<endian>``) once per session,
on a background thread, about 7-35 s after launch. On a loaded Windows host
that write was measured to take from seconds to more than 12 minutes. While it
is in progress, the parent process stops servicing content -> parent IPC.
That means createOffer()'s permission round trip, same-origin fetches,
WebSocket delivery, and Playwright's own commands all wait. Two measurements
show this. Holding that one file's write open by fault injection froze parent
IPC for exactly the hold (3 of 3 runs). In a natural run, a 14.5 s createOffer
hold ended 6 ms after the cache file's final write. The required-identity scenario starts
its 90 s pairing clock inside that window. When the hold lasted longer than
the clock, pairing failed in exactly the RUN-01 shape: the page showed
"negotiating" and no offer reached the daemon. Hosted CI never hit it, because
its Firefox step runs another WebRTC test first, and that test sits in the
window instead.

What the gate proves, in order, before the caller starts any pairing clock
-------------------------------------------------------------------------
1. Firefox only: the session's single startup-cache write has finished.
   Content cannot see that write, and a write that starts after an in-page
   check passes can still freeze the parent mid-pairing. So the gate observes
   it directly. The file must exist, be non-empty, and be open for writing by
   nobody. On Windows, a deny-write open must not hit a sharing violation. On
   Linux, the browser parent must hold no descriptor on it with write access.
   Where neither can be asked, the size must be stable for 2 s.
2. Every browser: the parent process answers now. A fresh RTCPeerConnection's
   createOffer() (which waits on the parent) and a same-origin fetch must both
   settle within ``probe_bound_ms``, for ``stable_probes`` consecutive probes.

A gate failure raises BrowserNotReady, which is never a pass, a skip or a
pairing verdict. It names the stage that was not ready and what was measured.
Once the gate passes, the caller's unchanged pairing assertions and their
90 s budget apply. The gate does not touch the daemon, the pairing code, or
any of their timeouts.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import psutil
from playwright.sync_api import Browser, Page, TimeoutError as PlaywrightTimeoutError


class BrowserNotReady(AssertionError):
    """The browser could not prove readiness. This is not a pairing result."""


def _firefox_parents() -> dict[Path, psutil.Process]:
    """Parent process of each Firefox launched under this test process, by profile."""
    parents: dict[Path, psutil.Process] = {}
    for child in psutil.Process().children(recursive=True):
        try:
            if "firefox" not in child.name().lower():
                continue
            argv = child.cmdline()
        except psutil.Error:
            continue
        if "-contentproc" in argv or "-profile" not in argv:
            continue
        index = argv.index("-profile")
        if index + 1 < len(argv):
            parents[Path(argv[index + 1].strip('"'))] = child
    return parents


def _firefox_profile_dirs() -> set[Path]:
    """Profiles of the Firefox instances launched under this test process."""
    return set(_firefox_parents())


def _held_for_write_by(path: Path, holders: list[psutil.Process]) -> bool | None:
    """Linux: True if one of ``holders`` has ``path`` open for writing.

    Read from /proc/<pid>/fd, where an open descriptor carries its access
    mode. None means the question could not be answered (no holder to ask, or
    one whose descriptors are unreadable), so the caller must not treat it as
    "nobody is writing".
    """
    if not holders:
        return None
    target = os.path.realpath(path)
    for holder in holders:
        try:
            files = holder.open_files()
        except psutil.Error:
            return None
        for entry in files:
            mode = getattr(entry, "mode", None)
            if mode is None:
                return None
            if mode != "r" and os.path.realpath(entry.path) == target:
                return True
    return False


def _open_for_write_elsewhere(path: Path) -> bool | None:
    """True if the browser still holds ``path`` open for writing; None if unknowable.

    Windows asks the kernel with a deny-write open. Linux reads the access mode
    of the browser parent's own descriptors. Elsewhere there is no direct
    answer and the caller falls back to a stable size.
    """
    if sys.platform.startswith("linux"):
        profile = path.parent.parent
        return _held_for_write_by(path, [p for d, p in _firefox_parents().items() if d == profile])
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    generic_read, file_share_read, open_existing, attribute_normal = 0x80000000, 0x1, 3, 0x80
    # Deny-write sharing: this fails with a sharing violation exactly when an
    # existing handle has write access. Read-only, closed immediately.
    handle = create(str(path), generic_read, file_share_read, None, open_existing, attribute_normal, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        # A sharing violation means a writer still holds the file. Any other
        # failure proves nothing, so it is treated as "not finished" as well.
        return True
    kernel32.CloseHandle(handle)
    return False


def _wait_for_startup_cache(deadline: float, report: dict[str, Any]) -> None:
    started = time.monotonic()
    profiles = _firefox_profile_dirs()
    if len(profiles) != 1:
        raise BrowserNotReady(
            f"browser not ready: expected one Firefox profile under this test process, found {sorted(map(str, profiles))}"
        )
    cache_dir = next(iter(profiles)) / "startupCache"
    report["startup_cache_dir"] = str(cache_dir)
    last_size: int | None = None
    stable_since = started
    while True:
        candidates = sorted(p for p in cache_dir.glob("startupCache.*") if p.is_file())
        size = candidates[0].stat().st_size if candidates else None
        now = time.monotonic()
        if size != last_size:
            last_size, stable_since = size, now
        if candidates and size:
            held = _open_for_write_elsewhere(candidates[0])
            if held is False or (held is None and now - stable_since >= 2.0):
                report["startup_cache"] = {
                    "file": candidates[0].name, "bytes": size,
                    "waited_s": round(now - started, 1),
                }
                return
        if now >= deadline:
            raise BrowserNotReady(
                f"browser not ready: Firefox's startup-cache write had not finished after "
                f"{now - started:.0f}s (file={candidates[0].name if candidates else None}, bytes={size}). "
                "Its parent process cannot be trusted to answer during pairing; this is a "
                "browser/host condition, not a pairing failure."
            )
        time.sleep(0.25)


# Polled by Playwright's wait_for_function. The first call starts the probe
# loop and every call returns the finished state, or false while it runs.
# Delivery goes through Playwright, so a parent stall cannot hang the gate: the
# wait_for_function timeout is enforced by the Playwright driver itself. (A
# bare page.evaluate has no timeout and would wait out the whole stall.)
_PARENT_PROBES = """(cfg) => {
  let state = window.__olBrowserReadiness;
  if (!state) {
    state = {done: false, ok: false, consecutive: 0, probes: [], waited_ms: 0};
    window.__olBrowserReadiness = state;
    const within = (promise, ms) => new Promise((resolve) => {
      const timer = setTimeout(() => resolve('timeout'), ms);
      Promise.resolve(promise).then(
        () => { clearTimeout(timer); resolve('ok'); },
        (error) => { clearTimeout(timer); resolve('error: ' + String((error && error.message) || error)); },
      );
    });
    (async () => {
      const t0 = performance.now();
      while (performance.now() - t0 < cfg.overallMs) {
        const p0 = performance.now();
        let pc = null;
        let offer;
        try {
          pc = new RTCPeerConnection({iceServers: []});
          pc.createDataChannel('readiness');
          offer = await within(pc.createOffer(), cfg.boundMs);
        } catch (error) {
          offer = 'error: ' + String((error && error.message) || error);
        } finally {
          try { if (pc) pc.close(); } catch (_) {}
        }
        const offerMs = performance.now() - p0;
        const f0 = performance.now();
        const fetched = await within(
          fetch(cfg.path, {cache: 'no-store', credentials: 'same-origin'}).then(
            (r) => (r.ok ? r.text() : Promise.reject(new Error('HTTP ' + r.status))),
          ),
          cfg.boundMs,
        );
        const good = offer === 'ok' && fetched === 'ok';
        state.probes.push({
          at_ms: Math.round(p0 - t0), offer, offer_ms: Math.round(offerMs),
          fetch: fetched, fetch_ms: Math.round(performance.now() - f0),
        });
        if (state.probes.length > 48) state.probes.splice(0, state.probes.length - 48);
        state.consecutive = good ? state.consecutive + 1 : 0;
        if (state.consecutive >= cfg.stable) { state.ok = true; break; }
        await new Promise((resolve) => setTimeout(resolve, cfg.pauseMs));
      }
      state.waited_ms = Math.round(performance.now() - t0);
      state.done = true;
    })();
  }
  return state.done ? state : false;
}"""

# The release workflow runs this test under pytest-timeout --timeout=600. The
# gate's default budget leaves room for the rest of the test, so a browser that
# is not ready fails with BrowserNotReady rather than an anonymous timeout.
DEFAULT_TIMEOUT_S = 420.0


def wait_for_startup_cache_write(browser: Browser, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    """Stage 1 alone: block until a Firefox session's one-time startup-cache write is done.

    Needs no page, so the e2e conftest runs it once per browser session before
    the first browser test. Every WebRTC test of the session then starts after
    the window in which the parent process can stall, whichever test runs
    first. A no-op that reports ``skipped`` for other browsers.
    """
    report: dict[str, Any] = {"browser": browser.browser_type.name}
    if browser.browser_type.name != "firefox":
        report["skipped"] = "only Firefox writes this cache on a background thread"
        return report
    _wait_for_startup_cache(time.monotonic() + timeout_s, report)
    return report


def wait_for_browser_ready(
    page: Page,
    browser: Browser,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    probe_bound_ms: int = 2_000,
    stable_probes: int = 3,
    probe_path: str = "/api/v1/peer-rtc/ice-config",
    require_startup_cache: bool | None = None,
) -> dict[str, Any]:
    """Block until ``browser`` is past its startup-cache write and its parent answers.

    ``page`` must already be on the daemon origin that the pairing will use.
    Returns what was measured. Raises BrowserNotReady, never a pairing
    verdict, when readiness is not proven within ``timeout_s``.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    report: dict[str, Any] = {"browser": browser.browser_type.name, "gate_version": 2}
    if require_startup_cache is None:
        require_startup_cache = browser.browser_type.name == "firefox"
    if require_startup_cache:
        _wait_for_startup_cache(deadline, report)
    remaining_ms = max(1_000, int((deadline - time.monotonic()) * 1000))
    cfg = {"boundMs": probe_bound_ms, "stable": stable_probes, "overallMs": remaining_ms,
           "pauseMs": 250, "path": probe_path}
    try:
        handle = page.wait_for_function(_PARENT_PROBES, arg=cfg, polling=250, timeout=remaining_ms + 5_000)
        state = handle.json_value()
    except PlaywrightTimeoutError as exc:
        raise BrowserNotReady(
            f"browser not ready: the parent process did not complete readiness probes within "
            f"{time.monotonic() - started:.0f}s (Playwright could not even read the result); "
            "this is a browser/host condition, not a pairing failure"
        ) from exc
    report["parent_probes"] = state["probes"]
    report["parent_waited_s"] = round(state["waited_ms"] / 1000, 1)
    report["waited_s"] = round(time.monotonic() - started, 1)
    if not state["ok"]:
        raise BrowserNotReady(
            f"browser not ready: the parent process did not answer {stable_probes} consecutive "
            f"createOffer()+fetch probes within {probe_bound_ms} ms each in {report['waited_s']}s; "
            f"last probes={state['probes'][-3:]}; this is a browser/host condition, not a pairing failure"
        )
    return report
