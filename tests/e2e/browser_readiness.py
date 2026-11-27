"""Browser readiness for live WebRTC tests (audit finding RUN-01).

Why this exists
---------------
Every Firefox that Playwright launches gets a fresh profile, and that Firefox
process writes its startup cache
(``<profile>/startupCache/startupCache.<word>.<endian>``) twice during its
life. These are Windows measurements under competing load:

* The first write begins 2-10 s after launch, without waiting for any
  navigation. The second begins about 120 s after launch (3 of 3 runs, at
  120.1-120.6 s). Each write took from 3 s to about 3 minutes.
* The writing thread runs in background mode (very low I/O priority). That
  competing disk load is what stretches the write is inferred from this, not
  measured.
* While a write is in progress, the parent process stops servicing content
  and Playwright as soon as its main thread touches that cache: a navigation,
  a new context or page, or the first WebRTC use. It stays stopped until the
  write ends. Over the write, an in-page fetch in another context of the same
  browser and Playwright's own new_context()/new_page() were held
  (7-175 s), and the parent's main thread used no CPU. The daemon's HTTPS
  listener meanwhile answered a direct TLS + GET in under 2 s.
* A page.goto() with a 30 s clock started inside a first write failed in
  every run where that write lasted longer than about 30 s.

Because the second write comes about two minutes in, waiting for "the" write
once per session cannot work. This module removes the cause instead. Firefox
reads the cache location from the ``MOZ_STARTUP_CACHE`` environment variable.
Pointing it at a file in a directory that does not exist makes every cache
write fail immediately. With that setting, under the same load (4 of 4 runs):
no cache file was written and the directory was never created. In both former
write windows a new context and page took under 0.6 s, a navigation under
0.5 s and createOffer() under 30 ms, with no parent hold over 1.5 s. Without
it, interleaved, the same steps were held for 7-152 s. Firefox runs normally
without a persistent startup cache.

What the gate proves
--------------------
1. Firefox only, per process: the startup cache of every Firefox running
   under this test process is disabled. Its environment carries the
   relocation, the target directory does not exist, and its profile holds no
   cache file. A Firefox launched any other way fails this stage, because it
   is exposed to both write windows.
   * The e2e conftest sets the relocation in the test process environment
     before Playwright starts, so every Firefox launched without its own
     ``env`` inherits it. It checks the session ``browser`` before its first
     test.
   * ``launch_settled`` and ``launch_settled_many`` relocate and check the
     browsers a test launches itself, including with a caller's ``env``.
2. Every browser, immediately before a pairing clock: the parent answers now
   (``wait_for_browser_ready``). A fresh RTCPeerConnection's createOffer()
   (which waits on the parent) and a same-origin fetch must both settle within
   ``probe_bound_ms``, for ``stable_probes`` consecutive probes.

A gate failure raises BrowserNotReady, which is never a pass, a skip or a
product verdict. It names the stage and what was measured. Once the gate
passes, the caller's unchanged assertions and budgets apply. Nothing here
touches the daemon, the product code, or any of their timeouts.
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import psutil
from playwright.sync_api import Browser, BrowserType, Page, TimeoutError as PlaywrightTimeoutError

STARTUP_CACHE_ENV = "MOZ_STARTUP_CACHE"


class BrowserNotReady(AssertionError):
    """The browser could not prove readiness. This is not a product result."""


def startup_cache_disabled_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """A Firefox launch environment whose startup cache can never be written.

    The cache file is placed in a fresh, never-created directory, so each
    write Firefox attempts fails at once instead of holding its parent.
    """
    env = dict(os.environ if base is None else base)
    absent = Path(tempfile.gettempdir()) / f"one-link-e2e-no-startup-cache-{uuid.uuid4().hex}"
    env[STARTUP_CACHE_ENV] = str(absent / "startupCache.disabled")
    return env


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


def _process_environ(process: psutil.Process) -> Mapping[str, str] | None:
    try:
        return process.environ()
    except psutil.Error:
        return None


def _startup_cache_problem(profile: Path, environ: Mapping[str, str] | None) -> str | None:
    """Why this Firefox's startup cache is not disabled, or None when it is."""
    if environ is None:
        return "its environment could not be read, so the relocation cannot be confirmed"
    target = environ.get(STARTUP_CACHE_ENV)
    if not target:
        return f"it was launched without {STARTUP_CACHE_ENV}, so it will write its startup cache twice"
    if Path(target).parent.exists():
        return f"{STARTUP_CACHE_ENV} points into a directory that exists, so the cache can still be written"
    written = sorted(p.name for p in (profile / "startupCache").glob("startupCache.*"))
    if written:
        return f"its profile holds {written}, so the relocation did not take effect"
    return None


def _wait_for_startup_cache(
    deadline: float, report: dict[str, Any], profiles: set[Path] | None = None,
) -> None:
    """Stage 1: every Firefox in ``profiles`` (default: all running) has its startup cache disabled.

    The relocation is decided at launch, so there is nothing to wait for. The
    deadline only bounds the wait for the process to show up and expose its
    environment. A Firefox exposed to the startup-cache writes fails at once.
    """
    started = time.monotonic()
    while True:
        parents = _firefox_parents()
        selected = parents if profiles is None else {p: parents[p] for p in profiles if p in parents}
        missing = set() if profiles is None else set(profiles) - set(selected)
        if not selected and profiles is None:
            problems = {"(none)": "expected at least one Firefox process under this test process, found none"}
        else:
            problems = {p.name: why for p, proc in selected.items()
                        if (why := _startup_cache_problem(p, _process_environ(proc))) is not None}
            problems.update({p.name: "its process is not running under this test process" for p in missing})
        if not problems:
            report["startup_cache"] = {p.name: "disabled" for p in selected}
            report["startup_cache_checked_s"] = round(time.monotonic() - started, 1)
            return
        unreadable = all("could not be read" in why or "not running" in why for why in problems.values())
        if not unreadable or time.monotonic() >= deadline:
            raise BrowserNotReady(
                f"browser not ready: stage 'startup cache disabled' failed: {problems}. A Firefox "
                "with a writable startup cache stops servicing navigation, WebRTC and Playwright "
                "while it writes (about 2-10 s and 120 s after launch); this is a browser/host "
                "condition, not a product failure."
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

# The release workflow runs these tests under pytest-timeout --timeout=600. The
# gate's default budget leaves room for the rest of the test, so a browser that
# is not ready fails with BrowserNotReady rather than an anonymous timeout.
DEFAULT_TIMEOUT_S = 420.0
# Stage 1 only waits for a just-launched process to become visible.
STAGE1_TIMEOUT_S = 30.0


def wait_for_startup_cache_write(browser: Browser, *, timeout_s: float = STAGE1_TIMEOUT_S) -> dict[str, Any]:
    """Stage 1 for every Firefox already running under this test process.

    The e2e conftest calls it before the first test that uses the session's
    ``browser``. Returns a report with ``skipped`` set, doing nothing, for
    other browsers.
    """
    report: dict[str, Any] = {"browser": browser.browser_type.name}
    if browser.browser_type.name != "firefox":
        report["skipped"] = "only Firefox has this startup-cache write"
        return report
    _wait_for_startup_cache(time.monotonic() + timeout_s, report)
    return report


def launch_settled_many(
    browser_type: BrowserType, count: int, *, timeout_s: float = STAGE1_TIMEOUT_S, **launch_kwargs: Any,
) -> list[Browser]:
    """Launch ``count`` browsers for a test, Firefox with its startup cache disabled.

    Use this wherever a test launches its own browsers. A bare
    ``browser_type.launch()`` relies on the e2e session default and nothing
    checks it, and one given its own ``env`` loses the relocation. Each new
    process passes stage 1 before it is returned. If stage 1 fails, every
    browser launched here is closed and BrowserNotReady names the stage.
    """
    firefox = browser_type.name == "firefox"
    if firefox:
        launch_kwargs["env"] = startup_cache_disabled_env(launch_kwargs.get("env"))
    before = _firefox_profile_dirs() if firefox else set()
    browsers: list[Browser] = []
    try:
        for _ in range(count):
            browsers.append(browser_type.launch(**launch_kwargs))
        if firefox:
            new = _firefox_profile_dirs() - before
            if len(new) != count:
                raise BrowserNotReady(
                    f"browser not ready: could not identify the {count} Firefox processes these launches "
                    f"started ({len(new)} new profiles under this test process)"
                )
            _wait_for_startup_cache(time.monotonic() + timeout_s, {}, profiles=new)
    except BaseException:
        for launched in browsers:
            launched.close()
        raise
    return browsers


def launch_settled(
    browser_type: BrowserType, *, timeout_s: float = STAGE1_TIMEOUT_S, **launch_kwargs: Any,
) -> Browser:
    """Launch one browser for a test, Firefox with its startup cache disabled."""
    return launch_settled_many(browser_type, 1, timeout_s=timeout_s, **launch_kwargs)[0]


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
    """Block until ``browser`` passes stage 1 and its parent answers now.

    ``page`` must already be on the daemon origin that the pairing will use.
    Returns what was measured. Raises BrowserNotReady, never a product
    verdict, when readiness is not proven within ``timeout_s``.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    report: dict[str, Any] = {"browser": browser.browser_type.name, "gate_version": 3}
    if require_startup_cache is None:
        require_startup_cache = browser.browser_type.name == "firefox"
    if require_startup_cache:
        _wait_for_startup_cache(min(deadline, started + STAGE1_TIMEOUT_S), report)
    remaining_ms = max(1_000, int((deadline - time.monotonic()) * 1000))
    cfg = {"boundMs": probe_bound_ms, "stable": stable_probes, "overallMs": remaining_ms,
           "pauseMs": 250, "path": probe_path}
    try:
        handle = page.wait_for_function(_PARENT_PROBES, arg=cfg, polling=250, timeout=remaining_ms + 5_000)
        state = handle.json_value()
    except PlaywrightTimeoutError as exc:
        raise BrowserNotReady(
            f"browser not ready: stage 'parent answers' did not complete its probes within "
            f"{time.monotonic() - started:.0f}s (Playwright could not even read the result); "
            "this is a browser/host condition, not a product failure"
        ) from exc
    report["parent_probes"] = state["probes"]
    report["parent_waited_s"] = round(state["waited_ms"] / 1000, 1)
    report["waited_s"] = round(time.monotonic() - started, 1)
    if not state["ok"]:
        raise BrowserNotReady(
            f"browser not ready: stage 'parent answers' failed. The parent did not answer {stable_probes} consecutive "
            f"createOffer()+fetch probes within {probe_bound_ms} ms each in {report['waited_s']}s; "
            f"last probes={state['probes'][-3:]}; this is a browser/host condition, not a product failure"
        )
    return report
