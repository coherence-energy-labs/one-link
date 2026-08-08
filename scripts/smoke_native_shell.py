#!/usr/bin/env python3
"""Does One Link's window actually OPEN and LOAD the interface on this machine?

WHY THIS EXISTS. `native_shell.yml` proves the shell COMPILES on Windows, Linux and macOS. A
compile is the floor. The window opening -- a real webview runtime, a real display, the page
actually fetched -- was verified end to end only on Windows, by hand, on one developer machine.
That is why the shell is `--required` on Windows alone: everywhere else it degrades to the browser
path, and "it builds" was never evidence it would work.

This closes that gap on any platform that can give the process a display, CI included (Linux via
xvfb). It is deliberately a SMOKE test, and its claim is exactly:

    the shell started, verified the interface, opened a window, and the webview FETCHED the page.

WHAT IT DOES NOT CLAIM: that the page rendered correctly, that the app is usable, or that pixels
were right. Proving the UI *runs* needs a live daemon and authenticated API traffic -- that is a
heavier experiment, and it has been done on Windows. Do not read a green run here as more than the
sentence above.

THE LOAD SIGNAL IS THE SERVER'S OWN LOG, not the shell's word for it. `OL_SHELL_READY` means the
window was created; it says nothing about whether the webview fetched anything. A request arriving
at a server the shell does not control is the part that cannot be faked by a window that opened
onto a blank surface.
"""
from __future__ import annotations

import argparse
import http.server
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
READY = "OL_SHELL_READY"
FAILED = "OL_SHELL_FAILED"

_hits: list[str] = []
_hits_lock = threading.Lock()


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Serves the real interface and records what was asked for."""

    def log_message(self, *_args) -> None:      # silence per-request noise on stderr
        pass

    def do_GET(self) -> None:                   # noqa: N802 - stdlib casing
        with _hits_lock:
            _hits.append(self.path)
        super().do_GET()


def shell_binary() -> Path | None:
    # `OL_SHELL_BIN` lets you smoke a build that is not in the default target dir -- e.g. a second
    # `CARGO_TARGET_DIR` used because the normal binary is locked by a running window.
    override = os.environ.get("OL_SHELL_BIN", "").strip()
    if override:
        cand = Path(override)
        return cand if cand.is_file() else None
    base = REPO / "native" / "ol_shell" / "target" / "release"
    for name in ("ol_shell.exe", "ol_shell"):
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--timeout", type=float, default=90.0,
                    help="seconds to wait for the window to report ready")
    ap.add_argument("--root", type=Path, default=None,
                    help="install root to hand the shell (default: the repo's src/one_link). "
                         "Point it at a tampered COPY to check this smoke can actually fail: the "
                         "shell must refuse, and a harness that cannot report a refusal is not "
                         "evidence of anything when it passes.")
    ap.add_argument("--expect-refusal", action="store_true",
                    help="invert the verdict: PASS only if the shell REFUSES to open. Used to "
                         "calibrate this script against a modified interface.")
    args = ap.parse_args()

    exe = shell_binary()
    if exe is None:
        print(f"FAIL: no shell binary under {REPO / 'native/ol_shell/target/release'}; "
              "build it first with `cargo build --release`")
        return 2

    package_root = args.root.resolve() if args.root else REPO / "src" / "one_link"
    web = package_root / "web"
    if not (web / "index.html").is_file():
        print(f"FAIL: no interface to serve at {web / 'index.html'}")
        return 2

    handler = lambda *a, **k: _Handler(*a, directory=str(web), **k)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"
    print(f"  serving the real interface at {url}")
    print(f"  shell: {exe}")

    proc = subprocess.Popen(
        [str(exe)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        print("FAIL: the shell did not expose its pipes")
        proc.kill()
        return 2

    # Same three lines the launcher sends: URL, install root, geometry.
    proc.stdin.write(f"{url}\n{package_root}\n900 700 40 40\n")
    proc.stdin.flush()

    # A blocking readline cannot be given a deadline portably, so it lives on its own thread and
    # the deadline is enforced here. Without this, a shell that never speaks hangs the job until
    # the CI timeout, which reports "cancelled" rather than the reason.
    lines: queue.Queue[str] = queue.Queue()

    def pump(stream, tag: str) -> None:
        for line in stream:
            lines.put(f"{tag}{line.rstrip()}")

    threading.Thread(target=pump, args=(proc.stdout, ""), daemon=True).start()
    threading.Thread(target=pump, args=(proc.stderr, "!"), daemon=True).start()

    ready = False
    said: list[str] = []
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if proc.poll() is not None and lines.empty():
            break
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            continue
        said.append(line)
        if line.startswith(READY):
            ready = True
            break
        if FAILED in line:
            break

    # Give the webview a moment to actually request the page: the window is created before its
    # first fetch completes, so checking instantly would race the thing being measured.
    if ready:
        fetch_deadline = time.time() + 20.0
        while time.time() < fetch_deadline:
            with _hits_lock:
                if _hits:
                    break
            time.sleep(0.25)

    with _hits_lock:
        hits = list(_hits)

    for line in said:
        print(f"    shell said: {line}")

    loaded = any(h in ("/", "/index.html") for h in hits)
    print(f"\n  window opened (OL_SHELL_READY): {ready}")
    print(f"  interface FETCHED by the webview: {loaded}  {hits[:6]}")

    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    httpd.shutdown()

    if args.expect_refusal:
        # CALIBRATION MODE. The interface handed to the shell was modified, so the ONLY correct
        # outcome is a refusal to open, naming the reason. A window that appears here means the
        # build-time pin is not being enforced, and every green run of this smoke is worthless.
        refused = (not ready) and any(FAILED in line for line in said)
        if refused:
            print("\n  PASS (calibration): the shell REFUSED a modified interface, and said why.")
            return 0
        print("\n  FAIL (calibration): the shell opened a window on a modified interface, or died "
              "without saying why -- the pin is not doing its job.")
        return 1

    if ready and loaded:
        print("\n  PASS: the window opened and loaded the real interface on this platform.")
        return 0
    print("\n  FAIL: " + ("the window opened but never fetched the page"
                          if ready else "the window never reported ready"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
