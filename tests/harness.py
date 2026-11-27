"""Test harness for spawning real daemons in subprocesses.

Each `daemon_pair()` invocation spins up two independent daemons in temp
ONE_LINK_HOME directories, waits for mDNS discovery to converge, and yields
control ports + identities for the test body. Cleans up on exit.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from one_link import control_ipc


# ── live-daemon integration gate ───────────────────────────────────
#
# Tests that spawn REAL daemon subprocesses (this harness, plus a few
# files with their own _spawn_daemon helpers) bind ports in the
# well-known range, open many file descriptors, and drive real mDNS.
# Run en masse inside the ~7000-test suite ON A MACHINE ALREADY RUNNING
# LIVE DAEMONS, they starve the host (fd / port / CPU exhaustion) and a
# rotating subset flakes — including hermetic source-inspection tests
# whose inspect.getsource() open() fails when the fd table is full.
#
# So they run in their own quiet lane, gated like the browser-E2E suite:
#
#     ONE_LINK_RUN_LIVE_INTEGRATION=1 pytest tests/   # everything
#     pytest tests/                                    # default: skips
#                                                      # the live lane,
#                                                      # stays hermetic +
#                                                      # deterministic
#
# The gate is applied at the SPAWN PRIMITIVE (here + each local
# _spawn_daemon), so it skips PER TEST: a hermetic test sharing a file
# with a daemon-spawning one still runs in the default gate.
LIVE_INTEGRATION_ENV = "ONE_LINK_RUN_LIVE_INTEGRATION"
# port -> (secret, home). The home is carried so teardown can purge
# unconditionally and a stale entry can be re-read from its source of
# truth: ephemeral control ports are recycled by the OS, so the port
# alone is not a safe key for trust material.
_CONTROL_SECRETS: dict[int, tuple[str, Path]] = {}


def daemon_boot_budget_s() -> float:
    """How long a test waits for a daemon it started to become ready.

    One budget for every test that starts a daemon. It has to be generous
    enough that a slow but healthy start on a loaded runner is never called a
    failure; a start that never happens is bounded by the per-test timeout.
    Overridable for constrained hardware.
    """
    return float(os.environ.get("ONE_LINK_TEST_DAEMON_BOOT_S", "45"))


def live_integration_enabled() -> bool:
    return os.environ.get(LIVE_INTEGRATION_ENV) == "1"


def require_live_daemon() -> None:
    """Skip the calling test unless the live-daemon lane is enabled.
    Call this from any code path that spawns a real daemon subprocess."""
    current = os.environ.get("PYTEST_CURRENT_TEST", "").rsplit(" (", 1)[0]
    if current:
        import pytest

        nodeid = current.split("[", 1)[0].replace("\\", "/")
        manifest = Path(__file__).with_name("live_daemon_manifest.json")
        registered = json.loads(manifest.read_text(encoding="utf-8"))["nodeids"]
        if nodeid not in registered:
            pytest.fail(
                "unregistered live-daemon test: add @pytest.mark.live_daemon and "
                "regenerate scripts/live_suite.py --write-manifest before spawning"
            )
    if not live_integration_enabled():
        import pytest

        pytest.skip(
            "live-daemon integration gated; run with "
            f"{LIVE_INTEGRATION_ENV}=1 pytest (keeps the default gate "
            "hermetic + deterministic even on a busy host)"
        )


def private_mdns_type() -> str:
    """A unique, RFC-6335-valid mDNS service type for one cohort of
    test daemons, so they only ever discover each other — never the
    developer's live daemons (or other concurrent test cohorts) on the
    same LAN. Protocol label kept <=15 chars."""
    return f"_olp{uuid.uuid4().hex[:8]}._tcp.local."


@dataclass
class DaemonHandle:
    home: Path
    log: Path
    proc: subprocess.Popen
    control_port: int
    peer_port: int
    short_id: str
    fingerprint: str
    hostname: str
    control_secret: str
    # Audit fix: keep the log file handle on the handle so it can be
    # closed deterministically on _stop. Without this Python's GC
    # closes the BufferedWriter at finalization time, emitting a
    # ResourceWarning that shows up under pytest -W error::ResourceWarning.
    log_fh: BinaryIO | None = None


@dataclass
class DaemonPair:
    a: DaemonHandle
    b: DaemonHandle
    tmp: Path


def _read_port(
    home: Path,
    name: str,
    timeout: float = 15.0,
    *,
    proc: subprocess.Popen | None = None,
    log: Path | None = None,
) -> int:
    """Wait for a daemon port file, and on failure say WHY.

    The old version raised a bare "port file did not appear", which made an
    intermittent Windows CI failure unexplainable: it reported neither whether
    the daemon was still running, nor its exit status, nor the log it had
    already written. Three tests failed that way on a single run with nothing
    to act on. Passing ``proc``/``log`` turns the same failure into evidence.

    It also fails FAST when the child is already dead instead of waiting out
    the whole budget for a file that can no longer be written.
    """

    p = home / "data" / name
    started = time.monotonic()
    end = started + timeout
    while True:
        if p.exists():
            try:
                return int(p.read_text().strip())
            except (ValueError, OSError):
                # A partially written file: keep waiting for the full value.
                pass
        exited = proc.poll() if proc is not None else None
        if exited is not None:
            raise RuntimeError(
                f"daemon exited with code {exited} before writing {p} "
                f"after {time.monotonic() - started:.2f}s; log tail:\n"
                f"{_read_log(log) if log is not None else '<no log captured>'}"
            )
        if time.monotonic() >= end:
            break
        time.sleep(0.05)
    alive = "alive" if proc is not None and proc.poll() is None else "not running"
    raise RuntimeError(
        f"port file did not appear: {p} (waited "
        f"{time.monotonic() - started:.2f}s of {timeout:.2f}s, daemon {alive}); "
        f"log tail:\n{_read_log(log) if log is not None else '<no log captured>'}"
    )


def _wait_port(port: int, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.05)
        finally:
            s.close()
    return False


def request(control_port: int, *, timeout: float = 30.0, **req) -> dict:
    """Send a single control request and read one JSON response line.

    Under Windows TCP control-socket churn (documented in
    test_two_device_soak.py:85), a freshly-accepted connection can
    drop EOF before the daemon's reader serves the request, OR a
    fresh connect() can hit ConnectionRefusedError when the
    accept queue is briefly drained under suite-level resource
    pressure. Both surface as either an empty response or a
    refused connect.

    Retry up to 3 times with exponential backoff (0.1, 0.4, 1.6s)
    so an 11-minute suite under heavy subprocess churn doesn't
    spuriously fail on transient TCP-stack hiccups. A real daemon
    crash (proc.poll() != None) is undetectable from this side,
    but the timeout still caps the total wait at ~timeout seconds.
    """
    import time as _time
    last_exc: Exception | None = None
    backoff_s = (0.1, 0.4, 1.6)
    max_attempts = len(backoff_s) + 1
    for attempt in range(max_attempts):
        try:
            secret, home = _CONTROL_SECRETS[int(control_port)]
            try:
                return control_ipc.request_control(
                    control_port,
                    req,
                    timeout=timeout,
                    secret=secret,
                )
            except control_ipc.ControlAuthenticationError as auth_error:
                # A cached secret can be STALE: this cache is keyed by control
                # port, and the OS recycles ephemeral ports between tests. If a
                # previous daemon's entry outlived it, a new daemon holding the
                # same port is sent the wrong secret and rejects the MAC. Re-read
                # the authoritative secret from this daemon's own home and retry
                # once, so a leaked entry cannot fail a healthy daemon.
                try:
                    fresh = control_ipc.read_control_secret(home / "data")
                except Exception:
                    # The home may already be torn down. Surface the
                    # AUTHENTICATION failure that actually happened rather than a
                    # secret-file error raised by the recovery attempt, which
                    # would replace the real diagnosis with a downstream symptom.
                    raise auth_error from None
                if fresh == secret:
                    # The cached secret already matches the daemon's own file, so
                    # the rejection is real. Never retry it into silence.
                    raise
                _CONTROL_SECRETS[int(control_port)] = (fresh, home)
                return control_ipc.request_control(
                    control_port,
                    req,
                    timeout=timeout,
                    secret=fresh,
                )
        except (ConnectionAbortedError, ConnectionResetError, OSError) as e:
            last_exc = e
        if attempt < len(backoff_s):
            _time.sleep(backoff_s[attempt])
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("control request returned no response")


def _spawn(
    home: Path,
    log: Path,
    mdns_type: str | None = None,
    *,
    periodic_folder_sync: bool = True,
) -> tuple[subprocess.Popen, BinaryIO]:
    """Returns (proc, log_fh). Caller stores the log_fh on the handle
    and closes it after the proc exits — keeps Python's GC from
    emitting ResourceWarning at random later moments."""
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(env.get("ONE_LINK_HOME") or "") or str(home)
    env["ONE_LINK_HOME"] = str(home)  # always per-test
    env["ONE_LINK_ALLOW_SAME_HOST_PEERS"] = "1"
    # Private mDNS scope so this cohort never cross-discovers the
    # developer's live daemons (or another concurrent test cohort) on
    # the same LAN — the live lane stays reliable on a busy host.
    if mdns_type:
        env["ONE_LINK_MDNS_SERVICE_TYPE"] = mdns_type
    # Production and tests default to loopback. LAN exposure is an explicit
    # launcher opt-in and would also conflict with another local test/daemon
    # holding a well-known port on a different interface.
    env.setdefault("ONE_LINK_BIND_HOST", "127.0.0.1")
    # v0.7.x: defence-in-depth. conftest.py already sets this at
    # module-import time, but if a future test path starts a daemon
    # before conftest runs (or via a different code path), keep
    # tests from popping real Explorer windows on the developer.
    env.setdefault("ONE_LINK_DISABLE_REVEAL", "1")
    # Wave 2g+ test hook ``_send_raw_message`` is hardened behind
    # this env in production so it doesn't ship a control-plane
    # bypass. Test daemons explicitly opt in.
    env.setdefault("ONE_LINK_DEV_HOOKS", "1")
    # v0.21.x: rotation integration test uses /api/peers/{fp}/_test_force_dial
    # to skip mDNS rediscovery after a daemon restart. The endpoint is
    # 404 unless this env is set — keeps the surface inert in
    # production builds.
    env.setdefault("ONE_LINK_ENABLE_TEST_API", "1")
    # Accept-first is ON by default in production, but the existing
    # two-daemon file-send tests expect the receiver to auto-receive.
    # Default it OFF for harness daemons; a test that specifically
    # exercises accept-first sets ONE_LINK_REQUIRE_FILE_ACCEPT=1 in
    # its own environment (setdefault preserves that override).
    env.setdefault("ONE_LINK_REQUIRE_FILE_ACCEPT", "0")
    log.parent.mkdir(parents=True, exist_ok=True)
    f = open(log, "wb")
    daemon_module = (
        "one_link.cli" if periodic_folder_sync else "tests.manual_folder_sync_daemon"
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", daemon_module, "daemon", "-v"],
        env=env,
        stdout=f,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    # Popen does not retain creationflags; _stop needs proof this process
    # leads its own group before it may send CTRL_BREAK_EVENT (see _stop).
    proc._one_link_new_process_group = True  # type: ignore[attr-defined]
    return proc, f


def _stop(
    proc: subprocess.Popen,
    *,
    home: Path | None = None,
    control_port: int | None = None,
    control_secret: str | None = None,
) -> None:
    """Stop a test daemon GRACEFULLY so it has a chance to send mDNS goodbye
    packets — this is what stops cross-test pollution where a dead daemon's
    record lingers in another daemon's discovery registry.

    On Windows we send Ctrl+Break (the daemon is in its own process group).
    The daemon's outer try/except turns it into KeyboardInterrupt, which
    triggers Daemon.stop() → Discovery.stop() → async_unregister_service.

    On POSIX, SIGTERM does the same job via Python's default signal handling.
    SIGKILL (terminate's behaviour on Windows, .kill() everywhere) is the
    last-resort fallback.

    ``Popen.pid`` is not necessarily the socket-owning daemon PID on Windows:
    a virtual-environment ``python.exe`` launcher can remain as the parent of
    the base interpreter.  Teardown therefore authenticates the daemon through
    its per-home control secret first, then verifies and reaps every remaining
    One Link process whose ``ONE_LINK_HOME`` exactly matches this test home.
    """
    resolved_home = Path(home).resolve() if home is not None else None
    serving_pid: int | None = None
    resolved_control_port = control_port
    secret = control_secret

    if resolved_home is not None:
        if resolved_control_port is None:
            try:
                resolved_control_port = _read_port(
                    resolved_home,
                    "control.port",
                    timeout=0.25,
                )
            except RuntimeError:
                resolved_control_port = None
        if secret is None:
            try:
                secret = control_ipc.read_control_secret(resolved_home / "data")
            except RuntimeError:
                secret = None
        if resolved_control_port is not None and secret is not None:
            try:
                status = control_ipc.request_control(
                    resolved_control_port,
                    {"cmd": "status"},
                    timeout=2.0,
                    secret=secret,
                )
                expected_data = os.path.normcase(
                    str((resolved_home / "data").resolve())
                )
                reported_data = os.path.normcase(
                    str(Path(str(status.get("home") or "")).resolve())
                )
                candidate_pid = status.get("pid")
                if (
                    status.get("ok") is True
                    and type(candidate_pid) is int
                    and candidate_pid > 0
                    and reported_data == expected_data
                ):
                    serving_pid = candidate_pid
                    control_ipc.request_control(
                        resolved_control_port,
                        {"cmd": "shutdown"},
                        timeout=2.0,
                        secret=secret,
                    )
            except (OSError, RuntimeError, ValueError):
                pass

    if proc.poll() is not None and resolved_home is None:
        return

    import signal

    # Give an authenticated shutdown enough time to flush state, withdraw
    # runtime publications, and send mDNS goodbye before using OS signals.
    if serving_pid is not None:
        try:
            import psutil

            psutil.Process(serving_pid).wait(timeout=8.0)
        except ImportError:
            pass
        except psutil.NoSuchProcess:
            pass
        except psutil.TimeoutExpired:
            pass

    sent_graceful = False
    if proc.poll() is None:
        try:
            if os.name == "nt":
                # CTRL_BREAK_EVENT is only scoped when the target leads its
                # own process group (CREATE_NEW_PROCESS_GROUP). Sent at a
                # non-leader pid, GenerateConsoleCtrlEvent falls back to the
                # WHOLE console group -- which in CI includes the pwsh step
                # host, and PowerShell treats Ctrl+Break as "enter the
                # debugger", wedging the job ("Entering debug mode"). Only
                # break-signal processes our spawners tagged as group
                # leaders; everything else gets terminate() below.
                if getattr(proc, "_one_link_new_process_group", False) or (
                    getattr(proc, "creationflags", 0)
                    & subprocess.CREATE_NEW_PROCESS_GROUP
                ):
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                    sent_graceful = True
            else:
                proc.send_signal(signal.SIGTERM)
                sent_graceful = True
        except Exception:
            pass

    if sent_graceful and proc.poll() is None:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    if resolved_home is not None:
        # Fail-safe cleanup is strictly scoped to this test's exact home and a
        # One Link daemon command line. It can never target the developer's
        # normal daemon or another concurrent cohort.
        try:
            import psutil

            expected_home = os.path.normcase(str(resolved_home))
            matches: list[psutil.Process] = []
            for candidate in psutil.process_iter(["cmdline"]):
                try:
                    argv = candidate.info.get("cmdline") or []
                    lowered = [str(arg).strip().lower() for arg in argv]
                    is_daemon = (
                        "-m" in lowered
                        and any(module in lowered for module in (
                            "one_link.cli", "tests.manual_folder_sync_daemon",
                        ))
                        and "daemon" in lowered
                    )
                    candidate_home = candidate.environ().get("ONE_LINK_HOME")
                    if (
                        is_daemon
                        and candidate_home
                        and os.path.normcase(str(Path(candidate_home).resolve()))
                        == expected_home
                    ):
                        matches.append(candidate)
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    continue
            for candidate in matches:
                with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                    candidate.terminate()
            _, alive = psutil.wait_procs(matches, timeout=3.0)
            for candidate in alive:
                with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                    candidate.kill()
            _, alive = psutil.wait_procs(alive, timeout=3.0)
            if alive:
                raise RuntimeError(
                    "test daemon teardown left exact-home processes alive: "
                    + ", ".join(str(candidate.pid) for candidate in alive)
                )
        except ImportError:
            pass

    # Reap or terminate the launcher stub after its serving child is gone.
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    # Purge by port when known, but NEVER rely on that alone: resolved_control_port
    # comes from a best-effort _read_port that returns None once the daemon has
    # removed its port file, and this cleanup used to be skipped entirely in that
    # case. The leaked entry then poisoned whichever later daemon the OS handed
    # the same recycled port, surfacing as an intermittent
    # ControlAuthenticationError on Windows. Purging by home as well makes
    # cleanup unconditional, because the home is what this teardown actually owns.
    purge_control_secrets(port=resolved_control_port, home=resolved_home)


def control_secret_for(port: int) -> str:
    """The cached control secret for a daemon's control port.

    Use this instead of indexing ``_CONTROL_SECRETS`` directly: the cache stores
    ``(secret, home)`` so teardown can purge by home and a stale entry can be
    re-read from source, and callers should not have to know that shape.
    """

    secret, _home = _CONTROL_SECRETS[int(port)]
    return secret


def purge_control_secrets(
    *,
    port: int | None = None,
    home: Path | None = None,
) -> None:
    """Drop cached control secrets for a torn-down daemon.

    Purging by port alone was NOT enough. The port comes from a best-effort
    ``_read_port`` that returns None once the daemon has deleted its port file,
    and the old cleanup was skipped entirely in that case. The leaked entry then
    poisoned whichever later daemon the OS handed the same recycled ephemeral
    port, surfacing as an intermittent ControlAuthenticationError on Windows
    (which recycles ports aggressively). The home is what a teardown actually
    owns, so purging by home makes the cleanup unconditional.
    """

    if port is not None:
        _CONTROL_SECRETS.pop(int(port), None)
    if home is not None:
        for cached_port in [
            cached_port
            for cached_port, (_secret, cached_home) in _CONTROL_SECRETS.items()
            if cached_home == home
        ]:
            _CONTROL_SECRETS.pop(cached_port, None)


def _read_log(p: Path, n: int = 4000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[-n:]
    except OSError:
        return "<no log>"


def _bring_up(
    home: Path,
    log: Path,
    label: str,
    mdns_type: str | None = None,
    *,
    periodic_folder_sync: bool = True,
) -> DaemonHandle:
    proc, log_fh = _spawn(
        home, log, mdns_type=mdns_type, periodic_folder_sync=periodic_folder_sync,
    )
    try:
        # 15 s was too tight for a loaded Windows hosted runner: three
        # unrelated live tests failed on one run purely because the daemon had
        # not finished booting. A longer budget costs nothing now that a dead
        # child raises immediately above -- it only helps the case where the
        # runner is merely slow, and never hides a daemon that actually failed.
        ctrl = _read_port(home, "control.port", timeout=60.0, proc=proc, log=log)
        peer = _read_port(home, "peer.port", timeout=60.0, proc=proc, log=log)
        secret_path = home / "data" / control_ipc.CONTROL_SECRET_FILE
        secret_deadline = time.time() + 8.0
        while time.time() < secret_deadline and not secret_path.is_file():
            time.sleep(0.05)
        secret = control_ipc.read_control_secret(home / "data")
        _CONTROL_SECRETS[ctrl] = (secret, home)
        if not _wait_port(ctrl, timeout=8.0):
            raise RuntimeError(
                f"daemon {label} control socket not responsive\n--- log ---\n"
                f"{_read_log(log)}"
            )
        info = request(ctrl, cmd="peers")
        if not info.get("ok"):
            raise RuntimeError(f"daemon {label} 'peers' failed: {info}")
        # The control socket coming up does NOT imply the HTTP server
        # has finished initializing - control + HTTP run as separate
        # tasks. ui.token + server.port get written by the HTTP server's
        # startup hook, and tests that read those files via
        # ``home/"data"/"ui.token"`` can race the writes under load.
        # Wait for both files to appear before returning so the test never
        # sees a missing-file FileNotFoundError.
        #
        # The budget was a flat 6s, which measured RUNNER LOAD rather than
        # daemon correctness: a shared CI box that has just compiled the
        # native engine needs longer than a warm dev machine to get a
        # first-boot daemon (identity mint, key authority, SQLCipher schema)
        # to the point of writing these files, and the whole live-integration
        # step failed on that alone. Per-test timeouts already bound a genuine
        # hang, so this only needs to be generous enough that a slow-but-
        # healthy boot is never called a failure. Overridable for operators
        # running on constrained hardware.
        startup_budget = daemon_boot_budget_s()
        http_deadline = time.time() + startup_budget
        ui_token_path = home / "data" / "ui.token"
        server_port_path = home / "data" / "server.port"
        while time.time() < http_deadline:
            if ui_token_path.is_file() and server_port_path.is_file():
                # Files exist; one more guard against partial writes.
                # Both files are tiny so any non-empty read is the
                # finished write (atomic rename or single-write).
                try:
                    if (
                        ui_token_path.stat().st_size > 0
                        and server_port_path.stat().st_size > 0
                    ):
                        break
                except OSError:
                    pass
            time.sleep(0.05)
        else:
            raise RuntimeError(
                f"daemon {label} HTTP server did not write ui.token + "
                f"server.port within {startup_budget:g}s"
                f"\n--- log ---\n{_read_log(log)}"
            )
        return DaemonHandle(
            home=home,
            log=log,
            proc=proc,
            control_port=ctrl,
            peer_port=peer,
            short_id=info["me"]["short_id"],
            fingerprint=info["me"]["fingerprint"],
            hostname=info["me"]["hostname"],
            control_secret=secret,
            log_fh=log_fh,
        )
    except Exception:
        _stop(proc, home=home)
        try:
            log_fh.close()
        except Exception:
            pass
        raise


def _pin_test_peer(source: DaemonHandle, peer: DaemonHandle) -> None:
    """Pin one live test peer through the authenticated production API.

    mDNS discovery deliberately leaves new peers pending. Transport tests that
    exercise chat/files must opt into a paired cohort instead of depending on
    the historical ``policy=None`` fail-open behavior for pending LAN peers.
    The HTTP path keeps the fixture aligned with the daemon's canonical trust
    mutation and mDNS-seeding semantics; it does not write SQLite directly.
    """
    server_port = int((source.home / "data" / "server.port").read_text().strip())
    ui_token = (source.home / "data" / "ui.token").read_text().strip()
    body = json.dumps({"trust": "pinned"}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{server_port}/api/peers/{peer.fingerprint}/trust",
        data=body,
        headers={
            "Authorization": f"Bearer {ui_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as response:
            status = int(response.status)
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"test trust pin {source.short_id}->{peer.short_id} failed "
            f"with HTTP {exc.code}: {detail}"
        ) from exc
    if status != 200 or not payload.get("ok"):
        raise RuntimeError(
            f"test trust pin {source.short_id}->{peer.short_id} returned "
            f"HTTP {status}: {payload!r}"
        )


# How much of each daemon's log a failing live test carries. It was 4000
# characters, and two hosted failures arrived unreadable: one "peer caps" line
# is about 700 characters, so the tail began some twenty lines before the end,
# after the events that mattered. A whole short test's log is 20 to 60 thousand.
FAILED_TEST_LOG_TAIL = 60_000


def _attach_daemon_logs(exc: BaseException, logs: dict[str, Path]) -> None:
    """Add each daemon's log tail to a failing live test's exception.

    pytest prints exception notes under the traceback, so the evidence reaches
    the hosted job log with no artifact to fetch. Reading the logs must never
    replace the original failure, and a generator being closed or an interrupt
    is not a test failure.
    """
    if isinstance(exc, (GeneratorExit, KeyboardInterrupt)):
        return
    for label, path in logs.items():
        try:
            tail = _read_log(path, FAILED_TEST_LOG_TAIL)
        except Exception as read_error:
            tail = f"<log unreadable: {type(read_error).__name__}: {read_error}>"
        exc.add_note(f"--- daemon {label} log tail ---\n{tail}")


@contextmanager
def daemon_pair(
    *, pin_trust: bool = False, periodic_folder_sync: bool = True,
) -> Iterator[DaemonPair]:
    """Spin up two daemons, converge mDNS, and optionally pin both peers.

    ``pin_trust=False`` preserves the pending-peer surface needed by pairing
    and authorization tests. Live transport tests pass ``pin_trust=True`` so
    capability checks run with the same post-pairing authority as production.

    ``periodic_folder_sync=False`` uses a test-only CLI entry point that omits
    the scheduled folder pushes. Manual sync, watchers, authenticated transport,
    and receipt verification still run normally, so a single-sync test cannot
    accidentally prove convergence caused by an earlier background cycle.
    """
    # Gate: spawning real daemon subprocesses is the live-integration
    # lane. Skip the calling test in the default (hermetic) gate.
    require_live_daemon()
    # One private mDNS scope shared by A + B so they discover each other
    # but nothing else — immune to ambient daemons on the LAN.
    mdns_type = private_mdns_type()
    tmp = Path(tempfile.mkdtemp(prefix="one_link_it_"))
    a_home = tmp / "A"
    b_home = tmp / "B"
    a_home.mkdir()
    b_home.mkdir()
    a_log = tmp / "a.log"
    b_log = tmp / "b.log"
    a: DaemonHandle | None = None
    b: DaemonHandle | None = None
    try:
        a = _bring_up(
            a_home, a_log, "A", mdns_type=mdns_type,
            periodic_folder_sync=periodic_folder_sync,
        )
        b = _bring_up(
            b_home, b_log, "B", mdns_type=mdns_type,
            periodic_folder_sync=periodic_folder_sync,
        )
        # Wait for cross-discovery
        deadline = time.time() + 20.0
        while time.time() < deadline:
            ra = request(a.control_port, cmd="peers")
            rb = request(b.control_port, cmd="peers")
            a_sees_b = any(p["short_id"] == b.short_id for p in ra.get("peers", []))
            b_sees_a = any(p["short_id"] == a.short_id for p in rb.get("peers", []))
            if a_sees_b and b_sees_a:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(
                "mDNS discovery did not converge in 20s\n"
                f"A.peers = {ra.get('peers')}\nB.peers = {rb.get('peers')}\n"
                f"--- A log ---\n{_read_log(a_log)}\n"
                f"--- B log ---\n{_read_log(b_log)}"
            )
        if pin_trust:
            _pin_test_peer(a, b)
            _pin_test_peer(b, a)
        try:
            yield DaemonPair(a=a, b=b, tmp=tmp)
        except BaseException as exc:
            # A live test that fails on a hosted runner leaves only its
            # assertion ("a.txt didn't land on B within 30s") unless the
            # daemons' own account travels with it.
            _attach_daemon_logs(exc, {"A": a_log, "B": b_log})
            raise
    finally:
        if a is not None:
            _stop(
                a.proc,
                home=a.home,
                control_port=a.control_port,
                control_secret=a.control_secret,
            )
            try:
                if a.log_fh is not None:
                    a.log_fh.close()
            except Exception:
                pass
        if b is not None:
            _stop(
                b.proc,
                home=b.home,
                control_port=b.control_port,
                control_secret=b.control_secret,
            )
            try:
                if b.log_fh is not None:
                    b.log_fh.close()
            except Exception:
                pass
        # Best-effort cleanup. Keep on failure so logs survive — pytest
        # passes/fails are signalled separately.
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


async def await_peer_in_api(
    session,
    base: str,
    token: str,
    short_id: str,
    *,
    timeout: float = 8.0,
) -> dict:
    """Poll GET /api/peers until a peer with `short_id` appears, or fail.

    Eliminates an entire class of cross-test flakes: under heavy CI load the
    HTTP /api/peers endpoint can momentarily return an empty list even after
    mDNS has converged at the daemon's discovery registry, because the daemon
    coalesces some state via async tasks. Bare `next(p for p in peers if ...)`
    against the snapshot then raises StopIteration which Python turns into
    `RuntimeError: coroutine raised StopIteration`. Use this helper instead.
    """
    import time as _time
    deadline = _time.time() + timeout
    last: list[dict] = []
    while _time.time() < deadline:
        async with session.get(
            base + "/api/peers",
            headers={"X-One-Link-Token": token},
        ) as r:
            j = await r.json()
        last = j.get("peers", [])
        for pp in last:
            if pp.get("short_id") == short_id:
                return pp
        await _async_sleep_short()
    raise AssertionError(
        f"peer {short_id} did not appear in /api/peers within {timeout}s; "
        f"last snapshot: {last!r}"
    )


async def _async_sleep_short() -> None:
    import asyncio as _asyncio
    await _asyncio.sleep(0.05)


def message_log(home: Path) -> list[dict]:
    """Read message history from the daemon's sqlite state, returning dicts
    in the same wire-shape the JSONL log used. Tests written before the
    sqlite migration still work."""
    db = home / "data" / "state.db"
    if not db.exists():
        return []
    import sqlite3
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, ts_ms, direction, peer_fp, msg_type, body, room_id, "
            "metadata_json FROM messages ORDER BY ts_ms"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    out: list[dict] = []
    for r in rows:
        try:
            md = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
        except Exception:
            md = {}
        d = {
            "t": r["msg_type"],
            "id": r["id"],
            "ts": r["ts_ms"],
            "dir": r["direction"],
            "peer_fp": r["peer_fp"],
            "peer": md.get("short_id") or (r["peer_fp"][:8] if r["peer_fp"] else "?"),
            "room_id": r["room_id"],
        }
        if r["body"] is not None:
            d["body"] = r["body"]
        for k, v in md.items():
            if k != "short_id" and k not in d:
                d[k] = v
        out.append(d)
    return out


def inbox_files(home: Path) -> list[Path]:
    p = home / "data" / "inbox"
    if not p.exists():
        return []
    # Filter to actual files. The daemon stashes a ``.resume``
    # sidecar subdirectory next to the user-visible payloads; if we
    # returned that, callers iterating with .read_bytes() would
    # PermissionError on the directory entry.
    return sorted(e for e in p.iterdir() if e.is_file())


def wait_for_inbox_file(
    home: Path,
    name_suffix: str,
    *,
    expected_size: int | None = None,
    timeout: float = 15.0,
    poll_interval: float = 0.05,
    stable_for: float = 0.2,
) -> Path:
    """Wait until a file whose name ends with ``name_suffix`` appears in
    the daemon's inbox AND the size has stabilised. Returns the
    matching Path. Raises ``AssertionError`` if the file does not
    appear within ``timeout``, or never settles.

    ``expected_size`` — if set, wait until the file is at least that
    large. The receiver creates the inbox file when streaming starts,
    not when the transfer completes; without a size gate the caller
    races a partially-written file.

    ``stable_for`` — additional seconds the size must remain unchanged
    before the file is considered settled. Cheap insurance against the
    last-chunk-still-flushing race.

    Replaces brittle ``time.sleep(N)`` patterns in integration tests
    with an event-driven check that keeps the suite fast on a hot box
    and reliable on a slow one (CI, AV scan, hot native rebuild)."""
    deadline = time.monotonic() + timeout
    last_files: list[Path] = []
    target: Path | None = None
    while time.monotonic() < deadline:
        last_files = inbox_files(home)
        for f in last_files:
            if f.name.endswith(name_suffix):
                target = f
                break
        if target is not None:
            try:
                size = target.stat().st_size
            except FileNotFoundError:
                target = None
                time.sleep(poll_interval)
                continue
            if expected_size is None or size >= expected_size:
                stable_until = time.monotonic() + stable_for
                last_size = size
                ok = True
                while time.monotonic() < stable_until:
                    time.sleep(poll_interval)
                    try:
                        cur = target.stat().st_size
                    except FileNotFoundError:
                        ok = False
                        break
                    if cur != last_size:
                        last_size = cur
                        stable_until = time.monotonic() + stable_for
                if ok:
                    return target
        time.sleep(poll_interval)
    raise AssertionError(
        f"timed out after {timeout}s waiting for stable inbox file "
        f"ending with {name_suffix!r} "
        f"(expected_size={expected_size}); saw {[f.name for f in last_files]}"
    )
