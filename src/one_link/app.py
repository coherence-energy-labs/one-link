"""`one-link app` - launch the desktop UI.

The launcher owns the "just works" contract:

1. Reuse a running daemon only when it proves it is this build.
2. Gracefully stop stale daemons instead of opening a mismatched UI/backend.
3. Spawn a fresh daemon and open the browser once the self-check passes.

Users should never need to know what a daemon, port, token, schema, or
background process is.
"""

from __future__ import annotations

import json
import contextlib
import ctypes
import http.client
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import click

from one_link import __version__
from one_link import control_ipc
from one_link import daemon as daemon_mod
from one_link.build_identity import runtime_build_identity
from one_link.fault_observability import report_best_effort_failure
from one_link.paths import data_dir
from one_link.process_security import (
    hidden_creationflags,
    launch_explicit_command,
    launch_loopback_url,
    resolve_current_interpreter,
    resolve_explicit_executable,
    resolve_system_executable,
    sanitized_process_env,
    trusted_process_env,
    trusted_system_directories,
    validate_loopback_url,
)


log = logging.getLogger("one_link.app")


@dataclass(frozen=True)
class RunningDaemon:
    control_port: int
    server_port: int
    token: str
    status: dict
    #: Single-use, TTL-bounded credential minted for THIS launch. `token` is a Bearer for
    #: the authenticated control channel and must never reach a command line; this is the
    #: only credential allowed in a browser URL. See `UIServer.mint_launch_nonce`.
    launch_nonce: Optional[str] = None

    @property
    def compatible(self) -> bool:
        build = runtime_build_identity()
        return (
            self.status.get("ok") is True
            and self.status.get("app_version") == __version__
            and self.status.get("source_fingerprint")
            == build["source_fingerprint"]
            and bool(self.status.get("protocol_version"))
            and int(self.status.get("schema_version") or 0) > 0
        )


def _alive(port: int, timeout: float = 0.3) -> bool:
    return daemon_mod.is_daemon_alive(port, timeout=timeout)


def _daemon_is_lan_bound(info: "RunningDaemon") -> bool:
    """v0.15.4 — ask the daemon directly whether it's LAN-bound.
    Earlier versions probed via socket.connect() to the LAN IP, but
    Windows + Linux kernels route same-host connects to your own
    LAN IP back through loopback even when the listener is bound
    to 127.0.0.1 only — so the probe gave a false positive and
    --lan never actually rebound the daemon.

    The /api/status payload includes `bind_host` since v0.15.2;
    treating any non-loopback value as LAN-bound is the only
    reliable signal."""
    bind_host = info.status.get("bind_host")
    if not bind_host:
        # Pre-v0.15.2 daemon (no bind_host field) — assume worst
        # case (loopback) so --lan triggers a restart.
        return False
    return bind_host not in ("127.0.0.1", "localhost", "::1")


def _control_request(
    port: int,
    cmd: str,
    timeout: float = 2.0,
    *,
    secret: str | None = None,
    **kwargs,
) -> dict:
    try:
        return control_ipc.request_control(
            int(port),
            {"cmd": cmd, **kwargs},
            timeout=timeout,
            secret=secret,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _open_verified_ui_instance(
    server_port: int,
    control_status: dict,
    *,
    secret: str,
    timeout: float = 1.5,
) -> http.client.HTTPConnection | None:
    """Open and authenticate a keep-alive channel to the daemon's UI.

    The caller requests ``ui_launch_info`` only after this proof succeeds, then
    sends the owner bearer over this *same TCP connection*.  Requiring an open
    HTTP/1.1 keep-alive socket closes the proof-to-bearer port-swap race: a
    listener cannot be replaced underneath an already-connected socket.

    A stale port hint or malicious localhost listener therefore never receives
    the UI token merely because it can imitate an unsigned status payload. The
    fresh challenge is HMAC-bound to the authenticated control daemon's process
    identity, build fingerprint, and reported port.
    """

    challenge = control_ipc.make_ui_instance_challenge()
    query = urllib.parse.urlencode({"challenge": challenge})
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        int(server_port),
        timeout=timeout,
    )
    try:
        connection.request(
            "GET",
            f"/api/local-instance-proof?{query}",
            headers={"Accept": "application/json", "Connection": "keep-alive"},
        )
        response = connection.getresponse()
        raw = response.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            connection.close()
            return None
        # A proof on a connection the server intends to close cannot safely
        # carry the later bearer; HTTPConnection would reconnect to whatever
        # process acquired the port. Require a live HTTP/1.1 channel.
        if response.status != 200 or response.version < 11 or response.will_close:
            connection.close()
            return None
        body = json.loads(raw.decode("utf-8"))
    except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError):
        connection.close()
        return None
    if not isinstance(body, dict) or body.get("ok") is not True:
        connection.close()
        return None
    instance_id = str(control_status.get("daemon_instance_id") or "")
    source_fp = str(control_status.get("source_fingerprint") or "")
    pid = control_status.get("pid")
    if not instance_id or not source_fp or not isinstance(pid, int):
        connection.close()
        return None
    if (
        body.get("daemon_instance_id") != instance_id
        or body.get("source_fingerprint") != source_fp
        or body.get("pid") != pid
        or body.get("ui_server_port") != int(server_port)
    ):
        connection.close()
        return None
    if not control_ipc.verify_ui_instance_proof(
        str(body.get("proof") or ""),
        secret,
        challenge=challenge,
        instance_id=instance_id,
        pid=pid,
        port=int(server_port),
        source_fingerprint=source_fp,
    ):
        connection.close()
        return None
    sock = connection.sock
    if sock is None:
        connection.close()
        return None
    try:
        peer = sock.getpeername()
    except OSError:
        connection.close()
        return None
    if not isinstance(peer, tuple) or peer[:2] != ("127.0.0.1", int(server_port)):
        connection.close()
        return None
    return connection


def _ui_status_on_verified_connection(
    connection: http.client.HTTPConnection,
    token: str,
) -> dict:
    """Fetch runtime identity without permitting HTTPConnection to reconnect.

    Dashboard status can enumerate the chunk cache and refresh OS hardware
    probes. Launcher authentication needs only the process/build/profile
    identity, so it must not wait for that unrelated work.
    """

    if connection.sock is None:
        return {"ok": False, "error": "verified UI connection is closed"}
    try:
        connection.request(
            "GET",
            "/api/runtime-identity",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if response.status != 200:
            return {"ok": False, "error": f"UI status HTTP {response.status}"}
        if len(raw) > 2 * 1024 * 1024:
            return {"ok": False, "error": "UI status response is oversized"}
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {
            "ok": False,
            "error": "UI status response is not an object",
        }
    except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}


def _runtime_matches_control(control_status: dict, ui_status: dict) -> bool:
    if ui_status.get("ok") is not True:
        return False
    control_me = control_status.get("me") or {}
    ui_me = ui_status.get("me") or {}
    control_fp = control_me.get("fingerprint")
    ui_fp = ui_me.get("fingerprint")
    if control_fp and ui_fp and control_fp != ui_fp:
        return False
    build = runtime_build_identity()
    return (
        ui_status.get("app_version") == control_status.get("app_version")
        and ui_status.get("daemon_instance_id")
        == control_status.get("daemon_instance_id")
        and ui_status.get("pid") == control_status.get("pid")
        and control_status.get("source_fingerprint")
        == build["source_fingerprint"]
        and ui_status.get("source_fingerprint")
        == build["source_fingerprint"]
    )


def resolve_authenticated_daemon(
    control_port: int,
    secret: str,
    *,
    timeout: float = 2.0,
) -> Optional[RunningDaemon]:
    """Resolve an explicit daemon/UI pair through both authentication layers."""

    ctrl = int(control_port)
    if not 1 <= ctrl <= 65535:
        return None
    operation_timeout = max(0.1, float(timeout))
    status = _control_request(
        ctrl,
        "status",
        timeout=operation_timeout,
        secret=secret,
    )
    if status.get("ok") is not True:
        return None
    srv = status.get("ui_server_port")
    if not isinstance(srv, int) or not 1 <= srv <= 65535:
        return None
    verified_connection = _open_verified_ui_instance(
        int(srv),
        status,
        secret=secret,
        timeout=operation_timeout,
    )
    if verified_connection is None:
        return None
    try:
        launch = _control_request(
            ctrl,
            "ui_launch_info",
            timeout=operation_timeout,
            secret=secret,
        )
        if (
            launch.get("ok") is not True
            or launch.get("ui_server_port") != srv
            or launch.get("daemon_instance_id") != status.get("daemon_instance_id")
            or launch.get("pid") != status.get("pid")
            or launch.get("source_fingerprint") != status.get("source_fingerprint")
        ):
            return None
        token = launch.get("token")
        if (
            not isinstance(token, str)
            or not 32 <= len(token) <= 512
            or token != token.strip()
        ):
            return None
        ui_status = _ui_status_on_verified_connection(verified_connection, token)
    finally:
        verified_connection.close()
    if not _runtime_matches_control(status, ui_status):
        return None
    nonce = launch.get("launch_nonce")
    if nonce is not None and (
        not isinstance(nonce, str) or not 32 <= len(nonce) <= 512 or nonce != nonce.strip()
    ):
        return None
    return RunningDaemon(ctrl, int(srv), token, status, launch_nonce=nonce)


def _resolve_running_daemon(*, timeout: float = 2.0) -> Optional[RunningDaemon]:
    """Return the reachable daemon plus its self-reported status.

    Side-effect-free: passes clear_stale=False so a poll during a
    daemon's boot never deletes the daemon's freshly-written
    control.port (which it writes once and never recreates)."""
    try:
        ctrl = daemon_mod.read_control_port(clear_stale=False)
        secret = control_ipc.read_control_secret()
    except RuntimeError:
        return None
    return resolve_authenticated_daemon(ctrl, secret, timeout=timeout)


def _wait_for_daemon(timeout: float = 45.0) -> Optional[RunningDaemon]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _resolve_running_daemon()
        if r is not None:
            return r
        time.sleep(0.15)
    return None


def _lock_pid() -> int | None:
    return daemon_mod._read_lock_pid()


def _terminate_pid(pid: int, timeout: float = 5.0) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    if os.name == "nt":
        # Console-less children can ignore SIGTERM on Windows. Last resort.
        try:
            taskkill = resolve_system_executable("taskkill.exe", platform_name="windows")
            result = subprocess.run(
                [taskkill, "/PID", str(int(pid)), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                creationflags=hidden_creationflags(),
                cwd=str(Path(taskkill).parent),
                env=trusted_process_env(platform_name="windows"),
                shell=False,
            )
            return result.returncode == 0
        except Exception:
            return False
    # SIGTERM timed out and this platform has no stronger fallback.
    return False


def _stop_running_daemon(info: RunningDaemon) -> bool:
    """Best-effort authenticated stop before a build or bind-mode change."""
    status = info.status or {}
    if status.get("ok") is not True:
        return False
    _control_request(info.control_port, "shutdown", timeout=2.0)
    deadline = time.time() + 6.0
    while time.time() < deadline:
        if not _alive(info.control_port):
            return True
        time.sleep(0.15)
    pid = status.get("pid")
    # ``RunningDaemon.status`` came from authenticated IPC and was cross-checked
    # against the HMAC-proven UI process. Never substitute the unauthenticated
    # lock file here: a stale/recycled daemon.lock PID could name an unrelated
    # process. Revalidate the authenticated PID against the live OS command line
    # immediately before any forceful fallback.
    if (
        type(pid) is not int
        or pid <= 0
        or not daemon_mod._pid_matches_one_link_daemon(pid)
    ):
        return False
    return _terminate_pid(pid)


def _stop_verified_legacy_daemon() -> bool | None:
    """Replace a pre-authentication daemon without trusting its socket.

    Clients never create ``control.secret``. Its absence plus a live lock PID
    whose command line and ``ONE_LINK_HOME`` are independently verified is the
    narrow upgrade case where an older daemon cannot understand the hardened
    handshake. Return ``True`` when stopped, ``False`` only when a verified
    legacy daemon could not be stopped, and ``None`` when there is no safely
    identifiable legacy process. A present/corrupt secret is never bypassed.
    """

    secret_path = data_dir() / control_ipc.CONTROL_SECRET_FILE
    if secret_path.exists() or secret_path.is_symlink():
        return None
    pid = _lock_pid()
    if not isinstance(pid, int) or pid <= 0 or not daemon_mod._pid_is_alive(pid):
        return None
    if not daemon_mod._pid_matches_one_link_daemon(pid):
        return None
    return _terminate_pid(pid)


DAEMON_LAUNCH_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB before rotation
DAEMON_LAUNCH_LOG_KEEP = 3                       # keep .log.1 .. .log.3


def _rotate_daemon_launch_log(log_path: Path) -> None:
    """Size-based rotation for ``daemon-launch.err.log``.

    The file is now opened in append mode (not truncate) so the
    forensic trail survives the launcher → supervisor → daemon
    restart chain. Without rotation that file would grow forever; a
    flapping daemon could produce gigabytes. We rotate to .log.1, .2,
    .3 (oldest dropped) when the active file crosses
    DAEMON_LAUNCH_LOG_MAX_BYTES. Best-effort; failures are non-fatal
    because we are on a startup path where producing a fresh log is
    only the second priority — getting the daemon up is the first.
    """
    try:
        if not log_path.exists():
            return
        if log_path.stat().st_size < DAEMON_LAUNCH_LOG_MAX_BYTES:
            return
    except OSError:
        return
    # Shift .N → .N+1, drop the oldest.
    for i in range(DAEMON_LAUNCH_LOG_KEEP, 0, -1):
        src = log_path.with_suffix(log_path.suffix + f".{i}")
        dst = log_path.with_suffix(log_path.suffix + f".{i + 1}")
        if src.exists():
            try:
                if i == DAEMON_LAUNCH_LOG_KEEP:
                    src.unlink()
                else:
                    src.replace(dst)
            except OSError:
                pass
    try:
        log_path.replace(log_path.with_suffix(log_path.suffix + ".1"))
    except OSError:
        pass


def _spawn_daemon() -> subprocess.Popen:
    """Spawn the daemon child. Redirects stderr to a known log file
    instead of DEVNULL so the desktop-shortcut launch path (pythonw
    no-console) leaves an inspectable trail when the daemon fails to
    come up. Without this trail the user sees "daemon failed to start
    cleanly" with no diagnostic — every operator support call ends up
    needing the daemon re-launched with `-v` from a terminal just to
    capture the error.

    The log is APPENDED to across launches (was previously truncated
    on every spawn, which silently deleted the supervisor's startup
    record + every prior restart's traceback). Size-based rotation at
    DAEMON_LAUNCH_LOG_MAX_BYTES keeps disk usage bounded; older
    rotations live next to it as ``daemon-launch.err.log.1`` ... .3.
    """
    log_path = data_dir() / "daemon-launch.err.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _rotate_daemon_launch_log(log_path)

    if getattr(sys, "frozen", False):
        daemon_cmd = [resolve_current_interpreter(), "daemon", "-v"]
    else:
        daemon_cmd = [
            resolve_current_interpreter(),
            "-P",
            "-m",
            "one_link.cli",
            "daemon",
            "-v",
        ]

    # Windows: the launcher (especially under PyInstaller --onefile and
    # when launched from a terminal that has its own Job Object) is
    # inside a Win32 Job Object that does NOT have
    # JOB_OBJECT_LIMIT_BREAKAWAY_OK set. That means a normal
    # subprocess.Popen with CREATE_BREAKAWAY_FROM_JOB is silently
    # ignored — the daemon stays in the parent's job and dies when
    # the launcher exits.
    #
    # The robust fix is to launch the daemon via the Windows shell,
    # which spawns the new process under explorer's tree (no shared
    # job). We use `cmd /c start "" /B exe daemon -v` then immediately
    # discover the resulting daemon PID by polling for the listen
    # socket / port file. This is the same technique GUI installers
    # use to start "fire and forget" background services.
    # PYTHONUNBUFFERED=1 — never lose the last 4 KiB of daemon stderr on
    # a crash. Without this, the child's stdout fd to daemon-launch.err.log
    # is block-buffered (~4 KiB); a final uncaught exception's traceback
    # gets queued in that buffer and dropped when the process exits
    # abruptly. We have lived through that exact symptom (silent
    # mid-conversation death, log ends with normal traffic, no
    # traceback) — line-flush mode for the child eliminates the entire
    # buffering-trap failure class.
    child_env = {**sanitized_process_env(), "PYTHONUNBUFFERED": "1"}
    if os.name == "nt":
        return _spawn_daemon_windows_detached(daemon_cmd, log_path, env=child_env)
    # POSIX: setsid() detaches from the controlling terminal and the
    # daemon survives the launcher exiting. No Job Object on Linux/mac.
    # Append (not truncate) so the supervisor's startup record + any
    # previous run's tail survive this spawn — rotation above keeps
    # disk usage bounded.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    return subprocess.Popen(
        daemon_cmd,
        stdout=subprocess.DEVNULL,
        stderr=(log_fh if log_fh is not None else subprocess.DEVNULL),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=child_env,
        cwd=str(Path(daemon_cmd[0]).parent),
        shell=False,
    )


def _spawn_supervisor() -> subprocess.Popen:
    """Spawn ``one-link supervisor`` instead of the daemon directly.

    The supervisor stays alive watching its child daemon, auto-
    restarting on crash with backoff + circuit breaker. From the
    launcher's perspective the two are interchangeable: both detach,
    both write to ``daemon-launch.err.log``, both surface on the
    same UI port. The difference is what happens on crash:

      * ``_spawn_daemon``     → crash = process gone, user reloads.
      * ``_spawn_supervisor`` → crash = automatic respawn, user's
        browser-side reconnect already covers the gap.

    Mirrors ``_spawn_daemon``'s frozen/source split and env exactly
    so the resulting process tree only differs by one CLI command
    name.
    """
    log_path = data_dir() / "daemon-launch.err.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _rotate_daemon_launch_log(log_path)
    if getattr(sys, "frozen", False):
        cmd = [resolve_current_interpreter(), "supervisor"]
    else:
        cmd = [
            resolve_current_interpreter(),
            "-P",
            "-m",
            "one_link.cli",
            "supervisor",
        ]
    child_env = {**sanitized_process_env(), "PYTHONUNBUFFERED": "1"}
    if os.name == "nt":
        return _spawn_daemon_windows_detached(cmd, log_path, env=child_env)
    # Append (not truncate) — see _spawn_daemon for the rationale.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=(log_fh if log_fh is not None else subprocess.DEVNULL),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=child_env,
        cwd=str(Path(cmd[0]).parent),
        shell=False,
    )


def _spawn_daemon_windows_detached(
    daemon_cmd: list[str], log_path: Path,
    *, env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """Spawn the daemon detached on Windows so it outlives the launcher.

    History: this used to write a .cmd file and invoke
    ``cmd /c start "" /B``. That `start` form mis-parsed the quoted
    interpreter path + ``-m`` args and returned "The system cannot find
    the path specified" (rc 1) — the daemon never launched, the log
    stayed empty, and a bare ``except: pass`` swallowed the failure, so
    the launcher waited out its full timeout and reported a false
    "daemon failed to start cleanly". This is the root cause of that bug.

    Now we spawn the interpreter DIRECTLY with detachment creation
    flags (verified reliable; no shell, no quoting hazard) and send the
    daemon's stdout+stderr to ``log_path`` so a real startup failure is
    actually diagnosable. We prefer full Job-Object breakaway (so the
    daemon survives a launcher in a kill-on-close job); if the parent
    job forbids breakaway we retry without it (still detaches from the
    console and survives a normal terminal/shortcut close)."""
    NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    BREAKAWAY = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
    if not daemon_cmd:
        raise ValueError("daemon command is empty")
    daemon_cmd = [resolve_explicit_executable(daemon_cmd[0]), *daemon_cmd[1:]]

    # Append, never truncate — preserves the launcher's full forensic
    # chain (supervisor lines + every prior daemon run) across this
    # spawn. _rotate_daemon_launch_log() caps size from the calling
    # _spawn_daemon / _spawn_supervisor.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    out = log_fh if log_fh is not None else subprocess.DEVNULL

    base = NO_WINDOW | DETACHED | NEW_GROUP
    last_err: Exception | None = None
    for flags in (base | BREAKAWAY, base):
        try:
            return subprocess.Popen(
                daemon_cmd,
                stdout=out,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
                close_fds=True,
                env=env,
                cwd=str(Path(daemon_cmd[0]).parent),
                shell=False,
            )
        except (OSError, ValueError) as e:
            # A restrictive Job Object can reject CREATE_BREAKAWAY_FROM_JOB
            # with "access denied"; drop the breakaway flag and retry. We
            # deliberately do not fall back to flags=0: that would reattach
            # the background daemon to a console/job and recreate the
            # inherited-session lifetime bug this function exists to avoid.
            last_err = e
            continue
    raise RuntimeError(
        f"could not spawn daemon subprocess: {last_err}"
    )


def _default_window_geometry() -> tuple[int, int, int, int]:
    """Return (width, height, x, y) for the desktop window.

    Compute 80% of the primary monitor size, clamped to a sensible
    max (1400x900 — bigger feels overwhelming on dense layouts),
    centered on screen. Falls back to 1280x800 at (120, 80) when
    the screen size can't be detected.
    """
    width, height = 1280, 800
    screen_w, screen_h = 0, 0
    if os.name == "nt":
        try:
            import ctypes
            user32 = ctypes.windll.user32
            # SM_CXSCREEN / SM_CYSCREEN — primary monitor pixels.
            screen_w = int(user32.GetSystemMetrics(0))
            screen_h = int(user32.GetSystemMetrics(1))
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            report_best_effort_failure(
                log,
                "windows_screen_geometry",
                exc,
                level=logging.DEBUG,
            )
    else:
        # tkinter is in the stdlib; cheap probe that works on
        # macOS / Linux without GUI libs.
        try:
            import tkinter as _tk
            root = _tk.Tk()
            root.withdraw()
            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            root.destroy()
        except Exception as exc:
            # tkinter can raise TclError at construction or any later display
            # query; importing it conditionally keeps headless installs valid.
            report_best_effort_failure(
                log,
                "tk_screen_geometry",
                exc,
                level=logging.DEBUG,
            )
    if screen_w >= 800 and screen_h >= 600:
        # 80% of screen, but clamp the max so on 4K monitors the
        # window stays at a reasonable read width.
        width = min(int(screen_w * 0.80), 1400)
        height = min(int(screen_h * 0.80), 900)
    x = max(0, (screen_w - width) // 2) if screen_w else 120
    y = max(0, (screen_h - height) // 2) if screen_h else 80
    return width, height, x, y


def _windows_known_folder(csidl: int) -> Path | None:
    """Read a Windows known folder through Shell32, never environment text."""

    if os.name != "nt":
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32_768)
        result = int(
            ctypes.windll.shell32.SHGetFolderPathW(
                None,
                int(csidl),
                None,
                0,
                buffer,
            )
        )
        path = Path(buffer.value)
        if result == 0 and path.is_absolute():
            return path
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return None


def _find_chromium_browser_exe() -> Optional[str]:
    """Locate Edge or Chrome on the local machine. Used by the
    standalone-window launcher: both browsers support ``--app=URL``
    which opens a Chromium tab in a frameless standalone window
    (no tabs, no URL bar) — the closest to "native desktop app"
    we can get without bundling a runtime.

    Returns the absolute path to the browser exe, or ``None`` if
    neither is found. Edge wins the tie because it's preinstalled
    on every Windows 10/11 machine.
    """
    if os.name == "nt":
        # CSIDL values: LOCAL_APPDATA=0x1c, PROGRAM_FILES=0x26,
        # PROGRAM_FILESX86=0x2a. Shell32 resolves redirects and architecture
        # correctly without trusting attacker-controlled environment values.
        program_files = _windows_known_folder(0x26)
        program_files_x86 = _windows_known_folder(0x2A)
        local_app_data = _windows_known_folder(0x1C)
        roots = tuple(
            root
            for root in (program_files_x86, program_files, local_app_data)
            if root is not None
        )
        relative_candidates = (
            ("Microsoft", "Edge", "Application", "msedge.exe"),
            ("Google", "Chrome", "Application", "chrome.exe"),
        )
        for relative in relative_candidates:
            for root in roots:
                try:
                    return resolve_explicit_executable(root.joinpath(*relative))
                except (OSError, ValueError):
                    continue
        return None
    # POSIX: fixed system directories only; never the caller's PATH/cwd.
    for name in ("microsoft-edge", "google-chrome", "chromium", "chrome"):
        for root in trusted_system_directories():
            try:
                return resolve_explicit_executable(root / name)
            except (OSError, ValueError):
                continue
    return None


def _is_existing_app_window_running(profile_dir: Path) -> bool:
    """Return True if the isolated One Link app-mode profile already owns
    a visible top-level browser window.

    Double-clicking the exe repeatedly should feel idempotent. Without this
    guard every launch asks Edge/Chrome for another ``--app`` window, and on
    Windows that looks like One Link is "popping up" on a timer when a user
    has clicked more than once or an external launcher retries.
    """
    if os.name != "nt":
        return False
    try:
        import subprocess as _subprocess

        ps = (
            "$profile = $args[0]; "
            "Get-CimInstance Win32_Process | "
            "Where-Object { "
            "  $_.Name -match '^(msedge|chrome)\\.exe$' -and "
            "  $_.CommandLine -like ('*--user-data-dir=' + $profile + '*') -and "
            "  $_.CommandLine -like '*--app=http://127.0.0.1:*' "
            "} | Select-Object -First 1 -ExpandProperty ProcessId"
        )
        powershell = resolve_system_executable(
            "powershell.exe",
            platform_name="windows",
        )
        res = _subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps,
                str(profile_dir),
            ],
            stdout=_subprocess.PIPE,
            stderr=_subprocess.DEVNULL,
            text=True,
            timeout=2.0,
            creationflags=hidden_creationflags(),
            check=False,
            cwd=str(Path(powershell).parent),
            env=trusted_process_env(platform_name="windows"),
            shell=False,
        )
        return bool(res.stdout.strip())
    except Exception:
        return False



#: One Link's own window, built from `native/ol_shell`. Absent in a source checkout that has not
#: built it; present in a release bundle.
SHELL_EXE = "ol_shell.exe" if sys.platform == "win32" else "ol_shell"

#: What the shell prints once the window AND the webview exist. "The process started" and "a window
#: opened" are different facts, and only the second one is worth falling back on.
SHELL_READY = "OL_SHELL_READY"

#: How long to wait for that line. A cold WebView2 first-run can take a few seconds; beyond this,
#: falling back beats a user staring at nothing.
SHELL_READY_TIMEOUT_S = 20.0


#: Set by the test suite so a run cannot open real windows on a developer's machine. NOT a
#: production switch: nothing in One Link sets it, and a user who set it would simply get the
#: browser path with the usual message. Tests that want the real shell unset it explicitly.
NO_SHELL_ENV = "ONE_LINK_NO_NATIVE_SHELL"


def _shell_path() -> Optional[Path]:
    """Where the native shell lives, or None.

    Beside the executable in a frozen bundle; under `native/ol_shell/target/release` in a source
    checkout, so a developer who has built it gets the real window too.
    """
    if os.environ.get(NO_SHELL_ENV):
        return None
    here = Path(getattr(sys, "_MEIPASS", "") or Path(sys.executable).parent)
    for candidate in (
        here / SHELL_EXE,
        here / "native" / SHELL_EXE,
        Path(__file__).resolve().parents[2] / "native" / "ol_shell" / "target" / "release" / SHELL_EXE,
    ):
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _package_root() -> Path:
    """The directory the shell verifies: where `web/index.html` and `data/certified/` live."""
    return Path(__file__).resolve().parent


#: Refusals that mean SOMETHING CHANGED YOUR INSTALL, as opposed to "this machine lacks a
#: webview runtime". The difference matters more to a user than to us: one is an inconvenience,
#: the other is the only warning they will ever get.
_SHELL_TAMPER_MARKERS = ("INTERFACE MODIFIED", "CERTIFIED SURFACE REFUSED", "SIGNATURE INVALID",
                         "DIGEST MISMATCH", "not a pinned signer")


def _report_shell_refusal(reason: str) -> None:
    """Tell the user WHY their own window would not open, and shout when it matters.

    THE GAP THIS CLOSES. The shell verifies the interface against a hash compiled into it and
    refuses to render one that was modified after install. That is the most serious thing this
    program can detect about itself -- and until now the user experience of it was *a browser
    opening instead*. Someone whose install had been tampered with would have seen a slightly
    different window and nothing else.

    A missing WebView2 runtime is an inconvenience and reads like one. Tampering is not, and must
    not be delivered in the same voice as a missing dependency.
    """
    text = reason or "no reason given"
    if any(marker in text for marker in _SHELL_TAMPER_MARKERS):
        _safe_echo("")
        _safe_echo("  " + "!" * 68)
        _safe_echo("  ONE LINK REFUSED TO OPEN ITS OWN WINDOW.")
        _safe_echo("")
        _safe_echo(f"  {text}")
        _safe_echo("")
        _safe_echo("  This means the interface or its proofs are NOT the ones that shipped.")
        _safe_echo("  Something changed them after installation. That is worth taking")
        _safe_echo("  seriously: reinstall One Link from a source you trust before using it.")
        _safe_echo("")
        _safe_echo("  Opening in a browser instead so you are not locked out -- but the same")
        _safe_echo("  modified interface will be served there.")
        _safe_echo("  " + "!" * 68)
        _safe_echo("")
        return
    _safe_echo(f"  native window unavailable ({text}); using the browser path")


def _shut_down_shell(proc: "subprocess.Popen[str]") -> None:
    """End a shell that will not be used, so a failed launch leaves nothing behind.

    Every caller is on a path that has already decided to fall back to the browser. A shell left
    running is either blocked forever on a URL it never got, or about to open a second window the
    user did not ask for. Best effort throughout: this runs while handling another failure, and
    must never be the thing that raises.
    """
    with contextlib.suppress(Exception):
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()


def _open_native_shell(url: str) -> bool:
    """Open One Link's own window. True if a window actually appeared.

    WHY THE URL GOES ON STDIN. It carries the single-use launch credential, and a command line is
    readable by any process running as the same user with no elevation — measured on Windows via
    `Win32_Process`. This is the same finding that produced the launch-nonce fix; the native shell
    is the first launch path that never puts the credential anywhere another process can read.

    WHY THIS RETURNS A BOOL RATHER THAN RAISING. A shell that cannot start is not an error the user
    should see as a crash — it is a downgrade to the browser path, and the caller announces it.
    """
    exe = _shell_path()
    if exe is None:
        return False
    try:
        proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, ValueError) as exc:
        _safe_echo(f"  (native window could not start: {exc})")
        return False

    # Popen types these as optional because they are only pipes when asked for. We DID ask, so this
    # should never fire — but reaching through a `None` here would raise `AttributeError` out of a
    # function whose whole contract is to return False and let the browser path take over. A crash
    # instead of a downgrade is exactly the failure this function exists to prevent.
    stdin, stdout, stderr = proc.stdin, proc.stdout, proc.stderr
    if stdin is None or stdout is None or stderr is None:
        _shut_down_shell(proc)
        _safe_echo("  (native window did not expose its pipes; using the browser path)")
        return False

    try:
        # Line 1: the URL with its single-use credential. Line 2: what to verify before drawing.
        # Line 3: the geometry the browser path already uses, so the window a user gets does not
        # depend on which launch path ran. These are logical pixels at both ends — the same numbers
        # Edge app-mode receives as `--window-size`, so the two paths open the same window.
        win_w, win_h, win_x, win_y = _default_window_geometry()
        stdin.write(f"{url}\n{_package_root()}\n{win_w} {win_h} {win_x} {win_y}\n")
        stdin.flush()
    except (OSError, ValueError) as exc:
        # The shell is blocked reading a URL it will now never receive. Left alone it waits forever,
        # so the downgrade to the browser path would silently leak a stuck process on every launch.
        _shut_down_shell(proc)
        _safe_echo(f"  (native window would not accept the launch URL: {exc})")
        return False

    deadline = time.time() + SHELL_READY_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            # It exited before opening a window. The shell writes its reason to stderr, and that
            # reason is the whole point: "INTERFACE MODIFIED" and "WebView2 runtime is not
            # installed" want very different responses from a user.
            reason = ""
            try:
                reason = (stderr.read() or "").strip().splitlines()[-1]
            except (OSError, ValueError, IndexError):
                pass
            _report_shell_refusal(reason)
            return False
        line = stdout.readline()
        if not line:
            continue
        if SHELL_READY in line:
            # The shell is now detached from this call: it owns its window, and it does NOT own the
            # daemon. Closing the window ends the shell and leaves peers reachable, which is the
            # behaviour One Link has always had and the reason this function does not wait on it.
            return True
    # It never said ready, so we are about to open the browser path. If the shell is merely slow it
    # would pop its own window afterwards and the user would be looking at TWO One Links. One window
    # per launch is the promise; enforcing it means ending the one that missed its deadline.
    _shut_down_shell(proc)
    _safe_echo("  native window did not report ready in time; using the browser path")
    return False


def _open_browser_url(url: str, *, standalone: bool = True) -> None:
    """Open ``url`` in the user's default browser, OR — when
    ``standalone`` is True (the default) — in a Chromium-style
    "app window" via ``msedge --app=URL`` / ``chrome --app=URL``.

    The app-mode flag tells the browser to:
    - drop the URL bar, tabs, and bookmark strip
    - open a single window with just the page content
    - use a separate process group so closing it doesn't take down
      other browser tabs

    Net visual effect: the user sees a One Link "desktop app" with
    just our UI — no browser chrome. Indistinguishable from a
    native app for everyday use.

    Falls back to the fixed OS browser launcher when no Chromium binary is
    found or the launch fails; ``$BROWSER`` is deliberately not honored.
    """
    url = validate_loopback_url(url)

    # ONE LINK'S OWN WINDOW FIRST. The app-mode path below is a real chromeless window, but it is
    # Edge's: it needs Edge installed, shows Edge in the process list, and puts the launch URL on a
    # command line. The native shell needs no browser, takes the credential on stdin, refuses to
    # render an interface whose hash does not match the one it was built against, and fences
    # navigation to loopback using a decision proven over every integer input.
    if standalone and _open_native_shell(url):
        return

    if standalone:
        browser = _find_chromium_browser_exe()
        if browser is not None:
            try:
                # --new-window guarantees a fresh window even if the
                # browser is already running; --app=URL is the
                # app-mode flag both Edge and Chrome accept.
                #
                # The extra flags suppress Edge's residual UI strip
                # (signin pill, first-run banner, default-browser
                # prompt) which otherwise renders as an empty gap
                # below the title bar. --user-data-dir isolates One
                # Link's Edge profile from the user's regular Edge
                # — no synced bookmarks, no extensions, no Microsoft
                # account, no "you already have this profile open"
                # conflicts when Edge is also open as a browser.
                profile_dir = data_dir() / "edge-app-profile"
                profile_dir.mkdir(parents=True, exist_ok=True)
                # Keep this launch path intentionally conservative. A
                # previous over-hardened flag set disabled a long list of
                # Edge/Chrome features and could make double-clicks look
                # dead on some Windows machines. These flags are the small
                # reliable set verified to open a visible isolated app
                # window while keeping One Link away from the user's normal
                # browser profile.
                # May 16 2026 — sensible default window size + position.
                # User reported "the app opens at half-view." Edge
                # --app= mode otherwise restores the LAST window
                # geometry from the isolated profile dir; on a fresh
                # profile that defaults to a small/awkward size. We
                # compute a window that's 80% of the primary screen
                # (clamped to 1400x900 max so on huge monitors the
                # window doesn't dominate) centered on screen.
                # Always make a user-triggered desktop launch visible.
                # A stale/minimized Edge app-mode process can still match
                # _is_existing_app_window_running(), which made double-clicks
                # look like One Link did nothing. Opening a fresh app window is
                # better than silently returning when the user explicitly
                # clicked the desktop app.
                win_w, win_h, win_x, win_y = _default_window_geometry()
                args = [
                    browser,
                    f"--app={url}",
                    "--new-window",
                    "--app-auto-launched",
                    f"--user-data-dir={profile_dir}",
                    "--window-name=One Link",
                    f"--window-size={win_w},{win_h}",
                    f"--window-position={win_x},{win_y}",
                    "--no-first-run",
                    "--no-default-browser-check",
                ]
                launch_explicit_command(args, platform_name=sys.platform)
                # 2026-06-04: Do NOT call os.startfile(url) as a
                # "fallback" after a successful Popen. Edge's
                # msedge.exe --app=URL launcher process detaches a
                # real Edge window into the existing edge.exe browser
                # process group then exits — so proc.poll() != None
                # within ~1 s is the NORMAL success path, not a
                # failure. The previous code treated that fast exit
                # as failure and ran os.startfile, which opened a
                # SECOND tab in the user's default browser on top of
                # the Chromium app-mode window. Result reported by
                # users on first-install: "two windows opened at
                # once." Popen raising is the only real failure
                # signal; if it didn't raise, the launch succeeded
                # and Edge/Chrome will surface the window in a
                # moment.
                return
            except (OSError, RuntimeError, ValueError) as exc:
                # Popen raised — Chromium really did fail to launch.
                # Fall through to default browser. User gets a tab
                # but at least sees something.
                report_best_effort_failure(
                    log,
                    "chromium_app_launch",
                    exc,
                    interval_s=30.0,
                )
    launch_loopback_url(url, platform_name=sys.platform)


def _detect_lan_ip() -> str:
    """v0.15.2 — best-effort LAN IPv4 detection. Opens a UDP socket
    and "connects" to a public address; the OS picks the right
    outbound interface but no packet is actually sent. Returns
    127.0.0.1 if there's no usable interface (e.g. airplane mode).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 8.8.8.8 is Google DNS — never actually contacted, just used
        # as a routing target so the OS picks the egress interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _safe_echo(*args, **kwargs) -> None:
    """Best-effort console output for GUI-packaged launchers."""
    try:
        click.echo(*args, **kwargs)
    except OSError:
        return


def _safe_secho(*args, **kwargs) -> None:
    try:
        click.secho(*args, **kwargs)
    except OSError:
        return


def _print_lan_warning(lan_ip: str, port: int) -> None:
    """Explain explicit LAN mode without printing an owner credential."""
    _safe_echo("")
    _safe_secho(
        "  ** LAN MODE - One Link UI is now exposed to your local network.",
        fg="yellow",
        bold=True,
    )
    _safe_echo(
        "     Owner access remains local/HTTPS-only; plain LAN HTTP never accepts "
        "owner credentials."
    )
    _safe_echo(
        "     Start phone pairing from the local One Link window so it uses a "
        "short-lived invite."
    )
    _safe_echo("")
    _safe_secho(
        f"  Phone pairing landing: http://{lan_ip}:{port}/connect",
        fg="cyan",
        bold=True,
    )
    _safe_echo("")


def _launch_log_says_already_running(log_path: Path) -> bool:
    """Tail-scan the launch log for the daemon's instance-lock
    rejection marker. Used by the friendly error dialog to swap in
    the focused "another One Link is running" copy instead of the
    generic "couldn't come up" message when that's what actually
    happened. Best-effort — missing file / unreadable bytes return
    False so we fall back to the generic copy.
    """
    try:
        with open(log_path, "rb") as fh:
            try:
                fh.seek(-4096, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    return "already running" in tail and "ONE_LINK_HOME" in tail


def _spawn_splash() -> Optional[subprocess.Popen]:
    """Open the native splash window the user sees while the daemon
    is coming up. Best-effort — if the splash subprocess can't
    spawn for any reason (no DISPLAY on Linux, broken tkinter, etc.)
    we return None and the launcher just proceeds without the splash.
    The splash watches its stdin pipe; closing the pipe (or this
    process exiting) makes it dismiss itself. No IPC protocol.
    """
    try:
        executable = resolve_current_interpreter()
        if getattr(sys, "frozen", False):
            cmd = [executable, "splash"]
        else:
            cmd = [executable, "-P", "-m", "one_link.splash"]
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=hidden_creationflags(),
            start_new_session=os.name != "nt",
            close_fds=True,
            env=sanitized_process_env(),
            cwd=str(Path(executable).parent),
            shell=False,
        )
    except Exception:
        return None


def _close_splash(proc: Optional[subprocess.Popen]) -> None:
    """Dismiss the splash. Closes its stdin so the watcher thread
    inside the splash sees EOF and tears down the tk root cleanly.
    Falls back to terminate() if the close+wait races a hung splash."""
    if proc is None:
        return
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except (OSError, ValueError) as exc:
            report_best_effort_failure(
                log, "splash_stdin_close", exc, level=logging.DEBUG,
            )
    try:
        proc.wait(timeout=2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    except (ChildProcessError, OSError) as exc:
        report_best_effort_failure(
            log, "splash_wait", exc, level=logging.DEBUG,
        )
    try:
        proc.terminate()
    except (OSError, ProcessLookupError) as exc:
        report_best_effort_failure(
            log, "splash_terminate", exc, level=logging.DEBUG,
        )


def run_app(
    *,
    no_browser: bool = False,
    standalone: bool = True,
    lan: bool = False,
    supervise: bool = False,
) -> int:
    # Splash window opens IMMEDIATELY — before any subprocess work —
    # so the user sees something the moment they double-click the
    # icon. Suppressed when --no-browser (headless launches, e.g.
    # autostart-at-boot) since there's nobody at the keyboard to
    # look at it. Failures spawning the splash are silently swallowed
    # — the launcher continues either way, the user just loses the
    # splash, no other harm done.
    splash_proc = None if no_browser else _spawn_splash()
    _safe_echo("One Link")
    # Bind policy is explicit and symmetric. The safe default is loopback;
    # --lan is a deliberate opt-in and --loopback-only also replaces a
    # previously LAN-bound daemon instead of silently reusing it.
    os.environ["ONE_LINK_BIND_HOST"] = (
        "0.0.0.0" if lan else "127.0.0.1"  # nosec B104
    )

    spawned: Optional[subprocess.Popen] = None
    info = _resolve_running_daemon()
    if info is None:
        # The control socket can appear a beat before the UI port/token are
        # published. Desktop shortcuts must treat that as "still starting",
        # not as permission to launch a competing daemon.
        info = _wait_for_daemon(timeout=2.0)

    if info is not None and info.compatible:
        is_lan_bound = _daemon_is_lan_bound(info)
        if is_lan_bound != bool(lan):
            mode = "LAN" if lan else "loopback-only"
            _safe_echo(f"  switching daemon to {mode} mode...")
            if not _stop_running_daemon(info):
                _close_splash(splash_proc)
                return 2
            # Give the OS a moment to release the listening socket so
            # the freshly-spawned daemon can rebind the well-known port.
            time.sleep(1.0)
            info = _wait_for_daemon(timeout=1.0)
            if info is not None and _daemon_is_lan_bound(info) != bool(lan):
                _close_splash(splash_proc)
                return 2

    if info is not None and not info.compatible:
        running = info.status.get("app_version") or "unknown"
        _safe_echo(f"  replacing stale daemon ({running} -> {__version__})...")
        _stop_running_daemon(info)
        info = _wait_for_daemon(timeout=1.0)
        if info is not None and not info.compatible:
            info = None

    if info is None:
        legacy_stop = _stop_verified_legacy_daemon()
        if legacy_stop is False:
            _safe_echo("  ! verified legacy daemon could not be stopped safely")
            _close_splash(splash_proc)
            return 2
        if legacy_stop is True:
            _safe_echo("  replaced legacy daemon with authenticated control IPC.")
            time.sleep(0.5)

    if info is None:
        # Spawn-and-wait, with one retry via the error dialog if the
        # daemon doesn't bind in time. The retry path covers the
        # transient cases (port still in TIME_WAIT from a previous
        # daemon, slow disk on first launch, antivirus scanning the
        # exe). Deterministic failures (corrupt install, missing dep)
        # fail both attempts and the user gets a friendly Quit.
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            if supervise:
                _safe_echo("  starting daemon under supervisor...")
                spawned = _spawn_supervisor()
            else:
                _safe_echo("  starting daemon...")
                spawned = _spawn_daemon()
            info = _wait_for_daemon()
            if info is not None and info.compatible:
                _safe_echo("  daemon up.")
                break
            _safe_echo("  ! daemon failed to start cleanly")
            try:
                spawned.terminate()
            except (OSError, ProcessLookupError) as exc:
                report_best_effort_failure(
                    log, "failed_spawn_terminate", exc, level=logging.DEBUG,
                )
            spawned = None
            # Don't let the splash sit behind the error dialog.
            _close_splash(splash_proc)
            splash_proc = None
            if no_browser or attempt >= max_attempts:
                # Headless caller (autostart at boot) gets no dialog —
                # they're not at the keyboard to see it. Also bail
                # silently after the last attempt; the error dialog
                # would have shown on the prior attempt.
                return 2
            # Show the friendly retry/quit dialog. ``choice`` is
            # either "retry" (loop again) or "quit" (bail clean).
            #
            # Specific case detection: if the launch log shows the
            # "already running" marker, the daemon couldn't acquire
            # the instance lock because ANOTHER One Link is alive on
            # this account. Retrying will hit the same wall. Show a
            # focused message instead of the generic "couldn't come
            # up" copy so the user knows exactly what to do.
            log_path = data_dir() / "daemon-launch.err.log"
            already_running = _launch_log_says_already_running(log_path)
            from one_link.error_dialog import show_startup_failure
            if already_running:
                reason = (
                    "Another One Link is already running for your "
                    "account — open the tray icon or the existing "
                    "browser tab to use it, or close it and then "
                    "click Try again to launch this version."
                )
            else:
                reason = (
                    "The background daemon couldn't come up within "
                    "the startup window. That's usually a transient "
                    "thing — another copy already running, a port "
                    "still releasing, or a slow disk on first launch."
                )
            choice = show_startup_failure(
                reason=reason,
                log_path=log_path,
                data_dir=data_dir(),
            )
            if choice != "retry":
                return 2
            # Reopen the splash for the retry attempt so the user
            # sees the same "Starting…" feedback as the first try.
            splash_proc = _spawn_splash()
    else:
        _safe_echo("  using running daemon.")

    # Reachable only via the loop's `break` (info is up) or the
    # already-running branch; every failure path above returns first.
    assert info is not None
    # THE CREDENTIAL THAT GOES IN THE URL IS THE NONCE, NOT THE TOKEN. This URL is handed
    # to `msedge.exe --app=...`, and a command line is readable by any same-user process
    # with no elevation (measured on Windows via Win32_Process). The nonce is single-use
    # and expires, so an argv snapshot is worthless a moment later.
    if info.launch_nonce:
        url = f"http://127.0.0.1:{info.server_port}/?t={info.launch_nonce}"
    else:
        # Cannot happen in a matched build -- `resolve_authenticated_daemon` refuses any
        # daemon whose `source_fingerprint` differs, so the daemon always speaks this
        # protocol. Kept as a LOUD degraded path rather than a silent fallback: putting
        # the long-lived token back on a command line is the exact defect this replaced,
        # and a fallback nobody can see is how it would return.
        _safe_echo(
            "  WARNING: the daemon minted no launch nonce; falling back to the "
            "long-lived token in the launch URL. It will be visible to any process "
            "running as you. Please report this -- it should be unreachable."
        )
        url = f"http://127.0.0.1:{info.server_port}/?t={info.token}"
    _safe_echo(f"  open: http://127.0.0.1:{info.server_port}/ (authenticated)")
    if not no_browser:
        try:
            _open_browser_url(url, standalone=standalone)
        except Exception as e:
            _safe_echo(f"  (couldn't auto-open browser: {e})")
    # Browser tab is open (or we deliberately skipped it). Dismiss
    # the splash now so the user's eye moves to the chat UI, not the
    # "Starting…" panel sitting on top of it.
    _close_splash(splash_proc)
    splash_proc = None

    if lan:
        lan_ip = _detect_lan_ip()
        if lan_ip == "127.0.0.1":
            _safe_secho(
                "  (could not detect a LAN IP — is Wi-Fi/Ethernet up?)",
                fg="yellow",
            )
        else:
            _print_lan_warning(lan_ip, info.server_port)

    if spawned is not None:
        # The daemon is fully detached — Windows: spawned through the
        # shell out of the launcher's Job Object; POSIX: setsid() so
        # closing the terminal does not kill it. It will keep running
        # after this launcher process exits, so paired peers stay
        # online and in-flight transfers complete. The launcher's job
        # is done: report status and exit. The UI window (browser /
        # webview) owns its own lifetime now.
        _safe_echo("\n  Daemon is running in the background.")
        _safe_echo("  Your peers stay online even if you close this window.")
        _safe_echo("  To stop the daemon explicitly: `one-link daemon-stop`")
    return 0
