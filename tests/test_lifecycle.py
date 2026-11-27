"""Daemon lifecycle: persistent UI token, fixed port, single-instance.

These tests target the "browser tab should survive a daemon restart"
property — the user-visible reason these matter.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import urllib.error
import urllib.request

import pytest


# The daemon's UI port discovery prefers the well-known range
# [7117, 7117+16) and falls back to an OS-assigned port only when EVERY
# slot is occupied (see server.py _start). On a dev box already running
# several daemons that range can be saturated, in which case binding a
# high port is the CORRECT behaviour, not a regression. These constants
# + probe let the port assertions verify the real contract: "prefer the
# well-known range when a slot is free."
_WELL_KNOWN_BASE = 7117
_WELL_KNOWN_SPAN = 16


def _well_known_range_has_free_slot(host: str = "127.0.0.1") -> bool:
    """True iff at least one port in the well-known UI range can be
    bound right now. A 0.0.0.0-bound rival on a port also blocks the
    matching 127.0.0.1 bind, so probing loopback correctly detects
    saturation regardless of how other daemons bound."""
    for candidate in range(_WELL_KNOWN_BASE, _WELL_KNOWN_BASE + _WELL_KNOWN_SPAN):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, candidate))
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


def _assert_well_known_or_saturated_fallback(port: int) -> None:
    """The daemon must land in the well-known range — unless that range
    was fully occupied, in which case an OS-assigned fallback port is
    correct. Only a non-well-known port WHILE a slot was free is a
    real port-discovery regression."""
    if _WELL_KNOWN_BASE <= port <= _WELL_KNOWN_BASE + _WELL_KNOWN_SPAN:
        return
    assert not _well_known_range_has_free_slot(), (
        f"daemon bound {port} outside the well-known range "
        f"[{_WELL_KNOWN_BASE}, {_WELL_KNOWN_BASE + _WELL_KNOWN_SPAN}] "
        f"while a well-known port was free — port-discovery regression"
    )
    assert port > 0, "daemon failed to bind any port"


def _assert_os_assigned(port: int) -> None:
    """ONE_LINK_UI_PORT=0: a real port, and not one from the well-known range."""
    assert 0 < port <= 65535, f"daemon published an impossible UI port {port}"
    assert not _WELL_KNOWN_BASE <= port <= _WELL_KNOWN_BASE + _WELL_KNOWN_SPAN, (
        f"daemon bound {port} in the well-known range although an OS-assigned port was requested"
    )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _control_request(
    port: int,
    cmd: str,
    *,
    home: Path,
    timeout: float = 5.0,
) -> dict:
    from one_link import control_ipc

    secret = control_ipc.read_control_secret(home / "data")
    return control_ipc.request_control(
        port,
        {"cmd": cmd},
        timeout=timeout,
        secret=secret,
    )


# The daemon and log behind each home, so a missing port file can say why.
_STARTED: dict[Path, tuple[subprocess.Popen, Path]] = {}


def _read_port(home: Path, name: str, timeout: float | None = None) -> int:
    """Wait for a port file; on failure say whether the daemon is alive and what it logged.

    A daemon that is slow to start logs which startup step it is in. A bare
    "port file did not appear" throws that away, and for a long time this
    intermittent failure on hosted Windows runners stayed unexplained.

    It is explained now, by that evidence. On 2026-11-27 a start took longer
    than the flat 12 s this helper waited: every start-up step in the daemon's
    log was slow, schema initialisation alone 8.1 s against 0.2 to 1.1 s on a
    workstation. That is the runner's load, which none of these tests is
    about, and the harness had already met and settled the same thing for its
    own wait (see ``daemon_boot_budget_s``). The default here is now that one
    budget. A daemon that never starts is still bounded, by it and by each
    test's timeout.
    """
    from tests.harness import _read_port as read_port_with_evidence
    from tests.harness import daemon_boot_budget_s

    proc, log = _STARTED.get(home, (None, None))
    wait = daemon_boot_budget_s() if timeout is None else timeout
    return read_port_with_evidence(home, name, wait, proc=proc, log=log)


def _read_text(
    home: Path,
    name: str,
    timeout: float = 12.0,
    *,
    different_from: str | None = None,
) -> str:
    p = home / "data" / name
    end = time.time() + timeout
    while time.time() < end:
        if p.exists():
            try:
                t = p.read_text(encoding="utf-8").strip()
                if t and t != different_from:
                    return t
            except OSError:
                pass
        time.sleep(0.1)
    raise RuntimeError(f"file did not appear: {p}")


def _owner_api_status(port: int, token: str) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code)


def _spawn_daemon(home: Path, log: Path, *, ui_port: str | None = "0") -> subprocess.Popen:
    """Start a real daemon. ``ui_port`` is its ONE_LINK_UI_PORT; None leaves the variable unset.

    The default is an OS-assigned port, so a test daemon never takes the
    product's well-known UI port on a machine that also runs a real one. Only
    the test of the default port policy passes None.
    """
    # Live-daemon lane only: skip in the default hermetic gate.
    from tests.harness import private_mdns_type, require_live_daemon

    require_live_daemon()
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    if ui_port is None:
        env.pop("ONE_LINK_UI_PORT", None)
    else:
        env["ONE_LINK_UI_PORT"] = ui_port
    # Private mDNS scope so this daemon never cross-discovers ambient
    # daemons on the LAN while the lifecycle test exercises port/token.
    env["ONE_LINK_MDNS_SERVICE_TYPE"] = private_mdns_type()
    log.parent.mkdir(parents=True, exist_ok=True)
    # CREATE_NEW_PROCESS_GROUP is load-bearing: teardown delegates to the
    # harness _stop, whose Windows graceful path is CTRL_BREAK_EVENT --
    # and a break event aimed at a non-group-leader broadcasts to the
    # ENTIRE console, putting a CI pwsh step host into its debugger.
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=open(log, "wb"),
        stderr=subprocess.STDOUT,
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        ),
    )
    proc._one_link_new_process_group = os.name == "nt"  # type: ignore[attr-defined]
    _STARTED[home] = (proc, log)
    return proc


def _stop(proc: subprocess.Popen, *, home: Path) -> None:
    # Reuse the authenticated exact-home process-tree cleanup used by every
    # other live-daemon test. A Windows venv launcher PID is not necessarily
    # the interpreter PID that owns One Link's sockets.
    from tests.harness import _stop as stop_harness_daemon

    stop_harness_daemon(proc, home=home)


def test_stale_runtime_publication_is_removed_without_following_paths(
    tmp_path: Path,
) -> None:
    from one_link.server import _remove_stale_runtime_publication

    publication = tmp_path / "ui.token"
    publication.write_text("stale", encoding="ascii")
    _remove_stale_runtime_publication(publication, label="test token")
    assert not publication.exists()

    publication.mkdir()
    with pytest.raises(RuntimeError, match="is a directory"):
        _remove_stale_runtime_publication(publication, label="test token")
    assert publication.is_dir()


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_owner_bootstrap_token_rotates_across_daemon_restart():
    """A bearer leaked by an old plaintext cookie dies on restart."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_lifecycle_"))
    try:
        home = tmp / "H"
        home.mkdir()
        log1 = tmp / "1.log"
        log2 = tmp / "2.log"

        proc = _spawn_daemon(home, log1)
        try:
            token1 = _read_text(home, "ui.token")
            port1 = _read_port(home, "server.port")
            assert len(token1) >= 32
            _assert_os_assigned(port1)
        finally:
            _stop(proc, home=home)

        # Restart cleanly
        time.sleep(0.4)
        proc2 = _spawn_daemon(home, log2)
        try:
            token2 = _read_text(home, "ui.token", different_from=token1)
            port2 = _read_port(home, "server.port")
            assert token2 != token1, (
                f"owner bootstrap token survived restart: {token1!r}"
            )
            assert _owner_api_status(port2, token1) == 401
            assert _owner_api_status(port2, token2) == 200
        finally:
            _stop(proc2, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _bootstrap_browser_bearer(port: int, token: str) -> tuple[str, bool]:
    """Load the owner page as a window does; return (the bearer it is given, persisted?)."""
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/?t={token}", timeout=10.0) as response:
        page = response.read().decode("utf-8", errors="replace")
    match = re.search(r'const b=("[^"]*");const persist=(true|false);', page)
    assert match, "the owner page no longer carries the bootstrap bearer script"
    return json.loads(match.group(1)), match.group(2) == "true"


@pytest.mark.live_daemon
@pytest.mark.timeout(240)
def test_a_browser_session_survives_daemon_restarts():
    """The other half of the test above: the owner token dies with the process,
    and the browser session a window is given does NOT.

    From 2026-07-25 to 2026-11-25 it did. The schema runner re-applied the
    one-way session-key migration on every start, so each restart (each
    update) signed every open window out, and no test restarted a daemon with
    a session to notice. Two restarts here, because the damage compounded: a
    session that survives one could still be lost on the next.
    """
    tmp = Path(tempfile.mkdtemp(prefix="ol_lifecycle_"))
    try:
        home = tmp / "H"
        home.mkdir()

        proc = _spawn_daemon(home, tmp / "0.log")
        try:
            owner_token = _read_text(home, "ui.token")
            port = _read_port(home, "server.port")
            bearer, persisted = _bootstrap_browser_bearer(port, owner_token)
            assert persisted, "a default install no longer gives its window a persistent session"
            assert bearer != owner_token, "the window was handed the process owner token"
            assert re.fullmatch("[0-9a-f]{64}", bearer)
            assert _owner_api_status(port, bearer) == 200
        finally:
            _stop(proc, home=home)

        for restart in (1, 2):
            time.sleep(0.4)
            proc = _spawn_daemon(home, tmp / f"{restart}.log")
            try:
                previous_owner_token = owner_token
                owner_token = _read_text(home, "ui.token", different_from=previous_owner_token)
                port = _read_port(home, "server.port")
                assert _owner_api_status(port, bearer) == 200, (
                    f"restart {restart} signed the browser session out"
                )
                # The rule the neighbouring test pins still holds beside it.
                assert _owner_api_status(port, previous_owner_token) == 401
            finally:
                _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_ui_port_is_in_well_known_range():
    """The daemon must prefer the well-known range when a slot is free.
    When the range is saturated by other daemons, an OS-assigned
    fallback port is correct (the daemon must still start).

    This is the product's default policy, so it is the one live test that
    leaves ONE_LINK_UI_PORT unset and lets a test daemon take a well-known
    port, for the seconds this test runs."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_port_"))
    try:
        home = tmp / "H"
        home.mkdir()
        log = tmp / "out.log"

        proc = _spawn_daemon(home, log, ui_port=None)
        try:
            port = _read_port(home, "server.port")
            _assert_well_known_or_saturated_fallback(port)
        finally:
            _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_ui_port_zero_gives_a_real_daemon_an_os_assigned_port():
    """ONE_LINK_UI_PORT=0: the daemon serves its owner API on a port outside the well-known range."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_port0_"))
    try:
        home = tmp / "H"
        home.mkdir()
        proc = _spawn_daemon(home, tmp / "out.log", ui_port="0")
        try:
            port = _read_port(home, "server.port")
            _assert_os_assigned(port)
            assert _owner_api_status(port, _read_text(home, "ui.token")) == 200
        finally:
            _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_ui_port_exact_is_bound_exactly_by_a_real_daemon():
    """ONE_LINK_UI_PORT=N: the daemon serves on N and nowhere else."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_portn_"))
    try:
        home = tmp / "H"
        home.mkdir()
        wanted = _free_loopback_port()
        proc = _spawn_daemon(home, tmp / "out.log", ui_port=str(wanted))
        try:
            assert _read_port(home, "server.port") == wanted
            assert _owner_api_status(wanted, _read_text(home, "ui.token")) == 200
        finally:
            _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(90)
def test_ui_port_in_use_stops_a_real_daemon_instead_of_moving_it():
    """An exact port that is taken is a startup failure: no fallback port, no headless daemon."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_portbusy_"))
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        home = tmp / "H"
        home.mkdir()
        log = tmp / "out.log"
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        taken = int(holder.getsockname()[1])
        proc = _spawn_daemon(home, log, ui_port=str(taken))
        try:
            try:
                code = proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                pytest.fail("the daemon kept running although its exact UI port was taken")
            assert code != 0, "the daemon reported success without its UI port"
            assert not (home / "data" / "server.port").exists(), "a UI port was published anyway"
            assert "ONE_LINK_UI_PORT" in log.read_text(encoding="utf-8", errors="replace")
        finally:
            _stop(proc, home=home)
    finally:
        holder.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_control_status_and_shutdown_contract(monkeypatch):
    """The launcher depends on status/shutdown to self-heal stale daemons."""
    from one_link import __version__

    tmp = Path(tempfile.mkdtemp(prefix="ol_lifecycle_status_"))
    try:
        home = tmp / "H"
        home.mkdir()
        monkeypatch.setenv("ONE_LINK_HOME", str(home))
        proc = _spawn_daemon(home, tmp / "out.log")
        try:
            ctrl = _read_port(home, "control.port")
            ui_port = _read_port(home, "server.port")
            status = _control_request(ctrl, "status", home=home)
            assert status["ok"] is True
            assert status["app_version"] == __version__
            # On Windows a virtual-environment ``python.exe`` launcher can be
            # the Popen process while the interpreter that owns the sockets is
            # its child.  The HMAC-authenticated control status, exact data
            # home, and OS process inspection are the security contract; PID
            # equality with the launcher stub is not.
            daemon_pid = status["pid"]
            assert type(daemon_pid) is int and daemon_pid > 0
            assert Path(status["home"]).resolve() == (home / "data").resolve()
            from one_link import daemon as daemon_module
            assert daemon_module._pid_matches_one_link_daemon(daemon_pid)
            assert status["schema_version"] >= 1
            assert status["protocol_version"]
            assert isinstance(status["ui_server_port"], int)
            assert status["ui_server_port"] == ui_port

            # The launcher's production path is _wait_for_daemon -- a retry
            # loop around the single-shot 2-second probe. Asserting on one
            # bare probe made this red whenever a loaded CI runner missed a
            # single 2s window (observed at the 97% mark of a 71-minute
            # suite, with the daemon demonstrably answering status right
            # before). Exercise the contract the launcher actually relies on.
            from one_link.app import _wait_for_daemon

            resolved = _wait_for_daemon(timeout=30.0)
            assert resolved is not None
            assert resolved.control_port == ctrl
            assert resolved.server_port == ui_port
            assert resolved.status["daemon_instance_id"] == status["daemon_instance_id"]

            shutdown = _control_request(ctrl, "shutdown", home=home)
            assert shutdown == {"ok": True, "stopping": True}
            proc.wait(timeout=10)
            assert proc.poll() is not None
        finally:
            _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_harness_stop_reaps_serving_interpreter_and_launcher():
    """Teardown must not leak the socket-owning child behind a venv launcher."""
    import psutil

    tmp = Path(tempfile.mkdtemp(prefix="ol_harness_stop_"))
    home = tmp / "H"
    home.mkdir()
    proc = _spawn_daemon(home, tmp / "out.log")
    stopped = False
    try:
        ctrl = _read_port(home, "control.port")
        _read_port(home, "server.port")
        status = _control_request(ctrl, "status", home=home)
        daemon_pid = status["pid"]
        assert type(daemon_pid) is int and daemon_pid > 0
        assert psutil.pid_exists(daemon_pid)

        _stop(proc, home=home)
        stopped = True

        assert proc.poll() is not None
        assert not psutil.pid_exists(daemon_pid)
        assert not (home / "data" / "control.port").exists()
        assert not (home / "data" / "server.port").exists()
        assert not (home / "data" / "ui.token").exists()
    finally:
        if not stopped:
            _stop(proc, home=home)
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)


def test_launcher_rejects_unknown_or_mismatched_daemon():
    from one_link import __version__
    from one_link.app import RunningDaemon
    from one_link.build_identity import runtime_build_identity

    _bid = runtime_build_identity()
    good = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={
            "ok": True,
            "app_version": __version__,
            "source_fingerprint": _bid["source_fingerprint"],
            "protocol_version": "OL1.2",
            "schema_version": 5,
        },
    )
    old = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={
            "ok": True,
            "app_version": "0.1.0",
            "protocol_version": "OL1.2",
            "schema_version": 5,
        },
    )
    unknown = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={"ok": False, "error": "unknown cmd"},
    )
    assert good.compatible is True
    assert old.compatible is False
    assert unknown.compatible is False


def test_launcher_rejects_ui_that_does_not_match_control_identity():
    from one_link import __version__
    from one_link.app import _runtime_matches_control
    from one_link.build_identity import runtime_build_identity

    _sf = runtime_build_identity()["source_fingerprint"]
    control = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }
    matching_ui = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }
    wrong_identity = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "bb" * 32},
    }
    wrong_version = {
        "ok": True,
        "app_version": "0.0.1",
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }

    assert _runtime_matches_control(control, matching_ui) is True
    assert _runtime_matches_control(control, wrong_identity) is False
    assert _runtime_matches_control(control, wrong_version) is False
    assert _runtime_matches_control(control, {"ok": False}) is False


def test_launcher_uses_hardened_loopback_url_open(monkeypatch):
    """Fallback never delegates executable selection to ``$BROWSER``."""
    from one_link import app as app_mod

    opened = []

    monkeypatch.setattr(
        app_mod,
        "launch_loopback_url",
        lambda url, **_kwargs: opened.append(url),
    )
    monkeypatch.setattr(app_mod, "_find_chromium_browser_exe", lambda: None)
    # The launch ladder gained a rung above these: One Link's own window (§10.4). This test is
    # about the LAST rung -- the plain browser open -- so every rung above it must be disabled,
    # or the assertion below passes only on machines where the shell was never built.
    monkeypatch.setattr(app_mod, "_shell_path", lambda: None)

    app_mod._open_browser_url("http://127.0.0.1:7117/?t=test")

    assert opened == ["http://127.0.0.1:7117/?t=test"]


def test_launcher_prefers_control_reported_ui_port(monkeypatch):
    from one_link import __version__
    from one_link import app as app_mod
    from one_link.build_identity import runtime_build_identity

    _sf = runtime_build_identity()["source_fingerprint"]
    # read_control_port now takes clear_stale (the launcher's detection
    # poll passes clear_stale=False so it never deletes a booting
    # daemon's control.port). The mock must accept it.
    monkeypatch.setattr(
        app_mod.daemon_mod, "read_control_port",
        lambda clear_stale=True: 43210,
    )
    monkeypatch.setattr(
        app_mod,
        "_alive",
        lambda port, **_kwargs: port == 43210,
    )
    monkeypatch.setattr(
        app_mod.control_ipc,
        "read_control_secret",
        lambda: "authenticated-control-secret",
    )
    verified_connection = type(
        "VerifiedConnection",
        (),
        {"close": lambda self: None},
    )()
    monkeypatch.setattr(
        app_mod,
        "_open_verified_ui_instance",
        lambda *a, **kw: verified_connection,
    )
    monkeypatch.setattr(
        app_mod,
        "_control_request",
        lambda _port, cmd, **_kwargs: (
            {
                "ok": True,
                "ui_server_port": 7999,
                "token": "t" * 32,
                "daemon_instance_id": "instance-1",
                "pid": 99,
                "source_fingerprint": _sf,
            }
            if cmd == "ui_launch_info"
            else {
                "ok": True,
                "app_version": __version__,
                "source_fingerprint": _sf,
                "protocol_version": "OL1.2",
                "schema_version": 16,
                "ui_server_port": 7999,
                "daemon_instance_id": "instance-1",
                "pid": 99,
                "me": {"fingerprint": "cc" * 32},
            }
        ),
    )
    monkeypatch.setattr(
        app_mod,
        "_ui_status_on_verified_connection",
        lambda connection, token: {
            "ok": connection is verified_connection and token == "t" * 32,
            "app_version": __version__,
            "source_fingerprint": _sf,
            "daemon_instance_id": "instance-1",
            "pid": 99,
            "me": {"fingerprint": "cc" * 32},
        },
    )

    info = app_mod._resolve_running_daemon()

    assert info is not None
    assert info.server_port == 7999


@pytest.mark.live_daemon
@pytest.mark.timeout(60)
def test_corrupt_token_file_is_replaced_safely():
    """If the persisted token file is garbage, daemon generates a fresh one
    rather than using the unsafe short value."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_corrupt_"))
    try:
        home = tmp / "H"
        (home / "data").mkdir(parents=True)
        # Pre-seed a too-short / unsafe token
        (home / "data" / "ui.token").write_text("xx")
        log = tmp / "out.log"
        proc = _spawn_daemon(home, log)
        try:
            # Wait for full startup — server.port is written at end of UIServer.start().
            _read_port(home, "server.port")
            # Daemon writes server.port and ui.token in quick succession; small
            # margin ensures the new token has fully landed on disk.
            time.sleep(0.2)
            token = (home / "data" / "ui.token").read_text(encoding="utf-8").strip()
            assert len(token) >= 32, f"daemon kept unsafe short token: {token!r}"
        finally:
            _stop(proc, home=home)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_load_or_create_token_unit(monkeypatch, tmp_path):
    """Unit test the token logic directly.

    2026-05-22 audit Batch X: use ``monkeypatch.setenv`` instead of
    mutating ``os.environ`` directly + try/finally pop. Under
    pytest-xdist the bare mutation surfaces as flakiness on
    unrelated tests if a process is interrupted between set and pop.
    """
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # First call: no file → generates fresh.
    from one_link.paths import data_dir
    token_path = data_dir() / "ui.token"
    if token_path.exists():
        token_path.unlink()

    t1 = UIServer._load_or_create_token()
    assert len(t1) >= 32
    # Second call: still no file written (token is only persisted on
    # daemon start). Each call returns a fresh one.
    t2 = UIServer._load_or_create_token()
    assert len(t2) >= 32

    # Even a syntactically valid prior-process token is not authority for this
    # process. This invalidates host-wide cookies planted by old releases.
    token_path.write_text("a" * 50)
    t3 = UIServer._load_or_create_token()
    assert t3 != "a" * 50
    assert len(t3) >= 32
    assert len({t1, t2, t3}) == 3

    # Corrupt token: too short → fresh one generated
    token_path.write_text("nope")
    t4 = UIServer._load_or_create_token()
    assert t4 != "nope"
    assert len(t4) >= 32

    # Corrupt token: invalid chars → fresh one generated
    token_path.write_text("a" * 40 + "\n!@#$")
    t5 = UIServer._load_or_create_token()
    assert "!" not in t5
    assert len(t5) >= 32
