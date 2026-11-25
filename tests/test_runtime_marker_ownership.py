"""Runtime discovery is read-only; marker retirement requires instance ownership."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from one_link import control_ipc, daemon as daemon_mod


@pytest.fixture
def runtime_data(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    return daemon_mod.data_dir()


def _publish_hints(data: Path, value: str = "43117") -> dict[Path, bytes]:
    paths = [data / name for name in ("control.port", "peer.port", "server.port", "ui.token")]
    for path in paths:
        daemon_mod._publish_runtime_ascii_scalar(path, value)
    return {path: path.read_bytes() for path in paths}


def _assert_preserved(snapshot: dict[Path, bytes]) -> None:
    assert {path: path.read_bytes() for path in snapshot} == snapshot


def _lock_owner():
    owner = object.__new__(daemon_mod.Daemon)
    owner._lock_file = None
    owner._runtime_lifecycle = None
    owner._acquire_instance_lock()
    owner._runtime_lifecycle = daemon_mod._begin_runtime_lifecycle()
    return owner


@pytest.mark.parametrize("lock_value", [None, b"unreadable", b"99999999", b"malformed"])
@pytest.mark.parametrize("port_value", [b"43117", b"not-a-port", b"9" * 65, b"\xff"])
def test_failed_reader_preserves_all_runtime_publications(
    runtime_data, monkeypatch, lock_value, port_value,
):
    snapshot = _publish_hints(runtime_data)
    port_path = runtime_data / "control.port"
    port_path.write_bytes(port_value)
    snapshot[port_path] = port_value
    lock_path = runtime_data / daemon_mod.DAEMON_LOCK_FILE
    if lock_value is not None:
        lock_path.write_bytes(lock_value)
        snapshot[lock_path] = lock_value
    original_reader = daemon_mod._read_runtime_ascii_scalar

    def read_scalar(path, **kwargs):
        if path == lock_path and lock_value == b"unreadable":
            raise PermissionError(13, "Windows byte range is locked")
        return original_reader(path, **kwargs)

    monkeypatch.setattr(daemon_mod, "_read_runtime_ascii_scalar", read_scalar)
    monkeypatch.setattr(daemon_mod, "is_daemon_alive", lambda _port: False)
    with pytest.raises(RuntimeError, match="(?:bad|stale) control.port"):
        daemon_mod.read_control_port()
    _assert_preserved(snapshot)
    if lock_value is None:
        assert not lock_path.exists()


def _permission_locked_hint(monkeypatch, runtime_data):
    lock_path = runtime_data / daemon_mod.DAEMON_LOCK_FILE
    lock_path.write_text(str(os.getpid()), encoding="ascii")
    original_reader = daemon_mod._read_runtime_ascii_scalar

    def read_scalar(path, **kwargs):
        if path == lock_path:
            raise PermissionError(13, "Windows byte range is locked")
        return original_reader(path, **kwargs)

    monkeypatch.setattr(daemon_mod, "_read_runtime_ascii_scalar", read_scalar)


@pytest.mark.parametrize("lock_value", [None, "", "bad", "0", "-1", "4294967296", "9" * 65])
def test_missing_or_malformed_lock_never_enables_lifecycle_scan(
    runtime_data, monkeypatch, lock_value,
):
    daemon_mod._begin_runtime_lifecycle()
    if lock_value is not None:
        (runtime_data / daemon_mod.DAEMON_LOCK_FILE).write_text(lock_value, encoding="ascii")

    def unexpected_scan(*_args):
        pytest.fail("missing or malformed lock evidence enabled a port scan")

    monkeypatch.setattr(daemon_mod, "_candidate_control_ports_for_pid", unexpected_scan)
    monkeypatch.setattr(daemon_mod, "_candidate_local_listen_ports", unexpected_scan)
    assert daemon_mod._recover_control_port_from_live_pid() is None


@pytest.mark.parametrize("record", [
    b"{", b"[]", b"9" * 4097, b"\xff", b"[" * 1100 + b"]" * 1100,
    b'{"schema":1,"run_id":"00000000000000000000000000000000","pid":true,"started_ns":1}',
    b'{"schema":1,"run_id":"not-a-run","pid":1,"started_ns":1}',
])
def test_unreadable_lock_and_malformed_lifecycle_fail_closed(
    runtime_data, monkeypatch, record,
):
    _permission_locked_hint(monkeypatch, runtime_data)
    (runtime_data / daemon_mod.LIFECYCLE_FILE).write_bytes(record)
    monkeypatch.setattr(
        daemon_mod, "_candidate_control_ports_for_pid",
        lambda _pid: pytest.fail("malformed lifecycle enabled a port scan"),
    )
    assert daemon_mod._recover_control_port_from_live_pid() is None
    assert (runtime_data / daemon_mod.LIFECYCLE_FILE).read_bytes() == record


@pytest.mark.parametrize("status_delta", [
    {"ok": False}, {"pid": 0}, {"pid": True}, {"pid": "1"},
    {"pid": os.getpid() + 1}, {"home": "different-profile"},
])
def test_lifecycle_hint_requires_exact_authenticated_pid_and_home(
    runtime_data, monkeypatch, status_delta,
):
    _permission_locked_hint(monkeypatch, runtime_data)
    daemon_mod._begin_runtime_lifecycle()
    status = {"ok": True, "pid": os.getpid(), "home": str(runtime_data), **status_delta}
    monkeypatch.setattr(daemon_mod, "_candidate_control_ports_for_pid", lambda _pid: [43117])
    monkeypatch.setattr(daemon_mod, "query_control_status", lambda *_args, **_kwargs: status)
    assert daemon_mod._recover_control_port_from_live_pid() is None
    assert not (runtime_data / "control.port").exists()


def test_recovery_returns_authenticated_port_without_overwriting_successor(
    runtime_data, monkeypatch,
):
    _permission_locked_hint(monkeypatch, runtime_data)
    daemon_mod._begin_runtime_lifecycle()
    monkeypatch.setattr(daemon_mod, "_candidate_control_ports_for_pid", lambda _pid: [43117])
    successor = {}

    def authenticated_response(_port, **_kwargs):
        # The successor publishes after the reader selected its old PID/port.
        # Even a final exists()/lifecycle check before replace would race.
        daemon_mod._begin_runtime_lifecycle()
        successor.update(_publish_hints(runtime_data, "43118"))
        return {"ok": True, "pid": os.getpid(), "home": str(runtime_data)}

    monkeypatch.setattr(daemon_mod, "query_control_status", authenticated_response)
    assert daemon_mod._recover_control_port_from_live_pid() == 43117
    _assert_preserved(successor)


def test_recovery_limits_candidate_count_and_probe_start_window(runtime_data, monkeypatch):
    (runtime_data / daemon_mod.DAEMON_LOCK_FILE).write_text(str(os.getpid()), encoding="ascii")
    monkeypatch.setattr(daemon_mod, "_candidate_control_ports_for_pid", lambda _pid: list(range(1, 201)))
    observed = []

    def no_response(port, *, timeout):
        observed.append((port, timeout))
        return {}

    monkeypatch.setattr(daemon_mod, "query_control_status", no_response)
    monkeypatch.setattr(daemon_mod.time, "monotonic", lambda: 100.0)
    assert daemon_mod._recover_control_port_from_live_pid() is None
    assert len(observed) == daemon_mod._CONTROL_RECOVERY_MAX_CANDIDATES
    assert all(timeout == 0.75 for _port, timeout in observed)

    observed.clear()
    clock = iter([100.0, 100.0, 104.5, 105.1])
    monkeypatch.setattr(daemon_mod.time, "monotonic", lambda: next(clock))
    assert daemon_mod._recover_control_port_from_live_pid() is None
    assert observed == [(1, 0.75), (2, 0.5)]


@pytest.mark.parametrize("ownership_change", ["released", "closed", "different_lifecycle", "malformed_lifecycle"])
def test_retirement_requires_open_owner_and_matching_lifecycle(
    runtime_data, ownership_change,
):
    predecessor = _lock_owner()
    try:
        if ownership_change == "released":
            predecessor._release_instance_lock()
        elif ownership_change == "closed":
            predecessor._lock_file.close()
        elif ownership_change == "different_lifecycle":
            daemon_mod._begin_runtime_lifecycle()
        else:
            (runtime_data / daemon_mod.LIFECYCLE_FILE).write_text("{}", encoding="ascii")
        snapshot = _publish_hints(runtime_data, "43118")
        predecessor._retire_runtime_publications()
        _assert_preserved(snapshot)
        assert not (runtime_data / daemon_mod.CLEAN_SHUTDOWN_FILE).exists()
    finally:
        if predecessor._lock_file is not None and predecessor._lock_file.closed:
            predecessor._lock_file = None
        predecessor._release_instance_lock()


@pytest.mark.asyncio
async def test_run_retires_before_unlock_and_preserves_successor_publications(
    runtime_data, monkeypatch,
):
    predecessor = None
    successor = None
    publications = {}
    original_release = daemon_mod.Daemon._release_instance_lock

    async def no_network_start(self):
        nonlocal predecessor
        predecessor = self
        assert self._lock_file is not None
        self._runtime_lifecycle = daemon_mod._begin_runtime_lifecycle()
        publications.update(_publish_hints(runtime_data))

    async def no_network_serve(_self):
        return None

    def release_then_publish_successor(self):
        nonlocal successor
        if self is predecessor and self._lock_file is not None:
            # These observations occur before the real OS unlock.
            assert not any(path.exists() for path in publications)
            assert (runtime_data / daemon_mod.DAEMON_LOCK_FILE).exists()
            assert (runtime_data / daemon_mod.CLEAN_SHUTDOWN_FILE).exists()
            original_release(self)
            successor = _lock_owner()
            publications.clear()
            publications.update(_publish_hints(runtime_data, "43118"))
        else:
            original_release(self)

    monkeypatch.setattr(daemon_mod.Daemon, "start", no_network_start)
    monkeypatch.setattr(daemon_mod.Daemon, "serve_forever", no_network_serve)
    monkeypatch.setattr(daemon_mod.Daemon, "_release_instance_lock", release_then_publish_successor)
    monkeypatch.setattr(daemon_mod, "_check_previous_heartbeat", lambda: None)
    monkeypatch.setattr(daemon_mod.crash_log, "install_loop_hook", lambda _loop: None)
    try:
        await daemon_mod.run()
        assert predecessor is not None and successor is not None
        _assert_preserved(publications)
        predecessor._retire_runtime_publications()
        _assert_preserved(publications)
        assert not (runtime_data / daemon_mod.CLEAN_SHUTDOWN_FILE).exists()
    finally:
        if successor is not None:
            original_release(successor)
        if predecessor is not None:
            original_release(predecessor)


@pytest.mark.skipif(os.name != "nt", reason="requires actual Windows mandatory byte locking")
def test_windows_byte_locked_owner_survives_failed_probe_and_authenticated_recovery(
    runtime_data,
):
    """No daemon/UI is launched: the fixture owns a real lock and IPC listener."""
    owner = _lock_owner()
    secret = control_ipc.load_or_create_control_secret()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(20)
    port = listener.getsockname()[1]
    _publish_hints(runtime_data, str(port))
    errors = []

    def serve_fixture():
        try:
            for healthy in (False, True):
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(10)
                    hello = control_ipc.recv_json_line(
                        connection, max_bytes=control_ipc.CONTROL_HANDSHAKE_MAX_BYTES,
                    )
                    challenge, client_nonce, server_nonce = control_ipc.make_server_challenge(hello, secret)
                    connection.sendall(control_ipc.encode_json_line(
                        challenge, max_bytes=control_ipc.CONTROL_HANDSHAKE_MAX_BYTES,
                    ))
                    envelope = control_ipc.recv_json_line(
                        connection, max_bytes=control_ipc.CONTROL_REQUEST_MAX_BYTES,
                    )
                    request, exchange = control_ipc.verify_client_request(
                        envelope, secret, client_nonce=client_nonce, server_nonce=server_nonce,
                    )
                    assert request == {"cmd": "status"}
                    connection.sendall(control_ipc.encode_server_response(
                        {"ok": healthy, "pid": os.getpid(), "home": str(runtime_data)},
                        secret, exchange,
                    ))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve_fixture, daemon=True)
    thread.start()
    script = r'''
import json, os
from one_link import daemon as d
data = d.data_dir()
lock = data / d.DAEMON_LOCK_FILE
try:
    d._read_runtime_ascii_scalar(lock)
except PermissionError as exc:
    assert exc.errno == 13
else:
    raise AssertionError("Windows did not enforce the fixture's byte lock")
assert d._read_lock_pid() is None
snapshot = {data / name: (data / name).read_bytes() for name in
            ("control.port", "peer.port", "server.port", "ui.token")}
try:
    d.read_control_port()
except RuntimeError as exc:
    assert "stale control.port" in str(exc)
else:
    raise AssertionError("unhealthy authenticated fixture was accepted")
assert all(path.read_bytes() == value for path, value in snapshot.items())
(data / "control.port").unlink()  # simulate only this fixture's missing hint
expected_pid = int(os.environ["ONE_LINK_TEST_OWNER_PID"])
expected_port = int(os.environ["ONE_LINK_TEST_OWNER_PORT"])
def fixture_ports(pid):
    assert pid == expected_pid
    return [expected_port]  # scan only the fixture endpoint
d._candidate_control_ports_for_pid = fixture_ports
assert d.read_control_port() == expected_port
assert not (data / "control.port").exists()  # readers never publish
assert all(path.read_bytes() == value for path, value in snapshot.items()
           if path.name != "control.port")
print(json.dumps({"byte_lock_denied_read": True, "failed_probe_preserved_hints": True,
                  "authenticated_pid_home_recovered": True, "reader_did_not_publish": True}))
'''
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": str(Path(daemon_mod.__file__).resolve().parents[1]),
        "PYTHONDONTWRITEBYTECODE": "1",
        "ONE_LINK_TEST_OWNER_PID": str(os.getpid()),
        "ONE_LINK_TEST_OWNER_PORT": str(port),
    })
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-P", "-c", script], env=env,
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert all(json.loads(result.stdout).values())
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert not errors, errors
    finally:
        listener.close()
        owner._release_instance_lock()
        thread.join(timeout=2)
    assert daemon_mod._read_lock_pid() == os.getpid()
