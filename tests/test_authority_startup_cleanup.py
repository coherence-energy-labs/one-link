"""Authority refusal closes early resources before releasing instance ownership."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sqlite3

import pytest

from one_link import cap_root_key, capsule_store, daemon as daemon_mod, lockbox, paths, peer_quic
from one_link.identity import load_or_create
from one_link.key_material import KeyMaterialError, KeyMaterialProtectionError


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["state", "capsule", "capability"])
async def test_run_closes_early_resources_before_unlocking_on_authority_refusal(
    tmp_path, monkeypatch, failure,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ONE_LINK_QUIC_TRANSPORT", "1")
    monkeypatch.delenv("ONE_LINK_PASSPHRASE", raising=False)
    load_or_create()  # An existing legacy identity prevents seed provisioning.
    data = paths.data_dir()
    box = lockbox.acquire_lockbox(data)
    cap_root_key.load_or_create_cap_root_key(data)
    capsule_box = lockbox.LockBox(os.urandom(32)) if failure == "capsule" else box
    (data / capsule_store.CAPSULE_KEY_FILENAME).write_bytes(capsule_box.wrap(os.urandom(32)))
    if failure == "capability":
        (data / "cap_root.key").write_bytes(b"invalid existing authority")
    protected = {
        path: path.read_bytes()
        for path in (
            paths.key_path(), data / lockbox.DRK_FILENAME,
            data / capsule_store.CAPSULE_KEY_FILENAME, data / "cap_root.key",
        )
    }
    # A failed startup cannot retire hints belonging to an earlier lifecycle.
    publications = {}
    for name in ("control.port", "peer.port", "server.port", "ui.token"):
        path = data / name
        path.write_text("43117", encoding="ascii")
        publications[path] = path.read_bytes()
    constructed = []
    stores = []
    repositories = []
    events = []
    real_init = daemon_mod.Daemon.__init__
    real_release = daemon_mod.Daemon._release_instance_lock
    real_state = daemon_mod.State
    real_repository = capsule_store.CapsuleRepository

    def owner_has_lock():
        return constructed[0]._lock_file is not None and not constructed[0]._lock_file.closed

    def observe_init(self, identity):
        real_init(self, identity)
        constructed.append(self)

    def observe_release(self):
        if constructed and self is constructed[0]:
            events.append("unlock")
        real_release(self)

    def open_state():
        if failure == "state":
            raise KeyMaterialProtectionError("existing state authority refused")
        state = real_state()
        stores.append(state)
        close = state.close

        def close_state():
            assert owner_has_lock()
            events.append("state_close")
            close()

        monkeypatch.setattr(state, "close", close_state)
        return state

    def open_repository(*args, **kwargs):
        repository = real_repository(*args, **kwargs)
        repositories.append(repository)
        close = repository.close

        def close_repository():
            assert owner_has_lock()
            events.append("capsule_close")
            close()

        monkeypatch.setattr(repository, "close", close_repository)
        return repository

    class BoundEndpoint:
        def __init__(self):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(("127.0.0.1", 0))
            self.local_addr = f"127.0.0.1:{self.socket.getsockname()[1]}"

        def close(self, *_args):
            assert owner_has_lock()
            events.append("endpoint_close")
            self.socket.close()

    endpoint = BoundEndpoint()
    monkeypatch.setattr(daemon_mod.Daemon, "__init__", observe_init)
    monkeypatch.setattr(daemon_mod.Daemon, "_release_instance_lock", observe_release)
    monkeypatch.setattr(daemon_mod, "State", open_state)
    monkeypatch.setattr(capsule_store, "CapsuleRepository", open_repository)
    monkeypatch.setattr(peer_quic, "HAS_NATIVE", True)
    monkeypatch.setattr(peer_quic, "make_server_endpoint", lambda *_args: endpoint)

    async def forbidden(*_args, **_kwargs):
        pytest.fail("authority refusal reached a listener or full shutdown")

    monkeypatch.setattr(asyncio, "start_server", forbidden)
    monkeypatch.setattr(daemon_mod.Daemon, "stop", forbidden)
    before_tasks = asyncio.all_tasks()
    try:
        with pytest.raises(KeyMaterialError):
            await daemon_mod.run()
        daemon = constructed[0]
        expected = ["endpoint_close"]
        if repositories:
            expected.append("capsule_close")
        if stores:
            expected.append("state_close")
        assert events == [*expected, "unlock"]
        assert endpoint.socket.fileno() == -1
        assert daemon._lock_file is None
        assert daemon._quic_server_endpoint is None
        assert daemon._quic_accept_task is None
        assert daemon._quic_local_port is None
        assert daemon.state is None
        assert daemon._capsule_store is None
        assert asyncio.all_tasks() == before_tasks
        for state in stores:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                state._conn.execute("SELECT 1")
        for repository in repositories:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                repository._db.execute("SELECT 1")
        assert {path: path.read_bytes() for path in protected} == protected
        assert {path: path.read_bytes() for path in publications} == publications
        assert not (data / "master.seed").exists()
        assert not (data / daemon_mod.CLEAN_SHUTDOWN_FILE).exists()
        # The failed owner released the real singleton lock only after cleanup.
        successor = object.__new__(daemon_mod.Daemon)
        successor._lock_file = None
        successor._acquire_instance_lock()
        successor._release_instance_lock()
    finally:
        # Contain resources even when this regression is run against old code.
        endpoint.socket.close()
        for daemon in constructed:
            task = daemon._quic_accept_task
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            daemon._release_instance_lock()
        for repository in repositories:
            with contextlib.suppress(Exception):
                real_repository.close(repository)
        for state in stores:
            with contextlib.suppress(Exception):
                real_state.close(state)


@pytest.mark.asyncio
async def test_abort_continues_cleanup_and_preserves_original_authority_error(monkeypatch):
    daemon = object.__new__(daemon_mod.Daemon)
    events = []
    refused = KeyMaterialProtectionError("existing authority refused")

    class Endpoint:
        def close(self, *_args):
            events.append("endpoint")
            raise OSError("endpoint close failed")

    class Cover:
        def stop(self, *, join_timeout):
            assert join_timeout == 2.0
            events.append("cover")

    class Store:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(self.name)

    daemon._quic_server_endpoint = Endpoint()
    daemon._quic_accept_task = None
    daemon._quic_local_port = 43117
    daemon._cover_traffic = Cover()
    daemon._capsule_store = Store("capsule")
    daemon.state = Store("state")
    daemon.sealed_master = object()
    failures = []
    monkeypatch.setattr(daemon_mod, "report_best_effort_failure", lambda _log, stage, _exc: failures.append(stage))
    with pytest.raises(KeyMaterialProtectionError) as result:
        try:
            raise refused
        except KeyMaterialProtectionError:
            await daemon._abort_authority_startup()
            raise
    assert result.value is refused
    assert events == ["endpoint", "cover", "capsule", "state"]
    assert failures == ["abort_start_quic_endpoint"]
