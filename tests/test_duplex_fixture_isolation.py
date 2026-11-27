"""The one-connection fixture must exclude earlier scheduled convergence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from one_link import daemon as daemon_module, foldersync
from one_link.daemon import Daemon
from one_link.wire import decode_msg, encode_msg
from tests import harness, manual_folder_sync_daemon
from tests.test_folder_full_duplex_sync_e2e import _assert_durable_sync_receipt
from tests.test_folder_sync_bidi_v0210 import (
    _background_push_daemon,
    _EmptyWantsChannel,
    _peer,
)


@pytest.mark.asyncio
async def test_manual_fixture_omits_scheduler_but_keeps_explicit_dispatch(monkeypatch):
    original_loop = Daemon._folder_sync_loop
    original_push = Daemon.push_folder_to_peer
    original_receipt = Daemon._accept_folder_sync_commit
    monkeypatch.setattr(Daemon, "_folder_sync_loop", original_loop)
    entered = []
    monkeypatch.setattr(manual_folder_sync_daemon.cli, "main", lambda: entered.append(True))
    manual_folder_sync_daemon.main()

    scheduler = SimpleNamespace(run_forever=AsyncMock(), run_cycle=AsyncMock())
    daemon = SimpleNamespace(_folder_sync_scheduler=lambda: scheduler)
    await Daemon._folder_sync_loop(daemon)
    scheduler.run_forever.assert_not_awaited()
    scheduler.run_cycle.assert_not_awaited()
    await Daemon._run_one_folder_sync_cycle(daemon)
    scheduler.run_cycle.assert_awaited_once()
    assert entered == [True]
    assert Daemon.push_folder_to_peer is original_push
    assert Daemon._accept_folder_sync_commit is original_receipt


@pytest.mark.parametrize("periodic", [True, False])
def test_fixture_entry_point_is_explicit_and_home_scoped(tmp_path, monkeypatch, periodic):
    calls = []
    proc = SimpleNamespace()
    monkeypatch.setattr(
        harness.subprocess, "Popen",
        lambda argv, **kwargs: calls.append((argv, kwargs)) or proc,
    )
    home = tmp_path / "home"
    _, log = harness._spawn(
        home, tmp_path / "daemon.log", periodic_folder_sync=periodic,
    )
    log.close()
    argv, kwargs = calls[0]
    expected = "one_link.cli" if periodic else "tests.manual_folder_sync_daemon"
    assert argv == [harness.sys.executable, "-m", expected, "daemon", "-v"]
    assert kwargs["env"]["ONE_LINK_HOME"] == str(home)


def test_manual_fixture_cleanup_keeps_other_homes_and_commands(tmp_path, monkeypatch):
    import psutil

    home = tmp_path / "owned"
    stopped = []

    def candidate(label, module, candidate_home):
        return SimpleNamespace(
            info={"cmdline": ["python", "-m", module, "daemon"]},
            environ=lambda: {"ONE_LINK_HOME": str(candidate_home)},
            terminate=lambda: stopped.append(label),
        )

    processes = [
        candidate("manual", "tests.manual_folder_sync_daemon", home),
        candidate("normal", "one_link.cli", home),
        candidate("other_home", "tests.manual_folder_sync_daemon", tmp_path / "other"),
        candidate("other_command", "unrelated.module", home),
    ]
    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: processes)
    monkeypatch.setattr(psutil, "wait_procs", lambda matches, timeout: (matches, []))
    monkeypatch.setattr(
        harness.control_ipc, "request_control", lambda *args, **kwargs: {"ok": False},
    )
    harness._stop(
        SimpleNamespace(poll=lambda: 0), home=home, control_port=12345,
        control_secret="isolated-fixture-secret",
    )
    assert stopped == ["manual", "normal"]


@pytest.mark.asyncio
async def test_prior_convergence_requires_a_two_entry_receipt(monkeypatch):
    """A prior background merge changes the sender manifest, not receipt truth."""
    daemon = _background_push_daemon()
    rows = [
        *daemon.folder_engine.manifest_for.return_value,
        {"file_path": "from_peer.bin", "blob_hash": "b" * 64,
         "size": 20, "mtime_ms": 0, "vclock": {}},
    ]
    daemon.folder_engine.manifest_for.return_value = rows
    daemon.folder_engine.manifest_root.return_value = foldersync.manifest_root_for_entries(rows)
    channel = _EmptyWantsChannel()
    original_recv = channel.recv

    async def recv():
        frame = decode_msg(await original_recv())
        if frame["t"] == "FOLDER_SYNC_COMMIT":
            frame["paths_verified"] = len(rows)
        return encode_msg(frame)

    channel.recv = recv
    monkeypatch.setattr(daemon_module.ch, "initiate", AsyncMock(return_value=channel))
    result = await daemon.push_folder_to_peer(_peer(), "myfolder")
    response = {"ok": True, "results": [{"status": "pushed", **result}]}
    _assert_durable_sync_receipt(response, expected_entries=2, expected_wants=0)
    with pytest.raises(AssertionError):
        _assert_durable_sync_receipt(response, expected_entries=1, expected_wants=0)
