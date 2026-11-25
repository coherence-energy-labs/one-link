"""Daemon resilience: stale state, dropped peers, malformed runtime traffic.

These exercise behaviors that often hide bugs in long-running services:
the daemon must keep serving good clients even after a bad one misbehaves.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from one_link import control_ipc
from tests.harness import daemon_pair, request, require_live_daemon


pytestmark = pytest.mark.timeout(120)


def test_cli_import_has_no_windows_wmi_startup_hang():
    """CLI import must be boring-fast. It used to import aiohttp/zeroconf
    transitively and could hang inside Windows WMI before One Link even wrote
    control.port."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import one_link.cli; print('ok')",
        ],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


@pytest.mark.live_daemon
def test_stale_port_files_dont_break_daemon():
    """Drop a port file from a 'previous' daemon run, then start a new daemon
    in the same home. The new daemon must overwrite cleanly."""
    require_live_daemon()  # spawns a real daemon subprocess
    tmp = Path(tempfile.mkdtemp(prefix="one_link_stale_"))
    try:
        home = tmp / "H"
        home.mkdir()
        # Pre-seed stale files
        (home / "data").mkdir()
        (home / "data" / "control.port").write_text("99999")
        (home / "data" / "peer.port").write_text("99998")

        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(home)
        log = tmp / "out.log"
        with open(log, "wb") as f:
            proc = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        try:
            # The assertion is that stale ports get REPLACED, not that boot is
            # fast: a fixed short deadline made this red whenever a loaded CI
            # runner spent >8s in cold-start + identity keygen + ACL rounds.
            # Give a generous ceiling; the check still fails honestly if the
            # daemon never rewrites the file.
            deadline = time.time() + 45.0
            ctrl = None
            while time.time() < deadline:
                try:
                    ctrl_text = (home / "data" / "control.port").read_text().strip()
                    if ctrl_text and ctrl_text != "99999":
                        ctrl = int(ctrl_text)
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            assert ctrl is not None, log.read_text(encoding="utf-8", errors="replace")[-2000:]

            # Verify the new daemon is alive on the new port
            res = control_ipc.request_control(
                ctrl,
                {"cmd": "peers"},
                timeout=30.0,
                secret=control_ipc.read_control_secret(home / "data"),
            )
            assert res["ok"]
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_read_control_port_rejects_dead_hints_without_deleting_runtime_files(monkeypatch):
    """A reader rejects stale hints; only the lock owner may retire them.

    Startup replaces old publications after acquiring the singleton lock.
    A failed client probe must not race a live owner or its successor.
    """
    from one_link import daemon as daemon_mod

    tmp = Path(tempfile.mkdtemp(prefix="one_link_dead_runtime_"))
    try:
        home = tmp / "H"
        data = home / "data"
        data.mkdir(parents=True)
        monkeypatch.setenv("ONE_LINK_HOME", str(home))

        (data / "control.port").write_text("65530")
        (data / "peer.port").write_text("65529")
        (data / "server.port").write_text("65528")
        (data / "daemon.lock").write_text("999999")

        with pytest.raises(RuntimeError, match="stale control.port"):
            daemon_mod.read_control_port()

        assert (data / "control.port").read_text() == "65530"
        assert (data / "peer.port").read_text() == "65529"
        assert (data / "server.port").read_text() == "65528"
        assert (data / "daemon.lock").read_text() == "999999"
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_control_liveness_requires_status_protocol():
    """A random process accepting TCP on localhost is not a One Link daemon."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    async def _close_after_accept():
        loop = asyncio.get_running_loop()
        conn, _ = await loop.run_in_executor(None, listener.accept)
        conn.close()
        listener.close()

    from one_link import daemon as daemon_mod

    async def _run():
        closer = asyncio.create_task(_close_after_accept())
        try:
            assert daemon_mod.is_daemon_alive(port, timeout=0.2) is False
        finally:
            await closer

    asyncio.run(_run())


@pytest.mark.live_daemon
def test_daemon_survives_garbage_on_peer_port():
    """Hammer the peer port with garbage from many clients; daemon stays up."""
    with daemon_pair(pin_trust=True) as p:
        for _ in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("127.0.0.1", p.b.peer_port))
                s.sendall(os.urandom(64))
                s.close()
            except OSError:
                pass

        # B should still be responsive
        res = request(p.b.control_port, cmd="peers")
        assert res["ok"]


@pytest.mark.live_daemon
def test_daemon_survives_burst_of_disconnects():
    """Open then immediately close the peer port many times. Daemon must
    not leak descriptors or hang."""
    with daemon_pair(pin_trust=True) as p:
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", p.b.peer_port))
                s.close()
            except OSError:
                pass

        res = request(p.b.control_port, cmd="peers")
        assert res["ok"]

        # And legit traffic still works
        ok = request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="still alive"
        )
        assert ok["ok"], ok


@pytest.mark.live_daemon
def test_two_daemons_in_same_home_second_fails_gracefully():
    """Spinning a second daemon at the same ONE_LINK_HOME — what happens?

    The second process must not stay alive and advertise the same local
    device again; that duplicate advertising is what fills the sidebar
    with repeated entries."""
    require_live_daemon()  # spawns real daemon subprocesses
    tmp = Path(tempfile.mkdtemp(prefix="one_link_dup_"))
    try:
        home = tmp / "H"
        home.mkdir()
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(home)
        log1 = tmp / "1.log"
        log2 = tmp / "2.log"
        with open(log1, "wb") as f1, open(log2, "wb") as f2:
            p1 = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env, stdout=f1, stderr=subprocess.STDOUT,
            )
            # 2026-05-22 audit Batch BB: poll for p1's instance-lock
            # file ``daemon.lock`` to appear (or for stdout to settle)
            # instead of a brittle ``time.sleep(2.0)``. Under slow CI
            # the lock may not exist yet — false-pass; under fast CI
            # the sleep wastes 2 s of wall time.
            lock_file = home / "data" / "daemon.lock"
            deadline = time.time() + 10.0
            while time.time() < deadline:
                if lock_file.exists() and p1.poll() is None:
                    break
                if p1.poll() is not None:
                    # p1 exited prematurely; let assertion below fire
                    break
                time.sleep(0.1)
            p2 = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env, stdout=f2, stderr=subprocess.STDOUT,
            )
            # Poll for p2 to exit (instance-lock rejection should be
            # fast — sub-second on healthy machines).
            deadline = time.time() + 10.0
            while time.time() < deadline:
                if p2.poll() is not None:
                    break
                time.sleep(0.1)
            try:
                assert p1.poll() is None, "p1 unexpectedly exited"
                assert p2.poll() is not None, "p2 should exit under instance lock"
                log_text = log2.read_text(encoding="utf-8", errors="replace")
                assert "already running" in log_text
            finally:
                for p in (p1, p2):
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.live_daemon
def test_peer_disconnects_during_chunk_does_not_break_daemon():
    """Initiator opens a connection, sends a partial offer, drops mid-stream.
    Receiver daemon should clean up and continue serving good peers."""
    with daemon_pair(pin_trust=True) as p:
        # Open raw connection, send half of a HELLO frame, close.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            # Frame header says 200 bytes, send only 50.
            s.sendall((200).to_bytes(4, "big") + b"\x00" * 50)
            time.sleep(0.5)
        finally:
            s.close()

        # Legit message should still work
        time.sleep(0.5)
        res = request(p.a.control_port, cmd="send", peer=p.b.short_id, body="post")
        assert res["ok"], res


@pytest.mark.live_daemon
def test_burst_load_50_messages_no_silent_fallback():
    """2026-05-22 audit Batch LL: 50 messages back-to-back stress
    the per-peer send pipeline + ACK plumbing harder than the 10-
    message burst soak. If the channel desyncs the ratchet, or
    queues a request behind a stalled write, this exposes it.

    Two regression nets are tighter than in the smaller soak test:

      * Counter equality on the receive side (no missed AND no
        duplicate deliveries — T3-N pattern extended).
      * degradation_events ring empty on both daemons (T2-L
        pattern extended) — silent native-transfer / QUIC fallback
        would otherwise fire here and the message would still land,
        masking the regression.
    """
    from collections import Counter
    from tests.harness import message_log
    with daemon_pair(pin_trust=True) as p:
        N = 50
        for i in range(N):
            res = request(
                p.a.control_port, cmd="send",
                peer=p.b.short_id, body=f"stress-{i:03d}",
            )
            assert res.get("ok") is True, (i, res)
        # Bounded polling for delivery via the harness's message_log
        # helper which reads from state.db (not messages.jsonl).
        deadline = time.time() + 30.0
        delivered: Counter = Counter()
        while time.time() < deadline:
            delivered = Counter(
                m["body"] for m in message_log(p.b.home)
                if m.get("t") == "TEXT" and m.get("dir") == "in"
                and isinstance(m.get("body"), str)
                and m["body"].startswith("stress-")
            )
            if sum(delivered.values()) >= N:
                break
            time.sleep(0.1)
        # Every body delivered exactly once.
        expected = Counter(f"stress-{i:03d}" for i in range(N))
        missing = expected - delivered
        duplicates = {b: n for b, n in delivered.items() if n > 1}
        assert not missing, f"missing {len(missing)}/{N}: {sorted(missing)[:5]}"
        assert not duplicates, f"duplicate deliveries: {duplicates}"
        # No silent-fallback events on either side.
        for handle in (p.a, p.b):
            diag = request(handle.control_port, cmd="transfer_diagnostics")
            events = diag.get("degradation_events") or []
            bad = [
                e for e in events
                if e.get("kind") in (
                    "native_transfer_unavailable",
                    "native_transfer_receiver_unavailable",
                    "stream_quic_batch_failed",
                    "file_offer_batch_inner_failed",
                    "provenance_broadcast_failed",
                )
            ]
            assert not bad, (
                f"silent fallback fired during burst-50 on "
                f"{handle.short_id}: {bad}"
            )


@pytest.mark.live_daemon
def test_bidi_concurrent_sends_no_deadlock():
    """2026-05-22 audit Batch LL: stress per-peer send-lock contention.
    Spawn 20 concurrent sends in BOTH directions simultaneously
    using threads against the control socket. The per-peer send
    pipeline must not deadlock under contention — every send
    must return ``ok`` within the timeout.
    """
    import threading
    with daemon_pair(pin_trust=True) as p:
        a_results: list[dict] = []
        b_results: list[dict] = []
        errors: list[BaseException] = []
        N = 20

        def send_a(i: int) -> None:
            try:
                a_results.append(request(
                    p.a.control_port, cmd="send",
                    peer=p.b.short_id, body=f"a-{i:02d}",
                ))
            except BaseException as e:  # pragma: no cover
                errors.append(e)

        def send_b(i: int) -> None:
            try:
                b_results.append(request(
                    p.b.control_port, cmd="send",
                    peer=p.a.short_id, body=f"b-{i:02d}",
                ))
            except BaseException as e:  # pragma: no cover
                errors.append(e)

        threads = []
        for i in range(N):
            t1 = threading.Thread(target=send_a, args=(i,), daemon=True)
            t2 = threading.Thread(target=send_b, args=(i,), daemon=True)
            threads.append(t1)
            threads.append(t2)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60.0)
            assert not t.is_alive(), "send thread deadlocked"

        assert not errors, f"send threads raised: {errors}"
        assert len(a_results) == N, f"A: got {len(a_results)}/{N}"
        assert len(b_results) == N, f"B: got {len(b_results)}/{N}"
        for i, r in enumerate(a_results):
            assert r.get("ok"), (i, "a", r)
        for i, r in enumerate(b_results):
            assert r.get("ok"), (i, "b", r)
