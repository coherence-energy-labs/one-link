"""A real daemon asked to stop does stop, whatever is still connected to it.

Measured on 2026-11-26 before this was fixed (Python 3.12.13): a daemon with
nothing connected stopped in 1.8 s; with one message-tail client attached, or
one quiet peer session, it was still running 45 s after it acknowledged the
stop. A tail client never detaches by itself, so that stop never finished, and
whatever was replacing the daemon had to kill it. That is the "prior shutdown
was unclean" integrity check on the next start.

Each test opens the kind of connection a running install really has, asks the
daemon to stop through the authenticated control channel (what `one-link
daemon-stop` does), and requires a clean exit. The bound is 20 s: about ten
times what a stop takes, and far below the failure, which is minutes or never.

The decisions behind this are unit-tested against real asyncio servers in
tests/test_connection_shutdown.py.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.harness import DaemonHandle, daemon_pair, request

pytestmark = pytest.mark.timeout(180)

STOP_BOUND_S = 20.0
REPO = Path(__file__).resolve().parent.parent


def _stop_and_time(handle: DaemonHandle) -> float:
    """Ask for a stop the way `one-link daemon-stop` does; seconds until the process is gone."""
    reply = request(handle.control_port, cmd="shutdown")
    assert reply.get("ok") is True and reply.get("stopping") is True, reply
    started = time.monotonic()
    try:
        handle.proc.wait(timeout=STOP_BOUND_S)
    except subprocess.TimeoutExpired:
        tail = handle.log.read_text(encoding="utf-8", errors="replace")[-1500:]
        pytest.fail(
            f"the daemon acknowledged the stop and was still running {STOP_BOUND_S:.0f} s later\n"
            f"--- its log tail ---\n{tail}"
        )
    assert handle.proc.returncode == 0, f"the daemon exited {handle.proc.returncode}, not cleanly"
    return time.monotonic() - started


def _wait_for_log(handle: DaemonHandle, needle: str, *, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in handle.log.read_text(encoding="utf-8", errors="replace"):
            return
        time.sleep(0.2)
    raise AssertionError(f"{needle!r} never appeared in the daemon's log")


@pytest.mark.live_daemon
def test_a_daemon_with_a_message_tail_attached_stops_and_the_tail_ends():
    with daemon_pair(pin_trust=True) as p:
        env = dict(os.environ, ONE_LINK_HOME=str(p.b.home))
        tail = subprocess.Popen(
            [sys.executable, "-P", "-u", "-m", "one_link.cli", "tail"],
            env=env, cwd=str(REPO), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            assert tail.stdout is not None
            first = tail.stdout.readline().decode("utf-8", errors="replace")
            assert "tailing" in first, f"the tail client did not attach: {first!r}"
            assert tail.poll() is None

            _stop_and_time(p.b)

            # The subscriber is told, by its stream ending, rather than left
            # attached to a daemon that is gone.
            assert tail.wait(timeout=15.0) == 0
        finally:
            if tail.poll() is None:
                tail.kill()
                tail.wait(timeout=10.0)


@pytest.mark.live_daemon
def test_a_daemon_with_a_quiet_peer_session_stops():
    with daemon_pair(pin_trust=True) as p:
        # A sends once and keeps its session to B open, as a paired device does.
        assert request(p.a.control_port, cmd="send", peer=p.b.short_id, body="hello").get("ok")
        _wait_for_log(p.b, "peer connected:")
        time.sleep(1.0)
        _stop_and_time(p.b)
        assert "stopping: ended" in p.b.log.read_text(encoding="utf-8", errors="replace"), (
            "the daemon stopped without ending the session that was open"
        )


@pytest.mark.live_daemon
def test_a_daemon_holding_a_file_offer_for_its_owner_stops(monkeypatch):
    """A session carrying a held offer is allowed five quiet minutes, not two.
    That must not become five minutes of waiting to stop."""
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    with daemon_pair(pin_trust=True) as p:
        source = p.tmp / "held.txt"
        source.write_bytes(b"waiting for the owner\n" * 200)
        outcome: dict = {}

        def send() -> None:
            try:
                outcome["reply"] = request(
                    p.a.control_port, timeout=120.0, cmd="send_file", peer=p.b.short_id, path=str(source),
                )
            except Exception as exc:  # B goes away under the send
                outcome["error"] = f"{type(exc).__name__}: {exc}"

        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        _wait_for_log(p.b, "file offer HELD pending accept")

        _stop_and_time(p.b)

        # The sender finds out promptly that the receiver went away; it is not
        # left waiting out its five-minute acceptance window on a dead session.
        sender.join(timeout=60.0)
        assert not sender.is_alive(), "the sender was still waiting on a receiver that had stopped"
        assert not (outcome.get("reply") or {}).get("ok"), outcome
