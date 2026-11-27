"""A session probe that fails says why.

Why this file exists. ``Daemon._probe_outbound_session`` sends a PING on an
open session and waits 1.5 s for the PONG. It answered ``False`` for a timeout,
for a reset connection and for any other error alike, and logged nothing. A
hosted live test failed once on that ``False`` ("authenticated probe failed")
right after a daemon restart, and neither daemon's log held a line about it,
so the failure could not be read and has not been reproduced in 19 runs on a
workstation. The next one carries its cause.
"""
from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import one_link.daemon as daemon_mod
from one_link.daemon import Daemon, OutboundSession
from one_link.wire import decode_msg, encode_msg, make_msg


class _Channel:
    """A session channel whose replies the test scripts."""

    def __init__(self, replies) -> None:
        self.sent: list[dict] = []
        self._replies = list(replies)

    async def send(self, data: bytes) -> None:
        self.sent.append(decode_msg(data))

    async def recv(self) -> bytes:
        if not self._replies:
            await asyncio.Event().wait()  # the peer says nothing more
        reply = self._replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        if callable(reply):
            reply = reply(self.sent[-1])
        return encode_msg(reply)


def _daemon() -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon.me = SimpleNamespace(short_id="prober")
    daemon._outbound_sessions = {}
    daemon._on_peer_message = AsyncMock()
    daemon._stamp_pair_health = lambda *args, **kwargs: None
    return daemon


def _session(channel: _Channel) -> OutboundSession:
    return OutboundSession(
        peer_fp="ab" * 32, peer=SimpleNamespace(short_id="abababab"), channel=channel,
        lock=asyncio.Lock(), last_used=0.0,
    )


def _probe(channel: _Channel, caplog) -> tuple[bool, list[str]]:
    async def scenario() -> bool:
        return await _daemon()._probe_outbound_session(_session(channel))

    with caplog.at_level(logging.INFO, logger="one_link.daemon"):
        answer = asyncio.run(scenario())
    return answer, [record.getMessage() for record in caplog.records if "session probe" in record.getMessage()]


@pytest.fixture(autouse=True)
def _short_deadline(monkeypatch) -> None:
    monkeypatch.setattr(daemon_mod, "OUTBOUND_SESSION_PING_DEADLINE_S", 0.2)


def test_a_peer_that_never_answers_is_reported_as_a_timeout_with_nothing_read(caplog):
    channel = _Channel([])
    answer, lines = _probe(channel, caplog)
    assert answer is False
    assert [frame["t"] for frame in channel.sent] == ["PING"]
    assert len(lines) == 1
    assert lines[0].startswith("session probe to abababab failed: TimeoutError")
    assert lines[0].endswith("frames read: none")


def test_frames_read_while_waiting_are_named(caplog):
    channel = _Channel([
        make_msg("ROTATION_CERT_ACK", "peer"),
        lambda ping: make_msg("PONG", "peer", of="not-" + ping["id"]),
    ])
    answer, lines = _probe(channel, caplog)
    assert answer is False
    assert len(lines) == 1 and "TimeoutError" in lines[0]
    assert lines[0].endswith("frames read: ROTATION_CERT_ACK, PONG"), lines[0]


def test_a_reset_connection_is_reported_as_one(caplog):
    channel = _Channel([ConnectionResetError("connection reset by peer")])
    answer, lines = _probe(channel, caplog)
    assert answer is False
    assert len(lines) == 1
    assert "failed: ConnectionResetError (connection reset by peer)" in lines[0]


def test_time_spent_waiting_for_the_session_is_told_apart_from_time_waiting_for_the_answer(caplog):
    """A probe queued behind a transfer on the same session is not a silent peer."""

    async def scenario() -> bool:
        daemon, session = _daemon(), _session(_Channel([]))
        await session.lock.acquire()
        asyncio.get_running_loop().call_later(0.5, session.lock.release)
        return await daemon._probe_outbound_session(session)

    with caplog.at_level(logging.INFO, logger="one_link.daemon"):
        assert asyncio.run(scenario()) is False
    line = next(record.getMessage() for record in caplog.records if "session probe" in record.getMessage())
    waited_for_session = float(line.split("; ")[1].split("s waiting for the session")[0])
    waited_for_answer = float(line.split("waiting for the session, ")[1].split("s for the answer")[0])
    assert 0.4 <= waited_for_session < 1.5, line
    assert 0.15 <= waited_for_answer < 0.45, line


def test_a_probe_that_is_answered_logs_nothing(caplog):
    channel = _Channel([lambda ping: make_msg("PONG", "peer", of=ping["id"])])
    answer, lines = _probe(channel, caplog)
    assert answer is True
    assert lines == []
