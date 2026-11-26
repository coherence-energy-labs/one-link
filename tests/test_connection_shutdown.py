"""A stopping daemon does not wait for a connection to end by itself.

Found on 2026-11-26 while preparing to restart a running install. Since Python
3.12 a closed ``asyncio.Server`` waits for every connection it accepted, and
the daemon's stop path predates that. Measured on scratch daemons: nothing
connected, stopped in 1.8 s; one message-tail client attached, or one quiet
peer session, still running 45 s after the stop was acknowledged. A tail
client never detaches by itself, so that stop never finished.

These tests use real asyncio servers and real sockets, with handlers shaped
like the daemon's (they return only when their connection ends). The same
situations with real daemons are in
tests/test_daemon_stops_with_open_connections.py.

On Python 3.11 a closed server does not wait, so everything here passes there
with or without the fix; the 3.12 lanes are the ones that can fail. The first
test states that premise so it is checked rather than assumed.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import connection_shutdown
from one_link.connection_shutdown import AcceptedConnections, end_open_connections, serve_until_stopped

# Generous against a loaded machine, far below the failure it guards against
# (tens of seconds to forever).
PROMPT_S = 5.0


async def _until_the_connection_ends(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Like the daemon's peer and tail handlers: nothing ends it but the connection."""
    try:
        await reader.read()
    finally:
        writer.close()


async def _serve(handler, accepted: AcceptedConnections) -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(accepted.tracking(handler), host="127.0.0.1", port=0)
    return server, server.sockets[0].getsockname()[1]


async def _connect(port: int, count: int = 1) -> list[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    clients = [await asyncio.open_connection("127.0.0.1", port) for _ in range(count)]
    await asyncio.sleep(0.1)  # let the server accept and start each handler
    return clients


async def _saw_the_end(client: tuple[asyncio.StreamReader, asyncio.StreamWriter]) -> bool:
    reader, writer = client
    try:
        data = await asyncio.wait_for(reader.read(), timeout=PROMPT_S)
    except (ConnectionError, OSError):
        data = b""
    finally:
        writer.close()
    return data == b""


class _Channel:
    """The part of one_link.channel.Channel the stop uses."""

    def __init__(self, writer: asyncio.StreamWriter, *, stall: bool = False) -> None:
        self.writer = writer
        self.closes = 0
        self._stall = stall

    async def close(self) -> None:
        self.closes += 1
        if self._stall:
            await asyncio.sleep(3600)
        self.writer.close()
        await self.writer.wait_closed()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.version_info < (3, 12), reason="a closed server waits for its connections from Python 3.12")
async def test_the_premise_a_closed_server_waits_for_an_open_connection():
    """Why this module exists. If this stops holding, the module can be retired."""
    accepted = AcceptedConnections()
    server, port = await _serve(_until_the_connection_ends, accepted)
    clients = await _connect(port)
    server.close()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(server.wait_closed(), timeout=0.7)
    for _reader, writer in clients:
        writer.close()
    await asyncio.wait_for(server.wait_closed(), timeout=PROMPT_S)


@pytest.mark.asyncio
async def test_a_requested_stop_ends_open_connections_and_returns():
    accepted = AcceptedConnections()
    peers, peer_port = await _serve(_until_the_connection_ends, accepted)
    control, control_port = await _serve(_until_the_connection_ends, accepted)
    clients = await _connect(peer_port, 3) + await _connect(control_port, 2)
    assert len(accepted.open_writers()) == 5

    stopping = asyncio.Event()
    serving = asyncio.create_task(serve_until_stopped((peers, control), stopping, {}, accepted))
    await asyncio.sleep(0.2)
    assert not serving.done(), "it stopped serving before being asked"

    started = time.monotonic()
    stopping.set()
    await asyncio.wait_for(serving, timeout=PROMPT_S)
    assert time.monotonic() - started < PROMPT_S
    assert not peers.is_serving() and not control.is_serving()
    assert all([await _saw_the_end(client) for client in clients]), "a client was left connected"
    assert accepted.open_writers() == ()


@pytest.mark.asyncio
async def test_an_interrupted_serve_ends_open_connections_too():
    """Cancellation of the serving task (an interrupt) takes the same way out."""
    accepted = AcceptedConnections()
    server, port = await _serve(_until_the_connection_ends, accepted)
    clients = await _connect(port, 2)
    serving = asyncio.create_task(serve_until_stopped((server,), asyncio.Event(), {}, accepted))
    await asyncio.sleep(0.2)

    serving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(serving, timeout=PROMPT_S)
    assert not server.is_serving()
    assert all([await _saw_the_end(client) for client in clients])


@pytest.mark.asyncio
async def test_an_authenticated_channel_is_closed_through_the_channel_once():
    """channel.close() releases sends queued behind the handshake; a bare
    transport close would leak them."""
    accepted = AcceptedConnections()
    live: dict[str, list[_Channel]] = {}

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        channel = _Channel(writer)
        live.setdefault("peer", []).append(channel)
        await reader.read()

    server, port = await _serve(handler, accepted)
    clients = await _connect(port, 2)
    channels = list(live["peer"])
    # The daemon lists a channel under its peer; the same object must not be closed twice.
    live["again"] = [channels[0]]

    stopping = asyncio.Event()
    stopping.set()
    await asyncio.wait_for(serve_until_stopped((server,), stopping, live, accepted), timeout=PROMPT_S)
    assert [channel.closes for channel in channels] == [1, 1]
    assert all([await _saw_the_end(client) for client in clients])


@pytest.mark.asyncio
async def test_a_channel_whose_close_stalls_is_aborted_after_the_grace():
    accepted = AcceptedConnections()
    live: dict[str, list[_Channel]] = {}

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        live.setdefault("peer", []).append(_Channel(writer, stall=True))
        await reader.read()

    server, port = await _serve(handler, accepted)
    clients = await _connect(port)
    stopping = asyncio.Event()
    stopping.set()
    started = time.monotonic()
    await asyncio.wait_for(
        serve_until_stopped((server,), stopping, live, accepted, grace_s=0.3, sweep_s=0.1), timeout=PROMPT_S,
    )
    # The grace is 0.3 s. The bound is 0.2 s because Windows timers tick every
    # ~16 ms and a 0.3 s timeout was measured firing at 0.297 s; a close that
    # is abandoned without any grace returns in a few milliseconds.
    assert time.monotonic() - started >= 0.2, "the stalled close was not given its grace"
    assert all([await _saw_the_end(client) for client in clients])


@pytest.mark.asyncio
async def test_a_handler_that_returns_without_closing_does_not_hold_the_stop():
    accepted = AcceptedConnections()

    async def forgetful(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        return  # the transport is still open and the server still counts it

    server, port = await _serve(forgetful, accepted)
    clients = await _connect(port, 2)
    assert len(accepted.open_writers()) == 2, "a returned handler's open connection was forgotten"
    stopping = asyncio.Event()
    stopping.set()
    await asyncio.wait_for(serve_until_stopped((server,), stopping, {}, accepted), timeout=PROMPT_S)
    assert all([await _saw_the_end(client) for client in clients])


@pytest.mark.asyncio
async def test_a_connection_that_registers_after_the_stop_began_is_still_ended():
    """The loop accepts a connection a moment before its handler starts. A stop
    that looked once, in that moment, would miss it and then wait on it."""
    accepted = AcceptedConnections()
    late = asyncio.Event()

    async def registers_late(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await late.wait()
        await accepted.tracking(_until_the_connection_ends)(reader, writer)

    server = await asyncio.start_server(registers_late, host="127.0.0.1", port=0)
    clients = await _connect(server.sockets[0].getsockname()[1])
    assert accepted.open_writers() == ()

    stopping = asyncio.Event()
    stopping.set()
    serving = asyncio.create_task(serve_until_stopped((server,), stopping, {}, accepted, sweep_s=0.1))
    await asyncio.sleep(0.35)  # several looks, none of which can see the connection yet
    if sys.version_info >= (3, 12):
        assert not serving.done(), "the server let go of a connection nobody closed"
    late.set()
    await asyncio.wait_for(serving, timeout=PROMPT_S)
    assert all([await _saw_the_end(client) for client in clients])


@pytest.mark.asyncio
async def test_servers_closed_before_serving_return_quietly_and_real_errors_do_not():
    accepted = AcceptedConnections()
    closed, _ = await _serve(_until_the_connection_ends, accepted)
    other, _ = await _serve(_until_the_connection_ends, accepted)
    closed.close()
    await closed.wait_closed()
    # One server never served; the stop still closes the other and returns.
    await asyncio.wait_for(
        serve_until_stopped((closed, other), asyncio.Event(), {}, accepted), timeout=PROMPT_S,
    )
    assert not other.is_serving()

    class _Broken:
        def close(self) -> None:
            pass

        async def serve_forever(self) -> None:
            raise RuntimeError("address already in use")

    with pytest.raises(RuntimeError, match="address already in use"):
        await asyncio.wait_for(
            serve_until_stopped((_Broken(),), asyncio.Event(), {}, accepted), timeout=PROMPT_S,
        )


@pytest.mark.asyncio
async def test_ending_connections_reports_what_it_ended_and_is_safe_to_repeat():
    accepted = AcceptedConnections()
    server, port = await _serve(_until_the_connection_ends, accepted)
    clients = await _connect(port, 3)
    assert await end_open_connections({}, accepted) == 3
    assert await end_open_connections({}, accepted) == 0
    assert all([await _saw_the_end(client) for client in clients])
    server.close()
    await asyncio.wait_for(server.wait_closed(), timeout=PROMPT_S)


# ── the daemon's own wiring ─────────────────────────────────────────────────


def _daemon(tmp_path: Path, monkeypatch):
    from one_link.daemon import Daemon
    from one_link.identity import Identity, fingerprint_of

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes_raw()
    fp = fingerprint_of(raw)
    return Daemon(Identity(private=sk, public=sk.public_key(), public_bytes=raw, fingerprint=fp,
                           short_id=fp[:8], hostname="stop-host"))


@pytest.mark.asyncio
async def test_request_shutdown_makes_the_daemons_serve_forever_return_with_connections_open(tmp_path, monkeypatch):
    """Daemon.request_shutdown and Daemon.serve_forever, with real servers in the
    daemon's own slots and connections shaped like a tail client and a peer."""
    daemon = _daemon(tmp_path, monkeypatch)
    daemon._peer_server, peer_port = await _serve(_until_the_connection_ends, daemon._accepted_connections)
    daemon._control_server, control_port = await _serve(_until_the_connection_ends, daemon._accepted_connections)
    clients = await _connect(peer_port) + await _connect(control_port)

    serving = asyncio.create_task(daemon.serve_forever())
    await asyncio.sleep(0.2)
    assert not serving.done()

    await daemon.request_shutdown(delay_s=0)
    await asyncio.wait_for(serving, timeout=PROMPT_S)
    assert daemon._shutdown_requested is True
    assert all([await _saw_the_end(client) for client in clients])
    # stop() awaits these again; they must have nothing left to wait for.
    await asyncio.wait_for(daemon._peer_server.wait_closed(), timeout=1.0)
    await asyncio.wait_for(daemon._control_server.wait_closed(), timeout=1.0)


def test_both_of_the_daemons_servers_register_what_they_accept():
    """The stop can only end connections it knows about."""
    from one_link import daemon as daemon_module

    source = Path(daemon_module.__file__).read_text(encoding="utf-8")
    assert source.count("asyncio.start_server(") == 2, "a third server: register its connections too"
    assert "self._accepted_connections.tracking(self._handle_peer)," in source
    assert "self._accepted_connections.tracking(self._handle_control)," in source
    assert "await connection_shutdown.serve_until_stopped(" in source
    assert connection_shutdown.CLOSE_GRACE_S <= 5 and connection_shutdown.SWEEP_INTERVAL_S <= 1
