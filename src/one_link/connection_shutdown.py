"""A stopping daemon does not wait for a connection to end by itself.

Since Python 3.12, ``asyncio.Server.wait_closed()`` waits until every connection
the server accepted has been closed, and ``Server.serve_forever()`` awaits it
once the server is closed. The daemon's stop path was written for the earlier
behaviour (its own comment: "existing handlers outlive wait_closed(); it only
prevents new accepts"). On 3.12 a requested stop therefore waited for

* every authenticated peer session, until that peer had been quiet for the idle
  limit (120 s, or the acceptance window of about five minutes for a session
  carrying a file offer held for the owner);
* every ``tail`` subscriber on the control socket for as long as it stayed
  attached, which is indefinitely;
* every control command still in progress.

Measured on scratch daemons (2026-11-26, Python 3.12.13): with nothing
connected a daemon stopped in 1.8 s; with a tail client attached, or with one
quiet peer session, it was still running 45 s after the stop was acknowledged.
On a live install this turned an update's stop into a 90-second wait that ended
only when a peer hit its idle limit, and it is why a launcher replacing a
daemon timed out and killed it, leaving the "prior shutdown was unclean"
integrity check for the next start.

Stopping means stopping: the listeners are closed, every accepted connection is
closed, and only then does the daemon retire its stores. A transfer in progress
is interrupted and resumes after the restart, as it did before 3.12. The
updater's own drain refuses to begin while transfers are active; that guard is
separate and unchanged.

The daemon registers every connection its two servers accept
(:class:`AcceptedConnections`) and serves through :func:`serve_until_stopped`,
which is the one place that ends them, whichever way the stop arrives: the
stopping event (``Daemon.request_shutdown``) or cancellation of the serving
task (an interrupt).

An independent review of this module found two things it had missed, both
closed here. A connection that is *closing* is not yet closed: one closed with
bytes still unsent to a client that has stopped reading (a tail subscriber
evicted for being slow, say) is still counted by the server, and the stop used
to skip it and could wait on it for ever. And before Python 3.12, where a
closed server does not wait, serving had already ended by the time the stop
looked, so it ended nothing; connections are now ended once in every case.

Tests: ``tests/test_connection_shutdown.py`` (real asyncio servers, including
the 3.12 behaviour this exists for) and
``tests/test_daemon_stops_with_open_connections.py`` (real daemons with a tail
client, a quiet peer session, a held file offer and owner windows that no
longer answer).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, Awaitable, Callable, Iterable, Mapping, Sequence

log = logging.getLogger("one_link.connection_shutdown")

# How long one connection gets to close in an orderly way before it is aborted.
CLOSE_GRACE_S = 2.0
# How often the stop looks again for connections that registered late (one
# that was mid-handshake when the stop began, for example).
SWEEP_INTERVAL_S = 0.5

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class AcceptedConnections:
    """Every connection a server accepted and has not been seen to close."""

    def __init__(self) -> None:
        self._writers: set[asyncio.StreamWriter] = set()

    def tracking(self, handler: Handler) -> Handler:
        """Wrap a ``start_server`` callback so its connections are registered."""

        async def tracked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self._writers.add(writer)
            try:
                await handler(reader, writer)
            finally:
                # Forget a connection only once its transport has let go of it.
                # The server goes on counting one whose handler returned
                # without closing it, and also one that was closed with bytes
                # still unsent to a client that is not reading: closing is not
                # closed. Both stay registered so that a stop can end them.
                if writer.is_closing():
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    self._writers.discard(writer)

        return tracked

    def open_writers(self) -> tuple[asyncio.StreamWriter, ...]:
        return tuple(self._writers)

    def forget_closed(self) -> None:
        self._writers = {writer for writer in self._writers if not writer.is_closing()}


def _abort(writer: Any) -> None:
    transport = getattr(writer, "transport", None)
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.abort()


async def end_open_connections(
    live_channels: Mapping[str, Iterable[Any]],
    accepted: AcceptedConnections,
    *,
    grace_s: float = CLOSE_GRACE_S,
) -> int:
    """Close every authenticated channel and every other accepted connection.

    Channels are closed through ``channel.close()`` so sends queued behind
    their handshake are released rather than leaked; anything else the servers
    accepted (a connection still in its handshake, a tail subscriber, a control
    command in progress) is closed at the transport. A connection that does
    not close within ``grace_s`` is aborted. Returns how many were ended.
    """
    channels = {id(c): c for group in list(live_channels.values()) for c in list(group)}

    async def close_channel(channel: Any) -> None:
        try:
            await asyncio.wait_for(channel.close(), timeout=grace_s)
        except Exception:  # a close that fails or stalls must not hold the stop
            _abort(getattr(channel, "writer", None))

    if channels:
        await asyncio.gather(*(close_channel(channel) for channel in channels.values()))
    channel_writers = {id(getattr(channel, "writer", None)) for channel in channels.values()}
    # Including the ones already closing: a transport that is still flushing
    # to a client that does not read is still a connection the server waits for.
    writers = [w for w in accepted.open_writers() if id(w) not in channel_writers]
    for writer in writers:
        with contextlib.suppress(Exception):
            writer.close()
    if writers:
        waits = {asyncio.ensure_future(writer.wait_closed()): writer for writer in writers}
        done, pending = await asyncio.wait(waits, timeout=grace_s)
        for task in pending:
            task.cancel()
            _abort(waits[task])
        for task in done:
            # A connection the other side had already reset reports that here.
            task.exception() if not task.cancelled() else None
    accepted.forget_closed()
    ended = len(channels) + len(writers)
    if ended:
        log.info("stopping: ended %d open connection(s)", ended)
    return ended


async def serve_until_stopped(
    servers: Sequence[asyncio.AbstractServer],
    stopping: asyncio.Event,
    live_channels: Mapping[str, Iterable[Any]],
    accepted: AcceptedConnections,
    *,
    grace_s: float = CLOSE_GRACE_S,
    sweep_s: float = SWEEP_INTERVAL_S,
) -> None:
    """Serve until ``stopping`` is set or this task is cancelled, then let go.

    On the way out the servers are closed and their connections are ended,
    repeatedly, until the servers report that nothing is left. Returning from
    here therefore never depends on a peer, a subscriber or a command finishing
    by itself.
    """
    serving: list[asyncio.Future[Any]] = [
        asyncio.ensure_future(server.serve_forever()) for server in servers
    ]
    stop_wait: asyncio.Future[Any] = asyncio.ensure_future(stopping.wait())
    try:
        # Any one server ending (closed, or failed) ends the serving of all.
        await asyncio.wait({*serving, stop_wait}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop_wait.cancel()
        for server in servers:
            server.close()
        # Once in every case: before Python 3.12 a closed server does not wait
        # for its connections, so nothing below would run and they would be
        # left for the process exit to cut.
        await end_open_connections(live_channels, accepted, grace_s=grace_s)
        while still_serving := [task for task in serving if not task.done()]:
            await asyncio.wait(still_serving, timeout=sweep_s)
            await end_open_connections(live_channels, accepted, grace_s=grace_s)
    for task in serving:
        if task.cancelled():
            continue  # how Server.serve_forever() reports that it was closed
        failure = task.exception()
        if failure is None:
            continue
        if isinstance(failure, RuntimeError) and "is closed" in str(failure):
            continue  # closed before it ever served
        raise failure
