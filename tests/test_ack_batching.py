"""A sender and a receiver that batch acknowledgements never wait on each other.

Why this file exists. A file send between two freshly paired daemons stalled
for 30 s and was reported as paused ("peer did not ACK within 30.0s") in 2 of
71 runs on a workstation and once on a hosted runner. The sender had stopped
to wait for an acknowledgement; the receiver was holding that acknowledgement
until more chunks arrived. ``src/one_link/ack_batching.py`` describes how the
two got there.

The stall is a property of rules, not of timing, so it is searched for rather
than sampled. ``_simulate`` runs the send loop of ``Daemon.send_file`` against
the receive rule of ``Daemon._ack_file_chunk``, calling the functions both of
them call and the real window controller. The only free variable is how fast
each acknowledgement looked to that controller (fast, middling or slow), and
``_search`` tries every sequence of those, visiting each reachable state once.

Declared space of the search: every combination in ``_GRID`` (the batch size
the peers negotiated, the controller's starting and largest window, its growth
step) for transfers of up to ``_CHUNKS`` chunks. A result of "no stall" is a
statement about that space and about these rules, not about the network. What
ties the rules to the daemon is the last test in this file.
"""
from __future__ import annotations

import asyncio
import dataclasses
import io
import itertools
import re
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from one_link import ack_batching
from one_link.daemon import FILE_ACK_BATCH_MAX, Daemon, IncomingFile
from one_link.transfer_brain import AdaptiveTransferScheduler
from one_link.wire import decode_msg

# How an acknowledgement can look to the window controller, as a round trip in
# milliseconds against the 25 ms target the profile below gives it: at most
# 1.35x the target opens the window, at least 4x halves it, in between does
# neither.
_FAST, _MIDDLING, _SLOW = 1.0, 50.0, 1000.0
_SPEEDS = (_FAST, _MIDDLING, _SLOW)

_CHUNKS = 12
_GRID = tuple(
    {"negotiated": negotiated, "initial_window": initial, "max_window": largest, "growth": growth}
    for negotiated, initial, largest, growth in itertools.product(
        (1, 2, 3, 4, 5, 8, 16, FILE_ACK_BATCH_MAX),
        (1, 2, 3, 4, 6, 8),
        (8, 32),
        (1, 2, 4),
    )
    if initial <= largest
)


def _whenever_the_window_is_full(scheduler, unanswered: int, _last_declared_batch: int) -> bool:
    """What the sender did before: a full window was reason enough to wait."""
    return not scheduler.can_send(unanswered)


class _Refused(Exception):
    """The sender was told its transfer is refused. That ends it; it is not a stall."""


class _NeedsChoice(Exception):
    def __init__(self, state: tuple) -> None:
        super().__init__("the next acknowledgement's speed has not been chosen")
        self.state = state


def _simulate(
    speeds: tuple[float, ...],
    *,
    negotiated: int,
    initial_window: int,
    max_window: int,
    growth: int,
    chunks: int,
    waits,
    receiver_answers_partial_batches: bool,
    refuses: int | None = None,
    sender_hears_any_refusal: bool = True,
    receiver_forgets_on_abandon: bool = True,
) -> dict[str, Any] | str | None:
    """One transfer. Returns ``None`` when it completes, ``"refused"`` when the
    sender is told the receiver refused a chunk, or a description of the stall.

    ``refuses`` is the chunk the receiver refuses, abandoning the transfer (a
    full disk, a broken sequence): it says so at once and answers nothing
    after it.

    Raises ``_NeedsChoice`` when ``speeds`` runs out, carrying the full state at
    that point so the search can recognise a state it has already expanded.
    """
    scheduler = AdaptiveTransferScheduler(
        {"chunk_size": 1, "window_chunks": initial_window, "growth_step_bytes": growth, "target_ack_ms": 10.0},
        max_window_chunks=max_window,
    )
    pending: deque[int] = deque()  # the sender's unsettled chunks, in the order sent
    acknowledged_early: set[int] = set()  # answered by a batch frame, not settled yet
    held: list[int] = []  # the receiver's unanswered chunks
    frames: deque[tuple[str, tuple[int, ...]]] = deque()  # receiver -> sender, in order
    used = 0
    last_batch = 0
    sent = 0
    sent_past_a_full_window = False
    abandoned = False

    def settle_front() -> None:
        # The settle closures of Daemon.send_file: one chunk per call.
        nonlocal used
        front = pending[0]
        if used == len(speeds):
            raise _NeedsChoice((
                sent, scheduler.window_chunks, scheduler._good_acks, sent_past_a_full_window, abandoned,
                tuple(pending), tuple(sorted(acknowledged_early)), tuple(held), tuple(frames),
            ))
        pending.popleft()
        scheduler.observe_ack(
            ack_ms=speeds[used], raw_bytes=1, wire_bytes=1, in_flight_chunks=len(pending),
        )
        used += 1
        assert front not in pending

    def receive(chunk: int, batch: int) -> None:
        nonlocal abandoned
        if abandoned:
            return  # a chunk for a transfer the receiver abandoned gets no reply
        if chunk == refuses:
            # The chunk handlers' reject paths: Daemon._abort_incoming_file, then the refusal.
            abandoned = True
            if receiver_forgets_on_abandon:
                held.clear()
            frames.append(("refused", (chunk,)))
            return
        # Daemon._ack_file_chunk
        if batch <= 1:
            if held:
                frames.append(("batch", tuple(held)))
                held.clear()
            frames.append(("ack", (chunk,)))
            return
        held.append(chunk)
        if ack_batching.batch_is_due(len(held), batch):
            frames.append(("batch", tuple(held)))
            held.clear()

    def acknowledgement_arrives_for(front: int) -> bool:
        # The reply wait inside Daemon.send_file. The receiver has read every
        # chunk sent so far, so an empty queue means nothing more is coming.
        if front in acknowledged_early:
            acknowledged_early.discard(front)
            return True
        while True:
            if not frames:
                if receiver_answers_partial_batches and held:
                    frames.append(("batch", tuple(held)))
                    held.clear()
                    continue
                return False
            kind, ids = frames.popleft()
            if kind == "refused":
                # ack_batching.refusal_of_unanswered_chunk. Before it, only a
                # refusal of the very chunk being waited for was heard.
                if ids == (front,) or (sender_hears_any_refusal and ids[0] in pending):
                    raise _Refused()
                continue
            if kind == "batch":
                rest = set(ids)
                if front in rest:
                    rest.discard(front)
                    acknowledged_early.update(rest)
                    return True
                acknowledged_early.update(rest)
            elif ids == (front,):
                return True
            # An individual acknowledgement of any other chunk is ignored.

    def settle_one() -> dict[str, Any] | None:
        if not acknowledgement_arrives_for(pending[0]):
            return {
                "chunks_sent": sent,
                "window": scheduler.window_chunks,
                "last_declared_batch": last_batch,
                "sender_waits_for": pending[0],
                "sender_unanswered": list(pending),
                "receiver_holds": list(held),
                "speeds": speeds[:used],
            }
        settle_front()
        return None

    def send_everything() -> dict[str, Any] | None:
        nonlocal last_batch, sent, sent_past_a_full_window
        for index in range(chunks):
            last_batch = ack_batching.declared_batch(negotiated, scheduler.window_chunks, chunks - index)
            receive(index, last_batch)
            pending.append(index)
            sent += 1
            waited = False
            while waits(scheduler, len(pending), last_batch):
                stall = settle_one()
                if stall is not None:
                    return stall
                waited = True
            if not scheduler.can_send(len(pending)):
                # The loop is about to send although the window is full, because
                # the last promise is not met yet. It may do that for one chunk.
                assert not sent_past_a_full_window or waited, "two chunks in a row were sent past a full window"
                sent_past_a_full_window = True
            else:
                sent_past_a_full_window = False
        while pending:
            stall = settle_one()
            if stall is not None:
                return stall
        return None

    try:
        return send_everything()
    except _Refused:
        return "refused"


def _search(
    *, chunks: int = _CHUNKS, outcomes: dict[str, int] | None = None, **config,
) -> tuple[dict[str, Any] | None, int]:
    """Try every sequence of acknowledgement speeds.

    Returns (first stall or None, transfers that ended without one). ``outcomes``
    is filled with how many of those completed and how many were refused.
    """
    seen: set[tuple] = set()
    stack: list[tuple[float, ...]] = [()]
    ended = 0
    while stack:
        speeds = stack.pop()
        try:
            result = _simulate(speeds, chunks=chunks, **config)
        except _NeedsChoice as need:
            if need.state not in seen:
                seen.add(need.state)
                stack.extend(speeds + (speed,) for speed in _SPEEDS)
            continue
        if isinstance(result, dict):
            return result, ended
        ended += 1
        if outcomes is not None:
            kind = "refused" if result == "refused" else "completed"
            outcomes[kind] = outcomes.get(kind, 0) + 1
    return None, ended


# ── the rules, searched ──────────────────────────────────────────────


def test_no_wait_is_endless_even_with_a_receiver_that_never_answers_a_partial_batch():
    completed = 0
    for config in _GRID:
        stall, finished = _search(
            waits=ack_batching.sender_waits, receiver_answers_partial_batches=False, **config,
        )
        assert stall is None, (config, stall)
        assert finished > 0, config
        completed += finished
    # Every configuration ran transfers to their end; most have many distinct histories.
    assert completed > 20 * len(_GRID)


def test_the_search_finds_the_stall_in_the_sender_that_waited_whenever_its_window_was_full():
    """The search can fail: with the rule that shipped it finds the field failure."""
    stalls = {}
    for index, config in enumerate(_GRID):
        stall, _finished = _search(
            waits=_whenever_the_window_is_full, receiver_answers_partial_batches=False, **config,
        )
        if stall is not None:
            stalls[index] = stall
    assert len(stalls) > len(_GRID) // 2, "the shipped rule should stall in most configurations that batch"
    for stall in stalls.values():
        # The shape of the field failure: the sender waits with fewer chunks
        # unanswered than its last chunk promised, so the receiver, holding
        # every one of them, is still waiting for more.
        assert len(stall["sender_unanswered"]) < stall["last_declared_batch"]
        assert stall["receiver_holds"] == stall["sender_unanswered"]
        assert stall["window"] < stall["last_declared_batch"], "the window had to shrink after the promise"
        assert _SLOW in stall["speeds"]
    # It needs batching: with a negotiated batch of one there is nothing to hold.
    assert all(_GRID[index]["negotiated"] > 1 for index in stalls)
    assert not any(config["negotiated"] == 1 for config in (_GRID[index] for index in stalls))


def test_the_smallest_stall_of_the_shipped_rule():
    """Pins the witness the module's account is written from."""
    config = {"negotiated": 2, "initial_window": 3, "max_window": 8, "growth": 1}
    found = None
    for chunks in range(1, _CHUNKS + 1):
        stall, _finished = _search(
            chunks=chunks, waits=_whenever_the_window_is_full, receiver_answers_partial_batches=False, **config,
        )
        if stall is not None:
            found = (chunks, stall)
            break
    assert found is not None
    chunks, stall = found
    # Four chunks to send; the stall comes after the third.
    assert (chunks, stall["chunks_sent"]) == (4, 3)
    assert stall["speeds"] == (_SLOW, _SLOW), "the first two chunks, answered in one batch, both read as slow"
    assert stall["last_declared_batch"] == 2 and stall["window"] == 1
    assert stall["sender_unanswered"] == stall["receiver_holds"] == [2]
    # No configuration stalls sooner.
    for other in _GRID:
        earlier, _finished = _search(
            chunks=3, waits=_whenever_the_window_is_full, receiver_answers_partial_batches=False, **other,
        )
        assert earlier is None, other
    # And the corrected rule completes the same transfer whatever the speeds.
    assert _search(
        chunks=chunks, waits=ack_batching.sender_waits, receiver_answers_partial_batches=False, **config,
    )[0] is None


def test_a_receiver_that_answers_partial_batches_ends_every_wait_of_the_shipped_sender():
    for config in _GRID:
        stall, finished = _search(
            waits=_whenever_the_window_is_full, receiver_answers_partial_batches=True, **config,
        )
        assert stall is None, (config, stall)
        assert finished > 0, config


# ── a chunk the receiver refuses ─────────────────────────────────────
#
# Everything above assumes each chunk is answered. A receiver that refuses a
# chunk says so at once, out of turn, and abandons the transfer. An independent
# review of the first version of this change produced the case below; the
# claim had not covered it.

_REFUSAL_CHUNKS = 6
_REFUSAL_GRID = tuple(
    config for config in _GRID
    if config["negotiated"] in (1, 2, 4, 8) and config["initial_window"] in (1, 2, 4, 8)
    and config["max_window"] == 8 and config["growth"] in (1, 2)
)


def _refusals(**rules) -> tuple[list[tuple[dict, int, dict]], dict[str, int]]:
    """Every configuration and every chunk the receiver could refuse: (stalls, how the rest ended)."""
    stalls = []
    outcomes: dict[str, int] = {}
    for config in _REFUSAL_GRID:
        for refused in range(_REFUSAL_CHUNKS):
            stall, _ended = _search(
                chunks=_REFUSAL_CHUNKS, outcomes=outcomes, refuses=refused,
                waits=ack_batching.sender_waits, **rules, **config,
            )
            if stall is not None:
                stalls.append((config, refused, stall))
    return stalls, outcomes


@pytest.mark.parametrize("receiver_is_current", [True, False])
def test_a_refused_chunk_ends_the_transfer_whatever_the_receiver_was_holding(receiver_is_current):
    stalls, outcomes = _refusals(
        receiver_answers_partial_batches=receiver_is_current, receiver_forgets_on_abandon=receiver_is_current,
    )
    assert stalls == [], stalls[:1]
    # Every history ended with the sender told of the refusal. None completed:
    # a refused chunk is never answered, so a sender that finished would have
    # been told a lie.
    assert outcomes.get("completed", 0) == 0
    assert outcomes["refused"] >= len(_REFUSAL_GRID) * _REFUSAL_CHUNKS


@pytest.mark.parametrize("receiver_is_current", [True, False])
def test_a_sender_that_hears_only_the_answer_it_awaits_misses_a_refusal_behind_a_held_answer(receiver_is_current):
    """The search can fail here too. It is also what remains for a sender that predates the change."""
    stalls, _outcomes = _refusals(
        sender_hears_any_refusal=False,
        receiver_answers_partial_batches=receiver_is_current, receiver_forgets_on_abandon=receiver_is_current,
    )
    assert stalls, "the old reply wait no longer misses a refusal in this model"
    for config, refused, stall in stalls:
        # It waits for an earlier chunk, having thrown away the refusal of a later one.
        assert stall["sender_waits_for"] < refused, (config, refused, stall)
        assert config["negotiated"] > 1, "without batching, answers arrive in the order awaited"


def test_the_smallest_missed_refusal():
    """Two chunks: the first held for a batch of two, the second refused."""
    config = {"negotiated": 2, "initial_window": 2, "max_window": 8, "growth": 1}
    rules = {"waits": ack_batching.sender_waits, "receiver_answers_partial_batches": False, "refuses": 1}
    stall, _ended = _search(
        chunks=2, sender_hears_any_refusal=False, receiver_forgets_on_abandon=False, **rules, **config,
    )
    assert stall is not None
    assert stall["sender_waits_for"] == 0 and stall["receiver_holds"] == [0] and stall["chunks_sent"] == 2
    outcomes: dict[str, int] = {}
    assert _search(chunks=2, outcomes=outcomes, receiver_forgets_on_abandon=False, **rules, **config)[0] is None
    assert outcomes == {"refused": 1}


# ── the pieces ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("negotiated", "window", "remaining", "expected"),
    [
        (8, 4, 100, 4),    # no more than the window
        (8, 32, 100, 8),   # no more than the peer agreed to
        (8, 32, 3, 3),     # no more than is left to send
        (8, 32, 1, 1),     # the last chunk is always answered by itself
        (1, 32, 100, 1),   # a peer that does not batch
        (8, 0, 100, 1),    # never less than one
        (0, 8, 100, 1),
        (8, 8, 0, 1),
    ],
)
def test_declared_batch(negotiated, window, remaining, expected):
    assert ack_batching.declared_batch(negotiated, window, remaining) == expected


@pytest.mark.parametrize(
    ("unanswered", "promised", "expected"),
    [(1, 2, False), (2, 2, True), (3, 2, True), (1, 1, True), (0, 1, False), (7, 8, False), (8, 8, True)],
)
def test_a_sender_waits_only_on_a_promise_it_has_kept(unanswered, promised, expected):
    assert ack_batching.may_wait(unanswered, promised) is expected


_PENDING = [("c1", 10, 0.0), ("c2", 10, 0.0), ("c3", 10, 0.0)]


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ({"t": "ACK", "of": "c2", "rejected": "receiver_disk_write_failed"}, "receiver_disk_write_failed"),
        ({"t": "ACK", "of": "c3", "ok": False, "error": "no room"}, "no room"),
        ({"t": "ACK", "of": "c3", "ok": False}, "peer rejected file-transfer request"),
        ({"t": "ACK", "of": "c1", "rejected": "bad_file_chunk_sequence"}, "bad_file_chunk_sequence"),
        ({"t": "ACK", "of": "c2"}, None),                                   # an ordinary answer
        ({"t": "ACK", "of": "c2", "ok": True}, None),
        ({"t": "ACK", "of": "c9", "rejected": "something"}, None),          # not one of ours: left to the caller
        ({"t": "ACK", "rejected": "something"}, None),
        ({"t": "FILE_ACK_BATCH", "ofs": ["c2"], "rejected": "x"}, None),    # only an ACK refuses a chunk
        ({"t": "FILE_DECLINED", "of": "c2", "rejected": "x"}, None),        # even one that names a pending chunk
    ],
)
def test_a_refusal_is_recognised_only_for_a_chunk_that_is_still_unanswered(message, expected):
    assert ack_batching.refusal_of_unanswered_chunk(message, [deque(_PENDING)]) == expected


def test_a_refusal_is_looked_for_in_every_queue_and_in_none_when_there_is_none():
    refusal = {"t": "ACK", "of": "c2", "rejected": "why"}
    assert ack_batching.refusal_of_unanswered_chunk(refusal, [deque(), deque(_PENDING)]) == "why"
    assert ack_batching.refusal_of_unanswered_chunk(refusal, [deque()]) is None
    assert ack_batching.refusal_of_unanswered_chunk(refusal, []) is None


def test_a_partial_batch_is_answered_after_the_delay_and_only_once():
    async def scenario() -> None:
        holder = SimpleNamespace(ack_batch_ids=["a"], ack_batch_timer=None)
        flushed: list[list[str]] = []
        tasks: list[asyncio.Task] = []

        async def flush() -> None:
            flushed.append(list(holder.ack_batch_ids))
            holder.ack_batch_ids.clear()

        def spawn(coro):
            task = asyncio.ensure_future(coro)
            tasks.append(task)
            return task

        assert ack_batching.arm_partial_flush(holder, flush, spawn=spawn, delay_s=0.2)
        # A later chunk neither restarts the timer nor arms a second one.
        await asyncio.sleep(0.12)
        holder.ack_batch_ids.append("b")
        assert not ack_batching.arm_partial_flush(holder, flush, spawn=spawn, delay_s=0.2)
        assert flushed == []
        # 0.27 s after arming: a timer restarted at 0.12 s would not have fired yet.
        await asyncio.sleep(0.15)
        await asyncio.gather(*tasks)
        assert flushed == [["a", "b"]], "the oldest chunk waited longer than the delay, or was answered twice"
        assert holder.ack_batch_timer is None
        # Nothing held: nothing to arm.
        assert not ack_batching.arm_partial_flush(holder, flush, spawn=spawn, delay_s=0.2)

    asyncio.run(scenario())


def test_a_batch_that_fills_first_cancels_the_timer():
    async def scenario() -> None:
        holder = SimpleNamespace(ack_batch_ids=["a"], ack_batch_timer=None)
        spawned: list[Any] = []

        async def flush() -> None:  # pragma: no cover - must not run
            raise AssertionError("the timer fired after it was cancelled")

        assert ack_batching.arm_partial_flush(holder, flush, spawn=spawned.append, delay_s=0.03)
        ack_batching.disarm_partial_flush(holder)
        assert holder.ack_batch_timer is None
        ack_batching.disarm_partial_flush(holder)  # twice is harmless
        await asyncio.sleep(0.1)
        assert spawned == []

    asyncio.run(scenario())


def test_a_timer_that_finds_nothing_held_sends_nothing():
    async def scenario() -> None:
        holder = SimpleNamespace(ack_batch_ids=["a"], ack_batch_timer=None)
        spawned: list[Any] = []

        async def flush() -> None:  # pragma: no cover - must not run
            raise AssertionError("an empty batch was sent")

        ack_batching.arm_partial_flush(holder, flush, spawn=spawned.append, delay_s=0.03)
        holder.ack_batch_ids.clear()  # answered some other way, timer left armed
        await asyncio.sleep(0.1)
        assert spawned == [] and holder.ack_batch_timer is None

    asyncio.run(scenario())


def test_a_late_answer_on_a_closed_connection_is_not_an_error():
    async def scenario() -> None:
        holder = SimpleNamespace(ack_batch_ids=["a"], ack_batch_timer=None)
        tasks: list[asyncio.Task] = []

        async def flush() -> None:
            raise ConnectionResetError("the connection ended")

        def spawn(coro):
            task = asyncio.ensure_future(coro)
            tasks.append(task)
            return task

        ack_batching.arm_partial_flush(holder, flush, spawn=spawn, delay_s=0.01)
        await asyncio.sleep(0.1)
        assert len(tasks) == 1
        assert await asyncio.gather(*tasks) == [None]

    asyncio.run(scenario())


# ── the daemon's receiver, for real ──────────────────────────────────


class _RecordingChannel:
    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    async def send(self, data: bytes) -> None:
        self.frames.append(decode_msg(data))


def _incoming_file() -> IncomingFile:
    return IncomingFile(
        name="f.bin", size=1, blob_hex="ab" * 32, out_path=Path("f.bin"), handle=io.BytesIO(), hasher=object(),
    )


def _bare_daemon() -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon.me = SimpleNamespace(short_id="receiver")
    return daemon


def _acks(channel: _RecordingChannel) -> list[tuple[str, list[str]]]:
    out = []
    for frame in channel.frames:
        if frame["t"] == "FILE_ACK_BATCH":
            out.append(("batch", list(frame["ofs"])))
        elif frame["t"] == "ACK":
            out.append(("ack", [frame["of"]]))
    return out


def test_the_incoming_file_record_carries_the_timer():
    names = {field.name for field in dataclasses.fields(IncomingFile)}
    assert {"ack_batch_ids", "ack_batch_timer"} <= names
    assert _incoming_file().ack_batch_timer is None


def test_the_daemon_answers_a_batch_the_sender_never_fills():
    """Two chunks promising a batch of eight, and then nothing: the old receiver waited for ever."""

    async def scenario() -> None:
        daemon, channel, incoming = _bare_daemon(), _RecordingChannel(), _incoming_file()
        await daemon._ack_file_chunk(channel, {"id": "c1", "ack_batch": 8}, incoming)
        await daemon._ack_file_chunk(channel, {"id": "c2", "ack_batch": 8}, incoming)
        assert _acks(channel) == [], "a partial batch is held, not answered at once"
        assert incoming.ack_batch_timer is not None
        await asyncio.sleep(ack_batching.PARTIAL_BATCH_FLUSH_S * 3)
        await asyncio.gather(*list(getattr(daemon, "_background_tasks", ())))
        assert _acks(channel) == [("batch", ["c1", "c2"])]
        assert incoming.ack_batch_ids == [] and incoming.ack_batch_timer is None

    asyncio.run(scenario())


def test_the_daemon_answers_a_full_batch_at_once_and_drops_the_timer():
    async def scenario() -> None:
        daemon, channel, incoming = _bare_daemon(), _RecordingChannel(), _incoming_file()
        await daemon._ack_file_chunk(channel, {"id": "c1", "ack_batch": 2}, incoming)
        assert incoming.ack_batch_timer is not None
        await daemon._ack_file_chunk(channel, {"id": "c2", "ack_batch": 2}, incoming)
        assert _acks(channel) == [("batch", ["c1", "c2"])]
        assert incoming.ack_batch_timer is None
        await asyncio.sleep(ack_batching.PARTIAL_BATCH_FLUSH_S * 2)
        assert _acks(channel) == [("batch", ["c1", "c2"])], "the cancelled timer answered again"

    asyncio.run(scenario())


def test_an_individual_answer_sends_what_was_held_first_so_answers_stay_in_order():
    async def scenario() -> None:
        daemon, channel, incoming = _bare_daemon(), _RecordingChannel(), _incoming_file()
        await daemon._ack_file_chunk(channel, {"id": "c1", "ack_batch": 4}, incoming)
        await daemon._ack_file_chunk(channel, {"id": "c2"}, incoming)  # no batch: answered by itself
        assert _acks(channel) == [("batch", ["c1"]), ("ack", ["c2"])]
        assert incoming.ack_batch_timer is None
        await daemon._ack_file_chunk(channel, {"id": "c3", "ack_batch": 4}, incoming)
        await daemon._ack_file_chunk(channel, {"id": "c4", "ack_batch": 4}, incoming, force_individual=True)
        assert _acks(channel)[2:] == [("batch", ["c3"]), ("ack", ["c4"])]
        await asyncio.sleep(ack_batching.PARTIAL_BATCH_FLUSH_S * 2)
        assert len(_acks(channel)) == 4, "a timer left armed answered again"

    asyncio.run(scenario())


def test_an_abandoned_transfer_drops_the_answers_it_was_holding():
    """Otherwise the timer answers for a transfer that has ended, a tenth of a second after it did."""

    async def scenario(tmp: Path) -> None:
        daemon, channel = _bare_daemon(), _RecordingChannel()
        incoming = IncomingFile(
            name="f.bin", size=1, blob_hex="ab" * 32, out_path=tmp / "f.part", handle=io.BytesIO(), hasher=object(),
        )
        daemon.state = None
        daemon._incoming_files = {incoming.blob_hex: incoming}
        daemon._release_inbound_reservation = lambda f: None
        daemon._resume_metadata_root = tmp
        daemon._update_transfer = lambda *args, **kwargs: None
        await daemon._ack_file_chunk(channel, {"id": "c1", "ack_batch": 4}, incoming)
        assert incoming.ack_batch_ids == ["c1"] and incoming.ack_batch_timer is not None
        daemon._abort_incoming_file(incoming.blob_hex, incoming)
        assert incoming.ack_batch_ids == [] and incoming.ack_batch_timer is None
        assert incoming.blob_hex not in daemon._incoming_files
        await asyncio.sleep(ack_batching.PARTIAL_BATCH_FLUSH_S * 3)
        assert _acks(channel) == [], "an answer was sent for a transfer that had been abandoned"

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        asyncio.run(scenario(Path(tmp)))


# ── the daemon's sender is the loop that was searched ────────────────


def test_both_send_loops_are_the_loop_that_was_searched():
    """The search covers one loop shape: promise with ``declared_batch``, then
    wait while ``sender_waits`` says so -- the two calls ``_simulate`` makes.

    It says nothing about a send loop that computes its batch some other way
    or waits on some other condition, so both loops are held to that shape,
    and the receiver to the rule and the timer the search assumes.
    """
    source = (Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py").read_text(encoding="utf-8")
    flat = re.sub(r"\s+", " ", source)
    for scheduler, pending in (("cdc_scheduler", "pending_cdc_sizes"), ("stream_scheduler", "pending_sizes")):
        promise = f"chunk_ack_batch = ack_batching.declared_batch( negotiated_ack_batch, {scheduler}.window_chunks,"
        assert flat.count(promise) == 1, promise
        wait = f"while ack_batching.sender_waits( {scheduler}, len({pending}), chunk_ack_batch, ):"
        assert flat.count(wait) == 1, wait
    # The stream path has a second loop: chunks re-sent on the connection after
    # a failed QUIC batch wait on the promise each of them was built with.
    resent = 'while ack_batching.sender_waits( stream_scheduler, len(pending_sizes), int(fb_msg.get("ack_batch") or 1), ):'
    assert flat.count(resent) == 1
    # Nothing in the daemon asks a window controller directly whether to stop.
    assert flat.count("ack_batching.sender_waits(") == 3
    assert ".can_send(" not in source
    assert "chunk_ack_batch = min(" not in source, "a batch is still computed inline"
    assert flat.count("ack_batching.batch_is_due(len(f.ack_batch_ids), batch_size)") == 1
    assert flat.count("ack_batching.arm_partial_flush(") == 1
    # A flush disarms the timer, and so does abandoning the transfer, which also drops what was held.
    assert flat.count("ack_batching.disarm_partial_flush(f)") == 2
    assert flat.count(
        "def _abort_incoming_file(self, blob: str, f: IncomingFile) -> None: "
        "ack_batching.disarm_partial_flush(f) f.ack_batch_ids.clear()"
    ) == 1
    # The reply wait hears a refusal of any chunk still in either loop's queue.
    assert flat.count("refusal = ack_batching.refusal_of_unanswered_chunk(m, unanswered_chunks)") == 1
    assert flat.count("unanswered_chunks.append(pending_cdc_sizes)") == 1
    assert flat.count("unanswered_chunks.append(pending_sizes)") == 1
