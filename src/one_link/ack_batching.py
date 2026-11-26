"""Batched chunk acknowledgements: what a sender promises and what a receiver waits for.

A file sender pipelines chunks inside a window and lets the receiver answer
several of them with one ``FILE_ACK_BATCH``. Each chunk carries the batch size
the receiver should fill before answering (``ack_batch``), and the receiver
answers when it holds that many.

That number is a promise: *I will not stop and wait for an acknowledgement
until at least this many chunks are unanswered.* The sender derives it from its
window (``declared_batch``) and stops when the window is full. The window is
adaptive, and a slow acknowledgement halves it.

The defect this module closes. The promise was made with the window as it was
when the chunk was sent, and the decision to stop was made with the window as
it was afterwards. Reading one slow acknowledgement in between could halve the
window, so the sender stopped to wait with fewer chunks unanswered than its
last chunk had promised. The receiver held every one of them and waited for
more. Neither side had a timer shorter than the sender's 30 s acknowledgement
deadline, so the transfer stalled for 30 s and was reported as paused ("peer
did not ACK within 30.0s"). Measured on a workstation: 2 of 71 sends of a
64 MiB file between two freshly paired daemons. It was also the single failure
of a hosted live test, which is how it was found. The smallest case is three
chunks: a window of three and a batch of two, where the first two chunks are
answered slowly and the third has already promised a batch of two.

Two rules, one on each side, either of which is sufficient by itself:

* Sender (``may_wait``): stop and wait only when the chunks unanswered are at
  least the batch the last chunk promised. Otherwise send one more chunk, even
  past a window that has just shrunk. This is what protects a transfer to a
  receiver that predates this module.
* Receiver (``arm_partial_flush``): a batch that is not yet full is answered
  anyway after ``PARTIAL_BATCH_FLUSH_S``. A receiver no longer depends on the
  sender keeping its promise, which is what protects a transfer from a sender
  that predates this module.

Tests: ``tests/test_ack_batching.py`` searches every reachable state of the
sender's send loop against the receiver's rule, driven by the real window
controller, for a wait that can never end. It finds none with either rule in
place and finds the field failure with neither.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

log = logging.getLogger("one_link.ack_batching")

# How long a receiver holds a batch that is not yet full before answering it
# anyway. Far below the sender's acknowledgement deadline (30 s), and long
# enough that a sender streaming chunks back to back fills its batches first.
PARTIAL_BATCH_FLUSH_S = 0.1


def declared_batch(negotiated: int, window_chunks: int, remaining: int) -> int:
    """The batch size a sender may put on the chunk it is about to send.

    Never more than the peer agreed to, never more than the window, and never
    more than the chunks still to come including this one, so the last chunk
    of a transfer is always answered by itself.
    """
    return max(1, min(int(negotiated), max(1, int(window_chunks)), max(1, int(remaining))))


def may_wait(unanswered: int, last_declared_batch: int) -> bool:
    """Whether a sender whose window is full may stop and wait for an answer.

    Only when it has at least as many chunks unanswered as the last chunk it
    sent promised. Otherwise the receiver may be holding all of them and
    waiting for more, so the sender sends one more chunk first, even past a
    window that has just shrunk. That chunk promises a batch no larger than
    the shrunken window, which the chunks already unanswered fill, so the
    receiver answers on reading it: the window is overrun by one chunk, once.

    There is always such a chunk to send. A promise of two or more is only
    made while at least that many chunks remain (``declared_batch``), and the
    last chunk of a transfer promises one.
    """
    return int(unanswered) >= int(last_declared_batch)


def sender_waits(scheduler: Any, unanswered: int, last_declared_batch: int) -> bool:
    """Whether a pipelined sender stops sending now and waits for an answer.

    It does when its window is full and ``may_wait`` allows it. ``scheduler``
    is the transfer's window controller (``can_send(unanswered)``). Every send
    loop asks this and nothing else, so the rule that was searched is the rule
    that runs.
    """
    return not scheduler.can_send(unanswered) and may_wait(unanswered, last_declared_batch)


def batch_is_due(held: int, batch_size: int) -> bool:
    """Whether a receiver holding ``held`` unanswered chunks answers now."""
    return int(held) >= int(batch_size)


def disarm_partial_flush(holder: Any) -> None:
    """Cancel the pending answer-anyway timer of ``holder``, if there is one."""
    timer = getattr(holder, "ack_batch_timer", None)
    if timer is not None:
        timer.cancel()
        holder.ack_batch_timer = None


def arm_partial_flush(
    holder: Any,
    flush: Callable[[], Awaitable[None]],
    *,
    spawn: Callable[[Awaitable[None]], Any],
    delay_s: float = PARTIAL_BATCH_FLUSH_S,
) -> bool:
    """Answer ``holder``'s unfilled batch after ``delay_s`` unless it fills first.

    ``holder`` carries ``ack_batch_ids`` (the unanswered ids) and
    ``ack_batch_timer``. The timer is not restarted by later chunks, so the
    oldest unanswered chunk waits at most ``delay_s``. ``flush`` sends whatever
    is held at that moment; ``spawn`` runs it as a task the caller tracks.
    Returns whether a timer was armed by this call.
    """
    if getattr(holder, "ack_batch_timer", None) is not None or not holder.ack_batch_ids:
        return False

    def fire() -> None:
        holder.ack_batch_timer = None
        if holder.ack_batch_ids:
            spawn(_flush_quietly(flush))

    holder.ack_batch_timer = asyncio.get_running_loop().call_later(delay_s, fire)
    return True


async def _flush_quietly(flush: Callable[[], Awaitable[None]]) -> None:
    # The connection may have ended while the timer was pending. The transfer's
    # own path reports that; a late answer has nobody to report to.
    try:
        await flush()
    except Exception as exc:
        log.debug("partial acknowledgement batch was not sent: %s", exc)
