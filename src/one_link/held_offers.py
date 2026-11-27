"""Offers that are waiting for the owner, and what later offers are told meanwhile.

With accept-first (the default), an incoming file is HELD until the owner
accepts it. A held offer keeps its ``IncomingFile``, its blob entry and its
admission reservation, so until 2026-11-25 the offer handler treated it as a
transfer in progress:

* a second send of the same file from the same device was refused with
  ``admission_blob_in_use_by_another_delivery``;
* with three files held, every further file from that device was refused with
  ``admission_peer_inbound_transfer_quota``;
* the session that carried the held offer was closed at the ordinary idle
  limit (120 s), although its sender had been told to wait and waits five
  minutes. The sender's command then failed with a dropped connection, which is
  what made senders send again, into the first refusal.

All three are answers about load, given to a sender whose files were simply
waiting for a person to click Accept. A live install produced 13 of the first
kind in 16 minutes (holder status ``offered``, held up to 855 s) and then the
second, while its owner's window was unable to show the prompt at all.

The truthful answer is the one the first offer got: ``FILE_OFFER_HELD``. The
sender shows "Waiting for them to accept" and retries; nothing is recorded as
failed on either side.

This module holds those decisions. The daemon keeps the offer handler and calls
in at three points; what this module needs from the daemon is the explicit
:class:`HeldOfferPort`. The decisions that need no daemon at all
(:func:`quota_is_waiting_on_the_owner`, :func:`read_deadline_s`) take plain
values.

Tests: ``tests/test_held_offer_makes_later_offers_wait.py`` (each decision) and
``tests/test_held_offers_two_daemon_e2e.py`` (two real daemons, the real accept
API, including an owner who answers 135 seconds in).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping, MutableMapping, Protocol

from one_link.wire import encode_msg, make_msg

log = logging.getLogger("one_link.held_offers")

OFFER_WAITS_REASON = "awaiting_acceptance"

# The admission reasons that mean "a quota is full". A per-peer quota counts
# one sender's reservations; a global one counts everyone's.
# tests/test_held_offer_makes_later_offers_wait.py checks these against the
# reasons transfer_safety actually produces.
QUOTA_REASONS_PER_PEER = frozenset({"peer_inbound_transfer_quota", "peer_inbound_byte_quota"})
QUOTA_REASONS_GLOBAL = frozenset({"global_inbound_transfer_quota", "global_inbound_byte_quota"})

# A session waiting for OUR owner may stay silent for the sender's acceptance
# wait plus this margin, so it is the sender's own timeout that ends the wait.
HELD_OFFER_READ_MARGIN_S = 15.0


class HeldOfferPort(Protocol):
    """What settling an offer against a held one needs from the daemon."""

    # Read-only members, so the daemon's concrete dict and identity satisfy
    # the port without the port being able to replace either.
    @property
    def me(self) -> Any: ...

    @property
    def _pending_file_offers(self) -> MutableMapping[str, dict]: ...

    def _abort_incoming_file(self, blob: str, f: Any) -> None: ...

    def _update_transfer(self, transfer_id: str | None, **kwargs: Any) -> Any: ...

    def _merge_transfer_metadata(self, transfer_id: str, updates: dict) -> dict: ...

    def _broadcast_file_offer_resolved(self, transfer_id: str) -> None: ...


def quota_is_waiting_on_the_owner(
    pending_offers: Mapping[str, dict], reason: str, peer_fp: str,
) -> bool:
    """Is the quota that refused an offer occupied by offers nobody has answered yet?

    A per-peer quota counts this sender's own held offers; a global one counts
    everyone's. If none is held, the quota is full of transfers that are
    really running and the refusal stands.
    """
    unanswered = [ctx for ctx in pending_offers.values() if not ctx.get("accepted")]
    if reason in QUOTA_REASONS_PER_PEER:
        return any(ctx.get("peer_fp") == peer_fp for ctx in unanswered)
    if reason in QUOTA_REASONS_GLOBAL:
        return bool(unanswered)
    return False


def read_deadline_s(
    pending_offers: Mapping[str, dict],
    channel: Any,
    *,
    idle_s: float,
    accept_wait_s: float,
) -> float:
    """How long ``channel`` may send nothing before it is closed.

    ``idle_s`` bounds a peer that opens a channel and goes quiet (security
    audit H4). A channel carrying an offer we HELD is quiet because we told its
    sender to keep the session open while our owner decides; it gets the
    acceptance window instead. It stays bounded: one window per silence, for
    the channel a held offer is currently bound to. A retry re-binds the
    offer to its own channel, and a wait already started on the earlier
    channel runs out its window, so the number of channels a peer can hold
    this way is bounded by its connection cap, not by its held offers. An
    authenticated peer could already keep any channel open by sending on it.
    """
    for ctx in pending_offers.values():
        if ctx.get("channel") is channel and not ctx.get("accepted"):
            return max(idle_s, accept_wait_s + HELD_OFFER_READ_MARGIN_S)
    return idle_s


async def tell_sender_offer_waits(channel: Any, msg: dict, *, short_id: str, blob: str | None) -> None:
    """Answer an offer with FILE_OFFER_HELD: wait for the owner, then ask again."""
    await channel.send(encode_msg(make_msg(
        "FILE_OFFER_HELD",
        short_id,
        of=msg.get("id"),
        blob=blob,
        reason=OFFER_WAITS_REASON,
    )))


async def settle_offer_against_held_offer(
    port: HeldOfferPort,
    channel: Any,
    msg: dict,
    *,
    holder: Any,
    peer_fp: str,
    peer_sid: str,
    name: str,
    size: int,
    blob: str,
    delivery_id: str,
    delivery_name: str,
    delivery_rel_path: str,
    delivery_kind: str,
) -> str:
    """A different delivery offers content that ``holder`` already claims.

    Returns what was done:

    ``"waiting"``     the holder is an offer the owner has not answered. The
                      sender was told FILE_OFFER_HELD; no state was created and
                      the one prompt the owner sees is unchanged.
    ``"superseded"``  the owner ACCEPTED the holder but the acceptance could not
                      be delivered (its sender went away) and no byte has moved.
                      This delivery is the same file under the same name and
                      declared size to the same place, from the same device, with
                      a live connection: it inherits the acceptance. The stale
                      holder was released. If the handler then refuses this
                      delivery for another reason (disk space, say), the
                      acceptance is not kept: the owner is asked again next time.
    ``"refuse"``      anything else: the content really is being delivered under
                      another identity, and the guard that keeps one delivery
                      from adopting another's data applies.
    """
    holder_id = holder.transfer_id or ""
    ctx = port._pending_file_offers.get(holder_id)
    if (
        ctx is None
        or ctx.get("peer_fp") != peer_fp
        or holder.peer_fp != peer_fp
        or holder.finalizing
    ):
        return "refuse"
    held_ms = -1
    started = getattr(holder, "started_ms", None)
    if isinstance(started, int) and started > 0:
        held_ms = int(time.time() * 1000) - started
    if not ctx.get("accepted"):
        await tell_sender_offer_waits(channel, msg, short_id=port.me.short_id, blob=blob)
        log.info(
            "file offer WAITS behind a held offer: %s from %s blob=%s "
            "incoming_delivery=%s holder_delivery=%s held_ms=%s",
            name, peer_sid, blob[:8], delivery_id or "(none)",
            holder.delivery_id or "(none)", held_ms,
        )
        return "waiting"
    # Consent is recorded BEFORE async swarm assistance and reply delivery.
    # Merely seeing an accepted pending entry does not establish that its
    # acceptance reply failed, and a reply can fail after sending FILE_WANTS.
    # Do not displace a writer with bytes or staged chunk state, or one whose
    # reply is still in flight. The original delivery owns that progress.
    if (
        ctx.get("accept_reply_failed") is not True
        or ctx.get("accept_reply_in_flight")
        or not holder.acceptance_granted
        or holder.received
        or holder.next_seq
        or holder.cdc_streamed
        or holder.cdc_parts
        or holder.cdc_pending_state
    ):
        return "refuse"
    if (
        (holder.delivery_name or holder.name) != delivery_name
        or holder.delivery_rel_path != delivery_rel_path
        or holder.delivery_kind != delivery_kind
        or int(holder.size) != int(size)
    ):
        # The owner accepted a specific name, size and destination. A delivery
        # that differs in any of them is not what was accepted. Size matters
        # even though the content hash is the same: admission reserves the
        # DECLARED size and bytes are received up to it before the hash can be
        # checked, so a larger declaration under an inherited acceptance would
        # be storage the owner never agreed to. (Found by independent review.)
        return "refuse"
    port._pending_file_offers.pop(holder_id, None)
    port._abort_incoming_file(blob, holder)
    # The ledger has no "cancelled" status; like a declined offer this row is
    # ``failed`` with a delivery_state that says why. It asks nothing of the
    # owner, so it is never raised as something to look at.
    port._update_transfer(
        holder_id,
        status="failed",
        metadata=port._merge_transfer_metadata(holder_id, {
            "needs_accept": False,
            "delivery_state": "superseded",
            "transient": False,
            "attention_dismissed": True,
            "superseded_by_delivery": delivery_id,
            # Says only what is known here. Whether the newer request goes on
            # to be received is decided later in the handler.
            "user_message": (
                "The sender sent this file again. This earlier request was "
                "replaced by the newer one."
            ),
        }),
    )
    port._broadcast_file_offer_resolved(holder_id)
    log.info(
        "accepted file offer SUPERSEDED by a newer delivery of the same file: "
        "%s from %s blob=%s incoming_delivery=%s holder_delivery=%s held_ms=%s",
        name, peer_sid, blob[:8], delivery_id or "(none)",
        holder.delivery_id or "(none)", held_ms,
    )
    return "superseded"
