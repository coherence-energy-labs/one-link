"""An offer that is waiting for the owner makes later offers wait. It does not fail them.

With accept-first (the default) an incoming file is held until the owner
accepts it. The held offer keeps its blob entry and its admission reservation,
and the rest of the handler used to read that as a transfer in progress.

On 2026-11-25 a live install, whose owner window could not show the prompt,
answered a second device like this for sixteen minutes:

  * a second send of a held file: ``admission_blob_in_use_by_another_delivery``
    (13 times; the holder's status was ``offered`` and it had been held for up
    to 855 seconds);
  * with three files held, any further file:
    ``admission_peer_inbound_transfer_quota``.

Both are answers about load. Nothing was loaded; three files were waiting for a
click. The truthful answer is the one the first offer got, FILE_OFFER_HELD, and
that is what these tests pin, together with the one case where waiting would
never end: the owner accepted, but the sender that was told to wait is gone.

The real handler, two real daemons and a real accept are exercised in
tests/test_held_offers_two_daemon_e2e.py.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import held_offers
from one_link.daemon import Daemon, IncomingFile
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg

PEER = "c1" * 32
OTHER_PEER = "d2" * 32
BLOB = "ab" * 32
HOLDER_ID = "in:holder"


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    raw = pub.public_bytes_raw()
    fp = fingerprint_of(raw)
    return Identity(private=sk, public=pub, public_bytes=raw, fingerprint=fp, short_id=fp[:8], hostname="x")


class _Channel:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))


@pytest.fixture
def daemon(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    d = Daemon(_identity())
    d.state = State(db_path=tmp_path / "s.db")
    try:
        yield d
    finally:
        d.state.close()


def _hold(
    d: Daemon,
    tmp_path: Path,
    *,
    transfer_id: str = HOLDER_ID,
    blob: str = BLOB,
    peer_fp: str = PEER,
    accepted: bool = False,
    name: str = "notes.txt",
    rel_path: str = "",
    kind: str = "file",
    finalizing: bool = False,
) -> IncomingFile:
    """Put the daemon in the state the real handler leaves after holding an offer."""
    out = tmp_path / f"{transfer_id.replace(':', '_')}.part"
    handle = open(out, "wb")
    f = IncomingFile(
        name=name,
        size=10,
        blob_hex=blob,
        out_path=out,
        handle=handle,
        hasher=None,
        delivery_id="aa" * 16,
        delivery_name=name,
        delivery_rel_path=rel_path,
        delivery_kind=kind,
        peer_fp=peer_fp,
        transfer_id=transfer_id,
        reservation_id=f"res:{transfer_id}",
    )
    f.finalizing = finalizing
    f.acceptance_granted = accepted
    d._incoming_files[blob] = f
    reserved = d._transfer_reservation_ledger().reserve(
        reservation_id=f.reservation_id,
        name=name,
        size=10,
        peer_fp=peer_fp,
        policy=d._transfer_admission_policy,
    )
    assert reserved.ok, reserved
    d.state.upsert_transfer(
        id=transfer_id, direction="in", peer_fp=peer_fp, kind="file", name=name, size=10,
        blob_hash=blob, status="offered", progress_bytes=0, total_bytes=10,
        chunks_done=0, chunks_total=0,
        metadata={"needs_accept": not accepted, "delivery_state": "awaiting_acceptance"},
    )
    d._pending_file_offers[transfer_id] = {
        "channel": _Channel(), "peer_fp": peer_fp, "peer_sid": peer_fp[:8], "blob": blob,
        "msg_id": "first", "msg": {"id": "first"}, "mode": "stream", "missing": None,
        "name": name, "size": 10, "created_ms": 1, "accepted": accepted,
        "accept_reply_failed": accepted,
    }
    return f


async def _settle(d: Daemon, holder: IncomingFile, channel: _Channel, **over) -> str:
    args = dict(
        holder=holder,
        peer_fp=PEER,
        peer_sid=PEER[:8],
        name=holder.name,
        blob=holder.blob_hex,
        delivery_id="bb" * 16,
        delivery_name=holder.delivery_name,
        delivery_rel_path=holder.delivery_rel_path,
        delivery_kind=holder.delivery_kind,
        size=holder.size,
    )
    args.update(over)
    return await held_offers.settle_offer_against_held_offer(d, channel, {"id": "second"}, **args)


def _reservations(d: Daemon) -> list[str]:
    return sorted(item.reservation_id for item in d._transfer_reservation_ledger().snapshot())


# ── a second send of a file nobody has answered yet ─────────────────────────


@pytest.mark.asyncio
async def test_a_second_send_of_an_unanswered_file_is_told_to_wait(daemon, tmp_path, caplog):
    holder = _hold(daemon, tmp_path)
    channel = _Channel()
    with caplog.at_level(logging.INFO, logger="one_link.held_offers"):
        outcome = await _settle(daemon, holder, channel)

    assert outcome == "waiting"
    # Exactly the answer the first offer got, addressed to THIS offer.
    assert len(channel.sent) == 1
    reply = channel.sent[0]
    assert reply["t"] == "FILE_OFFER_HELD"
    assert reply["of"] == "second" and reply["blob"] == BLOB
    assert reply["reason"] == "awaiting_acceptance"
    assert "rejected" not in reply

    # Nothing about the held offer changed: the owner still has one prompt.
    assert daemon._incoming_files[BLOB] is holder
    assert [o["transfer_id"] for o in daemon.list_pending_file_offers()] == [HOLDER_ID]
    assert _reservations(daemon) == [f"res:{HOLDER_ID}"]
    assert not holder.handle.closed
    row = daemon.state.get_transfer(HOLDER_ID)
    assert row.status == "offered" and row.metadata["needs_accept"] is True
    # And nothing was recorded as a failure for the second send.
    assert daemon.state.get_transfer(f"in:{BLOB}") is None

    waits = [r.getMessage() for r in caplog.records if "WAITS behind a held offer" in r.getMessage()]
    assert len(waits) == 1
    assert "holder_delivery=" + "aa" * 16 in waits[0] and "incoming_delivery=" + "bb" * 16 in waits[0]


@pytest.mark.asyncio
async def test_waiting_does_not_depend_on_the_second_send_using_the_same_name(daemon, tmp_path):
    """Telling a sender to wait gives it nothing, so it needs no match on name or place."""
    holder = _hold(daemon, tmp_path)
    channel = _Channel()
    outcome = await _settle(
        daemon, holder, channel, name="renamed.txt", delivery_name="renamed.txt", delivery_rel_path="sub/renamed.txt",
        delivery_kind="folder",
    )
    assert outcome == "waiting"
    assert channel.sent[0]["t"] == "FILE_OFFER_HELD"


# ── the cases where the guard still applies ─────────────────────────────────


@pytest.mark.asyncio
async def test_content_really_being_delivered_is_still_refused(daemon, tmp_path):
    """No pending question for the owner: this is a transfer in progress."""
    holder = _hold(daemon, tmp_path)
    daemon._pending_file_offers.clear()  # accepted and under way
    channel = _Channel()
    assert await _settle(daemon, holder, channel) == "refuse"
    assert channel.sent == []
    assert daemon._incoming_files[BLOB] is holder


@pytest.mark.asyncio
async def test_a_holder_that_is_finalizing_is_never_displaced(daemon, tmp_path):
    for accepted in (False, True):
        daemon._incoming_files.clear()
        daemon._pending_file_offers.clear()
        holder = _hold(daemon, tmp_path, accepted=accepted, finalizing=True, transfer_id=f"in:fin{accepted}")
        channel = _Channel()
        assert await _settle(daemon, holder, channel) == "refuse"
        assert channel.sent == []
        assert daemon._incoming_files[BLOB] is holder
        daemon._transfer_reservation_ledger().release(holder.reservation_id, peer_fp=PEER)
        holder.handle.close()


@pytest.mark.asyncio
async def test_another_devices_held_offer_gives_this_sender_nothing(daemon, tmp_path):
    """The pending question belongs to a different sender. Neither wait nor inherit."""
    for accepted in (False, True):
        daemon._incoming_files.clear()
        daemon._pending_file_offers.clear()
        holder = _hold(daemon, tmp_path, peer_fp=OTHER_PEER, accepted=accepted, transfer_id=f"in:other{accepted}")
        channel = _Channel()
        assert await _settle(daemon, holder, channel) == "refuse"
        assert channel.sent == []
        assert daemon._incoming_files[BLOB] is holder
        daemon._transfer_reservation_ledger().release(holder.reservation_id, peer_fp=OTHER_PEER)
        holder.handle.close()


# ── accepted, but the sender that was told to wait is gone ──────────────────


@pytest.mark.asyncio
async def test_a_new_send_inherits_an_acceptance_that_could_not_be_delivered(daemon, tmp_path, caplog):
    holder = _hold(daemon, tmp_path, accepted=True)
    out_path = holder.out_path
    channel = _Channel()
    with caplog.at_level(logging.INFO, logger="one_link.held_offers"):
        outcome = await _settle(daemon, holder, channel)

    assert outcome == "superseded"
    # The stale holder is fully released: blob, handle, partial, reservation, prompt.
    assert BLOB not in daemon._incoming_files
    assert holder.handle.closed
    assert not out_path.exists()
    assert _reservations(daemon) == []
    assert HOLDER_ID not in daemon._pending_file_offers
    # Its row says what happened, and is not presented as an error to act on.
    row = daemon.state.get_transfer(HOLDER_ID)
    assert row.status == "failed"  # the ledger's terminal status; delivery_state says why
    assert row.metadata["delivery_state"] == "superseded"
    assert row.metadata["needs_accept"] is False
    assert row.metadata["superseded_by_delivery"] == "bb" * 16
    assert "sent this file again" in row.metadata["user_message"]
    assert daemon.list_pending_file_offers() == []
    assert not any(item.get("transfer_id") == HOLDER_ID for item in daemon.list_attention_items()), (
        "a superseded offer was raised as something the owner must look at"
    )
    assert not any("state.update_transfer failed" in r.getMessage() for r in caplog.records), (
        "the ledger refused the superseded row"
    )
    # Nothing is said to the sender here: the handler goes on to admit this
    # offer as an accepted one and answers it then.
    assert channel.sent == []
    assert any("SUPERSEDED by a newer delivery" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "difference",
    [
        {"delivery_name": "other-name.txt"},
        {"delivery_rel_path": "elsewhere/notes.txt"},
        {"delivery_kind": "folder"},
        # Same content hash, a larger declared size: admission would reserve
        # the declared size and receive up to it before the hash is checked.
        {"size": 10 * 1024 * 1024 * 1024},
        {"size": 9},
    ],
)
async def test_an_acceptance_is_not_inherited_by_a_different_name_or_destination(daemon, tmp_path, difference):
    """The owner accepted one file, of one size, under one name, going to one place."""
    holder = _hold(daemon, tmp_path, accepted=True)
    channel = _Channel()
    assert await _settle(daemon, holder, channel, **difference) == "refuse"
    assert channel.sent == []
    assert daemon._incoming_files[BLOB] is holder
    assert daemon._pending_file_offers[HOLDER_ID]["accepted"] is True
    assert _reservations(daemon) == [f"res:{HOLDER_ID}"]
    assert not holder.handle.closed


@pytest.mark.asyncio
async def test_a_decline_after_an_undeliverable_acceptance_leaves_nothing_to_inherit(daemon, tmp_path):
    """Accepted, could not be delivered, then the owner changed their mind.

    Inheritance needs a holder that is still pending and accepted. A decline
    removes both the pending entry and the holder, so the same file sent again
    is an ordinary new offer and the owner is asked."""
    holder = _hold(daemon, tmp_path, accepted=True)
    result = await daemon.decline_file_offer(HOLDER_ID)
    assert result == {"ok": True}
    assert BLOB not in daemon._incoming_files, "a declined offer still claims its content"
    assert HOLDER_ID not in daemon._pending_file_offers
    assert _reservations(daemon) == []
    assert holder.handle.closed
    row = daemon.state.get_transfer(HOLDER_ID)
    assert row.metadata["delivery_state"] == "declined"
    # With no holder for the blob, the offer handler never reaches the
    # settle step; and asked directly, a released holder gives nothing.
    assert await _settle(daemon, holder, _Channel()) == "refuse"


# ── a quota that is full of unanswered offers ───────────────────────────────


def test_a_per_peer_quota_waits_only_on_that_senders_own_unanswered_offers(daemon, tmp_path):
    per_peer = ("peer_inbound_transfer_quota", "peer_inbound_byte_quota")
    for reason in per_peer:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False, "nothing is held"

    _hold(daemon, tmp_path, peer_fp=OTHER_PEER, transfer_id="in:theirs", blob="cd" * 32)
    for reason in per_peer:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False, (
            "another sender's unanswered offer does not occupy this sender's quota"
        )

    _hold(daemon, tmp_path, peer_fp=PEER, transfer_id="in:mine", blob="ef" * 32)
    for reason in per_peer:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is True

    # Once the owner has answered, the slot is held by a transfer, not a question.
    daemon._pending_file_offers["in:mine"]["accepted"] = True
    for reason in per_peer:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False


def test_a_global_quota_waits_on_anyones_unanswered_offer(daemon, tmp_path):
    reasons = ("global_inbound_transfer_quota", "global_inbound_byte_quota")
    for reason in reasons:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False
    _hold(daemon, tmp_path, peer_fp=OTHER_PEER, transfer_id="in:theirs", blob="cd" * 32)
    for reason in reasons:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is True
    daemon._pending_file_offers["in:theirs"]["accepted"] = True
    for reason in reasons:
        assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False


@pytest.mark.parametrize(
    "reason",
    ["insufficient_disk_space", "declared_size_too_large", "invalid_size", "reservation_conflict", "", "admission_denied"],
)
def test_refusals_that_are_not_about_a_full_queue_never_become_waiting(daemon, tmp_path, reason):
    """A disk that is full, or an offer that is malformed, is not waiting on anyone."""
    _hold(daemon, tmp_path)
    assert held_offers.quota_is_waiting_on_the_owner(daemon._pending_file_offers, reason, PEER) is False


# ── the session that carries a held offer ───────────────────────────────────


def _deadline(d: Daemon, channel) -> float:
    """The read deadline exactly as the daemon's channel loop asks for it."""
    from one_link import daemon as daemon_module

    return held_offers.read_deadline_s(
        d._pending_file_offers, channel,
        idle_s=daemon_module.PEER_IDLE_S, accept_wait_s=daemon_module.FILE_OFFER_ACCEPT_WAIT_S,
    )


def test_a_session_we_told_to_wait_gets_the_acceptance_window_not_the_idle_limit(daemon, tmp_path):
    """The receiver closed such a session at its idle limit while the sender,
    as instructed, was still waiting for the owner. That is what turned an
    unanswered prompt into a failed command, and the failed command into the
    re-send that was then refused."""
    from one_link import daemon as daemon_module

    idle = daemon_module.PEER_IDLE_S
    window = daemon_module.FILE_OFFER_ACCEPT_WAIT_S
    assert idle < window, "the two limits no longer disagree; re-read this test"

    unrelated = _Channel()
    assert _deadline(daemon, unrelated) == idle

    _hold(daemon, tmp_path)
    waiting = daemon._pending_file_offers[HOLDER_ID]["channel"]
    deadline = _deadline(daemon, waiting)
    # Longer than the sender's own wait, so the sender's timeout ends the
    # wait and the receiver never cuts the session out from under it...
    assert deadline > window
    # ...and still a bound: a quiet peer cannot pin the channel open.
    assert deadline <= window + 60
    # Only the channel that carries the held offer is given the window.
    assert _deadline(daemon, unrelated) == idle

    # Once the owner has answered, the channel is an ordinary one again.
    daemon._pending_file_offers[HOLDER_ID]["accepted"] = True
    assert _deadline(daemon, waiting) == idle
    daemon._pending_file_offers.pop(HOLDER_ID)
    assert _deadline(daemon, waiting) == idle


def test_the_channel_read_loop_asks_for_its_deadline_each_time():
    """The window applies only if the loop that reads the channel consults it."""
    from one_link import daemon as daemon_module

    source = Path(daemon_module.__file__).read_text(encoding="utf-8")
    assert "read_deadline_s = held_offers.read_deadline_s(" in source
    assert "idle_s=PEER_IDLE_S, accept_wait_s=FILE_OFFER_ACCEPT_WAIT_S," in source
    assert "channel.recv(), timeout=read_deadline_s" in source
    assert "channel.recv(), timeout=PEER_IDLE_S" not in source, (
        "a channel read still uses the fixed idle limit"
    )


def test_the_offer_handler_consults_these_decisions_at_its_three_points():
    """The decisions live in one_link.held_offers; the handler has to ask them.

    Behaviour through the real handler is tested between two daemons
    (tests/test_held_offers_two_daemon_e2e.py); this pins the seams so a
    refactor that drops one fails here, in the default suite."""
    from one_link import daemon as daemon_module

    source = Path(daemon_module.__file__).read_text(encoding="utf-8")
    assert source.count("await held_offers.settle_offer_against_held_offer(") == 1
    assert source.count("if held_offers.quota_is_waiting_on_the_owner(") == 1
    assert source.count("await held_offers.tell_sender_offer_waits(") == 1
    # The declared size reaches the inheritance decision.
    assert "name=name, size=size," in source
    # The inherited consent must reach the acceptance decision.
    decision = source[source.index("acceptance_granted = bool("):]
    assert "or inherited_acceptance" in decision[:400]
    assert "if settled == \"waiting\":" in source and "if settled == \"superseded\":" in source


def test_the_quota_reasons_named_here_are_the_ones_admission_produces():
    """If admission renames a reason, the waiting rule must not silently stop matching."""
    from one_link import transfer_safety

    source = Path(transfer_safety.__file__).read_text(encoding="utf-8")
    for reason in held_offers.QUOTA_REASONS_PER_PEER | held_offers.QUOTA_REASONS_GLOBAL:
        assert f'reason="{reason}"' in source, f"admission no longer produces {reason}"
    produced = {
        line.split('reason="', 1)[1].split('"', 1)[0]
        for line in source.splitlines()
        if 'reason="' in line and "quota" in line
    }
    assert produced == set(held_offers.QUOTA_REASONS_PER_PEER | held_offers.QUOTA_REASONS_GLOBAL), (
        "admission has a quota reason the waiting rule does not know about"
    )

@pytest.mark.asyncio
@pytest.mark.parametrize("progress", [
    {"received": 1}, {"next_seq": 1}, {"cdc_streamed": {0}},
    {"cdc_parts": {0: b""}}, {"cdc_pending_state": [{"chunk_hash": "a" * 64}]},
])
async def test_a_failed_accept_reply_cannot_displace_partial_progress(daemon, tmp_path, progress):
    """FILE_WANTS may have reached the sender before a later reply step failed."""
    holder = _hold(daemon, tmp_path, accepted=True)
    for key, value in progress.items():
        setattr(holder, key, value)
    assert await _settle(daemon, holder, _Channel()) == "refuse"
    assert daemon._incoming_files[BLOB] is holder
    assert daemon._pending_file_offers[HOLDER_ID]["accept_reply_failed"] is True
    assert _reservations(daemon) == [f"res:{HOLDER_ID}"]
    assert not holder.handle.closed
    assert holder.out_path.exists()


@pytest.mark.asyncio
async def test_accepted_context_without_failed_reply_evidence_is_not_superseded(daemon, tmp_path):
    holder = _hold(daemon, tmp_path, accepted=True)
    daemon._pending_file_offers[HOLDER_ID].pop("accept_reply_failed")
    assert await _settle(daemon, holder, _Channel()) == "refuse"
    assert daemon._incoming_files[BLOB] is holder
    assert not holder.handle.closed


@pytest.mark.asyncio
async def test_accept_reply_in_flight_cannot_be_superseded(daemon, tmp_path):
    holder = _hold(daemon, tmp_path)
    entered, proceed = asyncio.Event(), asyncio.Event()

    class SlowChannel:
        async def send(self, payload):
            entered.set()
            await proceed.wait()

    ctx = daemon._pending_file_offers[HOLDER_ID]
    ctx["channel"] = SlowChannel()
    accept = asyncio.create_task(daemon.accept_file_offer(HOLDER_ID))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        assert ctx["accepted"] is True
        assert ctx["accept_reply_failed"] is False
        assert await _settle(daemon, holder, _Channel()) == "refuse"
        assert daemon._incoming_files[BLOB] is holder
        assert not holder.handle.closed
    finally:
        proceed.set()
        result = await asyncio.wait_for(accept, timeout=5)
    assert result == {"ok": True}
    assert HOLDER_ID not in daemon._pending_file_offers
    assert daemon._incoming_files[BLOB] is holder


@pytest.mark.asyncio
async def test_real_failed_accept_reply_records_inheritance_eligibility(daemon, tmp_path):
    holder = _hold(daemon, tmp_path)

    class DeadChannel:
        async def send(self, payload):
            raise ConnectionError("synthetic lost reply")

    ctx = daemon._pending_file_offers[HOLDER_ID]
    ctx["channel"] = DeadChannel()
    assert await daemon.accept_file_offer(HOLDER_ID) == {
        "ok": False, "error": "sender offline; it will resend",
    }
    assert ctx["accepted"] is True and ctx["accept_reply_failed"] is True
    assert holder.acceptance_granted is True
    assert await _settle(daemon, holder, _Channel()) == "superseded"
    assert BLOB not in daemon._incoming_files


@pytest.mark.asyncio
async def test_decline_revokes_the_writer_before_waiting_on_the_wire(daemon, tmp_path):
    holder = _hold(daemon, tmp_path, accepted=True)
    entered, proceed = asyncio.Event(), asyncio.Event()

    class SlowDecline:
        async def send(self, payload):
            assert decode_msg(payload)["t"] == "FILE_DECLINED"
            entered.set()
            await proceed.wait()

    daemon._pending_file_offers[HOLDER_ID]["channel"] = SlowDecline()
    task = asyncio.create_task(daemon.decline_file_offer(HOLDER_ID))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        assert BLOB not in daemon._incoming_files
        assert holder.handle.closed
        assert _reservations(daemon) == []
        assert daemon.state.get_transfer(HOLDER_ID).metadata["delivery_state"] == "declined"
    finally:
        proceed.set()
        assert await asyncio.wait_for(task, timeout=5) == {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("reply_fails", [False, True])
async def test_inflight_accept_cannot_overwrite_a_concurrent_decline(daemon, tmp_path, reply_fails):
    holder = _hold(daemon, tmp_path)
    entered, proceed = asyncio.Event(), asyncio.Event()

    class OverlappingChannel:
        async def send(self, payload):
            kind = decode_msg(payload)["t"]
            if kind == "ACK":
                entered.set()
                await proceed.wait()
                if reply_fails:
                    raise ConnectionResetError("reply lost")
            else:
                assert kind == "FILE_DECLINED"

    daemon._pending_file_offers[HOLDER_ID]["channel"] = OverlappingChannel()
    accept = asyncio.create_task(daemon.accept_file_offer(HOLDER_ID))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        assert await daemon.decline_file_offer(HOLDER_ID) == {"ok": True}
        assert holder.handle.closed and BLOB not in daemon._incoming_files
    finally:
        proceed.set()
        result = await asyncio.wait_for(accept, timeout=5)
    assert result["ok"] is False
    row = daemon.state.get_transfer(HOLDER_ID)
    assert row.status == "failed"
    assert row.metadata["delivery_state"] == "declined"


@pytest.mark.asyncio
async def test_duplicate_owner_accept_does_not_send_another_reply(daemon, tmp_path):
    _hold(daemon, tmp_path)
    entered, proceed = asyncio.Event(), asyncio.Event()
    sent = []

    class SlowAccept:
        async def send(self, payload):
            sent.append(decode_msg(payload)["t"])
            entered.set()
            await proceed.wait()

    daemon._pending_file_offers[HOLDER_ID]["channel"] = SlowAccept()
    task = asyncio.create_task(daemon.accept_file_offer(HOLDER_ID))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        # Launch a duplicate without deadlocking the original implementation.
        duplicate = asyncio.create_task(daemon.accept_file_offer(HOLDER_ID))
        await asyncio.sleep(0)
        assert duplicate.done()
        assert len(sent) == 1
        assert (await duplicate)["ok"] is False
    finally:
        proceed.set()
        await asyncio.wait_for(task, timeout=5)
        if "duplicate" in locals():
            await asyncio.wait_for(duplicate, timeout=5)
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_stale_pending_context_cannot_accept_or_abort_another_writer(daemon, tmp_path):
    holder = _hold(daemon, tmp_path)
    holder.transfer_id = "in:newer-delivery"
    channel = daemon._pending_file_offers[HOLDER_ID]["channel"]
    assert (await daemon.accept_file_offer(HOLDER_ID))["ok"] is False
    assert (await daemon.decline_file_offer(HOLDER_ID))["ok"] is False
    assert daemon._incoming_files[BLOB] is holder
    assert not holder.handle.closed
    assert not holder.acceptance_granted
    assert channel.sent == []


def test_reaper_cannot_park_new_writer_using_a_stale_delivery_row(daemon, tmp_path, monkeypatch):
    holder = _hold(daemon, tmp_path)
    daemon.state.upsert_transfer(
        id="in:old-delivery", direction="in", peer_fp=PEER, kind="file",
        name=holder.name, size=holder.size, blob_hash=BLOB, status="paused",
        progress_bytes=0, total_bytes=holder.size, chunks_done=0, chunks_total=0,
        metadata={"needs_accept": False, "delivery_state": "waiting_for_sender"},
    )
    monkeypatch.setattr(daemon, "STUCK_TRANSFER_DEADLINE_MS", 0)
    assert daemon._reap_stuck_transfers() == 0
    assert daemon._incoming_files[BLOB] is holder
    assert not holder.handle.closed
    assert HOLDER_ID in daemon._pending_file_offers
    assert _reservations(daemon) == [f"res:{HOLDER_ID}"]
