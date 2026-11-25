"""What one send attempt moved, and what the whole transfer moved.

``send_file`` returns a receipt for the call that just ran: the bytes and
chunks THAT attempt put on a transport.  The ledger row is the transfer: it
lives across every attempt, so its byte columns and its route totals cover
all of them.  These tests drive the real send path in-process against a
scripted peer and pin both windows, their unit, and the fallback count.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import blake3
import pytest

import one_link.daemon as daemon_mod
from one_link.capabilities import (
    CHAT,
    FILES,
    FILE_CDC,
    FILE_COMMIT_RECEIPT_V1,
    NATIVE_TRANSFER_INDEXED_V1,
)
from one_link.daemon import Daemon, OutboundSession, TransferPausedError
from one_link.discovery import Peer
from one_link.identity import Identity
from one_link.state import State, TransferRecord
from one_link.transfer_brain import transfer_result_report
from one_link.transfer_doctor import transfer_autopilot_truth
from one_link.transfer_routes import PayloadRouteAccounting
from one_link.wire import make_msg
from tests.test_linked_mesh_v070 import _FakeChannel, _new_identity

#: The smallest fixed boundary a retry is allowed to republish, so the second
#: attempt offers the same manifest the first one did.
CHUNK = 64 * 1024
CDC_PEER = [CHAT, FILES, FILE_CDC, FILE_COMMIT_RECEIPT_V1]
STREAM_PEER = [CHAT, FILES, FILE_COMMIT_RECEIPT_V1]


class _LinkLossChannel(_FakeChannel):
    """Serves its scripted replies, then drops like a reset socket."""

    async def recv(self) -> bytes:
        if self._replies.empty():
            raise ConnectionResetError("injected link loss")
        return await super().recv()


@dataclass
class _Rig:
    daemon: Daemon
    state: State
    them: Identity
    peer: Peer
    source: Path

    def connect(self, features: list[str], *, lossy: bool = False) -> _FakeChannel:
        """A fresh session, as after the reconnect that follows a paused send."""
        kind = _LinkLossChannel if lossy else _FakeChannel
        channel = kind(
            peer_ed_pub=self.them.public_bytes, peer_short_id=self.them.short_id,
        )
        channel.peer_caps = {
            "protocol": "OL1.2",
            "features": list(features),
            "from": self.them.short_id,
            "app_version": "0.21.0",
        }
        self.daemon._outbound_sessions[self.them.fingerprint] = OutboundSession(
            peer_fp=self.them.fingerprint,
            peer=self.peer,
            channel=channel,  # type: ignore[arg-type]
            lock=asyncio.Lock(),
            last_used=time.time(),
            regime="lan",
        )
        return channel

    def reply(self, channel: _FakeChannel, kind: str, count: int = 1, **fields: Any) -> None:
        for _ in range(count):
            channel.queue_reply(make_msg(kind, self.them.short_id, **fields))

    def row(self, transfer_id: str) -> TransferRecord:
        record = self.state.get_transfer(transfer_id)
        assert record is not None
        return record

    async def attempt_that_loses_the_link(self, features: list[str], **script: Any) -> str:
        """Run one attempt whose peer stops answering; return the paused id."""
        channel = self.connect(features, lossy=True)
        if "wants" in script:
            self.reply(channel, "FILE_WANTS", wants=script["wants"])
        self.reply(channel, "ACK", script["acks"])
        with pytest.raises(TransferPausedError) as paused:
            await self.daemon.send_file(self.peer, self.source)
        return str(paused.value.transfer_id)


def _rig(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    *,
    cdc_chunks: bool = False,
) -> _Rig:
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ONE_LINK_HOME", str(home / "home"))
    monkeypatch.setattr(daemon_mod, "FAST_FIXED_CHUNK_SIZE", CHUNK)
    monkeypatch.setattr(daemon_mod, "STREAM_MIN_CHUNK_SIZE", CHUNK)
    them = _new_identity()
    state = State(db_path=home / "sender.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id, pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon = Daemon(_new_identity())
    daemon.state = state
    # A background resume would race the explicit retry each test issues.
    monkeypatch.setattr(daemon, "_schedule_resume_paused", lambda *_a, **_k: None)
    peer = Peer(
        short_id=them.short_id, hostname="receiver", address="127.0.0.1",
        port=12345, ed_pub_hex=them.public_bytes.hex(),
    )
    source = home / "payload.bin"
    source.write_bytes(payload)
    if cdc_chunks:
        state.record_file_index_cache(
            **daemon._file_cache_signature(source),
            blob_hash=blake3.blake3(payload).hexdigest(),
            index_kind="fixed",
            chunks=[
                {
                    "index": index,
                    "start": start,
                    "end": start + len(payload[start:start + CHUNK]),
                    "size": len(payload[start:start + CHUNK]),
                    "hash": blake3.blake3(payload[start:start + CHUNK]).hexdigest(),
                }
                for index, start in enumerate(range(0, len(payload), CHUNK))
            ],
        )
    return _Rig(daemon, state, them, peer, source)


def _noise(chunks: int) -> bytes:
    """Incompressible, so raw and encoded sizes agree and only counts differ."""
    return random.Random(20261125).randbytes(chunks * CHUNK)


def _compressible(chunks: int) -> bytes:
    return b"".join(bytes([65 + index]) * CHUNK for index in range(chunks))


# ─── claim 1: the route table has one unit, and says which ─────────────


@pytest.mark.asyncio
async def test_route_bytes_are_encoded_payload_in_a_compressed_cdc_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = _rig(tmp_path, monkeypatch, _compressible(5), cdc_chunks=True)
    try:
        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[0, 1, 2, 3, 4])
        rig.reply(channel, "ACK", 5)
        rig.reply(channel, "FILE_COMMIT")

        result = await rig.daemon.send_file(rig.peer, rig.source)

        assert result["compressed_chunks"] == 5
        assert result["raw_bytes_sent"] == 5 * CHUNK
        assert 0 < result["wire_bytes_sent"] < result["raw_bytes_sent"]
        # Every acknowledged chunk adds the same quantity to the route table
        # and to wire_bytes_sent, so the table has one unit and one total.
        assert sum(result["payload_bytes_by_transport"].values()) == result["wire_bytes_sent"]
        assert sum(result["payload_chunks_by_transport"].values()) == result["chunks"] == 5
        assert result["payload_transport"] == "tcp"
        row = rig.row(result["transfer_id"])
        assert (row.raw_bytes, row.wire_bytes) == (
            result["raw_bytes_sent"], result["wire_bytes_sent"],
        )
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_route_bytes_are_encoded_payload_in_a_stream_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = _rig(tmp_path, monkeypatch, _compressible(3))
    try:
        channel = rig.connect(STREAM_PEER)
        rig.reply(channel, "ACK", 4)
        rig.reply(channel, "FILE_COMMIT")

        result = await rig.daemon.send_file(rig.peer, rig.source)

        # The stream lane never compresses: encoded size is the file size.
        assert result["chunks"] == 3
        assert result["raw_bytes_sent"] == result["wire_bytes_sent"] == 3 * CHUNK
        assert result["payload_bytes_by_transport"] == {"tcp": 3 * CHUNK}
        assert result["payload_chunks_by_transport"] == {"tcp": 3}
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_receipt_states_its_unit_and_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unit was right but unwritten; a reader had to infer it."""
    rig = _rig(tmp_path, monkeypatch, _compressible(5), cdc_chunks=True)
    try:
        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[0, 1, 2, 3, 4])
        rig.reply(channel, "ACK", 5)
        rig.reply(channel, "FILE_COMMIT")

        result = await rig.daemon.send_file(rig.peer, rig.source)

        assert result["payload_bytes_unit"] == "encoded_payload_bytes"
        assert result["payload_accounting_window"] == "attempt"
        # A transfer finished in one attempt: both windows hold the same numbers,
        # and the transfer window names raw and encoded bytes separately.
        totals = result["payload_transfer_totals"]
        assert totals["payload_bytes_by_transport"] == result["payload_bytes_by_transport"]
        assert totals["payload_chunks_by_transport"] == result["payload_chunks_by_transport"]
        assert totals["wire_bytes"] == result["wire_bytes_sent"] < 5 * CHUNK
        assert totals["raw_bytes"] == result["raw_bytes_sent"] == 5 * CHUNK
    finally:
        rig.state.close()


def test_every_snapshot_field_is_reserved_from_caller_metadata() -> None:
    """A caller's ``extra_metadata`` must not be able to forge the accounting."""
    assert set(PayloadRouteAccounting().snapshot()) <= (
        daemon_mod._OUTBOUND_DELIVERY_RESERVED_METADATA_KEYS
    )


# ─── claim 2: every fallback is counted ────────────────────────────────


def _quic_lane(rig: _Rig, monkeypatch: pytest.MonkeyPatch, *, fail_index: int) -> list[int]:
    """Open the gated CDC-over-QUIC lane and fail one chunk on it."""
    monkeypatch.setattr(daemon_mod, "FILE_QUIC_CHUNKS_ENABLED", True)
    rig.daemon._quic_outbound[rig.them.fingerprint] = object()
    carried: list[int] = []

    async def _send_chunk_via_quic(_peer_fp: str, _peer: Peer, message: dict) -> dict:
        if int(message["index"]) == fail_index:
            return {"ok": False, "error": "injected quic stream reset"}
        carried.append(int(message["index"]))
        return {"ok": True, "rtt_ms": 1.0, "response_len": 0, "receipt": None}

    monkeypatch.setattr(rig.daemon, "send_chunk_via_quic", _send_chunk_via_quic)
    return carried


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("batch_size", "fallback_site"),
    [(1, "cdc_quic_batch_failed"), (2, "cdc_quic_final_flush_failed")],
)
async def test_quic_fallback_on_the_last_chunk_is_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, batch_size: int, fallback_site: str,
) -> None:
    """Five chunks; the fifth fails on QUIC and is re-shipped on the stream.

    With one chunk per batch (the shipped value) the failure is met inside
    the send loop.  With two per batch the fifth chunk is the leftover that
    only the flush after the loop sees; that flush recorded the degradation
    but not the fallback.
    """
    monkeypatch.setattr(daemon_mod, "QUIC_CDC_BATCH_SIZE", batch_size)
    rig = _rig(tmp_path, monkeypatch, _noise(5), cdc_chunks=True)
    try:
        carried = _quic_lane(rig, monkeypatch, fail_index=4)
        channel = rig.connect([*CDC_PEER, NATIVE_TRANSFER_INDEXED_V1])
        rig.reply(channel, "FILE_WANTS", wants=[0, 1, 2, 3, 4])
        rig.reply(channel, "ACK")
        rig.reply(channel, "FILE_COMMIT")

        result = await rig.daemon.send_file(rig.peer, rig.source)

        assert carried == [0, 1, 2, 3]
        assert [event["kind"] for event in rig.daemon._degradation_events] == [fallback_site]
        assert result["payload_chunks_by_transport"] == {"quic": 4, "tcp": 1}
        assert result["payload_bytes_by_transport"] == {"quic": 4 * CHUNK, "tcp": CHUNK}
        assert result["payload_transport"] == "mixed"
        assert result["payload_fallbacks"] == 1
        row = rig.row(result["transfer_id"])
        assert row.metadata["payload_fallbacks"] == 1
        assert row.metadata["payload_transfer_totals"]["payload_fallbacks"] == 1
    finally:
        rig.state.close()


# ─── claim 3: the attempt and the transfer ─────────────────────────────


@pytest.mark.asyncio
async def test_resumed_send_reports_the_attempt_and_ledgers_the_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three of five chunks land, the link drops, the resume sends two."""
    rig = _rig(tmp_path, monkeypatch, _noise(5), cdc_chunks=True)
    try:
        transfer_id = await rig.attempt_that_loses_the_link(
            CDC_PEER, wants=[0, 1, 2, 3, 4], acks=3,
        )

        # The paused row keeps what the failed attempt moved, and on which route.
        paused = rig.row(transfer_id)
        assert paused.status == "paused"
        assert (paused.raw_bytes, paused.wire_bytes) == (3 * CHUNK, 3 * CHUNK)
        assert paused.metadata["payload_bytes_by_transport"] == {"tcp": 3 * CHUNK}
        assert paused.metadata["payload_transfer_totals"]["chunks"] == 3

        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[3, 4])
        rig.reply(channel, "ACK", 2)
        rig.reply(channel, "FILE_COMMIT")
        result = await rig.daemon.send_file(rig.peer, rig.source, transfer_id=transfer_id)

        # The receipt is this call: two chunks, timed by this call.
        assert result["confirmed"] is True
        assert result["chunks"] == 2
        assert result["raw_bytes_sent"] == result["wire_bytes_sent"] == 2 * CHUNK
        assert result["payload_accounting_window"] == "attempt"
        assert result["payload_bytes_by_transport"] == {"tcp": 2 * CHUNK}
        assert result["payload_chunks_by_transport"] == {"tcp": 2}

        # The same receipt and the ledger row carry the whole transfer.
        row = rig.row(transfer_id)
        assert row.status == "complete"
        assert (row.raw_bytes, row.wire_bytes) == (5 * CHUNK, 5 * CHUNK)
        for totals in (result["payload_transfer_totals"], row.metadata["payload_transfer_totals"]):
            assert totals == {
                "payload_transport": "tcp",
                "payload_bytes_by_transport": {"tcp": 5 * CHUNK},
                "payload_chunks_by_transport": {"tcp": 5},
                "payload_fallbacks": 0,
                "raw_bytes": 5 * CHUNK,
                "wire_bytes": 5 * CHUNK,
                "chunks": 5,
            }
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_resumed_bytes_are_not_reported_as_prior_knowledge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The receiver "already has" three chunks only because this transfer sent them."""
    rig = _rig(tmp_path, monkeypatch, _noise(5), cdc_chunks=True)
    try:
        transfer_id = await rig.attempt_that_loses_the_link(
            CDC_PEER, wants=[0, 1, 2, 3, 4], acks=3,
        )
        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[3, 4])
        rig.reply(channel, "ACK", 2)
        rig.reply(channel, "FILE_COMMIT")
        result = await rig.daemon.send_file(rig.peer, rig.source, transfer_id=transfer_id)

        report = result["transfer_report"]
        assert report["skipped_bytes"] == 0
        assert report["saved_bytes"] == 0
        assert report["bandwidth_savings_ratio"] == 0.0
        assert report["resumed_bytes"] == 3 * CHUNK
        # Three chunks another attempt sent, in its own time, are not this
        # attempt's payload: its effective rate is its real rate.
        assert report["effective_payload_bytes"] == report["raw_bytes_sent"] == 2 * CHUNK
        assert report["effective_throughput_bps"] == report["raw_throughput_bps"]
        # What the planner learns from this send is not a saving either.
        assert result["transfer_engine_oracle"]["cdc"]["savings_ratio"] == 0.0

        row = rig.row(transfer_id)
        assert row.metadata["resumed_bytes"] == 3 * CHUNK
        assert row.metadata["skipped_bytes"] == 0
        assert row.metadata["skipped_ratio"] == 0.0
        assert row.metadata["transfer_report"] == report

        # The UI's facts: every byte crossed the wire, none was avoided, and
        # nothing beyond the planner's own pre-send estimate is called known.
        truth = transfer_autopilot_truth(row)
        assert truth["wire_bytes"] == 5 * CHUNK
        assert truth["saved_bytes"] == 0
        assert truth["skipped_bytes"] == 0
        estimate = float(row.metadata["autopilot_plan"]["estimated_savings_ratio"])
        assert truth["known_pct"] <= round(estimate * 100.0, 1)
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_prior_knowledge_is_still_reported_beside_a_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chunk 0 was known before the transfer began; chunks 1-2 were resumed."""
    rig = _rig(tmp_path, monkeypatch, _noise(5), cdc_chunks=True)
    try:
        transfer_id = await rig.attempt_that_loses_the_link(
            CDC_PEER, wants=[1, 2, 3, 4], acks=2,
        )
        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[3, 4])
        rig.reply(channel, "ACK", 2)
        rig.reply(channel, "FILE_COMMIT")
        result = await rig.daemon.send_file(rig.peer, rig.source, transfer_id=transfer_id)

        report = result["transfer_report"]
        assert report["skipped_bytes"] == CHUNK
        assert report["saved_bytes"] == CHUNK
        assert report["resumed_bytes"] == 2 * CHUNK
        row = rig.row(transfer_id)
        assert row.metadata["skipped_ratio"] == 0.2
        # Four chunks crossed the wire over two attempts; one never had to.
        assert (row.raw_bytes, row.wire_bytes) == (4 * CHUNK, 4 * CHUNK)
        assert row.progress_bytes == 5 * CHUNK
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_retry_that_sends_everything_again_counts_both_sends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stream retry cannot skip: the file crosses the wire twice."""
    rig = _rig(tmp_path, monkeypatch, _noise(3))
    try:
        transfer_id = await rig.attempt_that_loses_the_link(STREAM_PEER, acks=4)
        assert rig.row(transfer_id).raw_bytes == 3 * CHUNK

        channel = rig.connect(STREAM_PEER)
        rig.reply(channel, "ACK", 4)
        rig.reply(channel, "FILE_COMMIT")
        result = await rig.daemon.send_file(rig.peer, rig.source, transfer_id=transfer_id)

        assert result["confirmed"] is True
        assert result["raw_bytes_sent"] == result["wire_bytes_sent"] == 3 * CHUNK
        assert result["payload_chunks_by_transport"] == {"tcp": 3}
        row = rig.row(transfer_id)
        assert (row.raw_bytes, row.wire_bytes) == (6 * CHUNK, 6 * CHUNK)
        assert row.metadata["payload_transfer_totals"]["payload_chunks_by_transport"] == {"tcp": 6}
        # Nothing was skipped, so nothing is "resumed" and nothing is saved.
        assert result["transfer_report"]["skipped_bytes"] == 0
        assert result["transfer_report"]["saved_bytes"] == 0
        assert result["transfer_report"]["resumed_bytes"] == 0
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_replayed_commit_keeps_what_the_first_attempt_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every chunk was acknowledged, then the receipt was lost with the link.

    The retry is answered with the stored commit and sends nothing.  The call
    moved no payload; the transfer moved the whole file.
    """
    rig = _rig(tmp_path, monkeypatch, _noise(3))
    try:
        transfer_id = await rig.attempt_that_loses_the_link(STREAM_PEER, acks=4)

        channel = rig.connect(STREAM_PEER)
        rig.reply(channel, "FILE_COMMIT")
        result = await rig.daemon.send_file(rig.peer, rig.source, transfer_id=transfer_id)

        assert result["commit_replayed"] is True
        assert result["chunks"] == 0
        assert result["raw_bytes_sent"] == result["wire_bytes_sent"] == 0
        assert result["payload_transport"] == "none"
        assert result["payload_bytes_by_transport"] == {}
        assert not any(m.get("t") == "FILE_CHUNK" for m in channel.sent)

        row = rig.row(transfer_id)
        assert row.status == "complete"
        assert (row.raw_bytes, row.wire_bytes) == (3 * CHUNK, 3 * CHUNK)
        for totals in (result["payload_transfer_totals"], row.metadata["payload_transfer_totals"]):
            assert totals["payload_transport"] == "tcp"
            assert totals["payload_bytes_by_transport"] == {"tcp": 3 * CHUNK}
            assert totals["chunks"] == 3
    finally:
        rig.state.close()


@pytest.mark.asyncio
async def test_refused_send_keeps_what_it_moved_for_a_later_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A permanent failure ends the attempt, not the record of its bytes."""
    rig = _rig(tmp_path, monkeypatch, _noise(5), cdc_chunks=True)
    try:
        channel = rig.connect(CDC_PEER)
        rig.reply(channel, "FILE_WANTS", wants=[0, 1, 2, 3, 4])
        rig.reply(channel, "ACK", 3)
        rig.reply(channel, "ACK", rejected="quota_exceeded")
        with pytest.raises(RuntimeError, match="quota_exceeded"):
            await rig.daemon.send_file(rig.peer, rig.source)

        row = rig.state.list_transfers(limit=1)[0]
        assert row.status == "failed"
        assert (row.raw_bytes, row.wire_bytes) == (3 * CHUNK, 3 * CHUNK)
        assert row.metadata["payload_chunks_by_transport"] == {"tcp": 3}
        totals = row.metadata["payload_transfer_totals"]
        assert (totals["raw_bytes"], totals["wire_bytes"], totals["chunks"]) == (
            3 * CHUNK, 3 * CHUNK, 3,
        )
        # The manual retry of this row starts from those totals.
        retry = PayloadRouteAccounting.continuing("auto", row)
        assert retry.ledger_counters() == {"raw_bytes": 3 * CHUNK, "wire_bytes": 3 * CHUNK}
    finally:
        rig.state.close()


# ─── the report and the UI truth, without a daemon ─────────────────────


def test_report_splits_resumed_bytes_out_of_skipped_bytes() -> None:
    report = transfer_result_report(
        raw_bytes=200, wire_bytes=150, elapsed_s=1.0, skipped_bytes=800, resumed_bytes=500,
    )
    assert report["accounting_window"] == "attempt"
    assert report["resumed_bytes"] == 500
    assert report["skipped_bytes"] == 300
    assert report["effective_payload_bytes"] == 500
    assert report["saved_bytes"] == 350
    assert report["bandwidth_savings_ratio"] == 0.7


def test_report_cannot_resume_more_than_the_attempt_skipped() -> None:
    """Earlier bytes the receiver did not keep were sent again, not resumed."""
    report = transfer_result_report(
        raw_bytes=1000, wire_bytes=1000, elapsed_s=1.0, skipped_bytes=100, resumed_bytes=900,
    )
    assert report["resumed_bytes"] == 100
    assert report["skipped_bytes"] == 0
    assert report["saved_bytes"] == 0


def _row(**metadata: Any) -> dict[str, Any]:
    return {
        "id": "t", "status": "active", "direction": "out",
        "progress_bytes": 800, "total_bytes": 1000, "wire_bytes": 800,
        "metadata": metadata,
    }


def test_ui_truth_does_not_call_resumed_bytes_already_known() -> None:
    resumed = transfer_autopilot_truth(
        _row(prior_hit_rate_actual=0.8, skipped_ratio=0.0, skipped_bytes=0, resumed_bytes=800)
    )
    assert resumed["known_pct"] == 0.0
    assert resumed["sent_only_missing_pieces"] is False
    assert not any("already known" in fact for fact in resumed["facts"])


def test_ui_truth_still_reports_real_prior_knowledge() -> None:
    known = transfer_autopilot_truth(
        _row(prior_hit_rate_actual=0.8, skipped_ratio=0.8, skipped_bytes=800)
    )
    assert known["known_pct"] == 80.0
    assert "80% already known" in known["facts"]
    # Known before the transfer AND resumed: only the first is "already known".
    both = transfer_autopilot_truth(
        _row(prior_hit_rate_actual=0.8, skipped_ratio=0.2, skipped_bytes=200, resumed_bytes=600)
    )
    assert both["known_pct"] == 20.0
    assert "20% already known" in both["facts"]
