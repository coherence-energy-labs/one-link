"""Accept-first incoming-file policy.

By default One Link now HOLDS a standalone incoming file offer until the
user explicitly accepts it, instead of auto-downloading silently. These
pin the core gating + accept/decline behaviour without spinning up two
real daemons (the wire-level FILE_OFFER_HELD handshake is exercised by
the two-daemon e2e).
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon, IncomingFile
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pb = pub.public_bytes_raw()
    fp = fingerprint_of(pb)
    return Identity(
        private=sk, public=pub, public_bytes=pb,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))


class _ClosedChannel(_FakeChannel):
    async def send(self, payload: bytes) -> None:
        raise ConnectionResetError("sender disconnected")


def _daemon(tmp_path: Path) -> Daemon:
    d = Daemon(_new_identity())
    d.state = State(db_path=tmp_path / "s.db")
    return d


def _held_transfer(
    d: Daemon, tid: str, peer_fp: str, tmp_path: Path, *, blob: str = "ab" * 32,
    size: int = 10, name: str = "photo.png",
) -> None:
    d.state.upsert_transfer(
        id=tid, direction="in", peer_fp=peer_fp, kind="file",
        name=name, size=size, blob_hash=blob, status="offered",
        progress_bytes=0, total_bytes=size, chunks_done=0, chunks_total=0,
        metadata={"needs_accept": True, "delivery_state": "awaiting_acceptance"},
    )
    # These narrow response-correlation tests now include the current
    # writer. The real CDC path is exercised separately by daemon tests.
    d._incoming_files[blob] = IncomingFile(
        name=name, size=size, blob_hex=blob, peer_fp=peer_fp,
        transfer_id=tid, out_path=tmp_path / (blob + ".part"),
        handle=BytesIO(), hasher=None,
    )


# ── setting default ─────────────────────────────────────────────


def test_require_accept_defaults_on(tmp_path, monkeypatch):
    # The suite-wide conftest sets the env OFF; clear it to verify the
    # true production default (env absent, no setting → ON). __init__
    # reads the env, so delenv must precede Daemon construction.
    monkeypatch.delenv("ONE_LINK_REQUIRE_FILE_ACCEPT", raising=False)
    d = _daemon(tmp_path)
    try:
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is True
    finally:
        d.state.close()


def test_require_accept_can_be_turned_off(tmp_path, monkeypatch):
    monkeypatch.delenv("ONE_LINK_REQUIRE_FILE_ACCEPT", raising=False)
    d = _daemon(tmp_path)
    try:
        d.state.set_setting("incoming_files_require_accept", "false")
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is False
    finally:
        d.state.close()


def test_env_override_wins_over_setting(tmp_path, monkeypatch):
    """ONE_LINK_REQUIRE_FILE_ACCEPT overrides the stored setting (used
    by the integration harness)."""
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "0")
    d = _daemon(tmp_path)
    try:
        d.state.set_setting("incoming_files_require_accept", "true")
        d.refresh_runtime_settings()
        assert d._incoming_files_require_accept is False  # env wins
    finally:
        d.state.close()


# ── accept resumes the pull ─────────────────────────────────────


@pytest.mark.asyncio
async def test_accept_sends_ack_and_marks_active(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "aa" * 32
        _held_transfer(d, "in:abc", peer, tmp_path)
        ch = _FakeChannel()
        d._pending_file_offers["in:abc"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "aaaa",
            "blob": "ab" * 32, "msg_id": "m1", "msg": {"id": "m1"},
            "mode": "stream", "missing": None, "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.accept_file_offer("in:abc")
        assert res["ok"] is True
        # The deferred ACK (stream-mode resume) went to the sender.
        assert any(m.get("t") == "ACK" and m.get("of") == "m1" for m in ch.sent)
        # Pending cleared, transfer now active + no longer needs accept.
        assert "in:abc" not in d._pending_file_offers
        rec = d.state.get_transfer("in:abc")
        assert rec.status == "active"
        assert rec.metadata.get("needs_accept") is False
    finally:
        d.state.close()


@pytest.mark.asyncio
async def test_accept_cdc_sends_file_wants(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "bb" * 32
        _held_transfer(d, "in:cdc", peer, tmp_path, blob="cd" * 32)
        ch = _FakeChannel()
        d._pending_file_offers["in:cdc"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "bbbb",
            "blob": "cd" * 32, "msg_id": "m2", "msg": {"id": "m2"},
            "mode": "cdc", "missing": [0, 1, 2], "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.accept_file_offer("in:cdc")
        assert res["ok"] is True
        wants = [m for m in ch.sent if m.get("t") == "FILE_WANTS"]
        assert wants and wants[0]["wants"] == [0, 1, 2]
    finally:
        d.state.close()


@pytest.mark.asyncio
async def test_accept_survives_closed_channel_and_hides_reprompt(tmp_path):
    """Consent is durable even when the sender's original session died."""
    d = _daemon(tmp_path)
    try:
        peer = "dd" * 32
        _held_transfer(d, "in:retry", peer, tmp_path, blob="de" * 32, size=100, name="ACE.zip")
        d._pending_file_offers["in:retry"] = {
            "channel": _ClosedChannel(), "peer_fp": peer, "peer_sid": "dddd",
            "blob": "de" * 32, "msg_id": "old", "msg": {"id": "old"},
            "mode": "cdc", "missing": [2, 3], "name": "ACE.zip",
            "size": 100, "created_ms": 1, "accepted": False,
        }

        result = await d.accept_file_offer("in:retry")

        assert result["ok"] is False
        assert d._pending_file_offers["in:retry"]["accepted"] is True
        assert d.list_pending_file_offers() == []
        assert not any(
            item["kind"] == "pending_accept"
            for item in d.list_attention_items()
        )
        row = d.state.get_transfer("in:retry")
        assert row.status == "paused"
        assert row.metadata["needs_accept"] is False
        assert row.metadata["delivery_state"] == "waiting_for_sender"
    finally:
        d.state.close()


def test_prior_inline_offer_does_not_forge_resume_acceptance(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "ee" * 32
        blob = "01" * 32
        d.state.record_message(
            id="original-offer", ts_ms=1, direction="in", peer_fp=peer,
            msg_type="FILE_OFFER", body=None,
            metadata={"blob": blob, "chat_inline": True, "name": "ACE.zip"},
        )
        assert d._prior_inbound_file_offer_state(peer, blob) == (
            True, False, "ACE.zip",
        )
        assert d._prior_inbound_file_offer_state(peer, "02" * 32) == (
            False, False, None,
        )
    finally:
        d.state.close()


# ── decline tells the sender + cleans up ────────────────────────


@pytest.mark.asyncio
async def test_decline_sends_file_declined_and_fails_transfer(tmp_path):
    d = _daemon(tmp_path)
    try:
        peer = "cc" * 32
        _held_transfer(d, "in:dec", peer, tmp_path, blob="ef" * 32)
        ch = _FakeChannel()
        d._pending_file_offers["in:dec"] = {
            "channel": ch, "peer_fp": peer, "peer_sid": "cccc",
            "blob": "ef" * 32, "msg_id": "m3", "msg": {"id": "m3"},
            "mode": "cdc", "missing": [0], "name": "photo.png",
            "size": 10, "created_ms": 0,
        }
        res = await d.decline_file_offer("in:dec")
        assert res["ok"] is True
        assert any(m.get("t") == "FILE_DECLINED" for m in ch.sent)
        assert "in:dec" not in d._pending_file_offers
        rec = d.state.get_transfer("in:dec")
        assert rec.status == "failed"
        assert rec.metadata.get("delivery_state") == "declined"
    finally:
        d.state.close()


@pytest.mark.asyncio
async def test_accept_unknown_offer_is_idempotent(tmp_path):
    d = _daemon(tmp_path)
    try:
        res = await d.accept_file_offer("in:nope")
        assert res["ok"] is False
    finally:
        d.state.close()


def test_list_pending_file_offers_shape(tmp_path):
    d = _daemon(tmp_path)
    try:
        d._pending_file_offers["in:x"] = {
            "channel": _FakeChannel(), "peer_fp": "aa" * 32,
            "peer_sid": "aaaa", "blob": "ab" * 32, "msg_id": "m",
            "msg": {}, "mode": "stream", "missing": None,
            "name": "photo.png", "size": 42, "created_ms": 123,
        }
        offers = d.list_pending_file_offers()
        assert len(offers) == 1
        assert offers[0]["transfer_id"] == "in:x"
        assert offers[0]["name"] == "photo.png"
        assert offers[0]["size"] == 42
    finally:
        d.state.close()


# ── the FILE_OFFER handler actually gates (source-level guard) ──


def test_file_offer_handler_holds_when_require_accept():
    import inspect
    from one_link.daemon import Daemon as _D
    src = inspect.getsource(_D._handle_peer_msg) if hasattr(_D, "_handle_peer_msg") else ""
    # The hold logic lives in the FILE_OFFER branch; assert the guard +
    # the FILE_OFFER_HELD signal exist somewhere in the daemon source.
    full = inspect.getsource(__import__("one_link.daemon", fromlist=["x"]))
    assert "_incoming_files_require_accept" in full
    assert "FILE_OFFER_HELD" in full
    assert "_file_accept_allow" in full


def test_file_offer_gate_rejects_sender_controlled_consent_bypass():
    """Sender hints and filename heuristics must never replace consent."""
    import inspect
    from one_link import daemon as _dm

    full = inspect.getsource(_dm)
    assert "_looks_like_inline_chat_image" not in full
    assert "and not _chat_inline_msg" not in full
    assert "and not _looks_inline" not in full
    assert "neither may bypass the accept-first boundary" in full


def test_send_file_signature_supports_display_name_and_chat_inline():
    """The sender must accept the clean-name + chat-inline overrides
    so api_send_file can strip the staging prefix and tag chat content."""
    import inspect
    from one_link.daemon import Daemon

    sig = str(inspect.signature(Daemon.send_file))
    assert "display_name" in sig
    assert "chat_inline" in sig


def test_chat_renderer_collapses_retry_offers_by_blob():
    html = (
        Path(__file__).parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert "renderedOfferBlobs" in html
    assert "renderedOfferBlobs.has(key)" in html
    assert "renderedOfferBlobs.add(key)" in html
