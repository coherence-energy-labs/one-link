"""An explicitly requested file transport survives pause and durable resume.

``send_file(transport="tcp")`` persists ``transport_requested`` on the ledger
row.  Every path that re-runs a paused row (the reconnect/backoff resume and
the manual HTTP retry) must re-issue that exact request: resuming as ``auto``
silently lets the transfer ride another route and records a receipt that says
nothing specific was asked for.  The "reject unsupported selection" contract
from 0731ae5 must therefore hold on resumed attempts exactly as on the first.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from one_link.daemon import Daemon, OutboundSession, TransferPausedError
from one_link.discovery import Peer
from one_link.state import State
from tests.test_file_commit_receipts import _SenderChannel, _identity


def _runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    peer_identity = _identity()
    state = State(db_path=tmp_path / "sender.db")
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    daemon = Daemon(_identity())
    daemon.state = state
    # Background resume tasks would race the explicit resume under test.
    monkeypatch.setattr(daemon, "_schedule_resume_paused", lambda *_a, **_k: None)
    peer = Peer(
        short_id=peer_identity.short_id,
        hostname="receiver",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=peer_identity.public_bytes.hex(),
    )
    source = tmp_path / "explicit-route.bin"
    source.write_bytes(b"payload that was asked to ride tcp")
    return daemon, state, peer_identity, peer, source


async def _pause_first_attempt(
    daemon: Daemon,
    monkeypatch: pytest.MonkeyPatch,
    peer: Peer,
    source: Path,
    *,
    transport: str,
) -> str:
    real_dial = daemon._get_outbound_session
    reachable = {"yes": False}

    async def _dial(*args, **kwargs):
        if not reachable["yes"]:
            raise ConnectionRefusedError("peer listener not reachable yet")
        return await real_dial(*args, **kwargs)

    monkeypatch.setattr(daemon, "_get_outbound_session", _dial)
    with pytest.raises(TransferPausedError) as paused:
        await daemon.send_file(peer, source, transport=transport)
    reachable["yes"] = True
    return str(paused.value.transfer_id)


def _install_session(daemon: Daemon, peer_identity, peer: Peer, *, regime: str):
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon._outbound_sessions[peer_identity.fingerprint] = OutboundSession(
        peer_fp=peer_identity.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime=regime,
    )
    return channel


@pytest.mark.asyncio
async def test_resume_over_the_requested_route_records_the_requested_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer_identity, peer, source = _runtime(tmp_path, monkeypatch)
    try:
        transfer_id = await _pause_first_attempt(
            daemon, monkeypatch, peer, source, transport="tcp",
        )

        paused = state.get_transfer(transfer_id)
        assert paused.status == "paused"
        assert paused.metadata["transport_requested"] == "tcp"

        channel = _install_session(daemon, peer_identity, peer, regime="lan")

        async def _resolve(_peer_fp: str):
            return peer

        monkeypatch.setattr(daemon, "resolve_for_send", _resolve)
        result = await daemon.resume_paused_transfers_for(
            peer_identity.fingerprint, force=True,
        )

        assert result["resumed"] == 1
        row = state.get_transfer(transfer_id)
        assert row.status == "complete"
        assert row.metadata["commit_confirmed"] is True
        assert row.metadata["transport_requested"] == "tcp"
        assert row.metadata["payload_transport"] == "tcp"
        assert any(m.get("t") == "FILE_OFFER" for m in channel.sent)
    finally:
        state.close()


@pytest.mark.asyncio
async def test_resume_refuses_a_route_the_original_request_excluded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer_identity, peer, source = _runtime(tmp_path, monkeypatch)
    try:
        transfer_id = await _pause_first_attempt(
            daemon, monkeypatch, peer, source, transport="tcp",
        )

        # The device comes back reachable only through the relay.  A tcp
        # request resumed as ``auto`` would deliver over it and call it done.
        channel = _install_session(daemon, peer_identity, peer, regime="relay")

        async def _resolve(_peer_fp: str):
            return peer

        monkeypatch.setattr(daemon, "resolve_for_send", _resolve)
        result = await daemon.resume_paused_transfers_for(
            peer_identity.fingerprint, force=True,
        )

        assert result["resumed"] == 0
        assert result["errors"] == 1
        row = state.get_transfer(transfer_id)
        assert row.status == "failed"
        assert row.metadata["error_class"] == "UnsupportedFileTransport"
        assert row.metadata["transport_requested"] == "tcp"
        assert row.metadata["delivery_state"] == "needs_attention"
        assert not any(m.get("t") == "FILE_OFFER" for m in channel.sent)
    finally:
        state.close()


@pytest.mark.asyncio
async def test_resume_without_a_recorded_request_keeps_auto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rows that predate transport selection (and queued intents, which have
    no selection) resume with the default rather than an invented one."""
    daemon, state, peer_identity, peer, source = _runtime(tmp_path, monkeypatch)
    try:
        state.upsert_transfer(
            id="t-legacy", direction="out", peer_fp=peer_identity.fingerprint,
            kind="file", name=source.name, size=source.stat().st_size,
            status="paused", progress_bytes=0, total_bytes=source.stat().st_size,
            chunks_done=0, chunks_total=1,
            metadata={"path": str(source), "next_retry_ms": 0},
        )
        calls: list[dict[str, Any]] = []

        async def _send(_peer, path, *, transfer_id=None, **kwargs):
            calls.append({"transfer_id": transfer_id, **kwargs})
            state.update_transfer(transfer_id, status="complete")
            return {"ok": True}

        async def _resolve(_peer_fp: str):
            return peer

        monkeypatch.setattr(daemon, "resolve_for_send", _resolve)
        monkeypatch.setattr(daemon, "send_file", _send)
        result = await daemon.resume_paused_transfers_for(peer_identity.fingerprint)
        assert result["resumed"] == 1
        assert calls == [{"transfer_id": "t-legacy"}]
        assert Daemon.retry_send_kwargs({"path": str(source)}) == {}
    finally:
        state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "persisted",
    ["quic", "webrtc", "TCP", "", None, 7],
)
async def test_resume_fails_an_unsupported_persisted_selection_without_dialing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, persisted,
) -> None:
    """A ledger row can only carry a selection send_file validated, so any
    other value is corruption or an old experimental lane.  It must fail the
    row visibly, never resume as auto and never loop on every pump."""
    daemon, state, peer_identity, peer, source = _runtime(tmp_path, monkeypatch)
    try:
        state.upsert_transfer(
            id="t-bad-route", direction="out", peer_fp=peer_identity.fingerprint,
            kind="file", name=source.name, size=source.stat().st_size,
            status="paused", progress_bytes=0, total_bytes=source.stat().st_size,
            chunks_done=0, chunks_total=1,
            metadata={
                "path": str(source), "next_retry_ms": 0,
                "transport_requested": persisted,
            },
        )
        other = source.with_name("next-in-queue.bin")
        other.write_bytes(b"independent row")
        state.upsert_transfer(
            id="t-next", direction="out", peer_fp=peer_identity.fingerprint,
            kind="file", name=other.name, size=other.stat().st_size,
            status="paused", progress_bytes=0, total_bytes=other.stat().st_size,
            chunks_done=0, chunks_total=1,
            metadata={"path": str(other), "next_retry_ms": 0, "transport_requested": "tcp"},
        )
        calls: list[dict[str, Any]] = []

        async def _send(_peer, path, *, transfer_id=None, **kwargs):
            calls.append({"transfer_id": transfer_id, **kwargs})
            state.update_transfer(transfer_id, status="complete")
            return {"ok": True}

        async def _resolve(_peer_fp: str):
            return peer

        monkeypatch.setattr(daemon, "resolve_for_send", _resolve)
        monkeypatch.setattr(daemon, "send_file", _send)
        result = await daemon.resume_paused_transfers_for(peer_identity.fingerprint)

        bad = state.get_transfer("t-bad-route")
        assert bad.status == "failed"
        assert bad.metadata["error_class"] == "UnsupportedFileTransport"
        assert bad.metadata["delivery_state"] == "needs_attention"
        assert bad.metadata["transport_requested"] == persisted
        assert calls == [{"transfer_id": "t-next", "transport": "tcp"}]
        assert result["resumed"] == 1
        assert result["errors"] == 1
        with pytest.raises(ValueError, match="file_transport"):
            Daemon.retry_send_kwargs({"transport_requested": persisted})
    finally:
        state.close()


class _FakeReq:
    def __init__(self, transfer_id: str) -> None:
        self.query: dict[str, str] = {}
        self.match_info = {"transfer_id": transfer_id}


def _retry_server(rec, calls: list[dict[str, Any]]):
    from one_link.server import UIServer

    async def _resolve(_peer_fp: str):
        return SimpleNamespace(short_id="peer")

    async def _send(_peer, path, *, transfer_id=None, **kwargs):
        calls.append({"path": Path(path), "transfer_id": transfer_id, **kwargs})
        return {"ok": True}

    server = object.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=SimpleNamespace(
            get_transfer=lambda _transfer_id: rec,
            get_peer=lambda _peer_fp: SimpleNamespace(trust="pinned"),
        ),
        _remote_commit_is_failstopped=lambda _transfer_id: False,
        resolve_for_send=_resolve,
        send_file=_send,
    )
    return server


@pytest.mark.asyncio
async def test_manual_retry_reissues_the_persisted_transport(tmp_path: Path) -> None:
    source = tmp_path / "manual.bin"
    source.write_bytes(b"manual retry source")
    rec = SimpleNamespace(
        id="out:" + ("ab" * 32) + ":123456789abc",
        direction="out",
        status="paused",
        name="manual.bin",
        peer_fp="cd" * 32,
        metadata={
            "path": str(source),
            "display_name": "Manual.bin",
            "chat_inline": True,
            "rel_path": "docs/Manual.bin",
            "transport_requested": "relay",
        },
    )
    calls: list[dict[str, Any]] = []
    server = _retry_server(rec, calls)

    response = await server.api_retry_transfer(_FakeReq(rec.id))

    assert response.status == 200
    assert calls == [{
        "path": source,
        "transfer_id": rec.id,
        "display_name": "Manual.bin",
        "chat_inline": True,
        "rel_path": "docs/Manual.bin",
        "transport": "relay",
    }]


@pytest.mark.asyncio
async def test_manual_retry_refuses_unsupported_persisted_transport(tmp_path: Path) -> None:
    source = tmp_path / "manual.bin"
    source.write_bytes(b"manual retry source")
    rec = SimpleNamespace(
        id="out:" + ("ef" * 32) + ":123456789abc",
        direction="out",
        status="failed",
        name="manual.bin",
        peer_fp="cd" * 32,
        metadata={"path": str(source), "transport_requested": "quic"},
    )
    calls: list[dict[str, Any]] = []
    server = _retry_server(rec, calls)

    response = await server.api_retry_transfer(_FakeReq(rec.id))
    body = json.loads(response.text)

    assert response.status == 409
    assert body["ok"] is False
    assert body["code"] == "unsupported_file_transport"
    assert body["transfer_id"] == rec.id
    assert calls == []
