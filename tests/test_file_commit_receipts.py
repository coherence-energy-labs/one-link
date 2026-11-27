from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import stat
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capabilities import (
    CHAT,
    FILES,
    FILE_COMMIT_RECEIPT_V1,
    LOCAL_CAPABILITIES,
    TRANSPORT_LAYER_CAPS,
)
import one_link.daemon as daemon_module
from one_link.daemon import (
    Daemon,
    FolderArchiveCommitError,
    IncomingFile,
    OutboundSession,
    ReceiverCommitError,
    SenderCommitAccountingError,
    TransferLedgerUnavailableError,
    TransferPausedError,
    _durable_commit_path,
    _inbound_delivery_transfer_id,
    _validate_file_commit_receipt,
)
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.paths import inbox_dir
from one_link.resume import ResumeSidecar
from one_link.state import State
from one_link.transfer_safety import TransferAdmissionPolicy
from one_link.wire import decode_msg, encode_msg, make_msg


DELIVERY_ID = "12" * 16


def _inbound_transfer_id(peer: Identity, delivery_id: str = DELIVERY_ID) -> str:
    return f"in:{peer.fingerprint}:{delivery_id}"


def test_legacy_inbound_transfer_id_binds_presentation_contract() -> None:
    peer_fp = "ab" * 32
    blob = "cd" * 32
    common = {
        "peer_fp": peer_fp,
        "delivery_id": "",
        "blob": blob,
        "delivery_kind": "file",
    }
    first = _inbound_delivery_transfer_id(
        **common,
        delivery_name="same.bin",
        delivery_rel_path="folder-a/same.bin",
    )
    retry = _inbound_delivery_transfer_id(
        **common,
        delivery_name="same.bin",
        delivery_rel_path="folder-a/same.bin",
    )
    renamed = _inbound_delivery_transfer_id(
        **common,
        delivery_name="renamed.bin",
        delivery_rel_path="folder-a/renamed.bin",
    )
    moved = _inbound_delivery_transfer_id(
        **common,
        delivery_name="same.bin",
        delivery_rel_path="folder-b/same.bin",
    )

    assert first == retry
    assert len({first, renamed, moved}) == 3
    assert first.startswith(f"in:legacy:{peer_fp}:{blob}:")


def test_modern_inbound_transfer_id_uses_nonce_not_presentation() -> None:
    peer_fp = "ef" * 32
    delivery_id = "12" * 16
    transfer_id = _inbound_delivery_transfer_id(
        peer_fp=peer_fp,
        delivery_id=delivery_id,
        blob="34" * 32,
        delivery_name="name.bin",
        delivery_rel_path="path/name.bin",
        delivery_kind="file",
    )

    assert transfer_id == f"in:{peer_fp}:{delivery_id}"


@pytest.mark.asyncio
async def test_active_legacy_same_blob_different_path_is_not_coalesced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        daemon._incoming_files_require_accept = False
        content = b"same legacy bytes, distinct presentation intents"
        blob = blake3.blake3(content).hexdigest()
        channel = _RecordingChannel(peer, commit_capable=False)
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="legacy-first-offer",
                name="same.bin",
                rel_path="folder-a/same.bin",
                size=len(content),
                blob=blob,
                mode="stream",
            ),
        )
        first_owner = daemon._incoming_files[blob]

        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="legacy-distinct-offer",
                name="renamed.bin",
                rel_path="folder-b/renamed.bin",
                size=len(content),
                blob=blob,
                mode="stream",
            ),
        )

        assert daemon._incoming_files[blob] is first_owner
        assert first_owner.delivery_name == "same.bin"
        assert first_owner.delivery_rel_path == "folder-a/same.bin"
        assert channel.sent[-1]["t"] == "ACK"
        assert channel.sent[-1]["of"] == "legacy-distinct-offer"
        assert channel.sent[-1]["rejected"] == (
            "admission_blob_in_use_by_another_delivery"
        )
    finally:
        incoming = daemon._incoming_files.get(blob) if "blob" in locals() else None
        if incoming is not None:
            daemon._abort_incoming_file(blob, incoming)
        state.close()


def _identity() -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname="commit-test",
    )


class _RecordingChannel:
    def __init__(self, peer: Identity, *, commit_capable: bool = True) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        features = [CHAT, FILES]
        if commit_capable:
            features.append(FILE_COMMIT_RECEIPT_V1)
        self.peer_caps = {
            "protocol": "OL1.2",
            "features": features,
            "from": peer.short_id,
            "app_version": "0.21.0",
        }
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))


def _receiver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Daemon, State, Identity]:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    peer = _identity()
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint=peer.fingerprint,
        short_id=peer.short_id,
        pubkey=peer.public_bytes,
    )
    state.set_peer_trust(peer.fingerprint, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    return daemon, state, peer



def _archive_headroom_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate tiny commit-path fixtures from the host's disk occupancy.

    This changes only the test inbox's capacity observation. Real archive
    I/O, fsync, and publication remain active; capacity rejection tests
    supply their own explicitly constrained snapshots.
    """
    real_disk_usage = daemon_module.shutil.disk_usage
    target = inbox_dir().resolve()
    gib = 1024**3

    def disk_usage(path):
        if Path(path).resolve() == target:
            return SimpleNamespace(total=64 * gib, used=32 * gib, free=32 * gib)
        return real_disk_usage(path)

    monkeypatch.setattr(daemon_module.shutil, "disk_usage", disk_usage)


def _install_incoming(
    daemon: Daemon,
    state: State,
    peer: Identity,
    *,
    blob: str,
    size: int,
    path: Path,
    mode: str = "stream",
) -> IncomingFile:
    is_archive = path.parent.name == daemon._FOLDER_ARCHIVE_MAGIC
    delivery_rel_path = (
        f"{daemon._FOLDER_ARCHIVE_MAGIC}/{path.name}" if is_archive else ""
    )
    delivery_kind = "folder_archive" if is_archive else "file"
    transfer_id = _inbound_transfer_id(peer)
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=peer.fingerprint,
        kind="file",
        name=path.name,
        size=size,
        blob_hash=blob,
        status="offered",
        total_bytes=size,
        metadata={
            "mode": mode,
            "path": str(path),
            "delivery_id": DELIVERY_ID,
            "delivery_name": path.name,
            "delivery_rel_path": delivery_rel_path,
            "delivery_kind": delivery_kind,
        },
    )
    incoming = IncomingFile(
        name=path.name,
        size=size,
        blob_hex=blob,
        out_path=path,
        handle=open(path, "w+b"),
        hasher=blake3.blake3(),
        final_path=path,
        delivery_id=DELIVERY_ID,
        delivery_name=path.name,
        delivery_rel_path=delivery_rel_path,
        delivery_kind=delivery_kind,
        transfer_id=transfer_id,
        peer_fp=peer.fingerprint,
        offer_id="offer-commit-1",
        commit_receipt_required=True,
    )
    daemon._incoming_files[blob] = incoming
    return incoming


def _commit(
    *,
    offer_id: str = "offer-1",
    blob: str = "ab" * 32,
    size: int = 7,
    mode: str = "stream",
    delivery_id: str = DELIVERY_ID,
    delivery_name: str = "payload.bin",
    delivery_rel_path: str = "",
    delivery_kind: str = "file",
    **updates,
) -> dict:
    receipt = {
        "t": "FILE_COMMIT",
        "receipt_version": 1,
        "of": offer_id,
        "blob": blob,
        "size": size,
        "mode": mode,
        "delivery_id": delivery_id,
        "delivery_name": delivery_name,
        "delivery_rel_path": delivery_rel_path,
        "delivery_kind": delivery_kind,
        "ok": True,
        "durable": True,
        "committed_bytes": size,
        "verified_hash": blob,
        "reason": "",
        "retryable": False,
    }
    receipt.update(updates)
    return receipt


def _complete_commit_metadata(
    *,
    peer: Identity,
    blob: str,
    content_path: Path,
    size: int,
    delivery_name: str | None = None,
    delivery_rel_path: str = "",
    delivery_kind: str = "file",
    delivery_id: str = DELIVERY_ID,
) -> dict:
    committed_ms = int(time.time() * 1000)
    return {
        "mode": "stream",
        "path": str(content_path),
        "delivery_id": delivery_id,
        "delivery_name": delivery_name or content_path.name,
        "delivery_rel_path": delivery_rel_path,
        "delivery_kind": delivery_kind,
        "file_commit_evidence": {
            "version": 1,
            "peer_fp": peer.fingerprint,
            "delivery_id": delivery_id,
            "delivery_name": delivery_name or content_path.name,
            "delivery_rel_path": delivery_rel_path,
            "delivery_kind": delivery_kind,
            "blob": blob,
            "size": size,
            "path": str(content_path),
            "identity": _durable_commit_path(content_path),
            "committed_ms": committed_ms,
            "replay_until_ms": committed_ms + 86_400_000,
        },
    }


async def _start_modern_offer(
    daemon: Daemon,
    peer: Identity,
    channel: _RecordingChannel,
    *,
    name: str,
    content: bytes,
    delivery_id: str = DELIVERY_ID,
    rel_path: str = "",
    chunks: list[dict] | None = None,
) -> IncomingFile:
    daemon._incoming_files_require_accept = False
    blob = blake3.blake3(content).hexdigest()
    fields: dict = {
        "id": f"offer-{delivery_id}",
        "name": name,
        "size": len(content),
        "blob": blob,
        "mode": "cdc" if chunks is not None else "stream",
        "delivery_id": delivery_id,
    }
    if rel_path:
        fields["rel_path"] = rel_path
    if chunks is not None:
        fields["chunks"] = chunks
    await daemon._on_peer_message(
        channel,
        make_msg("FILE_OFFER", peer.short_id, **fields),
    )
    return daemon._incoming_files[blob]


@pytest.mark.asyncio
async def test_cdc_offer_requests_no_bytes_when_resume_sidecar_cannot_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        daemon._incoming_files_require_accept = False
        content = b"resume boundary"
        blob = blake3.blake3(content).hexdigest()
        chunk = {
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": blob,
        }
        monkeypatch.setattr(
            daemon_module,
            "_persist_resume_sidecar",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("injected sidecar outage")
            ),
        )
        channel = _RecordingChannel(peer)
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="sidecar-failure-offer",
                name="resume.bin",
                size=len(content),
                blob=blob,
                mode="cdc",
                chunks=[chunk],
                delivery_id=DELIVERY_ID,
            ),
        )

        assert all(message.get("t") != "FILE_WANTS" for message in channel.sent)
        assert channel.sent[-1]["t"] == "ACK"
        assert channel.sent[-1]["rejected"] == (
            "admission_resume_state_unavailable"
        )
        assert blob not in daemon._incoming_files
        assert daemon._transfer_reservation_ledger().get(
            _inbound_transfer_id(peer)
        ) is None
    finally:
        state.close()


@pytest.mark.asyncio
async def test_file_offer_requests_no_bytes_when_transfer_ledger_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        daemon._incoming_files_require_accept = False
        content = b"ledger boundary"
        blob = blake3.blake3(content).hexdigest()
        monkeypatch.setattr(daemon, "_upsert_transfer", lambda **_kwargs: None)
        channel = _RecordingChannel(peer)
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="ledger-failure-offer",
                name="ledger.bin",
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=DELIVERY_ID,
            ),
        )

        assert all(message.get("t") != "FILE_WANTS" for message in channel.sent)
        assert channel.sent[-1]["t"] == "ACK"
        assert channel.sent[-1]["rejected"] == (
            "admission_transfer_ledger_unavailable"
        )
        assert blob not in daemon._incoming_files
        assert not list(
            (inbox_dir() / daemon_module.INCOMING_STAGING_DIR).glob("*.part")
        )
    finally:
        state.close()


def test_commit_receipt_capability_is_transport_negotiated() -> None:
    assert FILE_COMMIT_RECEIPT_V1 in LOCAL_CAPABILITIES
    assert FILE_COMMIT_RECEIPT_V1 in TRANSPORT_LAYER_CAPS


def test_transfer_terminal_commit_temporarily_uses_sqlite_full_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _daemon, state, peer = _receiver(tmp_path, monkeypatch)
    statements: list[str] = []
    try:
        transfer_id = _inbound_transfer_id(peer)
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name="durable.bin",
            size=1,
            blob_hash="ab" * 32,
            status="active",
            metadata={},
        )
        state._conn.set_trace_callback(statements.append)
        state.update_transfer_durable(transfer_id, status="complete")
        state._conn.set_trace_callback(None)

        normalized = [statement.upper().replace("  ", " ") for statement in statements]
        full_index = next(
            index
            for index, statement in enumerate(normalized)
            if "PRAGMA SYNCHRONOUS = FULL" in statement
        )
        restore_index = next(
            index
            for index, statement in enumerate(normalized[full_index + 1 :], full_index + 1)
            if "PRAGMA SYNCHRONOUS = NORMAL" in statement
        )
        update_index = next(
            index
            for index, statement in enumerate(normalized)
            if statement.lstrip().startswith("UPDATE TRANSFERS")
        )
        assert full_index < update_index < restore_index
        assert state.get_transfer(transfer_id).status == "complete"
    finally:
        state._conn.set_trace_callback(None)
        state.close()


def test_commit_receipt_validator_rejects_forged_and_crossed_fields() -> None:
    blob = "ab" * 32
    valid = _commit(blob=blob)
    assert _validate_file_commit_receipt(
        valid,
        offer_id="offer-1",
        blob=blob,
        size=7,
        mode="stream",
        delivery_id=DELIVERY_ID,
        delivery_name="payload.bin",
        delivery_rel_path="",
        delivery_kind="file",
    )["durable"] is True

    mutations = (
        {"of": "another-offer"},
        {"blob": "cd" * 32},
        {"size": 8},
        {"mode": "cdc"},
        {"delivery_id": "34" * 16},
        {"delivery_name": "crossed.bin"},
        {"delivery_rel_path": "another/place"},
        {"delivery_kind": "folder_archive"},
        {"verified_hash": "cd" * 32},
        {"committed_bytes": 6},
        {"durable": False},
        {"ok": "yes"},
    )
    for mutation in mutations:
        forged = _commit(blob=blob)
        forged.update(mutation)
        with pytest.raises(ReceiverCommitError):
            _validate_file_commit_receipt(
                forged,
                offer_id="offer-1",
                blob=blob,
                size=7,
                mode="stream",
                delivery_id=DELIVERY_ID,
                delivery_name="payload.bin",
                delivery_rel_path="",
                delivery_kind="file",
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("binary", [False, True])
async def test_receiver_hash_failure_never_emits_success_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binary: bool,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        expected = b"GOOD"
        corrupt = b"EVIL"
        blob = blake3.blake3(expected).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(expected),
            path=tmp_path / ("binary.bin" if binary else "json.bin"),
        )
        channel = _RecordingChannel(peer)
        if binary:
            msg = {
                **make_msg(
                    "FILE_BIN_CHUNK",
                    peer.short_id,
                    id="final-chunk",
                    blob=blob,
                    seq=0,
                    eof=True,
                ),
                "_binary_data": corrupt,
            }
        else:
            msg = make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="final-chunk",
                blob=blob,
                seq=0,
                data=base64.b64encode(corrupt).decode("ascii"),
                eof=True,
            )

        await daemon._on_peer_message(channel, msg)

        commits = [m for m in channel.sent if m.get("t") == "FILE_COMMIT"]
        assert len(commits) == 1
        assert commits[0]["of"] == incoming.offer_id
        assert commits[0]["ok"] is False
        assert commits[0]["durable"] is False
        assert state.get_transfer(incoming.transfer_id).status == "failed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_receiver_fsync_failure_returns_retryable_failed_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"durable only after fsync"
        blob = blake3.blake3(content).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=tmp_path / "fsync.bin",
        )
        channel = _RecordingChannel(peer)

        def _fail_fsync(_fd: int) -> None:
            raise OSError("injected fsync failure")

        monkeypatch.setattr("one_link.daemon.os.fsync", _fail_fsync)
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="final-fsync-chunk",
                blob=blob,
                seq=0,
                data=base64.b64encode(content).decode("ascii"),
                eof=True,
            ),
        )

        commit = next(m for m in channel.sent if m.get("t") == "FILE_COMMIT")
        assert commit["of"] == incoming.offer_id
        assert commit["ok"] is False
        assert commit["retryable"] is True
        assert commit["reason"] == "receiver_disk_commit_failed"
        assert state.get_transfer(incoming.transfer_id).status == "failed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_parent_directory_fsync_failure_never_emits_positive_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"directory entry must be durable too"
        blob = blake3.blake3(content).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=tmp_path / "directory-fsync.bin",
        )
        channel = _RecordingChannel(peer)

        def _fail_parent_fsync(_path: Path) -> None:
            raise OSError("injected parent-directory fsync failure")

        monkeypatch.setattr(
            daemon_module,
            "_fsync_parent_directory",
            _fail_parent_fsync,
        )
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="final-directory-fsync-chunk",
                blob=blob,
                seq=0,
                data=base64.b64encode(content).decode("ascii"),
                eof=True,
            ),
        )

        commits = [m for m in channel.sent if m.get("t") == "FILE_COMMIT"]
        assert len(commits) == 1
        assert commits[0]["of"] == incoming.offer_id
        assert commits[0]["ok"] is False
        assert commits[0]["durable"] is False
        assert commits[0]["retryable"] is True
        assert state.get_transfer(incoming.transfer_id).status == "failed"
    finally:
        state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("binary", [False, True])
async def test_private_staging_detects_disk_mutation_before_atomic_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binary: bool,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"whole-file-proof-must-read-the-disk"
        blob = blake3.blake3(content).hexdigest()
        channel = _RecordingChannel(peer)
        incoming = await _start_modern_offer(
            daemon,
            peer,
            channel,
            name="atomic.bin",
            content=content,
        )
        assert incoming.out_path.parent.name == daemon_module.INCOMING_STAGING_DIR
        assert incoming.final_path is not None
        assert not incoming.final_path.exists()
        split = len(content) // 2

        if binary:
            first = {
                **make_msg(
                    "FILE_BIN_CHUNK",
                    peer.short_id,
                    id="atomic-first",
                    blob=blob,
                    seq=0,
                    eof=False,
                ),
                "_binary_data": content[:split],
            }
        else:
            first = make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="atomic-first",
                blob=blob,
                seq=0,
                data=base64.b64encode(content[:split]).decode("ascii"),
                eof=False,
            )
        await daemon._on_peer_message(channel, first)
        incoming.handle.flush()
        os.fsync(incoming.handle.fileno())

        with open(incoming.out_path, "r+b") as tamper:
            tamper.seek(0)
            tamper.write(b"X")
            tamper.flush()
            os.fsync(tamper.fileno())

        if binary:
            final = {
                **make_msg(
                    "FILE_BIN_CHUNK",
                    peer.short_id,
                    id="atomic-final",
                    blob=blob,
                    seq=1,
                    eof=True,
                ),
                "_binary_data": content[split:],
            }
        else:
            final = make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="atomic-final",
                blob=blob,
                seq=1,
                data=base64.b64encode(content[split:]).decode("ascii"),
                eof=True,
            )
        await daemon._on_peer_message(channel, final)

        receipt = [m for m in channel.sent if m.get("t") == "FILE_COMMIT"][-1]
        assert receipt["ok"] is False
        assert receipt["reason"] == "receiver_disk_commit_failed"
        assert not incoming.final_path.exists()
        assert state.get_transfer(incoming.transfer_id).status == "failed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_cdc_cache_miss_returns_retryable_commit_not_late_file_wants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"cached piece"
        blob = blake3.blake3(content).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=tmp_path / "cdc.bin",
            mode="cdc",
        )
        incoming.cdc_chunks = [{
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": blob,
        }]
        incoming.cdc_missing = set()
        incoming.cdc_parts = {}
        state.update_transfer(incoming.transfer_id, status="active")
        channel = _RecordingChannel(peer)
        monkeypatch.setattr(
            daemon,
            "_finish_cdc_file_assemble",
            lambda _f, _blob: (False, 0, {0}),
        )
        monkeypatch.setattr(
            daemon,
            "_reserve_cdc_recovery_cache",
            lambda _f, _misses: True,
        )

        await daemon._finish_cdc_file(
            blob,
            peer.fingerprint,
            peer.short_id,
            make_msg("FILE_CDC_CHUNK", peer.short_id, id="last-cdc"),
            channel=channel,
        )

        assert all(m.get("t") != "FILE_WANTS" for m in channel.sent)
        commit = next(m for m in channel.sent if m.get("t") == "FILE_COMMIT")
        assert commit["ok"] is False
        assert commit["retryable"] is True
        assert commit["reason"] == "cdc_finalize_cache_miss"
        assert state.get_transfer(incoming.transfer_id).status == "paused"
        incoming.handle.close()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_cdc_retry_during_finalization_answers_each_offer_on_its_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    release = threading.Event()
    try:
        content = b"finalization-race-content"
        blob = blake3.blake3(content).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=tmp_path / "finalization-race.bin",
            mode="cdc",
        )
        incoming.handle.write(content)
        incoming.handle.flush()
        os.fsync(incoming.handle.fileno())
        incoming.handle.close()
        incoming.cdc_chunks = [{
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": blob,
        }]
        incoming.cdc_missing = set()
        incoming.cdc_streamed = {0}
        incoming.cdc_done_bytes = len(content)
        old_channel = _RecordingChannel(peer)
        new_channel = _RecordingChannel(peer)
        incoming.commit_waiters = {"offer-old": old_channel}
        incoming.offer_id = "offer-old"
        started = threading.Event()

        def _blocked_assemble(_f: IncomingFile, _blob: str):
            started.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test did not release CDC finalizer")
            return True, len(content), set()

        monkeypatch.setattr(daemon, "_finish_cdc_file_assemble", _blocked_assemble)
        task = asyncio.create_task(daemon._finish_cdc_file(
            blob,
            peer.fingerprint,
            peer.short_id,
            make_msg("FILE_CDC_CHUNK", peer.short_id, id="last-cdc"),
            channel=old_channel,  # type: ignore[arg-type]
        ))
        assert await asyncio.to_thread(started.wait, 5)
        assert incoming.finalizing is True
        original_manifest = [dict(chunk) for chunk in incoming.cdc_chunks]
        split = len(content) // 2
        changed_manifest = [
            {
                "index": 0,
                "start": 0,
                "end": split,
                "size": split,
                "hash": blake3.blake3(content[:split]).hexdigest(),
            },
            {
                "index": 1,
                "start": split,
                "end": len(content),
                "size": len(content) - split,
                "hash": blake3.blake3(content[split:]).hexdigest(),
            },
        ]
        await daemon._on_peer_message(
            new_channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="offer-new",
                name=incoming.name,
                size=len(content),
                blob=blob,
                delivery_id=DELIVERY_ID,
                chunks=changed_manifest,
            ),
        )
        assert incoming.cdc_chunks == original_manifest
        assert [m.get("t") for m in new_channel.sent] == [
            "FILE_COMMIT_VERIFYING"
        ]
        release.set()
        await task

        old_receipts = [m for m in old_channel.sent if m.get("t") == "FILE_COMMIT"]
        new_receipts = [m for m in new_channel.sent if m.get("t") == "FILE_COMMIT"]
        assert [m["of"] for m in old_receipts] == ["offer-old"]
        assert [m["of"] for m in new_receipts] == ["offer-new"]
        assert [m.get("t") for m in new_channel.sent] == [
            "FILE_COMMIT_VERIFYING",
            "FILE_COMMIT",
        ]
        assert old_receipts[0]["ok"] is True
        assert new_receipts[0]["ok"] is True
        assert state.get_transfer(incoming.transfer_id).status == "complete"
        assert daemon._incoming_files == {}
    finally:
        release.set()
        state.close()


@pytest.mark.asyncio
async def test_commit_receipt_fanout_is_newest_first_concurrent_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"fanout"
        path = tmp_path / "fanout.bin"
        path.write_bytes(content)
        closed_handle = open(path, "rb")
        closed_handle.close()
        order: list[str] = []
        fast_messages: list[dict] = []

        class _Blocked:
            async def send(self, _payload: bytes) -> None:
                order.append("old")
                await asyncio.Event().wait()

        class _Fast:
            async def send(self, payload: bytes) -> None:
                order.append("new")
                fast_messages.append(decode_msg(payload))

        incoming = IncomingFile(
            name=path.name,
            size=len(content),
            blob_hex=blake3.blake3(content).hexdigest(),
            out_path=path,
            handle=closed_handle,
            hasher=blake3.blake3(),
            final_path=path,
            delivery_id=DELIVERY_ID,
            delivery_name=path.name,
            delivery_kind="file",
            peer_fp=peer.fingerprint,
            transfer_id=_inbound_transfer_id(peer),
            commit_receipt_required=True,
            commit_waiters={"old-offer": _Blocked(), "new-offer": _Fast()},
        )
        monkeypatch.setattr(daemon_module, "FILE_COMMIT_SEND_TIMEOUT_S", 0.05)
        started = time.monotonic()
        sent = await daemon._send_incoming_file_commit_receipts(
            incoming,
            mode="stream",
            ok=True,
            committed_bytes=len(content),
        )
        elapsed = time.monotonic() - started

        assert order[:2] == ["new", "old"]
        assert elapsed < 0.5
        assert sent == 1
        assert [message["of"] for message in fast_messages] == ["new-offer"]
        assert incoming.commit_waiters == {}
    finally:
        state.close()


@pytest.mark.asyncio
async def test_cdc_auxiliary_persist_failure_cannot_reverse_durable_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"durable boundary precedes chat event"
        blob = blake3.blake3(content).hexdigest()
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=tmp_path / "persist-after-commit.bin",
            mode="cdc",
        )
        incoming.handle.write(content)
        incoming.handle.flush()
        os.fsync(incoming.handle.fileno())
        incoming.handle.close()
        incoming.cdc_chunks = [{
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": blob,
        }]
        incoming.cdc_missing = set()
        incoming.cdc_streamed = {0}
        incoming.cdc_done_bytes = len(content)
        channel = _RecordingChannel(peer)
        incoming.commit_waiters = {"persist-offer": channel}
        incoming.offer_id = "persist-offer"
        monkeypatch.setattr(
            daemon,
            "_finish_cdc_file_assemble",
            lambda _f, _blob: (True, len(content), set()),
        )
        monkeypatch.setattr(
            daemon,
            "_persist",
            lambda **_kwargs: (_ for _ in ()).throw(
                OSError("injected auxiliary event failure")
            ),
        )

        await daemon._finish_cdc_file(
            blob,
            peer.fingerprint,
            peer.short_id,
            make_msg("FILE_CDC_CHUNK", peer.short_id, id="persist-final"),
            channel=channel,  # type: ignore[arg-type]
        )

        receipts = [m for m in channel.sent if m.get("t") == "FILE_COMMIT"]
        assert len(receipts) == 1
        assert receipts[0]["ok"] is True
        assert receipts[0]["of"] == "persist-offer"
        assert state.get_transfer(incoming.transfer_id).status == "complete"
        assert incoming.out_path.read_bytes() == content
        assert daemon._incoming_files == {}
    finally:
        state.close()


@pytest.mark.asyncio
async def test_distinct_delivery_ids_publish_distinct_files_and_ledgers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"same bytes intentionally sent twice"
        blob = blake3.blake3(content).hexdigest()
        published: list[Path] = []
        transfer_ids: list[str] = []
        for index, delivery_id in enumerate(("21" * 16, "22" * 16)):
            channel = _RecordingChannel(peer)
            incoming = await _start_modern_offer(
                daemon,
                peer,
                channel,
                name="duplicate-intent.bin",
                content=content,
                delivery_id=delivery_id,
            )
            staging = incoming.out_path
            final = incoming.final_path
            assert final is not None and not final.exists()
            await daemon._on_peer_message(
                channel,
                make_msg(
                    "FILE_CHUNK",
                    peer.short_id,
                    id=f"delivery-final-{index}",
                    blob=blob,
                    seq=0,
                    data=base64.b64encode(content).decode("ascii"),
                    eof=True,
                ),
            )
            receipt = next(
                message
                for message in channel.sent
                if message.get("t") == "FILE_COMMIT"
            )
            assert receipt["ok"] is True
            assert receipt["delivery_id"] == delivery_id
            assert not staging.exists()
            assert final.read_bytes() == content
            published.append(final)
            transfer_ids.append(str(incoming.transfer_id))

        assert published[0] != published[1]
        assert transfer_ids == [
            _inbound_transfer_id(peer, "21" * 16),
            _inbound_transfer_id(peer, "22" * 16),
        ]
        assert all(state.get_transfer(row_id).status == "complete" for row_id in transfer_ids)
    finally:
        state.close()


@pytest.mark.asyncio
async def test_active_blob_cannot_be_crossed_into_another_delivery_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"one active content object"
        first_channel = _RecordingChannel(peer)
        first = await _start_modern_offer(
            daemon,
            peer,
            first_channel,
            name="first-name.bin",
            content=content,
            delivery_id="31" * 16,
        )
        second_channel = _RecordingChannel(peer)
        daemon._incoming_files_require_accept = False
        await daemon._on_peer_message(
            second_channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="crossed-delivery-offer",
                name="second-name.bin",
                size=len(content),
                blob=first.blob_hex,
                mode="stream",
                delivery_id="32" * 16,
            ),
        )

        assert daemon._incoming_files[first.blob_hex] is first
        rejection = second_channel.sent[-1]
        assert rejection["t"] == "ACK"
        assert rejection["rejected"] == "admission_blob_in_use_by_another_delivery"
        assert state.get_transfer(first.transfer_id).name == "first-name.bin"
        daemon._abort_incoming_file(first.blob_hex, first)
    finally:
        state.close()


@pytest.mark.asyncio
async def test_restart_partial_is_never_claimed_or_deleted_by_new_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"resumable bytes"
        blob = blake3.blake3(content).hexdigest()
        partial = inbox_dir() / daemon_module.INCOMING_STAGING_DIR / "resume.part"
        partial.parent.mkdir(parents=True, exist_ok=True)
        partial.write_bytes(content[:4])
        old_delivery = "71" * 16
        sidecar = ResumeSidecar(
            blob_hex=blob,
            peer_fp=peer.fingerprint,
            name="resume.bin",
            size=len(content),
            out_path=str(partial),
            cdc_chunks=[{
                "index": 0,
                "start": 0,
                "end": len(content),
                "size": len(content),
                "hash": blob,
            }],
            delivery_id=old_delivery,
            delivery_name="resume.bin",
            delivery_kind="file",
            final_path=str(inbox_dir() / "resume.bin"),
        )
        daemon._resume_registry.register(sidecar)
        channel = _RecordingChannel(peer)
        daemon._incoming_files_require_accept = False
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="new-delivery-vs-resume",
                name="resume.bin",
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id="72" * 16,
            ),
        )

        assert channel.sent[-1]["rejected"] == (
            "admission_resume_owned_by_another_delivery"
        )
        assert partial.read_bytes() == content[:4]
        assert daemon._resume_registry.pop_match(
            peer.fingerprint,
            blob,
            delivery_id=old_delivery,
        ) is sidecar
        assert blob not in daemon._incoming_files
    finally:
        state.close()


@pytest.mark.asyncio
async def test_385_mib_resume_from_81_mib_keeps_one_logical_offer_and_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for the reported 385 MiB ZIP stalling near 81 MiB.

    The source is sparse so the test is CI-friendly; the interrupted receiver
    partial contains and cryptographically validates the full first 81 MiB.
    Repeated authenticated offers for the same delivery must request only the
    remaining 304 chunks while retaining one ledger/history intent, one
    staging inode, and zero public files until the final commit.
    """

    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    blob = ""
    try:
        mib = 1024 * 1024
        total_chunks = 385
        completed_chunks = 81
        total_size = total_chunks * mib
        completed_size = completed_chunks * mib
        delivery_id = "81" * 16
        blob = blake3.blake3(b"ACE.zip synthetic 385 MiB resume contract").hexdigest()

        # A real 385 MiB logical source without forcing CI to materialize the
        # untouched 304 MiB. The receiver partial below contains real bytes.
        source = tmp_path / "ACE.zip"
        with open(source, "w+b") as source_handle:
            source_handle.truncate(total_size)
        assert source.stat().st_size == 385 * mib

        staging_dir = inbox_dir() / daemon_module.INCOMING_STAGING_DIR
        staging_dir.mkdir(parents=True, exist_ok=True)
        partial = staging_dir / f"{blob}.{delivery_id}.part"
        chunks: list[dict] = []
        with open(partial, "xb") as partial_handle:
            for index in range(total_chunks):
                start = index * mib
                if index < completed_chunks:
                    block = bytes([index]) * mib
                    partial_handle.write(block)
                    chunk_hash = blake3.blake3(block).hexdigest()
                else:
                    # Not-yet-received content needs only a valid advertised
                    # digest at negotiation time; its bytes never enter this
                    # interrupted-transfer regression.
                    chunk_hash = blake3.blake3(
                        f"unreceived-chunk-{index}".encode()
                    ).hexdigest()
                chunks.append({
                    "index": index,
                    "start": start,
                    "end": start + mib,
                    "size": mib,
                    "hash": chunk_hash,
                })
            partial_handle.flush()
            os.fsync(partial_handle.fileno())
        assert partial.stat().st_size == 81 * mib

        final_path = inbox_dir() / "ACE.zip"
        sidecar = ResumeSidecar(
            blob_hex=blob,
            peer_fp=peer.fingerprint,
            name="ACE.zip",
            size=total_size,
            out_path=str(partial),
            cdc_chunks=chunks,
            acceptance_granted=True,
            delivery_id=delivery_id,
            delivery_name="ACE.zip",
            delivery_rel_path="",
            delivery_kind="file",
            final_path=str(final_path),
        )
        daemon._resume_registry.register(sidecar)
        transfer_id = _inbound_transfer_id(peer, delivery_id)
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name="ACE.zip",
            size=total_size,
            blob_hash=blob,
            status="paused",
            progress_bytes=completed_size,
            total_bytes=total_size,
            chunks_done=completed_chunks,
            chunks_total=total_chunks,
            metadata={
                "mode": "cdc",
                "path": str(final_path),
                "delivery_id": delivery_id,
                "delivery_name": "ACE.zip",
                "delivery_rel_path": "",
                "delivery_kind": "file",
            },
        )
        original_offer = make_msg(
            "FILE_OFFER",
            peer.short_id,
            id="ace-385-original-offer",
            name="ACE.zip",
            size=total_size,
            blob=blob,
            mode="cdc",
            chunks=chunks,
            delivery_id=delivery_id,
        )
        daemon._persist(
            msg=original_offer,
            direction="in",
            peer_fp=peer.fingerprint,
            peer_short_id=peer.short_id,
        )
        monkeypatch.setattr(
            daemon_module.shutil,
            "disk_usage",
            lambda _path: SimpleNamespace(
                total=20 * 1024**3,
                used=2 * 1024**3,
                free=18 * 1024**3,
            ),
        )
        daemon._incoming_files_require_accept = False
        channel = _RecordingChannel(peer)

        for attempt in (1, 2):
            retry_offer = dict(original_offer)
            retry_offer["id"] = f"ace-385-resume-{attempt}"
            await daemon._on_peer_message(channel, retry_offer)

        wants = [message for message in channel.sent if message.get("t") == "FILE_WANTS"]
        assert len(wants) == 2
        expected_missing = list(range(completed_chunks, total_chunks))
        assert all(message["wants"] == expected_missing for message in wants)
        assert all(message.get("t") != "FILE_COMMIT" for message in channel.sent)

        owner = daemon._incoming_files[blob]
        assert owner.out_path.resolve() == partial.resolve()
        assert owner.final_path.resolve() == final_path.resolve()
        assert owner.cdc_streamed == set(range(completed_chunks))
        assert owner.cdc_done_bytes == completed_size
        assert owner.cdc_missing == set(expected_missing)
        assert partial.stat().st_size == completed_size
        assert not final_path.exists()
        assert len(list(staging_dir.glob("*.part"))) == 1

        row = state.get_transfer(transfer_id)
        assert row.progress_bytes == completed_size
        assert row.chunks_done == completed_chunks
        assert row.chunks_total == total_chunks
        assert len(state.list_transfers(peer_fp=peer.fingerprint)) == 1
        offer_history = [
            message
            for message in state.recent_messages(
                peer_fp=peer.fingerprint,
                limit=20,
            )
            if message.direction == "in" and message.msg_type == "FILE_OFFER"
        ]
        assert len(offer_history) == 1
    finally:
        incoming = daemon._incoming_files.get(blob) if blob else None
        if incoming is not None:
            daemon._abort_incoming_file(blob, incoming)
        state.close()


@pytest.mark.asyncio
async def test_lost_commit_retry_replays_verified_receipt_without_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        inbox = inbox_dir()
        inbox.mkdir(parents=True, exist_ok=True)
        content = b"already durably received"
        blob = blake3.blake3(content).hexdigest()
        committed_path = inbox / f"{blob[:8]}_archive.zip"
        committed_path.write_bytes(content)
        state.upsert_transfer(
            id=_inbound_transfer_id(peer),
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name="archive.zip",
            size=len(content),
            blob_hash=blob,
            status="complete",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata=_complete_commit_metadata(
                peer=peer,
                blob=blob,
                content_path=committed_path,
                size=len(content),
                delivery_name="archive.zip",
            ),
        )
        monkeypatch.setattr(
            daemon_module,
            "hash_path",
            lambda _path: (_ for _ in ()).throw(
                AssertionError("stable commit replay must be O(1)")
            ),
        )
        before = sorted(inbox.iterdir())
        channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="retry-offer-id",
                name="archive.zip",
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=DELIVERY_ID,
            ),
        )

        assert [m.get("t") for m in channel.sent] == ["FILE_COMMIT"]
        assert channel.sent[0]["of"] == "retry-offer-id"
        assert channel.sent[0]["verified_hash"] == blob
        assert daemon._incoming_files == {}
        assert sorted(inbox.iterdir()) == before
        assert state.get_transfer(_inbound_transfer_id(peer)).status == "complete"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_changed_small_commit_rehashes_with_correlated_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        inbox = inbox_dir()
        inbox.mkdir(parents=True, exist_ok=True)
        content = b"bounded replay verification"
        blob = blake3.blake3(content).hexdigest()
        committed_path = inbox / "bounded-rehash.bin"
        committed_path.write_bytes(content)
        metadata = _complete_commit_metadata(
            peer=peer,
            blob=blob,
            content_path=committed_path,
            size=len(content),
        )
        state.upsert_transfer(
            id=_inbound_transfer_id(peer),
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=committed_path.name,
            size=len(content),
            blob_hash=blob,
            status="complete",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata=metadata,
        )
        stat = committed_path.stat()
        os.utime(
            committed_path,
            ns=(stat.st_atime_ns, stat.st_mtime_ns + 10_000_000),
        )
        channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="rehash-offer-id",
                name=committed_path.name,
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=DELIVERY_ID,
            ),
        )

        assert [m.get("t") for m in channel.sent] == [
            "FILE_COMMIT_VERIFYING",
            "FILE_COMMIT",
        ]
        progress, receipt = channel.sent
        assert progress["of"] == "rehash-offer-id"
        assert progress["blob"] == blob
        assert receipt["of"] == "rehash-offer-id"
        assert receipt["ok"] is True
        refreshed = state.get_transfer(_inbound_transfer_id(peer)).metadata[
            "file_commit_evidence"
        ]
        assert refreshed["identity"] != metadata["file_commit_evidence"]["identity"]
    finally:
        state.close()


@pytest.mark.asyncio
async def test_changed_oversize_commit_never_performs_unbounded_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        inbox = inbox_dir()
        inbox.mkdir(parents=True, exist_ok=True)
        content = b"represented as oversized by a lowered test bound"
        blob = blake3.blake3(content).hexdigest()
        committed_path = inbox / "oversize-rehash.bin"
        committed_path.write_bytes(content)
        state.upsert_transfer(
            id=_inbound_transfer_id(peer),
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=committed_path.name,
            size=len(content),
            blob_hash=blob,
            status="complete",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata=_complete_commit_metadata(
                peer=peer,
                blob=blob,
                content_path=committed_path,
                size=len(content),
            ),
        )
        stat = committed_path.stat()
        os.utime(
            committed_path,
            ns=(stat.st_atime_ns, stat.st_mtime_ns + 10_000_000),
        )
        monkeypatch.setattr(
            daemon_module,
            "FILE_COMMIT_REPLAY_REHASH_MAX_BYTES",
            len(content) - 1,
        )
        monkeypatch.setattr(
            daemon_module,
            "hash_path",
            lambda _path: (_ for _ in ()).throw(
                AssertionError("oversize replay must not rehash")
            ),
        )
        channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="oversize-offer-id",
                name=committed_path.name,
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=DELIVERY_ID,
            ),
        )

        assert all(m.get("t") != "FILE_COMMIT" for m in channel.sent)
        assert all(m.get("t") != "FILE_COMMIT_VERIFYING" for m in channel.sent)
        if blob in daemon._incoming_files:
            daemon._abort_incoming_file(blob, daemon._incoming_files[blob])
    finally:
        state.close()


@pytest.mark.asyncio
async def test_expired_replay_window_refreshes_verified_file_and_archive_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        inbox_dir().mkdir(parents=True, exist_ok=True)
        for index, kind in enumerate(("file", "folder_archive"), start=1):
            delivery_id = f"{index + 40:02x}" * 16
            name = f"expired-{index}.zip" if kind == "folder_archive" else "expired.bin"
            rel_path = (
                f"{daemon._FOLDER_ARCHIVE_MAGIC}/{name}"
                if kind == "folder_archive"
                else ""
            )
            content = f"expired-{kind}".encode()
            blob = blake3.blake3(content).hexdigest()
            path = inbox_dir() / f"committed-{index}.bin"
            path.write_bytes(content)
            metadata = _complete_commit_metadata(
                peer=peer,
                blob=blob,
                content_path=path,
                size=len(content),
                delivery_id=delivery_id,
                delivery_name=name,
                delivery_rel_path=rel_path,
                delivery_kind=kind,
            )
            evidence = metadata["file_commit_evidence"]
            evidence["replay_until_ms"] = int(time.time() * 1000) - 1
            if kind == "folder_archive":
                target = inbox_dir() / f"expired-target-{index}"
                target.mkdir()
                manifest_digest = "ab" * 32
                marker_payload = {
                    "schema": 1,
                    "blob": blob,
                    "manifest_digest": manifest_digest,
                    "files_extracted": 1,
                    "bytes_extracted": len(content),
                }
                (target / daemon_module.FOLDER_ARCHIVE_COMMIT_MARKER).write_text(
                    json.dumps(marker_payload),
                    encoding="utf-8",
                )
                evidence["postprocess"] = {
                    "kind": "folder_archive_v1",
                    "complete": True,
                    "target_root": str(target),
                    "commit_marker": daemon_module.FOLDER_ARCHIVE_COMMIT_MARKER,
                    "manifest_digest": manifest_digest,
                    "files_extracted": 1,
                    "bytes_extracted": len(content),
                }
            transfer_id = _inbound_transfer_id(peer, delivery_id)
            state.upsert_transfer(
                id=transfer_id,
                direction="in",
                peer_fp=peer.fingerprint,
                kind="file",
                name=name,
                size=len(content),
                blob_hash=blob,
                status="complete",
                progress_bytes=len(content),
                total_bytes=len(content),
                metadata=metadata,
            )
            channel = _RecordingChannel(peer)
            replay = await daemon._verified_prior_inbound_commit(
                transfer_id=transfer_id,
                peer_fp=peer.fingerprint,
                blob=blob,
                size=len(content),
                channel=channel,
                offer_id=f"expired-offer-{index}",
                mode="stream",
                delivery_id=delivery_id,
                delivery_name=name,
                delivery_rel_path=rel_path,
                delivery_kind=kind,
            )
            assert replay.disposition == "committed"
            refreshed = state.get_transfer(transfer_id)
            assert (
                refreshed.metadata["file_commit_evidence"]["replay_until_ms"]
                > int(time.time() * 1000)
            )
            assert channel.sent == []
    finally:
        state.close()


def test_prune_and_delete_preserve_inbound_commit_dedup_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        inbox_dir().mkdir(parents=True, exist_ok=True)
        content = b"commit evidence must outlive activity history"
        blob = blake3.blake3(content).hexdigest()
        committed = inbox_dir() / "protected-commit.bin"
        committed.write_bytes(content)
        transfer_id = _inbound_transfer_id(peer)
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=committed.name,
            size=len(content),
            blob_hash=blob,
            status="complete",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata=_complete_commit_metadata(
                peer=peer,
                blob=blob,
                content_path=committed,
                size=len(content),
            ),
        )

        assert state.prune_transfers(keep_latest=0) == 0
        assert state.delete_transfer(transfer_id) is False
        assert state.get_transfer(transfer_id) is not None
    finally:
        state.close()


@pytest.mark.asyncio
async def test_prepared_ledger_recovers_crash_after_publish_before_terminal_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"published inode survives terminal-ledger crash"
        blob = blake3.blake3(content).hexdigest()
        delivery_id = "55" * 16
        transfer_id = _inbound_transfer_id(peer, delivery_id)
        final = inbox_dir() / "prepared-recovery.bin"
        staging, handle = daemon_module._open_private_incoming_staging(
            blob=blob,
            delivery_id=delivery_id,
        )
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=final.name,
            size=len(content),
            blob_hash=blob,
            status="active",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata={
                "mode": "stream",
                "path": str(final),
                "delivery_id": delivery_id,
                "delivery_name": final.name,
                "delivery_rel_path": "",
                "delivery_kind": "file",
            },
        )
        closed_handle = open(staging, "rb")
        closed_handle.close()
        incoming = IncomingFile(
            name=final.name,
            size=len(content),
            blob_hex=blob,
            out_path=staging,
            handle=closed_handle,
            hasher=blake3.blake3(),
            final_path=final,
            delivery_id=delivery_id,
            delivery_name=final.name,
            delivery_kind="file",
            peer_fp=peer.fingerprint,
            transfer_id=transfer_id,
            commit_receipt_required=True,
        )
        original_record = daemon._record_incoming_file_commit

        def _crash_before_terminal(*_args, **_kwargs):
            raise OSError("injected terminal-ledger crash")

        monkeypatch.setattr(daemon, "_record_incoming_file_commit", _crash_before_terminal)
        with pytest.raises(OSError, match="terminal-ledger crash"):
            await daemon._commit_received_file(
                incoming,
                chunks_done=1,
                chunks_total=1,
            )
        prepared = state.get_transfer(transfer_id)
        assert prepared.status == "active"
        assert prepared.metadata["file_commit_prepare"]["final_path"] == str(final.resolve())
        assert final.read_bytes() == content
        assert not staging.exists()

        monkeypatch.setattr(daemon, "_record_incoming_file_commit", original_record)
        channel = _RecordingChannel(peer)
        daemon._incoming_files_require_accept = False
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="prepared-retry-offer",
                name=final.name,
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=delivery_id,
            ),
        )

        assert [message["t"] for message in channel.sent] == [
            "FILE_COMMIT_VERIFYING",
            "FILE_COMMIT",
        ]
        assert channel.sent[-1]["ok"] is True
        assert state.get_transfer(transfer_id).status == "complete"
        assert final.read_bytes() == content
    finally:
        state.close()


@pytest.mark.asyncio
async def test_unresolved_prepared_evidence_blocks_fresh_path_and_file_wants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        content = b"prepared evidence with temporarily unavailable bytes"
        blob = blake3.blake3(content).hexdigest()
        delivery_id = "57" * 16
        transfer_id = _inbound_transfer_id(peer, delivery_id)
        final = inbox_dir() / "must-not-duplicate.bin"
        staging = inbox_dir() / daemon_module.INCOMING_STAGING_DIR / "missing.part"
        prepare = {
            "version": 1,
            "peer_fp": peer.fingerprint,
            "delivery_id": delivery_id,
            "delivery_name": final.name,
            "delivery_rel_path": "",
            "delivery_kind": "file",
            "blob": blob,
            "size": len(content),
            "staging_path": str(staging),
            "staging_identity": {
                "size": len(content),
                "mtime_ns": 1,
                "ctime_ns": 1,
                "dev": 1,
                "ino": 1,
            },
            "final_path": str(final),
            "prepared_ms": int(time.time() * 1000),
        }
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=final.name,
            size=len(content),
            blob_hash=blob,
            status="active",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata={
                "mode": "stream",
                "path": str(final),
                "delivery_id": delivery_id,
                "delivery_name": final.name,
                "delivery_rel_path": "",
                "delivery_kind": "file",
                "file_commit_prepare": prepare,
            },
        )
        before = sorted(inbox_dir().rglob("*")) if inbox_dir().exists() else []
        channel = _RecordingChannel(peer)
        daemon._incoming_files_require_accept = False
        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="unresolved-prepare-offer",
                name=final.name,
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=delivery_id,
            ),
        )

        assert [message["t"] for message in channel.sent] == [
            "FILE_COMMIT_VERIFYING",
            "ACK",
        ]
        assert channel.sent[-1]["rejected"] == (
            "delivery_commit_evidence_unresolved:prepared_recovery_pending"
        )
        assert all(message["t"] != "FILE_WANTS" for message in channel.sent)
        assert blob not in daemon._incoming_files
        assert not final.exists() and not staging.exists()
        assert sorted(inbox_dir().rglob("*")) == before
        row = state.get_transfer(transfer_id)
        assert row.status == "active"
        assert row.metadata["file_commit_prepare"] == prepare
    finally:
        state.close()


@pytest.mark.asyncio
async def test_folder_archive_commit_replay_survives_postprocessing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    try:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/readme.txt", b"folder payload")
        content = archive_buffer.getvalue()
        blob = blake3.blake3(content).hexdigest()
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "project.zip"
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=archive_path,
        )
        first_channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            first_channel,
            make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="folder-final-chunk",
                blob=blob,
                seq=0,
                data=base64.b64encode(content).decode("ascii"),
                eof=True,
            ),
        )

        target = inbox_dir() / "project"
        assert not archive_path.exists()
        assert (target / "nested" / "readme.txt").read_bytes() == b"folder payload"
        evidence = state.get_transfer(incoming.transfer_id).metadata[
            "file_commit_evidence"
        ]
        assert evidence["postprocess"]["complete"] is True
        assert evidence["postprocess"]["manifest_digest"]
        assert (target / evidence["postprocess"]["commit_marker"]).is_file()
        before = sorted(str(path.relative_to(inbox_dir())) for path in inbox_dir().rglob("*"))
        retry_channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            retry_channel,
            make_msg(
                "FILE_OFFER",
                peer.short_id,
                id="folder-retry-offer",
                name="project.zip",
                size=len(content),
                blob=blob,
                mode="stream",
                delivery_id=DELIVERY_ID,
                rel_path=f"{daemon._FOLDER_ARCHIVE_MAGIC}/project.zip",
            ),
        )

        assert [m.get("t") for m in retry_channel.sent] == ["FILE_COMMIT"]
        assert retry_channel.sent[0]["of"] == "folder-retry-offer"
        assert retry_channel.sent[0]["ok"] is True
        assert daemon._incoming_files == {}
        after = sorted(str(path.relative_to(inbox_dir())) for path in inbox_dir().rglob("*"))
        assert after == before
    finally:
        state.close()


@pytest.mark.asyncio
async def test_unsafe_folder_archive_is_atomic_and_never_receipted_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    try:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("../escape.txt", b"escape")
            archive.writestr("safe.txt", b"must not partially publish")
        content = archive_buffer.getvalue()
        blob = blake3.blake3(content).hexdigest()
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        incoming = _install_incoming(
            daemon,
            state,
            peer,
            blob=blob,
            size=len(content),
            path=magic / "unsafe.zip",
        )
        channel = _RecordingChannel(peer)

        await daemon._on_peer_message(
            channel,
            make_msg(
                "FILE_CHUNK",
                peer.short_id,
                id="unsafe-folder-final",
                blob=blob,
                seq=0,
                data=base64.b64encode(content).decode("ascii"),
                eof=True,
            ),
        )

        receipt = next(m for m in channel.sent if m.get("t") == "FILE_COMMIT")
        assert receipt["ok"] is False
        assert receipt["reason"] == "unsafe_folder_archive_member"
        assert receipt["retryable"] is False
        assert not (inbox_dir() / "unsafe").exists()
        assert not (inbox_dir() / "escape.txt").exists()
        assert not list(inbox_dir().glob(".one-link-folder-*.staging"))
        assert state.get_transfer(incoming.transfer_id).status == "failed"
    finally:
        state.close()


@pytest.mark.parametrize(
    "members",
    [
        [("Readme.txt", b"a"), ("README.TXT", b"b")],
        [("node", b"file"), ("node/child.txt", b"child")],
    ],
)
def test_folder_archive_rejects_casefold_duplicates_and_type_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    members: list[tuple[str, bytes]],
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "collision.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name, data in members:
                archive.writestr(name, data)

        with pytest.raises(FolderArchiveCommitError):
            daemon._maybe_extract_folder_archive(archive_path)

        assert archive_path.exists()
        assert not (inbox_dir() / "collision").exists()
        assert not list(inbox_dir().glob(".one-link-folder-*.staging"))
    finally:
        state.close()


def test_folder_archive_rejects_symlink_and_bounded_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        symlink_archive = magic / "symlink.zip"
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(symlink_archive, "w") as archive:
            archive.writestr(link, "target")
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_special_file_rejected",
        ):
            daemon._maybe_extract_folder_archive(symlink_archive)

        bounded_archive = magic / "bounded.zip"
        with zipfile.ZipFile(bounded_archive, "w") as archive:
            archive.writestr("payload.bin", b"12345")
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_MAX_UNCOMPRESSED_BYTES",
            4,
        )
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_uncompressed_limit",
        ):
            daemon._maybe_extract_folder_archive(bounded_archive)

        entry_archive = magic / "entry-limit.zip"
        with zipfile.ZipFile(entry_archive, "w") as archive:
            archive.writestr("one.txt", b"1")
            archive.writestr("two.txt", b"2")
        monkeypatch.setattr(daemon_module, "FOLDER_ARCHIVE_MAX_ENTRIES", 1)
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_too_many_entries",
        ):
            daemon._maybe_extract_folder_archive(entry_archive)
        ratio_archive = magic / "ratio-limit.zip"
        with zipfile.ZipFile(
            ratio_archive,
            "w",
            zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr("zeros.bin", b"\x00" * (65 * 1024 * 1024))
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_MAX_ENTRIES",
            4_096,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_MAX_UNCOMPRESSED_BYTES",
            16 * 1024 * 1024 * 1024,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_MAX_EXPANSION_RATIO",
            2,
        )
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_expansion_ratio_limit",
        ):
            daemon._maybe_extract_folder_archive(ratio_archive)
        assert not (inbox_dir() / "symlink").exists()
        assert not (inbox_dir() / "bounded").exists()
    finally:
        state.close()


def test_folder_archive_expansion_cap_never_exceeds_admission_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    try:
        daemon._transfer_admission_policy = TransferAdmissionPolicy(
            max_declared_bytes=4,
            min_free_reserve_bytes=0,
            free_reserve_ratio=0.0,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_MAX_UNCOMPRESSED_BYTES",
            16 * 1024 * 1024 * 1024,
        )
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "admission-cap.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.bin", b"12345")

        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_uncompressed_limit",
        ):
            daemon._maybe_extract_folder_archive(archive_path)
        assert not (inbox_dir() / "admission-cap").exists()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_folder_archive_commit_runs_off_loop_with_bounded_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    ticker: asyncio.Task | None = None
    try:
        assert daemon_module.FOLDER_ARCHIVE_MAX_ENTRIES > 0
        assert daemon_module.FOLDER_ARCHIVE_MAX_UNCOMPRESSED_BYTES > 0
        assert daemon_module.FOLDER_ARCHIVE_MAX_EXPANSION_RATIO > 0
        assert daemon_module.FOLDER_ARCHIVE_MAX_ENTRIES <= 4_096
        assert (
            daemon_module.FOLDER_ARCHIVE_MAX_UNCOMPRESSED_BYTES
            <= 16 * 1024 * 1024 * 1024
        )
        assert daemon_module.FOLDER_ARCHIVE_MAX_EXPANSION_RATIO <= 200
        assert daemon_module.FOLDER_ARCHIVE_COMMIT_MAX_DEADLINE_S <= 30 * 60
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/payload.txt", b"off-loop archive payload")
        content = buffer.getvalue()
        blob = blake3.blake3(content).hexdigest()
        delivery_id = "66" * 16
        transfer_id = _inbound_transfer_id(peer, delivery_id)
        staging, writable = daemon_module._open_private_incoming_staging(
            blob=blob,
            delivery_id=delivery_id,
        )
        writable.write(content)
        writable.flush()
        os.fsync(writable.fileno())
        writable.close()
        closed_handle = open(staging, "rb")
        closed_handle.close()
        final = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC / "offload.zip"
        channel = _RecordingChannel(peer)
        incoming = IncomingFile(
            name=final.name,
            size=len(content),
            blob_hex=blob,
            out_path=staging,
            handle=closed_handle,
            hasher=blake3.blake3(),
            final_path=final,
            delivery_id=delivery_id,
            delivery_name=final.name,
            delivery_rel_path=f"{daemon._FOLDER_ARCHIVE_MAGIC}/{final.name}",
            delivery_kind="folder_archive",
            peer_fp=peer.fingerprint,
            transfer_id=transfer_id,
            commit_receipt_required=True,
            commit_waiters={"archive-offer": channel},
        )
        state.upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer.fingerprint,
            kind="file",
            name=final.name,
            size=len(content),
            blob_hash=blob,
            status="active",
            progress_bytes=len(content),
            total_bytes=len(content),
            metadata={
                "mode": "stream",
                "path": str(final),
                "delivery_id": delivery_id,
                "delivery_name": final.name,
                "delivery_rel_path": incoming.delivery_rel_path,
                "delivery_kind": "folder_archive",
            },
        )
        original_extract = daemon._maybe_extract_folder_archive

        def _slow_extract(*args, **kwargs):
            time.sleep(0.08)
            return original_extract(*args, **kwargs)

        monkeypatch.setattr(daemon, "_maybe_extract_folder_archive", _slow_extract)
        monkeypatch.setattr(daemon_module, "FILE_COMMIT_PROGRESS_INTERVAL_S", 0.01)
        ticks = 0
        stop = False

        async def _ticker() -> None:
            nonlocal ticks
            while not stop:
                ticks += 1
                await asyncio.sleep(0.005)

        ticker = asyncio.create_task(_ticker())
        event = await daemon._commit_received_file(
            incoming,
            chunks_done=1,
            chunks_total=1,
        )
        stop = True
        await ticker
        ticker = None

        assert ticks >= 5
        assert event is not None
        assert (Path(event["target_root"]) / "nested" / "payload.txt").read_bytes() == (
            b"off-loop archive payload"
        )
        progress = [
            message
            for message in channel.sent
            if message.get("t") == "FILE_COMMIT_VERIFYING"
        ]
        assert progress
        assert [message["progress_seq"] for message in progress] == list(
            range(1, len(progress) + 1)
        )
        assert not staging.exists()
        assert state.get_transfer(transfer_id).status == "complete"
    finally:
        if ticker is not None:
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
        state.close()


@pytest.mark.asyncio
async def test_folder_archive_worker_deadline_cancels_cooperatively(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    cancelled = threading.Event()
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "slow.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("payload.txt", b"slow")
        blob = blake3.blake3(archive_path.read_bytes()).hexdigest()

        def _cooperative_slow(*_args, **kwargs):
            stop = kwargs["cancel_event"]
            while not stop.wait(0.002):
                pass
            cancelled.set()
            raise FolderArchiveCommitError(
                "folder_archive_commit_cancelled",
                retryable=True,
            )

        monkeypatch.setattr(
            daemon,
            "_maybe_extract_folder_archive",
            _cooperative_slow,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_COMMIT_MIN_DEADLINE_S",
            0.02,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_COMMIT_MAX_DEADLINE_S",
            0.02,
        )
        monkeypatch.setattr(
            daemon_module,
            "FOLDER_ARCHIVE_CANCEL_GRACE_S",
            0.5,
        )
        started = time.monotonic()
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_commit_deadline",
        ) as failed:
            await daemon._run_folder_archive_commit(
                archive_path,
                expected_blob=blob,
                defer_source_cleanup=True,
                intended_path=archive_path,
            )

        assert time.monotonic() - started < 0.75
        assert failed.value.retryable is True
        assert cancelled.wait(timeout=0.5)
        assert archive_path.exists()
        assert not (inbox_dir() / "slow").exists()
    finally:
        state.close()


def test_folder_archive_rejects_volume_below_production_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "low-space.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("new.txt", b"must-not-publish")
        before = archive_path.read_bytes()
        gib = 1024**3
        monkeypatch.setattr(
            daemon_module.shutil, "disk_usage",
            lambda _path: SimpleNamespace(
                total=2048 * gib, used=2047 * gib, free=gib,
            ),
        )
        with pytest.raises(
            FolderArchiveCommitError, match="insufficient_space_for_folder_archive",
        ):
            daemon._maybe_extract_folder_archive(archive_path)
        assert archive_path.read_bytes() == before
        assert not (inbox_dir() / "low-space").exists()
    finally:
        state.close()


def test_folder_archive_publish_never_overwrites_existing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    try:
        existing = inbox_dir() / "project"
        existing.mkdir(parents=True, exist_ok=True)
        sentinel = existing / "keep.txt"
        sentinel.write_bytes(b"existing-user-content")
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "project.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("new.txt", b"new-content")

        event = daemon._maybe_extract_folder_archive(archive_path)

        published = Path(event["target_root"])
        assert published != existing
        assert published.name == "project (1)"
        assert sentinel.read_bytes() == b"existing-user-content"
        assert (published / "new.txt").read_bytes() == b"new-content"
        assert (published / daemon_module.FOLDER_ARCHIVE_COMMIT_MARKER).is_file()
    finally:
        state.close()


def test_folder_archive_publish_race_preserves_concurrent_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "raced.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("new.txt", b"incoming-content")

        original_publish = daemon_module._publish_directory_noreplace
        raced_target: Path | None = None

        def _race(source: Path, destination: Path) -> None:
            nonlocal raced_target
            raced_target = Path(destination)
            raced_target.mkdir()
            (raced_target / "sentinel.txt").write_bytes(b"concurrent-content")
            original_publish(source, destination)

        monkeypatch.setattr(
            daemon_module,
            "_publish_directory_noreplace",
            _race,
        )
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_publish_failed",
        ) as failed:
            daemon._maybe_extract_folder_archive(archive_path)

        assert failed.value.retryable is True
        assert raced_target is not None
        assert (raced_target / "sentinel.txt").read_bytes() == b"concurrent-content"
        assert not (raced_target / "new.txt").exists()
        assert archive_path.exists()
        assert not list(inbox_dir().glob(".one-link-folder-*.staging"))
    finally:
        state.close()


def test_folder_archive_path_swap_cannot_change_descriptor_bound_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A→B→A pathname swap cannot make B inherit A's commit proof.

    The test deliberately disables ZIP's CRC comparison to model an attacker
    who forges that non-cryptographic checksum. Both ZIPs have the same member
    layout and stored length. The pathname names B only while extraction is in
    progress, then names A again before final BLAKE3 attestation. Reopening by
    path would publish ``evil`` under A's hash; one bound descriptor publishes
    only A's bytes.
    """

    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "swap-proof.zip"
        attacker_path = magic / ".attacker.zip"
        safe_backup = magic / ".safe-open-inode.zip"
        safe_payload = b"safe"
        evil_payload = b"evil"
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.writestr("payload.txt", safe_payload)
        with zipfile.ZipFile(
            attacker_path,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.writestr("payload.txt", evil_payload)
        expected_blob = blake3.blake3(archive_path.read_bytes()).hexdigest()

        real_zip_file = zipfile.ZipFile
        zip_opens = 0
        swapped = False
        swap_blocked = False
        restored = False

        def _swap_before_second_zip_open(file, *args, **kwargs):
            nonlocal zip_opens, swapped, swap_blocked
            zip_opens += 1
            if zip_opens == 2:
                try:
                    os.replace(archive_path, safe_backup)
                    os.replace(attacker_path, archive_path)
                    swapped = True
                except PermissionError:
                    # Windows' descriptor denies rename/delete sharing. That
                    # kernel-enforced lock is an even stronger form of the
                    # same invariant; POSIX exercises the full A→B→A race.
                    swap_blocked = True
            return real_zip_file(file, *args, **kwargs)

        def _forged_crc_update(self, newdata: bytes) -> None:
            nonlocal restored
            if swapped and not restored:
                # The active ZipExtFile keeps reading its already-open inode.
                # Restore A at the pathname before final attestation.
                os.replace(archive_path, attacker_path)
                os.replace(safe_backup, archive_path)
                restored = True
            if self._running_crc is not None:
                self._running_crc = zipfile.crc32(
                    newdata,
                    self._running_crc,
                )

        monkeypatch.setattr(zipfile, "ZipFile", _swap_before_second_zip_open)
        monkeypatch.setattr(zipfile.ZipExtFile, "_update_crc", _forged_crc_update)

        event = daemon._maybe_extract_folder_archive(
            archive_path,
            expected_blob=expected_blob,
            defer_source_cleanup=True,
        )

        assert zip_opens == 2
        assert swap_blocked or restored
        published = Path(event["target_root"])
        assert (published / "payload.txt").read_bytes() == safe_payload
        assert blake3.blake3(archive_path.read_bytes()).hexdigest() == expected_blob
        assert attacker_path.is_file()
    finally:
        state.close()


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "os.pwrite is POSIX-only, and Windows' descriptor sharing rules deny a "
        "concurrent write to the open source at all -- a kernel-enforced form "
        "of the same invariant, as the A->B->A swap test documents."
    ),
)
def test_folder_archive_in_place_source_rewrite_is_still_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropping ctime from the identity tuple must not cost real detection.

    ctime was removed as a reject condition because POSIX rename(2) bumps it
    on a source whose content never changed (see the A->B->A swap test). This
    pins that the guard still catches the thing ctime was imagined to catch: a
    genuine in-place rewrite of the source, at the SAME byte length so the
    size check cannot be what fires. Detection rests on the full re-hash
    through the bound descriptor plus dev/ino/size/mtime_ns.
    """

    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "rewrite-proof.zip"
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.writestr("payload.txt", b"safe")
        expected_blob = blake3.blake3(archive_path.read_bytes()).hexdigest()
        original = archive_path.read_bytes()

        real_zip_file = zipfile.ZipFile
        zip_opens = 0
        rewritten = False

        def _rewrite_after_second_open(file, *args, **kwargs):
            nonlocal zip_opens, rewritten
            zip_opens += 1
            handle = real_zip_file(file, *args, **kwargs)
            if zip_opens == 2 and not rewritten:
                # Rewrite in place AFTER the directory has been parsed, at the
                # same length, flipping a trailing byte the member reads never
                # touch. Extraction therefore succeeds on content it already
                # committed to, and only the source attestation can catch it.
                mutated = bytearray(original)
                mutated[-1] ^= 0xFF
                fd = os.open(archive_path, os.O_WRONLY)
                try:
                    os.pwrite(fd, bytes(mutated), 0)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                assert archive_path.stat().st_size == len(original)
                rewritten = True
            return handle

        monkeypatch.setattr(zipfile, "ZipFile", _rewrite_after_second_open)

        # Assert the mutation actually happened BEFORE asserting the rejection.
        # A hook that silently never fires would otherwise read as whichever
        # outcome the run order produced, proving nothing either way.
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_hash_changed|folder_archive_source_changed",
        ) as rejection:
            daemon._maybe_extract_folder_archive(
                archive_path,
                expected_blob=expected_blob,
                defer_source_cleanup=True,
            )
        assert rewritten, "the rewrite hook never fired -- nothing was proven"
        assert archive_path.read_bytes() != original
        assert str(rejection.value)
        assert not (inbox_dir() / "rewrite-proof").exists()
    finally:
        state.close()


def test_folder_archive_io_failure_leaves_no_partial_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, state, _peer = _receiver(tmp_path, monkeypatch)
    _archive_headroom_fixture(monkeypatch)
    try:
        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        archive_path = magic / "io-failure.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("file.txt", b"content")

        monkeypatch.setattr(
            daemon_module.os,
            "fsync",
            lambda _fd: (_ for _ in ()).throw(OSError("injected fsync failure")),
        )
        with pytest.raises(
            FolderArchiveCommitError,
            match="folder_archive_publish_failed",
        ):
            daemon._maybe_extract_folder_archive(archive_path)

        assert archive_path.exists()
        assert not (inbox_dir() / "io-failure").exists()
        assert not list(inbox_dir().glob(".one-link-folder-*.staging"))
    finally:
        state.close()


@pytest.mark.asyncio
async def test_folder_extractions_atomically_reserve_expanded_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second archive cannot spend the first archive's live promise.

    Both helpers observe the same synthetic 1000-byte free-space snapshot.
    The first is paused after atomically growing its reservation to 600 bytes;
    the second must therefore be rejected at 1200 aggregate bytes even though
    its independent raw disk check would pass at 600 bytes.
    """

    daemon, state, peer = _receiver(tmp_path, monkeypatch)
    release_first = threading.Event()
    first_reserved = threading.Event()
    first_task: asyncio.Task | None = None
    try:
        policy = TransferAdmissionPolicy(
            max_declared_bytes=10_000,
            min_free_reserve_bytes=0,
            free_reserve_ratio=0.0,
        )
        daemon._transfer_admission_policy = policy
        monkeypatch.setattr(
            daemon_module.shutil,
            "disk_usage",
            lambda _path: SimpleNamespace(total=1000, used=0, free=1000),
        )

        magic = inbox_dir() / daemon._FOLDER_ARCHIVE_MAGIC
        magic.mkdir(parents=True, exist_ok=True)
        incoming_files: list[IncomingFile] = []
        for index, byte in enumerate((b"A", b"B"), start=1):
            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(
                archive_buffer,
                "w",
                zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr("payload.bin", byte * 600)
            archive_bytes = archive_buffer.getvalue()
            blob = blake3.blake3(archive_bytes).hexdigest()
            incoming = _install_incoming(
                daemon,
                state,
                peer,
                blob=blob,
                size=len(archive_bytes),
                path=magic / f"archive-{index}.zip",
            )
            incoming.reservation_id = f"archive-reservation-{index}"
            incoming.handle.write(archive_bytes)
            incoming.handle.flush()
            os.fsync(incoming.handle.fileno())
            incoming.handle.close()
            incoming_files.append(incoming)

        ledger = daemon._transfer_reservation_ledger()
        for incoming in incoming_files:
            admitted = ledger.reserve(
                reservation_id=incoming.reservation_id,
                name=incoming.name,
                size=incoming.size,
                peer_fp=peer.fingerprint,
                policy=policy,
            )
            assert admitted.ok is True
            assert ledger.consume(
                incoming.reservation_id,
                incoming.size,
            ) == 0

        original_consume = daemon._consume_inbound_reservation

        def _block_first_consumption(
            incoming: IncomingFile,
            committed_bytes: int,
            *,
            cache: bool = False,
        ) -> None:
            if incoming is incoming_files[0] and not first_reserved.is_set():
                first_reserved.set()
                if not release_first.wait(timeout=5):
                    raise TimeoutError("first extraction was not released")
            original_consume(incoming, committed_bytes, cache=cache)

        monkeypatch.setattr(
            daemon,
            "_consume_inbound_reservation",
            _block_first_consumption,
        )
        first = incoming_files[0]
        first_task = asyncio.create_task(asyncio.to_thread(
            daemon._maybe_extract_folder_archive,
            first.out_path,
            expected_blob=first.blob_hex,
            defer_source_cleanup=True,
            incoming=first,
        ))
        assert await asyncio.to_thread(first_reserved.wait, 5)
        assert ledger.get(first.reservation_id).remaining_bytes == 600

        second = incoming_files[1]
        with pytest.raises(
            FolderArchiveCommitError,
            match="insufficient_space_for_folder_archive",
        ):
            await asyncio.to_thread(
                daemon._maybe_extract_folder_archive,
                second.out_path,
                expected_blob=second.blob_hex,
                defer_source_cleanup=True,
                incoming=second,
            )
        # The second raw snapshot was still 1000 free bytes; rejection came
        # from the ledger's outstanding-first-promise sum.
        assert daemon_module.shutil.disk_usage(inbox_dir()).free == 1000
        assert ledger.get(second.reservation_id).remaining_bytes == 0
        assert not (inbox_dir() / "archive-2").exists()

        release_first.set()
        event = await first_task
        assert Path(event["target_root"]).is_dir()
        assert ledger.get(first.reservation_id).remaining_bytes == 0
    finally:
        release_first.set()
        if first_task is not None and not first_task.done():
            try:
                await asyncio.wait_for(first_task, timeout=5)
            except Exception:
                pass
        state.close()


class _SenderChannel:
    def __init__(
        self,
        peer: Identity,
        *,
        commit_capable: bool,
        commit_mutation: dict | None = None,
    ) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        features = [CHAT, FILES]
        if commit_capable:
            features.append(FILE_COMMIT_RECEIPT_V1)
        self.peer_caps = {
            "protocol": "OL1.2",
            "features": features,
            "from": peer.short_id,
            "app_version": "0.21.0",
        }
        self.sent: list[dict] = []
        self._replied: set[str] = set()
        self._committed_offers: set[str] = set()
        self.commit_capable = commit_capable
        self.commit_mutation = dict(commit_mutation or {})

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        offer = next(
            m
            for m in reversed(self.sent)
            if m.get("t") == "FILE_OFFER"
            and str(m.get("id") or "") not in self._committed_offers
        )
        for frame in self.sent:
            frame_id = str(frame.get("id") or "")
            if not frame_id or frame_id in self._replied:
                continue
            if frame.get("t") in {"FILE_OFFER", "FILE_CHUNK"}:
                self._replied.add(frame_id)
                return encode_msg(make_msg(
                    "ACK",
                    self.peer_short_id,
                    of=frame_id,
                ))
        if self.commit_capable:
            receipt = _commit(
                offer_id=str(offer["id"]),
                blob=str(offer["blob"]),
                size=int(offer["size"]),
                mode="stream",
                delivery_id=str(offer["delivery_id"]),
                delivery_name=str(offer["name"]),
                delivery_rel_path=str(offer.get("rel_path") or ""),
                delivery_kind=(
                    "folder_archive"
                    if str(offer.get("rel_path") or "").startswith(
                        "__one_link_folder__/"
                    )
                    else "file"
                ),
            )
            receipt.update(self.commit_mutation)
            receipt.setdefault("id", "commit-receipt-id")
            receipt.setdefault("ts", int(time.time() * 1000))
            receipt.setdefault("from", self.peer_short_id)
            self._committed_offers.add(str(offer["id"]))
            return encode_msg(receipt)
        raise AssertionError("legacy sender must not wait for FILE_COMMIT")


class _CommitReplaySenderChannel(_SenderChannel):
    def __init__(self, peer: Identity, *, progress_frames: int) -> None:
        super().__init__(peer, commit_capable=True)
        self.progress_frames = progress_frames
        self.recv_count = 0

    async def recv(self) -> bytes:
        offer = next(m for m in self.sent if m.get("t") == "FILE_OFFER")
        self.recv_count += 1
        if self.recv_count <= self.progress_frames:
            return encode_msg(make_msg(
                "FILE_COMMIT_VERIFYING",
                self.peer_short_id,
                receipt_version=1,
                of=str(offer["id"]),
                blob=str(offer["blob"]),
                size=int(offer["size"]),
                mode="stream",
                delivery_id=str(offer["delivery_id"]),
                delivery_name=str(offer["name"]),
                delivery_rel_path=str(offer.get("rel_path") or ""),
                delivery_kind="file",
                stage="bounded_rehash",
                progress_seq=0,
                max_wait_s=300,
            ))
        receipt = _commit(
            offer_id=str(offer["id"]),
            blob=str(offer["blob"]),
            size=int(offer["size"]),
            mode="stream",
            delivery_id=str(offer["delivery_id"]),
            delivery_name=str(offer["name"]),
            delivery_rel_path=str(offer.get("rel_path") or ""),
            delivery_kind="file",
        )
        receipt.update({
            "id": "replayed-commit",
            "ts": int(time.time() * 1000),
            "from": self.peer_short_id,
        })
        return encode_msg(receipt)


class _DropAfterOfferChannel(_SenderChannel):
    """Record the remotely-visible offer, then lose the transport outcome."""

    async def send(self, payload: bytes) -> None:
        message = decode_msg(payload)
        self.sent.append(message)
        if message.get("t") == "FILE_OFFER":
            raise ConnectionError("injected connection loss after offer write")


async def _send_with_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: _SenderChannel,
    peer_identity: Identity,
    *,
    capture_error: bool = False,
) -> tuple[dict, State]:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "sender-state.db")
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    peer = Peer(
        short_id=peer_identity.short_id,
        hostname="receiver",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=peer_identity.public_bytes.hex(),
    )
    daemon._outbound_sessions[peer_identity.fingerprint] = OutboundSession(
        peer_fp=peer_identity.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    source = tmp_path / "send.bin"
    source.write_bytes(b"commit-confirmed payload")
    try:
        result = await daemon.send_file(peer, source)
    except Exception as exc:
        if not capture_error:
            state.close()
            raise
        result = {"error": exc}
    return result, state


def _sender_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: _SenderChannel,
    peer_identity: Identity,
) -> tuple[Daemon, State, Peer, Path]:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "sender-runtime-state.db")
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    monkeypatch.setattr(daemon, "_schedule_resume_paused", lambda _peer_fp: None)
    peer = Peer(
        short_id=peer_identity.short_id,
        hostname="receiver",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=peer_identity.public_bytes.hex(),
    )
    _install_sender_session(daemon, peer_identity, peer, channel)
    source = tmp_path / "stable-delivery.bin"
    source.write_bytes(b"stable logical delivery")
    return daemon, state, peer, source


def _install_sender_session(
    daemon: Daemon,
    peer_identity: Identity,
    peer: Peer,
    channel: _SenderChannel,
) -> None:
    daemon._outbound_sessions[peer_identity.fingerprint] = OutboundSession(
        peer_fp=peer_identity.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )


@pytest.mark.asyncio
async def test_sender_marks_complete_only_after_exact_commit_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _identity()
    channel = _SenderChannel(peer, commit_capable=True)
    result, state = await _send_with_channel(tmp_path, monkeypatch, channel, peer)
    try:
        row = state.get_transfer(result["transfer_id"])
        assert result["confirmed"] is True
        assert row.status == "complete"
        assert row.metadata["commit_confirmed"] is True
        assert row.metadata["commit_receipt"]["verified_hash"] == result["blob"]
    finally:
        state.close()


@pytest.mark.asyncio
async def test_sender_delivery_id_is_stable_for_retry_and_unique_for_new_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    first_channel = _SenderChannel(
        peer_identity,
        commit_capable=True,
        commit_mutation={
            "ok": False,
            "durable": False,
            "committed_bytes": 0,
            "verified_hash": "",
            "reason": "retry_this_delivery",
            "retryable": True,
        },
    )
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        first_channel,
        peer_identity,
    )
    try:
        with pytest.raises(TransferPausedError) as paused:
            await daemon.send_file(peer, source)
        first_offer = next(
            message for message in first_channel.sent if message.get("t") == "FILE_OFFER"
        )

        retry_channel = _SenderChannel(peer_identity, commit_capable=True)
        _install_sender_session(daemon, peer_identity, peer, retry_channel)
        retried = await daemon.send_file(
            peer,
            source,
            transfer_id=paused.value.transfer_id,
        )
        retry_offer = next(
            message for message in retry_channel.sent if message.get("t") == "FILE_OFFER"
        )
        assert retried["confirmed"] is True
        assert retry_offer["delivery_id"] == first_offer["delivery_id"]

        new_channel = _SenderChannel(peer_identity, commit_capable=True)
        _install_sender_session(daemon, peer_identity, peer, new_channel)
        new_send = await daemon.send_file(peer, source)
        new_offer = next(
            message for message in new_channel.sent if message.get("t") == "FILE_OFFER"
        )
        assert new_send["transfer_id"] != retried["transfer_id"]
        assert new_offer["delivery_id"] != retry_offer["delivery_id"]
    finally:
        state.close()


@pytest.mark.asyncio
async def test_sender_extra_metadata_cannot_override_delivery_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        with pytest.raises(
            ValueError,
            match="cannot override delivery accounting fields",
        ):
            await daemon.send_file(
                peer,
                source,
                extra_metadata={
                    "folder_send_group": "folder:safe-group",
                    "delivery_id": "attacker-controlled",
                    "commit_confirmed": True,
                    "path": str(tmp_path / "wrong-source.bin"),
                },
            )
        assert channel.sent == []
        assert state.list_transfers(limit=20) == []

        result = await daemon.send_file(
            peer,
            source,
            extra_metadata={"folder_send_group": "folder:safe-group"},
        )
        offer = next(m for m in channel.sent if m.get("t") == "FILE_OFFER")
        row = state.get_transfer(result["transfer_id"])

        assert len(offer["delivery_id"]) == 32
        assert row.metadata["delivery_id"] == offer["delivery_id"]
        assert row.metadata["delivery_name"] == source.name
        assert row.metadata["delivery_rel_path"] == ""
        assert row.metadata["delivery_kind"] == "file"
        assert row.metadata["path"] == str(source)
        assert row.metadata["mode"] in {"stream", "cdc"}
        assert row.metadata["folder_send_group"] == "folder:safe-group"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_concurrent_same_transfer_id_emits_only_one_legacy_offer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Session serialization must also recheck terminal delivery state."""
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=False)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        blob = blake3.blake3(source.read_bytes()).hexdigest()
        transfer_id = f"out:{blob}:123456789abc"
        queued = daemon.queue_file_transfer(
            peer_fp=peer_identity.fingerprint,
            path=source,
            transfer_id=transfer_id,
            schedule_resume=False,
        )
        stable_delivery_id = queued.metadata["delivery_id"]

        first, second = await asyncio.gather(
            daemon.send_file(peer, source, transfer_id=transfer_id),
            daemon.send_file(peer, source, transfer_id=transfer_id),
        )

        offers = [m for m in channel.sent if m.get("t") == "FILE_OFFER"]
        assert len(offers) == 1
        assert offers[0]["delivery_id"] == stable_delivery_id
        assert {first["transfer_id"], second["transfer_id"]} == {transfer_id}
        assert sum(bool(result.get("duplicate_offer_refused")) for result in (first, second)) == 1
        assert all(result["confirmed"] is False for result in (first, second))
        assert state.get_transfer(transfer_id).metadata["delivery_state"] == "sent_unconfirmed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_remote_receipt_local_accounting_failure_is_durable_fail_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        original_durable_update = state.update_transfer_durable

        def _fail_terminal_durable_update(transfer_id: str, **fields):
            if fields.get("status") == "complete":
                raise OSError("injected durable terminal accounting failure")
            return original_durable_update(transfer_id, **fields)

        monkeypatch.setattr(
            state,
            "update_transfer_durable",
            _fail_terminal_durable_update,
        )
        with pytest.raises(SenderCommitAccountingError):
            await daemon.send_file(peer, source)
        offer = next(message for message in channel.sent if message.get("t") == "FILE_OFFER")
        row = next(
            record
            for record in state.list_transfers(limit=20)
            if record.direction == "out" and record.blob_hash == offer["blob"]
        )
        marker = daemon._remote_commit_failstop_path(row.id)
        payload = json.loads(marker.read_text(encoding="utf-8"))
        assert payload["phase"] == "remote_committed"
        assert payload["receipt"]["delivery_id"] == offer["delivery_id"]
        assert daemon._remote_commit_is_failstopped(row.id) is True
        assert row.status == "failed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_legacy_peer_is_sent_unconfirmed_never_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _identity()
    channel = _SenderChannel(peer, commit_capable=False)
    result, state = await _send_with_channel(tmp_path, monkeypatch, channel, peer)
    try:
        row = state.get_transfer(result["transfer_id"])
        assert result["confirmed"] is False
        assert result["status"] == "sent_unconfirmed"
        assert row.status == "failed"
        assert row.metadata["delivery_state"] == "sent_unconfirmed"
        assert row.metadata["transient"] is False
        probe = Daemon(_identity())
        probe.state = state
        assert not probe._remote_commit_failstop_path(result["transfer_id"]).exists()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_legacy_terminal_accounting_crash_failstops_restart_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=False)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        original_update = daemon._update_transfer

        def _fail_legacy_terminal(transfer_id: str, **kwargs):
            metadata = kwargs.get("metadata") or {}
            if metadata.get("delivery_state") == "sent_unconfirmed":
                return None
            return original_update(transfer_id, **kwargs)

        monkeypatch.setattr(daemon, "_update_transfer", _fail_legacy_terminal)
        with pytest.raises(SenderCommitAccountingError):
            await daemon.send_file(peer, source)

        offer = next(m for m in channel.sent if m.get("t") == "FILE_OFFER")
        row = next(
            item
            for item in state.list_transfers(limit=20)
            if item.direction == "out" and item.blob_hash == offer["blob"]
        )
        marker = daemon._remote_commit_failstop_path(row.id)
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        assert marker_payload["phase"] == "outcome_unknown"
        assert marker_payload["delivery"]["receipt_capable"] is False
        assert daemon._remote_commit_is_failstopped(row.id) is True
        assert row.metadata["offer_boundary_committed"] is True
        assert row.metadata["receipt_capable"] is False
        assert row.metadata["offer_boundary_contract"]["delivery_id"] == (
            offer["delivery_id"]
        )

        # The SQLite boundary, not the redundant JSON sidecar, is the primary
        # crash truth. Deleting the sidecar must never turn an ACK-only legacy
        # delivery into permission for a duplicate offer.
        marker.unlink()
        assert daemon._remote_commit_is_failstopped(row.id) is True

        # The transport API itself must fail closed too.  Scheduler guards
        # alone do not protect a manual HTTP/control-plane caller that reuses
        # this durable transfer id.
        direct_retry = Daemon(daemon.me)
        direct_retry.state = state

        async def _must_not_dial_direct(*_args, **_kwargs):
            raise AssertionError("legacy ambiguous delivery dialed directly")

        monkeypatch.setattr(
            direct_retry,
            "_get_outbound_session",
            _must_not_dial_direct,
        )
        with pytest.raises(SenderCommitAccountingError, match="duplicate offer refused"):
            await direct_retry.send_file(
                peer,
                source,
                transfer_id=row.id,
            )

        # Corrupt/unparseable sidecar evidence also fails closed. It cannot
        # override or weaken the exact FULL-synced ledger contract.
        marker.write_text("{not-json", encoding="utf-8")
        assert daemon._remote_commit_is_failstopped(row.id) is True

        state.update_transfer(row.id, status="paused")
        restarted = Daemon(daemon.me)
        restarted.state = state

        async def _resolve(_peer_fp: str):
            return peer

        async def _must_not_send(*_args, **_kwargs):
            raise AssertionError("legacy ambiguous delivery was retried")

        monkeypatch.setattr(restarted, "resolve_for_send", _resolve)
        monkeypatch.setattr(restarted, "send_file", _must_not_send)
        assert restarted._schedule_due_transfer_retries() == 0
        resumed = await restarted.resume_paused_transfers_for(
            peer_identity.fingerprint,
            force=True,
        )
        assert resumed["resumed"] == 0
        assert resumed["errors"] == 0
        assert marker.exists()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_modern_offer_boundary_allows_only_exact_retry_without_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _DropAfterOfferChannel(peer_identity, commit_capable=True)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        with pytest.raises(TransferPausedError):
            await daemon.send_file(peer, source)

        offer = next(m for m in channel.sent if m.get("t") == "FILE_OFFER")
        row = next(
            item
            for item in state.list_transfers(limit=20)
            if item.direction == "out" and item.blob_hash == offer["blob"]
        )
        assert row.metadata["offer_boundary_committed"] is True
        assert row.metadata["receipt_capable"] is True
        contract = dict(row.metadata["offer_boundary_contract"])
        assert contract["delivery_id"] == offer["delivery_id"]
        assert contract["mode"] == offer["mode"]

        marker = daemon._remote_commit_failstop_path(row.id)
        assert marker.is_file()
        marker.unlink()
        assert daemon._remote_commit_is_failstopped(row.id) is False

        # Any drift in the durable binding revokes retry permission even for a
        # receipt-capable peer with a stable nonce.
        state.update_transfer(
            row.id,
            metadata={
                **row.metadata,
                "offer_boundary_contract": {
                    **contract,
                    "blob": "00" * 32,
                },
            },
        )
        assert daemon._remote_commit_is_failstopped(row.id) is True
    finally:
        state.close()


@pytest.mark.asyncio
async def test_send_file_refuses_before_dial_when_intent_ledger_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        monkeypatch.setattr(
            state,
            "upsert_transfer",
            lambda **_kwargs: (_ for _ in ()).throw(OSError("database offline")),
        )

        async def _must_not_dial(*_args, **_kwargs):
            raise AssertionError("dialed without a durable transfer intent")

        monkeypatch.setattr(daemon, "_get_outbound_session", _must_not_dial)
        with pytest.raises(TransferLedgerUnavailableError):
            await daemon.send_file(peer, source)
        assert channel.sent == []
        assert state.list_transfers(limit=20) == []
    finally:
        state.close()


@pytest.mark.asyncio
async def test_send_file_refuses_offer_when_required_ledger_advance_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        original_update = state.update_transfer

        def _fail_offered(transfer_id: str, **fields):
            if fields.get("status") == "offered":
                raise OSError("database failed before offer")
            return original_update(transfer_id, **fields)

        monkeypatch.setattr(state, "update_transfer", _fail_offered)
        with pytest.raises(TransferLedgerUnavailableError):
            await daemon.send_file(peer, source)

        assert channel.sent == []
        row = state.list_transfers(limit=1)[0]
        assert row.status == "queued"
        assert not daemon._remote_commit_failstop_path(row.id).exists()
    finally:
        state.close()


def test_queue_file_transfer_retains_staged_source_when_ledger_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, _peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        monkeypatch.setattr(
            state,
            "upsert_transfer",
            lambda **_kwargs: (_ for _ in ()).throw(OSError("database offline")),
        )
        with pytest.raises(TransferLedgerUnavailableError) as failed:
            daemon.queue_file_transfer(
                peer_fp=peer_identity.fingerprint,
                path=source,
                schedule_resume=False,
            )
        assert failed.value.staged_path is not None
        assert failed.value.staged_path.is_file()
        assert failed.value.staged_path.read_bytes() == source.read_bytes()
    finally:
        state.close()


def test_queue_transfer_id_replay_reuses_only_verified_exact_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, _peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        blob = blake3.blake3(source.read_bytes()).hexdigest()
        transfer_id = f"out:{blob}:{'ab' * 6}"
        first = daemon.queue_file_transfer(
            peer_fp=peer_identity.fingerprint,
            path=source,
            transfer_id=transfer_id,
            schedule_resume=False,
            display_name="stable.bin",
            rel_path="tree/stable.bin",
        )
        first_path = Path(first.metadata["path"])
        replay = daemon.queue_file_transfer(
            peer_fp=peer_identity.fingerprint,
            path=source,
            transfer_id=transfer_id,
            schedule_resume=False,
            display_name="stable.bin",
            rel_path="tree/stable.bin",
        )
        assert replay.id == first.id
        assert Path(replay.metadata["path"]) == first_path
        assert replay.metadata["delivery_id"] == first.metadata["delivery_id"]

        first_path.write_bytes(b"tampered staged source")
        with pytest.raises(OSError, match="receiver staging"):
            daemon.queue_file_transfer(
                peer_fp=peer_identity.fingerprint,
                path=source,
                transfer_id=transfer_id,
                schedule_resume=False,
                display_name="stable.bin",
                rel_path="tree/stable.bin",
            )
        with pytest.raises(ValueError, match="another delivery"):
            daemon.queue_file_transfer(
                peer_fp=peer_identity.fingerprint,
                path=source,
                transfer_id=transfer_id,
                schedule_resume=False,
                display_name="other.bin",
                rel_path="tree/stable.bin",
            )
    finally:
        state.close()


@pytest.mark.asyncio
async def test_batch_entrypoint_uses_distinct_receipted_deliveries_for_same_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=True)
    daemon, state, peer, first = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    second = tmp_path / "same-content-second.bin"
    second.write_bytes(first.read_bytes())
    try:
        result = await daemon.send_files_batched(
            peer,
            [
                (first, "tree/first.bin"),
                (second, "tree/second.bin"),
            ],
        )

        offers = [m for m in channel.sent if m.get("t") == "FILE_OFFER"]
        assert result["ok"] is True
        assert result["sent"] == 2
        assert all(m.get("t") != "FILE_OFFER_BATCH" for m in channel.sent)
        assert len(offers) == 2
        assert offers[0]["blob"] == offers[1]["blob"]
        assert offers[0]["delivery_id"] != offers[1]["delivery_id"]
        assert {offer["rel_path"] for offer in offers} == {
            "tree/first.bin",
            "tree/second.bin",
        }
        rows = [
            row
            for row in state.list_transfers(limit=20)
            if row.direction == "out" and row.blob_hash == offers[0]["blob"]
        ]
        assert len(rows) == 2
        assert all(row.status == "complete" for row in rows)
        assert len({row.metadata["delivery_id"] for row in rows}) == 2
    finally:
        state.close()


@pytest.mark.asyncio
async def test_batch_entrypoint_never_uses_legacy_batch_or_claims_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(peer_identity, commit_capable=False)
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        result = await daemon.send_files_batched(peer, [(source, "legacy.bin")])
        assert result["ok"] is False
        assert result["sent"] == 0
        assert result["failed"] == 1
        assert [m["t"] for m in channel.sent].count("FILE_OFFER") == 1
        assert all(m.get("t") != "FILE_OFFER_BATCH" for m in channel.sent)
        row = state.list_transfers(limit=1)[0]
        assert row.status == "failed"
        assert row.metadata["delivery_state"] == "sent_unconfirmed"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_batch_entrypoint_treats_negative_commit_as_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity()
    channel = _SenderChannel(
        peer_identity,
        commit_capable=True,
        commit_mutation={
            "ok": False,
            "durable": False,
            "committed_bytes": 0,
            "verified_hash": "",
            "reason": "receiver_publish_failed",
            "retryable": False,
        },
    )
    daemon, state, peer, source = _sender_runtime(
        tmp_path,
        monkeypatch,
        channel,
        peer_identity,
    )
    try:
        result = await daemon.send_files_batched(peer, [(source, "failed.bin")])
        assert result["ok"] is False
        assert result["failed"] == 1
        assert result["sent"] == 0
        assert result["results"][0]["error_class"] == "ReceiverCommitError"
    finally:
        state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retryable", "expected_status", "expected_delivery_state"),
    [
        (True, "paused", "waiting_for_device"),
        (False, "failed", "needs_attention"),
    ],
)
async def test_negative_commit_retryability_controls_resume_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retryable: bool,
    expected_status: str,
    expected_delivery_state: str,
) -> None:
    peer = _identity()
    channel = _SenderChannel(
        peer,
        commit_capable=True,
        commit_mutation={
            "ok": False,
            "durable": False,
            "committed_bytes": 0,
            "verified_hash": "",
            "reason": "injected_receiver_commit_failure",
            "retryable": retryable,
        },
    )
    result, state = await _send_with_channel(
        tmp_path,
        monkeypatch,
        channel,
        peer,
        capture_error=True,
    )
    try:
        if retryable:
            assert isinstance(result["error"], TransferPausedError)
            assert isinstance(result["error"].__cause__, ReceiverCommitError)
            assert result["error"].__cause__.retryable is True
        else:
            assert isinstance(result["error"], ReceiverCommitError)
            assert result["error"].retryable is False
        row = state.list_transfers(limit=1)[0]
        assert row.status == expected_status
        assert row.metadata["delivery_state"] == expected_delivery_state
        assert row.metadata["transient"] is retryable
    finally:
        await asyncio.sleep(0.05)
        state.close()


@pytest.mark.asyncio
async def test_sender_accepts_one_bounded_commit_verification_progress_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _identity()
    channel = _CommitReplaySenderChannel(peer, progress_frames=1)
    result, state = await _send_with_channel(tmp_path, monkeypatch, channel, peer)
    try:
        assert result["confirmed"] is True
        assert result["commit_replayed"] is True
        assert result["chunks"] == 0
        assert channel.recv_count == 2
        assert state.get_transfer(result["transfer_id"]).status == "complete"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_sender_rejects_repeated_commit_verification_progress_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _identity()
    channel = _CommitReplaySenderChannel(peer, progress_frames=2)
    result, state = await _send_with_channel(
        tmp_path,
        monkeypatch,
        channel,
        peer,
        capture_error=True,
    )
    try:
        assert isinstance(result["error"], ReceiverCommitError)
        assert "repeated" in str(result["error"])
        assert channel.recv_count == 2
        row = state.list_transfers(limit=1)[0]
        assert row.status == "failed"
        assert row.metadata["transient"] is False
    finally:
        state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"blob": "ff" * 32},
        {"of": "crossed-offer"},
        {"committed_bytes": 0},
        {"durable": False},
    ],
)
async def test_sender_fails_closed_on_forged_or_crossed_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: dict,
) -> None:
    peer = _identity()
    channel = _SenderChannel(
        peer,
        commit_capable=True,
        commit_mutation=mutation,
    )
    with pytest.raises(ReceiverCommitError):
        await _send_with_channel(tmp_path, monkeypatch, channel, peer)
