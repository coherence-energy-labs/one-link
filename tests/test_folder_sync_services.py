"""Folder-sync manifest policy, receipt protocol and scheduler without a Daemon.

The receipt service runs against fake ports: an in-memory blob index, manifest
store and materialization verifier, recorded writer aborts, and fake channels
that capture wire frames. The end-to-end test wires two services (sender and
receiver) through those channels and runs the full OFFER -> VERIFY -> COMMIT
exchange.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from one_link import foldersync
from one_link.folder_manifest_policy import (
    FOLDER_BLOB_MAX_BYTES,
    FOLDER_SYNC_MAX_CLOCK_ADVANCE,
    canonical_folder_wire_path,
    folder_channel_binding,
    folder_manifest_digest,
    folder_sync_paths,
    safe_folder_offer_name,
    validate_folder_manifest_against_local_paths,
    validate_folder_manifest_causality,
    validate_folder_manifest_entries,
)
from one_link.folder_sync_receipts import (
    FolderReceiptBook,
    FolderReceiptLimits,
    FolderSyncReceiptService,
    FolderVerificationStorage,
)
from one_link.folder_sync_scheduler import FolderSyncScheduler
from one_link.wire import decode_msg, encode_msg

SENDER = "a" * 64
RECEIVER = "b" * 64


def entry(path: str, blob: str | None = "1" * 64, size: int | None = 7, **clock: int) -> dict:
    return {
        "file_path": path,
        "blob_hash": blob,
        "size": size if blob is not None else None,
        "mtime_ms": 1,
        "vclock": clock or {SENDER: 1},
    }


# ─── manifest policy ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    ["a.txt", "dir/sub/file.bin", "ünïcode/ok.txt", "/".join(["d"] * 63) + "/f"],
)
def test_canonical_paths_are_accepted(path: str) -> None:
    assert canonical_folder_wire_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "", "/abs", "C:/drive", "a\\b", "a/./b", "a/../b", "a//b", "trail.", "trail ",
        "CON", "dir/nul.txt", "com¹.log", "a\x00b", "bad<name", "/".join(["d"] * 65),
        "x" * 1025, ("y" * 256) + "/f", 7, None,
    ],
)
def test_non_canonical_paths_are_rejected(path: object) -> None:
    assert canonical_folder_wire_path(path) is None


def test_folder_offer_names_are_single_portable_leaves() -> None:
    assert safe_folder_offer_name("Photos 2026") == "Photos 2026"
    for bad in ("", " lead", "trail.", "..", "a/b", "a\\b", "LPT1", "x" * 256, 5):
        assert safe_folder_offer_name(bad) is None


def test_manifest_entries_fail_closed() -> None:
    validate_folder_manifest_entries([entry("a"), entry("b", blob=None)])
    cases = [
        ([{**entry("a"), "extra": 1}], "non-canonical entry schema"),
        ([entry("../x")], "unsafe path"),
        ([entry("d/.one-link-x.tmp")], "reserved internal path"),
        ([entry("Readme"), entry("README")], "path collision"),
        ([entry("caf\u00e9"), entry("cafe\u0301")], "path collision"),
        ([entry("dir"), entry("dir/child")], "path collision"),
        ([entry("dir/child"), entry("dir")], "path collision"),
        ([{**entry("t", blob=None), "size": 3}], "tombstone declares live content"),
        ([entry("a", blob="A" * 64)], "invalid content metadata"),
        ([entry("a", size=-1)], "invalid content metadata"),
        ([entry("a"), entry("b", size=8)], "conflicting sizes"),
        ([entry("a", blob="2" * 64, size=FOLDER_BLOB_MAX_BYTES), entry("b", blob="3" * 64, size=1)],
         "durable verification byte limit"),
        ([{**entry("a"), "mtime_ms": -1}], "invalid timestamp"),
        ([{**entry("a"), "vclock": {"": 1}}], "invalid vector clock"),
        ([{**entry("a"), "vclock": {SENDER: 0}}], "invalid vector clock"),
        ([{**entry("a"), "vclock": {f"n{i}": 1 for i in range(257)}}], "invalid vector clock"),
    ]
    for entries, message in cases:
        with pytest.raises(RuntimeError, match=message):
            validate_folder_manifest_entries(entries)


class LocalManifest:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = {row["file_path"]: row for row in rows}

    def get_manifest_entry(self, folder_name: str, file_path: str):
        return self.rows.get(file_path)

    def list_manifest(self, folder_name: str):
        return list(self.rows.values())


def test_peer_may_only_advance_its_own_clock_by_a_bounded_step() -> None:
    local = LocalManifest([{"file_path": "a", "vclock": {SENDER: 5, "third": 2}}])
    ok = {**entry("a"), "vclock": {SENDER: 5 + FOLDER_SYNC_MAX_CLOCK_ADVANCE, "third": 2}}
    validate_folder_manifest_causality(folder_name="f", entries=[ok], peer_fp=SENDER, local=local)
    jump = {**ok, "vclock": {SENDER: 6 + FOLDER_SYNC_MAX_CLOCK_ADVANCE}}
    with pytest.raises(RuntimeError, match="jump exceeds policy"):
        validate_folder_manifest_causality(folder_name="f", entries=[jump], peer_fp=SENDER, local=local)
    forged = {**ok, "vclock": {SENDER: 6, "third": 3}}
    with pytest.raises(RuntimeError, match="unauthenticated clock node"):
        validate_folder_manifest_causality(folder_name="f", entries=[forged], peer_fp=SENDER, local=local)
    with pytest.raises(RuntimeError, match="state is unavailable"):
        validate_folder_manifest_causality(folder_name="f", entries=[ok], peer_fp=SENDER, local=None)


def test_remote_paths_cannot_alias_or_straddle_local_files() -> None:
    local = LocalManifest([{"file_path": "Docs/report.txt"}, {"file_path": "notes"}])
    validate_folder_manifest_against_local_paths(
        folder_name="f", entries=[entry("Docs/report.txt"), entry("Docs/new.txt")], local=local
    )
    for path, message in (
        ("docs/REPORT.txt", "aliases an existing local path"),
        ("notes/inner.txt", "descends from an existing local file"),
        ("Docs", "collides with an existing local descendant"),
    ):
        with pytest.raises(RuntimeError, match=message):
            validate_folder_manifest_against_local_paths(
                folder_name="f", entries=[entry(path)], local=local
            )
    broken = LocalManifest([{"file_path": "ok"}, {"file_path": "OK"}])
    with pytest.raises(RuntimeError, match="portable path collision"):
        validate_folder_manifest_against_local_paths(folder_name="f", entries=[], local=broken)


def test_manifest_digest_binds_every_field_and_paths_are_ordered() -> None:
    base = [entry("a"), entry("b", blob="2" * 64)]
    assert folder_manifest_digest(base) == folder_manifest_digest([dict(e) for e in base])
    assert folder_manifest_digest(base) != folder_manifest_digest([{**base[0], "mtime_ms": 2}, base[1]])
    assert folder_sync_paths([entry("b"), entry("a"), entry("b"), {"file_path": ""}, "x"]) == ("b", "a")


def test_channel_binding_is_the_transcript_or_a_pinned_random_value() -> None:
    transcript = SimpleNamespace(transcript_hex="e" * 64)
    assert folder_channel_binding(transcript) == "e" * 64
    weak = SimpleNamespace(transcript_hex="E" * 64)
    first = folder_channel_binding(weak)
    assert first != "E" * 64 and folder_channel_binding(weak) == first
    assert folder_channel_binding(SimpleNamespace()) != first


# ─── receipt protocol ──────────────────────────────────────────────────


@dataclass
class FakeChannel:
    transcript_hex: str
    sent: list = field(default_factory=list)

    async def send(self, data: bytes) -> None:
        self.sent.append(decode_msg(data))


class Blobs:
    def __init__(self, present: set[str]) -> None:
        self.present = present

    def has(self, blob_hash: str) -> bool:
        return blob_hash in self.present


class Engine:
    def __init__(self, ok: bool = True, root: str = "9" * 64) -> None:
        self.ok, self.root, self.calls = ok, root, []

    def verify_materialized_paths(self, **kwargs):
        self.calls.append(kwargs)
        return (self.ok, "" if self.ok else "materialization_mismatch", self.root if self.ok else "")


class ReceiptPort:
    def __init__(self, *, storage: FolderVerificationStorage | None = None) -> None:
        self.storage = storage
        self.limits = FolderReceiptLimits()
        self.incoming: list[tuple] = []
        self.aborted: list[tuple[tuple, bool]] = []
        self.validated: list[list] = []

    def local_short_id(self) -> str:
        return "me"

    def receipt_limits(self) -> FolderReceiptLimits:
        return self.limits

    def incoming_blob_keys(self):
        return tuple(self.incoming)

    def abort_blob_key(self, key, *, preserve_partial: bool = False) -> None:
        self.aborted.append((key, preserve_partial))
        self.incoming.remove(key)

    def validate_manifest_entries(self, entries: list[dict]) -> None:
        self.validated.append(entries)
        validate_folder_manifest_entries(entries)

    def verification_storage(self):
        return self.storage

    async def send_folder_message(self, channel, msg, *, deadline=None) -> None:
        await channel.send(encode_msg(msg))


def manifest(*entries: dict) -> tuple[list[dict], str, str]:
    rows = list(entries)
    return rows, foldersync.manifest_root_for_entries(rows), folder_manifest_digest(rows)


SYNC_ID = "5" * 32


def run(coro):
    return asyncio.run(coro)


def _receiver(rows, root, digest, *, wants, storage=None, port=None, channel=None, clock=None):
    port = port or ReceiptPort(storage=storage)
    service = FolderSyncReceiptService(port, monotonic=clock)
    channel = channel or FakeChannel("d" * 64)
    context = service.register_inbound(
        channel=channel,
        peer_fp=SENDER,
        sync_id=SYNC_ID,
        folder_name="docs",
        source_root=root,
        manifest_digest=digest,
        entry_count=len(rows),
        wants=wants,
        blob_sizes=[(row["blob_hash"], row["size"]) for row in rows if row["blob_hash"] in wants],
        affected_paths=[row["file_path"] for row in rows],
        source_entries=rows,
    )
    return service, port, channel, context


def _verify_frame(context, *, wants=None, **override) -> dict:
    frame = {
        "t": "FOLDER_SYNC_VERIFY", "id": "6" * 32, "sync_id": SYNC_ID, "folder": "docs",
        "source_root": context.source_root, "manifest_digest": context.manifest_digest,
        "entry_count": context.entry_count,
        "wants": list(context.wants if wants is None else wants),
    }
    frame.update(override)
    return frame


def test_full_offer_verify_commit_exchange_between_two_services() -> None:
    rows, root, digest = manifest(entry("a", blob="1" * 64), entry("b", blob="2" * 64, size=3))
    link_a, link_b = FakeChannel("d" * 64), FakeChannel("d" * 64)
    sender = FolderSyncReceiptService(ReceiptPort())
    sender.register_outbound(
        channel=link_a, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entries=rows,
    )
    state = {r["file_path"]: dict(r) for r in rows}
    storage = FolderVerificationStorage(
        blobs=Blobs({"1" * 64, "2" * 64}),
        state=SimpleNamespace(get_manifest_entry=lambda folder, path: state.get(path)),
        engine=Engine(),
    )
    receiver, rport, _, context = _receiver(
        rows, root, digest, wants=("1" * 64, "2" * 64), storage=storage, channel=link_b
    )

    verify_id = run(sender.send_verify(
        channel=link_a, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entry_count=2, wants=context.wants,
    ))
    verify = link_a.sent[-1]
    assert verify["t"] == "FOLDER_SYNC_VERIFY" and verify["id"] == verify_id
    run(receiver.handle_verify(link_b, verify, SENDER))
    commit = link_b.sent[-1]
    assert commit["t"] == "FOLDER_SYNC_COMMIT" and commit["of"] == verify_id
    assert commit["ok"] is True and commit["durable"] is True
    assert commit["source_outcome"] == "exact" and commit["applied_root"] == "9" * 64
    assert receiver.book.inbound == {} and len(receiver.book.verified_inbound) == 1

    accepted = sender.accept_commit(channel=link_a, msg=commit, peer_fp=RECEIVER)
    assert accepted.verify_id == verify_id
    assert sender.book.outbound == {} and len(sender.book.verified_outbound) == 1
    with pytest.raises(RuntimeError, match="no active proof context"):
        sender.accept_commit(channel=link_a, msg=commit, peer_fp=RECEIVER)  # one-shot
    with pytest.raises(RuntimeError, match="no active proof context"):
        run(receiver.handle_verify(link_b, verify, SENDER))  # VERIFY is one-shot too


def test_outbound_offer_must_bind_its_manifest_and_wants() -> None:
    rows, root, digest = manifest(entry("a"))
    port = ReceiptPort()
    service = FolderSyncReceiptService(port)
    link = FakeChannel("d" * 64)
    with pytest.raises(RuntimeError, match="does not bind its manifest"):
        service.register_outbound(
            channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
            source_root=root, manifest_digest="f" * 64, entries=rows,
        )
    with pytest.raises(RuntimeError, match="invalid outbound folder manifest proof"):
        service.register_outbound(
            channel=link, peer_fp=RECEIVER, sync_id="short", folder_name="docs",
            source_root=root, manifest_digest=digest, entries=rows,
        )
    assert len(port.validated) == 2  # the daemon's validation seam ran each time
    service.register_outbound(
        channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entries=rows,
    )
    with pytest.raises(RuntimeError, match="admission refused"):  # duplicate key
        service.register_outbound(
            channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
            source_root=root, manifest_digest=digest, entries=rows,
        )
    with pytest.raises(RuntimeError, match="does not match outbound offer"):
        run(service.send_verify(
            channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
            source_root=root, manifest_digest=digest, entry_count=1, wants=["7" * 64],
        ))


def test_commit_receipts_are_exact_and_negative_ones_are_bounded() -> None:
    rows, root, digest = manifest(entry("a"))
    link = FakeChannel("d" * 64)
    service = FolderSyncReceiptService(ReceiptPort())
    service.register_outbound(
        channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entries=rows,
    )
    verify_id = run(service.send_verify(
        channel=link, peer_fp=RECEIVER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entry_count=1, wants=["1" * 64],
    ))
    good = {
        "of": verify_id, "sync_id": SYNC_ID, "folder": "docs", "source_root": root,
        "manifest_digest": digest, "entry_count": 1, "wanted_count": 1, "paths_verified": 1,
        "conflict_count": 0, "source_outcome": "exact", "ok": True, "durable": True,
        "applied_root": "9" * 64,
    }
    for bad, message in (
        ({**good, "of": "0" * 32}, "crossed or malformed"),
        ({**good, "conflict_count": 2}, "crossed or malformed"),
        ({**good, "ok": False, "reason": "x" * 500}, "could not commit folder sync: " + "x" * 128 + "$"),
        ({**good, "ok": False, "applied_root": "zz"}, "malformed negative"),
        ({**good, "applied_root": ""}, "no applied root"),
        ({**good, "source_outcome": "exact", "conflict_count": 1}, "inconsistent source outcome"),
        ({**good, "source_outcome": "guess"}, "inconsistent source outcome"),
    ):
        with pytest.raises(RuntimeError, match=message):
            service.accept_commit(channel=link, msg=bad, peer_fp=RECEIVER)
        assert service.book.outbound  # a refused receipt never consumes the proof
    service.accept_commit(channel=link, msg=good, peer_fp=RECEIVER)


def test_inbound_registration_rejects_malformed_contracts() -> None:
    rows, root, digest = manifest(entry("a"))
    base = dict(
        channel=FakeChannel("d" * 64), peer_fp=SENDER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entry_count=1, wants=["1" * 64],
        blob_sizes=[("1" * 64, 7)], affected_paths=["a"], source_entries=rows,
    )
    service = FolderSyncReceiptService(ReceiptPort())
    for override, message in (
        ({"folder_name": "../x"}, "invalid folder sync receipt contract"),
        ({"wants": [7]}, "must be strings"),
        ({"wants": ["X" * 64]}, "invalid folder sync wanted hash"),
        ({"blob_sizes": [("1" * 64, -1)]}, "wanted size contract"),
        ({"blob_sizes": []}, "size contract is incomplete"),
        ({"resume_ranges": [("1" * 64, 7, 3, "0" * 64)]}, "blob resume contract"),
        ({"affected_paths": ["b"]}, "source proof contract is incomplete"),
    ):
        with pytest.raises(RuntimeError, match=message):
            service.register_inbound(**{**base, **override})
    assert service.book.inbound == {}


def test_inbound_admission_is_bounded_per_channel_and_by_retained_paths() -> None:
    rows, root, digest = manifest(entry("a"))
    service, port, channel, _ = _receiver(rows, root, digest, wants=("1" * 64,))
    with pytest.raises(RuntimeError, match="admission refused"):
        service.register_inbound(
            channel=channel, peer_fp=SENDER, sync_id="7" * 32, folder_name="docs",
            source_root=root, manifest_digest=digest, entry_count=1, wants=["1" * 64],
            blob_sizes=[("1" * 64, 7)], affected_paths=["a"], source_entries=rows,
        )
    port.limits = FolderReceiptLimits(per_channel_max=8, retained_paths_max=3)
    with pytest.raises(RuntimeError, match="admission refused"):
        service.register_inbound(
            channel=channel, peer_fp=SENDER, sync_id="8" * 32, folder_name="docs",
            source_root=root, manifest_digest=digest, entry_count=1, wants=["1" * 64],
            blob_sizes=[("1" * 64, 7)], affected_paths=["a"], source_entries=rows,
        )
    assert len(service.book.inbound) == 1


def test_failed_proofs_reply_negative_and_abort_partial_writers() -> None:
    rows, root, digest = manifest(entry("a"))
    state = SimpleNamespace(get_manifest_entry=lambda folder, path: dict(rows[0]))
    storage = FolderVerificationStorage(blobs=Blobs(set()), state=state, engine=Engine())
    service, port, channel, context = _receiver(rows, root, digest, wants=("1" * 64,), storage=storage)
    key = (SENDER, "d" * 64, SYNC_ID)
    port.incoming.append((*key, "1" * 64))
    run(service.handle_verify(channel, _verify_frame(context), SENDER))
    commit = channel.sent[-1]
    assert commit["ok"] is False and commit["reason"] == "requested_blob_not_durable"
    assert port.aborted == [((*key, "1" * 64), False)]
    assert service.book.inbound == {} and service.book.verified_inbound == {}


@pytest.mark.parametrize(
    "storage_kind,frame_override,reason",
    [
        ("none", {}, "folder_storage_unavailable"),
        ("ok", {"manifest_digest": "0" * 64}, "receipt_contract_mismatch"),
        ("ok", {"wants": []}, "receipt_contract_mismatch"),
        ("unmaterialized", {}, "materialization_mismatch"),
        ("missing_source", {}, "source_projection_missing"),
        ("stale_source", {}, "source_projection_not_reconciled"),
    ],
)
def test_verify_reports_each_failure_reason(storage_kind, frame_override, reason) -> None:
    rows, root, digest = manifest(entry("a", **{SENDER: 3}))
    current = {"none": None, "ok": dict(rows[0]), "unmaterialized": dict(rows[0]),
               "missing_source": None, "stale_source": {**rows[0], "vclock": {SENDER: 2}}}[storage_kind]
    storage = None
    if storage_kind != "none":
        storage = FolderVerificationStorage(
            blobs=Blobs({"1" * 64}),
            state=SimpleNamespace(get_manifest_entry=lambda folder, path: current),
            engine=Engine(ok=storage_kind != "unmaterialized"),
        )
    service, _port, channel, context = _receiver(rows, root, digest, wants=("1" * 64,), storage=storage)
    frame = _verify_frame(context, **frame_override)
    run(service.handle_verify(channel, frame, SENDER))
    commit = channel.sent[-1]
    assert commit["ok"] is False and commit["durable"] is False and commit["reason"] == reason


def test_concurrent_local_change_is_reported_as_reconciled_conflict() -> None:
    rows, root, digest = manifest(entry("a"))
    newer = {**rows[0], "blob_hash": "4" * 64, "vclock": {SENDER: 1, RECEIVER: 1}}
    storage = FolderVerificationStorage(
        blobs=Blobs({"1" * 64}),
        state=SimpleNamespace(get_manifest_entry=lambda folder, path: newer),
        engine=Engine(),
    )
    service, _port, channel, context = _receiver(rows, root, digest, wants=("1" * 64,), storage=storage)
    run(service.handle_verify(channel, _verify_frame(context), SENDER))
    commit = channel.sent[-1]
    assert commit["ok"] is True
    assert commit["source_outcome"] == "reconciled_conflict" and commit["conflict_count"] == 1


def test_ttl_expiry_and_capacity_eviction_release_inbound_writers() -> None:
    now = [0.0]
    rows, root, digest = manifest(entry("a"))
    port = ReceiptPort()
    port.limits = FolderReceiptLimits(receipt_ttl_s=10.0)
    service, port, _channel, _ = _receiver(
        rows, root, digest, wants=("1" * 64,), port=port, clock=lambda: now[0]
    )
    key = (SENDER, "d" * 64, SYNC_ID)
    port.incoming.append((*key, "1" * 64))
    assert key in service.book.blob_progress
    now[0] = 10.5
    service.prune()
    assert service.book.inbound == {} and key not in service.book.blob_progress
    assert port.aborted == [((*key, "1" * 64), True)]  # fsynced prefix kept for resume

    def register(index: int, sync_id: str) -> None:
        service.register_inbound(
            channel=FakeChannel(f"{index}" * 64), peer_fp=SENDER, sync_id=sync_id,
            folder_name="docs", source_root=root, manifest_digest=digest, entry_count=1,
            wants=["1" * 64], blob_sizes=[("1" * 64, 7)], affected_paths=["a"],
            source_entries=rows,
        )

    port.limits = FolderReceiptLimits(context_max=2, per_channel_max=8)
    register(1, "1" * 32)
    register(2, "2" * 32)
    with pytest.raises(RuntimeError, match="admission refused"):  # full: refuse, never evict
        register(3, "3" * 32)
    # A lowered bound evicts least-recently-admitted contexts and their writers.
    oldest = (SENDER, "1" * 64, "1" * 32)
    port.incoming.append((*oldest, "1" * 64))
    port.limits = FolderReceiptLimits(context_max=1, per_channel_max=8)
    service.prune()
    assert [k[2] for k in service.book.inbound] == ["2" * 32]
    assert port.aborted[-1] == ((*oldest, "1" * 64), True)


def test_release_channel_drops_only_that_channels_state() -> None:
    rows, root, digest = manifest(entry("a"))
    service, port, channel, _ = _receiver(rows, root, digest, wants=("1" * 64,))
    other = FakeChannel("e" * 64)
    service.register_inbound(
        channel=other, peer_fp=SENDER, sync_id=SYNC_ID, folder_name="docs",
        source_root=root, manifest_digest=digest, entry_count=1, wants=["1" * 64],
        blob_sizes=[("1" * 64, 7)], affected_paths=["a"], source_entries=rows,
    )
    port.incoming.extend([(SENDER, "d" * 64, SYNC_ID, "1" * 64), (SENDER, "e" * 64, SYNC_ID, "1" * 64)])
    service.release_channel(channel, SENDER)
    assert list(service.book.inbound) == [(SENDER, "e" * 64, SYNC_ID)]
    assert port.incoming == [(SENDER, "e" * 64, SYNC_ID, "1" * 64)]


def test_replaced_state_maps_are_normalized_and_the_gate_is_bounded() -> None:
    port = ReceiptPort()
    port.limits = FolderReceiptLimits(verify_concurrency=1)
    service = FolderSyncReceiptService(port, book=FolderReceiptBook(inbound={}))  # type: ignore[arg-type]
    service.prune()
    assert isinstance(service.book.inbound, OrderedDict)
    gate = service.verify_gate()
    assert gate is service.verify_gate()

    async def overlap() -> int:
        active = peak = 0

        async def job():
            nonlocal active, peak
            async with service.verify_gate():
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(job(), job(), job())
        return peak

    service.book.verify_gate = None
    assert run(overlap()) == 1


# ─── scheduler ─────────────────────────────────────────────────────────


class SchedulerPort:
    def __init__(self) -> None:
        self.ready = True
        self.folders = [
            {"name": "docs", "shared_with": [SENDER, RECEIVER, "c" * 64]},
            {"name": "pics", "shared_with": [RECEIVER]},
        ]
        self.pins = {SENDER, RECEIVER}
        self.peers = [SimpleNamespace(fp=SENDER, short_id="a"), SimpleNamespace(fp=RECEIVER, short_id="b")]
        self.pushes: list[tuple] = []
        self.fail_for: set[str] = set()
        self.broadcasts: list[dict] = []
        self.broadcast_error = False
        self.ui = True

    def sync_ready(self) -> bool:
        return self.ready

    def list_folders(self):
        return self.folders

    def discovered_peers(self):
        return self.peers

    def peer_fp_from_peer(self, peer):
        return peer.fp

    def is_pinned(self, peer_fp: str) -> bool:
        return peer_fp in self.pins

    async def push_folder_to_peer(self, peer, folder_name, *, bidirectional, background):
        self.pushes.append((peer.fp, folder_name, bidirectional, background))
        if peer.fp in self.fail_for:
            raise ConnectionError("peer went away")

    def ui_broadcaster(self):
        if not self.ui:
            return None

        def broadcast(event):
            if self.broadcast_error:
                raise RuntimeError("socket closed")
            self.broadcasts.append(event)

        return broadcast


def test_cycle_pushes_each_shared_folder_to_pinned_discovered_peers() -> None:
    port = SchedulerPort()
    port.fail_for = {SENDER}
    scheduler = FolderSyncScheduler(port)
    assert run(scheduler.run_cycle()) == 3
    assert port.pushes == [
        (SENDER, "docs", True, True),
        (RECEIVER, "docs", True, True),
        (RECEIVER, "pics", True, True),
    ]
    port.ready = False
    assert run(scheduler.run_cycle()) == 0


def test_cycle_stops_cleanly_when_the_daemon_shuts_down_during_a_push() -> None:
    """A push awaits; if sync stops being ready meanwhile, the cycle ends without asking discovery again."""

    class ShuttingDownPort(SchedulerPort):
        async def push_folder_to_peer(self, peer, folder_name, *, bidirectional, background):
            await super().push_folder_to_peer(
                peer, folder_name, bidirectional=bidirectional, background=background
            )
            self.ready = False  # shutdown began while this push was in flight

        def discovered_peers(self):
            if not self.ready:
                raise RuntimeError("discovery is gone")
            return super().discovered_peers()

    port = ShuttingDownPort()
    scheduler = FolderSyncScheduler(port)
    assert run(scheduler.run_cycle()) == 1
    assert port.pushes == [(SENDER, "docs", True, True)]


def test_loop_settles_then_repeats_until_cancelled() -> None:
    port = SchedulerPort()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise asyncio.CancelledError

    scheduler = FolderSyncScheduler(port, sleep=fake_sleep)
    run(scheduler.run_forever(initial_delay_s=8.0, interval_s=30.0))
    assert sleeps == [8.0, 30.0, 30.0]
    assert len(port.pushes) == 6  # two cycles of three pushes


def test_local_changes_reach_the_ui_and_broadcast_failures_are_contained() -> None:
    port = SchedulerPort()
    scheduler = FolderSyncScheduler(port)
    change = SimpleNamespace(file_path="a.txt", blob_hash=None)
    run(scheduler.on_local_change("docs", change))
    assert port.broadcasts == [
        {"type": "folder_change", "folder": "docs", "file": "a.txt", "deleted": True}
    ]
    port.broadcast_error = True
    run(scheduler.on_local_change("docs", change))
    port.ui = False
    run(scheduler.on_local_change("docs", change))
    assert len(port.broadcasts) == 1
