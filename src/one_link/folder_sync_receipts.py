"""Folder-sync proof protocol: receipts, durable verification and commit.

One in-channel folder reconciliation is a small state machine per
``(peer_fp, channel_binding, sync_id)`` key::

    sender:   register_outbound ──► send_verify ──► accept_commit
                 (MANIFEST_PUSH)    (FOLDER_SYNC_VERIFY)   (FOLDER_SYNC_COMMIT)
    receiver: register_inbound ──► handle_verify (durable proof, replies COMMIT)

:class:`FolderSyncReceiptService` owns that state (:class:`FolderReceiptBook`)
and every transition. It never touches transport, blob writers or storage
directly: it reaches them through :class:`FolderSyncReceiptPort`.

Contracts preserved from the daemon implementation:

* every receipt is bound to one authenticated channel; a disconnect releases
  all of that channel's receipts, writers and progress;
* admission is bounded globally, per channel, and by retained path/hash
  volume, and contexts expire on a monotonic TTL with LRU eviction; expiring
  or evicting an inbound receipt aborts its partial blob writers (keeping the
  fsynced prefix for resume);
* VERIFY is one-shot: the proof context is consumed before COMMIT is sent, so
  a peer cannot replay an expensive disk proof or race two VERIFY frames;
* the durable proof runs on a worker thread under a bounded concurrency gate
  and a wall-clock deadline, and reports ``exact`` versus
  ``reconciled_conflict`` truthfully; a negative or inconsistent COMMIT
  is refused with a bounded reason.

Failures raise ``RuntimeError`` with the historical messages.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional, Protocol, Sequence

from one_link import foldersync
from one_link.folder_manifest_policy import (
    FOLDER_BLOB_MAX_BYTES,
    FOLDER_SYNC_MANIFEST_MAX_ENTRIES,
    FOLDER_SYNC_VERIFY_MAX_BYTES,
    folder_channel_binding,
    folder_manifest_digest,
    folder_sync_paths,
    is_blob_hex,
    safe_folder_offer_name,
)
from one_link.wire import make_msg

FOLDER_SYNC_SESSION_ABSOLUTE_S = 6 * 60 * 60.0
FOLDER_SYNC_RECEIPT_TTL_S = FOLDER_SYNC_SESSION_ABSOLUTE_S + 10 * 60.0
FOLDER_SYNC_RECEIPT_CONTEXT_MAX = 64
FOLDER_SYNC_RECEIPTS_PER_CHANNEL_MAX = 1
FOLDER_SYNC_RECEIPT_RETAINED_PATHS_MAX = 262_144
FOLDER_SYNC_VERIFY_CONCURRENCY = 2

ReceiptKey = tuple[str, str, str]


@dataclass(frozen=True)
class FolderSyncReceiptContext:
    """Bound proof state for one in-channel folder reconciliation."""

    peer_fp: str
    channel_binding: str
    sync_id: str
    folder_name: str
    source_root: str
    manifest_digest: str
    entry_count: int
    wants: tuple[str, ...]
    affected_paths: tuple[str, ...]
    created_at: float
    offered_hashes: tuple[str, ...] = ()
    blob_sizes: tuple[tuple[str, int], ...] = ()
    resume_ranges: tuple[tuple[str, int, int, str], ...] = ()
    source_proofs: tuple[tuple[str, str | None, tuple[tuple[str, int], ...]], ...] = ()
    verify_id: str = ""


@dataclass(frozen=True)
class FolderReceiptLimits:
    """Admission bounds. ``resume_alignment`` is the wire chunk size."""

    receipt_ttl_s: float = FOLDER_SYNC_RECEIPT_TTL_S
    context_max: int = FOLDER_SYNC_RECEIPT_CONTEXT_MAX
    per_channel_max: int = FOLDER_SYNC_RECEIPTS_PER_CHANNEL_MAX
    retained_paths_max: int = FOLDER_SYNC_RECEIPT_RETAINED_PATHS_MAX
    verify_concurrency: int = FOLDER_SYNC_VERIFY_CONCURRENCY
    verify_deadline_s: float = FOLDER_SYNC_SESSION_ABSOLUTE_S
    resume_alignment: int = 256 * 1024


@dataclass
class FolderReceiptBook:
    """All in-memory receipt state; channel-lifetime by construction.

    Mutable blob progress lives beside the frozen proofs so completing one of
    many wanted blobs never re-verifies every other one.
    """

    inbound: OrderedDict[ReceiptKey, FolderSyncReceiptContext] = field(default_factory=OrderedDict)
    outbound: OrderedDict[ReceiptKey, FolderSyncReceiptContext] = field(default_factory=OrderedDict)
    verified_inbound: OrderedDict[ReceiptKey, float] = field(default_factory=OrderedDict)
    verified_outbound: OrderedDict[ReceiptKey, float] = field(default_factory=OrderedDict)
    blob_progress: dict[ReceiptKey, set[str]] = field(default_factory=dict)
    verify_gate: Optional[asyncio.Semaphore] = None


class DurableBlobIndex(Protocol):
    def has(self, blob_hash: str) -> bool: ...


class MaterializationVerifier(Protocol):
    def verify_materialized_paths(
        self,
        *,
        folder_name: str,
        paths: Sequence[str],
        max_paths: int,
        max_total_bytes: int,
        deadline_monotonic: float,
    ) -> tuple[bool, str, str]: ...


class ManifestEntryReader(Protocol):
    def get_manifest_entry(self, folder_name: str, file_path: str) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True)
class FolderVerificationStorage:
    blobs: DurableBlobIndex
    state: ManifestEntryReader
    engine: MaterializationVerifier


class FolderSyncReceiptPort(Protocol):
    """Exactly what the receipt protocol needs from the daemon."""

    def local_short_id(self) -> str: ...

    def receipt_limits(self) -> FolderReceiptLimits: ...

    def incoming_blob_keys(self) -> Sequence[tuple]: ...

    def abort_blob_key(self, key: tuple, *, preserve_partial: bool = False) -> None: ...

    def validate_manifest_entries(self, entries: list[dict]) -> None: ...

    def verification_storage(self) -> FolderVerificationStorage | None: ...

    async def send_folder_message(
        self, channel: Any, msg: dict, *, deadline: float | None = None
    ) -> None: ...


def _valid_delivery_id(value: object) -> bool:
    """The stable 128-bit wire delivery nonce (32 lowercase hex characters)."""

    return (
        isinstance(value, str)
        and len(value) == 32
        and all(ch in "0123456789abcdef" for ch in value)
    )


_BOOK_FIELDS = ("inbound", "outbound", "verified_inbound", "verified_outbound")


class FolderSyncReceiptService:
    """Own folder-sync receipt admission, verification and commit."""

    def __init__(
        self,
        port: FolderSyncReceiptPort,
        *,
        book: FolderReceiptBook | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self.port = port
        self.book = book if book is not None else FolderReceiptBook()
        self._monotonic = monotonic if monotonic is not None else (lambda: time.monotonic())

    # ── bookkeeping ──────────────────────────────────────────────────

    def _mapping(self, name: str) -> OrderedDict:
        mapping = getattr(self.book, name)
        if not isinstance(mapping, OrderedDict):
            mapping = OrderedDict()
            setattr(self.book, name, mapping)
        return mapping

    def _progress(self) -> dict:
        progress = self.book.blob_progress
        if not isinstance(progress, dict):
            progress = {}
            self.book.blob_progress = progress
        return progress

    def _abort_inbound_writers(self, receipt_key: ReceiptKey, *, preserve_partial: bool) -> None:
        for blob_key in tuple(self.port.incoming_blob_keys()):
            if blob_key[:3] == receipt_key:
                self.port.abort_blob_key(blob_key, preserve_partial=preserve_partial)

    def prune(self) -> None:
        """Expire contexts past the TTL and evict the oldest above capacity."""

        limits = self.port.receipt_limits()
        now = self._monotonic()
        for name in _BOOK_FIELDS:
            mapping = self._mapping(name)
            stores_context = name in {"inbound", "outbound"}
            expired = [
                key
                for key, value in mapping.items()
                if now - (value.created_at if stores_context else float(value))
                > limits.receipt_ttl_s
            ]
            evicted: list[ReceiptKey] = []
            for key in expired:
                mapping.pop(key, None)
                evicted.append(key)
            while len(mapping) > limits.context_max:
                key, _value = mapping.popitem(last=False)
                evicted.append(key)
            if name == "inbound":
                for key in evicted:
                    self._abort_inbound_writers(key, preserve_partial=True)
                    self._progress().pop(key, None)

    def release_channel(self, channel: Any, peer_fp: str) -> None:
        """Release every receipt, writer and progress entry bound to a channel."""

        binding = folder_channel_binding(channel)
        for key in tuple(self.port.incoming_blob_keys()):
            if key[0] == peer_fp and key[1] == binding:
                self.port.abort_blob_key(key, preserve_partial=True)
        for name in _BOOK_FIELDS:
            mapping = getattr(self.book, name)
            if not isinstance(mapping, OrderedDict):
                continue
            for key in tuple(mapping):
                if key[0] == peer_fp and key[1] == binding:
                    mapping.pop(key, None)
                    self._progress().pop(key, None)

    def verify_gate(self) -> asyncio.Semaphore:
        gate = self.book.verify_gate
        if not isinstance(gate, asyncio.Semaphore):
            gate = asyncio.Semaphore(self.port.receipt_limits().verify_concurrency)
            self.book.verify_gate = gate
        return gate

    @staticmethod
    def _key(channel: Any, peer_fp: str, sync_id: str) -> ReceiptKey:
        return (peer_fp, folder_channel_binding(channel), sync_id)

    def _admit(
        self,
        name: str,
        verified_name: str,
        key: ReceiptKey,
        context: FolderSyncReceiptContext,
        *,
        retained_of: Callable[[FolderSyncReceiptContext], int],
        refusal: str,
    ) -> None:
        limits = self.port.receipt_limits()
        mapping = self._mapping(name)
        channel_contexts = sum(1 for existing in mapping if existing[:2] == key[:2])
        retained = sum(retained_of(existing) for existing in mapping.values())
        if (
            key in mapping
            or key in self._mapping(verified_name)
            or len(mapping) >= limits.context_max
            or channel_contexts >= limits.per_channel_max
            or retained + retained_of(context) > limits.retained_paths_max
        ):
            raise RuntimeError(refusal)
        mapping[key] = context
        mapping.move_to_end(key)

    # ── receiver ─────────────────────────────────────────────────────

    def register_inbound(
        self,
        *,
        channel: Any,
        peer_fp: str,
        sync_id: str,
        folder_name: str,
        source_root: str,
        manifest_digest: str,
        entry_count: int,
        wants: Iterable[str],
        blob_sizes: Iterable[tuple[str, int]],
        affected_paths: Iterable[str],
        source_entries: Iterable[dict],
        resume_ranges: Iterable[tuple[str, int, int, str]] = (),
    ) -> FolderSyncReceiptContext:
        """Admit the receiver side of one sync after its wants are known."""

        if (
            not _valid_delivery_id(sync_id)
            or not is_blob_hex(source_root)
            or not is_blob_hex(manifest_digest)
            or safe_folder_offer_name(folder_name) is None
            or type(entry_count) is not int
            or entry_count < 0
            or entry_count > FOLDER_SYNC_MANIFEST_MAX_ENTRIES
        ):
            raise RuntimeError("invalid folder sync receipt contract")
        raw_wants = tuple(wants)
        if any(not isinstance(value, str) for value in raw_wants):
            raise RuntimeError("folder sync wanted hashes must be strings")
        clean_wants = tuple(dict.fromkeys(raw_wants))
        if any(not is_blob_hex(value) for value in clean_wants):
            raise RuntimeError("invalid folder sync wanted hash")
        clean_sizes: dict[str, int] = {}
        for blob_hash, size in blob_sizes:
            if (
                blob_hash not in clean_wants
                or type(size) is not int
                or size < 0
                or size > FOLDER_BLOB_MAX_BYTES
                or (blob_hash in clean_sizes and clean_sizes[blob_hash] != size)
            ):
                raise RuntimeError("invalid folder sync wanted size contract")
            clean_sizes[blob_hash] = size
        if set(clean_sizes) != set(clean_wants):
            raise RuntimeError("folder sync wanted size contract is incomplete")
        alignment = self.port.receipt_limits().resume_alignment
        clean_resume: dict[str, tuple[int, int, str]] = {}
        for blob_hash, size, offset, prefix_digest in resume_ranges:
            if (
                blob_hash not in clean_wants
                or clean_sizes.get(blob_hash) != size
                or type(offset) is not int
                or offset < 0
                or offset > size
                or (offset % alignment != 0 and offset != size)
                or not isinstance(prefix_digest, str)
                or not is_blob_hex(prefix_digest)
                or blob_hash in clean_resume
            ):
                raise RuntimeError("invalid folder blob resume contract")
            clean_resume[blob_hash] = (size, offset, prefix_digest)
        if clean_resume and set(clean_resume) != set(clean_wants):
            raise RuntimeError("folder blob resume contract is incomplete")
        clean_paths = tuple(dict.fromkeys(str(value) for value in affected_paths))
        if len(clean_paths) > FOLDER_SYNC_MANIFEST_MAX_ENTRIES:
            raise RuntimeError("folder sync path count exceeds receipt bound")
        source_proofs = tuple(
            (
                str(entry["file_path"]),
                entry.get("blob_hash"),
                tuple(sorted(dict(entry.get("vclock") or {}).items())),
            )
            for entry in source_entries
        )
        if (
            len(source_proofs) != entry_count
            or tuple(path for path, _blob, _clock in source_proofs) != clean_paths
        ):
            raise RuntimeError("folder sync source proof contract is incomplete")
        key = self._key(channel, peer_fp, sync_id)
        context = FolderSyncReceiptContext(
            peer_fp=peer_fp,
            channel_binding=key[1],
            sync_id=sync_id,
            folder_name=folder_name,
            source_root=str(source_root),
            manifest_digest=manifest_digest,
            entry_count=int(entry_count),
            wants=clean_wants,
            affected_paths=clean_paths,
            created_at=self._monotonic(),
            blob_sizes=tuple(clean_sizes.items()),
            resume_ranges=tuple(
                (blob_hash, *clean_resume[blob_hash])
                for blob_hash in clean_wants
                if blob_hash in clean_resume
            ),
            source_proofs=source_proofs,
        )
        self.prune()
        self._admit(
            "inbound",
            "verified_inbound",
            key,
            context,
            retained_of=lambda ctx: len(ctx.affected_paths) + len(ctx.wants),
            refusal="folder sync receipt admission refused",
        )
        self._progress()[key] = set()
        self.prune()
        return context

    async def handle_verify(self, channel: Any, msg: dict, peer_fp: str) -> None:
        """Prove durable materialization for a VERIFY and reply with COMMIT."""

        sync_id = str(msg.get("sync_id") or "")
        key = self._key(channel, peer_fp, sync_id)
        self.prune()
        context = self.book.inbound.get(key)
        if context is None:
            raise RuntimeError("folder verification has no active proof context")
        ok = False
        reason = "receipt_context_missing"
        applied_root = ""
        source_outcome = "unverified"
        conflict_count = 0
        wire_wants = msg.get("wants")
        exact_contract = (
            _valid_delivery_id(str(msg.get("id") or ""))
            and msg.get("folder") == context.folder_name
            and msg.get("source_root") == context.source_root
            and msg.get("manifest_digest") == context.manifest_digest
            and type(msg.get("entry_count")) is int
            and int(msg["entry_count"]) == context.entry_count
            and isinstance(wire_wants, list)
            and tuple(wire_wants) == context.wants
        )
        storage = self.port.verification_storage() if exact_contract else None
        if not exact_contract:
            reason = "receipt_contract_mismatch"
        elif storage is None:
            reason = "folder_storage_unavailable"
        else:
            deadline = self._monotonic() + self.port.receipt_limits().verify_deadline_s
            async with self.verify_gate():
                ok, reason, applied_root, source_outcome, conflict_count = await asyncio.to_thread(
                    _verify_durable_folder_state, context, storage, deadline
                )
        commit = make_msg(
            "FOLDER_SYNC_COMMIT",
            self.port.local_short_id(),
            of=msg.get("id"),
            sync_id=sync_id,
            folder=context.folder_name,
            source_root=context.source_root,
            manifest_digest=context.manifest_digest,
            applied_root=applied_root,
            entry_count=context.entry_count,
            wanted_count=len(context.wants),
            paths_verified=len(context.affected_paths),
            source_outcome=source_outcome,
            conflict_count=conflict_count,
            ok=ok,
            durable=ok,
            reason=reason,
        )
        # VERIFY is one-shot for a sync id. Consume its proof context before
        # replying so a paired peer cannot replay an expensive disk proof or
        # race multiple VERIFY frames against one materialization attempt.
        self.book.inbound.pop(key, None)
        self._progress().pop(key, None)
        if ok:
            verified = self._mapping("verified_inbound")
            verified[key] = self._monotonic()
            verified.move_to_end(key)
        else:
            self._abort_inbound_writers(key, preserve_partial=False)
        self.prune()
        await self.port.send_folder_message(channel, commit)

    # ── sender ───────────────────────────────────────────────────────

    def register_outbound(
        self,
        *,
        channel: Any,
        peer_fp: str,
        sync_id: str,
        folder_name: str,
        source_root: str,
        manifest_digest: str,
        entries: Iterable[dict],
    ) -> FolderSyncReceiptContext:
        """Bind an outbound manifest offer to the proof it must later receive."""

        entry_list = list(entries)
        self.port.validate_manifest_entries(entry_list)
        if (
            not _valid_delivery_id(sync_id)
            or not is_blob_hex(source_root)
            or not is_blob_hex(manifest_digest)
            or len(entry_list) > FOLDER_SYNC_MANIFEST_MAX_ENTRIES
        ):
            raise RuntimeError("invalid outbound folder manifest proof context")
        if (
            foldersync.manifest_root_for_entries(entry_list) != source_root
            or folder_manifest_digest(entry_list) != manifest_digest
        ):
            raise RuntimeError("outbound folder proof does not bind its manifest")
        offered = tuple(
            dict.fromkeys(
                str(entry.get("blob_hash"))
                for entry in entry_list
                if (
                    isinstance(entry, dict)
                    and entry.get("blob_hash") is not None
                    and is_blob_hex(str(entry.get("blob_hash")))
                )
            )
        )
        offered_sizes: dict[str, int] = {}
        for entry in entry_list:
            blob_hash = entry.get("blob_hash")
            if blob_hash is None:
                continue
            size = entry.get("size")
            if not isinstance(blob_hash, str) or type(size) is not int:
                raise RuntimeError("outbound folder manifest entry has invalid content metadata")
            prior_size = offered_sizes.setdefault(blob_hash, size)
            if prior_size != size:
                raise RuntimeError("one folder hash has conflicting offered sizes")
        key = self._key(channel, peer_fp, sync_id)
        context = FolderSyncReceiptContext(
            peer_fp=peer_fp,
            channel_binding=key[1],
            sync_id=sync_id,
            folder_name=folder_name,
            source_root=source_root,
            manifest_digest=manifest_digest,
            entry_count=len(entry_list),
            wants=(),
            affected_paths=folder_sync_paths(entry_list),
            created_at=self._monotonic(),
            offered_hashes=offered,
            blob_sizes=tuple(offered_sizes.items()),
        )
        self.prune()
        self._admit(
            "outbound",
            "verified_outbound",
            key,
            context,
            retained_of=lambda ctx: len(ctx.affected_paths) + len(ctx.offered_hashes),
            refusal="outbound folder sync receipt admission refused",
        )
        self.prune()
        return context

    async def send_verify(
        self,
        *,
        channel: Any,
        peer_fp: str,
        sync_id: str,
        folder_name: str,
        source_root: str,
        manifest_digest: str,
        entry_count: int,
        wants: Iterable[str],
        deadline: float | None = None,
    ) -> str:
        """Ask the receiver to prove the wanted subset; returns the VERIFY id."""

        if not _valid_delivery_id(sync_id):
            raise RuntimeError("cannot verify an invalid folder sync id")
        raw_wants = tuple(wants)
        if any(not isinstance(value, str) for value in raw_wants):
            raise RuntimeError("folder verification hashes must be strings")
        clean_wants = tuple(dict.fromkeys(raw_wants))
        if any(not is_blob_hex(value) for value in clean_wants):
            raise RuntimeError("cannot verify invalid folder blob hashes")
        verify = make_msg(
            "FOLDER_SYNC_VERIFY",
            self.port.local_short_id(),
            sync_id=sync_id,
            folder=folder_name,
            source_root=str(source_root),
            manifest_digest=manifest_digest,
            entry_count=int(entry_count),
            wants=list(clean_wants),
        )
        self.prune()
        key = self._key(channel, peer_fp, sync_id)
        outbound = self._mapping("outbound")
        offered_context = outbound.get(key)
        if (
            offered_context is None
            or offered_context.verify_id
            or offered_context.folder_name != folder_name
            or offered_context.source_root != str(source_root)
            or offered_context.manifest_digest != manifest_digest
            or offered_context.entry_count != int(entry_count)
            or any(value not in offered_context.offered_hashes for value in clean_wants)
        ):
            raise RuntimeError("folder verification does not match outbound offer")
        context = FolderSyncReceiptContext(
            peer_fp=peer_fp,
            channel_binding=key[1],
            sync_id=sync_id,
            folder_name=folder_name,
            source_root=str(source_root),
            manifest_digest=manifest_digest,
            entry_count=int(entry_count),
            wants=clean_wants,
            affected_paths=offered_context.affected_paths,
            created_at=self._monotonic(),
            offered_hashes=offered_context.offered_hashes,
            blob_sizes=offered_context.blob_sizes,
            verify_id=str(verify["id"]),
        )
        outbound[key] = context
        outbound.move_to_end(key)
        self.prune()
        await self.port.send_folder_message(channel, verify, deadline=deadline)
        return context.verify_id

    def accept_commit(self, *, channel: Any, msg: dict, peer_fp: str) -> FolderSyncReceiptContext:
        """Accept exactly the COMMIT that answers our VERIFY, or raise."""

        sync_id = str(msg.get("sync_id") or "")
        key = self._key(channel, peer_fp, sync_id)
        self.prune()
        context = self.book.outbound.get(key)
        if context is None:
            raise RuntimeError("folder sync commit has no active proof context")
        if (
            msg.get("of") != context.verify_id
            or msg.get("folder") != context.folder_name
            or msg.get("source_root") != context.source_root
            or msg.get("manifest_digest") != context.manifest_digest
            or type(msg.get("entry_count")) is not int
            or int(msg["entry_count"]) != context.entry_count
            or type(msg.get("wanted_count")) is not int
            or int(msg["wanted_count"]) != len(context.wants)
            or type(msg.get("paths_verified")) is not int
            or int(msg["paths_verified"]) != len(context.affected_paths)
            or type(msg.get("conflict_count")) is not int
            or int(msg["conflict_count"]) < 0
            or int(msg["conflict_count"]) > len(context.affected_paths)
            or not isinstance(msg.get("source_outcome"), str)
        ):
            raise RuntimeError("crossed or malformed folder sync commit receipt")
        if msg.get("ok") is not True or msg.get("durable") is not True:
            negative_root = msg.get("applied_root")
            if negative_root not in {None, ""} and not is_blob_hex(str(negative_root)):
                raise RuntimeError("malformed negative folder sync receipt")
            raise RuntimeError(
                "receiver could not commit folder sync: "
                + str(msg.get("reason") or "unverified")[:128]
            )
        if not is_blob_hex(str(msg.get("applied_root") or "")):
            raise RuntimeError("positive folder receipt has no applied root")
        source_outcome = str(msg["source_outcome"])
        conflict_count = int(msg["conflict_count"])
        if (
            source_outcome not in {"exact", "reconciled_conflict"}
            or (source_outcome == "exact" and conflict_count != 0)
            or (source_outcome == "reconciled_conflict" and conflict_count == 0)
        ):
            raise RuntimeError("folder receipt has an inconsistent source outcome")
        self.book.outbound.pop(key, None)
        verified = self._mapping("verified_outbound")
        verified[key] = self._monotonic()
        verified.move_to_end(key)
        self.prune()
        return context


def _verify_durable_folder_state(
    context: FolderSyncReceiptContext,
    storage: FolderVerificationStorage,
    deadline_monotonic: float,
) -> tuple[bool, str, str, str, int]:
    """Blocking durable proof; returns (ok, reason, applied_root, outcome, conflicts)."""

    missing = [blob_hash for blob_hash in context.wants if not storage.blobs.has(blob_hash)]
    if missing:
        return False, "requested_blob_not_durable", "", "unverified", 0
    materialized, materialize_reason, snapshot_root = storage.engine.verify_materialized_paths(
        folder_name=context.folder_name,
        paths=context.affected_paths,
        max_paths=FOLDER_SYNC_MANIFEST_MAX_ENTRIES,
        max_total_bytes=FOLDER_SYNC_VERIFY_MAX_BYTES,
        deadline_monotonic=deadline_monotonic,
    )
    if not materialized:
        return False, materialize_reason, "", "unverified", 0
    conflicts = 0
    for source_path, source_hash, source_clock_pairs in context.source_proofs:
        current = storage.state.get_manifest_entry(context.folder_name, source_path)
        if current is None:
            return False, "source_projection_missing", "", "unverified", 0
        current_clock = dict(current.get("vclock") or {})
        if any(int(current_clock.get(node, 0) or 0) < counter for node, counter in source_clock_pairs):
            return False, "source_projection_not_reconciled", "", "unverified", 0
        if current.get("blob_hash") != source_hash:
            conflicts += 1
    outcome = "exact" if conflicts == 0 else "reconciled_conflict"
    return True, "", snapshot_root, outcome, conflicts
