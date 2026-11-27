"""Reusable file preparation through explicit filesystem, cache and policy ports.

The service is independent of daemon/session state. The daemon adapts a live
peer into a frozen PeerIndexProfile and supplies the current cache/indexers.
Only a descriptor-verified source may produce a reusable wire manifest.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Protocol

import blake3

from one_link.capabilities import FILE_CDC_BINARY_FRAME, FILE_SWARM, normalize_caps
from one_link.cdc import MAX_CHUNK_BYTES, Chunk, FileIndex, fixed_index_file, index_file
from one_link.file_source import DescriptorFileSource, FileSource

log = logging.getLogger(__name__)


class FileIndexCache(Protocol):
    """The cache/storage surface preparation needs, not the complete State API."""

    def get_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        dev: int | str = 0,
        ino: int | str = 0,
        file_id: str = "",
        change_ns: int | str = 0,
    ) -> dict | None: ...

    def record_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        blob_hash: str,
        index_kind: str,
        chunks: Iterable[dict],
        dev: int | str = 0,
        ino: int | str = 0,
        file_id: str = "",
        change_ns: int | str = 0,
        index_mode: str = "",
    ) -> None: ...

    def record_chunk_sources_for_file(
        self,
        *,
        path: str,
        file_size: int,
        mtime_ms: int,
        chunks: Iterable[dict],
        source: str = "file_index",
    ) -> int: ...


class CdcIndexer(Protocol):
    def __call__(self, handle: BinaryIO, *, size: int) -> FileIndex: ...


class FixedIndexer(Protocol):
    def __call__(self, handle: BinaryIO, *, size: int, chunk_size: int) -> FileIndex: ...


@dataclass(frozen=True)
class FileIndexers:
    cdc: CdcIndexer = index_file
    fixed: FixedIndexer = fixed_index_file


@dataclass(frozen=True)
class PeerIndexProfile:
    """Snapshot of the peer inputs that may affect a file's wire boundaries."""

    version: str | None = None
    features: tuple[str, ...] = ()
    cadence_bytes: int | None = None


@dataclass(frozen=True)
class FileIndexPolicy:
    large_file_threshold: int = 16 << 20
    fixed_min: int = 64 << 10
    chunk_max: int = 4 << 20
    modern_fixed: int = 1 << 20
    legacy_fixed: int = MAX_CHUNK_BYTES
    manifest_chunks_max: int = 262_144


@dataclass(frozen=True)
class PreparedFileIndex:
    """One descriptor-verified content identity and reusable wire manifest."""

    file_index: FileIndex
    signature: dict[str, Any]
    index_kind: str
    cache_hit: bool = False


def version_at_least(version: str | None, major: int, minor: int, patch: int) -> bool:
    if not version:
        return False
    try:
        nums = []
        for part in str(version).strip().lstrip("v").split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            nums.append(int(digits or 0))
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums[:3]) >= (major, minor, patch)
    except Exception:
        return False


def fixed_chunk_size_for_peer(
    peer_version: str | None,
    *,
    size: int = 0,
    policy: FileIndexPolicy = FileIndexPolicy(),
    peer_features: list[str] | tuple[str, ...] | set[str] | None = None,
) -> int:
    """Largest fixed-manifest chunk this peer can safely parse.

    v0.12.5 receivers accept up to STREAM_MAX_CHUNK_SIZE in FILE_OFFER
    manifests. Older receivers clamp CDC-ish offers around 512 KiB, so we use
    the classic 256 KiB chunk when version is unknown/older to preserve
    zero-chunk repeat sends instead of silently falling back to streaming.
    """

    features = set(normalize_caps(peer_features or ()))
    modern_peer = (
        version_at_least(peer_version, 0, 12, 5)
        or FILE_CDC_BINARY_FRAME in features
        or FILE_SWARM in features
    )
    if modern_peer:
        size = max(0, int(size or 0))
        if size >= 2 * 1024 * 1024 * 1024:
            return policy.chunk_max
        if size >= 512 * 1024 * 1024:
            return 2 * 1024 * 1024
        return policy.modern_fixed
    return policy.legacy_fixed


def _valid_hash(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


class FilePreparationService:
    """Own source proof, manifest selection and validated persistent reuse."""

    def __init__(
        self,
        *,
        cache: FileIndexCache | None = None,
        source: FileSource | None = None,
        indexers: FileIndexers = FileIndexers(),
        policy: FileIndexPolicy = FileIndexPolicy(),
    ) -> None:
        self.cache = cache
        self.source = source if source is not None else DescriptorFileSource()
        self.indexers = indexers
        self.policy = policy

    def cached_index(self, sig: dict) -> tuple[FileIndex, str] | None:
        if self.cache is None or not self.source.signature_is_strong(sig):
            return None
        try:
            row = self.cache.get_file_index_cache(**sig)
        except Exception as e:
            log.debug("file index cache lookup skipped for %s: %s", sig.get("path"), e)
            return None
        if not row:
            return None
        try:
            expected_size = int(sig["size"])
            if int(row["size"]) != expected_size:
                raise ValueError("cached file size does not match source identity")
            blob_hash = str(row["blob_hash"])
            if not _valid_hash(blob_hash):
                raise ValueError("cached whole-file hash is invalid")
            raw_chunks = row.get("chunks") or []
            if not isinstance(raw_chunks, list):
                raise ValueError("cached manifest is not a list")
            if not 1 <= len(raw_chunks) <= self.policy.manifest_chunks_max:
                raise ValueError("cached manifest count is outside protocol bounds")
            parsed_chunks: list[Chunk] = []
            running_end = 0
            for expected_index, raw_chunk in enumerate(raw_chunks):
                if not isinstance(raw_chunk, dict):
                    raise ValueError("cached manifest entry is not an object")
                index = int(raw_chunk["index"])
                start = int(raw_chunk["start"])
                end = int(raw_chunk["end"])
                chunk_hash = str(raw_chunk["hash"])
                if (
                    index != expected_index
                    or start != running_end
                    or start < 0
                    or end < start
                    or end > expected_size
                    or end - start > self.policy.chunk_max
                    or not _valid_hash(chunk_hash)
                ):
                    raise ValueError("cached manifest violates contiguous bounds")
                if expected_size > 0 and end == start:
                    raise ValueError("cached manifest has an empty data chunk")
                if expected_size == 0 and (
                    len(raw_chunks) != 1
                    or start != 0
                    or end != 0
                    or chunk_hash != blake3.blake3().hexdigest()
                ):
                    raise ValueError("cached empty-file manifest is invalid")
                parsed_chunks.append(
                    Chunk(
                        index=index,
                        start=start,
                        end=end,
                        hash=chunk_hash,
                    )
                )
                running_end = end
            if running_end != expected_size:
                raise ValueError("cached manifest does not cover the whole file")
            chunks = tuple(parsed_chunks)
            return (
                FileIndex(
                    blob_hash=blob_hash,
                    size=expected_size,
                    chunks=chunks,
                ),
                str(row.get("index_mode") or row.get("index_kind") or "unknown"),
            )
        except Exception as e:
            log.debug("file index cache decode skipped for %s: %s", sig.get("path"), e)
            return None

    def record_index(
        self,
        path: Path,
        file_index: FileIndex,
        *,
        index_kind: str,
        signature: dict[str, Any] | None = None,
    ) -> None:
        if self.cache is None:
            return
        try:
            sig = dict(signature or self.source.signature(path))
            if not self.source.signature_is_strong(sig):
                return
            if int(sig["size"]) != int(file_index.size):
                raise ValueError("file index size does not match source identity")
            chunk_rows = [
                {
                    "index": c.index,
                    "start": c.start,
                    "end": c.end,
                    "size": c.size,
                    "hash": c.hash,
                }
                for c in file_index.chunks
            ]
            self.cache.record_file_index_cache(
                **sig,
                blob_hash=file_index.blob_hash,
                index_kind=index_kind,
                index_mode=index_kind,
                chunks=chunk_rows,
            )
            if chunk_rows:
                self.cache.record_chunk_sources_for_file(
                    path=sig["path"],
                    file_size=int(sig["size"]),
                    mtime_ms=int(int(sig["mtime_ns"]) // 1_000_000),
                    chunks=chunk_rows,
                    source=f"file_index:{index_kind}",
                )
        except Exception as e:
            log.debug("file index cache write skipped for %s: %s", path, e)

    def prepare(
        self,
        path: Path,
        *,
        peer: PeerIndexProfile = PeerIndexProfile(),
        cadence_provider: Callable[[], int | None] | None = None,
        fixed_chunk_size: int | None = None,
    ) -> PreparedFileIndex:
        """Build or reuse one descriptor-verified hash + wire manifest.

        Large files use the peer-compatible fixed fast lane (one hash/index
        pass, typically 1 MiB chunks); smaller files retain CDC dedup. The
        exact strong identity is persisted so browser admission, durable queue,
        and live send can reuse this proof without another whole-file read.
        """

        explicit_fixed_chunk_size = fixed_chunk_size is not None
        if fixed_chunk_size is not None:
            fixed_chunk_size = int(fixed_chunk_size)
            if not self.policy.fixed_min <= fixed_chunk_size <= self.policy.chunk_max:
                raise ValueError("fixed_chunk_size is outside the resumable range")
        signature = self.source.signature(path)
        size = int(signature["size"])
        effective_fixed_chunk_size = fixed_chunk_size
        if effective_fixed_chunk_size is None and size >= self.policy.large_file_threshold:
            effective_fixed_chunk_size = fixed_chunk_size_for_peer(
                peer.version,
                size=size,
                peer_features=peer.features,
                policy=self.policy,
            )
            # Resolve the optional field input only when automatic fixed
            # sizing needs it. Small files and explicit resume maps never
            # invoke a live-field callback.
            try:
                raw = cadence_provider() if cadence_provider is not None else peer.cadence_bytes
                cadence = None if raw is None or isinstance(raw, bool) else int(raw)
            except (TypeError, ValueError, OverflowError):
                cadence = None
            if cadence is not None and cadence < effective_fixed_chunk_size:
                effective_fixed_chunk_size = max(self.policy.fixed_min, cadence)

        required_index_mode = (
            f"fixed:{effective_fixed_chunk_size}"
            if effective_fixed_chunk_size is not None
            else "cdc"
        )
        cached = self.cached_index(signature)
        cached_is_compatible = False
        if cached is not None and cached[0].chunks:
            if explicit_fixed_chunk_size:
                # A retry's explicit boundaries are its wire/resume contract.
                cached_is_compatible = cached[1] == required_index_mode
            elif effective_fixed_chunk_size is None:
                # Small-file cached CDC/fixed maps are both valid and avoid a
                # needless re-index solely because an older row used the
                # legacy public ``fixed`` mode label.
                cached_is_compatible = True
            else:
                # Automatic tuning is a maximum ratchet cadence, not a demand
                # to inflate already-proven smaller chunks.  Reuse any safe
                # manifest at or below the peer/field bound; reject a larger
                # one because it would violate negotiated framing or cadence.
                cached_is_compatible = (
                    cached[1] == required_index_mode
                    or max(int(chunk.size) for chunk in cached[0].chunks)
                    <= effective_fixed_chunk_size
                )
        if cached is not None and cached[0].chunks and cached_is_compatible:
            return PreparedFileIndex(cached[0], signature, cached[1], True)

        with self.source.open_verified(path, signature) as handle:
            if effective_fixed_chunk_size is not None:
                file_index = self.indexers.fixed(
                    handle,
                    size=size,
                    chunk_size=effective_fixed_chunk_size,
                )
                index_kind = f"fixed:{effective_fixed_chunk_size}"
            else:
                file_index = self.indexers.cdc(handle, size=size)
                index_kind = "cdc"
        self.record_index(
            path,
            file_index,
            index_kind=index_kind,
            signature=signature,
        )
        return PreparedFileIndex(file_index, signature, index_kind, False)
