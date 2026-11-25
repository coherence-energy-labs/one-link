"""Content-defined chunking and dedup planning.

This is the One Link Python mirror of the OneField CDC-dedup transport
kernel. It does not change the wire protocol by itself; it gives folder sync
and future file transfer a deterministic way to split related files so peers
can exchange "which chunks do you already have?" before sending bytes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable

import blake3


MIN_CHUNK_BYTES = 16 * 1024
AVG_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 256 * 1024
_MASK_64 = (1 << 64) - 1
_BOUNDARY_MASK = AVG_CHUNK_BYTES - 1
_GEAR = tuple(
    int.from_bytes(blake3.blake3(bytes([i])).digest(length=8), "little")
    for i in range(256)
)


@dataclass(frozen=True)
class Chunk:
    """A content-defined byte range and its BLAKE3 digest."""

    index: int
    start: int
    end: int
    hash: str

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class FileIndex:
    """Whole-file BLAKE3 plus its CDC chunks."""

    blob_hash: str
    size: int
    chunks: tuple[Chunk, ...]
    # Execution provenance is not part of the content/resume identity.
    engine: str = field(default="unspecified", compare=False)


@dataclass(frozen=True)
class DedupPlan:
    """Which chunks need to cross the wire for a receiver's known hash set."""

    total_chunks: int
    missing_chunks: tuple[Chunk, ...]
    total_bytes: int
    bytes_to_send: int

    @property
    def hit_rate(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return 1.0 - (len(self.missing_chunks) / self.total_chunks)

    @property
    def byte_savings(self) -> int:
        return self.total_bytes - self.bytes_to_send


def _should_cut(chunk_len: int, rolling_hash: int) -> bool:
    if chunk_len < MIN_CHUNK_BYTES:
        return False
    if chunk_len >= MAX_CHUNK_BYTES:
        return True
    return (rolling_hash & _BOUNDARY_MASK) == 0


def chunk_bytes(data: bytes) -> tuple[Chunk, ...]:
    """Split bytes into deterministic content-defined chunks.

    Boundaries depend on content, not offset, so inserting bytes near the
    front of a file only shifts nearby chunks instead of invalidating the
    entire tail.
    """

    native = _chunk_bytes_native(data)
    if native is not None:
        return native

    chunks: list[Chunk] = []
    start = 0
    rolling = 0
    gear = _GEAR
    mask = _MASK_64

    for pos, b in enumerate(data):
        rolling = ((rolling << 1) + gear[b]) & mask

        end = pos + 1
        if _should_cut(end - start, rolling):
            chunks.append(_make_chunk(len(chunks), start, end, data))
            start = end
            rolling = 0

    # 2026-05-21 audit T3-S: skip the tail-chunk emission for empty
    # input. Without this, ``_chunk_bytes`` returned a single
    # zero-length chunk whose hash is the well-known
    # ``BLAKE3(b"")`` — a peer could poison the chunk cache by
    # claiming any blob "has" that hash. Zero-byte transfers are
    # represented as an empty chunk list and handled by the
    # caller's "transfer is empty" path.
    if start < len(data) or (not chunks and len(data) > 0):
        chunks.append(_make_chunk(len(chunks), start, len(data), data))
    return tuple(chunks)


def index_path(path: Path, *, read_size: int = 1024 * 1024) -> FileIndex:
    """Hash and CDC-index a file in one streaming pass.

    Payload buffering is bounded by the read window and chunk state; returned
    chunk metadata grows with the number of chunks. Live transfer uses the
    same scanner through ``index_file`` on its identity-bound descriptor.
    """

    with open(path, "rb") as handle:
        return index_file(
            handle,
            size=int(os.fstat(handle.fileno()).st_size),
            read_size=read_size,
        )


def index_file(
    handle: BinaryIO,
    *,
    size: int,
    read_size: int = 1024 * 1024,
) -> FileIndex:
    """Hash and CDC-index one already-open, identity-bound file handle.

    Native and Python engines use identical Gear parameters and boundaries.
    The native path consumes this descriptor directly; it never reopens its
    pathname or substitutes a different chunking algorithm.
    """

    if read_size <= 0:
        raise ValueError("read_size must be positive")
    expected_size = int(size)
    if expected_size < 0:
        raise ValueError("size must be non-negative")

    native = _index_file_native(handle, size=expected_size, read_size=read_size)
    if native is not None:
        return native

    chunks: list[Chunk] = []
    file_hasher = blake3.blake3()
    chunk_buf = bytearray()
    rolling = 0
    gear = _GEAR
    mask = _MASK_64
    offset = 0

    handle.seek(0)
    for part in iter(lambda: handle.read(read_size), b""):
        file_hasher.update(part)
        for b in part:
            rolling = ((rolling << 1) + gear[b]) & mask
            chunk_buf.append(b)
            if _should_cut(len(chunk_buf), rolling):
                end = offset + len(chunk_buf)
                chunks.append(
                    Chunk(
                        index=len(chunks),
                        start=offset,
                        end=end,
                        hash=blake3.blake3(chunk_buf).hexdigest(),
                    )
                )
                offset = end
                chunk_buf = bytearray()
                rolling = 0

    if chunk_buf or not chunks:
        end = offset + len(chunk_buf)
        chunks.append(
            Chunk(
                index=len(chunks),
                start=offset,
                end=end,
                hash=blake3.blake3(chunk_buf).hexdigest(),
            )
        )
    observed_size = offset + len(chunk_buf)
    if chunks:
        observed_size = chunks[-1].end
    if observed_size != expected_size:
        raise OSError("file size changed while building CDC index")
    handle.seek(0)
    return FileIndex(
        blob_hash=file_hasher.hexdigest(),
        size=expected_size,
        chunks=tuple(chunks),
        engine="python-gear",
    )


def hash_path(path: Path, *, read_size: int = 4 * 1024 * 1024) -> str:
    """Return the whole-file BLAKE3 hash without building a chunk index.

    This is the fast lane for peers that only support the baseline stream
    protocol. We still need a content identity for the durable transfer
    ledger, but we should not pay Python CDC's byte-by-byte rolling-hash cost
    when the receiver cannot use CDC chunks.
    """

    file_hasher = blake3.blake3()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(read_size), b""):
            file_hasher.update(part)
    return file_hasher.hexdigest()


def fixed_index_path(
    path: Path,
    *,
    chunk_size: int = MAX_CHUNK_BYTES,
    read_size: int = 4 * 1024 * 1024,
) -> FileIndex:
    """Hash a file into fixed-size chunks with bounded memory.

    Fixed manifests are not a replacement for CDC when a file has inserted or
    deleted bytes, but they are dramatically cheaper for brand-new large media
    sends and for peers that already share exact aligned blocks. This gives the
    transfer planner a high-throughput lane while CDC remains available for
    true prior-knowledge drift.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if read_size <= 0:
        raise ValueError("read_size must be positive")

    with open(path, "rb") as handle:
        return fixed_index_file(
            handle,
            size=int(os.fstat(handle.fileno()).st_size),
            chunk_size=chunk_size,
            read_size=read_size,
        )


def fixed_index_file(
    handle: BinaryIO,
    *,
    size: int,
    chunk_size: int = MAX_CHUNK_BYTES,
    read_size: int = 4 * 1024 * 1024,
) -> FileIndex:
    """Build a fixed manifest from one already-open, stable file handle."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if read_size <= 0:
        raise ValueError("read_size must be positive")
    expected_size = int(size)
    if expected_size < 0:
        raise ValueError("size must be non-negative")

    chunks: list[Chunk] = []
    file_hasher = blake3.blake3()
    chunk_buf = bytearray()
    offset = 0

    def flush() -> None:
        nonlocal chunk_buf, offset
        if not chunk_buf and chunks:
            return
        end = offset + len(chunk_buf)
        chunks.append(
            Chunk(
                index=len(chunks),
                start=offset,
                end=end,
                hash=blake3.blake3(chunk_buf).hexdigest(),
            )
        )
        offset = end
        chunk_buf = bytearray()

    handle.seek(0)
    for part in iter(lambda: handle.read(read_size), b""):
        file_hasher.update(part)
        view = memoryview(part)
        pos = 0
        while pos < len(view):
            take = min(chunk_size - len(chunk_buf), len(view) - pos)
            chunk_buf.extend(view[pos: pos + take])
            pos += take
            if len(chunk_buf) == chunk_size:
                flush()

    if chunk_buf or not chunks:
        flush()
    observed_size = chunks[-1].end if chunks else 0
    if observed_size != expected_size:
        raise OSError("file size changed while building fixed index")
    handle.seek(0)
    return FileIndex(
        blob_hash=file_hasher.hexdigest(),
        size=expected_size,
        chunks=tuple(chunks),
        engine="python-fixed",
    )


def chunk_path(path: Path, *, read_size: int = 1024 * 1024) -> tuple[Chunk, ...]:
    """Chunk a file from disk with bounded memory."""

    return index_path(path, read_size=read_size).chunks


def build_dedup_plan(chunks: Iterable[Chunk], receiver_hashes: set[str]) -> DedupPlan:
    materialized = tuple(chunks)
    missing = tuple(c for c in materialized if c.hash not in receiver_hashes)
    return DedupPlan(
        total_chunks=len(materialized),
        missing_chunks=missing,
        total_bytes=sum(c.size for c in materialized),
        bytes_to_send=sum(c.size for c in missing),
    )


def _make_chunk(index: int, start: int, end: int, data: bytes) -> Chunk:
    return Chunk(
        index=index,
        start=start,
        end=end,
        hash=blake3.blake3(data[start:end]).hexdigest(),
    )


def _chunk_bytes_native(data: bytes) -> tuple[Chunk, ...] | None:
    try:
        from .native_cdc import get_native_cdc_scanner

        scanner = get_native_cdc_scanner()
        if scanner is None:
            return None
        buf = bytearray(data)
        cuts, rolling, chunk_len = scanner.scan(
            buf,
            length=len(buf),
            initial_rolling=0,
            initial_chunk_len=0,
            min_chunk=MIN_CHUNK_BYTES,
            max_chunk=MAX_CHUNK_BYTES,
            boundary_mask=_BOUNDARY_MASK,
        )
        _ = rolling, chunk_len
        chunks: list[Chunk] = []
        start = 0
        for cut in cuts:
            chunks.append(_make_chunk(len(chunks), start, cut, data))
            start = cut
        # 2026-05-21 audit T3-S: same empty-input fix as the Python
        # path. Empty input → empty chunk tuple, not a single
        # zero-length chunk with the trivially-constructible
        # ``BLAKE3(b"")`` hash.
        if start < len(data) or (not chunks and len(data) > 0):
            chunks.append(_make_chunk(len(chunks), start, len(data), data))
        return tuple(chunks)
    except Exception:
        return None


def _index_path_native(path: Path, *, read_size: int) -> FileIndex | None:
    """Compatibility wrapper; file identity and length come from one open."""
    if read_size <= 0:
        return None
    with open(path, "rb") as handle:
        return _index_file_native(
            handle, size=int(os.fstat(handle.fileno()).st_size), read_size=read_size,
        )


def _index_file_native(
    handle: BinaryIO, *, size: int, read_size: int,
) -> FileIndex | None:
    """Stream the verified C scanner over an already-open descriptor.

    Only unavailable acceleration selects Python. Once scanning starts, IO or
    contract errors propagate rather than being hidden by a second scan.
    Rolling state and the chunk hasher span read boundaries without retaining
    or rescanning a pending chunk. Memory is O(read_size + output chunks).
    """
    try:
        from .native_cdc import get_native_cdc_scanner
        scanner = get_native_cdc_scanner()
    except (ImportError, OSError, RuntimeError):
        return None
    if scanner is None:
        return None
    readinto = getattr(handle, "readinto", None)
    if not callable(readinto):
        # BinaryIO's public read/seek contract also permits wrapper streams
        # without readinto. They retain the Python path without consuming data.
        return None
    chunks: list[Chunk] = []
    file_hasher = blake3.blake3()
    chunk_hasher = blake3.blake3()
    buf = bytearray(read_size)
    absolute = 0
    chunk_start = 0
    rolling = 0
    chunk_len = 0
    handle.seek(0)
    while True:
        n = readinto(buf)
        if n is None or n < 0 or n > len(buf):
            raise OSError("invalid read length while building CDC index")
        if not n:
            break
        if absolute + n > size:
            raise OSError("file size changed while building CDC index")
        view = memoryview(buf)[:n]
        file_hasher.update(view)
        cuts, rolling, chunk_len = scanner.scan(
            buf, length=n, initial_rolling=rolling, initial_chunk_len=chunk_len,
            min_chunk=MIN_CHUNK_BYTES, max_chunk=MAX_CHUNK_BYTES,
            boundary_mask=_BOUNDARY_MASK,
        )
        segment_start = 0
        for cut in cuts:
            if cut <= segment_start or cut > n:
                raise RuntimeError(f"native CDC returned invalid cut {cut}")
            chunk_hasher.update(view[segment_start:cut])
            end = absolute + cut
            chunks.append(
                Chunk(
                    index=len(chunks), start=chunk_start, end=end,
                    hash=chunk_hasher.hexdigest(),
                )
            )
            chunk_start = end
            chunk_hasher = blake3.blake3()
            segment_start = cut
        if segment_start < n:
            chunk_hasher.update(view[segment_start:n])
        absolute += n
    if absolute != size:
        raise OSError("file size changed while building CDC index")
    if chunk_len or not chunks:
        chunks.append(
            Chunk(
                index=len(chunks), start=chunk_start, end=absolute,
                hash=chunk_hasher.hexdigest(),
            )
        )
    handle.seek(0)
    return FileIndex(
        blob_hash=file_hasher.hexdigest(), size=absolute, chunks=tuple(chunks),
        engine="native-c-gear",
    )
