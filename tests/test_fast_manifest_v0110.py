from pathlib import Path

import pytest

from one_link.cdc import fixed_index_path, hash_path, index_path
from one_link.state import State
from one_link.transfer_intent import (
    FileManifest,
    plan_transfer_intent_for_manifest,
)


def test_hash_path_matches_cdc_blob_without_chunking(tmp_path: Path):
    p = tmp_path / "movie.bin"
    p.write_bytes((b"frame-data-" * 4097) + b"tail")

    assert hash_path(p) == index_path(p).blob_hash


def test_fixed_index_path_is_deterministic_and_bounded(tmp_path: Path):
    p = tmp_path / "aligned.bin"
    p.write_bytes(bytes(range(251)) * 4096)

    a = fixed_index_path(p, chunk_size=8192, read_size=1024)
    b = fixed_index_path(p, chunk_size=8192, read_size=4096)

    assert a == b
    assert a.blob_hash == hash_path(p)
    assert all(0 <= c.size <= 8192 for c in a.chunks)
    assert sum(c.size for c in a.chunks) == a.size


def test_fixed_index_path_rejects_invalid_sizes(tmp_path: Path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"x")

    with pytest.raises(ValueError):
        fixed_index_path(p, chunk_size=0)
    with pytest.raises(ValueError):
        fixed_index_path(p, read_size=0)


def test_thin_manifest_plans_baseline_without_chunk_manifest(tmp_path: Path):
    p = tmp_path / "legacy-video.mp4"
    p.write_bytes(b"video" * 1024)
    manifest = FileManifest(
        name=p.name,
        size=p.stat().st_size,
        blob_hash=hash_path(p),
        chunks=(),
    )

    intent = plan_transfer_intent_for_manifest(
        manifest=manifest,
        path=p,
        peer_fp="aa" * 32,
        local_version="0.11.0",
        peer_version="0.6.0",
        peer_capabilities=["chat", "files"],
        intent_id="xfer-1",
    )

    assert intent.manifest.chunk_count == 0
    assert intent.can_offer_cdc is False
    assert intent.compatibility.transfer_mode == "baseline_file"
    assert intent.preferred_method == "file_baseline"


def test_file_index_cache_roundtrips_and_invalidates_on_stat_change(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        p = tmp_path / "movie.bin"
        p.write_bytes(b"abcdef")
        st = p.stat()
        chunks = [
            {
                "index": 0,
                "start": 0,
                "end": 6,
                "size": 6,
                "hash": hash_path(p),
            }
        ]
        state.record_file_index_cache(
            path=str(p.resolve()),
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            ctime_ns=st.st_ctime_ns,
            blob_hash=hash_path(p),
            index_kind="fixed",
            chunks=chunks,
        )

        cached = state.get_file_index_cache(
            path=str(p.resolve()),
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            ctime_ns=st.st_ctime_ns,
        )
        assert cached is not None
        assert cached["index_kind"] == "fixed"
        assert cached["chunks"] == chunks
        assert state.get_file_index_cache(
            path=str(p.resolve()),
            size=st.st_size + 1,
            mtime_ns=st.st_mtime_ns,
            ctime_ns=st.st_ctime_ns,
        ) is None
    finally:
        state.close()


def test_bulk_chunk_sources_for_file_roundtrip(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        p = tmp_path / "source.mov"
        p.write_bytes(b"abcdefghij")
        st = p.stat()
        chunks = [
            {
                "index": 0,
                "start": 0,
                "end": 5,
                "size": 5,
                "hash": "a" * 64,
            },
            {
                "index": 1,
                "start": 5,
                "end": 10,
                "size": 5,
                "hash": "b" * 64,
            },
        ]

        n = state.record_chunk_sources_for_file(
            path=str(p.resolve()),
            file_size=st.st_size,
            mtime_ms=int(st.st_mtime * 1000),
            chunks=chunks,
            source="file_index:fixed",
        )

        assert n == 2
        assert state.chunks_sourced(["a" * 64, "b" * 64]) == ["a" * 64, "b" * 64]
        src = state.get_chunk_sources("a" * 64)[0]
        assert src["path"] == str(p.resolve())
        assert src["start"] == 0
        assert src["size"] == 5
        assert src["source"] == "file_index:fixed"
    finally:
        state.close()


def test_chunk_sources_accept_size_only_end_only_and_skip_malformed(tmp_path: Path):
    """A chunk may describe its extent by `size` or by `end`; neither is required with the other.

    The size used to be read as c.get("size", int(c["end"]) - start), whose
    default is evaluated eagerly: a size-only chunk raised KeyError and was
    silently dropped from the source index.
    """
    state = State(db_path=tmp_path / "state.db")
    try:
        p = tmp_path / "source.bin"
        p.write_bytes(b"abcdefghijklmno")
        st = p.stat()
        chunks = [
            {"start": 0, "size": 5, "hash": "a" * 64},              # size only
            {"start": 5, "end": 10, "hash": "b" * 64},              # end only
            {"start": 10, "end": 15, "size": 5, "hash": "c" * 64},  # both
            {"start": 15, "hash": "d" * 64},                        # neither: malformed
            {"start": 0, "size": 0, "hash": "e" * 64},              # empty extent
        ]
        recorded = state.record_chunk_sources_for_file(
            path=str(p.resolve()), file_size=st.st_size, mtime_ms=int(st.st_mtime * 1000), chunks=chunks,
        )
        assert recorded == 3
        assert state.chunks_sourced([letter * 64 for letter in "abcde"]) == ["a" * 64, "b" * 64, "c" * 64]
        assert [state.get_chunk_sources(letter * 64)[0]["size"] for letter in "abc"] == [5, 5, 5]
        assert state.get_chunk_sources("a" * 64)[0]["start"] == 0
        assert state.get_chunk_sources("b" * 64)[0]["start"] == 5
    finally:
        state.close()
