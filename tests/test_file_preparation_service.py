"""Preparation contracts exercised without constructing or importing Daemon."""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest

from one_link.capabilities import FILE_CDC_BINARY_FRAME
from one_link.cdc import fixed_index_file, index_file
from one_link.file_preparation import (
    FileIndexers,
    FileIndexPolicy,
    FilePreparationService,
    PeerIndexProfile,
)
from one_link.file_source import DescriptorFileSource


class MemoryCache:
    """Minimal three-operation cache port; no unrelated State capabilities."""

    def __init__(self):
        self.rows = {}
        self.lookups = 0
        self.writes = 0
        self.source_writes = 0

    @staticmethod
    def key(sig):
        return tuple(sig[name] for name in DescriptorFileSource.signature_fields())

    def get_file_index_cache(self, **sig):
        self.lookups += 1
        return copy.deepcopy(self.rows.get(self.key(sig)))

    def record_file_index_cache(self, **row):
        self.writes += 1
        self.rows[self.key(row)] = copy.deepcopy(row)

    def record_chunk_sources_for_file(self, **row):
        self.source_writes += 1
        return len(row["chunks"])


class CountingIndexers:
    def __init__(self):
        self.cdc_calls = 0
        self.fixed_sizes = []

    def cdc(self, handle, *, size):
        self.cdc_calls += 1
        return index_file(handle, size=size)

    def fixed(self, handle, *, size, chunk_size):
        self.fixed_sizes.append(chunk_size)
        return fixed_index_file(handle, size=size, chunk_size=chunk_size)

    def port(self):
        return FileIndexers(cdc=self.cdc, fixed=self.fixed)


def source_file(tmp_path: Path) -> Path:
    source = tmp_path / "source.bin"
    source.write_bytes(bytes(range(256)) * 5000)
    return source


def test_service_uses_verified_cache_without_scanning_twice(tmp_path):
    path = source_file(tmp_path)
    cache = MemoryCache()
    indexers = CountingIndexers()
    service = FilePreparationService(cache=cache, indexers=indexers.port())
    first = service.prepare(path)
    second = service.prepare(path)
    assert first.file_index == second.file_index
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert indexers.cdc_calls == 1
    assert cache.writes == cache.source_writes == 1


def test_small_files_and_explicit_resume_boundaries_never_query_live_cadence(tmp_path):
    path = source_file(tmp_path)
    indexers = CountingIndexers()
    service = FilePreparationService(indexers=indexers.port())

    def forbidden():
        raise AssertionError("unneeded field access")

    assert service.prepare(path, cadence_provider=forbidden).index_kind == "cdc"
    assert (
        service.prepare(path, fixed_chunk_size=128 << 10, cadence_provider=forbidden).index_kind
        == "fixed:131072"
    )
    assert indexers.cdc_calls == 1
    assert indexers.fixed_sizes == [128 << 10]


def test_peer_cadence_and_explicit_retry_maps_remain_distinct(tmp_path):
    path = source_file(tmp_path)
    indexers = CountingIndexers()
    service = FilePreparationService(
        cache=MemoryCache(),
        indexers=indexers.port(),
        policy=FileIndexPolicy(large_file_threshold=0),
    )
    peer = PeerIndexProfile(features=(FILE_CDC_BINARY_FRAME,), cadence_bytes=250_000)
    first = service.prepare(path, peer=peer)
    assert first.index_kind == "fixed:250000"
    assert max(c.size for c in first.file_index.chunks) <= 250_000
    # Automatic tuning may reuse proven smaller chunks; an explicit retry is
    # an exact boundary contract and must re-index when its mode differs.
    relaxed = service.prepare(path, peer=PeerIndexProfile(features=peer.features))
    assert relaxed.cache_hit is True
    explicit = service.prepare(path, peer=peer, fixed_chunk_size=128 << 10)
    assert explicit.cache_hit is False
    assert explicit.index_kind == "fixed:131072"
    assert indexers.fixed_sizes == [250_000, 128 << 10]


@pytest.mark.parametrize("cadence", [None, True, False, -1, 1, 250_000])
def test_cadence_inputs_keep_the_fixed_floor_and_boolean_rule(tmp_path, cadence):
    path = source_file(tmp_path)
    service = FilePreparationService(policy=FileIndexPolicy(large_file_threshold=0))
    result = service.prepare(
        path,
        peer=PeerIndexProfile(features=(FILE_CDC_BINARY_FRAME,)),
        cadence_provider=lambda: cadence,
    )
    expected = 1 << 20 if cadence is None or isinstance(cadence, bool) else max(64 << 10, cadence)
    assert result.index_kind == f"fixed:{expected}"


@pytest.mark.parametrize(
    "field,value",
    [
        ("blob_hash", "+" + "0" * 63),
        ("size", 1),
        ("chunks", [{"index": 0, "start": 1, "end": 2, "hash": "0" * 64}]),
    ],
)
def test_corrupt_cache_rows_are_rejected_and_rebuilt(tmp_path, field, value):
    path = source_file(tmp_path)
    cache = MemoryCache()
    indexers = CountingIndexers()
    service = FilePreparationService(cache=cache, indexers=indexers.port())
    original = service.prepare(path)
    key = cache.key(original.signature)
    cache.rows[key][field] = value
    repaired = service.prepare(path)
    assert repaired.cache_hit is False
    assert repaired.file_index == original.file_index
    assert indexers.cdc_calls == 2


def test_weak_source_identity_never_authorizes_persistent_reuse(tmp_path):
    class WeakIdentity(DescriptorFileSource):
        def signature_from_handle(self, path, handle):
            signature = super().signature_from_handle(path, handle)
            signature["file_id"] = ""
            return signature

    cache = MemoryCache()
    indexers = CountingIndexers()
    service = FilePreparationService(cache=cache, source=WeakIdentity(), indexers=indexers.port())
    path = source_file(tmp_path)
    service.prepare(path)
    service.prepare(path)
    assert indexers.cdc_calls == 2
    assert cache.lookups == cache.writes == 0


def test_indexing_failure_closes_bound_descriptor_and_does_not_publish_cache(tmp_path):
    path = source_file(tmp_path)
    cache = MemoryCache()
    observed = []

    def fail(handle, *, size):
        observed.append(handle)
        assert not handle.closed
        assert size == path.stat().st_size
        raise OSError("injected index read failure")

    service = FilePreparationService(cache=cache, indexers=FileIndexers(cdc=fail))
    with pytest.raises(OSError, match="injected"):
        service.prepare(path)
    assert observed[0].closed
    assert cache.writes == cache.source_writes == 0


def test_missing_source_and_invalid_explicit_size_do_not_touch_cache(tmp_path):
    cache = MemoryCache()
    service = FilePreparationService(cache=cache)
    with pytest.raises(OSError):
        service.prepare(tmp_path / "missing")
    with pytest.raises(ValueError, match="resumable"):
        service.prepare(tmp_path / "missing", fixed_chunk_size=1)
    assert cache.lookups == cache.writes == 0


def test_services_can_load_without_the_daemon_or_server():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import one_link.file_preparation; import one_link.transfer_commit_guard; assert 'one_link.daemon' not in sys.modules; assert 'one_link.server' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
