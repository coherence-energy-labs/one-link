"""The production descriptor scanner must preserve Python's byte contract."""
from __future__ import annotations

import io
import os
import random

import pytest

from one_link import cdc, native_cdc


@pytest.mark.parametrize("read_size", [7, 8192, 1024 * 1024])
@pytest.mark.parametrize("kind", ["empty", "random", "repetitive", "edited"])
def test_descriptor_native_matches_python_across_read_boundaries(
    monkeypatch, read_size, kind,
):
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC", raising=False)
    if native_cdc.get_native_cdc_scanner() is None:
        pytest.skip("native C scanner unavailable on this test host")
    payload = random.Random(20261124).randbytes(cdc.MAX_CHUNK_BYTES + 8193)
    if kind == "empty":
        payload = b""
    elif kind == "repetitive":
        payload = b"repeated payload" * 18000
    elif kind == "edited":
        payload = payload[:50000] + b"inserted" * 53 + payload[50000:]
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_CDC", "1")
    expected = cdc.index_file(io.BytesIO(payload), size=len(payload), read_size=read_size)
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC")
    handle = io.BytesIO(payload)
    handle.seek(len(payload))
    actual = cdc.index_file(handle, size=len(payload), read_size=read_size)
    assert actual == expected
    assert actual.engine == "native-c-gear"
    assert expected.engine == "python-gear"
    assert handle.tell() == 0


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("claimed_size", [2, 4])
def test_declared_size_mismatch_fails_for_both_engines(monkeypatch, native, claimed_size):
    if native:
        monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC", raising=False)
    else:
        monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_CDC", "1")
    if native and native_cdc.get_native_cdc_scanner() is None:
        pytest.skip("native C scanner unavailable on this test host")
    with pytest.raises(OSError, match="size changed"):
        cdc.index_file(io.BytesIO(b"abc"), size=claimed_size, read_size=2)


@pytest.mark.skipif(os.name == "nt", reason="Windows may deny replacing an open file")
def test_native_scans_original_descriptor_after_path_replacement(tmp_path, monkeypatch):
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC", raising=False)
    if native_cdc.get_native_cdc_scanner() is None:
        pytest.skip("native C scanner unavailable on this test host")
    path = tmp_path / "source.bin"
    original = random.Random(91).randbytes(400000)
    path.write_bytes(original)
    with path.open("rb") as handle:
        replacement = tmp_path / "replacement.bin"
        replacement.write_bytes(b"different file")
        replacement.replace(path)
        actual = cdc.index_file(handle, size=len(original), read_size=8192)
    assert actual.chunks == cdc.chunk_bytes(original)
    assert actual.size == len(original)
    assert actual.engine == "native-c-gear"


def test_native_scan_error_is_not_hidden_by_python_retry(monkeypatch):
    class BrokenScanner:
        def scan(self, *args, **kwargs):
            raise RuntimeError("scanner contract failure")

    monkeypatch.setattr(native_cdc, "get_native_cdc_scanner", lambda: BrokenScanner())
    with pytest.raises(RuntimeError, match="scanner contract failure"):
        cdc.index_file(io.BytesIO(b"abc"), size=3)


def test_read_seek_only_stream_retains_supported_python_fallback(monkeypatch):
    class ReadSeekOnly:
        def __init__(self, data):
            self.inner = io.BytesIO(data)

        def read(self, size=-1):
            return self.inner.read(size)

        def seek(self, offset):
            return self.inner.seek(offset)

    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC", raising=False)
    payload = random.Random(3).randbytes(100000)
    actual = cdc.index_file(ReadSeekOnly(payload), size=len(payload))
    assert actual.chunks == cdc.chunk_bytes(payload)
    assert actual.engine == "python-gear"
