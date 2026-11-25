"""Installed native file exports must preserve the in-memory format contract.

These are binding tests, not a claim that every production transfer chooses
format-aware FastCDC. The daemon's existing Gear-CDC format remains separate.
"""
from __future__ import annotations

import io
import struct
import zipfile

import pytest

chunk = pytest.importorskip("one_link_native.chunk")
PARAMS = (1024, 4096, 16384)


def _noise(size: int) -> bytes:
    # Deterministic corpus with enough variation to exercise natural cuts.
    import random

    return random.Random(0xC0E).randbytes(size)


def _mcap() -> bytes:
    magic = b"\x89MCAP0\r\n"
    records = [b"\x01" + struct.pack("<Q", 4) + b"ros2"]
    for size in (5000, 1, 20000, 100, 250000, 7000):
        records.append(b"\x05" + struct.pack("<Q", size) + _noise(size))
    return magic + b"".join(records) + magic


def _mp4() -> bytes:
    return b"".join(
        struct.pack(">I", size + 8) + kind + _noise(size)
        for kind, size in ((b"ftyp", 24), (b"moov", 14000), (b"mdat", 260000))
    )


def _wav() -> bytes:
    metadata = b"LIST" + struct.pack("<I", 12000) + _noise(12000)
    audio = b"data" + struct.pack("<I", 170001) + _noise(170001) + b"\x00"
    body = b"WAVE" + metadata + audio
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _h264() -> bytes:
    return b"".join(
        b"\x00\x00\x00\x01" + bytes([kind]) + b"\x55" * size
        for kind, size in ((7, 14000), (5, 45000), (1, 7000), (7, 25000), (5, 51000))
    )


def _zip() -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for i, size in enumerate((17000, 2000, 80000, 120000)):
            info = zipfile.ZipInfo(f"entry-{i}.bin", date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, _noise(size))
    return target.getvalue()


def _rows(boundaries):
    return [(b.start, b.end, bytes(b.raw_address), b.format_forced) for b in boundaries]


@pytest.mark.parametrize("name,make", [
    ("mcap", _mcap), ("mp4", _mp4), ("wav", _wav),
    ("h264", _h264), ("zip", _zip), ("none", lambda: _noise(300_007)),
])
@pytest.mark.parametrize("custom", [False, True])
def test_file_export_matches_buffer_boundaries_hashes_and_flags(tmp_path, name, make, custom):
    data = make()
    path = tmp_path / f"recording-{name}.bin"
    path.write_bytes(data)
    if custom:
        actual = chunk.format_aware_file_params(str(path), name, *PARAMS)
        expected = chunk.format_aware_boundaries_params(data, name, *PARAMS)
    else:
        actual = chunk.format_aware_file(str(path), name)
        expected = chunk.format_aware_boundaries(data, name)
    assert _rows(actual) == _rows(expected)
    assert actual[0].start == 0
    assert actual[-1].end == len(data)
    for boundary in actual:
        assert boundary.length == boundary.end - boundary.start
        assert bytes(boundary.raw_address) == chunk.chunk_address_raw(data[boundary.start:boundary.end])
        assert boundary.raw_address_hex() == boundary.raw_address.hex()
    if name != "none":
        assert any(boundary.format_forced for boundary in actual)


@pytest.mark.parametrize("name", ["mcap", "mp4", "wav", "h264", "zip", "none", "auto", ""])
@pytest.mark.parametrize("data", [b"", b"x", b"malformed container" * 1500])
def test_empty_tiny_and_nonmatching_files_preserve_buffer_fallback(tmp_path, name, data):
    path = tmp_path / "input.bin"
    path.write_bytes(data)
    assert _rows(chunk.format_aware_file(str(path), name)) == _rows(chunk.format_aware_boundaries(data, name))


@pytest.mark.parametrize("alias,canonical", [("MOV", "mp4"), ("m4v", "mp4"), ("annexb", "h264"), ("h264annexb", "h264")])
def test_format_aliases_work_through_the_file_export(tmp_path, alias, canonical):
    data = _mp4() if canonical == "mp4" else _h264()
    path = tmp_path / "input"
    path.write_bytes(data)
    assert _rows(chunk.format_aware_file(str(path), alias)) == _rows(chunk.format_aware_file(str(path), canonical))


@pytest.mark.parametrize("params", [(0, 4096, 16384), (4096, 1024, 16384), (1024, 16384, 4096), (1024, 4096, (16 << 20) + 1)])
def test_invalid_profiles_fail_before_the_file_is_opened(tmp_path, params):
    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(ValueError):
        chunk.format_aware_file_params(missing, "mcap", *params)
    with pytest.raises(ValueError):
        chunk.cdc_file_params(missing, *params)


def test_invalid_format_and_path_errors_have_distinct_types(tmp_path):
    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(ValueError, match="unsupported"):
        chunk.format_aware_file(missing, "unsupported-container")
    with pytest.raises(OSError):
        chunk.format_aware_file(missing, "mcap")
    with pytest.raises(OSError):
        chunk.cdc_file(missing)
    with pytest.raises(OSError):
        chunk.format_aware_file(str(tmp_path), "mcap")


def test_unicode_path_and_parameterized_plain_file(tmp_path):
    path = tmp_path / "recording-\u03bb-\u65e5\u672c.mcap"
    data = _mcap()
    path.write_bytes(data)
    assert _rows(chunk.format_aware_file(str(path), "mcap")) == _rows(chunk.format_aware_boundaries(data, "mcap"))
    actual = [(b.start, b.end, bytes(b.raw_address)) for b in chunk.cdc_file_params(str(path), *PARAMS)]
    expected = [(b.start, b.end, bytes(b.raw_address)) for b in chunk.cdc_iter_params(data, *PARAMS)]
    assert actual == expected


@pytest.mark.parametrize("name", ["zip", "h264"])
def test_whole_file_limit_refuses_sparse_file_without_silent_fallback(tmp_path, name):
    assert chunk.CDC_FILE_WINDOW_BYTES == 32 << 20
    assert chunk.FORMAT_AWARE_IN_MEMORY_LIMIT == 256 << 20
    path = tmp_path / "over-limit"
    with path.open("wb") as target:
        target.truncate(chunk.FORMAT_AWARE_IN_MEMORY_LIMIT + 1)
    with pytest.raises(ValueError, match="whole file in memory"):
        chunk.format_aware_file(str(path), name)
    with pytest.raises(ValueError, match="whole file in memory"):
        chunk.format_aware_file_params(str(path), name, *PARAMS)


def test_record_framed_file_crosses_the_real_32_mib_window(tmp_path):
    # One large MCAP record crosses the actual payload window. Avoid a
    # container-sized list of records and assert the full file/hash contract.
    payload = _noise((32 << 20) + 4097)
    magic = b"\x89MCAP0\r\n"
    data = magic + b"\x01" + struct.pack("<Q", 4) + b"ros2"
    data += b"\x05" + struct.pack("<Q", len(payload)) + payload + magic
    path = tmp_path / "large-record.mcap"
    path.write_bytes(data)
    assert _rows(chunk.format_aware_file(str(path), "mcap")) == _rows(chunk.format_aware_boundaries(data, "mcap"))
