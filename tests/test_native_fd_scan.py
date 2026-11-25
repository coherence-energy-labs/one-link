"""Descriptor-bound native scans (cdc_fd, format_aware_fd) and the chunk-profile contract.

The *_fd exports scan exactly the bytes of a file the caller already opened and
verified, never reopening its pathname. They must equal the path and buffer
exports on the same bytes, enforce the declared length, ignore the caller's file
position, and keep reading the verified file if its pathname is replaced.

The profile witnesses (sizes FastCDC itself refuses) used to abort the process
or loop unboundedly; each now runs in a child interpreter so a regression fails
one test instead of killing the suite.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import textwrap
import zipfile

import pytest

chunk = pytest.importorskip("one_link_native.chunk")
PARAMS = (1024, 4096, 16384)
FD_EXPORTS = [
    ("cdc_fd", ()),
    ("cdc_fd_params", PARAMS),
    ("format_aware_fd", ("none",)),
    ("format_aware_fd_params", ("none", *PARAMS)),
]


def os_handle(handle) -> int:
    if sys.platform == "win32":
        import msvcrt

        return msvcrt.get_osfhandle(handle.fileno())
    return handle.fileno()


def _noise(size: int, seed: int = 0xFD5C) -> bytes:
    return random.Random(seed).randbytes(size)


def _mcap() -> bytes:
    magic = b"\x89MCAP0\r\n"
    records = [b"\x01" + struct.pack("<Q", 4) + b"ros2"]
    for size in (5000, 1, 20000, 100, 250000, 7000):
        records.append(b"\x05" + struct.pack("<Q", size) + _noise(size, size))
    return magic + b"".join(records) + magic


def _mp4() -> bytes:
    return b"".join(
        struct.pack(">I", size + 8) + kind + _noise(size, size)
        for kind, size in ((b"ftyp", 24), (b"moov", 14000), (b"mdat", 260000))
    )


def _wav() -> bytes:
    metadata = b"LIST" + struct.pack("<I", 12000) + _noise(12000)
    audio = b"data" + struct.pack("<I", 170001) + _noise(170001, 3) + b"\x00"
    body = b"WAVE" + metadata + audio
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _zip() -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for i, size in enumerate((17000, 2000, 80000, 120000)):
            info = zipfile.ZipInfo(f"entry-{i}.bin", date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, _noise(size, i))
    return target.getvalue()


CORPUS = {"mcap": _mcap, "mp4": _mp4, "wav": _wav, "zip": _zip, "none": lambda: _noise(300_000, 9)}


def _flat(boundaries) -> list[tuple]:
    return [
        (b.start, b.end, bytes(b.raw_address), getattr(b, "format_forced", None)) for b in boundaries
    ]


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_fd_export_equals_path_and_buffer_exports(tmp_path: Path, name: str):
    data = CORPUS[name]()
    path = tmp_path / f"sample.{name}"
    path.write_bytes(data)
    with path.open("rb") as handle:
        fd_default = chunk.format_aware_fd(os_handle(handle), len(data), name)
        fd_custom = chunk.format_aware_fd_params(os_handle(handle), len(data), name, *PARAMS)
        plain_fd = chunk.cdc_fd(os_handle(handle), len(data))
        plain_fd_custom = chunk.cdc_fd_params(os_handle(handle), len(data), *PARAMS)
    assert _flat(fd_default) == _flat(chunk.format_aware_file(str(path), name))
    assert _flat(fd_default) == _flat(chunk.format_aware_boundaries(data, name))
    assert _flat(fd_custom) == _flat(chunk.format_aware_file_params(str(path), name, *PARAMS))
    assert _flat(fd_custom) == _flat(chunk.format_aware_boundaries_params(data, name, *PARAMS))
    assert _flat(plain_fd) == _flat(chunk.cdc_file(str(path)))
    assert _flat(plain_fd_custom) == _flat(chunk.cdc_file_params(str(path), *PARAMS))
    assert fd_default and fd_default[-1].end == len(data)


def test_fd_scan_ignores_the_callers_file_position(tmp_path: Path):
    data = _mcap()
    path = tmp_path / "positioned.mcap"
    path.write_bytes(data)
    with path.open("rb") as handle:
        handle.seek(len(data) // 2)
        moved = chunk.format_aware_fd(os_handle(handle), len(data), "mcap")
        handle.seek(0)
        from_start = chunk.format_aware_fd(os_handle(handle), len(data), "mcap")
        handle.seek(0)
        assert handle.read() == data, "the caller's handle stays readable after a scan"
    assert _flat(moved) == _flat(from_start)


@pytest.mark.parametrize("name,args", FD_EXPORTS, ids=[entry[0] for entry in FD_EXPORTS])
def test_fd_scan_rejects_an_already_closed_positive_handle(tmp_path: Path, name: str, args):
    path = tmp_path / "closed.bin"
    data = _noise(4096)
    path.write_bytes(data)
    scan = getattr(chunk, name)
    with path.open("rb") as handle:
        raw = os_handle(handle)
        assert raw > 0
    # The integer remains after its owner's close. It must reach an OS error,
    # without first being assumed to represent a live borrowed Rust resource.
    with pytest.raises(OSError, match="cannot duplicate"):
        scan(raw, len(data), *args)


@pytest.mark.parametrize("name,args", FD_EXPORTS, ids=[entry[0] for entry in FD_EXPORTS])
def test_fd_scan_owns_only_its_duplicate_on_success_and_failure(tmp_path: Path, name: str, args):
    path = tmp_path / "owned.bin"
    data = _noise(32768)
    path.write_bytes(data)
    scan = getattr(chunk, name)
    with path.open("rb", buffering=0) as handle:
        raw = os_handle(handle)
        identity = os.fstat(handle.fileno())
        boundaries = scan(raw, len(data), *args)
        assert boundaries and boundaries[-1].end == len(data)
        handle.seek(0)
        assert handle.read() == data
        # Error propagation also drops only the duplicate, leaving the
        # caller's original file identity and ownership intact.
        with pytest.raises(OSError):
            scan(raw, len(data) + 1, *args)
        after = os.fstat(handle.fileno())
        assert (after.st_dev, after.st_ino) == (identity.st_dev, identity.st_ino)
        assert os_handle(handle) == raw
        handle.seek(0)
        assert handle.read() == data


@pytest.mark.parametrize("delta", [-1, 1, 4096])
def test_fd_scan_refuses_any_length_other_than_the_verified_size(tmp_path: Path, delta: int):
    data = _mp4()
    path = tmp_path / "sized.mp4"
    path.write_bytes(data)
    with path.open("rb") as handle:
        with pytest.raises(OSError):
            chunk.format_aware_fd(os_handle(handle), len(data) + delta, "mp4")
        with pytest.raises(OSError):
            chunk.cdc_fd(os_handle(handle), len(data) + delta)


def test_fd_scan_validates_arguments_before_touching_the_handle(tmp_path: Path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"x" * 5000)
    with path.open("rb") as handle:
        with pytest.raises(ValueError):
            chunk.format_aware_fd(os_handle(handle), 5000, "not-a-format")
        with pytest.raises(ValueError):
            chunk.cdc_fd_params(os_handle(handle), 5000, 1, 2, 4)
        with pytest.raises(ValueError):
            chunk.format_aware_fd_params(os_handle(handle), 5000, "mp4", 63, 256, 1024)
    # Negative values are never file descriptors, and on Windows they are
    # pseudo-handles (-1 the current process, -2 the current thread) that must
    # not be duplicated into a "file".
    for bad in (-1, -2, -7):
        with pytest.raises(ValueError):
            chunk.cdc_fd(bad, 10)
        with pytest.raises(ValueError):
            chunk.format_aware_fd(bad, 10, "mcap")
    if sys.platform == "win32":
        with pytest.raises(ValueError):
            chunk.cdc_fd(0, 10)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows refuses to replace a file opened without FILE_SHARE_DELETE")
def test_fd_scan_reads_the_verified_file_after_its_pathname_is_replaced(tmp_path: Path):
    original = _mcap()
    replacement = _noise(len(original), 77)
    path = tmp_path / "victim.mcap"
    path.write_bytes(original)
    with path.open("rb") as handle:
        swap = tmp_path / "swap.mcap"
        swap.write_bytes(replacement)
        os.replace(swap, path)
        through_handle = chunk.format_aware_fd(os_handle(handle), len(original), "mcap")
    assert _flat(through_handle) == _flat(chunk.format_aware_boundaries(original, "mcap"))
    assert _flat(chunk.format_aware_file(str(path), "mcap")) == _flat(
        chunk.format_aware_boundaries(replacement, "mcap")
    )


def test_witnessed_16_byte_mp4_is_one_plain_chunk_through_every_export(tmp_path: Path):
    data = bytes.fromhex("0000000166747970fffffffffffffffc")
    path = tmp_path / "hostile.mp4"
    path.write_bytes(data)
    expected = [(0, 16, False)]
    assert [(b.start, b.end, b.format_forced) for b in chunk.format_aware_boundaries(data, "mp4")] == expected
    assert [(b.start, b.end, b.format_forced) for b in chunk.format_aware_file(str(path), "mp4")] == expected
    with path.open("rb") as handle:
        got = chunk.format_aware_fd(os_handle(handle), len(data), "mp4")
    assert [(b.start, b.end, b.format_forced) for b in got] == expected


REFUSED_PROFILES = [(1, 2, 4), (63, 256, 1024), ((1 << 20) + 1, 2 << 20, 4 << 20), (64, 255, 1024), (64, 256, 1023)]


@pytest.mark.parametrize("profile", REFUSED_PROFILES)
def test_profiles_fastcdc_refuses_raise_valueerror_and_never_abort(tmp_path: Path, profile):
    target = tmp_path / "probe.bin"
    target.write_bytes(_noise(100, 5))
    script = textwrap.dedent(
        f"""
        import sys
        from one_link_native import chunk
        profile = {profile!r}
        path = {str(target)!r}
        data = open(path, "rb").read()
        calls = [
            lambda: list(chunk.cdc_iter_params(data, *profile)),
            lambda: chunk.format_aware_boundaries_params(data, "none", *profile),
            lambda: chunk.format_aware_boundaries_params(data, "mp4", *profile),
            lambda: chunk.cdc_file_params(path, *profile),
            lambda: chunk.format_aware_file_params(path, "mcap", *profile),
            lambda: chunk.format_aware_file_params(path, "zip", *profile),
        ]
        with open(path, "rb") as handle:
            if sys.platform == "win32":
                import msvcrt
                h = msvcrt.get_osfhandle(handle.fileno())
            else:
                h = handle.fileno()
            calls.append(lambda: chunk.cdc_fd_params(h, len(data), *profile))
            calls.append(lambda: chunk.format_aware_fd_params(h, len(data), "wav", *profile))
            refused = 0
            for call in calls:
                try:
                    call()
                except ValueError:
                    refused += 1
        print("refused", refused, "of", len(calls))
        sys.exit(0 if refused == len(calls) else 1)
        """
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr[-2000:])
    assert "refused 8 of 8" in proc.stdout
