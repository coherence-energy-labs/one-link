"""cdc_file scans in bounded parallel windows; its boundaries must equal cdc_iter's.

Guards the windowing edges: files smaller than one maximum chunk (a window
sized to the file fills before EOF is observed -- that once raised "file
scan made no progress"), files that straddle window and chunk-size
boundaries, and multi-window files.
"""
import os

import pytest

chunk = pytest.importorskip("one_link_native.chunk")
if not hasattr(chunk, "cdc_file"):
    pytest.skip("one_link_native without cdc_file", allow_module_level=True)

SIZES = [0, 1, 63, 64, 100, 8191, 8192, 8193, 65_535, 262_143, 262_144, 262_145,
         1_048_577, 5_000_000, (32 << 20) + 4097, (70 << 20) + 13]


@pytest.mark.parametrize("size", SIZES)
def test_cdc_file_matches_cdc_iter(tmp_path, size):
    data = os.urandom(size)
    path = tmp_path / f"f{size}.bin"
    path.write_bytes(data)
    streamed = [(b.start, b.end, bytes(b.raw_address)) for b in chunk.cdc_file(str(path))]
    in_memory = [(b.start, b.end, bytes(b.raw_address)) for b in chunk.cdc_iter(data)]
    assert streamed == in_memory
    assert sum(e - s for s, e, _ in streamed) == size


def test_cdc_file_on_low_entropy_multi_window_data(tmp_path):
    # all-zero runs force maximum-size chunks: the acceptance rule (a cut is
    # final only once it has seen max_size bytes) is exercised at every window
    data = bytes(40 << 20) + os.urandom(3 << 20) + bytes(5 << 20)
    path = tmp_path / "zeros.bin"
    path.write_bytes(data)
    assert [(b.start, b.end) for b in chunk.cdc_file(str(path))] == [
        (b.start, b.end) for b in chunk.cdc_iter(data)
    ]
