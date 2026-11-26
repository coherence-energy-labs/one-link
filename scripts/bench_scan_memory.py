#!/usr/bin/env python3
"""Qualify the native file scanners' memory contract on multi-GB, dense and sparse files.

Contract under test (native/ol_chunk/FILE_SCANNING.md): peak memory of
``cdc_file`` / ``format_aware_file`` / ``*_fd`` is a bounded workspace plus
O(returned chunks), and never O(records) -- except the in-memory compatibility
APIs, which are not measured here.

Design. Dense (tiny records) and sparse (large records) MCAP logs of the same
size differ ~1000x in record count, and each is measured at several sizes. The
scanners treat the two differently on purpose: a sparse walk jumps from header
to header through a 64 KiB window, a dense walk reads sequentially through a
bounded sliding window. So each kind of log has its own fixed workspace, and
the model is

    peak = workspace[kind] + b_chunk * chunks + b_record * records

fitted per API. The fit decides the workspace and per-chunk clauses. It does
not decide the per-record clause: within one kind chunks and records both grow
with file size, and the kinds do not show one per-chunk cost (see the end of
this section), so no fit over these logs separates the two slopes at the ~1 MiB
the record limit needs (0.05 bytes over the 25 million records between 256 MiB
and 1 GiB is 1.2 MiB).

Records are separated by experiment instead. At the largest size a second
dense log, mcap-mid, has the same file size and larger records (512 bytes
against 32). Both take the dense walk, whose cuts fall about avg_size apart
whatever the record size, so the two logs return about the same number of
chunks (measured: within about 2%) for 16 times fewer records. With chunks
held nearly fixed, the difference between the two peaks is per-record memory:

    bytes_per_record = (peak[dense] - peak[mid] - chunk_cost * d_chunks) / d_records

Peaks are medians over a cell's repeats; d_chunks and d_records are dense
minus mid. chunk_cost is the dense log's own growth per returned chunk between
its smallest and largest size, with ALL of that growth attributed to chunks
and clipped to [0, 1024]; that over-credits chunks only through d_chunks. What
the pair can resolve is

    (2 * max(repeat spread of dense, of mid) + |d_chunks| * 1024) / d_records

so a pair whose chunk counts differ widely declares itself underpowered rather
than trusting a guessed chunk cost. The contract:

* every workspace[kind] is within the bound FILE_SCANNING.md declares for
  that code path;
* b_chunk is within the cost of one returned chunk;
* the dense/mid pair's bytes_per_record is at most 0.05: memory does not grow
  with the number of records;
* no single sample leaves the envelope  workspace bound + per-chunk cost.
* at each size, dense-minus-sparse peak, adjusted for returned chunks, is at
  most max(8 MiB, 10% of the larger raw peak). The adjustment uses only the
  same API's plain-file output slope, clipped to [0, 1024] bytes per chunk;
  a negative joint-fit coefficient cannot manufacture a density penalty.

A run whose pair cannot resolve one retained bit per record, or that has no
pair, is reported as underpowered and fails: it is not evidence either way,
so it gets that verdict alone, with its estimate shown.

What the pair does not see. It has one size, so a constant difference between
the 32-byte and the 512-byte walk is charged to records (1.1 MiB of it reaches
the limit at 768 MiB).

What the pair refuses to judge. Repeats rescan one file, so their spread
cannot see a difference between files, and there is one: measured on Windows,
the peak steps up by 0.1-0.4 MiB when the chunk count passes 4,096 and 16,384,
for 32- and 512-byte records alike. The cause is a hypothesis (the capacity of
the returned chunk list doubling); the step is measured. With a 64 KiB average
chunk a file of 2^k MiB returns about 2^n chunks, exactly where that capacity
doubles, so two logs of the same size land on opposite sides of a step for a
difference of a few dozen chunks. At 256 MiB and 1 GiB the pair read 0.01 to
0.04 bytes/record low with no per-record memory at all, several times the
resolution above and enough to pass a leak just over the limit. So a pair
whose two chunk counts lie on opposite sides of a power of two is
underpowered, whatever its spread. Sizes of 3 * 2^k MiB put the count midway
between doublings: at 192 and 768 MiB the pair read zero within its stated
resolution. CI measures those two, and the default sizes have the same form.

(An earlier model gave both kinds one shared intercept. When the dense walk
gained its own bounded window, that model attributed the constant difference
between the kinds to b_record and reported O(records) memory for a scanner
whose memory was flat across a 4x change in record count.)

(A later one read b_record off the joint fit, arguing that the plain log pins
b_chunk for every kind. Hosted CI at 4621947 measured otherwise. Median peak
growth from 256 MiB to 1 GiB per returned chunk, format_aware_fd: Linux dense
141 B, sparse 126, plain 31; Windows 155, 42, 106; macOS 210, 237, 195. The
dense walk grew 1.65-2.75 MiB while records grew by 25 million, and the sparse
walk, with 3 thousand records, grew as much per chunk on Linux and macOS: the
growth is the returned chunk list. The plain scan under-reports it, because
its 32 MiB window dominates the peak and is freed before the output list is
complete, and the sparse log's 0.1-0.4 MiB of growth is at allocator
granularity. With b_chunk pinned low by the plain log, the fit charged the
dense walk's remaining per-chunk growth to records: 0.0501 bytes/record on
Linux, a failure for a scanner with no per-record memory. The joint fit's
record coefficient is still reported, as a diagnostic that decides nothing.)

Each measurement runs in a fresh child process. Linux resets VmHWM immediately
before the native scan; Windows uses PeakWorkingSetSize and macOS uses
ru_maxrss with independently read current RSS. A lifetime peak that masks the
scan is inconclusive, not a zero-growth pass. Qualification requires a complete
grid of validated measurement-window records, the mcap-mid cell at the largest
size included; replay of older reports is diagnostic only. The workspace,
chunk, record, power, and density limits are unchanged.

Usage:
    python scripts/bench_scan_memory.py --sizes-mib 192,768,3072 --repeats 3 \
        --workdir <scratch dir on the disk to test> --report test-results/scan-memory.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import sys
import time
from typing import Any, Sequence

MCAP_MAGIC = b"\x89MCAP0\r\n"
MIB = 1 << 20
BATCH = 8 * MIB

# Declared bounds (native/ol_chunk/FILE_SCANNING.md, "Memory behavior"), with room
# for the interpreter and allocator around them.
#   windowed-stream: the plain-CDC payload window, max(32 MiB, 4 * max_size),
#     plus the parallel candidate workspace that window bounds.
#   record-walk: with the bounded native fix, 64 KiB segment batches and
#     64 KiB read-ahead bound the default header/batch capacities to 768/320
#     KiB. Long segments can still use the plain-CDC window; the existing
#     40 MiB qualification envelope remains unchanged.
# One returned chunk costs a Python Boundary object, its 32-byte address bytes
# object, a list slot and the Rust Vec entry it came from.
MAX_WORKSPACE_BYTES = {"windowed-stream": 48 * MIB, "record-walk": 40 * MIB}
MAX_BYTES_PER_CHUNK = 1024
MAX_BYTES_PER_RECORD = 0.05
DENSE_SPARSE_TOLERANCE = (8 * MIB, 0.10)
# The smallest per-record retention worth the name is one bit. A run whose
# dense/mid pair cannot resolve that proves nothing about records.
MIN_RESOLVABLE_BYTES_PER_RECORD = 0.125
# The pair that measures per-record memory: two dense logs of one size. The
# mid log is generated, and required, at the largest size only.
DENSE_KIND, MID_KIND = "mcap-dense", "mcap-mid"


def write_mcap(path: Path, size: int, record_bytes: int) -> int:
    """Write a valid MCAP v0 log of exactly ``size`` bytes; return its record count.

    Every record carries fresh random bytes, so the log has no period and no
    two records alike. An earlier generator tiled one 8 MiB batch and padded
    the end with up to 8 MiB of copies of a single record. Both were corpus
    artefacts that decided the measured peak: the period equalled the dense
    scanner's batch size, which locked its window into one of two states
    (about 16 or 24 MiB touched) for a whole file by where the first cut fell,
    and a run of identical records is the tie case that the scanner hands to
    plain CDC with a buffer of its own.
    """
    payload_len = record_bytes - 9
    record_head = b"\x05" + struct.pack("<Q", payload_len)
    records_per_batch = max(1, BATCH // record_bytes)
    header = b"\x01" + struct.pack("<Q", 4) + b"ros2"
    body_budget = size - len(MCAP_MAGIC) * 2 - len(header)
    records = 1
    with path.open("wb") as out:
        out.write(MCAP_MAGIC + header)
        remaining = body_budget
        while remaining >= record_bytes:
            count = min(records_per_batch, remaining // record_bytes)
            batch = bytearray(os.urandom(count * record_bytes))
            # Stamp the 9-byte record header over the start of each record.
            for offset, value in enumerate(record_head):
                batch[offset::record_bytes] = bytes([value]) * count
            out.write(batch)
            remaining -= count * record_bytes
            records += count
        if remaining >= 9:
            out.write(b"\x05" + struct.pack("<Q", remaining - 9) + os.urandom(remaining - 9))
            records += 1
        elif remaining:
            out.write(b"\x00" * remaining)  # opcode 0 ends the record walk; still exact size
        out.write(MCAP_MAGIC)
    actual = path.stat().st_size
    if actual != size:
        raise RuntimeError(f"generated {actual} bytes, wanted {size}")
    return records


def write_plain(path: Path, size: int) -> int:
    """Write ``size`` random bytes with no period (see write_mcap)."""
    with path.open("wb") as out:
        left = size
        while left:
            n = min(left, BATCH)
            out.write(os.urandom(n))
            left -= n
    return 0


def _linux_peak_and_current() -> tuple[int, int]:
    values: dict[str, int] = {}
    with open("/proc/self/status", encoding="ascii") as status:
        for line in status:
            key, _, value = line.partition(":")
            if key in {"VmHWM", "VmRSS"}:
                parts = value.split()
                if len(parts) != 2 or parts[1] != "kB":
                    raise RuntimeError("invalid Linux RSS counter units")
                values[key] = int(parts[0]) * 1024
    if set(values) != {"VmHWM", "VmRSS"}:
        raise RuntimeError("Linux RSS counters unavailable")
    return values["VmHWM"], values["VmRSS"]


def _peak_and_current() -> tuple[int, int]:
    if sys.platform.startswith("linux"):
        return _linux_peak_and_current()
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        psapi = ctypes.WinDLL("psapi")
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize), int(counters.WorkingSetSize)
    if sys.platform == "darwin":
        import resource
        import psutil

        # ru_maxrss is a lifetime maximum, in bytes on Darwin. It is
        # NOT current RSS. Import both modules before reading the baseline.
        current = psutil.Process().memory_info().rss
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(peak), int(current)
    raise RuntimeError(f"unsupported peak-memory platform: {sys.platform}")


def _start_peak_window() -> tuple[str, bool, int, int]:
    if sys.platform.startswith("linux"):
        # Linux exposes a resettable high-water counter; getrusage does not
        # reset with clear_refs. Use the same VmHWM metric on both sides.
        with open("/proc/self/clear_refs", "w", encoding="ascii") as refs:
            refs.write("5\n")
        counter, reset = "linux-vmhwm", True
    elif sys.platform == "win32":
        counter, reset = "windows-working-set", False
    elif sys.platform == "darwin":
        counter, reset = "darwin-rss", False
    else:
        raise RuntimeError(f"unsupported peak-memory platform: {sys.platform}")
    peak, current = _peak_and_current()
    return counter, reset, peak, current


def _peak_evidence(counter: str, reset: bool, before: int, current: int,
                   after: int, current_after: int) -> dict:
    return {
        "peak_counter": counter, "peak_reset": reset,
        "peak_before_bytes": before, "current_before_bytes": current,
        "peak_after_bytes": after, "current_after_bytes": current_after,
        "peak_delta_bytes": after - current,
        # If the prior maximum was not exceeded, the true peak over the
        # scan window lies somewhere between current and that old maximum.
        "masked_peak_uncertainty_bytes": before - current if after == before else 0,
    }


def _measurement_error(row: dict) -> str | None:
    counter = row.get("peak_counter")
    reset = row.get("peak_reset")
    if counter not in {"linux-vmhwm", "windows-working-set", "darwin-rss"}:
        return "missing or unknown peak counter"
    if type(reset) is not bool or reset != (counter == "linux-vmhwm"):
        return "invalid peak reset evidence"
    keys = ("peak_before_bytes", "current_before_bytes", "peak_after_bytes",
            "current_after_bytes", "peak_delta_bytes", "masked_peak_uncertainty_bytes")
    if any(type(row.get(k)) is not int or row[k] < 0 for k in keys):
        return "missing or invalid peak-window measurements"
    before, current, after, current_after, delta, masked = (row[k] for k in keys)
    if not (0 < current <= before <= after and 0 < current_after <= after):
        return "inconsistent resident-memory counters"
    if delta != after - current or masked != (before - current if before == after else 0):
        return "peak-window delta or masking evidence is inconsistent"
    if masked:
        return f"prior lifetime peak masks the scanner by up to {masked} bytes"
    return None


def child(api: str, path: str, fmt: str) -> None:
    from one_link_native import chunk  # imported before the baseline

    size = os.path.getsize(path)
    counter, reset, peak_before, current_before = _start_peak_window()
    started = time.perf_counter()
    # Boundary and FormatBoundary share start/end; only the latter has format_forced.
    result: Sequence[Any]
    if api == "format_aware_file":
        result = chunk.format_aware_file(path, fmt)
    elif api == "cdc_file":
        result = chunk.cdc_file(path)
    elif api == "format_aware_fd":
        with open(path, "rb") as handle:
            if sys.platform == "win32":
                import msvcrt

                h = msvcrt.get_osfhandle(handle.fileno())
            else:
                h = handle.fileno()
            result = chunk.format_aware_fd(h, size, fmt)
    else:
        raise SystemExit(f"unknown api {api}")
    elapsed = time.perf_counter() - started
    peak_after, current_after = _peak_and_current()
    if result[-1].end != size:
        raise SystemExit("scan did not cover the file")
    forced = sum(1 for b in result if getattr(b, "format_forced", False))
    print(json.dumps({
        "chunks": len(result), "forced_chunks": forced, "seconds": elapsed,
        **_peak_evidence(counter, reset, peak_before, current_before, peak_after, current_after),
    }))


def least_squares(columns: list[list[float]], y: list[float]) -> list[float]:
    """Coefficients of  y = sum(beta[k] * columns[k])  by column-scaled normal equations.

    Raises ValueError when the samples given cannot tell the columns apart
    (too few sizes, or one kind of log only).
    """
    k, n = len(columns), len(y)
    if n < k:
        raise ValueError(f"degenerate design: {n} samples cannot determine {k} coefficients")
    scale = [max(abs(v) for v in column) or 1.0 for column in columns]
    scaled = [[v / factor for v in column] for column, factor in zip(columns, scale)]
    m = [
        [sum(a * b for a, b in zip(scaled[i], scaled[j])) for j in range(k)]
        + [sum(a * b for a, b in zip(scaled[i], y))]
        for i in range(k)
    ]
    for col in range(k):
        pivot = max(range(col, k), key=lambda r: abs(m[r][col]))
        if abs(m[pivot][col]) < 1e-9 * n:
            raise ValueError(
                "degenerate design: measure at least two sizes, and dense and sparse logs, "
                "so chunks and records vary independently"
            )
        m[col], m[pivot] = m[pivot], m[col]
        for r in range(k):
            if r != col:
                f = m[r][col] / m[col][col]
                for c in range(col, k + 1):
                    m[r][c] -= f * m[col][c]
    return [m[i][k] / m[i][i] / scale[i] for i in range(k)]


def code_path(sample: dict) -> str:
    """Which scanner a sample exercised: the record walk, or the windowed plain-CDC stream.

    The two have different workspaces (the windowed stream keeps a 32 MiB
    payload window; the record walk scans one segment at a time), so they are
    given separate kind intercepts and workspace bounds.
    """
    if sample["api"] in ("format_aware_file", "format_aware_fd") and sample["kind"].startswith("mcap"):
        return "record-walk"
    return "windowed-stream"


def density_comparisons(api: str, rows: list[dict]) -> tuple[dict, list[dict], list[str]]:
    """Keep the original density limit using an independent output-cost estimate."""
    sizes = sorted(
        {r["size"] for r in rows if r["kind"] == "mcap-dense"}
        & {r["size"] for r in rows if r["kind"] == "mcap-sparse"}
    )
    if not sizes:
        return {}, [], []
    plain = [r for r in rows if r["kind"] == "plain"]
    calibration = {"source": "plain-only", "samples": len(plain)}
    if len({r["size"] for r in plain}) < 2:
        return calibration, [], [
            f"{api}: density comparison requires plain-file output calibration at two sizes"
        ]
    try:
        _, fitted_cost = least_squares(
            [[1.0] * len(plain), [float(r["chunks"]) for r in plain]],
            [float(r["peak_delta_bytes"]) for r in plain],
        )
    except ValueError as exc:
        return calibration, [], [f"{api}: density output calibration is underpowered: {exc}"]
    # Output objects cannot have negative cost. Do not let a noisy estimate
    # credit more than the contract's existing maximum per returned chunk.
    cost = min(float(MAX_BYTES_PER_CHUNK), max(0.0, fitted_cost))
    calibration.update({"fitted_bytes_per_chunk": fitted_cost, "applied_bytes_per_chunk": cost})
    pairs, failures = [], []
    for size in sizes:
        dense = [r for r in rows if r["kind"] == "mcap-dense" and r["size"] == size]
        sparse = [r for r in rows if r["kind"] == "mcap-sparse" and r["size"] == size]
        raw_d = statistics.median(r["peak_delta_bytes"] for r in dense)
        raw_s = statistics.median(r["peak_delta_bytes"] for r in sparse)
        adjusted = statistics.median(r["peak_delta_bytes"] - cost * r["chunks"] for r in dense) \
            - statistics.median(r["peak_delta_bytes"] - cost * r["chunks"] for r in sparse)
        limit = max(DENSE_SPARSE_TOLERANCE[0], DENSE_SPARSE_TOLERANCE[1] * max(raw_d, raw_s))
        pairs.append({
            "api": api, "path": code_path(dense[0]), "size": size,
            "dense_records": dense[0]["records"], "sparse_records": sparse[0]["records"],
            "dense_chunks": dense[0]["chunks"], "sparse_chunks": sparse[0]["chunks"],
            "dense_median": raw_d, "sparse_median": raw_s,
            "output_cost_bytes_per_chunk": cost, "chunk_adjusted_difference": adjusted, "limit": limit,
        })
        if adjusted > limit:
            failures.append(
                f"{api} @ {size / MIB:.0f} MiB: chunk-adjusted dense exceeds sparse by "
                f"{adjusted / MIB:.1f} MiB (limit {limit / MIB:.1f} MiB; plain-only output cost)"
            )
    return calibration, pairs, failures


def record_pair(api: str, rows: list[dict]) -> dict:
    """Per-record memory from the dense and mid logs of the largest size.

    The two logs have one file size and one scanner; they return about the
    same number of chunks and differ ~16x in records. So

        bytes_per_record = (peak[dense] - peak[mid] - chunk_cost * d_chunks) / d_records

    needs no model of what a chunk costs beyond the small d_chunks. For that
    term chunk_cost is the dense log's own growth per chunk between its
    smallest and largest size, all of it attributed to chunks, clipped to
    [0, MAX_BYTES_PER_CHUNK]. ``resolvable_bytes_per_record`` is what the pair
    can tell from zero: twice the larger repeat spread, plus the most that
    d_chunks chunks may cost, over d_records.

    That resolution assumes a chunk costs at most MAX_BYTES_PER_CHUNK more
    than the one before it. Measured, the peak steps by 0.1-0.4 MiB where the
    chunk count passes a power of two, and two logs on opposite sides of one
    differ by the step with no per-record memory. Such a pair is refused:
    ``straddles_power_of_two`` names the boundary.

    ``underpowered`` is None, or why this pair is no evidence about records.
    """
    largest = max(r["size"] for r in rows)
    pair: dict[str, Any] = {
        "api": api, "path": code_path({"api": api, "kind": DENSE_KIND}), "size": largest,
        "bytes_per_record": None, "resolvable_bytes_per_record": None, "underpowered": None,
    }
    dense_rows = [r for r in rows if r["kind"] == DENSE_KIND]
    dense = [r for r in dense_rows if r["size"] == largest]
    mid = [r for r in rows if r["kind"] == MID_KIND and r["size"] == largest]
    absent = [kind for kind, cell in ((DENSE_KIND, dense), (MID_KIND, mid)) if not cell]
    if absent:
        pair["underpowered"] = (f"no {' or '.join(absent)} log at the largest size ({largest / MIB:.0f} MiB), "
                                "so per-record memory was not measured")
        return pair
    smallest = min(r["size"] for r in dense_rows)
    small = [r for r in dense_rows if r["size"] == smallest]
    peak_dense, peak_mid, peak_small = (
        statistics.median(r["peak_delta_bytes"] for r in cell) for cell in (dense, mid, small)
    )
    spread_dense, spread_mid = (
        max(r["peak_delta_bytes"] for r in cell) - min(r["peak_delta_bytes"] for r in cell) for cell in (dense, mid)
    )
    d_records = dense[0]["records"] - mid[0]["records"]
    d_chunks = dense[0]["chunks"] - mid[0]["chunks"]
    growth_chunks = dense[0]["chunks"] - small[0]["chunks"]
    pair.update({
        "dense_records": dense[0]["records"], "mid_records": mid[0]["records"], "d_records": d_records,
        "dense_chunks": dense[0]["chunks"], "mid_chunks": mid[0]["chunks"], "d_chunks": d_chunks,
        "dense_median": peak_dense, "mid_median": peak_mid,
        "dense_repeat_spread_bytes": spread_dense, "mid_repeat_spread_bytes": spread_mid,
    })
    if d_records <= 0:
        pair["underpowered"] = "the mid log does not have fewer records than the dense log"
        return pair
    if growth_chunks <= 0:
        pair["underpowered"] = ("the dense log was not measured at a smaller size with fewer chunks, "
                                "so a returned chunk could not be costed")
        return pair
    fitted_cost = (peak_dense - peak_small) / growth_chunks
    # As in density_comparisons: output cannot cost less than nothing, and no
    # estimate may credit more than the contract allows one returned chunk.
    cost = min(float(MAX_BYTES_PER_CHUNK), max(0.0, fitted_cost))
    per_record = (peak_dense - peak_mid - cost * d_chunks) / d_records
    resolvable = (2.0 * max(spread_dense, spread_mid) + abs(d_chunks) * MAX_BYTES_PER_CHUNK) / d_records
    # floor(log2) of the two counts differs: a power of two lies between them
    # (a count exactly on one is past it).
    chunk_counts = (dense[0]["chunks"], mid[0]["chunks"])
    boundary = 1 << (max(chunk_counts).bit_length() - 1)
    straddles = chunk_counts[0].bit_length() != chunk_counts[1].bit_length()
    pair.update({
        "chunk_cost_source": "dense-growth", "chunk_cost_sizes": [smallest, largest],
        "fitted_bytes_per_chunk": fitted_cost, "applied_bytes_per_chunk": cost,
        "bytes_per_record": per_record, "resolvable_bytes_per_record": resolvable,
        "straddles_power_of_two": boundary if straddles else None,
    })
    if resolvable > MIN_RESOLVABLE_BYTES_PER_RECORD:
        pair["underpowered"] = (
            f"the dense/mid pair at {largest / MIB:.0f} MiB resolves only {resolvable:.3f} bytes/record "
            f"(repeat spread {max(spread_dense, spread_mid) / MIB:.2f} MiB, chunk counts differ by "
            f"{abs(d_chunks):,}, {d_records:,} fewer records; estimate {per_record:+.4f}); use a larger size, "
            "more repeats, or a mid record size whose chunk count matches the dense log's"
        )
    elif straddles:
        pair["underpowered"] = (
            f"the dense and mid logs at {largest / MIB:.0f} MiB returned {chunk_counts[0]:,} and "
            f"{chunk_counts[1]:,} chunks, on opposite sides of {boundary:,}: the peak steps there with no "
            f"per-record memory, and repeats of one file cannot see it (estimate {per_record:+.4f}); use sizes "
            "of the form 3*2^k MiB (192, 768), whose chunk counts fall midway between powers of two"
        )
    return pair


def evaluate(samples: list[dict]) -> dict:
    """Fit  peak = workspace[kind] + b_chunk*chunks + b_record*records  per API; test the contract.

    One API's samples are fitted together, each kind of log with its own
    workspace. The fit decides the workspace bounds and the per-chunk bound.
    Its b_record is reported as ``diagnostic_bytes_per_record`` and decides
    nothing: the per-record verdict comes from ``record_pair``.

    An earlier version let b_record decide, reasoning that a returned chunk
    costs the same whichever scanner produced it, so the plain log (thousands
    of chunks, no records) pins b_chunk and the dense log is left to speak
    about records. Measured, the plain log shows a lower per-chunk cost than
    the record walk does (hosted Linux: 31 against 141 bytes), and the fit
    charged the difference to records (module docstring).

    The mid log is fitted with its own workspace like every other kind, so
    that workspace is held to the record walk's bound. Measured at one size,
    it has no leverage on either slope: b_chunk and the diagnostic are the
    same with or without it.
    """
    verdicts: list[str] = []
    groups: dict[str, list[dict]] = {}
    for sample in samples:
        groups.setdefault(sample["api"], []).append(sample)
    fits = {}
    growth = []
    density_output_cost = {}
    density_pairs = []
    record_pairs = []
    for api, rows in sorted(groups.items()):
        label = api
        kinds = sorted({r["kind"] for r in rows})
        paths = {kind: code_path({"api": api, "kind": kind}) for kind in kinds}
        bounds = {kind: MAX_WORKSPACE_BYTES[paths[kind]] for kind in kinds}
        with_records = any(r["records"] for r in rows)
        columns = [[1.0 if r["kind"] == kind else 0.0 for r in rows] for kind in kinds]
        columns.append([float(r["chunks"]) for r in rows])
        if with_records:
            columns.append([float(r["records"]) for r in rows])
        beta = least_squares(columns, [float(r["peak_delta_bytes"]) for r in rows])
        workspace = dict(zip(kinds, beta))
        b_chunk = beta[len(kinds)]
        b_record = beta[len(kinds) + 1] if with_records else 0.0

        # Repeat spread: how far two measurements of the same file disagree.
        cells: dict[tuple[str, int], list[dict]] = {}
        for r in rows:
            cells.setdefault((r["kind"], r["size"]), []).append(r)
        spread = max(
            max(r["peak_delta_bytes"] for r in cell) - min(r["peak_delta_bytes"] for r in cell)
            for cell in cells.values()
        )
        fits[label] = {
            "workspace_bytes": workspace, "workspace_bound_bytes": bounds, "code_paths": paths,
            "bytes_per_chunk": b_chunk,
            # NOT the gate. The fit cannot separate records from chunks to the
            # precision the record limit needs; see dense_vs_mid.
            "diagnostic_bytes_per_record": b_record, "records_vary": with_records,
            "repeat_spread_bytes": spread, "samples": len(rows),
        }
        for kind, value in workspace.items():
            if value > bounds[kind]:
                verdicts.append(f"{label}: {kind} workspace {value / MIB:.1f} MiB exceeds the declared "
                                f"{bounds[kind] / MIB:.0f} MiB ({paths[kind]})")
        if b_chunk > MAX_BYTES_PER_CHUNK:
            verdicts.append(f"{label}: {b_chunk:.0f} bytes/chunk exceeds {MAX_BYTES_PER_CHUNK}")
        # One-sided: the contract forbids memory that GROWS with records. The
        # verdict rests on the dense/mid pair, never on b_record above. A pair
        # that is missing, cannot resolve one bit per record, or straddles a
        # power-of-two chunk count is no evidence either way, so it is
        # reported as that and as nothing else.
        if with_records:
            pair = record_pair(api, rows)
            record_pairs.append(pair)
            per_record = pair["bytes_per_record"]
            if pair["underpowered"]:
                verdicts.append(f"{label}: underpowered: {pair['underpowered']}")
            elif per_record > MAX_BYTES_PER_RECORD:
                verdicts.append(f"{label}: {per_record:.4f} bytes/record exceeds {MAX_BYTES_PER_RECORD} "
                                "(O(records) memory)")
        for r in rows:
            envelope = bounds[r["kind"]] + MAX_BYTES_PER_CHUNK * r["chunks"]
            if r["peak_delta_bytes"] > envelope:
                verdicts.append(f"{label}: sample at {r['size'] / MIB:.0f} MiB ({r['kind']}) used "
                                f"{r['peak_delta_bytes'] / MIB:.1f} MiB > envelope {envelope / MIB:.1f} MiB")
        # The same statement without a model, for a reader: what each kind's
        # peak did between its smallest and its largest file.
        for kind in kinds:
            sizes = sorted({r["size"] for r in rows if r["kind"] == kind})
            if len(sizes) < 2:
                continue
            small, large = cells[(kind, sizes[0])], cells[(kind, sizes[-1])]
            growth.append({
                "api": api, "path": paths[kind], "kind": kind, "smallest_size": sizes[0], "largest_size": sizes[-1],
                "records": [small[0]["records"], large[0]["records"]],
                "chunks": [small[0]["chunks"], large[0]["chunks"]],
                "median_peak_bytes": [statistics.median(r["peak_delta_bytes"] for r in small),
                                      statistics.median(r["peak_delta_bytes"] for r in large)],
            })
        calibration, pairs, failures = density_comparisons(api, rows)
        density_output_cost[api] = calibration
        density_pairs.extend(pairs)
        verdicts.extend(failures)
    return {"fits": fits, "growth": growth, "density_output_cost": density_output_cost,
            "dense_vs_sparse": density_pairs, "dense_vs_mid": record_pairs,
            "relative_throughput": relative_throughput(samples),
            "failures": verdicts, "passed": not verdicts}


def qualify(samples: list[dict], design: dict | None) -> dict:
    """Only complete, observed peak windows may promote the model to a pass."""
    errors: list[str] = []
    counters: set[str] = set()
    expected: set[tuple] = set()
    seen: set[tuple] = set()
    valid_apis = {"format_aware_file", "format_aware_fd", "cdc_file"}
    kinds = {DENSE_KIND, "mcap-sparse", "plain"}  # measured at every size
    if not isinstance(design, dict):
        errors.append("measurement design missing; historical report is diagnostic only")
    else:
        apis, sizes, repeats = (design.get(k) for k in ("apis", "sizes", "repeats"))
        if not (isinstance(apis, list) and bool(apis) and
                all(isinstance(x, str) and x in valid_apis for x in apis) and
                len(set(apis)) == len(apis) and isinstance(sizes, list) and len(sizes) >= 2 and
                all(type(x) is int and x > 0 for x in sizes) and len(set(sizes)) == len(sizes) and
                type(repeats) is int and repeats >= 2):
            errors.append("invalid or underpowered measurement design")
        else:
            # The grid is every kind at every size, plus the mid log at the
            # largest size: the cell the per-record verdict rests on.
            # Limit expected grid construction to the number of supplied rows.
            if len(apis) * (len(sizes) * len(kinds) + 1) * repeats != len(samples):
                errors.append("measurement grid has a missing or extra sample")
            else:
                expected = {(api, kind, size, rep) for api in apis for kind in kinds
                            for size in sizes for rep in range(repeats)}
                expected |= {(api, MID_KIND, max(sizes), rep) for api in apis for rep in range(repeats)}
    model_rows_valid = bool(samples)
    for i, row in enumerate(samples):
        if not isinstance(row, dict):
            errors.append(f"sample {i}: not an object")
            model_rows_valid = False
            continue
        api, kind = row.get("api"), row.get("kind")
        if not (isinstance(api, str) and api in valid_apis and
                isinstance(kind, str) and (kind in kinds or kind == MID_KIND) and
                all(type(row.get(k)) is int and row[k] >= 0 for k in
                    ("size", "records", "chunks", "repeat", "peak_delta_bytes")) and
                row["size"] > 0 and row["chunks"] > 0 and
                (row["records"] == 0 if kind == "plain" else row["records"] > 0)):
            errors.append(f"sample {i}: invalid model fields")
            model_rows_valid = False
            continue
        identity = (api, kind, row["size"], row["repeat"])
        if identity in seen:
            errors.append(f"sample {i}: duplicate measurement cell")
        seen.add(identity)
        error = _measurement_error(row)
        if error:
            errors.append(f"sample {i}: {error}")
        else:
            counters.add(row["peak_counter"])
        seconds = row.get("seconds")
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            errors.append(f"sample {i}: missing or invalid timing")
    if not samples:
        errors.append("no measurement samples")
    if expected != seen:
        errors.append("samples do not match the declared complete measurement grid")
    if len(counters) != 1:
        errors.append("no single validated memory counter covers the run")
    result = {"fits": {}, "growth": [], "density_output_cost": {}, "dense_vs_sparse": [],
              "dense_vs_mid": [], "relative_throughput": [], "failures": [], "passed": False}
    if model_rows_valid:
        try:
            result = evaluate(samples)
        except (ValueError, KeyError, TypeError, ArithmeticError) as exc:
            errors.append(f"model could not be evaluated: {exc}")
    result["measurement_failures"] = errors
    result["measurement_valid"] = not errors
    result["failures"] = [*result["failures"], *errors]
    result["passed"] = not result["failures"] and model_rows_valid
    return result


def relative_throughput(samples: list[dict]) -> list[dict]:
    """Scan speed of each kind of log against the plain log of the same size, in the same run.

    Reported, not gated. Memory is not the only thing a scanner's buffer sizes
    decide: smaller batches hash fewer segments in parallel. A memory limit
    with no cost beside it will always prefer the smallest buffer, so every
    run states what the current sizes cost in speed. The plain log is the
    control: it shares the machine, the file size and the page cache, and its
    scanner does not depend on those buffers. Absolute MiB/s on a shared
    runner means little; this ratio is comparable between runs.
    """
    timed = [s for s in samples if s.get("seconds")]
    cells: dict[tuple[str, int, str], list[float]] = {}
    for s in timed:
        cells.setdefault((s["api"], s["size"], s["kind"]), []).append(s["size"] / MIB / s["seconds"])
    rows = []
    for (api, size, kind), speeds in sorted(cells.items()):
        plain = cells.get((api, size, "plain"))
        if kind == "plain" or not plain:
            continue
        rows.append({
            "api": api, "size": size, "kind": kind,
            "median_mib_per_s": statistics.median(speeds),
            "plain_median_mib_per_s": statistics.median(plain),
            "ratio_to_plain": statistics.median(speeds) / statistics.median(plain),
        })
    return rows


def print_verdict(verdict: dict) -> None:
    for label, fit in verdict["fits"].items():
        spaces = "  ".join(f"{kind} {value / MIB:.1f}" for kind, value in fit["workspace_bytes"].items())
        print(f"fit {label}: workspace MiB [{spaces}]  {fit['bytes_per_chunk']:.0f} B/chunk  "
              f"(repeat spread {fit['repeat_spread_bytes'] / MIB:.2f} MiB; joint-fit diagnostic, not gated: "
              f"{fit['diagnostic_bytes_per_record']:.5f} B/record)")
    for pair in verdict["dense_vs_mid"]:
        if pair["bytes_per_record"] is None:
            print(f"  {pair['api']} {pair['size'] / MIB:.0f} MiB: dense-mid pair not measured: {pair['underpowered']}")
            continue
        print(f"  {pair['api']} {pair['size'] / MIB:.0f} MiB: dense-mid pair {pair['bytes_per_record']:+.5f} B/record "
              f"(limit {MAX_BYTES_PER_RECORD}; resolves {pair['resolvable_bytes_per_record']:.4f}"
              f"{', UNDERPOWERED' if pair['underpowered'] else ''}): "
              f"records {pair['dense_records']:,} vs {pair['mid_records']:,}, "
              f"chunks {pair['dense_chunks']:,} vs {pair['mid_chunks']:,}, "
              f"peak {pair['dense_median'] / MIB:.2f} vs {pair['mid_median'] / MIB:.2f} MiB, "
              f"{pair['applied_bytes_per_chunk']:.0f} B/chunk from dense growth")
    for g in verdict["growth"]:
        low, high = g["median_peak_bytes"]
        print(f"  {g['api']} {g['kind']}: {g['smallest_size'] / MIB:.0f} -> {g['largest_size'] / MIB:.0f} MiB, "
              f"records {g['records'][0]:,} -> {g['records'][1]:,}, chunks {g['chunks'][0]:,} -> {g['chunks'][1]:,}: "
              f"peak {low / MIB:.1f} -> {high / MIB:.1f} MiB")
    for pair in verdict["dense_vs_sparse"]:
        print(f"  {pair['api']} {pair['size'] / MIB:.0f} MiB: plain-only chunk-adjusted dense-sparse "
              f"{pair['chunk_adjusted_difference'] / MIB:+.2f} MiB (limit {pair['limit'] / MIB:.1f} MiB; "
              f"{pair['output_cost_bytes_per_chunk']:.1f} B/chunk)")
    for row in verdict["relative_throughput"]:
        print(f"  speed {row['api']} {row['kind']} {row['size'] / MIB:.0f} MiB: {row['median_mib_per_s']:.0f} MiB/s, "
              f"{row['ratio_to_plain']:.2f}x the plain log's {row['plain_median_mib_per_s']:.0f} (reported, not gated)")
    print("PASS" if verdict["passed"] else "FAIL: " + "; ".join(verdict["failures"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--child", nargs=3, metavar=("API", "PATH", "FORMAT"), help=argparse.SUPPRESS)
    # 3 * 2^k MiB: chunk counts midway between powers of two (module docstring).
    parser.add_argument("--sizes-mib", default="192,768,3072")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--dense-record-bytes", type=int, default=32)
    parser.add_argument("--mid-record-bytes", type=int, default=512,
                        help="record size of the mcap-mid log, written at the largest size only; it must take the "
                             "dense walk (stay below min_size) so that it returns about as many chunks as the dense log")
    parser.add_argument("--sparse-record-bytes", type=int, default=256 * 1024)
    parser.add_argument("--apis", default="format_aware_file,cdc_file,format_aware_fd")
    parser.add_argument("--workdir", type=Path, required=False)
    parser.add_argument("--report", type=Path, required=False)
    parser.add_argument("--evaluate", type=Path, help="re-evaluate the samples of a saved report")
    args = parser.parse_args(argv)
    if args.child:
        child(*args.child)
        return 0
    if args.evaluate:
        saved = json.loads(args.evaluate.read_text(encoding="utf-8"))
        verdict = qualify(saved["samples"], saved.get("design"))
        saved.update(verdict)
        out = args.report or args.evaluate
        out.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
        print_verdict(verdict)
        return 0 if verdict["passed"] else 1
    if args.workdir is None or args.report is None:
        parser.error("--workdir and --report are required")
    args.workdir.mkdir(parents=True, exist_ok=True)
    sizes = [int(x) * MIB for x in args.sizes_mib.split(",")]
    apis = args.apis.split(",")
    if (len(sizes) < 2 or len(set(sizes)) != len(sizes) or any(x <= 0 for x in sizes)
            or not apis or len(set(apis)) != len(apis)
            or any(a not in {"format_aware_file", "format_aware_fd", "cdc_file"} for a in apis)
            or args.repeats < 2
            or not 9 <= args.dense_record_bytes < args.mid_record_bytes < args.sparse_record_bytes):
        parser.error("qualification requires at least two distinct positive sizes, two repeats, "
                     "valid unique APIs, and record sizes with dense < mid < sparse")
    design = {"apis": apis, "sizes": sizes, "repeats": args.repeats}
    samples = []
    for size in sizes:
        kinds = [(DENSE_KIND, args.dense_record_bytes)]
        if size == max(sizes):
            # Straight after the dense log it is paired with.
            kinds.append((MID_KIND, args.mid_record_bytes))
        kinds += [("mcap-sparse", args.sparse_record_bytes), ("plain", 0)]
        for kind, record_bytes in kinds:
            path = args.workdir / f"scan-{kind}-{size // MIB}MiB.bin"
            t0 = time.perf_counter()
            records = write_plain(path, size) if kind == "plain" else write_mcap(path, size, record_bytes)
            gen_s = time.perf_counter() - t0
            try:
                for api in apis:
                    fmt = "none" if kind == "plain" else "mcap"
                    for rep in range(args.repeats):
                        proc = subprocess.run(
                            [sys.executable, __file__, "--child", api, str(path), fmt],
                            capture_output=True, text=True, timeout=3600,
                        )
                        if proc.returncode != 0:
                            raise RuntimeError(f"{api} {kind} {size}: {proc.stderr[-1500:]}")
                        row = json.loads(proc.stdout.strip().splitlines()[-1])
                        row.update({"api": api, "kind": kind, "size": size, "records": records, "repeat": rep})
                        samples.append(row)
                        print(
                            f"{api:18s} {kind:11s} {size / MIB:6.0f} MiB rec={records:>11,d} chunks={row['chunks']:>8,d} "
                            f"peak+{row['peak_delta_bytes'] / MIB:7.1f} MiB {size / MIB / row['seconds']:7.0f} MiB/s",
                            flush=True,
                        )
            finally:
                path.unlink(missing_ok=True)
            print(f"  generated {kind} {size / MIB:.0f} MiB in {gen_s:.1f}s", flush=True)
    verdict = qualify(samples, design)
    from one_link_native import __version__ as native_version  # type: ignore[attr-defined]

    report = {
        "schema": "one-link/scan-memory-qualification/v3",
        "design": design,
        "environment": {
            "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "python": sys.version.split()[0], "native_version": native_version, "cpus": os.cpu_count(),
        },
        "bounds": {"max_workspace_bytes": MAX_WORKSPACE_BYTES, "max_bytes_per_chunk": MAX_BYTES_PER_CHUNK,
                   "max_bytes_per_record": MAX_BYTES_PER_RECORD,
                   "dense_sparse_tolerance": DENSE_SPARSE_TOLERANCE,
                   "min_resolvable_bytes_per_record": MIN_RESOLVABLE_BYTES_PER_RECORD},
        "samples": samples,
        **verdict,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_verdict(verdict)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
