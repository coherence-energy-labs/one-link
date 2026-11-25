#!/usr/bin/env python3
"""Qualify the native file scanners' memory contract on multi-GB, dense and sparse files.

Contract under test (native/ol_chunk/FILE_SCANNING.md): peak memory of
``cdc_file`` / ``format_aware_file`` / ``*_fd`` is a bounded workspace plus
O(returned chunks), and never O(records) -- except the in-memory compatibility
APIs, which are not measured here.

Design. Dense (tiny records) and sparse (large records) MCAP logs of the same
size produce about the same number of chunks (forced cuts closer than the
minimum chunk are absorbed) but differ ~1000x in record count. So:

* records-independence: at every size, peak(dense) - peak(sparse) must be
  within noise, although dense holds ~1000x more records;
* a least-squares fit  peak = a + b_chunk * chunks + b_record * records  over
  every sample must give b_record ~ 0 and b_chunk within the per-chunk object
  cost, with intercept a within the declared workspace.

Each measurement runs in a fresh child process and reports its own peak
resident memory (Windows PeakWorkingSetSize, POSIX ru_maxrss) relative to its
resident memory just before the call, so samples cannot contaminate each other.

Usage:
    python scripts/bench_scan_memory.py --sizes-mib 256,1024,4096 --repeats 3 \
        --workdir <scratch dir on the disk to test> --report test-results/scan-memory.json
"""

from __future__ import annotations

import argparse
import json
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

# First-principles bounds (see FILE_SCANNING.md). Workspace: the 32 MiB payload
# window plus parallel-CDC candidate workspace bounded by that window and a
# 64 KiB header read-ahead; one returned chunk costs a Python Boundary object, its
# 32-byte address bytes object, a list slot and the Rust Vec entry it came from.
MAX_INTERCEPT_BYTES = 160 * MIB
MAX_BYTES_PER_CHUNK = 1024
MAX_BYTES_PER_RECORD = 0.05
DENSE_SPARSE_TOLERANCE = (8 * MIB, 0.10)  # absolute floor, fraction of peak


def write_mcap(path: Path, size: int, record_bytes: int) -> int:
    """Write a valid MCAP v0 log of exactly ``size`` bytes; return its record count."""
    payload_len = record_bytes - 9
    block = os.urandom(4 * MIB)
    one = bytearray()
    records_per_batch = max(1, BATCH // record_bytes)
    for i in range(records_per_batch):
        off = (i * 7919) % (len(block) - payload_len)
        one += b"\x05" + struct.pack("<Q", payload_len) + block[off : off + payload_len]
    batch = bytes(one)
    header = b"\x01" + struct.pack("<Q", 4) + b"ros2"
    body_budget = size - len(MCAP_MAGIC) * 2 - len(header)
    records = 1
    with path.open("wb") as out:
        out.write(MCAP_MAGIC + header)
        written = 0
        while written + len(batch) <= body_budget:
            out.write(batch)
            written += len(batch)
            records += records_per_batch
        remaining = body_budget - written
        while remaining >= record_bytes:
            out.write(batch[:record_bytes])
            remaining -= record_bytes
            written += record_bytes
            records += 1
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
    block = os.urandom(BATCH)
    with path.open("wb") as out:
        left = size
        while left:
            n = min(left, len(block))
            out.write(block[:n])
            left -= n
    return 0


def _peak_and_current() -> tuple[int, int]:
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
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak = peak if sys.platform == "darwin" else peak * 1024
    current = peak
    try:
        with open("/proc/self/statm", encoding="ascii") as statm:
            current = int(statm.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except OSError:
        pass
    return int(peak), int(current)


def child(api: str, path: str, fmt: str) -> None:
    from one_link_native import chunk  # imported before the baseline

    size = os.path.getsize(path)
    peak_before, current_before = _peak_and_current()
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
    peak_after, _ = _peak_and_current()
    if result[-1].end != size:
        raise SystemExit("scan did not cover the file")
    forced = sum(1 for b in result if getattr(b, "format_forced", False))
    print(json.dumps({
        "chunks": len(result), "forced_chunks": forced, "seconds": elapsed,
        "peak_delta_bytes": peak_after - current_before,
        "peak_before_bytes": peak_before, "current_before_bytes": current_before, "peak_after_bytes": peak_after,
    }))


def lstsq3(rows: list[tuple[float, float, float]]) -> tuple[float, float, float]:
    """Least squares for y = a + b*x1 + c*x2 via the 3x3 normal equations."""
    n = len(rows)
    s = [[0.0] * 3 for _ in range(3)]
    t = [0.0] * 3
    for x1, x2, y in rows:
        v = (1.0, x1, x2)
        for i in range(3):
            t[i] += v[i] * y
            for j in range(3):
                s[i][j] += v[i] * v[j]
    if n < 3:
        raise ValueError("need at least three samples")
    m = [row[:] + [t[i]] for i, row in enumerate(s)]
    for col in range(3):
        pivot = max(range(col, 3), key=lambda r: abs(m[r][col]))
        if abs(m[pivot][col]) < 1e-12:
            raise ValueError("degenerate design: vary chunks and records independently")
        m[col], m[pivot] = m[pivot], m[col]
        for r in range(3):
            if r != col:
                f = m[r][col] / m[col][col]
                for c in range(col, 4):
                    m[r][c] -= f * m[col][c]
    return tuple(m[i][3] / m[i][i] for i in range(3))  # type: ignore[return-value]


def lstsq2(rows: list[tuple[float, float]]) -> tuple[float, float]:
    """Least squares for y = a + b*x."""
    n = len(rows)
    if n < 2:
        raise ValueError("need at least two samples")
    mx = sum(x for x, _ in rows) / n
    my = sum(y for _, y in rows) / n
    sxx = sum((x - mx) ** 2 for x, _ in rows)
    if sxx == 0:
        raise ValueError("degenerate design: chunk counts do not vary")
    b = sum((x - mx) * (y - my) for x, y in rows) / sxx
    return my - b * mx, b


def code_path(sample: dict) -> str:
    """Which scanner a sample exercised: the record walk, or the windowed plain-CDC stream.

    The two have different workspaces (the windowed stream keeps a 32 MiB
    payload window; the record walk scans one segment at a time), so they are
    fitted separately -- pooling them mis-specifies the intercept.
    """
    if sample["api"] in ("format_aware_file", "format_aware_fd") and sample["kind"].startswith("mcap"):
        return "record-walk"
    return "windowed-stream"


def evaluate(samples: list[dict]) -> dict:
    """Fit memory per (api, code path) and test the contract.

    The dense-versus-sparse comparison is CHUNK-ADJUSTED: format-aware chunking
    can return different chunk counts for dense and sparse logs of one size,
    and per-chunk output is allowed. Memory that grew with records would
    survive the adjustment (dense holds ~1000x more records) and fail here.
    """
    verdicts: list[str] = []
    groups: dict[tuple[str, str], list[dict]] = {}
    for s in samples:
        groups.setdefault((s["api"], code_path(s)), []).append(s)
    fits = {}
    for (api, path), rows in sorted(groups.items()):
        label = f"{api}/{path}"
        records_vary = len({r["records"] for r in rows}) > 1 and any(r["records"] for r in rows)
        if records_vary:
            a, b_chunk, b_record = lstsq3([(r["chunks"], r["records"], r["peak_delta_bytes"]) for r in rows])
        else:
            a, b_chunk = lstsq2([(r["chunks"], r["peak_delta_bytes"]) for r in rows])
            b_record = 0.0
        fits[label] = {"intercept_bytes": a, "bytes_per_chunk": b_chunk, "bytes_per_record": b_record,
                       "records_vary": records_vary, "samples": len(rows)}
        if a > MAX_INTERCEPT_BYTES:
            verdicts.append(f"{label}: intercept {a / MIB:.1f} MiB exceeds {MAX_INTERCEPT_BYTES / MIB:.0f} MiB workspace")
        if b_chunk > MAX_BYTES_PER_CHUNK:
            verdicts.append(f"{label}: {b_chunk:.0f} bytes/chunk exceeds {MAX_BYTES_PER_CHUNK}")
        # One-sided: the contract forbids memory that GROWS with records. Within
        # one corpus kind chunks and records are proportional, so the joint fit
        # can trade a little per-chunk cost for a small negative per-record term;
        # that is collinearity, not memory, and the chunk-adjusted dense/sparse
        # comparison below is the direct test of record independence.
        if b_record > MAX_BYTES_PER_RECORD:
            verdicts.append(f"{label}: {b_record:.4f} bytes/record exceeds {MAX_BYTES_PER_RECORD} (O(records) memory)")
        for r in rows:
            bound = MAX_INTERCEPT_BYTES + MAX_BYTES_PER_CHUNK * r["chunks"]
            if r["peak_delta_bytes"] > bound:
                verdicts.append(f"{label}: sample at {r['size'] / MIB:.0f} MiB ({r['kind']}) used "
                                f"{r['peak_delta_bytes'] / MIB:.1f} MiB > envelope {bound / MIB:.1f} MiB")
    pairs = []
    for (api, path), rows in sorted(groups.items()):
        if path != "record-walk" and api != "cdc_file":
            continue
        b_chunk = fits[f"{api}/{path}"]["bytes_per_chunk"]
        for size in sorted({r["size"] for r in rows}):
            dense = [r for r in rows if r["size"] == size and r["kind"] == "mcap-dense"]
            sparse = [r for r in rows if r["size"] == size and r["kind"] == "mcap-sparse"]
            if not dense or not sparse:
                continue
            d = statistics.median(r["peak_delta_bytes"] - b_chunk * r["chunks"] for r in dense)
            sp = statistics.median(r["peak_delta_bytes"] - b_chunk * r["chunks"] for r in sparse)
            raw_d = statistics.median(r["peak_delta_bytes"] for r in dense)
            raw_s = statistics.median(r["peak_delta_bytes"] for r in sparse)
            limit = max(DENSE_SPARSE_TOLERANCE[0], DENSE_SPARSE_TOLERANCE[1] * max(raw_d, raw_s))
            pairs.append({"api": api, "path": path, "size": size, "dense_records": dense[0]["records"],
                          "sparse_records": sparse[0]["records"], "dense_chunks": dense[0]["chunks"],
                          "sparse_chunks": sparse[0]["chunks"], "dense_median": raw_d, "sparse_median": raw_s,
                          "chunk_adjusted_difference": d - sp, "limit": limit})
            if d - sp > limit:
                verdicts.append(f"{api} @ {size / MIB:.0f} MiB: chunk-adjusted dense exceeds sparse by {(d - sp) / MIB:.1f} MiB")
    return {"fits": fits, "dense_vs_sparse": pairs, "failures": verdicts, "passed": not verdicts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--child", nargs=3, metavar=("API", "PATH", "FORMAT"), help=argparse.SUPPRESS)
    parser.add_argument("--sizes-mib", default="256,1024,4096")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--dense-record-bytes", type=int, default=32)
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
        verdict = evaluate(saved["samples"])
        saved.update(verdict)
        out = args.report or args.evaluate
        out.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
        for label, fit in verdict["fits"].items():
            print(f"fit {label}: a={fit['intercept_bytes'] / MIB:.1f} MiB  {fit['bytes_per_chunk']:.0f} B/chunk  "
                  f"{fit['bytes_per_record']:.5f} B/record")
        for p in verdict["dense_vs_sparse"]:
            print(f"  {p['api']} {p['size'] / MIB:.0f} MiB: records {p['dense_records']:,} vs {p['sparse_records']:,}; "
                  f"chunk-adjusted dense-sparse {p['chunk_adjusted_difference'] / MIB:+.2f} MiB (limit {p['limit'] / MIB:.1f})")
        print("PASS" if verdict["passed"] else "FAIL: " + "; ".join(verdict["failures"]))
        return 0 if verdict["passed"] else 1
    if args.workdir is None or args.report is None:
        parser.error("--workdir and --report are required")
    args.workdir.mkdir(parents=True, exist_ok=True)
    sizes = [int(x) * MIB for x in args.sizes_mib.split(",")]
    apis = args.apis.split(",")
    samples = []
    kinds = [("mcap-dense", args.dense_record_bytes), ("mcap-sparse", args.sparse_record_bytes), ("plain", 0)]
    for size in sizes:
        for kind, record_bytes in kinds:
            path = args.workdir / f"scan-{kind}-{size // MIB}MiB.bin"
            t0 = time.perf_counter()
            records = write_plain(path, size) if kind == "plain" else write_mcap(path, size, record_bytes)
            gen_s = time.perf_counter() - t0
            try:
                for api in apis:
                    fmt = "none" if kind == "plain" else "mcap"
                    if kind == "plain" and api == "format_aware_fd":
                        continue
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
    verdict = evaluate(samples)
    from one_link_native import __version__ as native_version  # type: ignore[attr-defined]

    report = {
        "schema": "one-link/scan-memory-qualification/v1",
        "environment": {
            "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "python": sys.version.split()[0], "native_version": native_version, "cpus": os.cpu_count(),
            "workdir": str(args.workdir),
        },
        "bounds": {"max_intercept_bytes": MAX_INTERCEPT_BYTES, "max_bytes_per_chunk": MAX_BYTES_PER_CHUNK,
                   "max_bytes_per_record": MAX_BYTES_PER_RECORD, "dense_sparse_tolerance": DENSE_SPARSE_TOLERANCE},
        "samples": samples,
        **verdict,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for api, fit in verdict["fits"].items():
        print(f"fit {api}: a={fit['intercept_bytes'] / MIB:.1f} MiB  {fit['bytes_per_chunk']:.0f} B/chunk  {fit['bytes_per_record']:.5f} B/record")
    print("PASS" if verdict["passed"] else "FAIL: " + "; ".join(verdict["failures"]))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
