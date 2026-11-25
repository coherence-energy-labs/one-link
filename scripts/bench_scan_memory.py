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

fitted per API. Within one kind chunks and records both grow
with file size; across kinds their ratio differs ~1000x, which is what
separates the two slopes. The contract also retains the original density
overhead check, independently of that joint fit:

* every workspace[kind] is within the bound FILE_SCANNING.md declares for
  that code path;
* b_chunk is within the cost of one returned chunk;
* b_record is ~0: memory does not grow with the number of records;
* no single sample leaves the envelope  workspace bound + per-chunk cost.
* at each size, dense-minus-sparse peak, adjusted for returned chunks, is at
  most max(8 MiB, 10% of the larger raw peak). The adjustment uses only the
  same API's plain-file output slope, clipped to [0, 1024] bytes per chunk;
  a negative joint-fit coefficient cannot manufacture a density penalty.

A run whose repeat-to-repeat spread could hide one retained bit per record is
reported as underpowered and fails: it is not evidence either way.

(An earlier model gave both kinds one shared intercept. When the dense walk
gained its own bounded window, that model attributed the constant difference
between the kinds to b_record and reported O(records) memory for a scanner
whose memory was flat across a 4x change in record count.)

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
# repeat spread cannot resolve that proves nothing about records.
MIN_RESOLVABLE_BYTES_PER_RECORD = 0.125


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


def evaluate(samples: list[dict]) -> dict:
    """Fit  peak = workspace[kind] + b_chunk*chunks + b_record*records  per API; test the contract.

    One API's samples are fitted together. The cost of a returned chunk is the
    same whichever scanner produced it, so the plain log (thousands of chunks,
    no records) pins b_chunk and the dense log is left to speak about records.
    Fitting each code path alone leaves b_chunk to the sparse log, whose few
    chunks cannot resolve it, and the dense log's ordinary per-chunk growth is
    then charged to records.
    """
    verdicts: list[str] = []
    groups: dict[str, list[dict]] = {}
    for sample in samples:
        groups.setdefault(sample["api"], []).append(sample)
    fits = {}
    growth = []
    density_output_cost = {}
    density_pairs = []
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
        # Records vary WITHIN a kind only through file size (the level of each
        # kind is its workspace), so this span is the lever arm b_record rests on.
        record_span = max(
            max(r["records"] for r in rows if r["kind"] == kind) - min(r["records"] for r in rows if r["kind"] == kind)
            for kind in kinds
        )
        resolvable = (2.0 * spread / record_span) if record_span else None
        fits[label] = {
            "workspace_bytes": workspace, "workspace_bound_bytes": bounds, "code_paths": paths,
            "bytes_per_chunk": b_chunk, "bytes_per_record": b_record, "records_vary": with_records,
            "repeat_spread_bytes": spread, "record_span": record_span,
            "resolvable_bytes_per_record": resolvable, "samples": len(rows),
        }
        for kind, value in workspace.items():
            if value > bounds[kind]:
                verdicts.append(f"{label}: {kind} workspace {value / MIB:.1f} MiB exceeds the declared "
                                f"{bounds[kind] / MIB:.0f} MiB ({paths[kind]})")
        if b_chunk > MAX_BYTES_PER_CHUNK:
            verdicts.append(f"{label}: {b_chunk:.0f} bytes/chunk exceeds {MAX_BYTES_PER_CHUNK}")
        # One-sided: the contract forbids memory that GROWS with records.
        if with_records:
            if b_record > MAX_BYTES_PER_RECORD:
                verdicts.append(f"{label}: {b_record:.4f} bytes/record exceeds {MAX_BYTES_PER_RECORD} "
                                "(O(records) memory)")
            elif resolvable is None or resolvable > MIN_RESOLVABLE_BYTES_PER_RECORD:
                shown = "nothing (records do not vary within a kind)" if resolvable is None \
                    else f"only {resolvable:.3f} bytes/record"
                verdicts.append(f"{label}: underpowered: repeat spread {spread / MIB:.2f} MiB over a span of "
                                f"{record_span:,} records resolves {shown}; use larger sizes or more repeats")
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
            "dense_vs_sparse": density_pairs, "failures": verdicts, "passed": not verdicts}


def print_verdict(verdict: dict) -> None:
    for label, fit in verdict["fits"].items():
        spaces = "  ".join(f"{kind} {value / MIB:.1f}" for kind, value in fit["workspace_bytes"].items())
        print(f"fit {label}: workspace MiB [{spaces}]  {fit['bytes_per_chunk']:.0f} B/chunk  "
              f"{fit['bytes_per_record']:.5f} B/record  (repeat spread {fit['repeat_spread_bytes'] / MIB:.2f} MiB)")
    for g in verdict["growth"]:
        low, high = g["median_peak_bytes"]
        print(f"  {g['api']} {g['kind']}: {g['smallest_size'] / MIB:.0f} -> {g['largest_size'] / MIB:.0f} MiB, "
              f"records {g['records'][0]:,} -> {g['records'][1]:,}, chunks {g['chunks'][0]:,} -> {g['chunks'][1]:,}: "
              f"peak {low / MIB:.1f} -> {high / MIB:.1f} MiB")
    for pair in verdict["dense_vs_sparse"]:
        print(f"  {pair['api']} {pair['size'] / MIB:.0f} MiB: plain-only chunk-adjusted dense-sparse "
              f"{pair['chunk_adjusted_difference'] / MIB:+.2f} MiB (limit {pair['limit'] / MIB:.1f} MiB; "
              f"{pair['output_cost_bytes_per_chunk']:.1f} B/chunk)")
    print("PASS" if verdict["passed"] else "FAIL: " + "; ".join(verdict["failures"]))


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
        print_verdict(verdict)
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
