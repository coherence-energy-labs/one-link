"""File engine v2 — perf-lab benchmarks for the native chunk layer.

Companion to ``perf_lab.py``. Surfaces the Phase A1 acceptance-gate numbers
for the native FastCDC v2020 + BLAKE3 + ADR-0006 derivation kernels:

- CDC scan throughput (target ≥ 2 GiB/s/core scalar; ≥ 5 GiB/s/core SIMD).
- BLAKE3 raw + convergent chunk-address throughput.
- AEAD key / ratchet_key_id / stripe_seed derivation throughput.
- Explicit Python Gear-CDC context and an equivalent native-C Gear-CDC pair.

Per ADR-0008 these benchmarks are JSON-serializable and feed the per-PR
benchmark gate. CI uses alternating artifact pairs, per-class limits, and an
explicit inconclusive outcome when measurement uncertainty crosses a limit.
The CI workflow lives at ``.github/workflows/native_bench_gate.yml``.
"""

from __future__ import annotations

import argparse
import blake3
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Callable
from unittest.mock import patch

import secrets
import tempfile
import threading

from . import aead_native, chunk_native, chunk_store_native, quic_native, wal_native
from . import cdc
from .benchmark_contract import corpus_bytes, provenance


MiB = 1024 * 1024
GiB = 1024 * 1024 * 1024


def _xorshift_buf(seed: int, size: int) -> bytes:
    # Preserve the private helper name for callers, but generate the versioned
    # public corpus outside timing with randbytes rather than a Python loop.
    return corpus_bytes(size, seed=seed, kind="random")


@dataclass
class BenchResult:
    """One measured throughput data point.

    All times are wall-clock seconds. Throughput is reported in bytes per
    second; callers convert to MiB/s or GiB/s as desired.
    """

    name: str
    bytes_processed: int
    iterations: int
    seconds_total: float
    seconds_per_iter_median: float
    bytes_per_second_median: float
    metadata: dict[str, object]
    seconds_per_iteration: list[float] = field(default_factory=list)
    bytes_per_iteration: list[int] = field(default_factory=list)
    warmup_iterations: int = 0


def _bench(
    name: str,
    fn: Callable[[], int],
    iterations: int = 5,
    metadata: dict[str, object] | None = None,
    warmup_iterations: int = 0,
) -> BenchResult:
    """Run ``fn`` ``iterations`` times. ``fn`` returns bytes processed.

    Reports median to suppress outliers from cold caches and OS scheduling.
    """
    if iterations < 1 or warmup_iterations < 0:
        raise ValueError("iterations must be positive and warmup nonnegative")
    for _ in range(warmup_iterations):
        fn()
    durations: list[float] = []
    byte_counts: list[int] = []
    bytes_one_iter = 0
    for _ in range(iterations):
        start = time.perf_counter_ns()
        bytes_one_iter = fn()
        elapsed_ns = time.perf_counter_ns() - start
        if type(bytes_one_iter) is not int or bytes_one_iter < 0:
            raise ValueError("benchmark must return a nonnegative byte count")
        byte_counts.append(bytes_one_iter)
        durations.append(elapsed_ns / 1e9)
    if len(set(byte_counts)) != 1:
        raise ValueError("benchmark work changed across repetitions")
    median_s = statistics.median(durations)
    return BenchResult(
        name=name,
        bytes_processed=bytes_one_iter,
        iterations=iterations,
        seconds_total=sum(durations),
        seconds_per_iter_median=median_s,
        bytes_per_second_median=(bytes_one_iter / median_s) if median_s > 0 else 0.0,
        metadata={"measurement_scope": "component", "corpus_version": "native-component-inputs-v2", **(metadata or {})},
        seconds_per_iteration=durations,
        bytes_per_iteration=byte_counts,
        warmup_iterations=warmup_iterations,
    )


def bench_native_cdc_scan(size_mib: int = 256, iterations: int = 5) -> BenchResult:
    if not chunk_native.HAS_NATIVE:
        raise RuntimeError("native chunk module unavailable")
    n = size_mib * MiB
    buf = _xorshift_buf(0x1234_5678_DEAD_BEEF + size_mib, n)
    reference = tuple(chunk_native.cdc_iter(buf))
    cursor = 0
    for boundary in reference:
        if boundary.start != cursor or not cursor < boundary.end <= n:
            raise RuntimeError("native CDC output does not form a complete partition")
        if boundary.raw_address != blake3.blake3(buf[boundary.start:boundary.end]).digest():
            raise RuntimeError("native CDC chunk hash differs from verified input")
        cursor = boundary.end
    if cursor != n:
        raise RuntimeError("native CDC output is truncated")

    def go() -> int:
        if tuple(chunk_native.cdc_iter(buf)) != reference:
            raise RuntimeError("native CDC output changed across repetitions")
        return n

    return _bench(
        f"native_cdc_scan_{size_mib}MiB",
        go,
        iterations=iterations,
        metadata={"input_bytes": n, "kernel": "FastCDC v2020 + Gear-256",
                  "output_verification": "preflight independent BLAKE3 and complete partition; exact outputs each iteration"},
    )


def bench_legacy_cdc_scan(size_mib: int = 256, iterations: int = 3) -> BenchResult:
    """Explicit Python Gear-CDC; not algorithm-equivalent to Rust FastCDC."""
    n = size_mib * MiB
    buf = _xorshift_buf(0x1234_5678_DEAD_BEEF + size_mib, n)

    def go() -> int:
        cdc.chunk_bytes(buf)
        return n

    # The benchmark runs synchronously. Patching only this private dispatch
    # boundary avoids mutating the native loader's process-wide cache/status.
    with patch.object(cdc, "_chunk_bytes_native", return_value=None):
        return _bench(
            f"legacy_cdc_scan_{size_mib}MiB", go, iterations=iterations,
            metadata={"input_bytes": n, "kernel": "Gear-CDC (16/64/256 KiB)",
                      "engine": "python", "equivalent_to_rust_fastcdc": False},
        )


def bench_equivalent_gear_cdc(size_mib: int = 4, iterations: int = 5) -> list[BenchResult]:
    """Compare exact Python/C Gear boundaries and hashes before measuring.

    A native failure is explicit; fallback can never masquerade as native C.
    Both sides include boundary scanning, BLAKE3 hashes and Chunk construction.
    """
    buf = corpus_bytes(size_mib * MiB, seed=0xCDC)
    with patch.object(cdc, "_chunk_bytes_native", return_value=None):
        reference = cdc.chunk_bytes(buf)
    native = cdc._chunk_bytes_native(buf)
    if native is None:
        raise RuntimeError("native C Gear-CDC unavailable; cannot run equivalent pair")
    if native != reference:
        raise RuntimeError("native/Python Gear-CDC boundaries or hashes differ")

    def native_go() -> int:
        result = cdc._chunk_bytes_native(buf)
        if result is None or result != reference:
            raise RuntimeError("native Gear-CDC dispatch/equivalence failed")
        return len(buf)

    def python_go() -> int:
        if cdc.chunk_bytes(buf) != reference:
            raise RuntimeError("Python Gear-CDC equivalence failed")
        return len(buf)

    meta = {"input_bytes": len(buf), "kernel": "Gear-CDC (16/64/256 KiB)",
            "output_verified": "exact boundaries and hashes on every iteration"}
    out = [_bench(f"gear_cdc_c_{size_mib}MiB", native_go, iterations,
                  {**meta, "engine": "ctypes-c"})]
    with patch.object(cdc, "_chunk_bytes_native", return_value=None):
        out.append(_bench(f"gear_cdc_python_{size_mib}MiB", python_go, iterations,
                          {**meta, "engine": "python"}))
    return out


def bench_native_chunk_address_raw(size_kib: int = 64, iterations: int = 1000) -> BenchResult:
    n = size_kib * 1024
    buf = _xorshift_buf(0xCAFE_BABE + size_kib, n)

    def go() -> int:
        chunk_native.chunk_address_raw(buf)
        return n

    return _bench(
        f"native_blake3_addr_raw_{size_kib}KiB",
        go,
        iterations=iterations,
        metadata={"input_bytes": n},
    )


def bench_native_chunk_address_convergent(
    size_kib: int = 64, iterations: int = 1000
) -> BenchResult:
    n = size_kib * 1024
    buf = _xorshift_buf(0xCAFE_BABE + size_kib + 1, n)

    def go() -> int:
        chunk_native.chunk_address_convergent(buf)
        return n

    return _bench(
        f"native_blake3_addr_convergent_{size_kib}KiB",
        go,
        iterations=iterations,
        metadata={"input_bytes": n},
    )


def bench_native_aead_key_derivation(iterations: int = 100_000) -> BenchResult:
    chain = b"\x42" * 32
    chunk = b"\x01" * 32

    def go() -> int:
        chunk_native.derive_aead_key(chain, chunk)
        return 64  # bytes of input

    return _bench(
        "native_derive_aead_key",
        go,
        iterations=iterations,
        metadata={"per_iter_bytes": 64},
    )


def bench_native_stripe_seed(iterations: int = 100_000) -> BenchResult:
    chunk = b"\x77" * 32

    def go() -> int:
        chunk_native.derive_stripe_seed(chunk, 10)
        return 33  # 32 + stripe_k

    return _bench(
        "native_derive_stripe_seed",
        go,
        iterations=iterations,
        metadata={"per_iter_bytes": 33, "stripe_k": 10},
    )


# ─── AEAD benchmarks ──────────────────────────────────────────────────


def bench_native_aead(
    kind: str = "aes",
    chunk_size_kib: int = 64,
    iterations: int = 200,
) -> tuple[BenchResult, BenchResult]:
    """Encrypt + decrypt one chunk per iteration; return (enc_result, dec_result)."""
    if not aead_native.HAS_NATIVE:
        raise RuntimeError("aead_native unavailable")
    n = chunk_size_kib * 1024
    plaintext = _xorshift_buf(0xCAFE_AEAD ^ chunk_size_kib, n)
    chunk_id = secrets.token_bytes(32)
    key = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, kind)  # type: ignore[arg-type]
    # warm-up
    ct = cipher.encrypt_chunk(chunk_id, plaintext)
    if cipher.decrypt_chunk(chunk_id, len(plaintext), ct) != plaintext:
        raise RuntimeError("native AEAD did not round-trip the benchmark input")

    def enc() -> int:
        if len(cipher.encrypt_chunk(chunk_id, plaintext)) != len(ct):
            raise RuntimeError("native AEAD ciphertext length changed")
        return len(plaintext)

    def dec() -> int:
        if cipher.decrypt_chunk(chunk_id, len(plaintext), ct) != plaintext:
            raise RuntimeError("native AEAD decrypt returned incorrect bytes")
        return len(plaintext)

    enc_res = _bench(
        f"native_aead_{kind}_encrypt_{chunk_size_kib}KiB",
        enc,
        iterations=iterations,
        metadata={"input_bytes": n, "kind": kind},
        warmup_iterations=min(20, max(1, iterations // 10)),
    )
    dec_res = _bench(
        f"native_aead_{kind}_decrypt_{chunk_size_kib}KiB",
        dec,
        iterations=iterations,
        metadata={"input_bytes": n, "kind": kind},
        warmup_iterations=min(20, max(1, iterations // 10)),
    )
    return enc_res, dec_res


# ─── WAL benchmarks ───────────────────────────────────────────────────


def bench_native_wal_group_commit(
    batch_size: int = 128,
    payload_kib: int = 4,
    iterations: int = 5,
) -> BenchResult:
    if not wal_native.HAS_NATIVE:
        raise RuntimeError("wal_native unavailable")
    payload = b"\xCD" * (payload_kib * 1024)
    total_bytes = batch_size * len(payload)

    def go() -> int:
        with tempfile.TemporaryDirectory() as d:
            with wal_native.Wal.create(d, "chunk") as wal:
                for _ in range(batch_size):
                    wal.append(wal_native.WalRecord(0x01, 0x00, payload))
                wal.flush()
        return total_bytes

    return _bench(
        f"native_wal_group_commit_batch={batch_size}_payload={payload_kib}KiB",
        go,
        iterations=iterations,
        metadata={"batch_size": batch_size, "payload_kib": payload_kib},
    )


# ─── Chunk store benchmarks ──────────────────────────────────────────


def bench_native_chunk_store_write(
    batch_size: int = 32,
    plaintext_kib: int = 64,
    iterations: int = 5,
) -> BenchResult:
    if not chunk_store_native.HAS_NATIVE:
        raise RuntimeError("chunk_store_native unavailable")
    plaintext_bytes = plaintext_kib * 1024
    total_bytes = batch_size * plaintext_bytes

    def go() -> int:
        with tempfile.TemporaryDirectory() as d:
            with chunk_store_native.ChunkStore.open(d) as store:
                ct_len = plaintext_bytes + ((plaintext_bytes + 16383) // 16384) * 16
                ct = b"\xCD" * ct_len
                for i in range(batch_size):
                    cid = i.to_bytes(4, "little") + b"\xAA" * 28
                    store.append_chunk(
                        cid, b"\x55" * 16, plaintext_bytes, ct
                    )
                store.flush()
        return total_bytes

    return _bench(
        f"native_chunk_store_write_batch={batch_size}_plaintext={plaintext_kib}KiB",
        go,
        iterations=iterations,
        metadata={"batch_size": batch_size, "plaintext_kib": plaintext_kib},
    )


def bench_native_chunk_store_locate(iterations: int = 1_000_000) -> BenchResult:
    """Memtable + bloom lookup throughput (warm path)."""
    if not chunk_store_native.HAS_NATIVE:
        raise RuntimeError("chunk_store_native unavailable")
    with tempfile.TemporaryDirectory() as d:
        store = chunk_store_native.ChunkStore.open(d)
        ids = []
        ct = b"\xEE" * 80
        for i in range(1024):
            cid = i.to_bytes(4, "little") + b"\xBB" * 28
            store.append_chunk(cid, b"\x33" * 16, 64, ct)
            ids.append(cid)
        store.flush()

        def go() -> int:
            stride = 101
            idx = 0
            for _ in range(iterations):
                store.locate_chunk(ids[idx % len(ids)])
                idx = (idx + stride) % (len(ids) * stride)
            return iterations * 32

        result = _bench(
            "native_chunk_store_locate",
            go,
            iterations=1,
            metadata={"chunks_indexed": len(ids), "lookups": iterations},
        )
        store.close()
    return result


# ─── QUIC benchmarks ──────────────────────────────────────────────────


def _bench_quic_loopback_round_trip(
    payload_kib: int,
    iterations: int = 50,
) -> BenchResult:
    """Sequential request/response round-trips on a single connection."""
    if not quic_native.HAS_NATIVE:
        raise RuntimeError("quic_native unavailable")
    payload_bytes = payload_kib * 1024
    bulk_response = b"\xCD" * payload_bytes

    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    permitted = {bob.fingerprint}
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp in permitted,
        quic_native.EndpointConfig(
            bind="127.0.0.1:0",
            idle_timeout_ms=30_000,
            stream_receive_window_bytes=16 * 1024 * 1024,
            send_window_bytes=128 * 1024 * 1024,
        ),
    )
    addr = server.local_addr

    holder: list = []
    done = threading.Event()
    bench_iterations = 3

    def loop() -> None:
        conn = server.accept_blocking(timeout_ms=30_000)
        holder.append(conn)
        if conn is None:
            done.set()
            return
        if hasattr(conn, "serve_fixed_stream_responses_blocking"):
            conn.serve_fixed_stream_responses_blocking(
                bench_iterations,
                iterations,
                quic_native.FRAME_CHUNK_RESPONSE,
                bulk_response,
                max_in_flight=1,
            )
            time.sleep(0.05)
            done.set()
            return
        if hasattr(conn, "serve_fixed_responses_blocking"):
            conn.serve_fixed_responses_blocking(
                iterations * bench_iterations,
                quic_native.FRAME_CHUNK_RESPONSE,
                bulk_response,
                max_in_flight=1,
            )
            time.sleep(0.05)
            done.set()
            return
        for _ in range(iterations * bench_iterations):
            r = conn.recv_frame_blocking(timeout_ms=10_000)
            if r is None:
                break
            sid, _kind, _payload = r
            conn.send_response_on(sid, quic_native.FRAME_CHUNK_RESPONSE, bulk_response)
        time.sleep(0.05)
        done.set()

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(
        bob,
        quic_native.EndpointConfig(
            bind="127.0.0.1:0",
            idle_timeout_ms=30_000,
            stream_receive_window_bytes=16 * 1024 * 1024,
            send_window_bytes=128 * 1024 * 1024,
        ),
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    cids = [bytes([i & 0xFF] * 32) for i in range(iterations)]
    selected_api = next((name for name in (
        "send_frame_stream_round_trips_count", "send_frame_stream_round_trips",
        "send_frame_round_trips", "send_frame_round_trip"
    ) if hasattr(conn, name)), "unavailable")

    def go() -> int:
        # This component helper excludes daemon orchestration and receipts.
        # Its selected API and validation scope are part of the report.
        if hasattr(conn, "send_frame_stream_round_trips_count"):
            received = conn.send_frame_stream_round_trips_count(
                quic_native.FRAME_CHUNK_REQUEST,
                cids,
                quic_native.FRAME_CHUNK_RESPONSE,
            )
            if received != iterations * payload_bytes:
                raise RuntimeError(
                    f"QUIC stream benchmark expected {iterations * payload_bytes} "
                    f"response bytes, got {received}"
                )
            return received
        if hasattr(conn, "send_frame_stream_round_trips"):
            replies = conn.send_frame_stream_round_trips(
                quic_native.FRAME_CHUNK_REQUEST, cids
            )
        elif hasattr(conn, "send_frame_round_trips"):
            replies = conn.send_frame_round_trips(
                quic_native.FRAME_CHUNK_REQUEST, cids
            )
        else:
            replies = [
                conn.send_frame_round_trip(quic_native.FRAME_CHUNK_REQUEST, cid)
                for cid in cids
            ]
        if len(replies) != iterations:
            raise RuntimeError("QUIC component returned an incomplete response set")
        for kind, response_payload in replies:
            if kind != quic_native.FRAME_CHUNK_RESPONSE or response_payload != bulk_response:
                raise RuntimeError("QUIC component returned an incorrect response")
        return iterations * payload_bytes

    result = _bench(
        f"native_quic_round_trip_{payload_kib}KiB_x{iterations}",
        go,
        iterations=bench_iterations,
        metadata={"payload_kib": payload_kib, "round_trips": iterations,
                  "api": selected_api, "measurement_scope": "native_loopback_helper_excludes_daemon",
                  "payload_validation": "response kind and byte count" if "count" in selected_api else "exact response bytes"},
    )
    done.wait(timeout=5)
    conn.close()
    if holder and holder[0] is not None:
        holder[0].close()
    server.close()
    t.join(timeout=2)
    client.close()
    return result


def _bench_quic_parallel_streams(
    payload_kib: int = 64,
    parallelism: int = 16,
    iterations_per_stream: int = 4,
) -> BenchResult:
    """Concurrent request/response round-trips on one connection."""
    if not quic_native.HAS_NATIVE:
        raise RuntimeError("quic_native unavailable")
    payload_bytes = payload_kib * 1024
    bulk_response = b"\xCD" * payload_bytes
    total_round_trips = parallelism * iterations_per_stream

    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    permitted = {bob.fingerprint}
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp in permitted,
        quic_native.EndpointConfig(
            bind="127.0.0.1:0",
            idle_timeout_ms=30_000,
            stream_receive_window_bytes=16 * 1024 * 1024,
            send_window_bytes=128 * 1024 * 1024,
        ),
    )
    addr = server.local_addr

    holder: list = []
    done = threading.Event()
    bench_iterations = 3
    stream_lanes = 2 if payload_kib >= 256 and total_round_trips >= 2 else 1
    requests_per_stream = total_round_trips // stream_lanes

    def loop() -> None:
        conn = server.accept_blocking(timeout_ms=30_000)
        holder.append(conn)
        if conn is None:
            done.set()
            return
        if hasattr(conn, "serve_fixed_stream_responses_blocking"):
            conn.serve_fixed_stream_responses_blocking(
                stream_lanes * bench_iterations,
                requests_per_stream,
                quic_native.FRAME_CHUNK_RESPONSE,
                bulk_response,
                max_in_flight=stream_lanes,
            )
            time.sleep(0.05)
            done.set()
            return
        if hasattr(conn, "serve_fixed_responses_blocking"):
            conn.serve_fixed_responses_blocking(
                total_round_trips * bench_iterations,
                quic_native.FRAME_CHUNK_RESPONSE,
                bulk_response,
                max_in_flight=parallelism,
            )
            time.sleep(0.05)
            done.set()
            return
        for _ in range(total_round_trips * bench_iterations):
            r = conn.recv_frame_blocking(timeout_ms=10_000)
            if r is None:
                break
            sid, _kind, _payload = r
            conn.send_response_on(sid, quic_native.FRAME_CHUNK_RESPONSE, bulk_response)
        time.sleep(0.05)
        done.set()

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(
        bob,
        quic_native.EndpointConfig(
            bind="127.0.0.1:0",
            idle_timeout_ms=30_000,
            stream_receive_window_bytes=16 * 1024 * 1024,
            send_window_bytes=128 * 1024 * 1024,
        ),
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    cids = [
        bytes([(worker_id * 37 + i) & 0xFF] * 32)
        for worker_id in range(parallelism)
        for i in range(iterations_per_stream)
    ]
    selected_api = next((name for name in (
        "send_frame_stream_round_trips_count_parallel", "send_frame_stream_round_trips_parallel",
        "send_frame_round_trips_parallel", "send_frame_round_trip"
    ) if hasattr(conn, name)), "unavailable")

    def go() -> int:
        # Parallel native bulk streams avoid spinning Python worker threads
        # and amortize stream setup across each lane.
        if hasattr(conn, "send_frame_stream_round_trips_count_parallel"):
            received = conn.send_frame_stream_round_trips_count_parallel(
                quic_native.FRAME_CHUNK_REQUEST,
                cids,
                quic_native.FRAME_CHUNK_RESPONSE,
                lanes=stream_lanes,
            )
            if received != total_round_trips * payload_bytes:
                raise RuntimeError(
                    f"QUIC parallel benchmark expected "
                    f"{total_round_trips * payload_bytes} response bytes, got {received}"
                )
            return received
        if hasattr(conn, "send_frame_stream_round_trips_parallel"):
            replies = conn.send_frame_stream_round_trips_parallel(
                quic_native.FRAME_CHUNK_REQUEST,
                cids,
                lanes=stream_lanes,
            )
        elif hasattr(conn, "send_frame_round_trips_parallel"):
            replies = conn.send_frame_round_trips_parallel(
                quic_native.FRAME_CHUNK_REQUEST,
                cids,
                max_in_flight=parallelism,
            )
        else:
            threads: list[threading.Thread] = []
            replies_by_worker: list[list[tuple[int, bytes]]] = [
                [] for _ in range(parallelism)
            ]

            def worker(worker_id: int) -> None:
                for i in range(iterations_per_stream):
                    cid = bytes([(worker_id * 37 + i) & 0xFF] * 32)
                    replies_by_worker[worker_id].append(
                        conn.send_frame_round_trip(
                            quic_native.FRAME_CHUNK_REQUEST, cid
                        )
                    )

            for w in range(parallelism):
                th = threading.Thread(target=worker, args=(w,), daemon=True)
                threads.append(th)
                th.start()
            for th in threads:
                th.join(timeout=30)
            replies = [item for worker_replies in replies_by_worker for item in worker_replies]
        if len(replies) != total_round_trips:
            raise RuntimeError(
                f"QUIC parallel benchmark expected {total_round_trips} replies, "
                f"got {len(replies)}"
            )
        for kind, response_payload in replies:
            if kind != quic_native.FRAME_CHUNK_RESPONSE or response_payload != bulk_response:
                raise RuntimeError("QUIC component returned an incorrect response")
        return total_round_trips * payload_bytes

    result = _bench(
        f"native_quic_parallel_{parallelism}x{iterations_per_stream}_{payload_kib}KiB",
        go,
        iterations=bench_iterations,
        metadata={
            "payload_kib": payload_kib,
            "parallelism": parallelism,
            "iterations_per_stream": iterations_per_stream,
            "stream_lanes": stream_lanes,
            "requests_per_stream": requests_per_stream,
            "api": selected_api,
            "measurement_scope": "native_loopback_helper_excludes_daemon",
            "payload_validation": "response kind and byte count" if "count" in selected_api else "exact response bytes",
        },
    )
    done.wait(timeout=10)
    conn.close()
    if holder and holder[0] is not None:
        holder[0].close()
    server.close()
    t.join(timeout=5)
    client.close()
    return result


def run_full_suite(size_mib: int = 256, include_legacy: bool = True) -> list[BenchResult]:
    """Run the complete A1 native-bench suite.

    ``size_mib`` controls the CDC scan input size (256 MiB default; reduce
    for quick checks on slow disks).
    """
    results: list[BenchResult] = []
    if not chunk_native.HAS_NATIVE:
        raise RuntimeError(
            "one_link_native not installed; run `cd native && maturin "
            "develop --release` before running native benches"
        )
    # ol_chunk
    results.append(bench_native_cdc_scan(size_mib=size_mib))
    if include_legacy:
        # Legacy is slow (~8 MiB/s); use 32 MiB so the run finishes quickly.
        results.append(bench_legacy_cdc_scan(size_mib=min(size_mib, 32)))
        results.extend(bench_equivalent_gear_cdc(size_mib=min(size_mib, 4)))
    results.append(bench_native_chunk_address_raw(size_kib=64))
    results.append(bench_native_chunk_address_convergent(size_kib=64))
    results.append(bench_native_aead_key_derivation())
    results.append(bench_native_stripe_seed())
    # ol_aead
    if aead_native.HAS_NATIVE:
        for kind in ("aes", "chacha"):
            for size_kib in (16, 64, 256):
                enc, dec = bench_native_aead(kind=kind, chunk_size_kib=size_kib, iterations=100)
                results.append(enc)
                results.append(dec)
    # ol_wal
    if wal_native.HAS_NATIVE:
        results.append(bench_native_wal_group_commit(batch_size=128, payload_kib=4))
        results.append(bench_native_wal_group_commit(batch_size=128, payload_kib=64))
    # ol_chunk_store
    if chunk_store_native.HAS_NATIVE:
        results.append(bench_native_chunk_store_write(batch_size=32, plaintext_kib=64))
        results.append(bench_native_chunk_store_write(batch_size=128, plaintext_kib=64))
        results.append(bench_native_chunk_store_locate(iterations=500_000))
    # ol_quic
    if quic_native.HAS_NATIVE:
        for size_kib in (16, 64, 256, 1024):
            iters = 200 if size_kib <= 64 else 50 if size_kib <= 256 else 20
            results.append(_bench_quic_loopback_round_trip(payload_kib=size_kib, iterations=iters))
        # Parallel multi-stream: hits multi-thread tokio scheduler hard.
        results.append(_bench_quic_parallel_streams(payload_kib=64, parallelism=16, iterations_per_stream=4))
        results.append(_bench_quic_parallel_streams(payload_kib=256, parallelism=8, iterations_per_stream=4))
    return results


def render_report(results: list[BenchResult]) -> str:
    """Render a tabular summary suitable for terminal + CI logs."""
    lines = []
    diag = chunk_native.diagnostics()
    lines.append("# One Link file-engine v2 — native chunk benchmarks")
    lines.append(
        f"# native: {diag['native_available']} | version: {diag.get('version')} "
        f"| kernel: {diag.get('kernel', 'n/a')}"
    )
    lines.append(
        f"# host: {platform.platform()} | python: {platform.python_version()}"
    )
    lines.append("")
    header = (
        f"{'name':<48} {'iter':>6} {'GiB/s':>10} {'MB/s':>10} {'ms/iter':>10}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        gibs = r.bytes_per_second_median / GiB
        mbs = r.bytes_per_second_median / 1_000_000
        ms = r.seconds_per_iter_median * 1000
        lines.append(
            f"{r.name:<48} {r.iterations:>6} {gibs:>10.3f} {mbs:>10.2f} {ms:>10.3f}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run One Link file-engine v2 native chunk benchmarks."
    )
    parser.add_argument(
        "--size-mib",
        type=int,
        default=256,
        help="CDC scan input size in MiB (default 256).",
    )
    parser.add_argument(
        "--no-legacy",
        action="store_true",
        help="Skip the slow legacy Python CDC comparison run.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON results for CI ingestion (default: human-readable).",
    )
    args = parser.parse_args(argv)

    results = run_full_suite(size_mib=args.size_mib, include_legacy=not args.no_legacy)
    if args.json:
        identity = provenance()
        out = {
            "schema": "one-link-native-benchmark-v2",
            "measurement_contract": {"scope": "components", "corpus": "seeded-randbytes-v1", "size_mib": args.size_mib},
            "provenance": identity,
            "diagnostics": chunk_native.diagnostics(),
            "host": identity["host"],
            "results": [asdict(r) for r in results],
        }
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_report(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
