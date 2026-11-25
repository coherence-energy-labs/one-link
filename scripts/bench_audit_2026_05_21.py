"""Micro-benchmarks for the 2026-05-21 audit's hot-path patches.

Goal: verify that none of the security/reliability fixes introduced
a measurable slowdown on the production hot paths. Each benchmark
isolates one fix and runs it N times in a tight loop, reporting
ns/op and ops/sec medians.

Reported surfaces:
  * `double_ratchet.decrypt` — T1-A added snapshot/revert.
  * `Daemon._capability_allowed` — T1-D + T3-W changed the
    state-missing / verifier-exception paths.
  * `_format_error` — T3-E new helper used in best-effort
    error returns.
  * `_safe_transfer_name` — T3-R added `:`-strip.
  * `_csrf_origin_ok` — T2-O new per-POST check (synthetic
    aiohttp.Request).
  * FILE_WANTS bounds-check loop — T3-T replaced a set
    comprehension with an explicit guarded loop.

The benchmark is intentionally dependency-light + deterministic so
running ``python scripts/bench_audit_2026_05_21.py`` gives reproducible
numbers across runs.

Reference numbers (median over 10k iterations, single core, idle
laptop) live in AUDIT_2026-05-21.md.
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Callable, cast

import sys
from pathlib import Path

# Add src/ so we can run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _bench(name: str, fn: Callable[[], object], iters: int = 10_000) -> dict:
    if iters < 1:
        raise ValueError("iters must be positive")
    # Warm up — JIT-y caches, importing AEAD backend, etc.
    for _ in range(min(200, iters)):
        fn()
    durations: list[float] = []
    # Repeat the sample run a few times so we can report median and worst batch-average.
    for _ in range(5):
        t0 = time.perf_counter_ns()
        for _ in range(iters):
            fn()
        t1 = time.perf_counter_ns()
        durations.append((t1 - t0) / iters)
    median = statistics.median(durations)
    worst_batch_average = max(durations)  # maximum batch-average; not an operation percentile
    return {
        "name": name,
        "iters": iters,
        "ns_per_op_median": median,
        "ns_per_op_worst_batch_average": worst_batch_average,
        "batch_mean_ns_per_op_samples": durations,
        "sample_kind": "batch means; not individual-operation tail latency",
        "ops_per_sec_median": 1e9 / median if median > 0 else float("inf"),
    }


# ── DR decrypt ─────────────────────────────────────────────────────

def _bench_dr_decrypt() -> dict:
    from one_link.double_ratchet import encrypt, decrypt, init_pair

    alice, bob = init_pair(os.urandom(32))

    # Pre-build a pool of encrypted frames so the bench measures decrypt,
    # not encrypt. Each call advances Alice's send chain so frames are
    # distinct.
    frames: list[tuple] = []
    for _ in range(2_000):
        h, ct = encrypt(alice, b"benchmark payload of fixed size")
        frames.append((h, ct))

    counter = {"i": 0}

    def step() -> None:
        h, ct = frames[counter["i"] % len(frames)]
        counter["i"] += 1
        # Re-init bob for each iter so we always decrypt frame 0..N
        # in lockstep with the prebuilt encrypts. But re-init is
        # expensive; instead we use a different (alice2, bob2) below.

    # Build a matched stream: 2000 alice→bob frames, then decrypt them
    # in order. After exhausting, re-bootstrap. Wrap mutable state in a
    # single-element list so the closure doesn't need ``nonlocal``.
    def make_run() -> Callable[[], None]:
        pair = init_pair(os.urandom(32))
        index = 0
        pool = [
            encrypt(pair[0], b"benchmark payload of fixed size")
            for _ in range(2_000)
        ]

        def run() -> None:
            nonlocal index, pair, pool
            if index >= len(pool):
                # Reset matched pair; cost amortized across iters.
                pair = init_pair(os.urandom(32))
                pool = [
                    encrypt(pair[0], b"benchmark payload of fixed size")
                    for _ in range(2_000)
                ]
                index = 0
            h, ct = pool[index]
            decrypt(pair[1], h, ct)
            index += 1
        return run

    return _bench("dr_decrypt (T1-A snapshot/revert)", make_run(), iters=2_000)


def _bench_dr_decrypt_pre_t1a() -> dict:
    """Baseline comparison: the pre-T1-A version of `decrypt` (no
    snapshot/revert) inlined here so we can A/B against the current
    code without checking out an older commit. The body is intentionally
    a faithful copy of the pre-patch logic.
    """
    from one_link.double_ratchet import (
        encrypt, init_pair, MAX_SKIP_KEYS,
        _try_skipped, _dh_ratchet, _skip_recv_keys,
        _aead_nonce, _aead_for, kdf_chain,
    )

    def _decrypt_pre_t1a(state, header, ciphertext, ad=b""):
        seen_key = (header.dh, header.n)
        if seen_key in state.decrypted_seen:
            raise RuntimeError("ratchet: replayed message rejected")
        pt = _try_skipped(state, header, ciphertext, ad)
        if pt is not None:
            return pt
        if state.dh_recv_pub != header.dh:
            _dh_ratchet(state, header)
        if header.n > state.recv_n:
            _skip_recv_keys(state, header.n)
        elif header.n < state.recv_n:
            raise RuntimeError("ratchet: out-of-order on current chain")
        if state.recv_chain_key is None:
            raise RuntimeError("ratchet: receive chain not initialized")
        state.recv_chain_key, msg_key = kdf_chain(state.recv_chain_key)
        nonce = _aead_nonce(header.n)
        aead_ad = header.encode() + (ad or b"")
        pt = _aead_for(msg_key).decrypt(nonce, ciphertext, aead_ad)
        state.recv_n += 1
        state.decrypted_seen[seen_key] = True
        while len(state.decrypted_seen) > MAX_SKIP_KEYS * 4:
            state.decrypted_seen.popitem(last=False)
        return pt

    def make_run() -> Callable[[], None]:
        pair = init_pair(os.urandom(32))
        index = 0
        pool = [
            encrypt(pair[0], b"benchmark payload of fixed size")
            for _ in range(2_000)
        ]

        def run() -> None:
            nonlocal index, pair, pool
            if index >= len(pool):
                pair = init_pair(os.urandom(32))
                pool = [
                    encrypt(pair[0], b"benchmark payload of fixed size")
                    for _ in range(2_000)
                ]
                index = 0
            h, ct = pool[index]
            _decrypt_pre_t1a(pair[1], h, ct)
            index += 1
        return run

    return _bench("dr_decrypt (pre-T1-A baseline)", make_run(), iters=2_000)


# ── _format_error ──────────────────────────────────────────────────

def _bench_format_error() -> dict:
    from one_link.daemon import _format_error
    # Mix of empty + non-empty exceptions to cover both branches.
    excs = [
        OSError(),  # empty str()
        ValueError("permission denied"),
        RuntimeError("handshake timed out"),
        ConnectionResetError("WinError 10054"),
    ]
    counter = {"i": 0}

    def run() -> None:
        e = excs[counter["i"] & 0x3]
        counter["i"] += 1
        _format_error(e)

    return _bench("format_error (T3-E)", run, iters=100_000)


# ── _safe_transfer_name ────────────────────────────────────────────

def _bench_safe_transfer_name() -> dict:
    # Build a fake daemon-shaped object that just calls the bound method.
    from one_link.daemon import Daemon
    safe = Daemon._safe_transfer_name
    # Reserved-names lookup is a class attribute; instantiate a stub
    # only enough to satisfy the bound-method dispatch.

    stub = cast(Daemon, object.__new__(Daemon))
    names = [
        "normal_file.pdf",
        "with spaces in name.docx",
        "weird:ads.txt",  # NTFS ADS — exercises T3-R replace
        "../../etc/passwd",
        "CON.txt",
        "very_long_filename_" * 30 + ".bin",
    ]
    counter = {"i": 0}

    def run() -> None:
        safe(stub, names[counter["i"] % len(names)])
        counter["i"] += 1

    return _bench("safe_transfer_name (T3-R + base)", run, iters=20_000)


# ── _csrf_origin_ok ────────────────────────────────────────────────

def _bench_csrf_origin_ok() -> dict:
    from aiohttp import web
    from one_link.server import UIServer

    stub = cast(UIServer, object.__new__(UIServer))
    csrf = UIServer._csrf_origin_ok

    # Synthesise the lightest possible request-shaped object: server only
    # reads headers + the helper's own attributes.
    class _Req:
        def __init__(self, origin: str | None, bearer: bool) -> None:
            self.headers: dict[str, str] = {}
            self.scheme = "http"
            self.host = "127.0.0.1:7117"
            if origin:
                self.headers["Origin"] = origin
            if bearer:
                self.headers["Authorization"] = "Bearer xxx"

    reqs = [
        _Req("http://127.0.0.1:7117", False),
        _Req("http://localhost:8080", False),
        _Req(None, True),
        _Req("http://attacker.example", False),
        _Req(None, False),
    ]
    counter = {"i": 0}

    def run() -> None:
        request = cast(web.Request, reqs[counter["i"] % len(reqs)])
        csrf(stub, request)
        counter["i"] += 1

    return _bench("csrf_origin_ok (T2-O)", run, iters=50_000)


# ── FILE_WANTS bounds check ────────────────────────────────────────

def _bench_file_wants_bounds() -> dict:
    chunk_count = 1024
    # Mix of valid / negative / overflow / out-of-range / non-int values
    raw = list(range(0, 2048, 2)) + [-1, -100, 2**62, "garbage", None, 9999]

    def run() -> None:
        wanted: set[int] = set()
        for x in raw:
            if not isinstance(x, (int, str)):
                continue
            try:
                i = int(x)
            except (TypeError, ValueError):
                continue
            if 0 <= i < chunk_count:
                wanted.add(i)

    return _bench("file_wants_bounds_loop (T3-T)", run, iters=5_000)


# ── state.update_transfer ──────────────────────────────────────────

def _bench_update_transfer() -> dict:
    """T3-K wrapped ``update_transfer`` in ``_write_lock`` across
    read + write. Validate the added lock acquisition doesn't slow
    the common (single-threaded) call by more than a few percent.
    """
    import tempfile
    from one_link.state import State

    td = tempfile.mkdtemp(prefix="ol_bench_state_")
    state = State(db_path=Path(td) / "state.db")
    # Seed a transfer to update.
    state.upsert_transfer(
        id="bench-t1",
        direction="out",
        peer_fp="deadbeef" * 8,
        kind="file",
        name="bench.bin",
        size=1024,
        blob_hash="deadbeef" * 8,
        status="active",
        progress_bytes=0,
        total_bytes=1024,
        chunks_done=0,
        chunks_total=4,
        raw_bytes=0,
        wire_bytes=0,
        # Synthetic metadata only: no file is created or opened at this path.
        metadata={"path": "/tmp/bench.bin"},  # nosec B108
    )
    progress = {"n": 0}

    def run() -> None:
        progress["n"] += 1
        state.update_transfer(
            "bench-t1",
            progress_bytes=progress["n"] % 1024,
            chunks_done=progress["n"] % 4,
        )

    return _bench("update_transfer (T3-K lock)", run, iters=5_000)


# ── list_peer_files pagination ─────────────────────────────────────

def _bench_list_peer_files() -> dict:
    """T3-I added LIMIT/OFFSET. Confirm the paginated lookup is at
    least as fast as the previous unbounded full-scan on a typical
    population (1000 messages per peer)."""
    import tempfile
    import time as _time
    from one_link.state import State

    td = tempfile.mkdtemp(prefix="ol_bench_peer_files_")
    state = State(db_path=Path(td) / "state.db")
    peer_fp = "deadbeef" * 8
    # Seed 1000 file messages via the public record_message API.
    base_ts = int(_time.time() * 1000)
    for i in range(1000):
        state.record_message(
            id=f"msg-{i:04d}",
            ts_ms=base_ts + i,
            direction="in",
            peer_fp=peer_fp,
            msg_type="file",
            body=None,
            metadata={
                "name": f"file_{i}.bin",
                "size": 1024,
                "blob": f"{i:064x}",
            },
        )

    def run() -> None:
        # Default limit=2000 (bigger than population), exercises the
        # SELECT + ORDER BY + LIMIT + OFFSET pipeline once per call.
        state.list_peer_files(peer_fp)

    return _bench("list_peer_files (T3-I LIMIT)", run, iters=500)


# ── Content-Disposition build ──────────────────────────────────────

def _bench_content_disposition() -> dict:
    """T3-L: build Content-Disposition via RFC 5987 + ASCII fallback.
    Validate the per-download cost is sub-µs."""
    from urllib.parse import quote as _urlquote

    test_names = [
        "report.pdf",
        "naïve résumé.docx",   # unicode in name
        'evil"\n\r.exe',        # CRLF/quote injection bait
        "very_long_" * 30 + ".bin",
        "汉字文件.txt",         # CJK
    ]
    counter = {"i": 0}

    def run() -> None:
        raw_name = test_names[counter["i"] % len(test_names)]
        counter["i"] += 1
        ascii_name = "".join(
            c if 0x20 <= ord(c) < 0x7f and c not in ('"', "\\")
            else "_"
            for c in raw_name
        )[:200] or "file"
        _ = f'inline; filename="{ascii_name}"; filename*=UTF-8\'\'{_urlquote(raw_name, safe="")}'

    return _bench("content_disposition (T3-L)", run, iters=100_000)


# ── CDC empty-file path ────────────────────────────────────────────

def _bench_cdc_empty_input() -> dict:
    """T3-S: empty input must now return an empty chunk tuple
    (was: a single zero-length tail chunk)."""
    from one_link.cdc import chunk_bytes

    def run() -> None:
        out = chunk_bytes(b"")
        # Sanity: pure benchmark won't fail on a regression, but
        # this assertion is a one-time correctness check.
        assert out == (), f"empty input returned non-empty chunks: {out}"

    return _bench("cdc_empty_input (T3-S)", run, iters=100_000)


# ── T1-B candidate: per-chunk ratchet-keyed AEAD ───────────────────

def _bench_native_aead_current() -> dict:
    """Current production path: per-chunk encrypt uses session-static
    ``shared_secret`` as AEAD key; ratchet output is discarded.
    Measure the encrypt cost so we can compare with the T1-B candidate
    that uses ratchet output as the per-chunk key (constructs a new
    AEAD instance every call)."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    shared_secret = b"\xaa" * 32
    aead = ChaCha20Poly1305(shared_secret)
    plaintext = b"\xcc" * (256 * 1024)
    chunk_id = b"\xdd" * 32
    state = {"idx": 0}

    def run() -> None:
        nonce = state["idx"].to_bytes(12, "little")
        aead.encrypt(nonce, plaintext, chunk_id)
        state["idx"] += 1

    return _bench("native_aead current (static key, 256 KiB)", run, iters=200)


def _bench_native_aead_t1b_candidate() -> dict:
    """T1-B candidate: per-chunk key from a derived KDF. Mirrors the
    cost of using ``ratchet.next_key()`` output instead of session-
    static ``shared_secret``. The KDF call here is a stand-in;
    ``chunk_ratchet.ChunkRatchet.next_key`` calls into a native BLAKE3
    chain step.
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import hashlib

    base_secret = b"\xaa" * 32
    plaintext = b"\xcc" * (256 * 1024)
    chunk_id = b"\xdd" * 32
    index = 0
    chain_key = base_secret

    def run() -> None:
        nonlocal chain_key, index
        # KDF chain step (BLAKE3 stand-in via SHA256 since blake3 is
        # already heavily benchmarked elsewhere).
        chunk_key = hashlib.sha256(b"\x01" + chain_key).digest()
        chain_key = hashlib.sha256(b"\x02" + chain_key).digest()
        aead = ChaCha20Poly1305(chunk_key)
        nonce = index.to_bytes(12, "little")
        aead.encrypt(nonce, plaintext, chunk_id)
        index += 1

    return _bench(
        "native_aead T1-B candidate (per-chunk key, 256 KiB)",
        run, iters=200,
    )


# ── Real native_transfer encrypt+decrypt (post-T1-B) ───────────────

def _bench_native_transfer_e2e() -> dict:
    """End-to-end native_transfer.NativeTransferSession round-trip
    using the REAL production code path (post-T1-B per-chunk
    ratchet keying). 256 KiB plaintext, ChaCha20-Poly1305.
    """
    from one_link.native_transfer import (
        NativeTransferSession,
    )

    secret = b"\xaa" * 32
    sender = NativeTransferSession(
        shared_secret=secret, cipher_backend="fast", aead_kind="chacha",
    )
    receiver = NativeTransferSession(
        shared_secret=secret, cipher_backend="fast", aead_kind="chacha",
    )
    plaintext = b"\xcc" * (256 * 1024)

    def run() -> None:
        record = sender.encrypt_chunk_bytes(plaintext)
        out = receiver.decrypt_chunk(record)
        assert len(out) == len(plaintext), "round-trip plaintext length mismatch"

    return _bench("native_transfer e2e post-T1-B (256 KiB)", run, iters=200)


# ── Driver ─────────────────────────────────────────────────────────

def main() -> int:
    benchmarks = [
        _bench_dr_decrypt_pre_t1a,
        _bench_dr_decrypt,
        _bench_format_error,
        _bench_safe_transfer_name,
        _bench_csrf_origin_ok,
        _bench_file_wants_bounds,
        _bench_update_transfer,
        _bench_list_peer_files,
        _bench_content_disposition,
        _bench_cdc_empty_input,
        _bench_native_aead_current,
        _bench_native_aead_t1b_candidate,
        _bench_native_transfer_e2e,
    ]
    print(f"{'name':<46} {'ns/op (med)':>14} {'worst batch avg':>14} {'ops/sec':>14}")
    print("-" * 92)
    for b in benchmarks:
        try:
            r = b()
        except Exception as exc:
            print(f"{b.__name__:<46} FAILED: {exc}")
            continue
        print(
            f"{r['name']:<46}"
            f" {r['ns_per_op_median']:>14,.0f}"
            f" {r['ns_per_op_worst_batch_average']:>14,.0f}"
            f" {r['ops_per_sec_median']:>14,.0f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
