"""Perf regression gates for the CDC file engine.

These tests don't measure absolute performance — wall-clock numbers
vary too much across CI runners + developer laptops. They assert
*ranges* that catch regressions of the kind Wave 1d / 1f / 1g / 1i
introduced: a future change that puts the whole file back in heap,
or eats 10× as many wall-clock seconds, will fail one of these.

Each gate has a generous floor so green CI runs aren't flaky. The
goal is "alarm if something obvious broke," not "fail any
slowdown."

Tagged ``@pytest.mark.soak`` so they ride the same opt-in track as
``test_two_device_soak.py`` — pytest -m soak picks them up; a plain
``pytest`` skips them.
"""

from __future__ import annotations

import os
import statistics
import threading
import time
from pathlib import Path

import pytest

psutil = pytest.importorskip("psutil")

from tests.harness import (
    daemon_pair,
    inbox_files,
    request,
)


pytestmark = [pytest.mark.timeout(180), pytest.mark.soak]


def _build_payload(size: int, seed: int = 0) -> bytes:
    import random
    rng = random.Random(seed)
    block = bytes(rng.randint(0, 255) for _ in range(4096))
    if size <= len(block):
        return block[:size]
    repeat = size // len(block)
    tail = size % len(block)
    return block * repeat + block[:tail]


def _wait_for_payload(home: Path, payload: bytes, timeout: float) -> Path | None:
    end = time.time() + timeout
    while time.time() < end:
        for f in inbox_files(home):
            try:
                if f.stat().st_size == len(payload) and f.read_bytes() == payload:
                    return f
            except OSError:
                pass
        time.sleep(0.05)
    return None


# ──────────────────────────────────────────────────────────────────
# Memory regression gate (stream-to-disk must not regress)
# ──────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_perf_gate_receiver_rss_under_cap(tmp_path: Path) -> None:
    """The receiver's RSS during a 64 MiB transfer must stay under
    a generous cap. Pre-Wave-1d the receiver would have held all
    64 MiB in heap, pushing RSS well past 150 MiB; with stream-to-
    disk it sits around 86 MiB. Cap at 200 MiB — plenty of slack
    for noisy CI without missing real regressions."""
    size = 64 * 1024 * 1024  # 64 MiB
    payload = _build_payload(size)
    src = tmp_path / "perf_memory.bin"
    src.write_bytes(payload)

    samples: list[int] = []
    peak = [0]
    stop = threading.Event()

    def sample(pid: int) -> None:
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return
        while not stop.is_set():
            try:
                rss = proc.memory_info().rss
                samples.append(rss)
                peak[0] = max(peak[0], rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(0.05)

    with daemon_pair(pin_trust=True) as p:
        t = threading.Thread(target=sample, args=(p.b.proc.pid,), daemon=True)
        t.start()
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src), timeout=120)
        assert res["ok"], res
        landed = _wait_for_payload(p.b.home, payload, timeout=120.0)
        assert landed is not None, "64 MiB transfer never arrived"
        stop.set()
        t.join(timeout=2.0)

    # 200 MiB cap. Pre-Wave-1d: ~150 MiB minimum (base + file in
    # heap). Post-Wave-1d: ~86 MiB. The 200 MiB cap gives us
    # ~115 MiB of margin over the current real value AND ~50 MiB
    # under the pre-Wave-1d floor, so a regression that puts file
    # bytes back in heap fails cleanly.
    cap_bytes = 200 * 1024 * 1024
    assert peak[0] < cap_bytes, (
        f"receiver RSS peak {peak[0] / 1024 / 1024:.1f} MiB during a "
        f"64 MiB transfer exceeds the {cap_bytes / 1024 / 1024:.0f} MiB "
        f"regression cap — Wave 1d stream-to-disk may have regressed "
        f"and chunks are being buffered in heap again."
    )


# ──────────────────────────────────────────────────────────────────
# Throughput regression gate
# ──────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_perf_gate_throughput_16mib_floor(tmp_path: Path) -> None:
    """A 16 MiB loopback transfer must complete inside a floor with
    real headroom for the machine class it runs on.

    Dev hardware lands ~150 ms; the 2-second local floor flags a 10×
    regression. GitHub-hosted runners were MEASURED at 6.7–7.5 s for
    the identical code across release runs #3 and #5 (2 vCPUs, AV
    scanning spawned daemons, a concurrent quality job) — with and
    without a native CDC compiler, so that is the platform's honest
    baseline, not a code regression. The CI floor of 20 s still trips
    on a ~3× regression against that measured baseline and on every
    catastrophic class the gate exists for."""
    size = 16 * 1024 * 1024
    payload = _build_payload(size, seed=1)
    src = tmp_path / "perf_throughput.bin"
    src.write_bytes(payload)

    with daemon_pair(pin_trust=True) as p:
        t0 = time.time()
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src), timeout=60)
        assert res["ok"], res
        landed = _wait_for_payload(p.b.home, payload, timeout=60.0)
        elapsed = time.time() - t0
        assert landed is not None

    floor = 20.0 if os.environ.get("CI") == "true" else 2.0
    assert elapsed < floor, (
        f"16 MiB transfer took {elapsed:.2f}s (floor {floor:.0f}s) — "
        f"a real regression against this machine class's measured "
        f"baseline. Investigate before merging."
    )


# ──────────────────────────────────────────────────────────────────
# Cache GC regression gate
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_cache_gc_eviction_throughput(tmp_path: Path) -> None:
    """Eviction over a synthetic 1000-entry cache must finish in
    under 2 seconds. Current run: ~64 ms. Cap at 2 s gives 30×
    margin while catching catastrophic regressions in the
    file-walking or state-DB hookup."""
    from one_link.chunk_cache_gc import evict_to_target

    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    n = 1000
    chunk_size = 65536
    for i in range(n):
        h = f"{i:064x}"
        prefix = cache / h[:2]
        prefix.mkdir(parents=True, exist_ok=True)
        (prefix / h[2:]).write_bytes(b"\0" * chunk_size)
        # Backdate everything past the min_age floor.
        os.utime(prefix / h[2:], (now - 86400 * 30, now - 86400 * 30))

    class _NoopState:
        def forget_chunk_available(self, _h: str) -> None: pass

    t0 = time.perf_counter()
    report = evict_to_target(
        cache,
        max_bytes=(n * chunk_size) // 4,  # force aggressive eviction
        target_bytes=(n * chunk_size) // 8,
        state=_NoopState(),
        min_age_seconds=0,
        now=now,
    )
    elapsed = time.perf_counter() - t0
    assert report.evicted_files > 0, "eviction did not run"
    assert elapsed < 2.0, (
        f"cache GC took {elapsed:.2f}s for {n} entries — investigate."
    )


# ──────────────────────────────────────────────────────────────────
# Sidecar IO regression gate
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_sidecar_write_stays_near_raw_disk_cost(tmp_path: Path) -> None:
    """Resume sidecar persist must stay close to the raw cost of durably
    writing the same bytes on the same disk.

    The daemon writes one sidecar per 64 chunks at the debounce cadence, so
    a multi-ms regression here would dominate wall-time on big transfers.
    A fixed wall-clock cap measured the runner's disk, not the code: CI
    disks with write-through/AV overhead run ~30 ms where a dev NVMe runs
    ~740 µs, and both are the same healthy code. The regression this gate
    exists to catch (schema bloat, extra IO round-trips, validation
    blowups) shows up as the RATIO between persist_sidecar and a bare
    fsync'd write+replace of the same payload in the same directory — that
    ratio is disk-invariant. The absolute 5 ms cap still applies whenever
    the disk itself is fast enough for it to be meaningful."""
    from one_link.resume import ResumeSidecar, persist_sidecar

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "x.bin"
    partial.write_bytes(b"x" * 64)
    sc = ResumeSidecar(
        blob_hex="a" * 64,
        peer_fp="P" * 64,
        name="perf.bin",
        size=4096,
        out_path=str(partial),
        cdc_chunks=[
            {"index": 0, "hash": "a" * 64, "size": 4096, "start": 0, "end": 4096},
        ],
    )
    payload = sc.to_json()

    # Baseline: the exact durability primitive persist_sidecar uses —
    # same-directory temp, write, flush, fsync, atomic replace — with the
    # same payload bytes. 100 reps, median, same as the gated measurement.
    # INTERLEAVED, because the ratio is only disk-invariant if both halves see
    # the SAME disk conditions. Measuring all 100 baseline reps first and all
    # 100 gated reps afterwards silently assumes the machine does not change in
    # between, and on a shared runner it does: this gate failed at 12x with a
    # 5365 us baseline, meaning the disk was ALREADY pathological (a healthy
    # fsync is well under 2 ms) and got worse while the second loop ran. Nothing
    # about the code under test had changed. Alternating which operation goes
    # first also keeps neither one permanently paying for the other's cache
    # warming. The 8x cap and the 5 ms floor below are deliberately unchanged --
    # this makes the gate harder to fool, not easier to pass.
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    baseline_target = baseline_dir / "baseline.json"
    baseline_durations: list[float] = []
    durations: list[float] = []

    def _timed_baseline(index: int) -> float:
        tmp_file = baseline_dir / f".baseline_{index}.tmp"
        start = time.perf_counter()
        with tmp_file.open("x", encoding="utf-8", newline="") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, baseline_target)
        return time.perf_counter() - start

    def _timed_sidecar() -> float:
        start = time.perf_counter()
        persist_sidecar(inbox, sc)
        return time.perf_counter() - start

    for i in range(100):
        if i % 2 == 0:
            baseline_durations.append(_timed_baseline(i))
            durations.append(_timed_sidecar())
        else:
            durations.append(_timed_sidecar())
            baseline_durations.append(_timed_baseline(i))

    # Medians, so a single GC pause or scanner hit does not move the verdict.
    baseline_us = statistics.median(baseline_durations) * 1e6
    median_us = statistics.median(durations) * 1e6

    cap_us = max(5000.0, 8.0 * baseline_us)
    assert median_us < cap_us, (
        f"sidecar persist median {median_us:.0f} µs exceeds "
        f"{cap_us:.0f} µs (8× the {baseline_us:.0f} µs raw durable-write "
        f"baseline on this disk). Schema bloated? Extra IO round-trips?"
    )
