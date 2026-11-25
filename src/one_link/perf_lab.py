"""One Link performance lab.

Benchmarks here are deterministic, local, and dependency-light. They are not a
replacement for two-machine LAN throughput tests, but they give us repeatable
numbers for the core pieces that make "send anything" fast:

* whole-file hash throughput;
* fixed-manifest throughput;
* CDC indexing throughput;
* prior-knowledge byte savings;
* swarm scheduler planning speed;
* transfer-doctor/torture resilience;
* SQLite transfer-ledger write pressure;
* compression throughput.
* adaptive transfer-brain strategy selection.
* runtime ACK-clocked scheduler window control.
"""

from __future__ import annotations

import json
import platform
import random
import statistics
import tempfile
import time
import zlib
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

from .platform_guard import install_windows_platform_fastpath

install_windows_platform_fastpath()

from .cdc import build_dedup_plan, fixed_index_path, hash_path, index_path
from .daemon import Daemon, _stream_transfer_profile
from .native_cdc import get_native_cdc_scanner
from .benchmark_contract import comparison_issues, corpus_bytes, provenance
from .state import State
from .swarm_plan import plan_swarm_sources, source_from_hashes
from .transfer_brain import (
    AdaptiveTransferScheduler,
    TransferRouteObservation,
    decision_from_observations,
)
from .transfer_sim import simulate_never_lose_transfer, synthetic_manifest


MiB = 1024 * 1024


@dataclass(frozen=True)
class BenchResult:
    name: str
    metrics: dict[str, Any]
    seconds: float
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "seconds": round(self.seconds, 6),
            "metrics": self.metrics,
            "notes": self.notes,
        }


def _mb_per_s(nbytes: int, seconds: float) -> float:
    return round((nbytes / MiB) / max(seconds, 1e-9), 3)


def _time(fn: Callable[[], dict]) -> BenchResult:
    t0 = time.perf_counter()
    out = fn()
    elapsed = time.perf_counter() - t0
    return BenchResult(
        name=str(out.pop("name")),
        metrics=out,
        seconds=elapsed,
        notes=str(out.pop("notes", "")) if "notes" in out else "",
    )


def _index_benchmark(*, name: str, size_mib: int, seed: int, mode: str, repeats: int = 5) -> BenchResult:
    if size_mib < 1 or repeats < 1:
        raise ValueError("size_mib and repeats must be positive")
    size = size_mib * MiB
    durations = []
    scanner = get_native_cdc_scanner() if mode in {"cdc", "daemon"} else None
    scan_calls = 0
    with tempfile.TemporaryDirectory(prefix="ol_perf_index_") as td:
        path = Path(td) / "payload.bin"
        path.write_bytes(corpus_bytes(size, seed=seed))
        expected_hash = hash_path(path)
        daemon = Daemon.__new__(Daemon)
        daemon.state = None  # explicitly measure an uncached production preparation
        daemon._outbound_sessions = {}
        index_kind = mode
        last = None
        # Observe the actual dispatch, not just native availability. The small
        # wrapper overhead is included in the measured region and disclosed.
        original_scan = scanner.scan if scanner is not None else None

        def observed_scan(*args, **kwargs):
            nonlocal scan_calls
            scan_calls += 1
            assert original_scan is not None
            return original_scan(*args, **kwargs)

        observer = patch.object(scanner, "scan", observed_scan) if scanner is not None else nullcontext()
        with observer:
            for _ in range(repeats):
                started = time.perf_counter()
                if mode == "hash":
                    observed_hash = hash_path(path)
                elif mode == "fixed":
                    last = fixed_index_path(path)
                    observed_hash = last.blob_hash
                elif mode == "cdc":
                    last = index_path(path)
                    observed_hash = last.blob_hash
                else:
                    prepared = daemon.prepare_file_for_transfer(path)
                    last = prepared.file_index
                    index_kind = prepared.index_kind
                    observed_hash = last.blob_hash
                    if prepared.cache_hit:
                        raise RuntimeError("uncached preparation unexpectedly reused an index")
                durations.append(time.perf_counter() - started)
                if observed_hash != expected_hash:
                    raise RuntimeError("index/hash result differs from verified input")
                if last is not None and (last.size != size or sum(c.size for c in last.chunks) != size):
                    raise RuntimeError("index does not cover the complete source")
    elapsed = statistics.median(durations)
    engine = getattr(last, "engine", None) or ("ctypes-c" if scan_calls else "blake3" if mode == "hash" else "python-boundaries+blake3")
    return BenchResult(
        name=name, seconds=elapsed,
        metrics={
            "size_bytes": size, "chunks": len(last.chunks) if last is not None else 0,
            "mib_per_s": _mb_per_s(size, elapsed), "blob_hash": expected_hash,
            "engine": engine, "index_kind": index_kind,
            "native_scan_calls": scan_calls, "samples_sec": durations,
            "samples": repeats, "verified_samples": repeats,
            "measurement_scope": "production_descriptor_preparation_no_persistent_cache" if mode == "daemon" else "indexing_component",
            "storage_state": "freshly written OS-cache-warm regular file",
        },
        notes="Input generation excluded; actual dispatch observer included; output hash/coverage verification outside timing.",
    )


def bench_hash_only(*, size_mib: int, seed: int) -> BenchResult:
    return _index_benchmark(name="hash_only_manifest", size_mib=size_mib, seed=seed, mode="hash")


def bench_fixed_indexing(*, size_mib: int, seed: int) -> BenchResult:
    return _index_benchmark(name="fixed_indexing", size_mib=size_mib, seed=seed, mode="fixed")


def bench_cdc_indexing(*, size_mib: int, seed: int) -> BenchResult:
    return _index_benchmark(name="cdc_indexing", size_mib=size_mib, seed=seed, mode="cdc")


def bench_daemon_preparation(*, size_mib: int, seed: int) -> BenchResult:
    return _index_benchmark(name="daemon_source_preparation", size_mib=size_mib, seed=seed, mode="daemon")


def bench_prior_knowledge(*, size_mib: int, mutation_bytes: int, seed: int) -> BenchResult:
    def run() -> dict:
        rng = random.Random(seed)  # nosec B311
        with tempfile.TemporaryDirectory(prefix="ol_perf_prior_") as td:
            root = Path(td)
            base = root / "base.bin"
            changed = root / "changed.bin"
            payload = rng.randbytes(size_mib * MiB)
            base.write_bytes(payload)
            insert = rng.randbytes(mutation_bytes)
            changed.write_bytes(payload[: MiB] + insert + payload[MiB:])
            base_idx = index_path(base)
            changed_idx = index_path(changed)
            t0 = time.perf_counter()
            plan = build_dedup_plan(changed_idx.chunks, {c.hash for c in base_idx.chunks})
            plan_seconds = time.perf_counter() - t0
        return {
            "name": "prior_knowledge_dedup",
            "changed_size_bytes": changed_idx.size,
            "chunks": changed_idx.chunk_count if hasattr(changed_idx, "chunk_count") else len(changed_idx.chunks),
            "hit_rate": round(plan.hit_rate, 6),
            "bytes_to_send": plan.bytes_to_send,
            "bytes_saved": plan.byte_savings,
            "bandwidth_reduction": round(plan.byte_savings / max(1, changed_idx.size), 6),
            "plan_micros": round(plan_seconds * 1_000_000, 3),
        }

    return _time(run)


def bench_swarm_scheduler(*, chunks: int, sources: int, seed: int) -> BenchResult:
    def run() -> dict:
        manifest = synthetic_manifest(
            name="scheduler.bin",
            size=chunks * MiB,
            chunk_size=MiB,
        )
        rng = random.Random(seed)  # nosec B311
        srcs = []
        all_hashes = [c.hash for c in manifest.chunks]
        for i in range(sources):
            # Each source gets a deterministic overlapping subset.
            claim = [
                h for j, h in enumerate(all_hashes)
                if (j + i) % max(2, min(7, sources)) == 0 or rng.random() < 0.08
            ]
            srcs.append(source_from_hashes(
                f"{i:064x}",
                claim,
                trust_score=1.0 + (i % 3) * 0.25,
                latency_ms=5.0 + i,
                bandwidth_bps=50_000_000 + (i * 5_000_000),
                reliability=0.90 + (i % 5) * 0.015,
            ))
        t0 = time.perf_counter()
        plan = plan_swarm_sources(manifest=manifest, needed_indexes=None, sources=srcs)
        elapsed = time.perf_counter() - t0
        return {
            "name": "swarm_scheduler",
            "chunks": chunks,
            "sources": sources,
            "assigned": len([a for a in plan.assignments if a.status == "assigned"]),
            "missing": len(plan.missing_indexes),
            "chunks_per_s": round(chunks / max(elapsed, 1e-9), 3),
            "assigned_bytes": plan.assigned_bytes,
            "missing_bytes": plan.missing_bytes,
            "source_count": len(plan.sources),
        }

    return _time(run)


def bench_torture_sim(*, size_mib: int, seed: int) -> BenchResult:
    def run() -> dict:
        report = simulate_never_lose_transfer(
            size=size_mib * MiB,
            chunk_size=4 * MiB,
            seed=seed,
            drop_rate=0.25,
            corruption_rate=0.04,
        )
        return {
            "name": "never_lose_torture_sim",
            "delivered": report.delivered,
            "size_bytes": report.file_size,
            "chunks_total": report.chunks_total,
            "attempts": report.attempts,
            "retries": report.retries,
            "offline_waits": report.offline_waits,
            "corruptions": report.corruptions,
            "bytes_sent": report.bytes_sent,
            "bytes_saved": report.bytes_saved,
            "best_route": report.best_route,
        }

    return _time(run)


def bench_sqlite_ledger(*, rows: int) -> BenchResult:
    def run() -> dict:
        with tempfile.TemporaryDirectory(prefix="ol_perf_state_") as td:
            state = State(db_path=Path(td) / "state.db")
            t0 = time.perf_counter()
            for i in range(rows):
                state.upsert_transfer(
                    id=f"bench-{i}",
                    direction="out",
                    peer_fp="aa" * 32,
                    kind="file",
                    name=f"file-{i}.bin",
                    size=1024,
                    status="active" if i % 2 else "paused",
                    progress_bytes=i % 1024,
                    total_bytes=1024,
                    chunks_done=i % 4,
                    chunks_total=4,
                    metadata={"bench": True, "i": i},
                )
            elapsed = time.perf_counter() - t0
            listed = len(state.list_transfers(limit=min(rows, 500)))
            state.close()
        return {
            "name": "sqlite_transfer_ledger",
            "rows": rows,
            "writes_per_s": round(rows / max(elapsed, 1e-9), 3),
            "listed": listed,
        }

    return _time(run)


def bench_compression(*, size_mib: int) -> BenchResult:
    def run() -> dict:
        data = (b"compressible-transfer-block\n" * ((size_mib * MiB) // 28 + 1))[: size_mib * MiB]
        samples: list[float] = []
        packed_size = 0
        for _ in range(3):
            t0 = time.perf_counter()
            packed = zlib.compress(data, level=1)
            samples.append(time.perf_counter() - t0)
            packed_size = len(packed)
        med = statistics.median(samples)
        return {
            "name": "zlib_level1_compression",
            "size_bytes": len(data),
            "packed_bytes": packed_size,
            "ratio": round(packed_size / max(1, len(data)), 6),
            "mib_per_s": _mb_per_s(len(data), med),
        }

    return _time(run)


def bench_transfer_brain(*, size_mib: int) -> BenchResult:
    def run() -> dict:
        observations = [
            TransferRouteObservation(
                route="lan",
                ok=True,
                latency_ms=4.0 + (i % 3),
                bandwidth_bps=700_000_000 + (i % 5) * 20_000_000,
                energy_cost=0.6,
            )
            for i in range(40)
        ]
        observations.extend(
            TransferRouteObservation(route="relay", ok=(i % 4 != 0), latency_ms=95.0, bandwidth_bps=60_000_000)
            for i in range(20)
        )
        t0 = time.perf_counter()
        low_prior = decision_from_observations(
            size_bytes=size_mib * MiB,
            supports_cdc=True,
            supports_swarm=True,
            prior_hit_rate=0.0,
            observations=observations,
            routes=("lan", "relay"),
        )
        high_prior_python = decision_from_observations(
            size_bytes=size_mib * MiB,
            supports_cdc=True,
            supports_swarm=True,
            prior_hit_rate=0.985,
            observations=observations,
            routes=("lan", "relay"),
        )
        high_prior_accelerated = decision_from_observations(
            size_bytes=size_mib * MiB,
            supports_cdc=True,
            supports_swarm=True,
            prior_hit_rate=0.985,
            observations=observations,
            routes=("lan", "relay"),
            speeds={"cdc_mib_s": 1200.0},
        )
        elapsed = time.perf_counter() - t0
        return {
            "name": "adaptive_transfer_brain",
            "decisions_per_s": round(3 / max(elapsed, 1e-9), 3),
            "low_prior_mode": low_prior.selected.mode.value,
            "high_prior_python_mode": high_prior_python.selected.mode.value,
            "high_prior_accelerated_mode": high_prior_accelerated.selected.mode.value,
            "low_prior_ms": round(low_prior.selected.estimated_ms, 3),
            "high_prior_python_ms": round(high_prior_python.selected.estimated_ms, 3),
            "high_prior_accelerated_ms": round(high_prior_accelerated.selected.estimated_ms, 3),
            "high_prior_accelerated_wire_bytes": high_prior_accelerated.selected.estimated_wire_bytes,
            "health": high_prior_accelerated.health.value,
        }

    return _time(run)


def bench_stream_pipeline_profiles() -> BenchResult:
    def run() -> dict:
        sizes = {
            "small": 8 * MiB,
            "medium": 256 * MiB,
            "large": 2 * 1024 * MiB,
            "huge": 20 * 1024 * MiB,
        }
        profiles = {name: _stream_transfer_profile(size) for name, size in sizes.items()}
        return {
            "name": "stream_pipeline_profiles",
            "small_chunk": profiles["small"]["chunk_size"],
            "medium_chunk": profiles["medium"]["chunk_size"],
            "large_chunk": profiles["large"]["chunk_size"],
            "huge_chunk": profiles["huge"]["chunk_size"],
            "huge_window_bytes": profiles["huge"]["window_bytes"],
            "huge_window_chunks": profiles["huge"]["window_chunks"],
            "notes": "bounded in-flight baseline stream profile",
        }

    return _time(run)


def bench_adaptive_runtime_scheduler(*, chunks: int) -> BenchResult:
    def run() -> dict:
        scheduler = AdaptiveTransferScheduler({
            "chunk_size": MiB,
            "window_chunks": 4,
            "target_ack_ms": 18,
            "reason": "perf_lab",
        }, max_window_chunks=32)
        slow_events = 0
        for i in range(max(1, int(chunks))):
            ack_ms = 8.0 + (i % 5)
            if i and i % 257 == 0:
                ack_ms = 120.0
                slow_events += 1
            scheduler.observe_ack(
                ack_ms=ack_ms,
                raw_bytes=MiB,
                wire_bytes=MiB,
                in_flight_chunks=max(0, scheduler.window_chunks - 1),
            )
        snap = scheduler.snapshot()
        return {
            "name": "adaptive_runtime_scheduler",
            "chunks": int(chunks),
            "chunks_per_s": 0,  # filled by _time wrapper below is not possible; use seconds outside metrics
            "final_window_chunks": snap["window_chunks"],
            "ack_count": snap["ack_count"],
            "slow_events": slow_events,
            "timeline_events": len(snap["timeline"]),
            "ack_ema_ms": snap["ack_ema_ms"] or 0,
        }

    result = _time(run)
    metrics = dict(result.metrics)
    metrics["chunks_per_s"] = round(float(metrics["chunks"]) / max(result.seconds, 1e-9), 3)
    return BenchResult(
        name=result.name,
        metrics=metrics,
        seconds=result.seconds,
        notes="ACK-clocked live transfer window controller",
    )


def run_perf_lab(
    *,
    scale: str = "quick",
    seed: int = 20260507,
) -> dict:
    if scale not in {"quick", "standard", "heavy"}:
        raise ValueError("scale must be quick, standard, or heavy")
    cfg = {
        "quick": {"cdc_mib": 4, "prior_mib": 4, "scheduler_chunks": 512, "ledger_rows": 500, "sim_mib": 256},
        "standard": {"cdc_mib": 32, "prior_mib": 32, "scheduler_chunks": 4096, "ledger_rows": 5000, "sim_mib": 1024},
        "heavy": {"cdc_mib": 256, "prior_mib": 256, "scheduler_chunks": 32768, "ledger_rows": 25000, "sim_mib": 10 * 1024},
    }[scale]
    started = time.time()
    results = [
        bench_hash_only(size_mib=cfg["cdc_mib"], seed=seed),
        bench_fixed_indexing(size_mib=cfg["cdc_mib"], seed=seed),
        bench_cdc_indexing(size_mib=cfg["cdc_mib"], seed=seed),
        bench_daemon_preparation(size_mib=cfg["cdc_mib"], seed=seed),
        bench_prior_knowledge(size_mib=cfg["prior_mib"], mutation_bytes=4096, seed=seed + 1),
        bench_swarm_scheduler(chunks=cfg["scheduler_chunks"], sources=12, seed=seed + 2),
        bench_torture_sim(size_mib=cfg["sim_mib"], seed=seed + 3),
        bench_sqlite_ledger(rows=cfg["ledger_rows"]),
        bench_compression(size_mib=max(1, cfg["cdc_mib"] // 2)),
        bench_transfer_brain(size_mib=cfg["sim_mib"]),
        bench_stream_pipeline_profiles(),
        bench_adaptive_runtime_scheduler(chunks=cfg["scheduler_chunks"]),
    ]
    return {
        "schema": "one-link-perf-lab-v1",
        "scale": scale,
        "measurement_contract": {"index_repetitions": 5, "corpus": "seeded-randbytes-v1", "storage_state": "OS-cache-warm", "scope": "local-components-and-descriptor-preparation"},
        "provenance": provenance(),
        "seed": seed,
        "started_unix": started,
        "duration_s": round(time.time() - started, 6),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "benchmarks": [r.to_dict() for r in results],
    }


def write_report(report: dict, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return output


def compare_reports(old: dict, new: dict) -> dict:
    """Return metric deltas from two perf-lab reports.

    Ratios greater than 1.0 mean the new report is higher. Whether higher is
    better depends on the metric, so we keep this as raw math for now.
    """

    issues = comparison_issues(old, new)
    old_by_name = {b["name"]: b for b in old.get("benchmarks", [])}
    new_by_name = {b["name"]: b for b in new.get("benchmarks", [])}
    benches: dict[str, dict] = {}
    all_issues = list(issues)
    for name in sorted(set(old_by_name) & set(new_by_name)):
        old_metrics = old_by_name[name].get("metrics", {})
        new_metrics = new_by_name[name].get("metrics", {})
        metrics: dict[str, dict] = {}
        bench_issues = list(issues)
        for contract_key in ("engine", "index_kind", "measurement_scope", "size_bytes", "storage_state"):
            if old_metrics.get(contract_key) != new_metrics.get(contract_key):
                bench_issues.append(f"different {name}.{contract_key}")
        all_issues.extend(issue for issue in bench_issues if issue not in all_issues)
        for key in sorted(set(old_metrics) & set(new_metrics)):
            old_v = old_metrics[key]
            new_v = new_metrics[key]
            if isinstance(old_v, bool) or isinstance(new_v, bool):
                metrics[key] = {"old": old_v, "new": new_v, "changed": old_v != new_v}
            elif isinstance(old_v, (int, float)) and isinstance(new_v, (int, float)):
                delta = float(new_v) - float(old_v)
                ratio = None if float(old_v) == 0 or bench_issues else float(new_v) / float(old_v)
                metrics[key] = {
                    "old": old_v,
                    "new": new_v,
                    "delta": round(delta, 6),
                    "ratio": round(ratio, 6) if ratio is not None else None,
                    "comparable": not bench_issues,
                    "comparison_issues": bench_issues,
                }
            elif old_v != new_v:
                metrics[key] = {"old": old_v, "new": new_v, "changed": True}
        benches[name] = metrics
    return {
        "schema": "one-link-perf-compare-v1",
        "status": "inconclusive" if all_issues else "comparable",
        "comparison_issues": all_issues,
        "old_scale": old.get("scale"),
        "new_scale": new.get("scale"),
        "benchmarks": benches,
    }
