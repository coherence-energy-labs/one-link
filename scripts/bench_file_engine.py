"""End-to-end file engine benchmark.

Spawns a daemon pair, runs a series of representative scenarios, and
reports throughput / memory / chunk-count / cache-hit metrics so we
can answer the question "is it actually fast and lean?" with
numbers instead of vibes.

Scenarios include cold transfers across explicit corpora, sender/receiver RSS,
warm and edited-file reuse, mixed-size trees, concurrency, verified transport
comparisons, restart delivery, metadata persistence and cache eviction.
Every attempt has an outcome. Failed or inconclusive scenarios return nonzero;
successful-only latency summaries never replace the completion rate.

Run::

    python scripts/bench_file_engine.py

Pass --json to emit machine-readable results::

    python scripts/bench_file_engine.py --json bench_results.json
"""

from __future__ import annotations

import argparse
import hashlib
import blake3
import http.client
import json
import os
import statistics
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

# Make the project's tests/ harness importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psutil  # noqa: E402  (must come after sys.path mutation)

from one_link import app as app_mod  # noqa: E402
from one_link import control_ipc  # noqa: E402
from one_link.benchmark_contract import CORPORA, corpus_bytes, file_sha256, provenance  # noqa: E402
from tests.harness import (  # noqa: E402
    LIVE_INTEGRATION_ENV,
    _bring_up,
    _stop,
    private_mdns_type,
    daemon_pair as _daemon_pair,
    inbox_files,
    request,
)


# ──────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────

def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KiB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MiB"
    return f"{n / 1024 ** 3:.2f} GiB"


def _api(home: Path, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call one benchmark daemon's authenticated loopback API."""

    data_dir = home / "data"
    control_port = int(
        control_ipc.read_private_bytes_strict(
            data_dir / "control.port",
            max_bytes=64,
            label="control port",
        )
        .decode("ascii")
        .strip()
    )
    secret = control_ipc.read_control_secret(data_dir)
    daemon = app_mod.resolve_authenticated_daemon(
        control_port,
        secret,
        timeout=10.0,
    )
    if daemon is None:
        raise RuntimeError("benchmark daemon/UI authentication failed")
    port = daemon.server_port
    token = daemon.token
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    if not 200 <= response.status < 300:
        detail = raw.decode("utf-8", errors="replace")[:1024]
        raise RuntimeError(
            f"benchmark API {method} {path} failed ({response.status}): {detail}"
        )
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"benchmark API {method} {path} returned a non-object")
    return payload


def _wait_api_peer(home: Path, short_id: str, *, timeout_s: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        payload = _api(home, "GET", "/api/peers?include_unpaired=1")
        last = [item for item in payload.get("peers", []) if isinstance(item, dict)]
        for peer in last:
            if peer.get("short_id") == short_id:
                return peer
        time.sleep(0.05)
    raise RuntimeError(f"benchmark peer {short_id} did not appear; peers={last!r}")


@contextmanager
def daemon_pair() -> Iterator[Any]:
    """Yield an isolated pair with explicit file capability policy."""

    scope = private_mdns_type()
    with patch("tests.harness.private_mdns_type", return_value=scope), _daemon_pair() as pair:
        pair.benchmark_mdns_type = scope
        peer_a = _wait_api_peer(pair.b.home, pair.a.short_id)
        peer_b = _wait_api_peer(pair.a.home, pair.b.short_id)
        for home, peer in ((pair.a.home, peer_b), (pair.b.home, peer_a)):
            fingerprint = str(peer.get("fingerprint") or "")
            if not fingerprint:
                raise RuntimeError("benchmark peer did not expose a fingerprint")
            trust_result = _api(
                home,
                "POST",
                f"/api/peers/{fingerprint}/trust",
                {"trust": "pinned"},
            )
            if trust_result.get("ok") is not True:
                raise RuntimeError(f"benchmark trust setup failed: {trust_result!r}")
            result = _api(
                home,
                "POST",
                f"/api/peers/{fingerprint}/capabilities",
                {"allowed": ["chat", "files"], "note": "isolated benchmark lane"},
            )
            if result.get("ok") is not True:
                raise RuntimeError(f"benchmark capability setup failed: {result!r}")
        yield pair


def _human_throughput(bytes_: int, seconds: float) -> str:
    if seconds <= 0:
        return "∞"
    bps = bytes_ / seconds
    if bps < 1024 ** 2:
        return f"{bps / 1024:.1f} KiB/s"
    if bps < 1024 ** 3:
        return f"{bps / 1024 ** 2:.1f} MiB/s"
    return f"{bps / 1024 ** 3:.2f} GiB/s"


def _wait_for_payload(home: Path, payload: bytes, timeout: float, *, exclude: set[Path] | None = None) -> tuple[Path | None, float]:
    """Independently verify a newly delivered file with bounded-memory hashing."""
    expected = hashlib.sha256(payload).hexdigest()
    excluded = exclude or set()
    checked: set[tuple[str, int, int]] = set()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for path in inbox_files(home):
            if path in excluded:
                continue
            try:
                stat = path.stat()
                identity = (str(path), stat.st_mtime_ns, stat.st_size)
                if stat.st_size != len(payload) or identity in checked:
                    continue
                checked.add(identity)
                if file_sha256(path) == expected:
                    return path, time.perf_counter()
            except OSError:
                continue
        time.sleep(0.05)
    return None, time.perf_counter()


def _payload_counts(record: dict) -> tuple[dict, dict] | None:
    """Validate a labelled accounting window before using its route claim."""
    bytes_by_route = record.get("payload_bytes_by_transport")
    chunks_by_route = record.get("payload_chunks_by_transport")
    routes = {"tcp", "relay", "webrtc", "quic", "unknown"}
    if not isinstance(bytes_by_route, dict) or not isinstance(chunks_by_route, dict):
        return None
    if set(bytes_by_route) != set(chunks_by_route) or not set(bytes_by_route) <= routes:
        return None
    if any(type(v) is not int or v < 0 for v in bytes_by_route.values()):
        return None
    if any(type(v) is not int or v <= 0 for v in chunks_by_route.values()):
        return None
    label = next(iter(chunks_by_route)) if len(chunks_by_route) == 1 else (
        "mixed" if chunks_by_route else "none")
    if record.get("payload_transport") != label:
        return None
    if type(record.get("payload_fallbacks")) is not int or record["payload_fallbacks"] < 0:
        return None
    return bytes_by_route, chunks_by_route


def _nonnegative_counter(value: Any) -> bool:
    return type(value) is int and value >= 0


def _verified_payload_accounting(result: dict) -> bool:
    """Validate units, counter identities and attempt/whole-transfer linkage.

    This is application acknowledgement accounting, not a packet capture.
    A route label cannot override contradictory counters or missing evidence.
    """
    if (result.get("payload_accounting_scope") != "acknowledged_application_payload"
            or result.get("payload_bytes_unit") != "encoded_payload_bytes"
            or result.get("payload_accounting_window") != "attempt"):
        return False
    current = _payload_counts(result)
    totals = result.get("payload_transfer_totals")
    if current is None or not isinstance(totals, dict):
        return False
    overall = _payload_counts(totals)
    if overall is None:
        return False
    byte_counts, chunk_counts = current
    total_bytes, total_chunks = overall
    if not all(_nonnegative_counter(v) for v in (
        result.get("wire_bytes_sent"), result.get("raw_bytes_sent"),
        totals.get("wire_bytes"), totals.get("raw_bytes"), totals.get("chunks"),
    )):
        return False
    return (
        result["wire_bytes_sent"] == sum(byte_counts.values())
        and totals["wire_bytes"] == sum(total_bytes.values())
        and totals["chunks"] == sum(total_chunks.values())
        and totals["raw_bytes"] >= result["raw_bytes_sent"]
        and totals["payload_fallbacks"] >= result["payload_fallbacks"]
        and all(total_bytes.get(k, -1) >= v for k, v in byte_counts.items())
        and all(total_chunks.get(k, -1) >= v for k, v in chunk_counts.items())
    )


def _forced_route_verified(result: dict, requested: str, size: int) -> bool:
    if not _verified_payload_accounting(result):
        return False
    totals = result["payload_transfer_totals"]
    return (
        result.get("transport_requested") == requested
        and result["payload_transport"] == requested
        and result["payload_fallbacks"] == 0
        and totals["payload_fallbacks"] == 0
        and totals["payload_transport"] == requested
        and (size == 0 or result["payload_bytes_by_transport"].get(requested, 0) > 0)
    )


def _transfer_attempt(pair: Any, src: Path, payload: bytes, *, transport: str = "auto", timeout: float = 300.0) -> dict:
    """One request-to-verified-receiver observation; no failed attempt disappears."""
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    expected_blake3 = blake3.blake3(payload).hexdigest()
    previous = set(inbox_files(pair.b.home))
    row: dict[str, Any] = {
        "status": "failed", "logical_bytes": len(payload),
        "source_sha256": expected_sha256, "source_blake3": expected_blake3,
        "transport_requested": transport, "payload_transport": None,
        "payload_transport_verified": False, "receiver_verified": False,
        "application_wire_bytes": None, "wire_accounting_scope": "application payload; not packet capture",
    }
    started = time.perf_counter()
    try:
        response = request(pair.a.control_port, cmd="send_file", peer=pair.b.short_id,
                           path=str(src), transport=transport, timeout=timeout)
        row["request_seconds"] = time.perf_counter() - started
        row["request_ok"] = response.get("ok") is True
        if not row["request_ok"]:
            error = str(response.get("error") or "send request rejected")
            row.update(error=error, error_class=str(response.get("error_class") or "SendRejected"))
            if "transport" in error.lower() and any(word in error.lower() for word in ("unsupported", "unavailable", "disabled", "not supported")):
                row["status"] = "inconclusive"
            return row
        result = response.get("result")
        if not isinstance(result, dict):
            row["error"] = "send response omitted its result"
            return row
        row["application_confirmed"] = result.get("confirmed") is True
        row["application_size_matches"] = result.get("size") == len(payload)
        row["application_hash_matches"] = result.get("blob") == expected_blake3
        row["application_wire_bytes"] = result.get("wire_bytes_sent")
        row["application_raw_bytes"] = result.get("raw_bytes_sent")
        row["skipped_chunks"] = result.get("cdc_skipped")
        row["transfer_report"] = result.get("transfer_report")
        row["performance_summary"] = result.get("performance_summary")
        # The route fields describe this one call (window "attempt") in encoded
        # payload bytes; keep the receipt's own unit, window and whole-transfer
        # totals beside them so a stored row cannot be read in another unit.
        for key in ("payload_transport", "payload_bytes_by_transport", "payload_chunks_by_transport", "payload_fallbacks",
                    "payload_accounting_scope", "payload_bytes_unit", "payload_accounting_window", "payload_transfer_totals"):
            row[key] = result.get(key)
        row["payload_transport_verified"] = _verified_payload_accounting(result)
        remaining = max(0.0, timeout - (time.perf_counter() - started))
        landed, _ = _wait_for_payload(pair.b.home, payload, remaining, exclude=previous)
        row["receiver_verified"] = landed is not None
        row["verified_completion_seconds"] = time.perf_counter() - started
        if landed is None:
            row["error"] = "verified receiver file did not arrive before the deadline"
        elif not all(row[key] for key in ("application_confirmed", "application_size_matches", "application_hash_matches")):
            row["error"] = "receiver bytes arrived but application commit/hash/size receipt was not confirmed"
        elif transport != "auto" and not _forced_route_verified(result, transport, len(payload)):
            row.update(status="inconclusive", error="forced transport was not verified by payload accounting")
        else:
            row["status"] = "passed"
            row["logical_goodput_bps"] = len(payload) / max(row["verified_completion_seconds"], 1e-9)
        return row
    except Exception as exc:
        row.update(error=str(exc), error_class=type(exc).__name__)
        return row
    finally:
        row["attempt_seconds"] = time.perf_counter() - started


def _attempt_summary(attempts: list[dict]) -> dict:
    successful = [row for row in attempts if row.get("status") == "passed"]
    times = [float(row["verified_completion_seconds"]) for row in successful]
    status = "passed" if attempts and len(successful) == len(attempts) else "failed" if any(row.get("status") == "failed" for row in attempts) else "inconclusive"
    return {
        "status": status, "attempted": len(attempts), "completed": len(successful),
        "completion_rate": len(successful) / len(attempts) if attempts else 0.0,
        "successful_elapsed_samples_sec": times,
        "successful_elapsed_median_sec": statistics.median(times) if times else None,
        "attempts": attempts,
    }


def _authenticated_benchmark_process(handle: Any) -> tuple[psutil.Process, tuple]:
    """Bind measurements to the serving daemon, not its Python launcher.

    A Windows virtualenv launcher can be a different process. Only the
    authenticated test daemon may name the PID, and it must belong to the
    disposable process tree we started for that exact profile. Do not attach
    the sampler to an arbitrary local process or a reused PID.
    """
    status = request(handle.control_port, cmd="status", timeout=10.0)
    pid = status.get("pid")
    instance = status.get("daemon_instance_id")
    source = status.get("source_fingerprint")
    home = status.get("home")
    me = status.get("me")
    if (
        status.get("ok") is not True
        or type(pid) is not int or pid <= 0
        or not isinstance(instance, str) or not instance
        or not isinstance(source, str) or not source
        or not isinstance(home, str) or not home
        or Path(home).resolve() != (handle.home / "data").resolve()
        or not isinstance(me, dict) or me.get("fingerprint") != handle.fingerprint
        or handle.proc.poll() is not None
    ):
        raise RuntimeError("benchmark daemon identity could not be authenticated")
    proc = psutil.Process(pid)
    if pid != handle.proc.pid and not any(
        parent.pid == handle.proc.pid for parent in proc.parents()
    ):
        raise RuntimeError("authenticated benchmark PID is outside the spawned process tree")
    created = proc.create_time()
    if not proc.is_running():
        raise RuntimeError("authenticated benchmark process is no longer running")
    return proc, (pid, created, instance, source)


class _RssTracker:
    """Bounded sampled RSS, with process identity and coverage failure evidence.

    This is NOT the OS high-water counter or a whole-process-tree measurement.
    A missing sample, lost process or sampler that fails to terminate cannot
    produce a qualified memory observation. The baseline and final sample
    bracket the transfer; intermediate values are aggregated in O(1) space.
    """

    def __init__(self, proc: psutil.Process, interval: float = 0.05) -> None:
        if not 0 < interval <= 1:
            raise ValueError("RSS sample interval must be in (0, 1] seconds")
        self.proc = proc
        self.pid = proc.pid
        self.interval = interval
        self._stop = threading.Event()
        self._peak = 0
        self._sum = 0
        self._count = 0
        self._first: float | None = None
        self._last: float | None = None
        self._max_gap = 0.0
        self._error: str | None = None
        self._thread: threading.Thread | None = None
        self.baseline_bytes: int | None = None

    def _sample(self) -> int:
        if not self.proc.is_running():
            raise RuntimeError("benchmark process exited or PID was reused")
        rss = self.proc.memory_info().rss
        if type(rss) is not int or rss <= 0:
            raise RuntimeError("invalid RSS observation")
        if not self.proc.is_running():
            raise RuntimeError("benchmark process identity changed during sample")
        observed = time.perf_counter()
        if self._last is not None:
            self._max_gap = max(self._max_gap, observed - self._last)
        if self._first is None:
            self._first = observed
        self._last = observed
        self._peak = max(self._peak, rss)
        self._sum += rss
        self._count += 1
        return rss

    def start(self) -> None:
        if self._thread is not None or self._stop.is_set():
            raise RuntimeError("RSS sampler cannot be restarted")
        self.baseline_bytes = self._sample()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._sample()
            except (psutil.Error, OSError, RuntimeError) as exc:
                self._error = type(exc).__name__
                return

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is None:
            raise RuntimeError("RSS sampler was not started")
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            # Do not race the still-running collector to read its counters.
            return {
                "valid": False, "error": "RSS sampler did not stop",
                "peak_bytes": None, "mean_bytes": None, "samples": None,
                "sample_duration_sec": None, "max_sample_gap_sec": None,
            }
        if self._error is None:
            try:
                self._sample()
            except (psutil.Error, OSError, RuntimeError) as exc:
                self._error = type(exc).__name__
        duration = (self._last - self._first
                    if self._first is not None and self._last is not None else None)
        valid = self._error is None and self._count >= 2
        return {
            "valid": valid, "error": self._error,
            "peak_bytes": self._peak if valid else None,
            "mean_bytes": self._sum // self._count if valid else None,
            "samples": self._count,
            "sample_duration_sec": duration,
            "max_sample_gap_sec": self._max_gap,
        }


def _build_payload(size: int, seed: int = 0, *, kind: str = "random") -> bytes:
    """Build a versioned deterministic corpus; random is the default."""
    return corpus_bytes(size, seed=seed, kind=kind)


# ──────────────────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────────────────

SIZES_DEFAULT = [
    ("1 KiB",   1024),
    ("1 MiB",   1024 * 1024),
    ("16 MiB",  16 * 1024 * 1024),
    ("64 MiB",  64 * 1024 * 1024),
    ("256 MiB", 256 * 1024 * 1024),
]

# How many times to repeat each ``--scenario cold`` size; we
# report the median so a single hiccup doesn't skew the headline
# numbers. Override via ``--repeat`` on the command line.
REPEAT_DEFAULT = 3


def bench_cold_transfer(sizes: list[tuple[str, int]], *, repeat: int = REPEAT_DEFAULT, corpus: str = "random") -> list[dict]:
    """Measure every requested attempt on fresh daemons and fresh chunk caches."""
    if repeat < 1:
        raise ValueError("repeat must be positive")
    results = []
    kinds = CORPORA if corpus == "all" else (corpus,)
    for kind in kinds:
        for label, size in sizes:
            payload = _build_payload(size, kind=kind)
            attempts = []
            for trial in range(repeat):
                started = time.perf_counter()
                try:
                    with tempfile.TemporaryDirectory() as td:
                        src = Path(td) / "cold.bin"
                        src.write_bytes(payload)
                        with daemon_pair() as pair:
                            row = _transfer_attempt(pair, src, payload)
                except Exception as exc:
                    row = {"status": "failed", "error": str(exc), "error_class": type(exc).__name__, "stage": "setup", "attempt_seconds": time.perf_counter() - started}
                row["trial"] = trial + 1
                attempts.append(row)
            summary = _attempt_summary(attempts)
            median = summary["successful_elapsed_median_sec"]
            times = summary["successful_elapsed_samples_sec"]
            results.append({
                "scenario": "cold_transfer", "size_label": label, "size_bytes": size,
                "corpus": kind, "seed": 0, **summary,
                "elapsed_median_sec": median,
                "elapsed_min_sec": min(times) if times else None,
                "throughput_median_bps": size / median if summary["status"] == "passed" and median else None,
                "samples": len(times),
            })
            print(f"  cold {kind}/{label}: {summary['status']} {summary['completed']}/{repeat} verified; median={median}")
    return results


def _bench_memory(size: int, *, sender: bool) -> dict:
    payload = _build_payload(size, seed=11 if sender else 1)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "memory.bin"
        src.write_bytes(payload)
        with daemon_pair() as pair:
            target = pair.a if sender else pair.b
            proc, identity = _authenticated_benchmark_process(target)
            tracker = _RssTracker(proc)
            tracker.start()
            try:
                attempt = _transfer_attempt(pair, src, payload)
            finally:
                memory = tracker.stop()
            try:
                _, after = _authenticated_benchmark_process(target)
                same_instance = identity == after
            except (psutil.Error, OSError, RuntimeError, ValueError):
                same_instance = False
    summary = _attempt_summary([attempt])
    valid = memory["valid"] and same_instance
    if not valid and summary["status"] == "passed":
        summary.update(status="inconclusive",
                       error=memory["error"] or "RSS process identity/coverage changed")
    baseline_rss = tracker.baseline_bytes
    peak = memory["peak_bytes"] if valid else None
    return {
        "scenario": "sender_memory" if sender else "receiver_memory", "size_bytes": size,
        **summary, "rss_baseline_bytes": baseline_rss if valid else None,
        "rss_peak_bytes": peak, "rss_mean_bytes": memory["mean_bytes"] if valid else None,
        "rss_growth_bytes": max(0, peak - baseline_rss) if peak is not None and baseline_rss is not None else None,
        "rss_samples": memory["samples"],
        "rss_sample_interval_sec": tracker.interval,
        "rss_sample_duration_sec": memory["sample_duration_sec"],
        "rss_max_sample_gap_sec": memory["max_sample_gap_sec"],
        "rss_measurement_valid": valid,
        "rss_process_identity_verified": same_instance,
        "rss_process_scope": "authenticated serving daemon only",
        "rss_peak_kind": "sampled_lower_bound",
        "qualification": "Sampled RSS of one serving process at one file size, not its OS high-water mark, process tree, or proof of asymptotic bounds.",
    }


def bench_sender_memory(size: int) -> dict:
    return _bench_memory(size, sender=True)


def bench_receiver_memory(size: int) -> dict:
    return _bench_memory(size, sender=False)


def _bench_file_set(payloads: list[bytes], *, scenario: str, concurrency: int = 1) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    if not payloads or concurrency < 1:
        raise ValueError("at least one file and positive concurrency are required")
    with tempfile.TemporaryDirectory() as td:
        paths = []
        for i, payload in enumerate(payloads):
            path = Path(td) / f"group-{i % 3}" / f"file-{i}.bin"
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(payload)
            paths.append(path)
        with daemon_pair() as pair:
            started = time.perf_counter()
            def send(i: int) -> dict:
                return {"file_index": i, **_transfer_attempt(pair, paths[i], payloads[i])}
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                attempts = list(pool.map(send, range(len(paths))))
            elapsed = time.perf_counter() - started
    summary = _attempt_summary(attempts)
    delivered_bytes = sum(row["logical_bytes"] for row in attempts if row["status"] == "passed")
    return {
        "scenario": scenario, "n": len(paths), "concurrency": concurrency,
        "total_bytes": sum(map(len, payloads)), "verified_bytes": delivered_bytes,
        "elapsed_sec": elapsed, "aggregate_throughput_bps": delivered_bytes / max(elapsed, 1e-9) if summary["status"] == "passed" else None,
        **summary,
    }


def bench_many_small_files(n: int = 20, per_size: int = 4096) -> dict:
    return _bench_file_set([_build_payload(per_size, seed=200 + i) for i in range(n)], scenario="many_small_files")


def bench_mixed_tree(n: int = 20) -> dict:
    sizes = (0, 128, 4096, 65536, 1024 * 1024)
    payloads = [_build_payload(sizes[i % len(sizes)], seed=500 + i, kind=CORPORA[i % len(CORPORA)]) for i in range(n)]
    return _bench_file_set(payloads, scenario="mixed_tree")


def bench_share_link_round_trip(size: int = 1 * 1024 * 1024) -> dict:
    """Wave 2g+ share-link end-to-end latency: mint on A, claim on
    B, file lands. Captures the wall-time cost of the new
    out-of-band-token flow vs paired-peer send_file (proxy via
    cold_transfer at same size). Useful to know: is share-link
    delivery materially slower than direct send, or is the
    overhead just the mint round-trip?"""
    payload = _build_payload(size, seed=303)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "sharelink.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            # Warm channel both directions.
            request(p.a.control_port, cmd="send",
                    peer=p.b.short_id, body="warm")
            time.sleep(0.5)
            t0 = time.time()
            mint = request(p.a.control_port, cmd="create_share_link",
                           path=str(src))
            if not mint.get("ok"):
                return {"scenario": "share_link_round_trip",
                        "size_bytes": size, "error": mint}
            mint_elapsed = time.time() - t0
            claim = request(p.b.control_port,
                            cmd="claim_share_link_from_peer",
                            peer=p.a.short_id,
                            token_hex=mint["token_hex"])
            if not claim.get("ok"):
                return {"scenario": "share_link_round_trip",
                        "size_bytes": size, "error": claim}
            # Wait for file to arrive.
            end = time.time() + 30.0
            landed = False
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    try:
                        if f.stat().st_size == size and f.read_bytes() == payload:
                            landed = True
                            break
                    except OSError:
                        pass
                if landed:
                    break
                time.sleep(0.05)
            total_elapsed = time.time() - t0
    out = {
        "scenario": "share_link_round_trip",
        "size_bytes": size,
        "mint_elapsed_sec": round(mint_elapsed, 4),
        "total_elapsed_sec": round(total_elapsed, 4),
        "delivery_elapsed_sec": round(total_elapsed - mint_elapsed, 4),
        "throughput_bps": size / total_elapsed if landed and total_elapsed > 0 else None,
        "status": "passed" if landed else "failed",
        "completed": landed,
    }
    print(f"  share-link round-trip {_human_bytes(size)}: "
          f"mint {mint_elapsed * 1000:.1f}ms + delivery "
          f"{(total_elapsed - mint_elapsed) * 1000:.1f}ms = "
          f"{total_elapsed:.3f}s ({_human_throughput(size, total_elapsed)})")
    return out


def bench_quic_vs_webrtc(size: int = 16 * 1024 * 1024, *, repeat: int = 3, transports: tuple[str, str] = ("quic", "webrtc")) -> dict:
    """Compare explicitly requested payload routes with receipt verification.

    A pinned peer is an authorization state, not a transport observation.
    Unavailable routes and fallback produce an inconclusive row and no ratio.
    Both arms have identical trust, capability, input and preparation policies.
    """
    if repeat < 1 or len(set(transports)) != 2:
        raise ValueError("positive repeat and two distinct transports are required")
    payload = _build_payload(size, seed=42)
    attempts = []
    for trial in range(repeat):
        order = transports if trial % 2 == 0 else tuple(reversed(transports))
        for transport in order:
            try:
                with tempfile.TemporaryDirectory() as td:
                    src = Path(td) / "route.bin"
                    src.write_bytes(payload)
                    with daemon_pair() as pair:
                        row = _transfer_attempt(pair, src, payload, transport=transport)
            except Exception as exc:
                row = {"status": "failed", "error": str(exc), "error_class": type(exc).__name__, "stage": "setup"}
            row.update(pair_index=trial, transport_requested=transport)
            attempts.append(row)
    summary = _attempt_summary(attempts)
    arms = {route: _attempt_summary([row for row in attempts if row["transport_requested"] == route]) for route in transports}
    ratios = []
    for trial in range(repeat):
        pair = {row["transport_requested"]: row for row in attempts if row["pair_index"] == trial}
        if all(pair[route]["status"] == "passed" for route in transports):
            ratios.append(pair[transports[1]]["verified_completion_seconds"] / pair[transports[0]]["verified_completion_seconds"])
    return {
        "scenario": "transport_comparison", "size_bytes": size, "corpus": "random", "seed": 42,
        "transports": list(transports), "arms": arms, **summary,
        "paired_speedup_first_over_second": statistics.median(ratios) if summary["status"] == "passed" and len(ratios) == repeat else None,
        "paired_ratio_samples": ratios, "ratio_published_only_when_every_pair_verified": True,
    }


def bench_concurrent_transfers(n: int = 4, size: int = 32 * 1024 * 1024) -> dict:
    return _bench_file_set([_build_payload(size, seed=100 + i) for i in range(n)], scenario="concurrent_transfers", concurrency=min(n, 16))


def _bench_related_pair(size: int, *, edited: bool) -> dict:
    payloads = [_build_payload(size, seed=2), _build_payload(size, seed=2, kind="related" if edited else "random")]
    with tempfile.TemporaryDirectory() as td:
        paths = [Path(td) / "base.bin", Path(td) / "second.bin"]
        for path, payload in zip(paths, payloads):
            path.write_bytes(payload)
        with daemon_pair() as pair:
            attempts = [_transfer_attempt(pair, path, payload) for path, payload in zip(paths, payloads)]
    summary = _attempt_summary(attempts)
    return {
        "scenario": "related_file" if edited else "warm_dedup", "size_bytes": size,
        "second_edit_bytes": min(4096, size - size // 2) if edited else 0,
        **summary,
        "speedup_x": attempts[0]["verified_completion_seconds"] / max(attempts[1]["verified_completion_seconds"], 1e-9) if summary["status"] == "passed" else None,
        "qualification": "Two sequential observations; includes request, receiver verification and completion. No tail-latency inference.",
    }


def bench_warm_dedup(size: int = 64 * 1024 * 1024) -> dict:
    return _bench_related_pair(size, edited=False)


def bench_related_file(size: int = 16 * 1024 * 1024) -> dict:
    return _bench_related_pair(size, edited=True)


def _kill_benchmark_serving_process(handle: Any) -> tuple:
    """Abruptly stop only the authenticated disposable daemon we spawned."""
    proc, identity = _authenticated_benchmark_process(handle)
    if proc.pid == handle.proc.pid:
        handle.proc.kill()
    else:
        # On Windows a virtualenv launcher can survive its serving child or
        # vice versa. Never infer a daemon crash from killing just the wrapper.
        proc.kill()
        proc.wait(timeout=10)
    handle.proc.wait(timeout=10)
    if proc.is_running() or handle.proc.poll() is None:
        raise RuntimeError("benchmark daemon or launcher remained alive after termination")
    return identity


def _already_delivered_payload(home: Path, payload: bytes) -> bool:
    expected = hashlib.sha256(payload).hexdigest()
    for path in inbox_files(home):
        if path.stat().st_size == len(payload) and file_sha256(path) == expected:
            return True
    return False


def bench_resume_effectiveness(size: int = 32 * 1024 * 1024) -> dict:
    """Interrupt an owned receiver, retain its private discovery scope, verify restart delivery."""
    payload = _build_payload(size, seed=3)
    sender_outcomes: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "resume.bin"
        src.write_bytes(payload)
        with daemon_pair() as pair:
            def send() -> None:
                try:
                    sender_outcomes.append(request(pair.a.control_port, cmd="send_file", peer=pair.b.short_id, path=str(src), timeout=120))
                except Exception as exc:
                    sender_outcomes.append({"ok": False, "error": str(exc), "error_class": type(exc).__name__})
            sender = threading.Thread(target=send, daemon=True)
            sender.start()
            cache = pair.b.home / "data" / "file_chunks"
            deadline = time.monotonic() + 30
            cached = 0
            while time.monotonic() < deadline and sender.is_alive():
                if cache.is_dir():
                    cached = sum(1 for path in cache.rglob("*") if path.is_file())
                if cached >= 5:
                    break
                time.sleep(0.02)
            if cached < 5 or not sender.is_alive():
                sender.join(timeout=120)
                return {"scenario": "resume_effectiveness", "status": "inconclusive",
                        "error": "could not observe an in-progress transfer at the requested cache checkpoint",
                        "size_bytes": size, "cache_files_observed": cached, "initial_sender_outcomes": sender_outcomes}
            killed_identity = _kill_benchmark_serving_process(pair.b)
            if pair.b.log_fh is not None:
                pair.b.log_fh.close()
            sender.join(timeout=125)
            if sender.is_alive():
                return {"scenario": "resume_effectiveness", "status": "failed", "error": "sender request did not terminate after receiver stop"}
            # A completion that raced the kill is not evidence of recovery.
            # No receiver is running now, so this check cannot race its writes.
            if _already_delivered_payload(pair.b.home, payload):
                return {"scenario": "resume_effectiveness", "status": "inconclusive",
                        "error": "receiver completed before verified abrupt termination",
                        "size_bytes": size, "initial_sender_outcomes": sender_outcomes}
            for name in ("control.port", "peer.port", "server.port", "ui.token", "instance.lock"):
                try:
                    (pair.b.home / "data" / name).unlink()
                except FileNotFoundError:
                    pass
            started = time.perf_counter()
            replacement = None
            try:
                replacement = _bring_up(pair.b.home, pair.b.log, "B-resume", mdns_type=pair.benchmark_mdns_type)
                _, new_identity = _authenticated_benchmark_process(replacement)
                if replacement.fingerprint != pair.b.fingerprint or new_identity[2] == killed_identity[2]:
                    return {"scenario": "resume_effectiveness", "status": "failed",
                            "error": "replacement daemon did not preserve peer identity and create a fresh instance"}
                landed, _ = _wait_for_payload(replacement.home, payload, 120.0)
                elapsed = time.perf_counter() - started
                return {
                    "scenario": "resume_effectiveness", "status": "passed" if landed is not None else "failed",
                    "size_bytes": size, "cache_files_observed_at_kill": cached,
                    "completed_after_resume": landed is not None, "receiver_verified": landed is not None,
                    "elapsed_after_restart_sec": elapsed, "source_sha256": hashlib.sha256(payload).hexdigest(),
                    "initial_sender_outcomes": sender_outcomes,
                    "resume_wire_bytes": None,
                    "abrupt_serving_process_termination_verified": True,
                    "fresh_instance_and_peer_continuity_verified": True,
                    "qualification": "Restart plus independently verified delivery; cache-file count is not an acknowledged-byte or re-fetch count.",
                }
            finally:
                # The harness's context owns the original captured handle,
                # not this replacement. Explicitly stop and close our new one.
                if replacement is not None:
                    try:
                        _stop(replacement.proc, home=replacement.home, control_port=replacement.control_port, control_secret=replacement.control_secret)
                    finally:
                        if replacement.log_fh is not None:
                            replacement.log_fh.close()


# ──────────────────────────────────────────────────────────────────
# microbenchmarks
# ──────────────────────────────────────────────────────────────────

def bench_resume_sidecar(n: int = 1000) -> dict:
    """Time ``n`` persist + ``n`` load operations against a fresh
    inbox. Resume sidecar reads happen at startup; writes happen
    once per chunk-touch debounce window (Wave 1d's every-64-chunks
    cadence)."""
    if n < 1:
        raise ValueError("n must be positive")
    from one_link.resume import (
        ResumeSidecar, persist_sidecar, load_sidecar,
    )
    with tempfile.TemporaryDirectory() as td:
        inbox = Path(td) / "inbox"
        inbox.mkdir()
        metadata_root = Path(td) / "private-metadata"
        partial = inbox / "x.bin"
        partial.write_bytes(b"x" * 64)
        # Build n distinct sidecars.
        sidecars = []
        for i in range(n):
            blob = f"{i:064x}"
            sidecars.append(ResumeSidecar(
                blob_hex=blob,
                peer_fp="P" * 64,
                name=f"file_{i}.bin",
                size=4096,
                out_path=str(partial),
                cdc_chunks=[{"index": 0, "hash": "a" * 64, "size": 4096, "start": 0, "end": 4096}],
            ))
        t0 = time.perf_counter()
        for sc in sidecars:
            persist_sidecar(inbox, sc, metadata_root=metadata_root)
        write_elapsed = time.perf_counter() - t0
        t0 = time.perf_counter()
        for sc in sidecars:
            loaded = load_sidecar(inbox, sc.blob_hex, metadata_root=metadata_root)
            if loaded is None or (loaded.blob_hex, loaded.size, loaded.out_path, loaded.cdc_chunks) != (sc.blob_hex, sc.size, sc.out_path, sc.cdc_chunks):
                raise RuntimeError("persisted sidecar did not round-trip its manifest")
        read_elapsed = time.perf_counter() - t0
    out = {
        "scenario": "resume_sidecar_microbench",
        "status": "passed",
        "measurement_scope": "metadata persistence with fsync and verified loads",
        "n": n,
        "write_total_sec": round(write_elapsed, 4),
        "write_per_op_us": round(write_elapsed * 1e6 / n, 2),
        "read_total_sec": round(read_elapsed, 4),
        "read_per_op_us": round(read_elapsed * 1e6 / n, 2),
    }
    print(f"  sidecar ops × {n}: "
          f"write {out['write_per_op_us']:.1f} µs/op, "
          f"read {out['read_per_op_us']:.1f} µs/op")
    return out


def bench_chunk_cache_gc(n_chunks: int = 1000, chunk_size: int = 65536) -> dict:
    """Time an eviction pass over ``n_chunks`` entries totalling
    ~``n_chunks * chunk_size`` bytes. Backstops the assertion that
    cache GC is fast enough to run synchronously at startup even
    on a cache that's grown to thousands of entries."""
    if n_chunks < 1 or chunk_size < 1:
        raise ValueError("chunk count and size must be positive")
    from one_link.chunk_cache_gc import evict_to_target
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "file_chunks"
        cache.mkdir()
        now = time.time()
        for i in range(n_chunks):
            h = f"{i:064x}"
            prefix = cache / h[:2]
            prefix.mkdir(parents=True, exist_ok=True)
            p = prefix / h[2:]
            p.write_bytes(b"\0" * chunk_size)
            # Spread mtimes so LRU has a real ordering to sort.
            os.utime(p, (now - i * 60, now - i * 60))

        class _FakeState:
            def __init__(self): self.forgotten = []
            def forget_chunk_available(self, h): self.forgotten.append(h)

        state = _FakeState()
        # Evict to 50 % of total bytes.
        target = (n_chunks * chunk_size) // 2
        t0 = time.perf_counter()
        report = evict_to_target(
            cache,
            max_bytes=target - 1,  # any value < total triggers
            target_bytes=target,
            state=state,
            min_age_seconds=0,
            now=now + 86400,  # all entries past min_age
        )
        elapsed = time.perf_counter() - t0
        remaining = sum(path.stat().st_size for path in cache.rglob("*") if path.is_file())
        verified = report.errors == 0 and remaining <= target and remaining + report.evicted_bytes == n_chunks * chunk_size and len(state.forgotten) == report.evicted_files
    out = {
        "scenario": "chunk_cache_gc_microbench",
        "status": "passed" if verified else "failed",
        "remaining_bytes": remaining,
        "eviction_errors": report.errors,
        "n_chunks": n_chunks,
        "chunk_size_bytes": chunk_size,
        "evicted_files": report.evicted_files,
        "evicted_bytes": report.evicted_bytes,
        "elapsed_sec": round(elapsed, 4),
        "evict_rate_files_per_sec": round(
            report.evicted_files / elapsed, 1
        ) if elapsed > 0 else 0,
    }
    print(f"  cache GC: evicted {report.evicted_files}/{n_chunks} entries "
          f"({_human_bytes(report.evicted_bytes)}) in {elapsed * 1000:.1f} ms "
          f"= {out['evict_rate_files_per_sec']:.0f} files/s")
    return out


# ──────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────

def _enable_live_benchmark_lane() -> None:
    """Explicitly opt this live benchmark into the daemon-spawn lane."""

    # The shared test harness is fail-closed by default so a normal pytest run
    # cannot accidentally spawn dozens of real daemons. Invoking this script
    # is itself the operator's explicit request for a live benchmark.
    os.environ[LIVE_INTEGRATION_ENV] = "1"


def main() -> int:
    _enable_live_benchmark_lane()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json", type=Path, default=None,
        help="Write machine-readable results JSON to this path",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Skip the slowest scenarios (>= 64 MiB sizes)",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "cold", "memory", "sender_memory", "warm", "resume",
            "sidecar", "cache", "concurrent", "quic_vs_webrtc",
            "many_small", "mixed_tree", "related", "share_link", "all",
        ],
        default="all",
        help="Run only the named scenario family",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=REPEAT_DEFAULT,
        help=("How many times to repeat each cold-transfer size. "
              "Retains every attempt and reports verified-success medians; "
              "failures and unavailable measurements return nonzero."),
    )
    parser.add_argument("--corpus", choices=[*CORPORA, "all"], default="random", help="Cold-transfer corpus (default: unique random bytes).")
    parser.add_argument("--transports", nargs=2, choices=["tcp", "relay", "quic", "webrtc"], default=["quic", "webrtc"], help="Explicit payload routes for the transport-comparison scenario.")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")

    sizes = SIZES_DEFAULT
    if args.quick:
        sizes = [(l, s) for (l, s) in sizes if s <= 16 * 1024 * 1024]

    results: dict[str, Any] = {
        "schema": "one-link-file-benchmark-v2", "started_unix": time.time(),
        "provenance": provenance(PROJECT_ROOT),
        "measurement_contract": {
            "timer": "perf_counter; request through independent receiver verification",
            "scope": "same-host isolated daemon pair", "storage_state": "freshly written OS-cache-warm source",
            "corpus_version": "seeded-randbytes-v1", "corpus": args.corpus,
            "wire_accounting": "application payload counters; no packet capture",
            "daemon_fixture": "paired/trusted peers, automatic file acceptance; fixture settings are not normal-user qualification",
        },
    }
    section_outcomes: list[str] = []

    def run_section(name: str, fn) -> None:
        if args.scenario not in (name, "all"):
            return
        print(f"\n--- {name} ---")
        try:
            result = fn()
        except Exception as exc:
            result = {"status": "failed", "error": str(exc), "error_class": type(exc).__name__}
        rows = result if isinstance(result, list) else [result]
        if not rows:
            rows = [{"status": "inconclusive", "error": "scenario returned no observations"}]
            result = rows
        for row in rows:
            if row.get("status") not in {"passed", "failed", "inconclusive"}:
                row["status"] = "inconclusive"
                row.setdefault("error", "scenario omitted an explicit supported verdict")
            section_outcomes.append(row["status"])
        results[name] = result

    run_section("cold", lambda: bench_cold_transfer(sizes, repeat=args.repeat, corpus=args.corpus))
    run_section("memory", lambda: bench_receiver_memory(
        64 * 1024 * 1024 if args.quick else 256 * 1024 * 1024
    ))
    run_section("sender_memory", lambda: bench_sender_memory(
        64 * 1024 * 1024 if args.quick else 256 * 1024 * 1024
    ))
    run_section("concurrent", lambda: bench_concurrent_transfers(
        n=4,
        size=8 * 1024 * 1024 if args.quick else 32 * 1024 * 1024,
    ))
    run_section("quic_vs_webrtc", lambda: bench_quic_vs_webrtc(
        size=8 * 1024 * 1024 if args.quick else 16 * 1024 * 1024, repeat=args.repeat, transports=tuple(args.transports),
    ))
    run_section("many_small", lambda: bench_many_small_files(
        n=10 if args.quick else 20,
        per_size=4096,
    ))
    run_section("mixed_tree", lambda: bench_mixed_tree(n=10 if args.quick else 20))
    run_section("related", lambda: bench_related_file(size=4 * 1024 * 1024 if args.quick else 16 * 1024 * 1024))
    run_section("share_link", lambda: bench_share_link_round_trip(
        size=256 * 1024 if args.quick else 1 * 1024 * 1024,
    ))
    run_section("warm", lambda: bench_warm_dedup(
        16 * 1024 * 1024 if args.quick else 64 * 1024 * 1024
    ))
    run_section("resume", lambda: bench_resume_effectiveness(
        16 * 1024 * 1024 if args.quick else 32 * 1024 * 1024
    ))
    run_section("sidecar", lambda: bench_resume_sidecar(1000))
    run_section("cache", lambda: bench_chunk_cache_gc(1000, 65536))

    results["finished_unix"] = time.time()
    results["status"] = "failed" if "failed" in section_outcomes else "inconclusive" if "inconclusive" in section_outcomes else "passed"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, allow_nan=False), encoding="utf-8")
        print(f"\nResults written to {args.json}")
    return {"passed": 0, "failed": 1, "inconclusive": 2}[results["status"]]


if __name__ == "__main__":
    sys.exit(main())
