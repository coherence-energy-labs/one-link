"""The multi-GB scan-memory qualifier (scripts/bench_scan_memory.py) must be able to fail.

Synthetic samples with known memory models exercise each clause of the contract:
bounded workspace (intercept), bounded per-chunk cost, no growth with records
(fit and chunk-adjusted dense/sparse comparison), and a per-sample envelope.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bench_scan_memory", ROOT / "scripts" / "bench_scan_memory.py")
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)
MIB = 1 << 20


def corpus(model) -> list[dict]:
    rows = []
    for size_mib in (256, 1024, 4096):
        size = size_mib * MIB
        layouts = {
            "mcap-dense": (size // 8192, size // 32),     # format-aware dense: min-size chunks
            "mcap-sparse": (size // 262144, size // 262144),
            "plain": (size // 70000, 0),
        }
        for api in ("format_aware_file", "cdc_file"):
            for kind, (chunks, records) in layouts.items():
                if api == "cdc_file":
                    chunks = size // 76000
                for rep in range(3):
                    rows.append({"api": api, "kind": kind, "size": size, "chunks": chunks, "records": records,
                                 "repeat": rep, "peak_delta_bytes": int(model(api, kind, chunks, records) + rep * 1000)})
    return rows


def healthy(api, kind, chunks, records):
    window = 34 * MIB if (api == "cdc_file" or kind == "plain") else 1 * MIB
    return window + 150 * chunks


def test_a_bounded_workspace_plus_per_chunk_output_passes():
    verdict = bench.evaluate(corpus(healthy))
    assert verdict["passed"], verdict["failures"]
    assert verdict["dense_vs_sparse"], "the chunk-adjusted comparison must run"


def test_memory_that_grows_with_records_fails():
    def leaky(api, kind, chunks, records):
        return healthy(api, kind, chunks, records) + 2 * records  # 2 bytes per retained record

    verdict = bench.evaluate(corpus(leaky))
    assert not verdict["passed"]
    assert any("bytes/record" in f or "chunk-adjusted" in f for f in verdict["failures"])


def test_an_unbounded_workspace_fails():
    verdict = bench.evaluate(corpus(lambda *a: healthy(*a) + 300 * MIB))
    assert not verdict["passed"] and any("intercept" in f for f in verdict["failures"])


def test_an_oversized_per_chunk_cost_fails():
    verdict = bench.evaluate(corpus(lambda api, kind, chunks, records: 2 * MIB + 8192 * chunks))
    assert not verdict["passed"] and any("bytes/chunk" in f for f in verdict["failures"])


def test_one_outlier_sample_breaks_the_envelope():
    rows = corpus(healthy)
    rows[-1]["peak_delta_bytes"] = 4096 * MIB
    verdict = bench.evaluate(rows)
    assert not verdict["passed"] and any("envelope" in f for f in verdict["failures"])


@pytest.mark.parametrize("record_bytes", [32, 1024, 262144])
def test_generated_logs_are_exact_size_valid_mcap(tmp_path: Path, record_bytes: int):
    chunk = pytest.importorskip("one_link_native.chunk")
    path = tmp_path / "log.mcap"
    records = bench.write_mcap(path, 4 * MIB, record_bytes)
    assert path.stat().st_size == 4 * MIB
    data = path.read_bytes()
    assert data.startswith(bench.MCAP_MAGIC) and data.endswith(bench.MCAP_MAGIC)
    assert records >= (4 * MIB) // record_bytes - 2
    boundaries = chunk.format_aware_file(str(path), "mcap")
    assert boundaries[-1].end == 4 * MIB
    if record_bytes >= 262144:
        assert any(b.format_forced for b in boundaries), "the record walk must see the generated framing"
