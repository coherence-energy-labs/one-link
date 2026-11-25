"""The multi-GB scan-memory qualifier (scripts/bench_scan_memory.py) must fail what breaks the
contract and pass what keeps it.

Synthetic samples with known memory models exercise each clause: a bounded
workspace per kind of log, a bounded per-chunk cost, no growth with records, a
per-sample envelope, and enough measurement power to see one bit per record.
The samples three CI runners measured at c7d57a1 are replayed as well: they are
the case an earlier model got wrong.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bench_scan_memory", ROOT / "scripts" / "bench_scan_memory.py")
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)
MIB = 1 << 20
APIS = ("format_aware_file", "format_aware_fd", "cdc_file")


def corpus(model, sizes_mib=(256, 1024, 4096), repeats=3, jitter=lambda api, kind, size_mib, rep: rep * 1000) -> list[dict]:
    rows = []
    for size_mib in sizes_mib:
        size = size_mib * MIB
        layouts = {
            "mcap-dense": (size // 65536, size // 32),        # v2: kept dense cuts about avg_size apart
            "mcap-sparse": (size // 262144, size // 262144),  # one chunk per large record
            "plain": (size // 70000, 0),
        }
        for api in APIS:
            for kind, (chunks, records) in layouts.items():
                if api == "cdc_file":
                    chunks = size // 76000  # plain CDC, whatever the container
                for rep in range(repeats):
                    peak = model(api, kind, chunks, records) + jitter(api, kind, size_mib, rep)
                    rows.append({"api": api, "kind": kind, "size": size, "chunks": chunks, "records": records,
                                 "repeat": rep, "peak_delta_bytes": int(peak)})
    return rows


def healthy(api, kind, chunks, records):
    """What the scanners are documented to do: a fixed workspace per kind, plus output."""
    if api == "cdc_file" or kind == "plain":
        workspace = 33 * MIB   # the 32 MiB payload window
    elif kind == "mcap-dense":
        workspace = 25 * MIB   # the dense walk's sliding header window
    else:
        workspace = 9 * MIB    # the sparse walk's 64 KiB window and one segment
    return workspace + 110 * chunks


def record_walk(api, kind) -> bool:
    return api != "cdc_file" and kind != "plain"


def test_a_fixed_workspace_per_kind_plus_per_chunk_output_passes_and_is_recovered():
    verdict = bench.evaluate(corpus(healthy))
    assert verdict["passed"], verdict["failures"]
    for api in APIS:
        fit = verdict["fits"][api]
        assert abs(fit["bytes_per_chunk"] - 110) < 5, fit
        assert abs(fit["bytes_per_record"]) < 0.001, fit
        expected = {"mcap-dense": 33 if api == "cdc_file" else 25,
                    "mcap-sparse": 33 if api == "cdc_file" else 9, "plain": 33}
        for kind, mib in expected.items():
            assert abs(fit["workspace_bytes"][kind] / MIB - mib) < 0.1, (api, kind, fit)
    assert verdict["growth"], "the per-kind growth table must be reported"


def test_a_constant_difference_between_dense_and_sparse_is_not_charged_to_records():
    """The false positive this model replaces: 16 MiB between the kinds, no growth with records."""
    two_sizes = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    verdict = bench.evaluate(two_sizes)
    assert verdict["passed"], verdict["failures"]
    assert abs(verdict["fits"]["format_aware_file"]["bytes_per_record"]) < 0.001


@pytest.mark.parametrize("per_record", [2.0, 8.0, 0.125])
def test_memory_that_grows_with_records_fails(per_record):
    """Down to one retained bit per record, on the two sizes CI measures."""
    def leaky(api, kind, chunks, records):
        return healthy(api, kind, chunks, records) + (per_record * records if record_walk(api, kind) else 0)

    verdict = bench.evaluate(corpus(leaky, sizes_mib=(256, 1024), repeats=2))
    assert not verdict["passed"]
    named = [f for f in verdict["failures"] if "bytes/record" in f and "O(records)" in f]
    assert {f.split(":")[0] for f in named} == {"format_aware_file", "format_aware_fd"}, verdict["failures"]


def test_a_workspace_above_the_declared_bound_fails():
    """52 MiB is what macOS measured while the dense window grew by doubling."""
    def doubled(api, kind, chunks, records):
        extra = 27 * MIB if (record_walk(api, kind) and kind == "mcap-dense") else 0
        return healthy(api, kind, chunks, records) + extra

    verdict = bench.evaluate(corpus(doubled))
    assert not verdict["passed"]
    assert any("mcap-dense workspace 52.0 MiB exceeds the declared 40 MiB (record-walk)" in f
               for f in verdict["failures"]), verdict["failures"]
    assert not any(f.startswith("cdc_file") for f in verdict["failures"])


def test_the_windowed_stream_has_its_own_larger_bound():
    assert bench.MAX_WORKSPACE_BYTES["record-walk"] < bench.MAX_WORKSPACE_BYTES["windowed-stream"]
    verdict = bench.evaluate(corpus(lambda *a: healthy(*a) + 20 * MIB))
    assert not verdict["passed"]
    assert any("plain workspace" in f and "(windowed-stream)" in f for f in verdict["failures"])


def test_an_oversized_per_chunk_cost_fails():
    verdict = bench.evaluate(corpus(lambda api, kind, chunks, records: 2 * MIB + 8192 * chunks))
    assert not verdict["passed"] and any("bytes/chunk" in f for f in verdict["failures"])


def test_one_outlier_sample_breaks_the_envelope():
    rows = corpus(healthy)
    rows[-1]["peak_delta_bytes"] = 4096 * MIB
    verdict = bench.evaluate(rows)
    assert not verdict["passed"] and any("envelope" in f for f in verdict["failures"])


def test_a_run_too_noisy_to_see_one_bit_per_record_is_underpowered_not_passed():
    def noisy(api, kind, size_mib, rep):
        return rep * 8 * MIB if (record_walk(api, kind) and kind == "mcap-dense") else rep * 1000

    verdict = bench.evaluate(corpus(healthy, sizes_mib=(256, 1024), repeats=2, jitter=noisy))
    assert not verdict["passed"]
    assert any("underpowered" in f and f.startswith("format_aware_file") for f in verdict["failures"])
    assert not any(f.startswith("cdc_file") for f in verdict["failures"])


def test_one_size_cannot_separate_a_workspace_from_growth():
    with pytest.raises(ValueError, match="degenerate design"):
        bench.evaluate(corpus(healthy, sizes_mib=(1024,)))


def measured(runner: str) -> list[dict]:
    fixture = json.loads((ROOT / "tests" / "scan_memory_ci_c7d57a1.json").read_text(encoding="utf-8"))
    columns = fixture["columns"]
    rows = [dict(zip(columns, row)) for row in fixture["runners"][runner]]
    for row in rows:
        row["size"] = row.pop("size_mib") * MIB
    return rows


@pytest.mark.parametrize("runner", ["ubuntu", "windows"])
def test_measured_samples_whose_memory_is_flat_in_records_pass(runner):
    """CI at c7d57a1: 4x the records moved the dense peak by at most 0.6 MiB, and the old model failed it."""
    rows = measured(runner)
    dense = [r for r in rows if r["api"] == "format_aware_file" and r["kind"] == "mcap-dense"]
    small = max(r["peak_delta_bytes"] for r in dense if r["size"] == 256 * MIB)
    large = max(r["peak_delta_bytes"] for r in dense if r["size"] == 1024 * MIB)
    assert large - small < 1 * MIB, "the fixture is the flat case"
    verdict = bench.evaluate(rows)
    assert verdict["passed"], verdict["failures"]
    assert verdict["fits"]["format_aware_file"]["bytes_per_record"] < bench.MAX_BYTES_PER_RECORD / 5


def test_measured_samples_from_the_doubling_window_fail_on_workspace():
    """macOS at c7d57a1: the dense window grew by doubling and briefly held two copies."""
    verdict = bench.evaluate(measured("macos"))
    assert not verdict["passed"]
    assert any("mcap-dense workspace" in f and "exceeds the declared 40 MiB (record-walk)" in f
               for f in verdict["failures"]), verdict["failures"]
    assert not any(f.startswith("cdc_file") for f in verdict["failures"])


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
