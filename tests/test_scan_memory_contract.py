"""The multi-GB scan-memory qualifier (scripts/bench_scan_memory.py) must fail what breaks the
contract and pass what keeps it.

Synthetic samples with known memory models exercise each clause: a bounded
workspace per kind of log, a bounded per-chunk cost, no growth with records, a
per-sample envelope, the original same-size density overhead limit, and enough
measurement power to see one bit per record.
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
        workspace = 15 * MIB   # a bounded extra workspace, within the density limit
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
        expected = {"mcap-dense": 33 if api == "cdc_file" else 15,
                    "mcap-sparse": 33 if api == "cdc_file" else 9, "plain": 33}
        for kind, mib in expected.items():
            assert abs(fit["workspace_bytes"][kind] / MIB - mib) < 0.1, (api, kind, fit)
    assert verdict["growth"], "the per-kind growth table must be reported"


def test_a_constant_difference_between_dense_and_sparse_is_not_charged_to_records():
    """A permitted fixed 6 MiB difference is not charged to record retention."""
    two_sizes = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    verdict = bench.evaluate(two_sizes)
    assert verdict["passed"], verdict["failures"]
    assert abs(verdict["fits"]["format_aware_file"]["bytes_per_record"]) < 0.001


def test_a_constant_16_mib_density_overhead_still_fails_the_original_limit():
    def excessive_density(api, kind, chunks, records):
        extra = 10 * MIB if record_walk(api, kind) and kind == "mcap-dense" else 0
        return healthy(api, kind, chunks, records) + extra

    verdict = bench.evaluate(corpus(excessive_density, sizes_mib=(256, 1024), repeats=2))
    assert not verdict["passed"]
    for api in ("format_aware_file", "format_aware_fd"):
        assert abs(verdict["fits"][api]["bytes_per_record"]) < 0.001
        pairs = [p for p in verdict["dense_vs_sparse"] if p["api"] == api]
        assert len(pairs) == 2
        assert all(p["limit"] == 8 * MIB for p in pairs)
        assert all(p["chunk_adjusted_difference"] == pytest.approx(16 * MIB) for p in pairs)
        assert any(f.startswith(api + " @") for f in verdict["failures"])


def test_extra_returned_chunks_are_adjusted_using_only_plain_file_cost():
    rows = corpus(lambda api, kind, chunks, records: 2 * MIB + 700 * chunks)
    verdict = bench.evaluate(rows)
    assert verdict["passed"], verdict["failures"]
    for cost in verdict["density_output_cost"].values():
        assert cost["source"] == "plain-only"
        assert cost["applied_bytes_per_chunk"] == pytest.approx(700)
    assert any(p["dense_median"] - p["sparse_median"] > p["limit"] for p in verdict["dense_vs_sparse"])
    assert all(abs(p["chunk_adjusted_difference"]) < 1 for p in verdict["dense_vs_sparse"])


def test_negative_plain_output_slope_cannot_inflate_the_density_gap():
    rows = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    for row in rows:
        if row["kind"] == "plain":
            row["peak_delta_bytes"] = 33 * MIB - 100 * row["chunks"]
    verdict = bench.evaluate(rows)
    for cost in verdict["density_output_cost"].values():
        assert cost["fitted_bytes_per_chunk"] == pytest.approx(-100)
        assert cost["applied_bytes_per_chunk"] == 0
    for pair in verdict["dense_vs_sparse"]:
        assert pair["chunk_adjusted_difference"] == pair["dense_median"] - pair["sparse_median"]


def test_plain_output_credit_cannot_exceed_the_existing_chunk_cost_limit():
    verdict = bench.evaluate(corpus(lambda api, kind, chunks, records: 2 * MIB + 8192 * chunks))
    assert not verdict["passed"] and any("bytes/chunk" in f for f in verdict["failures"])
    assert all(cost["applied_bytes_per_chunk"] == 1024 for cost in verdict["density_output_cost"].values())


def test_density_limit_retains_ten_percent_when_raw_peak_is_large():
    def large_output(api, kind, chunks, records):
        workspace = (18 if kind == "mcap-dense" else 9) * MIB
        return workspace + 150 * chunks

    verdict = bench.evaluate(corpus(large_output, sizes_mib=(40960, 65536), repeats=2))
    assert verdict["passed"], verdict["failures"]
    for pair in verdict["dense_vs_sparse"]:
        assert pair["limit"] == pytest.approx(0.10 * max(pair["dense_median"], pair["sparse_median"]))
        assert pair["chunk_adjusted_difference"] == pytest.approx(9 * MIB)


def test_missing_plain_fd_samples_cannot_qualify_a_density_comparison():
    rows = [r for r in corpus(healthy) if not (r["api"] == "format_aware_fd" and r["kind"] == "plain")]
    verdict = bench.evaluate(rows)
    assert not verdict["passed"]
    assert any(f.startswith("format_aware_fd: density comparison requires plain-file")
               for f in verdict["failures"])


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
        extra = 37 * MIB if (record_walk(api, kind) and kind == "mcap-dense") else 0
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
def test_measured_flat_record_growth_does_not_erase_density_or_coverage_failures(runner):
    """Historical rows can have a flat record slope without qualifying the density contract."""
    rows = measured(runner)
    dense = [r for r in rows if r["api"] == "format_aware_file" and r["kind"] == "mcap-dense"]
    small = max(r["peak_delta_bytes"] for r in dense if r["size"] == 256 * MIB)
    large = max(r["peak_delta_bytes"] for r in dense if r["size"] == 1024 * MIB)
    assert large - small < 1 * MIB, "the fixture is the flat case"
    verdict = bench.evaluate(rows)
    assert not verdict["passed"]
    assert verdict["fits"]["format_aware_file"]["bytes_per_record"] < bench.MAX_BYTES_PER_RECORD / 5
    assert not any("O(records)" in f for f in verdict["failures"])
    # The historical protocol never measured plain files through the fd API.
    assert any(f.startswith("format_aware_fd: density comparison requires plain-file")
               for f in verdict["failures"])
    if runner == "windows":
        assert any(f.startswith("format_aware_file @") for f in verdict["failures"])


def test_measured_samples_from_the_doubling_window_fail_on_workspace():
    """macOS at c7d57a1: the dense window grew by doubling and briefly held two copies."""
    verdict = bench.evaluate(measured("macos"))
    assert not verdict["passed"]
    assert any("mcap-dense workspace" in f and "exceeds the declared 40 MiB (record-walk)" in f
               for f in verdict["failures"]), verdict["failures"]
    assert not any(f.startswith("cdc_file") for f in verdict["failures"])


def test_scan_speed_is_reported_against_the_plain_log_of_the_same_run():
    """The memory limit has a cost beside it: what the buffer sizes do to speed, as a ratio a run can compare."""
    rows = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    speeds = {"mcap-dense": 600.0, "mcap-sparse": 2400.0, "plain": 1200.0}  # MiB/s
    for row in rows:
        row["seconds"] = (row["size"] / MIB) / speeds[row["kind"]] * (1.0 + 0.02 * row["repeat"])
    verdict = bench.evaluate(rows)
    assert verdict["passed"], "a speed ratio is reported, never a reason to fail"
    table = {(r["api"], r["size"] // MIB, r["kind"]): r for r in verdict["relative_throughput"]}
    assert set(table) == {(api, size, kind) for api in APIS for size in (256, 1024)
                          for kind in ("mcap-dense", "mcap-sparse")}, "one row per non-plain kind, API and size"
    dense = table[("format_aware_file", 1024, "mcap-dense")]
    assert dense["ratio_to_plain"] == pytest.approx(0.5, rel=1e-6)
    assert dense["median_mib_per_s"] == pytest.approx((600.0 + 600.0 / 1.02) / 2, rel=1e-6)  # two repeats
    assert table[("format_aware_fd", 256, "mcap-sparse")]["ratio_to_plain"] == pytest.approx(2.0, rel=1e-6)


def test_samples_without_timing_report_no_speed_rather_than_a_guess():
    assert bench.evaluate(corpus(healthy))["relative_throughput"] == []
    assert bench.relative_throughput(measured("ubuntu")) == []


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
