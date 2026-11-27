"""The multi-GB scan-memory qualifier (scripts/bench_scan_memory.py) must fail what breaks the
contract and pass what keeps it.

Synthetic samples with known memory models exercise each clause: a bounded
workspace per kind of log, a bounded per-chunk cost, no growth with records, a
per-sample envelope, the original same-size density overhead limit, and enough
measurement power to see one bit per record.
The samples three CI runners measured at c7d57a1 are replayed as well: they are
the case an earlier model got wrong. So are the samples of 4621947, where the
next model failed Linux: it read per-record memory off a joint fit whose
per-chunk cost the plain log had pinned too low. Per-record memory is now
measured by a pair of dense logs of one size (mcap-dense, mcap-mid) that return
about the same number of chunks for 16 times fewer records.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bench_scan_memory", ROOT / "scripts" / "bench_scan_memory.py")
bench = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bench)
MIB = 1 << 20
APIS = ("format_aware_file", "format_aware_fd", "cdc_file")
FORMAT_AWARE = ("format_aware_file", "format_aware_fd")
DENSE_WALK = ("mcap-dense", "mcap-mid")  # two record sizes, one scanner path


def dense_log(size):
    """32-byte records. v2: kept dense cuts fall about avg_size apart."""
    return size // 65536, size // 32


def mid_log(size):
    """512-byte records: measured, about 1% more chunks than the 32-byte log, and 16 times fewer records."""
    return size // 64800, size // 512


def corpus(model, sizes_mib=(256, 1024, 4096), repeats=3, jitter=lambda api, kind, size_mib, rep: rep * 1000,
           mid=mid_log, dense=dense_log) -> list[dict]:
    """``dense`` and ``mid`` give (chunks, records) of the two dense logs. The mid log exists at the largest
    size only; None omits it."""
    rows = []
    for size_mib in sizes_mib:
        size = size_mib * MIB
        layouts = {"mcap-dense": dense(size)}
        if mid is not None and size_mib == max(sizes_mib):
            layouts["mcap-mid"] = mid(size)
        layouts.update({
            "mcap-sparse": (size // 262144, size // 262144),  # one chunk per large record
            "plain": (size // 70000, 0),
        })
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
    elif kind in DENSE_WALK:
        workspace = 15 * MIB   # a bounded extra workspace, within the density limit
    else:
        workspace = 9 * MIB    # the sparse walk's 64 KiB window and one segment
    return workspace + 110 * chunks


def record_walk(api, kind) -> bool:
    return api != "cdc_file" and kind != "plain"


def record_pairs(verdict) -> dict:
    return {pair["api"]: pair for pair in verdict["dense_vs_mid"]}


def test_a_fixed_workspace_per_kind_plus_per_chunk_output_passes_and_is_recovered():
    verdict = bench.evaluate(corpus(healthy))
    assert verdict["passed"], verdict["failures"]
    for api in APIS:
        fit = verdict["fits"][api]
        assert abs(fit["bytes_per_chunk"] - 110) < 5, fit
        assert abs(fit["diagnostic_bytes_per_record"]) < 0.001, fit
        expected = {"mcap-dense": 33 if api == "cdc_file" else 15, "mcap-mid": 33 if api == "cdc_file" else 15,
                    "mcap-sparse": 33 if api == "cdc_file" else 9, "plain": 33}
        assert set(fit["workspace_bytes"]) == set(expected)
        for kind, mib in expected.items():
            assert abs(fit["workspace_bytes"][kind] / MIB - mib) < 0.1, (api, kind, fit)
        pair = record_pairs(verdict)[api]
        assert pair["size"] == 4096 * MIB, "the pair is the largest size's"
        assert abs(pair["bytes_per_record"]) < 1e-6 and pair["underpowered"] is None, pair
        assert pair["applied_bytes_per_chunk"] == pytest.approx(110)
    assert verdict["growth"], "the per-kind growth table must be reported"


def test_a_constant_difference_between_dense_and_sparse_is_not_charged_to_records():
    """A permitted fixed 6 MiB difference is not charged to record retention."""
    two_sizes = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    verdict = bench.evaluate(two_sizes)
    assert verdict["passed"], verdict["failures"]
    assert abs(verdict["fits"]["format_aware_file"]["diagnostic_bytes_per_record"]) < 0.001
    assert abs(record_pairs(verdict)["format_aware_file"]["bytes_per_record"]) < 1e-6


def test_a_constant_16_mib_density_overhead_still_fails_the_original_limit():
    def excessive_density(api, kind, chunks, records):
        extra = 10 * MIB if record_walk(api, kind) and kind in DENSE_WALK else 0
        return healthy(api, kind, chunks, records) + extra

    verdict = bench.evaluate(corpus(excessive_density, sizes_mib=(256, 1024), repeats=2))
    assert not verdict["passed"]
    for api in FORMAT_AWARE:
        assert abs(verdict["fits"][api]["diagnostic_bytes_per_record"]) < 0.001
        assert abs(record_pairs(verdict)[api]["bytes_per_record"]) < 1e-6
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
        workspace = (18 if kind in DENSE_WALK else 9) * MIB
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
    for api in FORMAT_AWARE:
        assert record_pairs(verdict)[api]["bytes_per_record"] == pytest.approx(per_record, abs=0.01)
    assert abs(record_pairs(verdict)["cdc_file"]["bytes_per_record"]) < 1e-6


def test_a_workspace_above_the_declared_bound_fails():
    """52 MiB is what macOS measured while the dense window grew by doubling."""
    def doubled(api, kind, chunks, records):
        extra = 37 * MIB if (record_walk(api, kind) and kind in DENSE_WALK) else 0
        return healthy(api, kind, chunks, records) + extra

    verdict = bench.evaluate(corpus(doubled))
    assert not verdict["passed"]
    for kind in DENSE_WALK:
        assert any(f"{kind} workspace 52.0 MiB exceeds the declared 40 MiB (record-walk)" in f
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


# --- per-record memory is measured by the dense/mid pair, not read off the joint fit ---

def hosted_shape(walk_cost=140, plain_cost=30, per_record=0.0):
    """The shape hosted CI measured at 4621947: a returned chunk shows its cost on the record walk
    (Linux 141 bytes) and far less of it on the plain log (31), whose 32 MiB window dominates the peak."""
    def model(api, kind, chunks, records):
        if not record_walk(api, kind):
            return 32.5 * MIB + plain_cost * chunks
        workspace = (0.5 if kind == "mcap-sparse" else 0.3) * MIB
        return workspace + walk_cost * chunks + per_record * records
    return model


@pytest.mark.parametrize("walk_cost", [140, 240])
def test_a_chunk_cost_the_plain_log_under_reports_is_not_charged_to_records(walk_cost):
    """The hosted Linux failure: no per-record memory at all, and 0.0501 bytes/record off the joint fit."""
    verdict = bench.evaluate(corpus(hosted_shape(walk_cost=walk_cost), sizes_mib=(256, 1024), repeats=2))
    assert verdict["passed"], verdict["failures"]
    for api in FORMAT_AWARE:
        fit, pair = verdict["fits"][api], record_pairs(verdict)[api]
        # The joint fit still reads this scanner as O(records); that number is reported and decides nothing.
        assert fit["bytes_per_chunk"] < walk_cost / 3, "the plain log pins the shared per-chunk cost near its own"
        assert fit["diagnostic_bytes_per_record"] > bench.MAX_BYTES_PER_RECORD
        assert "bytes_per_record" not in fit, "the fit must not carry a field that reads as the gate"
        assert abs(pair["bytes_per_record"]) < 1e-6
        assert pair["applied_bytes_per_chunk"] == pytest.approx(walk_cost)
        assert pair["resolvable_bytes_per_record"] < bench.MIN_RESOLVABLE_BYTES_PER_RECORD / 10


@pytest.mark.parametrize("per_record", [0.25, 1.0])
def test_a_per_record_leak_fails_through_the_pair(per_record):
    verdict = bench.evaluate(corpus(hosted_shape(per_record=per_record), sizes_mib=(256, 1024), repeats=2))
    assert not verdict["passed"]
    named = [f for f in verdict["failures"] if "bytes/record" in f and "O(records)" in f]
    assert {f.split(":")[0] for f in named} == set(FORMAT_AWARE), verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert pair["bytes_per_record"] == pytest.approx(per_record, abs=0.01) and pair["underpowered"] is None
    assert abs(record_pairs(verdict)["cdc_file"]["bytes_per_record"]) < 1e-6


@pytest.mark.parametrize("mid_chunk_bytes", [58000, 74000])
def test_a_chunk_count_difference_is_costed_from_the_dense_walk_in_either_direction(mid_chunk_bytes):
    """13% more chunks in the mid log, or 11% fewer: costed at the walk's 140 bytes, not the plain log's 30.
    At 768 MiB both counts stay between 8,192 and 16,384."""
    rows = corpus(hosted_shape(), sizes_mib=(192, 768), repeats=2, mid=lambda size: (size // mid_chunk_bytes, size // 512))
    verdict = bench.evaluate(rows)
    assert verdict["passed"], verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert abs(pair["d_chunks"]) > 1300 and (pair["d_chunks"] > 0) == (mid_chunk_bytes > 65536)
        assert pair["dense_median"] - pair["mid_median"] == pytest.approx(140 * pair["d_chunks"])
        assert abs(pair["bytes_per_record"]) < 1e-6 and pair["straddles_power_of_two"] is None


def test_one_bit_per_record_fails_when_the_dense_log_has_more_chunks_to_be_credited():
    def leaky(api, kind, chunks, records):
        return healthy(api, kind, chunks, records) + (0.125 * records if record_walk(api, kind) else 0)

    rows = corpus(leaky, sizes_mib=(192, 768), repeats=2, mid=lambda size: (size // 66300, size // 512))
    verdict = bench.evaluate(rows)
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert pair["d_chunks"] > 100
        # All dense growth is credited to chunks, the leak's included: 366 bytes for a chunk that costs 110.
        assert pair["applied_bytes_per_chunk"] == pytest.approx(110 + 0.125 * 2048)
        assert 0.12 < pair["bytes_per_record"] < 0.125
        assert any(f.startswith(api) and "O(records)" in f for f in verdict["failures"])


def test_the_pairs_chunk_cost_is_clipped_to_what_a_chunk_may_cost():
    def shrinking(api, kind, chunks, records):
        if record_walk(api, kind) and kind in DENSE_WALK:
            return 20 * MIB - 50 * chunks
        return healthy(api, kind, chunks, records)

    pair = record_pairs(bench.evaluate(corpus(shrinking, sizes_mib=(256, 1024), repeats=2)))["format_aware_fd"]
    assert pair["fitted_bytes_per_chunk"] == pytest.approx(-50) and pair["applied_bytes_per_chunk"] == 0
    assert pair["d_chunks"] < 0
    assert pair["bytes_per_record"] == pytest.approx(-50 * pair["d_chunks"] / pair["d_records"])

    verdict = bench.evaluate(corpus(lambda api, kind, chunks, records: 2 * MIB + 8192 * chunks,
                                    sizes_mib=(256, 1024), repeats=2))
    pair = record_pairs(verdict)["format_aware_fd"]
    assert pair["fitted_bytes_per_chunk"] == pytest.approx(8192) and pair["applied_bytes_per_chunk"] == 1024
    assert any("bytes/chunk" in f for f in verdict["failures"]), "the per-chunk bound is what fails this scanner"


def test_without_the_mid_log_records_are_unmeasured_not_passed():
    verdict = bench.evaluate(corpus(healthy, sizes_mib=(256, 1024), repeats=2, mid=None))
    assert not verdict["passed"]
    assert sorted(verdict["failures"]) == sorted(f"{api}: {NO_PAIR}" for api in APIS), "and nothing else is wrong"
    assert all(pair["bytes_per_record"] is None for pair in verdict["dense_vs_mid"])

    # A mid log at the smaller size only is not the pair either.
    rows = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    for row in rows:
        if row["kind"] == "mcap-mid":
            row["size"] = 256 * MIB
    verdict = bench.evaluate(rows)
    assert {f.split(":")[0] for f in verdict["failures"] if NO_PAIR in f} == set(APIS)

    # A leak is not called one by a run that did not measure it, and is not passed.
    def leaky(api, kind, chunks, records):
        return healthy(api, kind, chunks, records) + (records if record_walk(api, kind) else 0)

    verdict = bench.evaluate(corpus(leaky, sizes_mib=(256, 1024), repeats=2, mid=None))
    assert not verdict["passed"] and not any("O(records)" in f for f in verdict["failures"])
    assert verdict["fits"]["format_aware_fd"]["diagnostic_bytes_per_record"] == pytest.approx(1.0, abs=0.01)


def test_an_api_measured_on_plain_logs_only_gets_no_record_verdict():
    rows = [row for row in corpus(healthy, sizes_mib=(256, 1024), repeats=2) if row["kind"] == "plain"]
    verdict = bench.evaluate(rows)
    assert verdict["passed"], verdict["failures"]
    assert verdict["dense_vs_mid"] == []


def test_a_pair_whose_chunk_counts_differ_declares_itself_underpowered():
    """8 KiB records reach min_size: every record is a cut, eight times the dense log's chunks."""
    verdict = bench.evaluate(corpus(healthy, sizes_mib=(256, 1024), repeats=2,
                                    mid=lambda size: (size // 8192, size // 8192)))
    assert sorted(f.split(":")[0] for f in verdict["failures"]) == sorted(FORMAT_AWARE), verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert pair["d_chunks"] == 16384 - 131072
        assert pair["resolvable_bytes_per_record"] == pytest.approx((2 * 1000 + 114688 * 1024) / pair["d_records"])
        assert pair["resolvable_bytes_per_record"] > 3
        # This scanner is linear, so the estimate happens to be right. It is still not trusted.
        assert abs(pair["bytes_per_record"]) < 1e-6
        assert any(f.startswith(api + ": underpowered") and "chunk counts differ by 114,688" in f
                   for f in verdict["failures"])
    # Plain CDC ignores the container: equal chunk counts, a powered pair, nothing to report.
    assert record_pairs(verdict)["cdc_file"]["underpowered"] is None


@pytest.mark.parametrize("fewer_chunks,powered", [(2600, True), (3100, False)])
def test_the_chunk_count_difference_a_pair_tolerates_is_set_by_the_per_chunk_limit(fewer_chunks, powered):
    """Over the 23.6 million records of a 768 MiB pair, one bit per record is 2.8 MiB: 2,880 chunks at the
    1,024 bytes one may cost. Both counts stay between 8,192 and 16,384."""
    rows = corpus(healthy, sizes_mib=(192, 768), repeats=2,
                  mid=lambda size: (size // 65536 - fewer_chunks, size // 512))
    verdict = bench.evaluate(rows)
    assert verdict["passed"] is powered, verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert pair["d_chunks"] == fewer_chunks and abs(pair["bytes_per_record"]) < 1e-6
        assert (pair["underpowered"] is None) is powered and pair["straddles_power_of_two"] is None
        if not powered:
            assert any(f.startswith(api) and f"chunk counts differ by {fewer_chunks:,}" in f for f in verdict["failures"])


def stepped(step_mib=0.4, per_record=0.0):
    """Measured on Windows: the record walk's peak is 0.3-0.4 MiB higher once it returns 16,384 chunks."""
    def model(api, kind, chunks, records):
        extra = per_record * records if record_walk(api, kind) else 0
        if record_walk(api, kind) and kind in DENSE_WALK and chunks >= 16384:
            extra += step_mib * MIB
        return healthy(api, kind, chunks, records) + extra
    return model


@pytest.mark.parametrize("dense_offset,boundary", [(-36, 16384), (-1, 16384), (0, None), (18, None)])
def test_a_pair_on_opposite_sides_of_a_power_of_two_is_underpowered(dense_offset, boundary):
    """Measured at 1 GiB with no per-record memory: 16,348 chunks against 16,429 read 0.013 bytes/record low,
    16,402 against 16,543 read zero. Repeats of one file cannot tell the two cases apart; the chunk counts can."""
    def rows(model):
        return corpus(model, sizes_mib=(256, 1024), repeats=2,
                      dense=lambda size: (size // 65536 + dense_offset, size // 32))

    verdict = bench.evaluate(rows(stepped()))
    assert verdict["passed"] is (boundary is None), verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert (pair["dense_chunks"], pair["mid_chunks"]) == (16384 + dense_offset, 16570)
        assert pair["straddles_power_of_two"] == boundary
        assert pair["resolvable_bytes_per_record"] < bench.MIN_RESOLVABLE_BYTES_PER_RECORD / 10, "by spread, powered"
        if boundary:
            assert pair["bytes_per_record"] == pytest.approx(-0.4 * MIB / pair["d_records"], abs=1e-4), "the step"
            assert any(f.startswith(api + ": underpowered") and "opposite sides of 16,384" in f and "3*2^k MiB" in f
                       for f in verdict["failures"]), verdict["failures"]
        else:
            # Both logs are past the step. It is in the dense log's growth, so in the cost of a chunk: 0.0002.
            assert abs(pair["bytes_per_record"]) < 1e-3 and pair["underpowered"] is None
    # Plain CDC returned the same number of chunks for both logs: nothing to refuse.
    assert record_pairs(verdict)["cdc_file"]["straddles_power_of_two"] is None
    assert not any(f.startswith("cdc_file") for f in verdict["failures"])

    # A leak just over the limit, which the step would hide: 0.06 - 0.013 reads under 0.05.
    verdict = bench.evaluate(rows(stepped(per_record=0.06)))
    assert not verdict["passed"]
    leak_named = {f.split(":")[0] for f in verdict["failures"] if "O(records)" in f}
    if boundary:
        assert all(record_pairs(verdict)[api]["bytes_per_record"] < bench.MAX_BYTES_PER_RECORD for api in FORMAT_AWARE)
        assert leak_named == set() and sorted(f.split(":")[0] for f in verdict["failures"]) == sorted(FORMAT_AWARE)
    else:
        assert leak_named == set(FORMAT_AWARE), "clear of the boundary the pair is judged, and the leak fails"


@pytest.mark.parametrize("noisy_kind", DENSE_WALK)
@pytest.mark.parametrize("spread_mib,powered", [(1.5, True), (2.5, False)])
def test_repeat_noise_in_either_log_of_the_pair_decides_its_power(noisy_kind, spread_mib, powered):
    """Twice the larger repeat spread must stay under the 3.75 MiB that one bit per record amounts to."""
    def jitter(api, kind, size_mib, rep):
        noisy = record_walk(api, kind) and kind == noisy_kind and size_mib == 1024
        return int(rep * spread_mib * MIB) if noisy else rep * 1000

    verdict = bench.evaluate(corpus(healthy, sizes_mib=(256, 1024), repeats=2, jitter=jitter))
    assert verdict["passed"] is powered, verdict["failures"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert max(pair["dense_repeat_spread_bytes"], pair["mid_repeat_spread_bytes"]) == int(spread_mib * MIB)
        assert pair["resolvable_bytes_per_record"] == pytest.approx(
            (2 * int(spread_mib * MIB) + abs(pair["d_chunks"]) * 1024) / pair["d_records"])
        assert (pair["underpowered"] is None) is powered
    if not powered:
        assert sorted(f.split(":")[0] for f in verdict["failures"]) == sorted(FORMAT_AWARE)
        assert all("underpowered" in f and "O(records)" not in f for f in verdict["failures"])


def test_one_outlying_repeat_does_not_move_the_estimate_and_is_not_hidden():
    def outlier(api, kind, size_mib, rep):
        return 6 * MIB if (rep == 2 and kind == "mcap-dense" and size_mib == 1024 and record_walk(api, kind)) else 0

    verdict = bench.evaluate(corpus(healthy, sizes_mib=(256, 1024), repeats=3, jitter=outlier))
    assert not verdict["passed"]
    for api in FORMAT_AWARE:
        pair = record_pairs(verdict)[api]
        assert abs(pair["bytes_per_record"]) < 1e-6, "the median of three repeats; their mean reads 0.064"
        assert pair["dense_repeat_spread_bytes"] == 6 * MIB and pair["underpowered"]


def test_a_constant_gap_between_the_two_dense_walks_is_charged_to_records():
    """The pair has one size, so it cannot tell a constant from growth. It errs toward failing:
    at 1 GiB, 1.5 MiB of gap is the limit."""
    def gap(mib):
        def model(api, kind, chunks, records):
            extra = mib * MIB if (record_walk(api, kind) and kind == "mcap-dense") else 0
            return healthy(api, kind, chunks, records) + extra
        return model

    verdict = bench.evaluate(corpus(gap(1), sizes_mib=(256, 1024), repeats=2))
    assert verdict["passed"], verdict["failures"]
    assert record_pairs(verdict)["format_aware_fd"]["bytes_per_record"] == pytest.approx(MIB / 31457280)
    verdict = bench.evaluate(corpus(gap(2), sizes_mib=(256, 1024), repeats=2))
    assert {f.split(":")[0] for f in verdict["failures"] if "O(records)" in f} == set(FORMAT_AWARE)


def test_the_mid_log_has_no_leverage_on_the_joint_fit_and_its_workspace_is_bounded():
    rows = corpus(hosted_shape(), sizes_mib=(256, 1024), repeats=2)
    with_mid = bench.evaluate(rows)["fits"]
    without = bench.evaluate([row for row in rows if row["kind"] != "mcap-mid"])["fits"]
    for api in APIS:
        for name in ("bytes_per_chunk", "diagnostic_bytes_per_record"):
            assert with_mid[api][name] == pytest.approx(without[api][name], rel=1e-6, abs=1e-9), (api, name)

    # A workspace only the mid log has: the pair reads it as negative record memory and the envelope
    # has room for it. The fitted workspace is what holds it to the record walk's bound.
    def heavy_mid(api, kind, chunks, records):
        extra = 30 * MIB if (record_walk(api, kind) and kind == "mcap-mid") else 0
        return healthy(api, kind, chunks, records) + extra

    verdict = bench.evaluate(corpus(heavy_mid, sizes_mib=(256, 1024), repeats=2))
    assert sorted(verdict["failures"]) == sorted(
        f"{api}: mcap-mid workspace 45.0 MiB exceeds the declared 40 MiB (record-walk)" for api in FORMAT_AWARE)


# What a run with no mcap-mid log at its largest size (here 1 GiB) is told, for every API that has records.
NO_PAIR = ("underpowered: no mcap-mid log at the largest size (1024 MiB), "
           "so per-record memory was not measured")


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
    assert verdict["fits"]["format_aware_file"]["diagnostic_bytes_per_record"] < bench.MAX_BYTES_PER_RECORD / 5
    assert not any("O(records)" in f for f in verdict["failures"])
    # The historical protocol never measured plain files through the fd API.
    assert any(f.startswith("format_aware_fd: density comparison requires plain-file")
               for f in verdict["failures"])
    if runner == "windows":
        assert any(f.startswith("format_aware_file @") for f in verdict["failures"])
    # Nor the mid log: a flat joint-fit slope is not a measurement of records.
    assert {f.split(":")[0] for f in verdict["failures"] if NO_PAIR in f} == set(APIS)


def test_measured_samples_from_the_doubling_window_fail_on_workspace():
    """macOS at c7d57a1: the dense window grew by doubling and briefly held two copies."""
    verdict = bench.evaluate(measured("macos"))
    assert not verdict["passed"]
    assert any("mcap-dense workspace" in f and "exceeds the declared 40 MiB (record-walk)" in f
               for f in verdict["failures"]), verdict["failures"]
    # Plain CDC is blamed for nothing it measured; these rows predate the mid log, and that is said of every API.
    assert [f for f in verdict["failures"] if f.startswith("cdc_file")] == ["cdc_file: " + NO_PAIR]


def hosted(runner: str) -> tuple[list[dict], dict]:
    """CI run 45827193074 at 4621947: complete, validated peak windows, and no mid log."""
    fixture = json.loads((ROOT / "tests" / "scan_memory_ci_4621947.json").read_text(encoding="utf-8"))
    columns = fixture["columns"]
    rows = [dict(zip(columns, row)) for row in fixture["runners"][runner]]
    for row in rows:
        row["size"] = row.pop("size_mib") * MIB
    design = {"apis": fixture["apis"], "sizes": [size * MIB for size in fixture["sizes_mib"]],
              "repeats": fixture["repeats"]}
    return rows, design


@pytest.mark.parametrize("runner", ["ubuntu", "windows", "macos"])
def test_hosted_reports_without_the_mid_log_are_not_promoted(runner):
    """Linux failed at 0.0501 bytes/record and the others passed. None of the three measured records."""
    rows, design = hosted(runner)
    assert len(rows) == 36 and not any(row["kind"] == "mcap-mid" for row in rows)
    result = bench.qualify(rows, design)
    assert not result["passed"] and not result["measurement_valid"]
    assert result["measurement_failures"] == ["measurement grid has a missing or extra sample",
                                              "samples do not match the declared complete measurement grid"]
    model = [f for f in result["failures"] if f not in result["measurement_failures"]]
    assert sorted(model) == sorted(f"{api}: {NO_PAIR}" for api in APIS), "the unmeasured pair, and nothing else"
    assert all(pair["bytes_per_record"] is None for pair in result["dense_vs_mid"])
    fit = result["fits"]["format_aware_fd"]
    if runner == "ubuntu":
        # The number that failed the run is still computed. It is labelled, and it decides nothing.
        assert fit["diagnostic_bytes_per_record"] == pytest.approx(0.0501, abs=5e-5)
        assert fit["diagnostic_bytes_per_record"] > bench.MAX_BYTES_PER_RECORD
    else:
        assert fit["diagnostic_bytes_per_record"] < bench.MAX_BYTES_PER_RECORD


def test_hosted_growth_per_returned_chunk_is_what_the_model_section_cites():
    """Median peak growth from 256 MiB to 1 GiB per returned chunk, format_aware_fd: dense, sparse, plain."""
    cited = {"ubuntu": (141, 126, 31), "windows": (155, 42, 106), "macos": (210, 237, 195)}
    for runner, expected in cited.items():
        growth = {g["kind"]: g for g in bench.evaluate(hosted(runner)[0])["growth"] if g["api"] == "format_aware_fd"}
        per_chunk = []
        for kind in ("mcap-dense", "mcap-sparse", "plain"):
            (low, high), (few, many) = growth[kind]["median_peak_bytes"], growth[kind]["chunks"]
            per_chunk.append(round((high - low) / (many - few)))
        assert tuple(per_chunk) == expected, runner
        # 25 million more records, 1.65-2.75 MiB more peak; the sparse log has 3 thousand records in all.
        dense = growth["mcap-dense"]
        assert dense["records"][1] - dense["records"][0] == 25165824
        assert 1.6 * MIB < dense["median_peak_bytes"][1] - dense["median_peak_bytes"][0] < 2.8 * MIB


def test_scan_speed_is_reported_against_the_plain_log_of_the_same_run():
    """The memory limit has a cost beside it: what the buffer sizes do to speed, as a ratio a run can compare."""
    rows = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    speeds = {"mcap-dense": 600.0, "mcap-mid": 900.0, "mcap-sparse": 2400.0, "plain": 1200.0}  # MiB/s
    for row in rows:
        row["seconds"] = (row["size"] / MIB) / speeds[row["kind"]] * (1.0 + 0.02 * row["repeat"])
    verdict = bench.evaluate(rows)
    assert verdict["passed"], "a speed ratio is reported, never a reason to fail"
    table = {(r["api"], r["size"] // MIB, r["kind"]): r for r in verdict["relative_throughput"]}
    measured_cells = {(api, size, kind) for api in APIS for size in (256, 1024) for kind in ("mcap-dense", "mcap-sparse")}
    measured_cells |= {(api, 1024, "mcap-mid") for api in APIS}  # the mid log exists at the largest size only
    assert set(table) == measured_cells, "one row per non-plain kind, API and size"
    assert table[("format_aware_fd", 1024, "mcap-mid")]["ratio_to_plain"] == pytest.approx(0.75, rel=1e-6)
    dense = table[("format_aware_file", 1024, "mcap-dense")]
    assert dense["ratio_to_plain"] == pytest.approx(0.5, rel=1e-6)
    assert dense["median_mib_per_s"] == pytest.approx((600.0 + 600.0 / 1.02) / 2, rel=1e-6)  # two repeats
    assert table[("format_aware_fd", 256, "mcap-sparse")]["ratio_to_plain"] == pytest.approx(2.0, rel=1e-6)


def test_samples_without_timing_report_no_speed_rather_than_a_guess():
    assert bench.evaluate(corpus(healthy))["relative_throughput"] == []
    assert bench.relative_throughput(measured("ubuntu")) == []


@pytest.mark.parametrize("record_bytes", [32, 512, 1024, 262144])
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


@pytest.mark.parametrize("mid_record_bytes", ["32", "31", str(256 * 1024)])
def test_the_mid_record_size_must_lie_strictly_between_dense_and_sparse(tmp_path: Path, mid_record_bytes: str, capsys):
    # Megabyte sizes: a run that wrongly got past the check would write megabytes, not the default gigabytes.
    with pytest.raises(SystemExit) as refused:
        bench.main(["--sizes-mib", "1,2", "--repeats", "2", "--workdir", str(tmp_path / "work"),
                    "--report", str(tmp_path / "report.json"), "--mid-record-bytes", mid_record_bytes])
    assert refused.value.code == 2
    assert "dense < mid < sparse" in capsys.readouterr().err
    assert not (tmp_path / "report.json").exists()


def test_a_real_run_measures_the_grid_qualification_requires(tmp_path: Path, capsys):
    """The producer and the gate must agree on the grid: the mid log at the largest size, and only there."""
    pytest.importorskip("one_link_native.chunk")
    report_path = tmp_path / "report.json"
    code = bench.main(["--sizes-mib", "1,2", "--repeats", "2", "--workdir", str(tmp_path / "work"),
                       "--report", str(report_path)])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    cells = {(row["kind"], row["size"] // MIB) for row in report["samples"]}
    assert cells == {(kind, size) for kind in ("mcap-dense", "mcap-sparse", "plain") for size in (1, 2)} | {("mcap-mid", 2)}
    assert len(report["samples"]) == 3 * (2 * 3 + 1) * 2
    grid = {"measurement grid has a missing or extra sample",
            "samples do not match the declared complete measurement grid"}
    assert not grid & set(report["measurement_failures"]), report["measurement_failures"]
    mid = [row for row in report["samples"] if row["kind"] == "mcap-mid"]
    assert {row["records"] for row in mid} == {2 * MIB // 512 + 1}, "512-byte records by default"
    assert {pair["api"] for pair in report["dense_vs_mid"]} == set(APIS)
    assert all(pair["size"] == 2 * MIB and pair["mid_records"] == 2 * MIB // 512 + 1 for pair in report["dense_vs_mid"])
    assert list((tmp_path / "work").iterdir()) == [], "every generated log is deleted"
    # Megabyte logs say nothing about the contract; the exit code only has to be the verdict's.
    assert code == (0 if report["passed"] else 1)
    assert "dense-mid pair" in capsys.readouterr().out

def measured_grid():
    rows = corpus(healthy, sizes_mib=(256, 1024), repeats=2)
    for row in rows:
        delta = row["peak_delta_bytes"]
        row.update(bench._peak_evidence("linux-vmhwm", True, 12*MIB, 12*MIB,
                                       12*MIB+delta, 12*MIB+delta))
        row["seconds"] = 1.0
    return rows, {"apis": list(APIS), "sizes": [256*MIB, 1024*MIB], "repeats": 2}


def test_complete_valid_measurement_windows_promote_the_model():
    rows, design = measured_grid()
    assert len(rows) == 3 * (2 * 3 + 1) * 2, "every kind at both sizes, and the mid log at the larger one"
    result = bench.qualify(rows, design)
    assert result["passed"] and result["measurement_valid"], result["failures"]
    assert len(result["dense_vs_mid"]) == 3


@pytest.mark.parametrize("defect", ["missing", "duplicate", "empty", "counter", "reset",
                                    "mask", "delta", "timing", "legacy", "mixed",
                                    "no_mid", "mid_at_the_smaller_size", "mid_at_both_sizes", "one_api_without_mid"])
def test_measurement_gate_does_not_promote_incomplete_or_masked_samples(defect):
    rows, design = measured_grid()
    if defect == "missing":
        rows.pop()
    elif defect == "no_mid":
        rows = [row for row in rows if row["kind"] != "mcap-mid"]
    elif defect == "mid_at_the_smaller_size":
        for row in rows:
            if row["kind"] == "mcap-mid":
                row["size"] = 256 * MIB
    elif defect == "mid_at_both_sizes":
        rows += [{**row, "size": 256 * MIB} for row in rows if row["kind"] == "mcap-mid"]
    elif defect == "one_api_without_mid":
        # The count is kept by a second copy of another cell's repeats: only the grid's identity can refuse it.
        for row in rows:
            if row["kind"] == "mcap-mid" and row["api"] == "cdc_file":
                row["kind"], row["repeat"] = "mcap-dense", row["repeat"] + 2
    elif defect == "duplicate":
        rows[-1] = rows[0].copy()
    elif defect == "empty":
        rows.clear()
    elif defect == "counter":
        rows[0].pop("peak_counter")
    elif defect == "reset":
        rows[0]["peak_reset"] = False
    elif defect == "mask":
        row = rows[0]
        after = row["peak_after_bytes"]
        row.update(bench._peak_evidence("windows-working-set", False,
                                       after, row["current_before_bytes"], after, after))
    elif defect == "delta":
        rows[0]["peak_delta_bytes"] += 1
    elif defect == "timing":
        rows[0]["seconds"] = float("nan")
    elif defect == "mixed":
        rows[0]["peak_counter"] = "windows-working-set"
        rows[0]["peak_reset"] = False
    else:
        design = None
    result = bench.qualify(rows, design)
    assert not result["passed"] and not result["measurement_valid"]
    assert result["measurement_failures"]


def test_actual_linux_high_water_reset_rejects_an_old_peak():
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux VmHWM reset control")
    # Run outside pytest: its lifetime peak is intentionally irrelevant.
    code = r"""
import importlib.util, mmap
spec = importlib.util.spec_from_file_location("bench", __import__("sys").argv[1])
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
page = mmap.PAGESIZE
large = mmap.mmap(-1, 64 << 20)
large[::page] = b"x" * ((64 << 20)//page)
old, _ = bench._peak_and_current()
large.close()
counter, reset, baseline, current = bench._start_peak_window()
assert counter == "linux-vmhwm" and reset
assert old - baseline >= 32 << 20, (old, baseline)
small = mmap.mmap(-1, 8 << 20)
small[::page] = b"x" * ((8 << 20)//page)
after, current_after = bench._peak_and_current()
assert 4 << 20 <= after - current <= 16 << 20, (current, after)
assert after < old
evidence = bench._peak_evidence(counter, reset, baseline, current, after, current_after)
assert bench._measurement_error(evidence) is None
small.close()
"""
    result = subprocess.run([sys.executable, "-c", code, str(ROOT/"scripts/bench_scan_memory.py")],
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
