from __future__ import annotations

import json
import copy

import pytest

from one_link.perf_lab import compare_reports, run_perf_lab, write_report


def test_perf_lab_quick_report_schema(tmp_path):
    report = run_perf_lab(scale="quick", seed=123)

    assert report["schema"] == "one-link-perf-lab-v1"
    assert report["scale"] == "quick"
    names = {b["name"] for b in report["benchmarks"]}
    assert {
        "hash_only_manifest",
        "fixed_indexing",
        "cdc_indexing",
        "daemon_source_preparation",
        "prior_knowledge_dedup",
        "swarm_scheduler",
        "never_lose_torture_sim",
        "sqlite_transfer_ledger",
        "zlib_level1_compression",
        "adaptive_transfer_brain",
        "stream_pipeline_profiles",
        "adaptive_runtime_scheduler",
    } <= names

    by_name = {b["name"]: b for b in report["benchmarks"]}
    assert by_name["hash_only_manifest"]["metrics"]["mib_per_s"] > 0
    assert by_name["fixed_indexing"]["metrics"]["mib_per_s"] > 0
    assert by_name["cdc_indexing"]["metrics"]["mib_per_s"] > 0
    preparation = by_name["daemon_source_preparation"]["metrics"]
    assert preparation["mib_per_s"] > 0
    assert preparation["index_kind"] == "cdc"
    assert preparation["samples"] == preparation["verified_samples"] == 5
    assert len(preparation["samples_sec"]) == 5
    assert report["provenance"]["host"]["host_id"]
    assert by_name["prior_knowledge_dedup"]["metrics"]["bytes_saved"] > 0
    assert by_name["swarm_scheduler"]["metrics"]["chunks_per_s"] > 0
    assert by_name["never_lose_torture_sim"]["metrics"]["delivered"] is True
    assert by_name["sqlite_transfer_ledger"]["metrics"]["writes_per_s"] > 0
    assert by_name["zlib_level1_compression"]["metrics"]["mib_per_s"] > 0
    assert by_name["adaptive_transfer_brain"]["metrics"]["decisions_per_s"] > 0
    assert by_name["stream_pipeline_profiles"]["metrics"]["huge_window_bytes"] > 0
    assert by_name["adaptive_runtime_scheduler"]["metrics"]["chunks_per_s"] > 0
    assert by_name["adaptive_runtime_scheduler"]["metrics"]["ack_count"] > 0

    out = write_report(report, tmp_path / "perf.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema"] == report["schema"]


def test_perf_lab_rejects_unknown_scale():
    try:
        run_perf_lab(scale="galaxy")  # type: ignore[arg-type]
    except ValueError as e:
        assert "scale" in str(e)
    else:
        raise AssertionError("unknown scale accepted")


def test_perf_lab_compare_reports_ratios():
    identity = {
        "schema": "one-link-perf-lab-v1", "seed": 123,
        "measurement_contract": {"corpus": "seeded-randbytes-v1"},
        "provenance": {"host": {"platform": "Linux", "machine": "x86_64", "python": "3.12.14", "processor": "test CPU", "host_id": "same-host"}},
    }
    old = {
        **identity,
        "scale": "quick",
        "benchmarks": [
            {"name": "cdc_indexing", "metrics": {"mib_per_s": 10.0}},
            {"name": "never_lose_torture_sim", "metrics": {"delivered": True}},
        ],
    }
    new = {
        **identity,
        "scale": "quick",
        "benchmarks": [
            {"name": "cdc_indexing", "metrics": {"mib_per_s": 15.0}},
            {"name": "never_lose_torture_sim", "metrics": {"delivered": True}},
        ],
    }

    cmp = compare_reports(old, new)

    assert cmp["schema"] == "one-link-perf-compare-v1"
    assert cmp["benchmarks"]["cdc_indexing"]["mib_per_s"]["ratio"] == 1.5
    assert cmp["benchmarks"]["never_lose_torture_sim"]["delivered"]["changed"] is False


@pytest.mark.parametrize("field", ["scale", "seed", "host", "engine"])
def test_incompatible_local_reports_do_not_publish_speedup(field):
    old = {
        "schema": "one-link-perf-lab-v1", "scale": "quick", "seed": 123,
        "measurement_contract": {"corpus": "seeded-randbytes-v1"},
        "provenance": {"host": {"platform": "Linux", "machine": "x86_64", "python": "3.12.14", "processor": "CPU", "host_id": "same-host"}},
        "benchmarks": [{"name": "cdc_indexing", "metrics": {"mib_per_s": 100.0, "engine": "python"}}],
    }
    new = copy.deepcopy(old)
    new["benchmarks"][0]["metrics"]["mib_per_s"] = 1000.0
    if field == "scale": new["scale"] = "heavy"
    if field == "seed": new["seed"] = 456
    if field == "host": new["provenance"]["host"]["host_id"] = "different-host"
    if field == "engine": new["benchmarks"][0]["metrics"]["engine"] = "native"
    comparison = compare_reports(old, new)
    assert comparison["status"] == "inconclusive"
    assert comparison["comparison_issues"]
    assert comparison["benchmarks"]["cdc_indexing"]["mib_per_s"]["ratio"] is None


def test_legacy_report_without_provenance_remains_readable_but_unqualified():
    report = {"scale": "quick", "benchmarks": [{"name": "sample", "metrics": {"mib_per_s": 10.0}}]}
    comparison = compare_reports(report, report)
    assert comparison["status"] == "inconclusive"
    assert comparison["benchmarks"]["sample"]["mib_per_s"]["ratio"] is None
