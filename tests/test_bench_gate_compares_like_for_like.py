"""Performance acceptance must retain uncertainty and every measured repetition."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import bench_gate, bench_paired_native

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/native_bench_gate.yml"
HOST = {"platform": "Linux-6.18-x86_64", "machine": "x86_64", "python": "3.12.14", "cpu_count": 4, "host_id": "same-host"}


def payload(value: float, *, arm: str = "candidate", pair: int = 0) -> dict:
    return {
        "host": dict(HOST),
        "provenance": {"session_id": "one-study", "pair_index": str(pair), "arm": arm,
                       "source_revision": "common-harness", "native_source_revision": f"{arm}-commit",
                       "native": {"artifacts": [{"name": "native.so", "sha256": f"{arm}-hash"}]}, "host": dict(HOST)},
        "results": [{"name": "native_cdc_scan", "bytes_per_second_median": value,
                     "bytes_processed": 1024, "iterations": 5, "metadata": {"input_bytes": 1024}}],
    }


def write(tmp_path: Path, name: str, data: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def run(tmp_path: Path, bases: list[float], fresh: list[float], *args: str) -> tuple[int, dict]:
    a = [write(tmp_path, f"c{i}.json", payload(v, pair=i)) for i, v in enumerate(fresh)]
    b = [write(tmp_path, f"b{i}.json", payload(v, arm="baseline", pair=i)) for i, v in enumerate(bases)]
    output = tmp_path / "decision.json"
    code = bench_gate.main(["--results", *map(str, a), "--baseline", *map(str, b), "--require-comparable-host", "--json", str(output), *args])
    return code, json.loads(output.read_text())


@pytest.mark.parametrize("base,fresh,expected", [
    ([100] * 5, [100] * 5, 0),
    ([100] * 5, [97] * 5, 0),
    ([100] * 5, [90] * 5, 1),
    ([100, 100, 100, 100, 40], [60] * 5, 2),
    ([100] * 3, [80, 100, 80], 2),
    ([562.58, 460, 393.12], [419.83, 410, 400], 2),
])
def test_observed_regressions_and_uncertainty_are_never_best_of_n_passes(tmp_path, base, fresh, expected):
    code, report = run(tmp_path, base, fresh)
    assert code == expected
    assert report["status"] == {0: "pass", 1: "fail", 2: "inconclusive"}[expected]
    decision = report["decisions"][0]
    assert decision["baseline_bps"] == base
    assert decision["candidate_bps"] == fresh


def test_paired_regression_cannot_be_hidden_by_one_baseline_outlier(tmp_path):
    code, report = run(tmp_path, [100, 100, 100, 100, 40], [60] * 5, "--require-paired-runs", "--min-samples", "5")
    assert code != 0
    assert report["decisions"][0]["ratio_median"] == pytest.approx(0.6)


def test_true_paired_nonregression_passes_despite_between_pair_host_drift(tmp_path):
    base = [100, 60, 90, 45, 110]
    code, report = run(tmp_path, base, [x * 0.99 for x in base], "--require-paired-runs", "--min-samples", "5")
    assert code == 0
    assert report["decisions"][0]["ratio_interval_95"] == pytest.approx([0.99, 0.99])


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0, -1])
def test_invalid_values_are_inconclusive(tmp_path, bad):
    code, report = run(tmp_path, [100], [bad])
    assert code == 2
    assert "finite and positive" in report["error"]


@pytest.mark.parametrize("change", ["host", "missing_metric", "duplicate", "work", "session", "pair", "build"])
def test_every_repetition_is_validated(tmp_path, change):
    heads = [payload(100, pair=i) for i in range(5)]
    bases = [payload(100, arm="baseline", pair=i) for i in range(5)]
    if change == "host": heads[3]["host"]["cpu_count"] = 24
    if change == "missing_metric": heads[3]["results"] = []
    if change == "duplicate": heads[3]["results"] *= 2
    if change == "work": heads[3]["results"][0]["metadata"]["input_bytes"] = 2048
    if change == "session": heads[3]["provenance"]["session_id"] = "other"
    if change == "pair": heads[3]["provenance"]["pair_index"] = "0"
    if change == "build": heads[3]["provenance"]["native"]["artifacts"][0]["sha256"] = "different"
    aa = [write(tmp_path, f"a{i}.json", x) for i, x in enumerate(heads)]
    bb = [write(tmp_path, f"b{i}.json", x) for i, x in enumerate(bases)]
    code = bench_gate.main(["--results", *map(str, aa), "--baseline", *map(str, bb), "--require-comparable-host", "--require-paired-runs", "--min-samples", "5"])
    assert code == 2


def test_missing_baseline_is_not_a_green_initialization(tmp_path):
    head = write(tmp_path, "head.json", payload(100))
    assert bench_gate.main(["--results", str(head), "--baseline", str(tmp_path / "absent.json")]) == 2


def test_ci_minimum_repetitions_are_enforced(tmp_path):
    assert run(tmp_path, [100] * 4, [100] * 4, "--min-samples", "5")[0] == 2


def test_per_metric_limit_applies_only_to_the_named_metric_and_is_reported(tmp_path, capsys):
    assert run(tmp_path, [100] * 5, [92] * 5, "--metric-limit", "native_cdc*=12")[0] == 0
    assert "TOLERATED" in capsys.readouterr().out
    assert run(tmp_path, [100] * 5, [92] * 5, "--metric-limit", "native_aead*=12")[0] == 1
    assert run(tmp_path, [100] * 5, [80] * 5, "--metric-limit", "native_cdc*=12")[0] == 1


@pytest.mark.parametrize("spec", ["name", "=12", "name=", "name=abc", "name=nan", "name=inf", "name=-1", "name=100"])
def test_invalid_limits_cannot_disable_the_gate(tmp_path, spec):
    with pytest.raises(SystemExit) as error:
        run(tmp_path, [100], [100], "--metric-limit", spec)
    assert error.value.code == 2


def test_paired_schedule_alternates_and_keeps_every_arm():
    assert bench_paired_native.paired_order(3) == [(0, "candidate"), (0, "baseline"), (1, "baseline"), (1, "candidate"), (2, "candidate"), (2, "baseline")]


def test_paired_runner_preserves_virtual_environment_python_symlink(tmp_path):
    target = tmp_path / "base-python"
    target.touch()
    selected = tmp_path / "venv-python"
    try:
        selected.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable on this platform")
    assert bench_paired_native.interpreter_path(selected) == selected
    assert bench_paired_native.interpreter_path(selected) != selected.resolve()


def test_workflows_build_separately_and_require_complete_paired_evidence():
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text())
    assert set(spec["jobs"]) == {"applicability", "bench_gate", "drift_watch", "aggregate"}
    for name in ("bench_gate", "drift_watch"):
        job = spec["jobs"][name]
        runs = "\n".join(step.get("run", "") for step in job["steps"])
        assert "git worktree add --detach" in runs
        assert "git checkout --force" not in runs
        assert "bench_paired_native.py" in runs and "--profile ci --repeats 20" in runs
        assert "--candidate-python" in runs and "--baseline-python" in runs
        assert "--require-comparable-host --require-paired-runs --min-samples 20" in runs
        assert "bench_baselines/native_chunk.json" not in runs
        assert any(step.get("if") == "always()" and "upload-artifact@" in step.get("uses", "") for step in job["steps"])
    events = spec.get("on", spec.get(True))
    # PRs always emit the required aggregate. The explicit, tested diff scope
    # uses the same policy as this master push filter (test_native_ci_scope.py).
    assert "pull_request" in events and not events["pull_request"]
    patterns = events["push"]["paths"]
    for changed in ("scripts/bench_gate.py", "scripts/bench_paired_native.py", "src/one_link/aead_native.py", "src/one_link/quic_native.py", "src/one_link/wal_native.py", "src/one_link/chunk_store_native.py", "src/one_link/benchmark_contract.py", "uv.lock"):
        assert any(bench_gate.fnmatch.fnmatchcase(changed, pattern) for pattern in patterns), changed


def test_json_cli_returns_nonzero_for_the_original_audit_fixture(tmp_path):
    heads = [write(tmp_path, f"head-{i}.json", payload(60)) for i in range(5)]
    bases = [write(tmp_path, f"base-{i}.json", payload(v)) for i, v in enumerate([100, 100, 100, 100, 40])]
    completed = subprocess.run([sys.executable, str(REPO / "scripts" / "bench_gate.py"), "--results", *map(str, heads), "--baseline", *map(str, bases)], capture_output=True, text=True, check=False)
    assert completed.returncode == 2
    assert "INCONCLUSIVE" in completed.stderr
    assert "PASS:" not in completed.stdout
