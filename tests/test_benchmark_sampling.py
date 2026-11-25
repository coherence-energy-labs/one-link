"""CI sampling is predeclared, balanced, executed and retained verbatim."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link import perf_lab_native as lab
from scripts import bench_paired_native as paired


def test_long_quic_server_plan_preserves_requests_within_native_bounds():
    groups = lab._quic_server_groups(34, 1024)
    assert groups == [8, 8, 8, 8, 2]
    assert sum(groups) * 1024 == 34 * 1024
    assert all(streams * 1024 <= 8192 for streams in groups)
    with pytest.raises(ValueError, match="helper bounds"):
        lab._quic_server_groups(1, 8193)


def test_server_error_is_retained_and_closes_the_waiting_connection():
    closed, errors = [], []
    connection = SimpleNamespace(close=lambda: closed.append("connection"))
    server = SimpleNamespace(close=lambda: closed.append("endpoint"))
    done = threading.Event()
    failure = ValueError("native helper rejected request count")

    def serve(): raise failure

    lab._run_quic_server(serve, server, [connection], done, errors)
    assert errors == [failure] and done.is_set()
    assert closed == ["connection", "endpoint"]


@pytest.mark.parametrize("profile,storage_samples,quic_samples,warmups", [("quick", 5, 3, 0), ("ci", 31, 31, 3)])
def test_suite_actually_dispatches_the_requested_sampling_plan(monkeypatch, profile, storage_samples, quic_samples, warmups):
    calls = []
    for adapter in (lab.chunk_native, lab.aead_native, lab.wal_native, lab.chunk_store_native, lab.quic_native):
        monkeypatch.setattr(adapter, "HAS_NATIVE", True)

    def stub(name):
        def run(**kwargs):
            calls.append((name, kwargs))
            result = SimpleNamespace(metadata={})
            return (result, SimpleNamespace(metadata={})) if name == "bench_native_aead" else result
        return run

    for name in ("bench_native_cdc_scan", "bench_native_chunk_address_raw", "bench_native_chunk_address_convergent",
                 "bench_native_aead_key_derivation", "bench_native_stripe_seed", "bench_native_aead",
                 "bench_native_wal_group_commit", "bench_native_chunk_store_write", "bench_native_chunk_store_locate",
                 "_bench_quic_loopback_round_trip", "_bench_quic_parallel_streams"):
        monkeypatch.setattr(lab, name, stub(name))
    results = lab.run_full_suite(size_mib=8, include_legacy=False, sampling_profile=profile)
    assert len(results) == 28
    assert all(result.metadata["sampling_profile"] == profile for result in results)
    storage = [kwargs for name, kwargs in calls if name in ("bench_native_wal_group_commit", "bench_native_chunk_store_write")]
    assert len(storage) == 4 and all(args["iterations"] == storage_samples for args in storage)
    sequential = [kwargs for name, kwargs in calls if name == "_bench_quic_loopback_round_trip"]
    parallel = [kwargs for name, kwargs in calls if name == "_bench_quic_parallel_streams"]
    assert len(sequential) == 4 and len(parallel) == 2
    assert all(args["bench_iterations"] == quic_samples and args["warmup_iterations"] == warmups
               for args in sequential + parallel)
    if profile == "ci":
        assert [args["iterations"] for args in sequential] == [1024, 256, 64, 20]
        assert [args["iterations_per_stream"] for args in parallel] == [16, 8]
        assert all(args["payload_kib"] * args["iterations"] >= 16384 for args in sequential)
        assert all(args["payload_kib"] * args["parallelism"] * args["iterations_per_stream"] >= 16384 for args in parallel)
    else:
        assert [args["iterations"] for args in sequential] == [200, 200, 50, 20]
        assert [args["iterations_per_stream"] for args in parallel] == [4, 4]


@pytest.mark.parametrize("parallel", [False, True])
def test_quic_executes_warmup_on_the_same_connection_and_retains_all_31_samples(monkeypatch, parallel):
    observed = {"batches": 0, "closed": 0, "streams": 0}

    def serve(streams, requests, _kind, payload, **kwargs):
        assert streams * requests <= 8192
        observed["streams"] += streams
        observed.update(requests=requests, payload_bytes=len(payload))

    def round_trips(_kind, requests, _response_kind, **kwargs):
        observed["batches"] += 1
        return len(requests) * observed["payload_bytes"]

    def close():
        observed["closed"] += 1

    conn = SimpleNamespace(serve_fixed_stream_responses_blocking=serve,
                           send_frame_stream_round_trips_count=round_trips,
                           send_frame_stream_round_trips_count_parallel=round_trips, close=close)
    endpoint = SimpleNamespace(local_addr="127.0.0.1:1", accept_blocking=lambda **_: conn,
                               connect_blocking=lambda *a, **k: conn, close=close)
    monkeypatch.setattr(lab.quic_native, "HAS_NATIVE", True)
    monkeypatch.setattr(lab.quic_native, "Identity", SimpleNamespace(generate=lambda: SimpleNamespace(fingerprint="fixture")))
    monkeypatch.setattr(lab.quic_native, "Endpoint", SimpleNamespace(server=lambda *a, **k: endpoint, client=lambda *a, **k: endpoint))
    monkeypatch.setattr(lab.quic_native, "EndpointConfig", lambda **_: None)
    monkeypatch.setattr(lab.time, "sleep", lambda _: None)

    class ImmediateThread:
        def __init__(self, target, **_): self.target = target
        def start(self): self.target()
        def join(self, **_): pass

    monkeypatch.setattr(lab.threading, "Thread", ImmediateThread)
    if parallel:
        result = lab._bench_quic_parallel_streams(payload_kib=256, parallelism=8, iterations_per_stream=8,
                                                  bench_iterations=31, warmup_iterations=3)
        assert observed["streams"] == 68  # Two lanes, 31 measured + 3 warm-up batches.
        assert observed["requests"] == 32
    else:
        result = lab._bench_quic_loopback_round_trip(payload_kib=16, iterations=1024,
                                                    bench_iterations=31, warmup_iterations=3)
        assert observed["streams"] == 34
        assert observed["requests"] == 1024
    assert observed["batches"] == 34
    assert result.iterations == 31 and result.warmup_iterations == 3
    assert len(result.seconds_per_iteration) == 31
    assert result.bytes_per_iteration == [16 * 1024 * 1024] * 31
    assert result.seconds_total == sum(result.seconds_per_iteration)
    assert observed["closed"] == 4


def test_cli_records_the_sampling_contract_it_executed(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(lab, "run_full_suite", lambda **kwargs: calls.append(kwargs) or [])
    monkeypatch.setattr(lab, "provenance", lambda: {"host": {}})
    monkeypatch.setattr(lab.chunk_native, "diagnostics", dict)
    assert lab.main(["--profile", "ci", "--json", "--no-legacy", "--size-mib", "8"]) == 0
    assert calls == [{"size_mib": 8, "include_legacy": False, "sampling_profile": "ci"}]
    contract = json.loads(capsys.readouterr().out)["measurement_contract"]
    assert contract["sampling_profile"] == "ci"
    assert contract["sampling_plan"] == {"storage_iterations": 31, "quic_iterations": 31,
                                         "quic_warmup_iterations": 3, "quic_min_batch_kib": 16384}


def test_twenty_pairs_have_ten_of_each_starting_arm():
    order = paired.paired_order(20)
    assert len(order) == 40
    assert [arm for _, arm in order[::2]].count("candidate") == 10
    assert [arm for _, arm in order[::2]].count("baseline") == 10
    assert all({arm for _, arm in order[index:index + 2]} == {"candidate", "baseline"}
               for index in range(0, 40, 2))


def runner_args(tmp_path):
    python = tmp_path / "fixture-python"
    python.touch()
    sources = {arm: tmp_path / arm for arm in ("candidate", "baseline")}
    for path in sources.values(): path.mkdir()
    output = tmp_path / "observations"
    args = [arg for arm, source in sources.items() for arg in
            (f"--{arm}-python", str(python), f"--{arm}-source", str(source))]
    return args + ["--output", str(output), "--profile", "ci", "--repeats", "20"], output


@pytest.mark.parametrize("wrong_profile", [False, True])
def test_runner_passes_profile_to_every_child_and_preserves_any_failure(monkeypatch, tmp_path, wrong_profile):
    args, output = runner_args(tmp_path)
    monkeypatch.setattr(paired, "source_revision", lambda path: path.name + "-revision")
    commands = []

    def child(command, *, env, stdout, **_):
        commands.append(command)
        json.dump({"provenance": {"session_id": env["ONE_LINK_BENCH_SESSION"],
                                  "native_source_revision": env["ONE_LINK_BENCH_NATIVE_REVISION"]},
                   "measurement_contract": {"sampling_profile": "quick" if wrong_profile else "ci"}}, stdout)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(paired.subprocess, "run", child)
    assert paired.main(args) == (2 if wrong_profile else 0)
    manifest = json.loads((output / "study.json").read_text())
    assert manifest["requested_pairs"] == 20 and manifest["sampling_profile"] == "ci"
    assert all(command[-2:] == ["--profile", "ci"] for command in commands)
    if wrong_profile:
        assert len(commands) == 1
        assert manifest["status"] == "inconclusive"
        assert (output / "candidate-1.json").is_file()
        assert "sampling profile" in manifest["order"][0]["error"]
    else:
        assert len(commands) == len(manifest["order"]) == 40
        assert len(list(output.glob("candidate-*.json"))) == 20
        assert len(list(output.glob("baseline-*.json"))) == 20
        assert manifest["status"] == "completed"


def test_ci_profile_cannot_silently_reduce_or_extend_its_predeclared_pair_count(tmp_path):
    args, output = runner_args(tmp_path)
    for count in (5, 19, 21):
        with pytest.raises(SystemExit) as error:
            paired.main([*args[:-1], str(count)])
        assert error.value.code == 2
        assert not output.exists()


def test_both_workflow_arms_use_the_complete_predeclared_study():
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/native_bench_gate.yml").read_text())
    for name in ("bench_gate", "drift_watch"):
        commands = "\n".join(step.get("run", "") for step in spec["jobs"][name]["steps"])
        assert "--profile ci --repeats 20 --size-mib 128" in commands
        assert "--results bench-results/candidate-{1..20}.json" in commands
        assert "--baseline bench-results/baseline-{1..20}.json" in commands
        assert "--min-samples 20" in commands
        assert "--max-regression-percent 5" in commands
        for metric in ("native_aead_*", "native_blake3_*", "native_derive_*"):
            assert f"--metric-limit '{metric}=12'" in commands
