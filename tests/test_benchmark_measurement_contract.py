from __future__ import annotations

import hashlib
import json
import zlib
from contextlib import contextmanager
from types import SimpleNamespace

import blake3
import pytest

from one_link.benchmark_contract import CORPORA, corpus_bytes
from one_link import perf_lab_native
from scripts import bench_file_engine as bench


@pytest.mark.parametrize("kind", CORPORA)
@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 65537])
def test_corpus_contract_is_deterministic_and_exact_size(kind, size):
    data = corpus_bytes(size, seed=73, kind=kind)
    assert data == corpus_bytes(size, seed=73, kind=kind)
    assert len(data) == size


def test_default_corpus_does_not_repeat_blocks_or_collapse_under_compression():
    data = bench._build_payload(1024 * 1024, seed=0)
    assert len(zlib.compress(data, 1)) >= len(data) * 0.99
    assert len({data[i:i + 65536] for i in range(0, len(data), 65536)}) == 16
    repetitive = bench._build_payload(len(data), seed=0, kind="repetitive")
    assert len(zlib.compress(repetitive, 1)) < len(data) * 0.02
    compressed = bench._build_payload(len(data), seed=0, kind="compressed")
    assert len(zlib.compress(compressed, 1)) >= len(data) * 0.99


def test_related_corpus_preserves_all_bytes_except_the_declared_edit():
    original = corpus_bytes(1024 * 1024, seed=9)
    edited = corpus_bytes(len(original), seed=9, kind="related")
    midpoint = len(original) // 2
    assert original[:midpoint] == edited[:midpoint]
    assert original[midpoint + 4096:] == edited[midpoint + 4096:]
    assert original[midpoint:midpoint + 4096] != edited[midpoint:midpoint + 4096]


def fake_pair(tmp_path):
    receiver = tmp_path / "receiver"
    receiver.mkdir(exist_ok=True)
    return SimpleNamespace(a=SimpleNamespace(control_port=1), b=SimpleNamespace(home=receiver, short_id="receiver"))


def receipt(payload, route="tcp"):
    return {"ok": True, "result": {"confirmed": True, "size": len(payload), "blob": blake3.blake3(payload).hexdigest(),
        "payload_transport": route, "payload_bytes_by_transport": {route: len(payload)},
        "payload_chunks_by_transport": {route: 1}, "payload_fallbacks": 0,
        "payload_bytes_unit": "encoded_payload_bytes", "payload_accounting_window": "attempt",
        "payload_transfer_totals": {"payload_transport": route, "payload_bytes_by_transport": {route: len(payload)},
            "payload_chunks_by_transport": {route: 1}, "payload_fallbacks": 0,
            "raw_bytes": len(payload), "wire_bytes": len(payload), "chunks": 1},
        "wire_bytes_sent": len(payload), "raw_bytes_sent": len(payload)}}


def test_complete_attempt_verifies_bytes_and_receipt(monkeypatch, tmp_path):
    pair = fake_pair(tmp_path)
    data = b"public benchmark fixture" * 100
    source = tmp_path / "source.bin"
    source.write_bytes(data)
    monkeypatch.setattr(bench, "inbox_files", lambda home: list(home.iterdir()))
    def send(*args, **kwargs):
        assert kwargs["transport"] == "tcp"
        (pair.b.home / "received.bin").write_bytes(data)
        return receipt(data)
    monkeypatch.setattr(bench, "request", send)
    result = bench._transfer_attempt(pair, source, data, transport="tcp", timeout=1)
    assert result["status"] == "passed"
    assert result["receiver_verified"] and result["payload_transport_verified"]
    assert result["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert result["logical_goodput_bps"] > 0
    # The stored row keeps the receipt's own unit and window labels.
    assert result["payload_bytes_unit"] == "encoded_payload_bytes"
    assert result["payload_accounting_window"] == "attempt"
    assert result["payload_transfer_totals"]["wire_bytes"] == result["application_wire_bytes"] == len(data)


@pytest.mark.parametrize("failure", ["missing_file", "wrong_hash", "unconfirmed", "wrong_route", "missing_route_accounting"])
def test_incomplete_or_mislabeled_transfer_cannot_produce_successful_throughput(monkeypatch, tmp_path, failure):
    pair = fake_pair(tmp_path)
    data = b"fixture"
    response = receipt(data)
    if failure == "wrong_hash": response["result"]["blob"] = "0" * 64
    if failure == "unconfirmed": response["result"]["confirmed"] = False
    if failure == "wrong_route": response["result"]["payload_transport"] = "relay"
    if failure == "missing_route_accounting": response["result"].pop("payload_bytes_by_transport")
    monkeypatch.setattr(bench, "inbox_files", lambda _: [])
    monkeypatch.setattr(bench, "request", lambda *a, **k: response)
    monkeypatch.setattr(bench, "_wait_for_payload", lambda *a, **k: (None if failure == "missing_file" else tmp_path / "received", 0))
    result = bench._transfer_attempt(pair, tmp_path / "source", data, transport="tcp")
    assert result["status"] != "passed"
    assert "logical_goodput_bps" not in result


def test_unsupported_route_is_inconclusive_and_retained(monkeypatch, tmp_path):
    pair = fake_pair(tmp_path)
    monkeypatch.setattr(bench, "inbox_files", lambda _: [])
    monkeypatch.setattr(bench, "request", lambda *a, **k: {"ok": False, "error": "unsupported_file_transport: quic"})
    result = bench._transfer_attempt(pair, tmp_path / "source", b"x", transport="quic")
    assert result["status"] == "inconclusive"
    assert result["transport_requested"] == "quic"
    assert "logical_goodput_bps" not in result


def test_existing_receiver_file_cannot_satisfy_warm_transfer(tmp_path, monkeypatch):
    pair = fake_pair(tmp_path)
    old = pair.b.home / "old.bin"
    old.write_bytes(b"old payload")
    monkeypatch.setattr(bench, "inbox_files", lambda home: list(home.iterdir()))
    result, _ = bench._wait_for_payload(pair.b.home, b"old payload", 0.01, exclude={old})
    assert result is None


def test_audit_missing_delivery_fixture_keeps_both_failed_attempts(monkeypatch, tmp_path):
    pair = fake_pair(tmp_path)
    @contextmanager
    def pair_context(): yield pair
    monkeypatch.setattr(bench, "daemon_pair", pair_context)
    monkeypatch.setattr(bench, "inbox_files", lambda _: [])
    monkeypatch.setattr(bench, "request", lambda *a, **k: receipt(b"x"))
    monkeypatch.setattr(bench, "_wait_for_payload", lambda *a, **k: (None, 0))
    rows = bench.bench_cold_transfer([("one byte", 1)], repeat=2)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert rows[0]["attempted"] == 2 and rows[0]["completed"] == 0
    assert len(rows[0]["attempts"]) == 2
    assert rows[0]["throughput_median_bps"] is None


def test_transport_comparison_alternates_without_publishing_partial_speedup(monkeypatch, tmp_path):
    pair = fake_pair(tmp_path)
    @contextmanager
    def pair_context(): yield pair
    monkeypatch.setattr(bench, "daemon_pair", pair_context)
    calls = []
    def attempt(*args, transport, **kwargs):
        calls.append(transport)
        if transport == "quic": return {"status": "inconclusive"}
        return {"status": "passed", "verified_completion_seconds": 1.0}
    monkeypatch.setattr(bench, "_transfer_attempt", attempt)
    result = bench.bench_quic_vs_webrtc(size=64, repeat=3, transports=("quic", "tcp"))
    assert calls == ["quic", "tcp", "tcp", "quic", "quic", "tcp"]
    assert len(result["attempts"]) == 6
    assert result["status"] == "inconclusive"
    assert result["paired_speedup_first_over_second"] is None


def test_cli_returns_nonzero_and_writes_empty_scenario_failure(monkeypatch, tmp_path):
    target = tmp_path / "results.json"
    monkeypatch.setattr("sys.argv", ["bench", "--scenario", "cold", "--json", str(target)])
    monkeypatch.setattr(bench, "bench_cold_transfer", lambda *a, **k: [])
    assert bench.main() == 2
    output = json.loads(target.read_text())
    assert output["status"] == "inconclusive"
    assert output["cold"][0]["error"] == "scenario returned no observations"


def test_native_benchmark_preserves_raw_observations():
    result = perf_lab_native._bench("public", lambda: 64, iterations=3, warmup_iterations=1)
    assert len(result.seconds_per_iteration) == 3
    assert result.bytes_per_iteration == [64] * 3
    assert result.warmup_iterations == 1


def test_native_benchmark_rejects_changing_work():
    values = iter([1, 2])
    with pytest.raises(ValueError, match="work changed"):
        perf_lab_native._bench("bad", lambda: next(values), iterations=2)


def test_python_legacy_comparator_cannot_invoke_native(monkeypatch):
    native_calls = []
    monkeypatch.setattr(perf_lab_native.cdc, "_chunk_bytes_native", lambda _: native_calls.append(True))
    result = perf_lab_native.bench_legacy_cdc_scan(size_mib=1, iterations=1)
    assert result.metadata["engine"] == "python"
    assert native_calls == []


def test_equivalent_gear_pair_checks_hashes_and_boundaries():
    from one_link.native_cdc import get_native_cdc_scanner
    if get_native_cdc_scanner() is None:
        pytest.skip("native C compiler/scanner unavailable")
    rows = perf_lab_native.bench_equivalent_gear_cdc(size_mib=1, iterations=2)
    assert {r.metadata["engine"] for r in rows} == {"ctypes-c", "python"}
    assert all(len(r.seconds_per_iteration) == 2 for r in rows)
