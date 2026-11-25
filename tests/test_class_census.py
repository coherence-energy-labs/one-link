"""MNT-01 ratchet: Daemon and UIServer may only shrink, and each shrink is locked in.

``tests/class_census.py`` measures both classes with ``ast``; the committed
baseline is ``tests/class_census_baseline.json``. Regenerate after an
extraction with ``python -m tests.class_census --write --label "..."``.
The self-tests below prove the gate fails on growth, on a stale (too high)
baseline, on silent reclassification and on unexplained history growth.
"""

from __future__ import annotations

import copy

import pytest

from tests import class_census as census

SAMPLE = '''
class Target:
    attr = 1

    def __init__(self):
        self.a = 1
        self.b, (self.c, *self.d) = 2, (3, 4)
        self.e: int = 5
        self.f += 1
        setattr(self, "g", 7)
        other.h = 8

    @staticmethod
    @decorated
    def send_call_signal():
        return 1

    async def _handle_folder_sync_verify(self):
        pass

    def peer_label(self):
        pass

    def misc(self):
        x = 1
        return x
'''


def sample_census(source: str = SAMPLE) -> dict:
    return {"Target": census.census_class_source(source, "Target")}


# ─── the ratchet ───────────────────────────────────────────────────────


def test_orchestration_classes_match_the_ratchet_baseline() -> None:
    baseline = census.load_baseline()
    current = census.census_targets()
    violations = census.check_baseline(baseline, current)
    assert not violations, "\n".join(v.render() for v in violations)


def test_the_gate_fires_on_the_real_classes() -> None:
    baseline = census.load_baseline()
    current = census.census_targets()
    for target in ("Daemon", "UIServer"):
        for metric in census.SCALAR_METRICS:
            lowered = copy.deepcopy(baseline)
            lowered["classes"][target][metric] -= 1
            kinds = {(v.kind, v.target, v.metric) for v in census.compare(lowered["classes"], current)}
            assert ("grew", target, metric) in kinds
            raised = copy.deepcopy(baseline)
            raised["classes"][target][metric] += 1
            kinds = {(v.kind, v.target, v.metric) for v in census.compare(raised["classes"], current)}
            assert ("stale", target, metric) in kinds


def test_baseline_history_records_the_extraction() -> None:
    history = census.load_baseline()["history"]
    first, last = history[0]["totals"], history[-1]["totals"]
    for target in ("Daemon", "UIServer"):
        assert last[target]["method_lines"] < first[target]["method_lines"]


# ─── measurement ───────────────────────────────────────────────────────


def test_census_counts_methods_lines_and_assigned_state() -> None:
    record = sample_census()["Target"]
    assert record["methods"] == 5
    # Decorator lines are part of a method's span.
    assert record["method_lines"] == 7 + 4 + 2 + 2 + 3
    assert record["self_attributes_assigned"] == 7  # a b c d e f g, never other.h
    assert record["domains"]["call"] == {"methods": 1, "lines": 4}
    assert record["domains"]["folder"] == {"methods": 1, "lines": 2}
    assert record["domains"]["peer"] == {"methods": 1, "lines": 2}
    assert record["domains"]["other"] == {"methods": 2, "lines": 10}


@pytest.mark.parametrize("target", ["Daemon", "UIServer"])
def test_domains_partition_every_method_exactly_once(target: str) -> None:
    record = census.census_targets()[target]
    assert sum(b["methods"] for b in record["domains"].values()) == record["methods"]
    assert sum(b["lines"] for b in record["domains"].values()) == record["method_lines"]


@pytest.mark.parametrize(
    "name,domain",
    [
        ("send_call_signal", "call"),  # call outranks send
        ("_push_folder_to_peer", "folder"),  # folder outranks peer
        ("api_courier_import", "courier"),
        ("_handle_blob_chunk", "transfer"),
        ("_peer_fp_from_peer", "peer"),
        ("send_text", "send"),
        ("start", "other"),
    ],
)
def test_domain_classifier_is_first_match(name: str, domain: str) -> None:
    assert census.domain_for(name) == domain


def test_unknown_class_and_bad_source_are_errors() -> None:
    with pytest.raises(census.CensusError):
        census.census_class_source(SAMPLE, "Missing")
    with pytest.raises(census.CensusError):
        census.census_class_source("class Target(:\n", "Target")


# ─── comparison self-tests ─────────────────────────────────────────────


def test_equal_census_has_no_violations() -> None:
    assert census.compare(sample_census(), sample_census()) == []


def test_growth_and_stale_baselines_are_both_violations() -> None:
    grown = SAMPLE + "\n    def added_peer_method(self):\n        return 2\n"
    violations = census.compare(sample_census(), sample_census(grown))
    grew = {(v.metric, v.baseline, v.current) for v in violations if v.kind == "grew"}
    assert ("methods", 5, 6) in grew and ("domains.peer.methods", 1, 2) in grew
    assert all(v.kind == "grew" for v in violations)
    stale = census.compare(sample_census(grown), sample_census())
    assert stale and all(v.kind == "stale" for v in stale)
    assert "lock the gain in" in stale[0].render() and "GREW" in violations[0].render()


def test_missing_and_unexpected_targets_are_violations() -> None:
    assert {v.kind for v in census.compare(sample_census(), {})} == {"missing"}
    assert {v.kind for v in census.compare({}, sample_census())} == {"unexpected"}
    broken = sample_census()
    broken["Target"]["methods"] = "5"
    assert {v.kind for v in census.compare(broken, sample_census())} == {"missing"}


def test_reclassification_invalidates_the_baseline() -> None:
    baseline = census.build_baseline(sample_census(), label="sample")
    assert census.check_baseline(baseline, sample_census()) == []
    tampered = copy.deepcopy(baseline)
    tampered["classifier_digest"] = "0" * 64
    assert {v.kind for v in census.check_baseline(tampered, sample_census())} == {"classifier"}
    renamed = copy.deepcopy(baseline)
    del renamed["classes"]["Target"]["domains"]["call"]
    assert "classifier" in {v.kind for v in census.check_baseline(renamed, sample_census())}


def test_history_may_only_shrink_unless_growth_is_explained() -> None:
    small = sample_census()
    big = sample_census(SAMPLE + "\n    def added(self):\n        pass\n")
    baseline = census.build_baseline(big, label="before")
    baseline = census.build_baseline(small, label="after extraction", previous=baseline)
    assert census.check_history(baseline) == []
    with pytest.raises(census.CensusError, match="growth-reason"):
        census.build_baseline(big, label="regrow", previous=baseline)
    explained = census.build_baseline(big, label="regrow", previous=baseline, growth_reason="reviewed")
    assert explained["history"][-1]["growth_reason"] == "reviewed"
    assert census.check_history(explained) == []
    silent = copy.deepcopy(explained)
    del silent["history"][-1]["growth_reason"]
    assert {v.kind for v in census.check_history(silent)} == {"history"}
    stale_tail = copy.deepcopy(baseline)
    stale_tail["history"][-1]["totals"]["Target"]["methods"] += 1
    assert any(v.metric == "history[-1].totals" for v in census.check_history(stale_tail))
    assert census.check_history({"history": []})
    with pytest.raises(census.CensusError, match="label"):
        census.build_baseline(small, label="  ")
