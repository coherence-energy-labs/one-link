"""No audit item may disappear from the Phase Zero reconciliation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "docs" / "audit"
SOURCE = ROOT / "remediation-2026-11-24.json"
COVERAGE = ROOT / "PHASE_ZERO_OVERHAUL_COVERAGE.json"


def test_overhaul_reconciles_every_inherited_finding():
    text = SOURCE.read_text(encoding="utf-8")
    original = json.loads(text)
    coverage = json.loads(COVERAGE.read_text(encoding="utf-8"))
    assert coverage["audit_source_normalized_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    inherited = {row["id"]: row for row in original["findings"]}
    tracked = {row["id"]: row for row in coverage["findings"]}
    assert len(tracked) == len(coverage["findings"])
    assert tracked.keys() == inherited.keys()
    clustered = [fid for cluster in coverage["root_cause_clusters"].values() for fid in cluster["finding_ids"]]
    assert len(clustered) == len(set(clustered)) == len(tracked)
    assert set(clustered) == set(tracked)
    for fid, row in tracked.items():
        assert row["title"] == inherited[fid]["title"]
        assert row["inherited_status"] == inherited[fid]["status"]
        assert row["inherited_remaining"] == inherited[fid]["remaining"]
        assert row["current_reconciliation"].strip()
        assert fid in coverage["root_cause_clusters"][row["root_cause_cluster"]]["finding_ids"]
        assert row["release_qualification"] == "not_closed_by_this_increment"
    assert coverage["global_requirements"] == original["remaining_global_qualification"]
