"""The remediation ledger and its report must agree with each other and with the repository.

PR #88 once shipped a committed ledger whose counts (12 verified) contradicted the
pull request's headline (22 verified): the final dispositions lived only in prose
outside the repository. These checks make that state unrepresentable:

* status_counts equals the per-finding statuses, and every status is defined;
* the Markdown report's status table states the same counts;
* every evidence id a finding cites exists in the evidence catalog;
* every commit a finding cites is in the commit catalog and in this repository's
  history (when git and full history are available);
* a verified finding cites at least one executed validation;
* every finding states what remains, or explicitly that nothing does.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "audit" / "remediation-2026-11-24.json"
REPORT = ROOT / "docs" / "audit" / "REMEDIATION_REPORT_2026-11-24.md"
DATA = json.loads(LEDGER.read_text(encoding="utf-8"))
LABELS = {
    "implemented_and_verified": "Implemented and verified",
    "implemented_pending_qualification": "Implemented; qualification pending",
    "partially_remediated": "Partially remediated",
    "prepared_not_applied": "Prepared; not applied",
    "open_external_action": "Open: external action required",
}


def test_status_counts_match_findings_and_every_status_is_defined():
    statuses = collections.Counter(finding["status"] for finding in DATA["findings"])
    assert dict(statuses) == {k: v for k, v in DATA["status_counts"].items() if v}
    assert set(statuses) <= set(DATA["status_definitions"])
    ids = [finding["id"] for finding in DATA["findings"]]
    assert len(ids) == len(set(ids)), "duplicate finding id"


def test_report_status_table_states_the_ledger_counts():
    text = REPORT.read_text(encoding="utf-8")
    for status, count in DATA["status_counts"].items():
        label = LABELS[status]
        match = re.search(rf"^\|\s*{re.escape(label)}\s*\|\s*(\d+)\s*\|", text, re.M)
        if count:
            assert match, f"report has no status-table row for {label!r}"
        if match:
            assert int(match.group(1)) == count, f"report says {match.group(1)} {label}, ledger says {count}"


def test_each_finding_is_stated_in_the_report_with_its_ledger_status():
    """A finding's own section, or its row in the review table, names the status the ledger records."""
    text = REPORT.read_text(encoding="utf-8")
    for finding in DATA["findings"]:
        fid, label = finding["id"], LABELS[finding["status"]]
        section = re.search(rf"^#### {re.escape(fid)} — [^\n]*\n\n\*\*([^·\n]+?) · Original priority", text, re.M)
        row = re.search(rf"^\|\s*{re.escape(fid)}\s*\|.*\|\s*([^|]+?)\s*\|\s*$", text, re.M)
        stated = section.group(1) if section else (row.group(1) if row else None)
        assert stated is not None, f"{fid} is in the ledger but not in the report"
        assert stated == label, f"{fid}: report says {stated!r}, ledger says {label!r}"


def test_cited_evidence_exists():
    catalog = {entry["id"] for entry in DATA["evidence_catalog"]}
    missing = sorted(
        {eid for finding in DATA["findings"] for v in finding.get("validation", []) for eid in v.get("evidence_ids", [])}
        - catalog
    )
    assert not missing, missing


def test_verified_findings_cite_executed_validation_and_every_finding_states_what_remains():
    for finding in DATA["findings"]:
        if finding["status"] == "implemented_and_verified":
            assert finding.get("validation"), finding["id"]
            assert any(v.get("tests") or v.get("evidence_ids") for v in finding["validation"]), finding["id"]
        assert isinstance(finding.get("remaining"), list), finding["id"]


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")
def test_cited_commits_are_catalogued_and_exist_in_history():
    if _git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        pytest.skip("shallow clone: history needed to resolve cited commits")
    catalog = {entry["id"]: entry for entry in DATA["commit_catalog"]}
    cited = {c for finding in DATA["findings"] for change in finding.get("changes", []) for c in change.get("commits", [])}
    assert not sorted(cited - set(catalog)), sorted(cited - set(catalog))
    for short, entry in catalog.items():
        assert entry["revision"].startswith(short), short
        assert _git("cat-file", "-e", f"{entry['revision']}^{{commit}}").returncode == 0, entry["revision"]
