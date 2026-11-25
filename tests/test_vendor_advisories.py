"""Keep path overrides visible to live advisory checks and preserve failures."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from scripts import audit_vendor_advisories as audit
from scripts import verify_vendor_patches as vendor


SHELL_MANIFEST = Path(__file__).resolve().parents[1] / "native/ol_shell/Cargo.toml"
KNOWN_ID = "GHSA-wrw7-89jp-8q8g"


@pytest.fixture
def reviewed_source(monkeypatch):
    selected = vendor.inspect_patches(SHELL_MANIFEST)
    for value in selected.values():
        value["upstream_archive_verified"] = True

    def verify(manifest, *, fetch_upstream):
        assert manifest == SHELL_MANIFEST
        assert fetch_upstream is True
        return copy.deepcopy(selected)

    monkeypatch.setattr(audit, "inspect_patches", verify)
    return selected


def response(document, *, status=200):
    return {"http_status": status, "body": json.dumps(document),
            "body_sha256": "transport-digest", "response_too_large": False,
            "response_incomplete": False, "response_valid_utf8": True}


def run(monkeypatch, tmp_path, transport):
    monkeypatch.setattr(audit, "query_osv", transport)
    destination = tmp_path / "upstream-advisories.json"
    code = audit.main(["--manifest", str(SHELL_MANIFEST), "--report", str(destination)])
    return code, json.loads(destination.read_text(encoding="utf-8"))


def test_known_advisory_is_visible_and_bound_to_the_verified_patch(monkeypatch, tmp_path, reviewed_source):
    finding = {"id": KNOWN_ID, "aliases": ["RUSTSEC-2024-0429"],
               "details": "Complete upstream details remain in the raw report."}

    def transport(query):
        assert query == {"package": {"ecosystem": "crates.io", "name": "glib"}, "version": "0.18.5"}
        return response({"vulns": [finding]})

    code, report = run(monkeypatch, tmp_path, transport)
    assert code == 0
    package = report["packages"][0]
    assert json.loads(package["responses"][0]["body"])["vulns"] == [finding]
    assert package["advisories"][0]["disposition"] == "covered-by-verified-source-backport"
    assert package["source_tree_sha256"] == reviewed_source[("glib", "0.18.5")]["proof"]["source_tree_sha256"]
    assert package["source_provenance_verified"] is True


def test_new_advisory_fails_even_when_aliases_contain_a_reviewed_id(monkeypatch, tmp_path, reviewed_source):
    findings = [{"id": KNOWN_ID}, {"id": "GHSA-new-affected-advisory", "aliases": [KNOWN_ID]}]
    code, report = run(monkeypatch, tmp_path, lambda _: response({"vulns": findings}))
    assert code == 1
    assert report["status"] == "failed"
    assert "GHSA-new-affected-advisory" in report["errors"][0]
    assert json.loads(report["packages"][0]["responses"][0]["body"])["vulns"] == findings


@pytest.mark.parametrize("failure", ["timeout", "http", "invalid-json", "schema", "oversized", "incomplete", "invalid-utf8"])
def test_failed_or_incomplete_query_never_passes_and_keeps_report(monkeypatch, tmp_path, reviewed_source, failure):
    def transport(_):
        if failure == "timeout":
            raise TimeoutError("query deadline exceeded")
        if failure == "http":
            return response({"error": "service unavailable"}, status=503)
        if failure == "invalid-json":
            return {**response({}), "body": "upstream returned a truncated body"}
        if failure == "schema":
            return response({"unrecognized-response": "cannot establish a complete advisory result"})
        if failure == "incomplete":
            return {**response({}), "response_incomplete": True}
        if failure == "invalid-utf8":
            return {**response({}), "response_valid_utf8": False}
        return {**response({}), "response_too_large": True}

    code, report = run(monkeypatch, tmp_path, transport)
    assert code == 1
    assert report["status"] == "failed"
    assert report["errors"]
    assert report["packages"][0]["status"] == "failed"
    if failure != "timeout":
        assert report["packages"][0]["responses"][0]["body"]


def test_all_query_pages_are_retained_and_new_later_finding_fails(monkeypatch, tmp_path, reviewed_source):
    def transport(query):
        if "page_token" not in query:
            return response({"vulns": [{"id": KNOWN_ID}], "next_page_token": "second"})
        assert query["page_token"] == "second"
        return response({"vulns": [{"id": "unreviewed-later-advisory"}]})

    code, report = run(monkeypatch, tmp_path, transport)
    assert code == 1
    assert len(report["packages"][0]["responses"]) == 2
    assert len(report["packages"][0]["advisories"]) == 2


@pytest.mark.parametrize("token", [0, False, [], {}, None])
def test_malformed_pagination_tokens_never_hide_an_incomplete_result(monkeypatch, tmp_path, reviewed_source, token):
    code, report = run(monkeypatch, tmp_path, lambda _: response({
        "vulns": [{"id": KNOWN_ID}], "next_page_token": token,
    }))
    assert code == 1
    assert "invalid pagination token" in report["errors"][0]
    assert report["packages"][0]["responses"]


def test_no_advisory_disposition_without_verified_upstream_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(audit, "inspect_patches", lambda *args, **kwargs: vendor.inspect_patches(SHELL_MANIFEST))

    def must_not_query(_):
        pytest.fail("unverified source cannot authorize a registry advisory disposition")

    code, report = run(monkeypatch, tmp_path, must_not_query)
    assert code == 1
    assert report["packages"] == []
    assert "verified original crate archives" in report["errors"][0]


@pytest.mark.parametrize("missing", ["advisories", "upstream_fix_commit"])
def test_invalid_review_metadata_keeps_failure_evidence(monkeypatch, tmp_path, reviewed_source, missing):
    del reviewed_source[("glib", "0.18.5")]["proof"]["backport"][missing]

    def must_not_query(_):
        pytest.fail("incomplete review metadata must fail before a query")

    code, report = run(monkeypatch, tmp_path, must_not_query)
    assert code == 1
    assert report["errors"]
    assert report["packages"][0]["status"] == "failed"


@pytest.mark.parametrize("name", ["security.yml", "release.yml"])
def test_continuous_and_release_workflows_require_live_gate_and_retain_failures(name):
    root = SHELL_MANIFEST.parents[2]
    workflow = yaml.safe_load((root / ".github/workflows" / name).read_text(encoding="utf-8"))
    jobs = [job for job in workflow["jobs"].values() if any(
        "scripts/audit_vendor_advisories.py" in step.get("run", "") for step in job.get("steps", [])
    )]
    assert jobs, "local path packages must retain a live upstream advisory gate"
    for job in jobs:
        assert not job.get("continue-on-error", False)
        steps = job["steps"]
        gate = next(step for step in steps if "scripts/audit_vendor_advisories.py" in step.get("run", ""))
        assert not gate.get("continue-on-error", False)
        assert "|| true" not in gate["run"]
        assert "--report " in gate["run"]
        report_path = gate["run"].split("--report ", 1)[1].split()[0]
        uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
        assert any(step.get("if") == "always()" and any(
            report_path == line or report_path.startswith(line.rstrip("/") + "/")
            for line in step.get("with", {}).get("path", "").splitlines()
        ) for step in uploads), "failed advisory replies must remain available"
