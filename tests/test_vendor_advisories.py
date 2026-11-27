"""Keep path overrides visible to live advisory checks and preserve failures."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from scripts import audit_vendor_advisories as audit
from scripts import verify_vendor_patches as vendor


ROOT = Path(__file__).resolve().parents[1]
SHELL_MANIFEST = ROOT / "native/ol_shell/Cargo.toml"
NATIVE_MANIFEST = ROOT / "native/Cargo.toml"
KNOWN_ID = "GHSA-wrw7-89jp-8q8g"
GLIB = ("glib", "0.18.5")
ML_KEM = ("ml-kem", "0.2.3")


def _selected(*manifests):
    selected = {}
    for manifest in manifests:
        for key, value in vendor.inspect_patches(manifest).items():
            value["upstream_archive_verified"] = True
            value["manifests"] = [manifest.relative_to(ROOT).as_posix()]
            selected[key] = value
    return selected


@pytest.fixture
def reviewed_source(monkeypatch):
    selected = _selected(SHELL_MANIFEST)

    def verify(root, *, fetch_upstream):
        assert root == ROOT
        assert fetch_upstream is True
        return {"packages": copy.deepcopy(selected)}

    monkeypatch.setattr(audit, "inspect_repository", verify)
    return selected


def response(document, *, status=200):
    return {"http_status": status, "body": json.dumps(document),
            "body_sha256": "transport-digest", "response_too_large": False,
            "response_incomplete": False, "response_valid_utf8": True}


def run(monkeypatch, tmp_path, transport):
    monkeypatch.setattr(audit, "query_osv", transport)
    destination = tmp_path / "upstream-advisories.json"
    code = audit.main(["--root", str(ROOT), "--report", str(destination)])
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
    assert package["source_tree_sha256"] == reviewed_source[GLIB]["proof"]["source_tree_sha256"]
    assert package["source_provenance_verified"] is True
    assert package["upstream_fix_commit"] == reviewed_source[GLIB]["proof"]["backport"]["upstream_fix_commit"]
    assert package["manifests"] == ["native/ol_shell/Cargo.toml"]


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
    unverified = {key: {**value, "upstream_archive_verified": False}
                  for key, value in _selected(SHELL_MANIFEST).items()}
    monkeypatch.setattr(audit, "inspect_repository", lambda *args, **kwargs: {"packages": unverified})

    def must_not_query(_):
        pytest.fail("unverified source cannot authorize a registry advisory disposition")

    code, report = run(monkeypatch, tmp_path, must_not_query)
    assert code == 1
    assert report["packages"] == []
    assert "verified original crate archives" in report["errors"][0]


def test_repository_provenance_failure_is_reported_before_any_query(monkeypatch, tmp_path):
    def inconsistent(*args, **kwargs):
        raise vendor.VendorError("native/fuzz/Cargo.lock resolves ml-kem 0.2.3 from the registry")

    monkeypatch.setattr(audit, "inspect_repository", inconsistent)
    code, report = run(monkeypatch, tmp_path, lambda _: pytest.fail("no query after a provenance failure"))
    assert code == 1
    assert "native/fuzz/Cargo.lock" in report["errors"][0]


@pytest.mark.parametrize("change", ["missing-advisories", "missing-remedy", "malformed-commit",
                                    "duplicate-ids", "empty-id", "bad-reference"])
def test_invalid_review_metadata_keeps_failure_evidence(monkeypatch, tmp_path, reviewed_source, change):
    backport = reviewed_source[GLIB]["proof"]["backport"]
    if change == "missing-advisories":
        del backport["advisories"]
    elif change == "missing-remedy":
        del backport["upstream_fix_commit"]
    elif change == "malformed-commit":
        backport["upstream_fix_commit"] = "b5a4071"
    elif change == "duplicate-ids":
        backport["advisories"] = [KNOWN_ID, KNOWN_ID]
    elif change == "empty-id":
        backport["advisories"] = [""]
    else:
        backport["reference_crate_url"] = "https://example.invalid/glib.crate"
        backport["reference_crate_sha256"] = "0" * 64

    def must_not_query(_):
        pytest.fail("incomplete review metadata must fail before a query")

    code, report = run(monkeypatch, tmp_path, must_not_query)
    assert code == 1
    assert report["errors"]
    assert report["packages"][0]["status"] == "failed"


def _with_ml_kem(monkeypatch, advisories):
    selected = _selected(SHELL_MANIFEST, NATIVE_MANIFEST)
    selected[ML_KEM]["proof"]["backport"]["advisories"] = advisories
    monkeypatch.setattr(audit, "inspect_repository", lambda *args, **kwargs: {"packages": copy.deepcopy(selected)})
    return selected


def test_every_backport_in_the_repository_is_queried(monkeypatch, tmp_path):
    _with_ml_kem(monkeypatch, [])
    queried = []

    def transport(query):
        queried.append(query["package"]["name"])
        return response({"vulns": [{"id": KNOWN_ID}]} if query["package"]["name"] == "glib" else {})

    code, report = run(monkeypatch, tmp_path, transport)
    assert code == 0, report["errors"]
    assert sorted(queried) == ["glib", "ml-kem"]
    ml_kem = next(entry for entry in report["packages"] if entry["package"]["name"] == "ml-kem")
    assert ml_kem["reviewed_backport_advisories"] == []
    assert ml_kem["reference_crate_url"].endswith("/ml-kem-0.3.4.crate")
    assert ml_kem["manifests"] == ["native/Cargo.toml"]


def test_a_backport_that_declares_no_advisory_fails_on_any_finding(monkeypatch, tmp_path):
    _with_ml_kem(monkeypatch, [])

    def transport(query):
        if query["package"]["name"] == "glib":
            return response({"vulns": [{"id": KNOWN_ID}]})
        return response({"vulns": [{"id": "RUSTSEC-2099-0001"}]})

    code, report = run(monkeypatch, tmp_path, transport)
    assert code == 1
    assert report["errors"] == ["ml-kem 0.2.3: unreviewed affected advisory RUSTSEC-2099-0001"]


def test_every_committed_provenance_record_declares_its_advisories_and_remedy():
    # The real records: an absent list is not "none"; a reviewer must state it.
    for manifest in (SHELL_MANIFEST, NATIVE_MANIFEST):
        for (name, version), value in vendor.inspect_patches(manifest).items():
            backport = value["proof"]["backport"]
            assert isinstance(backport.get("advisories"), list), f"{name} {version} must declare advisories"
            audit._remedy(backport)


@pytest.mark.parametrize("name", ["security.yml", "release.yml"])
def test_continuous_and_release_workflows_require_live_gate_and_retain_failures(name):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
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
        assert "--manifest" not in gate["run"]
        report_path = gate["run"].split("--report ", 1)[1].split()[0]
        uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
        assert any(step.get("if") == "always()" and any(
            report_path == line or report_path.startswith(line.rstrip("/") + "/")
            for line in step.get("with", {}).get("path", "").splitlines()
        ) for step in uploads), "failed advisory replies must remain available"


@pytest.mark.parametrize("name", ["security.yml", "release.yml"])
def test_every_rust_graph_denies_warnings_and_ignores_only_dispositioned_ids(name):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
    gates = [line.strip() for job in workflow["jobs"].values() for step in job.get("steps", [])
             for line in step.get("run", "").splitlines()
             if line.strip().startswith("cargo audit") and "|| true" not in line]
    locks = {line.split("--file ", 1)[1].split()[0] for line in gates}
    assert locks == {"native/Cargo.lock", "native/fuzz/Cargo.lock", "native/ol_shell/Cargo.lock"}
    for line in gates:
        assert "--deny warnings" in line, line
        ignored = line.split("--ignore ")[1:]
        ids = [item.split()[0] for item in ignored]
        if "native/ol_shell/Cargo.lock" in line:
            # The single reviewed disposition: proc-macro-error is unmaintained
            # with no patched release (docs/DEPENDENCY_QUALIFICATION.md).
            assert ids == ["RUSTSEC-2024-0370"], line
        else:
            assert ids == [], line
    documentation = (ROOT / "docs/DEPENDENCY_QUALIFICATION.md").read_text(encoding="utf-8")
    assert "RUSTSEC-2024-0370" in documentation and "--ignore RUSTSEC-2024-0370" in documentation
