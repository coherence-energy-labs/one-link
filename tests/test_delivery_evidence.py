"""Exercise release evidence failures with real temporary files and processes."""

from __future__ import annotations

import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest
import yaml

from scripts import bootstrap_source, live_suite, repository_policy, run_native_timing
from scripts import verify_native_runtime, verify_reproducible_wheels


ROOT = Path(__file__).resolve().parents[1]


def wheel(directory: Path, *, content: bytes = b"native-binary", year: int = 2024) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "one_link_native-0.22.1-cp311-abi3-linux_x86_64.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(zipfile.ZipInfo("one_link_native.so", (year, 1, 1, 0, 0, 0)), content)
    return path


def test_rebuild_compares_complete_wheel_bytes_and_reports_member_differences(tmp_path):
    candidate, rebuilt = tmp_path / "candidate", tmp_path / "rebuilt"
    wheel(candidate)
    wheel(rebuilt)
    assert verify_reproducible_wheels.compare(candidate, rebuilt)["passed"]
    wheel(rebuilt, year=2025)
    result = verify_reproducible_wheels.compare(candidate, rebuilt)
    assert not result["passed"]
    assert "metadata" in result["wheels"][0]["reason"]
    assert result["wheels"][0]["members"] == []
    wheel(rebuilt, content=b"changed-binary")
    result = verify_reproducible_wheels.compare(candidate, rebuilt)
    assert not result["passed"]
    assert result["wheels"][0]["members"][0]["name"] == "one_link_native.so"


def test_rebuild_refuses_missing_duplicate_corrupt_and_identical_inputs(tmp_path):
    candidate, rebuilt = tmp_path / "candidate", tmp_path / "rebuilt"
    assert not verify_reproducible_wheels.compare(candidate, rebuilt)["passed"]
    left = wheel(candidate)
    assert not verify_reproducible_wheels.compare(candidate, rebuilt)["passed"]
    assert not verify_reproducible_wheels.compare(candidate, candidate)["passed"]
    right = wheel(rebuilt)
    wheel(candidate / "ambiguous")
    result = verify_reproducible_wheels.compare(candidate, rebuilt)
    assert "duplicate wheel" in result["errors"][0]
    (candidate / "ambiguous" / left.name).unlink()
    left.write_bytes(b"not-a-wheel")
    right.write_bytes(left.read_bytes())
    result = verify_reproducible_wheels.compare(candidate, rebuilt)
    assert not result["passed"] and result["errors"]


def test_rebuild_failure_cli_still_writes_machine_readable_evidence(tmp_path):
    report = tmp_path / "evidence" / "result.json"
    assert verify_reproducible_wheels.main([
        "--candidate", str(tmp_path / "absent-a"), "--rebuilt", str(tmp_path / "absent-b"),
        "--report", str(report), "--source-revision", "test-commit",
    ]) == 1
    result = json.loads(report.read_text())
    assert result["source_revision"] == "test-commit"
    assert not result["passed"]
    assert "VACUOUS" in result["errors"][0]


def test_live_manifest_detects_stale_or_empty_selection_and_stable_shards(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    case = tests / "test_example.py"
    case.write_text("import pytest\n@pytest.mark.live_daemon\ndef test_live(): pass\n")
    manifest = tests / "live_daemon_manifest.json"
    assert live_suite.main(["--root", str(tmp_path), "--write-manifest"]) == 0
    assert live_suite.checked_manifest(tmp_path, manifest) == ["tests/test_example.py::test_live"]
    case.write_text(case.read_text() + "\n@pytest.mark.live_daemon\ndef test_new(): pass\n")
    with pytest.raises(ValueError, match="stale"):
        live_suite.checked_manifest(tmp_path, manifest)
    nodeids = [f"tests/test_example.py::test_{i}" for i in range(100)]
    shards = [live_suite.shard(nodeids, i, 4) for i in range(4)]
    assert sorted(sum(shards, [])) == sorted(nodeids)
    assert sum(len(set(s)) for s in shards) == len(nodeids)
    for i, selected in enumerate(shards):
        assert selected == live_suite.shard([*nodeids, "another::test_case"], i, 4)[:len(selected)]
    case.write_text("def test_hermetic(): pass\n")
    with pytest.raises(SystemExit):
        live_suite.main(["--root", str(tmp_path), "--write-manifest"])


def event(plugin, nodeid, phase, outcome="passed"):
    plugin.pytest_runtest_logreport(SimpleNamespace(
        nodeid=nodeid, when=phase, outcome=outcome, duration=0.01))


def test_live_evidence_retains_first_failure_and_incomplete_parameter_cases(tmp_path):
    nodeid = "tests/test_example.py::test_live"
    plugin = live_suite.EvidencePlugin([nodeid], tmp_path / "outcomes.json")
    plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=nodeid + "[one]")]))
    for phase in ("setup", "call", "teardown"):
        event(plugin, nodeid + "[one]", phase)
    assert plugin.complete(0)
    # A retry must not overwrite earlier failures with its eventual success.
    event(plugin, nodeid + "[one]", "call", "failed")
    event(plugin, nodeid + "[one]", "call", "passed")
    assert not plugin.complete(0)
    assert len(plugin.report["cases"][nodeid + "[one]"]["call"]) == 3
    plugin.pytest_collection_finish(SimpleNamespace(items=[
        SimpleNamespace(nodeid=nodeid + "[one]"), SimpleNamespace(nodeid=nodeid + "[two]")]))
    assert not plugin.complete(0)
    assert plugin.report["collected_cases"] == 2
    assert plugin.report["completed_cases"] == 1


def test_live_acceptance_rejects_pytest_success_with_a_skipped_case(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers = live_daemon: fixture acceptance\n")
    (tests / "test_example.py").write_text(
        "import pytest\n@pytest.mark.live_daemon\ndef test_pass(): pass\n"
        "@pytest.mark.live_daemon\ndef test_skip(): pytest.skip('fixture unavailable')\n")
    assert live_suite.main(["--root", str(tmp_path), "--write-manifest"]) == 0
    report = tmp_path / "test-results" / "live-suite.json"
    report.parent.mkdir()
    sentinel = report.parent / "native-runtime.json"
    sentinel.write_text('{"source": "this-run"}')
    result = subprocess.run([
        sys.executable, str(Path(live_suite.__file__)), "--root", str(tmp_path),
        "--run", "--report", str(report),
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, result.stdout + result.stderr
    evidence = json.loads(report.read_text())
    assert evidence["pytest_exit_code"] == 0
    assert evidence["status"] == "failed"
    assert evidence["collected_cases"] == 2
    assert evidence["cases"]["tests/test_example.py::test_skip"]["call"][0]["outcome"] == "skipped"
    assert report.with_suffix(".xml").is_file()
    assert json.loads(sentinel.read_text()) == {"source": "this-run"}


@pytest.mark.skipif(os.name != "posix", reason="controlled timing entry point requires Linux")
def test_timing_attempts_retain_success_failure_and_timeout_logs(tmp_path):
    results = []
    for name, source, timeout in (
        ("ok", "print('measurement completed')", 5),
        ("failed", "raise SystemExit(7)", 5),
        ("timeout", "import time; print('began', flush=True); time.sleep(30)", 0.2),
    ):
        results.append(run_native_timing.run_target(
            [sys.executable, "-c", source], cwd=tmp_path, log=tmp_path / (name + ".log"),
            timeout=timeout, env=dict(os.environ)))
    assert [row["status"] for row in results] == ["passed", "failed", "timeout"]
    assert results[1]["exit_code"] == 7
    assert "measurement completed" in (tmp_path / "ok.log").read_text()
    assert "began" in (tmp_path / "timeout.log").read_text()


def test_native_runtime_checks_versions_binary_and_executed_abi(tmp_path, monkeypatch):
    binary = tmp_path / ("one_link_native" + importlib.machinery.EXTENSION_SUFFIXES[0])
    binary.write_bytes(b"fixture-native-binary")
    native = SimpleNamespace(__version__="0.22.1", one_link_native=SimpleNamespace(__file__=str(binary)))
    core = SimpleNamespace(__version__="0.22.1")
    kem = SimpleNamespace(runtime_is_usable=lambda: True)
    modules = {"one_link": core, "one_link_native": native, "one_link.pqkem_native": kem}
    monkeypatch.setattr(verify_native_runtime.importlib, "import_module", modules.__getitem__)
    monkeypatch.setattr(verify_native_runtime.importlib.metadata, "version", lambda name: "0.22.1")
    report = verify_native_runtime.inspect_runtime("0.22.1")
    assert report["status"] == "passed"
    assert report["native_binary"]["size_bytes"] == binary.stat().st_size
    assert len(report["native_binary"]["sha256"]) == 64
    native.__version__ = "0.21.0"
    kem.runtime_is_usable = lambda: False
    report = verify_native_runtime.inspect_runtime("0.22.1")
    assert report["status"] == "failed"
    assert any("0.21.0" in error for error in report["errors"])
    assert any("ABI self-test" in error for error in report["errors"])


def test_bootstrap_source_identity_detects_edits_to_already_dirty_inputs(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "native").mkdir()
    source = tmp_path / "native" / "implementation.rs"
    source.write_text("original")
    subprocess.run(["git", "add", "native"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    source.write_text("first edit")
    before = bootstrap_source._source_identity(tmp_path)
    source.write_text("second edit")
    after = bootstrap_source._source_identity(tmp_path)
    assert before["revision"] == after["revision"]
    assert before["tracked_worktree_dirty"] and after["tracked_worktree_dirty"]
    assert before["build_inputs_sha256"] != after["build_inputs_sha256"]
    added = tmp_path / "native" / "added.rs"
    added.write_text("new source")
    assert "native/added.rs" in bootstrap_source._source_identity(tmp_path)["build_inputs_sha256"]


def test_ruleset_proposal_preserves_existing_controls_and_requires_real_producer():
    policy = json.loads(repository_policy.POLICY.read_text())
    observed = {
        "id": 20516627, "name": policy["ruleset_name"], "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [], "rules": [
            {"type": "deletion"}, {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 2, "require_code_owner_review": True,
                "allowed_merge_methods": ["squash"], "require_last_push_approval": True}},
            {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "existing stronger gate", "integration_id": 42}]}}
        ],
    }
    before = json.dumps(observed, sort_keys=True)
    proposed = repository_policy.proposal(observed, policy)
    assert json.dumps(observed, sort_keys=True) == before
    assert proposed["conditions"] == observed["conditions"]
    assert proposed["bypass_actors"] == []
    assert "id" not in proposed
    assert not repository_policy.validate(proposed, policy)
    rules = {rule["type"]: rule["parameters"] for rule in proposed["rules"] if "parameters" in rule}
    assert rules["pull_request"]["required_approving_review_count"] == 2
    assert rules["pull_request"]["require_code_owner_review"]
    assert rules["pull_request"]["allowed_merge_methods"] == ["squash"]
    assert rules["pull_request"]["require_last_push_approval"]
    checks = rules["required_status_checks"]["required_status_checks"]
    assert {"context": "existing stronger gate", "integration_id": 42} in checks
    checks[-1]["integration_id"] = 123
    assert any("producer" in error for error in repository_policy.validate(proposed, policy))


def workflow(name):
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def test_release_signing_and_publication_require_the_actual_artifact_rebuild():
    jobs = workflow("release.yml")["jobs"]
    for name in ("sign", "publish"):
        assert "verify_reproducibility" in jobs[name]["needs"]
    steps = jobs["verify_reproducibility"]["steps"]
    download = next(step for step in steps if "download-artifact@" in step.get("uses", ""))
    assert download["with"]["name"] == "native-wheel-linux-x86_64"
    assert any("verify_reproducible_wheels.py" in step.get("run", "") for step in steps)
    upload = next(step for step in steps if "upload-artifact@" in step.get("uses", ""))
    assert upload["if"] == "always()"


def test_required_contexts_are_defined_by_unfiltered_pr_workflows():
    policy = json.loads(repository_policy.POLICY.read_text())
    available = set()
    for name in ("full_suite_and_e2e.yml", "lint.yml", "security.yml",
                 "native_build.yml", "native_bench_gate.yml"):
        document = workflow(name)
        assert "pull_request" in document["on"]
        assert document["on"]["pull_request"] in ("", None)
        available.update(job.get("name", key) for key, job in document["jobs"].items())
    assert {check["context"] for check in policy["required_status_checks"]} <= available
    jobs = workflow("full_suite_and_e2e.yml")["jobs"]
    authority = jobs["continuous_acceptance_gate"]
    assert set(authority["needs"]) == {
        "native_runtime", "full_suite", "e2e_browser", "live_daemon_gate", "native_picker_smoke"}
    assert "always()" in authority["if"]
    command = authority["steps"][0]["run"]
    assert 'test "$result" = success || exit 1' in command
    native_steps = jobs["native_runtime"]["steps"]
    assert any("python scripts/bootstrap_source.py --report" in step.get("run", "")
               for step in native_steps)
    upload = next(step for step in native_steps if "upload-artifact@" in step.get("uses", ""))
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "acceptance-native/"


def test_browser_sessions_cannot_remove_prior_browser_or_native_evidence():
    jobs = workflow("full_suite_and_e2e.yml")["jobs"]
    commands = "\n".join(step.get("run", "") for step in jobs["e2e_browser"]["steps"])
    assert "--output=test-results/playwright-chromium" in commands
    assert "--output=test-results/playwright-firefox" in commands
    assert "--junitxml=test-results/browser-chromium.xml" in commands
    assert "--junitxml=test-results/browser-firefox.xml" in commands
    for name in ("release_quality_linux", "release_quality_windows"):
        steps = workflow("release.yml")["jobs"][name]["steps"]
        assert any("scripts/live_suite.py --run" in step.get("run", "") for step in steps)
        upload = next(step for step in steps if "upload-artifact@" in step.get("uses", ""))
        assert upload["if"] == "always()"


def test_independent_supply_chain_steps_and_evidence_survive_a_prior_failure():
    steps = workflow("security.yml")["jobs"]["audit"]["steps"]
    for term in ("zizmor", "pip-audit", "bandit", "generate SBOM"):
        step = next(step for step in steps if term in step.get("name", ""))
        assert "!cancelled()" in step["if"]
        assert "steps.audit_tools.outcome == 'success'" in step["if"]
        assert "continue-on-error" not in step
    upload = next(step for step in steps if "upload-artifact@" in step.get("uses", ""))
    assert upload["if"] == "always()"


def test_controlled_timing_is_separate_from_required_correctness():
    correctness = workflow("native_build.yml")["jobs"]["rust_workspace"]
    assert not any("--include-ignored" in step.get("run", "") for step in correctness["steps"])
    timing = workflow("native_timing.yml")
    assert set(timing["on"]) == {"workflow_dispatch"}
    job = next(iter(timing["jobs"].values()))
    assert "one-link-timing" in job["runs-on"]
    assert not job.get("continue-on-error")
    assert any("--build-only" in step.get("run", "") for step in job["steps"])
    assert all(not step.get("continue-on-error") for step in job["steps"])


def test_shell_graph_is_audited_and_inventoried_without_hiding_upstream_warnings():
    for name in ("security.yml", "release.yml"):
        document = workflow(name)
        text = (ROOT / ".github/workflows" / name).read_text()
        assert "cargo audit --file native/Cargo.lock --deny warnings" in text
        assert "cargo audit --file native/fuzz/Cargo.lock --deny warnings" in text
        assert "cargo audit --file native/ol_shell/Cargo.lock --json" in text
        assert "cargo-audit-shell.json" in text
        assert "--additional-cargo shell native/ol_shell/Cargo.toml" in text
        assert "--additional-cargo fuzz native/fuzz/Cargo.toml" in text
        gates = [step for job in document["jobs"].values() for step in job.get("steps", [])
                 if step.get("run", "").strip() == "cargo audit --file native/ol_shell/Cargo.lock"]
        assert len(gates) == 1
        assert "!cancelled()" in gates[0]["if"]
        assert not gates[0].get("continue-on-error")
    release = workflow("release.yml")["jobs"]
    assert not any("libwebkit2gtk" in step.get("run", "") for step in release["native_wheels"]["steps"])
    assert any("libwebkit2gtk" in step.get("run", "") for step in release["binaries"]["steps"])


def test_full_history_secret_findings_are_redacted_and_retained_on_failure():
    steps = workflow("security.yml")["jobs"]["secrets"]["steps"]
    scan = next(step for step in steps if "./gitleaks git" in step.get("run", ""))
    assert "--redact=100" in scan["run"]
    assert "--report-format=json --report-path=gitleaks-redacted.json" in scan["run"]
    assert not scan.get("continue-on-error")
    upload = next(step for step in steps if "upload-artifact@" in step.get("uses", ""))
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "gitleaks-redacted.json"
    release = workflow("release.yml")["jobs"]["release_quality_linux"]["steps"]
    scan = next(step for step in release if "./gitleaks git" in step.get("run", ""))
    assert "--redact=100" in scan["run"]
    assert "--report-path=test-results/gitleaks-redacted.json" in scan["run"]
