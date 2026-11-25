"""Required native contexts must never mistake absent work for success."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native_ci_scope.py"
SPEC = importlib.util.spec_from_file_location("native_ci_scope", SCRIPT)
assert SPEC and SPEC.loader
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Native CI fixture")
    git(repo, "config", "user.email", "native-ci@example.invalid")
    for name in ("native/src/lib.rs", "docs/guide.md", "uv.lock"):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("baseline\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "baseline")
    return repo


def candidate(repo, kind, changes=None):
    base = git(repo, "rev-parse", "HEAD")
    for name, value in (changes or {}).items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if value is None:
            path.unlink()
        else:
            path.write_text(value)
    git(repo, "add", "--all")
    git(repo, "commit", "--allow-empty", "-m", "candidate")
    head = git(repo, "rev-parse", "HEAD")
    event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    report = scope.compute_scope(repo, kind, "pull_request", event, head)
    return event, report


def dependencies(report):
    kind = report["kind"]
    outputs = {key: report[key] for key in
               ("checkout_sha", "base_sha", "head_sha", "comparison_base_sha")}
    outputs.update({"applicable": str(report["applicable"]).lower(),
                    "proof": json.dumps(scope.compact_proof(report))})
    needs = {"applicability": {"result": "success", "outputs": outputs}}
    for job in scope.WORK_JOBS[kind]:
        success = report["applicable"] and (kind == "correctness" or
                   job == ("bench_gate" if report["event_name"] == "pull_request" else "drift_watch"))
        needs[job] = {"result": "success" if success else "skipped"}
    return needs


def decide(report, event, needs=None):
    return scope.gate_decision(report["kind"], needs or dependencies(report),
                               report["event_name"], event, report["checkout_sha"])


@pytest.mark.parametrize("kind", scope.PATHS)
@pytest.mark.parametrize("changes,applicable", [
    ({"docs/guide.md": "documentation\n"}, False),
    ({}, False),
    ({"native/src/lib.rs": "changed code\n"}, True),
    ({"native/src/lib.rs": None}, True),
    ({"native/src/lib.rs": None, "docs/moved.rs": "baseline\n"}, True),
    ({"native/src/space and\nnewline.rs": "code\n"}, True),
    ({"uv.lock": "dependencies\n"}, True),
    ({"scripts/native_ci_scope.py": "policy\n"}, True),
])
def test_complete_diff_handles_docs_code_empty_deleted_and_moved_paths(repository, kind, changes, applicable):
    event, report = candidate(repository, kind, changes)
    assert report["applicable"] is applicable
    assert report["diff_verified"] is True
    assert set(report["changed_paths"]) == set(changes)
    assert ("all applicable work succeeded" if applicable else "proves no applicable paths") in decide(report, event)


def test_scope_inspects_the_entire_diff_without_github_path_filter_limits(repository):
    changes = {f"docs/note-{index:04}.md": "doc\n" for index in range(350)}
    changes["native/src/lib.rs"] = "changed\n"
    _, report = candidate(repository, "performance", changes)
    assert report["changed_count"] == 351
    assert report["matching_paths"] == ["native/src/lib.rs"]
    assert report["applicable"]


def test_real_merge_keeps_base_head_and_tested_candidate_distinct(repository):
    git(repository, "checkout", "-b", "feature")
    _, feature = candidate(repository, "performance", {"docs/guide.md": "feature docs\n"})
    git(repository, "checkout", "main")
    _, main = candidate(repository, "performance", {"native/src/lib.rs": "base advanced\n"})
    git(repository, "merge", "--no-ff", "feature", "-m", "test merge")
    merged = git(repository, "rev-parse", "HEAD")
    event = {"pull_request": {"base": {"sha": main["head_sha"]}, "head": {"sha": feature["head_sha"]}}}
    report = scope.compute_scope(repository, "performance", "pull_request", event, merged)
    assert len({report["base_sha"], report["head_sha"], report["checkout_sha"]}) == 3
    assert report["comparison_base_sha"] == main["head_sha"]
    assert report["changed_paths"] == ["docs/guide.md"]
    assert not report["applicable"]  # The base's own change is not attributed to this PR.
    decide(report, event)


@pytest.mark.parametrize("problem", ["missing_base", "missing_head", "unknown_base", "wrong_checkout", "nonancestor_head"])
def test_scope_rejects_missing_wrong_or_unrelated_commit_identities(repository, problem):
    event, report = candidate(repository, "correctness", {"docs/guide.md": "doc\n"})
    checkout = report["checkout_sha"]
    if problem.startswith("missing_"):
        del event["pull_request"][problem.removeprefix("missing_")]
    elif problem == "unknown_base":
        event["pull_request"]["base"]["sha"] = "f" * 40
    elif problem == "wrong_checkout":
        checkout = report["base_sha"]
    else:
        git(repository, "checkout", "-b", "unrelated", report["base_sha"])
        _, other = candidate(repository, "correctness", {"docs/unrelated.md": "other\n"})
        git(repository, "checkout", "--detach", checkout)
        event["pull_request"]["head"]["sha"] = other["head_sha"]
    with pytest.raises(scope.ScopeError):
        scope.compute_scope(repository, "correctness", "pull_request", event, checkout)


@pytest.mark.parametrize("kind", scope.PATHS)
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_scope_failure_never_turns_skipped_jobs_into_a_passing_gate(repository, kind, result):
    event, report = candidate(repository, kind, {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    needs["applicability"]["result"] = result
    with pytest.raises(scope.ScopeError, match="applicability did not succeed"):
        decide(report, event, needs)


@pytest.mark.parametrize("kind,job", [("correctness", "rust_workspace"), ("correctness", "python_binding"), ("performance", "bench_gate")])
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_relevant_changes_require_every_work_job_success(repository, kind, job, result):
    event, report = candidate(repository, kind, {"native/src/lib.rs": "changed\n"})
    needs = dependencies(report)
    needs[job]["result"] = result
    with pytest.raises(scope.ScopeError, match=f"{job} result"):
        decide(report, event, needs)


@pytest.mark.parametrize("field,value", [
    ("diff_verified", False), ("diff_sha256", ""), ("matching_count", 1),
    ("changed_count", -1), ("changed_count", True), ("applicable", "false"),
    ("checkout_sha", "f" * 40), ("head_sha", "f" * 40), ("base_sha", "f" * 40),
    ("comparison_base_sha", "f" * 40), ("policy_sha256", "0" * 64), ("kind", "other"),
])
def test_not_applicable_requires_valid_identity_policy_and_diff_proof(repository, field, value):
    event, report = candidate(repository, "performance", {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    proof = scope.compact_proof(report)
    proof[field] = value
    needs["applicability"]["outputs"]["proof"] = json.dumps(proof)
    with pytest.raises(scope.ScopeError):
        decide(report, event, needs)


@pytest.mark.parametrize("field", ["proof", "applicable", "base_sha", "head_sha", "checkout_sha", "comparison_base_sha"])
def test_missing_scope_outputs_fail_closed(repository, field):
    event, report = candidate(repository, "correctness", {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    del needs["applicability"]["outputs"][field]
    with pytest.raises(scope.ScopeError):
        decide(report, event, needs)


@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
@pytest.mark.parametrize("kind", scope.PATHS)
def test_non_pr_runs_cannot_use_not_applicable_and_select_the_correct_work(repository, event_name, kind):
    head = git(repository, "rev-parse", "HEAD")
    event = {"before": "0" * 40, "after": head} if event_name == "push" else {}
    report = scope.compute_scope(repository, kind, event_name, event, head)
    assert report["applicable"] is True
    assert report["diff_verified"] is False
    decide(report, event)
    omitted_empty_outputs = dependencies(report)
    omitted_empty_outputs["applicability"]["outputs"] = {
        key: value for key, value in omitted_empty_outputs["applicability"]["outputs"].items() if value != ""
    }
    decide(report, event, omitted_empty_outputs)
    false_report = deepcopy(report)
    false_report["applicable"] = False
    with pytest.raises(scope.ScopeError, match="non-PR native work cannot be skipped"):
        decide(false_report, event)


def test_scope_cli_retains_full_evidence_and_never_emits_clean_outputs_on_error(repository, tmp_path):
    event, report = candidate(repository, "performance", {"docs/guide.md": "doc\n"})
    event_file, output_file, evidence = [tmp_path / name for name in ("event.json", "outputs", "report.json")]
    event_file.write_text(json.dumps(event))
    env = {**os.environ, "GITHUB_EVENT_PATH": str(event_file), "GITHUB_EVENT_NAME": "pull_request",
           "GITHUB_SHA": report["checkout_sha"], "GITHUB_OUTPUT": str(output_file)}
    command = [sys.executable, str(SCRIPT), "scope", "--kind", "performance", "--repo", str(repository), "--report", str(evidence)]
    completed = subprocess.run(command, env=env, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(evidence.read_text()) == report
    outputs = dict(line.split("=", 1) for line in output_file.read_text().splitlines())
    assert outputs["applicable"] == "false"
    assert "changed_paths" not in json.loads(outputs["proof"])
    output_file.unlink()
    event_file.write_text("{}")
    failed = subprocess.run(command, env=env, capture_output=True, text=True)
    assert failed.returncode != 0
    assert not output_file.exists()
    assert json.loads(evidence.read_text())["status"] == "error"


@pytest.mark.parametrize("kind,filename", [("correctness", "native_build.yml"), ("performance", "native_bench_gate.yml")])
def test_every_pr_produces_exact_gate_and_preserves_required_work_dependencies(kind, filename):
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    events = spec.get("on", spec.get(True))
    assert "pull_request" in events and not events["pull_request"]
    assert set(events["push"]["paths"]) == set(scope.PATHS[kind])
    jobs = spec["jobs"]
    applicability = jobs["applicability"]
    assert applicability["outputs"]["proof"] == "${{ steps.scope.outputs.proof }}"
    assert applicability["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert applicability["steps"][0]["with"]["fetch-depth"] == 0
    assert any(step.get("id") == "scope" and f"scope --kind {kind}" in step["run"] for step in applicability["steps"])
    for name in scope.WORK_JOBS[kind]:
        job = jobs[name]
        assert "applicability" in job["needs"]
        assert "needs.applicability.outputs.applicable == 'true'" in job["if"]
        assert job["steps"][0]["with"]["ref"] == "${{ needs.applicability.outputs.checkout_sha }}"
    gate = jobs["aggregate"]
    assert gate["name"] == f"native {kind} gate"
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == {"applicability", *scope.WORK_JOBS[kind]}
    assert gate["steps"][-1]["env"]["NATIVE_CI_NEEDS"] == "${{ toJSON(needs) }}"
    assert gate["steps"][-1]["run"] == f"python scripts/native_ci_scope.py gate --kind {kind}"
    assert all(not job.get("continue-on-error") and all(not step.get("continue-on-error")
               for step in job["steps"]) for job in jobs.values())
    if kind == "correctness":
        assert "rust_workspace" in jobs["python_binding"]["needs"]
    else:
        assert "github.event_name == 'pull_request'" in jobs["bench_gate"]["if"]
        assert "github.event_name != 'pull_request'" in jobs["drift_watch"]["if"]
        commands = "\n".join(step.get("run", "") for step in jobs["bench_gate"]["steps"])
        assert 'test "$comparison_base" = "$COMPARISON_BASE"' in commands
