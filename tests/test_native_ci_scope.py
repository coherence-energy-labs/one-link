"""Required native contexts must never mistake absent work for success."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import subprocess
import sys
import tomllib
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/native_ci_scope.py"
SPEC = importlib.util.spec_from_file_location("native_ci_scope", SCRIPT)
assert SPEC and SPEC.loader
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)
# The bytes Git stores for this policy (a Windows checkout may convert to CRLF).
POLICY_BYTES = SCRIPT.read_bytes().replace(b"\r\n", b"\n")
WORKFLOW_FILES = {kind: ROOT / path for kind, path in scope.WORKFLOWS.items()}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def write(repo, name, value):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))


def init_repo(path, files):
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Native CI fixture")
    git(path, "config", "user.email", "native-ci@example.invalid")
    git(path, "config", "core.autocrlf", "false")
    git(path, "config", "commit.gpgsign", "false")
    for name, value in files.items():
        write(path, name, value)
    git(path, "add", "--all")
    git(path, "commit", "-q", "-m", "baseline")
    return path


BASELINE = {
    "native/ol_shell/src/lib.rs": "baseline\n",
    "docs/guide.md": "baseline\n",
    "uv.lock": "baseline\n",
    scope.POLICY_PATH: POLICY_BYTES,
}


@pytest.fixture
def repository(tmp_path):
    return init_repo(tmp_path / "source", BASELINE)


def commit_changes(repo, changes):
    for name, value in (changes or {}).items():
        if value is None:
            (repo / name).unlink()
        else:
            write(repo, name, value)
    git(repo, "add", "--all")
    git(repo, "commit", "-q", "--allow-empty", "-m", "candidate")
    return git(repo, "rev-parse", "HEAD")


def candidate(repo, kind, changes=None):
    base = git(repo, "rev-parse", "HEAD")
    head = commit_changes(repo, changes)
    event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    report = scope.compute_scope(repo, kind, "pull_request", event, head)
    return event, report


def dependencies(report, extra=()):
    kind = report["kind"]
    outputs = {key: report[key] for key in
               ("checkout_sha", "base_sha", "head_sha", "comparison_base_sha")}
    outputs.update({"applicable": str(report["applicable"]).lower(),
                    "proof": json.dumps(scope.compact_proof(report))})
    needs = {"applicability": {"result": "success", "outputs": outputs}}
    for job in (*scope.WORK_JOBS[kind], *extra):
        success = report["applicable"] and (kind != "performance" or job in extra or
                   job == ("bench_gate" if report["event_name"] == "pull_request" else "drift_watch"))
        needs[job] = {"result": "success" if success else "skipped"}
    return needs


def decide(repo, report, event, needs=None):
    return scope.gate_decision(report["kind"], needs or dependencies(report),
                               report["event_name"], event, report["checkout_sha"], repo=repo)


# --- representation: everything is applicable unless a reviewed rule proves it inert ---

@pytest.mark.parametrize("pattern,path,expected", [
    ("docs/**", "docs/guide.md", True),
    ("docs/**", "docs/a/b/c.md", True),
    ("docs/**", "docs", False),
    ("docs/**", "native/docs/x.md", False),
    ("bench_*.json", "bench_cold_full.json", True),
    ("bench_*.json", "native/bench_cold_full.json", False),
    ("AUDIT_*.md", "AUDIT_2026/x.md", False),
    ("**/Cargo.toml", "Cargo.toml", True),
    ("**/Cargo.toml", "native/ol_chunk/Cargo.toml", True),
    ("**/.cargo/**", ".cargo/config.toml", True),
    ("**/.cargo/**", "native/.cargo/config", True),
    ("**/.cargo/**", "native/.cargoish/config", False),
    ("native/ol_shell/**", "native/ol_shell_extra/x.rs", False),
])
def test_segment_glob_never_lets_a_star_cross_a_directory(pattern, path, expected):
    assert scope.glob_match(path, pattern) is expected


@pytest.mark.parametrize("kind", scope.INERT)
def test_canary_any_new_unlisted_path_is_applicable(kind):
    # A path no reviewer has ever classified must run the work.
    for path in (f"{uuid.uuid4().hex}/{uuid.uuid4().hex}.bin", uuid.uuid4().hex,
                 f"native/{uuid.uuid4().hex}.toml", f"native/ol_{uuid.uuid4().hex}/src/lib.rs",
                 f".github/{uuid.uuid4().hex}.yml", f"docs.{uuid.uuid4().hex}",
                 f"src/one_link/{uuid.uuid4().hex}.py", f"scripts/{uuid.uuid4().hex}.py"):
        assert scope.inert_rule(kind, path) is None, path


def test_every_native_directory_the_shell_skips_exists_and_is_not_its_own():
    present = {path.name for path in (ROOT / "native").iterdir() if path.is_dir()}
    listed = set(scope._SHELL_INERT_NATIVE_DIRS)
    assert listed <= present, sorted(listed - present)
    assert not listed & {"ol_shell", "vendor", "patches", ".cargo"}


EXECUTION_INPUTS = (
    ".cargo/config.toml", ".cargo/config", "native/.cargo/config.toml", "native/ol_shell/.cargo/config.toml",
    "rust-toolchain.toml", "rust-toolchain", "native/rust-toolchain.toml", ".gitattributes",
    "pytest.ini", "tox.ini", "setup.cfg", "conftest.py", "pyproject.toml", "uv.lock", "setup.py",
    "MANIFEST.in", "LICENSE", "NOTICE", "README.md", "src/one_link/__init__.py",
    "src/one_link/web/index.html", "src/one_link/data/certified/origin_fence.json",
    ".github/actions/toolchain/action.yml", "native/Cargo.toml", "native/Cargo.lock",
    "native/fuzz/Cargo.toml", "native/vendor/ml-kem-0.2.3/src/algebra.rs",
    "native/patches/ml-kem-0.2.3.json", "native/ol_shell/patches/glib-0.18.5.json",
    "scripts/native_ci_scope.py", "scripts/run_ct_audit.py", "scripts/bench_scan_memory.py",
    "scripts/verify_vendor_patches.py",
)
PYTHON_TEST_INPUTS = ("tests/conftest.py", "tests/__init__.py", "tests/unit/conftest.py",
                      "tests/harness.py", "tests/test_chunk_native_v0210.py")


@pytest.mark.parametrize("kind", scope.INERT)
def test_every_input_a_native_job_reads_is_applicable(kind):
    inputs = (*EXECUTION_INPUTS, scope.WORKFLOWS[kind])
    if kind != "shell":
        inputs += PYTHON_TEST_INPUTS + ("native/ol_chunk/src/lib.rs", "native/ol_ct_audit/src/main.rs")
    else:
        inputs += ("native/ol_shell/src/main.rs", "native/ol_shell/build.rs", "frontend/owner/main/app.js")
    for path in inputs:
        assert scope.inert_rule(kind, path) is None, path


@pytest.mark.parametrize("kind,path", [
    *((kind, path) for kind in scope.INERT for path in (
        "docs/guide.md", "docs/decisions/0001-cdc-kernel.md", "CHANGELOG.md", "AUDIT_2026-05-21.md",
        "audit_extracts_may21/agent-1.md", "bench_cold_full.json", ".github/workflows/tests.yml",
        ".github/dependabot.yml")),
    ("correctness", "frontend/owner/main/app.js"), ("performance", "frontend/peer/x.js"),
    ("shell", "tests/test_foldersync.py"), ("shell", "native/ol_chunk/src/lib.rs"),
    ("shell", "native/fuzz/fuzz_targets/fuzz_crdt_merge.rs"),
])
def test_reviewed_inert_rules_do_skip_their_paths(kind, path):
    # The positive control: without it an always-applicable policy would also pass.
    assert scope.inert_rule(kind, path) is not None


def test_policy_refuses_malformed_patterns_and_rules_that_cover_forced_paths(monkeypatch):
    for bad in ("docs//x", "/docs/**", "docs/**x", "../docs/**", ""):
        with pytest.raises(scope.ScopeError, match="malformed"):
            scope._validate_pattern(bad)
    for rule in (scope.InertRule("scripts/**", "covers the policy"),
                 scope.InertRule(".github/**", "covers the workflow")):
        monkeypatch.setitem(scope.INERT, "correctness", (*scope.INERT["correctness"], rule))
        with pytest.raises(scope.ScopeError, match="would cover"):
            scope._validate_policy()


# --- complete-diff classification ---

@pytest.mark.parametrize("kind", scope.INERT)
@pytest.mark.parametrize("changes,applicable", [
    ({"docs/guide.md": "documentation\n"}, False),
    ({}, False),
    ({"native/ol_shell/src/lib.rs": "changed code\n"}, True),
    ({"native/ol_shell/src/lib.rs": None}, True),
    ({"native/ol_shell/src/lib.rs": None, "docs/moved.rs": "baseline\n"}, True),
    ({"native/ol_shell/src/space and newline.rs": "code\n"}, True),
    ({"uv.lock": "dependencies\n"}, True),
    ({".cargo/config.toml": "[target.'cfg(all())']\nrunner = ['true']\n"}, True),
    ({"rust-toolchain.toml": "[toolchain]\nchannel = '1.80.0'\n"}, True),
    ({".gitattributes": "native/** text eol=crlf\n"}, True),
    ({"pytest.ini": "[pytest]\naddopts = --collect-only\n"}, True),
    ({f"{uuid.uuid4().hex}/new.cfg": "unknown\n"}, True),
    ({scope.POLICY_PATH: POLICY_BYTES + b"# edited\n"}, True),
])
def test_complete_diff_handles_docs_code_empty_deleted_and_moved_paths(repository, kind, changes, applicable):
    event, report = candidate(repository, kind, changes)
    assert report["applicable"] is applicable
    assert report["diff_verified"] is True
    assert set(report["changed_paths"]) == set(changes)
    assert set(report["applicable_paths"]) | {item["path"] for item in report["inert_paths"]} == set(changes)
    assert report["policy_source"] == "base" and report["policy_revision"] == report["base_sha"]
    assert ("all applicable work succeeded" if applicable else "proves no applicable paths") in decide(
        repository, report, event)


@pytest.mark.parametrize("kind", ["correctness", "performance"])
def test_root_conftest_and_test_helpers_reach_the_python_binding_job(repository, kind):
    _, report = candidate(repository, kind, {"tests/conftest.py": "import pytest\n"})
    assert report["applicable"] and report["applicable_paths"] == ["tests/conftest.py"]


@pytest.mark.parametrize("kind", scope.INERT)
def test_nul_diff_preserves_newline_paths_without_host_filename_restrictions(repository, kind, monkeypatch):
    event, candidate_report = candidate(repository, kind, {"docs/guide.md": "doc\n"})
    # Git can report paths created on another platform that Windows cannot
    # materialize. Exercise that raw diff contract without creating such a
    # filename; commit identity and ancestry checks still use the real repo.
    path = "native/ol_shell/src/space and\nnewline.rs"
    raw_diff = b"docs/guide.md\0" + path.encode("utf-8") + b"\0"
    real_git = scope._git

    def diff_with_newline(repo, *args):
        if args[0] == "diff":
            assert "-z" in args and "--no-renames" in args
            return raw_diff
        return real_git(repo, *args)

    monkeypatch.setattr(scope, "_git", diff_with_newline)
    report = scope.compute_scope(repository, kind, "pull_request", event, candidate_report["checkout_sha"])
    assert report["changed_paths"] == ["docs/guide.md", path]
    assert report["applicable_paths"] == [path]
    assert report["changed_count"] == 2 and report["applicable_count"] == 1
    assert report["diff_sha256"] == hashlib.sha256(raw_diff).hexdigest()
    assert report["applicable"] is True
    assert "all applicable work succeeded" in decide(repository, report, event)


def test_scope_inspects_the_entire_diff_without_github_path_filter_limits(repository):
    changes = {f"docs/note-{index:04}.md": "doc\n" for index in range(350)}
    changes["native/ol_shell/src/lib.rs"] = "changed\n"
    _, report = candidate(repository, "performance", changes)
    assert report["changed_count"] == 351
    assert report["applicable_paths"] == ["native/ol_shell/src/lib.rs"]
    assert report["applicable"]


@pytest.mark.parametrize("path", [
    "native/ol_shell/Cargo.lock", "native/ol_shell/Cargo.toml", "native/ol_shell/src/main.rs",
    "native/ol_shell/build.rs", "native/ol_shell/vendor/glib-0.18.5/src/variant_iter.rs",
    "native/ol_shell/patches/glib-0.18.5.json", "native/ol_shell/regression/glib_variant_backport/src/lib.rs",
    "src/one_link/web/index.html", "src/one_link/web/assets/one-glyph.ico",
    "src/one_link/data/certified/origin_fence.json",
    "frontend/owner/main/transfer_facts.js", "scripts/build_owner_ui.py",
    "scripts/build_native_shell.py", "scripts/build_binary.py", "scripts/smoke_native_shell.py",
    "scripts/verify_vendor_patches.py", "scripts/audit_vendor_advisories.py",
    ".gitattributes", ".cargo/config.toml", "native/.cargo/config.toml",
    "rust-toolchain.toml", "native/rust-toolchain.toml", ".github/actions/toolchain/action.yml",
    "pyproject.toml", "uv.lock", ".github/workflows/native_shell.yml",
    "native/Cargo.toml", "native/Cargo.lock", "native/fuzz/Cargo.toml", "native/fuzz/Cargo.lock",
    "native/vendor/ml-kem-0.2.3/src/algebra.rs", "native/patches/ml-kem-0.2.3-ct-cbd.patch",
])
def test_shell_scope_includes_build_ui_vendor_and_shared_execution_inputs(repository, path):
    event, report = candidate(repository, "shell", {path: "changed input\n"})
    assert report["applicable"] and report["applicable_paths"] == [path]
    assert "all applicable work succeeded" in decide(repository, report, event)


def test_shell_gate_requires_the_complete_declared_needs_object(repository):
    event, report = candidate(repository, "shell", {"native/ol_shell/Cargo.lock": "lock\n"})
    valid = dependencies(report)
    assert set(valid) == {"applicability", "build"}
    for altered in ({key: value for key, value in valid.items() if key != "build"},
                    {**valid, "undeclared_shell_job": {"result": "success"}}):
        with pytest.raises(scope.ScopeError, match="dependency"):
            decide(repository, report, event, altered)


def test_real_merge_keeps_base_head_and_tested_candidate_distinct(repository):
    git(repository, "checkout", "-q", "-b", "feature")
    _, feature = candidate(repository, "performance", {"docs/guide.md": "feature docs\n"})
    git(repository, "checkout", "-q", "main")
    _, main = candidate(repository, "performance", {"native/ol_shell/src/lib.rs": "base advanced\n"})
    git(repository, "merge", "-q", "--no-ff", "feature", "-m", "test merge")
    merged = git(repository, "rev-parse", "HEAD")
    event = {"pull_request": {"base": {"sha": main["head_sha"]}, "head": {"sha": feature["head_sha"]}}}
    report = scope.compute_scope(repository, "performance", "pull_request", event, merged)
    assert len({report["base_sha"], report["head_sha"], report["checkout_sha"]}) == 3
    assert report["comparison_base_sha"] == main["head_sha"]
    assert report["changed_paths"] == ["docs/guide.md"]
    assert not report["applicable"]  # The base's own change is not attributed to this PR.
    decide(repository, report, event)


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
        git(repository, "checkout", "-q", "-b", "unrelated", report["base_sha"])
        _, other = candidate(repository, "correctness", {"docs/unrelated.md": "other\n"})
        git(repository, "checkout", "-q", "--detach", checkout)
        event["pull_request"]["head"]["sha"] = other["head_sha"]
    with pytest.raises(scope.ScopeError):
        scope.compute_scope(repository, "correctness", "pull_request", event, checkout)


# --- trust: the base revision's policy judges a pull request ---

SELF_EXEMPTING = POLICY_BYTES.replace(
    b"def inert_rule(kind: str, path: str) -> InertRule | None:",
    b"def inert_rule(kind: str, path: str) -> InertRule | None:\n"
    b"    return InertRule('**', 'self-exempting edit')\n\n\n"
    b"def _unused_inert_rule(kind: str, path: str) -> InertRule | None:", 1)


@pytest.mark.parametrize("kind", scope.INERT)
def test_a_pr_that_rewrites_the_policy_to_skip_everything_is_still_applicable(repository, kind):
    assert SELF_EXEMPTING != POLICY_BYTES
    event, report = candidate(repository, kind, {
        scope.POLICY_PATH: SELF_EXEMPTING, "native/ol_shell/src/lib.rs": "unreviewed\n"})
    assert report["policy_source"] == "base" and report["policy_revision"] == report["base_sha"]
    assert report["policy_changed"] is True and report["applicable"] is True
    assert scope.POLICY_PATH in report["applicable_paths"]
    needs = dependencies(report)
    for job in scope.WORK_JOBS[kind]:
        skipped = deepcopy(needs)
        skipped[job]["result"] = "skipped"
        if needs[job]["result"] == "success":
            with pytest.raises(scope.ScopeError, match=f"{job} result"):
                decide(repository, report, event, skipped)


def test_the_policy_names_only_the_trusted_revision_and_its_exact_bytes(repository):
    event, report = candidate(repository, "correctness", {"docs/guide.md": "doc\n"})
    base, head = report["base_sha"], report["checkout_sha"]
    identity = scope.resolve_policy(repository, "pull_request", event, head, base, POLICY_BYTES)
    assert identity == {"policy_revision": base, "policy_source": "base",
                        "policy_script_sha256": hashlib.sha256(POLICY_BYTES).hexdigest()}
    with pytest.raises(scope.ScopeError, match="not the trusted base policy revision"):
        scope.resolve_policy(repository, "pull_request", event, head, head, POLICY_BYTES)
    with pytest.raises(scope.ScopeError, match="not byte-identical"):
        scope.resolve_policy(repository, "pull_request", event, head, base, SELF_EXEMPTING)
    with pytest.raises(scope.ScopeError, match="commit SHA"):
        scope.resolve_policy(repository, "pull_request", event, head, "master", POLICY_BYTES)


def test_bootstrap_runs_the_candidate_policy_only_when_the_base_predates_it(tmp_path):
    repo = init_repo(tmp_path / "bootstrap", {key: value for key, value in BASELINE.items()
                                              if key != scope.POLICY_PATH})
    base = git(repo, "rev-parse", "HEAD")
    head = commit_changes(repo, {scope.POLICY_PATH: POLICY_BYTES, "docs/guide.md": "doc\n"})
    event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    assert scope.trusted_policy_revision(repo, "pull_request", event, head) == (head, "bootstrap")
    identity = scope.resolve_policy(repo, "pull_request", event, head, head, POLICY_BYTES)
    for kind in scope.INERT:
        report = scope.compute_scope(repo, kind, "pull_request", event, head, identity)
        assert report["policy_source"] == "bootstrap" and report["policy_changed"] is True
        assert report["applicable"] is True
        assert "all applicable work succeeded" in decide(repo, report, event)
        forged = dependencies(report)
        proof = json.loads(forged["applicability"]["outputs"]["proof"])
        proof["policy_changed"] = False
        forged["applicability"]["outputs"]["proof"] = json.dumps(proof)
        with pytest.raises(scope.ScopeError, match="bootstrap"):
            decide(repo, report, event, forged)


@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
def test_non_pr_runs_use_the_tested_checkouts_own_policy(repository, event_name):
    head = git(repository, "rev-parse", "HEAD")
    event = {"before": "0" * 40, "after": head} if event_name == "push" else {}
    assert scope.trusted_policy_revision(repository, event_name, event, head) == (head, "checkout")


def test_a_policy_change_may_add_a_job_that_succeeds_but_never_remove_one(repository):
    event, report = candidate(repository, "correctness", {scope.POLICY_PATH: POLICY_BYTES + b"# v3\n"})
    assert report["policy_changed"] is True
    added = dependencies(report, extra=("new_audit",))
    assert "policy transition adds new_audit" in decide(repository, report, event, added)
    for result in ("skipped", "failure", "cancelled", None):
        failing = deepcopy(added)
        failing["new_audit"]["result"] = result
        with pytest.raises(scope.ScopeError, match="new_audit result"):
            decide(repository, report, event, failing)
    removed = {key: value for key, value in dependencies(report).items() if key != "ct_audit"}
    with pytest.raises(scope.ScopeError, match="missing a required dependency: ct_audit"):
        decide(repository, report, event, removed)
    git(repository, "reset", "-q", "--hard", report["base_sha"])
    event, ordinary = candidate(repository, "correctness", {"native/ol_shell/src/lib.rs": "code\n"})
    with pytest.raises(scope.ScopeError, match="unknown dependency: new_audit"):
        decide(repository, ordinary, event, dependencies(ordinary, extra=("new_audit",)))


# --- gate: absent work is never success ---

@pytest.mark.parametrize("kind", scope.INERT)
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_scope_failure_never_turns_skipped_jobs_into_a_passing_gate(repository, kind, result):
    event, report = candidate(repository, kind, {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    needs["applicability"]["result"] = result
    with pytest.raises(scope.ScopeError, match="applicability did not succeed"):
        decide(repository, report, event, needs)


@pytest.mark.parametrize("kind,job", [
    ("correctness", "rust_workspace"), ("correctness", "python_binding"), ("correctness", "ct_audit"),
    ("correctness", "scan_memory"), ("performance", "bench_gate"), ("shell", "build")])
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_relevant_changes_require_every_work_job_success(repository, kind, job, result):
    event, report = candidate(repository, kind, {"native/ol_shell/src/lib.rs": "changed\n"})
    needs = dependencies(report)
    needs[job]["result"] = result
    with pytest.raises(scope.ScopeError, match=f"{job} result"):
        decide(repository, report, event, needs)


@pytest.mark.parametrize("field,value", [
    ("diff_verified", False), ("diff_sha256", ""), ("applicable_count", 1),
    ("changed_count", -1), ("changed_count", True), ("applicable", "false"),
    ("checkout_sha", "f" * 40), ("head_sha", "f" * 40), ("base_sha", "f" * 40),
    ("comparison_base_sha", "f" * 40), ("policy_sha256", "0" * 64), ("kind", "other"),
    ("policy_revision", "f" * 40), ("policy_source", "checkout"), ("policy_source", "bootstrap"),
    ("policy_script_sha256", "0" * 64), ("policy_changed", "false"), ("policy_changed", True),
    ("schema", "one-link-native-ci-scope/v1"),
])
def test_not_applicable_requires_valid_identity_policy_and_diff_proof(repository, field, value):
    event, report = candidate(repository, "performance", {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    proof = scope.compact_proof(report)
    proof[field] = value
    needs["applicability"]["outputs"]["proof"] = json.dumps(proof)
    with pytest.raises(scope.ScopeError):
        decide(repository, report, event, needs)


@pytest.mark.parametrize("field", ["proof", "applicable", "base_sha", "head_sha", "checkout_sha", "comparison_base_sha"])
def test_missing_scope_outputs_fail_closed(repository, field):
    event, report = candidate(repository, "correctness", {"docs/guide.md": "doc\n"})
    needs = dependencies(report)
    del needs["applicability"]["outputs"][field]
    with pytest.raises(scope.ScopeError):
        decide(repository, report, event, needs)


@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
@pytest.mark.parametrize("kind", scope.INERT)
def test_non_pr_runs_cannot_use_not_applicable_and_select_the_correct_work(repository, event_name, kind):
    head = git(repository, "rev-parse", "HEAD")
    event = {"before": "0" * 40, "after": head} if event_name == "push" else {}
    report = scope.compute_scope(repository, kind, event_name, event, head)
    assert report["applicable"] is True
    assert report["diff_verified"] is False
    assert report["policy_source"] == "checkout"
    decide(repository, report, event)
    omitted_empty_outputs = dependencies(report)
    omitted_empty_outputs["applicability"]["outputs"] = {
        key: value for key, value in omitted_empty_outputs["applicability"]["outputs"].items() if value != ""
    }
    decide(repository, report, event, omitted_empty_outputs)
    false_report = deepcopy(report)
    false_report["applicable"] = False
    with pytest.raises(scope.ScopeError, match="non-PR native work cannot be skipped"):
        decide(repository, false_report, event)


# --- the CLI exactly as the workflows run it ---

def run_policy(policy, command, kind, repo, env, *extra):
    return subprocess.run(
        [sys.executable, str(policy), command, "--kind", kind, "--repo", str(repo), *extra],
        env=env, capture_output=True, text=True)


def test_cli_runs_only_the_extracted_base_policy_and_records_its_identity(repository, tmp_path):
    event, report = candidate(repository, "performance", {"docs/guide.md": "doc\n"})
    base, head = report["base_sha"], report["checkout_sha"]
    policy = tmp_path / "native-ci-policy.py"
    policy.write_bytes(subprocess.check_output(["git", "-C", str(repository), "show", f"{base}:{scope.POLICY_PATH}"]))
    event_file, output_file, evidence = [tmp_path / name for name in ("event.json", "outputs", "report.json")]
    event_file.write_text(json.dumps(event))
    env = {**os.environ, "GITHUB_EVENT_PATH": str(event_file), "GITHUB_EVENT_NAME": "pull_request",
           "GITHUB_SHA": head, "GITHUB_OUTPUT": str(output_file)}
    env.pop("GITHUB_STEP_SUMMARY", None)
    completed = run_policy(policy, "scope", "performance", repository, env,
                           "--policy-revision", base, "--report", str(evidence))
    assert completed.returncode == 0, completed.stderr
    recorded = json.loads(evidence.read_text())
    assert recorded == report
    assert recorded["policy_script_sha256"] == hashlib.sha256(policy.read_bytes()).hexdigest()
    outputs = dict(line.split("=", 1) for line in output_file.read_text().splitlines())
    assert outputs["applicable"] == "false"
    assert "changed_paths" not in json.loads(outputs["proof"])
    gate_env = {**env, "NATIVE_CI_NEEDS": json.dumps({
        "applicability": {"result": "success", "outputs": outputs},
        "bench_gate": {"result": "skipped"}, "drift_watch": {"result": "skipped"}})}
    gated = run_policy(policy, "gate", "performance", repository, gate_env, "--policy-revision", base)
    assert gated.returncode == 0, gated.stderr
    assert f"policy base {base}" in gated.stdout

    # The candidate's revision, a modified copy and a malformed event never yield clean outputs.
    tampered = tmp_path / "tampered-policy.py"
    tampered.write_bytes(policy.read_bytes() + b"# tampered\n")
    for runner, revision in ((policy, head), (tampered, base)):
        output_file.unlink(missing_ok=True)
        failed = run_policy(runner, "scope", "performance", repository, env,
                            "--policy-revision", revision, "--report", str(evidence))
        assert failed.returncode != 0
        assert not output_file.exists()
        assert json.loads(evidence.read_text())["status"] == "error"
        assert run_policy(runner, "gate", "performance", repository, gate_env,
                          "--policy-revision", revision).returncode != 0
    event_file.write_text("{}")
    failed = run_policy(policy, "scope", "performance", repository, env,
                        "--policy-revision", base, "--report", str(evidence))
    assert failed.returncode != 0
    assert not output_file.exists()
    assert json.loads(evidence.read_text())["status"] == "error"


# --- workflow wiring ---

def _workflow(kind):
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(WORKFLOW_FILES[kind].read_text(encoding="utf-8"))


def _loader(run, command, kind):
    lines = run.rstrip("\n").splitlines()
    tail = lines[-1]
    expected = f'python "$policy" {command} --kind {kind} --policy-revision "$policy_rev"'
    assert tail.startswith(expected), tail
    return "\n".join(lines[:-1])


@pytest.mark.parametrize("kind", scope.INERT)
def test_every_pr_produces_exact_gate_and_preserves_required_work_dependencies(kind):
    spec = _workflow(kind)
    events = spec.get("on", spec.get(True))
    assert "pull_request" in events and not events["pull_request"]
    # No GitHub path filter: it cannot express "applicable unless proven inert".
    assert events["push"] == {"branches": ["master"]}
    jobs = spec["jobs"]
    applicability = jobs["applicability"]
    assert applicability["outputs"]["proof"] == "${{ steps.scope.outputs.proof }}"
    assert applicability["steps"][0]["with"]["ref"] == "${{ github.sha }}"
    assert applicability["steps"][0]["with"]["fetch-depth"] == 0
    step = next(step for step in applicability["steps"] if step.get("id") == "scope")
    assert step["env"]["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert step["run"].rstrip().endswith("--report native-scope.json")
    for name in scope.WORK_JOBS[kind]:
        job = jobs[name]
        assert "applicability" in job["needs"]
        assert "needs.applicability.outputs.applicable == 'true'" in job["if"]
        assert job["steps"][0]["with"]["ref"] == "${{ needs.applicability.outputs.checkout_sha }}"
        assert job["steps"][0]["with"]["persist-credentials"] is False
    gate = jobs["aggregate"]
    assert gate["name"] == f"native {kind} gate"
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == {"applicability", *scope.WORK_JOBS[kind]}
    assert set(jobs) == {"applicability", "aggregate", *scope.WORK_JOBS[kind]}
    assert gate["steps"][0]["with"]["fetch-depth"] == 0
    assert gate["steps"][-1]["env"]["NATIVE_CI_NEEDS"] == "${{ toJSON(needs) }}"
    assert gate["steps"][-1]["env"]["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert _loader(gate["steps"][-1]["run"], "gate", kind) == _loader(step["run"], "scope", kind)
    assert all(not job.get("continue-on-error") and all(not step.get("continue-on-error")
               for step in job["steps"]) for job in jobs.values())
    if kind == "correctness":
        assert "rust_workspace" in jobs["python_binding"]["needs"]
        audit = jobs["ct_audit"]
        assert audit["name"] == "constant-time dataflow audit (valgrind)"
        assert audit["needs"] == "applicability" and audit["runs-on"] == "ubuntu-latest"
        assert audit["timeout-minutes"] == 30
        runs = "\n".join(item.get("run", "") for item in audit["steps"])
        assert "rustup toolchain install 1.96.0" in runs and "rustup default 1.96.0" in runs
        assert "sudo apt-get install -y valgrind libc6-dbg" in runs and "valgrind --version" in runs
        build = next(item for item in audit["steps"] if "cargo build" in item.get("run", ""))
        assert build["working-directory"] == "native"
        assert build["run"] == "cargo build --locked --profile ct-audit -p ol_ct_audit"
        assert "uv sync --frozen --python python --only-group ct-audit" in runs
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        parser_dependencies = pyproject["dependency-groups"]["ct-audit"]
        assert parser_dependencies == ["defusedxml>=0.7.1,<0.8"]
        assert parser_dependencies[0] in pyproject["project"]["optional-dependencies"]["dev"]
        assert ("uv run --frozen --only-group ct-audit python scripts/run_ct_audit.py "
                "--binary native/target/ct-audit/ol_ct_audit "
                "--source-root native --report test-results/ct-audit/report.json") in runs
        upload = audit["steps"][-1]
        assert upload["if"] == "always()" and "upload-artifact@" in upload["uses"]
        assert upload["with"]["path"] == "test-results/ct-audit/"
        memory = jobs["scan_memory"]
        assert memory["name"] == "scan memory qualification (${{ matrix.os }})"
        assert memory["needs"] == "applicability"
        assert memory["strategy"] == {"fail-fast": False,
                                      "matrix": {"os": ["ubuntu-latest", "windows-latest", "macos-latest"]}}
        assert memory["defaults"]["run"]["shell"] == "bash"
        binding = jobs["python_binding"]["steps"]
        regression = next(item for item in binding if "pytest tests/test_chunk_native_v0210.py" in item.get("run", ""))
        assert "if" not in regression
        # The module's optional import must not turn a broken required build
        # into a skipped descriptor suite. Import it explicitly before pytest.
        assert regression["run"].splitlines()[0] == (
            'uv run --frozen --extra dev --extra release python -c "import one_link_native.chunk"'
        )
        assert "tests/test_native_fd_scan.py" in shlex.split(regression["run"], comments=True)
        for name in ("Install maturin + project deps", "Build + install one_link_native (editable)"):
            mine = next(item for item in memory["steps"] if item.get("name") == name)
            theirs = next(item for item in binding if item.get("name") == name)
            assert mine["run"] == theirs["run"], name
        measure = next(item for item in memory["steps"] if "bench_scan_memory.py" in item.get("run", ""))
        assert measure["timeout-minutes"] == 30 and "if" not in measure
        assert "--sizes-mib 256,1024 --repeats 2" in measure["run"]
        assert '--workdir "$SCAN_WORKDIR" --report "$SCAN_REPORT"' in measure["run"]
        assert measure["env"] == {"SCAN_WORKDIR": "${{ runner.temp }}/scanmem",
                                  "SCAN_REPORT": "test-results/scan-memory/${{ matrix.os }}.json"}
        upload = memory["steps"][-1]
        assert upload["if"] == "always()" and upload["with"]["path"] == "test-results/scan-memory/"
    elif kind == "performance":
        assert "github.event_name == 'pull_request'" in jobs["bench_gate"]["if"]
        assert "github.event_name != 'pull_request'" in jobs["drift_watch"]["if"]
        commands = "\n".join(step.get("run", "") for step in jobs["bench_gate"]["steps"])
        assert 'test "$comparison_base" = "$COMPARISON_BASE"' in commands
    else:
        assert kind == "shell"
        build = jobs["build"]
        assert build["strategy"]["matrix"] == {"os": ["windows-latest", "ubuntu-latest", "macos-latest"]}
        assert build["strategy"]["fail-fast"] is False
        steps = build["steps"]
        required = [
            "verify the pinned owner page matches its canonical sources",
            "verify reviewed vendor source and upstream patch",
            "build the window", "the UI pin is baked into the binary",
            "the window OPENS and LOADS the real interface",
        ]
        for name in required:
            step = next(item for item in steps if item.get("name") == name)
            assert "if" not in step
        regression = next(item for item in steps if item.get("name") == "optimized GLib Variant iterator regression tests")
        assert regression["if"] == "runner.os == 'Linux'"
        assert "--locked --release" in regression["run"]
        assert "-p ol_shell_glib_regression" in regression["run"]
        assert any("--page owner --check" in item.get("run", "") for item in steps)
        assert any("--fetch-upstream" in item.get("run", "") for item in steps)
        assert any(item.get("if") == "always()" and "upload-artifact@" in item.get("uses", "") for item in steps)


def test_one_identical_base_policy_loader_serves_every_scope_and_gate():
    loaders = set()
    for kind in scope.INERT:
        spec = _workflow(kind)
        scope_step = next(step for step in spec["jobs"]["applicability"]["steps"] if step.get("id") == "scope")
        loaders.add(_loader(scope_step["run"], "scope", kind))
        loaders.add(_loader(spec["jobs"]["aggregate"]["steps"][-1]["run"], "gate", kind))
    assert len(loaders) == 1
    loader = loaders.pop()
    assert "set -euo pipefail" in loader
    assert 'policy_rev="$GITHUB_SHA"' in loader
    assert ('listing="$(git ls-tree --full-tree --name-only "$PR_BASE_SHA" -- scripts/native_ci_scope.py)"'
            in loader)
    assert 'policy_rev="$PR_BASE_SHA"' in loader
    assert 'git show "$policy_rev:scripts/native_ci_scope.py" > "$policy"' in loader


@pytest.mark.parametrize("kind", scope.INERT)
def test_no_workflow_step_executes_the_policy_from_the_pr_tree(kind):
    text = WORKFLOW_FILES[kind].read_text(encoding="utf-8")
    assert "python scripts/native_ci_scope.py" not in text
    assert "scripts/native_ci_scope.py gate" not in text and "scripts/native_ci_scope.py scope" not in text
    # Another workflow file is inert only because this one calls nothing local.
    spec = _workflow(kind)
    for job in spec["jobs"].values():
        assert not str(job.get("uses", "")).startswith("./")
        for step in job.get("steps", []):
            assert not str(step.get("uses", "")).startswith("./")


# --- proofs behind the inert rules ---

_RUST_READS = (
    (re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)'), "file"),
    (re.compile(r'#\[path\s*=\s*"([^"]+)"\]'), "file"),
    (re.compile(r'env!\("CARGO_MANIFEST_DIR"\)\s*,\s*"([^"]+)"'), "crate"),
    (re.compile(r'env!\("CARGO_MANIFEST_DIR"\)\s*\)\s*\.join\(\s*"([^"]+)"\s*\)'), "crate"),
)


def _tracked(*patterns):
    pathspecs = [f":(glob){pattern}" for pattern in patterns]
    raw = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
                                   "--exclude-standard", "--", *pathspecs])
    return sorted({item for item in raw.decode("utf-8").split("\0") if item and (ROOT / item).is_file()})


def _crate_dir(relative):
    directory = posixpath.dirname(relative)
    while directory and not (ROOT / directory / "Cargo.toml").is_file():
        directory = posixpath.dirname(directory)
    return directory


def _compile_time_reads(prefix):
    reads = []
    for relative in _tracked(f"{prefix}/**/*.rs"):
        if "/vendor/" in relative or "/target/" in relative:
            continue
        text = (ROOT / relative).read_text(encoding="utf-8", errors="replace")
        for pattern, base in _RUST_READS:
            for match in pattern.finditer(text):
                origin = posixpath.dirname(relative) if base == "file" else _crate_dir(relative)
                target = posixpath.normpath(posixpath.join(origin, match.group(1).lstrip("/")))
                reads.append((relative, target))
    assert reads, f"the compile-time read extractor found nothing under {prefix}; it is blind"
    return reads


def test_native_sources_never_read_a_path_an_inert_rule_skips():
    for source, target in _compile_time_reads("native"):
        for kind in ("correctness", "performance"):
            assert scope.inert_rule(kind, target) is None, (source, target, kind)


def test_the_shell_reads_native_only_inside_its_own_workspace():
    reads = _compile_time_reads("native/ol_shell")
    assert ("native/ol_shell/build.rs", "src/one_link/web/index.html") in reads
    for source, target in reads:
        assert not target.startswith("native/") or target.startswith("native/ol_shell/"), (source, target)
        assert scope.inert_rule("shell", target) is None, (source, target)
    for manifest in _tracked("native/ol_shell/**/Cargo.toml", "native/ol_shell/Cargo.toml"):
        if "/vendor/" in manifest:
            continue
        document = tomllib.loads((ROOT / manifest).read_text(encoding="utf-8"))
        origin = posixpath.dirname(manifest)
        paths = [value["path"] for table in ("dependencies", "dev-dependencies", "build-dependencies")
                 for value in document.get(table, {}).values() if isinstance(value, dict) and "path" in value]
        for target in document.get("target", {}).values():
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                paths += [value["path"] for value in target.get(table, {}).values()
                          if isinstance(value, dict) and "path" in value]
        for source in document.get("patch", {}).values():
            paths += [value["path"] for value in source.values() if isinstance(value, dict) and "path" in value]
        paths += list(document.get("workspace", {}).get("members", []))
        for path in paths:
            resolved = posixpath.normpath(posixpath.join(origin, path))
            assert resolved.startswith("native/ol_shell/") or resolved == "native/ol_shell", (manifest, path)


def test_every_vendored_source_and_provenance_record_reaches_the_shell_job():
    from scripts import verify_vendor_patches as vendor

    manifests, configs = vendor.discover_cargo_inputs(ROOT)
    assert "native/ol_shell/Cargo.toml" in manifests and "native/Cargo.toml" in manifests
    for path in (*manifests, *configs):
        assert scope.inert_rule("shell", path) is None, path
    declared = 0
    for manifest in manifests:
        document = tomllib.loads((ROOT / manifest).read_text(encoding="utf-8"))
        origin = posixpath.dirname(manifest)
        records = {**document.get("package", {}).get("metadata", {}).get("one-link", {}).get("vendored-patches", {}),
                   **document.get("workspace", {}).get("metadata", {}).get("one-link", {}).get("vendored-patches", {})}
        for name, record in records.items():
            declared += 1
            source = document["patch"]["crates-io"][name]["path"]
            record_path = posixpath.normpath(posixpath.join(origin, record))
            owner = posixpath.dirname(posixpath.dirname(record_path))  # <workspace>/patches/<record>
            proof = json.loads((ROOT / record_path).read_text(encoding="utf-8"))
            for path in (record_path, posixpath.join(owner, proof["backport"]["patch_path"]),
                         posixpath.join(origin, source, "src/lib.rs")):
                assert scope.inert_rule("shell", posixpath.normpath(path)) is None, path
    assert declared >= 3  # glib (shell), ml-kem (native and fuzz)


def test_desired_shell_context_is_producer_bound_and_documented():
    policy = json.loads((ROOT / ".github/repository-policy.json").read_text(encoding="utf-8"))
    checks = policy["required_status_checks"]
    assert {"context": "native shell gate", "integration_id": 15368} in checks
    assert len({check["context"] for check in checks}) == len(checks) == 10
    documentation = (ROOT / "docs/REPOSITORY_POLICY.md").read_text(encoding="utf-8")
    assert "`native shell gate`" in documentation
    assert "must itself be observed on the exact intended candidate" in documentation


def test_release_protection_states_the_remaining_workflow_edit_exposure():
    text = (ROOT / "docs/RELEASE_PROTECTION.md").read_text(encoding="utf-8")
    assert "BASE revision" in text and "workflow YAML" in text
    assert "required workflows" in text and "refs/tags/v*" in text
