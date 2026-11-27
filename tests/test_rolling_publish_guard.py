"""Negative controls for the rolling release qualification boundary."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "rolling_publish_guard", Path(__file__).resolve().parents[1] / "scripts" / "rolling_publish_guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
REPO = "example/one-link"
SHA = "a" * 40
ENV = {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/master",
       "GITHUB_EVENT_NAME": "workflow_dispatch",
       "GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/publish_rolling.yml@refs/heads/master"}


def master(_):
    return {"ref": "refs/heads/master", "object": {"type": "commit", "sha": SHA}}


def test_exact_master():
    assert guard.master_identity(REPO, SHA, ENV, master) == SHA
    assert guard.master_identity(REPO, "", ENV, master) == SHA


@pytest.mark.parametrize("key,value", [
    ("GITHUB_REF", "refs/heads/audit"),
    ("GITHUB_SHA", "b" * 40),
    ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_WORKFLOW_REF", REPO + "/.github/workflows/publish_rolling.yml@refs/heads/audit"),
])
def test_wrong_dispatch_ref(key, value):
    with pytest.raises(ValueError):
        guard.master_identity(REPO, "", {**ENV, key: value}, master)


def test_requested_old_or_untrusted_commit():
    with pytest.raises(ValueError):
        guard.master_identity(REPO, "b" * 40, ENV, master)


def response(endpoint, **overrides):
    workflow = endpoint.split("/actions/workflows/")[1].split("/")[0]
    row = {"id": list(guard.WORKFLOWS).index(workflow) + 1,
           "run_number": 2, "run_attempt": 1,
           "name": guard.WORKFLOWS[workflow], "path": ".github/workflows/" + workflow,
           "head_sha": SHA, "head_branch": "master", "event": "push",
           "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
           "status": "completed", "conclusion": "success"}
    return {"workflow_runs": [{**row, "run_number": 1}, {**row, **overrides}]}


def test_gate_selects_exact_latest_build():
    assert guard.select_build(REPO, SHA, response) == len(guard.WORKFLOWS)


@pytest.mark.parametrize("changes", [
    {"head_sha": "b" * 40}, {"head_branch": "audit"}, {"event": "pull_request"},
    {"repository": {"full_name": "other/repo"}},
    {"head_repository": {"full_name": "other/repo"}},
    {"path": ".github/workflows/untrusted.yml"}, {"status": "in_progress"},
    {"conclusion": "failure"}, {"conclusion": "cancelled"}, {"id": True},
])
def test_gate_rejects_wrong_or_failed_latest_run(changes):
    with pytest.raises(ValueError):
        guard.select_build(REPO, SHA, lambda path: response(path, **changes))


def test_gate_rejects_missing_run():
    with pytest.raises(ValueError):
        guard.select_build(REPO, SHA, lambda _: {"workflow_runs": []})


@pytest.fixture
def assets(tmp_path):
    rows = []
    for name in sorted(guard.BINARIES):
        data = name.encode("ascii")
        (tmp_path / name).write_bytes(data)
        row = f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        rows.append(row)
        if name + ".sha256" in guard.SIDECARS:
            (tmp_path / (name + ".sha256")).write_text(row, encoding="ascii")
    (tmp_path / "manifest.txt").write_text("".join(rows), encoding="ascii")
    return tmp_path


def test_full_set(assets):
    assert set(guard.verify_assets(assets)) == guard.ASSETS


@pytest.mark.parametrize("defect", ["missing", "extra", "tamper", "sidecar", "duplicate", "traversal"])
def test_rejects_bad_artifact_sets(assets, defect):
    binary = assets / "one-link-macos-arm64.zip"
    manifest = assets / "manifest.txt"
    if defect == "missing":
        binary.unlink()
    elif defect == "extra":
        (assets / "untrusted.zip").write_bytes(b"unexpected")
    elif defect == "tamper":
        binary.write_bytes(b"corrupted")
    elif defect == "sidecar":
        (assets / (binary.name + ".sha256")).write_text("0" * 64 + "  " + binary.name + "\n")
    elif defect == "duplicate":
        text = manifest.read_text()
        manifest.write_text(text + text.splitlines()[0] + "\n")
    else:
        manifest.write_text("0" * 64 + "  ../outside\n")
    with pytest.raises(ValueError):
        guard.verify_assets(assets)


def release_response(assets):
    return {"tag_name": "auto-latest", "prerelease": True, "draft": False,
            "assets": [{"name": name, "size": (assets / name).stat().st_size,
                        "state": "uploaded",
                        "digest": "sha256:" + hashlib.sha256((assets / name).read_bytes()).hexdigest()}
                       for name in sorted(guard.ASSETS)]}


def test_public_release_matches_every_asset(assets):
    guard.verify_published(REPO, assets, lambda _: release_response(assets))


@pytest.mark.parametrize("defect", ["missing", "extra", "hash", "state", "size", "stable", "draft"])
def test_public_release_must_match(assets, defect):
    release = release_response(assets)
    if defect == "missing":
        release["assets"].pop()
    elif defect == "extra":
        release["assets"].append(release["assets"][0])
    elif defect == "hash":
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
    elif defect == "state":
        release["assets"][0]["state"] = "starter"
    elif defect == "size":
        release["assets"][0]["size"] += 1
    elif defect == "stable":
        release["prerelease"] = False
    else:
        release["draft"] = True
    with pytest.raises(ValueError):
        guard.verify_published(REPO, assets, lambda _: release)
