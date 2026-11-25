#!/usr/bin/env python3
"""Prove native CI applicability and reject incomplete required job results.

Only a successfully inspected pull-request diff can skip native work. Pushes
and manual runs execute it. The scope report retains event base/head, the exact
tested checkout, every changed path, and the policy used for the decision.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


PATHS: dict[str, tuple[str, ...]] = {
    "correctness": (
        "native/**",
        "src/one_link/web/assets/argon2id-v1.wasm",
        "src/one_link/web/assets/argon2id-worker.js",
        "src/one_link/web/assets/ed25519-v1.wasm",
        "scripts/verify_browser_argon2_wasm.py",
        "scripts/verify_browser_ed25519_wasm.py",
        "tests/test_browser_argon2_identity.py",
        "tests/test_browser_ed25519_identity.py",
        "src/one_link/chunk_native.py",
        "src/one_link/aead_native.py",
        "src/one_link/wal_native.py",
        "src/one_link/chunk_store_native.py",
        "src/one_link/quic_native.py",
        "src/one_link/perf_lab_native.py",
        "src/one_link/capability_native.py",
        "src/one_link/crdt_native.py",
        "src/one_link/hwkey_native.py",
        "tests/test_chunk_native_*.py",
        "tests/test_aead_native_*.py",
        "tests/test_wal_native_*.py",
        "tests/test_chunk_store_native_*.py",
        "tests/test_quic_native_*.py",
        "tests/unit/test_phase_c3_native_smoke.py",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/native_build.yml",
        "scripts/native_ci_scope.py",
        "tests/test_native_ci_scope.py",
    ),
    "performance": (
        "native/**",
        "src/one_link/*native.py",
        "src/one_link/native_cdc.py",
        "src/one_link/cdc.py",
        "src/one_link/benchmark_contract.py",
        "src/one_link/perf_lab*.py",
        "scripts/bench*.py",
        "tests/test_bench*.py",
        "tests/test_perf*.py",
        "bench_baselines/**",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/native_bench_gate.yml",
        "scripts/native_ci_scope.py",
        "tests/test_native_ci_scope.py",
    ),
    "shell": (
        "native/ol_shell/**",
        "src/one_link/web/**",
        "frontend/owner/**",
        "scripts/build_owner_ui.py",
        "scripts/build_native_shell.py",
        "scripts/build_binary.py",
        "scripts/smoke_native_shell.py",
        "scripts/verify_vendor_patches.py",
        "scripts/audit_vendor_advisories.py",
        "tests/test_vendor_patches.py",
        "tests/test_vendor_advisories.py",
        "tests/test_owner_ui_build.py",
        "tests/test_delivery_evidence.py",
        "pyproject.toml",
        "uv.lock",
        ".gitattributes",
        ".cargo/**",
        "native/.cargo/**",
        "rust-toolchain*",
        "native/rust-toolchain*",
        ".github/actions/**",
        ".github/workflows/native_shell.yml",
        "scripts/native_ci_scope.py",
        "tests/test_native_ci_scope.py",
    ),
}
WORK_JOBS = {
    "correctness": ("rust_workspace", "python_binding"),
    "performance": ("bench_gate", "drift_watch"),
    "shell": ("build",),
}
SCHEMA = "one-link-native-ci-scope/v1"


class ScopeError(ValueError):
    """The source diff or required work cannot be verified."""


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ScopeError(f"{label} must be an exact 40-character commit SHA")
    return value


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False,
    )
    if result.returncode:
        raise ScopeError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def _policy_hash(kind: str) -> str:
    return hashlib.sha256(json.dumps(PATHS[kind], separators=(",", ":")).encode()).hexdigest()


def _event_ids(event_name: str, event: dict[str, Any], checkout_sha: str) -> tuple[str, str]:
    if event_name == "pull_request":
        try:
            pr = event["pull_request"]
            return _sha(pr["base"]["sha"], "PR base"), _sha(pr["head"]["sha"], "PR head")
        except (KeyError, TypeError) as exc:
            raise ScopeError("pull_request event is missing base/head identities") from exc
    if event_name == "push":
        if _sha(event.get("after"), "push after") != checkout_sha:
            raise ScopeError("push after does not match the tested checkout")
        return _sha(event.get("before"), "push before"), checkout_sha
    if event_name == "workflow_dispatch":
        return "", checkout_sha
    raise ScopeError(f"unsupported event: {event_name!r}")


def compute_scope(
    repo: Path, kind: str, event_name: str, event: dict[str, Any], checkout_sha: str,
) -> dict[str, Any]:
    """Return a complete report, or raise without producing a clean decision."""
    checkout_sha = _sha(checkout_sha, "GITHUB_SHA")
    actual = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if actual != checkout_sha:
        raise ScopeError("checked-out HEAD does not match GITHUB_SHA")
    base_sha, head_sha = _event_ids(event_name, event, checkout_sha)
    report: dict[str, Any] = {
        "schema": SCHEMA, "status": "ok", "kind": kind, "event_name": event_name,
        "base_sha": base_sha, "head_sha": head_sha, "checkout_sha": checkout_sha,
        "comparison_base_sha": "", "policy_sha256": _policy_hash(kind),
        "patterns": list(PATHS[kind]), "applicable": True, "diff_verified": False,
        "changed_paths": [], "matching_paths": [], "changed_count": 0,
        "matching_count": 0, "diff_sha256": "", "reason": "non-PR run requires native work",
    }
    if event_name != "pull_request":
        return report

    # GitHub checks out the PR merge candidate. Both event identities must
    # actually belong to that candidate; a missing/fetched-wrong commit fails.
    for label, sha in (("base", base_sha), ("head", head_sha)):
        resolved = _git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}").decode().strip()
        if resolved != sha:
            raise ScopeError(f"PR {label} commit did not resolve exactly")
        _git(repo, "merge-base", "--is-ancestor", sha, checkout_sha)
    comparison_base = _git(repo, "merge-base", checkout_sha, base_sha).decode().strip()
    if comparison_base != base_sha:
        raise ScopeError("comparison merge base does not match the PR base identity")
    raw = _git(
        repo, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames",
        "--ignore-submodules=none", "-z", comparison_base, checkout_sha, "--",
    )
    if raw and not raw.endswith(b"\0"):
        raise ScopeError("git diff did not return complete NUL-terminated paths")
    try:
        changed = sorted(set(raw[:-1].decode("utf-8").split("\0"))) if raw else []
    except UnicodeDecodeError as exc:
        raise ScopeError("changed paths cannot be decoded losslessly") from exc
    if any(not path for path in changed):
        raise ScopeError("git diff returned an empty path")
    # No rename detection: moving a native file out of scope still exposes its
    # removed old path. NUL separation preserves spaces/newlines without caps.
    matching = [path for path in changed
                if any(fnmatch.fnmatchcase(path, pattern) for pattern in PATHS[kind])]
    report.update({
        "comparison_base_sha": comparison_base, "applicable": bool(matching),
        "diff_verified": True, "changed_paths": changed, "matching_paths": matching,
        "changed_count": len(changed), "matching_count": len(matching),
        "diff_sha256": hashlib.sha256(raw).hexdigest(),
        "reason": "matching source changes" if matching else "verified diff has no applicable paths",
    })
    return report


def compact_proof(report: dict[str, Any]) -> dict[str, Any]:
    """Keep unbounded path lists in the artifact, not size-limited job outputs."""
    return {key: value for key, value in report.items()
            if key not in {"patterns", "changed_paths", "matching_paths"}}


def gate_decision(
    kind: str, needs: dict[str, Any], event_name: str, event: dict[str, Any], checkout_sha: str,
) -> str:
    """Accept only proven irrelevance or every applicable job's success."""
    checkout_sha = _sha(checkout_sha, "GITHUB_SHA")
    if set(needs) != {"applicability", *WORK_JOBS[kind]}:
        raise ScopeError("aggregate is missing a required dependency or has an unknown dependency")
    scope = needs["applicability"]
    if scope.get("result") != "success":
        raise ScopeError("source applicability did not succeed")
    outputs = scope.get("outputs", {})
    try:
        proof = json.loads(outputs["proof"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ScopeError("source applicability proof is missing or invalid") from exc
    if not isinstance(proof, dict):
        raise ScopeError("source applicability proof is not an object")
    expected_base, expected_head = _event_ids(event_name, event, checkout_sha)
    expected = {
        "schema": SCHEMA, "status": "ok", "kind": kind, "event_name": event_name,
        "base_sha": expected_base, "head_sha": expected_head, "checkout_sha": checkout_sha,
        "policy_sha256": _policy_hash(kind),
    }
    if any(proof.get(key) != value for key, value in expected.items()):
        raise ScopeError("source applicability identity or policy does not match this run")
    if type(proof.get("applicable")) is not bool:
        raise ScopeError("source applicability did not provide an explicit boolean decision")
    for key in ("checkout_sha", "base_sha", "head_sha", "comparison_base_sha"):
        # Actions omits empty job outputs (manual runs have no comparison
        # base). Missing required nonempty identities still fail this check.
        if outputs.get(key, "") != proof.get(key):
            raise ScopeError(f"source applicability {key} outputs disagree")
    applicable = proof["applicable"]
    if outputs.get("applicable") != str(applicable).lower():
        raise ScopeError("source applicability decision outputs disagree")
    if event_name == "pull_request":
        if proof.get("diff_verified") is not True or proof.get("comparison_base_sha") != expected_base:
            raise ScopeError("pull-request diff was not verified against its base")
        digest = proof.get("diff_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ScopeError("pull-request diff fingerprint is missing")
        changed, matching = proof.get("changed_count"), proof.get("matching_count")
        if type(changed) is not int or type(matching) is not int or not 0 <= matching <= changed:
            raise ScopeError("pull-request path counts are invalid")
        if applicable != (matching > 0):
            raise ScopeError("applicability contradicts the matching path count")
    elif not applicable or proof.get("diff_verified") is not False:
        raise ScopeError("non-PR native work cannot be skipped")

    expected_results = dict.fromkeys(WORK_JOBS[kind], "skipped")
    if applicable:
        if kind != "performance":
            expected_results = dict.fromkeys(WORK_JOBS[kind], "success")
        else:
            selected = "bench_gate" if event_name == "pull_request" else "drift_watch"
            expected_results[selected] = "success"
    for job, result in expected_results.items():
        observed = needs[job].get("result")
        if observed != result:
            raise ScopeError(f"{job} result is {observed!r}; required {result!r}")
    if applicable:
        return f"native {kind} gate: all applicable work succeeded at {checkout_sha}"
    return (f"native {kind} gate: verified diff proves no applicable paths "
            f"({proof['changed_count']} changed; base {expected_base}; head {expected_head}; "
            f"tested {checkout_sha})")


def _append_summary(message: str) -> None:
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(message + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scope", "gate"))
    parser.add_argument("--kind", choices=tuple(PATHS), required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("native-scope.json"))
    args = parser.parse_args(argv)
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise ScopeError("event payload must be an object")
        event_name, checkout_sha = os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_SHA"]
        if args.command == "gate":
            needs = json.loads(os.environ["NATIVE_CI_NEEDS"])
            if not isinstance(needs, dict):
                raise ScopeError("aggregate dependencies must be an object")
            message = gate_decision(args.kind, needs, event_name, event, checkout_sha)
        else:
            report = compute_scope(args.repo, args.kind, event_name, event, checkout_sha)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            if path := os.environ.get("GITHUB_OUTPUT"):
                with Path(path).open("a", encoding="utf-8") as stream:
                    for key in ("applicable", "checkout_sha", "base_sha", "head_sha", "comparison_base_sha"):
                        value = report[key]
                        stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
                    stream.write("proof=" + json.dumps(compact_proof(report), separators=(",", ":")) + "\n")
            message = (f"native {args.kind} applicability: {report['reason']}; "
                       f"base {report['base_sha']}; head {report['head_sha']}; tested {checkout_sha}")
        print(message)
        _append_summary(message)
        return 0
    except (ScopeError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        message = f"native {args.kind} {args.command} failed: {exc}"
        if args.command == "scope":
            args.report.write_text(json.dumps({
                "schema": SCHEMA, "status": "error", "kind": args.kind, "error": str(exc),
            }, indent=2) + "\n", encoding="utf-8")
        print(message, file=sys.stderr)
        _append_summary(message)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
