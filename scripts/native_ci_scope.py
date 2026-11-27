#!/usr/bin/env python3
"""Prove native CI applicability and reject incomplete required job results.

Representation. A changed path is APPLICABLE unless it matches a reviewed
inert rule for that gate kind. Each rule names paths that no job of that kind
reads, with the reason. Unknown and new paths are applicable by default, so a
forgotten input runs the work instead of silently skipping it.

Only a successfully inspected pull-request diff can skip native work. Pushes
and manual runs always execute it. The scope report keeps the event base/head,
the exact tested checkout, every changed path with its classification, and the
identity of the policy that decided.

Trust. A pull request is judged by this file as it exists at the PR's BASE
revision. The workflow extracts that revision's copy with ``git show`` and runs
it. The running bytes are verified against the named revision, and their hash
is recorded in the proof. A PR may edit this file, but the edit takes effect
only after review and merge. A PR that changes this file is always applicable.
If the base predates the policy (bootstrap), the candidate's copy runs instead.
It can skip nothing, because its own file is part of the diff. Pushes and
manual runs use the tested checkout's copy, which is the same revision as the
workflow file that started the run. A PR can still edit the workflow YAML; see
docs/RELEASE_PROTECTION.md.
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
from typing import Any, NamedTuple


POLICY_PATH = "scripts/native_ci_scope.py"
SCHEMA = "one-link-native-ci-scope/v2"
WORKFLOWS = {
    "correctness": ".github/workflows/native_build.yml",
    "performance": ".github/workflows/native_bench_gate.yml",
    "shell": ".github/workflows/native_shell.yml",
}
WORK_JOBS = {
    "correctness": ("rust_workspace", "python_binding", "ct_audit", "scan_memory"),
    "performance": ("bench_gate", "drift_watch"),
    "shell": ("build",),
}
POLICY_SOURCES = ("base", "bootstrap", "checkout")


class InertRule(NamedTuple):
    """Paths that provably do not reach one gate kind's jobs.

    ``pattern`` and ``unless`` use path-segment globs: ``*``, ``?`` and
    ``[...]`` match within one segment; a ``**`` segment matches any number of
    segments, and at least one when it ends the pattern. A path matching any
    ``unless`` pattern stays applicable.
    """

    pattern: str
    reason: str
    unless: tuple[str, ...] = ()


_PROSE: tuple[InertRule, ...] = (
    InertRule("docs/**", "Prose, ADRs and the static site. Native sources cite docs/ only in "
              "comments; no native job, script or test it runs opens a docs/ path."),
    InertRule("AUDIT_*.md", "Root audit prose. MANIFEST.in excludes it from the sdist; it is "
              "not package metadata and no native job reads it."),
    InertRule("CHANGELOG.md", "Release prose excluded from the sdist; read by no native job."),
    InertRule("CONTRIBUTING.md", "Contributor prose excluded from the sdist; read by no native job."),
    InertRule("ROADMAP.md", "Planning prose excluded from the sdist; read by no native job."),
    InertRule("SECURITY.md", "Disclosure policy prose; read by no native job."),
    InertRule("TESTING.md", "Testing prose; read by no native job."),
    InertRule("audit_extracts_may21/**", "Archived audit extracts, read only by the offline "
              "scripts/extract_audit_2026_05_21_findings.py."),
    InertRule("bench_*.json", "Archived root-level measurement outputs written by offline "
              "benchmark scripts. The bench gate measures fresh runs against bench_baselines/."),
    InertRule("_proof_fountain_k1024.json", "Archived output of the offline fountain stress script."),
    InertRule(".github/dependabot.yml", "Dependabot update schedule; no job reads it."),
    InertRule(".github/repository-policy.json", "Desired repository settings for "
              "scripts/repository_policy.py; no native job reads it."),
)


def _other_workflows(kind: str) -> InertRule:
    return InertRule(
        ".github/workflows/**",
        "Another workflow file cannot change this workflow's jobs. The kind's own workflow "
        "stays applicable and makes no local reusable-workflow or action call (tested).",
        unless=(WORKFLOWS[kind],),
    )


_UI_SOURCES = InertRule(
    "frontend/**",
    "Owner/peer UI sources. scripts/build_owner_ui.py compiles them into the committed "
    "src/one_link/web bundle; no correctness or performance job runs it or reads frontend/. "
    "The shell gate checks the bundle against them.",
)

# Existing native directories that the shell job provably does not build or
# read. A new crate or a new file directly under native/ is not listed and
# therefore runs the shell gate until a reviewer adds it here.
_SHELL_INERT_NATIVE_DIRS = (
    "fuzz", "ol_aead", "ol_align", "ol_argon2_wasm", "ol_bandit", "ol_bloom", "ol_canon",
    "ol_capability", "ol_chunk", "ol_chunk_store", "ol_codegen", "ol_coherence_field",
    "ol_compress", "ol_confidential", "ol_crdt", "ol_ct_audit", "ol_decide", "ol_device_mesh",
    "ol_discovery", "ol_duress", "ol_ed25519_wasm", "ol_erasure", "ol_fec", "ol_fountain",
    "ol_fskit", "ol_fuse", "ol_grammar", "ol_homology", "ol_hwkey", "ol_netcode", "ol_onion",
    "ol_pair_qr", "ol_pqkem", "ol_pqsig", "ol_prefetch", "ol_proximity_pair", "ol_quic",
    "ol_radio_batcher", "ol_ratchet", "ol_routing", "ol_selector", "ol_threshold_recovery",
    "ol_transfer", "ol_wal", "ol_winfs", "one_link_native", "test_support",
)
# Inside those directories these files still reach the shell job: the
# repository-wide vendor verification step reads every manifest, lockfile,
# Cargo configuration, vendored source and provenance record.
_SHELL_NATIVE_INPUTS = (
    "**/Cargo.toml", "**/Cargo.lock", "**/.cargo/**", "**/rust-toolchain",
    "**/rust-toolchain.toml", "**/vendor/**", "**/patches/**",
)


def _shell_native(directory: str) -> InertRule:
    return InertRule(
        f"native/{directory}/**",
        "native/ol_shell is its own Cargo workspace; every path dependency, member and patch of "
        "it lies inside native/ol_shell, and its sources read native/ only inside it (tested). "
        "So this crate's sources cannot reach the shell build.",
        unless=_SHELL_NATIVE_INPUTS,
    )


INERT: dict[str, tuple[InertRule, ...]] = {
    "correctness": (*_PROSE, _other_workflows("correctness"), _UI_SOURCES),
    "performance": (*_PROSE, _other_workflows("performance"), _UI_SOURCES),
    "shell": (
        *_PROSE,
        _other_workflows("shell"),
        InertRule("tests/**", "The shell job runs no Python test suite, and none of the scripts it "
                  "runs (build_owner_ui, verify_vendor_patches, smoke_native_shell) reads tests/."),
        *(_shell_native(directory) for directory in _SHELL_INERT_NATIVE_DIRS),
    ),
}


class ScopeError(ValueError):
    """The source diff, the policy identity or the required work cannot be verified."""


def _validate_pattern(pattern: str) -> None:
    parts = pattern.split("/")
    if (not pattern or any(not part or part in {".", ".."} for part in parts)
            or any("**" in part and part != "**" for part in parts)):
        raise ScopeError(f"malformed policy pattern: {pattern!r}")


def glob_match(path: str, pattern: str) -> bool:
    """Match a Git path against a path-segment glob (see InertRule)."""
    return _match(tuple(path.split("/")), tuple(pattern.split("/")))


def _match(parts: tuple[str, ...], pats: tuple[str, ...]) -> bool:
    if not pats:
        return not parts
    head, rest = pats[0], pats[1:]
    if head == "**":
        first = 1 if not rest else 0
        return any(_match(parts[index:], rest) for index in range(first, len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _match(parts[1:], rest)


def inert_rule(kind: str, path: str) -> InertRule | None:
    """Return the reviewed rule that proves ``path`` inert for ``kind``, if any."""
    if path == POLICY_PATH or path == WORKFLOWS[kind]:
        return None
    for rule in INERT[kind]:
        if glob_match(path, rule.pattern) and not any(glob_match(path, item) for item in rule.unless):
            return rule
    return None


def _validate_policy() -> None:
    if set(INERT) != set(WORK_JOBS) or set(WORKFLOWS) != set(WORK_JOBS):
        raise ScopeError("policy kinds disagree")
    if {"ol_shell", "vendor", "patches", ".cargo"} & set(_SHELL_INERT_NATIVE_DIRS):
        raise ScopeError("the shell's own workspace and the vendored sources can never be inert for it")
    for kind, rules in INERT.items():
        for rule in rules:
            for pattern in (rule.pattern, *rule.unless):
                _validate_pattern(pattern)
            # The policy and the kind's own workflow are forced applicable in
            # inert_rule(); a rule that would cover them is a policy error.
            for forced in (POLICY_PATH, WORKFLOWS[kind]):
                if glob_match(forced, rule.pattern) and not any(glob_match(forced, item) for item in rule.unless):
                    raise ScopeError(f"inert rule {rule.pattern!r} would cover {forced} for {kind}")


_validate_policy()


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


def _commit(repo: Path, sha: str, label: str) -> None:
    resolved = _git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}").decode().strip()
    if resolved != sha:
        raise ScopeError(f"{label} commit did not resolve exactly")


def _policy_hash(kind: str) -> str:
    rules = [[rule.pattern, list(rule.unless)] for rule in INERT[kind]]
    material = {"policy_path": POLICY_PATH, "workflow": WORKFLOWS[kind],
                "inert": rules, "work_jobs": list(WORK_JOBS[kind])}
    return hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()


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


def trusted_policy_revision(
    repo: Path, event_name: str, event: dict[str, Any], checkout_sha: str,
) -> tuple[str, str]:
    """Return (revision, source) of the only policy allowed to judge this run."""
    checkout_sha = _sha(checkout_sha, "GITHUB_SHA")
    base_sha, _ = _event_ids(event_name, event, checkout_sha)
    if event_name != "pull_request":
        return checkout_sha, "checkout"
    _commit(repo, base_sha, "PR base")
    listing = _git(repo, "ls-tree", "-z", "--full-tree", "--name-only", base_sha, "--", POLICY_PATH)
    if listing == POLICY_PATH.encode() + b"\0":
        return base_sha, "base"
    if listing:
        raise ScopeError("PR base policy listing is ambiguous")
    return checkout_sha, "bootstrap"


def resolve_policy(
    repo: Path, event_name: str, event: dict[str, Any], checkout_sha: str,
    declared_revision: Any, running_bytes: bytes | None,
) -> dict[str, str]:
    """Verify that the running policy is exactly the trusted revision's file.

    ``running_bytes`` is the running script. The CLI always passes its own
    bytes. A library caller may pass None, which identifies the trusted policy
    without asserting what is executing.
    """
    revision, source = trusted_policy_revision(repo, event_name, event, checkout_sha)
    if declared_revision is not None and _sha(declared_revision, "policy revision") != revision:
        raise ScopeError(f"policy revision {declared_revision} is not the trusted {source} "
                         f"policy revision {revision}")
    blob = _git(repo, "cat-file", "blob", f"{revision}:{POLICY_PATH}")
    if running_bytes is not None and running_bytes != blob:
        raise ScopeError(f"the running policy is not byte-identical to {POLICY_PATH} at {revision}")
    return {"policy_revision": revision, "policy_source": source,
            "policy_script_sha256": hashlib.sha256(blob).hexdigest()}


def compute_scope(
    repo: Path, kind: str, event_name: str, event: dict[str, Any], checkout_sha: str,
    policy: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a complete report, or raise without producing a clean decision."""
    checkout_sha = _sha(checkout_sha, "GITHUB_SHA")
    actual = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if actual != checkout_sha:
        raise ScopeError("checked-out HEAD does not match GITHUB_SHA")
    base_sha, head_sha = _event_ids(event_name, event, checkout_sha)
    if policy is None:
        policy = resolve_policy(repo, event_name, event, checkout_sha, None, None)
    report: dict[str, Any] = {
        "schema": SCHEMA, "status": "ok", "kind": kind, "event_name": event_name,
        "base_sha": base_sha, "head_sha": head_sha, "checkout_sha": checkout_sha,
        "comparison_base_sha": "", "policy_sha256": _policy_hash(kind), **policy,
        "policy_changed": False,
        "inert_rules": [{"pattern": rule.pattern, "unless": list(rule.unless), "reason": rule.reason}
                        for rule in INERT[kind]],
        "applicable": True, "diff_verified": False,
        "changed_paths": [], "applicable_paths": [], "inert_paths": [], "changed_count": 0,
        "applicable_count": 0, "diff_sha256": "", "reason": "non-PR run requires native work",
    }
    if event_name != "pull_request":
        if policy["policy_source"] != "checkout":
            raise ScopeError("a non-PR run must use the tested checkout's policy")
        return report

    # GitHub checks out the PR merge candidate. Both event identities must
    # actually belong to that candidate; a missing/fetched-wrong commit fails.
    for label, sha in (("base", base_sha), ("head", head_sha)):
        _commit(repo, sha, f"PR {label}")
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
    applicable_paths, inert_paths = [], []
    for path in changed:
        rule = inert_rule(kind, path)
        if rule is None:
            applicable_paths.append(path)
        else:
            inert_paths.append({"path": path, "rule": rule.pattern})
    policy_changed = POLICY_PATH in changed
    if policy["policy_source"] == "bootstrap" and not policy_changed:
        raise ScopeError("a bootstrap policy must be introduced by the diff it judges")
    report.update({
        "comparison_base_sha": comparison_base, "applicable": bool(applicable_paths),
        "diff_verified": True, "changed_paths": changed, "applicable_paths": applicable_paths,
        "inert_paths": inert_paths, "changed_count": len(changed),
        "applicable_count": len(applicable_paths), "policy_changed": policy_changed,
        "diff_sha256": hashlib.sha256(raw).hexdigest(),
        "reason": ("the policy itself changed" if policy_changed else
                   "applicable source changes" if applicable_paths else
                   "every changed path is covered by a reviewed inert rule"),
    })
    return report


def compact_proof(report: dict[str, Any]) -> dict[str, Any]:
    """Keep unbounded path lists in the artifact, not size-limited job outputs."""
    return {key: value for key, value in report.items()
            if key not in {"inert_rules", "changed_paths", "applicable_paths", "inert_paths"}}


def gate_decision(
    kind: str, needs: dict[str, Any], event_name: str, event: dict[str, Any], checkout_sha: str,
    policy: dict[str, str] | None = None, repo: Path | None = None,
) -> str:
    """Accept only proven irrelevance or every applicable job's success.

    The dependency set must be exactly the policy's jobs. One exception keeps a
    change to the policy reviewable under the base policy: when the pull
    request edits this file, the workflow may add jobs the base does not know,
    and each of them must succeed. No change can remove a job the judging
    policy requires.
    """
    checkout_sha = _sha(checkout_sha, "GITHUB_SHA")
    required = {"applicability", *WORK_JOBS[kind]}
    if not required <= set(needs):
        missing = ", ".join(sorted(required - set(needs)))
        raise ScopeError(f"aggregate is missing a required dependency: {missing}")
    scope = needs["applicability"]
    if not isinstance(scope, dict) or scope.get("result") != "success":
        raise ScopeError("source applicability did not succeed")
    outputs = scope.get("outputs", {})
    if not isinstance(outputs, dict):
        raise ScopeError("source applicability outputs are invalid")
    try:
        proof = json.loads(outputs["proof"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ScopeError("source applicability proof is missing or invalid") from exc
    if not isinstance(proof, dict):
        raise ScopeError("source applicability proof is not an object")
    if policy is None:
        if repo is None:
            raise ScopeError("the gate needs a verified policy identity or a repository")
        policy = resolve_policy(repo, event_name, event, checkout_sha, None, None)
    expected_base, expected_head = _event_ids(event_name, event, checkout_sha)
    expected = {
        "schema": SCHEMA, "status": "ok", "kind": kind, "event_name": event_name,
        "base_sha": expected_base, "head_sha": expected_head, "checkout_sha": checkout_sha,
        "policy_sha256": _policy_hash(kind), **policy,
    }
    if any(proof.get(key) != value for key, value in expected.items()):
        raise ScopeError("source applicability identity or policy does not match this run")
    if type(proof.get("applicable")) is not bool or type(proof.get("policy_changed")) is not bool:
        raise ScopeError("source applicability did not provide explicit boolean decisions")
    for key in ("checkout_sha", "base_sha", "head_sha", "comparison_base_sha"):
        # Actions omits empty job outputs (manual runs have no comparison
        # base). Missing required nonempty identities still fail this check.
        if outputs.get(key, "") != proof.get(key):
            raise ScopeError(f"source applicability {key} outputs disagree")
    applicable = proof["applicable"]
    policy_changed = proof["policy_changed"]
    if outputs.get("applicable") != str(applicable).lower():
        raise ScopeError("source applicability decision outputs disagree")
    if event_name == "pull_request":
        if proof.get("diff_verified") is not True or proof.get("comparison_base_sha") != expected_base:
            raise ScopeError("pull-request diff was not verified against its base")
        digest = proof.get("diff_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ScopeError("pull-request diff fingerprint is missing")
        changed, counted = proof.get("changed_count"), proof.get("applicable_count")
        if type(changed) is not int or type(counted) is not int or not 0 <= counted <= changed:
            raise ScopeError("pull-request path counts are invalid")
        if applicable != (counted > 0):
            raise ScopeError("applicability contradicts the applicable path count")
        if policy_changed and not applicable:
            raise ScopeError("a change to the policy itself cannot be skipped")
        if proof.get("policy_source") == "bootstrap" and not policy_changed:
            raise ScopeError("a bootstrap policy must be introduced by the diff it judges")
    elif not applicable or proof.get("diff_verified") is not False or policy_changed:
        raise ScopeError("non-PR native work cannot be skipped")

    extras = sorted(set(needs) - required)
    if extras and not policy_changed:
        raise ScopeError(f"aggregate has an unknown dependency: {', '.join(extras)} "
                         "(only a change to the policy itself may add a job)")
    expected_results = dict.fromkeys(WORK_JOBS[kind], "skipped")
    if applicable:
        if kind != "performance":
            expected_results = dict.fromkeys(WORK_JOBS[kind], "success")
        else:
            selected = "bench_gate" if event_name == "pull_request" else "drift_watch"
            expected_results[selected] = "success"
    expected_results.update(dict.fromkeys(extras, "success"))
    for job, result in expected_results.items():
        observed = needs[job].get("result") if isinstance(needs[job], dict) else None
        if observed != result:
            raise ScopeError(f"{job} result is {observed!r}; required {result!r}")
    if applicable:
        added = f" (policy transition adds {', '.join(extras)})" if extras else ""
        return (f"native {kind} gate: all applicable work succeeded at {checkout_sha}{added}; "
                f"policy {policy['policy_source']} {policy['policy_revision']}")
    return (f"native {kind} gate: verified diff proves no applicable paths "
            f"({proof['changed_count']} changed; base {expected_base}; head {expected_head}; "
            f"tested {checkout_sha}; policy {policy['policy_source']} {policy['policy_revision']})")


def _append_summary(message: str) -> None:
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(message + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scope", "gate"))
    parser.add_argument("--kind", choices=tuple(INERT), required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("native-scope.json"))
    parser.add_argument("--policy-revision", required=True,
                        help="commit this running file was extracted from (git show REV:" + POLICY_PATH + ")")
    args = parser.parse_args(argv)
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise ScopeError("event payload must be an object")
        event_name, checkout_sha = os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_SHA"]
        policy = resolve_policy(args.repo, event_name, event, checkout_sha,
                                args.policy_revision, Path(__file__).read_bytes())
        if args.command == "gate":
            needs = json.loads(os.environ["NATIVE_CI_NEEDS"])
            if not isinstance(needs, dict):
                raise ScopeError("aggregate dependencies must be an object")
            message = gate_decision(args.kind, needs, event_name, event, checkout_sha, policy)
        else:
            report = compute_scope(args.repo, args.kind, event_name, event, checkout_sha, policy)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            if path := os.environ.get("GITHUB_OUTPUT"):
                with Path(path).open("a", encoding="utf-8") as stream:
                    for key in ("applicable", "checkout_sha", "base_sha", "head_sha", "comparison_base_sha"):
                        value = report[key]
                        stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
                    stream.write("proof=" + json.dumps(compact_proof(report), separators=(",", ":")) + "\n")
            message = (f"native {args.kind} applicability: {report['reason']}; "
                       f"base {report['base_sha']}; head {report['head_sha']}; tested {checkout_sha}; "
                       f"policy {policy['policy_source']} {policy['policy_revision']} "
                       f"sha256 {policy['policy_script_sha256']}")
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
