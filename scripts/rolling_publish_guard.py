"""Fail-closed selection and integrity checks for the rolling prerelease."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlencode

SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
WORKFLOWS = {
    "tests.yml": "tests",
    "security.yml": "security",
    "lint.yml": "lint",
    "formal_verification.yml": "formal verification",
    "native_shell.yml": "native shell builds",
    "native_build.yml": "file-engine v2 native build",
    "native_bench_gate.yml": "file-engine v2 bench gate",
    "full_suite_and_e2e.yml": "full-suite + e2e",
    "auto_build.yml": "auto-build standalone binary",
}
BUILD = "auto_build.yml"
BINARIES = frozenset({
    "one-link-windows-x86_64.zip", "one-link-windows-arm64.zip",
    "one-link-setup-x86_64.exe", "one-link-setup-arm64.exe",
    "one-link-macos-arm64.zip", "one-link-macos-arm64.dmg",
    "one-link-linux-x86_64.zip", "one-link-linux-arm64.zip",
    "one-link-linux-x86_64.AppImage", "one-link-linux-arm64.AppImage",
})
SIDECARS = frozenset(name + ".sha256" for name in BINARIES if not name.endswith(".exe"))
ASSETS = BINARIES | SIDECARS | {"manifest.txt"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def api(path: str) -> dict:
    result = subprocess.run(["gh", "api", path], check=True, capture_output=True,
                            text=True, timeout=60)
    data = json.loads(result.stdout)
    require(isinstance(data, dict), "GitHub did not return an object")
    return data


def master_identity(repository: str, requested: str, environ: dict[str, str], get=api) -> str:
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "invalid repository identity")
    sha = environ.get("GITHUB_SHA", "")
    require(SHA_RE.fullmatch(sha) is not None, "invalid workflow commit")
    require(environ.get("GITHUB_REF") == "refs/heads/master", "publisher is master-only")
    require(environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "explicit dispatch required")
    require(environ.get("GITHUB_WORKFLOW_REF") ==
            repository + "/.github/workflows/publish_rolling.yml@refs/heads/master",
            "unexpected publisher workflow identity")
    require(not requested or requested == sha, "requested commit differs from publisher commit")
    ref = get(f"repos/{repository}/git/ref/heads/master")
    require(ref.get("ref") == "refs/heads/master" and
            ref.get("object", {}).get("type") == "commit" and
            ref.get("object", {}).get("sha") == sha, "master moved or is not the dispatched commit")
    return sha


def select_build(repository: str, sha: str, get=api) -> int:
    require(SHA_RE.fullmatch(sha) is not None, "invalid candidate commit")
    build_run = 0
    for filename, name in WORKFLOWS.items():
        query = urlencode({"branch": "master", "event": "push", "head_sha": sha, "per_page": 100})
        payload = get(f"repos/{repository}/actions/workflows/{filename}/runs?{query}")
        runs = payload.get("workflow_runs")
        require(isinstance(runs, list) and bool(runs), f"missing required workflow {name}")
        # Never select an older successful run in preference to the newest attempt.
        require(all(isinstance(r, dict) and type(r.get("run_number")) is int and
                    type(r.get("run_attempt")) is int for r in runs), f"invalid run list for {name}")
        run = max(runs, key=lambda r: (r["run_number"], r["run_attempt"]))
        require(run.get("name") == name and run.get("path") == ".github/workflows/" + filename and
                run.get("head_sha") == sha and run.get("head_branch") == "master" and
                run.get("event") == "push" and
                run.get("repository", {}).get("full_name") == repository and
                run.get("head_repository", {}).get("full_name") == repository,
                f"wrong source or workflow for {name}")
        require(run.get("status") == "completed" and run.get("conclusion") == "success",
                f"{name} did not pass on master at {sha}")
        require(type(run.get("id")) is int and run["id"] > 0, f"invalid run ID for {name}")
        if filename == BUILD:
            build_run = run["id"]
    require(build_run > 0, "missing exact build run")
    return build_run


def _manifest(text: str, expected: frozenset[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        # sha256sum and shasum both use whitespace and optionally a binary marker.
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        require(match is not None, "invalid digest row")
        digest, name = match.groups()
        require(name in expected and name not in result, "unexpected or duplicate digest member")
        result[name] = digest
    require(set(result) == set(expected), "manifest does not cover the exact required binary set")
    return result


def _digest(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def verify_assets(root: Path) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), "missing or unsafe artifact directory")
    entries = list(root.iterdir())
    require({p.name for p in entries} == ASSETS, "missing or extra release assets")
    require(all(p.is_file() and not p.is_symlink() and p.stat().st_size > 0 for p in entries),
            "nonregular, linked, or empty release asset")
    manifest = root / "manifest.txt"
    require(manifest.stat().st_size <= 16384, "oversized manifest")
    declared = _manifest(manifest.read_text(encoding="ascii"), BINARIES)
    for name, digest in sorted(declared.items()):
        require(_digest(root / name) == digest, f"binary digest mismatch: {name}")
        if name + ".sha256" in SIDECARS:
            sidecar = root / (name + ".sha256")
            require(sidecar.stat().st_size <= 1024, "oversized checksum sidecar")
            require(_manifest(sidecar.read_text(encoding="ascii"), frozenset({name}))[name] == digest,
                    f"sidecar digest mismatch: {name}")
    return {p.name: _digest(p) for p in entries}


def verify_published(repository: str, root: Path, get=api) -> None:
    expected = verify_assets(root)
    release = get(f"repos/{repository}/releases/tags/auto-latest")
    require(release.get("tag_name") == "auto-latest" and release.get("prerelease") is True
            and release.get("draft") is False, "unexpected release identity or trust tier")
    assets = release.get("assets")
    require(isinstance(assets, list), "missing public release asset listing")
    seen = set()
    for asset in assets:
        name = asset.get("name")
        require(name in expected and name not in seen, "duplicate or unexpected published asset")
        require(asset.get("state") == "uploaded" and
                asset.get("size") == (root / name).stat().st_size and
                asset.get("digest") == "sha256:" + expected[name],
                f"published asset bytes differ: {name}")
        seen.add(name)
    require(seen == set(expected), "public release is missing qualified assets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["resolve", "verify-assets", "recheck", "verify-published"])
    parser.add_argument("--requested", default="")
    parser.add_argument("--directory", type=Path, default=Path("out"))
    parser.add_argument("--build-run", type=int)
    args = parser.parse_args()
    if args.action == "verify-assets":
        print(json.dumps(verify_assets(args.directory), sort_keys=True))
        return
    repository = os.environ["GITHUB_REPOSITORY"]
    if args.action == "verify-published":
        verify_published(repository, args.directory)
        print("All published asset sizes and SHA-256 digests match the qualified set")
        return
    sha = master_identity(repository, args.requested, dict(os.environ))
    run_id = select_build(repository, sha)
    if args.action == "recheck":
        require(args.build_run == run_id, "build run changed since selection")
        verify_assets(args.directory)
    else:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"sha={sha}\nbuild_run={run_id}\n")
        print(f"Qualified master {sha}; build run {run_id}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"refusing to publish: {exc}") from exc
