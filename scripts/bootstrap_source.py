"""Build the supported Python/native combination from this reviewed source tree.

Prerequisites: Python 3.11+, uv >=0.13.4 and Rust 1.96.0 with a platform C
compiler. The script uses the committed Python and Cargo locks, builds the
native wheel into the project's isolated .venv, and verifies its loaded ABI.
It does not start a daemon or change the user's One Link profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
RUST_VERSION = "1.96.0"


def _command(argv: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print("$ " + " ".join(argv), flush=True)
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def _source_identity(root: Path) -> dict:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                     cwd=root, text=True)
    # Hash actual build inputs as well as HEAD. A dirty flag alone cannot
    # detect a second edit to an already-dirty source file during compilation.
    # Git's path inventory excludes ignored caches, build output and profiles.
    inventory = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
         "native", "src", "pyproject.toml", "uv.lock", "setup.cfg", "setup.py"], cwd=root,
    ).decode("utf-8").split("\0")
    paths = sorted(set(p for p in inventory if p))
    return {"revision": revision, "tracked_worktree_dirty": bool(status),
            "build_inputs_sha256": {
                p: hashlib.sha256((root / p).read_bytes()).hexdigest() if (root / p).is_file() else None
                for p in paths}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--e2e", action="store_true", help="also install locked browser-test packages")
    parser.add_argument("--check-only", action="store_true", help="inspect the existing environment without rebuilding")
    parser.add_argument("--report", type=Path, default=ROOT / "test-results/source-bootstrap.json")
    args = parser.parse_args(argv)
    args.report = args.report.resolve()
    uv = shutil.which("uv")
    if uv is None:
        parser.error("uv >=0.13.4 is required")
    uv_version = subprocess.check_output([uv, "--version"], text=True).strip()
    match = re.match(r"uv (\d+)\.(\d+)\.(\d+)", uv_version)
    if match is None or tuple(map(int, match.groups())) < (0, 13, 4):
        parser.error(f"uv >=0.13.4 is required; found {uv_version}")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    runtime_report = args.report.with_name(args.report.stem + "-runtime.json")
    report: dict = {"schema": "one-link-source-bootstrap/v1", "status": "incomplete",
                    "source": _source_identity(ROOT), "uv": uv_version,
                    "rebuilt": not args.check_only}
    started = time.monotonic()
    try:
        if not args.check_only:
            env = dict(os.environ, RUSTUP_TOOLCHAIN=RUST_VERSION)
            rust = subprocess.check_output(["rustc", "--version"], env=env, text=True).strip()
            if not rust.startswith(f"rustc {RUST_VERSION} "):
                raise RuntimeError(f"Rust {RUST_VERSION} is required; found {rust}")
            report["rustc"] = rust
            _command([uv, "lock", "--check"])
            # Keep uv itself installed when this script is invoked from the
            # project's development environment rather than a standalone uv.
            sync = [uv, "sync", "--frozen", "--extra", "dev", "--extra", "release",
                    "--extra", "security"]
            if args.e2e:
                sync += ["--extra", "e2e"]
            _command(sync)
            _command([uv, "run", "--project", str(ROOT), "--no-sync", "maturin",
                      "develop", "--release", "--locked"], cwd=ROOT / "native", env=env)
        _command([uv, "run", "--no-sync", "python", "scripts/verify_native_runtime.py",
                  "--report", str(runtime_report)])
        report["runtime"] = json.loads(runtime_report.read_text(encoding="utf-8"))
        report["source_after"] = _source_identity(ROOT)
        if report["source"] != report["source_after"]:
            raise RuntimeError("source identity changed during bootstrap; rebuild the final tree")
        report["status"] = "passed"
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        report.update(status="failed", error=f"{type(exc).__name__}: {exc}")
    report["elapsed_seconds"] = time.monotonic() - started
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {"status": report["status"], "report": str(args.report),
               "source_revision": report["source"]["revision"],
               "hashed_source_inputs": len(report["source"]["build_inputs_sha256"]),
               "rebuilt": report["rebuilt"], "elapsed_seconds": report["elapsed_seconds"]}
    if "error" in report:
        summary["error"] = report["error"]
    print(json.dumps(summary, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
