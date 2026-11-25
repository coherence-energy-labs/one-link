"""Update the universal uv lock and export audited runtime requirements.

``uv.lock`` is the committed, cross-platform source of dependency truth.
``requirements.lock`` is an ignored, hash-pinned compatibility export for
pip-audit/CycloneDX and is never independently resolved.

Usage:
    pip install "uv>=0.13.4,<0.14"
    python scripts/lock_deps.py            # writes requirements.lock
    python scripts/lock_deps.py --upgrade  # bump to latest within bounds
    python scripts/lock_deps.py --check    # fail if pyproject ahead of lock

The committed lock includes platform and Python markers, so Linux, macOS and
Windows consume one reviewed resolution without platform-specific drift.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _run(args: list[str]) -> int:
    print("$ " + " ".join(args))
    return subprocess.run(args, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--upgrade", action="store_true",
                   help="bump pinned versions to latest compatible")
    p.add_argument("--check", action="store_true",
                   help="fail if requirements.lock is out of date")
    args = p.parse_args(argv)
    root = _project_root()
    if args.check:
        return _run(["uv", "lock", "--check", "--directory", str(root)])

    lock_cmd = ["uv", "lock", "--directory", str(root)]
    if args.upgrade:
        lock_cmd.append("--upgrade")
    rc = _run(lock_cmd)
    if rc != 0:
        return rc
    return _run([
        "uv", "export", "--frozen", "--no-dev", "--no-emit-project",
        "--directory", str(root),
        "--output-file", str(root / "requirements.lock"),
    ])


if __name__ == "__main__":
    raise SystemExit(main())
