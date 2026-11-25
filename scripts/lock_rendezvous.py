"""Resolve the container dependency subset against the committed universal lock.

The exported constraints retain platform markers and hashes. uv performs the
actual dependency resolution and generates every artifact hash; this script
never invents lock entries or independently upgrades transitive packages.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv >=0.13.4 is required")
    subprocess.run([uv, "lock", "--check"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="one-link-container-lock-") as directory:
        constraints = Path(directory) / "root-constraints.txt"
        subprocess.run([
            uv, "export", "--frozen", "--all-extras", "--all-groups", "--no-extra", "native",
            "--no-emit-project", "--output-file", str(constraints),
        ], cwd=ROOT, stdout=subprocess.DEVNULL, check=True)
        subprocess.run([
            uv, "pip", "compile", "deploy/rendezvous/requirements.in", "--constraints", str(constraints),
            "--python-version", "3.12", "--universal", "--generate-hashes", "--no-annotate",
            "--custom-compile-command", "python scripts/lock_rendezvous.py",
            "--output-file", "deploy/rendezvous/requirements.lock",
        ], cwd=ROOT, stdout=subprocess.DEVNULL, check=True)
    print("Regenerated deploy/rendezvous/requirements.lock from the reviewed root versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
