"""Prepare a hash-pinned, diagnostic-only build-tool environment on native ARM64.

This does not change the application checkout, its lock, or its build isolation.
The later original uv sync uses a separate environment and its normal settings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit

CANDIDATE = "798026a8cb6af7cb45eedca4b2dec595ce4cb351"
PACKAGE_VERSIONS = {
    "setuptools": "84.2.1",
    "maturin": "1.14.1",
    "cffi": "2.1.0",
    "pycparser": "3.0",
}
WHEEL_SUFFIXES = {
    "setuptools": "-py3-none-any.whl",
    "maturin": "-py3-none-win_arm64.whl",
    "cffi": "-cp312-cp312-win_arm64.whl",
    "pycparser": "-py3-none-any.whl",
}


def command_output(argv: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, check=False, timeout=300
    )
    if result.returncode:
        # These commands only use fixed public URLs and runner paths.
        # Avoid forwarding an arbitrary subprocess diagnostic to the artifact.
        raise RuntimeError(f"command {Path(argv[0]).name} exited {result.returncode}")
    return result.stdout.strip()


def selected_requirements(lock: dict) -> tuple[str, dict]:
    packages = lock.get("package", [])
    rows = []
    manifest = {}
    for name, expected_version in PACKAGE_VERSIONS.items():
        matches = [package for package in packages if package.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one locked {name} package")
        package = matches[0]
        if package.get("version") != expected_version:
            raise ValueError(f"unexpected locked version for {name}")
        if package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ValueError(f"unexpected package source for {name}")
        dependencies = {item["name"] for item in package.get("dependencies", [])}
        if not dependencies.issubset(PACKAGE_VERSIONS):
            raise ValueError(f"unaccounted diagnostic dependency for {name}")
        matches = [
            wheel for wheel in package.get("wheels", [])
            if urlsplit(wheel["url"]).path.endswith(WHEEL_SUFFIXES[name])
        ]
        if len(matches) != 1:
            raise ValueError(f"expected one native/pure diagnostic wheel for {name}")
        wheel = matches[0]
        parsed = urlsplit(wheel["url"])
        digest = wheel.get("hash", "")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "files.pythonhosted.org"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        ):
            raise ValueError(f"invalid locked wheel location/hash for {name}")
        rows.append(f"{name} @ {wheel['url']} --hash={digest}")
        manifest[name] = {
            "version": expected_version,
            "wheel": Path(parsed.path).name,
            "sha256": digest.removeprefix("sha256:"),
        }
    return "\n".join(rows) + "\n", manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    evidence = output / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    source_commit = command_output(["git", "rev-parse", "HEAD"], cwd=source)
    if source_commit != CANDIDATE:
        raise RuntimeError("application checkout is not the exact candidate")
    command_output(["git", "diff", "--exit-code", "HEAD", "--"], cwd=source)
    if os.name != "nt" or platform.machine().lower() not in {"arm64", "aarch64"}:
        raise RuntimeError("diagnostic must run on native Windows ARM64")
    if sys.version_info[:3] != (3, 12, 10):
        raise RuntimeError("diagnostic requires the observed CPython 3.12.10")
    uv_version = command_output(["uv", "--version"])
    rust_version = command_output(["rustc", "-Vv"])
    cargo_version = command_output(["cargo", "--version"])
    if not uv_version.startswith("uv 0.13.10 "):
        raise RuntimeError("unexpected uv version")
    if not (
        rust_version.startswith("rustc 1.96.0 ")
        and "\nhost: aarch64-pc-windows-msvc\n" in f"\n{rust_version}\n"
    ):
        raise RuntimeError("unexpected Rust version or host architecture")
    lock_path = source / "uv.lock"
    lock_bytes = lock_path.read_bytes()
    requirements, wheels = selected_requirements(tomllib.loads(lock_bytes.decode()))
    requirements_path = evidence / "probe-requirements.txt"
    requirements_path.write_text(requirements, encoding="utf-8", newline="\n")
    probe_env = output / "probe-env"
    if probe_env.exists():
        raise RuntimeError("diagnostic environment already exists")
    command_output([
        "uv", "--no-config", "venv", "--python", sys.executable,
        "--no-python-downloads", str(probe_env),
    ])
    probe_python = probe_env / "Scripts" / "python.exe"
    command_output([
        "uv", "--no-config", "pip", "install", "--python", str(probe_python),
        "--no-index", "--no-deps", "--require-hashes", "--only-binary", ":all:",
        "--requirements", str(requirements_path),
    ])
    version_code = (
        "import importlib.metadata,json,platform,sys;"
        "print(json.dumps({'python':platform.python_version(),"
        "'machine':platform.machine(),'in_venv':sys.prefix!=sys.base_prefix,"
        "'packages':{name:importlib.metadata.version(name) for name in "
        "('setuptools','maturin','cffi','pycparser')}}))"
    )
    installed = json.loads(command_output([str(probe_python), "-c", version_code]))
    if installed["packages"] != PACKAGE_VERSIONS:
        raise RuntimeError("diagnostic environment does not match locked wheel versions")
    if installed["machine"].lower() not in {"arm64", "aarch64"}:
        raise RuntimeError("probe interpreter is not native ARM64")
    windows_version = sys.getwindowsversion()
    metadata = {
        "candidate_commit": CANDIDATE,
        "diagnostic_commit": os.environ.get("GITHUB_SHA"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "source_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "runner_image_os": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "windows_version": {
            "major": windows_version.major,
            "minor": windows_version.minor,
            "build": windows_version.build,
        },
        "uv": uv_version,
        "rustc": rust_version.splitlines(),
        "cargo": cargo_version,
        "probe_environment": installed,
        "probe_wheels": wheels,
        "scope": (
            "The probe wheels come from the application lock. The later original "
            "isolated source build may resolve different build-backend versions; "
            "compare its verbose evidence before attributing a probe result."
        ),
    }
    (evidence / "preflight.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({
        "ok": True, "candidate_commit": CANDIDATE,
        "python": metadata["python"], "machine": metadata["machine"],
        "probe_packages": installed["packages"],
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__}))
        raise SystemExit(1)
