"""Verify source/native version alignment, binary identity and the live KEM ABI.

The binary hash identifies the bytes loaded by this interpreter. Version
agreement and a self-test do not independently attest their source provenance;
bootstrap_source.py records the source/build context for a local source build.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import json
from pathlib import Path
import platform
import tomllib

from packaging.version import Version


def inspect_runtime(expected_version: str) -> dict:
    report: dict = {
        "schema": "one-link-native-runtime/v1", "status": "failed",
        "expected_version": expected_version, "python": platform.python_version(),
        "platform": platform.platform(), "errors": [], "pqkem_self_test": False,
    }
    try:
        core = importlib.import_module("one_link")
        native = importlib.import_module("one_link_native")
        versions = {
            "python_source_version": core.__version__,
            "native_module_version": getattr(native, "__version__", ""),
            "native_distribution_version": importlib.metadata.version("one_link_native"),
        }
        report.update(versions)
        for label, version in versions.items():
            if Version(version) != Version(expected_version):
                report["errors"].append(f"{label}={version} does not match {expected_version}")
        extension = getattr(native, "one_link_native", native)
        origin = getattr(extension, "__file__", None)
        if not origin or not any(str(origin).endswith(x) for x in importlib.machinery.EXTENSION_SUFFIXES):
            report["errors"].append("loaded native extension origin is unavailable or not a binary")
        else:
            path = Path(origin)
            with path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            report["native_binary"] = {"path": str(path.resolve()),
                                       "size_bytes": path.stat().st_size, "sha256": digest}
        pqkem = importlib.import_module("one_link.pqkem_native")
        report["pqkem_self_test"] = pqkem.runtime_is_usable() is True
        if not report["pqkem_self_test"]:
            report["errors"].append("required ML-KEM-768/X25519 ABI self-test failed")
    except (ImportError, AttributeError, OSError, ValueError) as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    if not report["errors"]:
        report["status"] = "passed"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-version")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    version = args.expected_version
    if version is None:
        with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as source:
            version = tomllib.load(source)["project"]["version"]
    report = inspect_runtime(version)
    content = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(content, encoding="utf-8")
    print(content, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
