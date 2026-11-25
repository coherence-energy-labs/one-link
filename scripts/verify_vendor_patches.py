"""Verify exact local Cargo backports and their unmodified upstream ancestors.

The default check is offline. Release/CI can additionally download the original
crate (hash pinned in the reviewed provenance) and prove that the selected
source differs only by the committed patch. No package version is rewritten.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import tomllib
from typing import Any
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "one-link-vendored-cargo-patch/v1"


class VendorError(ValueError):
    """The selected local source does not match its reviewed provenance."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(files: dict[str, str]) -> str:
    return sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def inside(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise VendorError(f"vendor path must be relative: {name!r}")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise VendorError(f"vendor path escapes its workspace: {name!r}")
    return path


def source_files(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise VendorError(f"symlinked vendor source is not supported: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256(path.read_bytes())
    if not result:
        raise VendorError(f"vendor source directory is empty: {root}")
    return result


def upstream_files(archive: bytes, name: str, version: str) -> dict[str, bytes]:
    result = {}
    prefix = f"{name}-{version}/"
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        for member in stream.getmembers():
            if not member.isfile() or not member.name.startswith(prefix):
                raise VendorError("upstream crate contains an unexpected archive member")
            relative = member.name.removeprefix(prefix)
            if relative in result or ".." in Path(relative).parts:
                raise VendorError("upstream crate has a duplicate or unsafe member")
            handle = stream.extractfile(member)
            if handle is None:
                raise VendorError("cannot read upstream archive member")
            result[relative] = handle.read()
    return result


def inspect_patches(
    manifest: Path, *, fetch_upstream: bool = False, upstream_archive: Path | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    manifest = manifest.resolve()
    root = manifest.parent
    workspace = tomllib.loads(manifest.read_text(encoding="utf-8"))
    declared = workspace.get("package", {}).get("metadata", {}).get("one-link", {}).get(
        "vendored-patches", {})
    local = {name: value["path"]
             for name, value in workspace.get("patch", {}).get("crates-io", {}).items()
             if isinstance(value, dict) and "path" in value}
    if set(declared) != set(local):
        raise VendorError("every local registry override must have exactly one provenance record")
    if upstream_archive is not None and len(local) != 1:
        raise VendorError("a supplied upstream archive requires exactly one local patch")
    if not local:
        return {}
    lock = tomllib.loads(manifest.with_name("Cargo.lock").read_text(encoding="utf-8"))
    result = {}
    for name in sorted(local):
        proof_path = inside(root, declared[name])
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        if proof.get("schema") != SCHEMA:
            raise VendorError(f"unsupported vendor provenance schema: {proof_path}")
        package = proof["package"]
        if package["name"] != name or package["path"] != local[name]:
            raise VendorError(f"vendor provenance does not match Cargo's selected path: {name}")
        source = inside(root, local[name])
        package_manifest = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        for field in ("name", "version", "license"):
            if package_manifest[field] != package[field]:
                raise VendorError(f"vendored package changed its original {field}: {name}")
        version = package["version"]
        selected = [row for row in lock["package"]
                    if row["name"] == name and row["version"] == version]
        if len(selected) != 1 or "source" in selected[0] or "checksum" in selected[0]:
            raise VendorError(f"Cargo.lock does not select the reviewed local package: {name}")
        actual = source_files(source)
        expected = proof["files"]
        if actual != expected:
            changed = sorted(key for key in set(actual) | set(expected)
                             if actual.get(key) != expected.get(key))
            raise VendorError(f"vendored source differs from reviewed bytes: {changed[:5]}")
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in expected.values()):
            raise VendorError("invalid vendored source digest")
        if tree_hash(actual) != proof["source_tree_sha256"]:
            raise VendorError("vendored source tree digest is inconsistent")
        original = proof["upstream_files"]
        if set(original) != set(expected):
            raise VendorError("backport added or removed upstream package files")
        if tree_hash(original) != proof["upstream"]["source_tree_sha256"]:
            raise VendorError("upstream source tree digest is inconsistent")
        changed = sorted(key for key in original if original[key] != expected[key])
        if changed != proof["backport"]["changed_files"]:
            raise VendorError("backport changed undeclared source files")
        patch_path = inside(root, proof["backport"]["patch_path"])
        patch = patch_path.read_bytes()
        if sha256(patch) != proof["backport"]["patch_sha256"]:
            raise VendorError("backport diff differs from reviewed bytes")
        checked_upstream = False
        if fetch_upstream or upstream_archive is not None:
            if upstream_archive is not None:
                archive = upstream_archive.read_bytes()
            else:
                url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
                if proof["upstream"]["crate_url"] != url:
                    raise VendorError("upstream archive is not the canonical crates.io package")
                request = urllib.request.Request(url, headers={"User-Agent": "one-link-vendor-verifier/1"})
                # The request URL above is fixed to the canonical HTTPS registry.
                with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
                    archive = response.read()
            if sha256(archive) != proof["upstream"]["crate_sha256"]:
                raise VendorError("upstream crate archive checksum mismatch")
            unpacked = upstream_files(archive, name, version)
            if {key: sha256(value) for key, value in unpacked.items()} != original:
                raise VendorError("upstream archive differs from recorded original package files")
            exact_diff = "".join("".join(difflib.unified_diff(
                unpacked[key].decode().splitlines(keepends=True),
                (source / key).read_bytes().decode().splitlines(keepends=True),
                fromfile=f"a/{key}", tofile=f"b/{key}",
            )) for key in changed)
            if exact_diff.encode() != patch:
                raise VendorError("selected source differs from upstream by more than the reviewed diff")
            checked_upstream = True
        result[(name, version)] = {
            "proof": proof, "proof_path": proof_path,
            "source_path": source, "patch_text": patch.decode(),
            "upstream_archive_verified": checked_upstream,
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "native/ol_shell/Cargo.toml")
    parser.add_argument("--fetch-upstream", action="store_true")
    parser.add_argument("--upstream-archive", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report: dict[str, Any] = {"schema": "one-link-vendor-verification/v1", "status": "failed"}
    try:
        inspected = inspect_patches(args.manifest, fetch_upstream=args.fetch_upstream,
                                    upstream_archive=args.upstream_archive)
        if not inspected:
            raise VendorError("no declared vendor patches were selected for qualification")
        report.update(status="passed", packages=[{
            "name": name, "version": version,
            "source_tree_sha256": value["proof"]["source_tree_sha256"],
            "file_count": len(value["proof"]["files"]),
            "changed_files": value["proof"]["backport"]["changed_files"],
            "patch_sha256": value["proof"]["backport"]["patch_sha256"],
            "upstream_crate_sha256": value["proof"]["upstream"]["crate_sha256"],
            "upstream_archive_verified": value["upstream_archive_verified"],
            "maintenance": value["proof"]["maintenance"],
        } for (name, version), value in inspected.items()])
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        report["error"] = str(exc)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
