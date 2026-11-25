"""Verify every local Cargo source override in the repository and its upstream ancestor.

Cargo can select dependency bytes other than the registry's through a
``[patch]`` (or legacy ``[replace]``) table in ANY workspace manifest, and
through ``[patch]``, ``[source]`` or ``paths`` in ANY ``.cargo/config(.toml)``.
This check discovers all of them: every Cargo manifest and Cargo configuration
file Git would build from (tracked, or untracked and not ignored).

* The only accepted override is a ``[patch.crates-io]`` entry that is exactly
  ``{ path = "..." }``, declared in the same manifest's
  ``[package|workspace.metadata.one-link.vendored-patches]`` with a reviewed
  provenance record, and selected as a source-less package by the
  ``Cargo.lock`` beside that manifest. Git, registry-renaming or otherwise
  undeclared patches fail, and so does any source override in a Cargo config.
* Every Cargo.lock in the repository must agree: a lockfile that resolves a
  backported package version from the registry instead fails, because that
  graph silently builds the unpatched code.
* The default check is offline. Release/CI can additionally download each
  original crate (hash pinned in the reviewed provenance) and prove that the
  selected source differs only by the committed patch. No package version is
  rewritten.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
from http.client import HTTPException
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import subprocess
import sys
import tarfile
import tomllib
from typing import Any, Callable
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "one-link-vendored-cargo-patch/v1"
REPORT_SCHEMA = "one-link-vendor-verification/v2"
CONFIG_SOURCE_KEYS = ("patch", "replace", "source", "paths")


class VendorError(ValueError):
    """The selected local source does not match its reviewed provenance."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(files: dict[str, str]) -> str:
    return sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def repository_root(start: Path) -> Path:
    """The nearest ancestor holding a ``.git`` entry; the start itself when there is none."""
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return start


def inside(repository: Path, name: str, *, base: Path | None = None) -> Path:
    """Resolve ``name`` against ``base`` (default: ``repository``); it must stay inside the repository.

    Absolute, drive- or root-anchored names are refused, and so is any name
    whose resolution passes through a symbolic link or junction.
    """
    if (not isinstance(name, str) or not name or PurePosixPath(name).is_absolute()
            or PureWindowsPath(name).anchor):
        raise VendorError(f"vendor path must be relative: {name!r}")
    repository = repository.resolve()
    origin = (base if base is not None else repository).resolve()
    lexical = Path(os.path.normpath(origin / name))
    resolved = lexical.resolve()
    if not resolved.is_relative_to(repository) or not lexical.is_relative_to(repository):
        raise VendorError(f"vendor path escapes the repository: {name!r}")
    if os.path.normcase(str(lexical.relative_to(repository))) != os.path.normcase(str(resolved.relative_to(repository))):
        raise VendorError(f"vendor path passes through a symbolic link: {name!r}")
    return resolved


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


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "one-link-vendor-verifier/1"})
    # Callers pass only the canonical HTTPS crates.io URL checked below.
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
        return response.read()


def _table(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VendorError(f"{label} must be a TOML table")
    return value


def _declared_records(document: dict[str, Any], label: str) -> dict[str, str]:
    """Provenance records from package.metadata and workspace.metadata."""
    found: dict[str, str] = {}
    for owner in ("package", "workspace"):
        metadata = _table(document.get(owner, {}), f"{label} [{owner}]").get("metadata", {})
        one_link = _table(metadata, f"{label} [{owner}.metadata]").get("one-link", {})
        records = _table(_table(one_link, f"{label} [{owner}.metadata.one-link]").get("vendored-patches", {}),
                         f"{label} [{owner}.metadata.one-link.vendored-patches]")
        for name, record in records.items():
            if name in found:
                raise VendorError(f"{label}: {name} has provenance in both package and workspace metadata")
            if not isinstance(record, str):
                raise VendorError(f"{label}: provenance record for {name} must be a relative path")
            found[name] = record
    return found


def manifest_patches(document: dict[str, Any], label: str) -> dict[str, str]:
    """Return {crate: path} for every accepted patch; refuse anything unverifiable."""
    if "replace" in document:
        raise VendorError(f"{label}: [replace] overrides cannot be verified; use a declared "
                          "[patch.crates-io] path backport")
    local: dict[str, str] = {}
    for source, entries in _table(document.get("patch", {}), f"{label} [patch]").items():
        for name, value in _table(entries, f"{label} [patch.{source}]").items():
            if source != "crates-io":
                raise VendorError(f"{label}: patch for {name} overrides source {source!r}; only "
                                  "declared crates-io path backports can be verified")
            if not isinstance(value, dict) or set(value) != {"path"} or not isinstance(value["path"], str):
                form = "git" if isinstance(value, dict) and "git" in value else "non-path"
                raise VendorError(f"{label}: {form} patch for {name} cannot be verified; vendor the "
                                  "exact source with a reviewed provenance record")
            local[name] = value["path"]
    return local


def inspect_patches(
    manifest: Path, *, fetch_upstream: bool = False, upstream_archive: Path | None = None,
    upstream_archives: dict[tuple[str, str], Path] | None = None,
    download: Callable[[str], bytes] = _download,
    repository: Path | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Verify every patch one manifest declares; return them keyed by (name, version).

    A manifest's ``[patch]`` path and its metadata pointer resolve against the
    manifest's directory. A provenance record lives in ``<workspace>/patches/``
    and its own ``package.path`` and ``patch_path`` resolve against that owning
    workspace. So several workspaces can share one record and one vendored
    tree, provided every declaring ``[patch]`` resolves to the record's
    directory. Every path must stay inside the repository.
    """
    manifest = manifest.resolve()
    root = manifest.parent
    repository = (repository or repository_root(root)).resolve()
    label = manifest.as_posix()
    workspace = tomllib.loads(manifest.read_text(encoding="utf-8"))
    declared = _declared_records(workspace, label)
    local = manifest_patches(workspace, label)
    if set(declared) != set(local):
        raise VendorError(f"{label}: every local registry override must have exactly one provenance "
                          "record, and every record a selected override")
    if upstream_archive is not None and len(local) != 1:
        raise VendorError("a supplied upstream archive requires exactly one local patch")
    if not local:
        return {}
    lock_path = manifest.with_name("Cargo.lock")
    if not lock_path.is_file():
        raise VendorError(f"{label} declares a patch but has no Cargo.lock beside it; Cargo honours "
                          "[patch] only at a workspace root")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    result = {}
    for name in sorted(local):
        proof_path = inside(repository, declared[name], base=root)
        if proof_path.parent.name != "patches":
            raise VendorError(f"provenance record for {name} must live in <workspace>/patches/: {proof_path}")
        owner = proof_path.parent.parent
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        if proof.get("schema") != SCHEMA:
            raise VendorError(f"unsupported vendor provenance schema: {proof_path}")
        package = proof["package"]
        source = inside(repository, local[name], base=root)
        if package["name"] != name or inside(repository, package["path"], base=owner) != source:
            raise VendorError(f"vendor provenance does not match Cargo's selected path: {name} "
                              f"({label} selects {local[name]!r}; the record names {package['path']!r} "
                              f"in {owner.as_posix()})")
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
        patch_path = inside(repository, proof["backport"]["patch_path"], base=owner)
        patch = patch_path.read_bytes()
        if sha256(patch) != proof["backport"]["patch_sha256"]:
            raise VendorError("backport diff differs from reviewed bytes")
        supplied = upstream_archive if upstream_archive is not None else (
            (upstream_archives or {}).get((name, version)))
        checked_upstream = False
        if fetch_upstream or supplied is not None:
            if supplied is not None:
                archive = supplied.read_bytes()
            else:
                url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
                if proof["upstream"]["crate_url"] != url:
                    raise VendorError("upstream archive is not the canonical crates.io package")
                archive = download(url)
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


def _git_files(root: Path, *patterns: str) -> list[str]:
    command = ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard",
               "--", *(f":(glob){pattern}" for pattern in patterns)]
    completed = subprocess.run(command, capture_output=True, check=False)
    if completed.returncode:
        raise VendorError("cannot enumerate Cargo inputs with git: "
                          + completed.stderr.decode(errors="replace").strip())
    try:
        names = completed.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as exc:
        raise VendorError("git returned a path that cannot be decoded losslessly") from exc
    # A tracked file deleted from the working tree is not read by Cargo.
    return sorted({name for name in names if name and (root / name).is_file()})


def discover_cargo_inputs(root: Path) -> tuple[list[str], list[str]]:
    """Return (manifests, configs): every Cargo.toml and .cargo/config(.toml) Git builds from."""
    manifests = _git_files(root, "**/Cargo.toml")
    configs = _git_files(root, "**/.cargo/config", "**/.cargo/config.toml")
    return manifests, configs


def _within(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory.rstrip("/") + "/")


def inspect_config(path: Path, label: str) -> None:
    """A Cargo configuration file must not redirect any dependency source."""
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    for key in CONFIG_SOURCE_KEYS:
        if key in document:
            raise VendorError(f"{label}: Cargo configuration [{key}] changes dependency sources; "
                              "declare a vendored backport in a workspace manifest instead")
    registry = document.get("registry", {})
    if isinstance(registry, dict) and "index" in registry:
        raise VendorError(f"{label}: Cargo configuration registry.index redirects crates.io")


def inspect_repository(
    root: Path = ROOT, *, fetch_upstream: bool = False,
    upstream_archives: dict[tuple[str, str], Path] | None = None,
    download: Callable[[str], bytes] = _download,
) -> dict[str, Any]:
    """Verify every source override in the repository; fail on any inconsistency."""
    root = root.resolve()
    manifests, configs = discover_cargo_inputs(root)
    if not manifests:
        raise VendorError(f"no Cargo manifests were found under {root}")
    for config in configs:
        inspect_config(root / config, config)
    documents = {name: tomllib.loads((root / name).read_text(encoding="utf-8")) for name in manifests}
    vendored_dirs = []
    for name, document in documents.items():
        for path in manifest_patches(document, name).values():
            vendored_dirs.append(posixpath.normpath(posixpath.join(posixpath.dirname(name), path)))
    # A vendored package's own manifest and lockfile are part of its verified
    # upstream bytes, and Cargo never reads a dependency's [patch] or lockfile.
    workspace_manifests = [name for name in manifests
                           if not any(_within(name, directory) for directory in vendored_dirs)]
    downloaded: dict[str, bytes] = {}

    def cached(url: str) -> bytes:
        if url not in downloaded:
            downloaded[url] = download(url)
        return downloaded[url]

    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for name in workspace_manifests:
        inspected = inspect_patches(root / name, fetch_upstream=fetch_upstream,
                                    upstream_archives=upstream_archives, download=cached, repository=root)
        for key, value in inspected.items():
            selected_by = value["source_path"].relative_to(root).as_posix()
            if key in packages:
                first = packages[key]
                same = (first["proof"]["source_tree_sha256"] == value["proof"]["source_tree_sha256"]
                        and first["proof"]["backport"]["patch_sha256"] == value["proof"]["backport"]["patch_sha256"])
                if not same:
                    raise VendorError(f"{key[0]} {key[1]} is backported differently by {first['manifests'][0]} "
                                      f"and {name}")
                first["manifests"].append(name)
                first["sources"].append(posixpath.normpath(selected_by))
                first["upstream_archive_verified"] = (first["upstream_archive_verified"]
                                                      and value["upstream_archive_verified"])
            else:
                packages[key] = {**value, "manifests": [name], "sources": [posixpath.normpath(selected_by)]}
    unknown = sorted(set(upstream_archives or {}) - set(packages))
    if unknown:
        raise VendorError(f"supplied upstream archives match no selected backport: {unknown}")
    lockfiles = [name for name in _git_files(root, "**/Cargo.lock")
                 if not any(_within(name, directory) for directory in vendored_dirs)]
    for lockfile in lockfiles:
        lock = tomllib.loads((root / lockfile).read_text(encoding="utf-8"))
        for row in lock.get("package", []):
            key = (row.get("name"), row.get("version"))
            if key in packages and "source" in row:
                raise VendorError(
                    f"{lockfile} resolves {key[0]} {key[1]} from {row['source']}, bypassing the reviewed "
                    f"backport that {', '.join(packages[key]['manifests'])} selects; add the same "
                    "[patch.crates-io] path and provenance record to that workspace")
    return {"packages": packages, "manifests": manifests, "workspace_manifests": workspace_manifests,
            "configs": configs, "lockfiles": lockfiles}


def _archive_argument(value: str) -> tuple[tuple[str, str], Path]:
    key, separator, path = value.partition("=")
    name, at, version = key.partition("@")
    if not separator or not at or not name or not version or not path:
        raise argparse.ArgumentTypeError("expected NAME@VERSION=PATH")
    return (name, version), Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository whose Cargo inputs are verified")
    parser.add_argument("--fetch-upstream", action="store_true")
    parser.add_argument("--upstream-archive", type=_archive_argument, action="append", default=[],
                        metavar="NAME@VERSION=PATH")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report: dict[str, Any] = {"schema": REPORT_SCHEMA, "status": "failed"}
    try:
        archives = dict(args.upstream_archive)
        if len(archives) != len(args.upstream_archive):
            raise VendorError("an upstream archive was supplied twice for one package")
        inspected = inspect_repository(args.root, fetch_upstream=args.fetch_upstream,
                                       upstream_archives=archives)
        report["inputs"] = {key: inspected[key] for key in
                            ("manifests", "workspace_manifests", "configs", "lockfiles")}
        if not inspected["packages"]:
            raise VendorError("no declared vendor patches were selected for qualification")
        report.update(status="passed", packages=[{
            "name": name, "version": version,
            "manifests": value["manifests"], "sources": value["sources"],
            "source_tree_sha256": value["proof"]["source_tree_sha256"],
            "file_count": len(value["proof"]["files"]),
            "changed_files": value["proof"]["backport"]["changed_files"],
            "patch_sha256": value["proof"]["backport"]["patch_sha256"],
            "upstream_crate_sha256": value["proof"]["upstream"]["crate_sha256"],
            "upstream_archive_verified": value["upstream_archive_verified"],
            "maintenance": value["proof"]["maintenance"],
        } for (name, version), value in sorted(inspected["packages"].items())])
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, HTTPException) as exc:
        report["error"] = str(exc)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
