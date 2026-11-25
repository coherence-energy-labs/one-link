"""Generate One Link's deterministic CycloneDX release inventory.

The Python portion is produced by the lock-aware, pinned ``cyclonedx-bom``
tool.  This module then performs a deterministic, offline merge of:

* the complete frozen Python requirements graph;
* every package and dependency edge in the selected Cargo workspace locks;
* every local Cargo workspace member; and
* SHA-256 hashes of the exact release artifacts already assembled on disk.

Release generation deliberately happens only after every wheel and standalone
bundle has been downloaded into one directory.  The resulting SBOM is then
checksummed, signed, attested, and published by ``release.yml``.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import quote, urlencode

if __package__:
    from .verify_vendor_patches import VendorError, inspect_patches
else:
    from verify_vendor_patches import VendorError, inspect_patches


CYCLONEDX_SPEC_VERSION = "1.6"
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+sparse+https://index.crates.io/",
}
SBOM_NAMESPACE = uuid.UUID("76864f3d-0379-5b8d-90f7-a4b43a625c03")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SbomError(ValueError):
    """Raised when an input cannot produce a complete, truthful SBOM."""


@dataclass(frozen=True)
class CargoPackage:
    """A normalized package record from Cargo.lock."""

    name: str
    version: str
    source: str | None
    checksum: str | None
    dependencies: tuple[str, ...]
    ref: str


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _absolute(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _read_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SbomError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SbomError(f"{label} {path} is not a TOML table")
    return value


def _sha256_file(path: Path) -> tuple[str, int]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise SbomError(f"refusing symlinked SBOM input: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise SbomError(f"SBOM input is not a regular file: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    after = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after:
        raise SbomError(f"SBOM input changed while it was hashed: {path}")
    return digest.hexdigest(), before.st_size


def _validate_frozen_requirements(path: Path) -> None:
    """Reject resolver inputs that are not exact, hash-pinned exports."""

    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SbomError(f"cannot read frozen requirements {path}: {exc}") from exc

    logical_lines: list[str] = []
    pending = ""
    for raw_line in raw_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continuation = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continuation else stripped
        pending = f"{pending} {fragment}".strip()
        if not continuation:
            logical_lines.append(pending)
            pending = ""
    if pending:
        raise SbomError(f"frozen requirements ends with an unfinished continuation: {path}")
    if not logical_lines:
        raise SbomError(f"frozen requirements contains no packages: {path}")

    for requirement in logical_lines:
        declaration = requirement.split("--hash=", 1)[0].strip()
        declaration = declaration.split(";", 1)[0].strip()
        if "==" not in declaration or declaration.startswith("=="):
            raise SbomError(f"Python requirement is not exactly pinned: {requirement!r}")
        hashes = re.findall(r"--hash=sha256:([0-9a-fA-F]{64})(?=\s|$)", requirement)
        if not hashes:
            raise SbomError(f"Python requirement has no SHA-256 distribution hash: {requirement!r}")


def _license_choice(value: str) -> list[dict[str, Any]]:
    """CycloneDX license entry for a Cargo `license` string.

    A compound SPDX expression ("Apache-2.0 OR MIT") must use the `expression`
    form; `license.id` accepts only a single SPDX identifier, and the schema
    rejects an expression there. Every component (workspace member, vendored
    backport, and its pedigree ancestor) goes through this one function.
    """
    if re.search(r"(?:^|\s)(?:AND|OR|WITH)(?:\s|$)|[()]", value):
        return [{"expression": value}]
    return [{"license": {"id": value}}]


def _cargo_purl(name: str, version: str, source: str | None) -> str:
    base = f"pkg:cargo/{quote(name, safe='-._~')}@{quote(version, safe='-._~')}"
    qualifiers: list[tuple[str, str]] = []
    if source is None:
        qualifiers.append(("repository_url", "workspace"))
    elif source not in CRATES_IO_SOURCES:
        key = "vcs_url" if source.startswith("git+") else "repository_url"
        qualifiers.append((key, source))
    if qualifiers:
        return f"{base}?{urlencode(qualifiers, quote_via=quote, safe='')}"
    return base


def _parse_cargo_packages(lock_path: Path) -> list[CargoPackage]:
    document = _read_toml(lock_path, "Cargo lockfile")
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise SbomError(f"Cargo lockfile contains no packages: {lock_path}")

    packages: list[CargoPackage] = []
    refs: set[str] = set()
    for index, raw in enumerate(raw_packages):
        if not isinstance(raw, dict):
            raise SbomError(f"Cargo package #{index} is not a table")
        name = raw.get("name")
        version = raw.get("version")
        source = raw.get("source")
        checksum = raw.get("checksum")
        dependencies = raw.get("dependencies", [])
        if not isinstance(name, str) or not name:
            raise SbomError(f"Cargo package #{index} has no valid name")
        if not isinstance(version, str) or not version:
            raise SbomError(f"Cargo package {name!r} has no valid version")
        if source is not None and not isinstance(source, str):
            raise SbomError(f"Cargo package {name} {version} has an invalid source")
        if checksum is not None:
            if not isinstance(checksum, str) or SHA256_RE.fullmatch(checksum) is None:
                raise SbomError(f"Cargo package {name} {version} has an invalid checksum")
        if source is not None and source.startswith("registry+") and checksum is None:
            raise SbomError(f"registry Cargo package {name} {version} has no checksum")
        if not isinstance(dependencies, list) or not all(
            isinstance(dep, str) and dep for dep in dependencies
        ):
            raise SbomError(f"Cargo package {name} {version} has invalid dependencies")

        ref = _cargo_purl(name, version, source)
        if ref in refs:
            raise SbomError(f"duplicate Cargo component identity: {ref}")
        refs.add(ref)
        packages.append(
            CargoPackage(
                name=name,
                version=version,
                source=source,
                checksum=checksum,
                dependencies=tuple(dependencies),
                ref=ref,
            )
        )
    return sorted(packages, key=lambda package: package.ref)


def _dependency_target(specification: str, packages: Sequence[CargoPackage]) -> str:
    parts = specification.split()
    if not parts:
        raise SbomError("Cargo dependency entry is empty")
    name = parts[0]
    version: str | None = None
    source: str | None = None
    if len(parts) >= 2 and not parts[1].startswith("("):
        version = parts[1]
    source_start = specification.find("(")
    if source_start >= 0:
        if not specification.endswith(")"):
            raise SbomError(f"malformed Cargo dependency entry: {specification!r}")
        source = specification[source_start + 1 : -1]

    candidates = [package for package in packages if package.name == name]
    if version is not None:
        candidates = [package for package in candidates if package.version == version]
    if source is not None:
        candidates = [package for package in candidates if package.source == source]
    if len(candidates) != 1:
        identities = ", ".join(package.ref for package in candidates) or "none"
        raise SbomError(
            f"Cargo dependency {specification!r} resolved to {len(candidates)} "
            f"packages ({identities})"
        )
    return candidates[0].ref


def _workspace_member_manifests(workspace_manifest: Path) -> dict[tuple[str, str], dict[str, str]]:
    workspace_document = _read_toml(workspace_manifest, "Cargo workspace manifest")
    workspace = workspace_document.get("workspace")
    if not isinstance(workspace, dict):
        raise SbomError(f"manifest has no [workspace] table: {workspace_manifest}")
    members = workspace.get("members", [])
    if not isinstance(members, list) or not all(
        isinstance(member, str) and member for member in members
    ):
        raise SbomError(f"workspace has no explicit members: {workspace_manifest}")
    members = list(members)
    if isinstance(workspace_document.get("package"), dict) and "." not in members:
        members.insert(0, ".")
    if not members:
        raise SbomError(f"workspace has no explicit members: {workspace_manifest}")

    workspace_root = workspace_manifest.parent.resolve()
    manifests: dict[tuple[str, str], dict[str, str]] = {}
    for pattern in members:
        matches = [workspace_root] if pattern == "." else sorted(
            workspace_root.glob(pattern), key=lambda path: path.as_posix()
        )
        if not matches:
            raise SbomError(f"workspace member pattern did not match: {pattern!r}")
        for member in matches:
            resolved_member = member.resolve()
            if not resolved_member.is_relative_to(workspace_root):
                raise SbomError(f"workspace member escapes its root: {member}")
            manifest = resolved_member / "Cargo.toml" if resolved_member.is_dir() else resolved_member
            document = _read_toml(manifest, "Cargo member manifest")
            package = document.get("package")
            if not isinstance(package, dict):
                raise SbomError(f"workspace member has no [package] table: {manifest}")
            name = package.get("name")
            version = package.get("version")
            if isinstance(version, dict) and version.get("workspace") is True:
                workspace_package = workspace_document.get("workspace", {}).get("package", {})
                version = workspace_package.get("version") if isinstance(workspace_package, dict) else None
            if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
                raise SbomError(f"workspace member has no concrete name/version: {manifest}")
            key = (name, version)
            if key in manifests:
                raise SbomError(f"duplicate workspace member package: {name} {version}")
            relative = manifest.parent.relative_to(workspace_root).as_posix()
            details = {"path": relative}
            license_value = package.get("license")
            if isinstance(license_value, str) and license_value:
                details["license"] = license_value
            description = package.get("description")
            if isinstance(description, str) and description:
                details["description"] = description
            manifests[key] = details
    return manifests


def _properties(owner: dict[str, Any], additions: dict[str, str]) -> None:
    current = owner.get("properties", [])
    if not isinstance(current, list):
        raise SbomError("CycloneDX properties must be a list")
    retained = [
        item
        for item in current
        if isinstance(item, dict) and item.get("name") not in additions
    ]
    retained.extend({"name": name, "value": value} for name, value in additions.items())
    owner["properties"] = sorted(
        retained,
        key=lambda item: (str(item.get("name", "")), str(item.get("value", ""))),
    )


def _cargo_inventory(
    lock_path: Path,
    workspace_manifest: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    packages = _parse_cargo_packages(lock_path)
    try:
        vendors = inspect_patches(workspace_manifest)
    except (OSError, ValueError, KeyError, TypeError, VendorError) as exc:
        raise SbomError(f"vendored dependency provenance failed: {exc}") from exc
    packages = [replace(package, ref=(
        f"urn:one-link:vendored-cargo:{package.name}:{package.version}:sha256:"
        + vendors[(package.name, package.version)]["proof"]["source_tree_sha256"]
    )) if (package.name, package.version) in vendors else package for package in packages]
    workspace_members = _workspace_member_manifests(workspace_manifest)
    local_packages = {
        (package.name, package.version): package
        for package in packages
        if package.source is None
    }
    missing = sorted(set(workspace_members) - set(local_packages))
    if missing:
        formatted = ", ".join(f"{name} {version}" for name, version in missing)
        raise SbomError(f"workspace members absent from Cargo.lock: {formatted}")

    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    for package in packages:
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": package.ref,
            "name": package.name,
            "version": package.version,
            "purl": package.ref,
        }
        if package.checksum is not None:
            component["hashes"] = [{"alg": "SHA-256", "content": package.checksum}]
        source_label = package.source if package.source is not None else "workspace"
        additions = {"one-link:cargo:source": source_label}
        member = workspace_members.get((package.name, package.version))
        if member is not None:
            additions["one-link:cargo:workspace-member"] = "true"
            additions["one-link:cargo:workspace-path"] = member["path"]
            if "license" in member:
                component["licenses"] = _license_choice(member["license"])
            if "description" in member:
                component["description"] = member["description"]
        vendor = vendors.get((package.name, package.version))
        if vendor is not None:
            proof = vendor["proof"]
            upstream = proof["upstream"]
            backport = proof["backport"]
            # Keep the original package/version visible to advisory scanners,
            # but identify the actual local bytes and their modified pedigree.
            component["purl"] = _cargo_purl(
                package.name, package.version, "registry+https://github.com/rust-lang/crates.io-index"
            )
            component["modified"] = True
            component["licenses"] = _license_choice(proof["package"]["license"])
            component["hashes"] = [{"alg": "SHA-256", "content": proof["source_tree_sha256"]}]
            component["pedigree"] = {
                "ancestors": [{
                    "type": "library", "name": package.name, "version": package.version,
                    "purl": component["purl"],
                    "hashes": [{"alg": "SHA-256", "content": upstream["crate_sha256"]}],
                    "licenses": _license_choice(proof["package"]["license"]),
                    "externalReferences": [{"type": "distribution", "url": upstream["crate_url"]}],
                }],
                "patches": [{"type": "backport", "diff": {
                    "text": {"contentType": "text/plain", "content": vendor["patch_text"]},
                    "url": backport["upstream_url"],
                }}],
                "notes": proof["maintenance"],
            }
            additions.update({
                "one-link:cargo:source": "vendored",
                "one-link:cargo:vendored-path": proof["package"]["path"],
                "one-link:cargo:source-tree-sha256": proof["source_tree_sha256"],
                "one-link:cargo:source-tree-hash-format": proof["tree_hash_format"],
                "one-link:cargo:upstream-crate-sha256": upstream["crate_sha256"],
                "one-link:cargo:upstream-fix-commit": backport["upstream_fix_commit"],
                "one-link:cargo:patch-sha256": backport["patch_sha256"],
                "one-link:cargo:backported-advisories": ",".join(backport["advisories"]),
            })
        _properties(component, additions)
        components.append(component)
        dependencies.append(
            {
                "ref": package.ref,
                "dependsOn": sorted(
                    {_dependency_target(dependency, packages) for dependency in package.dependencies}
                ),
            }
        )

    metadata = {
        "one-link:sbom:cargo-lock-sha256": _sha256_file(lock_path)[0],
        "one-link:sbom:cargo-workspace-manifest-sha256": _sha256_file(workspace_manifest)[0],
        "one-link:sbom:cargo-package-count": str(len(packages)),
        "one-link:sbom:cargo-workspace-member-count": str(len(workspace_members)),
        "one-link:sbom:cargo-scope": "complete Cargo.lock resolution, including build and test packages",
        "one-link:sbom:cargo-vendored-backport-count": str(len(vendors)),
    }
    return components, dependencies, metadata


def _python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _python_source_key(value: Any) -> str:
    if not isinstance(value, dict):
        raise SbomError(f"uv.lock package source is not a table: {value!r}")
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _python_lock_graph(
    lock_path: Path,
    bom: dict[str, Any],
    excluded_root_extras: Sequence[str],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Resolve the universal uv.lock graph without invoking a resolver."""

    document = _read_toml(lock_path, "uv lockfile")
    packages = document.get("package")
    if not isinstance(packages, list) or not packages:
        raise SbomError(f"uv lockfile contains no packages: {lock_path}")

    normalized: list[dict[str, Any]] = []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise SbomError(f"uv package #{index} is not a table")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise SbomError(f"uv package #{index} has no concrete name/version")
        source_key = _python_source_key(package.get("source"))
        normalized_name = _python_name(name)
        record: dict[str, Any] = {
            "raw": package,
            "name": normalized_name,
            "version": version,
            "source": source_key,
            "key": (normalized_name, version, source_key),
        }
        normalized.append(record)
        by_name.setdefault(normalized_name, []).append(record)

    roots = [
        record
        for record in normalized
        if "editable" in record["raw"].get("source", {})
    ]
    if len(roots) != 1:
        raise SbomError(f"uv lockfile must contain exactly one editable root; found {len(roots)}")
    root = roots[0]

    def resolve(specification: Any) -> dict[str, Any]:
        if not isinstance(specification, dict):
            raise SbomError(f"uv dependency is not a table: {specification!r}")
        raw_name = specification.get("name")
        if not isinstance(raw_name, str) or not raw_name:
            raise SbomError(f"uv dependency has no name: {specification!r}")
        candidates = list(by_name.get(_python_name(raw_name), []))
        version = specification.get("version")
        if version is not None:
            if not isinstance(version, str):
                raise SbomError(f"uv dependency has invalid version: {specification!r}")
            candidates = [candidate for candidate in candidates if candidate["version"] == version]
        source = specification.get("source")
        if source is not None:
            source_key = _python_source_key(source)
            candidates = [candidate for candidate in candidates if candidate["source"] == source_key]
        if len(candidates) != 1:
            raise SbomError(
                f"uv dependency {specification!r} resolved to {len(candidates)} packages"
            )
        return candidates[0]

    metadata = bom.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(root_component, dict):
        raise SbomError("CycloneDX base document has no root component")
    root_ref = _component_ref(root_component)

    component_refs: dict[tuple[str, str], str] = {}
    components = bom.get("components", [])
    if not isinstance(components, list):
        raise SbomError("CycloneDX components must be a list")
    for component in components:
        if not isinstance(component, dict):
            raise SbomError("CycloneDX component must be an object")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise SbomError("Python CycloneDX component has no name/version")
        key = (_python_name(name), version)
        if key in component_refs:
            raise SbomError(f"duplicate Python component identity: {key}")
        component_refs[key] = _component_ref(component)

    excluded = {_python_name(extra) for extra in excluded_root_extras}
    root_raw = root["raw"]
    initial_specs = list(root_raw.get("dependencies", []))
    optional = root_raw.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise SbomError("uv root optional-dependencies is not a table")
    for extra, specifications in optional.items():
        if _python_name(str(extra)) in excluded:
            continue
        if not isinstance(specifications, list):
            raise SbomError(f"uv root extra {extra!r} is not a dependency list")
        initial_specs.extend(specifications)
    groups = root_raw.get("dev-dependencies", {})
    if not isinstance(groups, dict):
        raise SbomError("uv root dev-dependencies is not a table")
    for group, specifications in groups.items():
        if not isinstance(specifications, list):
            raise SbomError(f"uv dependency group {group!r} is not a list")
        initial_specs.extend(specifications)

    reachable: dict[tuple[str, str, str], dict[str, Any]] = {root["key"]: root}
    selected_extras: dict[tuple[str, str, str], set[str]] = {root["key"]: set()}
    edges: dict[tuple[str, str, str], set[tuple[str, str, str]]] = {root["key"]: set()}
    queue: list[tuple[dict[str, Any], list[Any]]] = [(root, initial_specs)]
    while queue:
        parent, specifications = queue.pop(0)
        parent_key = parent["key"]
        for specification in specifications:
            target = resolve(specification)
            target_key = target["key"]
            edges.setdefault(parent_key, set()).add(target_key)
            first_visit = target_key not in reachable
            reachable[target_key] = target
            requested_extras = specification.get("extra", [])
            if not isinstance(requested_extras, list) or not all(
                isinstance(extra, str) for extra in requested_extras
            ):
                raise SbomError(f"uv dependency has invalid extras: {specification!r}")
            new_extras = set(requested_extras) - selected_extras.setdefault(target_key, set())
            if not first_visit and not new_extras:
                continue
            selected_extras[target_key].update(new_extras)
            target_specs = list(target["raw"].get("dependencies", [])) if first_visit else []
            target_optional = target["raw"].get("optional-dependencies", {})
            if not isinstance(target_optional, dict):
                raise SbomError(f"uv optional-dependencies is invalid for {target['name']}")
            for extra in sorted(new_extras):
                extra_specs = target_optional.get(extra)
                if not isinstance(extra_specs, list):
                    raise SbomError(f"uv dependency requested missing extra {target['name']}[{extra}]")
                target_specs.extend(extra_specs)
            queue.append((target, target_specs))

    graph_refs: dict[tuple[str, str, str], str] = {root["key"]: root_ref}
    for package_key, package in reachable.items():
        if package_key == root["key"]:
            continue
        component_key = (package["name"], package["version"])
        ref = component_refs.get(component_key)
        if ref is None:
            raise SbomError(f"uv.lock package missing from Python SBOM: {component_key}")
        graph_refs[package_key] = ref
    unused_components = sorted(set(component_refs.values()) - set(graph_refs.values()))
    if unused_components:
        raise SbomError(f"Python SBOM components are unreachable from uv.lock: {unused_components}")

    dependencies = [
        {
            "ref": graph_refs[key],
            "dependsOn": sorted(graph_refs[target] for target in edges.get(key, set())),
        }
        for key in sorted(reachable, key=lambda item: graph_refs[item])
    ]
    edge_count = sum(len(dependency["dependsOn"]) for dependency in dependencies)
    graph_metadata = {
        "one-link:sbom:python-lock-sha256": _sha256_file(lock_path)[0],
        "one-link:sbom:python-package-count": str(len(reachable) - 1),
        "one-link:sbom:python-dependency-edge-count": str(edge_count),
        "one-link:sbom:python-excluded-root-extras": ",".join(sorted(excluded)),
        "one-link:sbom:python-graph-scope": "universal marker-union dependency graph from uv.lock",
    }
    return dependencies, graph_metadata


def _artifact_inventory(
    artifact_dir: Path,
    output_path: Path,
    required_patterns: Sequence[str],
    *,
    allow_finalized_files: bool = False,
    finalized_auxiliary: Sequence[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    if not artifact_dir.is_dir():
        raise SbomError(f"release artifact directory does not exist: {artifact_dir}")
    output_resolved = output_path.resolve()
    entries = sorted(artifact_dir.iterdir(), key=lambda path: path.name)
    files: list[Path] = []
    for path in entries:
        if path.resolve() == output_resolved:
            continue
        if path.name == "SHA256SUMS" or path.name.endswith(".sigstore"):
            if allow_finalized_files:
                continue
            raise SbomError(
                f"SBOM must be generated before checksums/signatures, but found {path.name}"
                )
        if allow_finalized_files and path.name in finalized_auxiliary:
            continue
        if path.is_dir():
            raise SbomError(f"release artifact directory contains a subdirectory: {path}")
        if path.is_symlink():
            raise SbomError(f"refusing symlinked release artifact: {path}")
        if path.is_file():
            files.append(path)
    if not files:
        raise SbomError(f"release artifact directory is empty: {artifact_dir}")

    for pattern in required_patterns:
        if not any(fnmatch.fnmatchcase(path.name, pattern) for path in files):
            raise SbomError(f"release artifact pattern matched no file: {pattern!r}")
    if required_patterns:
        unmatched = [
            path.name
            for path in files
            if not any(fnmatch.fnmatchcase(path.name, pattern) for pattern in required_patterns)
        ]
        if unmatched:
            raise SbomError(f"unclassified release artifacts: {', '.join(unmatched)}")

    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    for path in files:
        digest, size = _sha256_file(path)
        encoded_name = quote(path.name, safe="-._~")
        ref = f"urn:one-link:release-artifact:{encoded_name}:sha256:{digest}"
        component: dict[str, Any] = {
            "type": "file",
            "bom-ref": ref,
            "name": path.name,
            "hashes": [{"alg": "SHA-256", "content": digest}],
        }
        _properties(
            component,
            {
                "one-link:release:artifact": "true",
                "one-link:release:filename": path.name,
                "one-link:release:size-bytes": str(size),
            },
        )
        components.append(component)
        dependencies.append({"ref": ref, "dependsOn": []})

    metadata = {
        "one-link:sbom:release-artifact-count": str(len(components)),
        "one-link:sbom:release-artifact-hash-algorithm": "SHA-256",
    }
    return components, dependencies, metadata


def _property_map(owner: dict[str, Any]) -> dict[str, str]:
    raw = owner.get("properties", [])
    if not isinstance(raw, list):
        raise SbomError("CycloneDX properties must be a list")
    result: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise SbomError("CycloneDX property must be an object")
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            raise SbomError("CycloneDX property must have string name/value")
        if name in result:
            raise SbomError(f"duplicate CycloneDX property: {name}")
        result[name] = value
    return result


def _artifact_fingerprint(component: dict[str, Any]) -> tuple[str, str, int]:
    properties = _property_map(component)
    if properties.get("one-link:release:artifact") != "true":
        raise SbomError("component is not marked as a One Link release artifact")
    name = component.get("name")
    if not isinstance(name, str) or properties.get("one-link:release:filename") != name:
        raise SbomError("release artifact has an inconsistent filename")
    hashes = component.get("hashes")
    if not isinstance(hashes, list):
        raise SbomError(f"release artifact has no hash list: {name}")
    sha256_values = [
        item.get("content")
        for item in hashes
        if isinstance(item, dict) and item.get("alg") == "SHA-256"
    ]
    if len(sha256_values) != 1 or not isinstance(sha256_values[0], str):
        raise SbomError(f"release artifact must have exactly one SHA-256 hash: {name}")
    digest = sha256_values[0]
    if SHA256_RE.fullmatch(digest) is None:
        raise SbomError(f"release artifact has an invalid SHA-256 hash: {name}")
    try:
        size = int(properties["one-link:release:size-bytes"])
    except (KeyError, ValueError) as exc:
        raise SbomError(f"release artifact has an invalid byte size: {name}") from exc
    if size < 0:
        raise SbomError(f"release artifact has a negative byte size: {name}")
    return name, digest, size


def _parse_sha256_manifest(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SbomError(f"cannot read checksum manifest {path}: {exc}") from exc
    if not lines:
        raise SbomError(f"checksum manifest is empty: {path}")
    result: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^\r\n]+)", line)
        if match is None:
            raise SbomError(f"malformed SHA256SUMS entry: {line!r}")
        digest, name = match.groups()
        if name in result:
            raise SbomError(f"duplicate SHA256SUMS entry: {name}")
        if Path(name).name != name or name in {".", ".."}:
            raise SbomError(f"unsafe SHA256SUMS filename: {name!r}")
        result[name] = digest
    return result


def verify_release_inventory(
    sbom_path: Path,
    artifact_dir: Path,
    artifact_patterns: Sequence[str],
    checksum_manifest: Path,
    checksum_auxiliary: Sequence[str] = (),
) -> None:
    """Re-hash the finalized unsigned payload and prove all views agree.

    ``checksum_auxiliary`` names finalized release metadata that cannot be a
    component of the SBOM without creating a digest cycle.  Each name is
    constrained to a direct regular-file child of ``artifact_dir`` and is
    nevertheless required to appear exactly in ``SHA256SUMS``.
    """

    auxiliary_names: set[str] = set()
    for name in checksum_auxiliary:
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name in {".", "..", sbom_path.name, checksum_manifest.name}
            or name in auxiliary_names
        ):
            raise SbomError(f"unsafe or duplicate checksum auxiliary filename: {name!r}")
        auxiliary_names.add(name)

    try:
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read release SBOM {sbom_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise SbomError("release SBOM is not a JSON object")
    _strict_schema_validate(_canonical_json(document))

    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise SbomError("release SBOM components must be a list")
    expected: dict[str, tuple[str, int]] = {}
    for component in raw_components:
        if not isinstance(component, dict):
            raise SbomError("release SBOM component must be an object")
        properties = _property_map(component)
        if properties.get("one-link:release:artifact") != "true":
            continue
        name, digest, size = _artifact_fingerprint(component)
        if name in expected:
            raise SbomError(f"duplicate release artifact in SBOM: {name}")
        expected[name] = (digest, size)
    if not expected:
        raise SbomError("release SBOM contains no release artifact components")

    actual_components, _, _ = _artifact_inventory(
        artifact_dir,
        sbom_path,
        artifact_patterns,
        allow_finalized_files=True,
        finalized_auxiliary=tuple(sorted(auxiliary_names)),
    )
    actual = {
        name: (digest, size)
        for name, digest, size in map(_artifact_fingerprint, actual_components)
    }
    if expected != actual:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )
        raise SbomError(
            "release artifacts do not match SBOM "
            f"(missing={missing}, extra={extra}, changed={changed})"
        )

    checksums = _parse_sha256_manifest(checksum_manifest)
    expected_checksums = {name: digest for name, (digest, _) in expected.items()}
    sbom_digest, _ = _sha256_file(sbom_path)
    expected_checksums[sbom_path.name] = sbom_digest
    for name in sorted(auxiliary_names):
        if name in expected_checksums:
            raise SbomError(f"checksum auxiliary duplicates SBOM artifact: {name!r}")
        auxiliary = artifact_dir / name
        try:
            digest, size = _sha256_file(auxiliary)
        except OSError as exc:
            raise SbomError(f"cannot hash checksum auxiliary {name}: {exc}") from exc
        if size <= 0:
            raise SbomError(f"checksum auxiliary is empty: {name}")
        expected_checksums[name] = digest
    if checksums != expected_checksums:
        missing = sorted(set(expected_checksums) - set(checksums))
        extra = sorted(set(checksums) - set(expected_checksums))
        changed = sorted(
            name
            for name in set(expected_checksums) & set(checksums)
            if expected_checksums[name] != checksums[name]
        )
        raise SbomError(
            "SHA256SUMS does not match SBOM/release bytes "
            f"(missing={missing}, extra={extra}, changed={changed})"
        )


def _component_ref(component: dict[str, Any]) -> str:
    ref = component.get("bom-ref")
    if not isinstance(ref, str) or not ref:
        raise SbomError(f"CycloneDX component has no bom-ref: {component!r}")
    return ref


def _merge_components(bom: dict[str, Any], additions: Iterable[dict[str, Any]]) -> None:
    current = bom.setdefault("components", [])
    if not isinstance(current, list) or not all(isinstance(item, dict) for item in current):
        raise SbomError("CycloneDX components must be a list of objects")
    by_ref = {_component_ref(component): component for component in current}
    if len(by_ref) != len(current):
        raise SbomError("CycloneDX base document has duplicate component references")
    for component in additions:
        ref = _component_ref(component)
        if ref in by_ref:
            raise SbomError(f"component reference collision while merging SBOM: {ref}")
        by_ref[ref] = component
    bom["components"] = [by_ref[ref] for ref in sorted(by_ref)]


def _merge_dependencies(bom: dict[str, Any], additions: Iterable[dict[str, Any]]) -> None:
    current = bom.setdefault("dependencies", [])
    if not isinstance(current, list) or not all(isinstance(item, dict) for item in current):
        raise SbomError("CycloneDX dependencies must be a list of objects")
    by_ref: dict[str, set[str]] = {}
    for dependency in [*current, *additions]:
        ref = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(ref, str) or not ref:
            raise SbomError(f"CycloneDX dependency has no ref: {dependency!r}")
        if not isinstance(depends_on, list) or not all(
            isinstance(target, str) and target for target in depends_on
        ):
            raise SbomError(f"CycloneDX dependency {ref!r} has invalid targets")
        by_ref.setdefault(ref, set()).update(depends_on)
    bom["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(by_ref[ref])}
        for ref in sorted(by_ref)
    ]


def _known_component_refs(bom: dict[str, Any]) -> set[str]:
    components = bom.get("components", [])
    known = {_component_ref(component) for component in components}
    metadata = bom.get("metadata")
    if isinstance(metadata, dict):
        root_component = metadata.get("component")
        if isinstance(root_component, dict):
            known.add(_component_ref(root_component))
    return known


def _validate_references(bom: dict[str, Any]) -> None:
    known = _known_component_refs(bom)
    for dependency in bom.get("dependencies", []):
        ref = dependency["ref"]
        if ref not in known:
            raise SbomError(f"dependency graph refers to an unknown component: {ref}")
        for target in dependency.get("dependsOn", []):
            if target not in known:
                raise SbomError(f"dependency graph refers to an unknown target: {target}")


def _canonical_json(bom: dict[str, Any]) -> str:
    return json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _strict_schema_validate(rendered: str) -> None:
    """Validate after merging, using the already locked CycloneDX library."""

    schema_module = importlib.import_module("cyclonedx.schema")
    validator_module = importlib.import_module("cyclonedx.validation.json")
    schema_version = getattr(schema_module.SchemaVersion, "V1_6")
    validator = validator_module.JsonStrictValidator(schema_version)
    errors = validator.validate_str(rendered, all_errors=True)
    if errors is None:
        return
    messages = [str(error) for error in errors]
    preview = "; ".join(messages[:5])
    raise SbomError(f"merged CycloneDX document failed schema validation: {preview}")


def augment_sbom(
    bom: dict[str, Any],
    *,
    requirements_lock: Path | None = None,
    python_lock: Path | None = None,
    excluded_python_extras: Sequence[str] = (),
    cargo_lock: Path | None = None,
    cargo_workspace: Path | None = None,
    additional_cargo: Sequence[tuple[str, Path]] = (),
    artifact_dir: Path | None = None,
    artifact_patterns: Sequence[str] = (),
    output_path: Path,
) -> dict[str, Any]:
    """Merge offline release inputs into a CycloneDX 1.6 document."""

    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        raise SbomError("base document must be CycloneDX JSON spec 1.6")
    if (cargo_lock is None) != (cargo_workspace is None):
        raise SbomError("--cargo-lock and --cargo-workspace must be provided together")
    graph_names = {"native"}
    for name, _ in additional_cargo:
        if re.fullmatch(r"[a-z][a-z0-9_-]*", name) is None or name in graph_names:
            raise SbomError(f"invalid or duplicate Cargo graph name: {name!r}")
        graph_names.add(name)
    if artifact_patterns and artifact_dir is None:
        raise SbomError("artifact patterns require --artifacts-dir")

    metadata = bom.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise SbomError("CycloneDX metadata must be an object")
    metadata_additions: dict[str, str] = {
        "one-link:sbom:inventory-scope": (
            "selected frozen Python and Cargo dependency graphs, including build/test packages; "
            "exact release artifact bytes when supplied; not per-artifact runtime reachability"
        )
    }
    if requirements_lock is not None:
        metadata_additions["one-link:sbom:python-requirements-sha256"] = _sha256_file(
            requirements_lock
        )[0]
        metadata_additions["one-link:sbom:python-scope"] = (
            "complete frozen uv export across declared extras and dependency groups; "
            "local native path represented by Cargo.lock"
        )

    added_components: list[dict[str, Any]] = []
    added_dependencies: list[dict[str, Any]] = []
    if python_lock is not None:
        dependencies, python_metadata = _python_lock_graph(
            python_lock,
            bom,
            excluded_python_extras,
        )
        added_dependencies.extend(dependencies)
        metadata_additions.update(python_metadata)
    if cargo_lock is not None and cargo_workspace is not None:
        components, dependencies, cargo_metadata = _cargo_inventory(cargo_lock, cargo_workspace)
        added_components.extend(components)
        added_dependencies.extend(dependencies)
        metadata_additions.update(cargo_metadata)
    for name, manifest in additional_cargo:
        components, dependencies, cargo_metadata = _cargo_inventory(
            manifest.with_name("Cargo.lock"), manifest
        )
        # A registry package can have different resolved edges in independent
        # lockfiles. Keep each graph's BOM identities distinct while retaining
        # its standard package URL; merging edges would invent a resolution
        # that no build actually used.
        refs = {
            component["bom-ref"]: f"urn:one-link:cargo-graph:{name}:"
            + quote(component["bom-ref"], safe="")
            for component in components
        }
        for component in components:
            component["bom-ref"] = refs[component["bom-ref"]]
            _properties(component, {"one-link:cargo:graph": name})
        for dependency in dependencies:
            dependency["ref"] = refs[dependency["ref"]]
            dependency["dependsOn"] = sorted(refs[ref] for ref in dependency["dependsOn"])
        added_components.extend(components)
        added_dependencies.extend(dependencies)
        metadata_additions.update({
            key.replace("one-link:sbom:cargo-", f"one-link:sbom:cargo-graph:{name}:", 1): value
            for key, value in cargo_metadata.items()
        })
    if artifact_dir is not None:
        components, dependencies, artifact_metadata = _artifact_inventory(
            artifact_dir,
            output_path,
            artifact_patterns,
        )
        added_components.extend(components)
        added_dependencies.extend(dependencies)
        metadata_additions.update(artifact_metadata)

    _properties(metadata, metadata_additions)
    _merge_components(bom, added_components)
    _merge_dependencies(bom, added_dependencies)
    _validate_references(bom)

    # cyclonedx-bom's reproducible mode omits wall-clock/random identifiers.
    # Bind the BOM serial deterministically to the complete merged inventory.
    bom.pop("serialNumber", None)
    inventory_digest = hashlib.sha256(_canonical_json(bom).encode("utf-8")).hexdigest()
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid5(SBOM_NAMESPACE, inventory_digest)}"
    return bom


def _cyclonedx_command(
    source: str,
    requirements_lock: Path,
    pyproject: Path,
    output_path: Path,
) -> list[str]:
    common = [
        "--pyproject",
        str(pyproject),
        "--mc-type",
        "application",
        "--spec-version",
        CYCLONEDX_SPEC_VERSION,
        "--output-reproducible",
        "--output-format",
        "JSON",
        "--output-file",
        str(output_path),
    ]
    if source == "requirements":
        return [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            str(requirements_lock),
            *common,
        ]
    return [sys.executable, "-m", "cyclonedx_py", "environment", *common]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="output path (default: dist/sbom.cdx.json)")
    parser.add_argument(
        "--from",
        dest="source",
        default="environment",
        choices=["environment", "requirements"],
        help="generate the Python base from the current environment or a frozen requirements file",
    )
    parser.add_argument(
        "--requirements",
        default="requirements.lock",
        help="frozen requirements input (default: requirements.lock)",
    )
    parser.add_argument("--python-lock", help="uv.lock supplying the exact Python dependency graph")
    parser.add_argument(
        "--exclude-python-extra",
        action="append",
        default=[],
        help="root uv extra excluded from the exported graph; repeat as needed",
    )
    parser.add_argument("--cargo-lock", help="Cargo.lock to merge")
    parser.add_argument("--cargo-workspace", help="workspace Cargo.toml to merge")
    parser.add_argument(
        "--additional-cargo", action="append", nargs=2, default=[],
        metavar=("NAME", "MANIFEST"),
        help="named independent Cargo manifest and its sibling lockfile; repeat as needed",
    )
    parser.add_argument("--artifacts-dir", help="directory containing final release artifacts")
    parser.add_argument(
        "--artifact-pattern",
        action="append",
        default=[],
        help="required artifact glob; repeat to require and classify every release file",
    )
    parser.add_argument(
        "--verify-release-sbom",
        help="verify an existing SBOM against final artifacts and SHA256SUMS without regenerating",
    )
    parser.add_argument("--checksum-manifest", help="SHA256SUMS input for verification mode")
    parser.add_argument(
        "--checksum-auxiliary",
        action="append",
        default=[],
        help=(
            "finalized metadata file covered by SHA256SUMS but intentionally "
            "excluded from the SBOM component graph; repeat as needed"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _project_root()
    output = _absolute(root, args.output or "dist/sbom.cdx.json")
    requirements = _absolute(root, args.requirements)
    pyproject = root / "pyproject.toml"
    python_lock = _absolute(root, args.python_lock) if args.python_lock else None
    cargo_lock = _absolute(root, args.cargo_lock) if args.cargo_lock else None
    cargo_workspace = _absolute(root, args.cargo_workspace) if args.cargo_workspace else None
    artifact_dir = _absolute(root, args.artifacts_dir) if args.artifacts_dir else None

    if args.verify_release_sbom:
        if artifact_dir is None or not args.checksum_manifest:
            print(
                "SBOM verification requires --artifacts-dir and --checksum-manifest",
                file=sys.stderr,
            )
            return 2
        try:
            verify_release_inventory(
                _absolute(root, args.verify_release_sbom),
                artifact_dir,
                args.artifact_pattern,
                _absolute(root, args.checksum_manifest),
                args.checksum_auxiliary,
            )
        except (OSError, SbomError) as exc:
            print(f"SBOM verification failed: {exc}", file=sys.stderr)
            return 2
        print("Release SBOM, artifacts, and SHA256SUMS match exactly")
        return 0

    if args.source == "requirements" and not requirements.is_file():
        print(
            f"frozen requirements input does not exist: {requirements}",
            file=sys.stderr,
        )
        return 2
    if args.source == "requirements":
        try:
            _validate_frozen_requirements(requirements)
        except SbomError as exc:
            print(f"SBOM generation failed: {exc}", file=sys.stderr)
            return 2
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="one-link-sbom-") as temporary:
            temporary_path = Path(temporary)
            base_path = temporary_path / "python-base.cdx.json"
            command = _cyclonedx_command(args.source, requirements, pyproject, base_path)
            print("$ " + subprocess.list2cmdline(command))
            result = subprocess.run(command, check=False)
            if result.returncode != 0:
                return result.returncode
            try:
                base = json.loads(base_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SbomError(f"cyclonedx-bom produced invalid JSON: {exc}") from exc
            if not isinstance(base, dict):
                raise SbomError("cyclonedx-bom output is not a JSON object")

            augmented = augment_sbom(
                base,
                requirements_lock=requirements if args.source == "requirements" else None,
                python_lock=python_lock,
                excluded_python_extras=args.exclude_python_extra,
                cargo_lock=cargo_lock,
                cargo_workspace=cargo_workspace,
                additional_cargo=[
                    (name, _absolute(root, manifest)) for name, manifest in args.additional_cargo
                ],
                artifact_dir=artifact_dir,
                artifact_patterns=args.artifact_pattern,
                output_path=output,
            )
            rendered = _canonical_json(augmented)
            _strict_schema_validate(rendered)
            descriptor, staged_name = tempfile.mkstemp(
                prefix=".sbom.cdx.",
                suffix=".tmp",
                dir=output.parent,
            )
            os.close(descriptor)
            staged_output = Path(staged_name)
            try:
                staged_output.write_text(rendered, encoding="utf-8", newline="\n")
                os.replace(staged_output, output)
            finally:
                staged_output.unlink(missing_ok=True)
    except (OSError, SbomError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 2

    print(f"SBOM written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
