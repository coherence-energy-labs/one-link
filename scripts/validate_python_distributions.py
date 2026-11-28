#!/usr/bin/env python3
"""Validate the exact wheel and sdist that a One Link release will publish.

The gate is intentionally independent of code inside the built distribution.
It compares archive bytes with the reviewed source contract, verifies wheel
RECORD integrity and archive safety, rebuilds a wheel from the exact sdist,
and probes both wheels from clean isolated virtual environments.
"""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
from collections import Counter
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unicodedata
import zipfile

from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version


MAX_ARCHIVE_ENTRIES = 16_384
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
SUBPROCESS_TIMEOUT_SECONDS = 300
REQUIRED_SDIST_BUILD_INPUTS = (
    "LICENSE",
    "LICENSE-NOTICE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "README.md",
    "pyproject.toml",
    "setup.py",
)
_NATIVE_SUFFIXES = (".dll", ".dylib", ".pyd", ".so")


class GateFailure(RuntimeError):
    """A release distribution violated its fail-closed contract."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


class SourceContract:
    """Immutable source-side inputs against which archives are measured."""

    def __init__(
        self,
        *,
        source_root: Path,
        version: Version,
        modules: tuple[str, ...],
        runtime_module_manifest_sha256: str,
        package_data: tuple[str, ...],
        package_data_manifest_sha256: str,
        payload_hashes: dict[str, str],
        sdist_input_hashes: dict[str, str],
        requires_python: str | None,
        license_expression: str | None,
        license_files: tuple[str, ...],
        requirements: tuple[Requirement, ...],
        provides_extras: tuple[str, ...],
    ) -> None:
        self.source_root = source_root
        self.version = version
        self.modules = modules
        self.runtime_module_manifest_sha256 = runtime_module_manifest_sha256
        self.package_data = package_data
        self.package_data_manifest_sha256 = package_data_manifest_sha256
        self.payload_hashes = payload_hashes
        self.sdist_input_hashes = sdist_input_hashes
        self.requires_python = requires_python
        self.license_expression = license_expression
        self.license_files = license_files
        self.requirements = requirements
        self.provides_extras = provides_extras


class ArchiveView:
    """Canonical regular-file bytes from one already safety-checked archive."""

    def __init__(self, entries: dict[str, bytes], *, top_level: str | None = None) -> None:
        self.entries = entries
        self.top_level = top_level


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_link_like(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(reparse and attributes & reparse)


def _require_source_file(path: Path, *, label: str) -> None:
    if _is_link_like(path):
        raise GateFailure(f"source contract entry is link-like or unreadable: {label}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise GateFailure(f"source contract entry is missing: {label}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise GateFailure(f"source contract entry is not a regular file: {label}")


def _source_version(source_root: Path) -> Version:
    pyproject = source_root / "pyproject.toml"
    try:
        import tomllib

        with pyproject.open("rb") as stream:
            value = tomllib.load(stream)["project"]["version"]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise GateFailure("could not read project.version from pyproject.toml") from exc
    try:
        expected = Version(str(value))
    except ValueError as exc:
        raise GateFailure(f"project.version is not valid PEP 440: {value!r}") from exc

    init_path = source_root / "src" / "one_link" / "__init__.py"
    try:
        tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    except (OSError, SyntaxError) as exc:
        raise GateFailure("could not parse one_link.__version__") from exc
    declared: str | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in targets
        ):
            continue
        value_node = node.value
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            declared = value_node.value
            break
    try:
        declared_version = Version(declared) if declared is not None else None
    except ValueError as exc:
        raise GateFailure(f"one_link.__version__ is not valid PEP 440: {declared!r}") from exc
    if declared_version != expected:
        raise GateFailure(f"source version mismatch: pyproject={expected}, one_link={declared!r}")
    return expected


def _load_source_build_identity(source_root: Path) -> types.ModuleType:
    path = source_root / "src" / "one_link" / "build_identity.py"
    spec = importlib.util.spec_from_file_location(
        "_one_link_distribution_source_contract",
        path,
    )
    if spec is None or spec.loader is None:
        raise GateFailure(f"could not load source build identity: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise GateFailure(f"source build identity failed to load: {exc}") from exc
    return module


def _source_project_metadata(
    source_root: Path,
) -> tuple[str | None, str | None, tuple[str, ...], tuple[Requirement, ...], tuple[str, ...]]:
    try:
        import tomllib

        with (source_root / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)["project"]
        requires_python_value = project.get("requires-python")
        requires_python = (
            str(requires_python_value) if requires_python_value is not None else None
        )
        license_value = project.get("license")
        license_expression = str(license_value) if license_value is not None else None
        raw_license_files = project.get("license-files", [])
        license_files = tuple(str(value) for value in raw_license_files)
        base_requirements = [Requirement(str(value)) for value in project.get("dependencies", [])]
        optional = project.get("optional-dependencies", {})
    except (OSError, KeyError, TypeError, ValueError, InvalidRequirement) as exc:
        raise GateFailure("could not read static project metadata from pyproject.toml") from exc
    if license_expression is not None and not isinstance(license_value, str):
        raise GateFailure("project.license must be a PEP 639 SPDX expression string")
    if tuple(sorted(set(license_files))) != license_files:
        raise GateFailure("project.license-files must be sorted and unique")
    if not isinstance(optional, dict):
        raise GateFailure("project.optional-dependencies must be a table")

    requirements = list(base_requirements)
    extras: list[str] = []
    try:
        for raw_extra, raw_requirements in optional.items():
            extra = canonicalize_name(str(raw_extra))
            extras.append(extra)
            if not isinstance(raw_requirements, list):
                raise GateFailure(f"optional dependency group is not a list: {raw_extra!r}")
            for value in raw_requirements:
                requirement = Requirement(str(value))
                extra_marker = f'extra == "{extra}"'
                marker = (
                    f"({requirement.marker}) and {extra_marker}"
                    if requirement.marker is not None
                    else extra_marker
                )
                requirement.marker = Marker(marker)
                requirements.append(requirement)
    except (InvalidRequirement, ValueError) as exc:
        raise GateFailure("project dependency metadata is not valid PEP 508") from exc
    if len(set(extras)) != len(extras):
        raise GateFailure("optional dependency names collide after normalization")
    return (
        requires_python,
        license_expression,
        license_files,
        tuple(requirements),
        tuple(extras),
    )


def _framed_manifest_sha256(domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain)
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def load_source_contract(source_root: Path) -> SourceContract:
    """Load and independently hash the reviewed source distribution contract."""
    root = source_root.expanduser().resolve()
    package_root = root / "src" / "one_link"
    identity = _load_source_build_identity(root)
    try:
        modules = tuple(identity.EXPECTED_STABLE_RUNTIME_MODULES)
        module_digest = str(identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256)
        package_data = tuple(identity.EXPECTED_STABLE_PACKAGE_DATA)
        data_digest = str(identity.EXPECTED_STABLE_PACKAGE_DATA_SHA256)
        source_path_for = identity.stable_module_source_path
    except (AttributeError, TypeError) as exc:
        raise GateFailure("build_identity omits the distribution contract") from exc

    if modules != tuple(sorted(set(modules))):
        raise GateFailure("stable runtime module contract is not sorted and unique")
    if package_data != tuple(sorted(set(package_data))):
        raise GateFailure("stable package-data contract is not sorted and unique")
    if len(module_digest) != 64 or len(data_digest) != 64:
        raise GateFailure("source contract contains an invalid manifest digest")
    independent_module_digest = _framed_manifest_sha256(
        b"ONE-LINK-STABLE-RUNTIME-MODULES-V1\x00",
        modules,
    )
    independent_data_digest = _framed_manifest_sha256(
        b"ONE-LINK-STABLE-PACKAGE-DATA-V1\x00",
        package_data,
    )
    if module_digest != independent_module_digest:
        raise GateFailure("stable runtime module manifest digest is stale")
    if data_digest != independent_data_digest:
        raise GateFailure("stable package-data manifest digest is stale")

    stable_source_names: set[str] = set()
    for module in modules:
        try:
            path = Path(source_path_for(package_root, module))
        except (TypeError, ValueError) as exc:
            raise GateFailure(f"invalid stable module mapping: {module}") from exc
        _require_source_file(path, label=module)
        try:
            relative = path.relative_to(package_root).as_posix()
        except ValueError as exc:
            raise GateFailure(f"stable module escaped package root: {module}") from exc
        archive_name = f"one_link/{relative}"
        if archive_name in stable_source_names:
            raise GateFailure(f"stable modules collide at {archive_name}")
        stable_source_names.add(archive_name)

    # The stable runtime manifest is deliberately narrower than the source
    # distribution: engineering helpers and the opt-in semantic-codec preview
    # remain importable from a source/wheel install. Hash every shipped Python
    # file, not only the stable standalone subset, so an unexpected or stale
    # executable module cannot hide beside an otherwise valid contract.
    payload_hashes: dict[str, str] = {}
    for walk_root, directory_names, file_names in os.walk(
        package_root,
        followlinks=False,
    ):
        current = Path(walk_root)
        safe_directories: list[str] = []
        for name in directory_names:
            child = current / name
            if _is_link_like(child):
                raise GateFailure(f"source package directory is link-like: {child}")
            if name != "__pycache__":
                safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in file_names:
            if not name.endswith(".py"):
                continue
            path = current / name
            relative = path.relative_to(package_root).as_posix()
            _require_source_file(path, label=relative)
            payload_hashes[f"one_link/{relative}"] = _sha256_file(path)
    if not stable_source_names <= set(payload_hashes):
        raise GateFailure(
            "stable runtime contract contains non-distributed source paths: "
            f"{sorted(stable_source_names - set(payload_hashes))!r}"
        )

    expected_data = set(package_data)
    discovered_data: set[str] = set()
    for subtree in ("data", "web"):
        directory = package_root / subtree
        if not directory.is_dir() or _is_link_like(directory):
            raise GateFailure(f"source package-data directory is unsafe: {directory}")
        for path in directory.rglob("*"):
            if path.is_dir():
                if _is_link_like(path):
                    raise GateFailure(f"source package-data directory is link-like: {path}")
                continue
            relative = path.relative_to(package_root).as_posix()
            _require_source_file(path, label=relative)
            discovered_data.add(relative)
    if discovered_data != expected_data:
        raise GateFailure(
            "package-data manifest differs from source tree: "
            f"missing={sorted(expected_data - discovered_data)!r}, "
            f"unexpected={sorted(discovered_data - expected_data)!r}"
        )
    for relative in package_data:
        path = package_root / PurePosixPath(relative)
        archive_name = f"one_link/{relative}"
        if archive_name in payload_hashes:
            raise GateFailure(f"module/data contract collision at {archive_name}")
        payload_hashes[archive_name] = _sha256_file(path)

    sdist_input_hashes: dict[str, str] = {}
    for relative in REQUIRED_SDIST_BUILD_INPUTS:
        path = root / relative
        _require_source_file(path, label=relative)
        sdist_input_hashes[relative] = _sha256_file(path)

    (
        requires_python,
        license_expression,
        license_files,
        requirements,
        provides_extras,
    ) = _source_project_metadata(root)
    return SourceContract(
        source_root=root,
        version=_source_version(root),
        modules=modules,
        runtime_module_manifest_sha256=module_digest,
        package_data=package_data,
        package_data_manifest_sha256=data_digest,
        payload_hashes=payload_hashes,
        sdist_input_hashes=sdist_input_hashes,
        requires_python=requires_python,
        license_expression=license_expression,
        license_files=license_files,
        requirements=requirements,
        provides_extras=provides_extras,
    )


def _canonical_archive_name(raw_name: str, *, directory: bool) -> str:
    if not raw_name or "\\" in raw_name or "\x00" in raw_name:
        raise GateFailure(f"archive contains an unsafe member name: {raw_name!r}")
    if unicodedata.normalize("NFC", raw_name) != raw_name:
        raise GateFailure(f"archive member is not NFC-normalized: {raw_name!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_name):
        raise GateFailure(f"archive member contains control characters: {raw_name!r}")
    name = raw_name[:-1] if directory and raw_name.endswith("/") else raw_name
    if not name or name.startswith("/") or "//" in name:
        raise GateFailure(f"archive contains an unsafe member name: {raw_name!r}")
    pieces = name.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces) or ":" in pieces[0]:
        raise GateFailure(f"archive member escapes its root: {raw_name!r}")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise GateFailure(f"archive member is absolute: {raw_name!r}")
    return path.as_posix()


def _register_archive_name(
    name: str,
    *,
    directory: bool,
    exact: set[str],
    folded: dict[str, str],
    kinds: dict[str, str],
) -> None:
    if name in exact:
        raise GateFailure(f"archive contains a duplicate member: {name}")
    exact.add(name)
    for parent_length in range(1, len(name.split("/"))):
        parent = "/".join(name.split("/")[:parent_length])
        if kinds.get(parent) == "file":
            raise GateFailure(
                f"archive file is also an ancestor of another member: {parent}, {name}"
            )
    if not directory and any(existing.startswith(f"{name}/") for existing in kinds):
        raise GateFailure(f"archive file collides with a member subtree: {name}")
    kinds[name] = "directory" if directory else "file"
    pieces = name.split("/")
    for length in range(1, len(pieces) + 1):
        prefix = "/".join(pieces[:length])
        key = unicodedata.normalize("NFC", prefix).casefold()
        prior = folded.get(key)
        if prior is not None and prior != prefix:
            raise GateFailure(f"archive contains case/Unicode-colliding paths: {prior}, {prefix}")
        folded[key] = prefix


def read_wheel(path: Path) -> ArchiveView:
    """Read one wheel while rejecting unsafe or ambiguous ZIP structure."""
    entries: dict[str, bytes] = {}
    exact: set[str] = set()
    folded: dict[str, str] = {}
    kinds: dict[str, str] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise GateFailure(f"wheel has too many entries: {len(infos)}")
            for info in infos:
                directory = info.is_dir()
                name = _canonical_archive_name(info.filename, directory=directory)
                _register_archive_name(
                    name,
                    directory=directory,
                    exact=exact,
                    folded=folded,
                    kinds=kinds,
                )
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK:
                    raise GateFailure(f"wheel contains a symbolic link: {name}")
                if directory:
                    continue
                if file_type not in {0, stat.S_IFREG}:
                    raise GateFailure(f"wheel contains a non-regular entry: {name}")
                if info.flag_bits & 0x1:
                    raise GateFailure(f"wheel contains an encrypted entry: {name}")
                if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise GateFailure(f"wheel member exceeds size limit: {name}")
                total += info.file_size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise GateFailure("wheel uncompressed payload exceeds size limit")
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    raise GateFailure(f"wheel member size changed while reading: {name}")
                entries[name] = payload
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, GateFailure):
            raise
        raise GateFailure(f"could not read wheel {path}: {exc}") from exc
    return ArchiveView(entries)


def read_sdist(path: Path) -> ArchiveView:
    """Read one sdist while rejecting traversal, links, and special files."""
    entries: dict[str, bytes] = {}
    exact: set[str] = set()
    folded: dict[str, str] = {}
    kinds: dict[str, str] = {}
    top_levels: set[str] = set()
    total = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                raise GateFailure(f"sdist has too many entries: {len(members)}")
            for member in members:
                name = _canonical_archive_name(member.name, directory=member.isdir())
                _register_archive_name(
                    name,
                    directory=member.isdir(),
                    exact=exact,
                    folded=folded,
                    kinds=kinds,
                )
                top_levels.add(name.split("/", 1)[0])
                if member.isdir():
                    continue
                if not member.isfile():
                    raise GateFailure(f"sdist contains a link or special entry: {name}")
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise GateFailure(f"sdist member exceeds size limit: {name}")
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise GateFailure("sdist payload exceeds size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise GateFailure(f"could not read sdist member: {name}")
                payload = stream.read()
                if len(payload) != member.size:
                    raise GateFailure(f"sdist member size changed while reading: {name}")
                entries[name] = payload
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, GateFailure):
            raise
        raise GateFailure(f"could not read sdist {path}: {exc}") from exc
    if len(top_levels) != 1:
        raise GateFailure(f"sdist must have exactly one top-level directory: {sorted(top_levels)}")
    return ArchiveView(entries, top_level=next(iter(top_levels)))


def _validate_wheel_record(entries: dict[str, bytes]) -> None:
    record_names = [name for name in entries if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise GateFailure(f"wheel must contain exactly one RECORD: {record_names!r}")
    record_name = record_names[0]
    try:
        text = entries[record_name].decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise GateFailure("wheel RECORD is not valid UTF-8 CSV") from exc
    recorded: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            raise GateFailure(f"wheel RECORD row does not have three fields: {row!r}")
        name = _canonical_archive_name(row[0], directory=False)
        if name in recorded:
            raise GateFailure(f"wheel RECORD duplicates {name}")
        recorded[name] = (row[1], row[2])
    if set(recorded) != set(entries):
        raise GateFailure(
            "wheel RECORD keys differ from archive: "
            f"missing={sorted(set(entries) - set(recorded))!r}, "
            f"unexpected={sorted(set(recorded) - set(entries))!r}"
        )
    for name, payload in entries.items():
        digest_field, size_field = recorded[name]
        if name == record_name:
            if digest_field or size_field:
                raise GateFailure("wheel RECORD must leave its own hash and size empty")
            continue
        try:
            algorithm, encoded = digest_field.split("=", 1)
        except ValueError as exc:
            raise GateFailure(f"wheel RECORD omits a digest for {name}") from exc
        if algorithm != "sha256":
            raise GateFailure(f"wheel RECORD uses non-SHA256 digest for {name}")
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        try:
            encoded_bytes = encoded.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise GateFailure(f"wheel RECORD digest is not ASCII for {name}") from exc
        if encoded_bytes != expected:
            raise GateFailure(f"wheel RECORD digest mismatch for {name}")
        if size_field != str(len(payload)):
            raise GateFailure(f"wheel RECORD size mismatch for {name}")


def _metadata_headers(payload: bytes, *, label: str) -> dict[str, list[str]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateFailure(f"{label} is not UTF-8") from exc
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line:
            break
        if line[:1].isspace():
            raise GateFailure(f"{label} contains an unsupported folded header")
        key, separator, value = line.partition(":")
        if not separator:
            raise GateFailure(f"{label} contains a malformed header: {line!r}")
        headers.setdefault(key.strip().lower(), []).append(value.strip())
    return headers


def _require_metadata_identity(payload: bytes, contract: SourceContract, *, label: str) -> None:
    headers = _metadata_headers(payload, label=label)
    if headers.get("metadata-version") != ["2.4"]:
        raise GateFailure(f"{label} does not use Metadata-Version 2.4")
    names = headers.get("name", [])
    versions = headers.get("version", [])
    if len(names) != 1 or canonicalize_name(names[0]) != "one-link":
        raise GateFailure(f"{label} has the wrong distribution name: {names!r}")
    try:
        parsed_versions = [Version(value) for value in versions]
    except ValueError as exc:
        raise GateFailure(f"{label} has an invalid version: {versions!r}") from exc
    if parsed_versions != [contract.version]:
        raise GateFailure(f"{label} version differs from source: {versions!r}")
    expected_requires_python = (
        [contract.requires_python] if contract.requires_python is not None else []
    )
    actual_requires_python = headers.get("requires-python", [])
    try:
        requires_python_matches = (
            len(actual_requires_python) == len(expected_requires_python)
            and all(
                SpecifierSet(actual) == SpecifierSet(expected)
                for actual, expected in zip(
                    actual_requires_python,
                    expected_requires_python,
                    strict=True,
                )
            )
        )
    except InvalidSpecifier as exc:
        raise GateFailure(f"{label} has invalid Requires-Python metadata") from exc
    if not requires_python_matches:
        raise GateFailure(
            f"{label} Requires-Python differs from source: {actual_requires_python!r}"
        )
    expected_license = (
        [contract.license_expression] if contract.license_expression is not None else []
    )
    if headers.get("license-expression", []) != expected_license:
        raise GateFailure(f"{label} License-Expression differs from source")
    if tuple(headers.get("license-file", [])) != contract.license_files:
        raise GateFailure(f"{label} License-File entries differ from source")
    actual_extras = tuple(
        canonicalize_name(value) for value in headers.get("provides-extra", [])
    )
    if actual_extras != contract.provides_extras:
        raise GateFailure(f"{label} Provides-Extra entries differ from source")
    try:
        actual_requirements = tuple(
            Requirement(value) for value in headers.get("requires-dist", [])
        )
    except InvalidRequirement as exc:
        raise GateFailure(f"{label} has invalid Requires-Dist metadata") from exc
    if Counter(actual_requirements) != Counter(contract.requirements):
        raise GateFailure(f"{label} Requires-Dist entries differ from source")


def _assert_payload_hashes(
    entries: dict[str, bytes],
    expected: dict[str, str],
    *,
    prefix: str,
    label: str,
    exact_namespace: str | None = None,
) -> None:
    missing: list[str] = []
    mismatched: list[str] = []
    for relative, digest in expected.items():
        archive_name = f"{prefix}{relative}"
        payload = entries.get(archive_name)
        if payload is None:
            missing.append(relative)
        elif _sha256_bytes(payload) != digest:
            mismatched.append(relative)
    unexpected: list[str] = []
    if exact_namespace is not None:
        namespace = f"{prefix}{exact_namespace}"
        expected_names = {f"{prefix}{relative}" for relative in expected}
        unexpected = sorted(
            name.removeprefix(prefix)
            for name in entries
            if name.startswith(namespace) and name not in expected_names
        )
    if missing or mismatched or unexpected:
        raise GateFailure(
            f"{label} differs from source contract: "
            f"missing={missing!r}, digest_mismatch={mismatched!r}, "
            f"unexpected={unexpected!r}"
        )


def _require_console_entry_points(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8", errors="strict")
        parser = _CaseSensitiveConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise GateFailure("wheel entry_points.txt is invalid") from exc
    sections = parser.sections()
    if sections != ["console_scripts"]:
        raise GateFailure(f"wheel has unexpected entry-point groups: {sections!r}")
    entries = dict(parser.items("console_scripts"))
    if entries != {"one-link": "one_link.cli:main"}:
        raise GateFailure(f"wheel console entry points differ from source: {entries!r}")


def validate_wheel(path: Path, contract: SourceContract) -> ArchiveView:
    """Validate one universal core wheel against source and wheel standards."""
    try:
        distribution, version, _build, tags = parse_wheel_filename(path.name)
    except ValueError as exc:
        raise GateFailure(f"invalid wheel filename: {path.name}") from exc
    if canonicalize_name(distribution) != "one-link" or version != contract.version:
        raise GateFailure(f"wheel filename identity differs from source: {path.name}")
    if {str(tag) for tag in tags} != {"py3-none-any"}:
        raise GateFailure(f"core wheel is not exactly py3-none-any: {path.name}")

    view = read_wheel(path)
    entries = view.entries
    _validate_wheel_record(entries)
    dist_infos = {
        name.split("/", 1)[0]
        for name in entries
        if "/" in name and name.split("/", 1)[0].endswith(".dist-info")
    }
    if len(dist_infos) != 1:
        raise GateFailure(f"wheel must contain exactly one dist-info directory: {dist_infos!r}")
    dist_info = next(iter(dist_infos))
    expected_dist_info = f"one_link-{contract.version}.dist-info"
    if dist_info != expected_dist_info:
        raise GateFailure(
            f"wheel dist-info directory differs from source: {dist_info!r}"
        )
    metadata_name = f"{dist_info}/METADATA"
    wheel_name = f"{dist_info}/WHEEL"
    entry_points_name = f"{dist_info}/entry_points.txt"
    for required in (metadata_name, wheel_name, entry_points_name):
        if required not in entries:
            raise GateFailure(f"wheel omits required metadata file: {required}")
    expected_dist_info_entries = {
        metadata_name,
        wheel_name,
        entry_points_name,
        f"{dist_info}/top_level.txt",
        f"{dist_info}/RECORD",
        *(f"{dist_info}/licenses/{name}" for name in contract.license_files),
    }
    expected_wheel_entries = set(contract.payload_hashes) | expected_dist_info_entries
    if set(entries) != expected_wheel_entries:
        raise GateFailure(
            "wheel regular-file layout differs from the exact distribution contract: "
            f"missing={sorted(expected_wheel_entries - set(entries))!r}, "
            f"unexpected={sorted(set(entries) - expected_wheel_entries)!r}"
        )
    _require_metadata_identity(entries[metadata_name], contract, label="wheel METADATA")
    wheel_headers = _metadata_headers(entries[wheel_name], label="wheel WHEEL")
    if wheel_headers.get("root-is-purelib") != ["true"]:
        raise GateFailure("core wheel does not declare Root-Is-Purelib: true")
    if wheel_headers.get("wheel-version") != ["1.0"]:
        raise GateFailure(
            f"core wheel metadata has invalid Wheel-Version: "
            f"{wheel_headers.get('wheel-version')!r}"
        )
    if wheel_headers.get("tag") != ["py3-none-any"]:
        raise GateFailure(f"core wheel metadata has invalid tags: {wheel_headers.get('tag')!r}")
    _require_console_entry_points(entries[entry_points_name])
    if entries[f"{dist_info}/top_level.txt"] != b"one_link\n":
        raise GateFailure("wheel top_level.txt differs from the one_link package")
    for name in contract.license_files:
        source_digest = contract.sdist_input_hashes.get(name)
        if source_digest is None:
            raise GateFailure(f"wheel license is outside the source contract: {name}")
        if _sha256_bytes(entries[f"{dist_info}/licenses/{name}"]) != source_digest:
            raise GateFailure(f"wheel license bytes differ from source: {name}")

    native_entries = sorted(
        name
        for name in entries
        if name.startswith("one_link/native/") or name.lower().endswith(_NATIVE_SUFFIXES)
    )
    if native_entries:
        raise GateFailure(f"universal core wheel contains native binaries: {native_entries!r}")
    _assert_payload_hashes(
        entries,
        contract.payload_hashes,
        prefix="",
        label="wheel payload",
        exact_namespace="one_link/",
    )
    return view


def validate_sdist(path: Path, contract: SourceContract) -> ArchiveView:
    """Validate one source archive against the exact source byte contract."""
    try:
        distribution, version = parse_sdist_filename(path.name)
    except ValueError as exc:
        raise GateFailure(f"invalid sdist filename: {path.name}") from exc
    if canonicalize_name(distribution) != "one-link" or version != contract.version:
        raise GateFailure(f"sdist filename identity differs from source: {path.name}")
    view = read_sdist(path)
    if view.top_level is None:
        raise GateFailure("sdist has no top-level directory")
    expected_top_level = f"one_link-{contract.version}"
    if view.top_level != expected_top_level:
        raise GateFailure(
            f"sdist top-level directory differs from source: {view.top_level!r}"
        )
    prefix = f"{view.top_level}/"
    pkg_info = f"{prefix}PKG-INFO"
    if pkg_info not in view.entries:
        raise GateFailure("sdist omits PKG-INFO")
    _require_metadata_identity(view.entries[pkg_info], contract, label="sdist PKG-INFO")
    native_entries = sorted(
        name for name in view.entries if name.lower().endswith(_NATIVE_SUFFIXES)
    )
    if native_entries:
        raise GateFailure(f"core sdist contains platform-native binaries: {native_entries!r}")
    egg_info = f"{prefix}src/one_link.egg-info"
    expected_egg_info_entries = {
        f"{egg_info}/PKG-INFO",
        f"{egg_info}/SOURCES.txt",
        f"{egg_info}/dependency_links.txt",
        f"{egg_info}/entry_points.txt",
        f"{egg_info}/requires.txt",
        f"{egg_info}/top_level.txt",
    }
    expected_sdist_entries = {
        pkg_info,
        f"{prefix}setup.cfg",
        *(f"{prefix}{name}" for name in contract.sdist_input_hashes),
        *(f"{prefix}src/{name}" for name in contract.payload_hashes),
        *expected_egg_info_entries,
    }
    if set(view.entries) != expected_sdist_entries:
        raise GateFailure(
            "sdist regular-file layout differs from the exact distribution contract: "
            f"missing={sorted(expected_sdist_entries - set(view.entries))!r}, "
            f"unexpected={sorted(set(view.entries) - expected_sdist_entries)!r}"
        )
    if view.entries[f"{egg_info}/PKG-INFO"] != view.entries[pkg_info]:
        raise GateFailure("sdist root and egg-info PKG-INFO bytes differ")
    generated_setup_cfg = view.entries[f"{prefix}setup.cfg"].replace(b"\r\n", b"\n")
    if generated_setup_cfg != b"[egg_info]\ntag_build = \ntag_date = 0\n\n":
        raise GateFailure("sdist generated setup.cfg differs from the locked backend contract")
    _require_console_entry_points(view.entries[f"{egg_info}/entry_points.txt"])
    if view.entries[f"{egg_info}/top_level.txt"] != b"one_link\n":
        raise GateFailure("sdist top_level.txt differs from the one_link package")
    _assert_payload_hashes(
        view.entries,
        contract.payload_hashes,
        prefix=f"{prefix}src/",
        label="sdist package payload",
        exact_namespace="one_link/",
    )
    _assert_payload_hashes(
        view.entries,
        contract.sdist_input_hashes,
        prefix=prefix,
        label="sdist build inputs",
    )
    return view


def _clean_environment() -> dict[str, str]:
    allowed = {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        name: value for name, value in os.environ.items() if name.upper() in allowed
    }
    environment["PYTHONNOUSERSITE"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    environment["UV_OFFLINE"] = "1"
    return environment


def _run(command: list[str], *, cwd: Path, label: str) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=_clean_environment(),
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateFailure(f"{label} could not run: {exc}") from exc
    if process.returncode != 0:
        diagnostic = ((process.stdout or "") + "\n" + (process.stderr or "")).strip()
        raise GateFailure(f"{label} exited {process.returncode}: {diagnostic[-3000:]}")
    return process


def _uv_executable() -> str:
    executable = shutil.which("uv")
    if executable is None:
        raise GateFailure("the pinned uv executable is required")
    return str(Path(executable).resolve())


def build_wheel_from_sdist(sdist: Path, output_dir: Path) -> Path:
    """Build a wheel from the exact sdist without network or fresh resolution."""
    output_dir.mkdir(parents=True, exist_ok=False)
    _run(
        [
            _uv_executable(),
            "build",
            "--wheel",
            "--offline",
            "--no-build-isolation",
            "--no-build-logs",
            "--no-create-gitignore",
            "--no-config",
            "--python",
            sys.executable,
            "--out-dir",
            str(output_dir),
            str(sdist.resolve()),
        ],
        cwd=output_dir.parent,
        label="sdist-to-wheel rebuild",
    )
    wheels = sorted(output_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise GateFailure(f"sdist rebuild produced {len(wheels)} wheels: {wheels!r}")
    return wheels[0]


_ISOLATED_PROBE = r"""from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import types

contract_path = Path(sys.argv[1])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
root_spec = importlib.util.find_spec("one_link")
if root_spec is None or root_spec.submodule_search_locations is None:
    raise SystemExit("one_link package root is not importable")
locations = tuple(root_spec.submodule_search_locations)
if len(locations) != 1:
    raise SystemExit(f"one_link has ambiguous package roots: {locations!r}")
package_root = Path(locations[0]).resolve(strict=True)
try:
    package_root.relative_to(Path(sys.prefix).resolve(strict=True))
except ValueError as exc:
    raise SystemExit(f"one_link resolved outside clean venv: {package_root}") from exc

statuses = {}
origins = {}
for module in contract["modules"]:
    try:
        spec = importlib.util.find_spec(module)
    except Exception as exc:
        statuses[module] = f"SPEC_ERROR:{type(exc).__name__}"
        continue
    if spec is None:
        statuses[module] = "MISSING"
        continue
    if spec.name != module or spec.loader is None or not spec.origin:
        statuses[module] = "INVALID_SPEC"
        continue
    try:
        origin = Path(spec.origin).resolve(strict=True)
        origin.relative_to(package_root)
    except (OSError, ValueError):
        statuses[module] = "OUTSIDE_INSTALL"
        continue
    get_code = getattr(spec.loader, "get_code", None)
    if not callable(get_code):
        statuses[module] = "MISSING_CODE_LOADER"
        continue
    try:
        code = get_code(module)
    except Exception as exc:
        statuses[module] = f"UNLOADABLE:{type(exc).__name__}"
        continue
    if not isinstance(code, types.CodeType):
        statuses[module] = "MISSING_CODE"
        continue
    statuses[module] = "PRESENT"
    origins[module] = origin.as_posix()

data_hashes = {}
for relative in contract["package_data"]:
    path = package_root.joinpath(*relative.split("/"))
    try:
        metadata = path.lstat()
    except OSError:
        data_hashes[relative] = "MISSING"
        continue
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    if stat.S_ISLNK(metadata.st_mode) or (reparse and attributes & reparse):
        data_hashes[relative] = "LINK"
        continue
    if not stat.S_ISREG(metadata.st_mode):
        data_hashes[relative] = "NOT_REGULAR"
        continue
    data_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

print(json.dumps({
    "prefix": str(Path(sys.prefix).resolve()),
    "package_root": str(package_root),
    "runtime_modules": statuses,
    "origins": origins,
    "package_data_sha256": data_hashes,
}, sort_keys=True))
"""


def clean_install_probe(
    wheel: Path,
    contract: SourceContract,
    workspace: Path,
    *,
    label: str,
) -> dict[str, object]:
    """Install a wheel without dependencies and independently resolve its code."""
    venv = workspace / "venv"
    probe = workspace / "probe.py"
    contract_file = workspace / "contract.json"
    workspace.mkdir(parents=True, exist_ok=False)
    probe.write_text(_ISOLATED_PROBE, encoding="utf-8", newline="\n")
    contract_file.write_text(
        json.dumps(
            {
                "modules": contract.modules,
                "package_data": contract.package_data,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
        newline="\n",
    )
    uv = _uv_executable()
    _run(
        [
            uv,
            "venv",
            "--python",
            sys.executable,
            "--no-project",
            "--no-config",
            "--offline",
            str(venv),
        ],
        cwd=workspace,
        label=f"{label} clean venv creation",
    )
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            "--no-deps",
            "--no-index",
            "--offline",
            "--no-config",
            str(wheel.resolve()),
        ],
        cwd=workspace,
        label=f"{label} clean wheel install",
    )
    process = _run(
        [str(python), "-I", str(probe), str(contract_file)],
        cwd=workspace,
        label=f"{label} isolated module probe",
    )
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise GateFailure(f"{label} isolated probe returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise GateFailure(f"{label} isolated probe did not return an object")
    statuses = payload.get("runtime_modules")
    if not isinstance(statuses, dict) or set(statuses) != set(contract.modules):
        raise GateFailure(f"{label} isolated probe returned incomplete module keys")
    invalid = sorted(module for module, status in statuses.items() if status != "PRESENT")
    if invalid:
        raise GateFailure(
            f"{label} clean install cannot load stable module code: "
            f"{[(module, statuses[module]) for module in invalid]!r}"
        )
    data_hashes = payload.get("package_data_sha256")
    expected_data_hashes = {
        relative: contract.payload_hashes[f"one_link/{relative}"]
        for relative in contract.package_data
    }
    if data_hashes != expected_data_hashes:
        raise GateFailure(f"{label} clean install package data differs from source")
    return payload


def validate_distributions(dist_dir: Path, source_root: Path) -> dict[str, object]:
    """Validate exact release artifacts and both clean installation paths."""
    requested_directory = dist_dir.expanduser()
    if _is_link_like(requested_directory) or not requested_directory.is_dir():
        raise GateFailure(f"distribution directory is missing or link-like: {dist_dir}")
    directory = requested_directory.resolve()
    contract = load_source_contract(source_root)
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise GateFailure(
            "distribution directory must contain exactly one core wheel and sdist: "
            f"wheels={wheels!r}, sdists={sdists!r}"
        )
    direct_wheel = wheels[0]
    sdist = sdists[0]
    _require_source_file(direct_wheel, label=direct_wheel.name)
    _require_source_file(sdist, label=sdist.name)
    validate_wheel(direct_wheel, contract)
    validate_sdist(sdist, contract)

    with tempfile.TemporaryDirectory(prefix="one-link-python-dist-") as temp_name:
        temporary = Path(temp_name)
        derived_wheel = build_wheel_from_sdist(sdist, temporary / "from-sdist")
        validate_wheel(derived_wheel, contract)
        derived_wheel_name = derived_wheel.name
        derived_wheel_sha256 = _sha256_file(derived_wheel)
        direct_probe = clean_install_probe(
            direct_wheel,
            contract,
            temporary / "direct-install",
            label="direct wheel",
        )
        derived_probe = clean_install_probe(
            derived_wheel,
            contract,
            temporary / "sdist-install",
            label="sdist-derived wheel",
        )

    return {
        "verification_status": "python_distributions_ok",
        "version": str(contract.version),
        "wheel": direct_wheel.name,
        "wheel_bytes": direct_wheel.stat().st_size,
        "wheel_sha256": _sha256_file(direct_wheel),
        "sdist": sdist.name,
        "sdist_bytes": sdist.stat().st_size,
        "sdist_sha256": _sha256_file(sdist),
        "sdist_derived_wheel": derived_wheel_name,
        "sdist_derived_wheel_sha256": derived_wheel_sha256,
        "source_payload_file_count": len(contract.payload_hashes),
        "source_python_file_count": sum(
            name.endswith(".py") for name in contract.payload_hashes
        ),
        "declared_requirement_count": len(contract.requirements),
        "declared_extra_count": len(contract.provides_extras),
        "stable_runtime_module_count": len(contract.modules),
        "stable_runtime_module_manifest_sha256": (contract.runtime_module_manifest_sha256),
        "stable_package_data_count": len(contract.package_data),
        "stable_package_data_manifest_sha256": contract.package_data_manifest_sha256,
        "direct_install_root": direct_probe["package_root"],
        "sdist_install_root": derived_probe["package_root"],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        required=True,
        help="directory containing exactly one core wheel and one sdist",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="reviewed One Link source root (defaults to this checkout)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_arg_parser().parse_args(argv)
    try:
        result = validate_distributions(arguments.dist_dir, arguments.source_root)
    except GateFailure as exc:
        if arguments.json:
            print(json.dumps({"verification_status": "failed", "error": str(exc)}))
        else:
            print(f"[python-distributions] FAIL: {exc}", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "[python-distributions] PASS: "
            f"{result['stable_runtime_module_count']} stable modules and "
            f"{result['stable_package_data_count']} package-data files verified "
            "in the exact wheel, sdist, and two clean installs"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
