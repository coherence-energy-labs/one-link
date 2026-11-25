"""Generate deterministic signed-authority input for standalone updates.

The output is not trusted merely because this script produced it.  The tagged
release workflow must checksum it, sign it with Sigstore under the exact tag,
attest it, and publish it beside every asset named here.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
import stat
import sys

from packaging.version import InvalidVersion, Version


REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from one_link.update_metadata import (  # noqa: E402
    PLATFORM_CONTRACTS,
    UPDATE_METADATA_FILENAME,
    UPDATE_METADATA_SCHEMA,
    UPDATE_OIDC_ISSUER,
    UPDATE_REPOSITORY,
    UPDATE_WORKFLOW,
    canonical_update_metadata_bytes,
    rollback_index_for_version,
)


class ManifestGenerationError(RuntimeError):
    """Release inputs cannot produce safe standalone update authority."""


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _hash_stable_regular_file(path: Path) -> tuple[str, int]:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ManifestGenerationError(f"release input is absent or unreadable: {path}") from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise ManifestGenerationError(f"release input is not a non-empty regular file: {path}")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ManifestGenerationError(f"release input cannot be opened safely: {path}") from exc
    try:
        opened = os.fstat(fd)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            count += len(block)
            digest.update(block)
        opened_after = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise ManifestGenerationError(f"release input changed while hashing: {path}") from exc
    identities = {
        (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns)
        for entry in (before, opened, opened_after, after)
    }
    if _is_link_or_reparse(after) or len(identities) != 1 or count != before.st_size:
        raise ManifestGenerationError(f"release input changed while hashing: {path}")
    return digest.hexdigest(), count


def _stable_version(value: str, *, label: str) -> Version:
    try:
        version = Version(value)
    except InvalidVersion as exc:
        raise ManifestGenerationError(f"{label} is not a valid version") from exc
    if (
        str(version) != value
        or len(version.release) != 3
        or version.epoch
        or version.pre
        or version.post
        or version.dev
        or version.local
    ):
        raise ManifestGenerationError(f"{label} must be canonical stable major.minor.patch")
    return version


def build_update_document(
    *,
    dist_dir: Path,
    tag: str,
    commit_sha: str,
    source_date_epoch: int,
    minimum_source_version: str,
    validity_days: int = 180,
) -> dict[str, object]:
    dist = Path(dist_dir).resolve(strict=True)
    if not dist.is_dir():
        raise ManifestGenerationError("distribution path is not a directory")
    if not tag.startswith("v"):
        raise ManifestGenerationError("release tag must start with v")
    version = _stable_version(tag[1:], label="release tag version")
    minimum = _stable_version(minimum_source_version, label="minimum source version")
    if minimum > version:
        raise ManifestGenerationError("minimum source version exceeds candidate version")
    if (
        len(commit_sha) != 40
        or commit_sha.lower() != commit_sha
        or any(character not in "0123456789abcdef" for character in commit_sha)
    ):
        raise ManifestGenerationError("commit SHA must be 40 lowercase hexadecimal characters")
    if type(source_date_epoch) is not int or source_date_epoch <= 0:
        raise ManifestGenerationError("source-date epoch must be a positive integer")
    if type(validity_days) is not int or not (1 <= validity_days <= 180):
        raise ManifestGenerationError("metadata validity must be between 1 and 180 days")
    created = datetime.fromtimestamp(source_date_epoch, tz=UTC).replace(microsecond=0)
    if created < datetime(2025, 1, 1, tzinfo=UTC):
        raise ManifestGenerationError("release source time predates update authority")
    expires = created + timedelta(days=validity_days)

    artifacts: list[dict[str, object]] = []
    for platform_key, contract in PLATFORM_CONTRACTS.items():
        digest, size = _hash_stable_regular_file(dist / contract.filename)
        artifacts.append(
            {
                "platform": platform_key,
                "filename": contract.filename,
                "size": size,
                "sha256": digest,
                "bundle_root": contract.bundle_root,
                "executable": contract.executable,
                "kind": "standalone-zip-v1",
            }
        )
    sbom_digest, sbom_size = _hash_stable_regular_file(dist / "sbom.cdx.json")
    return {
        "schema": UPDATE_METADATA_SCHEMA,
        "tag": tag,
        "version": str(version),
        "rollback_index": rollback_index_for_version(version),
        "minimum_source_version": str(minimum),
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "repository": UPDATE_REPOSITORY,
            "workflow": UPDATE_WORKFLOW,
            "oidc_issuer": UPDATE_OIDC_ISSUER,
            "commit_sha": commit_sha,
            "ref": f"refs/tags/{tag}",
        },
        "sbom": {
            "filename": "sbom.cdx.json",
            "size": sbom_size,
            "sha256": sbom_digest,
        },
        "artifacts": artifacts,
    }


def write_update_manifest(output: Path, document: dict[str, object]) -> Path:
    destination = Path(output).absolute()
    if destination.name != UPDATE_METADATA_FILENAME:
        raise ManifestGenerationError(f"output must be named {UPDATE_METADATA_FILENAME}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_update_metadata_bytes(document)
    if destination.exists():
        existing = destination.read_bytes()
        if existing != payload:
            raise ManifestGenerationError("existing update manifest differs; refusing replacement")
        return destination
    temporary = destination.with_name(f".{destination.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(fd, view[written:])
                if count <= 0:
                    raise ManifestGenerationError("short write while generating update manifest")
                written += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, destination)
        if os.name != "nt":
            destination.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)
    if destination.read_bytes() != payload:
        raise ManifestGenerationError("generated update manifest failed exact read-back")
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--minimum-source-version", required=True)
    parser.add_argument("--validity-days", type=int, default=180)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    output = args.output or args.dist_dir / UPDATE_METADATA_FILENAME
    try:
        document = build_update_document(
            dist_dir=args.dist_dir,
            tag=args.tag,
            commit_sha=args.commit_sha,
            source_date_epoch=args.source_date_epoch,
            minimum_source_version=args.minimum_source_version,
            validity_days=args.validity_days,
        )
        written = write_update_manifest(output, document)
    except (ManifestGenerationError, OSError, ValueError) as exc:
        print(f"UPDATE MANIFEST: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"UPDATE MANIFEST: PASS: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
