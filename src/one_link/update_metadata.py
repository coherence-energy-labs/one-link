"""Strict authenticated metadata contract for standalone One Link updates.

GitHub's release JSON is discovery data, not update authority.  The authority
consumed here is ``UPDATE_MANIFEST.json`` *after* its Sigstore bundle has been
verified against the exact tagged ``release.yml`` workflow identity.  This
module deliberately performs no network I/O and no signature verification;
callers must establish that boundary before parsing these bytes.

The signed document binds an immutable source commit, monotonically ordered
rollback index, bounded validity window, complete supported-platform matrix,
and the exact digest/size/layout of each standalone ZIP.  Unknown fields are
rejected so a producer cannot silently add security-significant semantics that
an older client ignores.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import platform
import re
from typing import Mapping

from packaging.version import InvalidVersion, Version


UPDATE_METADATA_SCHEMA = "one-link-update-manifest/v1"
UPDATE_REPOSITORY = "coherence-energy-labs/one-link"
UPDATE_WORKFLOW = ".github/workflows/release.yml"
UPDATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
UPDATE_METADATA_FILENAME = "UPDATE_MANIFEST.json"
UPDATE_METADATA_BUNDLE_FILENAME = "UPDATE_MANIFEST.json.sigstore"
MAX_UPDATE_METADATA_BYTES = 4 * 1024 * 1024
MAX_STANDALONE_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_METADATA_VALIDITY = timedelta(days=190)
MAX_CLOCK_SKEW = timedelta(minutes=10)
MIN_AUTHORITY_TIME = datetime(2025, 1, 1, tzinfo=UTC)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class UpdateMetadataError(ValueError):
    """Authenticated update metadata is malformed or violates policy."""


@dataclass(frozen=True)
class PlatformContract:
    key: str
    filename: str
    executable: str
    bundle_root: str = "one-link"


PLATFORM_CONTRACTS: Mapping[str, PlatformContract] = {
    "windows-x86_64": PlatformContract(
        "windows-x86_64",
        "one-link-windows-x86_64.zip",
        "one-link.exe",
    ),
    "windows-arm64": PlatformContract(
        "windows-arm64",
        "one-link-windows-arm64.zip",
        "one-link.exe",
    ),
    "linux-x86_64": PlatformContract(
        "linux-x86_64",
        "one-link-linux-x86_64.zip",
        "one-link",
    ),
    "linux-arm64": PlatformContract(
        "linux-arm64",
        "one-link-linux-arm64.zip",
        "one-link",
    ),
    "macos-arm64": PlatformContract(
        "macos-arm64",
        "one-link-macos-arm64.zip",
        "Contents/MacOS/one-link",
        bundle_root="one-link.app",
    ),
}


@dataclass(frozen=True)
class StandaloneArtifact:
    platform: str
    filename: str
    size: int
    sha256: str
    bundle_root: str
    executable: str
    kind: str


@dataclass(frozen=True)
class ReleaseEvidence:
    filename: str
    size: int
    sha256: str


@dataclass(frozen=True)
class AuthenticatedUpdateManifest:
    tag: str
    version: Version
    commit_sha: str
    rollback_index: int
    minimum_source_version: Version
    created_at: datetime
    expires_at: datetime
    repository: str
    workflow: str
    oidc_issuer: str
    sbom: ReleaseEvidence
    artifacts: Mapping[str, StandaloneArtifact]
    authenticated_metadata_sha256: str

    def artifact_for(self, platform_key: str) -> StandaloneArtifact:
        try:
            return self.artifacts[platform_key]
        except KeyError as exc:
            raise UpdateMetadataError(
                f"signed update has no artifact for {platform_key}"
            ) from exc


def _exact_keys(value: Mapping[str, object], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise UpdateMetadataError(
            f"{label} fields differ from schema (missing={missing}, unknown={unknown})"
        )


def _bounded_text(value: object, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise UpdateMetadataError(f"{label} must be non-empty bounded text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise UpdateMetadataError(f"{label} contains a control character")
    return value


def _positive_size(value: object, *, label: str) -> int:
    if type(value) is not int or not (0 < value <= MAX_STANDALONE_ARTIFACT_BYTES):
        raise UpdateMetadataError(f"{label} has an invalid byte size")
    return value


def _digest(value: object, *, label: str) -> str:
    text = _bounded_text(value, label=label, maximum=64)
    if not _HEX_64.fullmatch(text):
        raise UpdateMetadataError(f"{label} is not canonical lowercase SHA-256")
    return text


def _parse_utc(value: object, *, label: str) -> datetime:
    text = _bounded_text(value, label=label, maximum=32)
    if not _UTC_TIMESTAMP.fullmatch(text):
        raise UpdateMetadataError(f"{label} must be second-precision UTC with Z suffix")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise UpdateMetadataError(f"{label} is not a real UTC timestamp") from exc
    return parsed


def _stable_version(value: object, *, label: str) -> Version:
    text = _bounded_text(value, label=label, maximum=128)
    try:
        parsed = Version(text)
    except InvalidVersion as exc:
        raise UpdateMetadataError(f"{label} is not a valid version") from exc
    if parsed.epoch or parsed.pre or parsed.post or parsed.dev or parsed.local:
        raise UpdateMetadataError(f"{label} must be a stable public release version")
    if len(parsed.release) != 3:
        raise UpdateMetadataError(f"{label} must contain exactly major.minor.patch")
    return parsed


def canonical_update_metadata_bytes(document: Mapping[str, object]) -> bytes:
    """Return the only accepted producer serialization for signed metadata."""

    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise UpdateMetadataError("update metadata cannot be canonically encoded") from exc
    if len(encoded) > MAX_UPDATE_METADATA_BYTES:
        raise UpdateMetadataError("update metadata exceeds its byte budget")
    return encoded


def host_platform_key(
    *,
    system: str | None = None,
    machine: str | None = None,
) -> str:
    """Map the running OS/architecture to the release workflow's exact key."""

    os_name = (system or platform.system()).strip().lower()
    architecture = (machine or platform.machine()).strip().lower()
    if architecture in {"amd64", "x86_64", "x64"}:
        arch = "x86_64"
    elif architecture in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise UpdateMetadataError(f"unsupported update architecture: {architecture or 'empty'}")
    if os_name == "windows":
        key = f"windows-{arch}"
    elif os_name == "linux":
        key = f"linux-{arch}"
    elif os_name in {"darwin", "macos"}:
        key = f"macos-{arch}"
    else:
        raise UpdateMetadataError(f"unsupported update operating system: {os_name or 'empty'}")
    if key not in PLATFORM_CONTRACTS:
        raise UpdateMetadataError(f"unsupported standalone update target: {key}")
    return key


def parse_authenticated_update_manifest(
    raw: bytes,
    *,
    verified_tag: str,
    now: datetime | None = None,
) -> AuthenticatedUpdateManifest:
    """Parse metadata only after its exact-tag Sigstore check has succeeded.

    ``verified_tag`` is an explicit input from the signature verification
    ceremony.  Matching a tag found inside the document is not sufficient.
    """

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_UPDATE_METADATA_BYTES:
        raise UpdateMetadataError("signed update metadata is empty or oversized")
    if not _TAG.fullmatch(str(verified_tag)):
        raise UpdateMetadataError("verified release tag is not a stable canonical tag")
    try:
        decoded = raw.decode("utf-8", "strict")
        document = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateMetadataError("signed update metadata is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise UpdateMetadataError("signed update metadata root is not an object")
    canonical = canonical_update_metadata_bytes(document)
    if raw != canonical:
        raise UpdateMetadataError("signed update metadata is not canonically serialized")
    _exact_keys(
        document,
        {
            "schema",
            "tag",
            "version",
            "rollback_index",
            "minimum_source_version",
            "created_at",
            "expires_at",
            "source",
            "sbom",
            "artifacts",
        },
        label="update metadata",
    )
    if document["schema"] != UPDATE_METADATA_SCHEMA:
        raise UpdateMetadataError("unsupported update metadata schema")

    tag = _bounded_text(document["tag"], label="tag", maximum=128)
    if tag != verified_tag or not _TAG.fullmatch(tag):
        raise UpdateMetadataError("signed tag does not match the verified Sigstore identity")
    version = _stable_version(document["version"], label="version")
    if tag != f"v{version}":
        raise UpdateMetadataError("signed version does not exactly match signed tag")
    minimum_source = _stable_version(
        document["minimum_source_version"],
        label="minimum_source_version",
    )
    rollback_index = document["rollback_index"]
    if type(rollback_index) is not int or not (0 < rollback_index < 2**63):
        raise UpdateMetadataError("rollback_index must be a positive signed 64-bit integer")

    source = document["source"]
    if not isinstance(source, dict):
        raise UpdateMetadataError("source provenance is not an object")
    _exact_keys(
        source,
        {"repository", "workflow", "oidc_issuer", "commit_sha", "ref"},
        label="source provenance",
    )
    repository = _bounded_text(source["repository"], label="source.repository")
    workflow = _bounded_text(source["workflow"], label="source.workflow")
    oidc_issuer = _bounded_text(source["oidc_issuer"], label="source.oidc_issuer")
    commit_sha = _bounded_text(source["commit_sha"], label="source.commit_sha", maximum=40)
    source_ref = _bounded_text(source["ref"], label="source.ref", maximum=160)
    if repository != UPDATE_REPOSITORY:
        raise UpdateMetadataError("signed update repository is not the canonical repository")
    if workflow != UPDATE_WORKFLOW:
        raise UpdateMetadataError("signed update workflow is not the release authority")
    if oidc_issuer != UPDATE_OIDC_ISSUER:
        raise UpdateMetadataError("signed update OIDC issuer is not trusted")
    if not _COMMIT_SHA.fullmatch(commit_sha):
        raise UpdateMetadataError("signed source commit is not a full lowercase Git SHA")
    if source_ref != f"refs/tags/{tag}":
        raise UpdateMetadataError("signed source ref does not match the release tag")

    created_at = _parse_utc(document["created_at"], label="created_at")
    expires_at = _parse_utc(document["expires_at"], label="expires_at")
    observed = now or datetime.now(tz=UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise UpdateMetadataError("update verification clock must be timezone-aware")
    observed = observed.astimezone(UTC)
    if created_at < MIN_AUTHORITY_TIME:
        raise UpdateMetadataError("signed metadata creation time predates update authority")
    if created_at > observed + MAX_CLOCK_SKEW:
        raise UpdateMetadataError("signed metadata creation time is in the future")
    if expires_at <= created_at:
        raise UpdateMetadataError("signed metadata expiry does not follow creation")
    if expires_at - created_at > MAX_METADATA_VALIDITY:
        raise UpdateMetadataError("signed metadata validity window is excessive")
    if observed >= expires_at:
        raise UpdateMetadataError("signed update metadata has expired")

    sbom_value = document["sbom"]
    if not isinstance(sbom_value, dict):
        raise UpdateMetadataError("SBOM evidence is not an object")
    _exact_keys(sbom_value, {"filename", "size", "sha256"}, label="SBOM evidence")
    sbom_filename = _bounded_text(sbom_value["filename"], label="sbom.filename")
    if sbom_filename != "sbom.cdx.json":
        raise UpdateMetadataError("signed SBOM filename is not canonical")
    sbom = ReleaseEvidence(
        filename=sbom_filename,
        size=_positive_size(sbom_value["size"], label="sbom.size"),
        sha256=_digest(sbom_value["sha256"], label="sbom.sha256"),
    )

    artifacts_value = document["artifacts"]
    if not isinstance(artifacts_value, list):
        raise UpdateMetadataError("artifacts must be a complete ordered list")
    artifacts: dict[str, StandaloneArtifact] = {}
    filenames: set[str] = set()
    for index, entry in enumerate(artifacts_value):
        if not isinstance(entry, dict):
            raise UpdateMetadataError(f"artifact {index} is not an object")
        _exact_keys(
            entry,
            {"platform", "filename", "size", "sha256", "bundle_root", "executable", "kind"},
            label=f"artifact {index}",
        )
        platform_key = _bounded_text(entry["platform"], label=f"artifact {index}.platform")
        if platform_key in artifacts:
            raise UpdateMetadataError(f"duplicate artifact platform: {platform_key}")
        try:
            contract = PLATFORM_CONTRACTS[platform_key]
        except KeyError as exc:
            raise UpdateMetadataError(f"unsupported artifact platform: {platform_key}") from exc
        filename = _bounded_text(entry["filename"], label=f"artifact {index}.filename")
        executable = _bounded_text(entry["executable"], label=f"artifact {index}.executable")
        bundle_root = _bounded_text(entry["bundle_root"], label=f"artifact {index}.bundle_root")
        kind = _bounded_text(entry["kind"], label=f"artifact {index}.kind")
        if filename != contract.filename or filename in filenames:
            raise UpdateMetadataError(f"artifact filename violates platform contract: {filename}")
        if executable != contract.executable:
            raise UpdateMetadataError(f"artifact executable violates platform contract: {filename}")
        # Retain legacy signed one-link layouts. New macOS releases use .app;
        # the extractor still requires exact equality with this signed value.
        if bundle_root not in {"one-link", contract.bundle_root} or kind != "standalone-zip-v1":
            raise UpdateMetadataError(f"artifact layout violates standalone contract: {filename}")
        filenames.add(filename)
        artifacts[platform_key] = StandaloneArtifact(
            platform=platform_key,
            filename=filename,
            size=_positive_size(entry["size"], label=f"artifact {index}.size"),
            sha256=_digest(entry["sha256"], label=f"artifact {index}.sha256"),
            bundle_root=bundle_root,
            executable=executable,
            kind=kind,
        )
    if set(artifacts) != set(PLATFORM_CONTRACTS):
        raise UpdateMetadataError(
            "signed update does not contain the complete supported-platform matrix"
        )

    return AuthenticatedUpdateManifest(
        tag=tag,
        version=version,
        commit_sha=commit_sha,
        rollback_index=rollback_index,
        minimum_source_version=minimum_source,
        created_at=created_at,
        expires_at=expires_at,
        repository=repository,
        workflow=workflow,
        oidc_issuer=oidc_issuer,
        sbom=sbom,
        artifacts=artifacts,
        authenticated_metadata_sha256=hashlib.sha256(raw).hexdigest(),
    )


def rollback_index_for_version(version: str | Version) -> int:
    """Derive the release producer's stable monotonic 16-bit tuple index."""

    parsed = _stable_version(str(version), label="version")
    major, minor, patch = parsed.release
    if any(component > 0xFFFF for component in (major, minor, patch)):
        raise UpdateMetadataError("version component exceeds rollback-index encoding")
    # Low 16 bits are reserved for a future signed emergency rebuild counter.
    return (major << 48) | (minor << 32) | (patch << 16)


__all__ = [
    "AuthenticatedUpdateManifest",
    "MAX_UPDATE_METADATA_BYTES",
    "PLATFORM_CONTRACTS",
    "PlatformContract",
    "ReleaseEvidence",
    "StandaloneArtifact",
    "UPDATE_METADATA_BUNDLE_FILENAME",
    "UPDATE_METADATA_FILENAME",
    "UPDATE_METADATA_SCHEMA",
    "UpdateMetadataError",
    "canonical_update_metadata_bytes",
    "host_platform_key",
    "parse_authenticated_update_manifest",
    "rollback_index_for_version",
]
