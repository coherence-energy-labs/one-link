"""Crash-safe A/B-style replacement for authenticated standalone updates.

This module begins *after* :mod:`one_link.updater` has authenticated a release
artifact and :mod:`one_link.update_metadata` has parsed its signed authority.
It never downloads data and never trusts filenames, paths, versions, or hashes
supplied by a UI request.

The transaction is a same-filesystem directory exchange with a durable,
MAC-authenticated write-ahead journal:

1. validate the currently managed bundle and the authenticated ZIP;
2. safely extract and re-hash the complete candidate into a private sibling;
3. after an identity-bound parent-process exit, move current -> backup;
4. move candidate -> current and launch through the existing stable path;
5. accept a post-restart health marker only from the exact candidate tree;
6. advance the authenticated rollback high-water mark, then retire the backup.

Every rename boundary is journaled.  Recovery either resumes the bounded
health window or restores the previously validated bundle.  Ambiguous path
states fail closed and preserve evidence instead of guessing which tree to
delete.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import posixpath
import re
import secrets
import shutil
import stat
import subprocess
import time
from typing import Any, Callable, Iterator, Mapping, cast
import unicodedata
import zipfile

from packaging.version import InvalidVersion, Version

from one_link.key_material import (
    KeyMaterialError,
    atomic_create_bytes,
    atomic_replace_bytes,
    read_bytes_if_exists,
)
from one_link.update_metadata import (
    AuthenticatedUpdateManifest,
    MAX_STANDALONE_ARTIFACT_BYTES,
    StandaloneArtifact,
)


STATE_SCHEMA = "one-link-update-state/v1"
JOURNAL_KIND = "transaction-journal"
HIGH_WATER_KIND = "rollback-high-water"
HEALTH_KIND = "post-restart-health"
JOURNAL_FILENAME = "update-transaction.auth.json"
HIGH_WATER_FILENAME = "update-high-water.auth.json"
HEALTH_FILENAME = "update-health.auth.json"
LOCK_FILENAME = "update-transaction.lock"
AUTHORITY_FILENAME = "update-authority.key.wrapped"
MAX_STATE_BYTES = 2 * 1024 * 1024
DEFAULT_HEALTH_WINDOW = timedelta(minutes=3)
MAX_HEALTH_WINDOW = timedelta(minutes=15)
MAX_HISTORY_BINDINGS = 4096
ARCHIVE_MANIFEST = "one-link/BUNDLE_SHA256SUMS"
ARCHIVE_MANIFEST_HEADER = "# sha256\tkind\tbytes\tpath\ttarget"
MAX_ARCHIVE_MANIFEST_BYTES = 8 * 1024 * 1024
BLOCK_SIZE = 1024 * 1024

_TXID = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_WINDOWS_RESERVED = frozenset(
    {"CLOCK$", "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class UpdateTransactionError(RuntimeError):
    """Base class for a transaction that cannot safely continue."""


class UpdatePathError(UpdateTransactionError):
    """A managed path is unsafe, ambiguous, or outside its authority."""


class UpdateArchiveError(UpdateTransactionError):
    """The authenticated archive violates the standalone bundle contract."""


class UpdateStateError(UpdateTransactionError):
    """Durable update state is malformed, unauthenticated, or inconsistent."""


class UpdateRollbackError(UpdateTransactionError):
    """The candidate violates the rollback/version high-water policy."""


class UpdateProcessStillRunning(UpdateTransactionError):
    """The exact process instance that owns the installed tree is still live."""


class TransactionPhase(StrEnum):
    PREPARED = "prepared"
    BACKUP_INTENT = "backup_intent"
    BACKUP_CREATED = "backup_created"
    ACTIVATE_INTENT = "activate_intent"
    CANDIDATE_ACTIVE = "candidate_active"
    HEALTH_ACCEPTED = "health_accepted"
    HIGH_WATER_COMMITTED = "high_water_committed"
    COMMITTED = "committed"
    ROLLBACK_INTENT = "rollback_intent"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    instance_token: str
    executable: str


@dataclass(frozen=True)
class ProcessGuard:
    pid: int
    instance_token: str
    executable: str


@dataclass(frozen=True)
class BundleTree:
    root: Path
    manifest_sha256: str
    executable_sha256: str
    file_count: int
    payload_bytes: int


@dataclass(frozen=True)
class UpdateJournal:
    phase: str
    txid: str
    tag: str
    version: str
    commit_sha: str
    rollback_index: int
    artifact_filename: str
    artifact_size: int
    artifact_sha256: str
    metadata_sha256: str
    platform: str
    expected_executable: str
    install_root: str
    state_root: str
    stage_container: str
    backup_root: str
    failed_root: str
    candidate_manifest_sha256: str
    previous_manifest_sha256: str
    health_nonce: str
    health_deadline: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class HighWaterBinding:
    tag: str
    version: str
    rollback_index: int
    commit_sha: str
    artifact_sha256: str
    metadata_sha256: str


@dataclass(frozen=True)
class UpdateHighWater:
    maximum_version: str
    maximum_rollback_index: int
    bindings: tuple[HighWaterBinding, ...]


@dataclass(frozen=True)
class RecoveryResult:
    status: str
    phase: str | None
    txid: str | None
    detail: str


FaultHook = Callable[[str], None]
HealthProbe = Callable[[Path], bool]
IdentityReader = Callable[[int], ProcessIdentity | None]


def _noop_fault(_point: str) -> None:
    return None


def acquire_update_state_authority(state_root: Path, lockbox) -> bytes:
    """Load/create the stable updater MAC key protected by One Link's LockBox.

    The key is deliberately independent from the identity/master seed so an
    identity rotation does not erase rollback history.  Its persisted envelope
    is protected by the stable application DEK and published with no-replace
    semantics; malformed or undecryptable existing bytes never mint a new key.
    """

    from one_link.lockbox import LockBox, LockBoxError

    if not isinstance(lockbox, LockBox):
        raise TypeError("lockbox must be a one_link.lockbox.LockBox")
    root = _absolute_lexical(Path(state_root), label="state_root")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    _assert_no_link_ancestors(root, label="state_root", include_leaf=True)
    path = root / AUTHORITY_FILENAME

    def _unwrap(payload: bytes) -> bytes:
        try:
            key = lockbox.unwrap(payload)
        except (LockBoxError, ValueError, TypeError) as exc:
            raise UpdateStateError("wrapped update authority failed authentication") from exc
        if len(key) != 32:
            raise UpdateStateError("wrapped update authority has an invalid key length")
        return key

    try:
        existing = read_bytes_if_exists(
            path,
            label="wrapped update authority",
            max_bytes=4096,
        )
    except KeyMaterialError as exc:
        raise UpdateStateError("cannot safely read wrapped update authority") from exc
    if existing is not None:
        return _unwrap(existing)
    fresh = secrets.token_bytes(32)
    wrapped = lockbox.wrap(fresh)

    def _validate(candidate: bytes) -> None:
        recovered = _unwrap(candidate)
        if not hmac.compare_digest(recovered, fresh):
            raise UpdateStateError("published update authority differs from generated key")

    try:
        created = atomic_create_bytes(
            path,
            wrapped,
            label="wrapped update authority",
            validate=_validate,
        )
    except KeyMaterialError as exc:
        raise UpdateStateError("cannot durably publish wrapped update authority") from exc
    if created:
        return fresh
    try:
        winner = read_bytes_if_exists(
            path,
            label="wrapped update authority",
            max_bytes=4096,
        )
    except KeyMaterialError as exc:
        raise UpdateStateError("cannot read concurrent update authority winner") from exc
    if winner is None:
        raise UpdateStateError("concurrent update authority winner is absent")
    return _unwrap(winner)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise UpdateStateError("transaction time must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str, *, label: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise UpdateStateError(f"{label} is not canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise UpdateStateError(f"{label} is not a real UTC time") from exc


def _canonical_json(value: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise UpdateStateError("update state is not canonically serializable") from exc
    if len(encoded) > MAX_STATE_BYTES:
        raise UpdateStateError("update state exceeds its byte budget")
    return encoded


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _path_exists_no_follow(path: Path) -> bool:
    """Return false only for a proven-absent path, including broken links."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise UpdatePathError(f"cannot inspect managed update path: {path}") from exc
    return True


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(directory, flags)
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise UpdateStateError(f"cannot open directory for durability sync: {directory}") from exc
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise UpdateStateError(
                    f"cannot durably sync update directory: {directory}"
                ) from exc
    finally:
        os.close(fd)


def _absolute_lexical(path: Path, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise UpdatePathError(f"{label} must be absolute")
    normalized = Path(os.path.abspath(candidate))
    if normalized != candidate:
        raise UpdatePathError(f"{label} must be lexically normalized")
    if normalized == Path(normalized.anchor):
        raise UpdatePathError(f"{label} must not be a filesystem root")
    return normalized


def _assert_no_link_ancestors(path: Path, *, label: str, include_leaf: bool) -> None:
    candidate = _absolute_lexical(path, label=label)
    chain = list(reversed(candidate.parents))
    if include_leaf:
        chain.append(candidate)
    for entry in chain:
        try:
            metadata = os.lstat(entry)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise UpdatePathError(f"cannot inspect {label} path component: {entry}") from exc
        if _is_link_or_reparse(metadata):
            raise UpdatePathError(f"{label} crosses a link or reparse point: {entry}")
        if entry != candidate and not stat.S_ISDIR(metadata.st_mode):
            raise UpdatePathError(f"{label} ancestor is not a directory: {entry}")


def _same_or_below(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_roots(install_root: Path, state_root: Path) -> tuple[Path, Path]:
    install = _absolute_lexical(install_root, label="install_root")
    state = _absolute_lexical(state_root, label="state_root")
    _assert_no_link_ancestors(install, label="install_root", include_leaf=True)
    _assert_no_link_ancestors(state, label="state_root", include_leaf=True)
    if _same_or_below(state, install) or _same_or_below(install, state):
        raise UpdatePathError("install and transaction-state roots must be disjoint")
    try:
        install_parent = install.parent.resolve(strict=True)
    except OSError as exc:
        raise UpdatePathError("install parent must already exist") from exc
    if not install_parent.is_dir():
        raise UpdatePathError("install parent is not a directory")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(state, 0o700)
    _assert_no_link_ancestors(state, label="state_root", include_leaf=True)
    return install, state


def _collision_key(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).replace("\\", "/")
    return "/".join(part.rstrip(" .").casefold() for part in normalized.split("/"))


def _validate_component(component: str, *, context: str) -> None:
    if (
        not component
        or component in {".", ".."}
        or len(component.encode("utf-8", "surrogatepass")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in component)
        or component[-1:] in {" ", "."}
        or any(character in '<>:"/\\|?*' for character in component)
    ):
        raise UpdateArchiveError(f"unsafe portable path component in {context}: {component!r}")
    if component.split(".", 1)[0].rstrip(" .").upper() in _WINDOWS_RESERVED:
        raise UpdateArchiveError(f"Windows-reserved path component in {context}: {component!r}")


DEFAULT_ARCHIVE_ROOT = "one-link"


def _manifest_name_for(root: str) -> str:
    return f"{root}/BUNDLE_SHA256SUMS"


def _discover_manifest_root(raw: bytes) -> str:
    """The single top-level directory every manifest row sits under.

    Taken from the MANIFEST, not from the directory name on disk. Those are
    not the same thing: the update transaction stages an extracted bundle into
    directories of its own choosing while the rows inside still say
    `one-link/...`, so keying off the folder name rejected every row during a
    staged update. The packager's archive validator has always discovered the
    root this way (`archive_root = roots.pop()`).

    Discovery is not trust. `_parse_bundle_manifest` then requires EVERY row to
    share this root, and `validate_installed_bundle` maps each row to
    `bundle / <relative>` -- so a manifest naming an unexpected root still
    cannot reach outside the bundle, and the file-set equality check still has
    to match what is actually on disk.
    """
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise UpdateArchiveError("bundle member manifest is not strict UTF-8") from exc
    lines = text.splitlines()
    # Header first, so a wrong FORMAT still reports "invalid header" rather
    # than the vaguer "names no members" it would otherwise get here. The
    # classic sha256sum layout auto_build used to emit has no header at all,
    # and that diagnostic is how it was identified.
    if not lines or lines[0] != ARCHIVE_MANIFEST_HEADER:
        raise UpdateArchiveError("bundle member manifest has an invalid header")
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        head = PurePosixPath(fields[3]).parts[:1]
        if head:
            return head[0]
    raise UpdateArchiveError("bundle member manifest names no members")


def _validate_archive_name(value: str, root: str = DEFAULT_ARCHIVE_ROOT) -> PurePosixPath:
    """Every member must live under ROOT, with no traversal.

    The root is a PARAMETER because bundles are not all called `one-link`.
    macOS ships `one-link.app`, and the packager has always derived the root
    from the bundle directory (`_archive_root_for`, and its archive validator
    discovers it from the archive). This side hardcoded it, so the packager
    signed and shipped a macOS bundle this validator refused every row of --
    701 of 701, measured on v0.21.0's one-link-macos-arm64.zip.

    Containment does NOT come from the root name. It comes from the checks
    around it: no `..`, not absolute, no backslash, no leading slash, and
    `as_posix()` round-tripping the input. Those are unchanged; the root only
    decides WHICH directory everything must sit under.
    """
    if not value or "\\" in value or value.startswith("/"):
        raise UpdateArchiveError(f"unsafe archive member path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.parts[:1] != (root,)
        or path.as_posix() != value
    ):
        raise UpdateArchiveError(f"unsafe archive member path: {value!r}")
    for part in path.parts:
        _validate_component(part, context=value)
    return path


def _sha256_stream(stream, *, maximum: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for block in iter(lambda: stream.read(BLOCK_SIZE), b""):
        count += len(block)
        if maximum is not None and count > maximum:
            raise UpdateArchiveError("stream exceeds its authenticated byte bound")
        digest.update(block)
    return digest.hexdigest(), count


def _sha256_regular_file(path: Path, *, expected_size: int | None = None) -> str:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise UpdateArchiveError(f"cannot inspect file: {path}") from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise UpdateArchiveError(f"file is not a non-reparse regular file: {path}")
    if expected_size is not None and before.st_size != expected_size:
        raise UpdateArchiveError(f"file size differs from authenticated metadata: {path}")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UpdateArchiveError(f"cannot open file without following links: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UpdateArchiveError(f"opened update input is not regular: {path}")
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(fd, BLOCK_SIZE)
            if not block:
                break
            count += len(block)
            digest.update(block)
        after_open = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        after_path = os.lstat(path)
    except OSError as exc:
        raise UpdateArchiveError(f"update input changed while hashing: {path}") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after_open = (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
    )
    identity_after_path = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if (
        _is_link_or_reparse(after_path)
        or identity_before != identity_opened
        or identity_opened != identity_after_open
        or identity_after_open != identity_after_path
        or count != before.st_size
    ):
        raise UpdateArchiveError(f"update input changed while hashing: {path}")
    return digest.hexdigest()


@dataclass(frozen=True)
class _ManifestRow:
    digest: str
    kind: str
    size: int
    path: str
    target: str


def _parse_bundle_manifest(
    raw: bytes, root: str = DEFAULT_ARCHIVE_ROOT,
) -> Mapping[str, _ManifestRow]:
    if not raw or len(raw) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise UpdateArchiveError("bundle member manifest is empty or oversized")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise UpdateArchiveError("bundle member manifest is not strict UTF-8") from exc
    lines = text.splitlines()
    if not lines or lines[0] != ARCHIVE_MANIFEST_HEADER:
        raise UpdateArchiveError("bundle member manifest has an invalid header")
    rows: dict[str, _ManifestRow] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 5:
            raise UpdateArchiveError("bundle member manifest has a malformed row")
        digest, kind, size_text, name, target = fields
        _validate_archive_name(name, root)
        if name == _manifest_name_for(root) or name in rows:
            raise UpdateArchiveError(f"bundle member manifest duplicates {name!r}")
        if not _HEX_64.fullmatch(digest) or kind not in {"FILE", "SYMLINK"}:
            raise UpdateArchiveError(f"bundle member manifest row is invalid: {name!r}")
        try:
            size = int(size_text)
        except ValueError as exc:
            raise UpdateArchiveError(f"bundle member size is invalid: {name!r}") from exc
        if size < 0 or size > MAX_STANDALONE_ARTIFACT_BYTES:
            raise UpdateArchiveError(f"bundle member size exceeds policy: {name!r}")
        if kind == "FILE" and target:
            raise UpdateArchiveError(f"regular bundle member has a link target: {name!r}")
        rows[name] = _ManifestRow(digest, kind, size, name, target)
    if not rows:
        raise UpdateArchiveError("bundle member manifest has no payload rows")
    return rows


MAX_SYMLINK_HOPS = 40


def _resolve_through_manifest(
    start: str,
    rows: Mapping[str, "_ManifestRow"],
    root: str,
    *,
    label: str,
) -> str:
    """Walk `start` component by component, following SYMLINK rows on the way.

    A symlink target is not always a member of the manifest, because real
    bundles chain links THROUGH linked directories. PyInstaller's macOS layout
    does exactly that:

        Contents/Frameworks/Python.framework/Python  -> Versions/Current/Python
        Contents/Frameworks/Python.framework/Versions/Current -> 3.12
        Contents/Frameworks/PIL/.dylibs -> __dot__dylibs

    `Versions/Current/Python` is a member of NOTHING: `Current` is itself a
    link, so the literal path never appears in the manifest. Requiring the
    target to be a literal entry rejected 79 of the 126 symlinks in the real
    v0.21.0 macOS bundle. Resolving the chain first is what makes the check
    answerable.

    Containment is enforced at EVERY hop, not just at the end -- a link may not
    step outside `root` even transiently. Hops are bounded, so a cycle
    (a -> b -> a) terminates as a refusal rather than a hang.
    """
    current = start
    for _ in range(MAX_SYMLINK_HOPS):
        parts = [p for p in current.split("/") if p]
        jumped = False
        # Longest-prefix first is wrong here: a link must be applied at the
        # SHALLOWEST component that is one, because everything after it is
        # relative to wherever that link lands.
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            row = rows.get(prefix)
            if row is None or row.kind != "SYMLINK":
                continue
            rest = parts[i:]
            landed = posixpath.normpath(
                posixpath.join(posixpath.dirname(prefix), row.target)
            )
            candidate = posixpath.normpath(
                posixpath.join(landed, *rest) if rest else landed
            )
            candidate_parts = [p for p in candidate.split("/") if p]
            # Containment is checked at EVERY hop, not just at the end: a chain
            # may not step outside the root even transiently.
            if ".." in candidate_parts or candidate_parts[:1] != [root]:
                raise UpdateArchiveError(
                    f"bundle symlink escapes the bundle root: {label!r}"
                )
            current = candidate
            jumped = True
            break
        if not jumped:
            return current
        # Re-scan from the start: the path we landed on may itself traverse
        # further links. Bounded by MAX_SYMLINK_HOPS, so a -> b -> a
        # terminates as a refusal instead of spinning.
    raise UpdateArchiveError(
        f"bundle symlink chain is too deep or cyclic: {label!r}"
    )


def _safe_symlink_target(
    row: _ManifestRow, all_names: set[str], root: str = DEFAULT_ARCHIVE_ROOT,
    rows: Mapping[str, "_ManifestRow"] | None = None,
) -> None:
    target = row.target
    posix_target = PurePosixPath(target.replace("\\", "/"))
    windows_target = PureWindowsPath(target)
    if (
        not target
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
        or posix_target.is_absolute()
        or windows_target.is_absolute()
        or bool(windows_target.drive)
        or bool(windows_target.root)
    ):
        raise UpdateArchiveError(f"bundle symlink target is unsafe: {row.path!r}")
    relocated = PurePosixPath(
        posixpath.normpath(str(PurePosixPath(row.path).parent / posix_target))
    )
    relocated_name = relocated.as_posix()
    if relocated.parts[:1] != (root,) or ".." in relocated.parts:
        raise UpdateArchiveError(f"bundle symlink escapes or targets missing content: {row.path!r}")

    def _present(name: str) -> bool:
        return name in all_names or any(n.startswith(name + "/") for n in all_names)

    # A literal manifest member may itself be a link. Resolve before testing
    # presence so direct cycles cannot bypass the bounded chain validator.
    if rows is not None:
        relocated_name = _resolve_through_manifest(
            relocated_name, rows, root, label=row.path,
        )
    if _present(relocated_name):
        return
    raise UpdateArchiveError(f"bundle symlink escapes or targets missing content: {row.path!r}")


def _archive_budgets() -> tuple[int, int, int]:
    from one_link.build_identity import (
        STABLE_FROZEN_MAX_BUNDLE_BYTES,
        STABLE_FROZEN_MAX_ENTRIES,
        STABLE_FROZEN_MAX_ZIP_MEMBERS,
    )

    return (
        STABLE_FROZEN_MAX_BUNDLE_BYTES,
        STABLE_FROZEN_MAX_ENTRIES,
        STABLE_FROZEN_MAX_ZIP_MEMBERS,
    )


def _validate_zip_index(
    archive: zipfile.ZipFile,
    *,
    expected_executable: str,
) -> tuple[list[zipfile.ZipInfo], bytes, Mapping[str, _ManifestRow]]:
    max_bytes, max_entries, max_members = _archive_budgets()
    infos = archive.infolist()
    if not infos or len(infos) > min(max_entries, max_members):
        raise UpdateArchiveError("standalone ZIP member count is empty or excessive")
    names = [info.filename for info in infos]
    folded = [_collision_key(name) for name in names]
    if len(names) != len(set(names)) or len(folded) != len(set(folded)):
        raise UpdateArchiveError("standalone ZIP has duplicate or portable-colliding names")
    if names.count(ARCHIVE_MANIFEST) != 1:
        raise UpdateArchiveError("standalone ZIP must contain exactly one member manifest")
    expected_member = f"one-link/{expected_executable}"
    if names.count(expected_member) != 1:
        raise UpdateArchiveError("standalone ZIP does not contain its exact executable")
    total = 0
    symlink_names: set[str] = set()
    for info in infos:
        _validate_archive_name(info.filename)
        if info.is_dir() or info.flag_bits & 0x1 or info.file_size < 0 or info.compress_size < 0:
            raise UpdateArchiveError(f"standalone ZIP member shape is unsafe: {info.filename!r}")
        total += info.file_size
        if total > max_bytes + MAX_ARCHIVE_MANIFEST_BYTES:
            raise UpdateArchiveError("standalone ZIP uncompressed bytes exceed policy")
        mode = (int(info.external_attr) >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type == stat.S_IFLNK:
            symlink_names.add(info.filename)
        elif file_type not in {0, stat.S_IFREG}:
            raise UpdateArchiveError(f"standalone ZIP contains a special file: {info.filename!r}")
    for name in names:
        parts = PurePosixPath(name).parts
        prefixes = {"/".join(parts[:index]) for index in range(1, len(parts))}
        if prefixes & symlink_names:
            raise UpdateArchiveError(f"standalone ZIP nests content under a symlink: {name!r}")
    try:
        manifest_raw = archive.read(ARCHIVE_MANIFEST)
    except (KeyError, RuntimeError, OSError) as exc:
        raise UpdateArchiveError("cannot read standalone ZIP member manifest") from exc
    rows = _parse_bundle_manifest(manifest_raw)
    if set(rows) != set(names) - {ARCHIVE_MANIFEST}:
        raise UpdateArchiveError("standalone ZIP member set differs from its manifest")
    all_names = set(names)
    for info in infos:
        if info.filename == ARCHIVE_MANIFEST:
            continue
        row = rows[info.filename]
        mode = (int(info.external_attr) >> 16) & 0xFFFF
        is_link = stat.S_IFMT(mode) == stat.S_IFLNK
        if (row.kind == "SYMLINK") != is_link or info.file_size != row.size:
            raise UpdateArchiveError(f"standalone ZIP type/size differs from manifest: {info.filename!r}")
        if row.kind == "SYMLINK":
            _safe_symlink_target(row, all_names, rows=rows)
    if rows[expected_member].kind != "FILE" or rows[expected_member].size <= 0:
        raise UpdateArchiveError("standalone executable is not a non-empty regular file")
    return infos, manifest_raw, rows


def extract_authenticated_bundle(
    archive_path: Path,
    destination: Path,
    *,
    artifact: StandaloneArtifact,
) -> BundleTree:
    """Safely extract one digest-authenticated standalone ZIP into a new path."""

    archive_file = _absolute_lexical(Path(archive_path), label="archive_path")
    target = _absolute_lexical(Path(destination), label="stage_container")
    _assert_no_link_ancestors(archive_file, label="archive_path", include_leaf=True)
    _assert_no_link_ancestors(target.parent, label="stage_parent", include_leaf=True)
    if _path_exists_no_follow(target):
        raise UpdatePathError("transaction stage path already exists")
    try:
        path_before = os.lstat(archive_file)
    except OSError as exc:
        raise UpdateArchiveError("cannot inspect authenticated standalone ZIP") from exc
    if (
        _is_link_or_reparse(path_before)
        or not stat.S_ISREG(path_before.st_mode)
        or path_before.st_size != artifact.size
    ):
        raise UpdateArchiveError("authenticated standalone ZIP has an unsafe type or size")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(archive_file, flags)
    except OSError as exc:
        raise UpdateArchiveError("cannot open authenticated standalone ZIP") from exc
    try:
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (
                    path_before.st_dev,
                    path_before.st_ino,
                    path_before.st_size,
                    path_before.st_mtime_ns,
                )
            ):
                raise UpdateArchiveError("authenticated standalone ZIP changed while opening")
            target.mkdir(mode=0o700)
            if os.name != "nt":
                target.chmod(0o700)
        except BaseException:
            os.close(fd)
            fd = -1
            raise
        try:
            with os.fdopen(fd, "rb", closefd=True) as stream:
                fd = -1
                archive_digest, archive_size = _sha256_stream(
                    stream,
                    maximum=artifact.size,
                )
                if archive_size != artifact.size or not hmac.compare_digest(
                    archive_digest,
                    artifact.sha256,
                ):
                    raise UpdateArchiveError(
                        "standalone ZIP differs from authenticated release metadata"
                    )
                stream.seek(0)
                with zipfile.ZipFile(stream, "r") as archive:
                    infos, manifest_raw, rows = _validate_zip_index(
                        archive,
                        expected_executable=artifact.executable,
                    )
                    for info in infos:
                        if info.filename == ARCHIVE_MANIFEST:
                            continue
                        row = rows[info.filename]
                        if row.kind == "SYMLINK":
                            continue
                        destination_path = target.joinpath(*PurePosixPath(info.filename).parts)
                        destination_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        digest = hashlib.sha256()
                        count = 0
                        try:
                            source = archive.open(info, "r")
                            output = destination_path.open("xb")
                        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                            raise UpdateArchiveError(
                                f"cannot create extracted bundle member: {info.filename!r}"
                            ) from exc
                        with source, output:
                            for block in iter(lambda: source.read(BLOCK_SIZE), b""):
                                count += len(block)
                                if count > row.size:
                                    raise UpdateArchiveError(
                                        f"extracted member exceeds manifest size: {info.filename!r}"
                                    )
                                digest.update(block)
                                output.write(block)
                            output.flush()
                            os.fsync(output.fileno())
                        if count != row.size or not hmac.compare_digest(
                            digest.hexdigest(), row.digest
                        ):
                            raise UpdateArchiveError(
                                f"extracted member differs from manifest: {info.filename!r}"
                            )
                        mode = (int(info.external_attr) >> 16) & 0o777
                        safe_mode = 0o755 if mode & 0o111 else 0o644
                        if os.name != "nt":
                            destination_path.chmod(safe_mode)
                    manifest_path = target / ARCHIVE_MANIFEST
                    manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with manifest_path.open("xb") as output:
                        output.write(manifest_raw)
                        output.flush()
                        os.fsync(output.fileno())
                    if os.name != "nt":
                        manifest_path.chmod(0o644)
                    for info in infos:
                        if info.filename == ARCHIVE_MANIFEST:
                            continue
                        row = rows[info.filename]
                        if row.kind != "SYMLINK":
                            continue
                        if os.name == "nt":
                            raise UpdateArchiveError(
                                "Windows standalone updates reject symbolic-link members"
                            )
                        destination_path = target.joinpath(*PurePosixPath(info.filename).parts)
                        destination_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.symlink(row.target, destination_path)
                opened_after = os.fstat(stream.fileno())
                try:
                    path_after = os.lstat(archive_file)
                except OSError as exc:
                    raise UpdateArchiveError(
                        "standalone ZIP path changed while extracting"
                    ) from exc
                if (
                    _is_link_or_reparse(path_after)
                    or (
                        opened_after.st_dev,
                        opened_after.st_ino,
                        opened_after.st_size,
                        opened_after.st_mtime_ns,
                    )
                    != (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_size,
                        opened.st_mtime_ns,
                    )
                    or (
                        path_after.st_dev,
                        path_after.st_ino,
                        path_after.st_size,
                        path_after.st_mtime_ns,
                    )
                    != (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_size,
                        opened.st_mtime_ns,
                    )
                ):
                    raise UpdateArchiveError("standalone ZIP changed while extracting")
        finally:
            if fd >= 0:
                os.close(fd)
        _sync_directory(target)
        tree = validate_installed_bundle(
            target / artifact.bundle_root,
            expected_executable=artifact.executable,
        )
        expected_manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
        if tree.manifest_sha256 != expected_manifest_digest:
            raise UpdateArchiveError("extracted bundle manifest digest changed")
        return tree
    except BaseException:
        if _path_exists_no_follow(target):
            _remove_owned_tree(target, parent=target.parent, expected_name=target.name)
        raise


def validate_installed_bundle(root: Path, *, expected_executable: str) -> BundleTree:
    """Re-hash an extracted/current bundle and reject any extra path."""

    bundle = _absolute_lexical(Path(root), label="bundle_root")
    _assert_no_link_ancestors(bundle, label="bundle_root", include_leaf=False)
    try:
        metadata = os.lstat(bundle)
    except OSError as exc:
        raise UpdateArchiveError(f"managed bundle is absent or unreadable: {bundle}") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        # Say which of the two rejections happened, and say it without a
        # double negative. An operator reading "is not a non-reparse
        # directory" cannot tell whether their bundle root was a symlink, a
        # junction, or simply a file.
        reason = (
            "a symbolic link or reparse point"
            if _is_link_or_reparse(metadata)
            else "not a directory"
        )
        raise UpdateArchiveError(
            f"managed bundle root must be a real directory; {bundle} is {reason}"
        )
    manifest_path = bundle / "BUNDLE_SHA256SUMS"
    try:
        raw = read_bytes_if_exists(
            manifest_path,
            label="standalone bundle member manifest",
            max_bytes=MAX_ARCHIVE_MANIFEST_BYTES,
        )
    except KeyMaterialError as exc:
        raise UpdateArchiveError("bundle member manifest cannot be read safely") from exc
    if raw is None:
        raise UpdateArchiveError("bundle member manifest is absent")
    manifest_digest = hashlib.sha256(raw).hexdigest()
    # The root comes from the MANIFEST, not from the folder name on disk.
    # macOS installs as `one-link.app` (its launcher is Contents/MacOS/one-link,
    # so the install root IS the .app), and hardcoding "one-link" rejected every
    # row of every macOS bundle ever shipped. Using the DIRECTORY name instead
    # was my first attempt and it broke staged updates, where the transaction
    # extracts into a directory of its own choosing while the rows inside still
    # say `one-link/...`.
    archive_root = _discover_manifest_root(raw)
    rows = _parse_bundle_manifest(raw, archive_root)
    expected_relative: dict[str, _ManifestRow] = {}
    for name, row in rows.items():
        parts = PurePosixPath(name).parts
        if parts[:1] != (archive_root,):
            raise UpdateArchiveError("bundle manifest row leaves bundle root")
        relative = PurePosixPath(*parts[1:]).as_posix()
        expected_relative[relative] = row
    discovered: set[str] = set()
    payload_bytes = 0

    def _walk_error(error: OSError) -> None:
        raise error

    try:
        for directory, directory_names, file_names in os.walk(
            bundle,
            followlinks=False,
            onerror=_walk_error,
        ):
            directory_names.sort()
            file_names.sort()
            parent = Path(directory)
            for name in list(directory_names):
                child = parent / name
                child_metadata = os.lstat(child)
                if _is_link_or_reparse(child_metadata):
                    relative = child.relative_to(bundle).as_posix()
                    discovered.add(relative)
                    directory_names.remove(name)
                elif not stat.S_ISDIR(child_metadata.st_mode):
                    raise UpdateArchiveError(f"managed bundle has a special entry: {child}")
            discovered.update((parent / name).relative_to(bundle).as_posix() for name in file_names)
    except OSError as exc:
        raise UpdateArchiveError("managed bundle cannot be enumerated safely") from exc
    discovered.discard("BUNDLE_SHA256SUMS")
    if discovered != set(expected_relative):
        raise UpdateArchiveError(
            "managed bundle file set differs from its authenticated member manifest"
        )
    all_archive_names = set(rows) | {_manifest_name_for(archive_root)}
    for relative, row in expected_relative.items():
        path = bundle.joinpath(*PurePosixPath(relative).parts)
        try:
            item = os.lstat(path)
        except OSError as exc:
            raise UpdateArchiveError(f"managed bundle member is missing: {relative}") from exc
        if row.kind == "SYMLINK":
            if not stat.S_ISLNK(item.st_mode) or _is_link_or_reparse(item) is False:
                raise UpdateArchiveError(f"managed bundle link type differs: {relative}")
            _safe_symlink_target(row, all_archive_names, archive_root, rows)
            try:
                target = os.readlink(path)
            except OSError as exc:
                raise UpdateArchiveError(f"managed bundle link is unreadable: {relative}") from exc
            encoded = target.encode("utf-8")
            if (
                target != row.target
                or len(encoded) != row.size
                or hashlib.sha256(encoded).hexdigest() != row.digest
            ):
                raise UpdateArchiveError(f"managed bundle link differs: {relative}")
            payload_bytes += len(encoded)
            continue
        if _is_link_or_reparse(item) or not stat.S_ISREG(item.st_mode):
            raise UpdateArchiveError(f"managed bundle member is not regular: {relative}")
        digest = _sha256_regular_file(path, expected_size=row.size)
        if not hmac.compare_digest(digest, row.digest):
            raise UpdateArchiveError(f"managed bundle member digest differs: {relative}")
        payload_bytes += row.size
    executable = bundle.joinpath(*PurePosixPath(expected_executable).parts)
    executable_digest = _sha256_regular_file(executable)
    if executable.stat().st_size <= 0:
        raise UpdateArchiveError("managed bundle executable is empty")
    if os.name != "nt" and not (executable.stat().st_mode & 0o111):
        raise UpdateArchiveError("managed bundle executable lacks an execute bit")
    return BundleTree(
        root=bundle,
        manifest_sha256=manifest_digest,
        executable_sha256=executable_digest,
        file_count=len(rows),
        payload_bytes=payload_bytes,
    )


def _remove_owned_tree(path: Path, *, parent: Path, expected_name: str) -> None:
    candidate = _absolute_lexical(path, label="owned update path")
    expected_parent = _absolute_lexical(parent, label="owned update parent")
    if candidate.parent != expected_parent or candidate.name != expected_name:
        raise UpdatePathError("refusing to remove a path outside exact transaction ownership")
    try:
        metadata = os.lstat(candidate)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise UpdatePathError("cannot inspect transaction-owned cleanup path") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise UpdatePathError("transaction-owned cleanup path changed type")
    shutil.rmtree(candidate)
    _sync_directory(expected_parent)


class AuthenticatedUpdateState:
    """MAC-authenticated journal/high-water persistence under caller authority."""

    def __init__(self, root: Path, authority_key: bytes):
        if not isinstance(authority_key, bytes) or len(authority_key) != 32:
            raise ValueError("update state authority_key must be exactly 32 bytes")
        self.root = _absolute_lexical(Path(root), label="state_root")
        self._key = authority_key
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)
        _assert_no_link_ancestors(self.root, label="state_root", include_leaf=True)

    def _path(self, filename: str) -> Path:
        if Path(filename).name != filename or filename in {"", ".", ".."}:
            raise UpdateStateError("state filename is not a safe basename")
        return self.root / filename

    def _encode(self, kind: str, payload: Mapping[str, object]) -> bytes:
        body = {"schema": STATE_SCHEMA, "kind": kind, "payload": dict(payload)}
        body_bytes = _canonical_json(body)
        mac = hmac.new(self._key, body_bytes, hashlib.sha256).hexdigest()
        return _canonical_json({**body, "mac": mac})

    def _decode(self, raw: bytes, *, expected_kind: str) -> Mapping[str, object]:
        if not raw or len(raw) > MAX_STATE_BYTES:
            raise UpdateStateError("authenticated update state is empty or oversized")
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateStateError("authenticated update state is not strict JSON") from exc
        if not isinstance(value, dict) or set(value) != {"schema", "kind", "payload", "mac"}:
            raise UpdateStateError("authenticated update state envelope is malformed")
        if value["schema"] != STATE_SCHEMA or value["kind"] != expected_kind:
            raise UpdateStateError("authenticated update state schema/kind differs")
        payload = value["payload"]
        mac = value["mac"]
        if not isinstance(payload, dict) or not isinstance(mac, str) or not _HEX_64.fullmatch(mac):
            raise UpdateStateError("authenticated update state payload/MAC is malformed")
        body_bytes = _canonical_json(
            {"schema": STATE_SCHEMA, "kind": expected_kind, "payload": payload}
        )
        expected = hmac.new(self._key, body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise UpdateStateError("authenticated update state MAC verification failed")
        if raw != self._encode(expected_kind, payload):
            raise UpdateStateError("authenticated update state is not canonical")
        return payload

    def _write(self, filename: str, *, kind: str, payload: Mapping[str, object]) -> None:
        path = self._path(filename)
        encoded = self._encode(kind, payload)

        def _validate(candidate: bytes) -> None:
            self._decode(candidate, expected_kind=kind)

        try:
            atomic_replace_bytes(path, encoded, label=kind, validate=_validate)
        except KeyMaterialError as exc:
            raise UpdateStateError(f"cannot durably store {kind}") from exc

    def _read(self, filename: str, *, kind: str) -> Mapping[str, object] | None:
        try:
            raw = read_bytes_if_exists(
                self._path(filename),
                label=kind,
                max_bytes=MAX_STATE_BYTES,
            )
        except KeyMaterialError as exc:
            raise UpdateStateError(f"cannot safely read {kind}") from exc
        if raw is None:
            return None
        return self._decode(raw, expected_kind=kind)

    def write_journal(self, journal: UpdateJournal) -> None:
        _validate_journal(journal, expected_state_root=self.root)
        self._write(JOURNAL_FILENAME, kind=JOURNAL_KIND, payload=asdict(journal))

    def read_journal(self) -> UpdateJournal | None:
        payload = self._read(JOURNAL_FILENAME, kind=JOURNAL_KIND)
        if payload is None:
            return None
        try:
            journal = UpdateJournal(**cast(dict[str, Any], dict(payload)))
        except TypeError as exc:
            raise UpdateStateError("transaction journal fields differ from schema") from exc
        _validate_journal(journal, expected_state_root=self.root)
        return journal

    def write_health(self, payload: Mapping[str, object]) -> None:
        self._write(HEALTH_FILENAME, kind=HEALTH_KIND, payload=payload)

    def read_health(self) -> Mapping[str, object] | None:
        return self._read(HEALTH_FILENAME, kind=HEALTH_KIND)

    def read_high_water(self) -> UpdateHighWater | None:
        payload = self._read(HIGH_WATER_FILENAME, kind=HIGH_WATER_KIND)
        if payload is None:
            return None
        if set(payload) != {"maximum_version", "maximum_rollback_index", "bindings"}:
            raise UpdateStateError("rollback high-water fields differ from schema")
        raw_bindings = payload["bindings"]
        if not isinstance(raw_bindings, list) or len(raw_bindings) > MAX_HISTORY_BINDINGS:
            raise UpdateStateError("rollback high-water binding history is malformed")
        bindings: list[HighWaterBinding] = []
        for raw in raw_bindings:
            if not isinstance(raw, dict):
                raise UpdateStateError("rollback high-water binding is not an object")
            try:
                binding = HighWaterBinding(**raw)
            except TypeError as exc:
                raise UpdateStateError("rollback high-water binding fields differ") from exc
            _validate_binding(binding)
            bindings.append(binding)
        maximum_index = payload["maximum_rollback_index"]
        if type(maximum_index) is not int:
            raise UpdateStateError("rollback maximum index is not an integer")
        result = UpdateHighWater(
            maximum_version=str(payload["maximum_version"]),
            maximum_rollback_index=maximum_index,
            bindings=tuple(bindings),
        )
        _validate_high_water(result)
        return result

    def write_high_water(self, high_water: UpdateHighWater) -> None:
        _validate_high_water(high_water)
        self._write(
            HIGH_WATER_FILENAME,
            kind=HIGH_WATER_KIND,
            payload={
                "maximum_version": high_water.maximum_version,
                "maximum_rollback_index": high_water.maximum_rollback_index,
                "bindings": [asdict(binding) for binding in high_water.bindings],
            },
        )

    @contextmanager
    def lock(self) -> Iterator[None]:
        path = self._path(LOCK_FILENAME)
        flags = os.O_RDWR | os.O_CREAT | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise UpdateStateError("cannot open update transaction lock") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise UpdateStateError("update transaction lock is not a regular file")
            if os.name == "nt":
                import msvcrt

                if metadata.st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise UpdateStateError("another update transaction owns the lock") from exc
            else:
                import fcntl

                try:
                    flock = getattr(fcntl, "flock")
                    flock(fd, int(getattr(fcntl, "LOCK_EX")) | int(getattr(fcntl, "LOCK_NB")))
                except OSError as exc:
                    raise UpdateStateError("another update transaction owns the lock") from exc
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    getattr(fcntl, "flock")(fd, int(getattr(fcntl, "LOCK_UN")))
            except OSError:
                pass
            os.close(fd)


def _validate_binding(binding: HighWaterBinding) -> None:
    try:
        version = Version(binding.version)
    except InvalidVersion as exc:
        raise UpdateStateError("high-water binding version is invalid") from exc
    if str(version) != binding.version or version.pre or version.dev or version.local:
        raise UpdateStateError("high-water binding version is not canonical stable")
    if binding.tag != f"v{binding.version}":
        raise UpdateStateError("high-water binding tag/version differ")
    if type(binding.rollback_index) is not int or not (0 < binding.rollback_index < 2**63):
        raise UpdateStateError("high-water binding rollback index is invalid")
    if not _HEX_40.fullmatch(binding.commit_sha):
        raise UpdateStateError("high-water binding commit is invalid")
    if not _HEX_64.fullmatch(binding.artifact_sha256) or not _HEX_64.fullmatch(
        binding.metadata_sha256
    ):
        raise UpdateStateError("high-water binding digest is invalid")


def _validate_high_water(high_water: UpdateHighWater) -> None:
    try:
        maximum_version = Version(high_water.maximum_version)
    except InvalidVersion as exc:
        raise UpdateStateError("rollback maximum version is invalid") from exc
    if str(maximum_version) != high_water.maximum_version:
        raise UpdateStateError("rollback maximum version is not canonical")
    if type(high_water.maximum_rollback_index) is not int or not (
        0 < high_water.maximum_rollback_index < 2**63
    ):
        raise UpdateStateError("rollback maximum index is invalid")
    if not high_water.bindings or len(high_water.bindings) > MAX_HISTORY_BINDINGS:
        raise UpdateStateError("rollback binding history is empty or excessive")
    tags: set[str] = set()
    prior_index = -1
    prior_version = Version("0")
    for binding in high_water.bindings:
        _validate_binding(binding)
        version = Version(binding.version)
        if binding.tag in tags or binding.rollback_index <= prior_index or version <= prior_version:
            raise UpdateStateError("rollback binding history is duplicated or non-monotonic")
        tags.add(binding.tag)
        prior_index = binding.rollback_index
        prior_version = version
    if (
        high_water.bindings[-1].rollback_index != high_water.maximum_rollback_index
        or high_water.bindings[-1].version != high_water.maximum_version
    ):
        raise UpdateStateError("rollback maxima do not match the latest binding")


def _validate_journal(journal: UpdateJournal, *, expected_state_root: Path) -> None:
    try:
        TransactionPhase(journal.phase)
        version = Version(journal.version)
    except (ValueError, InvalidVersion) as exc:
        raise UpdateStateError("transaction journal phase/version is invalid") from exc
    if str(version) != journal.version or version.pre or version.dev or version.local:
        raise UpdateStateError("transaction journal version is not canonical stable")
    if journal.tag != f"v{journal.version}" or not _TXID.fullmatch(journal.txid):
        raise UpdateStateError("transaction journal tag or id is invalid")
    if not _HEX_40.fullmatch(journal.commit_sha):
        raise UpdateStateError("transaction journal commit is invalid")
    if not all(
        _HEX_64.fullmatch(value)
        for value in (
            journal.artifact_sha256,
            journal.metadata_sha256,
            journal.candidate_manifest_sha256,
            journal.previous_manifest_sha256,
            journal.health_nonce,
        )
    ):
        raise UpdateStateError("transaction journal contains an invalid digest/nonce")
    if type(journal.rollback_index) is not int or not (0 < journal.rollback_index < 2**63):
        raise UpdateStateError("transaction journal rollback index is invalid")
    if type(journal.artifact_size) is not int or not (
        0 < journal.artifact_size <= MAX_STANDALONE_ARTIFACT_BYTES
    ):
        raise UpdateStateError("transaction journal artifact size is invalid")
    install = _absolute_lexical(Path(journal.install_root), label="journal install_root")
    state = _absolute_lexical(Path(journal.state_root), label="journal state_root")
    if state != expected_state_root:
        raise UpdateStateError("transaction journal state root differs from authority root")
    expected_stage = install.parent / f".{install.name}.update-{journal.txid}.stage"
    expected_backup = install.parent / f".{install.name}.update-{journal.txid}.backup"
    expected_failed = install.parent / f".{install.name}.update-{journal.txid}.failed"
    if Path(journal.stage_container) != expected_stage:
        raise UpdateStateError("transaction journal stage path is not derived from its id")
    if Path(journal.backup_root) != expected_backup:
        raise UpdateStateError("transaction journal backup path is not derived from its id")
    if Path(journal.failed_root) != expected_failed:
        raise UpdateStateError("transaction journal failed path is not derived from its id")
    if Path(journal.artifact_filename).name != journal.artifact_filename:
        raise UpdateStateError("transaction journal artifact filename is unsafe")
    if not journal.expected_executable or ".." in PurePosixPath(
        journal.expected_executable
    ).parts:
        raise UpdateStateError("transaction journal executable path is unsafe")
    _parse_utc(journal.health_deadline, label="health_deadline")
    created = _parse_utc(journal.created_at, label="created_at")
    updated = _parse_utc(journal.updated_at, label="updated_at")
    if updated < created:
        raise UpdateStateError("transaction journal update time predates creation")


def _replace_phase(
    journal: UpdateJournal,
    phase: TransactionPhase,
    *,
    now: datetime,
) -> UpdateJournal:
    values = asdict(journal)
    values["phase"] = phase.value
    values["updated_at"] = _format_utc(now)
    return UpdateJournal(**values)


def _binding_for(journal: UpdateJournal) -> HighWaterBinding:
    return HighWaterBinding(
        tag=journal.tag,
        version=journal.version,
        rollback_index=journal.rollback_index,
        commit_sha=journal.commit_sha,
        artifact_sha256=journal.artifact_sha256,
        metadata_sha256=journal.metadata_sha256,
    )


def _assert_candidate_allowed(
    manifest: AuthenticatedUpdateManifest,
    artifact: StandaloneArtifact,
    *,
    current_version: str,
    high_water: UpdateHighWater | None,
) -> None:
    try:
        installed = Version(current_version)
    except InvalidVersion as exc:
        raise UpdateRollbackError("running application version is invalid") from exc
    if installed >= manifest.version:
        raise UpdateRollbackError("candidate is not newer than the running application")
    if installed < manifest.minimum_source_version:
        raise UpdateRollbackError("candidate requires an intermediate source version")
    if high_water is None:
        return
    binding = HighWaterBinding(
        tag=manifest.tag,
        version=str(manifest.version),
        rollback_index=manifest.rollback_index,
        commit_sha=manifest.commit_sha,
        artifact_sha256=artifact.sha256,
        metadata_sha256=manifest.authenticated_metadata_sha256,
    )
    for existing in high_water.bindings:
        if existing.tag == binding.tag:
            if existing != binding:
                raise UpdateRollbackError("immutable release tag was reissued with different bytes")
            raise UpdateRollbackError("this exact release is already committed")
    if manifest.rollback_index <= high_water.maximum_rollback_index:
        raise UpdateRollbackError("candidate rollback index does not advance high-water state")
    if manifest.version <= Version(high_water.maximum_version):
        raise UpdateRollbackError("candidate version does not advance high-water state")


def prepare_update_transaction(
    *,
    manifest: AuthenticatedUpdateManifest,
    platform_key: str,
    archive_path: Path,
    install_root: Path,
    state_root: Path,
    authority_key: bytes,
    current_version: str,
    now: datetime | None = None,
    health_window: timedelta = DEFAULT_HEALTH_WINDOW,
    fault: FaultHook = _noop_fault,
) -> UpdateJournal:
    """Validate and stage a candidate without changing the active bundle."""

    observed = (now or _utc_now()).astimezone(UTC)
    if not timedelta(seconds=30) <= health_window <= MAX_HEALTH_WINDOW:
        raise ValueError("health_window must be between 30 seconds and 15 minutes")
    install, state = _validate_roots(Path(install_root), Path(state_root))
    artifact = manifest.artifact_for(platform_key)
    store = AuthenticatedUpdateState(state, authority_key)
    with store.lock():
        prior = store.read_journal()
        if prior is not None and prior.phase not in {
            TransactionPhase.COMMITTED.value,
            TransactionPhase.ROLLED_BACK.value,
        }:
            raise UpdateStateError("an unfinished update transaction already exists")
        high_water = store.read_high_water()
        _assert_candidate_allowed(
            manifest,
            artifact,
            current_version=current_version,
            high_water=high_water,
        )
        previous = validate_installed_bundle(
            install,
            expected_executable=artifact.executable,
        )
        txid = secrets.token_hex(16)
        stage = install.parent / f".{install.name}.update-{txid}.stage"
        backup = install.parent / f".{install.name}.update-{txid}.backup"
        failed = install.parent / f".{install.name}.update-{txid}.failed"
        for reserved in (stage, backup, failed):
            if _path_exists_no_follow(reserved):
                raise UpdatePathError("derived transaction path unexpectedly exists")
        journal_persisted = False
        try:
            candidate = extract_authenticated_bundle(
                Path(archive_path),
                stage,
                artifact=artifact,
            )
            if candidate.root != stage / artifact.bundle_root:
                raise UpdatePathError("candidate bundle root differs from signed metadata")
            if install.parent.stat().st_dev != stage.stat().st_dev:
                raise UpdatePathError("candidate stage is not on the install filesystem")
            created = _format_utc(observed)
            journal = UpdateJournal(
                phase=TransactionPhase.PREPARED.value,
                txid=txid,
                tag=manifest.tag,
                version=str(manifest.version),
                commit_sha=manifest.commit_sha,
                rollback_index=manifest.rollback_index,
                artifact_filename=artifact.filename,
                artifact_size=artifact.size,
                artifact_sha256=artifact.sha256,
                metadata_sha256=manifest.authenticated_metadata_sha256,
                platform=platform_key,
                expected_executable=artifact.executable,
                install_root=str(install),
                state_root=str(state),
                stage_container=str(stage),
                backup_root=str(backup),
                failed_root=str(failed),
                candidate_manifest_sha256=candidate.manifest_sha256,
                previous_manifest_sha256=previous.manifest_sha256,
                health_nonce=secrets.token_hex(32),
                health_deadline=_format_utc(observed + health_window),
                created_at=created,
                updated_at=created,
            )
            store.write_journal(journal)
            journal_persisted = True
            fault("after_prepared_journal")
            return journal
        except BaseException:
            if not journal_persisted and _path_exists_no_follow(stage):
                _remove_owned_tree(stage, parent=install.parent, expected_name=stage.name)
            raise


def _process_token_linux(pid: int) -> ProcessIdentity | None:
    proc = Path("/proc") / str(pid)
    try:
        stat_text = (proc / "stat").read_text(encoding="ascii")
        executable = str((proc / "exe").resolve(strict=True))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise UpdateTransactionError("cannot inspect target process identity") from exc
    closing = stat_text.rfind(")")
    if closing < 0:
        raise UpdateTransactionError("target process stat record is malformed")
    remaining = stat_text[closing + 2 :].split()
    if len(remaining) <= 19:
        raise UpdateTransactionError("target process stat record is incomplete")
    start_ticks = remaining[19]
    token = hashlib.sha256(f"linux\0{start_ticks}\0{executable}".encode()).hexdigest()
    return ProcessIdentity(pid=pid, instance_token=token, executable=executable)


def _process_token_windows(pid: int) -> ProcessIdentity | None:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error in {5, 87, 1168}:
            if error == 5:
                raise UpdateTransactionError("access denied while inspecting target process")
            return None
        raise ctypes.WinError(error)
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # A terminated process still has a process OBJECT for as long as any
        # handle to it is open, so OpenProcess above can succeed for a pid that
        # has already exited. QueryFullProcessImageNameW then fails with
        # ERROR_GEN_FAILURE (31), which is not in the "gone" set the OpenProcess
        # branch knows about, so this raised PermissionError instead of
        # reporting the exit.
        #
        # Found by running the update ceremony against a real frozen bundle on
        # Windows: the daemon was stopped, it really had exited, and
        # require_guarded_process_exit raised rather than confirming it. On that
        # path the helper cannot proceed, so a Windows self-update stalls at the
        # step that waits for the old process to go away.
        #
        # lpExitTime is the authoritative answer and we already asked for it:
        # Windows leaves it zero for a process that has NOT exited, so reading
        # it cannot mistake a live process for a dead one. Returning None here
        # means "this instance is gone", which is exactly what has happened.
        exited_at = (int(exit_time.dwHighDateTime) << 32) | int(exit_time.dwLowDateTime)
        if exited_at:
            return None
        capacity = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(capacity.value)
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, buffer, ctypes.byref(capacity)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        created_ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        executable = str(Path(buffer.value).absolute())
        token = hashlib.sha256(
            f"windows\0{created_ticks}\0{executable.casefold()}".encode("utf-8")
        ).hexdigest()
        return ProcessIdentity(pid=pid, instance_token=token, executable=executable)
    finally:
        kernel32.CloseHandle(handle)


def _process_token_macos(pid: int) -> ProcessIdentity | None:
    ps = Path("/bin/ps")
    if not ps.is_file():
        raise UpdateTransactionError("macOS process identity reader is unavailable")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed absolute executable and argv
            [str(ps), "-p", str(pid), "-o", "lstart=", "-o", "comm="],
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5.0,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateTransactionError("cannot inspect macOS target process") from exc
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        return None
    executable_text = value.split()[-1]
    executable = str(Path(executable_text).absolute())
    token = hashlib.sha256(f"macos\0{value}".encode("utf-8")).hexdigest()
    return ProcessIdentity(pid=pid, instance_token=token, executable=executable)


def read_process_identity(pid: int) -> ProcessIdentity | None:
    if type(pid) is not int or pid <= 0:
        raise ValueError("pid must be a positive integer")
    system = platform.system()
    if system == "Linux":
        return _process_token_linux(pid)
    if system == "Windows":
        return _process_token_windows(pid)
    if system == "Darwin":
        return _process_token_macos(pid)
    raise UpdateTransactionError(f"unsupported process-identity platform: {system}")


def capture_process_guard(pid: int, *, reader: IdentityReader = read_process_identity) -> ProcessGuard:
    identity = reader(pid)
    if identity is None:
        raise UpdateTransactionError("cannot guard a process that is not running")
    if not _HEX_64.fullmatch(identity.instance_token):
        raise UpdateTransactionError("process identity token is malformed")
    return ProcessGuard(identity.pid, identity.instance_token, identity.executable)


def require_guarded_process_exit(
    guard: ProcessGuard,
    *,
    reader: IdentityReader = read_process_identity,
    timeout: float = 45.0,
    poll_interval: float = 0.1,
) -> None:
    """Wait only for the captured process instance; never trust a reused PID."""

    if (
        type(guard.pid) is not int
        or guard.pid <= 0
        or not _HEX_64.fullmatch(guard.instance_token)
        or not guard.executable
    ):
        raise UpdateTransactionError("process guard is malformed")
    if not (0 <= timeout <= 300) or not (0.01 <= poll_interval <= 5):
        raise ValueError("process wait bounds are invalid")
    deadline = time.monotonic() + timeout
    while True:
        current = reader(guard.pid)
        if current is None or current.instance_token != guard.instance_token:
            return
        if time.monotonic() >= deadline:
            raise UpdateProcessStillRunning("guarded application did not exit before deadline")
        time.sleep(poll_interval)


def _journal_paths(journal: UpdateJournal) -> tuple[Path, Path, Path, Path, Path]:
    install = Path(journal.install_root)
    stage = Path(journal.stage_container)
    candidate = stage / "one-link"
    backup = Path(journal.backup_root)
    failed = Path(journal.failed_root)
    return install, stage, candidate, backup, failed


def activate_prepared_update(
    *,
    state_root: Path,
    authority_key: bytes,
    process_guard: ProcessGuard,
    identity_reader: IdentityReader = read_process_identity,
    process_timeout: float = 45.0,
    now: datetime | None = None,
    fault: FaultHook = _noop_fault,
) -> UpdateJournal:
    """Move the prepared candidate into the stable install path."""

    require_guarded_process_exit(
        process_guard,
        reader=identity_reader,
        timeout=process_timeout,
    )
    observed = (now or _utc_now()).astimezone(UTC)
    store = AuthenticatedUpdateState(Path(state_root), authority_key)
    with store.lock():
        journal = store.read_journal()
        if journal is None or journal.phase != TransactionPhase.PREPARED.value:
            raise UpdateStateError("no prepared update transaction is available")
        install, stage, candidate, backup, failed = _journal_paths(journal)
        _validate_roots(install, Path(journal.state_root))
        if _path_exists_no_follow(backup) or _path_exists_no_follow(failed):
            raise UpdatePathError("transaction backup/failed path already exists")
        previous = validate_installed_bundle(
            install,
            expected_executable=journal.expected_executable,
        )
        candidate_tree = validate_installed_bundle(
            candidate,
            expected_executable=journal.expected_executable,
        )
        if previous.manifest_sha256 != journal.previous_manifest_sha256:
            raise UpdateArchiveError("active bundle changed after update preparation")
        if candidate_tree.manifest_sha256 != journal.candidate_manifest_sha256:
            raise UpdateArchiveError("candidate bundle changed after update preparation")
        journal = _replace_phase(journal, TransactionPhase.BACKUP_INTENT, now=observed)
        store.write_journal(journal)
        fault("after_backup_intent")
        try:
            os.replace(install, backup)
            _sync_directory(install.parent)
            fault("after_backup_rename_before_journal")
            journal = _replace_phase(journal, TransactionPhase.BACKUP_CREATED, now=observed)
            store.write_journal(journal)
            fault("after_backup_created_journal")
            journal = _replace_phase(journal, TransactionPhase.ACTIVATE_INTENT, now=observed)
            store.write_journal(journal)
            fault("after_activate_intent")
            os.replace(candidate, install)
            _sync_directory(install.parent)
            fault("after_candidate_rename_before_journal")
            active = validate_installed_bundle(
                install,
                expected_executable=journal.expected_executable,
            )
            if active.manifest_sha256 != journal.candidate_manifest_sha256:
                raise UpdateArchiveError("activated bundle differs from the staged candidate")
            journal = _replace_phase(journal, TransactionPhase.CANDIDATE_ACTIVE, now=observed)
            store.write_journal(journal)
            fault("after_candidate_active_journal")
            return journal
        except Exception:
            current = store.read_journal() or journal
            _rollback_locked(store, current, now=observed, detail="activation_error")
            raise


def _health_payload(journal: UpdateJournal, tree: BundleTree, *, now: datetime) -> Mapping[str, object]:
    return {
        "txid": journal.txid,
        "tag": journal.tag,
        "version": journal.version,
        "commit_sha": journal.commit_sha,
        "artifact_sha256": journal.artifact_sha256,
        "metadata_sha256": journal.metadata_sha256,
        "candidate_manifest_sha256": tree.manifest_sha256,
        "executable_sha256": tree.executable_sha256,
        "health_nonce": journal.health_nonce,
        "healthy_at": _format_utc(now),
    }


def _health_matches(journal: UpdateJournal, payload: Mapping[str, object] | None) -> bool:
    if payload is None:
        return False
    required = {
        "txid",
        "tag",
        "version",
        "commit_sha",
        "artifact_sha256",
        "metadata_sha256",
        "candidate_manifest_sha256",
        "executable_sha256",
        "health_nonce",
        "healthy_at",
    }
    if set(payload) != required:
        return False
    expected = {
        "txid": journal.txid,
        "tag": journal.tag,
        "version": journal.version,
        "commit_sha": journal.commit_sha,
        "artifact_sha256": journal.artifact_sha256,
        "metadata_sha256": journal.metadata_sha256,
        "candidate_manifest_sha256": journal.candidate_manifest_sha256,
        "health_nonce": journal.health_nonce,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        return False
    executable_digest = payload.get("executable_sha256")
    if not isinstance(executable_digest, str) or not _HEX_64.fullmatch(executable_digest):
        return False
    try:
        healthy_at = _parse_utc(str(payload["healthy_at"]), label="healthy_at")
        return healthy_at <= _parse_utc(journal.health_deadline, label="health_deadline")
    except UpdateStateError:
        return False


def _append_high_water(
    high_water: UpdateHighWater | None,
    binding: HighWaterBinding,
) -> UpdateHighWater:
    _validate_binding(binding)
    if high_water is None:
        return UpdateHighWater(binding.version, binding.rollback_index, (binding,))
    for existing in high_water.bindings:
        if existing.tag == binding.tag:
            if existing != binding:
                raise UpdateRollbackError("committed tag binding changed")
            return high_water
    if binding.rollback_index <= high_water.maximum_rollback_index:
        raise UpdateRollbackError("health candidate does not advance rollback index")
    if Version(binding.version) <= Version(high_water.maximum_version):
        raise UpdateRollbackError("health candidate does not advance version")
    bindings = high_water.bindings + (binding,)
    if len(bindings) > MAX_HISTORY_BINDINGS:
        raise UpdateRollbackError("rollback binding history reached its safety budget")
    return UpdateHighWater(binding.version, binding.rollback_index, bindings)


def _finalize_healthy_locked(
    store: AuthenticatedUpdateState,
    journal: UpdateJournal,
    *,
    now: datetime,
    fault: FaultHook,
) -> UpdateJournal:
    install, stage, _candidate, backup, failed = _journal_paths(journal)
    active = validate_installed_bundle(
        install,
        expected_executable=journal.expected_executable,
    )
    if active.manifest_sha256 != journal.candidate_manifest_sha256:
        raise UpdateArchiveError("healthy active bundle differs from candidate authority")
    health = store.read_health()
    if not _health_matches(journal, health):
        raise UpdateStateError("post-restart health marker is absent or mismatched")
    if journal.phase == TransactionPhase.CANDIDATE_ACTIVE.value:
        journal = _replace_phase(journal, TransactionPhase.HEALTH_ACCEPTED, now=now)
        store.write_journal(journal)
        fault("after_health_accepted_journal")
    if journal.phase == TransactionPhase.HEALTH_ACCEPTED.value:
        high_water = _append_high_water(store.read_high_water(), _binding_for(journal))
        store.write_high_water(high_water)
        fault("after_high_water_write_before_journal")
        journal = _replace_phase(journal, TransactionPhase.HIGH_WATER_COMMITTED, now=now)
        store.write_journal(journal)
        fault("after_high_water_committed_journal")
    if journal.phase == TransactionPhase.HIGH_WATER_COMMITTED.value:
        committed_high_water = store.read_high_water()
        if (
            committed_high_water is None
            or _binding_for(journal) not in committed_high_water.bindings
        ):
            raise UpdateStateError("committed rollback high-water binding is absent")
        if _path_exists_no_follow(backup):
            previous = validate_installed_bundle(
                backup,
                expected_executable=journal.expected_executable,
            )
            if previous.manifest_sha256 != journal.previous_manifest_sha256:
                raise UpdateArchiveError("rollback backup changed before retirement")
            _remove_owned_tree(backup, parent=install.parent, expected_name=backup.name)
        if _path_exists_no_follow(stage):
            _remove_owned_tree(stage, parent=install.parent, expected_name=stage.name)
        if _path_exists_no_follow(failed):
            raise UpdatePathError("unexpected failed-candidate path during commit")
        fault("after_backup_cleanup_before_commit_journal")
        journal = _replace_phase(journal, TransactionPhase.COMMITTED, now=now)
        store.write_journal(journal)
        fault("after_commit_journal")
    return journal


def mark_update_healthy(
    *,
    state_root: Path,
    authority_key: bytes,
    running_executable: Path,
    observed_version: str,
    health_probe: HealthProbe,
    now: datetime | None = None,
    fault: FaultHook = _noop_fault,
) -> UpdateJournal:
    """Commit only after the restarted candidate passes an explicit probe."""

    observed = (now or _utc_now()).astimezone(UTC)
    store = AuthenticatedUpdateState(Path(state_root), authority_key)
    with store.lock():
        journal = store.read_journal()
        if journal is None or journal.phase != TransactionPhase.CANDIDATE_ACTIVE.value:
            raise UpdateStateError("no health-pending candidate is active")
        if observed > _parse_utc(journal.health_deadline, label="health_deadline"):
            _rollback_locked(store, journal, now=observed, detail="health_deadline_expired")
            raise UpdateRollbackError("candidate missed its post-restart health deadline")
        if observed_version != journal.version:
            raise UpdateStateError("running candidate reports a different version")
        install = Path(journal.install_root)
        expected_executable = install.joinpath(*PurePosixPath(journal.expected_executable).parts)
        supplied = _absolute_lexical(Path(running_executable), label="running_executable")
        if supplied != expected_executable:
            raise UpdatePathError("health marker came from outside the activated bundle")
        tree = validate_installed_bundle(
            install,
            expected_executable=journal.expected_executable,
        )
        if tree.manifest_sha256 != journal.candidate_manifest_sha256:
            raise UpdateArchiveError("running candidate tree differs from staged authority")
        try:
            healthy = health_probe(expected_executable)
        except Exception as exc:
            raise UpdateTransactionError("candidate health probe raised an exception") from exc
        if healthy is not True:
            raise UpdateTransactionError("candidate health probe did not return exact success")
        store.write_health(_health_payload(journal, tree, now=observed))
        fault("after_health_marker")
        return _finalize_healthy_locked(store, journal, now=observed, fault=fault)


def _rollback_locked(
    store: AuthenticatedUpdateState,
    journal: UpdateJournal,
    *,
    now: datetime,
    detail: str,
) -> UpdateJournal:
    if journal.phase in {
        TransactionPhase.HEALTH_ACCEPTED.value,
        TransactionPhase.HIGH_WATER_COMMITTED.value,
        TransactionPhase.COMMITTED.value,
    }:
        raise UpdateRollbackError("cannot roll back after health authority was accepted")
    install, stage, candidate, backup, failed = _journal_paths(journal)
    journal = _replace_phase(journal, TransactionPhase.ROLLBACK_INTENT, now=now)
    store.write_journal(journal)
    install_exists = _path_exists_no_follow(install)
    backup_exists = _path_exists_no_follow(backup)
    if backup_exists:
        backup_tree = validate_installed_bundle(
            backup,
            expected_executable=journal.expected_executable,
        )
        if backup_tree.manifest_sha256 != journal.previous_manifest_sha256:
            raise UpdateArchiveError("rollback backup differs from prepared previous bundle")
        if install_exists:
            active = validate_installed_bundle(
                install,
                expected_executable=journal.expected_executable,
            )
            if active.manifest_sha256 == journal.previous_manifest_sha256:
                raise UpdatePathError("both active path and backup contain the previous bundle")
            if active.manifest_sha256 != journal.candidate_manifest_sha256:
                raise UpdatePathError("active path is neither candidate nor previous bundle")
            if _path_exists_no_follow(failed):
                raise UpdatePathError("failed-candidate quarantine path already exists")
            os.replace(install, failed)
            _sync_directory(install.parent)
        os.replace(backup, install)
        _sync_directory(install.parent)
    elif not install_exists:
        raise UpdatePathError("both active bundle and rollback backup are absent")
    else:
        active = validate_installed_bundle(
            install,
            expected_executable=journal.expected_executable,
        )
        if active.manifest_sha256 != journal.previous_manifest_sha256:
            raise UpdatePathError("rollback backup is absent and active bundle is not previous")
    if _path_exists_no_follow(failed):
        _remove_owned_tree(failed, parent=install.parent, expected_name=failed.name)
    if _path_exists_no_follow(stage):
        if _path_exists_no_follow(candidate):
            staged_tree = validate_installed_bundle(
                candidate,
                expected_executable=journal.expected_executable,
            )
            if staged_tree.manifest_sha256 != journal.candidate_manifest_sha256:
                raise UpdateArchiveError("staged candidate changed before rollback cleanup")
        _remove_owned_tree(stage, parent=install.parent, expected_name=stage.name)
    restored = validate_installed_bundle(
        install,
        expected_executable=journal.expected_executable,
    )
    if restored.manifest_sha256 != journal.previous_manifest_sha256:
        raise UpdateArchiveError("rollback did not restore the previous bundle exactly")
    values = asdict(journal)
    values["phase"] = TransactionPhase.ROLLED_BACK.value
    values["updated_at"] = _format_utc(now)
    rolled_back = UpdateJournal(**values)
    store.write_journal(rolled_back)
    # ``detail`` is deliberately not persisted: journal fields are a strict,
    # security-reviewed schema.  The caller receives it in RecoveryResult.
    _ = detail
    return rolled_back


def abort_update_transaction(
    *,
    state_root: Path,
    authority_key: bytes,
    now: datetime | None = None,
    detail: str = "authenticated_helper_aborted",
    fault: FaultHook = _noop_fault,
) -> RecoveryResult:
    """Immediately retire an update that the owning helper has rejected.

    Crash recovery deliberately keeps a healthy-looking candidate alive until
    its bounded health deadline because a candidate process may still be
    starting.  That is the wrong semantic after the live helper has observed a
    concrete launch or health failure: the candidate must be stopped and the
    byte-validated previous bundle restored immediately.  Health authority,
    once durably accepted, remains irreversible and is completed instead.
    """

    observed = (now or _utc_now()).astimezone(UTC)
    if not isinstance(detail, str) or not detail or len(detail) > 128:
        raise ValueError("update abort detail must be bounded non-empty text")
    store = AuthenticatedUpdateState(Path(state_root), authority_key)
    with store.lock():
        journal = store.read_journal()
        if journal is None:
            return RecoveryResult("none", None, None, "no update transaction exists")
        phase = TransactionPhase(journal.phase)
        if phase is TransactionPhase.COMMITTED:
            return RecoveryResult("committed", phase.value, journal.txid, "candidate is committed")
        if phase is TransactionPhase.ROLLED_BACK:
            return RecoveryResult(
                "rolled_back",
                phase.value,
                journal.txid,
                "previous bundle already restored",
            )
        if phase in {
            TransactionPhase.HEALTH_ACCEPTED,
            TransactionPhase.HIGH_WATER_COMMITTED,
        }:
            committed = _finalize_healthy_locked(
                store,
                journal,
                now=observed,
                fault=fault,
            )
            return RecoveryResult(
                "committed",
                committed.phase,
                committed.txid,
                "accepted health authority was committed",
            )
        rolled = _rollback_locked(
            store,
            journal,
            now=observed,
            detail=detail,
        )
        return RecoveryResult(
            "rolled_back",
            rolled.phase,
            rolled.txid,
            "helper rejection restored the previous bundle",
        )


def recover_update_transaction(
    *,
    state_root: Path,
    authority_key: bytes,
    now: datetime | None = None,
    fault: FaultHook = _noop_fault,
) -> RecoveryResult:
    """Repair or resume every journaled crash boundary deterministically."""

    observed = (now or _utc_now()).astimezone(UTC)
    store = AuthenticatedUpdateState(Path(state_root), authority_key)
    with store.lock():
        journal = store.read_journal()
        if journal is None:
            return RecoveryResult("none", None, None, "no update transaction exists")
        phase = TransactionPhase(journal.phase)
        if phase is TransactionPhase.COMMITTED:
            return RecoveryResult("committed", phase.value, journal.txid, "candidate is committed")
        if phase is TransactionPhase.ROLLED_BACK:
            return RecoveryResult("rolled_back", phase.value, journal.txid, "previous bundle restored")
        install, stage, candidate, backup, _failed = _journal_paths(journal)
        if phase is TransactionPhase.PREPARED:
            active = validate_installed_bundle(
                install,
                expected_executable=journal.expected_executable,
            )
            if (
                active.manifest_sha256 != journal.previous_manifest_sha256
                or _path_exists_no_follow(backup)
            ):
                raise UpdatePathError("prepared transaction paths are inconsistent")
            rolled = _rollback_locked(store, journal, now=observed, detail="prepared_aborted")
            return RecoveryResult("rolled_back", rolled.phase, rolled.txid, "unused stage retired")
        if phase in {
            TransactionPhase.BACKUP_INTENT,
            TransactionPhase.BACKUP_CREATED,
        }:
            rolled = _rollback_locked(store, journal, now=observed, detail="activation_interrupted")
            return RecoveryResult("rolled_back", rolled.phase, rolled.txid, "previous bundle restored")
        if phase is TransactionPhase.ACTIVATE_INTENT:
            if _path_exists_no_follow(install) and _path_exists_no_follow(backup):
                active = validate_installed_bundle(
                    install,
                    expected_executable=journal.expected_executable,
                )
                if active.manifest_sha256 == journal.candidate_manifest_sha256:
                    journal = _replace_phase(
                        journal,
                        TransactionPhase.CANDIDATE_ACTIVE,
                        now=observed,
                    )
                    store.write_journal(journal)
                else:
                    rolled = _rollback_locked(
                        store,
                        journal,
                        now=observed,
                        detail="activation_candidate_mismatch",
                    )
                    return RecoveryResult(
                        "rolled_back", rolled.phase, rolled.txid, "previous bundle restored"
                    )
            else:
                rolled = _rollback_locked(
                    store,
                    journal,
                    now=observed,
                    detail="activation_rename_incomplete",
                )
                return RecoveryResult(
                    "rolled_back", rolled.phase, rolled.txid, "previous bundle restored"
                )
        if journal.phase == TransactionPhase.CANDIDATE_ACTIVE.value:
            if _health_matches(journal, store.read_health()):
                committed = _finalize_healthy_locked(
                    store,
                    journal,
                    now=observed,
                    fault=fault,
                )
                return RecoveryResult(
                    "committed", committed.phase, committed.txid, "health marker replayed"
                )
            if observed <= _parse_utc(journal.health_deadline, label="health_deadline"):
                active = validate_installed_bundle(
                    install,
                    expected_executable=journal.expected_executable,
                )
                if (
                    active.manifest_sha256 != journal.candidate_manifest_sha256
                    or not _path_exists_no_follow(backup)
                ):
                    raise UpdatePathError("health-pending candidate paths are inconsistent")
                return RecoveryResult(
                    "awaiting_health",
                    journal.phase,
                    journal.txid,
                    "candidate remains inside its bounded health window",
                )
            rolled = _rollback_locked(store, journal, now=observed, detail="health_timeout")
            return RecoveryResult(
                "rolled_back", rolled.phase, rolled.txid, "candidate health deadline expired"
            )
        if journal.phase in {
            TransactionPhase.HEALTH_ACCEPTED.value,
            TransactionPhase.HIGH_WATER_COMMITTED.value,
        }:
            committed = _finalize_healthy_locked(
                store,
                journal,
                now=observed,
                fault=fault,
            )
            return RecoveryResult(
                "committed", committed.phase, committed.txid, "health commit resumed"
            )
        raise UpdateStateError(f"transaction phase has no recovery rule: {journal.phase}")


__all__ = [
    "AuthenticatedUpdateState",
    "abort_update_transaction",
    "BundleTree",
    "HighWaterBinding",
    "ProcessGuard",
    "ProcessIdentity",
    "RecoveryResult",
    "TransactionPhase",
    "UpdateArchiveError",
    "UpdateHighWater",
    "UpdateJournal",
    "UpdatePathError",
    "UpdateProcessStillRunning",
    "UpdateRollbackError",
    "UpdateStateError",
    "UpdateTransactionError",
    "acquire_update_state_authority",
    "activate_prepared_update",
    "capture_process_guard",
    "extract_authenticated_bundle",
    "mark_update_healthy",
    "prepare_update_transaction",
    "read_process_identity",
    "recover_update_transaction",
    "require_guarded_process_exit",
    "validate_installed_bundle",
]
