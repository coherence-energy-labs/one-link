"""Recovery setup — the three real paths the UI offers.

The wizard at Settings -> Setup -> Set recovery used to be a self-
attestation form: a modal that asked the user to type "I have my
recovery info" to confirm something they had no in-app way to
actually do. The CLI shipped `one-link backup show / restore`,
`social_recovery` shipped the Shamir 3-of-5 wrap, and
`backup_bundle` shipped the encrypted `.olbak` exporter — but
none of it was reachable from the UI. The button promised setup
and delivered a flag flip.

This module is the bridge. It exposes the three real recovery
paths over HTTP, lets the UI run a real flow per track, and
records per-track state in settings so the Setup checklist shows
which paths are configured rather than a single global yes/no.

The three tracks
----------------
1. **Recovery phrase** (BIP-39 24 words). The canonical sovereignty
   primitive: paper-only, no transport, restorable on any fresh
   install via `one-link backup restore`. Verified by re-typing
   three random word positions so the user can't muscle-memory
   through.

2. **Trusted contacts** (Shamir 3-of-5 via `social_recovery`). User
   picks N paired peers, daemon mints N wrapped share files each
   sealed to its target guardian's Ed25519 identity, browser
   downloads the share files. User delivers each file to its
   guardian via whatever medium they trust (USB, email, in person).
   We deliberately do NOT auto-ship over the daemon wire — that
   would couple "setup" to "guardian's daemon online and accepts"
   and add a new wire frame. The wrap is sealed; the medium does
   not matter.

3. **Encrypted backup file** (`.olbak` via `backup_bundle`). Daemon
   creates the bundle, streams it to the browser as a download.
   User puts the file somewhere safe (cloud, USB, second device).

Each track sets its own state setting. The legacy
`one_setup_recovery_configured_at_ms` setting stays for back-compat
and is set when ANY track is configured. The Setup checklist
checks each track individually for richer status text.

Security posture
----------------
- All endpoints sit behind `_guarded` (auth + CSRF + rate-limit).
- The phrase endpoint adds `Cache-Control: no-store, no-cache,
  must-revalidate, max-age=0` + `Pragma: no-cache` so the 24
  words never land in browser cache or service-worker storage.
- Verification is per-token rate-limited (5 attempts / 60s) to
  prevent brute-force on the verify path.
- Bundle export streams via `Content-Disposition: attachment` so
  it goes to disk, not into a tab the user might leave open.
- Share files use a custom extension (`.olss`) + base64-encoded
  blobs so they survive being pasted into email / chat.
- No track touches the master seed if it does not exist —
  legacy installs without `master.seed` (pre-mnemonic flow) get
  a clear 503 with a "run `one-link backup init` first" message.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from one_link.key_material import (
    KeyMaterialError,
    KeyMaterialIntegrityError,
    KeyMaterialPersistenceError,
    artifact_exists,
    atomic_replace_bytes,
    read_bytes_if_exists,
    sync_existing_authority,
)


# ── settings keys (per-track state) ──────────────────────────────────

SETTING_PHRASE_VERIFIED_AT_MS = "one_setup_recovery_phrase_verified_at_ms"
SETTING_BACKUP_LAST_EXPORT_AT_MS = "one_setup_recovery_backup_last_export_at_ms"
SETTING_BACKUP_LAST_EXPORT_SIZE = "one_setup_recovery_backup_last_export_size"
SETTING_SOCIAL_CONFIGURED_AT_MS = "one_setup_recovery_social_configured_at_ms"
SETTING_SOCIAL_GUARDIAN_COUNT = "one_setup_recovery_social_guardian_count"
SETTING_SOCIAL_THRESHOLD_K = "one_setup_recovery_social_threshold_k"
SETTING_LEGACY_CONFIGURED_AT_MS = "one_setup_recovery_configured_at_ms"


# A live daemon cannot replace the key hierarchy or its open SQLite database
# underneath itself.  Restore requests therefore publish a durable intent and
# protected seed stage; daemon startup replays that intent before loading an
# identity, DRK, or State.  The intent is removed only after exact read-back
# proves that all derived authority converged on the recovered seed.
RECOVERY_INTENT_FILENAME = "recovery-authority.intent.json"
RECOVERY_SEED_STAGE_FILENAME = ".recovery-authority.seed.pending"
RECOVERY_BUNDLE_STAGE_FILENAME = ".recovery-bundle.olbak.pending"
RECOVERY_ROTATION_STAGE_FILENAME = ".recovery-rotation.json.pending"
RECOVERY_LOCK_FILENAME = ".recovery-authority.lock"
RECOVERY_INTENT_VERSION = 3
_RECOVERY_INTENT_MAX_BYTES = 4096
_RECOVERY_ROTATION_STAGE_VERSION = 1
_RECOVERY_ROTATION_STAGE_MAX_BYTES = 8 * 1024 * 1024
MAX_ROTATION_PEERS = 65536
_RECOVERY_RESERVED_MEMBER_NAMES = frozenset(
    {
        RECOVERY_INTENT_FILENAME.casefold(),
        RECOVERY_SEED_STAGE_FILENAME.casefold(),
        RECOVERY_BUNDLE_STAGE_FILENAME.casefold(),
        RECOVERY_ROTATION_STAGE_FILENAME.casefold(),
        RECOVERY_LOCK_FILENAME.casefold(),
        # The daemon owns an open lock on the inode at this path while replay
        # runs.  Replacing its pathname from an archive would let a second
        # process lock a new inode and violate single-instance safety.
        "daemon.lock",
        "control.port",
        "peer.port",
        "server.port",
    }
)


class RecoveryTransactionError(RuntimeError):
    """A durable recovery transaction is corrupt, conflicting, or incomplete."""


class RecoveryInProgressError(RecoveryTransactionError):
    """Another restore owns the cross-process recovery transaction lock."""


@contextlib.contextmanager
def _recovery_transaction_lock(data_dir: Path):
    """Take a non-blocking cross-process lock for recovery publication."""
    root = Path(data_dir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / RECOVERY_LOCK_FILENAME
    flags = os.O_RDWR | os.O_CREAT | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise RecoveryTransactionError("cannot open recovery transaction lock") from exc
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\x00")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RecoveryInProgressError(
                    "another recovery transaction is already in progress"
                ) from exc
        else:
            import fcntl

            flock = getattr(fcntl, "flock")
            lock_ex = int(getattr(fcntl, "LOCK_EX"))
            lock_nb = int(getattr(fcntl, "LOCK_NB"))
            try:
                flock(fd, lock_ex | lock_nb)
            except OSError as exc:
                raise RecoveryInProgressError(
                    "another recovery transaction is already in progress"
                ) from exc
        locked = True
        if os.name != "nt":
            os.chmod(path, 0o600)
        yield
    finally:
        if locked:
            with contextlib.suppress(OSError):
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    flock = getattr(fcntl, "flock")
                    lock_un = int(getattr(fcntl, "LOCK_UN"))
                    flock(fd, lock_un)
        os.close(fd)


@contextlib.contextmanager
def recovery_transaction_guard(data_dir: Path):
    """Public fail-closed exclusion guard for other authority transitions.

    Full-application activation and identity recovery both replace durable
    authority.  Callers preparing an update handoff use this same lock so a
    restore cannot be published between updater preflight and daemon exit.
    """

    with _recovery_transaction_lock(Path(data_dir)):
        yield


def _private_hardener(path: Path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)


def _atomic_small_private_file(path: Path, payload: bytes, *, label: str) -> None:
    expected = bytes(payload)

    def _validate(actual: bytes) -> None:
        if not secrets.compare_digest(actual, expected):
            raise KeyMaterialIntegrityError(f"{label} read-back mismatch")

    atomic_replace_bytes(
        Path(path),
        expected,
        label=label,
        validate=_validate,
        harden_path=_private_hardener,
    )


def _hash_regular_file(path: Path, *, expected_size: int, label: str) -> bytes:
    """Hash one stable regular non-link file with bounded streaming memory."""
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot inspect {label}") from exc
    attrs = int(getattr(before, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(attrs & reparse)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size != expected_size
    ):
        raise KeyMaterialPersistenceError(f"{label} failed regular-file size proof")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(candidate), flags)
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot open {label} for proof") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != expected_size
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
            or (before.st_dev and opened.st_dev and before.st_dev != opened.st_dev)
        ):
            raise KeyMaterialPersistenceError(f"{label} changed while opening")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise KeyMaterialPersistenceError(f"{label} grew while hashing")
            digest.update(chunk)
        after = os.fstat(fd)
        if (
            total != expected_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise KeyMaterialPersistenceError(f"{label} changed while hashing")
        try:
            named_after = candidate.lstat()
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                f"{label} changed while hashing"
            ) from exc
        if (
            not stat.S_ISREG(named_after.st_mode)
            or (opened.st_ino and named_after.st_ino and opened.st_ino != named_after.st_ino)
            or (opened.st_dev and named_after.st_dev and opened.st_dev != named_after.st_dev)
            or named_after.st_size != opened.st_size
            or named_after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise KeyMaterialPersistenceError(f"{label} changed while hashing")
        return digest.digest()
    finally:
        os.close(fd)


def _atomic_large_private_file(path: Path, payload: bytes, *, label: str) -> None:
    """Durably replace a bounded large blob without the 1 MiB key helper cap."""
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp.{secrets.token_hex(12)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(tmp), flags, 0o600)
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot create temporary {label}") from exc
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            try:
                count = os.write(fd, view[offset:offset + (1 << 20)])
            except OSError as exc:
                raise KeyMaterialPersistenceError(f"cannot write {label}") from exc
            if count <= 0:
                raise KeyMaterialPersistenceError(f"short write while storing {label}")
            offset += count
        try:
            os.fsync(fd)
        except OSError as exc:
            raise KeyMaterialPersistenceError(f"cannot durably flush {label}") from exc
    except Exception:
        os.close(fd)
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    else:
        os.close(fd)
    try:
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        _private_hardener(tmp)
        before = tmp.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(payload):
            raise KeyMaterialPersistenceError(f"temporary {label} failed size proof")
        expected_digest = hashlib.sha256(payload).digest()
        if _hash_regular_file(
            tmp,
            expected_size=len(payload),
            label=f"temporary {label}",
        ) != expected_digest:
            raise KeyMaterialPersistenceError(f"temporary {label} failed digest proof")
        os.replace(tmp, target)
        sync_existing_authority(target, label=label)
        after = target.lstat()
        if not stat.S_ISREG(after.st_mode) or after.st_size != len(payload):
            raise KeyMaterialPersistenceError(f"published {label} failed size proof")
        if _hash_regular_file(
            target,
            expected_size=len(payload),
            label=f"published {label}",
        ) != expected_digest:
            raise KeyMaterialPersistenceError(f"published {label} failed digest proof")
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _intent_path(data_dir: Path) -> Path:
    return Path(data_dir) / RECOVERY_INTENT_FILENAME


def _seed_stage_path(data_dir: Path) -> Path:
    return Path(data_dir) / RECOVERY_SEED_STAGE_FILENAME


def _bundle_stage_path(data_dir: Path) -> Path:
    return Path(data_dir) / RECOVERY_BUNDLE_STAGE_FILENAME


def _rotation_stage_path(data_dir: Path) -> Path:
    return Path(data_dir) / RECOVERY_ROTATION_STAGE_FILENAME


def _canonical_intent_bytes(intent: dict[str, Any]) -> bytes:
    return (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _reject_reserved_recovery_members(names: list[str]) -> None:
    for name in names:
        first = str(name).replace("\\", "/").split("/", 1)[0].casefold()
        if first in _RECOVERY_RESERVED_MEMBER_NAMES:
            raise ValueError("backup archive targets recovery transaction metadata")


def _parse_recovery_intent(blob: bytes) -> dict[str, Any]:
    try:
        raw = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryTransactionError("recovery intent is not canonical JSON") from exc
    if not isinstance(raw, dict):
        raise RecoveryTransactionError("recovery intent schema is invalid")
    version = raw.get("version")
    legacy_required = {
        "version", "phase", "seed_sha256", "bundle_sha256", "created_ms",
    }
    v2_required = legacy_required | {"kind", "rotation_sha256"}
    current_required = v2_required | {"overwrite_files"}
    if version == 1:
        required = legacy_required
    elif version == 2:
        required = v2_required
    elif version == RECOVERY_INTENT_VERSION:
        required = current_required
    else:
        raise RecoveryTransactionError("recovery intent version is unsupported")
    if set(raw) != required:
        raise RecoveryTransactionError("recovery intent schema is invalid")
    kind = raw.get("kind", "restore")
    if kind not in {"restore", "rotation"}:
        raise RecoveryTransactionError("recovery intent kind is invalid")
    allowed_phases = (
        {"prepared", "applied", "finalized"}
        if kind == "rotation"
        else {"prepared", "applied"}
    )
    if raw.get("phase") not in allowed_phases:
        raise RecoveryTransactionError("recovery intent phase is invalid")
    seed_digest = raw.get("seed_sha256")
    bundle_digest = raw.get("bundle_sha256")
    if (
        not isinstance(seed_digest, str)
        or len(seed_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in seed_digest)
    ):
        raise RecoveryTransactionError("recovery intent seed digest is invalid")
    if bundle_digest is not None and (
        not isinstance(bundle_digest, str)
        or len(bundle_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in bundle_digest)
    ):
        raise RecoveryTransactionError("recovery intent bundle digest is invalid")
    rotation_digest = raw.get("rotation_sha256")
    if rotation_digest is not None and (
        not isinstance(rotation_digest, str)
        or len(rotation_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in rotation_digest)
    ):
        raise RecoveryTransactionError("recovery intent rotation digest is invalid")
    if kind == "restore" and rotation_digest is not None:
        raise RecoveryTransactionError("restore intent carries rotation metadata")
    if kind == "rotation" and (
        rotation_digest is None or bundle_digest is not None
    ):
        raise RecoveryTransactionError("rotation intent commitments are invalid")
    overwrite_files = raw.get("overwrite_files", kind != "rotation")
    if type(overwrite_files) is not bool:
        raise RecoveryTransactionError("recovery overwrite policy is invalid")
    if kind == "rotation" and overwrite_files:
        raise RecoveryTransactionError("rotation intent has an invalid overwrite policy")
    created_ms = raw.get("created_ms")
    if type(created_ms) is not int or created_ms < 0:
        raise RecoveryTransactionError("recovery intent timestamp is invalid")
    if _canonical_intent_bytes(raw) != blob:
        raise RecoveryTransactionError("recovery intent encoding is not canonical")
    return raw


def _load_recovery_intent(data_dir: Path) -> Optional[dict[str, Any]]:
    blob = read_bytes_if_exists(
        _intent_path(data_dir),
        label="recovery intent",
        max_bytes=_RECOVERY_INTENT_MAX_BYTES,
        harden_path=_private_hardener,
    )
    if blob is None:
        return None
    return _parse_recovery_intent(blob)


def has_pending_recovery(data_dir: Path) -> bool:
    """Return true for any durable restore intent; malformed intents raise."""
    return _load_recovery_intent(Path(data_dir)) is not None


def _stage_recovered_authority(
    *,
    data_dir: Path,
    seed: bytes,
    bundle_bytes: Optional[bytes] = None,
    rotation_bytes: Optional[bytes] = None,
    overwrite_files: bool = True,
) -> dict[str, Any]:
    """Publish protected recovery inputs, with the intent marker last."""
    from one_link import lockbox, master_seed

    root = Path(data_dir)
    # A recovery staged on top of an unfinished data-key migration could never
    # replay (the migration journal blocks every key operation) and would in
    # turn block the migration (it refuses while recovery is pending).
    unfinished = lockbox.data_key_migration_in_progress(root)
    if unfinished is not None:
        raise RecoveryTransactionError(
            "a data-key migration is unfinished on this installation; run "
            f"`{lockbox.MIGRATION_COMMANDS[unfinished]}` to finish it before "
            "staging a recovery or rotation"
        )
    candidate = bytes(seed)
    if len(candidate) != master_seed.SEED_LEN_BYTES:
        raise ValueError(f"seed must be {master_seed.SEED_LEN_BYTES} bytes")
    seed_digest = hashlib.sha256(candidate).hexdigest()
    bundle_digest = (
        hashlib.sha256(bundle_bytes).hexdigest() if bundle_bytes is not None else None
    )
    rotation_digest = (
        hashlib.sha256(rotation_bytes).hexdigest()
        if rotation_bytes is not None
        else None
    )
    if bundle_bytes is not None and rotation_bytes is not None:
        raise ValueError("recovery transaction cannot stage a bundle and rotation")
    kind = "rotation" if rotation_bytes is not None else "restore"
    if type(overwrite_files) is not bool:
        raise TypeError("overwrite_files must be bool")
    if kind == "rotation" and overwrite_files:
        raise ValueError("rotation recovery cannot overwrite archive files")
    intent = {
        "version": RECOVERY_INTENT_VERSION,
        "kind": kind,
        "phase": "prepared",
        "seed_sha256": seed_digest,
        "bundle_sha256": bundle_digest,
        "rotation_sha256": rotation_digest,
        "overwrite_files": overwrite_files,
        "created_ms": int(time.time() * 1000),
    }
    with _recovery_transaction_lock(root):
        current = _load_recovery_intent(root)
        if current is not None:
            if (
                current["seed_sha256"] == seed_digest
                and current["bundle_sha256"] == bundle_digest
                and current.get("kind", "restore") == kind
                and current.get("rotation_sha256") == rotation_digest
                and current.get(
                    "overwrite_files",
                    current.get("kind", "restore") != "rotation",
                ) == overwrite_files
            ):
                staged_seed = _load_staged_recovery_seed(root, current)
                if not secrets.compare_digest(staged_seed, candidate):
                    raise RecoveryTransactionError(
                        "pending recovery seed does not match this retry"
                    )
                if bundle_bytes is not None and current["phase"] == "prepared":
                    from one_link import backup_bundle

                    staged_bundle = backup_bundle.read_bundle_file_bounded(
                        _bundle_stage_path(root)
                    )
                    if not secrets.compare_digest(
                        hashlib.sha256(staged_bundle).digest(),
                        hashlib.sha256(bundle_bytes).digest(),
                    ):
                        raise RecoveryTransactionError(
                            "pending recovery bundle does not match this retry"
                        )
                if rotation_bytes is not None and current["phase"] == "prepared":
                    staged_rotation = read_bytes_if_exists(
                        _rotation_stage_path(root),
                        label="recovery rotation stage",
                        max_bytes=_RECOVERY_ROTATION_STAGE_MAX_BYTES,
                        harden_path=_private_hardener,
                    )
                    if staged_rotation is None or not secrets.compare_digest(
                        hashlib.sha256(staged_rotation).digest(),
                        hashlib.sha256(rotation_bytes).digest(),
                    ):
                        raise RecoveryTransactionError(
                            "pending recovery rotation does not match this retry"
                        )
                return current
            raise RecoveryTransactionError(
                "a different recovery transaction is already pending restart"
            )
        encoded_seed = master_seed._encode_seed(candidate)

        def _validate_seed_stage(blob: bytes) -> None:
            decoded = master_seed._decode_seed_blob(blob)
            if hashlib.sha256(decoded).hexdigest() != seed_digest:
                raise KeyMaterialIntegrityError("recovery seed stage digest mismatch")

        atomic_replace_bytes(
            _seed_stage_path(root),
            encoded_seed,
            label="recovery seed stage",
            validate=_validate_seed_stage,
            harden_path=_private_hardener,
        )
        if bundle_bytes is not None:
            _atomic_large_private_file(
                _bundle_stage_path(root),
                bytes(bundle_bytes),
                label="recovery bundle stage",
            )
        else:
            with contextlib.suppress(FileNotFoundError):
                _bundle_stage_path(root).unlink()
        if rotation_bytes is not None:
            _atomic_large_private_file(
                _rotation_stage_path(root),
                bytes(rotation_bytes),
                label="recovery rotation stage",
            )
        else:
            with contextlib.suppress(FileNotFoundError):
                _rotation_stage_path(root).unlink()
        _atomic_small_private_file(
            _intent_path(root),
            _canonical_intent_bytes(intent),
            label="recovery intent",
        )
    return intent


# ── data classes ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrackState:
    """One row in the recovery status response."""
    track: str
    ready: bool
    available: bool
    last_action_at_ms: int
    extra: dict[str, Any]


@dataclass(frozen=True)
class RecoveryStatus:
    phrase: TrackState
    social: TrackState
    backup: TrackState

    @property
    def any_ready(self) -> bool:
        return self.phrase.ready or self.social.ready or self.backup.ready

    def to_dict(self) -> dict[str, Any]:
        def t(ts: TrackState) -> dict[str, Any]:
            return {
                "track": ts.track,
                "ready": ts.ready,
                "available": ts.available,
                "last_action_at_ms": ts.last_action_at_ms,
                **ts.extra,
            }
        return {
            "phrase": t(self.phrase),
            "social": t(self.social),
            "backup": t(self.backup),
            "any_ready": self.any_ready,
        }


# ── status snapshot ──────────────────────────────────────────────────


def _setting_int(state, key: str) -> int:
    with contextlib.suppress(Exception):
        return int(state.get_setting(key) or 0)
    return 0


def snapshot_status(state, data_dir: Path) -> RecoveryStatus:
    """Build the per-track recovery snapshot the UI renders.

    `available` means the prerequisites are in place to RUN the
    flow now (e.g. a master seed exists for phrase + backup tracks,
    paired peers exist for the social track).
    `ready` means the user has actually completed that track at
    least once.
    """
    from one_link import lockbox, master_seed
    has_master_seed = master_seed.has_seed(Path(data_dir))
    requires_passphrase_factor = lockbox.requires_legacy_passphrase_recovery(
        Path(data_dir)
    )

    phrase_verified = _setting_int(state, SETTING_PHRASE_VERIFIED_AT_MS)
    backup_at = _setting_int(state, SETTING_BACKUP_LAST_EXPORT_AT_MS)
    backup_size = _setting_int(state, SETTING_BACKUP_LAST_EXPORT_SIZE)
    social_at = _setting_int(state, SETTING_SOCIAL_CONFIGURED_AT_MS)
    social_count = _setting_int(state, SETTING_SOCIAL_GUARDIAN_COUNT)
    social_k = _setting_int(state, SETTING_SOCIAL_THRESHOLD_K)

    candidates = _social_candidate_count(state)

    return RecoveryStatus(
        phrase=TrackState(
            track="phrase",
            ready=phrase_verified > 0 and not requires_passphrase_factor,
            available=has_master_seed,
            last_action_at_ms=phrase_verified,
            extra={
                "requires_master_seed": True,
                "requires_lockbox_passphrase": requires_passphrase_factor,
                "additional_recovery_factors": (
                    ["ONE_LINK_PASSPHRASE"] if requires_passphrase_factor else []
                ),
            },
        ),
        social=TrackState(
            track="social",
            ready=social_at > 0 and not requires_passphrase_factor,
            available=has_master_seed and candidates >= 2,
            last_action_at_ms=social_at,
            extra={
                "guardian_count": social_count,
                "threshold_k": social_k,
                "candidate_count": candidates,
                "requires_lockbox_passphrase": requires_passphrase_factor,
                "additional_recovery_factors": (
                    ["ONE_LINK_PASSPHRASE"] if requires_passphrase_factor else []
                ),
            },
        ),
        backup=TrackState(
            track="backup",
            ready=backup_at > 0,
            available=has_master_seed,
            last_action_at_ms=backup_at,
            extra={"last_export_size_bytes": backup_size},
        ),
    )


def is_any_track_ready(state) -> bool:
    """Lightweight check used by the Setup checklist row."""
    return any(
        _setting_int(state, k) > 0
        for k in (
            SETTING_PHRASE_VERIFIED_AT_MS,
            SETTING_BACKUP_LAST_EXPORT_AT_MS,
            SETTING_SOCIAL_CONFIGURED_AT_MS,
            SETTING_LEGACY_CONFIGURED_AT_MS,
        )
    )


def configured_track_labels(state) -> list[str]:
    """Human-readable track names the Setup checklist surfaces in
    its 'how recovery is set up' summary line."""
    out: list[str] = []
    if _setting_int(state, SETTING_PHRASE_VERIFIED_AT_MS) > 0:
        out.append("recovery phrase")
    if _setting_int(state, SETTING_SOCIAL_CONFIGURED_AT_MS) > 0:
        out.append("trusted contacts")
    if _setting_int(state, SETTING_BACKUP_LAST_EXPORT_AT_MS) > 0:
        out.append("encrypted backup")
    if not out and _setting_int(state, SETTING_LEGACY_CONFIGURED_AT_MS) > 0:
        out.append("manual confirmation")
    return out


# ── track 1: recovery phrase ─────────────────────────────────────────


WORD_COUNT = 24


def load_phrase_words(data_dir: Path) -> Optional[list[str]]:
    """Return the 24 BIP-39 words for the current master seed, or
    None if no seed file exists yet."""
    from one_link import master_seed, mnemonic
    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        return None
    try:
        phrase = mnemonic.encode(seed)
    finally:
        # Best-effort. Python bytes are immutable, but this drops
        # our reference; the GC collects on the next pass.
        seed = b"\x00" * len(seed)
        del seed
    return phrase.split()


def pick_verification_indices(rng: secrets.SystemRandom | None = None) -> list[int]:
    """Pick three distinct 1-indexed positions in the 24-word phrase
    that the user must type back to prove they wrote it down. We
    pick from the full range; clustering would hint at "we only
    ever ask about the first few" and be muscle-memorisable across
    sessions.
    """
    r = rng or secrets.SystemRandom()
    return sorted(r.sample(range(1, WORD_COUNT + 1), 3))


def verify_phrase_positions(
    *, data_dir: Path, indices: list[int], words: list[str],
) -> tuple[bool, list[int]]:
    """Check that `words[i]` matches the word at position `indices[i]`
    in the daemon's current 24-word phrase. Returns (ok, mismatch_indices).

    Comparison is case-insensitive + whitespace-stripped. Position
    1 is the first word.
    """
    phrase_words = load_phrase_words(data_dir)
    if phrase_words is None:
        raise FileNotFoundError("no master seed on this install")
    if len(indices) != len(words):
        raise ValueError("indices and words must be same length")
    if not indices:
        raise ValueError("at least one position required")
    mismatches: list[int] = []
    for idx, supplied in zip(indices, words):
        if not (1 <= idx <= WORD_COUNT):
            raise ValueError(f"position out of range: {idx}")
        canon = (supplied or "").strip().lower()
        if canon != phrase_words[idx - 1]:
            mismatches.append(idx)
    return (len(mismatches) == 0, mismatches)


def test_bundle_against_phrase(
    *, phrase: str, bundle_bytes: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Non-destructive 'will this backup decrypt with this phrase?'
    check. Decodes the phrase via mnemonic.decode (validates the
    BIP-39 checksum), derives the bundle key via the same HKDF the
    exporter used, runs AEAD-decrypt on the bundle in memory, and
    counts plaintext entries. Writes nothing to disk. Useful to
    verify a backup file + paper phrase pair are still valid
    without committing to a destructive restore.

    Result shape:
      {
        "valid_phrase":        True iff phrase decodes cleanly,
        "valid_bundle":        True iff AEAD-decrypt passes,
        "bundle_created_ms":   header's created_ms (only set when
                               valid_bundle is True),
        "file_count":          number of plaintext archive entries
                               (excluding MANIFEST),
        "error":               short human-readable message on
                               failure,
      }
    """
    from one_link import backup_bundle, mnemonic
    out: dict[str, Any] = {
        "valid_phrase": False,
        "valid_bundle": False,
        "bundle_created_ms": 0,
        "file_count": 0,
        "error": "",
    }
    try:
        seed = mnemonic.decode(phrase)
    except (ValueError, TypeError) as e:
        out["error"] = str(e)
        return out
    out["valid_phrase"] = True
    try:
        header, plaintext = backup_bundle.open_bundle(
            seed=seed, bundle_bytes=bundle_bytes,
        )
    except ValueError as e:
        out["error"] = str(e)
        return out
    finally:
        seed = b"\x00" * len(seed)
        del seed
    out["valid_bundle"] = True
    out["bundle_created_ms"] = int(header.created_ms)
    # Fully stream-validate the plaintext without writing to disk. This uses
    # the same finite member/size/expansion/path policy as a real restore, so
    # "verified" means the bundle is actually admissible, not merely that its
    # AEAD tag and outer gzip header happen to be valid.
    try:
        names = backup_bundle.inspect_bundle_archive(plaintext=plaintext)
        out["file_count"] = len(names)
    except (OSError, ValueError):
        # AEAD validity alone is insufficient: a bundle whose authenticated
        # plaintext is not a readable archive cannot restore anything. Do not
        # present that partial success as a valid backup to the user.
        out["valid_bundle"] = False
        out["error"] = "bundle decrypted, but its archive is malformed"
    return out


def test_phrase_against_current_seed(
    *, data_dir: Path, phrase: str,
) -> dict[str, Any]:
    """Non-destructive 'did I write down my 24 words correctly?' check.

    Decodes the phrase via mnemonic.decode (validates the BIP-39
    checksum) and, if a master seed exists on this install,
    compares the decoded bytes against the on-disk seed in
    constant time. Returns a small dict the UI renders as a
    green/amber/red status.

    Result shape:
      {
        "valid_checksum": True iff the phrase decodes cleanly,
        "matches_current_seed": True iff bytes equal master.seed,
        "matches_current_identity": True iff the phrase matches the seed AND
          the live Ed25519 identity and data root are derived from that seed,
        "has_current_seed": True iff master.seed exists,
        "has_current_identity": True iff identity.key exists,
        "error": short human-readable message on checksum failure,
      }

    Does NOT write any state. Does NOT touch identity.key or DRK.
    Safe to call any number of times.
    """
    from one_link import lockbox, master_seed, mnemonic, paths
    import secrets as _secrets
    out: dict[str, Any] = {
        "valid_checksum": False,
        "matches_current_seed": False,
        "matches_current_identity": False,
        "matches_current_data_root": False,
        "matches_current_authority": False,
        "has_current_seed": False,
        "has_current_identity": False,
        "has_current_identity_artifact": False,
        "requires_lockbox_passphrase": False,
        "additional_recovery_factors": [],
        "error": "",
    }
    try:
        candidate = mnemonic.decode(phrase)
    except (ValueError, TypeError) as e:
        out["error"] = str(e)
        return out
    out["valid_checksum"] = True
    try:
        current = master_seed.load_seed(Path(data_dir))
    except Exception as exc:
        from one_link.key_material import KeyMaterialError

        if not isinstance(exc, KeyMaterialError):
            raise
        out["has_current_seed"] = True
        out["has_current_identity"] = True
        out["has_current_identity_artifact"] = artifact_exists(
            paths.key_path(), label="identity key"
        )
        out["error"] = "current_master_seed_unavailable"
        candidate = b"\x00" * len(candidate)
        del candidate
        return out
    if current is None:
        out["has_current_identity_artifact"] = artifact_exists(
            paths.key_path(), label="identity key"
        )
        return out
    out["has_current_seed"] = True
    # Backward-compatible presence alias retained for v1 clients.  The new
    # artifact field is the literal identity.key signal; green verification is
    # governed by the strict all-authority match below.
    out["has_current_identity"] = True
    out["has_current_identity_artifact"] = artifact_exists(
        paths.key_path(), label="identity key"
    )
    # secrets.compare_digest is constant-time-ish; the bytes
    # involved are 32 each, and Python's eq would short-circuit on
    # the first differing byte. compare_digest doesn't.
    try:
        seed_matches = _secrets.compare_digest(
            bytes(current), bytes(candidate),
        )
        out["matches_current_seed"] = seed_matches
        try:
            evidence = master_seed.inspect_derived_authority(
                Path(data_dir),
                identity_path=paths.key_path(),
                seed=bytes(candidate),
            )
        except KeyMaterialError:
            evidence = {"identity": False, "data_root": False}
            out["error"] = "current_derived_authority_unavailable"
        identity_matches = evidence["identity"] is True
        data_root_matches = evidence["data_root"] is True
        requires_passphrase = lockbox.requires_legacy_passphrase_recovery(
            Path(data_dir)
        )
        out["requires_lockbox_passphrase"] = requires_passphrase
        out["additional_recovery_factors"] = (
            ["ONE_LINK_PASSPHRASE"] if requires_passphrase else []
        )
        if seed_matches and identity_matches and requires_passphrase:
            out["error"] = "lockbox_passphrase_recovery_not_migrated"
        out["matches_current_data_root"] = bool(
            seed_matches and data_root_matches
        )
        out["matches_current_identity"] = bool(
            seed_matches and identity_matches and data_root_matches
        )
        out["matches_current_authority"] = out["matches_current_identity"]
    finally:
        # Best-effort wipe of the candidate seed we just decoded.
        candidate = b"\x00" * len(candidate)
        current = b"\x00" * len(current)
        del candidate
        del current
    return out


def test_shares_against_current_seed(
    *, data_dir: Path, shares: list[tuple[int, bytes]],
) -> dict[str, Any]:
    """Non-destructive 'do my K guardian shares still reconstruct my
    identity?' check.

    Combines the supplied unwrapped Shamir shares and, if a master
    seed exists on this install, compares the reconstructed bytes
    against the on-disk seed in constant time. Returns the same
    green/amber/red shape as test_phrase_against_current_seed so
    the UI can render share verification with the same status badge.

    Result shape:
      {
        "valid_recovery":          True iff combine succeeded and
                                   yielded the right seed length,
        "matches_current_identity": True iff reconstructed bytes
                                    equal the on-disk master.seed,
        "has_current_identity":    True iff master.seed exists,
        "share_count":             number of shares the caller
                                   supplied,
        "error":                   short human-readable message on
                                   combine/length failure,
      }

    Does NOT write any state. Does NOT touch identity.key or DRK.
    Safe for a guardian to run repeatedly during a recovery setup
    audit (e.g., 'every six months I'll verify a K-quorum of my
    friends still hold valid shares').
    """
    from one_link import lockbox, master_seed, paths, social_recovery
    import secrets as _secrets
    out: dict[str, Any] = {
        "valid_recovery": False,
        "matches_current_seed": False,
        "matches_current_identity": False,
        "matches_current_data_root": False,
        "matches_current_authority": False,
        "has_current_seed": False,
        "has_current_identity": False,
        "has_current_identity_artifact": False,
        "requires_lockbox_passphrase": False,
        "additional_recovery_factors": [],
        "share_count": len(shares) if shares else 0,
        "error": "",
    }
    if not shares or len(shares) < 2:
        out["error"] = "need at least 2 shares to verify"
        return out
    try:
        candidate = social_recovery.combine_shares(shares)
    except (ValueError, TypeError) as e:
        out["error"] = str(e)
        return out
    if len(candidate) != master_seed.SEED_LEN_BYTES:
        out["error"] = (
            f"reconstructed seed has wrong length {len(candidate)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
        return out
    out["valid_recovery"] = True
    try:
        current = master_seed.load_seed(Path(data_dir))
    except Exception as exc:
        from one_link.key_material import KeyMaterialError

        if not isinstance(exc, KeyMaterialError):
            raise
        out["has_current_seed"] = True
        out["has_current_identity"] = True
        out["has_current_identity_artifact"] = artifact_exists(
            paths.key_path(), label="identity key"
        )
        out["error"] = "current_master_seed_unavailable"
        candidate = b"\x00" * len(candidate)
        del candidate
        return out
    if current is None:
        out["has_current_identity_artifact"] = artifact_exists(
            paths.key_path(), label="identity key"
        )
        return out
    out["has_current_seed"] = True
    out["has_current_identity"] = True
    out["has_current_identity_artifact"] = artifact_exists(
        paths.key_path(), label="identity key"
    )
    try:
        seed_matches = _secrets.compare_digest(
            bytes(current), bytes(candidate),
        )
        out["matches_current_seed"] = seed_matches
        try:
            evidence = master_seed.inspect_derived_authority(
                Path(data_dir),
                identity_path=paths.key_path(),
                seed=bytes(candidate),
            )
        except KeyMaterialError:
            evidence = {"identity": False, "data_root": False}
            out["error"] = "current_derived_authority_unavailable"
        identity_matches = evidence["identity"] is True
        data_root_matches = evidence["data_root"] is True
        requires_passphrase = lockbox.requires_legacy_passphrase_recovery(
            Path(data_dir)
        )
        out["requires_lockbox_passphrase"] = requires_passphrase
        out["additional_recovery_factors"] = (
            ["ONE_LINK_PASSPHRASE"] if requires_passphrase else []
        )
        if seed_matches and identity_matches and requires_passphrase:
            out["error"] = "lockbox_passphrase_recovery_not_migrated"
        out["matches_current_data_root"] = bool(
            seed_matches and data_root_matches
        )
        out["matches_current_identity"] = bool(
            seed_matches and identity_matches and data_root_matches
        )
        out["matches_current_authority"] = out["matches_current_identity"]
    finally:
        candidate = b"\x00" * len(candidate)
        current = b"\x00" * len(current)
        del candidate
        del current
    return out


def mark_phrase_verified(state, now_ms: Optional[int] = None) -> int:
    """Record that the user successfully verified the phrase."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_PHRASE_VERIFIED_AT_MS, str(now_ms))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


# ── track 2: encrypted backup file (.olbak) ──────────────────────────


def build_backup_bundle(
    *, data_dir: Path, include_files: bool = False,
) -> bytes:
    """Return the encoded .olbak bundle bytes. Raises FileNotFoundError
    if no master seed exists."""
    from one_link import backup_bundle, master_seed
    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        raise FileNotFoundError("no master seed on this install")
    try:
        bundle = backup_bundle.create_bundle(
            seed=seed,
            data_dir=Path(data_dir),
            include_files=include_files,
        )
    finally:
        seed = b"\x00" * len(seed)
        del seed
    return bundle


def mark_backup_exported(
    state, *, size_bytes: int, now_ms: Optional[int] = None,
) -> int:
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_BACKUP_LAST_EXPORT_AT_MS, str(now_ms))
    state.set_setting(SETTING_BACKUP_LAST_EXPORT_SIZE, str(int(size_bytes)))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


def backup_filename(now_ms: int | None = None) -> str:
    """Suggest a download filename. Stable shape so the user can
    spot multiple exports by date."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    import datetime
    ts = datetime.datetime.fromtimestamp(now_ms / 1000)
    return f"one-link-backup-{ts.strftime('%Y%m%d-%H%M%S')}.olbak"


# ── track 3: trusted contacts (social recovery) ──────────────────────


# Trust values that mean "the user has pinned this peer as theirs"
# in state.set_peer_trust calls across daemon.py. Anything else
# (candidate / rejected / etc.) is not a sensible guardian target.
_GUARDIAN_TRUST_VALUES = {"pinned"}


def _social_candidate_count(state) -> int:
    """Count of paired peers we can plausibly wrap shares to. The
    UI uses this to decide whether to even surface the social track
    ('You need at least 2 trusted contacts before you can set this
    up')."""
    try:
        peers = state.list_peers()
    except Exception:
        return 0
    n = 0
    for p in peers or []:
        if getattr(p, "trust", None) in _GUARDIAN_TRUST_VALUES:
            pub = getattr(p, "pubkey", b"")
            if isinstance(pub, (bytes, bytearray)) and len(pub) == 32:
                n += 1
    return n


def list_social_candidates(state) -> list[dict[str, Any]]:
    """Return the paired-peer roster the UI shows for guardian
    selection. Each entry has id (fingerprint), label, pubkey_b64
    (the Ed25519 32 bytes that share-wrap targets), and a hint so
    the user can spot 'my own iPad' vs 'Bob'."""
    out: list[dict[str, Any]] = []
    try:
        peers = state.list_peers()
    except Exception:
        return out
    for p in peers or []:
        if getattr(p, "trust", None) not in _GUARDIAN_TRUST_VALUES:
            continue
        pub = getattr(p, "pubkey", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            continue
        label = getattr(p, "display_name", None) or getattr(p, "short_id", None) or "Trusted device"
        out.append({
            "id": getattr(p, "fingerprint", "") or "",
            "label": str(label),
            "pubkey_b64": base64.b64encode(bytes(pub)).decode("ascii"),
            "hostname": getattr(p, "hostname", "") or "",
            "verified": bool(getattr(p, "verified_at_ms", None)),
            "last_seen_ms": int(getattr(p, "last_seen_ms", 0) or 0),
        })
    return out


def issue_social_shares(
    *,
    data_dir: Path,
    guardians: list[dict[str, Any]],
    threshold_k: int = 3,
) -> list[dict[str, Any]]:
    """Split the master seed into N Shamir shares, each sealed to
    one guardian's Ed25519 pubkey. Returns N share descriptors the
    UI can render + offer as downloads.

    Each guardian dict must carry `label` (display string for the
    UI / share filename) and either `pubkey_b64` (raw 32 bytes
    base64-encoded) or `pubkey_hex`. Returned share descriptors:

        {
          "guardian_label": str,       # what the user picked
          "share_index": int,          # 1..N, matches the Shamir x
          "filename": str,             # suggested .olss filename
          "blob_b64u": str,            # the wrapped share bytes
          "threshold_k": int,          # K = required to combine
          "total_n": int,              # N = total shares issued
          "setup_ms": int,
        }
    """
    from one_link import master_seed, social_recovery
    if not guardians:
        raise ValueError("at least 2 guardians required")
    if threshold_k < 2:
        raise ValueError("threshold_k must be at least 2")
    if threshold_k > len(guardians):
        raise ValueError(
            f"threshold_k={threshold_k} cannot exceed guardian count {len(guardians)}"
        )

    seed = master_seed.load_seed(Path(data_dir))
    if seed is None:
        raise FileNotFoundError("no master seed on this install")
    try:
        # Normalise guardian shape: each needs (label, ed25519 pubkey bytes).
        named_pubs: list[tuple[str, bytes]] = []
        seen_pubs: set[bytes] = set()
        for g in guardians:
            label = str(g.get("label") or "Guardian").strip() or "Guardian"
            pub_b64 = g.get("pubkey_b64")
            pub_hex = g.get("pubkey_hex")
            if pub_b64:
                try:
                    pub = base64.b64decode(str(pub_b64), validate=True)
                except Exception as e:
                    raise ValueError(f"bad pubkey_b64 for {label!r}: {e}")
            elif pub_hex:
                try:
                    pub = bytes.fromhex(str(pub_hex))
                except ValueError as e:
                    raise ValueError(f"bad pubkey_hex for {label!r}: {e}")
            else:
                raise ValueError(f"guardian {label!r} missing pubkey")
            if len(pub) != 32:
                raise ValueError(
                    f"guardian {label!r} pubkey must be 32 bytes, got {len(pub)}"
                )
            if pub in seen_pubs:
                raise ValueError(
                    f"guardian {label!r} pubkey duplicates another guardian"
                )
            seen_pubs.add(pub)
            named_pubs.append((label, pub))

        setup_ms = int(time.time() * 1000)
        pairs = social_recovery.setup_social_recovery(
            seed=seed,
            guardians=named_pubs,
            threshold_k=threshold_k,
        )
    finally:
        seed = b"\x00" * len(seed)
        del seed

    total_n = len(pairs)
    out: list[dict[str, Any]] = []
    for label, share in pairs:
        safe_label = _safe_filename_segment(label)
        filename = (
            f"one-link-share-{share.share_index}-of-{total_n}-{safe_label}.olss"
        )
        out.append({
            "guardian_label": label,
            "share_index": share.share_index,
            "filename": filename,
            "blob_b64u": base64.urlsafe_b64encode(share.encoded).decode("ascii"),
            "threshold_k": share.threshold,
            "total_n": share.total,
            "setup_ms": share.setup_ms,
        })
    return out


def mark_social_configured(
    state,
    *,
    guardian_count: int,
    threshold_k: int,
    now_ms: Optional[int] = None,
) -> int:
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    state.set_setting(SETTING_SOCIAL_CONFIGURED_AT_MS, str(now_ms))
    state.set_setting(SETTING_SOCIAL_GUARDIAN_COUNT, str(int(guardian_count)))
    state.set_setting(SETTING_SOCIAL_THRESHOLD_K, str(int(threshold_k)))
    state.set_setting(SETTING_LEGACY_CONFIGURED_AT_MS, str(now_ms))
    return now_ms


def _safe_filename_segment(s: str) -> str:
    """Reduce a label to a safe filename slug. ASCII letters,
    digits, dash, underscore; spaces collapse to dashes; everything
    else drops. Caps at 32 chars."""
    out_chars: list[str] = []
    for ch in s:
        if ch.isalnum() or ch in {"-", "_"}:
            out_chars.append(ch)
        elif ch == " ":
            out_chars.append("-")
    slug = "".join(out_chars).strip("-_")[:32]
    return slug or "guardian"


# ── settings-reset hook for the existing `reset` setup_action ────────


# ── restore from phrase ──────────────────────────────────────────────


def _durable_unlink(path: Path, *, label: str) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot remove committed {label}") from exc
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(str(Path(path).parent), flags)
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            f"cannot open {label} directory for cleanup durability"
        ) from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            f"cannot durably commit {label} cleanup"
        ) from exc
    finally:
        os.close(fd)


def _load_staged_recovery_seed(data_dir: Path, intent: dict[str, Any]) -> bytes:
    from one_link import master_seed

    blob = read_bytes_if_exists(
        _seed_stage_path(data_dir),
        label="recovery seed stage",
        max_bytes=65536,
        harden_path=_private_hardener,
    )
    if blob is not None:
        seed = master_seed._decode_seed_blob(blob)
    else:
        # A crash may happen after all authority files converged but before
        # stage cleanup finished.  The durable master seed is then a valid
        # replay source, but only after matching the journal commitment.
        fallback_seed = master_seed.load_seed(Path(data_dir))
        if fallback_seed is None:
            raise RecoveryTransactionError(
                "recovery intent exists but its protected seed stage is missing"
            )
        seed = fallback_seed
    if hashlib.sha256(seed).hexdigest() != intent["seed_sha256"]:
        raise RecoveryTransactionError(
            "recovery seed does not match the durable intent commitment"
        )
    return seed


def _is_canonical_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _canonical_rotation_stage_bytes(stage: dict[str, Any]) -> bytes:
    return (json.dumps(stage, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _parse_rotation_stage(
    blob: bytes,
    *,
    seed: bytes,
) -> tuple[dict[str, Any], Any]:
    """Validate committed rotation metadata and its old-key signature."""
    from one_link import identity_rotation, master_seed

    try:
        stage = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryTransactionError(
            "recovery rotation stage is not canonical JSON"
        ) from exc
    required = {
        "version",
        "old_pub_hex",
        "old_fp",
        "new_fp",
        "cert_json",
        "sig_hex",
        "peer_fps",
        "queued_ms",
    }
    if not isinstance(stage, dict) or set(stage) != required:
        raise RecoveryTransactionError("recovery rotation stage schema is invalid")
    if stage.get("version") != _RECOVERY_ROTATION_STAGE_VERSION:
        raise RecoveryTransactionError("recovery rotation stage version is unsupported")
    if _canonical_rotation_stage_bytes(stage) != blob:
        raise RecoveryTransactionError("recovery rotation stage encoding is not canonical")
    old_pub_hex = stage.get("old_pub_hex")
    if (
        not isinstance(old_pub_hex, str)
        or len(old_pub_hex) != 64
        or any(ch not in "0123456789abcdef" for ch in old_pub_hex)
    ):
        raise RecoveryTransactionError("recovery rotation old public key is invalid")
    try:
        old_pub = bytes.fromhex(old_pub_hex)
    except ValueError as exc:
        raise RecoveryTransactionError(
            "recovery rotation old public key is invalid"
        ) from exc
    if not _is_canonical_fingerprint(stage.get("old_fp")):
        raise RecoveryTransactionError("recovery rotation old fingerprint is invalid")
    if not _is_canonical_fingerprint(stage.get("new_fp")):
        raise RecoveryTransactionError("recovery rotation new fingerprint is invalid")
    peers = stage.get("peer_fps")
    if (
        not isinstance(peers, list)
        or len(peers) > MAX_ROTATION_PEERS
        or any(not _is_canonical_fingerprint(peer) for peer in peers)
        or peers != sorted(set(peers))
    ):
        raise RecoveryTransactionError("recovery rotation peer snapshot is invalid")
    queued_ms = stage.get("queued_ms")
    if type(queued_ms) is not int or queued_ms < 0:
        raise RecoveryTransactionError("recovery rotation timestamp is invalid")
    try:
        cert = identity_rotation.RotationCertificate.from_wire_dict(
            {
                "cert_json": stage.get("cert_json"),
                "sig_hex": stage.get("sig_hex"),
            }
        )
        identity_rotation.verify_certificate(
            cert=cert,
            expected_old_pubkey=old_pub,
        )
    except (ValueError, identity_rotation.CertVerifyError) as exc:
        raise RecoveryTransactionError(
            "recovery rotation certificate is invalid"
        ) from exc
    new_pub = master_seed.derive_identity_priv(bytes(seed)).public_key().public_bytes_raw()
    if (
        cert.old_fp != stage["old_fp"]
        or cert.new_fp != stage["new_fp"]
        or cert.new_pub_hex != new_pub.hex()
        or cert.ts_ms != queued_ms
    ):
        raise RecoveryTransactionError(
            "recovery rotation certificate does not match staged authority"
        )
    return stage, cert


def _load_staged_rotation(
    data_dir: Path,
    intent: dict[str, Any],
    *,
    seed: bytes,
) -> tuple[dict[str, Any], Any]:
    digest = intent.get("rotation_sha256")
    if not isinstance(digest, str):
        raise RecoveryTransactionError("recovery rotation commitment is missing")
    blob = read_bytes_if_exists(
        _rotation_stage_path(data_dir),
        label="recovery rotation stage",
        max_bytes=_RECOVERY_ROTATION_STAGE_MAX_BYTES,
        harden_path=_private_hardener,
    )
    if blob is None:
        raise RecoveryTransactionError("recovery rotation stage is missing")
    if hashlib.sha256(blob).hexdigest() != digest:
        raise RecoveryTransactionError(
            "recovery rotation stage does not match the durable intent commitment"
        )
    return _parse_rotation_stage(blob, seed=seed)


def stage_rotation_authority_replacement(
    *,
    data_dir: Path,
    seed: bytes,
    old_priv: Any,
    cert: Any,
    pinned_peer_fingerprints: list[str],
    identity_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Durably stage a signed identity rotation without live mutation.

    The current seed, identity, data-root authority, and SQLite announcement
    queue remain byte-for-byte unchanged.  Daemon startup applies the staged
    authority under its singleton lock, then commits the complete peer snapshot
    in one FULL-synchronous SQLite transaction before retiring this journal.
    """
    from one_link import identity_rotation, lockbox, master_seed, paths

    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    candidate = bytes(seed)
    if len(candidate) != master_seed.SEED_LEN_BYTES:
        raise ValueError(f"seed must be {master_seed.SEED_LEN_BYTES} bytes")
    try:
        old_pub = old_priv.public_key().public_bytes_raw()
    except (AttributeError, TypeError, ValueError) as exc:
        raise TypeError("old_priv must be an Ed25519 private key") from exc
    current_seed = master_seed.load_seed(root)
    if current_seed is None:
        raise RecoveryTransactionError("identity rotation requires a master seed")
    try:
        if lockbox.requires_legacy_passphrase_recovery(root):
            raise RecoveryTransactionError(
                "legacy passphrase-mode application data has no seed recovery "
                "envelope; start One Link with the source ONE_LINK_PASSPHRASE "
                "and export a new backup before identity rotation"
            )
        expected_old_pub = (
            master_seed.derive_identity_priv(current_seed)
            .public_key()
            .public_bytes_raw()
        )
        if not secrets.compare_digest(old_pub, expected_old_pub):
            raise RecoveryTransactionError(
                "live identity does not match the current master seed"
            )
        evidence = master_seed.inspect_derived_authority(
            root,
            identity_path=id_path,
            seed=current_seed,
        )
        if evidence != {"identity": True, "data_root": True}:
            raise RecoveryTransactionError(
                "current identity authority is not fully converged"
            )
    finally:
        current_seed = b"\x00" * len(current_seed)
        del current_seed
    try:
        identity_rotation.verify_certificate(
            cert=cert,
            expected_old_pubkey=old_pub,
        )
    except identity_rotation.CertVerifyError as exc:
        raise RecoveryTransactionError("rotation certificate is not authorized") from exc
    new_pub = master_seed.derive_identity_priv(candidate).public_key().public_bytes_raw()
    if cert.new_pub_hex != new_pub.hex():
        raise RecoveryTransactionError(
            "rotation certificate does not name the staged master seed"
        )
    peers = sorted(set(pinned_peer_fingerprints))
    if len(peers) > MAX_ROTATION_PEERS:
        raise RecoveryTransactionError(
            f"rotation peer snapshot exceeds {MAX_ROTATION_PEERS} peers"
        )
    if any(not _is_canonical_fingerprint(peer) for peer in peers):
        raise RecoveryTransactionError(
            "rotation peer snapshot contains an invalid fingerprint"
        )
    wire = cert.to_wire_dict()
    stage = {
        "version": _RECOVERY_ROTATION_STAGE_VERSION,
        "old_pub_hex": old_pub.hex(),
        "old_fp": cert.old_fp,
        "new_fp": cert.new_fp,
        "cert_json": wire["cert_json"],
        "sig_hex": wire["sig_hex"],
        "peer_fps": peers,
        "queued_ms": int(cert.ts_ms),
    }
    encoded = _canonical_rotation_stage_bytes(stage)
    if len(encoded) > _RECOVERY_ROTATION_STAGE_MAX_BYTES:
        raise RecoveryTransactionError("rotation peer snapshot is too large")
    # Validate our own serialized artifact before publishing any stage file.
    _parse_rotation_stage(encoded, seed=candidate)
    _stage_recovered_authority(
        data_dir=root,
        seed=candidate,
        rotation_bytes=encoded,
        overwrite_files=False,
    )
    return {
        "pending_restart": True,
        "staged_peer_count": len(peers),
        "old_fp": cert.old_fp,
        "new_fp": cert.new_fp,
    }


def pending_recovery_summary(data_dir: Path) -> dict[str, Any]:
    """Return a non-secret, validated description of the pending journal."""
    root = Path(data_dir)
    intent = _load_recovery_intent(root)
    if intent is None:
        return {"pending": False}
    kind = str(intent.get("kind", "restore"))
    out: dict[str, Any] = {
        "pending": True,
        "kind": kind,
        "phase": str(intent["phase"]),
        "restart_required": intent["phase"] == "prepared",
    }
    if kind == "rotation" and intent["phase"] != "finalized":
        seed = _load_staged_recovery_seed(root, intent)
        try:
            stage, _cert = _load_staged_rotation(root, intent, seed=seed)
            out.update(
                {
                    "staged_peer_count": len(stage["peer_fps"]),
                    "old_fp": stage["old_fp"],
                    "new_fp": stage["new_fp"],
                }
            )
        finally:
            seed = b"\x00" * len(seed)
            del seed
    return out


def reveal_pending_rotation_phrase(
    *,
    data_dir: Path,
    expected_new_fp: str,
) -> dict[str, Any]:
    """Recover the phrase for exactly the named, not-yet-applied rotation.

    A successful rotation response can be lost before the browser renders its
    24 words. The protected seed must remain available for boot replay, so an
    authenticated UI may re-read it while the journal is still ``prepared``.
    Requiring the caller's observed target fingerprint prevents a stale tab
    from accidentally disclosing a later rotation. Disclosure is retry-safe
    for response loss but ceases permanently when that journal advances.
    """
    from one_link import mnemonic

    if not _is_canonical_fingerprint(expected_new_fp):
        raise ValueError("expected rotation fingerprint is invalid")
    root = Path(data_dir)
    with _recovery_transaction_lock(root):
        intent = _load_recovery_intent(root)
        if intent is None or intent.get("kind", "restore") != "rotation":
            raise RecoveryTransactionError("no identity rotation is pending")
        if intent["phase"] != "prepared":
            raise RecoveryTransactionError(
                "the pending rotation phrase is no longer available"
            )
        seed = _load_staged_recovery_seed(root, intent)
        try:
            stage, cert = _load_staged_rotation(root, intent, seed=seed)
            if not secrets.compare_digest(stage["new_fp"], expected_new_fp):
                raise RecoveryTransactionError(
                    "the pending rotation does not match the requested fingerprint"
                )
            phrase = mnemonic.encode(seed)
            return {
                "new_phrase": phrase,
                "new_words": phrase.split(),
                "old_fp": stage["old_fp"],
                "new_fp": stage["new_fp"],
                "staged_peer_count": len(stage["peer_fps"]),
                "created_ms": int(intent["created_ms"]),
                "reason": cert.reason,
            }
        finally:
            seed = b"\x00" * len(seed)
            del seed


def complete_pending_recovery(
    *,
    data_dir: Path,
    identity_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Replay a staged restore before daemon key/state initialization.

    This operation is idempotent.  Its intent marker remains durable across
    every intermediate failure and is removed last, after the bundle (if any)
    has been promoted and seed/identity/DRK exact-match proofs pass. A rotation
    keeps its applied journal until ``finalize_pending_rotation`` atomically
    commits every peer announcement after State opens.
    """
    from one_link import backup_bundle, master_seed, paths

    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    with _recovery_transaction_lock(root):
        intent = _load_recovery_intent(root)
        if intent is None:
            # Inputs written before a crash that happened prior to the final
            # intent publication are unauthorized orphans, not a transaction.
            for orphan, label in (
                (_bundle_stage_path(root), "orphaned recovery bundle stage"),
                (_seed_stage_path(root), "orphaned recovery seed stage"),
                (_rotation_stage_path(root), "orphaned recovery rotation stage"),
            ):
                if artifact_exists(orphan, label=label):
                    _durable_unlink(orphan, label=label)
            return {"completed": False, "written": []}

        seed = _load_staged_recovery_seed(root, intent)
        written: list[str] = []
        bundle_digest = intent["bundle_sha256"]
        kind = str(intent.get("kind", "restore"))
        if intent["phase"] == "prepared":
            # Capture the source seed before a portable archive can replace its
            # machine-bound on-disk representation.  An in-place passphrase
            # LockBox migration can then rewrap its stable DEK to the target
            # seed without ever deleting or guessing authority.  Corrupt or
            # foreign source authority is recoverable by an authenticated
            # target-bound bundle/passphrase and therefore is not itself fatal.
            previous_seed: Optional[bytes]
            try:
                previous_seed = master_seed.load_seed(root)
            except KeyMaterialError:
                previous_seed = None
            if kind == "rotation":
                # A valid signed peer-transition certificate is a required
                # half of rotation authority. Never install the new key first
                # and discover corrupt/missing delivery metadata afterward.
                _load_staged_rotation(root, intent, seed=seed)
            if bundle_digest is not None:
                bundle_path = _bundle_stage_path(root)
                try:
                    bundle_bytes = backup_bundle.read_bundle_file_bounded(bundle_path)
                except (OSError, ValueError) as exc:
                    raise RecoveryTransactionError(
                        "pending recovery bundle is unavailable or invalid"
                    ) from exc
                if hashlib.sha256(bundle_bytes).hexdigest() != bundle_digest:
                    raise RecoveryTransactionError(
                        "pending recovery bundle does not match the intent commitment"
                    )
                _header, plaintext = backup_bundle.open_bundle(
                    seed=seed,
                    bundle_bytes=bundle_bytes,
                )
                # Full policy validation precedes publication.  The extraction
                # helper stages and rolls back observable promotion errors.
                inspected = backup_bundle.inspect_bundle_archive(plaintext=plaintext)
                _reject_reserved_recovery_members(inspected)
                written = backup_bundle.extract_bundle_to_dir(
                    plaintext=plaintext,
                    target_dir=root,
                    overwrite=bool(intent.get("overwrite_files", True)),
                )

            from one_link import state as _state

            master_seed.install_seed_derived_authority(
                root,
                identity_path=id_path,
                seed=seed,
                previous_seed=previous_seed,
                # A bundle-restored state.db is already keyed to this seed;
                # only a state.db that survives the transaction is re-keyed.
                state_db_restored=any(
                    str(name).replace("\\", "/").casefold()
                    == _state.DB_FILE.casefold()
                    for name in written
                ),
            )
            # A durable applied phase separates transaction work from cleanup.
            # If power fails after either stage file is removed, replay can
            # prove the committed authority and finish cleanup without needing
            # the already-applied bundle again.
            intent = {**intent, "phase": "applied"}
            _atomic_small_private_file(
                _intent_path(root),
                _canonical_intent_bytes(intent),
                label="applied recovery intent",
            )
        else:
            current = master_seed.load_seed(root)
            evidence = master_seed.inspect_derived_authority(
                root,
                identity_path=id_path,
                seed=seed,
            )
            if (
                current is None
                or not secrets.compare_digest(current, seed)
                or evidence != {"identity": True, "data_root": True}
            ):
                raise RecoveryTransactionError(
                    "applied recovery authority failed replay verification"
                )
            if kind == "rotation" and intent["phase"] == "applied":
                _load_staged_rotation(root, intent, seed=seed)

        if kind == "rotation":
            # Authority is durable, but the signed certificate stays journaled
            # until the restored/open State DB contains the complete peer
            # snapshot in one durable transaction.
            return {
                "completed": False,
                "authority_applied": True,
                "pending_finalization": True,
                "written": [],
            }

        # Inputs first, applied intent last.  A cleanup crash re-enters the
        # applied branch, proves exact convergence, and safely resumes here.
        if bundle_digest is not None:
            _durable_unlink(
                _bundle_stage_path(root), label="recovery bundle stage"
            )
        _durable_unlink(_seed_stage_path(root), label="recovery seed stage")
        _durable_unlink(_intent_path(root), label="recovery intent")
        return {"completed": True, "written": written}


def finalize_pending_rotation(
    *,
    data_dir: Path,
    state: Any,
    identity_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Commit a boot-applied rotation's peer queue, then retire its journal.

    Queue insertion is FULL-synchronous, all-or-nothing, idempotent, and
    exact-match checked. The ``finalized`` phase is published only after
    SQLite commits, so every crash boundary safely replays.
    """
    from one_link import master_seed, paths

    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    with _recovery_transaction_lock(root):
        intent = _load_recovery_intent(root)
        if intent is None or intent.get("kind", "restore") != "rotation":
            return {"completed": False, "queued_peer_count": 0}
        if intent["phase"] == "prepared":
            raise RecoveryTransactionError(
                "rotation authority must be applied before queue finalization"
            )

        seed = _load_staged_recovery_seed(root, intent)
        try:
            current = master_seed.load_seed(root)
            evidence = master_seed.inspect_derived_authority(
                root,
                identity_path=id_path,
                seed=seed,
            )
            if (
                current is None
                or not secrets.compare_digest(current, seed)
                or evidence != {"identity": True, "data_root": True}
            ):
                raise RecoveryTransactionError(
                    "rotation authority failed finalization verification"
                )

            queued_count = 0
            if intent["phase"] == "applied":
                stage, _cert = _load_staged_rotation(root, intent, seed=seed)
                rows = [
                    {
                        "peer_fp": peer_fp,
                        "old_fp": stage["old_fp"],
                        "new_fp": stage["new_fp"],
                        "cert_json": stage["cert_json"],
                        "sig_hex": stage["sig_hex"],
                        "queued_ms": stage["queued_ms"],
                    }
                    for peer_fp in stage["peer_fps"]
                ]
                queue_batch = getattr(
                    state,
                    "queue_rotation_announcements_durable",
                    None,
                )
                if not callable(queue_batch):
                    raise RecoveryTransactionError(
                        "state cannot durably finalize rotation announcements"
                    )
                queued_ids = queue_batch(rows)
                if len(queued_ids) != len(rows):
                    raise RecoveryTransactionError(
                        "rotation announcement queue failed exact count proof"
                    )
                queued_count = len(rows)
                intent = {**intent, "phase": "finalized"}
                _atomic_small_private_file(
                    _intent_path(root),
                    _canonical_intent_bytes(intent),
                    label="finalized recovery rotation intent",
                )
            else:
                # A cleanup crash can leave a finalized marker after metadata
                # was removed. The marker is the durable proof that exact queue
                # read-back succeeded, so missing metadata is safe here.
                staged = read_bytes_if_exists(
                    _rotation_stage_path(root),
                    label="recovery rotation stage",
                    max_bytes=_RECOVERY_ROTATION_STAGE_MAX_BYTES,
                    harden_path=_private_hardener,
                )
                if staged is not None:
                    stage, _cert = _parse_rotation_stage(staged, seed=seed)
                    if (
                        hashlib.sha256(staged).hexdigest()
                        != intent["rotation_sha256"]
                    ):
                        raise RecoveryTransactionError(
                            "finalized rotation metadata changed before cleanup"
                        )
                    queued_count = len(stage["peer_fps"])

            _durable_unlink(
                _rotation_stage_path(root),
                label="recovery rotation stage",
            )
            _durable_unlink(_seed_stage_path(root), label="recovery seed stage")
            _durable_unlink(_intent_path(root), label="recovery intent")
            return {
                "completed": True,
                "queued_peer_count": queued_count,
            }
        finally:
            seed = b"\x00" * len(seed)
            del seed


def restore_artifact_evidence(
    data_dir: Path,
    *,
    identity_path: Optional[Path] = None,
) -> dict[str, int]:
    """Count durable artifacts whose replacement requires confirmation."""
    from one_link import keychain, lockbox, master_seed, paths

    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    candidates = {
        "master_seed_artifact": root / master_seed.SEED_FILENAME,
        "identity_key_artifact": id_path,
        "data_root_key_artifact": root / lockbox.DRK_FILENAME,
        "lockbox_salt_artifact": root / lockbox.SALT_FILENAME,
        "lockbox_dek_envelope_artifact": root / lockbox.DEK_ENVELOPE_FILENAME,
        # Everything the current data key protects, from the registry the
        # key-minting guards use (state.db and its sidecars included).
        **{
            f"{artifact.name}_artifact": artifact.path(root)
            for artifact in lockbox.DEK_PROTECTED_ARTIFACTS
            if not artifact.regenerable
        },
        "state_key_artifact": root / keychain.LOCAL_KEY_FILENAME,
        "state_recovery_key_artifact": root / keychain.RECOVERY_KEY_FILENAME,
        "pending_recovery_artifact": _intent_path(root),
        "pending_recovery_seed_stage_artifact": _seed_stage_path(root),
        "pending_recovery_bundle_stage_artifact": _bundle_stage_path(root),
        "pending_recovery_rotation_stage_artifact": _rotation_stage_path(root),
    }
    evidence: dict[str, int] = {}
    for key, path in candidates.items():
        evidence[key] = int(artifact_exists(path, label=key.replace("_", " ")))
    return evidence


def is_install_clean_for_restore(
    state,
    *,
    data_dir: Optional[Path] = None,
    identity_path: Optional[Path] = None,
) -> tuple[bool, dict[str, int]]:
    """Return (clean, evidence). An install is "clean" if restoring
    a different identity over it does not destroy meaningful user
    state. We count what would be orphaned: pinned peers, sent +
    received messages, groups, shared folders, self-mesh devices.

    A clean install only needs the user to confirm the phrase.
    A dirty install requires `force=True` on the restore call AND
    a stern UI warning that the prior identity will be replaced.
    """
    evidence: dict[str, int] = {}
    snapshot = getattr(state, "recovery_safety_counts", None)
    if callable(snapshot):
        try:
            raw = snapshot()
            required = (
                "pinned_peers",
                "messages",
                "group_messages",
                "groups",
                "shared_folders",
                "self_mesh_devices",
                "pending_transfers",
                "pending_outbox",
                "pending_folder_offers",
                "pending_rotation_announcements",
                "held_recovery_shares",
            )
            evidence = {key: max(0, int(raw[key])) for key in required}
            if data_dir is not None:
                evidence.update(
                    restore_artifact_evidence(
                        Path(data_dir), identity_path=identity_path
                    )
                )
            return all(value == 0 for value in evidence.values()), evidence
        except Exception:
            # This function controls whether identity replacement needs the
            # explicit destructive confirmation.  A corrupt/unavailable DB or
            # malformed adapter must never be interpreted as an empty install.
            return False, {
                "pinned_peers": 0,
                "messages": 0,
                "group_messages": 0,
                "groups": 0,
                "shared_folders": 0,
                "self_mesh_devices": 0,
                "pending_transfers": 0,
                "pending_outbox": 0,
                "pending_folder_offers": 0,
                "pending_rotation_announcements": 0,
                "held_recovery_shares": 0,
                "inspection_failures": 1,
            }

    # Compatibility for old State-like adapters.  It remains fail-closed:
    # missing/throwing collection methods add inspection_failures so they can
    # never authorize an unconfirmed destructive restore.
    failures = 0
    try:
        peers = state.list_peers()
        pinned = [p for p in (peers or []) if getattr(p, "trust", None) == "pinned"]
        evidence["pinned_peers"] = len(pinned)
    except Exception:
        evidence["pinned_peers"] = 0
        failures += 1
    for fn, key in (
        ("recent_messages", "messages"),
        ("recent_group_messages", "group_messages"),
        ("list_group_ids", "groups"),
        ("list_folders", "shared_folders"),
        ("list_self_mesh_devices", "self_mesh_devices"),
    ):
        f = getattr(state, fn, None)
        if callable(f):
            try:
                if fn == "recent_messages":
                    items = f(limit=1)
                elif fn == "recent_group_messages":
                    # This compatibility path cannot enumerate all group
                    # rooms without a group id. A missing optimized snapshot
                    # remains an inspection failure below rather than an
                    # accidental clean verdict.
                    raise RuntimeError("group-message safety count unavailable")
                else:
                    items = f()
                if items is None:
                    evidence[key] = 0
                elif hasattr(items, "__len__"):
                    evidence[key] = len(items)
                else:
                    evidence[key] = sum(1 for _ in items)
            except Exception:
                evidence[key] = 0
                failures += 1
        else:
            evidence[key] = 0
            failures += 1
    # Older adapters do not expose durable operation queues. Their absence is
    # explicitly unknown, hence fail-closed, rather than guessed empty.
    for key in (
        "pending_transfers",
        "pending_outbox",
        "pending_folder_offers",
        "pending_rotation_announcements",
        "held_recovery_shares",
    ):
        evidence[key] = 0
        failures += 1
    evidence["inspection_failures"] = failures
    if data_dir is not None:
        try:
            evidence.update(
                restore_artifact_evidence(
                    Path(data_dir), identity_path=identity_path
                )
            )
        except Exception:
            evidence["artifact_inspection_failures"] = 1
    # A "dirty" install has any of these.
    clean = all(v == 0 for v in evidence.values())
    return clean, evidence


def stage_seed_authority_replacement(
    *,
    data_dir: Path,
    seed: bytes,
    allow_replace: bool,
    identity_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Publish one durable seed/identity/DRK replacement transaction.

    The function is the only supported primitive for CLI and HTTP paper/social
    recovery.  It never pre-deletes current authority.  A genuinely empty,
    offline target commits synchronously; any existing authority or state
    remains byte-identical until daemon startup owns the singleton lock and
    replays the intent.
    """

    from one_link import lockbox, master_seed, paths

    if not isinstance(seed, (bytes, bytearray)) or len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(f"seed must be {master_seed.SEED_LEN_BYTES} bytes")
    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    evidence = restore_artifact_evidence(root, identity_path=id_path)
    destructive = any(evidence.values())
    if destructive and not allow_replace:
        raise RecoveryTransactionError(
            "restore would replace existing authority or state without confirmation"
        )
    if (
        destructive
        and lockbox.requires_legacy_passphrase_recovery(root)
        and not os.environ.get(lockbox.PASSPHRASE_ENV, "")
    ):
        raise RecoveryTransactionError(
            "legacy application data requires the source "
            "ONE_LINK_PASSPHRASE as an explicit recovery factor"
        )
    _stage_recovered_authority(data_dir=root, seed=bytes(seed))
    if not destructive:
        complete_pending_recovery(data_dir=root, identity_path=id_path)
    return {
        "pending_restart": destructive,
        "evidence": evidence,
    }


def restore_seed_from_phrase(
    *,
    data_dir: Path,
    phrase: str,
    delete_identity_files: bool,
) -> bytes:
    """Decode the 24-word phrase and stage one authority transaction.

    Existing seed/identity/DRK/state files are never pre-deleted or modified.
    An empty offline target completes synchronously; replacement remains a
    durable intent until daemon startup owns the singleton lock and proves
    seed, identity, and data-root convergence.

    Raises ``ValueError`` on bad/incomplete phrase (mnemonic.decode's
    own checksum check), ``FileNotFoundError`` is not raised here -
    callers decide whether to allow overwriting an existing seed.

    Returns the 32-byte decoded seed for the caller's immediate verification.
    """
    from one_link import master_seed, mnemonic
    # Decode + verify checksum BEFORE touching disk. mnemonic.decode
    # raises ValueError with a clear message on bad phrase / typo.
    seed = mnemonic.decode(phrase)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"decoded seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    stage_seed_authority_replacement(
        data_dir=Path(data_dir),
        seed=seed,
        allow_replace=delete_identity_files,
    )
    return seed


def restore_from_bundle(
    *,
    data_dir: Path,
    phrase: str,
    bundle_bytes: bytes | bytearray | memoryview,
    delete_identity_files: bool,
    overwrite: bool,
    identity_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Combined phrase + .olbak restore. Decodes the phrase to a
    seed and authenticates the outer bundle with its seed-derived HKDF key.
    Current bundles also carry seed-wrapped LockBox/SQLCipher recovery
    artifacts; unmigrated legacy passphrase bundles explicitly require their
    source passphrase. A live target is durably staged, not extracted under an
    open daemon.

    Returns a small descriptor: which files were written, plus the
    bundle's created_ms timestamp so the UI can confirm "restored a
    backup from 3 days ago."

    Raises ``ValueError`` on bad phrase OR bad bundle (tampered /
    wrong key / truncated).
    """
    from one_link import backup_bundle, lockbox, master_seed, mnemonic
    from one_link import paths
    seed = mnemonic.decode(phrase)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"decoded seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    # Decrypt + length-check the bundle BEFORE touching the daemon's
    # state. If decryption fails (wrong seed, tamper) we want the
    # error to surface before we wipe identity.key + DRK.
    header, plaintext = backup_bundle.open_bundle(
        seed=seed, bundle_bytes=bundle_bytes,
    )
    # Fully validate the authenticated archive before publishing a durable
    # restore intent.  The bundle itself stays encrypted while staged.
    visible = backup_bundle.inspect_bundle_archive(plaintext=plaintext)
    _reject_reserved_recovery_members(visible)
    visible_names = {str(name).casefold() for name in visible}
    if (
        lockbox.SALT_FILENAME.casefold() in visible_names
        and lockbox.DEK_ENVELOPE_FILENAME.casefold() not in visible_names
        and not os.environ.get(lockbox.PASSPHRASE_ENV, "")
    ):
        raise RecoveryTransactionError(
            "this legacy backup requires its source ONE_LINK_PASSPHRASE "
            "in addition to the recovery phrase"
        )
    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    evidence = restore_artifact_evidence(root, identity_path=id_path)
    if any(evidence.values()) and not (delete_identity_files and overwrite):
        raise RecoveryTransactionError(
            "bundle restore would replace existing authority or state without confirmation"
        )
    _stage_recovered_authority(
        data_dir=root,
        seed=seed,
        bundle_bytes=bytes(bundle_bytes),
        overwrite_files=overwrite,
    )
    pending_restart = bool(delete_identity_files)
    validated_members = list(visible)
    if not delete_identity_files:
        completed = complete_pending_recovery(
            data_dir=root,
            identity_path=id_path,
        )
        visible = list(completed["written"])
    # Best-effort seed wipe.
    try:
        return {
            "written": [] if pending_restart else visible,
            "validated_members": validated_members,
            "file_count": len(validated_members),
            "bundle_created_ms": int(header.created_ms),
            "pending_restart": pending_restart,
        }
    finally:
        seed = b"\x00" * len(seed)
        del seed


# ── held-share import (guardian-side social recovery) ───────────────


def restore_from_shares(
    *,
    data_dir: Path,
    shares: list[tuple[int, bytes]],
    delete_identity_files: bool,
) -> bytes:
    """Combine K unwrapped Shamir shares and stage recovered authority.

    Mirrors ``restore_seed_from_phrase`` but takes shares instead of a phrase:
    the recoverer's third path. Existing live authority is never pre-deleted.

    Each share is (share_index, share_bytes) as produced by the
    guardian's unwrap_share call (or the unwrap HTTP endpoint).
    Must supply at least K of N where K is the threshold the
    original split used; the combine step infers K from the
    supplied count.

    Raises ValueError on malformed shares OR on combine failure
    (e.g., shares from different splits, fewer than threshold).
    Returns the 32-byte reconstructed seed for immediate verification.
    """
    from one_link import master_seed, social_recovery
    if not shares or len(shares) < 2:
        raise ValueError("need at least 2 shares to recover")
    seed = social_recovery.combine_shares(shares)
    if len(seed) != master_seed.SEED_LEN_BYTES:
        raise ValueError(
            f"reconstructed seed has wrong length {len(seed)}; "
            f"expected {master_seed.SEED_LEN_BYTES}"
        )
    try:
        stage_seed_authority_replacement(
            data_dir=Path(data_dir),
            seed=seed,
            allow_replace=delete_identity_files,
        )
        return seed
    finally:
        # Best-effort wipe of our reference; on-disk copy is the
        # canonical source going forward.
        seed_copy = seed
        seed = b"\x00" * len(seed)
        del seed
        # Wipe the local var too (not perfect; Python bytes are
        # immutable, but this drops our reference).
        del seed_copy


def parse_held_share_blob(blob: bytes) -> dict[str, Any]:
    """Parse an incoming .olss wrapped-share file. Returns a dict
    the state.insert_held_share helper can persist directly.

    Validates magic + version + header length. Does NOT verify the
    AEAD tag (that requires the guardian's private key; we defer
    that check until unwrap-time so a guardian can import shares
    on a device that doesn't have their key handy yet)."""
    from one_link import social_recovery
    wrapped = social_recovery.WrappedShare.parse(blob)
    return {
        "share_index": wrapped.share_index,
        "threshold_k": wrapped.threshold,
        "total_n": wrapped.total,
        "setup_ms": wrapped.setup_ms,
        "wrapped_blob": wrapped.encoded,
    }


def reset_all_recovery_state(state) -> None:
    """Wipe the per-track recovery settings. Called from the
    existing `reset` setup_action so the new state vanishes along
    with the rest of the one_setup flags."""
    for key in (
        SETTING_PHRASE_VERIFIED_AT_MS,
        SETTING_BACKUP_LAST_EXPORT_AT_MS,
        SETTING_BACKUP_LAST_EXPORT_SIZE,
        SETTING_SOCIAL_CONFIGURED_AT_MS,
        SETTING_SOCIAL_GUARDIAN_COUNT,
        SETTING_SOCIAL_THRESHOLD_K,
        SETTING_LEGACY_CONFIGURED_AT_MS,
    ):
        with contextlib.suppress(Exception):
            state.delete_setting(key)


# ── data-key migration: `one-link recovery set-passphrase` / remove ───
#
# Moves an installation's application data key between silent mode (the DEK
# is derive_drk(seed)) and passphrase mode (a fresh random DEK in the
# dual-slot envelope), in ONE offline, crash-replayable transaction:
#
#   1. the daemon instance lock (refuses while a daemon runs) and, for the
#      whole transaction, the envelope lock (a concurrent `backup export`
#      waits, boundedly, instead of archiving a half-migrated install);
#   2. a durable intent journal; while it exists every other envelope
#      transaction -- boot, export, recovery -- refuses;
#   3. preflight: every DEK_PROTECTED_ARTIFACTS envelope and every data-key
#      KEY_PROTECTED_FIELDS value must authenticate under the current key or
#      the target key, or nothing is changed;
#   4. carry the files, then the fields (one SQLite transaction), then the
#      SQLCipher database key, each classifying by decryption and doing only
#      what is still missing;
#   5. verify everything under the target key, THEN publish it (set: rename
#      the staged envelope live; remove: rename the envelope out of service);
#   6. verify again through the readers the daemon uses (acquire_lockbox,
#      inspect_derived_authority) and only then delete the old authority and
#      the journal.
#
# Mnemonic semantics: the master seed and identity never change, so the
# 24-word phrase is unchanged.  In passphrase mode the envelope's seed slot
# opens the DEK, so the phrase plus a backup bundle (which carries the
# envelope and salt) still recovers everything without the passphrase; the
# phrase alone recovers identity and the silent DRK, exactly as before.

DATA_KEY_MIGRATION_INTENT_VERSION = 1
MIGRATION_FAULT_POINTS = {
    "set_passphrase": (
        "intent_written", "staged", "files_carried", "fields_carried",
        "database_rekeyed", "published", "verified",
    ),
    "remove_passphrase": (
        "intent_written", "files_carried", "fields_carried",
        "database_rekeyed", "retired", "verified", "discarded",
    ),
}


class DataKeyMigrationError(RecoveryTransactionError):
    """A data-key migration refused, or found the installation inconsistent."""


@contextlib.contextmanager
def daemon_instance_lock(data_dir: Path):
    """Hold the daemon's own singleton lock for an offline transaction.

    The daemon's lock implementation is reused exactly as ``run()`` reuses it
    for its bootstrap, so a daemon cannot start mid-transaction and this
    refuses (after the daemon's own short hand-off wait) while one runs.
    """
    from one_link import paths
    from one_link.daemon import Daemon

    if Path(data_dir).resolve() != paths.data_dir().resolve():
        raise DataKeyMigrationError(
            "the data-key migration runs only on this ONE_LINK_HOME's data directory"
        )
    owner = object.__new__(Daemon)
    owner._lock_file = None
    try:
        owner._acquire_instance_lock()
    except RuntimeError as exc:
        raise DataKeyMigrationError(
            f"stop One Link first: {exc}; the data key cannot change under a running daemon"
        ) from exc
    try:
        yield
    finally:
        owner._release_instance_lock()


@contextlib.contextmanager
def _passphrase_environment(value: Optional[str]):
    """Scope ONE_LINK_PASSPHRASE for readers that consult it (keychain, LockBox)."""
    from one_link import lockbox

    name = lockbox.PASSPHRASE_ENV
    previous = os.environ.get(name)
    if value:
        os.environ[name] = value
    else:
        os.environ.pop(name, None)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _stored_database_key(root: Path) -> Optional[str]:
    """The keychain/local state-database key, ignoring ONE_LINK_PASSPHRASE."""
    from one_link import keychain

    with _passphrase_environment(None):
        return keychain._configured_passphrase_at(root)


def _migration_intent_path(root: Path) -> Path:
    from one_link import lockbox

    return root / lockbox.MIGRATION_INTENT_FILENAME


def _write_migration_intent(root: Path, kind: str) -> None:
    payload = json.dumps(
        {
            "version": DATA_KEY_MIGRATION_INTENT_VERSION,
            "kind": kind,
            "started_ms": int(time.time() * 1000),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    _atomic_small_private_file(
        _migration_intent_path(root), payload, label="data-key migration intent",
    )


def _rekey_state_database(
    db_path: Path, *, source_keys: list[Optional[str]], target_key: Optional[str],
) -> str:
    """Move the SQLCipher key of an offline state.db; classify by opening it.

    ``current`` (target opens it), ``rekeyed``, ``plaintext`` (no SQLCipher
    key to move: whoever opens it next encrypts it under the key it holds),
    or ``absent``.  Never guesses: a database that opens under neither key
    refuses.
    """
    from one_link import state_encryption

    kind = state_encryption.detect_db_state(db_path)
    if kind in ("missing", "empty"):
        return "absent"
    if kind == "plaintext":
        return "plaintext"
    if target_key and state_encryption.database_accepts_passphrase(db_path, target_key):
        return "current"
    if not target_key:
        raise DataKeyMigrationError(
            "state.db is encrypted but no target database key is available "
            "(at-rest key management is disabled or has no usable store)"
        )
    for source in source_keys:
        if source and state_encryption.database_accepts_passphrase(db_path, source):
            state_encryption.replace_encrypted_database_key_atomic(
                db_path=db_path,
                source_passphrase=source,
                destination_passphrase=target_key,
            )
            if not state_encryption.database_accepts_passphrase(db_path, target_key):
                raise DataKeyMigrationError(
                    "state.db does not open under its new key after re-keying"
                )
            return "rekeyed"
    raise DataKeyMigrationError(
        "state.db opens with neither the current nor the target database key"
    )


def _verify_under(
    root: Path, *, data_key: bytes, seed: bytes, database_keys: list[Optional[str]],
) -> None:
    """Fail loudly unless every artifact and field opens under ``data_key``."""
    from one_link import lockbox
    from one_link import state as state_module

    unopenable = lockbox.dek_artifacts_unopenable_by(root, lockbox.LockBox(data_key))
    if unopenable:
        raise DataKeyMigrationError(
            "verification failed: these artifacts do not open under the new "
            f"data key: {', '.join(a.relpath for a in unopenable)}"
        )
    report = state_module.rekey_offline_state_fields(
        root / state_module.DB_FILE,
        database_keys=database_keys,
        previous_data_key=data_key,
        target_data_key=data_key,
        seed=seed,
        dry_run=True,
    )
    bad = {
        name: counts for name, counts in report.items()
        if counts["unopenable"] or counts["rekeyed"]
    }
    if bad:
        raise DataKeyMigrationError(
            f"verification failed: state.db fields do not open under the new data key: {bad}"
        )


def _preflight(
    root: Path,
    *,
    current_key: bytes,
    target_key: Optional[bytes],
    seed: bytes,
    database_keys: list[Optional[str]],
) -> None:
    """Refuse before changing anything unless all data opens under a held key.

    ``target_key`` is ``None`` before the target exists (a first run of
    set-passphrase); on a replay, values already carried open under it.
    """
    from one_link import lockbox
    from one_link import state as state_module

    held = [current_key] + ([target_key] if target_key is not None else [])
    unopenable = lockbox.dek_artifacts_unopenable_by_any(root, held)
    if unopenable:
        raise DataKeyMigrationError(
            "refusing to migrate: these artifacts open under neither the "
            "current nor the target data key (the installation is already "
            f"inconsistent): {', '.join(a.relpath for a in unopenable)}"
        )
    report = state_module.rekey_offline_state_fields(
        root / state_module.DB_FILE,
        database_keys=database_keys,
        previous_data_key=current_key,
        target_data_key=target_key if target_key is not None else current_key,
        seed=seed,
        dry_run=True,
    )
    bad = sorted(name for name, counts in report.items() if counts["unopenable"])
    if bad:
        raise DataKeyMigrationError(
            "refusing to migrate: state.db fields open under neither the "
            f"current nor the target data key: {', '.join(bad)}"
        )


def _converged_evidence(root: Path, *, id_path: Path, seed: bytes) -> dict[str, Any]:
    from one_link import master_seed

    return master_seed.inspect_derived_authority(root, identity_path=id_path, seed=seed)


def _require_converged(root: Path, *, id_path: Path, seed: bytes, passphrase: Optional[str]) -> None:
    """Final proof, under the environment the daemon of the new mode runs with."""
    with _passphrase_environment(passphrase):
        evidence = _converged_evidence(root, id_path=id_path, seed=seed)
    if evidence != {"identity": True, "data_root": True}:
        raise DataKeyMigrationError(f"verification failed: authority evidence {evidence}")


def _probe_same_key(box: Any, data_key: bytes, *, what: str) -> None:
    from one_link import lockbox

    if not lockbox.holds_data_key(box, data_key):
        raise DataKeyMigrationError(
            f"verification failed: {what} does not hand out the migrated data key"
        )


def set_data_key_passphrase(
    *,
    data_dir: Path,
    passphrase: str,
    identity_path: Optional[Path] = None,
    _fault: Optional[Any] = None,
) -> dict[str, Any]:
    """Silent -> passphrase mode, in one offline crash-replayable transaction.

    Afterwards the passphrase is also the state database's SQLCipher key, so
    One Link must be started with ONE_LINK_PASSPHRASE set.  Re-running after
    any interruption finishes the same migration; a different passphrase on
    replay refuses.  Already in passphrase mode with this passphrase: a
    verified no-op.
    """
    return _migrate_data_key(
        kind="set_passphrase",
        data_dir=Path(data_dir),
        passphrase=passphrase,
        identity_path=identity_path,
        fault=_fault,
    )


def remove_data_key_passphrase(
    *,
    data_dir: Path,
    passphrase: str,
    identity_path: Optional[Path] = None,
    _fault: Optional[Any] = None,
) -> dict[str, Any]:
    """Passphrase -> silent mode, authorized by the passphrase being removed.

    The data key becomes derive_drk(seed) and the database key a stored
    keychain/local key again (minted if none exists), so One Link must then
    be started WITHOUT ONE_LINK_PASSPHRASE.
    """
    return _migrate_data_key(
        kind="remove_passphrase",
        data_dir=Path(data_dir),
        passphrase=passphrase,
        identity_path=identity_path,
        fault=_fault,
    )


def _migrate_data_key(
    *,
    kind: str,
    data_dir: Path,
    passphrase: str,
    identity_path: Optional[Path],
    fault: Optional[Any],
) -> dict[str, Any]:
    from one_link import lockbox, master_seed, paths
    from one_link import state as state_module

    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    step = fault if callable(fault) else (lambda _point: None)
    root = Path(data_dir)
    id_path = Path(identity_path) if identity_path is not None else paths.key_path()
    db_path = root / state_module.DB_FILE
    with daemon_instance_lock(root):
        if has_pending_recovery(root):
            raise DataKeyMigrationError(
                "a recovery transaction is pending; start One Link once to "
                "complete it before changing the data key"
            )
        seed = master_seed.load_seed(root)
        if seed is None:
            raise DataKeyMigrationError(
                "this installation has no recovery seed: run `one-link backup "
                "init` and start One Link once, then retry"
            )
        silent_key = master_seed.derive_drk(seed)
        with lockbox._envelope_mutation_lock(
            root, purpose=lockbox.MIGRATION_COMMANDS[kind], migration=True,
        ):
            in_progress = lockbox.data_key_migration_in_progress(root)
            if in_progress is not None and in_progress != kind:
                raise DataKeyMigrationError(
                    f"an unfinished {in_progress.replace('_', '-')} migration "
                    f"must be finished first: run `{lockbox.MIGRATION_COMMANDS[in_progress]}`"
                )
            if in_progress is None:
                # Judged as the daemon of the mode the install is ACTUALLY in
                # (a live envelope means passphrase mode): a passphrase in this
                # process's environment says nothing about a silent install.
                current_mode_passphrase = (
                    passphrase if lockbox._load_envelope(root) is not None else None
                )
                with _passphrase_environment(current_mode_passphrase):
                    evidence = _converged_evidence(root, id_path=id_path, seed=seed)
                # The one unconverged state this command repairs: seeded legacy
                # passphrase rows whose envelope was never published (the
                # bootstrap refuses them; set-passphrase publishes it).
                legacy_unmigrated = (
                    kind == "set_passphrase"
                    and evidence == {"identity": True, "data_root": False}
                    and lockbox.requires_legacy_passphrase_recovery(root)
                )
                if evidence != {"identity": True, "data_root": True} and not legacy_unmigrated:
                    raise DataKeyMigrationError(
                        f"installation authority is not converged ({evidence}); "
                        "start One Link once (or complete recovery) first"
                    )
            if kind == "set_passphrase":
                return _set_passphrase_steps(
                    root, db_path=db_path, seed=seed, silent_key=silent_key,
                    passphrase=passphrase, resumed=in_progress is not None,
                    id_path=id_path, step=step,
                )
            return _remove_passphrase_steps(
                root, db_path=db_path, seed=seed, silent_key=silent_key,
                passphrase=passphrase, resumed=in_progress is not None,
                id_path=id_path, step=step,
            )


def _set_passphrase_steps(
    root: Path,
    *,
    db_path: Path,
    seed: bytes,
    silent_key: bytes,
    passphrase: str,
    resumed: bool,
    id_path: Path,
    step: Any,
) -> dict[str, Any]:
    from one_link import lockbox
    from one_link import state as state_module

    stored_key = _stored_database_key(root)
    database_keys: list[Optional[str]] = [stored_key, passphrase]
    live = lockbox._load_envelope(root)
    if not resumed:
        if live is not None:
            # Already passphrase mode: verified no-op (wrong passphrase raises).
            lockbox.open_live_passphrase_envelope(root, passphrase=passphrase, seed=seed)
            return {"changed": False, "mode": "passphrase"}
        if artifact_exists(root / lockbox.SALT_FILENAME, label="lockbox KDF salt"):
            # Seeded legacy passphrase rows: their data key IS scrypt(passphrase,
            # salt).  Publish its dual-slot envelope byte-preservingly (the
            # mint guard proves, by the whole-file witnesses, that this salt's
            # key protects the data) instead of re-keying anything.
            with _passphrase_environment(passphrase):
                lockbox.ensure_recovery_envelope_for_backup(root, seed=seed)
                legacy_key = lockbox.open_live_passphrase_envelope(
                    root, passphrase=passphrase, seed=seed,
                )
                if legacy_key is None:
                    raise DataKeyMigrationError(
                        "the legacy passphrase envelope was not published"
                    )
                _probe_same_key(
                    lockbox.acquire_lockbox(root), legacy_key, what="acquire_lockbox",
                )
            _verify_under(root, data_key=legacy_key, seed=seed, database_keys=[passphrase])
            _require_converged(root, id_path=id_path, seed=seed, passphrase=passphrase)
            return {"changed": True, "mode": "passphrase", "legacy_envelope": True}
        _preflight(
            root, current_key=silent_key, target_key=None, seed=seed,
            database_keys=database_keys,
        )
        _write_migration_intent(root, "set_passphrase")
        step("intent_written")
    if live is not None:
        # Interrupted after publication: the live envelope holds the target.
        published = lockbox.open_live_passphrase_envelope(
            root, passphrase=passphrase, seed=seed,
        )
        if published is None:  # pragma: no cover - live was loaded above
            raise DataKeyMigrationError("the published envelope disappeared")
        target = published
    else:
        target = lockbox.stage_passphrase_envelope(root, passphrase=passphrase, seed=seed)
        step("staged")
    if resumed:
        _preflight(
            root, current_key=silent_key, target_key=target, seed=seed,
            database_keys=database_keys,
        )
    carried = lockbox.carry_dek_protected_envelopes(
        root, previous_key=silent_key, target_key=target,
    )
    if carried["retired"] or carried["unopenable"]:  # preflight proved otherwise
        raise DataKeyMigrationError(f"artifacts could not be carried: {carried}")
    step("files_carried")
    fields = state_module.rekey_offline_state_fields(
        db_path,
        database_keys=database_keys,
        previous_data_key=silent_key,
        target_data_key=target,
        seed=seed,
    )
    step("fields_carried")
    database = _rekey_state_database(
        db_path, source_keys=[stored_key], target_key=passphrase,
    )
    step("database_rekeyed")
    _verify_under(root, data_key=target, seed=seed, database_keys=[passphrase])
    lockbox.publish_staged_passphrase_envelope(
        root, passphrase=passphrase, seed=seed, expected_dek=target,
    )
    step("published")
    # Again, through the readers the daemon uses, the way it will use them.
    with _passphrase_environment(passphrase):
        _probe_same_key(lockbox.acquire_lockbox(root), target, what="acquire_lockbox")
    _verify_under(root, data_key=target, seed=seed, database_keys=[passphrase])
    _require_converged(root, id_path=id_path, seed=seed, passphrase=passphrase)
    if lockbox.recovery_envelope_matches_seed(root, seed) is not True:
        raise DataKeyMigrationError(
            "verification failed: the paper phrase does not open the new envelope"
        )
    step("verified")
    _durable_unlink(_migration_intent_path(root), label="data-key migration intent")
    return {
        "changed": True,
        "mode": "passphrase",
        "artifacts": carried,
        "fields": fields,
        "database": database,
    }


def _remove_passphrase_steps(
    root: Path,
    *,
    db_path: Path,
    seed: bytes,
    silent_key: bytes,
    passphrase: str,
    resumed: bool,
    id_path: Path,
    step: Any,
) -> dict[str, Any]:
    from one_link import keychain, lockbox, state_encryption
    from one_link import state as state_module

    stored_key = _stored_database_key(root)
    database_keys: list[Optional[str]] = [passphrase, stored_key]
    live = lockbox._load_envelope(root)
    if not resumed and live is None:
        if artifact_exists(root / lockbox.SALT_FILENAME, label="lockbox KDF salt"):
            raise DataKeyMigrationError(
                "a legacy passphrase salt exists without its recovery envelope; "
                "run `one-link recovery set-passphrase` with that passphrase "
                "first, then remove it"
            )
        return {"changed": False, "mode": "silent"}
    # The passphrase being removed authorizes the removal: a wrong one raises.
    previous = lockbox.open_live_passphrase_envelope(root, passphrase=passphrase, seed=seed)
    if not resumed:
        if previous is None:  # pragma: no cover - live was loaded above
            raise DataKeyMigrationError("the live envelope disappeared")
        _preflight(
            root, current_key=previous, target_key=None, seed=seed,
            database_keys=database_keys,
        )
        _write_migration_intent(root, "remove_passphrase")
        step("intent_written")
    carried: dict[str, list[str]] = {"carried": [], "retired": [], "unopenable": []}
    fields: dict[str, dict[str, int]] = {}
    if previous is not None:
        # Before retirement: the envelope still holds the key being left.
        # After it, everything was verified under the silent key already.
        if resumed:
            _preflight(
                root, current_key=previous, target_key=silent_key, seed=seed,
                database_keys=database_keys,
            )
        carried = lockbox.carry_dek_protected_envelopes(
            root, previous_key=previous, target_key=silent_key,
        )
        if carried["retired"] or carried["unopenable"]:
            raise DataKeyMigrationError(f"artifacts could not be carried: {carried}")
        step("files_carried")
        fields = state_module.rekey_offline_state_fields(
            db_path,
            database_keys=database_keys,
            previous_data_key=previous,
            target_data_key=silent_key,
            seed=seed,
        )
        step("fields_carried")
    target_db_key = stored_key
    if state_encryption.detect_db_state(db_path) == "encrypted" and target_db_key is None:
        if keychain._disabled():
            raise DataKeyMigrationError(
                "state.db is encrypted under the passphrase and at-rest key "
                "management is disabled, so there is no stored key to move it to"
            )
        # Mint the stored database key exactly once: a replay reads it back.
        with _passphrase_environment(None):
            target_db_key = keychain._publish_recovered_passphrase(
                root, secrets.token_urlsafe(32),
            )
    database = _rekey_state_database(
        db_path, source_keys=[passphrase], target_key=target_db_key,
    )
    step("database_rekeyed")
    _verify_under(root, data_key=silent_key, seed=seed, database_keys=[target_db_key])
    if previous is not None:
        lockbox.retire_passphrase_envelope(
            root, passphrase=passphrase, seed=seed, expected_dek=previous,
        )
    step("retired")
    with _passphrase_environment(None):
        _probe_same_key(lockbox.acquire_lockbox(root), silent_key, what="acquire_lockbox")
    if database in ("current", "rekeyed") and _stored_database_key(root) != target_db_key:
        raise DataKeyMigrationError(
            "verification failed: the stored database key is not the one "
            "state.db was moved to"
        )
    _verify_under(root, data_key=silent_key, seed=seed, database_keys=[target_db_key])
    _require_converged(root, id_path=id_path, seed=seed, passphrase=None)
    step("verified")
    lockbox.discard_retired_passphrase_authority(root)
    step("discarded")
    _durable_unlink(_migration_intent_path(root), label="data-key migration intent")
    return {
        "changed": True,
        "mode": "silent",
        "artifacts": carried,
        "fields": fields,
        "database": database,
    }
