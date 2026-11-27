"""Master seed — the single recoverable secret behind a daemon's
identity + at-rest data.

The 24-word BIP-39 mnemonic the user writes down on paper encodes this seed
exactly. The Ed25519 identity, silent lockbox data-root key, backup-bundle key,
and cluster seed derive from it via domain-separated HKDF-SHA256. Other stable
application secrets do not pretend to be derived: passphrase-mode LockBox and
SQLCipher keys remain independently generated and are authenticated/wrapped to
the seed in portable recovery artifacts. Consequently the phrase reconstructs
identity and seed-derived authority; recovering retained application data also
requires the corresponding exported backup/envelopes (and, for unmigrated
legacy data, the explicitly reported source passphrase).

Trust ground vs corporate substrate
-----------------------------------
The seed is stored on disk DPAPI-wrapped on Windows (same pattern
as lockbox.py — bound to the user's login credentials, which an
attacker can't unwrap without the user's password). On other
platforms the seed file is mode 0600 in the daemon's config dir.

The user's PAPER backup is the sovereignty layer: even a thief
who DPAPI-unwraps the seed in memory can't extract it from the
paper backup the user keeps in a drawer. The paper backup also
survives any platform substrate failure (hard drive death,
account lockout, OS reinstall).

Backward compatibility
----------------------
Daemons that pre-existed this module's introduction have separate
randomly-generated identity.key + DRK without a master seed.
``load_or_create_seed`` is used by explicit provisioning surfaces. Identity
and lockbox loading preserve the legacy flow when the seed path is proven
absent, but any existing invalid/unreadable/protection-failed artifact raises
instead of being reclassified as a first boot. The "Initialize seed" CLI
command lets existing daemons migrate explicitly — a key-rotating action with
clear UX consequences.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from one_link.key_material import (
    KeyMaterialIntegrityError,
    KeyMaterialPersistenceError,
    KeyMaterialProtectionError,
    artifact_exists,
    atomic_create_bytes,
    atomic_replace_bytes,
    read_bytes_if_exists,
    sync_existing_authority,
)


SEED_FILENAME = "master.seed"
SEED_LEN_BYTES = 32  # 256 bits — matches BIP-39 24-word entropy

# HKDF info strings. Domain-separated so a leak of one derived
# key doesn't compromise the others. Format follows the
# convention used elsewhere in the daemon: short ASCII labels
# with trailing pipe.
_INFO_DRK = b"OL/master/drk|v1"
_INFO_IDENTITY = b"OL/master/identity-ed25519|v1"
_INFO_CLUSTER_SEED = b"OL/master/cluster-seed|v1"
_INFO_BACKUP_BUNDLE = b"OL/master/backup-bundle|v1"


def _seed_path(data_dir: Path) -> Path:
    return Path(data_dir) / SEED_FILENAME


def has_seed(data_dir: Path) -> bool:
    """True iff any master-seed artifact exists.

    This deliberately does not mean "valid": an unreadable, corrupt, or
    non-regular artifact is existing authority and must not be mistaken for a
    first boot.  :func:`load_seed` performs validation and raises.
    """
    return artifact_exists(_seed_path(data_dir), label="master seed")


def seed_file_fingerprint(data_dir: Path) -> Optional[tuple[int, int]]:
    """Return a stable (mtime_ns, size) tuple for the seed file, or
    None if no seed file exists or stat fails.

    Audit L12 May 2026: the daemon records this at boot and can
    periodically re-check to detect on-disk replacement of the
    seed file by an attacker with brief FS access. Without this
    check, a daemon that loaded its identity at startup would
    silently re-derive from a swapped seed on next restart with
    no operator alarm. Operators wanting strong tamper-evidence
    should also pair this with a sealed master VK + refuse-to-start
    on fingerprint change (a separate hardening step).
    """
    p = _seed_path(data_dir)
    try:
        st = p.stat()
    except (OSError, FileNotFoundError):
        return None
    return (int(st.st_mtime_ns), int(st.st_size))


def _harden_seed_path(path: Path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)


def _decode_seed_blob(blob: bytes) -> bytes:
    if not blob:
        raise KeyMaterialIntegrityError("existing master seed is empty")
    if os.name == "nt":
        from one_link.lockbox import _dpapi_unprotect

        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None:
            raise KeyMaterialProtectionError(
                "existing master seed could not be DPAPI-unprotected"
            )
        if len(unwrapped) != SEED_LEN_BYTES:
            raise KeyMaterialIntegrityError(
                "existing master seed has an invalid unwrapped length"
            )
        return bytes(unwrapped)
    if len(blob) != SEED_LEN_BYTES:
        raise KeyMaterialIntegrityError("existing master seed has an invalid length")
    return bytes(blob)


def _encode_seed(seed: bytes) -> bytes:
    if os.name != "nt":
        return bytes(seed)
    from one_link.lockbox import _dpapi_protect

    wrapped = _dpapi_protect(bytes(seed))
    if not wrapped:
        raise KeyMaterialProtectionError(
            "DPAPI protection failed; refusing to persist a raw master seed"
        )
    return bytes(wrapped)


def load_seed(data_dir: Path) -> Optional[bytes]:
    """Load and validate the master seed; return ``None`` only if absent.

    Existing unreadable, empty, malformed, reparse, or DPAPI-unusable files
    raise a typed key-material error and are preserved byte-for-byte.
    """
    blob = read_bytes_if_exists(
        _seed_path(data_dir),
        label="master seed",
        max_bytes=65536,
        harden_path=_harden_seed_path,
    )
    if blob is None:
        return None
    return _decode_seed_blob(blob)


def store_seed(data_dir: Path, seed: bytes) -> None:
    """Persist the master seed to disk. Wraps with DPAPI on Windows
    (same scheme as lockbox.py); writes raw 32 bytes with mode 0600
    on POSIX. Atomic via temp + rename."""
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError(f"seed must be {SEED_LEN_BYTES} bytes")
    expected = bytes(seed)
    payload = _encode_seed(expected)

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(_decode_seed_blob(blob), expected):
            raise KeyMaterialIntegrityError(
                "persisted master seed does not match requested authority"
            )

    atomic_replace_bytes(
        _seed_path(data_dir),
        payload,
        label="master seed",
        validate=_validate,
        harden_path=_harden_seed_path,
    )


def _legacy_authority_artifacts(
    data_dir: Path,
    *,
    identity_path: Optional[Path] = None,
) -> list[Path]:
    """Return existing artifacts that make seed minting a key rotation."""
    from one_link import keychain, lockbox

    root = Path(data_dir)
    candidates = [
        root / lockbox.DRK_FILENAME,
        root / lockbox.SALT_FILENAME,
        root / lockbox.DEK_ENVELOPE_FILENAME,
        # Everything the current data key protects, from the one registry the
        # key-minting guards use, so a new protected artifact cannot be
        # forgotten here either.
        *(
            artifact.path(root)
            for artifact in lockbox.DEK_PROTECTED_ARTIFACTS
            if not artifact.regenerable
        ),
        root / keychain.LOCAL_KEY_FILENAME,
        root / keychain.RECOVERY_KEY_FILENAME,
        root / "recovery-authority.intent.json",
    ]
    if identity_path is None:
        # Only infer the process-global identity for the process-global data
        # directory.  Library callers routinely pass unrelated temporary roots.
        from one_link import paths

        try:
            if root.resolve(strict=False) == paths.data_dir().resolve(strict=False):
                identity_path = paths.key_path()
        except OSError:
            identity_path = None
    if identity_path is not None:
        candidates.append(Path(identity_path))
    return [
        path
        for path in candidates
        if artifact_exists(path, label="legacy authority artifact")
    ]


def load_or_create_seed(
    data_dir: Path,
    *,
    identity_path: Optional[Path] = None,
) -> tuple[bytes, bool]:
    """Return ``(seed, created)``. If a seed already exists on disk,
    load + return it with ``created=False``. Otherwise mint 32 fresh
    random bytes, persist them, and return ``(seed, True)``.

    First-launch callers use the ``created`` flag to decide whether
    to display the user's BIP-39 backup phrase ("WRITE THESE WORDS
    DOWN") on the way through. Subsequent launches see
    ``created=False`` and continue silently.
    """
    existing = load_seed(data_dir)
    if existing is not None:
        return existing, False
    legacy = _legacy_authority_artifacts(
        Path(data_dir), identity_path=identity_path
    )
    if legacy:
        names = ", ".join(sorted(path.name for path in legacy))
        raise KeyMaterialIntegrityError(
            "refusing to mint an unrelated recovery seed over existing "
            f"authority/state ({names}); explicit transactional migration is required"
        )
    seed = secrets.token_bytes(SEED_LEN_BYTES)
    payload = _encode_seed(seed)

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(_decode_seed_blob(blob), seed):
            raise KeyMaterialIntegrityError(
                "published master seed does not match generated authority"
            )

    created = atomic_create_bytes(
        _seed_path(data_dir),
        payload,
        label="master seed",
        validate=_validate,
        harden_path=_harden_seed_path,
    )
    if created:
        return seed, True
    sync_existing_authority(_seed_path(data_dir), label="master seed")
    winner = load_seed(data_dir)
    if winner is None:
        raise KeyMaterialPersistenceError(
            "concurrent master-seed publication reported a winner but no seed exists"
        )
    return winner, False


# ── derived keys ─────────────────────────────────────────────────


def derive_drk(seed: bytes) -> bytes:
    """Data root key for the lockbox. 32 bytes, AES-GCM-friendly."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # the seed itself is the high-entropy IKM
        info=_INFO_DRK,
    ).derive(bytes(seed))


def derive_identity_priv(seed: bytes) -> Ed25519PrivateKey:
    """Ed25519 identity private key. The Ed25519 spec accepts any
    32-byte buffer as the private seed; HKDF gives us 32 bytes
    of pseudo-random material indistinguishable from os.urandom."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_IDENTITY,
    ).derive(bytes(seed))
    return Ed25519PrivateKey.from_private_bytes(raw)


def derive_backup_key(seed: bytes) -> bytes:
    """AES-GCM key for encrypted-backup bundles. Distinct from the
    DRK + identity + cluster keys so a leak of the backup wrap key
    doesn't compromise the running daemon's at-rest data."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_BACKUP_BUNDLE,
    ).derive(bytes(seed))


def derive_cluster_seed(seed: bytes) -> bytes:
    """Per-install cluster seed used by future device-cluster
    Shamir splits. Distinct from the identity + DRK so a leak of
    cluster shares doesn't compromise the identity / lockbox key."""
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError("seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO_CLUSTER_SEED,
    ).derive(bytes(seed))


# ── recoverable authority bootstrap / convergence ──────────────────


def _silent_drk_matches_seed(data_dir: Path, seed: bytes) -> Optional[bool]:
    """Observe whether the persisted silent DRK is derived from ``seed``.

    ``None`` means the DRK path is proven absent.  Existing malformed,
    inaccessible, or DPAPI-unusable artifacts raise through the shared
    fail-closed key-material taxonomy.
    """
    from one_link import lockbox

    blob = read_bytes_if_exists(
        Path(data_dir) / lockbox.DRK_FILENAME,
        label="data root key",
        max_bytes=65536,
        harden_path=lockbox._harden_drk_path,
    )
    if blob is None:
        return None
    actual = lockbox._decode_drk_blob(blob)
    return secrets.compare_digest(actual, derive_drk(bytes(seed)))


def inspect_derived_authority(
    data_dir: Path,
    *,
    identity_path: Path,
    seed: bytes,
) -> dict[str, Optional[bool]]:
    """Return non-mutating identity/DRK alignment evidence for ``seed``."""
    from one_link import identity, lockbox

    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_LEN_BYTES:
        raise ValueError(f"seed must be {SEED_LEN_BYTES} bytes")
    silent_drk = _silent_drk_matches_seed(Path(data_dir), bytes(seed))
    envelope = lockbox.recovery_envelope_matches_seed(Path(data_dir), bytes(seed))
    if envelope is None:
        data_root = (
            False
            if lockbox.requires_legacy_passphrase_recovery(Path(data_dir))
            else silent_drk
        )
    else:
        # The DRK remains a required derived authority artifact, while the
        # envelope's seed slot proves that the actual passphrase-mode DEK is
        # recoverable too.  A paper check must never green-light only one.
        data_root = bool(silent_drk is True and envelope is True)
    return {
        "identity": identity.identity_file_matches_seed(
            Path(identity_path), bytes(seed)
        ),
        "data_root": data_root,
    }


def _store_seed_derived_drk(data_dir: Path, seed: bytes) -> None:
    """Atomically publish the exact silent DRK derived from ``seed``."""
    from one_link import lockbox

    expected = derive_drk(bytes(seed))
    payload = lockbox._encode_drk(expected)

    def _validate(blob: bytes) -> None:
        actual = lockbox._decode_drk_blob(blob)
        if not secrets.compare_digest(actual, expected):
            raise KeyMaterialIntegrityError(
                "persisted data root key does not match recovered authority"
            )

    atomic_replace_bytes(
        Path(data_dir) / lockbox.DRK_FILENAME,
        payload,
        label="data root key",
        validate=_validate,
        harden_path=lockbox._harden_drk_path,
    )


def install_seed_derived_authority(
    data_dir: Path,
    *,
    identity_path: Path,
    seed: bytes,
    previous_seed: Optional[bytes] = None,
    state_db_restored: bool = False,
) -> None:
    """Converge seed, Ed25519 identity, and silent DRK on one root.

    The application data key either survives (an envelope's stable DEK is
    rebound, never re-minted) or, in silent mode with a different seed, is
    replaced by the seed's DRK; registered whole-file envelopes are then
    re-wrapped under it before the old DRK is overwritten (see
    ``lockbox.carry_dek_protected_envelopes``), and so is every value sealed
    inside state.db -- LockBox fields and the seed-keyed path-PII fields --
    in one SQLite transaction (``state.carry_key_protected_fields``).  No
    crash point leaves the install split across two keys.

    Each individual artifact is atomically replaced and read back.  Recovery
    callers must keep their durable intent journal present until this function
    returns; after a process or power failure the next boot can then replay the
    idempotent convergence before loading any key into the daemon.
    """
    from one_link import identity, lockbox

    expected = bytes(seed)
    if len(expected) != SEED_LEN_BYTES:
        raise ValueError(f"seed must be {SEED_LEN_BYTES} bytes")
    if previous_seed is not None and len(previous_seed) != SEED_LEN_BYTES:
        raise ValueError(f"previous_seed must be {SEED_LEN_BYTES} bytes")
    # Rebind the stable application DEK before replacing the source seed.  The
    # recovery intent remains durable around this call, so a crash after this
    # atomic envelope write replays against the new slot idempotently.
    envelope_present = lockbox.rebind_recovery_envelope(
        Path(data_dir),
        target_seed=expected,
        current_seed=previous_seed,
    )
    if not envelope_present:
        # A fresh explicit-passphrase target can publish its first dual wrap
        # now.  Conversely, a legacy salt with no supplied passphrase proves
        # an additional source factor is required; fail before replacing any
        # seed/identity/DRK bytes.  The mint is still refused over data the
        # seed's own DRK protects (a restored silent bundle, a replay).
        lockbox.ensure_recovery_envelope_for_backup(
            Path(data_dir),
            seed=expected,
            replacing_data_root=True,
        )
        if lockbox.requires_legacy_passphrase_recovery(Path(data_dir)):
            raise KeyMaterialProtectionError(
                "legacy application data requires the source "
                "ONE_LINK_PASSPHRASE before recovery can replace authority"
            )
    # The data key this transaction converges on: the envelope's stable DEK,
    # or, in silent mode, the seed's DRK -- which differs from the persisted
    # one whenever the seed changes (identity rotation, phrase restore).
    # While the previous DRK still exists, carry every registered envelope
    # artifact across instead of orphaning it; retire what neither key opens.
    target_key = lockbox.envelope_data_key_for_seed(Path(data_dir), expected)
    if target_key is None:
        target_key = derive_drk(expected)
    previous_key: Optional[bytes] = None
    if not envelope_present:
        # Before this transaction the data key was the silent DRK -- also
        # when the step above has just published the first envelope.
        try:
            previous_key = lockbox._silent_key_on_disk(Path(data_dir))
        except (KeyMaterialProtectionError, KeyMaterialIntegrityError):
            # A restored member bound to another machine's DPAPI scope, or a
            # damaged DRK, cannot be opened; what only it protected is retired
            # (moved aside, never deleted) rather than guessed at.
            previous_key = None
        if previous_key is None and previous_seed is not None:
            # A seeded install whose DRK file is missing still protects its
            # data with derive_drk(previous_seed): its next silent boot would
            # have re-derived exactly that key.
            previous_key = derive_drk(bytes(previous_seed))
    lockbox.carry_dek_protected_envelopes(
        Path(data_dir),
        previous_key=previous_key,
        target_key=target_key,
    )
    # The same replacement, for values sealed inside state.db: LockBox fields
    # (data key) and path-PII fields (keyed by the seed itself, so they move
    # on every seed change in both modes).  One SQLite transaction, before any
    # key is published: an interruption leaves every row under the previous
    # keys, which this replay still holds; a committed re-key replays as a
    # no-op.  See state.KEY_PROTECTED_FIELDS.
    #
    # A state.db this transaction restored from a bundle is skipped: it was
    # written under the bundle seed's keys, which ARE the target keys, and
    # its SQLCipher key is sealed to that seed, which cannot be read until
    # the phrase-derived seed is stored below (the bundle's own master.seed
    # member is DPAPI-bound to the machine that exported it).  The daemon
    # adopts that key when it opens State after convergence.
    if not state_db_restored:
        from one_link import state as _state

        _state.carry_key_protected_fields(
            Path(data_dir),
            previous_data_key=previous_key,
            target_data_key=target_key,
            previous_seed=previous_seed,
            target_seed=expected,
        )
    store_seed(Path(data_dir), expected)
    identity.store_seed_derived_identity(Path(identity_path), expected)
    _store_seed_derived_drk(Path(data_dir), expected)
    loaded = load_seed(Path(data_dir))
    evidence = inspect_derived_authority(
        Path(data_dir), identity_path=Path(identity_path), seed=expected
    )
    if (
        loaded is None
        or not secrets.compare_digest(loaded, expected)
        or evidence != {"identity": True, "data_root": True}
    ):
        raise KeyMaterialIntegrityError(
            "recovered seed, identity, and data root failed convergence proof"
        )


def provision_seed_before_derived_authority(
    data_dir: Path,
    *,
    identity_path: Path,
) -> tuple[Optional[bytes], bool]:
    """Establish the recoverable root before daemon identity/DRK creation.

    A genuinely fresh install (no seed, identity, or DRK) receives a master
    seed first.  Legacy installs with independent identity/DRK authority remain
    usable but are not silently relabelled recoverable: this returns
    ``(None, False)`` and explicit migration remains required.  Whenever a seed
    exists, every already-published derived artifact must match it exactly or
    startup fails closed.
    """
    from one_link import identity, lockbox

    root = Path(data_dir)
    id_path = Path(identity_path)
    seed = load_seed(root)
    created = False
    if seed is None:
        legacy_identity = artifact_exists(id_path, label="identity key")
        legacy_drk = artifact_exists(
            root / lockbox.DRK_FILENAME,
            label="data root key",
        )
        if legacy_identity or legacy_drk:
            return None, False
        seed, created = load_or_create_seed(root, identity_path=id_path)

    # A passphrase-protected installation started without its passphrase, or
    # with a wrong one, refuses here: before the identity is read (reading it
    # re-encrypts a cleartext identity under whatever passphrase is set) and
    # before State could fall back to running without persistence.
    # An unfinished data-key migration is reported first: mid-migration the
    # identity file may be under either protection.
    refusal = lockbox.data_key_migration_refusal(root) or lockbox.passphrase_startup_refusal(
        root, probe_database=True,
    )
    if refusal is not None:
        raise refusal
    identity_match = identity.identity_file_matches_seed(id_path, seed)
    if identity_match is False:
        raise KeyMaterialIntegrityError(
            "master seed does not derive the persisted Ed25519 identity"
        )

    drk_match = _silent_drk_matches_seed(root, seed)
    if drk_match is False:
        raise KeyMaterialIntegrityError(
            "master seed does not derive the persisted data root key"
        )
    if drk_match is None:
        # The seed is already durable, so the lockbox's no-replace first
        # publication deterministically derives and verifies the DRK from it.
        actual = lockbox.acquire_or_create_silent_drk(root)
        if not secrets.compare_digest(actual, derive_drk(seed)):
            raise KeyMaterialIntegrityError(
                "new data root key does not match the master seed"
            )
    # Passphrase-mode recovery has one additional authority artifact. Publish
    # it while the daemon still owns the bootstrap instance lock, before the
    # observational convergence check and before opening application state.
    # Existing envelopes are verified, never silently rebound by this step.
    lockbox.prepare_bootstrap_recovery_envelope(root, seed=seed)
    return seed, created


# ── Row 10: sealed runtime ───────────────────────────────────────


def load_sealed_master(data_dir: Path):
    """Boot-time helper: load the master seed from disk, seal it
    under a per-process ``SoftwareProvider``, wipe the plaintext, and
    return a ``SealedMasterIdentity`` the daemon can keep in memory
    for its lifetime.

    Returns ``None`` if no seed exists on disk (caller decides
    whether to mint one + show the BIP-39 mnemonic).

    Returns ``False`` (specifically the bool) if the
    ``one_link_native.confidential`` extension isn't built — caller
    falls back to plaintext-in-memory legacy flow.

    The sealed handle exposes ``.sign(transcript)``,
    ``.master_vk()``, ``.attest(...)``, and ``.derive_child(...)``.
    It does NOT expose the raw seed; daemons that need legacy
    HKDF-derived material can still call the module-level
    ``derive_drk / derive_identity_priv / derive_backup_key /
    derive_cluster_seed`` from the plaintext seed before sealing.
    """
    seed = load_seed(data_dir)
    if seed is None:
        return None
    try:
        from one_link.confidential_native import (
            HAS_NATIVE,
            SealedMasterIdentity,
        )
    except ImportError:
        return False
    if not HAS_NATIVE:
        return False
    sealed = SealedMasterIdentity.from_seed_bytes(seed)
    # Best-effort plaintext wipe. Python `bytes` are immutable, so
    # this only catches buffer-style holders; the real protection
    # comes from the seal — once the sealed handle is constructed,
    # the plaintext is only re-materialised microseconds per sign
    # inside the Rust provider.
    seed = b"\x00" * SEED_LEN_BYTES
    del seed
    return sealed
