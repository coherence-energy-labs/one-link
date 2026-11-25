"""Fail-closed at-rest secret wrapping with recoverable DEK authority.

v0.20.7 (security audit H21 + M29 + partial C5): the desktop daemon
historically stored its highest-value secrets cleartext on disk:

  - `group_sender_chains.chain_key` (32-byte symmetric ratchet keys —
    recovery decrypts every retained group message that chain has
    emitted from that epoch forward).
  - The UI bearer token (full daemon control if exfiltrated).

The browser PWA path encrypts these via OPFS + Argon2id from a user
passphrase. This module protects the daemon's field-level secrets with
AES-GCM; the State database itself is separately protected by SQLCipher.

Design:

  - Every install has a stable 32-byte data-encryption key (DEK). Silent mode
    obtains it from the seed-derived/OS-protected data-root artifact.
  - Passphrase mode derives a wrapping key from ``ONE_LINK_PASSPHRASE`` and a
    per-install salt using scrypt. New installs wrap the stable DEK in a fixed
    versioned envelope with both passphrase and master-seed recovery slots.
  - Legacy passphrase ciphertext keeps its historical scrypt key as the stable
    DEK, so migration is byte-preserving: only the dual-slot envelope is added.
    Passphrase changes rewrap the DEK instead of orphaning existing rows.
  - Missing, corrupt, mismatched, or unauthenticated authority fails closed;
    no path silently invents a replacement key for existing ciphertext.
  - Wrap = AES-GCM-256 with a fresh 12-byte random nonce per call.
    Output format: ``b"\\x01" + nonce(12) + ciphertext + tag(16)``.
    The marker is sufficient only for legacy plaintext formats whose grammar
    excludes that byte. Fixed-width random secrets can naturally begin with
    0x01, so their state adapters length-discriminate cleartext (32 bytes)
    from the authenticated envelope (61 bytes).
  - Generic unwrap detects the marker; if absent it returns the input
    unchanged. If the marker is present but authentication fails, it raises
    instead of silently accepting tampered ciphertext.

Why scrypt and not Argon2id?

The audit's preferred KDF was Argon2id; ``cryptography>=42`` (our
floor) does not expose Argon2id directly. Adding ``argon2-cffi``
would require a new dependency. scrypt is in the same memory-hard
family, audited, and available without adding dependencies. The v1
parameters require approximately 128 MiB per derivation and materially
raise the cost of parallel offline guessing; they do not make weak
passphrases safe. When ``cryptography`` ships Argon2id (or
when the project takes the argon2-cffi dep), the DRK derivation
must move behind a new persisted envelope version with an explicit migration;
changing these v1 parameters in place would orphan existing ciphertext.

Backward compatibility:

  - Legacy plaintext values remain readable by marker/length discrimination;
    new sensitive writes are wrapped on every install.
  - Legacy passphrase mode requires the source passphrase exactly once to mint
    its seed recovery slot. Recovery status and backup export report/refuse
    that incomplete migration instead of claiming paper-only recoverability.
"""
from __future__ import annotations

import errno
import json
import os
import secrets
import hashlib
import sys
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

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


# 0x01 marker prefix for wrapped values. This is distinct from textual legacy
# formats such as base64url tokens, but NOT from arbitrary random bytes. State
# adapters for fixed-width binary secrets must discriminate by exact length.
WRAP_MARKER = b"\x01"
NONCE_LEN = 12
TAG_LEN = 16
MIN_WRAPPED_LEN = 1 + NONCE_LEN + TAG_LEN  # marker + nonce + tag (zero-byte plaintext)

# scrypt v1 parameters. RFC 7914's approximate working memory is
# 128 * N * r = 128 MiB. These constants are part of the persisted format:
# changing them without versioned KDF metadata would make existing data
# undecryptable.
SCRYPT_N = 1 << 17  # 131072
SCRYPT_R = 8
SCRYPT_P = 1


PASSPHRASE_ENV = "ONE_LINK_PASSPHRASE"

# v0.20.7 (security audit C5 silent-mode): name of the per-install
# data-root-key file. Lives in the daemon's config dir alongside
# identity.key. On Windows the contents are DPAPI-wrapped (so a
# stolen disk without the user's login credentials cannot unwrap
# the DRK). On other OSes the file is raw 32 random bytes with
# 0o600 perms — strictly better than cleartext sqlite (separate
# file, can be on a different partition / encrypted volume) but
# not equivalent to DPAPI's user-bound wrap. Users who want the
# full T8 protection on macOS / Linux should set
# ONE_LINK_PASSPHRASE which routes through scrypt instead.
DRK_FILENAME = "data-root-key.bin"
DRK_DPAPI_DESCRIPTION = "OneLink-DRK-v1"

# Passphrase mode historically used the scrypt output directly as the
# application data-encryption key.  That made already-wrapped rows impossible
# to recover from the paper seed even though the recovery UI reported the
# derived DRK as healthy.  v1 keeps that legacy key as the stable DEK (so no
# row rewrite is needed) and stores two authenticated wraps: one opened by the
# configured passphrase and one opened by the paper master seed.  The envelope
# is portable and therefore belongs in encrypted backup bundles; neither wrap
# contains a plaintext key.
DEK_ENVELOPE_FILENAME = "lockbox.dek-envelope-v1"
DEK_ENVELOPE_LOCK_FILENAME = ".lockbox.dek-envelope.lock"
DEK_ENVELOPE_MAGIC = b"OLLBDEK\x01"
DEK_ENVELOPE_NONCE_LEN = 12
DEK_ENVELOPE_CIPHERTEXT_LEN = 32 + 16
DEK_ENVELOPE_SALT_DIGEST_LEN = 32
DEK_ENVELOPE_LEN = (
    len(DEK_ENVELOPE_MAGIC)
    + DEK_ENVELOPE_SALT_DIGEST_LEN
    + DEK_ENVELOPE_NONCE_LEN
    + DEK_ENVELOPE_CIPHERTEXT_LEN
    + DEK_ENVELOPE_NONCE_LEN
    + DEK_ENVELOPE_CIPHERTEXT_LEN
)
_DEK_PASSPHRASE_WRAP_INFO = b"OL/lockbox/dek-passphrase-wrap|v1"
_DEK_SEED_WRAP_INFO = b"OL/master/lockbox-dek-recovery|v1"
_DEK_PASSPHRASE_AAD_SUFFIX = b"|passphrase"
_DEK_SEED_AAD_SUFFIX = b"|master-seed"


class LockBoxError(RuntimeError):
    """Raised when an unwrap operation fails authenticity check."""


class LockBox:
    """Wraps secrets at rest with an AES-GCM key derived from either
    a user passphrase (scrypt) or a per-install silent DRK (DPAPI on
    Windows, file-with-strict-perms elsewhere). The ``is_silent``
    flag distinguishes the two modes for callers that need to make
    a security/compatibility tradeoff (e.g. the UI token wrap is
    skipped in silent mode because (a) the on-disk window is brief
    — daemon restart rotates the token — and (b) the launcher would
    otherwise need its own DPAPI-unwrap path to read the token)."""

    def __init__(self, data_key: bytes, *, is_silent: bool = True):
        if len(data_key) != 32:
            raise ValueError("data_key must be 32 bytes")
        self._aead = AESGCM(data_key)
        self.is_silent = bool(is_silent)

    @classmethod
    def from_passphrase(cls, passphrase: bytes, salt: bytes) -> "LockBox":
        """Derive a fresh LockBox from a user passphrase + per-install
        salt. The passphrase bytes should be UTF-8 encoded;
        empty / None inputs are rejected (callers should branch on
        env-var presence instead)."""
        if not isinstance(passphrase, (bytes, bytearray)) or not passphrase:
            raise ValueError("passphrase must be non-empty bytes")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("salt must be at least 16 bytes")
        data_key = _derive_legacy_passphrase_dek(bytes(passphrase), bytes(salt))
        # Passphrase-derived = explicit user opt-in = stronger mode.
        return cls(data_key, is_silent=False)

    def wrap(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and return the wrapped blob.

        Output: WRAP_MARKER || nonce(12) || ciphertext || tag(16).
        ``aad=b""`` because the value is identified by its storage
        slot, not by content metadata. For per-context separation
        callers can pass a domain-bound input (we don't expose AAD
        on this surface to keep the storage format uniform).
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        nonce = secrets.token_bytes(NONCE_LEN)
        ct_with_tag = self._aead.encrypt(nonce, bytes(plaintext), b"")
        return WRAP_MARKER + nonce + ct_with_tag

    def unwrap(self, blob: bytes) -> bytes:
        """Decrypt a wrapped blob; raise LockBoxError on tag mismatch."""
        if not is_wrapped(blob):
            raise LockBoxError("not a wrapped blob")
        nonce = bytes(blob[1:1 + NONCE_LEN])
        ct = bytes(blob[1 + NONCE_LEN:])
        try:
            return self._aead.decrypt(nonce, ct, b"")
        except Exception as e:
            raise LockBoxError(f"unwrap failed: {e}") from e

    # Convenience surfaces — the most common state-layer pattern is
    # "wrap if I have a lockbox, otherwise pass through" + "unwrap if
    # marker present, otherwise pass through (legacy cleartext)."

    def maybe_wrap(self, plaintext: bytes) -> bytes:
        return self.wrap(plaintext)

    def maybe_unwrap(self, blob: bytes) -> bytes:
        if is_wrapped(blob):
            return self.unwrap(blob)
        return blob


@dataclass(frozen=True)
class _DekEnvelope:
    """Strict fixed-width v1 envelope for the stable application DEK."""

    salt_digest: bytes
    passphrase_nonce: bytes
    passphrase_ciphertext: bytes
    seed_nonce: bytes
    seed_ciphertext: bytes

    def encode(self) -> bytes:
        payload = b"".join(
            (
                DEK_ENVELOPE_MAGIC,
                self.salt_digest,
                self.passphrase_nonce,
                self.passphrase_ciphertext,
                self.seed_nonce,
                self.seed_ciphertext,
            )
        )
        if len(payload) != DEK_ENVELOPE_LEN:
            raise KeyMaterialIntegrityError("lockbox DEK envelope has invalid fields")
        return payload

    @classmethod
    def decode(cls, payload: bytes) -> "_DekEnvelope":
        if not isinstance(payload, bytes) or len(payload) != DEK_ENVELOPE_LEN:
            raise KeyMaterialIntegrityError(
                "lockbox DEK envelope has an invalid length"
            )
        if not secrets.compare_digest(
            payload[: len(DEK_ENVELOPE_MAGIC)], DEK_ENVELOPE_MAGIC
        ):
            raise KeyMaterialIntegrityError(
                "lockbox DEK envelope has an unsupported format"
            )
        offset = len(DEK_ENVELOPE_MAGIC)

        def take(length: int) -> bytes:
            nonlocal offset
            result = payload[offset : offset + length]
            offset += length
            return result

        envelope = cls(
            salt_digest=take(DEK_ENVELOPE_SALT_DIGEST_LEN),
            passphrase_nonce=take(DEK_ENVELOPE_NONCE_LEN),
            passphrase_ciphertext=take(DEK_ENVELOPE_CIPHERTEXT_LEN),
            seed_nonce=take(DEK_ENVELOPE_NONCE_LEN),
            seed_ciphertext=take(DEK_ENVELOPE_CIPHERTEXT_LEN),
        )
        if offset != len(payload):
            raise KeyMaterialIntegrityError("lockbox DEK envelope parser drift")
        return envelope


def _derive_legacy_passphrase_dek(passphrase: bytes, salt: bytes) -> bytes:
    """Derive the exact pre-envelope key so existing rows remain readable."""

    if not passphrase:
        raise ValueError("passphrase must be non-empty bytes")
    if len(salt) != 16:
        raise ValueError("lockbox KDF salt must be 16 bytes")
    return Scrypt(
        salt=bytes(salt),
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(bytes(passphrase))


def _hkdf_key(material: bytes, *, info: bytes) -> bytes:
    if len(material) != 32:
        raise ValueError("lockbox wrapping authority must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(bytes(material))


def _passphrase_wrap_key(legacy_dek: bytes) -> bytes:
    return _hkdf_key(legacy_dek, info=_DEK_PASSPHRASE_WRAP_INFO)


def _seed_wrap_key(seed: bytes) -> bytes:
    return _hkdf_key(seed, info=_DEK_SEED_WRAP_INFO)


def _slot_aad(salt_digest: bytes, *, seed_slot: bool) -> bytes:
    suffix = _DEK_SEED_AAD_SUFFIX if seed_slot else _DEK_PASSPHRASE_AAD_SUFFIX
    return DEK_ENVELOPE_MAGIC + salt_digest + suffix


def _encrypt_dek_slot(
    dek: bytes,
    *,
    wrapping_key: bytes,
    salt_digest: bytes,
    seed_slot: bool,
) -> tuple[bytes, bytes]:
    if len(dek) != 32 or len(salt_digest) != DEK_ENVELOPE_SALT_DIGEST_LEN:
        raise ValueError("invalid lockbox DEK envelope input")
    nonce = secrets.token_bytes(DEK_ENVELOPE_NONCE_LEN)
    ciphertext = AESGCM(wrapping_key).encrypt(
        nonce,
        bytes(dek),
        _slot_aad(salt_digest, seed_slot=seed_slot),
    )
    if len(ciphertext) != DEK_ENVELOPE_CIPHERTEXT_LEN:
        raise KeyMaterialIntegrityError("lockbox DEK wrap produced invalid output")
    return nonce, ciphertext


def _decrypt_dek_slot(
    envelope: _DekEnvelope,
    *,
    wrapping_key: bytes,
    seed_slot: bool,
) -> Optional[bytes]:
    nonce = envelope.seed_nonce if seed_slot else envelope.passphrase_nonce
    ciphertext = (
        envelope.seed_ciphertext
        if seed_slot
        else envelope.passphrase_ciphertext
    )
    try:
        plaintext = AESGCM(wrapping_key).decrypt(
            nonce,
            ciphertext,
            _slot_aad(envelope.salt_digest, seed_slot=seed_slot),
        )
    except Exception:
        # Authentication failure is the expected result for a candidate phrase,
        # seed, or passphrase that is not this envelope's authority.
        return None
    if len(plaintext) != 32:
        raise KeyMaterialIntegrityError(
            "authenticated lockbox DEK envelope contained an invalid key"
        )
    return bytes(plaintext)


def _new_envelope(*, dek: bytes, salt: bytes, passphrase_key: bytes, seed: bytes) -> _DekEnvelope:
    salt_digest = hashlib.sha256(bytes(salt)).digest()
    pass_nonce, pass_ciphertext = _encrypt_dek_slot(
        dek,
        wrapping_key=passphrase_key,
        salt_digest=salt_digest,
        seed_slot=False,
    )
    seed_nonce, seed_ciphertext = _encrypt_dek_slot(
        dek,
        wrapping_key=_seed_wrap_key(seed),
        salt_digest=salt_digest,
        seed_slot=True,
    )
    return _DekEnvelope(
        salt_digest=salt_digest,
        passphrase_nonce=pass_nonce,
        passphrase_ciphertext=pass_ciphertext,
        seed_nonce=seed_nonce,
        seed_ciphertext=seed_ciphertext,
    )


def _replace_envelope_slots(
    envelope: _DekEnvelope,
    *,
    dek: bytes,
    passphrase_key: Optional[bytes] = None,
    seed: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> _DekEnvelope:
    salt_digest = (
        hashlib.sha256(bytes(salt)).digest()
        if salt is not None
        else envelope.salt_digest
    )
    if not secrets.compare_digest(salt_digest, envelope.salt_digest):
        # The digest participates in both slots' AAD.  Changing it requires
        # re-encrypting both slots; preserving either ciphertext would corrupt
        # the envelope.
        if passphrase_key is None or seed is None:
            raise KeyMaterialProtectionError(
                "lockbox salt changed but both recovery factors are unavailable"
            )
    if passphrase_key is None:
        pass_nonce = envelope.passphrase_nonce
        pass_ciphertext = envelope.passphrase_ciphertext
    else:
        pass_nonce, pass_ciphertext = _encrypt_dek_slot(
            dek,
            wrapping_key=passphrase_key,
            salt_digest=salt_digest,
            seed_slot=False,
        )
    if seed is None:
        seed_nonce = envelope.seed_nonce
        seed_ciphertext = envelope.seed_ciphertext
    else:
        seed_nonce, seed_ciphertext = _encrypt_dek_slot(
            dek,
            wrapping_key=_seed_wrap_key(seed),
            salt_digest=salt_digest,
            seed_slot=True,
        )
    return _DekEnvelope(
        salt_digest=salt_digest,
        passphrase_nonce=pass_nonce,
        passphrase_ciphertext=pass_ciphertext,
        seed_nonce=seed_nonce,
        seed_ciphertext=seed_ciphertext,
    )


def _envelope_path(data_dir: Path) -> Path:
    return Path(data_dir) / DEK_ENVELOPE_FILENAME


def _harden_envelope_path(path: Path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)


def _load_envelope(data_dir: Path) -> Optional[_DekEnvelope]:
    payload = read_bytes_if_exists(
        _envelope_path(data_dir),
        label="lockbox DEK envelope",
        max_bytes=DEK_ENVELOPE_LEN + 1,
        harden_path=_harden_envelope_path,
    )
    return None if payload is None else _DekEnvelope.decode(payload)


# ─── the envelope transaction lock ──────────────────────────────────
#
# Real concurrent holders exist: `one-link backup export` runs beside a live
# daemon without the instance lock and holds this lock for the whole export;
# the daemon takes it at every seeded boot and from worker threads (TLS
# authority minting, the in-daemon export API); a data-key migration holds it
# for its whole transaction.  So a waiter waits -- bounded, with backoff --
# and on timeout names the holder, recorded in the lock file after byte 0
# (the byte Windows locks).  Within one process the lock is re-entrant per
# thread and threads wait for each other: two handles conflict exactly like
# two processes do (Windows byte-range locks and POSIX flock are per handle).

LOCK_WAIT_TIMEOUT_S = 30.0
_LOCK_BACKOFF_START_S = 0.01
_LOCK_BACKOFF_MAX_S = 0.25
_LOCK_HOLDER_MAX_BYTES = 512
_LOCK_CONTENTION_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "EACCES", None),
        getattr(errno, "EAGAIN", None),
        getattr(errno, "EWOULDBLOCK", None),
        getattr(errno, "EDEADLK", None),
        getattr(errno, "EDEADLOCK", None),
    )
    if code is not None
)

# A data-key migration (`one-link recovery set-passphrase` / remove-passphrase)
# journals itself here.  While it exists every other envelope transaction
# refuses: between carrying the data and publishing the new key, neither key
# alone describes the install.
MIGRATION_INTENT_FILENAME = "lockbox.data-key-migration-v1.json"
STAGED_ENVELOPE_FILENAME = DEK_ENVELOPE_FILENAME + ".staged"
STAGED_SALT_FILENAME = "lockbox.salt.staged"
RETIRED_ENVELOPE_FILENAME = DEK_ENVELOPE_FILENAME + ".retired"
RETIRED_SALT_FILENAME = "lockbox.salt.retired"
MIGRATION_COMMANDS = {
    "set_passphrase": "one-link recovery set-passphrase",
    "remove_passphrase": "one-link recovery remove-passphrase",
}


@dataclass
class _ProcessEnvelopeLock:
    rlock: Any
    depth: int = 0
    purpose: str = ""


_PROCESS_ENVELOPE_LOCKS: dict[str, _ProcessEnvelopeLock] = {}
_PROCESS_ENVELOPE_LOCKS_GUARD = threading.Lock()


def _process_envelope_lock(root: Path) -> _ProcessEnvelopeLock:
    key = os.path.normcase(os.path.abspath(str(root)))
    with _PROCESS_ENVELOPE_LOCKS_GUARD:
        held = _PROCESS_ENVELOPE_LOCKS.get(key)
        if held is None:
            held = _ProcessEnvelopeLock(rlock=threading.RLock())
            _PROCESS_ENVELOPE_LOCKS[key] = held
        return held


def _lock_holder_hint(fd: int) -> str:
    """`` (held by <purpose>, pid <n>)`` if the holder recorded itself."""
    try:
        os.lseek(fd, 1, os.SEEK_SET)
        record = json.loads(os.read(fd, _LOCK_HOLDER_MAX_BYTES).decode("utf-8"))
        purpose = str(record["purpose"])[:120]
        pid = int(record["pid"])
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError):
        return " (holder not recorded)"
    return f" (held by {purpose}, pid {pid})"


def _record_lock_holder(fd: int, purpose: str) -> None:
    record = json.dumps(
        {"pid": os.getpid(), "purpose": purpose, "since_ms": int(time.time() * 1000)},
        separators=(",", ":"),
    ).encode("utf-8")[:_LOCK_HOLDER_MAX_BYTES]
    try:
        os.lseek(fd, 1, os.SEEK_SET)
        os.write(fd, record)
        os.ftruncate(fd, 1 + len(record))
    except OSError:
        # The record only improves a waiter's error message.
        pass


def _acquire_envelope_file_lock(
    root: Path, *, purpose: str, deadline: float, timeout_s: float,
) -> int:
    path = root / DEK_ENVELOPE_LOCK_FILENAME
    flags = os.O_RDWR | os.O_CREAT | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            "cannot open lockbox DEK envelope lock"
        ) from exc
    try:
        if os.fstat(fd).st_size == 0:
            # Byte 0 is the locked byte on Windows; the holder record follows.
            os.write(fd, b"\x00")
            os.fsync(fd)
        delay = _LOCK_BACKOFF_START_S
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in _LOCK_CONTENTION_ERRNOS:
                    raise KeyMaterialPersistenceError(
                        f"cannot lock the lockbox DEK envelope: {exc}"
                    ) from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise KeyMaterialPersistenceError(
                        "another lockbox DEK envelope transaction is in "
                        f"progress{_lock_holder_hint(fd)}; gave up after "
                        f"{timeout_s:.0f}s"
                    ) from exc
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, _LOCK_BACKOFF_MAX_S)
        if sys.platform != "win32":
            os.chmod(path, 0o600)
        _record_lock_holder(fd, purpose)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _release_envelope_file_lock(fd: int) -> None:
    try:
        with suppress(OSError):
            os.ftruncate(fd, 1)
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            with suppress(OSError):
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            with suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def data_key_migration_in_progress(data_dir: Path) -> Optional[str]:
    """The kind of an unfinished data-key migration, or ``None``."""
    payload = read_bytes_if_exists(
        Path(data_dir) / MIGRATION_INTENT_FILENAME,
        label="data-key migration intent",
        max_bytes=4096,
    )
    if payload is None:
        return None
    try:
        kind = str(json.loads(payload.decode("utf-8"))["kind"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise KeyMaterialIntegrityError(
            "data-key migration intent is unreadable; the migration it "
            "describes cannot be finished or abandoned automatically"
        ) from None
    if kind not in MIGRATION_COMMANDS:
        raise KeyMaterialIntegrityError(
            f"data-key migration intent names an unknown migration {kind!r}"
        )
    return kind


def data_key_migration_refusal(data_dir: Path) -> Optional[KeyMaterialProtectionError]:
    """The refusal every key consumer gives while a migration is unfinished."""
    kind = data_key_migration_in_progress(data_dir)
    if kind is None:
        return None
    return KeyMaterialProtectionError(
        f"a data-key migration ({kind.replace('_', '-')}) is unfinished on "
        "this installation; nothing may use the data key until it completes. "
        f"Run `{MIGRATION_COMMANDS[kind]}` again to finish it"
    )


@contextmanager
def _envelope_mutation_lock(
    data_dir: Path,
    *,
    purpose: str = "lockbox key operation",
    migration: bool = False,
):
    """Serialize every envelope transaction; wait for a holder, boundedly.

    ``migration`` is set only by the data-key migration, which owns the
    intent journal; every other outermost acquisition refuses while one is
    unfinished.  A nested acquisition in the same thread is re-entrant and
    inherits the outer transaction's standing.
    """
    root = Path(data_dir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    timeout_s = float(LOCK_WAIT_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    held = _process_envelope_lock(root)
    if not held.rlock.acquire(timeout=max(0.0, timeout_s)):
        raise KeyMaterialPersistenceError(
            "another lockbox DEK envelope transaction in this process "
            f"(held by {held.purpose or 'unknown'}, pid {os.getpid()}) did "
            f"not finish; gave up after {timeout_s:.0f}s"
        )
    try:
        if held.depth > 0:
            held.depth += 1
            try:
                yield
            finally:
                held.depth -= 1
            return
        fd = _acquire_envelope_file_lock(
            root, purpose=purpose, deadline=deadline, timeout_s=timeout_s,
        )
        held.depth, held.purpose = 1, purpose
        try:
            if not migration:
                refusal = data_key_migration_refusal(root)
                if refusal is not None:
                    raise refusal
            yield
        finally:
            held.depth, held.purpose = 0, ""
            _release_envelope_file_lock(fd)
    finally:
        held.rlock.release()


def envelope_transaction(data_dir: Path, *, purpose: str):
    """Hold the envelope transaction lock across a multi-step operation.

    For callers outside this module whose consistency depends on no data-key
    change interleaving with them (a backup export archives the envelope,
    the DRK and state.db together).  Bounded wait; refuses during an
    unfinished data-key migration.
    """
    return _envelope_mutation_lock(data_dir, purpose=purpose)


def _publish_new_envelope(data_dir: Path, envelope: _DekEnvelope) -> _DekEnvelope:
    expected = envelope.encode()

    def validate(payload: bytes) -> None:
        _DekEnvelope.decode(payload)
        if not secrets.compare_digest(payload, expected):
            raise KeyMaterialIntegrityError(
                "published lockbox DEK envelope differs from requested authority"
            )

    if atomic_create_bytes(
        _envelope_path(data_dir),
        expected,
        label="lockbox DEK envelope",
        validate=validate,
        harden_path=_harden_envelope_path,
    ):
        return envelope
    sync_existing_authority(
        _envelope_path(data_dir), label="lockbox DEK envelope"
    )
    winner = _load_envelope(data_dir)
    if winner is None:
        raise KeyMaterialPersistenceError(
            "concurrent lockbox DEK envelope publication has no winner"
        )
    return winner


def _replace_envelope(data_dir: Path, envelope: _DekEnvelope) -> None:
    expected = envelope.encode()

    def validate(payload: bytes) -> None:
        _DekEnvelope.decode(payload)
        if not secrets.compare_digest(payload, expected):
            raise KeyMaterialIntegrityError(
                "persisted lockbox DEK envelope failed exact read-back"
            )

    atomic_replace_bytes(
        _envelope_path(data_dir),
        expected,
        label="lockbox DEK envelope",
        validate=validate,
        harden_path=_harden_envelope_path,
    )


def is_wrapped(blob: bytes) -> bool:
    """Cheap shape check: marker byte + minimum length."""
    if not isinstance(blob, (bytes, bytearray)):
        return False
    return len(blob) >= MIN_WRAPPED_LEN and blob[0:1] == WRAP_MARKER


def maybe_unwrap(blob: bytes, lockbox: Optional["LockBox"]) -> bytes:
    """Unwrap marker-delimited data or return legacy plaintext unchanged.

    This helper is safe only when the plaintext schema excludes
    ``WRAP_MARKER`` at byte zero. Callers storing fixed-width random bytes
    must distinguish their exact cleartext and envelope lengths first.
    """
    if is_wrapped(blob):
        if lockbox is None:
            raise LockBoxError(
                "found wrapped value but recoverable lockbox authority is unavailable"
            )
        return lockbox.unwrap(blob)
    return blob


def maybe_wrap(plaintext: bytes, lockbox: Optional["LockBox"]) -> bytes:
    """Top-level convenience: wrap if lockbox available, passthrough
    otherwise. Use this from state-layer write paths."""
    if lockbox is None:
        return plaintext
    return lockbox.wrap(plaintext)


# ─── the application DEK's protected-artifact registry ─────────────
#
# Every key-minting decision below asks one question: "does data protected by
# the current data key exist?"  That question is answered here and nowhere
# else.  A module that persists LockBox ciphertext registers its artifact in
# this table; ``tests/test_dek_authority_registry.py`` fails if any LockBox
# wrap site in the package belongs to a module with no entry, if an entry's
# path drifts from its writer's own filename constant, or if a real writer
# leaves a DEK envelope on disk at an unregistered path.

PROTECTION_ENVELOPE = "envelope"
PROTECTION_ENVELOPE_OR_LEGACY_CLEARTEXT = "envelope_or_legacy_cleartext"
PROTECTION_EMBEDDED = "embedded"
PROTECTION_REGENERABLE = "regenerable"
ENVELOPE_PROTECTIONS = frozenset(
    {PROTECTION_ENVELOPE, PROTECTION_ENVELOPE_OR_LEGACY_CLEARTEXT}
)

# Confirmed authority replacements move artifacts the converged key cannot
# open here (never delete them): the user confirmed replacing the authority
# that protected them, and their bytes stay available for forensic recovery.
RETIRED_ARTIFACTS_DIRNAME = "retired-dek-artifacts"


@dataclass(frozen=True)
class DekProtectedArtifact:
    """One persisted artifact whose readability depends on the application DEK.

    ``relpath`` is POSIX-relative to the data root.  ``protection`` says what
    a key mint can learn from it:

    * ``envelope``: the whole file is one LockBox wrap, so AES-GCM
      authentication proves which key protects it (a witness).
    * ``envelope_or_legacy_cleartext``: as above once migrated; a historical
      cleartext copy carries no key and is not a witness.
    * ``embedded``: wrapped values live inside a container (SQLite columns);
      presence is evidence, but only file names can be inspected cheaply.
    * ``regenerable``: rewritten on every boot, so losing it orphans nothing
      and its presence is not evidence of protected data.

    ``retire_with`` names paths whose content is protected transitively by
    this artifact and must move with it; ``retirable`` is False when moving
    the artifact aside would itself weaken security (the update authority
    MACs the rollback high-water mark).
    """

    name: str
    relpath: str
    writer: str
    protection: str
    max_bytes: int = 4096
    retirable: bool = False
    retire_with: tuple[str, ...] = ()
    # Embedded artifacts cannot be re-wrapped at this layer.  ``carried_by``
    # names the function that re-keys their sealed values during a confirmed
    # key replacement, or the registry entry they are a sidecar of.
    carried_by: str = ""

    @property
    def regenerable(self) -> bool:
        return self.protection == PROTECTION_REGENERABLE

    def path(self, data_dir: Path) -> Path:
        return Path(data_dir).joinpath(*self.relpath.split("/"))


DEK_PROTECTED_ARTIFACTS: tuple[DekProtectedArtifact, ...] = (
    DekProtectedArtifact(
        "state_db", "state.db", "one_link.state", PROTECTION_EMBEDDED,
        carried_by="one_link.state:carry_key_protected_fields",
    ),
    DekProtectedArtifact(
        "state_wal", "state.db-wal", "one_link.state", PROTECTION_EMBEDDED,
        carried_by="state_db",
    ),
    DekProtectedArtifact(
        "state_shm", "state.db-shm", "one_link.state", PROTECTION_EMBEDDED,
        carried_by="state_db",
    ),
    DekProtectedArtifact(
        "capsule_master_key",
        "capsule-master-key.bin",
        "one_link.capsule_store",
        PROTECTION_ENVELOPE,
        retirable=True,
        retire_with=("capsules",),
    ),
    DekProtectedArtifact(
        "tls_root_authority",
        "peer_https/root_ca_key.pem",
        "one_link.peer_https",
        PROTECTION_ENVELOPE_OR_LEGACY_CLEARTEXT,
        max_bytes=128 * 1024,
        retirable=True,
        retire_with=("peer_https/root_ca.pem",),
    ),
    DekProtectedArtifact(
        "update_state_authority",
        "updates/update-authority.key.wrapped",
        "one_link.update_transaction",
        PROTECTION_ENVELOPE,
    ),
    DekProtectedArtifact(
        "ui_token", "ui.token", "one_link.server", PROTECTION_REGENERABLE,
    ),
)


def present_dek_protected_artifacts(
    data_dir: Path,
    *,
    include_regenerable: bool = False,
) -> tuple[DekProtectedArtifact, ...]:
    """Registered artifacts present under ``data_dir``.

    Absence must be proven: an artifact that cannot be inspected raises
    (``KeyMaterialAccessError``) rather than being treated as missing.
    """
    root = Path(data_dir)
    return tuple(
        artifact
        for artifact in DEK_PROTECTED_ARTIFACTS
        if (include_regenerable or not artifact.regenerable)
        and artifact_exists(
            artifact.path(root), label=f"DEK-protected {artifact.name}"
        )
    )


def _read_dek_envelope_artifact(
    data_dir: Path, artifact: DekProtectedArtifact
) -> Optional[bytes]:
    """Bounded read of one envelope artifact.

    ``None`` means absent, or a legacy cleartext copy that carries no key.
    Anything else is returned as read: a damaged file that is not a LockBox
    envelope opens under no key, so it proves nothing to a mint guard and is
    "unopenable" to a key replacement -- never silently accepted.
    """
    blob = read_bytes_if_exists(
        artifact.path(Path(data_dir)),
        label=f"DEK-protected {artifact.name}",
        max_bytes=artifact.max_bytes,
    )
    if blob is None:
        return None
    if (
        not is_wrapped(blob)
        and artifact.protection == PROTECTION_ENVELOPE_OR_LEGACY_CLEARTEXT
    ):
        return None
    return blob


def _opens(data_key: Optional[bytes], blob: bytes) -> bool:
    if data_key is None:
        return False
    try:
        LockBox(data_key).unwrap(blob)
    except LockBoxError:
        return False
    return True


def dek_artifacts_unopenable_by(
    data_dir: Path, box: "LockBox"
) -> tuple[DekProtectedArtifact, ...]:
    """Present envelope artifacts that ``box`` cannot authenticate.

    This is a proof, not an inference: AES-GCM authentication either succeeds
    under the given data key or it does not.
    """
    root = Path(data_dir)
    rejected = []
    for artifact in present_dek_protected_artifacts(root):
        if artifact.protection not in ENVELOPE_PROTECTIONS:
            continue
        blob = _read_dek_envelope_artifact(root, artifact)
        if blob is None:
            continue
        try:
            box.unwrap(blob)
        except LockBoxError:
            rejected.append(artifact)
    return tuple(rejected)


def dek_artifacts_unopenable_by_any(
    data_dir: Path, data_keys: list[bytes],
) -> tuple[DekProtectedArtifact, ...]:
    """Present envelope artifacts that NONE of ``data_keys`` authenticates.

    The preflight of a key migration: everything must open under the key it
    is leaving or the key it is moving to, or the install is already damaged
    and nothing may be changed.  Read-only.
    """
    root = Path(data_dir)
    rejected = []
    for artifact in present_dek_protected_artifacts(root):
        if artifact.protection not in ENVELOPE_PROTECTIONS:
            continue
        blob = _read_dek_envelope_artifact(root, artifact)
        if blob is None:
            continue
        if not any(_opens(key, blob) for key in data_keys):
            rejected.append(artifact)
    return tuple(rejected)


def _existing_data_refusal(
    paths: list[str], *, seeded: bool = True,
) -> KeyMaterialProtectionError:
    """The refusal every passphrase mint gives over existing data.

    It names the migration that does the work: one offline transaction that
    re-wraps every protected artifact and field under the new key.
    """
    if seeded:
        remedy = (
            "start One Link without ONE_LINK_PASSPHRASE, or stop it and run "
            "`one-link recovery set-passphrase`"
        )
    else:
        remedy = (
            "this installation has no recovery seed: stop One Link, run "
            "`one-link backup init` with ONE_LINK_PASSPHRASE unset and start "
            "One Link once to establish one, then run "
            "`one-link recovery set-passphrase`"
        )
    return KeyMaterialProtectionError(
        "passphrase recovery envelope is missing for existing application "
        f"data ({', '.join(sorted(paths))}); explicit recovery migration is "
        f"required: {remedy}"
    )


def _silent_key_on_disk(data_dir: Path) -> Optional[bytes]:
    """The persisted silent DRK, or ``None`` when it is proven absent."""
    blob = read_bytes_if_exists(
        _drk_path(Path(data_dir)),
        label="data root key",
        max_bytes=65536,
        harden_path=_harden_drk_path,
    )
    return None if blob is None else _decode_drk_blob(blob)


def _surviving_silent_key(
    data_dir: Path,
    *,
    seed: bytes,
    replacing_data_root: bool,
) -> Callable[[], Optional[bytes]]:
    """The silent key that would keep a seeded install's existing data readable.

    Ordinarily that is the persisted DRK; when it is missing, the next silent
    boot re-derives ``derive_drk(seed)``, so data under it is still readable
    and still protected.  A confirmed recovery (``replacing_data_root``)
    installs ``derive_drk(seed)``: data under any other persisted DRK is what
    the user confirmed replacing (``None``), and a DRK this process cannot
    unprotect -- a bundle member DPAPI-bound to another machine -- cannot
    prove the data is under a different key, so it counts as the seed's own
    and the mint is refused.
    """

    def surviving() -> Optional[bytes]:
        from one_link import master_seed

        derived = master_seed.derive_drk(bytes(seed))
        try:
            on_disk = _silent_key_on_disk(Path(data_dir))
        except (KeyMaterialProtectionError, KeyMaterialIntegrityError):
            if not replacing_data_root:
                raise
            return derived
        if on_disk is None:
            return derived
        if not replacing_data_root:
            return on_disk
        return derived if secrets.compare_digest(on_disk, derived) else None

    return surviving


def _refuse_passphrase_dek_over_silent_data(
    data_dir: Path,
    *,
    surviving_silent_key: Callable[[], Optional[bytes]],
    salt_preexisted: bool,
    candidate: Optional[bytes],
) -> None:
    """Refuse to make scrypt(passphrase) the DEK while a silent key protects data.

    Publishing a passphrase envelope makes its DEK the install's data key for
    every later boot, silent boots included (they open it through the seed
    slot).  That is a key replacement unless the candidate already is the key
    protecting the data.  ``surviving_silent_key`` returns the silent key that
    would otherwise keep the existing data readable, or ``None`` when no such
    key survives (data a confirmed recovery is replacing).

    * No salt before this call: the candidate is brand new, so any registered
      data under a surviving silent key would be orphaned.  Refuse.
    * Salt already present: either legacy passphrase rows (the candidate IS
      their key; migration is byte-preserving) or an interrupted bootstrap's
      salt over silent rows.  File names cannot tell these apart; a
      whole-file witness can, so refuse iff some witness opens under the
      silent key and not under the candidate.
    """
    root = Path(data_dir)
    present = present_dek_protected_artifacts(root)
    if not present:
        return
    silent_key = surviving_silent_key()
    if silent_key is None:
        return
    if not salt_preexisted:
        raise _existing_data_refusal([artifact.relpath for artifact in present])
    if candidate is None:
        raise ValueError("a pre-existing salt requires its candidate data key")
    orphaned = []
    for artifact in present:
        if artifact.protection not in ENVELOPE_PROTECTIONS:
            continue
        blob = _read_dek_envelope_artifact(root, artifact)
        if blob is not None and _opens(silent_key, blob) and not _opens(candidate, blob):
            orphaned.append(artifact.relpath)
    if orphaned:
        raise _existing_data_refusal(orphaned)


def _durable_move(source: Path, target: Path) -> None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.replace(source, target)
    for directory in {source.parent, target.parent}:
        if sys.platform == "win32":
            # Windows has no directory fsync; os.replace is a single
            # MoveFileEx(MOVEFILE_REPLACE_EXISTING) on the same volume.
            continue
        fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def carry_dek_protected_envelopes(
    data_dir: Path,
    *,
    previous_key: Optional[bytes],
    target_key: bytes,
) -> dict[str, list[str]]:
    """Leave no envelope artifact the converged data key cannot open.

    Called by a confirmed seed/authority replacement while the previous key
    still exists on disk and before it is replaced.  For each registered
    whole-file envelope:

    * it opens under ``target_key``: kept (also the idempotent replay case);
    * it opens under ``previous_key``: re-wrapped under ``target_key``,
      atomically and read back, so the replacement carries it instead of
      orphaning it (identity rotation in silent mode replaces the DRK);
    * it opens under neither: it was protected by an authority this
      transaction does not hold and the user confirmed replacing.  A
      retirable artifact moves, with what it protects, under
      ``RETIRED_ARTIFACTS_DIRNAME``; a non-retirable one stays in place.

    Returns ``{"carried": [...], "retired": [...], "unopenable": [...]}`` as
    registry names.  Embedded artifacts (state.db columns) are outside this
    layer's reach and are not touched.
    """
    if len(target_key) != 32:
        raise ValueError("target_key must be 32 bytes")
    if previous_key is not None and len(previous_key) != 32:
        raise ValueError("previous_key must be 32 bytes")
    root = Path(data_dir)
    target = LockBox(target_key)
    outcome: dict[str, list[str]] = {"carried": [], "retired": [], "unopenable": []}
    retire_root: Optional[Path] = None
    for artifact in present_dek_protected_artifacts(root):
        if artifact.protection not in ENVELOPE_PROTECTIONS:
            continue
        blob = _read_dek_envelope_artifact(root, artifact)
        if blob is None or _opens(target_key, blob):
            continue
        if previous_key is not None and _opens(previous_key, blob):
            plaintext = LockBox(previous_key).unwrap(blob)
            label = f"DEK-protected {artifact.name}"

            def _validate(
                candidate: bytes, _expected: bytes = plaintext, _label: str = label,
            ) -> None:
                try:
                    recovered = target.unwrap(candidate)
                except LockBoxError as exc:
                    raise KeyMaterialIntegrityError(
                        f"re-wrapped {_label} does not open under the converged key"
                    ) from exc
                if not secrets.compare_digest(recovered, _expected):
                    raise KeyMaterialIntegrityError(
                        f"re-wrapped {_label} failed exact read-back"
                    )

            atomic_replace_bytes(
                artifact.path(root),
                target.wrap(plaintext),
                label=label,
                validate=_validate,
                harden_path=_harden_envelope_path,
            )
            outcome["carried"].append(artifact.name)
            continue
        if not artifact.retirable:
            outcome["unopenable"].append(artifact.name)
            continue
        if retire_root is None:
            retire_root = root / RETIRED_ARTIFACTS_DIRNAME / (
                f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
                f"{secrets.token_hex(4)}"
            )
        for relpath in (artifact.relpath, *artifact.retire_with):
            source = root.joinpath(*relpath.split("/"))
            if artifact_exists(source, label=f"retiring {relpath}"):
                _durable_move(source, retire_root.joinpath(*relpath.split("/")))
        outcome["retired"].append(artifact.name)
    return outcome


def envelope_data_key_for_seed(data_dir: Path, seed: bytes) -> Optional[bytes]:
    """The stable DEK held by the envelope's seed slot, ``None`` if no envelope.

    An envelope the seed cannot open raises: callers use this to learn the
    converged data key, and must not guess one.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    envelope = _load_envelope(Path(data_dir))
    if envelope is None:
        return None
    dek = _decrypt_dek_slot(
        envelope, wrapping_key=_seed_wrap_key(bytes(seed)), seed_slot=True,
    )
    if dek is None:
        raise KeyMaterialProtectionError(
            "lockbox DEK envelope is not recoverable by this master seed"
        )
    return dek


# ─── per-install salt persistence ──────────────────────────────────


SALT_FILENAME = "lockbox.salt"


def load_or_create_salt(data_dir: Path) -> bytes:
    """Read or generate the 16-byte per-install salt for the
    passphrase KDF. The salt is non-secret (it goes through the same
    storage as the wrapped data); it only ensures that a captured
    passphrase can't be used against another install's wrapped data
    via offline rainbow tables."""
    salt_path = Path(data_dir) / SALT_FILENAME
    existing = read_bytes_if_exists(
        salt_path,
        label="lockbox KDF salt",
        max_bytes=1024,
    )
    if existing is not None:
        if len(existing) != 16:
            raise KeyMaterialIntegrityError(
                "existing lockbox KDF salt has an invalid length"
            )
        return existing
    fresh = secrets.token_bytes(16)

    def _validate(blob: bytes) -> None:
        if len(blob) != 16:
            raise KeyMaterialIntegrityError(
                "published lockbox KDF salt has an invalid length"
            )

    if atomic_create_bytes(
        salt_path,
        fresh,
        label="lockbox KDF salt",
        validate=_validate,
    ):
        return fresh
    sync_existing_authority(salt_path, label="lockbox KDF salt")
    winner = read_bytes_if_exists(
        salt_path,
        label="lockbox KDF salt",
        max_bytes=1024,
    )
    if winner is None:
        raise KeyMaterialPersistenceError(
            "concurrent lockbox-salt publication reported a winner but none exists"
        )
    _validate(winner)
    return winner


def lockbox_from_env(data_dir: Path) -> Optional["LockBox"]:
    """Compatibility gate for callers that require an explicit passphrase.

    It returns ``None`` when the environment factor is absent, but when present
    it routes through the same versioned stable-DEK envelope as every supported
    production caller. It must never recreate the legacy direct-scrypt bypass.
    """
    pw = os.environ.get(PASSPHRASE_ENV, "")
    if not pw:
        return None
    return acquire_lockbox(Path(data_dir))


def _agree_deks(*candidates: Optional[bytes]) -> Optional[bytes]:
    available = [bytes(candidate) for candidate in candidates if candidate is not None]
    if not available:
        return None
    winner = available[0]
    if any(not secrets.compare_digest(winner, other) for other in available[1:]):
        raise KeyMaterialIntegrityError(
            "lockbox DEK envelope recovery slots disagree"
        )
    return winner


def _passphrase_envelope_candidate(
    envelope: _DekEnvelope,
    *,
    passphrase: str,
    salt: bytes,
) -> tuple[Optional[bytes], bytes]:
    legacy_dek = _derive_legacy_passphrase_dek(
        passphrase.encode("utf-8"), bytes(salt)
    )
    wrapping_key = _passphrase_wrap_key(legacy_dek)
    if not secrets.compare_digest(
        hashlib.sha256(bytes(salt)).digest(), envelope.salt_digest
    ):
        return None, wrapping_key
    return (
        _decrypt_dek_slot(
            envelope,
            wrapping_key=wrapping_key,
            seed_slot=False,
        ),
        wrapping_key,
    )


def recovery_envelope_matches_seed(data_dir: Path, seed: bytes) -> Optional[bool]:
    """Observe whether the application DEK has a valid wrap for ``seed``.

    ``None`` is a proven-absent envelope (silent DRK mode).  Malformed files
    raise; a well-formed envelope authenticated by another seed returns False.
    The function never creates or rewrites authority and is safe for recovery
    preflight and paper-phrase verification.
    """

    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    envelope = _load_envelope(Path(data_dir))
    if envelope is None:
        return None
    recovered = _decrypt_dek_slot(
        envelope,
        wrapping_key=_seed_wrap_key(bytes(seed)),
        seed_slot=True,
    )
    return recovered is not None


def requires_legacy_passphrase_recovery(data_dir: Path) -> bool:
    """Return True when paper/social recovery still needs the old passphrase.

    This is intentionally observational.  A configured passphrase or persisted
    legacy salt with no DEK envelope means direct-scrypt application rows may
    exist and the master seed alone has not been proven able to open them.
    """

    root = Path(data_dir)
    if _load_envelope(root) is not None:
        return False
    if bool(os.environ.get(PASSPHRASE_ENV, "")):
        return True
    from one_link.key_material import artifact_exists

    return artifact_exists(root / SALT_FILENAME, label="lockbox KDF salt")


def prepare_bootstrap_recovery_envelope(data_dir: Path, *, seed: bytes) -> bool:
    """Complete a new install's passphrase envelope before authority checks.

    The daemon owns its instance lock while calling this.  This mutation is
    deliberately separate from ``recovery_envelope_matches_seed``: inspection
    remains read-only, and an existing envelope is never repaired or rebound
    merely to make a startup check pass.  Atomic create plus the envelope lock
    makes interrupted first boots replayable with the original seed and salt.

    Existing application data without an envelope needs explicit migration.
    In particular, setting a passphrase on a previously silent installation
    must not replace the key that already encrypts its rows.  "Existing
    application data" is every non-regenerable entry of
    ``DEK_PROTECTED_ARTIFACTS``, not only the SQLite files: the capsule key,
    TLS root authority and update authority are wrapped by the same key.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    root = Path(data_dir)
    with _envelope_mutation_lock(root, purpose="bootstrap recovery envelope"):
        envelope = _load_envelope(root)
        if envelope is None:
            passphrase = os.environ.get(PASSPHRASE_ENV, "")
            if not passphrase:
                return False
            present = present_dek_protected_artifacts(root)
            if present:
                raise _existing_data_refusal(
                    [artifact.relpath for artifact in present]
                )
            salt = load_or_create_salt(root)
            dek = _derive_legacy_passphrase_dek(passphrase.encode("utf-8"), salt)
            envelope = _publish_new_envelope(
                root,
                _new_envelope(
                    dek=dek,
                    salt=salt,
                    passphrase_key=_passphrase_wrap_key(dek),
                    seed=bytes(seed),
                ),
            )
        recovered = _decrypt_dek_slot(
            envelope,
            wrapping_key=_seed_wrap_key(bytes(seed)),
            seed_slot=True,
        )
        if recovered is None:
            raise KeyMaterialIntegrityError(
                "persisted lockbox DEK envelope does not match the master seed"
            )
        return True


def ensure_recovery_envelope_for_backup(
    data_dir: Path,
    *,
    seed: bytes,
    replacing_data_root: bool = False,
) -> bool:
    """Ensure passphrase-mode application rows are portable in a backup.

    Returns True when an envelope exists and its seed slot is proven usable,
    False for ordinary silent-DRK mode.  Existing direct-scrypt installs are
    migrated without rewriting a single row: the exact legacy key becomes the
    stable DEK and is atomically dual-wrapped before export continues.

    A passphrase present in the environment never turns a silent install
    into a passphrase one here: the first envelope would replace the DRK as
    the data key of every later boot.  ``replacing_data_root`` is set only by
    a confirmed recovery transaction, which installs ``derive_drk(seed)`` as
    the silent key; data under any other DRK is what that transaction was
    confirmed to replace, so only data the seed's own DRK protects (a restored
    bundle, a replay) still blocks the mint.
    """

    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    root = Path(data_dir)
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    with _envelope_mutation_lock(root, purpose="backup recovery envelope"):
        envelope = _load_envelope(root)
        if envelope is None and not passphrase:
            if artifact_exists(root / SALT_FILENAME, label="lockbox KDF salt"):
                raise KeyMaterialProtectionError(
                    "legacy passphrase-mode LockBox has no DEK recovery "
                    "envelope; set the source ONE_LINK_PASSPHRASE before backup"
                )
            return False
        surviving = _surviving_silent_key(
            root, seed=bytes(seed), replacing_data_root=replacing_data_root,
        )
        salt_preexisted = artifact_exists(
            root / SALT_FILENAME, label="lockbox KDF salt"
        )
        if envelope is None and not salt_preexisted:
            # Checked before the salt exists: minting it is the new authority.
            _refuse_passphrase_dek_over_silent_data(
                root,
                surviving_silent_key=surviving,
                salt_preexisted=False,
                candidate=None,
            )
        if not passphrase:
            if envelope is None:
                raise KeyMaterialIntegrityError(
                    "lockbox DEK envelope disappeared during the locked backup transaction"
                )
            recovered = _decrypt_dek_slot(
                envelope,
                wrapping_key=_seed_wrap_key(bytes(seed)),
                seed_slot=True,
            )
            if recovered is None:
                raise KeyMaterialProtectionError(
                    "lockbox DEK envelope is not recoverable by this backup seed"
                )
            return True

        salt = load_or_create_salt(root)
        legacy_dek = _derive_legacy_passphrase_dek(
            passphrase.encode("utf-8"), salt
        )
        passphrase_key = _passphrase_wrap_key(legacy_dek)
        if envelope is None:
            if salt_preexisted:
                _refuse_passphrase_dek_over_silent_data(
                    root,
                    surviving_silent_key=surviving,
                    salt_preexisted=True,
                    candidate=legacy_dek,
                )
            envelope = _publish_new_envelope(
                root,
                _new_envelope(
                    dek=legacy_dek,
                    salt=salt,
                    passphrase_key=passphrase_key,
                    seed=bytes(seed),
                ),
            )

        passphrase_dek, passphrase_key = _passphrase_envelope_candidate(
            envelope,
            passphrase=passphrase,
            salt=salt,
        )
        seed_dek = _decrypt_dek_slot(
            envelope,
            wrapping_key=_seed_wrap_key(bytes(seed)),
            seed_slot=True,
        )
        dek = _agree_deks(passphrase_dek, seed_dek)
        if dek is None:
            raise KeyMaterialProtectionError(
                "neither the configured passphrase nor backup seed can open "
                "the lockbox DEK envelope"
            )
        salt_changed = not secrets.compare_digest(
            hashlib.sha256(salt).digest(), envelope.salt_digest
        )
        if passphrase_dek is None or seed_dek is None or salt_changed:
            envelope = _replace_envelope_slots(
                envelope,
                dek=dek,
                passphrase_key=passphrase_key,
                seed=bytes(seed),
                salt=salt if salt_changed else None,
            )
            _replace_envelope(root, envelope)
        return True


def rebind_recovery_envelope(
    data_dir: Path,
    *,
    target_seed: bytes,
    current_seed: Optional[bytes] = None,
) -> bool:
    """Bind an existing stable DEK to a replacement master seed.

    Recovery calls this while its durable intent still exists and before the
    master seed is replaced.  The DEK can be opened by the target seed (bundle
    restore/replay), the current seed (in-place seed rotation), or the explicit
    passphrase.  At least one must authenticate; no guessed or random key is
    ever published.  The passphrase slot is retained unless an explicit new
    passphrase/salt is available to authenticate or rotate it.
    """

    if not isinstance(target_seed, (bytes, bytearray)) or len(target_seed) != 32:
        raise ValueError("target_seed must be 32 bytes")
    if current_seed is not None and len(current_seed) != 32:
        raise ValueError("current_seed must be 32 bytes")
    root = Path(data_dir)
    with _envelope_mutation_lock(root, purpose="recovery envelope rebind"):
        envelope = _load_envelope(root)
        if envelope is None:
            return False
        target_dek = _decrypt_dek_slot(
            envelope,
            wrapping_key=_seed_wrap_key(bytes(target_seed)),
            seed_slot=True,
        )
        current_dek = None
        if current_seed is not None:
            current_dek = _decrypt_dek_slot(
                envelope,
                wrapping_key=_seed_wrap_key(bytes(current_seed)),
                seed_slot=True,
            )

        passphrase = os.environ.get(PASSPHRASE_ENV, "")
        passphrase_dek: Optional[bytes] = None
        passphrase_key: Optional[bytes] = None
        salt: Optional[bytes] = None
        salt_changed = False
        if passphrase:
            salt = load_or_create_salt(root)
            passphrase_dek, passphrase_key = _passphrase_envelope_candidate(
                envelope,
                passphrase=passphrase,
                salt=salt,
            )
            salt_changed = not secrets.compare_digest(
                hashlib.sha256(salt).digest(), envelope.salt_digest
            )

        dek = _agree_deks(target_dek, current_dek, passphrase_dek)
        if dek is None:
            raise KeyMaterialProtectionError(
                "lockbox DEK recovery requires the source master seed or "
                "the source ONE_LINK_PASSPHRASE"
            )
        if (
            target_dek is None
            or (passphrase and passphrase_dek is None)
            or salt_changed
        ):
            replacement = _replace_envelope_slots(
                envelope,
                dek=dek,
                passphrase_key=passphrase_key,
                seed=bytes(target_seed),
                salt=salt if salt_changed else None,
            )
            _replace_envelope(root, replacement)
        return True


# ─── data-key migration primitives (`one-link recovery *-passphrase`) ───
#
# recovery_api.set_data_key_passphrase / remove_data_key_passphrase own the
# transaction; these are its key operations.  Each is idempotent: it inspects
# what is on disk, classifies keys by authenticating them, and does only the
# work that is still missing.  They run inside the migration's envelope
# transaction (re-entrant), never on their own.


def _envelope_slots_open(
    envelope: _DekEnvelope, *, salt: bytes, passphrase: str, seed: bytes,
) -> bytes:
    """The DEK both slots authenticate; refuses unless BOTH open and agree."""
    passphrase_dek, _key = _passphrase_envelope_candidate(
        envelope, passphrase=passphrase, salt=salt,
    )
    if passphrase_dek is None:
        raise KeyMaterialProtectionError(
            "the passphrase does not open this installation's data key"
        )
    seed_dek = _decrypt_dek_slot(
        envelope, wrapping_key=_seed_wrap_key(bytes(seed)), seed_slot=True,
    )
    if seed_dek is None:
        raise KeyMaterialProtectionError(
            "the master seed does not open this installation's data key envelope"
        )
    dek = _agree_deks(passphrase_dek, seed_dek)
    if dek is None:  # pragma: no cover - both slots were proven present
        raise KeyMaterialIntegrityError("lockbox DEK envelope slots are empty")
    return dek


def _read_salt_file(path: Path, *, label: str) -> Optional[bytes]:
    salt = read_bytes_if_exists(path, label=label, max_bytes=1024)
    if salt is not None and len(salt) != 16:
        raise KeyMaterialIntegrityError(f"{label} has an invalid length")
    return salt


def _durable_rename(source: Path, target: Path) -> None:
    """Atomically rename within one directory and make it durable."""
    try:
        os.replace(source, target)
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            f"cannot publish {target.name}"
        ) from exc
    if sys.platform != "win32":
        fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _durable_remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot remove {path.name}") from exc
    if sys.platform != "win32":
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def stage_passphrase_envelope(
    data_dir: Path, *, passphrase: str, seed: bytes,
) -> bytes:
    """Stage the target envelope of set-passphrase; return its data key.

    The staged envelope IS the migration's durable record of the target key:
    it is published no-replace before any value is carried, under names no
    reader consults (``STAGED_*``).  The target DEK is fresh randomness, not
    scrypt(passphrase): knowing the passphrase and the (non-secret, backed-up)
    salt is then not enough to compute it.  A replay re-opens the staged
    envelope and proves the operator's passphrase against its passphrase
    slot, so a different passphrase on replay refuses instead of forking.
    """
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    root = Path(data_dir)
    staged_envelope = root / STAGED_ENVELOPE_FILENAME
    staged_salt = root / STAGED_SALT_FILENAME
    payload = read_bytes_if_exists(
        staged_envelope,
        label="staged lockbox DEK envelope",
        max_bytes=DEK_ENVELOPE_LEN + 1,
    )
    if payload is not None:
        salt = _read_salt_file(staged_salt, label="staged lockbox KDF salt")
        if salt is None:
            raise KeyMaterialIntegrityError(
                "staged lockbox DEK envelope exists without its staged salt"
            )
        return _envelope_slots_open(
            _DekEnvelope.decode(payload), salt=salt, passphrase=passphrase, seed=bytes(seed),
        )
    salt = _read_salt_file(staged_salt, label="staged lockbox KDF salt")
    if salt is None:
        salt = secrets.token_bytes(16)

        def _validate_salt(blob: bytes, _expected: bytes = salt) -> None:
            if not secrets.compare_digest(blob, _expected):
                raise KeyMaterialIntegrityError("staged lockbox KDF salt read-back mismatch")

        if not atomic_create_bytes(
            staged_salt, salt, label="staged lockbox KDF salt", validate=_validate_salt,
        ):
            raise KeyMaterialPersistenceError(
                "a concurrent writer published the staged lockbox KDF salt"
            )
    dek = secrets.token_bytes(32)
    legacy = _derive_legacy_passphrase_dek(passphrase.encode("utf-8"), salt)
    envelope = _new_envelope(
        dek=dek, salt=salt, passphrase_key=_passphrase_wrap_key(legacy), seed=bytes(seed),
    )
    expected = envelope.encode()

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(blob, expected):
            raise KeyMaterialIntegrityError("staged lockbox DEK envelope read-back mismatch")

    if not atomic_create_bytes(
        staged_envelope,
        expected,
        label="staged lockbox DEK envelope",
        validate=_validate,
        harden_path=_harden_envelope_path,
    ):
        raise KeyMaterialPersistenceError(
            "a concurrent writer published the staged lockbox DEK envelope"
        )
    return dek


def open_live_passphrase_envelope(
    data_dir: Path, *, passphrase: str, seed: bytes,
) -> Optional[bytes]:
    """The live envelope's DEK, proven by the passphrase AND the seed.

    ``None`` when no live envelope exists (silent mode).  A wrong passphrase
    raises rather than falling back to the seed slot: remove-passphrase must
    be authorized by the factor it removes.
    """
    root = Path(data_dir)
    envelope = _load_envelope(root)
    if envelope is None:
        return None
    salt = _read_salt_file(root / SALT_FILENAME, label="lockbox KDF salt")
    if salt is None:
        raise KeyMaterialProtectionError(
            "the lockbox KDF salt is missing, so the passphrase cannot be "
            "verified against this installation's data key"
        )
    return _envelope_slots_open(envelope, salt=salt, passphrase=passphrase, seed=bytes(seed))


def publish_staged_passphrase_envelope(
    data_dir: Path, *, passphrase: str, seed: bytes, expected_dek: bytes,
) -> None:
    """Make the staged envelope (and then its salt) the live authority.

    The envelope rename is the switch: from that instant every reader opens
    ``expected_dek``.  A live envelope with its salt still staged is already
    a consistent passphrase install (acquire_lockbox re-salts it), and the
    replay finishes the salt rename.  Every step re-proves the key first.
    """
    root = Path(data_dir)
    live = root / DEK_ENVELOPE_FILENAME
    staged = root / STAGED_ENVELOPE_FILENAME
    staged_salt = root / STAGED_SALT_FILENAME
    salt = _read_salt_file(staged_salt, label="staged lockbox KDF salt")
    if not artifact_exists(live, label="lockbox DEK envelope"):
        payload = read_bytes_if_exists(
            staged, label="staged lockbox DEK envelope", max_bytes=DEK_ENVELOPE_LEN + 1,
        )
        if payload is None or salt is None:
            raise KeyMaterialIntegrityError(
                "set-passphrase has neither a live nor a staged data-key envelope"
            )
        dek = _envelope_slots_open(
            _DekEnvelope.decode(payload), salt=salt, passphrase=passphrase, seed=bytes(seed),
        )
        if not secrets.compare_digest(dek, bytes(expected_dek)):
            raise KeyMaterialIntegrityError(
                "staged data-key envelope does not hold the key the data was carried to"
            )
        _durable_rename(staged, live)
    envelope = _load_envelope(root)
    if envelope is None:  # pragma: no cover - published or present above
        raise KeyMaterialIntegrityError("published lockbox DEK envelope disappeared")
    live_salt = _read_salt_file(root / SALT_FILENAME, label="lockbox KDF salt")
    if salt is not None:
        if live_salt is None:
            _durable_rename(staged_salt, root / SALT_FILENAME)
        elif secrets.compare_digest(live_salt, salt):
            _durable_remove(staged_salt)
        else:
            raise KeyMaterialIntegrityError(
                "a different lockbox KDF salt appeared during set-passphrase"
            )
    final_salt = _read_salt_file(root / SALT_FILENAME, label="lockbox KDF salt")
    if final_salt is None:
        raise KeyMaterialIntegrityError("published lockbox KDF salt is missing")
    dek = _envelope_slots_open(envelope, salt=final_salt, passphrase=passphrase, seed=bytes(seed))
    if not secrets.compare_digest(dek, bytes(expected_dek)):
        raise KeyMaterialIntegrityError(
            "the live data-key envelope does not hold the key the data was carried to"
        )


def retire_passphrase_envelope(
    data_dir: Path, *, passphrase: str, seed: bytes, expected_dek: bytes,
) -> None:
    """Take the envelope and salt out of service (remove-passphrase's switch).

    Renamed, not deleted: the old authority is deleted only after the
    silent key has been verified against every artifact and field
    (``discard_retired_passphrase_authority``).
    """
    root = Path(data_dir)
    live = root / DEK_ENVELOPE_FILENAME
    if artifact_exists(live, label="lockbox DEK envelope"):
        dek = open_live_passphrase_envelope(root, passphrase=passphrase, seed=seed)
        if dek is None or not secrets.compare_digest(dek, bytes(expected_dek)):
            raise KeyMaterialIntegrityError(
                "the live data-key envelope changed during remove-passphrase"
            )
        _durable_rename(live, root / RETIRED_ENVELOPE_FILENAME)
    if artifact_exists(root / SALT_FILENAME, label="lockbox KDF salt"):
        _durable_rename(root / SALT_FILENAME, root / RETIRED_SALT_FILENAME)


def passphrase_startup_refusal(
    data_dir: Path, *, probe_database: bool,
) -> Optional[KeyMaterialProtectionError]:
    """Why this process cannot open a passphrase-protected installation.

    ``None`` means "not this case": the caller keeps its ordinary behaviour.
    Read-only; never mints, rewraps or migrates anything.

    * ``probe_database=True`` -- the daemon's bootstrap, before the identity
      file is read (identity.load_or_create re-encrypts a cleartext identity
      under whatever passphrase is set, so a wrong one must be refused
      first), and State after its encrypted open failed.
    * ``probe_database=False`` -- State before the keychain could mint a
      database key: the cheap check, no KDF and no database open.

    What it proves: a live DEK envelope exists (only a passphrase ever
    creates one) and state.db is SQLCipher.  With ONE_LINK_PASSPHRASE set,
    whether it authenticates the envelope's passphrase slot -- AES-GCM,
    independent of the database, so a wrong passphrase is exact and a right
    one hands any later failure back to the caller.  Without it, whether a
    stored database key exists and (probing) opens state.db.  It cannot tell
    a database keyed by the passphrase from a damaged one; both start by
    supplying the passphrase.  A restored passphrase bundle whose database
    key recovery adopted into the keychain opens with that key and is never
    refused.  An installation without an envelope is never refused here.
    """
    root = Path(data_dir)
    envelope = _load_envelope(root)
    if envelope is None:
        return None
    from one_link import keychain, state_encryption

    database = root / "state.db"
    if state_encryption.detect_db_state(database) != "encrypted":
        return None
    fixes = (
        "set ONE_LINK_PASSPHRASE to the passphrase that protects it, or run "
        "`one-link recovery remove-passphrase` (which needs that passphrase)"
    )
    passphrase = os.environ.get(PASSPHRASE_ENV, "")
    if passphrase:
        if not probe_database:
            return None
        salt = _read_salt_file(root / SALT_FILENAME, label="lockbox KDF salt")
        if salt is None:
            return None  # cannot be checked here; acquire_lockbox re-salts
        opened, _key = _passphrase_envelope_candidate(
            envelope, passphrase=passphrase, salt=salt,
        )
        if opened is not None:
            return None
        return KeyMaterialProtectionError(
            "ONE_LINK_PASSPHRASE is not the passphrase that protects this "
            f"installation, so its state database cannot be opened; {fixes}"
        )
    stored = keychain._configured_passphrase_at(root)  # environment unset; never mints
    if stored is not None and (
        not probe_database or state_encryption.database_accepts_passphrase(database, stored)
    ):
        return None
    return KeyMaterialProtectionError(
        "this installation is protected by a passphrase and was started "
        f"without ONE_LINK_PASSPHRASE, so its state database cannot be opened; {fixes}"
    )


def holds_data_key(box: "LockBox", data_key: bytes) -> bool:
    """Whether ``box`` holds exactly ``data_key`` (an in-memory probe)."""
    probe = LockBox(bytes(data_key)).wrap(b"OL/lockbox/same-key-probe|v1")
    try:
        box.unwrap(probe)
    except LockBoxError:
        return False
    return True


def discard_retired_passphrase_authority(data_dir: Path) -> None:
    root = Path(data_dir)
    for name in (RETIRED_ENVELOPE_FILENAME, RETIRED_SALT_FILENAME):
        _durable_remove(root / name)


# ─── silent-mode DRK acquisition (v0.20.7 audit C5 partial-auto) ───


def _dpapi_protect(plaintext: bytes) -> Optional[bytes]:
    """Windows-only: DPAPI-wrap ``plaintext`` so it can be unwrapped
    only by a process running as the SAME user account on the SAME
    machine (or in a domain, the same user from any domain machine
    that trusts the master key). Returns the protected blob, or None
    if DPAPI is unavailable / fails. Best-effort by design."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte)),
            ]

        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        in_buf = (ctypes.c_byte * len(plaintext))(*plaintext)
        in_blob = _DATA_BLOB(len(plaintext), in_buf)
        out_blob = _DATA_BLOB(0, None)

        # CRYPTPROTECT_LOCAL_MACHINE = 0x4 would let any user on
        # the box decrypt; we DO NOT set it — the DRK should be
        # bound to this single user account.
        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            ctypes.c_wchar_p(DRK_DPAPI_DESCRIPTION),
            None,  # entropy
            None,  # reserved
            None,  # prompt struct
            0,     # flags
            ctypes.byref(out_blob),
        )
        if not ok:
            return None
        try:
            wrapped = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            kernel32.LocalFree(out_blob.pbData)
        return wrapped
    except Exception:
        return None


def _dpapi_unprotect(wrapped: bytes) -> Optional[bytes]:
    """Windows-only: DPAPI-unwrap. Returns the plaintext or None on
    failure (wrong user, wrong machine, corrupt blob)."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte)),
            ]

        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        in_buf = (ctypes.c_byte * len(wrapped))(*wrapped)
        in_blob = _DATA_BLOB(len(wrapped), in_buf)
        out_blob = _DATA_BLOB(0, None)

        descr = wintypes.LPWSTR()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            ctypes.byref(descr),
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
        if not ok:
            return None
        try:
            plaintext = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            kernel32.LocalFree(out_blob.pbData)
            if descr:
                kernel32.LocalFree(descr)
        return plaintext
    except Exception:
        return None


def _drk_path(data_dir: Path) -> Path:
    return Path(data_dir) / DRK_FILENAME


def _harden_drk_path(path: Path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)


def _decode_drk_blob(blob: bytes) -> bytes:
    if not blob:
        raise KeyMaterialIntegrityError("existing data root key is empty")
    if os.name == "nt":
        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None:
            raise KeyMaterialProtectionError(
                "existing data root key could not be DPAPI-unprotected"
            )
        if len(unwrapped) != 32:
            raise KeyMaterialIntegrityError(
                "existing data root key has an invalid unwrapped length"
            )
        return bytes(unwrapped)
    if len(blob) != 32:
        raise KeyMaterialIntegrityError("existing data root key has an invalid length")
    return bytes(blob)


def _encode_drk(drk: bytes) -> bytes:
    if os.name != "nt":
        return bytes(drk)
    wrapped = _dpapi_protect(bytes(drk))
    if not wrapped:
        raise KeyMaterialProtectionError(
            "DPAPI protection failed; refusing to persist a raw data root key"
        )
    return bytes(wrapped)


def acquire_or_create_silent_drk(data_dir: Path) -> bytes:
    """v0.20.7 (security audit C5 silent-mode): get the per-install
    32-byte data root key without involving the user.

    Only a proven-absent path may create.  Existing unreadable, corrupt, or
    DPAPI-unusable authority raises and remains byte-identical.  First
    publication is durable and no-replace; concurrent starts converge on the
    winner, and no generated key is returned until persisted bytes have been
    read back, unprotected, and compared.
    """
    p = _drk_path(data_dir)
    blob = read_bytes_if_exists(
        p,
        label="data root key",
        max_bytes=65536,
        harden_path=_harden_drk_path,
    )
    if blob is not None:
        return _decode_drk_blob(blob)

    # v0.20.7 (master-seed integration): if a master seed has been
    # provisioned, derive the DRK from it deterministically instead
    # of minting fresh randomness. Then a user who restores their
    # 24-word phrase on a new device gets the same DRK as the
    # original install — at-rest data unlocks transparently.
    fresh: Optional[bytes] = None
    from one_link import master_seed as _ms

    seed = _ms.load_seed(data_dir)
    if seed is not None:
        fresh = _ms.derive_drk(seed)
    if fresh is None:
        # A random DRK is a brand-new data-key authority.  On an install whose
        # data key is a passphrase authority it would silently become the key
        # of every later silent boot while the passphrase-era data stays
        # unreadable (the mirror image of a passphrase replacing a DRK).
        for name, label in (
            (SALT_FILENAME, "lockbox KDF salt"),
            (DEK_ENVELOPE_FILENAME, "lockbox DEK envelope"),
        ):
            if artifact_exists(Path(data_dir) / name, label=label):
                raise KeyMaterialProtectionError(
                    f"this installation's data key is a passphrase authority "
                    f"({name}); refusing to mint a silent data root key over "
                    "it. Set ONE_LINK_PASSPHRASE to the passphrase that "
                    "protects this installation"
                )
        fresh = secrets.token_bytes(32)
    payload = _encode_drk(fresh)

    def _validate(candidate: bytes) -> None:
        if not secrets.compare_digest(_decode_drk_blob(candidate), fresh):
            raise KeyMaterialIntegrityError(
                "published data root key does not match generated authority"
            )

    if atomic_create_bytes(
        p,
        payload,
        label="data root key",
        validate=_validate,
        harden_path=_harden_drk_path,
    ):
        return fresh
    sync_existing_authority(p, label="data root key")
    winner = read_bytes_if_exists(
        p,
        label="data root key",
        max_bytes=65536,
        harden_path=_harden_drk_path,
    )
    if winner is None:
        raise KeyMaterialPersistenceError(
            "concurrent data-root-key publication reported a winner but none exists"
        )
    return _decode_drk_blob(winner)


def acquire_lockbox(data_dir: Path) -> "LockBox":
    """v0.20.7: top-level "give me a lockbox now" entry point used
    by Daemon. Returns a LockBox using the strongest available key
    derivation:

      - If a passphrase-mode DEK envelope exists: authenticate its stable DEK
        with the configured passphrase or master-seed recovery slot.  A changed
        explicit passphrase is durably rewrapped without rewriting data.
      - If ``ONE_LINK_PASSPHRASE`` is set on a legacy install: derive the exact
        historical scrypt key, atomically dual-wrap it under the passphrase and
        master seed, then keep using it as the DEK.  Existing rows remain
        byte-for-byte readable while paper-seed recovery becomes truthful.
      - A passphrase never replaces a data key that already protects data.  An
        unseeded install with a silent DRK, or a seeded one whose registered
        ``DEK_PROTECTED_ARTIFACTS`` are under its DRK, refuses with the
        explicit-migration error instead of minting a salt or envelope.
      - Otherwise: silent DRK from ``acquire_or_create_silent_drk``, which in
        turn refuses to mint a random DRK over a passphrase authority.
        DPAPI-wrapped on Windows (so a stolen disk without the
        user's login credentials cannot unwrap), file-with-strict-
        perms on macOS/Linux (improvement over cleartext sqlite
        without requiring user setup).

    The point of this function is to make at-rest encryption the
    default for every install, with no UX friction. Audit C5
    silent-mode partial-auto.
    """
    from one_link import master_seed

    root = Path(data_dir)
    pw = os.environ.get(PASSPHRASE_ENV, "")
    seed = master_seed.load_seed(root)
    with _envelope_mutation_lock(root, purpose="data key acquisition"):
        envelope = _load_envelope(root)
        if pw:
            salt_preexisted = artifact_exists(
                root / SALT_FILENAME, label="lockbox KDF salt"
            )
            if envelope is None and not salt_preexisted:
                # Minting the salt here mints scrypt(passphrase) as the data
                # key, so the decision is made before the salt exists.
                if seed is None:
                    # Without a seed nothing derives the DRK: it exists only
                    # because a silent LockBox was issued, and no envelope
                    # will ever arbitrate between it and a passphrase key.
                    if artifact_exists(_drk_path(root), label="data root key"):
                        raise _existing_data_refusal([DRK_FILENAME], seeded=False)
                else:
                    _refuse_passphrase_dek_over_silent_data(
                        root,
                        surviving_silent_key=_surviving_silent_key(
                            root, seed=seed, replacing_data_root=False,
                        ),
                        salt_preexisted=False,
                        candidate=None,
                    )
            salt = load_or_create_salt(root)
            legacy_dek = _derive_legacy_passphrase_dek(pw.encode("utf-8"), salt)
            passphrase_key = _passphrase_wrap_key(legacy_dek)
            if envelope is None:
                if seed is None:
                    # A pre-master-seed legacy install remains readable.  It is
                    # deliberately not called recoverable until explicit seed
                    # migration can publish the second authenticated slot.
                    return LockBox(legacy_dek, is_silent=False)
                if salt_preexisted:
                    _refuse_passphrase_dek_over_silent_data(
                        root,
                        surviving_silent_key=_surviving_silent_key(
                            root, seed=seed, replacing_data_root=False,
                        ),
                        salt_preexisted=True,
                        candidate=legacy_dek,
                    )
                envelope = _publish_new_envelope(
                    root,
                    _new_envelope(
                        dek=legacy_dek,
                        salt=salt,
                        passphrase_key=passphrase_key,
                        seed=seed,
                    ),
                )

            passphrase_dek, passphrase_key = _passphrase_envelope_candidate(
                envelope,
                passphrase=pw,
                salt=salt,
            )
            seed_dek = None
            if seed is not None:
                seed_dek = _decrypt_dek_slot(
                    envelope,
                    wrapping_key=_seed_wrap_key(seed),
                    seed_slot=True,
                )
            dek = _agree_deks(passphrase_dek, seed_dek)
            if dek is None:
                raise KeyMaterialProtectionError(
                    "configured ONE_LINK_PASSPHRASE and master seed cannot "
                    "open the lockbox DEK envelope"
                )
            salt_changed = not secrets.compare_digest(
                hashlib.sha256(salt).digest(), envelope.salt_digest
            )
            if passphrase_dek is None or (seed is not None and seed_dek is None) or salt_changed:
                replacement = _replace_envelope_slots(
                    envelope,
                    dek=dek,
                    passphrase_key=passphrase_key,
                    seed=seed,
                    salt=salt if salt_changed else None,
                )
                _replace_envelope(root, replacement)
            return LockBox(dek, is_silent=False)

        if envelope is not None:
            if seed is None:
                raise KeyMaterialProtectionError(
                    "lockbox DEK envelope requires ONE_LINK_PASSPHRASE or "
                    "its master-seed recovery authority"
                )
            dek = _decrypt_dek_slot(
                envelope,
                wrapping_key=_seed_wrap_key(seed),
                seed_slot=True,
            )
            if dek is None:
                raise KeyMaterialProtectionError(
                    "master seed cannot authenticate the lockbox DEK envelope"
                )
            # is_silent=False describes the persisted data format, not which
            # recovery slot happened to open it on this boot.
            return LockBox(dek, is_silent=False)

        # Under the same lock as salt and envelope publication: whether a
        # random DRK may be minted depends on no passphrase authority existing,
        # and that answer must not change between the check and the mint.
        drk = acquire_or_create_silent_drk(root)
    return LockBox(drk)
