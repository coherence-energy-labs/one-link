"""OS keychain integration for One Link's at-rest encryption key.

The state.db SQLCipher passphrase is auto-generated on first run + stored
in the platform-native secure credential store:

    Windows  → Credential Manager (DPAPI-protected blobs)
    macOS    → Keychain Services
    Linux    → Secret Service (libsecret / GNOME Keyring / KWallet)

All three are backed by the `keyring` library, which auto-detects the
right backend per-OS.

Read order for the passphrase, in priority:

  1. `ONE_LINK_PASSPHRASE` env var (explicit override; honored even on
     keychain-capable machines so operators can lock paranoid mode in
     CI / containers without depending on a desktop keychain).
  2. OS keychain entry under the service name `ONE_LINK_KEYCHAIN_SERVICE`,
     account `ONE_LINK_KEYCHAIN_USER`.
  3. Private local ``state.key`` fallback.
  4. None, only after every configured store proves absence.

Auto-mint policy: on first daemon start when (1) and (2) are both empty,
`ensure_passphrase()` generates a fresh 32-byte url-safe-base64
passphrase, writes it to the keychain, and returns it. Subsequent
restarts pick it up via (2) and stay in paranoid mode automatically —
the user never has to remember anything.

Recovery: an inaccessible backend, unreadable/empty local key file, or
ambiguous write outcome is a typed startup failure, never permission to mint
a replacement.  Only proven absence may create.  First publication is
serialized across processes, read back, and either committed to the OS
credential store or atomically linked into a durable private local file.

This module never logs the passphrase, never echoes it to stderr, never
includes it in exception messages, and exposes no method to retrieve it
in a string suitable for display. The bytes only ever leave via direct
return to a caller.
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import secrets
import stat
import threading
import time
from collections.abc import Iterator

from one_link.key_material import (
    KeyMaterialAccessError,
    KeyMaterialIntegrityError,
    KeyMaterialPersistenceError,
    KeyMaterialProtectionError,
    atomic_create_bytes,
    read_bytes_if_exists,
    sync_existing_authority,
)

log = logging.getLogger("one_link.keychain")

ONE_LINK_KEYCHAIN_SERVICE = "one_link"
ONE_LINK_KEYCHAIN_USER = "state_db_key"
# The pre-scoping account name. One machine-global slot meant every profile
# (distinct ONE_LINK_HOME) on a machine shared -- or, on concurrent first
# boot, CLOBBERED -- one encryption authority: daemon A minted K_A, daemon B
# overwrote with K_B, and A's fail-closed read-back check then refused to
# start. Reads still consult this slot so existing installs keep their key;
# writes go to the per-profile account only.
_LEGACY_KEYCHAIN_ACCOUNT = ONE_LINK_KEYCHAIN_USER
_LEGACY_KEYCHAIN_TARGET = (ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER)
ENV_VAR = "ONE_LINK_PASSPHRASE"
# Filename of the local key-file fallback (see _local_key_path).
LOCAL_KEY_FILENAME = "state.key"
RECOVERY_KEY_FILENAME = "state.key.recovery-v1"
RECOVERY_KEY_MAGIC = b"OLDBKEY\x01\x00\x00\x00\x00"
RECOVERY_KEY_NONCE_LEN = 12
RECOVERY_KEY_MAX_BYTES = len(RECOVERY_KEY_MAGIC) + RECOVERY_KEY_NONCE_LEN + 4096 + 16
_RECOVERY_KEY_INFO = b"OL/master/state-db-key-recovery|v1"
_PROVISION_LOCK_FILENAME = ".state-key.provision.lock"
_provision_thread_lock = threading.RLock()


class KeychainBackendError(KeyMaterialAccessError):
    """The credential backend could not prove presence or absence."""


def _load_keyring():
    """Return the keyring module or None if the library isn't installed.
    Lazy-import so a stripped-down install without the keyring dep
    still boots — it falls back to the local key file (see
    _ensure_local_key) rather than to plaintext."""
    try:
        import keyring  # type: ignore[import-not-found]
        return keyring
    except ImportError:  # pragma: no cover - depends on install env
        return None
    except Exception as exc:  # pragma: no cover - broken install edge
        raise KeychainBackendError("keyring import failed") from exc


# An OS keychain call must never be able to hang One Link forever. macOS
# Keychain Services (and, more rarely, a stalled Secret Service) can block
# indefinitely when the keychain is missing, locked, or unreachable from a
# non-interactive session -- a locked Mac, an SSH shell, a fresh profile, a
# corporate policy prompt. This module already promises a documented
# fallback ("if the OS keychain is unavailable, One Link uses a
# permission-hardened local key file and keeps SQLCipher enabled"), but an
# unbounded call can never REACH that fallback: the daemon simply never
# finishes starting. Every keychain operation therefore runs on a daemon
# thread with a deadline, and a timeout is reported as exactly what it is --
# the backend being unavailable.
KEYCHAIN_CALL_TIMEOUT_SECONDS = 15.0


class KeychainUnresponsiveError(KeychainBackendError):
    """The OS keychain did not answer inside the deadline.

    Distinct from a generic backend error because a READ that never answers
    is side-effect-free: the host demonstrably has no usable credential
    store right now, which is semantically the same as having none at all,
    so the documented local-key path is the correct and safe response. A
    WRITE that times out is NOT covered by this reasoning -- its outcome is
    genuinely unknown -- and that call site keeps refusing to invent a key.
    """


# How long one observed timeout suppresses further attempts.
#
# The deadline above bounds a SINGLE call. It does not bound a host: on a Mac
# whose login keychain is locked (a fresh CI runner, an SSH session, a screen
# that has not been unlocked yet) EVERY call costs the full deadline, and the
# 15s is paid again and again for a verdict already reached. That is not a
# theoretical cost -- these calls are made from the daemon's event-loop thread,
# so each one freezes the whole daemon for the deadline: the control listener
# still accepts TCP connections (the kernel does that), but nothing is ever
# read from them and every authenticated request times out against a daemon
# that looks perfectly healthy in its own log.
#
# So the verdict is remembered. It expires rather than latching forever,
# because "unresponsive" is a statement about a moment: a user who unlocks
# their Mac mid-session must get their real keychain back without restarting.
KEYCHAIN_UNRESPONSIVE_COOLDOWN_SECONDS = 300.0

_keychain_breaker_lock = threading.Lock()
_keychain_unresponsive_until = 0.0

# Where the state.db key was actually resolved from, for honest reporting.
_last_key_source: str | None = None


def _keychain_breaker_is_open() -> bool:
    """True while a recent timeout still speaks for this host."""
    with _keychain_breaker_lock:
        return time.monotonic() < _keychain_unresponsive_until


def _trip_keychain_breaker() -> None:
    global _keychain_unresponsive_until
    with _keychain_breaker_lock:
        _keychain_unresponsive_until = (
            time.monotonic() + KEYCHAIN_UNRESPONSIVE_COOLDOWN_SECONDS
        )


def reset_keychain_breaker() -> None:
    """Forget any recorded unresponsiveness (the backend just answered)."""
    global _keychain_unresponsive_until
    with _keychain_breaker_lock:
        _keychain_unresponsive_until = 0.0


def _bounded_keychain_call(operation, *args, **kwargs):
    """Run one keychain operation with a hard deadline.

    A thread that is blocked inside the OS keychain cannot be cancelled, so
    it is abandoned as a daemon thread rather than joined; the caller gets a
    typed backend error and proceeds to the local-key path.

    A host that has already blown the deadline is not asked again until the
    cooldown expires -- see ``KEYCHAIN_UNRESPONSIVE_COOLDOWN_SECONDS``.
    """

    if _keychain_breaker_is_open():
        raise KeychainUnresponsiveError(
            "OS keychain did not respond within "
            f"{KEYCHAIN_CALL_TIMEOUT_SECONDS:.0f}s on a recent call; not "
            "asking again for "
            f"{KEYCHAIN_UNRESPONSIVE_COOLDOWN_SECONDS:.0f}s and using the "
            "local key file"
        )

    outcome: dict[str, object] = {}

    def _run() -> None:
        try:
            outcome["value"] = operation(*args, **kwargs)
        except BaseException as exc:  # surfaced verbatim to the caller
            outcome["error"] = exc

    worker = threading.Thread(
        target=_run,
        name="one-link-keychain-call",
        daemon=True,
    )
    worker.start()
    worker.join(KEYCHAIN_CALL_TIMEOUT_SECONDS)
    if worker.is_alive():
        _trip_keychain_breaker()
        raise KeychainUnresponsiveError(
            "OS keychain did not respond within "
            f"{KEYCHAIN_CALL_TIMEOUT_SECONDS:.0f}s; treating the backend as "
            "unavailable and using the local key file"
        )
    # The backend answered -- even an error is an answer, and proves the host
    # is not the wedged one the breaker exists for.
    reset_keychain_breaker()
    error = outcome.get("error")
    if error is not None:
        raise error  # type: ignore[misc]
    return outcome.get("value")


def _keyring_has_no_backend(exc: Exception) -> bool:
    """True iff ``exc`` is keyring's typed no-functional-backend signal.

    ``NoKeyringError`` is the library's deliberate statement that this host
    has no credential store to ask at all (headless Linux without a Secret
    Service, locked-down service accounts). That is semantically identical
    to keyring not being installed — which already falls back to the private
    local key file — and is NOT a failed lookup on an existing store, so
    honoring it does not weaken the absence-is-unproven rule for every other
    exception.
    """
    # A deadline expiry on a side-effect-free lookup is the same statement:
    # this host has no credential store we can actually use.
    if isinstance(exc, KeychainUnresponsiveError):
        return True
    try:
        from keyring.errors import NoKeyringError  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover - keyring missing or broken
        return False
    return isinstance(exc, NoKeyringError)


def keychain_target(data_root=None) -> tuple[str, str]:
    """Per-profile ``(service, account)`` for the state.db authority.

    The credential store is machine-global while One Link profiles are
    per-data-dir, so a single shared entry makes every profile share one
    encryption authority — and makes two concurrent FIRST boots destroy
    each other.

    The scoping must be on the SERVICE, not the account: keyring's Windows
    backend keys one credential per service target and carries the username
    only as an attribute, so ``set_password`` is a read-modify-write on that
    shared target. Two writers that both observe an empty store then write
    in sequence leave exactly one survivor, with no compound copy of the
    loser — whose fail-closed read-back then finds a foreign username and
    refuses to start. Distinct service targets remove the shared cell
    entirely, on every backend.

    Reads fall back to the legacy shared entry so existing installs keep
    decrypting their state.
    """
    from pathlib import Path

    if data_root is None:
        from one_link.paths import data_dir

        data_root = data_dir()
    normalized = str(Path(data_root).resolve()).replace("\\", "/")
    if os.name == "nt":
        normalized = normalized.casefold()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{ONE_LINK_KEYCHAIN_SERVICE}:{digest}", ONE_LINK_KEYCHAIN_USER


def keychain_account(data_root=None) -> str:
    """Back-compat shim: the account half of :func:`keychain_target`."""
    return keychain_target(data_root)[1]


def _migrate_legacy_slot(kr, service: str, account: str, value: str) -> None:
    """Best-effort copy of a legacy-entry authority into the scoped entry.

    Never deletes the legacy entry: other profiles on this machine may
    still be reading it, and destroying a shared authority would orphan
    their encrypted state. A failed migration just means the next read
    falls back to the legacy entry again.
    """
    try:
        _bounded_keychain_call(kr.set_password, service, account, value)
    except Exception as exc:
        log.warning(
            "keychain: could not migrate the legacy shared authority to the "
            "per-profile slot (%s); continuing on the legacy slot",
            type(exc).__name__,
        )


# ── Local key-file fallback ───────────────────────────────────────────
# 2026-06-16 (external-audit remediation): the OS keychain is the
# PREFERRED home for the state.db key, but on headless Linux (no Secret
# Service / D-Bus), locked-down service accounts, or when keyring's
# backend write simply fails, it isn't available. Previously the daemon
# silently fell back to a PLAINTEXT state.db in that case — a direct
# breach of One Link's "your data is yours and protected" promise.
#
# Now, when the OS keychain can't hold the key, we mint one and store it
# in a 0600 key file inside the data dir so at-rest encryption STAYS ON
# by default. Honest about the trade-off: a key file next to the DB is
# weaker than the OS keychain against an attacker who already has read
# access to the data dir — but it is strictly stronger than plaintext
# (opaque DB to backup/cloud-sync scrapes, misconfigured shares,
# forensic free-page recovery, casual inspection) and, combined with
# OS full-disk encryption (FileVault/BitLocker), gives real protection
# on a lost/stolen device. Plaintext now requires an explicit opt-in
# (see state.py ONE_LINK_ALLOW_PLAINTEXT) instead of happening silently.

def _local_key_path():
    from one_link.paths import data_dir
    return data_dir() / LOCAL_KEY_FILENAME


def _harden_local_key(path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)
        return
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    current = os.stat(path, follow_symlinks=False)
    if stat.S_IMODE(current.st_mode) != 0o600:
        raise KeyMaterialIntegrityError(
            "local state encryption key is not owner-only"
        )
    get_euid = getattr(os, "geteuid", None)
    if get_euid is not None and int(current.st_uid) != int(get_euid()):
        raise KeyMaterialIntegrityError(
            "local state encryption key is not owned by the current user"
        )


def _decode_local_key(blob: bytes) -> str:
    if not blob:
        raise KeyMaterialIntegrityError("existing local state key is empty")
    if len(blob) > 4096:
        raise KeyMaterialIntegrityError("existing local state key is oversized")
    try:
        value = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KeyMaterialIntegrityError(
            "existing local state key is not valid UTF-8"
        ) from exc
    if not value or value != value.strip() or any(ord(ch) < 0x20 for ch in value):
        raise KeyMaterialIntegrityError(
            "existing local state key has an invalid encoding"
        )
    return value


def _read_local_key() -> str | None:
    # Provenance is recorded HERE rather than at each caller: three separate
    # paths return this value, and a per-caller marker would be a twin-copy
    # waiting for one of them to be forgotten.
    key = _read_local_key_at(_local_key_path())
    if key is not None:
        _record_key_source(_local_key_source_label())
    return key


def _read_local_key_at(path) -> str | None:
    blob = read_bytes_if_exists(
        path,
        label="local state encryption key",
        max_bytes=4096,
        harden_path=_harden_local_key,
    )
    if blob is None:
        return None
    return _decode_local_key(blob)


def _write_local_key(pw: str) -> bool:
    """Exclusively and durably publish the local fallback key.

    Existing bytes are never truncated or replaced.  A concurrent winner is
    accepted only when it contains the exact same authority.
    """
    return _write_local_key_at(_local_key_path(), pw)


def _write_local_key_at(path, pw: str) -> bool:
    if not isinstance(pw, str) or not pw or pw != pw.strip():
        raise ValueError("local state encryption key must be non-empty text")
    payload = pw.encode("utf-8")
    if len(payload) > 4096:
        raise ValueError("local state encryption key is too large")

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(_decode_local_key(blob), pw):
            raise KeyMaterialIntegrityError(
                "local state encryption key does not match requested authority"
            )

    try:
        p = path
        created = atomic_create_bytes(
            p,
            payload,
            label="local state encryption key",
            validate=_validate,
            harden_path=_harden_local_key,
        )
        if created:
            return True
        sync_existing_authority(p, label="local state encryption key")
        existing = _read_local_key_at(p)
        if existing is None:
            raise KeyMaterialPersistenceError(
                "concurrent local-key publication reported a winner but none exists"
            )
        if not secrets.compare_digest(existing, pw):
            raise KeyMaterialIntegrityError(
                "refusing to overwrite a different existing local state key"
            )
        return True
    except KeyMaterialIntegrityError:
        raise
    except Exception as e:
        log.warning("local key-file write failed: %s", type(e).__name__)
        return False


class contextlib_suppress:
    def __enter__(self): return self
    def __exit__(self, *a): return True


DISABLE_ENV = "ONE_LINK_DISABLE_AT_REST_ENCRYPTION"


def _disabled() -> bool:
    """At-rest encryption is explicitly disabled. Used by the test
    suite (conftest sets the flag) so thousands of throwaway State()
    objects don't each hit the global OS keychain — which would both
    pollute the user's real credential store AND exhaust keychain /
    file handles at scale. An explicit ONE_LINK_PASSPHRASE always
    wins over this flag (the dedicated at-rest-encryption test opts
    back in that way)."""
    return os.environ.get(DISABLE_ENV) == "1"


@contextlib.contextmanager
def _exclusive_provision(lock_path=None) -> Iterator[None]:
    """Serialize first-key publication across threads and processes."""

    with _provision_thread_lock:
        if lock_path is None:
            lock_path = _local_key_path().with_name(_PROVISION_LOCK_FILENAME)
        else:
            lock_path = os.fspath(lock_path)
            from pathlib import Path

            lock_path = Path(lock_path)
        try:
            lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(
                str(lock_path),
                os.O_RDWR | os.O_CREAT | int(getattr(os, "O_BINARY", 0)),
                0o600,
            )
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                "cannot open state-key provisioning lock"
            ) from exc
        try:
            if os.fstat(fd).st_size < 1:
                os.write(fd, b"\x00")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                flock = getattr(fcntl, "flock")
                lock_ex = int(getattr(fcntl, "LOCK_EX"))
                lock_un = int(getattr(fcntl, "LOCK_UN"))
                flock(fd, lock_ex)
                try:
                    yield
                finally:
                    flock(fd, lock_un)
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                "state-key provisioning lock failed"
            ) from exc
        finally:
            os.close(fd)


def _record_key_source(label: str) -> str:
    """Remember where the state key actually came from, and return it."""
    global _last_key_source
    with _keychain_breaker_lock:
        _last_key_source = label
    return label


def last_key_source_label() -> str | None:
    """Where the state.db key ACTUALLY came from, or None if not yet resolved.

    Distinct from :func:`backend_label`, which names the keyring backend
    *installed* on this host. The two disagree exactly when it matters most:
    on a Mac with a locked login keychain the installed backend is still
    "macOS Keychain" while the key is really in the local 0600 file, and the
    boot log then contradicted itself one line apart --

        keychain: no functional OS keychain backend on this host; minting
                  the state key in the private local key file.
        state.db: AES-256 at-rest encryption ACTIVE (key from macOS Keychain)

    An operator auditing WHERE their encryption key lives was told the wrong
    place. This reports the resolution that actually happened.
    """
    with _keychain_breaker_lock:
        return _last_key_source


def _local_key_source_label() -> str:
    return f"local key file ({LOCAL_KEY_FILENAME})"


def get_passphrase() -> str | None:
    """Return authority, or ``None`` only when every store proves absence."""
    from one_link.passphrase_source import adopt_passphrase_file

    adopt_passphrase_file()
    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        _record_key_source(f"{ENV_VAR} environment override")
        return env
    if _disabled():
        # Don't even read the keychain — keep tests fully isolated
        # from the user's real credential store.
        return None
    kr = _load_keyring()
    if kr is not None:
        try:
            service, account = keychain_target()
            v = _bounded_keychain_call(kr.get_password, service, account)
            from_legacy = False
            if v is None:
                v = _bounded_keychain_call(kr.get_password, 
                    ONE_LINK_KEYCHAIN_SERVICE, _LEGACY_KEYCHAIN_ACCOUNT
                )
                from_legacy = v is not None
            if v is not None:
                if not isinstance(v, str) or not v:
                    raise KeyMaterialIntegrityError(
                        "existing OS keychain state key is empty or invalid"
                    )
                local = _read_local_key()
                if local is not None and not secrets.compare_digest(local, v):
                    raise KeyMaterialIntegrityError(
                        "OS keychain and local state-key authorities conflict"
                    )
                if from_legacy:
                    _migrate_legacy_slot(kr, service, account, v)
                _record_key_source(backend_label())
                return v
        except Exception as e:
            if isinstance(e, KeyMaterialIntegrityError):
                raise
            if _keyring_has_no_backend(e):
                log.info(
                    "keychain: no functional OS keychain backend on this "
                    "host; the private local key file is the authority "
                    "channel (at-rest encryption stays on)."
                )
                return _read_local_key()
            raise KeychainBackendError(
                "OS keychain lookup failed; authority absence is unproven"
            ) from e
    # Local key-file fallback (minted by ensure_passphrase when the OS
    # keychain is unavailable). Keeps at-rest encryption on across
    # restarts even where no OS keychain exists.
    return _read_local_key()


def _recovery_artifact_path(data_root):
    from pathlib import Path

    return Path(data_root) / RECOVERY_KEY_FILENAME


def _harden_recovery_artifact(path) -> None:
    """Apply the same private-file contract to the sealed recovery key."""

    _harden_local_key(path)


def _derive_recovery_wrapping_key(seed: bytes) -> bytes:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_RECOVERY_KEY_INFO,
    ).derive(bytes(seed))


def seal_state_passphrase_for_recovery(*, seed: bytes, passphrase: str) -> bytes:
    """Return a versioned, seed-wrapped SQLCipher authority artifact.

    The returned bytes are safe to place in an authenticated backup archive;
    the database passphrase never appears in plaintext in that archive.  A
    separate HKDF domain keeps this wrapping key independent from the outer
    ``.olbak`` key, identity key, DRK, and runtime SQLCipher authority.
    """

    if not isinstance(passphrase, str):
        raise TypeError("state database passphrase must be text")
    payload = passphrase.encode("utf-8")
    _decode_local_key(payload)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(RECOVERY_KEY_NONCE_LEN)
    ciphertext = AESGCM(_derive_recovery_wrapping_key(seed)).encrypt(
        nonce,
        payload,
        RECOVERY_KEY_MAGIC,
    )
    artifact = RECOVERY_KEY_MAGIC + nonce + ciphertext
    if len(artifact) > RECOVERY_KEY_MAX_BYTES:
        raise ValueError("sealed state database recovery key exceeds its size limit")
    return artifact


def unseal_state_passphrase_for_recovery(*, seed: bytes, artifact: bytes) -> str:
    """Authenticate, decrypt, and strictly validate a recovery artifact."""

    if not isinstance(artifact, bytes):
        raise KeyMaterialIntegrityError(
            "state database recovery key artifact must be bytes"
        )
    minimum = len(RECOVERY_KEY_MAGIC) + RECOVERY_KEY_NONCE_LEN + 17
    if len(artifact) < minimum or len(artifact) > RECOVERY_KEY_MAX_BYTES:
        raise KeyMaterialIntegrityError(
            "state database recovery key artifact has an invalid length"
        )
    if not secrets.compare_digest(
        artifact[:len(RECOVERY_KEY_MAGIC)], RECOVERY_KEY_MAGIC
    ):
        raise KeyMaterialIntegrityError(
            "state database recovery key artifact has an unsupported format"
        )
    offset = len(RECOVERY_KEY_MAGIC)
    nonce = artifact[offset:offset + RECOVERY_KEY_NONCE_LEN]
    ciphertext = artifact[offset + RECOVERY_KEY_NONCE_LEN:]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        payload = AESGCM(_derive_recovery_wrapping_key(seed)).decrypt(
            nonce,
            ciphertext,
            RECOVERY_KEY_MAGIC,
        )
    except Exception as exc:
        raise KeyMaterialIntegrityError(
            "state database recovery key authentication failed"
        ) from exc
    try:
        return _decode_local_key(payload)
    finally:
        # Python bytes cannot be reliably zeroized, but keep their lifetime
        # bounded and never include them in logs or exception messages.
        payload = b"\x00" * len(payload)


def _configured_passphrase_at(data_root) -> str | None:
    """Read env/keyring/local authority for one recovery target."""

    from pathlib import Path

    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        return env
    if _disabled():
        return None
    local_path = Path(data_root) / LOCAL_KEY_FILENAME
    kr = _load_keyring()
    if kr is not None:
        try:
            value = _bounded_keychain_call(kr.get_password, *keychain_target(data_root))
            if value is None:
                value = _bounded_keychain_call(kr.get_password, 
                    ONE_LINK_KEYCHAIN_SERVICE,
                    _LEGACY_KEYCHAIN_ACCOUNT,
                )
        except Exception as exc:
            if _keyring_has_no_backend(exc):
                return _read_local_key_at(local_path)
            raise KeychainBackendError(
                "OS keychain lookup failed during database recovery"
            ) from exc
        if value is not None:
            if not isinstance(value, str) or not value:
                raise KeyMaterialIntegrityError(
                    "existing OS keychain state key is empty or invalid"
                )
            local = _read_local_key_at(local_path)
            if local is not None and not secrets.compare_digest(local, value):
                raise KeyMaterialIntegrityError(
                    "OS keychain and local state-key authorities conflict"
                )
            return value
    return _read_local_key_at(local_path)


def _publish_recovered_passphrase(data_root, passphrase: str) -> str:
    """Publish an exact recovered authority, never a replacement random key."""

    from pathlib import Path

    root = Path(data_root)
    local_path = root / LOCAL_KEY_FILENAME
    lock_path = root / _PROVISION_LOCK_FILENAME
    with _exclusive_provision(lock_path):
        winner = _configured_passphrase_at(root)
        if winner is not None:
            return winner
        kr = _load_keyring()
        if kr is not None:
            service, account = keychain_target(root)
            try:
                _bounded_keychain_call(kr.set_password, 
                    service,
                    account,
                    passphrase,
                )
            except Exception as write_exc:
                if _keyring_has_no_backend(write_exc):
                    log.info(
                        "keychain: no functional OS keychain backend; the "
                        "recovered authority goes to the private local file."
                    )
                else:
                    try:
                        after = _bounded_keychain_call(kr.get_password, service, account)
                    except Exception as read_exc:
                        raise KeychainBackendError(
                            "OS keychain recovery-key write outcome is unknown"
                        ) from read_exc
                    if after is not None:
                        if not isinstance(after, str) or not after:
                            raise KeyMaterialIntegrityError(
                                "OS keychain returned invalid recovery authority"
                            )
                        return after
                    log.warning(
                        "keychain recovery write failed (%s) and absence was "
                        "re-confirmed; using the private local fallback",
                        type(write_exc).__name__,
                    )
            else:
                try:
                    after = _bounded_keychain_call(kr.get_password, service, account)
                except Exception as exc:
                    raise KeychainBackendError(
                        "OS keychain recovery-key write could not be read back"
                    ) from exc
                if not isinstance(after, str) or not secrets.compare_digest(
                    after,
                    passphrase,
                ):
                    raise KeyMaterialIntegrityError(
                        "OS keychain recovery-key read-back did not match"
                    )
                return after
        if not _write_local_key_at(local_path, passphrase):
            raise KeyMaterialPersistenceError(
                "could not persist the recovered state database authority"
            )
        winner = _read_local_key_at(local_path)
        if winner is None or not secrets.compare_digest(winner, passphrase):
            raise KeyMaterialPersistenceError(
                "recovered local state database authority failed read-back"
            )
        return winner


def _retire_recovery_artifact(data_root, expected: bytes) -> None:
    from pathlib import Path

    path = _recovery_artifact_path(data_root)
    current = read_bytes_if_exists(
        path,
        label="sealed state database recovery key",
        max_bytes=RECOVERY_KEY_MAX_BYTES,
        harden_path=_harden_recovery_artifact,
    )
    if current is None or not secrets.compare_digest(current, expected):
        raise KeyMaterialAccessError(
            "sealed state database recovery key changed before retirement"
        )
    try:
        path.unlink()
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            "could not retire the consumed state database recovery key"
        ) from exc
    if os.name != "nt":
        flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
        fd = os.open(str(Path(data_root)), flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def adopt_recovery_passphrase_for_database(db_path) -> bool:
    """Converge a restored DB on this machine's runtime key authority.

    No artifact means a fast ``False`` return.  When present, the master seed
    authenticates and unwraps the source SQLCipher key.  A fresh target stores
    that exact key in its OS keyring/private local fallback.  A target with an
    explicit ``ONE_LINK_PASSPHRASE`` or an existing keyring/local authority is
    honored by atomically re-encrypting the restored database to that key.

    The artifact is retired only after the final database is independently
    readable.  If power fails after the atomic rekey but before retirement,
    the next call detects that the target key already opens the database and
    completes idempotently.
    """

    from pathlib import Path

    path = Path(db_path).resolve()
    root = path.parent
    artifact = read_bytes_if_exists(
        _recovery_artifact_path(root),
        label="sealed state database recovery key",
        max_bytes=RECOVERY_KEY_MAX_BYTES,
        harden_path=_harden_recovery_artifact,
    )
    if artifact is None:
        return False
    if not path.is_file():
        raise KeyMaterialIntegrityError(
            "sealed state database recovery key exists without state.db"
        )
    from one_link import master_seed, state_encryption

    seed = master_seed.load_seed(root)
    if seed is None:
        raise KeyMaterialIntegrityError(
            "sealed state database recovery key exists without a master seed"
        )
    recovered = unseal_state_passphrase_for_recovery(
        seed=seed,
        artifact=artifact,
    )
    configured = _configured_passphrase_at(root)
    if configured is None:
        if _disabled():
            raise KeyMaterialProtectionError(
                "encrypted database recovery is incompatible with explicitly "
                "disabled at-rest encryption"
            )
        configured = _publish_recovered_passphrase(root, recovered)

    if secrets.compare_digest(configured, recovered):
        if not state_encryption.database_accepts_passphrase(path, recovered):
            raise KeyMaterialIntegrityError(
                "restored state database does not match its sealed recovery key"
            )
    elif state_encryption.database_accepts_passphrase(path, recovered):
        state_encryption.replace_encrypted_database_key_atomic(
            db_path=path,
            source_passphrase=recovered,
            destination_passphrase=configured,
        )
    elif not state_encryption.database_accepts_passphrase(path, configured):
        raise KeyMaterialIntegrityError(
            "restored state database matches neither recovery nor configured authority"
        )
    _retire_recovery_artifact(root, artifact)
    return True


def ensure_passphrase() -> str | None:
    """Get the passphrase or auto-mint and durably store one.

    Returns ``None`` only when key management is explicitly disabled or no
    secure key destination is usable.  The state layer treats that result as
    a fail-closed condition unless legacy plaintext mode was explicitly
    authorized by the operator.

    A fresh passphrase is 32 random bytes encoded as url-safe-base64.
    256 bits of entropy comfortably exceeds AES-256's key strength."""
    existing = get_passphrase()
    if existing is not None:
        return existing
    if _disabled():
        # Explicitly disabled (isolated tests / recovery tooling): never mint
        # or touch a real credential. The state layer decides whether an
        # explicit plaintext opt-in permits continuing.
        return None
    with _exclusive_provision():
        # Re-check under the process-wide lock.  This closes the ordinary
        # check-then-create race for both the OS backend and local fallback.
        existing = get_passphrase()
        if existing is not None:
            return existing
        new_pw = secrets.token_urlsafe(32)
        kr = _load_keyring()
        if kr is not None:
            service, account = keychain_target()
            try:
                _bounded_keychain_call(kr.set_password, 
                    service, account, new_pw,
                )
            except Exception as write_exc:
                if _keyring_has_no_backend(write_exc):
                    # Typed no-backend signal: there is no store the write
                    # could have partially landed in, so local creation is
                    # the designed channel, not a guess.
                    log.info(
                        "keychain: no functional OS keychain backend on "
                        "this host; minting the state key in the private "
                        "local key file."
                    )
                else:
                    # Some backends can commit and then report an error.
                    # Prove the postcondition before deciding whether local
                    # creation is safe; a failed lookup is not absence.
                    try:
                        after = _bounded_keychain_call(kr.get_password, service, account)
                    except Exception as read_exc:
                        raise KeychainBackendError(
                            "OS keychain write outcome is unknown; refusing fallback creation"
                        ) from read_exc
                    if after is not None:
                        if not isinstance(after, str) or not after:
                            raise KeyMaterialIntegrityError(
                                "OS keychain returned invalid authority after a write failure"
                            )
                        if secrets.compare_digest(after, new_pw):
                            return new_pw
                        # Another authority appeared; never overwrite it and
                        # use the proven backend winner.
                        return after
                    log.warning(
                        "keychain write failed (%s) and absence was "
                        "re-confirmed; using the private local fallback",
                        type(write_exc).__name__,
                    )
            else:
                try:
                    after = _bounded_keychain_call(kr.get_password, service, account)
                except Exception as exc:
                    raise KeychainBackendError(
                        "OS keychain write could not be read back"
                    ) from exc
                if not isinstance(after, str) or not secrets.compare_digest(
                    after, new_pw
                ):
                    raise KeyMaterialIntegrityError(
                        "OS keychain read-back did not match generated authority"
                    )
                log.info(
                    "keychain: minted fresh state.db encryption key; stored "
                    "in the OS credential store and read back successfully."
                )
                _record_key_source(backend_label())
                return new_pw
        else:
            log.warning(
                "keyring library/back end unavailable; using the local 0600 "
                "key file so at-rest encryption stays ON"
            )
        # OS keychain absent or confirmed not to have committed the failed
        # write.  Local publication is fsynced, no-replace, ACL-verified, and
        # read back before the key is returned.
        if _write_local_key(new_pw):
            log.info(
                "keychain: minted fresh state.db encryption key; stored in a "
                "0600 local key file (%s). at-rest encryption ACTIVE.",
                LOCAL_KEY_FILENAME,
            )
            _record_key_source(_local_key_source_label())
            return new_pw
    # Could not obtain or persist a key anywhere. Returning None signals
    # the caller; state.py refuses to silently run plaintext unless the
    # operator explicitly sets ONE_LINK_ALLOW_PLAINTEXT=1.
    log.error(
        "could not store a state.db encryption key in the OS keychain "
        "OR a local key file — at-rest encryption cannot be enabled"
    )
    return None


def rotate_passphrase() -> str | None:
    """Generate a brand-new passphrase + write it to the keychain.
    Used by the 'Forget passphrase' button. Caller is responsible
    for re-encrypting state.db with the new key in the SAME write
    transaction; otherwise the old DB becomes unreadable.

    Returns the new passphrase, or None if the keychain refused
    the write."""
    if os.environ.get(ENV_VAR, "").strip():
        raise KeyMaterialIntegrityError(
            "cannot rotate OS keychain authority while an environment override is active"
        )
    with _exclusive_provision():
        kr = _load_keyring()
        if kr is None:
            return None
        service, account = keychain_target()
        try:
            prior = _bounded_keychain_call(kr.get_password, service, account)
            if prior is None:
                # A not-yet-migrated install still holds its authority in the
                # legacy shared slot; the rotated key goes to the scoped slot
                # (reads prefer it), and the legacy slot is left untouched
                # because other profiles may still depend on it.
                prior = _bounded_keychain_call(kr.get_password, 
                    ONE_LINK_KEYCHAIN_SERVICE, _LEGACY_KEYCHAIN_ACCOUNT
                )
        except Exception as exc:
            raise KeychainBackendError(
                "cannot read OS keychain authority before rotation"
            ) from exc
        if prior is None:
            return None
        if not isinstance(prior, str) or not prior:
            raise KeyMaterialIntegrityError(
                "cannot rotate an invalid OS keychain authority"
            )
        new_pw = secrets.token_urlsafe(32)
        try:
            _bounded_keychain_call(kr.set_password, 
                service, account, new_pw,
            )
        except Exception as write_exc:
            try:
                after = _bounded_keychain_call(kr.get_password, service, account)
            except Exception as read_exc:
                raise KeychainBackendError(
                    "OS keychain rotation outcome is unknown"
                ) from read_exc
            if isinstance(after, str) and secrets.compare_digest(after, new_pw):
                return new_pw
            if after is None or (
                isinstance(after, str) and secrets.compare_digest(after, prior)
            ):
                log.warning("keychain rotate failed: %s", type(write_exc).__name__)
                return None
            raise KeyMaterialIntegrityError(
                "OS keychain rotation produced unknown authority"
            ) from write_exc
        try:
            after = _bounded_keychain_call(kr.get_password, service, account)
        except Exception as exc:
            raise KeychainBackendError(
                "OS keychain rotation could not be read back"
            ) from exc
        if not isinstance(after, str) or not secrets.compare_digest(after, new_pw):
            raise KeyMaterialIntegrityError(
                "OS keychain rotation read-back did not match"
            )
        return new_pw


def forget_passphrase() -> bool:
    """Delete the key from BOTH the OS keychain AND the local key file.
    Caller should have already decrypted-then-deleted state.db, or the
    user is permanently locked out of the existing DB. Returns True iff
    a key was actually removed from either store."""
    removed = False
    # Local key file (secure-overwrite before unlink so the key bytes
    # don't linger in free space).
    try:
        p = _local_key_path()
        if p.exists():
            try:
                size = p.stat().st_size
                with open(p, "r+b") as fh:
                    fh.write(secrets.token_bytes(max(32, size)))
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception as e:
                # Secure overwrite is best-effort on journaling filesystems
                # and SSDs, but a failure is still security-relevant. Keep
                # the requested unlink while making weaker erasure visible.
                log.warning(
                    "local key-file secure overwrite failed before unlink: %s",
                    type(e).__name__,
                )
            p.unlink()
            removed = True
    except Exception as e:
        log.warning("local key-file delete failed: %s", type(e).__name__)
    kr = _load_keyring()
    if kr is None:
        return removed
    # Delete the per-profile slot AND the legacy shared slot: pre-scoping,
    # every profile shared the legacy entry, so leaving it behind would let
    # get_passphrase silently resurrect the "forgotten" key. Post-scoping
    # profiles have their own slots and are unaffected by the legacy delete.
    for slot in (
        keychain_target(),
        (ONE_LINK_KEYCHAIN_SERVICE, _LEGACY_KEYCHAIN_ACCOUNT),
    ):
        try:
            _bounded_keychain_call(kr.delete_password, *slot)
            removed = True
        except Exception as e:
            # Most backends raise PasswordDeleteError on "not found";
            # treat that as "nothing to do" rather than failure.
            if type(e).__name__ not in (
                "PasswordDeleteError", "PasswordError",
                "KeyringError", "NoKeyringError",
            ):
                log.warning("keychain delete failed: %s", type(e).__name__)
    return removed


def backend_label() -> str:
    """Human-readable identifier for the active keychain backend,
    used in Settings + the boot log so the user can see WHERE their
    key lives ('Windows Credential Manager', 'macOS Keychain', etc).
    Returns 'unavailable' if the keyring library isn't loaded."""
    kr = _load_keyring()
    if kr is None:
        return "unavailable (keyring library not installed)"
    try:
        cls = type(kr.get_keyring()).__name__
    except Exception:
        return "unavailable (no usable backend)"
    return {
        "WinVaultKeyring": "Windows Credential Manager",
        "Keyring": "macOS Keychain",
        "SecretServiceKeyring": "Linux Secret Service",
        "KWallet5Keyring": "KDE KWallet",
        "GnomeKeyring": "GNOME Keyring",
        "Fail": "unavailable",
        "Null": "disabled",
    }.get(cls, cls)
