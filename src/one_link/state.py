"""Persistent state layer.

A single sqlite database under ONE_LINK_HOME/data/state.db backs:

- peers (fingerprint, trust state, last seen)
- messages (full chat history with FTS5 full-text search)
- rooms (multi-party named conversations)
- folders (designated sync folders)
- folder_manifest (CRDT — file_path → blob_hash with vector clocks)
- folder_pending_applies (crash-replay journal for materialize/delete)
- blobs (content-addressed blob index)

Concurrency model: a single shared `sqlite3.Connection` with
`check_same_thread=False` and `journal_mode=WAL`, guarded by a re-entrant
threading lock for writes. Reads can race; writes serialize.

Schema migrations are versioned in a `schema_version` table; applying one
migration at a time is idempotent.
"""

from __future__ import annotations

import hashlib
import json
import contextlib
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid

# v0.21.x at-rest encryption: when the DB is opened via SQLCipher
# (sqlcipher3), runtime errors are raised as ``sqlcipher3.dbapi2.*``
# which are a SEPARATE exception hierarchy from stdlib ``sqlite3.*``.
# Any ``except sqlite3.Error`` / ``suppress(sqlite3.OperationalError)``
# in this module would silently STOP catching DB errors on an
# encrypted connection, letting them propagate (e.g. a DELETE on a
# non-existent table that was previously swallowed). Build tuples
# that span BOTH hierarchies so the defensive catches keep working
# regardless of which backend opened the connection.
try:  # pragma: no cover - depends on install
    import sqlcipher3.dbapi2 as _sqlcipher_dbapi2

    DB_ERRORS: tuple = (sqlite3.Error, _sqlcipher_dbapi2.Error)
    DB_OPERATIONAL_ERRORS: tuple = (
        sqlite3.OperationalError, _sqlcipher_dbapi2.OperationalError,
    )
    DB_INTEGRITY_ERRORS: tuple = (
        sqlite3.IntegrityError, _sqlcipher_dbapi2.IntegrityError,
    )
except Exception:  # sqlcipher3 not installed → stdlib only
    DB_ERRORS = (sqlite3.Error,)
    DB_OPERATIONAL_ERRORS = (sqlite3.OperationalError,)
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)
from typing import Any, Iterable, Mapping, Optional

from one_link.paths import data_dir

DB_FILE = "state.db"


# ─── key-protected State fields: the one registry ────────────────────────────
#
# Every State column (or JSON member of a column) whose stored bytes depend on
# a key the install can rotate is listed here, with the key family it depends
# on.  Writers seal and readers open these values only through
# ``State._seal_field`` / ``State._open_field``, and identity rotation /
# recovery re-keys exactly this set (``State.rekey_protected_fields``) inside
# the same crash-replayable transaction that carries the whole-file LockBox
# envelopes.  ``tests/test_rotation_state_field_carry.py`` holds the registry
# complete: a static census of every seal/open primitive call in this module
# and a dynamic census of every cell the real writers leave in the database.

# The install's application data key (a LockBox): the silent DRK, which is
# derive_drk(seed) and so changes with the seed, or a passphrase envelope's
# stable DEK, which does not.
FIELD_FAMILY_DATA_KEY = "data_key"
# Deterministic AES-SIV under derive_path_pii_key(seed) (audit M30): changes
# with every seed change, in both LockBox modes.
FIELD_FAMILY_PATH_PII = "path_pii"


@dataclass(frozen=True)
class KeyProtectedField:
    name: str
    table: str
    column: str
    family: str
    label: str
    # Literal statements keep identifier selection in this reviewed registry.
    # Row cursors, replacement values and row IDs are always bound parameters.
    rekey_select_sql: str
    rekey_update_sql: str
    json_key: str = ""
    aad: bytes = b""
    plaintext_len: int = 32

    def __post_init__(self) -> None:
        # `table` and `column` name the cells the literal statements above
        # act on; the schema-presence check and the registry tests use them
        # as identifiers. They are restricted, at construction, to plain
        # lowercase ASCII identifiers, so no quoting, whitespace, punctuation
        # or statement text can ride in on one, whoever adds a field later.
        for role, identifier in (("table", self.table), ("column", self.column)):
            if not (
                identifier.isascii()
                and identifier.isidentifier()
                and identifier == identifier.lower()
            ):
                raise ValueError(
                    f"key-protected field {self.name!r}: {role} {identifier!r} is not a plain SQL identifier"
                )
        if self.family not in (FIELD_FAMILY_DATA_KEY, FIELD_FAMILY_PATH_PII):
            raise ValueError(f"key-protected field {self.name!r}: unknown key family {self.family!r}")


GROUP_SENDER_CHAIN_KEY = KeyProtectedField(
    "group_sender_chains.chain_key", "group_sender_chains", "chain_key",
    FIELD_FAMILY_DATA_KEY, label="chain_key",
    rekey_select_sql=(
        "SELECT rowid, chain_key FROM group_sender_chains "
        "WHERE rowid > ? AND chain_key IS NOT NULL ORDER BY rowid LIMIT 512"
    ),
    rekey_update_sql="UPDATE OR REPLACE group_sender_chains SET chain_key = ? WHERE rowid = ?",
)
SELF_MESH_ROOT_SEED = KeyProtectedField(
    "self_mesh_roots.root_seed", "self_mesh_roots", "root_seed",
    FIELD_FAMILY_DATA_KEY, label="self-mesh root seed",
    rekey_select_sql=(
        "SELECT rowid, root_seed FROM self_mesh_roots "
        "WHERE rowid > ? AND root_seed IS NOT NULL ORDER BY rowid LIMIT 512"
    ),
    rekey_update_sql="UPDATE OR REPLACE self_mesh_roots SET root_seed = ? WHERE rowid = ?",
)
TRANSFER_SOURCE_PATH = KeyProtectedField(
    "transfers.metadata_json.path", "transfers", "metadata_json",
    FIELD_FAMILY_PATH_PII, label="transfer source path",
    rekey_select_sql=(
        "SELECT rowid, metadata_json FROM transfers "
        "WHERE rowid > ? AND metadata_json IS NOT NULL ORDER BY rowid LIMIT 512"
    ),
    rekey_update_sql="UPDATE OR REPLACE transfers SET metadata_json = ? WHERE rowid = ?",
    json_key="path", aad=b"OL/state/transfers/path|v1",
)
CHUNK_SOURCE_PATH = KeyProtectedField(
    "chunk_sources.path", "chunk_sources", "path",
    FIELD_FAMILY_PATH_PII, label="chunk source path",
    rekey_select_sql=(
        "SELECT rowid, path FROM chunk_sources "
        "WHERE rowid > ? AND path IS NOT NULL ORDER BY rowid LIMIT 512"
    ),
    rekey_update_sql="UPDATE OR REPLACE chunk_sources SET path = ? WHERE rowid = ?",
    aad=b"OL/state/chunk_sources/path|v1",
)
FILE_INDEX_PATH = KeyProtectedField(
    "file_index_cache.path", "file_index_cache", "path",
    FIELD_FAMILY_PATH_PII, label="file index path",
    rekey_select_sql=(
        "SELECT rowid, path FROM file_index_cache "
        "WHERE rowid > ? AND path IS NOT NULL ORDER BY rowid LIMIT 512"
    ),
    rekey_update_sql="UPDATE OR REPLACE file_index_cache SET path = ? WHERE rowid = ?",
    aad=b"OL/state/file_index_cache/path|v1",
)
KEY_PROTECTED_FIELDS: tuple[KeyProtectedField, ...] = (
    GROUP_SENDER_CHAIN_KEY,
    SELF_MESH_ROOT_SEED,
    TRANSFER_SOURCE_PATH,
    CHUNK_SOURCE_PATH,
    FILE_INDEX_PATH,
)


def carry_key_protected_fields(
    data_dir: Path,
    *,
    previous_data_key: Optional[bytes],
    target_data_key: bytes,
    previous_seed: Optional[bytes],
    target_seed: bytes,
) -> dict[str, dict[str, int]]:
    """Re-key every registered field of ``data_dir``'s state.db, if needed.

    Called by a confirmed seed/authority replacement before either key is
    published.  Opens State only when a key actually changes and the
    database exists; the daemon opens it the same way moments later.
    """
    if not isinstance(target_seed, (bytes, bytearray)) or len(target_seed) != 32:
        raise ValueError("target_seed must be 32 bytes")
    db_path = Path(data_dir) / DB_FILE
    data_key_changes = previous_data_key is not None and not secrets.compare_digest(
        bytes(previous_data_key), bytes(target_data_key)
    )
    path_key_changes = previous_seed is not None and not secrets.compare_digest(
        bytes(previous_seed), bytes(target_seed)
    )
    if not (data_key_changes or path_key_changes) or not db_path.exists():
        return {}
    try:
        state = State(db_path=db_path)
    except Exception as exc:
        # Publishing the new key without re-keying would orphan every sealed
        # value the moment this database becomes readable again (a locked
        # keychain at boot, for example).  The transaction stays pending and
        # replays at the next boot instead.
        from one_link.key_material import KeyMaterialProtectionError

        raise KeyMaterialProtectionError(
            "state.db cannot be opened to re-key its protected fields, so the "
            "key replacement stays pending until it can: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    try:
        return state.rekey_protected_fields(
            previous_data_key=previous_data_key if data_key_changes else None,
            target_data_key=bytes(target_data_key),
            previous_seed=previous_seed if path_key_changes else None,
            target_seed=bytes(target_seed),
        )
    finally:
        state.close()


def rekey_field_rows(
    conn: Any,
    *,
    previous_data_key: Optional[bytes],
    target_data_key: bytes,
    previous_seed: Optional[bytes],
    target_seed: bytes,
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Classify and re-key every ``KEY_PROTECTED_FIELDS`` value on ``conn``.

    The caller owns the transaction (``State.rekey_protected_fields`` uses
    its durable write transaction; the offline data-key migration opens its
    own).  Semantics are documented on ``State.rekey_protected_fields``.
    ``dry_run`` classifies without writing: ``rekeyed`` then counts the
    values that WOULD be re-sealed.  Verifying that every value opens under
    one key K is a dry run with previous == target == K: anything that is
    not ``current`` is ``unopenable``.
    """
    from one_link.lockbox import LockBox, LockBoxError, MIN_WRAPPED_LEN
    from one_link.path_pii import PATH_PII_MARKER, PathPIIEncryptor

    target_box = LockBox(bytes(target_data_key))
    previous_box = (
        LockBox(bytes(previous_data_key)) if previous_data_key is not None else None
    )
    target_paths = PathPIIEncryptor(bytes(target_seed))
    previous_paths = (
        PathPIIEncryptor(bytes(previous_seed)) if previous_seed is not None else None
    )

    def _opens(box, blob: bytes) -> bool:
        try:
            box.unwrap(blob)
        except LockBoxError:
            return False
        return True

    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    report: dict[str, dict[str, int]] = {}
    for field in KEY_PROTECTED_FIELDS:
        counts = {"rekeyed": 0, "current": 0, "unopenable": 0}
        report[field.name] = counts
        # Path-PII ciphertext is deterministic: every chunk row of one
        # file stores the same value, so classify each distinct value
        # once: stored value -> ("current" | "unopenable", None) or
        # ("rekey", resealed value).
        path_verdicts: dict[str, tuple[str, Optional[str]]] = {}
        if field.table not in tables:
            continue  # an older schema without this table holds no such value
        if field.family == FIELD_FAMILY_DATA_KEY and previous_box is None:
            continue
        if field.family == FIELD_FAMILY_PATH_PII and previous_paths is None:
            continue
        # Exactly one previous key applies to this field's family and
        # the guards above guarantee it is present. Bind it once, as a
        # non-optional name, so a missing key can never be mistaken for
        # an undecryptable row further down.
        field_previous_box = previous_box if field.family == FIELD_FAMILY_DATA_KEY else None
        field_previous_paths = previous_paths if field.family != FIELD_FAMILY_DATA_KEY else None
        # The statements are literals of the reviewed registry entry, never
        # composed here; cursor, replacement value and row id are bound.
        select_page = field.rekey_select_sql
        update_row = field.rekey_update_sql
        last_rowid = 0
        while True:
            rows = conn.execute(select_page, (last_rowid,)).fetchall()
            if not rows:
                break
            for rowid, stored in rows:
                last_rowid = int(rowid)
                if field.family == FIELD_FAMILY_DATA_KEY:
                    blob = bytes(stored)
                    if len(blob) != field.plaintext_len + MIN_WRAPPED_LEN:
                        continue  # legacy cleartext: keyless
                    if _opens(target_box, blob):
                        counts["current"] += 1
                        continue
                    if field_previous_box is None:
                        raise RuntimeError(
                            f"re-key of {field.name} reached without its previous data key"
                        )
                    try:
                        plaintext = field_previous_box.unwrap(blob)
                    except LockBoxError:
                        counts["unopenable"] += 1
                        continue
                    sealed: Any = target_box.wrap(plaintext)
                else:
                    document: Any = None
                    if field.json_key:
                        try:
                            document = json.loads(stored)
                        except (TypeError, ValueError):
                            continue
                        if not isinstance(document, dict):
                            continue
                        value = document.get(field.json_key)
                    else:
                        value = stored
                    if not isinstance(value, str) or not value.startswith(
                        PATH_PII_MARKER
                    ):
                        continue  # legacy cleartext: keyless
                    verdict = path_verdicts.get(value)
                    if verdict is None:
                        if target_paths.unwrap(value, aad=field.aad) is not None:
                            verdict = ("current", None)
                        else:
                            if field_previous_paths is None:
                                raise RuntimeError(
                                    f"re-key of {field.name} reached without its previous path key"
                                )
                            plaintext_path = field_previous_paths.unwrap(
                                value, aad=field.aad,
                            )
                            verdict = (
                                ("unopenable", None)
                                if plaintext_path is None
                                else (
                                    "rekey",
                                    target_paths.wrap(plaintext_path, aad=field.aad),
                                )
                            )
                        path_verdicts[value] = verdict
                    if verdict[0] != "rekey":
                        counts[verdict[0]] += 1
                        continue
                    resealed = verdict[1]
                    if document is not None:
                        document[field.json_key] = resealed
                        sealed = json.dumps(
                            document, separators=(",", ":"), sort_keys=True,
                        )
                    else:
                        sealed = resealed
                # OR REPLACE: a deterministic path ciphertext can be a
                # key column (chunk_sources, file_index_cache); if the
                # same plaintext path already has a current-key row,
                # the two rows describe one path and one survives.
                if not dry_run:
                    conn.execute(update_row, (sealed, rowid))
                counts["rekeyed"] += 1
    return report


def open_offline_state_connection(
    db_path: Path, database_keys: Iterable[Optional[str]],
) -> tuple[Any, Optional[str]]:
    """Open an OFFLINE state.db with the first database key that authenticates.

    Returns ``(connection, key)``; ``key`` is ``None`` for a plaintext file.
    Never State(): that picks its SQLCipher key from the environment and may
    encrypt a plaintext file as a side effect.  The caller holds the daemon
    instance lock, so no other connection is open.
    """
    from one_link import state_encryption
    from one_link.key_material import KeyMaterialProtectionError

    kind = state_encryption.detect_db_state(Path(db_path))
    if kind == "plaintext":
        return sqlite3.connect(str(db_path), isolation_level=None), None
    if kind != "encrypted":
        raise KeyMaterialProtectionError(f"state.db is {kind}; nothing can be re-keyed in it")
    for key in database_keys:
        if not key:
            continue
        try:
            return state_encryption.open_encrypted_connection(Path(db_path), key), key
        except Exception:  # nosec B112 - wrong key: authentication is the classifier
            continue
    raise KeyMaterialProtectionError(
        "state.db opens with none of the database keys this migration holds"
    )


def rekey_offline_state_fields(
    db_path: Path,
    *,
    database_keys: Iterable[Optional[str]],
    previous_data_key: bytes,
    target_data_key: bytes,
    seed: bytes,
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Re-key (or, with ``dry_run``, classify) an offline state.db's data-key fields.

    One FULL-synchronous transaction: all of it or none of it.  Path-PII
    fields are keyed by the seed, which a data-key migration does not change,
    so they are not touched.  A missing state.db holds no field.
    """
    if not Path(db_path).exists():
        return {}
    conn, _key = open_offline_state_connection(Path(db_path), database_keys)
    try:
        kwargs: dict[str, Any] = dict(
            previous_data_key=previous_data_key,
            target_data_key=target_data_key,
            previous_seed=None,
            target_seed=seed,
        )
        if dry_run:
            return rekey_field_rows(conn, dry_run=True, **kwargs)
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("BEGIN IMMEDIATE")
        try:
            report = rekey_field_rows(conn, **kwargs)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return report
    finally:
        conn.close()


MAX_REMOTE_INSTRUCTION_SEEN_ROWS = 65_536
MAX_REMOTE_INSTRUCTION_REPLAY_RETENTION_MS = 16 * 60 * 1000
_LOWER_HEX_CHARS = frozenset("0123456789abcdef")
_FOLDER_PENDING_APPLY_PHASES = frozenset({
    "planned",
    "staging",
    "recovery_prepared",
    "recovery_moved",
    "publish_prepared",
    "published",
    "unlink_prepared",
})
_FOLDER_PENDING_APPLY_OPERATIONS = frozenset({"materialize", "delete"})
MAX_FOLDER_PENDING_APPLIES = 262_144

# Chat persistence is a peer-visible receipt boundary.  Keep a hard per-peer
# ceiling so a compromised paired device cannot grow the encrypted database
# without bound.  The daemon rejects new messages once either ceiling is
# reached; exact retransmissions are still accepted idempotently.
MAX_TEXT_MESSAGES_PER_PEER = 100_000
MAX_TEXT_BODY_BYTES_PER_PEER = 256 * 1024 * 1024
MAX_TEXT_BODY_BYTES = 64 * 1024
MAX_GROUP_MESSAGES_PER_GROUP = 100_000
MAX_GROUP_BODY_BYTES_PER_GROUP = 256 * 1024 * 1024
MAX_GROUP_EVENTS_PER_GROUP = 25_000
MAX_GROUP_EVENTS_TOTAL = 250_000
MAX_OUTBOX_PENDING_PER_PEER = 10_000
MAX_OUTBOX_ROWS_PER_PEER = 50_000
MAX_OUTBOX_PENDING_BYTES_PER_PEER = 256 * 1024 * 1024
MAX_OUTBOX_BODY_BYTES = 256 * 1024
BOUNDED_CHAT_MESSAGE_TYPES = frozenset({
    "TEXT",
    "REACTION",
    "EDIT_MSG",
    "DELETE_MSG",
    "READ_MARKER",
    "GROUP_RECEIPT",
    "GROUP_KEY_RECEIPT",
})
_BOUNDED_CHAT_MESSAGE_TYPES_ORDERED = tuple(sorted(BOUNDED_CHAT_MESSAGE_TYPES))
if len(_BOUNDED_CHAT_MESSAGE_TYPES_ORDERED) != 7:
    raise RuntimeError(
        "bounded chat type inventory changed; update the fixed SQL parameter contract"
    )
_BOUNDED_CHAT_USAGE_SQL = (
    "SELECT COUNT(*) AS n, COALESCE(SUM("
    "length(CAST(COALESCE(metadata_json, '') AS BLOB)) + "
    "CASE WHEN msg_type = 'TEXT' THEN "
    "length(CAST(COALESCE(body, '') AS BLOB)) + "
    "length(CAST(COALESCE(original_body, '') AS BLOB)) "
    "ELSE 0 END), 0) AS storage_bytes "
    "FROM messages WHERE peer_fp = ? AND msg_type IN (?, ?, ?, ?, ?, ?, ?)"
)


class MessageIdConflict(ValueError):
    """A message identifier was reused for different immutable content."""


class MessageQuotaExceeded(RuntimeError):
    """A bounded peer or group chat-history quota has been exhausted."""

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS peers (
    fingerprint   TEXT    PRIMARY KEY,   -- BLAKE3 hex of pubkey
    short_id      TEXT    NOT NULL,
    pubkey        BLOB    NOT NULL,
    hostname      TEXT,
    last_address  TEXT,
    last_port     INTEGER,
    trust         TEXT    NOT NULL,      -- 'pinned' | 'pending' | 'rejected'
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id              TEXT    PRIMARY KEY,
    ts_ms           INTEGER NOT NULL,
    direction       TEXT    NOT NULL,    -- 'in' | 'out'
    peer_fp         TEXT    NOT NULL,
    msg_type        TEXT    NOT NULL,    -- 'TEXT' | 'FILE_OFFER' | 'FILE_DONE' ...
    body            TEXT,
    room_id         TEXT,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_ts   ON messages(ts_ms);
CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_fp);
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);

-- Full-text search across message bodies.
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    body,
    content='messages',
    content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, body) VALUES (new.rowid, new.body);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.rowid, old.body);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.rowid, old.body);
    INSERT INTO messages_fts(rowid, body) VALUES (new.rowid, new.body);
END;

CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT    PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    created_ms    INTEGER NOT NULL,
    members_json  TEXT    NOT NULL          -- JSON array of fingerprints
);

CREATE TABLE IF NOT EXISTS folders (
    name             TEXT    PRIMARY KEY,
    local_path       TEXT    NOT NULL,
    shared_with_json TEXT    NOT NULL,
    created_ms       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS folder_manifest (
    folder_name  TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    blob_hash    TEXT,                      -- NULL = tombstone (deleted)
    size         INTEGER,
    mtime_ms     INTEGER,
    vclock_json  TEXT NOT NULL,             -- {peer_fp: counter}
    updated_ms   INTEGER NOT NULL,
    PRIMARY KEY (folder_name, file_path)
);
CREATE INDEX IF NOT EXISTS idx_manifest_folder ON folder_manifest(folder_name);

CREATE TABLE IF NOT EXISTS blobs (
    hash          TEXT    PRIMARY KEY,
    size          INTEGER NOT NULL,
    received_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_capabilities (
    fingerprint TEXT PRIMARY KEY,
    caps_json   TEXT NOT NULL,
    updated_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_capability_policy (
    fingerprint TEXT PRIMARY KEY,
    allowed_json TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);

-- H1: capability-policy + trust audit log. Append-only.
-- `kind` is one of: cap_policy_set, cap_policy_clear, trust_set
-- `before_json` / `after_json` capture the previous and new value for diff.
CREATE TABLE IF NOT EXISTS capability_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms       INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    before_json TEXT,
    after_json  TEXT,
    actor       TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cap_audit_ts ON capability_audit(ts_ms);
CREATE INDEX IF NOT EXISTS idx_cap_audit_fp ON capability_audit(fingerprint);

-- v0.6.2: groups + group events + per-(group, sender, epoch) sender keys.
-- The event log is the source of truth for group state; reduce_events
-- materializes the membership/role/name lazily. Sender chains are
-- stored separately because they advance per message and need fast
-- per-row update.
CREATE TABLE IF NOT EXISTS groups (
    group_id    BLOB    PRIMARY KEY,        -- 16-byte stable id
    name        TEXT    NOT NULL DEFAULT '',-- cached from latest reduce
    created_ms  INTEGER NOT NULL DEFAULT 0,
    state_hash  TEXT    NOT NULL DEFAULT '',-- last computed Merkle of events
    updated_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_events (
    group_id    BLOB    NOT NULL,
    event_id    TEXT    NOT NULL,           -- content-addressed hash
    timestamp_ms INTEGER NOT NULL,
    wire_json   TEXT    NOT NULL,           -- full serialized event
    PRIMARY KEY (group_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_group_events_ts
    ON group_events(group_id, timestamp_ms);

-- Sender chains: my own outbound chain per group AND every peer's
-- chain that they shared with me via GROUP_KEY_OFFER. Direction
-- ('out' / 'in') tells us which we're tracking. Counter is
-- materialized per row and bumped after every encrypt/decrypt.
CREATE TABLE IF NOT EXISTS group_sender_chains (
    group_id    BLOB NOT NULL,
    sender_pub  BLOB NOT NULL,              -- 32-byte Ed25519 pubkey
    direction   TEXT NOT NULL,              -- 'out' | 'in'
    epoch       INTEGER NOT NULL,
    chain_key   BLOB NOT NULL,              -- 32 bytes
    counter     INTEGER NOT NULL DEFAULT 0,
    updated_ms  INTEGER NOT NULL,
    PRIMARY KEY (group_id, sender_pub, direction, epoch)
);
CREATE INDEX IF NOT EXISTS idx_group_chains_lookup
    ON group_sender_chains(group_id, sender_pub, direction);

-- Per-group inbox of decrypted-and-verified plaintext messages.
-- Persisted so the UI can render history; encryption-side info kept
-- so the audit endpoint can show provenance.
CREATE TABLE IF NOT EXISTS group_messages (
    id           TEXT PRIMARY KEY,
    group_id     BLOB NOT NULL,
    sender_pub   BLOB NOT NULL,
    epoch        INTEGER NOT NULL,
    counter      INTEGER NOT NULL,
    direction    TEXT NOT NULL,             -- 'in' | 'out'
    body         TEXT NOT NULL,
    ts_ms        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_group_messages_group_ts
    ON group_messages(group_id, ts_ms);

CREATE TABLE IF NOT EXISTS transfers (
    id             TEXT PRIMARY KEY,
    direction      TEXT NOT NULL,
    peer_fp        TEXT NOT NULL,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    size           INTEGER NOT NULL,
    blob_hash      TEXT,
    status         TEXT NOT NULL,
    progress_bytes INTEGER NOT NULL,
    total_bytes    INTEGER NOT NULL,
    chunks_done    INTEGER NOT NULL,
    chunks_total   INTEGER NOT NULL,
    raw_bytes      INTEGER NOT NULL,
    wire_bytes     INTEGER NOT NULL,
    updated_ms     INTEGER NOT NULL,
    metadata_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfers_updated ON transfers(updated_ms);
CREATE INDEX IF NOT EXISTS idx_transfers_peer ON transfers(peer_fp);
-- 2026-05-22 audit Batch V — prune_transfers filters on status,
-- and on a long ledger that's a full table scan. Composite index
-- on (status, updated_ms) lets the planner serve the prune query
-- with an index seek + early-bound updated_ms range.
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status, updated_ms);

-- v0.7.1: store-and-forward outbox. Holds chat messages addressed to
-- a paired peer that's offline at send time. The daemon re-tries
-- delivery on every fresh outbound session for that peer; rows are
-- marked `delivered_ms` non-null on the first successful ACK.
-- (peer_fp, msg_id) is unique so the same message can't be enqueued
-- twice. attempts/last_error let the UI explain stuck deliveries.
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_fp         TEXT    NOT NULL,
    msg_id          TEXT    NOT NULL,
    msg_kind        TEXT    NOT NULL DEFAULT 'TEXT',
    msg_body_json   TEXT    NOT NULL,
    enqueued_ms     INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms INTEGER,
    last_error      TEXT,
    delivered_ms    INTEGER,
    UNIQUE(peer_fp, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_outbox_peer ON outbox(peer_fp);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(peer_fp, delivered_ms);

-- v0.7.2: folder sandbox capability audit. Append-only log of
-- accepted and rejected remote writes against a sync root, so the
-- user can answer "what did this peer do to my folder last week".
-- root_id binds the audit event to a stable identifier even if the
-- folder is renamed or recreated.
CREATE TABLE IF NOT EXISTS folder_audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms         INTEGER NOT NULL,
    folder_name   TEXT    NOT NULL,
    root_id       TEXT    NOT NULL,
    peer_fp       TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    blob_hash     TEXT,
    size          INTEGER,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_folder_audit_ts ON folder_audit(ts_ms);
CREATE INDEX IF NOT EXISTS idx_folder_audit_folder ON folder_audit(folder_name);
CREATE INDEX IF NOT EXISTS idx_folder_audit_peer ON folder_audit(peer_fp);

-- v0.7.5: per-message emoji reactions. (target_msg_id, peer_fp, emoji)
-- is the natural primary key — each peer can hold at most one of each
-- emoji on a given message (toggle on/off semantics).
CREATE TABLE IF NOT EXISTS message_reactions (
    target_msg_id  TEXT    NOT NULL,
    peer_fp        TEXT    NOT NULL,
    emoji          TEXT    NOT NULL,
    ts_ms          INTEGER NOT NULL,
    PRIMARY KEY (target_msg_id, peer_fp, emoji)
);
CREATE INDEX IF NOT EXISTS idx_reactions_target ON message_reactions(target_msg_id);
"""


class StateSchemaTooNewError(RuntimeError):
    """The database was written by a newer release than this one."""


def _now_ms() -> int:
    return int(time.time() * 1000)


# v0.21.x: forgiving FTS5 query builder. Plain users type 'k' and
# expect to find messages with 'kanye' or 'kjg'; raw FTS5 token
# matching only finds messages containing the standalone token 'k'.
# Convert each alphanumeric token to a quoted prefix-match ('"k"*') so
# substring-feeling search works. Pass-through honors literal
# phrase quotes ('"hello world"') for power users.
_FTS5_TOKEN_RE = __import__("re").compile(r"\w+", __import__("re").UNICODE)


def _normalize_user_query_to_fts5_prefix(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    s = raw.strip()
    if not s:
        return ""
    # Pass through explicit phrase queries: "...".  Reject the
    # empty / whitespace-only phrase ('""', '"   "') - those would
    # error or no-op against FTS5 MATCH; cleaner to return empty
    # so the caller short-circuits without a DB hit. Hypothesis
    # caught this edge with the '""' input.
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        inner = s[1:-1].strip()
        if not inner:
            return ""
        # A phrase with no word characters (only symbols, e.g. "@#$")
        # has nothing FTS5 can tokenize and would error / no-op against
        # MATCH; return empty so the caller short-circuits without a DB
        # hit. (Hypothesis property test caught this quote-wrapped
        # special-chars-only edge.)
        if not _FTS5_TOKEN_RE.search(inner):
            return ""
        # Treat the entire outer-quoted value as one literal phrase. Doubling
        # embedded quotes is FTS5's string escape and prevents an input such
        # as '"foo" OR "bar"' from escaping the phrase into query syntax.
        return '"' + inner.replace('"', '""') + '"'
    tokens = _FTS5_TOKEN_RE.findall(s)
    if not tokens:
        return ""
    # Quote every token before adding the prefix operator. Bare uppercase
    # tokens such as AND, OR, NOT, and NEAR are FTS5 grammar, not terms; the
    # formerly emitted `AND*` raised OperationalError. A quoted prefix
    # (`"AND"*`) remains a real prefix search while making every extracted
    # token parser-safe. Multi-token terms retain implicit-AND semantics.
    return " ".join(f'"{token}"*' for token in tokens)


@dataclass
class PeerRecord:
    fingerprint: str
    short_id: str
    pubkey: bytes
    hostname: Optional[str]
    last_address: Optional[str]
    last_port: Optional[int]
    trust: str
    first_seen_ms: int
    last_seen_ms: int
    # v0.7.3 per-device profile.
    local_alias: Optional[str] = None
    muted: bool = False
    # v0.7.7 verified-in-person trust state. `verified_at_ms` is set
    # the moment the user confirms a side-channel SAS match (face-to-
    # face, QR scan, audio readback). `verified_method` is one of
    # 'sas-digits', 'sas-qr', 'sas-audio', 'manual'. `verified_note`
    # is an optional free-text reminder ("met at office Tue").
    verified_at_ms: Optional[int] = None
    verified_method: Optional[str] = None
    verified_note: Optional[str] = None
    # v0.10.2 disappearing-message TTL. None = off; otherwise every
    # TEXT message sent to / received from this peer carries an
    # expires_at_ms = ts_ms + dm_ttl_ms. The daemon's reaper sweeps
    # expired rows + broadcasts msg_delete WS events.
    dm_ttl_ms: Optional[int] = None
    # v0.11.2 per-chat mute with duration. None = not muted; 0 = muted
    # forever (no auto-expire); N > 0 = muted until wall-clock ms N.
    # is_muted derives this with the current time so an expired mute
    # automatically un-mutes itself.
    muted_until_ms: Optional[int] = None

    @property
    def display_name(self) -> str:
        """Resolves to local_alias if set, else hostname, else short_id."""
        return self.local_alias or self.hostname or self.short_id

    @property
    def is_verified(self) -> bool:
        """v0.7.7: True iff the peer has been verified in person via
        a side-channel SAS confirm. Independent of `trust` — trust
        gates wire access; verification gates UI affordance."""
        return self.verified_at_ms is not None

    def is_muted_at(self, now_ms: int) -> bool:
        """v0.11.2: True iff the per-chat mute is active at `now_ms`.
        muted_until_ms = 0 means muted forever; >0 means muted until
        that timestamp. Falls back to the legacy `muted` boolean for
        rows persisted under v0.7.3 schema before muted_until_ms
        existed."""
        if self.muted_until_ms is not None:
            if self.muted_until_ms == 0:
                return True
            return self.muted_until_ms > now_ms
        return self.muted


@dataclass
class MessageRecord:
    id: str
    ts_ms: int
    direction: str
    peer_fp: str
    msg_type: str
    body: Optional[str]
    room_id: Optional[str]
    metadata: dict
    # v0.7.5: optional parent message id for reply/quote rendering.
    reply_to: Optional[str] = None
    # v0.7.6: edit / delete state.
    edited_at_ms: Optional[int] = None
    original_body: Optional[str] = None
    deleted_at_ms: Optional[int] = None
    # v0.10.2: disappearing-message expiry (ms epoch). NULL = never.
    expires_at_ms: Optional[int] = None

    @property
    def is_edited(self) -> bool:
        return self.edited_at_ms is not None

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at_ms is not None

    @property
    def is_expiring(self) -> bool:
        return self.expires_at_ms is not None


@dataclass
class TransferRecord:
    id: str
    direction: str
    peer_fp: str
    kind: str
    name: str
    size: int
    blob_hash: Optional[str]
    status: str
    progress_bytes: int
    total_bytes: int
    chunks_done: int
    chunks_total: int
    raw_bytes: int
    wire_bytes: int
    updated_ms: int
    metadata: dict


@dataclass
class OutboxEntry:
    """v0.7.1: pending or delivered store-and-forward message row."""
    id: int
    peer_fp: str
    msg_id: str
    msg_kind: str
    msg_body: dict
    enqueued_ms: int
    attempts: int
    last_attempt_ms: Optional[int]
    last_error: Optional[str]
    delivered_ms: Optional[int]

    @property
    def delivered(self) -> bool:
        return self.delivered_ms is not None


class State:
    """Singleton-style state handle. Construct once per daemon."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (data_dir() / DB_FILE)
        # v0.21.x at-rest encryption. Order:
        #   1. Try to get a passphrase (env var → OS keychain →
        #      auto-mint into the keychain on first run).
        #   2. If we have a passphrase AND sqlcipher3 is installed:
        #      open via SQLCipher. If the file is currently plaintext,
        #      migrate in place first (backup is kept).
        #   3. Otherwise fall back to stdlib sqlite3 (legacy mode).
        #
        # The encrypted boolean is exposed via .is_encrypted so
        # callers / Privacy panel can show "Disk encryption: ON / OFF"
        # honestly.
        self.is_encrypted = False
        self._encryption_backup_path: Optional[Path] = None
        # Boot passes through here; a stall is logged while it lasts.
        from one_link.lockbox import audible_step

        with audible_step("state.db open", logger=log):
            conn = self._open_connection_with_encryption_if_available()
        self._conn = conn
        # Row factory must come from the connection's OWN module —
        # sqlite3.Row only accepts sqlite3.Cursor, sqlcipher3.Row only
        # accepts sqlcipher3.dbapi2.Cursor. Crossing them raises
        # TypeError at fetchone(). Pull the right class off the
        # connection itself.
        try:
            conn_module = type(self._conn).__module__
            if "sqlcipher3" in conn_module:
                import sqlcipher3 as _sqc
                self._conn.row_factory = _sqc.Row
            else:
                self._conn.row_factory = sqlite3.Row
        except Exception:
            # Defensive: if row_factory assignment fails, fall back
            # to dict-via-description-name in the wrapper. The
            # downstream code uses row["col"] subscripting which
            # both Row classes support; we just need the assignment
            # itself to land cleanly.
            try:
                self._conn.row_factory = sqlite3.Row
            except BaseException:
                with contextlib.suppress(Exception):
                    self._conn.close()
                raise
        self._write_lock = threading.RLock()
        # Lazily hydrated from SQLite on the first TEXT insert per peer, then
        # maintained under _write_lock. Near a limit we re-read authoritative
        # SQL so history clears/expiry cannot leave a stale false rejection.
        self._text_usage_cache: dict[str, tuple[int, int]] = {}
        self._group_usage_cache: dict[bytes, tuple[int, int]] = {}
        self._group_event_count_cache: dict[bytes, int] = {}
        self._group_event_total_count: Optional[int] = None
        self._outbox_usage_cache: dict[str, tuple[int, int, int]] = {}
        # 2026-05-21 audit T2-R: state.db holds DR chain keys, group
        # sender keys, message bodies, peer trust state. On POSIX
        # the default mkdir/file mode follows the process umask
        # (often 0o022 → world-readable file). Lock it down to user-
        # only. Best-effort: chmod silently no-ops on Windows where
        # the permission model is ACL-based.
        with contextlib.suppress(Exception):
            os.chmod(self.db_path, 0o600)
        # v0.20.7 (security audit H21 + partial C5): optional
        # at-rest wrap for the highest-value secrets in the schema
        # (group sender chain keys and personal-mesh root seeds). Daemon
        # wires a LockBox here at boot when ONE_LINK_PASSPHRASE is set;
        # absent passphrase -> None -> values remain cleartext for legacy
        # compatibility. Fixed-width binary readers use exact-length
        # discrimination so a random leading wrap-marker byte is harmless.
        self._lockbox = None  # set via set_lockbox()
        # Boot-integrity dirty-bit. PRAGMA quick_check on an encrypted
        # DB decrypts + HMAC-verifies EVERY page — ~13-18s on a large
        # (200 MB+) state.db. Running it on every boot dominated startup
        # and blocked the UI. Instead we use a crash-detecting dirty
        # bit: a sidecar marker is written on clean close and removed on
        # open. If it's present at open, the prior shutdown was clean and
        # the DB is consistent (SQLCipher already HMAC-verifies every
        # page it reads at runtime, so silent on-disk corruption surfaces
        # the moment a row is touched regardless). Only an UNCLEAN prior
        # shutdown (crash / power loss / first boot) flags a deferred
        # check, which the daemon then runs in a BACKGROUND thread after
        # the UI is already serving — see run_deferred_integrity_check().
        # self.db_path may be a str (some callers pass a string path);
        # coerce locally so .with_name works without changing its type
        # for the rest of the class.
        _dbp = Path(self.db_path)
        self._clean_marker = _dbp.with_name(_dbp.name + ".clean")
        prior_clean = False
        with contextlib.suppress(Exception):
            prior_clean = self._clean_marker.is_file()
        self._needs_integrity_check = not prior_clean
        # Remove the marker now; close() re-creates it on a clean
        # shutdown. A crash (no close) leaves it absent → next boot
        # integrity-checks.
        with contextlib.suppress(Exception):
            self._clean_marker.unlink()
        try:
            with audible_step("state.db schema initialisation", logger=log):
                self._init_pragmas()
                self._migrate()
                self._cleanup_verified_plaintext_backup()
        except BaseException:
            # A half-constructed State must not retain a native SQLite handle.
            # Windows otherwise refuses recovery's atomic state.db replace;
            # repeated boot failures also leak descriptors and native memory.
            with contextlib.suppress(Exception):
                self._conn.close()
            raise

    def _cleanup_verified_plaintext_backup(self) -> None:
        """Erase migration recovery only after schema + full integrity truth."""

        if not self.is_encrypted:
            return
        from one_link import state_encryption as _se

        backup_path = _se.plaintext_backup_path(Path(self.db_path))
        try:
            os.lstat(backup_path)
        except FileNotFoundError:
            self._encryption_backup_path = None
            return
        except OSError as inspect_exc:
            # An ACL, transient I/O failure, or hostile filesystem object must
            # never be interpreted as "no backup". Keep the path visible to
            # operators and continue with the verified encrypted live DB; the
            # next boot retries the cleanup gate.
            self._encryption_backup_path = backup_path
            log.critical(
                "state.db encryption is active, but its plaintext migration "
                "backup could not be inspected and was retained: %s",
                inspect_exc,
            )
            return
        try:
            _se.verify_encrypted_state_for_backup_cleanup(
                self._conn,
                expected_schema_version=_se.STATE_SCHEMA_VERSION_CURRENT,
            )
            _se.cleanup_plaintext_migration_backup(self.db_path)
            self._encryption_backup_path = None
        except (
            _se.EncryptedDatabaseVerificationError,
            _se.PlaintextBackupCleanupError,
        ) as cleanup_exc:
            self._encryption_backup_path = backup_path
            log.critical(
                "state.db encryption is active, but its plaintext migration "
                "backup was retained because a verification/cleanup gate "
                "failed: %s",
                cleanup_exc,
            )

    def set_lockbox(self, lockbox) -> None:
        """v0.20.7: late-attach the at-rest wrap key. Daemon calls
        this once at boot after constructing State + the LockBox.
        Subsequent writes wrap; subsequent reads unwrap on demand."""
        self._lockbox = lockbox

    @contextlib.contextmanager
    def durable_write_transaction(self):
        """Serialize a FULL-synchronous multi-row receipt boundary."""

        sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
        with self._write_lock:
            if self._conn.in_transaction:
                raise RuntimeError("nested durable state transaction")
            sync_row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous_sync = int(sync_row[0]) if sync_row else 1
            self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield
                self._conn.execute("COMMIT")
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                self._text_usage_cache.clear()
                self._group_usage_cache.clear()
                self._group_event_count_cache.clear()
                self._group_event_total_count = None
                self._outbox_usage_cache.clear()
                raise
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous={sync_names.get(previous_sync, 'NORMAL')}"
                )

    # v0.20.7 (security audit M30): path-PII encryptor. Daemon late-
    # attaches one of these at boot when the master seed is available;
    # all chunk_sources / file_index_cache writes go through wrap, all
    # reads go through unwrap. Legacy cleartext rows are detected by
    # absence of the marker prefix and remain readable.
    _path_pii = None

    def set_path_pii_encryptor(self, encryptor) -> None:
        self._path_pii = encryptor

    # AAD strings: distinct per column so a path that exists in both
    # tables encrypts to different ciphertext, ensuring a leak of one
    # column doesn't help an attacker pivot via the other.
    # The AADs live in KEY_PROTECTED_FIELDS; these names remain for readers
    # outside this module (storage_lifecycle reads transfer paths).
    _PATH_PII_AAD_CHUNK_SOURCES = CHUNK_SOURCE_PATH.aad
    _PATH_PII_AAD_FILE_INDEX = FILE_INDEX_PATH.aad
    # 2026-05-22 audit T3-J: wrap the per-transfer source ``path``
    # so the ledger row + on-disk DB don't carry the user's
    # filesystem layout in plaintext. Distinct AAD per column so
    # leaked chunk_sources / file_index_cache rows can't help
    # decrypt this column even though many paths are the same.
    _PATH_PII_AAD_TRANSFER = TRANSFER_SOURCE_PATH.aad

    def _seal_field(self, field: KeyProtectedField, value: Any) -> Any:
        """Seal one registered field for storage under its key family.

        The only producer of key-protected State ciphertext: a value that
        bypasses this cannot be found by ``rekey_protected_fields``.
        """
        if field.family == FIELD_FAMILY_DATA_KEY:
            from one_link.lockbox import maybe_wrap

            return maybe_wrap(bytes(value), self._lockbox)
        return self._wrap_path(value, aad=field.aad)

    def _open_field(self, field: KeyProtectedField, stored: Any) -> Any:
        """Open one registered field read from storage.

        Data-key fields are fixed width: exactly ``plaintext_len`` bytes is
        legacy cleartext and ``plaintext_len + 29`` is a LockBox envelope.
        Length, not the one-byte marker, discriminates, because a random
        32-byte secret begins with the marker byte once in 256 values.
        """
        if field.family == FIELD_FAMILY_DATA_KEY:
            from one_link.lockbox import MIN_WRAPPED_LEN

            raw = bytes(stored)
            if len(raw) == field.plaintext_len:
                return raw
            if len(raw) != field.plaintext_len + MIN_WRAPPED_LEN:
                raise ValueError(
                    f"invalid stored {field.label} length: {len(raw)}"
                )
            if self._lockbox is None:
                raise RuntimeError(
                    f"found a non-cleartext {field.label} but no lockbox is "
                    "configured (was ONE_LINK_PASSPHRASE removed?)"
                )
            return self._lockbox.unwrap(raw)
        return self._unwrap_path(stored, aad=field.aad)

    def rekey_protected_fields(
        self,
        *,
        previous_data_key: Optional[bytes],
        target_data_key: bytes,
        previous_seed: Optional[bytes],
        target_seed: bytes,
    ) -> dict[str, dict[str, int]]:
        """Re-key every ``KEY_PROTECTED_FIELDS`` value in ONE durable transaction.

        A family whose previous key is ``None`` is unchanged and skipped.
        Each stored value is classified by authentication, never guessed:

        * opens under the target key: already current (a replay after the
          transaction committed converges here);
        * opens under the previous key: re-sealed under the target key;
        * opens under neither: counted as ``unopenable`` and left exactly as
          stored (it was sealed by a key this transaction does not hold).

        SQLite commits all of it or none of it, so an interruption leaves
        every row under the previous key and the replay re-runs it.
        """
        with self.durable_write_transaction():
            return rekey_field_rows(
                self._conn,
                previous_data_key=previous_data_key,
                target_data_key=target_data_key,
                previous_seed=previous_seed,
                target_seed=target_seed,
            )

    def _wrap_path(self, value: str, *, aad: bytes) -> str:
        if self._path_pii is None or not value:
            return value
        return self._path_pii.wrap(value, aad=aad)

    def _unwrap_path(self, value: str, *, aad: bytes) -> str:
        if self._path_pii is None or not value:
            return value
        out = self._path_pii.unwrap(value, aad=aad)
        # If unwrap returned None, the value is wrapped but
        # un-decryptable (tamper / wrong install). Surface the
        # opaque marker so callers don't accidentally treat stale
        # ciphertext as a real filesystem path.
        return out if out is not None else value

    # 2026-06-16 (external-audit remediation): plaintext at-rest mode is
    # no longer a SILENT fallback. It is allowed only when the operator
    # explicitly opts in (ONE_LINK_ALLOW_PLAINTEXT=1) or the test suite
    # has disabled at-rest encryption. Any other "couldn't encrypt" path
    # REFUSES TO START with an actionable error rather than quietly
    # writing the user's messages + identity to a plaintext DB — which
    # would betray One Link's core "your data is yours and protected"
    # promise.
    _ALLOW_PLAINTEXT_ENV = "ONE_LINK_ALLOW_PLAINTEXT"

    def _plaintext_connection_or_refuse(self, reason: str):
        import os as _os
        from one_link import keychain as _kc
        opted_in = (
            _os.environ.get(self._ALLOW_PLAINTEXT_ENV, "").strip().lower()
            in ("1", "true", "yes", "on")
        )
        # The test suite's encryption-disable flag is an implicit opt-in
        # so thousands of throwaway State() objects don't each hit the
        # OS keychain. (conftest hardening is tracked separately.)
        if opted_in or _kc._disabled():
            log.warning(
                "state.db: at-rest encryption OFF (%s). Running PLAINTEXT "
                "because %s is set. Your messages + identity are NOT "
                "encrypted at rest.",
                reason,
                self._ALLOW_PLAINTEXT_ENV if opted_in else _kc.DISABLE_ENV,
            )
            self.is_encrypted = False
            return sqlite3.connect(
                self.db_path,
                check_same_thread=False, isolation_level=None,
            )
        raise RuntimeError(
            "One Link refuses to start with an UNENCRYPTED state.db. "
            f"Reason: {reason}. At-rest encryption protects your messages "
            "and identity keys. Fix the underlying issue (install/enable "
            "the OS keychain, or set ONE_LINK_PASSPHRASE), or — if you "
            "truly accept plaintext storage — re-run with "
            f"{self._ALLOW_PLAINTEXT_ENV}=1."
        )

    def _open_connection_with_encryption_if_available(self):
        """Open self.db_path with SQLCipher. At-rest encryption is the
        DEFAULT and stays on as long as a key can be obtained from the
        OS keychain OR a local 0600 key file (keychain.ensure_passphrase
        falls back to the file when no OS keychain exists).

        Plaintext is NOT a silent fallback: every path that cannot
        encrypt routes through _plaintext_connection_or_refuse, which
        refuses to start unless plaintext is explicitly opted into.

        On first encrypted open of a previously-plaintext file, an
        in-place migration runs and the temporary plaintext backup is
        securely deleted once the encrypted DB is verified.

        Returns the open connection; sets self.is_encrypted accordingly.
        """
        from one_link import keychain as _kc
        from one_link import state_encryption as _se

        from one_link import lockbox as _lockbox

        _kc.adopt_recovery_passphrase_for_database(Path(self.db_path))
        # A passphrase-protected database started without its passphrase:
        # refuse before the keychain mints a database key that opens nothing.
        # KeyMaterialError: Daemon.start refuses instead of running stateless.
        refusal = _lockbox.passphrase_startup_refusal(
            Path(self.db_path).parent, probe_database=False,
        )
        if refusal is not None:
            raise refusal
        passphrase = _kc.ensure_passphrase()
        # Stash for run_deferred_integrity_check(), which opens its OWN
        # read connection (so the multi-second check never blocks the
        # live write connection). None in legacy plaintext mode.
        self._db_passphrase = passphrase
        if not passphrase or not _se._have_sqlcipher():
            # No key or no cipher engine. This is NOT a silent plaintext
            # fallback any more — refuse unless plaintext is opted into.
            if not passphrase:
                reason = (
                    "no encryption key available (OS keychain unusable "
                    "and the local key file could not be written; set "
                    "ONE_LINK_PASSPHRASE to provide one)"
                )
            else:
                reason = "sqlcipher3 is not installed/importable"
            return self._plaintext_connection_or_refuse(reason)

        # Encrypted path. Possible states:
        #   - missing  → fresh install; open encrypted from scratch
        #   - plaintext → migrate in place, then open
        #   - encrypted → open as-is
        state = _se.detect_db_state(self.db_path)
        if state == "plaintext":
            try:
                self._encryption_backup_path = (
                    _se.migrate_plaintext_to_encrypted(
                        self.db_path, passphrase,
                    )
                )
            except Exception as e:
                log.error(
                    "state.db: plaintext→encrypted migration FAILED (%s). "
                    "Your data is intact (untouched plaintext file).", e,
                )
                return self._plaintext_connection_or_refuse(
                    f"plaintext→encrypted migration failed ({type(e).__name__})"
                )

        try:
            conn = _se.open_encrypted_connection(
                self.db_path, passphrase,
            )
            self.is_encrypted = True
            log.info(
                "state.db: AES-256 at-rest encryption ACTIVE "
                "(key from %s)",
                # Where the key ACTUALLY resolved from -- backend_label()
                # names the backend merely INSTALLED here, which on a Mac
                # with a locked login keychain claimed "macOS Keychain" one
                # line after the log said the key went to the local file.
                _kc.last_key_source_label() or _kc.backend_label(),
            )
            return conn
        except Exception as e:
            # If the file on disk is actually encrypted, falling back
            # to plaintext sqlite3.connect just produces a worse
            # error ("file is not a database"). The honest action is
            # to refuse to start so the operator can intervene —
            # silently swapping the file for a plaintext one would
            # corrupt the user's data.
            if state == "encrypted":
                refusal = _lockbox.passphrase_startup_refusal(
                    Path(self.db_path).parent, probe_database=True,
                )
                if refusal is not None:
                    raise refusal from e
                raise RuntimeError(
                    f"state.db is encrypted but the current passphrase "
                    f"can't decrypt it. The most likely cause: the "
                    f"OS keychain entry has changed (key rotated, "
                    f"machine restored from backup) or the "
                    f"ONE_LINK_PASSPHRASE env var is wrong. Restore "
                    f"the previous passphrase to recover. (underlying "
                    f"error: {type(e).__name__})"
                ) from e
            log.error(
                "state.db: failed to open encrypted DB (%s) and the "
                "file appears empty/missing.", e,
            )
            return self._plaintext_connection_or_refuse(
                f"encrypted open failed on an empty/missing file "
                f"({type(e).__name__})"
            )

    def _init_pragmas(self) -> None:
        c = self._conn.cursor()
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA temp_store = MEMORY")
        c.execute("PRAGMA cache_size = -8000")  # 8 MB
        # v0.20.7 (security audit H22): zero freed pages on delete so
        # the disappearing-messages reaper actually erases plaintext
        # bodies from the file. Adds ~10% write cost; worth it.
        c.execute("PRAGMA secure_delete = ON")
        # v0.20.7: checkpoint WAL frequently so deleted-row plaintext
        # does not linger in state.db-wal between application
        # checkpoints. 50 pages ~= ~200KB worst case.
        c.execute("PRAGMA wal_autocheckpoint = 50")
        # NOTE: the boot integrity check (PRAGMA quick_check) is NO
        # LONGER run here. On an encrypted 200 MB+ DB it cost 13-18s of
        # full-file decrypt on EVERY boot and blocked the UI. It now runs
        # only after an unclean shutdown, in a background thread, via
        # run_deferred_integrity_check(). See the dirty-bit in __init__.
        c.close()

    def run_deferred_integrity_check(self) -> str:
        """Run PRAGMA quick_check IF the prior shutdown was unclean.

        Blocking (full-file decrypt on an encrypted DB), so the daemon
        calls this from a background thread AFTER the UI is already
        serving — it must never sit on the boot critical path. Returns
        "skipped" (clean prior shutdown), "ok" (checked, healthy), or
        the integrity-error string (checked, corrupt — logged at ERROR).

        2026-05-21 audit T3-X intent preserved: surface a corrupt
        state.db without silently rebuilding it (which would lose pinned
        peers / keys / audit log on a transient I/O blip)."""
        if not getattr(self, "_needs_integrity_check", False):
            return "skipped"
        try:
            # Open a SEPARATE read connection for the check. quick_check
            # takes seconds on a large encrypted DB; running it on the
            # live connection would either block every write (held under
            # _write_lock) or unsafely share one connection across
            # threads. WAL mode lets this independent reader see a
            # consistent snapshot while the daemon keeps writing.
            if self.is_encrypted and getattr(self, "_db_passphrase", None):
                from one_link import state_encryption as _se
                # The guard above proves the passphrase is set + truthy;
                # narrow str | None -> str for the typed call.
                assert self._db_passphrase is not None
                check_conn = _se.open_encrypted_connection(
                    self.db_path, self._db_passphrase,
                )
            else:
                check_conn = sqlite3.connect(
                    str(self.db_path), check_same_thread=False,
                )
            try:
                res = check_conn.execute("PRAGMA quick_check").fetchone()
            finally:
                check_conn.close()
            status = res[0] if res else "ok"
            if status != "ok":
                log.error(
                    "state.db integrity check FAILED (post-crash): %s. "
                    "The daemon will keep running but operations against "
                    "the corrupted store may fail. Consider renaming the "
                    "file and bootstrapping fresh.", status,
                )
            else:
                log.info(
                    "state.db integrity check passed (ran because the "
                    "prior shutdown was unclean)"
                )
            # Whether ok or not, don't re-run until the next unclean boot.
            self._needs_integrity_check = False
            return status
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("state.db integrity check raised: %s", exc)
            return "error"

    def _migrate(self) -> None:
        """Run schema migrations atomically.

        v0.20.7 (security audit H20): each migration step + its
        version stamp run inside a single ``BEGIN IMMEDIATE`` /
        ``COMMIT`` transaction. A SIGKILL between an ALTER TABLE and
        the version-stamp INSERT used to leave the DB in a half-
        migrated state (table already had the new column but
        ``schema_version`` claimed the old version, so the next boot
        re-ran the migration and either errored on duplicate column
        or quietly mis-stamped). With per-step transactions, the WAL
        rolls back on crash and the next boot retries the same step
        from a clean baseline.

        SQLite's ``isolation_level=None`` (autocommit) still permits
        explicit ``BEGIN``/``COMMIT`` to delimit a transaction, which
        is what we want here — every other code path stays in
        autocommit mode.
        """
        with self._write_lock:
            c = self._conn.cursor()
            try:
                stored = self._stored_schema_version(c)
                if stored is not None and stored > self.LATEST_SCHEMA_VERSION:
                    # Written by a newer release. Running this build's
                    # CREATE-IF-NOT-EXISTS script and backfills over a layout
                    # it has never seen would damage it quietly; refusing is
                    # the only safe answer, and it leaves the file untouched.
                    raise StateSchemaTooNewError(
                        f"{self.db_path} has schema version {stored}, but this "
                        f"version of One Link only understands up to "
                        f"{self.LATEST_SCHEMA_VERSION}. It was last opened by a "
                        "newer release. Install that release again, or restore "
                        "the snapshot it saved next to the database before it "
                        "upgraded."
                    )
                if stored is not None and stored < self.LATEST_SCHEMA_VERSION:
                    self._snapshot_before_migration(c, stored)
                # Bootstrap v1. SCHEMA_V1 is composed entirely of
                # ``CREATE ... IF NOT EXISTS`` statements (tables,
                # virtual tables, triggers, indexes), so a crash mid-
                # script is safe: the next boot re-runs the script and
                # idempotently fills in whatever is missing. We can't
                # wrap ``executescript`` in BEGIN IMMEDIATE because
                # SQLite's executescript implicitly commits the open
                # transaction — but the idempotency property keeps v1
                # bootstrap safe on its own.
                c.executescript(SCHEMA_V1)
                cur = c.execute("SELECT MAX(version) FROM schema_version")
                row = cur.fetchone()
                current = row[0] if row and row[0] is not None else 0
                if current < 1:
                    c.execute("INSERT INTO schema_version(version) VALUES(1)")
                    current = 1

                # vN+ migrations: each (apply_fn, target_version) pair
                # runs in its own transaction so a crash in the middle
                # of vN does not leave the schema with vN's tables but
                # vN-1's stamp.
                steps = [
                    (2, self._migrate_v2_folder_sandboxes),
                    (3, self._migrate_v3_peer_profile),
                    (4, self._migrate_v4_messages_reply_to),
                    (5, self._migrate_v5_edit_delete_read),
                    (6, self._migrate_v6_group_reply),
                    (7, self._migrate_v7_group_edit_delete),
                    (8, self._migrate_v8_peer_verification),
                    (9, self._migrate_v9_key_change_tracking),
                    (10, self._migrate_v10_folder_conflicts),
                    (11, self._migrate_v11_chunk_availability),
                    (12, self._migrate_v12_disappearing_messages),
                    (13, self._migrate_v13_prior_chunk_sources),
                    (14, self._migrate_v14_mute_until),
                    (15, self._migrate_v15_file_index_cache),
                    (16, self._migrate_v16_route_memory),
                    (17, self._migrate_v17_route_candidates),
                    (18, self._migrate_v18_personal_device_mesh),
                    (19, self._migrate_v19_self_mesh_enrollment),
                    (20, self._migrate_v20_self_mesh_performance),
                    (21, self._migrate_v21_device_guardian),
                    (22, self._migrate_v22_transfer_status_index),
                    (23, self._migrate_v23_rotation_announcements),
                    (24, self._migrate_v24_held_recovery_shares),
                    (25, self._migrate_v25_pending_folder_offers),
                    (26, self._migrate_v26_folder_lifecycle_audit),
                    (27, self._migrate_v27_ui_sessions),
                    (28, self._migrate_v28_ui_session_token_hashes),
                    (29, self._migrate_v29_file_index_identity),
                    (30, self._migrate_v30_folder_pending_applies),
                ]
                if steps[-1][0] != self.LATEST_SCHEMA_VERSION:
                    raise RuntimeError(
                        "LATEST_SCHEMA_VERSION does not match the last migration step"
                    )
                for target_version, apply_fn in steps:
                    self._run_atomic_migration(
                        c,
                        target_version=target_version,
                        current_version=current,
                        apply=apply_fn,
                        exactly_once=target_version not in self._REAPPLIED_EVERY_BOOT,
                    )
                if stored is not None and stored < self.LATEST_SCHEMA_VERSION:
                    self._prune_migration_snapshots(keep_version=stored)
            finally:
                c.close()

    #: Highest schema version this build writes. A database stamped higher
    #: was written by a newer release and is refused.
    LATEST_SCHEMA_VERSION = 30

    @staticmethod
    def _stored_schema_version(c: sqlite3.Cursor) -> Optional[int]:
        """Schema version of an existing database, ``None`` for a new file."""
        has_table = c.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
        ).fetchone()
        if not has_table:
            return None
        row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0]) if row and row[0] is not None else None

    def _migration_snapshot_path(self, version: int) -> Path:
        db = Path(self.db_path)
        return db.with_name(f"{db.name}.pre-migration-v{version}.bak")

    def _snapshot_before_migration(self, c: sqlite3.Cursor, stored: int) -> None:
        """Keep a copy of the database as it was before this upgrade.

        Migrations rewrite the only copy of the user's messages, peers and
        keys in place. If a step is wrong, or the new release has to be
        rolled back, the snapshot is the way home: stop One Link, move the
        snapshot over the database file, start the previous release.

        A snapshot that already exists for this version is kept as is; it
        was taken before an earlier attempt at the same upgrade and is the
        more pristine of the two.
        """
        db = Path(self.db_path)
        if not db.is_file():
            return  # in-memory database
        target = self._migration_snapshot_path(stored)
        if target.exists():
            return
        partial = target.with_name(target.name + ".partial")
        try:
            with contextlib.suppress(FileNotFoundError):
                partial.unlink()
            try:
                # A transactionally consistent copy. Under SQLCipher the copy
                # is encrypted with the same key as the original.
                c.execute("VACUUM INTO ?", (str(partial),))
            except sqlite3.Error:
                # Builds without VACUUM INTO: fold the WAL into the main file
                # and copy it. The write lock is held and nothing has been
                # written on this connection yet, so the file is quiescent.
                with contextlib.suppress(FileNotFoundError):
                    partial.unlink()
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                import shutil

                shutil.copyfile(db, partial)
            with contextlib.suppress(OSError):
                os.chmod(partial, 0o600)
            with open(partial, "rb") as fh:
                os.fsync(fh.fileno())
            os.replace(partial, target)
        except Exception as exc:
            with contextlib.suppress(OSError):
                partial.unlink()
            if os.environ.get("ONE_LINK_ALLOW_UNSNAPSHOTTED_MIGRATION") == "1":
                log.warning(
                    "state.db schema upgrade v%s -> v%s is proceeding WITHOUT a "
                    "snapshot (%s); ONE_LINK_ALLOW_UNSNAPSHOTTED_MIGRATION is set",
                    stored, self.LATEST_SCHEMA_VERSION, exc,
                )
                return
            raise RuntimeError(
                f"could not save a snapshot of {db} before upgrading its schema "
                f"from v{stored} to v{self.LATEST_SCHEMA_VERSION}: {exc}. Free "
                "disk space and start again; the database has not been changed. "
                "To upgrade without a snapshot, set "
                "ONE_LINK_ALLOW_UNSNAPSHOTTED_MIGRATION=1."
            ) from exc
        log.info(
            "state.db: saved pre-upgrade snapshot %s (schema v%s -> v%s)",
            target.name, stored, self.LATEST_SCHEMA_VERSION,
        )

    def _prune_migration_snapshots(self, *, keep_version: int) -> None:
        """After a successful upgrade keep only the snapshot it started from."""
        db = Path(self.db_path)
        keep = self._migration_snapshot_path(keep_version)
        for old in db.parent.glob(f"{db.name}.pre-migration-v*.bak"):
            if old != keep:
                with contextlib.suppress(OSError):
                    old.unlink()

    # Migrations that transform stored values one way. The runner re-applies
    # every other step on every boot (they are idempotent backfills); these
    # may run only on the boot that first crosses their version.
    #
    #   28  replaces each stored browser-session bearer with its SHA-256
    #       record key. A record key has the same shape as a bearer (64
    #       lowercase hex), so applying the step to an already-migrated row
    #       hashes the key again and the browser's bearer no longer matches
    #       anything. From 2026-07-25 until this set existed, that happened
    #       on EVERY daemon start: each restart signed every open window out,
    #       and "stay signed in across daemon restarts" could not work.
    #
    # tests/test_state_migrations_rerun.py re-opens a populated database and
    # fails on any row a re-run changes in the tables it populates, so a new
    # one-way step on those tables that is not listed here is caught.
    #
    # Not covered (independent review, 2026-11-25): a binary older than v28
    # opening a database already stamped >= 28 stores a raw bearer, and this
    # step will not convert it later. That row cannot authenticate here
    # (lookups hash what is presented), so the browser signs in once more.
    # Making the step idempotent would need a stored form that tells a record
    # key from a bearer; the two are indistinguishable today.
    _EXACTLY_ONCE_MIGRATIONS = frozenset({28})

    # The steps that existed when "re-apply everything on every boot" was the
    # rule, minus the one known to be one-way. They keep that behaviour,
    # because some of them double as boot-time backfills.
    #
    # Every step added after them runs exactly once. Re-running is the unsafe
    # default: step 28 showed that a one-way step nobody remembered to list
    # corrupts data on every start. A new step that really is an idempotent
    # backfill opts in by being added here, where the choice is visible.
    _REAPPLIED_EVERY_BOOT = frozenset(range(2, 31)) - _EXACTLY_ONCE_MIGRATIONS

    def _run_atomic_migration(
        self,
        c: sqlite3.Cursor,
        *,
        target_version: int,
        apply,
        current_version: Optional[int] = None,
        exactly_once: bool = False,
    ) -> None:
        """Apply ``apply(cursor)`` and (if first-time-crossing) stamp
        ``target_version`` in one transaction.

        Most migration steps are idempotent — they use ``CREATE ... IF
        NOT EXISTS`` and PRAGMA-introspected ``ALTER TABLE``, and a few
        also serve as boot-time backfills (e.g. v2's root_id sweep).
        Those are always run, so backfills keep healing any drifted
        rows, and only the version stamp is first-crossing-only. The
        whole thing is wrapped in a single ``BEGIN IMMEDIATE`` so a
        crash mid-step rolls back cleanly — no half-applied DDL with a
        stale version stamp.

        A step that is NOT idempotent passes ``exactly_once=True`` and is
        skipped once the database has reached its version. The stamp is
        written in the same transaction as the step, so "reached its
        version" and "the step was applied" are one fact.
        """
        if current_version is None:
            row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current_version = (
                row[0] if row and row[0] is not None else 0
            )
        if exactly_once and current_version >= target_version:
            return
        c.execute("BEGIN IMMEDIATE")
        try:
            apply(c)
            if current_version < target_version:
                c.execute(
                    "INSERT INTO schema_version(version) VALUES(?)",
                    (target_version,),
                )
            c.execute("COMMIT")
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                # Preserve the migration's original exception, but never hide
                # that rollback itself failed: the connection may now need to
                # be discarded before any further schema work is attempted.
                log.critical(
                    "schema migration v%s rollback failed; database "
                    "transaction state is uncertain",
                    target_version,
                    exc_info=True,
                )
            raise

    def _migrate_v16_route_memory(self, c: sqlite3.Cursor) -> None:
        """v0.14.2: durable route memory for adaptive transfers."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS route_memory (
                peer_fp       TEXT NOT NULL,
                route         TEXT NOT NULL,
                attempts      INTEGER NOT NULL,
                successes     INTEGER NOT NULL,
                failures      INTEGER NOT NULL,
                score         REAL NOT NULL,
                latency_ms    REAL,
                bandwidth_bps REAL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(peer_fp, route)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_memory_peer "
            "ON route_memory(peer_fp, updated_ms)"
        )

    def _migrate_v17_route_candidates(self, c: sqlite3.Cursor) -> None:
        """Durable concrete route candidates for the universal fabric.

        route_memory scores broad route families. route_candidates remembers
        actual dial targets learned from verified sessions, endpoint updates,
        signed QR/audio/BLE route tokens, and future transports. A route
        candidate is not trusted because it exists; callers still do the
        normal pinned-key handshake before promotion/use.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS route_candidates (
                peer_fp       TEXT NOT NULL,
                route         TEXT NOT NULL,
                transport     TEXT NOT NULL,
                host          TEXT NOT NULL,
                port          INTEGER NOT NULL,
                source        TEXT NOT NULL,
                verified      INTEGER NOT NULL DEFAULT 0,
                attempts      INTEGER NOT NULL DEFAULT 0,
                successes     INTEGER NOT NULL DEFAULT 0,
                failures      INTEGER NOT NULL DEFAULT 0,
                latency_ms    REAL,
                bandwidth_bps REAL,
                last_error    TEXT,
                first_seen_ms INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                expires_ms    INTEGER,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(peer_fp, route, transport, host, port)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_candidates_peer "
            "ON route_candidates(peer_fp, verified, updated_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_candidates_expiry "
            "ON route_candidates(expires_ms)"
        )

    def _migrate_v18_personal_device_mesh(self, c: sqlite3.Cursor) -> None:
        """Phase F5: Personal Device Mesh persistence.

        self_mesh_devices stores separately addressable devices under a
        shared root identity. self_mesh_presence stores LWW presence
        facts. remote_instruction_seen is the replay wall for signed
        phone-to-laptop command envelopes.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_devices (
                root_pub      BLOB NOT NULL,
                device_pub    BLOB NOT NULL,
                cert          BLOB,
                device_kind   TEXT NOT NULL,
                label         TEXT NOT NULL DEFAULT '',
                local         INTEGER NOT NULL DEFAULT 0,
                trusted       INTEGER NOT NULL DEFAULT 1,
                revoked       INTEGER NOT NULL DEFAULT 0,
                added_ms      INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(root_pub, device_pub)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_devices_root "
            "ON self_mesh_devices(root_pub, revoked, updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_presence (
                device_pub     BLOB PRIMARY KEY,
                state          TEXT NOT NULL,
                sequence       INTEGER NOT NULL,
                updated_ms     INTEGER NOT NULL,
                battery_pct    INTEGER,
                network        TEXT NOT NULL DEFAULT 'unknown',
                free_bytes     INTEGER,
                route          TEXT,
                latency_ms     REAL,
                bandwidth_bps  REAL,
                metadata_json  TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_presence_state "
            "ON self_mesh_presence(state, updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS remote_instruction_seen (
                command_id            TEXT PRIMARY KEY,
                first_seen_ms         INTEGER NOT NULL,
                expires_ms            INTEGER NOT NULL,
                action                TEXT NOT NULL DEFAULT '',
                controller_device_pub BLOB,
                target_device_pub     BLOB
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_remote_instruction_expiry "
            "ON remote_instruction_seen(expires_ms)"
        )

    def _migrate_v19_self_mesh_enrollment(self, c: sqlite3.Cursor) -> None:
        """Phase F5 continuation: enrollment roots + audit trail."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_roots (
                root_pub      BLOB PRIMARY KEY,
                label         TEXT NOT NULL DEFAULT '',
                root_seed     BLOB,
                created_ms    INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_roots_updated "
            "ON self_mesh_roots(updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_audit (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                event                 TEXT NOT NULL,
                severity              TEXT NOT NULL DEFAULT 'info',
                root_pub              BLOB,
                device_pub            BLOB,
                peer_fp               TEXT,
                command_id            TEXT,
                action                TEXT,
                path                  TEXT,
                detail                TEXT NOT NULL DEFAULT '',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_audit_ts "
            "ON self_mesh_audit(ts_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_audit_root "
            "ON self_mesh_audit(root_pub, ts_ms)"
        )

    def _migrate_v20_self_mesh_performance(self, c: sqlite3.Cursor) -> None:
        """Phase F5 polish: persisted performance telemetry."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_perf_samples (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                route_probe_runs      INTEGER NOT NULL DEFAULT 0,
                route_probe_ready     INTEGER NOT NULL DEFAULT 0,
                route_probe_total_ms  REAL NOT NULL DEFAULT 0,
                route_probe_avg_ms    REAL NOT NULL DEFAULT 0,
                presence_rows         INTEGER NOT NULL DEFAULT 0,
                device_rows           INTEGER NOT NULL DEFAULT 0,
                recent_audit_rows     INTEGER NOT NULL DEFAULT 0,
                status                TEXT NOT NULL DEFAULT 'unknown',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_perf_samples_ts "
            "ON self_mesh_perf_samples(ts_ms)"
        )

    def _migrate_v21_device_guardian(self, c: sqlite3.Cursor) -> None:
        """Device Guardian: anti-theft safety state + tamper-evident events."""
        cols = {r[1] for r in c.execute("PRAGMA table_info(self_mesh_devices)").fetchall()}
        if "safety_state" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_state TEXT NOT NULL DEFAULT 'trusted'"
            )
        if "safety_updated_ms" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_updated_ms INTEGER NOT NULL DEFAULT 0"
            )
        if "guardian_epoch" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN guardian_epoch INTEGER NOT NULL DEFAULT 0"
            )
        if "safety_reason" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_reason TEXT NOT NULL DEFAULT ''"
            )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS device_guardian_events (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                root_pub              BLOB NOT NULL,
                device_pub            BLOB NOT NULL,
                actor_device_pub      BLOB,
                from_state            TEXT NOT NULL,
                to_state              TEXT NOT NULL,
                decision              TEXT NOT NULL,
                reason                TEXT NOT NULL DEFAULT '',
                proofs_json           TEXT NOT NULL DEFAULT '[]',
                effects_json          TEXT NOT NULL DEFAULT '[]',
                event_hash            TEXT NOT NULL,
                prev_hash             TEXT NOT NULL DEFAULT '',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_guardian_events_device "
            "ON device_guardian_events(root_pub, device_pub, ts_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_guardian_events_hash "
            "ON device_guardian_events(event_hash)"
        )
        c.execute(
            """
            UPDATE self_mesh_devices
            SET safety_state = 'revoked',
                safety_updated_ms = CASE
                    WHEN safety_updated_ms = 0 THEN updated_ms
                    ELSE safety_updated_ms
                END,
                safety_reason = CASE
                    WHEN safety_reason = '' THEN 'backfilled from revoked flag'
                    ELSE safety_reason
                END
            WHERE revoked = 1 AND safety_state != 'revoked'
            """
        )

    def _migrate_v25_pending_folder_offers(self, c: sqlite3.Cursor) -> None:
        """v0.21.x folder-share ceremony: queue of folder manifests
        peers have offered us that we haven't accepted yet.

        Pre-v0.21.x, when peer A sent MANIFEST_PUSH for a folder that
        the receiving daemon B didn't already have registered locally,
        B silently dropped the frame. That meant 'Share' on the
        sender's UI did nothing visible on the receiver — there was
        no mechanism to PROPOSE sharing a new folder.

        This table caches such proposals so the receiver's UI can
        show 'Peer X wants to share folder Y (147 files, 50 MB) —
        pick where to save it on this device. [Accept] [Decline]'.

        Schema:
          id              INTEGER PRIMARY KEY AUTOINCREMENT
          peer_fp         TEXT    NOT NULL  -- sender's fingerprint
          folder_name     TEXT    NOT NULL  -- proposed folder name
          merkle_root     TEXT              -- sender's manifest root
          entries_json    TEXT    NOT NULL  -- serialized manifest entries
          entry_count     INTEGER NOT NULL  -- denormalized for UI
          total_bytes     INTEGER NOT NULL  -- denormalized for UI
          offered_ms      INTEGER NOT NULL  -- when we received the offer
          state           TEXT    NOT NULL  -- 'pending' | 'accepted' | 'declined'
          decided_ms      INTEGER           -- when user accepted/declined
          local_path      TEXT              -- chosen path (set on accept)

        UNIQUE(peer_fp, folder_name) so a re-offer of the same folder
        from the same peer updates the existing row instead of
        accumulating duplicates. State='accepted' or 'declined' rows
        are kept for audit until the user clears them.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_folder_offers (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_fp       TEXT    NOT NULL,
                folder_name   TEXT    NOT NULL,
                merkle_root   TEXT,
                entries_json  TEXT    NOT NULL,
                entry_count   INTEGER NOT NULL,
                total_bytes   INTEGER NOT NULL,
                offered_ms    INTEGER NOT NULL,
                state         TEXT    NOT NULL DEFAULT 'pending',
                decided_ms    INTEGER,
                local_path    TEXT,
                UNIQUE(peer_fp, folder_name)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_folder_offers_state"
            " ON pending_folder_offers(state, offered_ms)"
        )

    def _migrate_v26_folder_lifecycle_audit(self, c: sqlite3.Cursor) -> None:
        """v0.21.x activity-feed completeness: durable record of every
        folder-level lifecycle transition so the activity sidecar can
        show a sender's "Sent papers to kelly · 147 files · archive
        (61% smaller)" row alongside the per-file transfer rows.

        Pre-v26, manifest_push folder sends produced ZERO activity
        rows (chunks aren't recorded as transfers) and archive sends
        looked indistinguishable from a regular file send. This audit
        table is the source of truth for:

          - folder offers sent + received
          - folder offers accepted + declined (both directions)
          - folder sends complete + failed + cancelled (any mode)
          - folder send retry attempts
          - mode-selected by auto-router

        Schema:
          id             INTEGER PRIMARY KEY AUTOINCREMENT
          ts_ms          INTEGER NOT NULL  -- when the event happened
          direction      TEXT    NOT NULL  -- 'in' or 'out'
          event          TEXT    NOT NULL  -- see kinds below
          folder_name    TEXT    NOT NULL  -- which folder
          peer_fp        TEXT              -- counterparty (NULL for local-only)
          mode           TEXT              -- 'archive' | 'manifest_push' | 'per_file'
          file_count     INTEGER           -- entries in the folder
          total_bytes    INTEGER           -- pre-compression
          sent_bytes     INTEGER           -- actually-on-the-wire
          dedup_bytes    INTEGER           -- skipped due to peer-side dedup
          duration_ms    INTEGER           -- end-to-end time
          severity       TEXT    NOT NULL DEFAULT 'info'
          error_msg      TEXT              -- on failure paths
          metadata_json  TEXT              -- mode-specific extras

        Events:
          offer_sent | offer_received
          offer_accepted | offer_declined     (BOTH directions; direction
                                               column says who acted)
          send_started | send_complete
          send_failed | send_cancelled
          send_retry
          mode_selected (auto-router told us what it picked)

        Indexed on (ts_ms DESC) for activity-feed reads and on
        (folder_name, peer_fp) for per-folder drill-in.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS folder_lifecycle_audit (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms         INTEGER NOT NULL,
                direction     TEXT    NOT NULL,
                event         TEXT    NOT NULL,
                folder_name   TEXT    NOT NULL,
                peer_fp       TEXT,
                mode          TEXT,
                file_count    INTEGER,
                total_bytes   INTEGER,
                sent_bytes    INTEGER,
                dedup_bytes   INTEGER,
                duration_ms   INTEGER,
                severity      TEXT    NOT NULL DEFAULT 'info',
                error_msg     TEXT,
                metadata_json TEXT
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_folder_lifecycle_audit_ts"
            " ON folder_lifecycle_audit(ts_ms DESC)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_folder_lifecycle_audit_fp"
            " ON folder_lifecycle_audit(peer_fp, ts_ms DESC)"
        )

    def _migrate_v27_ui_sessions(self, c: sqlite3.Cursor) -> None:
        """v0.21.x persistent UI sessions: every successful ?t=<token>
        bootstrap mints a row here keyed by a random uuid. The uuid
        rides in a SameSite=Strict HttpOnly cookie that SURVIVES
        daemon restarts (state.db persists; the cookie does too).

        Pre-v27, the daemon's UI token rotates whenever the on-disk
        ui.token file can't be reloaded (lockbox key drift, file
        deleted, etc.). Old browser tabs + bookmarked URLs all stop
        working — users hit a dead-end 'access denied' page. The
        session table sidesteps the rotation: as long as the cookie
        is still valid (in this table), the daemon accepts it
        regardless of what ui.token says.

        Schema:
          id              INTEGER PRIMARY KEY AUTOINCREMENT
          session_uuid    TEXT    NOT NULL UNIQUE
          created_ms      INTEGER NOT NULL
          last_seen_ms    INTEGER NOT NULL
          revoked_ms      INTEGER           -- soft-delete via revoke
          user_agent_hash TEXT              -- truncated SHA256 of UA
                                            -- (privacy-preserving
                                            -- device label for the
                                            -- 'Active sessions' list)
          label           TEXT              -- best-effort human label
                                            -- ('Edge on Windows')
          remote_first    TEXT              -- IP the cookie was first
                                            -- minted from (loopback /
                                            -- LAN — never leaves the
                                            -- machine but lets the
                                            -- user audit)

        Index session_uuid for O(1) cookie lookups.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS ui_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_uuid    TEXT    NOT NULL UNIQUE,
                created_ms      INTEGER NOT NULL,
                last_seen_ms    INTEGER NOT NULL,
                revoked_ms      INTEGER,
                user_agent_hash TEXT,
                label           TEXT,
                remote_first    TEXT
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_ui_sessions_uuid"
            " ON ui_sessions(session_uuid)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_ui_sessions_active"
            " ON ui_sessions(revoked_ms, last_seen_ms DESC)"
        )

    def _migrate_v28_ui_session_token_hashes(self, c: sqlite3.Cursor) -> None:
        """Replace persistent UI bearer tokens with one-way record keys.

        v27 stored the exact HttpOnly cookie value in ``state.db``. A local
        database disclosure could therefore be replayed directly against a
        running daemon. Tokens are 256-bit random values, so a domain-separated
        SHA-256 record key is sufficient: lookup remains O(1), while the value
        at rest is no longer a bearer credential. Hashing a record key a second
        time would invalidate every outstanding browser session, so this step
        is listed in ``_EXACTLY_ONCE_MIGRATIONS``: the runner applies it only
        on the boot that first crosses v28. (The schema version alone did not
        make it exactly-once: the runner re-applies ordinary steps on every
        boot, and until that set existed it re-applied this one too.)
        """
        rows = c.execute(
            "SELECT id, session_uuid FROM ui_sessions"
        ).fetchall()
        for row in rows:
            token = str(row["session_uuid"] or "")
            record_key = self.ui_session_token_id(token)
            if record_key is None:
                # A malformed row could never authenticate through the HTTP
                # validator. Remove it instead of preserving attacker-chosen
                # junk in the credential index.
                c.execute("DELETE FROM ui_sessions WHERE id=?", (int(row["id"]),))
                continue
            c.execute(
                "UPDATE ui_sessions SET session_uuid=? WHERE id=?",
                (record_key, int(row["id"])),
            )

    def _migrate_v29_file_index_identity(self, c: sqlite3.Cursor) -> None:
        """Bind cached hashes/manifests to stable file-object identity.

        Path, size, and timestamps are not sufficient on Windows: ``st_ctime``
        is creation time, and a same-size rewrite can restore ``mtime``. Device
        + inode/file ID + NT change time prevent stale content proofs from
        being reused after replacement or in-place mutation. Existing cache
        rows deliberately miss once after migration because they lack that
        evidence.
        """

        columns = {
            str(row[1])
            for row in c.execute("PRAGMA table_info(file_index_cache)").fetchall()
        }
        additions = (
            ("device_id", "TEXT NOT NULL DEFAULT ''"),
            ("inode_id", "TEXT NOT NULL DEFAULT ''"),
            ("file_id", "TEXT NOT NULL DEFAULT ''"),
            ("change_ns", "TEXT NOT NULL DEFAULT ''"),
            ("index_mode", "TEXT NOT NULL DEFAULT ''"),
        )
        for name, declaration in additions:
            if name not in columns:
                c.execute(
                    f"ALTER TABLE file_index_cache ADD COLUMN {name} {declaration}"
                )

    def _migrate_v30_folder_pending_applies(self, c: sqlite3.Cursor) -> None:
        """Crash-replay journal for remote folder filesystem mutations.

        A committed CRDT winner and its replace/delete preconditions must be
        recoverable as one durable generation.  The journal tracks the exact
        target plus any internal staging/recovery leaf names across the small
        filesystem windows that SQLite cannot make transactional.
        """

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS folder_pending_applies (
                apply_id               TEXT PRIMARY KEY,
                folder_name            TEXT NOT NULL,
                file_path              TEXT NOT NULL,
                operation              TEXT NOT NULL
                    CHECK(operation IN ('materialize', 'delete')),
                target_blob_hash       TEXT,
                target_size            INTEGER,
                target_mtime_ms        INTEGER,
                target_vclock_json     TEXT NOT NULL,
                baseline_blob_hash     TEXT,
                baseline_evidence_json TEXT,
                phase                  TEXT NOT NULL
                    CHECK(phase IN (
                        'planned', 'staging', 'recovery_prepared',
                        'recovery_moved', 'publish_prepared', 'published',
                        'unlink_prepared'
                    )),
                staging_name           TEXT,
                recovery_name          TEXT,
                attempts               INTEGER NOT NULL DEFAULT 0
                    CHECK(attempts >= 0),
                last_error             TEXT,
                created_ms             INTEGER NOT NULL,
                updated_ms             INTEGER NOT NULL,
                UNIQUE(folder_name, file_path),
                FOREIGN KEY(folder_name) REFERENCES folders(name)
                    ON DELETE CASCADE,
                CHECK(
                    (operation = 'materialize' AND target_blob_hash IS NOT NULL)
                    OR (operation = 'delete' AND target_blob_hash IS NULL)
                )
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_folder_pending_applies_folder "
            "ON folder_pending_applies(folder_name, updated_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_folder_manifest_blob_hash "
            "ON folder_manifest(blob_hash, folder_name, file_path) "
            "WHERE blob_hash IS NOT NULL"
        )

    def _migrate_v24_held_recovery_shares(self, c: sqlite3.Cursor) -> None:
        """v0.21.x social-share recovery: guardian-side store of
        recovery shares the user is holding for someone else.

        When user X distributes Shamir shares of their identity to
        guardians, each guardian receives an .olss file. This table
        is the guardian's daemon's record of WHICH shares it holds
        + the metadata needed to surface them in the UI ('You hold
        share 3 of 5 for someone identified by SHA-256(master_pubkey)
        starting ab12...'). The wrapped blob stays sealed to the
        guardian's Ed25519 identity; only the guardian's daemon can
        unwrap it when the original user asks for recovery help.

        Schema:
          id                    INTEGER PRIMARY KEY AUTOINCREMENT
          share_index           INTEGER NOT NULL    -- 1..total_n
          threshold_k           INTEGER NOT NULL    -- K of N
          total_n               INTEGER NOT NULL
          setup_ms              INTEGER NOT NULL    -- when share was minted
          wrapped_blob          BLOB    NOT NULL    -- full .olss bytes
          imported_ms           INTEGER NOT NULL    -- when guardian imported
          label                 TEXT                -- user-supplied note
          owner_hint            TEXT                -- short fp of owner if known

        Indexed on imported_ms so list views fall back to insertion
        order naturally.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS held_recovery_shares (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                share_index    INTEGER NOT NULL,
                threshold_k    INTEGER NOT NULL,
                total_n        INTEGER NOT NULL,
                setup_ms       INTEGER NOT NULL,
                wrapped_blob   BLOB    NOT NULL,
                imported_ms    INTEGER NOT NULL,
                label          TEXT,
                owner_hint     TEXT
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_held_shares_imported"
            " ON held_recovery_shares(imported_ms)"
        )

    def _migrate_v23_rotation_announcements(self, c: sqlite3.Cursor) -> None:
        """v0.21.x identity rotation: per-peer queue of rotation
        certificates we owe delivery + ack on.

        One row per (peer, rotation cert) the local daemon wants the
        peer to apply. The background delivery task drains rows where
        ``acked_ms IS NULL`` and updates ``last_attempt_ms`` on each
        send. The inbound ack handler sets ``acked_ms`` when the peer
        confirms application, at which point the UI can shrink the
        'X of Y peers acknowledged your new key' counter.

        Cert blob is stored as the wire JSON (cert_json + sig_hex
        glued back together) so a replay of the canonical bytes
        through Ed25519 verify still passes. Rows survive daemon
        restart - this is the durable queue.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_rotation_announcements (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_fp         TEXT    NOT NULL,
                old_fp          TEXT    NOT NULL,
                new_fp          TEXT    NOT NULL,
                cert_json       TEXT    NOT NULL,
                sig_hex         TEXT    NOT NULL,
                queued_ms       INTEGER NOT NULL,
                last_attempt_ms INTEGER,
                attempt_count   INTEGER NOT NULL DEFAULT 0,
                acked_ms        INTEGER
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_pra_peer_unacked"
            " ON pending_rotation_announcements(peer_fp, acked_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_pra_unacked"
            " ON pending_rotation_announcements(acked_ms)"
        )

    def _migrate_v22_transfer_status_index(self, c: sqlite3.Cursor) -> None:
        """2026-05-22 audit Batch V — composite ``(status, updated_ms)``
        index on ``transfers``. ``prune_transfers`` filters on status
        and on a long ledger that becomes a full table scan; the
        composite index lets the planner serve the prune query with
        an index seek + bounded updated_ms range. ``IF NOT EXISTS``
        guards fresh DBs (which already created it via the schema
        bootstrap)."""
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfers_status "
            "ON transfers(status, updated_ms)"
        )

    def _migrate_v15_file_index_cache(self, c: sqlite3.Cursor) -> None:
        """v0.12.4: durable file fingerprint/manifest cache.

        Large-file sends should not re-hash and re-index an unchanged file
        every time the user sends it. The cache is keyed by canonical path and
        guarded by file size + nanosecond mtimes/ctimes, so a stale row is
        ignored automatically when the file changes.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS file_index_cache (
                path        TEXT PRIMARY KEY,
                size        INTEGER NOT NULL,
                mtime_ns    INTEGER NOT NULL,
                ctime_ns    INTEGER NOT NULL,
                blob_hash   TEXT    NOT NULL,
                index_kind  TEXT    NOT NULL,
                chunks_json TEXT    NOT NULL,
                updated_ms  INTEGER NOT NULL
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_index_cache_updated "
            "ON file_index_cache(updated_ms)"
        )

    def _migrate_v14_mute_until(self, c: sqlite3.Cursor) -> None:
        """v0.11.2: per-chat mute with duration.

        peers.muted_until_ms — wall-clock ms after which the mute
        auto-expires. NULL = not muted. 0 = muted forever (no auto-
        expire). N > 0 = muted until ts N. The legacy `muted` boolean
        column from v0.7.3 stays in place for back-compat but is now
        a derived value (muted_until_ms IS NOT NULL AND
        (muted_until_ms = 0 OR muted_until_ms > now)).

        Group mutes use the existing settings table keyed as
        `group_mute:<group_id_hex>` = until_ms — no schema change
        needed for the group case."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "muted_until_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN muted_until_ms INTEGER")

    def _migrate_v13_prior_chunk_sources(self, c: sqlite3.Cursor) -> None:
        """v0.10.3: path-backed chunk sources for prior knowledge transfer.

        The chunk cache stores bytes only after a chunk is actually needed.
        This table lets the daemon remember that a verified chunk exists in a
        local inbox/sync-folder file at a byte range, then hydrate it lazily.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_sources (
                chunk_hash TEXT NOT NULL,
                path       TEXT NOT NULL,
                start      INTEGER NOT NULL,
                size       INTEGER NOT NULL,
                mtime_ms   INTEGER NOT NULL,
                file_size  INTEGER NOT NULL,
                source     TEXT NOT NULL DEFAULT 'prior',
                updated_ms INTEGER NOT NULL,
                PRIMARY KEY(chunk_hash, path, start)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_sources_hash "
            "ON chunk_sources(chunk_hash)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_sources_updated "
            "ON chunk_sources(updated_ms)"
        )

    def _migrate_v12_disappearing_messages(self, c: sqlite3.Cursor) -> None:
        """v0.10.2: per-peer disappearing-message TTL.

        peers.dm_ttl_ms — when set, every TEXT message exchanged with
        this peer carries an expires_at_ms = ts_ms + dm_ttl_ms. None
        = TTL off (default). Both ends must support v12 for end-to-end
        expiry — receivers running older builds keep the message
        forever; sender's local copy still expires.

        messages.expires_at_ms — wall-clock ms when this row should
        be tombstoned. NULL = never expires (legacy + non-TTL chats).
        Indexed for fast reaper sweeps."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "dm_ttl_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN dm_ttl_ms INTEGER")
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "expires_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER")
        # Partial index — only rows with non-NULL expires_at_ms are
        # candidates for the reaper sweep, so a partial index keeps
        # the index page footprint tiny on chats that never use TTL.
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_expiry "
            "ON messages(expires_at_ms) "
            "WHERE expires_at_ms IS NOT NULL"
        )

    def _migrate_v11_chunk_availability(self, c: sqlite3.Cursor) -> None:
        """v0.9.x: local chunk availability index for swarm transfer."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_availability (
                chunk_hash  TEXT PRIMARY KEY,
                size        INTEGER NOT NULL,
                blob_hash   TEXT,
                chunk_index INTEGER,
                source      TEXT NOT NULL DEFAULT 'local',
                updated_ms  INTEGER NOT NULL
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_availability_blob "
            "ON chunk_availability(blob_hash)"
        )

    def _migrate_v10_folder_conflicts(self, c: sqlite3.Cursor) -> None:
        """v0.8.9: track CRDT-detected concurrent edits to the same
        file path. Today merge_manifest_entries silently latest-wins
        on the concurrent case; v0.8.9 records both sides so the user
        can override via the Folders → Conflicts UI. Idempotent."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS manifest_conflicts (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_name         TEXT    NOT NULL,
                file_path           TEXT    NOT NULL,
                detected_ms         INTEGER NOT NULL,
                peer_fp             TEXT,
                -- local snapshot at detection time
                local_blob_hash     TEXT,
                local_size          INTEGER,
                local_mtime_ms      INTEGER,
                local_vclock_json   TEXT    NOT NULL,
                -- remote snapshot
                remote_blob_hash    TEXT,
                remote_size         INTEGER,
                remote_mtime_ms     INTEGER,
                remote_vclock_json  TEXT    NOT NULL,
                -- which side was applied as the auto-merge winner
                applied_choice      TEXT    NOT NULL,
                -- user resolution
                resolved_ms         INTEGER,
                resolution          TEXT,
                resolved_by         TEXT
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_mc_folder"
            " ON manifest_conflicts(folder_name)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_mc_unresolved"
            " ON manifest_conflicts(resolved_ms)"
        )

    def _migrate_v9_key_change_tracking(self, c: sqlite3.Cursor) -> None:
        """v0.7.8: track every (hostname, ed_pub_hex) ever observed
        + log conflict events when a hostname rotates pubkeys (the
        re-install / MITM scenario). Idempotent."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS hostname_keys (
                hostname      TEXT    NOT NULL,
                ed_pub_hex    TEXT    NOT NULL,
                fingerprint   TEXT    NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                PRIMARY KEY (hostname, ed_pub_hex)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_hostname_keys_host"
            " ON hostname_keys(hostname)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS key_change_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms           INTEGER NOT NULL,
                hostname        TEXT    NOT NULL,
                old_fingerprint TEXT    NOT NULL,
                new_fingerprint TEXT    NOT NULL,
                old_pub_hex     TEXT    NOT NULL,
                new_pub_hex     TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                acked_ms        INTEGER
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_kce_acked"
            " ON key_change_events(acked_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_kce_new_fp"
            " ON key_change_events(new_fingerprint)"
        )

    def _migrate_v8_peer_verification(self, c: sqlite3.Cursor) -> None:
        """v0.7.7: peers gain side-channel verification state.
        Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "verified_at_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_at_ms INTEGER")
        if "verified_method" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_method TEXT")
        if "verified_note" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_note TEXT")

    def _migrate_v6_group_reply(self, c: sqlite3.Cursor) -> None:
        """v0.8.2: group messages gain reply_to for threaded context."""
        rows = c.execute("PRAGMA table_info(group_messages)").fetchall()
        existing = {row[1] for row in rows}
        if "reply_to" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN reply_to TEXT")

    def _migrate_v7_group_edit_delete(self, c: sqlite3.Cursor) -> None:
        """v0.8.2: group messages gain edit/delete state."""
        rows = c.execute("PRAGMA table_info(group_messages)").fetchall()
        existing = {row[1] for row in rows}
        if "edited_at_ms" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN edited_at_ms INTEGER")
        if "original_body" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN original_body TEXT")
        if "deleted_at_ms" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN deleted_at_ms INTEGER")

    def _migrate_v5_edit_delete_read(self, c: sqlite3.Cursor) -> None:
        """v0.7.6: add edit_at_ms / original_body / deleted_at_ms
        columns to messages, plus a peer_read_markers table for
        receipt tracking. Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "edited_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN edited_at_ms INTEGER")
        if "original_body" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN original_body TEXT")
        if "deleted_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN deleted_at_ms INTEGER")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS peer_read_markers (
                peer_fp        TEXT    PRIMARY KEY,
                up_to_ts_ms    INTEGER NOT NULL,
                updated_ms     INTEGER NOT NULL
            )
            """
        )

    def schema_version(self) -> int:
        """Return the latest applied schema version.

        Exposed through daemon status so launchers and UIs can detect a
        stale backend before the user hits a broken feature path.
        """
        try:
            row = self._conn.execute(
                "SELECT MAX(version) AS version FROM schema_version"
            ).fetchone()
            return int(row["version"] or 0) if row else 0
        except Exception:
            return 0

    def _migrate_v4_messages_reply_to(self, c: sqlite3.Cursor) -> None:
        """v0.7.5: messages.reply_to is the parent msg_id when a row
        is a reply/quote. Idempotent."""
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "reply_to" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN reply_to TEXT")

    def _migrate_v3_peer_profile(self, c: sqlite3.Cursor) -> None:
        """v0.7.3: add per-peer profile columns. local_alias is a
        user-set name override that wins over remote-advertised
        hostname in the UI. muted suppresses desktop notifications
        for messages from this peer (no protocol effect).
        Idempotent."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "local_alias" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN local_alias TEXT")
        if "muted" not in existing:
            c.execute(
                "ALTER TABLE peers ADD COLUMN muted INTEGER NOT NULL DEFAULT 0"
            )

    def _migrate_v2_folder_sandboxes(self, c: sqlite3.Cursor) -> None:
        """Add per-folder sandbox columns: root_id (stable id),
        max_file_bytes (size cap), ignored_patterns_json (deny-list
        globs), conflict_policy (latest-wins | local-priority |
        peer-priority). Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(folders)").fetchall()
        existing = {row[1] for row in rows}  # column name index
        if "root_id" not in existing:
            c.execute("ALTER TABLE folders ADD COLUMN root_id TEXT")
        if "max_file_bytes" not in existing:
            c.execute("ALTER TABLE folders ADD COLUMN max_file_bytes INTEGER")
        if "ignored_patterns_json" not in existing:
            c.execute(
                "ALTER TABLE folders ADD COLUMN ignored_patterns_json"
                " TEXT NOT NULL DEFAULT '[]'"
            )
        if "conflict_policy" not in existing:
            c.execute(
                "ALTER TABLE folders ADD COLUMN conflict_policy"
                " TEXT NOT NULL DEFAULT 'latest-wins'"
            )
        # Backfill root_id for any folder still missing one — needed
        # the moment we start writing it into folder_audit rows.
        rows = c.execute(
            "SELECT name FROM folders WHERE root_id IS NULL OR root_id = ''"
        ).fetchall()
        for row in rows:
            new_id = uuid.uuid4().hex
            c.execute(
                "UPDATE folders SET root_id = ? WHERE name = ?",
                (new_id, row["name"]),
            )

    # ─── peers ────────────────────────────────────────────────────────

    def upsert_peer(
        self,
        *,
        fingerprint: str,
        short_id: str,
        pubkey: bytes,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: Optional[int] = None,
        trust_default: str = "pending",
    ) -> PeerRecord:
        now = _now_ms()
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.execute(
                    """
                    INSERT INTO peers(fingerprint, short_id, pubkey, hostname,
                        last_address, last_port, trust, first_seen_ms, last_seen_ms)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        short_id     = excluded.short_id,
                        pubkey       = excluded.pubkey,
                        hostname     = COALESCE(excluded.hostname, peers.hostname),
                        last_address = COALESCE(excluded.last_address, peers.last_address),
                        last_port    = COALESCE(excluded.last_port, peers.last_port),
                        last_seen_ms = excluded.last_seen_ms
                    """,
                    (
                        fingerprint, short_id, pubkey, hostname,
                        address, port, trust_default, now, now,
                    ),
                )
                row = c.execute(
                    "SELECT * FROM peers WHERE fingerprint = ?", (fingerprint,)
                ).fetchone()
                # v0.7.8: track hostname↔key history + raise a key-change
                # event whenever a hostname rotates fingerprints. The
                # detection happens here (post-INSERT) so it covers every
                # code path that upserts a peer (handshake, discovery,
                # snapshot rehydration). pubkey is bytes — convert once.
                # The new-event id (if any) is stashed on the returned
                # PeerRecord via `_pending_key_change_event_id` so the
                # daemon can broadcast it without a second query.
                new_event_id: Optional[int] = None
                if hostname:
                    try:
                        ed_pub_hex = pubkey.hex() if isinstance(pubkey, (bytes, bytearray)) else str(pubkey)
                        new_event_id = self._record_hostname_key_seen_locked(
                            c=c,
                            hostname=hostname,
                            ed_pub_hex=ed_pub_hex,
                            fingerprint=fingerprint,
                            now=now,
                        )
                    except Exception:
                        # The new peer remains pending by default, so allowing
                        # the upsert is fail-closed for capabilities. Missing a
                        # hostname/key rotation alert is still security-
                        # relevant and must be visible immediately.
                        log.exception(
                            "SECURITY: hostname key-change tracking failed "
                            "for host=%r fingerprint=%s",
                            hostname,
                            fingerprint[:16],
                        )
                rec = self._row_to_peer(row)
                if new_event_id is not None:
                    # Attach as a runtime-only attribute; the dataclass
                    # itself is unchanged so callers that don't care
                    # see no difference.
                    object.__setattr__(rec, "_pending_key_change_event_id", new_event_id)
                return rec
            finally:
                c.close()

    def set_peer_trust(
        self,
        fingerprint: str,
        trust: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        if trust not in ("pinned", "pending", "rejected"):
            raise ValueError(f"invalid trust state: {trust!r}")
        applied_default_ttl = False
        with self._write_lock:
            row = self._conn.execute(
                "SELECT trust, dm_ttl_ms FROM peers WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            before = row["trust"] if row else None
            had_ttl = row and row["dm_ttl_ms"] is not None
            self._conn.execute(
                "UPDATE peers SET trust = ? WHERE fingerprint = ?",
                (trust, fingerprint),
            )
            if before != trust:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="trust_set",
                    before=before,
                    after=trust,
                    actor=actor,
                    note=note,
                )
            # v0.11.6: when transitioning to "pinned" for the first
            # time AND the user has a default disappearing-msg TTL
            # set globally AND this peer has no per-chat TTL, copy
            # the default in. This is the "applies to new pairings"
            # promise from the Storage settings pane.
            if (
                trust == "pinned"
                and before != "pinned"
                and not had_ttl
            ):
                raw = self._conn.execute(
                    "SELECT value FROM settings WHERE key = 'default_dm_ttl_ms'"
                ).fetchone()
                if raw is not None:
                    try:
                        default_ttl = int(raw["value"])
                    except (TypeError, ValueError):
                        default_ttl = 0
                    if default_ttl > 0:
                        self._conn.execute(
                            "UPDATE peers SET dm_ttl_ms = ? "
                            "WHERE fingerprint = ?",
                            (default_ttl, fingerprint),
                        )
                        applied_default_ttl = True
        # Returning intentionally None to preserve existing call
        # sites; applied_default_ttl is for tests + a future caller
        # that wants the signal.

    # Rows about a peer in these tables are route and hostname caches. They
    # are dropped together with a pruned pending peer. Every other table that
    # names a peer is history, and a peer with history is never pruned.
    _PENDING_PRUNE_CACHE_DELETES = {
        "route_memory": "DELETE FROM route_memory WHERE peer_fp = ?",
        "route_candidates": "DELETE FROM route_candidates WHERE peer_fp = ?",
        "hostname_keys": "DELETE FROM hostname_keys WHERE fingerprint = ?",
    }

    def _peer_history_tables_locked(self, c: sqlite3.Cursor) -> list[tuple[str, str]]:
        """Every ``(table, column)`` that ties stored history to a peer.

        Read from the live schema rather than a hand-kept list, so a table
        added later protects its peers from pruning without anyone having to
        remember this function exists.
        """
        cache_tables = set(self._PENDING_PRUNE_CACHE_DELETES)
        out: list[tuple[str, str]] = []
        names = [
            row[0]
            for row in c.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        ]
        for name in names:
            if name == "peers" or name in cache_tables or name.startswith("sqlite_"):
                continue
            quoted = name.replace('"', '""')
            columns = {
                row[1] for row in c.execute(f'PRAGMA table_info("{quoted}")').fetchall()
            }
            for column in ("peer_fp", "fingerprint"):
                if column in columns:
                    out.append((quoted, column))
        return out

    def prune_pending_peers(self, *, keep: int, protect: Iterable[str] = ()) -> int:
        """Delete surplus pending peers that never became anything.

        Anyone who completes a handshake gets a ``pending`` row, and a fresh
        identity costs the remote party nothing, so the count has to be
        bounded here. When more than ``keep`` pending rows exist, the least
        recently seen ones are deleted until the count fits, skipping any row
        the owner touched (alias, verification, mute), any fingerprint in
        ``protect`` (peers connected right now), and any peer that a history
        table still refers to. Pinned and rejected peers are never considered.

        Returns the number of peers deleted.
        """
        if keep < 0:
            raise ValueError("keep must not be negative")
        protected = set(protect)
        with self._write_lock:
            c = self._conn.cursor()
            try:
                total = c.execute(
                    "SELECT COUNT(*) FROM peers WHERE trust = 'pending'"
                ).fetchone()[0]
                surplus = int(total) - keep
                if surplus <= 0:
                    return 0
                history = self._peer_history_tables_locked(c)
                candidates = c.execute(
                    "SELECT fingerprint FROM peers"
                    " WHERE trust = 'pending'"
                    " AND local_alias IS NULL"
                    " AND verified_at_ms IS NULL"
                    " AND COALESCE(muted, 0) = 0"
                    " ORDER BY last_seen_ms ASC, first_seen_ms ASC"
                ).fetchall()
                victims: list[str] = []
                for row in candidates:
                    fp = row[0]
                    if fp in protected:
                        continue
                    # Table and column names come from this database's own
                    # schema (sqlite_master), quoted; the value is bound.
                    if any(
                        c.execute(
                            f'SELECT 1 FROM "{table}" WHERE "{column}" = ? LIMIT 1',  # nosec B608
                            (fp,),
                        ).fetchone()
                        for table, column in history
                    ):
                        continue
                    victims.append(fp)
                    if len(victims) >= surplus:
                        break
                if not victims:
                    return 0
                c.execute("BEGIN IMMEDIATE")
                try:
                    for fp in victims:
                        for delete_cached in self._PENDING_PRUNE_CACHE_DELETES.values():
                            with contextlib.suppress(*DB_OPERATIONAL_ERRORS):
                                c.execute(delete_cached, (fp,))
                        # A key-change alert that involved a pinned peer is
                        # 'high' and stays. The rest only ever compared two
                        # unpinned keys, one of which is now forgotten.
                        with contextlib.suppress(*DB_OPERATIONAL_ERRORS):
                            c.execute(
                                "DELETE FROM key_change_events"
                                " WHERE severity != 'high'"
                                " AND (old_fingerprint = ? OR new_fingerprint = ?)",
                                (fp, fp),
                            )
                        c.execute(
                            "DELETE FROM peers"
                            " WHERE fingerprint = ? AND trust = 'pending'",
                            (fp,),
                        )
                    c.execute("COMMIT")
                except BaseException:
                    c.execute("ROLLBACK")
                    raise
                return len(victims)
            finally:
                c.close()

    def get_peer(self, fingerprint: str) -> Optional[PeerRecord]:
        row = self._conn.execute(
            "SELECT * FROM peers WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return self._row_to_peer(row) if row else None

    def get_peer_by_short_id(self, short_id: str) -> Optional[PeerRecord]:
        """Resolve a short ID, or ``None`` when it does not name one peer.

        A short ID is 32 bits of the fingerprint, few enough that a second
        key with the same short ID can be ground out on purpose. A pinned
        peer therefore always wins over unpinned ones, and when the choice is
        still not unique the answer is ``None``: the caller has to use the
        full fingerprint rather than be handed whichever row came back first.
        """
        rows = self._conn.execute(
            "SELECT * FROM peers WHERE short_id = ?"
            " ORDER BY (trust = 'pinned') DESC, last_seen_ms DESC LIMIT 3",
            (short_id,),
        ).fetchall()
        if not rows:
            return None
        pinned = [r for r in rows if r["trust"] == "pinned"]
        if len(pinned) == 1:
            return self._row_to_peer(pinned[0])
        if pinned or len(rows) > 1:
            return None
        return self._row_to_peer(rows[0])

    def list_peers(self) -> list[PeerRecord]:
        rows = self._conn.execute(
            "SELECT * FROM peers ORDER BY last_seen_ms DESC"
        ).fetchall()
        return [self._row_to_peer(r) for r in rows]

    def recovery_safety_counts(self) -> dict[str, int]:
        """Return one consistent snapshot of state a restore can orphan.

        Recovery preflight is a destructive-operation guard, not a UI-only
        summary.  Keep the query inside :class:`State` so callers do not have
        to materialize every message/folder/device merely to learn whether an
        install is empty.  A single SQLite statement also gives all five
        counts from the same read snapshot while concurrent writers are
        active.

        Database errors intentionally propagate.  The recovery layer treats
        an unavailable safety snapshot as *not clean*; guessing zero here
        would turn a storage fault into permission to replace an identity.
        """
        row = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM peers WHERE trust = 'pinned')
                    AS pinned_peers,
                (SELECT COUNT(*) FROM messages) AS messages,
                (SELECT COUNT(*) FROM group_messages) AS group_messages,
                (SELECT COUNT(*) FROM groups) AS groups,
                (SELECT COUNT(*) FROM folders) AS shared_folders,
                (SELECT COUNT(*) FROM self_mesh_devices) AS self_mesh_devices,
                (SELECT COUNT(*) FROM transfers
                    WHERE status IN ('queued', 'offered', 'active', 'paused'))
                    AS pending_transfers,
                (SELECT COUNT(*) FROM outbox WHERE delivered_ms IS NULL)
                    AS pending_outbox,
                (SELECT COUNT(*) FROM pending_folder_offers
                    WHERE state = 'pending') AS pending_folder_offers,
                (SELECT COUNT(*) FROM pending_rotation_announcements
                    WHERE acked_ms IS NULL) AS pending_rotation_announcements,
                (SELECT COUNT(*) FROM held_recovery_shares)
                    AS held_recovery_shares
            """
        ).fetchone()
        if row is None:
            raise RuntimeError("recovery safety query returned no row")
        return {
            "pinned_peers": int(row["pinned_peers"] or 0),
            "messages": int(row["messages"] or 0),
            "group_messages": int(row["group_messages"] or 0),
            "groups": int(row["groups"] or 0),
            "shared_folders": int(row["shared_folders"] or 0),
            "self_mesh_devices": int(row["self_mesh_devices"] or 0),
            "pending_transfers": int(row["pending_transfers"] or 0),
            "pending_outbox": int(row["pending_outbox"] or 0),
            "pending_folder_offers": int(row["pending_folder_offers"] or 0),
            "pending_rotation_announcements": int(
                row["pending_rotation_announcements"] or 0
            ),
            "held_recovery_shares": int(row["held_recovery_shares"] or 0),
        }

    def update_handoff_safety_counts(self) -> dict[str, int]:
        """Return durable work that must finish before replacing the app.

        Queued and paused work is deliberately restart-safe.  ``offered`` and
        ``active`` rows may have remote commit state in flight, so an updater
        must defer until those rows reach a durable terminal/restartable state.
        Storage errors propagate and therefore fail the handoff closed.
        """

        row = self._conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM transfers
                    WHERE status IN ('offered', 'active')) AS active_transfers,
                (SELECT COUNT(*) FROM pending_folder_offers
                    WHERE state = 'pending') AS pending_folder_offers
            """
        ).fetchone()
        if row is None:
            raise RuntimeError("update handoff safety query returned no row")
        return {
            "active_transfers": int(row["active_transfers"] or 0),
            "pending_folder_offers": int(row["pending_folder_offers"] or 0),
        }

    def set_peer_capabilities(self, fingerprint: str, caps: Iterable[str]) -> None:
        values = sorted({str(c) for c in caps if str(c)})
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO peer_capabilities(fingerprint, caps_json, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    caps_json = excluded.caps_json,
                    updated_ms = excluded.updated_ms
                """,
                (fingerprint, json.dumps(values), _now_ms()),
            )

    def get_peer_capabilities(self, fingerprint: str) -> list[str]:
        row = self._conn.execute(
            "SELECT caps_json FROM peer_capabilities WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            return []
        try:
            return list(json.loads(row["caps_json"]))
        except Exception:
            return []

    def set_peer_capability_policy(
        self,
        fingerprint: str,
        allowed: Iterable[str],
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        values = sorted({str(c) for c in allowed if str(c)})
        with self._write_lock:
            before = self.get_peer_capability_policy(fingerprint)
            self._conn.execute(
                """
                INSERT INTO peer_capability_policy(fingerprint, allowed_json, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    allowed_json = excluded.allowed_json,
                    updated_ms = excluded.updated_ms
                """,
                (fingerprint, json.dumps(values), _now_ms()),
            )
            if before != values:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="cap_policy_set",
                    before=before,
                    after=values,
                    actor=actor,
                    note=note,
                )

    def clear_peer_capability_policy(
        self,
        fingerprint: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        with self._write_lock:
            before = self.get_peer_capability_policy(fingerprint)
            self._conn.execute(
                "DELETE FROM peer_capability_policy WHERE fingerprint = ?",
                (fingerprint,),
            )
            if before is not None:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="cap_policy_clear",
                    before=before,
                    after=None,
                    actor=actor,
                    note=note,
                )

    def get_peer_capability_policy(self, fingerprint: str) -> Optional[list[str]]:
        row = self._conn.execute(
            "SELECT allowed_json FROM peer_capability_policy WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            return None
        # 2026-05-21 audit T3-W: previously returned ``[]`` on JSON
        # decode failure — that's "deny-all", which is asymmetric with
        # the row-missing return of ``None`` ("allow-all-after-pair").
        # A corrupt row could silently lock out a paired peer entirely.
        # Raise instead: the caller (daemon ._capability_allowed) now
        # catches and fails CLOSED with a loud audit-log entry, which
        # is the correct safer default (T1-D).
        try:
            return list(json.loads(row["allowed_json"]))
        except Exception as exc:
            raise RuntimeError(
                f"peer_capability_policy.allowed_json corrupted for "
                f"{fingerprint[:8]}: {exc}"
            ) from exc

    # ─── capability / trust audit log (H1) ────────────────────────────
    def _record_capability_audit(
        self,
        *,
        fingerprint: str,
        kind: str,
        before: Any,
        after: Any,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        # Caller already holds _write_lock.
        self._conn.execute(
            """
            INSERT INTO capability_audit(
                ts_ms, fingerprint, kind, before_json, after_json, actor, note
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now_ms(),
                fingerprint,
                kind,
                None if before is None else json.dumps(before),
                None if after is None else json.dumps(after),
                actor,
                note,
            ),
        )

    def record_capability_grant_event(
        self,
        *,
        kind: str,
        granter_fp: str,
        subject_fp: str | None = None,
        capability: str | None = None,
        scope_summary: str | None = None,
        note: str | None = None,
    ) -> None:
        """2026-05-21 audit T3-V: durable audit row for signed-grant
        ``accept`` / ``revoke_subject`` / ``revoke_granter`` events.

        Previously the in-memory ``_cap_store`` swallowed every
        accept/revoke and only the ``cap_policy_set`` / trust changes
        landed in ``capability_audit``. A daemon restart wiped the
        in-memory store; the revocation log was lost. This row
        survives restart so an operator (and the audit dashboard)
        can reconstruct who granted / revoked what + when.

        Stored kinds: ``grant_accept``, ``grant_revoke_subject``,
        ``grant_revoke_granter``. The ``fingerprint`` column is set
        to the GRANTER's fp (queryable via the existing
        ``idx_cap_audit_fp`` index); ``subject_fp`` + ``capability``
        + ``scope_summary`` go into ``after_json``.
        """
        allowed_kinds = {
            "grant_accept", "grant_revoke_subject", "grant_revoke_granter",
        }
        if kind not in allowed_kinds:
            raise ValueError(f"unknown grant audit kind: {kind!r}")
        with self._write_lock:
            self._record_capability_audit(
                fingerprint=granter_fp,
                kind=kind,
                before=None,
                after={
                    "subject_fp": subject_fp,
                    "capability": capability,
                    "scope_summary": scope_summary,
                },
                actor=None,
                note=note,
            )

    def recent_capability_audit(
        self,
        *,
        fingerprint: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT id, ts_ms, fingerprint, kind, before_json, after_json,"
            " actor, note FROM capability_audit"
        )
        params: list[Any] = []
        if fingerprint is not None:
            sql += " WHERE fingerprint = ?"
            params.append(fingerprint)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        out: list[dict] = []
        for r in rows:
            def _parse(s: Optional[str]) -> Any:
                if s is None:
                    return None
                try:
                    return json.loads(s)
                except Exception:
                    return s
            out.append({
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "fingerprint": r["fingerprint"],
                "kind": r["kind"],
                "before": _parse(r["before_json"]),
                "after": _parse(r["after_json"]),
                "actor": r["actor"],
                "note": r["note"],
            })
        return out

    def activity_feed(
        self,
        *,
        since_ms: Optional[int] = None,
        kinds: Optional[Iterable[str]] = None,
        peer_fp: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """v0.9.1: cross-peer activity feed merging:
          - capability_audit (verify_set, verify_clear, trust_set,
            cap_policy_set, cap_policy_clear)
          - key_change_events (in + out)
          - transfers (file_send / file_recv complete + failed)
          - manifest_conflicts (detected + resolved)
          - peer first_seen synthetic events

        Returns newest-first rows, each shaped:
          {ts_ms, kind, severity, label, detail, peer_fp,
           peer_display_name, source}.

        Filters:
          - since_ms: drop rows with ts_ms < since_ms
          - kinds: keep only rows whose top-level kind matches
            (one of: trust, key_change, transfer, conflict, peer)
          - peer_fp: keep only rows attributable to this peer
          - limit: cap final list (default 200, hard max 2000)"""
        limit = max(1, min(int(limit), 2000))
        kinds_set = set(kinds) if kinds else None
        cutoff_raw = self.get_setting("activity_cleared_before_ms")
        if cutoff_raw:
            with contextlib.suppress(ValueError, TypeError):
                cutoff_ms = int(cutoff_raw)
                since_ms = max(int(since_ms or 0), cutoff_ms)

        events: list[dict] = []
        peer_cache: dict[str, str] = {}

        def _peer_label(fp: Optional[str]) -> Optional[str]:
            if not fp:
                return None
            if fp in peer_cache:
                return peer_cache[fp]
            rec = self.get_peer(fp)
            label = rec.display_name if rec else fp[:8]
            peer_cache[fp] = label
            return label

        # 1. capability_audit → trust kind
        if kinds_set is None or "trust" in kinds_set:
            sql = (
                "SELECT id, ts_ms, fingerprint, kind, before_json,"
                " after_json, actor, note FROM capability_audit"
            )
            params: list[Any] = []
            wclauses: list[str] = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("fingerprint = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                k = r["kind"]
                if k == "verify_set":
                    label, sev = "Verified in person", "good"
                elif k == "verify_clear":
                    label, sev = "Verification revoked", "warn"
                elif k == "trust_set":
                    after = json.loads(r["after_json"] or "null")
                    label = f"Trust → {after}"
                    sev = "info" if after == "pinned" else (
                        "bad" if after == "rejected" else "warn"
                    )
                elif k == "cap_policy_set":
                    label, sev = "Permissions changed", "info"
                elif k == "cap_policy_clear":
                    label, sev = "Permissions cleared (allow all)", "info"
                else:
                    label, sev = k.replace("_", " ").title(), "info"
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "trust",
                    "subkind": k,
                    "severity": sev,
                    "label": label,
                    "detail": r["note"] or "",
                    "peer_fp": r["fingerprint"],
                    "peer_display_name": _peer_label(r["fingerprint"]),
                    "source": "capability_audit",
                })

        # 2. key_change_events → key_change kind
        if kinds_set is None or "key_change" in kinds_set:
            sql = (
                "SELECT id, ts_ms, hostname, old_fingerprint,"
                " new_fingerprint, severity, acked_ms"
                " FROM key_change_events"
            )
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("(new_fingerprint = ? OR old_fingerprint = ?)")
                params.extend([peer_fp, peer_fp])
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                sev = r["severity"] or "low"
                evsev = "bad" if sev == "high" else (
                    "warn" if sev == "medium" else "info"
                )
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "key_change",
                    "subkind": "detected",
                    "severity": evsev,
                    "label": f"Key change · {r['hostname']}",
                    "detail": (
                        f"old {r['old_fingerprint'][:8]}… → "
                        f"new {r['new_fingerprint'][:8]}…"
                        + (" (acknowledged)" if r["acked_ms"] else " (unacked)")
                    ),
                    "peer_fp": r["new_fingerprint"],
                    "peer_display_name": _peer_label(r["new_fingerprint"]),
                    "source": "key_change_events",
                })

        # 3. transfers → transfer kind. Only terminal states are
        # interesting in the feed (mid-flight is the chat bubble's job).
        # v0.21.x: expose folder_send_group on every row so the UI can
        # collapse per-file folder-send transfers under their parent
        # folder_lifecycle_audit summary row. Backend stays simple
        # (just surface the tag); UI controls expand/collapse.
        if kinds_set is None or "transfer" in kinds_set:
            sql = (
                "SELECT id, direction, peer_fp, kind AS tkind, name,"
                " size, status, updated_ms, metadata_json"
                " FROM transfers"
                " WHERE status IN ('complete', 'failed')"
            )
            params = []
            if since_ms is not None:
                sql += " AND updated_ms >= ?"; params.append(int(since_ms))
            if peer_fp is not None:
                sql += " AND peer_fp = ?"; params.append(peer_fp)
            sql += " ORDER BY updated_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                ok = (r["status"] == "complete")
                direction = r["direction"]
                verb = (
                    "Received" if (ok and direction == "in") else
                    "Sent" if (ok and direction == "out") else
                    ("Receive failed" if direction == "in" else "Send failed")
                )
                label = f"{verb}: {r['name'] or '?'}"
                detail_parts = [r["tkind"] or "file"]
                if r["size"] is not None:
                    bsz = r["size"]
                    # Inline size formatting (KB/MB/GB) — same logic
                    # as fmtBytes on the client.
                    units = ["B", "KB", "MB", "GB", "TB"]
                    j = 0
                    while bsz >= 1024 and j < len(units) - 1:
                        bsz /= 1024
                        j += 1
                    fmt = f"{bsz:.1f} {units[j]}" if j > 0 and bsz < 10 else f"{int(bsz)} {units[j]}"
                    detail_parts.append(fmt)
                # Surface the folder_send_group tag so the UI can group
                # per-file transfer rows under their parent folder
                # summary. Stored inside metadata_json by daemon.py
                # when the file is part of a folder send.
                folder_send_group = None
                try:
                    md = json.loads(r["metadata_json"] or "null")
                    if isinstance(md, dict):
                        folder_send_group = md.get("folder_send_group")
                except (TypeError, ValueError):
                    pass
                ev = {
                    "ts_ms": r["updated_ms"],
                    "kind": "transfer",
                    "subkind": "complete" if ok else "failed",
                    "severity": "good" if ok else "bad",
                    "label": label,
                    "detail": " · ".join(detail_parts),
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "transfers",
                }
                if folder_send_group:
                    ev["folder_send_group"] = folder_send_group
                events.append(ev)

        # 4. manifest_conflicts → conflict kind
        if kinds_set is None or "self_mesh" in kinds_set:
            sql = "SELECT * FROM self_mesh_audit"
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("peer_fp = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                ev = r["event"]
                action = r["action"] or ""
                detail = r["detail"] or action.replace("_", " ")
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "self_mesh",
                    "subkind": ev,
                    "severity": r["severity"] or "info",
                    "label": f"My devices · {ev.replace('_', ' ')}",
                    "detail": detail,
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "self_mesh_audit",
                })

        if kinds_set is None or "conflict" in kinds_set:
            sql = (
                "SELECT id, folder_name, file_path, peer_fp,"
                " detected_ms, resolved_ms, resolution"
                " FROM manifest_conflicts"
            )
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("detected_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("peer_fp = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY detected_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                events.append({
                    "ts_ms": r["detected_ms"],
                    "kind": "conflict",
                    "subkind": "resolved" if r["resolved_ms"] else "detected",
                    "severity": "warn" if not r["resolved_ms"] else "info",
                    "label": (
                        f"Folder conflict ({r['resolution']})" if r["resolved_ms"]
                        else "Folder conflict detected"
                    ),
                    "detail": f"{r['folder_name']}/{r['file_path']}",
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "manifest_conflicts",
                })

        # 5. peer first_seen synthetic events
        if kinds_set is None or "peer" in kinds_set:
            sql = "SELECT fingerprint, hostname, first_seen_ms FROM peers"
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("first_seen_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("fingerprint = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY first_seen_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                events.append({
                    "ts_ms": r["first_seen_ms"],
                    "kind": "peer",
                    "subkind": "first_seen",
                    "severity": "info",
                    "label": f"Device first seen · {r['hostname'] or r['fingerprint'][:8]}",
                    "detail": "",
                    "peer_fp": r["fingerprint"],
                    "peer_display_name": _peer_label(r["fingerprint"]),
                    "source": "peers",
                })

        # 6. folder + offer kinds → folder_lifecycle_audit
        # v0.21.x: folder-level operations were invisible to the feed
        # (manifest_push wrote zero rows; archive looked like any
        # regular file). One audit table feeds two activity kinds so
        # offers + send-lifecycle can be filtered separately in the UI.
        folder_want = kinds_set is None or "folder" in kinds_set
        offer_want = kinds_set is None or "offer" in kinds_set
        if folder_want or offer_want:
            audit_events: list[str] = []
            if folder_want:
                audit_events.extend([
                    "send_started", "send_complete",
                    "send_failed", "send_cancelled",
                    "send_retry", "mode_selected",
                ])
            if offer_want:
                audit_events.extend([
                    "offer_sent", "offer_received",
                    "offer_accepted", "offer_declined",
                ])
            rows = self.list_folder_lifecycle_events(
                since_ms=since_ms, peer_fp=peer_fp,
                events=audit_events, limit=limit,
            )
            for r in rows:
                kind = "offer" if r["event"].startswith("offer_") else "folder"
                ev = r["event"]
                direction = r["direction"]
                folder_label = r["folder_name"]
                mode = r["mode"] or ""
                file_count = r["file_count"]
                total_bytes = r["total_bytes"]

                # Build a human label per event/direction.
                if ev == "offer_sent":
                    label = f"Offered folder {folder_label}"
                elif ev == "offer_received":
                    label = f"Folder offer received: {folder_label}"
                elif ev == "offer_accepted":
                    label = (
                        f"Peer accepted offer: {folder_label}"
                        if direction == "out"
                        else f"Accepted offer: {folder_label}"
                    )
                elif ev == "offer_declined":
                    label = (
                        f"Peer declined offer: {folder_label}"
                        if direction == "out"
                        else f"Declined offer: {folder_label}"
                    )
                elif ev == "send_started":
                    verb = "Sending" if direction == "out" else "Receiving"
                    label = f"{verb} folder {folder_label}"
                elif ev == "send_complete":
                    verb = "Sent" if direction == "out" else "Received"
                    label = f"{verb} folder {folder_label}"
                elif ev == "send_failed":
                    verb = "Send" if direction == "out" else "Receive"
                    label = f"{verb} failed: {folder_label}"
                elif ev == "send_cancelled":
                    label = f"Send cancelled: {folder_label}"
                elif ev == "send_retry":
                    label = f"Retrying folder {folder_label}"
                elif ev == "mode_selected":
                    label = f"Auto-routed folder {folder_label}"
                else:
                    label = f"{folder_label}: {ev}"

                # Build a detail line that's information-dense without
                # being noisy. Skip empty parts.
                detail_parts = []
                if mode:
                    detail_parts.append(mode)
                if file_count:
                    detail_parts.append(
                        f"{file_count} file{'s' if file_count != 1 else ''}"
                    )
                if total_bytes:
                    bsz = total_bytes
                    units = ["B", "KB", "MB", "GB", "TB"]
                    j = 0
                    while bsz >= 1024 and j < len(units) - 1:
                        bsz /= 1024
                        j += 1
                    detail_parts.append(
                        f"{bsz:.1f} {units[j]}" if j > 0 and bsz < 10
                        else f"{int(bsz)} {units[j]}"
                    )
                if r["dedup_bytes"]:
                    dsz = r["dedup_bytes"]
                    units = ["B", "KB", "MB", "GB", "TB"]
                    j = 0
                    while dsz >= 1024 and j < len(units) - 1:
                        dsz /= 1024
                        j += 1
                    detail_parts.append(
                        f"dedup {dsz:.1f} {units[j]}" if j > 0 and dsz < 10
                        else f"dedup {int(dsz)} {units[j]}"
                    )
                if r["error_msg"]:
                    detail_parts.append(r["error_msg"])

                meta = r.get("metadata") or {}
                # folder_send_group lets the UI link this summary row
                # to the per-file transfer children that carry the
                # same tag.
                fsg = meta.get("folder_send_group")
                out_ev = {
                    "ts_ms": r["ts_ms"],
                    "kind": kind,
                    "subkind": ev,
                    "direction": direction,
                    "severity": r["severity"],
                    "label": label,
                    "detail": " · ".join(detail_parts),
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "folder_name": folder_label,
                    "mode": mode or None,
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                    "source": "folder_lifecycle_audit",
                }
                if fsg:
                    out_ev["folder_send_group"] = fsg
                events.append(out_ev)

        events.sort(key=lambda e: e["ts_ms"], reverse=True)
        return events[:limit]

    def peer_trust_history(
        self,
        fingerprint: str,
        *,
        limit: int = 200,
    ) -> list[dict]:
        """v0.8.6: merged chronological trust history for one peer.

        Combines four sources into a single timeline (newest first):
          - peers row's first_seen_ms (synthetic 'first_seen' event)
          - capability_audit rows (verify_set, verify_clear, trust_set,
            cap_policy_set, cap_policy_clear)
          - key_change_events where this fingerprint is the new_fp
            OR the old_fp (rotation events affect both ends)
          - hostname_keys first_seen for any pubkey ever attached to
            the peer's hostname (synthetic 'pubkey_first_seen' event)

        Each entry is a uniform dict with keys: ts_ms, kind, label,
        detail, severity, source. The UI just renders the list — no
        further classification needed."""
        peer = self.get_peer(fingerprint)
        if peer is None:
            return []
        events: list[dict] = []

        # 1. First-seen synthetic event from the peers row.
        events.append({
            "ts_ms": peer.first_seen_ms,
            "kind": "first_seen",
            "label": "Device first seen",
            "detail": f"hostname: {peer.hostname or '(unknown)'}",
            "severity": "info",
            "source": "peers",
        })

        # 2. capability_audit: rich. Translate each kind to a human label.
        audit = self.recent_capability_audit(
            fingerprint=fingerprint, limit=limit,
        )
        for row in audit:
            kind = row["kind"]
            if kind == "verify_set":
                method = (row["after"] or {}).get("verified_method") if isinstance(row["after"], dict) else None
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": "Verified in person",
                    "detail": (
                        f"method: {method}" + (f" · note: {row['note']}" if row["note"] else "")
                        if method else (row["note"] or "")
                    ),
                    "severity": "good",
                    "source": "capability_audit",
                })
            elif kind == "verify_clear":
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": "Verification revoked",
                    "detail": row["note"] or "",
                    "severity": "warn",
                    "source": "capability_audit",
                })
            elif kind == "trust_set":
                before = row["before"]
                after = row["after"]
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": f"Trust changed: {before or '?'} → {after or '?'}",
                    "detail": row["note"] or "",
                    "severity": "info" if after == "pinned" else (
                        "bad" if after == "rejected" else "warn"
                    ),
                    "source": "capability_audit",
                })
            elif kind in ("cap_policy_set", "cap_policy_clear"):
                before = row["before"]
                after = row["after"]
                if kind == "cap_policy_clear":
                    label = "Permissions cleared (allow all)"
                    detail = ""
                else:
                    after_list = after if isinstance(after, list) else []
                    detail = (
                        f"now allow: {', '.join(after_list) or '(none)'}"
                    )
                    label = "Permissions changed"
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": label,
                    "detail": detail + ((" · " + row["note"]) if row["note"] else ""),
                    "severity": "info",
                    "source": "capability_audit",
                })
            else:
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": kind.replace("_", " ").title(),
                    "detail": row["note"] or "",
                    "severity": "info",
                    "source": "capability_audit",
                })

        # 3. key_change_events: include any event where this peer is
        # either the rotated-out fingerprint (old_fp) or rotated-in
        # fingerprint (new_fp). Both contexts are useful: "this device
        # used to be X, now it's Y" and "this device replaces Z".
        kce_in = self.list_key_change_events(
            new_fingerprint=fingerprint, limit=limit,
        )
        for ev in kce_in:
            sev = ev["severity"]
            events.append({
                "ts_ms": ev["ts_ms"],
                "kind": "key_change_in",
                "label": "Key change detected (this device replaces a prior one)",
                "detail": (
                    f"prior fp: {ev['old_fingerprint'][:8]}… · severity: {sev}"
                    + (" · acknowledged" if ev["acked_ms"] else " · UNACKNOWLEDGED")
                ),
                "severity": "bad" if sev == "high" else (
                    "warn" if sev == "medium" else "info"
                ),
                "source": "key_change_events",
            })
        # rotated-out (this peer's fingerprint shows up as old_fp).
        # No filter helper for old_fp; do a direct query.
        old_rows = self._conn.execute(
            "SELECT id, ts_ms, hostname, old_fingerprint, new_fingerprint,"
            " severity, acked_ms FROM key_change_events"
            " WHERE old_fingerprint = ? ORDER BY ts_ms DESC LIMIT ?",
            (fingerprint, int(limit)),
        ).fetchall()
        for r in old_rows:
            events.append({
                "ts_ms": r["ts_ms"],
                "kind": "key_change_out",
                "label": "This device was rotated out",
                "detail": (
                    f"replaced by: {r['new_fingerprint'][:8]}…"
                    + (" · acknowledged" if r["acked_ms"] else " · UNACKNOWLEDGED")
                ),
                "severity": "bad" if r["severity"] == "high" else (
                    "warn" if r["severity"] == "medium" else "info"
                ),
                "source": "key_change_events",
            })

        # Sort newest-first, cap to `limit`.
        events.sort(key=lambda e: e["ts_ms"], reverse=True)
        return events[:limit]

    # ─── key-change tracking (v0.7.8) ─────────────────────────────────

    _MAX_UNPINNED_KEY_CHANGE_ALERTS = 4

    def _record_hostname_key_seen_locked(
        self,
        *,
        c: sqlite3.Cursor,
        hostname: str,
        ed_pub_hex: str,
        fingerprint: str,
        now: int,
    ) -> Optional[int]:
        """Internal: insert/update the hostname_keys row for this
        observation, AND if the hostname has previously been seen with
        a DIFFERENT pubkey, emit a key_change_events row.

        Severity is graded by the strongest prior trust observed:
          - 'high'   ← any prior fingerprint for this hostname is pinned
          - 'medium' ← any prior fingerprint exists in peers (pending)
          - 'low'    ← only seen via discovery, never persisted in peers
        Caller must hold self._write_lock and pass an open cursor.
        Detection runs AFTER the upsert_peer INSERT so the new (hostname,
        pubkey) pair sees its own peers row — we filter it out via the
        `fingerprint != ?` clause below.

        Returns the integer id of the freshly-inserted key_change_events
        row (so the caller can broadcast it in real time), or None if
        no new conflict was logged."""
        # 1. Find any conflicting prior observation.
        prior_rows = c.execute(
            "SELECT ed_pub_hex, fingerprint FROM hostname_keys"
            " WHERE hostname = ? AND ed_pub_hex != ?"
            " ORDER BY last_seen_ms DESC",
            (hostname, ed_pub_hex),
        ).fetchall()
        # 2. Upsert the current (hostname, ed_pub_hex) row.
        c.execute(
            """
            INSERT INTO hostname_keys(
                hostname, ed_pub_hex, fingerprint,
                first_seen_ms, last_seen_ms
            ) VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(hostname, ed_pub_hex) DO UPDATE SET
                last_seen_ms = excluded.last_seen_ms,
                fingerprint  = excluded.fingerprint
            """,
            (hostname, ed_pub_hex, fingerprint, now, now),
        )
        # 3. If we found a conflict AND haven't already logged this
        # exact (old_fp, new_fp) pair, write a key_change_events row.
        if not prior_rows:
            return None
        new_event_id: Optional[int] = None
        unpinned_alerts = 0
        for old in prior_rows:
            old_fp = old["fingerprint"]
            old_pub_hex = old["ed_pub_hex"]
            if old_fp == fingerprint:
                # Hostname was reattached to a row we already wrote
                # under a different ed_pub_hex column — defensive guard,
                # shouldn't normally happen.
                continue
            # Idempotency: have we already logged THIS specific
            # (old_fp → new_fp) transition? If so, just bump nothing —
            # the existing row stays, acked or not.
            already = c.execute(
                "SELECT 1 FROM key_change_events"
                " WHERE hostname = ? AND old_fingerprint = ?"
                " AND new_fingerprint = ? LIMIT 1",
                (hostname, old_fp, fingerprint),
            ).fetchone()
            if already:
                continue
            # Severity grading via prior peers row's trust state.
            old_peer = c.execute(
                "SELECT trust FROM peers WHERE fingerprint = ?",
                (old_fp,),
            ).fetchone()
            if old_peer is not None and old_peer["trust"] == "pinned":
                severity = "high"
            elif old_peer is not None:
                severity = "medium"
            else:
                severity = "low"
            if severity != "high":
                # A hostname is whatever a device on the LAN says it is. One
                # that cycles through keys would otherwise log an alert
                # against every key it ever used, each time: quadratic rows
                # that say nothing new. A change away from a PINNED key is
                # always recorded; of the rest, only the most recent few.
                unpinned_alerts += 1
                if unpinned_alerts > self._MAX_UNPINNED_KEY_CHANGE_ALERTS:
                    continue
            cur = c.execute(
                """
                INSERT INTO key_change_events(
                    ts_ms, hostname,
                    old_fingerprint, new_fingerprint,
                    old_pub_hex, new_pub_hex,
                    severity, acked_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    now, hostname,
                    old_fp, fingerprint,
                    old_pub_hex, ed_pub_hex,
                    severity,
                ),
            )
            # First conflict (most-recent prior, if multiple) wins as
            # the broadcast id. Subsequent prior_rows iterations will
            # only fire when the hostname has rotated keys 3+ times,
            # which is rare; keeping the freshest is the practical UX.
            if new_event_id is None and cur.lastrowid is not None:
                new_event_id = int(cur.lastrowid)
        return new_event_id

    def list_hostname_keys(self, hostname: str) -> list[dict]:
        """Return every (ed_pub_hex, fingerprint, first_seen, last_seen)
        we've observed for a hostname, freshest first. Powers the
        device drawer's 'Key history' section."""
        rows = self._conn.execute(
            "SELECT hostname, ed_pub_hex, fingerprint,"
            " first_seen_ms, last_seen_ms FROM hostname_keys"
            " WHERE hostname = ? ORDER BY last_seen_ms DESC",
            (hostname,),
        ).fetchall()
        return [
            {
                "hostname": r["hostname"],
                "ed_pub_hex": r["ed_pub_hex"],
                "fingerprint": r["fingerprint"],
                "first_seen_ms": r["first_seen_ms"],
                "last_seen_ms": r["last_seen_ms"],
            }
            for r in rows
        ]

    def list_key_change_events(
        self,
        *,
        unacked_only: bool = False,
        new_fingerprint: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Return key-change events, freshest first. UI surfaces use
        `unacked_only=True` to drive the red banner; the device drawer
        passes `new_fingerprint=fp` to list events targeting that
        specific peer."""
        sql = (
            "SELECT id, ts_ms, hostname, old_fingerprint, new_fingerprint,"
            " old_pub_hex, new_pub_hex, severity, acked_ms"
            " FROM key_change_events"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if unacked_only:
            clauses.append("acked_ms IS NULL")
        if new_fingerprint is not None:
            clauses.append("new_fingerprint = ?")
            params.append(new_fingerprint)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "hostname": r["hostname"],
                "old_fingerprint": r["old_fingerprint"],
                "new_fingerprint": r["new_fingerprint"],
                "old_pub_hex": r["old_pub_hex"],
                "new_pub_hex": r["new_pub_hex"],
                "severity": r["severity"],
                "acked_ms": r["acked_ms"],
            }
            for r in rows
        ]

    def ack_key_change_event(self, event_id: int) -> bool:
        """Mark a key-change event acknowledged. Returns True if a
        previously-unacked row was just acked, False if the row didn't
        exist OR was already acked."""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE key_change_events SET acked_ms = ?"
                " WHERE id = ? AND acked_ms IS NULL",
                (_now_ms(), int(event_id)),
            )
            return cur.rowcount > 0

    def record_authorized_rotation(
        self,
        *,
        old_fingerprint: str,
        new_fingerprint: str,
        old_pub_hex: str,
        new_pub_hex: str,
        hostname: Optional[str] = None,
        ts_ms: Optional[int] = None,
    ) -> Optional[int]:
        """v0.21.x: log an inbound peer-rotation that was applied via
        a cryptographically-authorized cert. Reuses the v0.7.8
        key_change_events table so the existing activity feed /
        device-drawer key-history surfaces pick it up automatically,
        but with severity='low' + acked_ms preset so the manual-
        confirm warning UI does not fire (the cert provided proof,
        the user already saw the toast).

        Idempotent on (old_fingerprint, new_fingerprint): a
        repeated cert delivery does not insert a duplicate audit
        row. Returns the row id (or None if the row already existed).
        """
        if ts_ms is None:
            ts_ms = _now_ms()
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id FROM key_change_events"
                " WHERE old_fingerprint = ? AND new_fingerprint = ?"
                " LIMIT 1",
                (old_fingerprint, new_fingerprint),
            ).fetchone()
            if existing is not None:
                return None
            cur = self._conn.execute(
                """
                INSERT INTO key_change_events(
                    ts_ms, hostname,
                    old_fingerprint, new_fingerprint,
                    old_pub_hex, new_pub_hex,
                    severity, acked_ms
                ) VALUES(?, ?, ?, ?, ?, ?, 'low', ?)
                """,
                (
                    int(ts_ms),
                    hostname or "(rotation)",
                    old_fingerprint, new_fingerprint,
                    old_pub_hex, new_pub_hex,
                    int(ts_ms),  # auto-acked
                ),
            )
            return int(cur.lastrowid or 0)

    def ack_all_key_change_events_for(self, new_fingerprint: str) -> int:
        """Bulk-ack every unacked event targeting a peer (used when
        the device drawer's 'Got it' button is clicked). Returns the
        count of rows just acked."""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE key_change_events SET acked_ms = ?"
                " WHERE new_fingerprint = ? AND acked_ms IS NULL",
                (_now_ms(), new_fingerprint),
            )
            return cur.rowcount or 0

    # ─── held recovery shares (v0.21.x social-share recovery) ──────────
    # Guardian-side store of Shamir shares the user holds for someone
    # else. Each row is one .olss file the user imported via the UI.

    def insert_held_share(
        self,
        *,
        share_index: int,
        threshold_k: int,
        total_n: int,
        setup_ms: int,
        wrapped_blob: bytes,
        label: Optional[str] = None,
        owner_hint: Optional[str] = None,
        imported_ms: Optional[int] = None,
    ) -> int:
        """Persist one share. Idempotent on (wrapped_blob): re-importing
        the same .olss file returns the existing id rather than
        inserting a duplicate row. Returns the row id."""
        if imported_ms is None:
            imported_ms = _now_ms()
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id FROM held_recovery_shares WHERE wrapped_blob = ?"
                " LIMIT 1",
                (wrapped_blob,),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cur = self._conn.execute(
                """
                INSERT INTO held_recovery_shares(
                    share_index, threshold_k, total_n, setup_ms,
                    wrapped_blob, imported_ms, label, owner_hint
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(share_index), int(threshold_k), int(total_n),
                    int(setup_ms), wrapped_blob, int(imported_ms),
                    label, owner_hint,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_held_shares(self) -> list[dict]:
        """Return all stored shares, freshest-imported first. UI
        iterates this to render the 'Held recovery shares' card."""
        rows = self._conn.execute(
            "SELECT id, share_index, threshold_k, total_n, setup_ms,"
            " wrapped_blob, imported_ms, label, owner_hint"
            " FROM held_recovery_shares"
            " ORDER BY imported_ms DESC, id DESC"
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "share_index": int(r["share_index"]),
                "threshold_k": int(r["threshold_k"]),
                "total_n": int(r["total_n"]),
                "setup_ms": int(r["setup_ms"]),
                "wrapped_blob": bytes(r["wrapped_blob"]),
                "imported_ms": int(r["imported_ms"]),
                "label": r["label"],
                "owner_hint": r["owner_hint"],
            }
            for r in rows
        ]

    def get_held_share(self, share_id: int) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id, share_index, threshold_k, total_n, setup_ms,"
            " wrapped_blob, imported_ms, label, owner_hint"
            " FROM held_recovery_shares WHERE id = ?",
            (int(share_id),),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": int(row["id"]),
            "share_index": int(row["share_index"]),
            "threshold_k": int(row["threshold_k"]),
            "total_n": int(row["total_n"]),
            "setup_ms": int(row["setup_ms"]),
            "wrapped_blob": bytes(row["wrapped_blob"]),
            "imported_ms": int(row["imported_ms"]),
            "label": row["label"],
            "owner_hint": row["owner_hint"],
        }

    def delete_held_share(self, share_id: int) -> bool:
        """Drop a share the user no longer wants to hold (e.g., the
        owner asked them to discard, or they're cleaning up)."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM held_recovery_shares WHERE id = ?",
                (int(share_id),),
            )
            return (cur.rowcount or 0) > 0

    # ─── atomic peer fingerprint transition (v0.21.x rotation) ────────
    # When an inbound ROTATION_CERT verifies, the receiving daemon
    # must atomically migrate every fingerprint reference for that
    # peer from old_fp to new_fp so all of the user's per-peer state
    # (alias, mute, dm_ttl, trust, verified_*) AND chat history
    # follow the rotated identity. One transaction across every
    # peer-keyed table.

    def transition_peer_fingerprint(
        self,
        *,
        old_fp: str,
        new_fp: str,
        new_pubkey: bytes,
        new_short_id: Optional[str] = None,
    ) -> bool:
        """Cascade-update every fingerprint reference for a peer in
        one SQLite transaction. Returns True if a row with old_fp
        was found and migrated, False if there was no such peer.

        Tables cascaded:
          peers, messages, peer_capabilities, peer_capability_policy,
          capability_audit, transfers, outbox, folder_audit,
          message_reactions, route_memory, route_candidates,
          self_mesh_audit, manifest_conflicts, peer_read_markers,
          hostname_keys, pending_rotation_announcements.

        Tables NOT cascaded (historical record; the transition
        itself is the event being recorded):
          key_change_events.

        Per-peer state preserved on the peers row:
          trust, local_alias, muted, verified_at_ms, verified_method,
          verified_note, dm_ttl_ms, muted_until_ms, first_seen_ms.

        Updated on the peers row: fingerprint, pubkey, short_id,
        last_seen_ms.

        If new_fp already exists in peers (the new identity has
        already been seen, e.g. via a normal handshake before the
        cert arrived), we MERGE: copy the OLD row's preserved
        state onto the new row, then delete the old row. The
        cascading on other tables still UPDATEs old_fp -> new_fp,
        which is safe because their entries didn't yet exist for
        new_fp (they used to use old_fp).
        """
        if not isinstance(old_fp, str) or not isinstance(new_fp, str):
            raise TypeError("old_fp and new_fp must be strings")
        if old_fp == new_fp:
            raise ValueError("old_fp and new_fp must differ")
        if not isinstance(new_pubkey, (bytes, bytearray)) or len(new_pubkey) != 32:
            raise ValueError("new_pubkey must be 32 bytes")
        new_pubkey = bytes(new_pubkey)
        if new_short_id is None:
            # The daemon's own short_id derivation is BLAKE3-based;
            # fall back to a stable prefix of the new fingerprint so
            # transitioned peers stay visible in the UI even when
            # the caller forgets to compute the proper short_id.
            new_short_id = new_fp[:8]
        now = _now_ms()
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.execute("BEGIN IMMEDIATE")
                try:
                    old_row = c.execute(
                        "SELECT * FROM peers WHERE fingerprint = ?",
                        (old_fp,),
                    ).fetchone()
                    if old_row is None:
                        c.execute("ROLLBACK")
                        return False

                    new_row = c.execute(
                        "SELECT * FROM peers WHERE fingerprint = ?",
                        (new_fp,),
                    ).fetchone()

                    if new_row is None:
                        # Simple case: rename old peers row in place.
                        c.execute(
                            "UPDATE peers SET fingerprint = ?,"
                            " pubkey = ?, short_id = ?, last_seen_ms = ?"
                            " WHERE fingerprint = ?",
                            (new_fp, new_pubkey, new_short_id, now, old_fp),
                        )
                    else:
                        # Merge case: new_fp peer row already exists
                        # (handshake under the new identity ran
                        # before the cert arrived). Promote old
                        # per-peer state onto the new row, then
                        # delete the old row so the cascading
                        # UPDATEs below find no rows for old_fp.
                        c.execute(
                            "UPDATE peers SET"
                            " trust = ?, local_alias = ?, muted = ?,"
                            " verified_at_ms = ?, verified_method = ?,"
                            " verified_note = ?, dm_ttl_ms = ?,"
                            " muted_until_ms = ?, first_seen_ms = ?,"
                            " pubkey = ?, short_id = ?, last_seen_ms = ?"
                            " WHERE fingerprint = ?",
                            (
                                old_row["trust"],
                                old_row["local_alias"],
                                old_row["muted"],
                                old_row["verified_at_ms"],
                                old_row["verified_method"],
                                old_row["verified_note"],
                                old_row["dm_ttl_ms"],
                                old_row["muted_until_ms"],
                                old_row["first_seen_ms"],
                                new_pubkey, new_short_id, now,
                                new_fp,
                            ),
                        )
                        c.execute(
                            "DELETE FROM peers WHERE fingerprint = ?",
                            (old_fp,),
                        )

                    # Cascade-update every other peer-keyed table.
                    # ON CONFLICT REPLACE for PK-collision tables so
                    # a merge case doesn't blow up if the new_fp
                    # also has a row in (say) peer_capabilities.
                    for sql in (
                        "UPDATE messages           SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE transfers          SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE outbox             SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE folder_audit       SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE message_reactions  SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE route_memory       SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE route_candidates   SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE self_mesh_audit    SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE manifest_conflicts SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE pending_rotation_announcements"
                        "                          SET peer_fp     = ? WHERE peer_fp     = ?",
                        "UPDATE capability_audit   SET fingerprint = ? WHERE fingerprint = ?",
                        "UPDATE hostname_keys      SET fingerprint = ? WHERE fingerprint = ?",
                    ):
                        with contextlib.suppress(*DB_OPERATIONAL_ERRORS):
                            c.execute(sql, (new_fp, old_fp))

                    # PK-collision tables: peer_capabilities,
                    # peer_capability_policy, peer_read_markers. For
                    # these we DELETE any pre-existing new_fp row
                    # (the merge case promoted the OLD state already)
                    # then UPDATE.
                    for sql_pair in (
                        ("DELETE FROM peer_capabilities       WHERE fingerprint = ?",
                         "UPDATE peer_capabilities       SET fingerprint = ? WHERE fingerprint = ?"),
                        ("DELETE FROM peer_capability_policy  WHERE fingerprint = ?",
                         "UPDATE peer_capability_policy  SET fingerprint = ? WHERE fingerprint = ?"),
                        ("DELETE FROM peer_read_markers       WHERE peer_fp = ?",
                         "UPDATE peer_read_markers       SET peer_fp = ? WHERE peer_fp = ?"),
                    ):
                        del_sql, upd_sql = sql_pair
                        with contextlib.suppress(*DB_OPERATIONAL_ERRORS):
                            c.execute(del_sql, (new_fp,))
                            c.execute(upd_sql, (new_fp, old_fp))

                    c.execute("COMMIT")
                    # Message rows moved between peer namespaces. Any cached
                    # quota totals for either fingerprint are now stale.
                    self._text_usage_cache.pop(old_fp, None)
                    self._text_usage_cache.pop(new_fp, None)
                    self._outbox_usage_cache.pop(old_fp, None)
                    self._outbox_usage_cache.pop(new_fp, None)
                    return True
                except Exception:
                    c.execute("ROLLBACK")
                    raise
            finally:
                c.close()

    # ─── rotation announcements (v0.21.x) ─────────────────────────────
    # Per-peer queue of rotation certificates we owe delivery + ack on.
    # The background delivery task drains rows where ``acked_ms IS NULL``;
    # the inbound ack handler sets ``acked_ms`` when a peer confirms
    # application of the cert.

    def queue_rotation_announcement(
        self,
        *,
        peer_fp: str,
        old_fp: str,
        new_fp: str,
        cert_json: str,
        sig_hex: str,
        now_ms: Optional[int] = None,
    ) -> int:
        """Insert one row. Returns the row id. Idempotent on (peer_fp,
        new_fp): if a row already exists for this peer + this target
        new_fp, we don't duplicate."""
        if now_ms is None:
            now_ms = _now_ms()
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id FROM pending_rotation_announcements"
                " WHERE peer_fp = ? AND new_fp = ?"
                " ORDER BY id DESC LIMIT 1",
                (peer_fp, new_fp),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cur = self._conn.execute(
                """
                INSERT INTO pending_rotation_announcements(
                    peer_fp, old_fp, new_fp, cert_json, sig_hex,
                    queued_ms, last_attempt_ms, attempt_count, acked_ms
                ) VALUES(?, ?, ?, ?, ?, ?, NULL, 0, NULL)
                """,
                (peer_fp, old_fp, new_fp, cert_json, sig_hex, int(now_ms)),
            )
            return int(cur.lastrowid or 0)

    def queue_rotation_announcements_durable(
        self,
        rows: list[dict[str, Any]],
    ) -> list[int]:
        """Atomically publish and exact-read-back one rotation peer snapshot.

        Recovery boot replay uses this boundary after installing the staged
        identity. Either every signed announcement is durable under
        ``synchronous=FULL`` or none of the new rows are. A replay accepts an
        existing row only when every committed certificate field is identical;
        a colliding or partially-corrupt row fails closed.
        """
        from one_link import identity_rotation

        if not isinstance(rows, list) or len(rows) > 65536:
            raise ValueError("rotation announcement batch is invalid")
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        expected_keys = {
            "peer_fp",
            "old_fp",
            "new_fp",
            "cert_json",
            "sig_hex",
            "queued_ms",
        }
        for raw in rows:
            if not isinstance(raw, dict) or set(raw) != expected_keys:
                raise ValueError("rotation announcement row schema is invalid")
            row = dict(raw)
            for key in ("peer_fp", "old_fp", "new_fp"):
                value = row[key]
                if (
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(ch not in "0123456789abcdef" for ch in value)
                ):
                    raise ValueError(f"rotation announcement {key} is invalid")
            queued_ms = row["queued_ms"]
            if type(queued_ms) is not int or queued_ms < 0:
                raise ValueError("rotation announcement queued_ms is invalid")
            cert = identity_rotation.RotationCertificate.from_wire_dict(
                {
                    "cert_json": row["cert_json"],
                    "sig_hex": row["sig_hex"],
                }
            )
            if cert.old_fp != row["old_fp"] or cert.new_fp != row["new_fp"]:
                raise ValueError(
                    "rotation announcement certificate fingerprints mismatch"
                )
            batch_key = (row["peer_fp"], row["new_fp"])
            if batch_key in seen:
                raise ValueError("rotation announcement batch contains duplicates")
            seen.add(batch_key)
            normalized.append(row)

        row_ids: list[int] = []
        with self.durable_write_transaction():
            for row in normalized:
                matches = self._conn.execute(
                    "SELECT id, peer_fp, old_fp, new_fp, cert_json, sig_hex, queued_ms"
                    " FROM pending_rotation_announcements"
                    " WHERE peer_fp = ? AND new_fp = ? ORDER BY id ASC",
                    (row["peer_fp"], row["new_fp"]),
                ).fetchall()
                if len(matches) > 1:
                    raise RuntimeError(
                        "rotation announcement uniqueness proof failed"
                    )
                if matches:
                    existing = matches[0]
                    actual = {
                        "peer_fp": existing["peer_fp"],
                        "old_fp": existing["old_fp"],
                        "new_fp": existing["new_fp"],
                        "cert_json": existing["cert_json"],
                        "sig_hex": existing["sig_hex"],
                        "queued_ms": int(existing["queued_ms"]),
                    }
                    if actual != row:
                        raise RuntimeError(
                            "rotation announcement collision does not match journal"
                        )
                    row_id = int(existing["id"])
                else:
                    cur = self._conn.execute(
                        """
                        INSERT INTO pending_rotation_announcements(
                            peer_fp, old_fp, new_fp, cert_json, sig_hex,
                            queued_ms, last_attempt_ms, attempt_count, acked_ms
                        ) VALUES(?, ?, ?, ?, ?, ?, NULL, 0, NULL)
                        """,
                        (
                            row["peer_fp"],
                            row["old_fp"],
                            row["new_fp"],
                            row["cert_json"],
                            row["sig_hex"],
                            row["queued_ms"],
                        ),
                    )
                    row_id = int(cur.lastrowid or 0)
                proof = self._conn.execute(
                    "SELECT peer_fp, old_fp, new_fp, cert_json, sig_hex, queued_ms"
                    " FROM pending_rotation_announcements WHERE id = ?",
                    (row_id,),
                ).fetchone()
                if proof is None or {
                    "peer_fp": proof["peer_fp"],
                    "old_fp": proof["old_fp"],
                    "new_fp": proof["new_fp"],
                    "cert_json": proof["cert_json"],
                    "sig_hex": proof["sig_hex"],
                    "queued_ms": int(proof["queued_ms"]),
                } != row:
                    raise RuntimeError(
                        "rotation announcement durable read-back failed"
                    )
                row_ids.append(row_id)
        return row_ids

    def list_pending_rotation_announcements(
        self,
        *,
        peer_fp: Optional[str] = None,
        unacked_only: bool = True,
        limit: int = 256,
    ) -> list[dict]:
        """Read pending rows for the background delivery task OR the
        UI status panel ('X of Y peers acknowledged your new key')."""
        sql = (
            "SELECT id, peer_fp, old_fp, new_fp, cert_json, sig_hex,"
            " queued_ms, last_attempt_ms, attempt_count, acked_ms"
            " FROM pending_rotation_announcements"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp is not None:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if unacked_only:
            clauses.append("acked_ms IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY queued_ms ASC, id ASC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": int(r["id"]),
                "peer_fp": r["peer_fp"],
                "old_fp": r["old_fp"],
                "new_fp": r["new_fp"],
                "cert_json": r["cert_json"],
                "sig_hex": r["sig_hex"],
                "queued_ms": int(r["queued_ms"]),
                "last_attempt_ms": int(r["last_attempt_ms"]) if r["last_attempt_ms"] is not None else None,
                "attempt_count": int(r["attempt_count"] or 0),
                "acked_ms": int(r["acked_ms"]) if r["acked_ms"] is not None else None,
            }
            for r in rows
        ]

    def mark_rotation_attempt(self, row_id: int, *, now_ms: Optional[int] = None) -> None:
        """Background-task hook: bump attempt_count + last_attempt_ms
        after every send try, ack or not. UI surfaces the count so an
        unreachable peer doesn't look idle in the status panel."""
        if now_ms is None:
            now_ms = _now_ms()
        with self._write_lock:
            self._conn.execute(
                "UPDATE pending_rotation_announcements"
                " SET last_attempt_ms = ?, attempt_count = attempt_count + 1"
                " WHERE id = ?",
                (int(now_ms), int(row_id)),
            )

    def ack_rotation_announcement(
        self,
        *,
        peer_fp: str,
        new_fp: str,
        now_ms: Optional[int] = None,
    ) -> int:
        """Inbound-ack handler hook: mark every unacked row for this
        (peer_fp, new_fp) acknowledged. Returns count of rows acked.
        Idempotent: a duplicate ack is a no-op."""
        if now_ms is None:
            now_ms = _now_ms()
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE pending_rotation_announcements"
                " SET acked_ms = ?"
                " WHERE peer_fp = ? AND new_fp = ? AND acked_ms IS NULL",
                (int(now_ms), peer_fp, new_fp),
            )
            return int(cur.rowcount or 0)

    def rotation_announcement_summary(self) -> dict[str, int]:
        """Single-row counters for the UI status panel: how many
        announcements outstanding, how many acked. Used to render
        'X of Y peers acknowledged your new key' without pulling
        the full row list."""
        row = self._conn.execute(
            "SELECT"
            " COUNT(*)                                          AS total,"
            " SUM(CASE WHEN acked_ms IS NULL THEN 1 ELSE 0 END) AS pending,"
            " SUM(CASE WHEN acked_ms IS NOT NULL THEN 1 ELSE 0 END) AS acked"
            " FROM pending_rotation_announcements"
        ).fetchone()
        return {
            "total": int(row["total"] or 0),
            "pending": int(row["pending"] or 0),
            "acked": int(row["acked"] or 0),
        }

    # ─── groups (v0.6.2) ──────────────────────────────────────────────
    # `event` is a one_link.groups.GroupEvent — we serialize via to_wire().
    # This module avoids importing groups directly to dodge a cycle; the
    # daemon does that work and passes `wire_dict`.

    def upsert_group_event(
        self,
        *,
        group_id: bytes,
        event_id: str,
        timestamp_ms: int,
        wire_dict: dict,
    ) -> bool:
        """Persist a group event. Returns True if newly inserted,
        False for an exact replay. A colliding event id is rejected rather
        than silently treating different durable state as idempotent."""
        wire_json = json.dumps(
            wire_dict, separators=(",", ":"), sort_keys=True, allow_nan=False,
        )
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT timestamp_ms, wire_json FROM group_events "
                "WHERE group_id = ? AND event_id = ?",
                (group_id, event_id),
            ).fetchone()
            if existing is not None:
                try:
                    stored_json = json.dumps(
                        json.loads(existing["wire_json"]),
                        separators=(",", ":"), sort_keys=True, allow_nan=False,
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise MessageIdConflict(
                        f"stored group event {event_id!r} is invalid"
                    ) from exc
                if (
                    int(existing["timestamp_ms"]) != int(timestamp_ms)
                    or stored_json != wire_json
                ):
                    raise MessageIdConflict(
                        f"group event id {event_id!r} was reused for different content"
                    )
                return False
            group_count = self._group_event_count_cache.get(group_id)
            if group_count is None:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM group_events WHERE group_id = ?",
                    (group_id,),
                ).fetchone()
                group_count = int(row["n"] if row else 0)
                self._group_event_count_cache[group_id] = group_count
            total_count = self._group_event_total_count
            if total_count is None:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM group_events",
                ).fetchone()
                total_count = int(row["n"] if row else 0)
                self._group_event_total_count = total_count
            if (
                group_count >= MAX_GROUP_EVENTS_PER_GROUP
                or total_count >= MAX_GROUP_EVENTS_TOTAL
            ):
                raise MessageQuotaExceeded(
                    "group event-log quota reached; remove unused groups before "
                    "accepting more events"
                )
            cur = self._conn.execute(
                """
                INSERT INTO group_events(
                    group_id, event_id, timestamp_ms, wire_json
                ) VALUES(?, ?, ?, ?)
                """,
                (group_id, event_id, int(timestamp_ms), wire_json),
            )
            if cur.rowcount > 0:
                self._group_event_count_cache[group_id] = group_count + 1
                self._group_event_total_count = total_count + 1
            return cur.rowcount > 0

    def has_group_event(self, group_id: bytes, event_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM group_events WHERE group_id = ? AND event_id = ?",
            (group_id, event_id),
        ).fetchone()
        return row is not None

    def list_group_events(self, group_id: bytes) -> list[dict]:
        """All events for a group, returned as wire dicts ready to feed
        through GroupEvent.from_wire()."""
        rows = self._conn.execute(
            "SELECT event_id, wire_json FROM group_events WHERE group_id = ? "
            "ORDER BY timestamp_ms ASC, event_id ASC",
            (group_id,),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            try:
                decoded = json.loads(r["wire_json"])
            except (json.JSONDecodeError, TypeError) as exc:
                # Silently skipping one durable event changes the reduced
                # group state and can make replicas diverge. Surface explicit
                # corruption instead of returning a plausible partial log.
                raise ValueError(
                    "corrupt group event JSON: "
                    f"group={group_id.hex()} event={r['event_id']!r}"
                ) from exc
            if not isinstance(decoded, dict):
                raise ValueError(
                    "invalid group event shape: "
                    f"group={group_id.hex()} event={r['event_id']!r}"
                )
            out.append(decoded)
        return out

    def list_group_ids(self) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT group_id FROM groups ORDER BY updated_ms DESC"
        ).fetchall()
        return [r["group_id"] for r in rows]

    def upsert_group_meta(
        self,
        *,
        group_id: bytes,
        name: str,
        created_ms: int,
        state_hash: str,
    ) -> None:
        """Cache the materialized state of a group (name, hash) so the
        UI can render the list without re-reducing every event log."""
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO groups(group_id, name, created_ms, state_hash, updated_ms)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                    name = excluded.name,
                    state_hash = excluded.state_hash,
                    updated_ms = excluded.updated_ms
                """,
                (group_id, name, int(created_ms), state_hash, _now_ms()),
            )

    def get_group_meta(self, group_id: bytes) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT group_id, name, created_ms, state_hash, updated_ms "
            "FROM groups WHERE group_id = ?",
            (group_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "group_id": row["group_id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "state_hash": row["state_hash"],
            "updated_ms": row["updated_ms"],
        }

    # Sender chains.
    def upsert_sender_chain(
        self,
        *,
        group_id: bytes,
        sender_pub: bytes,
        direction: str,
        epoch: int,
        chain_key: bytes,
        counter: int,
    ) -> None:
        if direction not in ("in", "out"):
            raise ValueError(f"direction must be 'in' or 'out', got {direction!r}")
        if len(chain_key) != 32:
            raise ValueError("chain_key must be 32 bytes")
        if len(sender_pub) != 32:
            raise ValueError("sender_pub must be 32 bytes")
        if len(group_id) != 16:
            raise ValueError("group_id must be 16 bytes")
        # v0.20.7 (security audit H21): wrap the chain_key at rest if
        # the daemon was started with ONE_LINK_PASSPHRASE. Reads
        # detect the wrap marker and decrypt transparently; a stolen-
        # disk attacker without the passphrase sees AEAD ciphertext.
        # When no lockbox is configured this is a no-op passthrough
        # (cleartext on disk — same as before this fix).
        chain_key_at_rest = self._seal_field(GROUP_SENDER_CHAIN_KEY, chain_key)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO group_sender_chains(
                    group_id, sender_pub, direction, epoch,
                    chain_key, counter, updated_ms
                )
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id, sender_pub, direction, epoch)
                DO UPDATE SET
                    chain_key = excluded.chain_key,
                    counter = excluded.counter,
                    updated_ms = excluded.updated_ms
                """,
                (group_id, sender_pub, direction, int(epoch),
                 chain_key_at_rest, int(counter), _now_ms()),
            )

    def get_sender_chain(
        self,
        *,
        group_id: bytes,
        sender_pub: bytes,
        direction: str,
        epoch: Optional[int] = None,
    ) -> Optional[dict]:
        """Get the latest chain for (group, sender, direction). If
        `epoch` is given, returns that exact epoch; otherwise the
        highest known epoch."""
        if epoch is not None:
            row = self._conn.execute(
                "SELECT epoch, chain_key, counter FROM group_sender_chains "
                "WHERE group_id = ? AND sender_pub = ? AND direction = ? AND epoch = ?",
                (group_id, sender_pub, direction, int(epoch)),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT epoch, chain_key, counter FROM group_sender_chains "
                "WHERE group_id = ? AND sender_pub = ? AND direction = ? "
                "ORDER BY epoch DESC LIMIT 1",
                (group_id, sender_pub, direction),
            ).fetchone()
        if not row:
            return None
        # v0.20.7 (security audit H21): unwrap if the stored value
        # is lockbox-wrapped. Use length-based disambiguation: a
        # cleartext chain_key is exactly 32 bytes (validated at
        # write time), and a lockbox-wrapped one is 61 bytes
        # (marker + nonce + ct + tag). This avoids the 1/256 false
        # positive that a generic is_wrapped check would have on
        # the small-marker-byte collision class.
        chain_key = self._open_field(GROUP_SENDER_CHAIN_KEY, row["chain_key"])
        return {
            "epoch": row["epoch"],
            "chain_key": chain_key,
            "counter": row["counter"],
        }

    def _group_storage_usage(
        self, group_id: bytes, *, refresh: bool = False,
    ) -> tuple[int, int]:
        """Return cached (row count, retained UTF-8 body bytes) for a group."""

        cached = None if refresh else self._group_usage_cache.get(group_id)
        if cached is not None:
            return cached
        usage = self._conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM("
            "length(CAST(COALESCE(body, '') AS BLOB)) + "
            "length(CAST(COALESCE(original_body, '') AS BLOB))"
            "), 0) AS storage_bytes FROM group_messages WHERE group_id = ?",
            (group_id,),
        ).fetchone()
        cached = (
            int(usage["n"] if usage else 0),
            int(usage["storage_bytes"] if usage else 0),
        )
        self._group_usage_cache[group_id] = cached
        return cached

    def _group_edit_usage(
        self,
        *,
        group_id: bytes,
        current_body: object,
        original_body: object,
        new_body: str,
    ) -> tuple[int, int]:
        """Validate and return retained usage after one mutable group edit."""

        current_size = len(
            (current_body if isinstance(current_body, str) else "").encode("utf-8")
        )
        new_size = len(new_body.encode("utf-8"))

        def prospective(usage: tuple[int, int]) -> tuple[int, int]:
            count, byte_count = usage
            updated = (
                byte_count + new_size
                if original_body is None
                else byte_count - current_size + new_size
            )
            return count, updated

        updated_usage = prospective(self._group_storage_usage(group_id))
        if updated_usage[1] > MAX_GROUP_BODY_BYTES_PER_GROUP:
            updated_usage = prospective(
                self._group_storage_usage(group_id, refresh=True),
            )
        if updated_usage[1] > MAX_GROUP_BODY_BYTES_PER_GROUP:
            raise MessageQuotaExceeded(
                "group chat history quota reached; clear history before editing"
            )
        return updated_usage

    def insert_group_message(
        self,
        *,
        id: str,
        group_id: bytes,
        sender_pub: bytes,
        epoch: int,
        counter: int,
        direction: str,
        body: str,
        reply_to: Optional[str] = None,
        ts_ms: Optional[int] = None,
    ) -> bool:
        if not isinstance(id, str) or not id or len(id) > 128:
            raise ValueError("group message id must be 1..128 characters")
        if len(group_id) != 16 or len(sender_pub) != 32:
            raise ValueError("invalid group or sender identity")
        if direction not in {"in", "out"}:
            raise ValueError("group message direction must be 'in' or 'out'")
        if not isinstance(body, str) or not body.strip():
            raise ValueError("group message body must be non-empty")
        if len(body.encode("utf-8")) > MAX_TEXT_BODY_BYTES:
            raise ValueError(
                f"group message body exceeds {MAX_TEXT_BODY_BYTES} UTF-8 bytes"
            )
        ts = int(ts_ms if ts_ms is not None else _now_ms())
        values = (
            id, group_id, sender_pub, int(epoch), int(counter),
            direction, body, reply_to, ts,
        )
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id, group_id, sender_pub, epoch, counter, direction, "
                "body, original_body, reply_to, ts_ms "
                "FROM group_messages WHERE id = ?",
                (id,),
            ).fetchone()
            if existing is not None:
                immutable_body = (
                    existing["original_body"]
                    if existing["original_body"] is not None
                    else existing["body"]
                )
                stored = (
                    existing["id"], existing["group_id"],
                    existing["sender_pub"], existing["epoch"],
                    existing["counter"], existing["direction"],
                    immutable_body, existing["reply_to"], existing["ts_ms"],
                )
                if stored != values:
                    raise MessageIdConflict(
                        f"group message id {id!r} was reused for different content"
                    )
                return False
            count, byte_count = self._group_storage_usage(group_id)
            body_size = len(body.encode("utf-8"))
            if (
                count >= MAX_GROUP_MESSAGES_PER_GROUP
                or byte_count + body_size > MAX_GROUP_BODY_BYTES_PER_GROUP
            ):
                # Recount only at the boundary so a history clear cannot leave
                # a conservative cache as a permanent false rejection.
                count, byte_count = self._group_storage_usage(
                    group_id, refresh=True,
                )
            if (
                count >= MAX_GROUP_MESSAGES_PER_GROUP
                or byte_count + body_size > MAX_GROUP_BODY_BYTES_PER_GROUP
            ):
                raise MessageQuotaExceeded(
                    "group chat history quota reached; clear history before "
                    "accepting more messages"
                )
            self._conn.execute(
                """
                INSERT INTO group_messages(
                    id, group_id, sender_pub, epoch, counter,
                    direction, body, reply_to, ts_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._group_usage_cache[group_id] = (
                count + 1, byte_count + body_size,
            )
            return True

    def commit_group_ratchet_boundary(
        self,
        *,
        group_id: bytes,
        sender_pub: bytes,
        direction: str,
        epoch: int,
        expected_chain_key: bytes,
        expected_counter: int,
        advanced_chain_key: bytes,
        advanced_counter: int,
        message: Optional[dict[str, Any]] = None,
        receipt: Optional[dict[str, Any]] = None,
        action: Optional[dict[str, Any]] = None,
        outbox: Iterable[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        """FULL-sync one ratchet step with its history/outbox evidence.

        The encrypted envelope must never become remotely visible unless the
        exact chain advance and every intended recipient's durable outbox row
        committed together.  The receive side uses the same primitive with no
        outbox rows so a positive ACK binds the chain advance and plaintext
        history row to one SQLite commit.
        """

        if len(group_id) != 16 or len(sender_pub) != 32:
            raise ValueError("invalid group ratchet identity")
        if direction not in {"in", "out"}:
            raise ValueError("invalid group ratchet direction")
        if len(expected_chain_key) != 32 or len(advanced_chain_key) != 32:
            raise ValueError("group ratchet keys must be 32 bytes")
        if advanced_counter <= expected_counter:
            raise ValueError("group ratchet counter must advance")
        queued = [dict(row) for row in outbox]
        action_row = dict(action) if action is not None else None
        if action_row is not None and action_row.get("kind") not in {
            "reaction", "edit", "delete",
        }:
            raise ValueError("invalid durable group action")
        sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
        with self._write_lock:
            sync_row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous_sync = int(sync_row[0]) if sync_row else 1
            self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                current = self.get_sender_chain(
                    group_id=group_id,
                    sender_pub=sender_pub,
                    direction=direction,
                    epoch=int(epoch),
                )
                if (
                    current is None
                    or int(current["counter"]) != int(expected_counter)
                    or bytes(current["chain_key"]) != bytes(expected_chain_key)
                ):
                    raise MessageIdConflict(
                        "group ratchet state changed before durable commit"
                    )
                self.upsert_sender_chain(
                    group_id=group_id,
                    sender_pub=sender_pub,
                    direction=direction,
                    epoch=int(epoch),
                    chain_key=advanced_chain_key,
                    counter=int(advanced_counter),
                )
                inserted = None
                if message is not None:
                    inserted = self.insert_group_message(
                        id=str(message["id"]),
                        group_id=group_id,
                        sender_pub=sender_pub,
                        epoch=int(epoch),
                        counter=int(message["counter"]),
                        direction=direction,
                        body=message["body"],
                        reply_to=message.get("reply_to"),
                        ts_ms=int(message["ts_ms"]),
                    )
                receipt_inserted = None
                if receipt is not None:
                    receipt_inserted = self.record_message(
                        id=str(receipt["id"]),
                        ts_ms=int(receipt["ts_ms"]),
                        direction=direction,
                        peer_fp=str(receipt["peer_fp"]),
                        msg_type="GROUP_RECEIPT",
                        body=None,
                        metadata=dict(receipt["metadata"]),
                        durable=False,
                    )
                action_applied = None
                if action_row is not None and (
                    receipt is None or receipt_inserted is True
                ):
                    kind = str(action_row["kind"])
                    target = str(action_row.get("target") or "")
                    target_row = self._conn.execute(
                        "SELECT group_id, sender_pub, body, original_body, "
                        "deleted_at_ms "
                        "FROM group_messages WHERE id = ?",
                        (target,),
                    ).fetchone()
                    target_in_group = bool(
                        target_row is not None
                        and bytes(target_row["group_id"]) == group_id
                    )
                    if kind == "reaction":
                        emoji = str(action_row.get("emoji") or "")
                        actor_fp = str(action_row.get("actor_fp") or "")
                        op = str(action_row.get("op") or "")
                        if not actor_fp or not emoji or op not in {"add", "remove"}:
                            raise ValueError("invalid durable group reaction")
                        if target_in_group and target_row["deleted_at_ms"] is None:
                            if op == "add":
                                action_applied = self.record_reaction(
                                    target_msg_id=target,
                                    peer_fp=actor_fp,
                                    emoji=emoji,
                                )
                            else:
                                action_applied = self.remove_reaction(
                                    target_msg_id=target,
                                    peer_fp=actor_fp,
                                    emoji=emoji,
                                )
                        else:
                            action_applied = False
                    elif kind == "edit":
                        new_body = action_row.get("body")
                        if not isinstance(new_body, str) or not new_body.strip():
                            raise ValueError("invalid durable group edit body")
                        if len(new_body.encode("utf-8")) > MAX_TEXT_BODY_BYTES:
                            raise ValueError("durable group edit body is too large")
                        if (
                            target_in_group
                            and bytes(target_row["sender_pub"]) == sender_pub
                            and target_row["deleted_at_ms"] is None
                        ):
                            updated_usage = self._group_edit_usage(
                                group_id=group_id,
                                current_body=target_row["body"],
                                original_body=target_row["original_body"],
                                new_body=new_body,
                            )
                            update = self._conn.execute(
                                "UPDATE group_messages SET body = ?, edited_at_ms = ?, "
                                "original_body = COALESCE(original_body, body) "
                                "WHERE id = ? AND deleted_at_ms IS NULL",
                                (
                                    new_body,
                                    int(action_row["at_ms"]),
                                    target,
                                ),
                            )
                            action_applied = bool(update.rowcount)
                            if action_applied:
                                self._group_usage_cache[group_id] = updated_usage
                        else:
                            action_applied = False
                    else:
                        if target_in_group and bytes(target_row["sender_pub"]) == sender_pub:
                            update = self._conn.execute(
                                "UPDATE group_messages SET body = NULL, "
                                "deleted_at_ms = ?, "
                                "original_body = COALESCE(original_body, body) "
                                "WHERE id = ? AND deleted_at_ms IS NULL",
                                (int(action_row["at_ms"]), target),
                            )
                            action_applied = bool(update.rowcount)
                            if action_applied:
                                self._group_usage_cache.pop(group_id, None)
                        else:
                            action_applied = False
                outbox_ids: dict[str, int] = {}
                for row in queued:
                    peer_fp = str(row["peer_fp"])
                    outbox_ids[peer_fp] = self.enqueue_outbox(
                        peer_fp=peer_fp,
                        msg_id=str(row["msg_id"]),
                        msg_body=dict(row["msg_body"]),
                        msg_kind=str(row.get("msg_kind") or "GROUP_MSG"),
                    )
                self._conn.execute("COMMIT")
                return {
                    "message_inserted": inserted,
                    "receipt_inserted": receipt_inserted,
                    "action_applied": action_applied,
                    "outbox_ids": outbox_ids,
                }
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                self._text_usage_cache.clear()
                self._group_usage_cache.clear()
                self._outbox_usage_cache.clear()
                raise
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous={sync_names.get(previous_sync, 'NORMAL')}"
                )

    def recent_group_messages(
        self,
        *,
        group_id: bytes,
        limit: int = 100,
    ) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, group_id, sender_pub, epoch, counter, direction, "
            "body, reply_to, edited_at_ms, original_body, deleted_at_ms, "
            "ts_ms FROM group_messages WHERE group_id = ? "
            "ORDER BY ts_ms DESC LIMIT ?",
            (group_id, int(limit)),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "group_id": r["group_id"],
                "sender_pub": r["sender_pub"],
                "epoch": r["epoch"],
                "counter": r["counter"],
                "direction": r["direction"],
                "body": r["body"],
                "reply_to": r["reply_to"] if "reply_to" in r.keys() else None,
                "edited_at_ms": r["edited_at_ms"] if "edited_at_ms" in r.keys() else None,
                "original_body": r["original_body"] if "original_body" in r.keys() else None,
                "deleted_at_ms": r["deleted_at_ms"] if "deleted_at_ms" in r.keys() else None,
                "ts_ms": r["ts_ms"],
            }
            for r in rows
        ]

    def get_group_message(self, id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id, group_id, sender_pub, epoch, counter, direction, "
            "body, reply_to, edited_at_ms, original_body, deleted_at_ms, ts_ms "
            "FROM group_messages WHERE id = ?",
            (id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "group_id": row["group_id"],
            "sender_pub": row["sender_pub"],
            "epoch": row["epoch"],
            "counter": row["counter"],
            "direction": row["direction"],
            "body": row["body"],
            "reply_to": row["reply_to"],
            "edited_at_ms": row["edited_at_ms"],
            "original_body": row["original_body"],
            "deleted_at_ms": row["deleted_at_ms"],
            "ts_ms": row["ts_ms"],
        }

    def edit_group_message(
        self, *, id: str, new_body: str, edited_at_ms: int,
    ) -> Optional[dict]:
        if not isinstance(new_body, str) or not new_body.strip():
            raise ValueError("group message body must be non-empty")
        if len(new_body.encode("utf-8")) > MAX_TEXT_BODY_BYTES:
            raise ValueError(
                f"group message body exceeds {MAX_TEXT_BODY_BYTES} UTF-8 bytes"
            )
        with self._write_lock:
            cur = self.get_group_message(id)
            if cur is None or cur.get("deleted_at_ms"):
                return None
            group_id = bytes(cur["group_id"])
            updated_usage = self._group_edit_usage(
                group_id=group_id,
                current_body=cur.get("body"),
                original_body=cur.get("original_body"),
                new_body=new_body,
            )
            original = cur.get("original_body") or cur.get("body")
            update = self._conn.execute(
                "UPDATE group_messages SET body = ?, edited_at_ms = ?, "
                "original_body = COALESCE(original_body, ?) "
                "WHERE id = ? AND deleted_at_ms IS NULL",
                (new_body, int(edited_at_ms), original, id),
            )
            if not update.rowcount:
                return None
            self._group_usage_cache[group_id] = updated_usage
        return self.get_group_message(id)

    def delete_group_message(
        self, *, id: str, deleted_at_ms: int,
    ) -> Optional[dict]:
        with self._write_lock:
            cur = self.get_group_message(id)
            if cur is None:
                return None
            if cur.get("deleted_at_ms"):
                return cur
            update = self._conn.execute(
                "UPDATE group_messages SET body = NULL, deleted_at_ms = ?, "
                "original_body = COALESCE(original_body, body) "
                "WHERE id = ? AND deleted_at_ms IS NULL",
                (int(deleted_at_ms), id),
            )
            if not update.rowcount:
                return self.get_group_message(id)
            self._group_usage_cache.pop(bytes(cur["group_id"]), None)
        return self.get_group_message(id)

    def _row_to_peer(self, row: sqlite3.Row) -> PeerRecord:
        cols = row.keys()
        return PeerRecord(
            fingerprint=row["fingerprint"],
            short_id=row["short_id"],
            pubkey=row["pubkey"],
            hostname=row["hostname"],
            last_address=row["last_address"],
            last_port=row["last_port"],
            trust=row["trust"],
            first_seen_ms=row["first_seen_ms"],
            last_seen_ms=row["last_seen_ms"],
            local_alias=(
                row["local_alias"] if "local_alias" in cols else None
            ),
            muted=bool(row["muted"]) if "muted" in cols else False,
            verified_at_ms=(
                row["verified_at_ms"]
                if "verified_at_ms" in cols else None
            ),
            verified_method=(
                row["verified_method"]
                if "verified_method" in cols else None
            ),
            verified_note=(
                row["verified_note"]
                if "verified_note" in cols else None
            ),
            dm_ttl_ms=(
                row["dm_ttl_ms"]
                if "dm_ttl_ms" in cols else None
            ),
            muted_until_ms=(
                row["muted_until_ms"]
                if "muted_until_ms" in cols else None
            ),
        )

    def set_peer_profile(
        self,
        fingerprint: str,
        *,
        local_alias: Optional[str] = ...,  # type: ignore[assignment]
        muted: Optional[bool] = ...,       # type: ignore[assignment]
    ) -> Optional[PeerRecord]:
        """v0.7.3: update per-device profile fields. Pass `Ellipsis`
        (the default) to leave a field unchanged; pass None to
        explicitly clear the alias. Returns the refreshed record."""
        sets: list[str] = []
        params: list[Any] = []
        if local_alias is not Ellipsis:
            v = local_alias
            if v is not None:
                v = str(v).strip() or None
            sets.append("local_alias = ?")
            params.append(v)
        if muted is not Ellipsis:
            sets.append("muted = ?")
            params.append(1 if muted else 0)
        if not sets:
            return self.get_peer(fingerprint)
        params.append(fingerprint)
        with self._write_lock:
            self._conn.execute(
                f"UPDATE peers SET {', '.join(sets)} WHERE fingerprint = ?",  # nosec B608
                params,
            )
        return self.get_peer(fingerprint)

    # ─── verification (v0.7.7) ────────────────────────────────────────

    _ALLOWED_VERIFY_METHODS = (
        "sas-words-v3",
        "sas-digits",
        "sas-qr",
        "sas-audio",
        "manual",
    )

    def set_peer_verified(
        self,
        fingerprint: str,
        *,
        method: str,
        note: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> Optional[PeerRecord]:
        """v0.7.7: mark a peer as verified-in-person via a side-channel
        SAS confirm. `method` records HOW the user verified (digits
        read aloud, QR scan, audio readback, manual override).
        Records a capability_audit row so the trust transition is
        forensically auditable. Returns the refreshed PeerRecord, or
        None if the peer doesn't exist."""
        if method not in self._ALLOWED_VERIFY_METHODS:
            raise ValueError(
                f"verify method must be one of "
                f"{self._ALLOWED_VERIFY_METHODS!r}, got {method!r}"
            )
        clean_note: Optional[str] = None
        if note is not None:
            clean_note = str(note).strip() or None
            if clean_note and len(clean_note) > 280:
                # Same upper bound as a tweet — long enough for a
                # location/context reminder, short enough to render
                # in the device drawer without truncation games.
                raise ValueError("verify note too long (max 280 chars)")
        now = _now_ms()
        with self._write_lock:
            row = self._conn.execute(
                "SELECT verified_at_ms, verified_method FROM peers"
                " WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            before = {
                "verified_at_ms": row["verified_at_ms"],
                "verified_method": row["verified_method"],
            }
            self._conn.execute(
                "UPDATE peers SET verified_at_ms = ?, verified_method = ?,"
                " verified_note = ? WHERE fingerprint = ?",
                (now, method, clean_note, fingerprint),
            )
            after = {
                "verified_at_ms": now,
                "verified_method": method,
                "verified_note": clean_note,
            }
            if before != {
                "verified_at_ms": after["verified_at_ms"],
                "verified_method": after["verified_method"],
            } or row["verified_at_ms"] is None:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="verify_set",
                    before=before,
                    after=after,
                    actor=actor,
                    note=clean_note,
                )
        return self.get_peer(fingerprint)

    def clear_peer_verified(
        self,
        fingerprint: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Optional[PeerRecord]:
        """v0.7.7: revoke a verified-in-person mark (e.g. user no
        longer trusts the side channel, key changed, device changed
        hands). Audit log captures the before-state so the timeline
        survives the clear."""
        with self._write_lock:
            row = self._conn.execute(
                "SELECT verified_at_ms, verified_method, verified_note"
                " FROM peers WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            before = {
                "verified_at_ms": row["verified_at_ms"],
                "verified_method": row["verified_method"],
                "verified_note": row["verified_note"],
            }
            if row["verified_at_ms"] is None:
                # Idempotent no-op — nothing to clear, no audit row.
                return self.get_peer(fingerprint)
            self._conn.execute(
                "UPDATE peers SET verified_at_ms = NULL,"
                " verified_method = NULL, verified_note = NULL"
                " WHERE fingerprint = ?",
                (fingerprint,),
            )
            self._record_capability_audit(
                fingerprint=fingerprint,
                kind="verify_clear",
                before=before,
                after=None,
                actor=actor,
                note=note,
            )
        return self.get_peer(fingerprint)

    # ─── messages ─────────────────────────────────────────────────────

    def record_message(
        self,
        *,
        id: str,
        ts_ms: int,
        direction: str,
        peer_fp: str,
        msg_type: str,
        body: Optional[str],
        room_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        reply_to: Optional[str] = None,
        expires_at_ms: Optional[int] = None,
        durable: bool = False,
    ) -> bool:
        """Persist one immutable message envelope.

        ``id`` is an idempotency key, not a license to discard conflicts.
        An exact replay returns ``False``; reuse for different content raises
        :class:`MessageIdConflict`.  Chat/control writes can request a
        FULL-synchronous commit so an ACK is never sent for a row that only
        lived in process or OS page cache.
        """
        if not isinstance(id, str) or not id or len(id) > 128:
            raise ValueError("message id must be 1..128 characters")
        if direction not in {"in", "out"}:
            raise ValueError("message direction must be 'in' or 'out'")
        if not isinstance(peer_fp, str) or not peer_fp:
            raise ValueError("peer fingerprint required")
        if not isinstance(msg_type, str) or not msg_type:
            raise ValueError("message type required")
        if msg_type == "TEXT":
            if not isinstance(body, str):
                raise ValueError("TEXT body must be a string")
            body_size = len(body.encode("utf-8"))
            if body_size > MAX_TEXT_BODY_BYTES:
                raise ValueError(
                    f"TEXT body exceeds {MAX_TEXT_BODY_BYTES} UTF-8 bytes"
                )
        else:
            body_size = 0
        bounded_chat = msg_type in BOUNDED_CHAT_MESSAGE_TYPES
        bounded_types = _BOUNDED_CHAT_MESSAGE_TYPES_ORDERED

        metadata_json = json.dumps(
            metadata or {}, separators=(",", ":"), sort_keys=True,
            allow_nan=False,
        )
        storage_size = body_size + len(metadata_json.encode("utf-8"))
        values = (
            id, int(ts_ms), direction, peer_fp, msg_type, body, room_id,
            metadata_json, reply_to, expires_at_ms,
        )
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id, ts_ms, direction, peer_fp, msg_type, body,"
                " original_body, room_id, metadata_json, reply_to,"
                " expires_at_ms FROM messages WHERE id = ?",
                (id,),
            ).fetchone()
            if existing is not None:
                try:
                    existing_metadata = json.dumps(
                        json.loads(existing["metadata_json"] or "{}"),
                        separators=(",", ":"), sort_keys=True, allow_nan=False,
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise MessageIdConflict(
                        f"stored metadata for message id {id!r} is invalid"
                    ) from exc
                immutable_body = (
                    existing["original_body"]
                    if existing["original_body"] is not None
                    else existing["body"]
                )
                stored = (
                    existing["id"], int(existing["ts_ms"]),
                    existing["direction"], existing["peer_fp"],
                    existing["msg_type"], immutable_body,
                    existing["room_id"], existing_metadata,
                    existing["reply_to"], existing["expires_at_ms"],
                )
                if stored != values:
                    raise MessageIdConflict(
                        f"message id {id!r} was reused for different content"
                    )
                return False

            if bounded_chat:
                cached_usage = self._text_usage_cache.get(peer_fp)
                if cached_usage is None:
                    usage = self._conn.execute(
                        _BOUNDED_CHAT_USAGE_SQL,
                        (peer_fp, *bounded_types),
                    ).fetchone()
                    cached_usage = (
                        int(usage["n"] if usage else 0),
                        int(usage["storage_bytes"] if usage else 0),
                    )
                    self._text_usage_cache[peer_fp] = cached_usage
                count, byte_count = cached_usage
                if (
                    count >= MAX_TEXT_MESSAGES_PER_PEER
                    or byte_count + storage_size > MAX_TEXT_BODY_BYTES_PER_PEER
                ):
                    # A clear/edit/expiry can reduce authoritative usage behind
                    # the conservative cache. Recount only at the boundary.
                    usage = self._conn.execute(
                        _BOUNDED_CHAT_USAGE_SQL,
                        (peer_fp, *bounded_types),
                    ).fetchone()
                    count = int(usage["n"] if usage else 0)
                    byte_count = int(usage["storage_bytes"] if usage else 0)
                    self._text_usage_cache[peer_fp] = (count, byte_count)
                if (
                    count >= MAX_TEXT_MESSAGES_PER_PEER
                    or byte_count + storage_size > MAX_TEXT_BODY_BYTES_PER_PEER
                ):
                    raise MessageQuotaExceeded(
                        "chat history quota reached; clear history before "
                        "accepting more messages"
                    )

            previous_sync = 1
            if durable:
                sync_row = self._conn.execute("PRAGMA synchronous").fetchone()
                previous_sync = int(sync_row[0]) if sync_row else 1
                self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute(
                    """
                    INSERT INTO messages(
                        id, ts_ms, direction, peer_fp, msg_type, body, room_id,
                        metadata_json, reply_to, expires_at_ms
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
                if bounded_chat:
                    self._text_usage_cache[peer_fp] = (
                        count + 1, byte_count + storage_size,
                    )
            finally:
                if durable:
                    sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
                    self._conn.execute(
                        f"PRAGMA synchronous={sync_names.get(previous_sync, 'NORMAL')}"
                    )
            return True

    # ─── disappearing messages (v0.10.2) ──────────────────────────────

    # Friendly TTL labels — UI presents these; values are the ms.
    PEER_DM_TTL_PRESETS = {
        None: "Off",
        5 * 60 * 1000: "5 minutes",
        30 * 60 * 1000: "30 minutes",
        60 * 60 * 1000: "1 hour",
        24 * 60 * 60 * 1000: "1 day",
        7 * 24 * 60 * 60 * 1000: "1 week",
    }

    def set_peer_dm_ttl(
        self,
        fingerprint: str,
        ttl_ms: Optional[int],
    ) -> Optional[PeerRecord]:
        """v0.10.2: set the per-peer disappearing-message TTL. Pass
        None to clear (messages will no longer expire). Returns the
        refreshed PeerRecord, or None if the peer doesn't exist."""
        if ttl_ms is not None:
            if not isinstance(ttl_ms, int) or ttl_ms <= 0:
                raise ValueError("ttl_ms must be a positive integer")
            # Sanity cap: 30 days. Anything longer is "off" effectively;
            # we don't persist it because the UI's preset list doesn't
            # cover values that long.
            if ttl_ms > 30 * 24 * 60 * 60 * 1000:
                raise ValueError("ttl_ms too large (max 30 days)")
        with self._write_lock:
            row = self._conn.execute(
                "SELECT 1 FROM peers WHERE fingerprint = ?", (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE peers SET dm_ttl_ms = ? WHERE fingerprint = ?",
                (ttl_ms, fingerprint),
            )
        return self.get_peer(fingerprint)

    def get_peer_dm_ttl(self, fingerprint: str) -> Optional[int]:
        rec = self.get_peer(fingerprint)
        return rec.dm_ttl_ms if rec else None

    def set_peer_muted_until(
        self, fingerprint: str, until_ms: Optional[int],
    ) -> None:
        """v0.11.2: per-chat mute with duration.

        until_ms semantics:
          None  → unmute (clear muted_until_ms + legacy muted=0)
          0     → mute forever (muted_until_ms=0, legacy muted=1)
          N > 0 → mute until wall-clock ms N

        We also keep the legacy `muted` boolean column in sync so
        old read paths that haven't been ported still see a sane
        derived state."""
        if until_ms is not None and until_ms < 0:
            raise ValueError("until_ms must be None, 0, or positive")
        legacy_muted = 0 if until_ms is None else 1
        with self._write_lock:
            self._conn.execute(
                "UPDATE peers SET muted_until_ms = ?, muted = ? "
                "WHERE fingerprint = ?",
                (until_ms, legacy_muted, fingerprint),
            )

    def get_peer_muted_until(self, fingerprint: str) -> Optional[int]:
        rec = self.get_peer(fingerprint)
        return rec.muted_until_ms if rec else None

    def expire_due_messages(self, *, now_ms: Optional[int] = None) -> list[str]:
        """v0.10.2: tombstone every message whose expires_at_ms has
        passed. Returns the list of msg_ids that were just expired
        so the daemon can broadcast msg_delete WS events.

        Idempotent — re-expiring a row that's already deleted is a
        no-op (the AND deleted_at_ms IS NULL clause filters them out)."""
        cutoff = now_ms if now_ms is not None else _now_ms()
        with self._write_lock:
            rows = self._conn.execute(
                "SELECT id, peer_fp FROM messages"
                " WHERE expires_at_ms IS NOT NULL"
                "   AND expires_at_ms <= ?"
                "   AND deleted_at_ms IS NULL",
                (cutoff,),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if not ids:
                return []
            # Mark all expired in one statement.
            self._conn.execute(
                "UPDATE messages SET body = NULL, deleted_at_ms = ?,"
                " original_body = COALESCE(original_body, body)"
                " WHERE expires_at_ms IS NOT NULL"
                "   AND expires_at_ms <= ?"
                "   AND deleted_at_ms IS NULL",
                (cutoff, cutoff),
            )
            for row in rows:
                self._text_usage_cache.pop(row["peer_fp"], None)
        return ids

    # ─── reactions (v0.7.5) ───────────────────────────────────────────

    def record_reaction(
        self, *, target_msg_id: str, peer_fp: str, emoji: str,
    ) -> bool:
        """Add a reaction. Idempotent on (target, peer, emoji).
        Returns True if a new row was inserted, False if it already
        existed."""
        if not target_msg_id or not peer_fp or not emoji:
            raise ValueError("target_msg_id, peer_fp, emoji required")
        # Bound emoji length — actual single grapheme can be up to
        # ~50 bytes in Unicode, but a "reaction" with hundreds of
        # combining marks is abuse.
        if len(emoji) > 64:
            raise ValueError("emoji too long")
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO message_reactions(
                    target_msg_id, peer_fp, emoji, ts_ms
                ) VALUES(?, ?, ?, ?)
                ON CONFLICT(target_msg_id, peer_fp, emoji) DO NOTHING
                """,
                (target_msg_id, peer_fp, emoji, _now_ms()),
            )
            return cur.rowcount > 0

    def remove_reaction(
        self, *, target_msg_id: str, peer_fp: str, emoji: str,
    ) -> bool:
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM message_reactions"
                " WHERE target_msg_id = ? AND peer_fp = ? AND emoji = ?",
                (target_msg_id, peer_fp, emoji),
            )
            return cur.rowcount > 0

    def list_reactions_for_messages(
        self, msg_ids: Iterable[str],
    ) -> dict[str, dict[str, list[str]]]:
        """Return {target_msg_id: {emoji: [peer_fp, ...], ...}}.
        Empty for messages with no reactions."""
        ids = [str(m) for m in msg_ids if m]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        rows = self._conn.execute(
            f"SELECT target_msg_id, peer_fp, emoji FROM message_reactions"
            f" WHERE target_msg_id IN ({placeholders}) ORDER BY ts_ms ASC",  # nosec B608
            ids,
        ).fetchall()
        out: dict[str, dict[str, list[str]]] = {}
        for r in rows:
            mid = r["target_msg_id"]
            out.setdefault(mid, {}).setdefault(r["emoji"], []).append(r["peer_fp"])
        return out

    def search_messages(
        self,
        query: str,
        *,
        limit: int = 50,
        peer_fp: Optional[str] = None,
        room_id: Optional[str] = None,
        prefix_match: bool = True,
    ) -> list[MessageRecord]:
        """FTS5 search over message bodies. When prefix_match=True
        (default) the user's plain query is normalized so each
        whitespace-separated token becomes an FTS5 prefix-match
        (`"token"*`). That turns 'k' into '"k"*' so it finds messages
        containing 'kanye', 'kjg', 'oksana' - not just messages
        with the standalone token 'k'. This matches naive-user
        expectations.

        Callers that pre-format the query for FTS5 (e.g. wrapping
        in phrase quotes for global_search) should pass
        prefix_match=False to bypass the normalizer.
        """
        if prefix_match:
            fts_query = _normalize_user_query_to_fts5_prefix(query)
            if not fts_query:
                return []
        else:
            fts_query = query
        clauses = ["messages.rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)"]
        params: list[Any] = [fts_query]
        if peer_fp:
            clauses.append("messages.peer_fp = ?")
            params.append(peer_fp)
        if room_id:
            clauses.append("messages.room_id = ?")
            params.append(room_id)
        where = " AND ".join(clauses)
        sql = (
            f"SELECT * FROM messages WHERE {where} "  # nosec B608
            f"ORDER BY ts_ms DESC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_msg(r) for r in rows]

    def global_search(
        self,
        query: str,
        *,
        per_kind_limit: int = 10,
    ) -> dict:
        """v0.9.3: search across messages (FTS5), peers (LIKE), and
        groups (LIKE). Returns a dict keyed by kind so the caller
        can render each section.

        Query is escaped for FTS5 (`"…"` quoted) so user input
        with operators like AND / OR / NEAR doesn't accidentally
        change the search semantics. Empty query returns empty
        results without hitting the DB."""
        q = (query or "").strip()
        out: dict = {"messages": [], "peers": [], "groups": []}
        if not q:
            return out
        # 1. Messages via FTS5. Phrase-quoted so special chars don't
        # error out the parser ("auth: user" would otherwise be
        # parsed as field-restricted query).
        try:
            phrased = '"' + q.replace('"', '""') + '"'
            # global_search hand-rolls FTS5 phrase quoting above;
            # opt out of the prefix-match normalizer so the literal
            # phrase semantics are preserved.
            msgs = self.search_messages(
                phrased, limit=per_kind_limit, prefix_match=False,
            )
        except Exception:
            msgs = []
        for m in msgs:
            out["messages"].append({
                "id": m.id,
                "ts_ms": m.ts_ms,
                "direction": m.direction,
                "peer_fp": m.peer_fp,
                "msg_type": m.msg_type,
                "body": (m.body or "")[:200],
                "room_id": m.room_id,
                "reply_to": m.reply_to,
            })
        # 2. Peers by hostname / display alias / short_id / fingerprint
        # prefix. Case-insensitive.
        like = f"%{q}%"
        peer_rows = self._conn.execute(
            "SELECT * FROM peers"
            " WHERE LOWER(IFNULL(hostname, '')) LIKE LOWER(?)"
            "    OR LOWER(IFNULL(local_alias, '')) LIKE LOWER(?)"
            "    OR LOWER(short_id) LIKE LOWER(?)"
            "    OR LOWER(fingerprint) LIKE LOWER(?)"
            " ORDER BY (trust = 'pinned') DESC, last_seen_ms DESC"
            " LIMIT ?",
            (like, like, like, like, int(per_kind_limit)),
        ).fetchall()
        for r in peer_rows:
            rec = self._row_to_peer(r)
            out["peers"].append({
                "fingerprint": rec.fingerprint,
                "short_id": rec.short_id,
                "hostname": rec.hostname,
                "display_name": rec.display_name,
                "trust": rec.trust,
                "is_verified": rec.is_verified,
                "last_seen_ms": rec.last_seen_ms,
            })
        # 3. Groups by name. groups.name was added in v0.6.2.
        try:
            grp_rows = self._conn.execute(
                "SELECT group_id, name, updated_ms FROM groups"
                " WHERE LOWER(IFNULL(name, '')) LIKE LOWER(?)"
                " ORDER BY updated_ms DESC LIMIT ?",
                (like, int(per_kind_limit)),
            ).fetchall()
        except Exception:
            grp_rows = []
        for r in grp_rows:
            gid = r["group_id"]
            try:
                gid_hex = gid.hex() if isinstance(gid, (bytes, bytearray)) else str(gid)
            except Exception:
                gid_hex = ""
            out["groups"].append({
                "group_id": gid_hex,
                "name": r["name"] or "",
                "updated_ms": r["updated_ms"],
            })
        return out

    def recent_messages(
        self,
        *,
        peer_fp: Optional[str] = None,
        room_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[MessageRecord]:
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if room_id:
            clauses.append("room_id = ?")
            params.append(room_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM messages{where} ORDER BY ts_ms DESC LIMIT ?"  # nosec B608
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_msg(r) for r in reversed(rows)]

    def _row_to_msg(self, row: sqlite3.Row) -> MessageRecord:
        try:
            md = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            md = {}
        cols = row.keys()
        return MessageRecord(
            id=row["id"],
            ts_ms=row["ts_ms"],
            direction=row["direction"],
            peer_fp=row["peer_fp"],
            msg_type=row["msg_type"],
            body=row["body"],
            room_id=row["room_id"],
            metadata=md,
            reply_to=row["reply_to"] if "reply_to" in cols else None,
            edited_at_ms=row["edited_at_ms"] if "edited_at_ms" in cols else None,
            original_body=row["original_body"] if "original_body" in cols else None,
            deleted_at_ms=row["deleted_at_ms"] if "deleted_at_ms" in cols else None,
            expires_at_ms=row["expires_at_ms"] if "expires_at_ms" in cols else None,
        )

    # ─── edit / delete (v0.7.6) ───────────────────────────────────────

    def edit_message(
        self, *, id: str, new_body: str, edited_at_ms: int,
    ) -> Optional[MessageRecord]:
        """v0.7.6: replace a message's body and stamp edited_at_ms.
        Preserves the original body in original_body the first time
        an edit happens (subsequent edits don't overwrite it).
        Returns the refreshed record, or None if not found / deleted."""
        if not isinstance(new_body, str) or not new_body.strip():
            raise ValueError("message body must be non-empty")
        new_body_size = len(new_body.encode("utf-8"))
        if new_body_size > MAX_TEXT_BODY_BYTES:
            raise ValueError(
                f"message body exceeds {MAX_TEXT_BODY_BYTES} UTF-8 bytes"
            )
        with self._write_lock:
            cur = self.get_message(id)
            if cur is None or cur.is_deleted:
                return None
            if cur.msg_type == "TEXT":
                bounded_types = _BOUNDED_CHAT_MESSAGE_TYPES_ORDERED
                usage = self._conn.execute(
                    _BOUNDED_CHAT_USAGE_SQL,
                    (cur.peer_fp, *bounded_types),
                ).fetchone()
                count = int(usage["n"] if usage else 0)
                byte_count = int(usage["storage_bytes"] if usage else 0)
                old_body_size = len((cur.body or "").encode("utf-8"))
                # The first edit moves the prior body into original_body and
                # adds the new body; later edits replace only the mutable copy.
                edited_byte_count = (
                    byte_count + new_body_size
                    if cur.original_body is None
                    else byte_count - old_body_size + new_body_size
                )
                if edited_byte_count > MAX_TEXT_BODY_BYTES_PER_PEER:
                    raise MessageQuotaExceeded(
                        "chat history quota reached; clear history before editing"
                    )
            original = cur.original_body or cur.body
            update = self._conn.execute(
                "UPDATE messages SET body = ?, edited_at_ms = ?,"
                " original_body = COALESCE(original_body, ?)"
                " WHERE id = ? AND deleted_at_ms IS NULL",
                (new_body, int(edited_at_ms), original, id),
            )
            if not update.rowcount:
                return None
            if cur.msg_type == "TEXT":
                self._text_usage_cache[cur.peer_fp] = (
                    count, edited_byte_count,
                )
        return self.get_message(id)

    def clear_peer_history(self, peer_fp: str) -> int:
        """v0.11.5: hard-delete all message rows for a peer locally.
        Returns the number of rows deleted. The other side's copy
        is untouched — this is purely local data hygiene."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM messages WHERE peer_fp = ?",
                (peer_fp,),
            )
            self._text_usage_cache.pop(peer_fp, None)
            return cur.rowcount or 0

    def clear_group_history(self, group_id_hex: str) -> int:
        """v0.11.5: hard-delete all group message rows locally.
        Group event log (membership) is preserved — only chat
        content is wiped. Returns row count. Database failures propagate so
        callers never report a successful destructive action that did not
        happen."""
        group_id = bytes.fromhex(group_id_hex)
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM group_messages WHERE group_id = ?",
                (group_id,),
            )
            self._group_usage_cache.pop(group_id, None)
            return cur.rowcount or 0

    def _delete_all_locked(self, table: str, where: str = "", params: tuple = ()) -> int:
        sql = f"DELETE FROM {table}" + (f" WHERE {where}" if where else "")  # nosec B608
        cur = self._conn.execute(sql, params)
        return int(cur.rowcount or 0)

    @contextlib.contextmanager
    def _trace_clear_transaction_locked(self):
        """Make one trace-clear request all-or-nothing.

        The connection normally runs in autocommit mode.  Without an explicit
        transaction, a failure after the first ``DELETE`` permanently removed
        those earlier rows even if the HTTP request ultimately failed.  Keep
        the write lock held by the caller, acquire SQLite's writer reservation
        before the first mutation, and never disguise a rollback failure as a
        successful wipe.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._conn.execute("COMMIT")
        except BaseException:
            try:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
            except DB_ERRORS:
                log.critical(
                    "trace-clear rollback failed; database transaction "
                    "state is uncertain",
                    exc_info=True,
                )
            raise

    def _clear_chat_traces_locked(self) -> dict[str, int]:
        return {
            "messages": self._delete_all_locked("messages"),
            "group_messages": self._delete_all_locked("group_messages"),
            "message_reactions": self._delete_all_locked("message_reactions"),
            "outbox": self._delete_all_locked("outbox"),
        }

    def clear_chat_traces(self) -> dict[str, int]:
        """Hard-delete local chat traces without removing peers/groups."""
        with self._write_lock:
            with self._trace_clear_transaction_locked():
                cleared = self._clear_chat_traces_locked()
            self._text_usage_cache.clear()
            self._group_usage_cache.clear()
            self._outbox_usage_cache.clear()
            return cleared

    def _clear_file_traces_locked(self) -> dict[str, int]:
        return {
            "file_messages": self._delete_all_locked(
                "messages",
                "LOWER(msg_type) IN ('file', 'file_done', 'file_offer')",
            ),
            "transfers": self._delete_all_locked(
                "transfers", "LOWER(kind) = 'file'",
            ),
            "file_index_cache": self._delete_all_locked("file_index_cache"),
            "chunk_sources": self._delete_all_locked("chunk_sources"),
            "chunk_availability": self._delete_all_locked("chunk_availability"),
        }

    def clear_file_traces(self) -> dict[str, int]:
        """Clear file-transfer records and file metadata caches only.

        This intentionally does not delete inbox files or source files
        from the user's filesystem.
        """
        with self._write_lock:
            with self._trace_clear_transaction_locked():
                return self._clear_file_traces_locked()

    def _clear_folder_traces_locked(self) -> dict[str, int]:
        return {
            "folder_pending_applies": self._delete_all_locked(
                "folder_pending_applies"
            ),
            "folders": self._delete_all_locked("folders"),
            "folder_manifest": self._delete_all_locked("folder_manifest"),
            "folder_audit": self._delete_all_locked("folder_audit"),
            "manifest_conflicts": self._delete_all_locked("manifest_conflicts"),
            "folder_permissions": self._delete_all_locked(
                "settings", "key LIKE 'folder_permission:%'",
            ),
        }

    def clear_folder_traces(self) -> dict[str, int]:
        """Remove folder-sync metadata without deleting watched folders."""
        with self._write_lock:
            with self._trace_clear_transaction_locked():
                return self._clear_folder_traces_locked()

    def _clear_activity_traces_locked(self) -> dict[str, int]:
        self._conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("activity_cleared_before_ms", str(_now_ms())),
        )
        return {
            "transfers": self._delete_all_locked("transfers"),
            "capability_audit": self._delete_all_locked("capability_audit"),
            "key_change_events": self._delete_all_locked("key_change_events"),
            "folder_audit": self._delete_all_locked("folder_audit"),
            "self_mesh_audit": self._delete_all_locked("self_mesh_audit"),
            "self_mesh_perf_samples": self._delete_all_locked("self_mesh_perf_samples"),
            "device_guardian_events": self._delete_all_locked("device_guardian_events"),
            "remote_instruction_seen": self._delete_all_locked("remote_instruction_seen"),
        }

    def clear_activity_traces(self) -> dict[str, int]:
        """Clear local audit/activity rows. Peer identities are preserved."""
        with self._write_lock:
            with self._trace_clear_transaction_locked():
                return self._clear_activity_traces_locked()

    def clear_all_app_traces(self) -> dict[str, dict[str, int] | int]:
        """Clear local app traces while preserving identity, peers, and trust.

        The wipe removes local records/caches that reveal app activity.
        It does not delete user files from the filesystem and does not
        revoke device identity or pairing/trust state.
        """
        with self._write_lock:
            with self._trace_clear_transaction_locked():
                result: dict[str, dict[str, int] | int] = {
                    "chat": self._clear_chat_traces_locked(),
                    "files": self._clear_file_traces_locked(),
                    "folders": self._clear_folder_traces_locked(),
                    "activity": self._clear_activity_traces_locked(),
                }
                result["route_memory"] = self._delete_all_locked("route_memory")
                result["route_candidates"] = self._delete_all_locked(
                    "route_candidates"
                )
                # Courier bundles use a filesystem outbox, not a SQLite
                # table.  Preserve the response key for API compatibility;
                # the former DELETE targeted a table that has never existed
                # and depended on the broad exception swallow above.
                result["courier_outbox"] = 0
                result["settings_trace_keys"] = self._delete_all_locked(
                    "settings",
                    "key LIKE 'chatpref:%'",
                )
            self._text_usage_cache.clear()
            self._group_usage_cache.clear()
            self._outbox_usage_cache.clear()
            return result

    def storage_usage_by_peer(self) -> list[dict]:
        """v0.11.6: per-peer usage rollup for the Storage pane.
        Returns one entry per peer that has any messages, with
        msg_count and file_bytes (sum of metadata.size for file
        rows). The frontend joins this with peer display names."""
        rows = self._conn.execute(
            "SELECT peer_fp, COUNT(*) AS n, "
            "  SUM(CASE WHEN msg_type='file' THEN 1 ELSE 0 END) AS file_n "
            "FROM messages WHERE deleted_at_ms IS NULL "
            "GROUP BY peer_fp"
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            fp = r["peer_fp"]
            # Sum metadata.size across the file rows for this peer.
            file_bytes = 0
            file_rows = self._conn.execute(
                "SELECT metadata_json FROM messages "
                "WHERE peer_fp = ? AND msg_type = 'file' "
                "  AND deleted_at_ms IS NULL",
                (fp,),
            ).fetchall()
            for fr in file_rows:
                try:
                    md = json.loads(fr["metadata_json"]) if fr["metadata_json"] else {}
                except Exception:
                    md = {}
                size = md.get("size")
                if isinstance(size, (int, float)):
                    file_bytes += int(size)
            out.append({
                "peer_fp": fp,
                "msg_count": int(r["n"] or 0),
                "file_count": int(r["file_n"] or 0),
                "file_bytes": file_bytes,
            })
        # Largest by file_bytes first, then by msg_count.
        out.sort(key=lambda d: (-d["file_bytes"], -d["msg_count"]))
        return out

    def storage_usage_by_group(self) -> list[dict]:
        """v0.11.6: per-group rollup. Falls back to empty list when
        the group_messages table doesn't exist on this build."""
        try:
            rows = self._conn.execute(
                "SELECT group_id, COUNT(*) AS n "
                "FROM group_messages GROUP BY group_id"
            ).fetchall()
        except Exception:
            return []
        out: list[dict] = []
        for r in rows:
            out.append({
                "group_id": r["group_id"]
                            if isinstance(r["group_id"], str)
                            else r["group_id"].hex(),
                "msg_count": int(r["n"] or 0),
            })
        out.sort(key=lambda d: -d["msg_count"])
        return out

    def list_peer_files(
        self, peer_fp: str, *, limit: int = 2000, offset: int = 0,
    ) -> list[MessageRecord]:
        """v0.11.5: messages with file metadata for the media gallery.
        Returns oldest → newest so the gallery scrolls naturally.

        2026-05-21 audit T3-I: previously this scanned the entire
        per-peer file-message history with no LIMIT. On a chatty peer
        with 10k+ file messages, every gallery render shipped megabytes
        and traversed the full table. The default 2000-row cap keeps
        the gallery responsive; ``offset`` lets the UI paginate older
        history on demand. Caller-supplied limits are clamped to a
        sane ceiling (10k) to prevent control-plane DoS.
        """
        limit = max(1, min(int(limit), 10_000))
        offset = max(0, int(offset))
        rows = self._conn.execute(
            "SELECT * FROM messages "
            "WHERE peer_fp = ? AND msg_type = 'file' "
            "  AND (deleted_at_ms IS NULL) "
            "ORDER BY ts_ms ASC "
            "LIMIT ? OFFSET ?",
            (peer_fp, limit, offset),
        ).fetchall()
        return [self._row_to_msg(r) for r in rows]

    def delete_message(
        self, *, id: str, deleted_at_ms: int,
    ) -> Optional[MessageRecord]:
        """v0.7.6: soft-delete. Body cleared; deleted_at_ms stamped.
        Idempotent on already-deleted rows."""
        cur = self.get_message(id)
        if cur is None:
            return None
        if cur.is_deleted:
            return cur
        with self._write_lock:
            self._conn.execute(
                "UPDATE messages SET body = NULL, deleted_at_ms = ?,"
                " original_body = COALESCE(original_body, body)"
                " WHERE id = ?",
                (int(deleted_at_ms), id),
            )
            self._text_usage_cache.pop(cur.peer_fp, None)
        return self.get_message(id)

    def get_message(self, id: str) -> Optional[MessageRecord]:
        row = self._conn.execute(
            "SELECT * FROM messages WHERE id = ?", (id,),
        ).fetchone()
        return self._row_to_msg(row) if row else None

    # ─── read markers (v0.7.6) ────────────────────────────────────────

    def record_read_marker(self, peer_fp: str, up_to_ts_ms: int) -> None:
        """Mark all messages from `peer_fp` with ts ≤ `up_to_ts_ms`
        as read by us. Monotonic — older markers can't overwrite a
        newer one."""
        if not peer_fp:
            return
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO peer_read_markers(peer_fp, up_to_ts_ms, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(peer_fp) DO UPDATE SET
                    up_to_ts_ms = MAX(peer_read_markers.up_to_ts_ms, excluded.up_to_ts_ms),
                    updated_ms = excluded.updated_ms
                """,
                (peer_fp, int(up_to_ts_ms), _now_ms()),
            )

    def get_read_marker(self, peer_fp: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT up_to_ts_ms FROM peer_read_markers WHERE peer_fp = ?",
            (peer_fp,),
        ).fetchone()
        return int(row["up_to_ts_ms"]) if row else None

    def list_read_markers(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT peer_fp, up_to_ts_ms FROM peer_read_markers"
        ).fetchall()
        return {r["peer_fp"]: int(r["up_to_ts_ms"]) for r in rows}

    # --- transfers ---------------------------------------------------------

    def upsert_transfer(
        self,
        *,
        id: str,
        direction: str,
        peer_fp: str,
        kind: str,
        name: str,
        size: int,
        blob_hash: Optional[str] = None,
        status: str = "queued",
        progress_bytes: int = 0,
        total_bytes: Optional[int] = None,
        chunks_done: int = 0,
        chunks_total: int = 0,
        raw_bytes: int = 0,
        wire_bytes: int = 0,
        metadata: Optional[dict] = None,
    ) -> TransferRecord:
        if direction not in ("in", "out"):
            raise ValueError(f"invalid transfer direction: {direction!r}")
        if status not in (
            "queued", "offered", "active", "complete", "failed", "paused",
        ):
            raise ValueError(f"invalid transfer status: {status!r}")
        total = int(size if total_bytes is None else total_bytes)
        now = _now_ms()
        # 2026-05-22 audit T3-J: wrap the ``path`` field inside
        # ``metadata`` before JSON-encoding. Other metadata fields
        # stay cleartext (no PII risk + read paths consume them
        # without going through unwrap). Wrap is a no-op when the
        # path-PII encryptor isn't attached or the field is empty,
        # so legacy rows + un-wrapped paths keep working.
        meta_to_store = dict(metadata or {})
        raw_path = meta_to_store.get("path")
        if isinstance(raw_path, str) and raw_path:
            meta_to_store["path"] = self._seal_field(TRANSFER_SOURCE_PATH, raw_path)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO transfers(
                    id, direction, peer_fp, kind, name, size, blob_hash, status,
                    progress_bytes, total_bytes, chunks_done, chunks_total,
                    raw_bytes, wire_bytes, updated_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    direction = excluded.direction,
                    peer_fp = excluded.peer_fp,
                    kind = excluded.kind,
                    name = excluded.name,
                    size = excluded.size,
                    blob_hash = excluded.blob_hash,
                    status = excluded.status,
                    progress_bytes = excluded.progress_bytes,
                    total_bytes = excluded.total_bytes,
                    chunks_done = excluded.chunks_done,
                    chunks_total = excluded.chunks_total,
                    raw_bytes = excluded.raw_bytes,
                    wire_bytes = excluded.wire_bytes,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    id, direction, peer_fp, kind, name, int(size), blob_hash,
                    status, int(progress_bytes), total, int(chunks_done),
                    int(chunks_total), int(raw_bytes), int(wire_bytes), now,
                    json.dumps(meta_to_store, separators=(",", ":"), sort_keys=True),
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM transfers WHERE id = ?", (id,)
            ).fetchone()
        return self._row_to_transfer(row)

    def update_transfer(self, id: str, **fields: Any) -> Optional[TransferRecord]:
        allowed = {
            "status", "progress_bytes", "total_bytes", "chunks_done",
            "chunks_total", "raw_bytes", "wire_bytes", "metadata",
        }
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unknown transfer fields: {sorted(bad)!r}")
        # 2026-05-21 audit T3-K: hold the write lock across both the
        # read and the upsert. Without this, two concurrent updates
        # to the same transfer (e.g. parallel chunk ACK + a status
        # flip) each read the same `current`, each rebuild the full
        # record, and the second write clobbers the first — progress
        # counters and metadata.path could regress. The lock is an
        # RLock so callers that already hold it (e.g. a chunk-ACK
        # batch processor) re-enter cleanly.
        # 2026-05-22 audit Batch V: distinguish "caller did not pass
        # metadata" from "caller passed empty metadata" via a sentinel.
        # _row_to_transfer returns metadata={} when the stored JSON
        # is corrupt (or path-PII unwrap fails), and previously the
        # default fields.pop("metadata", current.metadata) inherited
        # that empty dict, then upserted it back — permanently
        # destroying the on-disk path field even when the caller
        # only wanted to bump a status. Sentinel-path skips the
        # metadata_json column entirely on the UPDATE statement so
        # the raw on-disk blob is preserved verbatim.
        _METADATA_UNSET = object()
        with self._write_lock:
            current = self.get_transfer(id)
            if current is None:
                return None
            metadata_arg = fields.pop("metadata", _METADATA_UNSET)
            if metadata_arg is _METADATA_UNSET:
                # Partial UPDATE: don't touch metadata_json. Only
                # the explicitly-named scalar fields (plus updated_ms)
                # roll forward.
                merged: dict[str, Any] = {
                    "status": current.status,
                    "progress_bytes": current.progress_bytes,
                    "total_bytes": current.total_bytes,
                    "chunks_done": current.chunks_done,
                    "chunks_total": current.chunks_total,
                    "raw_bytes": current.raw_bytes,
                    "wire_bytes": current.wire_bytes,
                }
                merged.update(fields)
                now = _now_ms()
                self._conn.execute(
                    """
                    UPDATE transfers
                    SET status = ?, progress_bytes = ?, total_bytes = ?,
                        chunks_done = ?, chunks_total = ?, raw_bytes = ?,
                        wire_bytes = ?, updated_ms = ?
                    WHERE id = ?
                    """,
                    (
                        merged["status"],
                        int(merged["progress_bytes"]),
                        int(merged["total_bytes"]),
                        int(merged["chunks_done"]),
                        int(merged["chunks_total"]),
                        int(merged["raw_bytes"]),
                        int(merged["wire_bytes"]),
                        now,
                        current.id,
                    ),
                )
                # 2026-05-22 audit Batch CC perf: build the returned
                # TransferRecord from the in-memory ``current`` + the
                # merged updates instead of a second SELECT. The
                # original metadata is preserved untouched (sentinel
                # path), so just clone ``current`` with the new fields.
                return TransferRecord(
                    id=current.id,
                    direction=current.direction,
                    peer_fp=current.peer_fp,
                    kind=current.kind,
                    name=current.name,
                    size=current.size,
                    blob_hash=current.blob_hash,
                    status=merged["status"],
                    progress_bytes=int(merged["progress_bytes"]),
                    total_bytes=int(merged["total_bytes"]),
                    chunks_done=int(merged["chunks_done"]),
                    chunks_total=int(merged["chunks_total"]),
                    raw_bytes=int(merged["raw_bytes"]),
                    wire_bytes=int(merged["wire_bytes"]),
                    updated_ms=now,
                    metadata=current.metadata,
                )
            metadata = metadata_arg
            data = {
                "id": current.id,
                "direction": current.direction,
                "peer_fp": current.peer_fp,
                "kind": current.kind,
                "name": current.name,
                "size": current.size,
                "blob_hash": current.blob_hash,
                "status": current.status,
                "progress_bytes": current.progress_bytes,
                "total_bytes": current.total_bytes,
                "chunks_done": current.chunks_done,
                "chunks_total": current.chunks_total,
                "raw_bytes": current.raw_bytes,
                "wire_bytes": current.wire_bytes,
                "metadata": metadata,
            }
            data.update(fields)
            return self.upsert_transfer(**data)

    def update_transfer_durable(
        self,
        id: str,
        **fields: Any,
    ) -> Optional[TransferRecord]:
        """Commit a transfer boundary with power-loss durability.

        The general activity ledger uses WAL + ``synchronous=NORMAL`` for
        throughput.  A pre-wire offer boundary and a FILE_COMMIT receipt are
        different: losing either row can turn crash recovery into a duplicate
        delivery. Temporarily raise this one autocommit transaction to FULL
        while holding the connection write lock. In WAL mode FULL synchronizes
        the WAL at transaction commit, which is the durable boundary the wire
        protocol requires.
        """

        synchronous_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
        with self._write_lock:
            row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous = int(row[0]) if row else 1
            self._conn.execute("PRAGMA synchronous = FULL")
            try:
                return self.update_transfer(id, **fields)
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous = {synchronous_names.get(previous, 'NORMAL')}"
                )

    def upsert_transfer_durable(self, **fields: Any) -> TransferRecord:
        """FULL-sync an entire transfer row before a peer-visible boundary.

        ``update_transfer_durable`` cannot change immutable contract columns
        such as ``peer_fp``. The authenticated peer fingerprint can become
        known only after dialing, so the final pre-offer row occasionally has
        to replace the provisional contract atomically. This companion keeps
        that replacement under the same FULL-sync guarantee.
        """

        synchronous_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
        with self._write_lock:
            row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous = int(row[0]) if row else 1
            self._conn.execute("PRAGMA synchronous = FULL")
            try:
                return self.upsert_transfer(**fields)
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous = {synchronous_names.get(previous, 'NORMAL')}"
                )

    def get_transfer(self, id: str) -> Optional[TransferRecord]:
        row = self._conn.execute(
            "SELECT * FROM transfers WHERE id = ?", (id,)
        ).fetchone()
        return self._row_to_transfer(row) if row else None

    def get_transfer_by_blob(self, blob_hash: str) -> Optional[TransferRecord]:
        """Resolve the best transfer row for a content hash.

        Backs content-addressed file serving (``/api/files/by-blob/{hash}``).
        A single blob can have several ledger rows — the same image received
        twice, an offer row plus its completed row, both an inbound and an
        outbound copy. For preview/open we want the row that points at a
        file actually on disk, so prefer a completed row whose
        ``metadata.path`` exists, then any row with a ``metadata.path``,
        then simply the newest. Returns None when no row carries the blob.
        """
        if not blob_hash:
            return None
        rows = self._conn.execute(
            "SELECT * FROM transfers WHERE blob_hash = ? ORDER BY updated_ms DESC",
            (blob_hash,),
        ).fetchall()
        if not rows:
            return None
        recs = [self._row_to_transfer(r) for r in rows]

        def _path_on_disk(rec: TransferRecord) -> bool:
            p = (rec.metadata or {}).get("path")
            if not isinstance(p, str) or not p:
                return False
            try:
                return Path(p).is_file()
            except OSError:
                return False

        # rows are already newest-first; the first hit in each tier wins.
        for rec in recs:
            if rec.status == "complete" and _path_on_disk(rec):
                return rec
        for rec in recs:
            if _path_on_disk(rec):
                return rec
        return recs[0]

    def list_transfers(
        self,
        *,
        peer_fp: Optional[str] = None,
        limit: int = 100,
    ) -> list[TransferRecord]:
        limit = max(1, min(int(limit), 500))
        if peer_fp:
            rows = self._conn.execute(
                "SELECT * FROM transfers WHERE peer_fp = ? ORDER BY updated_ms DESC LIMIT ?",
                (peer_fp, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM transfers ORDER BY updated_ms DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_transfer(r) for r in rows]

    @staticmethod
    def _transfer_has_commit_dedup_evidence(rec: TransferRecord) -> bool:
        """Keep delivery idempotency/outcome evidence out of activity pruning.

        A FILE_COMMIT response can be lost for arbitrarily long. Deleting the
        only durable delivery-nonce/commit mapping would make that exact retry
        look brand new and allocate a duplicate inbox path. These compact rows
        are protocol tombstones, not disposable UI history.
        """

        metadata = dict(rec.metadata or {})
        if rec.direction == "out":
            # A legacy receiver cannot prove its final durable commit, and a
            # local accounting crash after FILE_OFFER can likewise leave the
            # remote outcome ambiguous. Removing either row would erase the
            # sender-side no-offer guard and recreate the duplicate-delivery
            # bug. Explicitly proven pre-wire refusals are safe to remove.
            if metadata.get("pre_wire") is True:
                return False
            delivery_state = metadata.get("delivery_state")
            if delivery_state in {"sent_unconfirmed", "outcome_unknown"}:
                return True
            if metadata.get("error_class") in {
                "DeliveryUnconfirmed",
                "SenderCommitAccountingError",
            }:
                return True
            if (
                isinstance(metadata.get("offer_boundary_contract"), dict)
                and metadata.get("commit_confirmed") is not True
            ):
                return True
            return False
        if rec.direction != "in":
            return False
        for key in ("file_commit_evidence", "file_commit_prepare"):
            evidence = metadata.get(key)
            if not isinstance(evidence, dict):
                continue
            delivery_id = evidence.get("delivery_id")
            if (
                isinstance(delivery_id, str)
                and len(delivery_id) == 32
                and all(ch in "0123456789abcdef" for ch in delivery_id)
                and evidence.get("peer_fp") == rec.peer_fp
                and evidence.get("blob") == rec.blob_hash
                and type(evidence.get("size")) is int
                and int(evidence["size"]) == int(rec.size)
            ):
                return True
        return False

    def delete_transfer(self, id: str) -> bool:
        with self._write_lock:
            row = self._conn.execute(
                "SELECT * FROM transfers WHERE id = ?",
                (id,),
            ).fetchone()
            if row is None:
                return False
            try:
                raw_metadata = row["metadata_json"]
                decoded_metadata = json.loads(raw_metadata) if raw_metadata else {}
                if not isinstance(decoded_metadata, dict):
                    return False
                rec = self._row_to_transfer(row)
            except Exception:
                # Corrupt/unreadable accounting is not evidence that deleting
                # a possible commit tombstone is safe.
                return False
            # A live transfer row is a storage/protocol root, not disposable
            # activity history.  Cancellation first transitions it to a
            # terminal state; only then may delete remove the ledger row and
            # consider reclaiming daemon-owned upload staging.
            if rec.status not in ("complete", "failed"):
                return False
            if self._transfer_has_commit_dedup_evidence(rec):
                return False
            cur = self._conn.execute("DELETE FROM transfers WHERE id = ?", (id,))
            deleted = cur.rowcount > 0
            if deleted:
                # Filesystem reclamation is deliberately subordinate to the
                # state lock: another transfer cannot acquire the same source
                # between last-reference proof and unlink.  The lifecycle
                # helper fails closed (and leaves the file in place) on any
                # unreadable row, path escape, link, or identity race.
                try:
                    from one_link.storage_lifecycle import (
                        reclaim_removed_transfer_uploads,
                    )

                    result = reclaim_removed_transfer_uploads(
                        self,
                        [raw_metadata],
                    )
                    if result.errors:
                        log.warning(
                            "transfer %s deleted but upload cleanup retained "
                            "its source: %s",
                            id,
                            "; ".join(result.errors),
                        )
                except Exception as exc:
                    # Ledger deletion is already committed in autocommit mode.
                    # Never turn an incidental cleanup failure into a caller
                    # retry that could obscure the successful state mutation.
                    log.warning(
                        "transfer %s deleted; upload cleanup failed closed: %s",
                        id,
                        exc,
                    )
            return deleted

    def peer_had_blob(self, peer_fp: str, blob_hash: str) -> bool:
        """2026-05-22 audit Batch S — has this peer ever legitimately
        received (direction='out' to them) or sent (direction='in' from
        them) the blob identified by ``blob_hash``?

        Used to gate folder-less ``BLOB_REQUEST`` lookups: a peer can
        only refresh a blob hash they were already authorized to hold,
        not enumerate arbitrary hashes against our store.
        """
        if not peer_fp or not blob_hash:
            return False
        row = self._conn.execute(
            "SELECT 1 FROM transfers "
            "WHERE peer_fp = ? AND blob_hash = ? "
            "LIMIT 1",
            (peer_fp, blob_hash),
        ).fetchone()
        return row is not None

    def prune_transfers(
        self,
        *,
        statuses: Iterable[str] = ("complete", "failed"),
        older_than_ms: Optional[int] = None,
        keep_latest: int = 200,
        max_remove: int = 500,
    ) -> int:
        # Only terminal activity is eligible, regardless of caller input.
        # Deduplication also caps SQL placeholders at two for untrusted API
        # arrays instead of allowing a huge local request to inflate a query.
        clean_statuses = sorted(
            {
                str(status)
                for status in statuses
                if str(status) in ("complete", "failed")
            }
        )
        if not clean_statuses:
            return 0
        keep_latest = max(0, int(keep_latest))
        max_remove = max(1, min(int(max_remove), 5_000))
        params: list[Any] = clean_statuses
        where = f"status IN ({','.join('?' for _ in clean_statuses)})"
        if older_than_ms is not None:
            where += " AND updated_ms < ?"
            params.append(int(older_than_ms))
        keep_clause = ""
        if keep_latest:
            keep_clause = (
                " AND id NOT IN ("
                "SELECT id FROM transfers ORDER BY updated_ms DESC LIMIT ?"
                ")"
            )
            params.append(keep_latest)
        # Scan beyond the removal budget so old commit tombstones or corrupt
        # fail-closed rows cannot permanently starve later disposable
        # history. The scan itself remains finite; only ``max_remove`` rows
        # are ever mutated per call.
        scan_limit = min(50_000, max(5_000, max_remove * 20))
        params.append(scan_limit)
        with self._write_lock:
            candidates = self._conn.execute(
                f"SELECT * FROM transfers WHERE {where}{keep_clause} "  # nosec B608
                "ORDER BY updated_ms ASC, id ASC LIMIT ?",
                params,
            ).fetchall()
            removable: list[tuple[str]] = []
            removed_metadata: list[str] = []
            for row in candidates:
                try:
                    raw_metadata = row["metadata_json"]
                    decoded_metadata = json.loads(raw_metadata) if raw_metadata else {}
                    if not isinstance(decoded_metadata, dict):
                        rec = None
                    else:
                        rec = self._row_to_transfer(row)
                except (KeyError, TypeError, ValueError):
                    # Fail closed on unreadable metadata; it may be the only
                    # surviving commit proof for a delivery nonce.
                    rec = None
                if rec is None:
                    continue
                if (
                    rec.status in ("complete", "failed")
                    and not self._transfer_has_commit_dedup_evidence(rec)
                ):
                    removable.append((rec.id,))
                    removed_metadata.append(raw_metadata)
                    if len(removable) >= max_remove:
                        break
            if not removable:
                return 0
            self._conn.executemany(
                "DELETE FROM transfers WHERE id = ?",
                removable,
            )
            try:
                from one_link.storage_lifecycle import (
                    reclaim_removed_transfer_uploads,
                )

                result = reclaim_removed_transfer_uploads(
                    self,
                    removed_metadata,
                )
                if result.errors:
                    log.warning(
                        "transfer prune retained one or more upload sources: %s",
                        "; ".join(result.errors),
                    )
            except Exception as exc:
                log.warning("transfer prune upload cleanup failed closed: %s", exc)
            return len(removable)

    # ─── outbox (v0.7.1: store-and-forward) ──────────────────────────

    def upsert_route_memory(
        self,
        *,
        peer_fp: str,
        route: str,
        attempts: int,
        successes: int,
        failures: int,
        score: float,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        if not peer_fp:
            raise ValueError("peer_fp is required")
        if not route:
            raise ValueError("route is required")
        attempts_i = max(0, int(attempts))
        successes_i = max(0, min(attempts_i, int(successes)))
        failures_i = max(0, min(attempts_i - successes_i, int(failures)))
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO route_memory(
                    peer_fp, route, attempts, successes, failures, score,
                    latency_ms, bandwidth_bps, updated_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(peer_fp, route) DO UPDATE SET
                    attempts = excluded.attempts,
                    successes = excluded.successes,
                    failures = excluded.failures,
                    score = excluded.score,
                    latency_ms = excluded.latency_ms,
                    bandwidth_bps = excluded.bandwidth_bps,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    peer_fp,
                    route,
                    attempts_i,
                    successes_i,
                    failures_i,
                    float(score),
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    now,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )

    def list_route_memory(self, peer_fp: Optional[str] = None) -> list[dict]:
        if peer_fp:
            rows = self._conn.execute(
                """
                SELECT * FROM route_memory
                WHERE peer_fp = ?
                ORDER BY score DESC, updated_ms DESC
                """,
                (peer_fp,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM route_memory ORDER BY peer_fp, score DESC"
            ).fetchall()
        out: list[dict] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
            except json.JSONDecodeError:
                metadata = {}
            out.append({
                "peer_fp": row["peer_fp"],
                "route": row["route"],
                "attempts": int(row["attempts"]),
                "successes": int(row["successes"]),
                "failures": int(row["failures"]),
                "score": float(row["score"]),
                "latency_ms": (
                    float(row["latency_ms"]) if row["latency_ms"] is not None else None
                ),
                "bandwidth_bps": (
                    float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
                ),
                "updated_ms": int(row["updated_ms"]),
                "metadata": metadata if isinstance(metadata, dict) else {},
            })
        return out

    def upsert_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
        source: str,
        verified: bool = False,
        attempts: int | None = None,
        successes: int | None = None,
        failures: int | None = None,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        last_error: str | None = None,
        expires_ms: int | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        if not peer_fp:
            raise ValueError("peer_fp is required")
        if not route:
            raise ValueError("route is required")
        if not transport:
            raise ValueError("transport is required")
        host_s = str(host or "").strip()
        if not host_s:
            raise ValueError("host is required")
        port_i = int(port)
        if port_i <= 0 or port_i > 65535:
            raise ValueError("port must be 1..65535")
        current = self.get_route_candidate(
            peer_fp=peer_fp,
            route=str(route),
            transport=str(transport),
            host=host_s,
            port=port_i,
        )
        attempts_i = (
            int((current or {}).get("attempts") or 0)
            if attempts is None else max(0, int(attempts))
        )
        successes_i = (
            int((current or {}).get("successes") or 0)
            if successes is None else max(0, int(successes))
        )
        failures_i = (
            int((current or {}).get("failures") or 0)
            if failures is None else max(0, int(failures))
        )
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO route_candidates(
                    peer_fp, route, transport, host, port, source, verified,
                    attempts, successes, failures, latency_ms, bandwidth_bps,
                    last_error, first_seen_ms, updated_ms, expires_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(peer_fp, route, transport, host, port) DO UPDATE SET
                    source = excluded.source,
                    verified = MAX(route_candidates.verified, excluded.verified),
                    attempts = CASE
                        WHEN excluded.attempts IS NULL THEN route_candidates.attempts
                        ELSE excluded.attempts
                    END,
                    successes = CASE
                        WHEN excluded.successes IS NULL THEN route_candidates.successes
                        ELSE excluded.successes
                    END,
                    failures = CASE
                        WHEN excluded.failures IS NULL THEN route_candidates.failures
                        ELSE excluded.failures
                    END,
                    latency_ms = COALESCE(excluded.latency_ms, route_candidates.latency_ms),
                    bandwidth_bps = COALESCE(excluded.bandwidth_bps, route_candidates.bandwidth_bps),
                    last_error = excluded.last_error,
                    updated_ms = excluded.updated_ms,
                    expires_ms = excluded.expires_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    peer_fp,
                    str(route),
                    str(transport),
                    host_s,
                    port_i,
                    str(source)[:80],
                    1 if verified else 0,
                    attempts_i,
                    successes_i,
                    failures_i,
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    str(last_error)[:240] if last_error else None,
                    now,
                    now,
                    int(expires_ms) if expires_ms else None,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )

    def observe_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
        ok: bool,
        source: str = "runtime",
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        error: str | None = None,
        verified: bool | None = None,
        expires_ms: int | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        current = self.get_route_candidate(
            peer_fp=peer_fp,
            route=route,
            transport=transport,
            host=host,
            port=port,
        )
        attempts = int((current or {}).get("attempts") or 0) + 1
        successes = int((current or {}).get("successes") or 0) + (1 if ok else 0)
        failures = int((current or {}).get("failures") or 0) + (0 if ok else 1)
        self.upsert_route_candidate(
            peer_fp=peer_fp,
            route=route,
            transport=transport,
            host=host,
            port=port,
            source=source,
            verified=bool(verified if verified is not None else ok),
            attempts=attempts,
            successes=successes,
            failures=failures,
            latency_ms=latency_ms,
            bandwidth_bps=bandwidth_bps,
            last_error=None if ok else error,
            expires_ms=expires_ms,
            metadata={**((current or {}).get("metadata") or {}), **(metadata or {})},
        )

    def get_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
    ) -> Optional[dict]:
        row = self._conn.execute(
            """
            SELECT * FROM route_candidates
            WHERE peer_fp = ? AND route = ? AND transport = ? AND host = ? AND port = ?
            """,
            (peer_fp, route, transport, str(host), int(port)),
        ).fetchone()
        return self._row_to_route_candidate(row) if row else None

    def list_route_candidates(
        self,
        peer_fp: Optional[str] = None,
        *,
        verified_only: bool = False,
        include_expired: bool = False,
        limit: int = 64,
    ) -> list[dict]:
        now = _now_ms()
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if verified_only:
            clauses.append("verified = 1")
        if not include_expired:
            clauses.append("(expires_ms IS NULL OR expires_ms > ?)")
            params.append(now)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT * FROM route_candidates
            {where}
            ORDER BY
                verified DESC,
                successes DESC,
                failures ASC,
                COALESCE(bandwidth_bps, 0) DESC,
                COALESCE(latency_ms, 999999) ASC,
                updated_ms DESC
            LIMIT ?
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            (*params, max(1, min(512, int(limit)))),
        ).fetchall()
        return [self._row_to_route_candidate(r) for r in rows]

    def prune_route_candidates(self, *, now_ms: int | None = None) -> int:
        now = _now_ms() if now_ms is None else int(now_ms)
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM route_candidates WHERE expires_ms IS NOT NULL AND expires_ms <= ?",
                (now,),
            )
            return int(cur.rowcount)

    def upsert_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
        device_kind: str,
        cert: bytes | None = None,
        label: str = "",
        local: bool = False,
        trusted: bool = True,
        revoked: bool = False,
        safety_state: str | None = None,
        metadata: Optional[dict] = None,
        added_ms: int | None = None,
    ) -> dict:
        """Record one separately addressable device under a root identity."""
        from one_link.device_guardian import normalize_safety_state

        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        kind = str(device_kind or "").strip()
        if not kind:
            raise ValueError("device_kind is required")
        now = _now_ms()
        added = now if added_ms is None else int(added_ms)
        safety = normalize_safety_state(
            safety_state or ("revoked" if revoked else "trusted")
        )
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_devices(
                    root_pub, device_pub, cert, device_kind, label, local,
                    trusted, revoked, added_ms, updated_ms, metadata_json,
                    safety_state, safety_updated_ms, guardian_epoch, safety_reason
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_pub, device_pub) DO UPDATE SET
                    cert = COALESCE(excluded.cert, self_mesh_devices.cert),
                    device_kind = excluded.device_kind,
                    label = excluded.label,
                    local = excluded.local,
                    trusted = CASE
                        WHEN self_mesh_devices.safety_state IN (
                            'maybe_lost', 'frozen', 'revoked', 'quarantined'
                        ) OR excluded.safety_state IN (
                            'maybe_lost', 'frozen', 'revoked', 'quarantined'
                        )
                        THEN 0
                        ELSE excluded.trusted
                    END,
                    revoked = CASE
                        WHEN self_mesh_devices.safety_state = 'revoked'
                             OR excluded.safety_state = 'revoked'
                        THEN 1
                        ELSE excluded.revoked
                    END,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json,
                    safety_state = CASE
                        WHEN self_mesh_devices.safety_state = 'trusted'
                        THEN excluded.safety_state
                        ELSE self_mesh_devices.safety_state
                    END,
                    safety_updated_ms = CASE
                        WHEN self_mesh_devices.safety_updated_ms = 0
                        THEN excluded.safety_updated_ms
                        ELSE self_mesh_devices.safety_updated_ms
                    END
                """,
                (
                    bytes(root_pub),
                    bytes(device_pub),
                    bytes(cert) if cert is not None else None,
                    kind[:64],
                    str(label or "")[:120],
                    1 if local else 0,
                    1 if trusted else 0,
                    1 if revoked else 0,
                    added,
                    now,
                    meta_json,
                    safety,
                    now,
                    1 if safety == "revoked" else 0,
                    "enrolled revoked" if safety == "revoked" else "",
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
            (bytes(root_pub), bytes(device_pub)),
        ).fetchone()
        return self._row_to_self_mesh_device(row)

    def upsert_self_mesh_root(
        self,
        *,
        root_pub: bytes,
        label: str = "",
        root_seed: bytes | None = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Create/update a personal mesh root identity.

        ``root_seed`` is optional. When present, it is wrapped with the
        daemon LockBox if one is configured, matching other high-value
        state secrets.
        """
        self._validate_self_mesh_pub(root_pub, "root_pub")
        if root_seed is not None and len(bytes(root_seed)) != 32:
            raise ValueError("root_seed must be 32 bytes")
        if root_seed is not None:
            self._validate_self_mesh_root_seed(
                root_seed=bytes(root_seed),
                root_pub=bytes(root_pub),
            )
        now = _now_ms()
        seed_at_rest = (
            self._seal_field(SELF_MESH_ROOT_SEED, bytes(root_seed))
            if root_seed is not None else None
        )
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_roots(
                    root_pub, label, root_seed, created_ms, updated_ms,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_pub) DO UPDATE SET
                    label = excluded.label,
                    root_seed = COALESCE(excluded.root_seed, self_mesh_roots.root_seed),
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    bytes(root_pub),
                    str(label or "")[:120],
                    seed_at_rest,
                    now,
                    now,
                    meta_json,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_roots WHERE root_pub = ?",
            (bytes(root_pub),),
        ).fetchone()
        return self._row_to_self_mesh_root(row, include_seed=False)

    def list_self_mesh_roots(self, *, include_seed: bool = False) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM self_mesh_roots ORDER BY updated_ms DESC, label ASC"
        ).fetchall()
        return [
            self._row_to_self_mesh_root(r, include_seed=include_seed)
            for r in rows
        ]

    def get_self_mesh_root(
        self,
        root_pub: bytes,
        *,
        include_seed: bool = False,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        row = self._conn.execute(
            "SELECT * FROM self_mesh_roots WHERE root_pub = ?",
            (bytes(root_pub),),
        ).fetchone()
        return (
            self._row_to_self_mesh_root(row, include_seed=include_seed)
            if row else None
        )

    def get_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        row = self._conn.execute(
            "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
            (bytes(root_pub), bytes(device_pub)),
        ).fetchone()
        return self._row_to_self_mesh_device(row) if row else None

    def revoke_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                UPDATE self_mesh_devices
                SET revoked = 1, trusted = 0, safety_state = 'revoked',
                    guardian_epoch = guardian_epoch + 1,
                    safety_updated_ms = ?, safety_reason = 'legacy revoke',
                    updated_ms = ?
                WHERE root_pub = ? AND device_pub = ?
                """,
                (now, now, bytes(root_pub), bytes(device_pub)),
            )
        return self.get_self_mesh_device(root_pub=root_pub, device_pub=device_pub)

    def delete_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
    ) -> bool:
        """2026-05-23: hard-delete a self-mesh device row.

        Distinct from revoke_self_mesh_device which leaves a tombstone
        (revoked=True, safety_state='revoked'). Hard delete is for the
        Settings / Devices prune UI — user wants the stale entry GONE,
        not just marked. Use revoke when the device's keys may be
        compromised and you want the audit trail; use delete when the
        entry is debris (failed pair, regenerated identity, test
        artifact) that should not clutter the UI.

        Refuses to delete a row marked ``local=True`` — that's the
        daemon's own self-mesh entry and removing it via UI would
        instantly recreate on next boot anyway.

        Returns True if a row was removed, False if no match.
        """
        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM self_mesh_devices "
                "WHERE root_pub = ? AND device_pub = ? AND local = 0",
                (bytes(root_pub), bytes(device_pub)),
            )
            return cur.rowcount > 0

    def set_self_mesh_device_safety(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
        requested_state: str,
        actor_device_pub: bytes | None = None,
        proofs: Any = None,
        reason: str = "",
        actor_is_local: bool = True,
        active_suspicion: bool = False,
        metadata: Optional[dict] = None,
        ts_ms: int | None = None,
    ) -> dict:
        from one_link.device_guardian import (
            decide_device_safety_transition,
            event_hash,
            normalize_proofs,
        )

        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        if actor_device_pub is not None:
            self._validate_self_mesh_pub(actor_device_pub, "actor_device_pub")
        now = _now_ms() if ts_ms is None else int(ts_ms)
        with self._write_lock:
            row = self._conn.execute(
                "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
                (bytes(root_pub), bytes(device_pub)),
            ).fetchone()
            if row is None:
                raise ValueError("device is not enrolled")
            current = row["safety_state"] if "safety_state" in row.keys() else (
                "revoked" if row["revoked"] else "trusted"
            )
            decision = decide_device_safety_transition(
                current,
                requested_state,
                proofs=proofs,
                actor_is_local=actor_is_local,
                active_suspicion=active_suspicion,
                now=now,
            )
            prev = self._conn.execute(
                """
                SELECT event_hash FROM device_guardian_events
                WHERE root_pub = ? AND device_pub = ?
                ORDER BY id DESC LIMIT 1
                """,
                (bytes(root_pub), bytes(device_pub)),
            ).fetchone()
            prev_hash = str(prev["event_hash"]) if prev else ""
            proof_list = sorted(normalize_proofs(proofs))
            event_body = {
                "ts_ms": now,
                "root_pub": bytes(root_pub).hex(),
                "device_pub": bytes(device_pub).hex(),
                "actor_device_pub": bytes(actor_device_pub).hex() if actor_device_pub else "",
                "from_state": current,
                "to_state": decision.target_state,
                "allowed": decision.allowed,
                "event": decision.event,
                "reason": str(reason or decision.detail)[:500],
                "proofs": proof_list,
                "effects": list(decision.effects),
            }
            digest = event_hash(event_body, prev_hash)
            self._conn.execute(
                """
                INSERT INTO device_guardian_events(
                    ts_ms, root_pub, device_pub, actor_device_pub,
                    from_state, to_state, decision, reason, proofs_json,
                    effects_json, event_hash, prev_hash, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    bytes(root_pub),
                    bytes(device_pub),
                    bytes(actor_device_pub) if actor_device_pub is not None else None,
                    current,
                    decision.target_state,
                    "allowed" if decision.allowed else "denied",
                    str(reason or decision.detail)[:500],
                    json.dumps(proof_list, separators=(",", ":")),
                    json.dumps(list(decision.effects), separators=(",", ":")),
                    digest,
                    prev_hash,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )
            if decision.allowed and decision.target_state != current:
                revoked = decision.target_state == "revoked"
                trusted = decision.target_state in {"trusted", "recovered", "suspicious"}
                self._conn.execute(
                    """
                    UPDATE self_mesh_devices
                    SET safety_state = ?, safety_updated_ms = ?,
                        safety_reason = ?, updated_ms = ?,
                        revoked = ?, trusted = ?,
                        guardian_epoch = guardian_epoch + ?
                    WHERE root_pub = ? AND device_pub = ?
                    """,
                    (
                        decision.target_state,
                        now,
                        str(reason or decision.detail)[:500],
                        now,
                        1 if revoked else 0,
                        1 if trusted and not revoked else 0,
                        1 if decision.target_state in {"frozen", "revoked", "quarantined"} else 0,
                        bytes(root_pub),
                        bytes(device_pub),
                    ),
                )
            device = self.get_self_mesh_device(root_pub=root_pub, device_pub=device_pub)
            return {
                "ok": bool(decision.allowed),
                "decision": decision.to_dict(),
                "device": device,
                "event_hash": digest,
                "previous_hash": prev_hash,
            }

    def is_self_mesh_peer(self, peer_fp: str) -> bool:
        """Return whether ``peer_fp`` is a currently eligible self device.

        This predicate grants implicit consent to inbound folder offers, so a
        mere database row is not authority.  The row must represent another
        physical device, remain trusted and route-eligible, and carry a live
        root-signed certificate binding its root, public key, and device kind.
        Malformed or legacy uncertified rows fail closed and can be re-enrolled.
        """
        from one_link.device_guardian import safety_blocks_routing
        from one_link.identity import fingerprint_of
        from one_link.identity_dag import verify_device_cert

        if not isinstance(peer_fp, str) or not peer_fp:
            return False
        target = peer_fp.lower()
        try:
            rows = self.list_self_mesh_devices(include_revoked=False)
        except Exception:
            return False
        for row in rows:
            if (
                bool(row.get("local"))
                or not bool(row.get("trusted"))
                or bool(row.get("revoked"))
                or safety_blocks_routing(row.get("safety_state"))
            ):
                continue
            pub = row.get("device_pub")
            root_pub = row.get("root_pub")
            cert = row.get("cert")
            if (
                not isinstance(pub, bytes)
                or len(pub) != 32
                or not isinstance(root_pub, bytes)
                or len(root_pub) != 32
                or not isinstance(cert, bytes)
                or not cert
            ):
                continue
            try:
                parsed = verify_device_cert(cert, expected_root_pub=root_pub)
            except (TypeError, ValueError):
                parsed = None
            if parsed is None:
                continue
            if parsed.device_pub != pub or parsed.device_kind != row.get("device_kind"):
                continue
            fp = fingerprint_of(pub)
            if fp and fp.lower() == target:
                return True
        return False

    def list_self_mesh_devices(
        self,
        *,
        root_pub: bytes | None = None,
        include_revoked: bool = True,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        if not include_revoked:
            clauses.append("revoked = 0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT * FROM self_mesh_devices
            {where}
            ORDER BY local DESC, revoked ASC, updated_ms DESC, label ASC
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            params,
        ).fetchall()
        return [self._row_to_self_mesh_device(r) for r in rows]

    def list_device_guardian_events(
        self,
        *,
        root_pub: bytes | None = None,
        device_pub: bytes | None = None,
        limit: int = 200,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        if device_pub is not None:
            self._validate_self_mesh_pub(device_pub, "device_pub")
            clauses.append("device_pub = ?")
            params.append(bytes(device_pub))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        sql = (
            "SELECT * FROM device_guardian_events"
            f"{where} ORDER BY ts_ms DESC, id DESC LIMIT ?"  # nosec B608
        )
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_device_guardian_event(r) for r in rows]

    def upsert_self_mesh_presence(
        self,
        *,
        device_pub: bytes,
        state: str,
        updated_ms: int,
        sequence: int = 0,
        battery_pct: int | None = None,
        network: str = "unknown",
        free_bytes: int | None = None,
        route: str | None = None,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Merge a self-mesh presence fact using (sequence, updated_ms)."""
        self._validate_self_mesh_pub(device_pub, "device_pub")
        if state not in {"awake", "asleep", "dormant", "offline"}:
            raise ValueError("invalid self-mesh presence state")
        if network not in {"ethernet", "wifi", "cellular", "bluetooth", "offline", "unknown"}:
            raise ValueError("invalid self-mesh network")
        if battery_pct is not None and not (0 <= int(battery_pct) <= 100):
            raise ValueError("battery_pct must be 0..100")
        if free_bytes is not None and int(free_bytes) < 0:
            raise ValueError("free_bytes must be non-negative")
        seq = max(0, int(sequence))
        updated = int(updated_ms)
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_presence(
                    device_pub, state, sequence, updated_ms, battery_pct,
                    network, free_bytes, route, latency_ms, bandwidth_bps,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_pub) DO UPDATE SET
                    state = excluded.state,
                    sequence = excluded.sequence,
                    updated_ms = excluded.updated_ms,
                    battery_pct = excluded.battery_pct,
                    network = excluded.network,
                    free_bytes = excluded.free_bytes,
                    route = excluded.route,
                    latency_ms = excluded.latency_ms,
                    bandwidth_bps = excluded.bandwidth_bps,
                    metadata_json = excluded.metadata_json
                WHERE
                    excluded.sequence > self_mesh_presence.sequence
                    OR (
                        excluded.sequence = self_mesh_presence.sequence
                        AND excluded.updated_ms >= self_mesh_presence.updated_ms
                    )
                """,
                (
                    bytes(device_pub),
                    state,
                    seq,
                    updated,
                    int(battery_pct) if battery_pct is not None else None,
                    network,
                    int(free_bytes) if free_bytes is not None else None,
                    str(route)[:80] if route else None,
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    meta_json,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_presence WHERE device_pub = ?",
            (bytes(device_pub),),
        ).fetchone()
        return self._row_to_self_mesh_presence(row)

    def list_self_mesh_presence(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM self_mesh_presence
            ORDER BY updated_ms DESC, sequence DESC
            """
        ).fetchall()
        return [self._row_to_self_mesh_presence(r) for r in rows]

    def mark_remote_instruction_seen(
        self,
        *,
        command_id: str,
        expires_ms: int,
        action: str = "",
        controller_device_pub: bytes | None = None,
        target_device_pub: bytes | None = None,
        now_ms: int | None = None,
    ) -> bool:
        """Remember a remote-instruct command id.

        Returns True on first sight and False for a replay. Expired rows
        are pruned before insertion. New ids fail closed at a hard capacity
        rather than evicting still-live replay evidence. The insert is
        FULL-synchronized before the caller is allowed to execute the command,
        so an immediate crash or power loss cannot silently reopen the replay
        window.
        """
        if (
            not isinstance(command_id, str)
            or len(command_id) != 64
            or any(ch not in _LOWER_HEX_CHARS for ch in command_id)
        ):
            raise ValueError("command_id must be lowercase SHA-256 hex")
        cid = command_id
        if now_ms is None:
            now = _now_ms()
        else:
            if isinstance(now_ms, bool) or not isinstance(now_ms, int):
                raise ValueError("now_ms must be an integer")
            now = now_ms
        if isinstance(expires_ms, bool) or not isinstance(expires_ms, int):
            raise ValueError("expires_ms must be an integer")
        exp = expires_ms
        if not (0 <= now <= 2**63 - 1 and 0 <= exp <= 2**63 - 1):
            raise ValueError("remote instruction timestamp out of range")
        if exp <= now:
            raise ValueError("expires_ms must be in the future")
        if exp - now > MAX_REMOTE_INSTRUCTION_REPLAY_RETENTION_MS:
            raise ValueError("expires_ms exceeds replay retention limit")
        if not isinstance(action, str):
            raise ValueError("action must be text")
        if len(action) > 80 or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in action):
            raise ValueError("action is invalid")
        if controller_device_pub is not None:
            self._validate_self_mesh_pub(controller_device_pub, "controller_device_pub")
        if target_device_pub is not None:
            self._validate_self_mesh_pub(target_device_pub, "target_device_pub")
        synchronous_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
        with self._write_lock:
            row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous_sync = int(row[0]) if row else 1
            self._conn.execute("PRAGMA synchronous = FULL")
            try:
                self._conn.execute(
                    "DELETE FROM remote_instruction_seen WHERE expires_ms <= ?",
                    (now,),
                )
                cur = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO remote_instruction_seen(
                        command_id, first_seen_ms, expires_ms, action,
                        controller_device_pub, target_device_pub
                    )
                    SELECT ?, ?, ?, ?, ?, ?
                    WHERE (
                        SELECT COUNT(*) FROM remote_instruction_seen
                    ) < ?
                    """,
                    (
                        cid,
                        now,
                        exp,
                        action,
                        (
                            bytes(controller_device_pub)
                            if controller_device_pub is not None else None
                        ),
                        (
                            bytes(target_device_pub)
                            if target_device_pub is not None else None
                        ),
                        MAX_REMOTE_INSTRUCTION_SEEN_ROWS,
                    ),
                )
                if int(cur.rowcount) == 1:
                    return True
                replay = self._conn.execute(
                    "SELECT 1 FROM remote_instruction_seen WHERE command_id = ?",
                    (cid,),
                ).fetchone()
                if replay is not None:
                    return False
                raise RuntimeError("remote instruction replay cache is full")
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous = {synchronous_names.get(previous_sync, 'NORMAL')}"
                )

    def record_self_mesh_audit(
        self,
        *,
        event: str,
        severity: str = "info",
        root_pub: bytes | None = None,
        device_pub: bytes | None = None,
        peer_fp: str | None = None,
        command_id: str | None = None,
        action: str | None = None,
        path: str | None = None,
        detail: str = "",
        metadata: Optional[dict] = None,
        ts_ms: int | None = None,
    ) -> int:
        ev = str(event or "").strip()
        if not ev:
            raise ValueError("event is required")
        sev = str(severity or "info")
        if sev not in {"good", "info", "warn", "bad"}:
            raise ValueError("invalid self-mesh audit severity")
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
        if device_pub is not None:
            self._validate_self_mesh_pub(device_pub, "device_pub")
        now = _now_ms() if ts_ms is None else int(ts_ms)
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO self_mesh_audit(
                    ts_ms, event, severity, root_pub, device_pub, peer_fp,
                    command_id, action, path, detail, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    ev[:80],
                    sev,
                    bytes(root_pub) if root_pub is not None else None,
                    bytes(device_pub) if device_pub is not None else None,
                    str(peer_fp or "")[:128] if peer_fp else None,
                    str(command_id or "")[:128] if command_id else None,
                    str(action or "")[:80] if action else None,
                    str(path or "")[:1000] if path else None,
                    str(detail or "")[:500],
                    meta_json,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_self_mesh_audit(
        self,
        *,
        since_ms: int | None = None,
        root_pub: bytes | None = None,
        limit: int = 200,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if since_ms is not None:
            clauses.append("ts_ms >= ?")
            params.append(int(since_ms))
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        sql = f"""
            SELECT * FROM self_mesh_audit
            {where}
            ORDER BY ts_ms DESC, id DESC
            LIMIT ?
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            params,
        ).fetchall()
        return [self._row_to_self_mesh_audit(r) for r in rows]

    def record_self_mesh_perf_sample(
        self,
        sample: dict,
        *,
        ts_ms: int | None = None,
    ) -> int:
        now = _now_ms() if ts_ms is None else int(ts_ms)
        metadata = {
            k: v for k, v in dict(sample).items()
            if k not in {
                "route_probe_runs",
                "route_probe_ready",
                "route_probe_total_ms",
                "route_probe_avg_ms",
                "presence_rows",
                "device_rows",
                "recent_audit_rows",
                "status",
            }
        }
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO self_mesh_perf_samples(
                    ts_ms, route_probe_runs, route_probe_ready,
                    route_probe_total_ms, route_probe_avg_ms, presence_rows,
                    device_rows, recent_audit_rows, status, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    int(sample.get("route_probe_runs") or 0),
                    int(sample.get("route_probe_ready") or 0),
                    float(sample.get("route_probe_total_ms") or 0.0),
                    float(sample.get("route_probe_avg_ms") or 0.0),
                    int(sample.get("presence_rows") or 0),
                    int(sample.get("device_rows") or 0),
                    int(sample.get("recent_audit_rows") or 0),
                    str(sample.get("status") or "unknown")[:40],
                    json.dumps(metadata, separators=(",", ":"), sort_keys=True),
                ),
            )
            # Keep the table bounded without needing a background task.
            self._conn.execute(
                """
                DELETE FROM self_mesh_perf_samples
                WHERE id NOT IN (
                    SELECT id FROM self_mesh_perf_samples
                    ORDER BY ts_ms DESC, id DESC
                    LIMIT 1000
                )
                """
            )
            return int(cur.lastrowid or 0)

    def list_self_mesh_perf_samples(self, *, limit: int = 120) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM self_mesh_perf_samples
            ORDER BY ts_ms DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 1000)),),
        ).fetchall()
        return [self._row_to_self_mesh_perf_sample(r) for r in rows]

    def _outbox_usage(self, peer_fp: str) -> tuple[int, int, int]:
        """Return (pending rows, pending payload bytes, all rows) for a peer."""

        cached = self._outbox_usage_cache.get(peer_fp)
        if cached is not None:
            return cached
        row = self._conn.execute(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN delivered_ms IS NULL THEN 1 ELSE 0 END), 0) "
            "AS pending, COALESCE(SUM(CASE WHEN delivered_ms IS NULL THEN "
            "length(CAST(msg_body_json AS BLOB)) ELSE 0 END), 0) AS bytes "
            "FROM outbox WHERE peer_fp = ?",
            (peer_fp,),
        ).fetchone()
        cached = (
            int(row["pending"] if row else 0),
            int(row["bytes"] if row else 0),
            int(row["total"] if row else 0),
        )
        self._outbox_usage_cache[peer_fp] = cached
        return cached

    def enqueue_outbox(
        self,
        *,
        peer_fp: str,
        msg_id: str,
        msg_body: dict,
        msg_kind: str = "TEXT",
    ) -> int:
        """Queue a chat message for delivery to peer when next online.
        Returns the row id. If (peer_fp, msg_id) is already enqueued
        (delivered or not), returns the existing row id — idempotent."""
        if not peer_fp or not msg_id:
            raise ValueError("peer_fp and msg_id required")
        body_json = json.dumps(
            msg_body, separators=(",", ":"), sort_keys=True, allow_nan=False,
        )
        body_size = len(body_json.encode("utf-8"))
        if body_size > MAX_OUTBOX_BODY_BYTES:
            raise MessageQuotaExceeded("outbox message exceeds payload limit")
        now = _now_ms()
        with self._write_lock:
            row = self._conn.execute(
                "SELECT id, msg_kind, msg_body_json FROM outbox "
                "WHERE peer_fp = ? AND msg_id = ?",
                (peer_fp, msg_id),
            ).fetchone()
            if row is not None:
                try:
                    stored_json = json.dumps(
                        json.loads(row["msg_body_json"]), separators=(",", ":"),
                        sort_keys=True, allow_nan=False,
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise MessageIdConflict(
                        f"stored outbox message {msg_id!r} is invalid"
                    ) from exc
                if row["msg_kind"] != msg_kind or stored_json != body_json:
                    raise MessageIdConflict(
                        f"outbox message id {msg_id!r} was reused for different content"
                    )
                return int(row["id"])

            pending, pending_bytes, total = self._outbox_usage(peer_fp)
            if total >= MAX_OUTBOX_ROWS_PER_PEER:
                prune_count = max(
                    1000, total - MAX_OUTBOX_ROWS_PER_PEER + 1,
                )
                pruned = self._conn.execute(
                    "DELETE FROM outbox WHERE id IN ("
                    "SELECT id FROM outbox WHERE peer_fp = ? "
                    "AND delivered_ms IS NOT NULL "
                    "ORDER BY delivered_ms ASC, id ASC LIMIT ?)",
                    (peer_fp, prune_count),
                )
                total -= int(pruned.rowcount or 0)
            if (
                total >= MAX_OUTBOX_ROWS_PER_PEER
                or pending >= MAX_OUTBOX_PENDING_PER_PEER
                or pending_bytes + body_size
                > MAX_OUTBOX_PENDING_BYTES_PER_PEER
            ):
                self._outbox_usage_cache[peer_fp] = (
                    pending, pending_bytes, total,
                )
                raise MessageQuotaExceeded(
                    "outbox quota reached; deliver or cancel pending messages"
                )
            cur = self._conn.execute(
                """
                INSERT INTO outbox(
                    peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (peer_fp, msg_id, msg_kind, body_json, now),
            )
            if cur.lastrowid is None:
                raise RuntimeError("outbox insert did not return a row id")
            self._outbox_usage_cache[peer_fp] = (
                pending + 1, pending_bytes + body_size, total + 1,
            )
            return int(cur.lastrowid)

    def list_outbox(
        self,
        *,
        peer_fp: Optional[str] = None,
        pending_only: bool = True,
        limit: int = 200,
    ) -> list[OutboxEntry]:
        sql = (
            "SELECT id, peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms,"
            " attempts, last_attempt_ms, last_error, delivered_ms"
            " FROM outbox"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp is not None:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if pending_only:
            clauses.append("delivered_ms IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY enqueued_ms ASC, id ASC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [self._row_to_outbox(r) for r in rows]

    def get_outbox_entry(self, entry_id: int) -> Optional[OutboxEntry]:
        row = self._conn.execute(
            "SELECT id, peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms,"
            " attempts, last_attempt_ms, last_error, delivered_ms"
            " FROM outbox WHERE id = ?",
            (int(entry_id),),
        ).fetchone()
        return self._row_to_outbox(row) if row else None

    def mark_outbox_delivered(self, entry_id: int) -> bool:
        with self._write_lock:
            row = self._conn.execute(
                "SELECT peer_fp, length(CAST(msg_body_json AS BLOB)) AS bytes "
                "FROM outbox WHERE id = ? AND delivered_ms IS NULL",
                (int(entry_id),),
            ).fetchone()
            if row is None:
                return False
            cur = self._conn.execute(
                "UPDATE outbox SET delivered_ms = ?, last_error = NULL"
                " WHERE id = ? AND delivered_ms IS NULL",
                (_now_ms(), int(entry_id)),
            )
            changed = cur.rowcount > 0
            if changed:
                peer_fp = str(row["peer_fp"])
                usage = self._outbox_usage_cache.get(peer_fp)
                if usage is not None:
                    pending, pending_bytes, total = usage
                    self._outbox_usage_cache[peer_fp] = (
                        max(0, pending - 1),
                        max(0, pending_bytes - int(row["bytes"] or 0)),
                        total,
                    )
            return changed

    def record_outbox_attempt(
        self, entry_id: int, *, error: Optional[str] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE outbox SET attempts = attempts + 1,"
                " last_attempt_ms = ?, last_error = ? WHERE id = ?",
                (_now_ms(), error[:500] if error else None, int(entry_id)),
            )

    def cancel_outbox(self, entry_id: int) -> bool:
        """Drop a pending entry without delivery. Idempotent."""
        with self._write_lock:
            row = self._conn.execute(
                "SELECT peer_fp, length(CAST(msg_body_json AS BLOB)) AS bytes "
                "FROM outbox WHERE id = ? AND delivered_ms IS NULL",
                (int(entry_id),),
            ).fetchone()
            if row is None:
                return False
            cur = self._conn.execute(
                "DELETE FROM outbox WHERE id = ? AND delivered_ms IS NULL",
                (int(entry_id),),
            )
            changed = cur.rowcount > 0
            if changed:
                peer_fp = str(row["peer_fp"])
                usage = self._outbox_usage_cache.get(peer_fp)
                if usage is not None:
                    pending, pending_bytes, total = usage
                    self._outbox_usage_cache[peer_fp] = (
                        max(0, pending - 1),
                        max(0, pending_bytes - int(row["bytes"] or 0)),
                        max(0, total - 1),
                    )
            return changed

    def clear_outbox_for_peer(self, peer_fp: str) -> int:
        """Drop every (delivered or not) outbox row for a peer.
        Hooked from revoke_peer so we don't keep messages addressed
        to a peer the user no longer trusts."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM outbox WHERE peer_fp = ?", (peer_fp,),
            )
            self._outbox_usage_cache.pop(peer_fp, None)
            return int(cur.rowcount)

    def prune_outbox(
        self,
        *,
        older_than_ms: Optional[int] = None,
        delivered_only: bool = True,
    ) -> int:
        """Cleanup. Default: drop delivered rows. Pass
        `delivered_only=False, older_than_ms=...` to also drop
        ancient undelivered rows (e.g. peer never came back)."""
        clauses: list[str] = []
        params: list[Any] = []
        if delivered_only:
            clauses.append("delivered_ms IS NOT NULL")
        if older_than_ms is not None:
            clauses.append("enqueued_ms < ?")
            params.append(int(older_than_ms))
        if not clauses:
            return 0
        sql = "DELETE FROM outbox WHERE " + " AND ".join(clauses)  # nosec B608
        with self._write_lock:
            cur = self._conn.execute(sql, tuple(params))
            self._outbox_usage_cache.clear()
            return int(cur.rowcount)

    def _row_to_outbox(self, row: sqlite3.Row) -> OutboxEntry:
        try:
            body = json.loads(row["msg_body_json"]) if row["msg_body_json"] else {}
        except Exception:
            body = {}
        return OutboxEntry(
            id=int(row["id"]),
            peer_fp=row["peer_fp"],
            msg_id=row["msg_id"],
            msg_kind=row["msg_kind"],
            msg_body=body,
            enqueued_ms=int(row["enqueued_ms"]),
            attempts=int(row["attempts"]),
            last_attempt_ms=row["last_attempt_ms"],
            last_error=row["last_error"],
            delivered_ms=row["delivered_ms"],
        )

    def _row_to_route_candidate(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "peer_fp": row["peer_fp"],
            "route": row["route"],
            "transport": row["transport"],
            "host": row["host"],
            "port": int(row["port"]),
            "source": row["source"],
            "verified": bool(row["verified"]),
            "attempts": int(row["attempts"]),
            "successes": int(row["successes"]),
            "failures": int(row["failures"]),
            "latency_ms": (
                float(row["latency_ms"]) if row["latency_ms"] is not None else None
            ),
            "bandwidth_bps": (
                float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
            ),
            "last_error": row["last_error"],
            "first_seen_ms": int(row["first_seen_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "expires_ms": int(row["expires_ms"]) if row["expires_ms"] is not None else None,
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    @staticmethod
    def _validate_self_mesh_pub(value: bytes, name: str) -> None:
        if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes")

    @staticmethod
    def _validate_self_mesh_root_seed(*, root_seed: bytes, root_pub: bytes) -> None:
        """Reject corrupt or mismatched personal-mesh root material.

        The public key is stored separately from the wrapped seed.  Checking
        the relationship at both write and unwrap time prevents a damaged or
        tampered seed from minting certificates that appear successful but
        can never verify against the advertised root identity.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if len(root_seed) != 32:
            raise ValueError("root_seed must be 32 bytes")
        derived_pub = Ed25519PrivateKey.from_private_bytes(
            root_seed
        ).public_key().public_bytes_raw()
        if not secrets.compare_digest(derived_pub, root_pub):
            raise ValueError("root_seed does not match root_pub")

    def _row_to_self_mesh_root(
        self,
        row: sqlite3.Row,
        *,
        include_seed: bool = False,
    ) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        out = {
            "root_pub": bytes(row["root_pub"]),
            "label": row["label"],
            "has_root_seed": row["root_seed"] is not None,
            "created_ms": int(row["created_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "metadata": metadata if isinstance(metadata, dict) else {},
        }
        if include_seed and row["root_seed"] is not None:
            # A cleartext root seed is exactly 32 bytes; wrapping that seed
            # produces 61 bytes (marker + nonce + ciphertext + tag).  Length
            # is therefore the authoritative discriminator.  The generic
            # one-byte marker check has a 1/256 false-positive rate for random
            # 32-byte seeds, which previously made enrollment minting fail
            # intermittently whenever a valid seed happened to begin 0x01.
            root_seed = self._open_field(SELF_MESH_ROOT_SEED, row["root_seed"])
            self._validate_self_mesh_root_seed(
                root_seed=root_seed,
                root_pub=bytes(row["root_pub"]),
            )
            out["root_seed"] = root_seed
        return out

    def _row_to_self_mesh_device(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        cols = row.keys()
        return {
            "root_pub": bytes(row["root_pub"]),
            "device_pub": bytes(row["device_pub"]),
            "cert": bytes(row["cert"]) if row["cert"] is not None else None,
            "device_kind": row["device_kind"],
            "label": row["label"],
            "local": bool(row["local"]),
            "trusted": bool(row["trusted"]),
            "revoked": bool(row["revoked"]),
            "added_ms": int(row["added_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "safety_state": (
                row["safety_state"] if "safety_state" in cols
                else ("revoked" if row["revoked"] else "trusted")
            ),
            "safety_updated_ms": (
                int(row["safety_updated_ms"]) if "safety_updated_ms" in cols else int(row["updated_ms"])
            ),
            "guardian_epoch": (
                int(row["guardian_epoch"]) if "guardian_epoch" in cols else (1 if row["revoked"] else 0)
            ),
            "safety_reason": row["safety_reason"] if "safety_reason" in cols else "",
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_device_guardian_event(self, row: sqlite3.Row) -> dict:
        def _json_list(name: str) -> list:
            try:
                value = json.loads(row[name]) if row[name] else []
            except Exception:
                value = []
            return value if isinstance(value, list) else []

        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "root_pub": bytes(row["root_pub"]),
            "device_pub": bytes(row["device_pub"]),
            "actor_device_pub": (
                bytes(row["actor_device_pub"]) if row["actor_device_pub"] is not None else None
            ),
            "from_state": row["from_state"],
            "to_state": row["to_state"],
            "decision": row["decision"],
            "reason": row["reason"],
            "proofs": _json_list("proofs_json"),
            "effects": _json_list("effects_json"),
            "event_hash": row["event_hash"],
            "prev_hash": row["prev_hash"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_audit(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "event": row["event"],
            "severity": row["severity"],
            "root_pub": bytes(row["root_pub"]) if row["root_pub"] is not None else None,
            "device_pub": (
                bytes(row["device_pub"]) if row["device_pub"] is not None else None
            ),
            "peer_fp": row["peer_fp"],
            "command_id": row["command_id"],
            "action": row["action"],
            "path": row["path"],
            "detail": row["detail"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_perf_sample(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "route_probe_runs": int(row["route_probe_runs"]),
            "route_probe_ready": int(row["route_probe_ready"]),
            "route_probe_total_ms": float(row["route_probe_total_ms"]),
            "route_probe_avg_ms": float(row["route_probe_avg_ms"]),
            "presence_rows": int(row["presence_rows"]),
            "device_rows": int(row["device_rows"]),
            "recent_audit_rows": int(row["recent_audit_rows"]),
            "status": row["status"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_presence(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "device_pub": bytes(row["device_pub"]),
            "state": row["state"],
            "sequence": int(row["sequence"]),
            "updated_ms": int(row["updated_ms"]),
            "battery_pct": (
                int(row["battery_pct"]) if row["battery_pct"] is not None else None
            ),
            "network": row["network"],
            "free_bytes": (
                int(row["free_bytes"]) if row["free_bytes"] is not None else None
            ),
            "route": row["route"],
            "latency_ms": (
                float(row["latency_ms"]) if row["latency_ms"] is not None else None
            ),
            "bandwidth_bps": (
                float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
            ),
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_transfer(self, row: sqlite3.Row) -> TransferRecord:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        # 2026-05-22 audit T3-J: unwrap ``metadata.path`` if it's
        # wrapped on disk. ``_unwrap_path`` is a no-op for unwrapped
        # values, so legacy rows / unwrapped paths pass through.
        raw_path = metadata.get("path") if isinstance(metadata, dict) else None
        if isinstance(raw_path, str) and raw_path:
            metadata["path"] = self._open_field(TRANSFER_SOURCE_PATH, raw_path)
        return TransferRecord(
            id=row["id"],
            direction=row["direction"],
            peer_fp=row["peer_fp"],
            kind=row["kind"],
            name=row["name"],
            size=row["size"],
            blob_hash=row["blob_hash"],
            status=row["status"],
            progress_bytes=row["progress_bytes"],
            total_bytes=row["total_bytes"],
            chunks_done=row["chunks_done"],
            chunks_total=row["chunks_total"],
            raw_bytes=row["raw_bytes"],
            wire_bytes=row["wire_bytes"],
            updated_ms=row["updated_ms"],
            metadata=metadata,
        )

    # ─── rooms ────────────────────────────────────────────────────────

    def create_room(self, *, room_id: str, name: str, members: list[str]) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO rooms(id, name, created_ms, members_json)
                VALUES(?, ?, ?, ?)
                """,
                (room_id, name, _now_ms(), json.dumps(members)),
            )

    def get_room(self, room_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "members": json.loads(row["members_json"]),
        }

    def get_room_by_name(self, name: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM rooms WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "members": json.loads(row["members_json"]),
        }

    def list_rooms(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM rooms ORDER BY created_ms"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "created_ms": r["created_ms"],
                "members": json.loads(r["members_json"]),
            }
            for r in rows
        ]

    def update_room_members(self, room_id: str, members: list[str]) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE rooms SET members_json = ? WHERE id = ?",
                (json.dumps(members), room_id),
            )

    # ─── folders ──────────────────────────────────────────────────────

    def add_folder(
        self, *, name: str, local_path: str, shared_with: list[str],
        max_file_bytes: Optional[int] = None,
        ignored_patterns: Optional[list[str]] = None,
        conflict_policy: str = "latest-wins",
    ) -> None:
        if conflict_policy not in ("latest-wins", "local-priority", "peer-priority"):
            raise ValueError(f"invalid conflict_policy: {conflict_policy!r}")
        ip_json = json.dumps(list(ignored_patterns or []))
        root_id = uuid.uuid4().hex
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO folders(
                    name, local_path, shared_with_json, created_ms,
                    root_id, max_file_bytes, ignored_patterns_json,
                    conflict_policy
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name, local_path, json.dumps(shared_with), _now_ms(),
                    root_id,
                    int(max_file_bytes) if max_file_bytes is not None else None,
                    ip_json,
                    conflict_policy,
                ),
            )
            for peer_fp in shared_with:
                self._set_folder_peer_permission_locked(name, peer_fp, "rw")

    def remove_folder(self, name: str) -> None:
        with self._write_lock:
            self._conn.execute("DELETE FROM folders WHERE name = ?", (name,))
            self._conn.execute(
                "DELETE FROM folder_manifest WHERE folder_name = ?", (name,)
            )

    def get_folder(self, name: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM folders WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_folder(row)

    def list_folders(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM folders ORDER BY name"
        ).fetchall()
        return [self._row_to_folder(r) for r in rows]

    def _row_to_folder(self, r: sqlite3.Row) -> dict:
        cols = r.keys()
        try:
            ignored = json.loads(r["ignored_patterns_json"]) if (
                "ignored_patterns_json" in cols
                and r["ignored_patterns_json"]
            ) else []
        except Exception:
            ignored = []
        return {
            "name": r["name"],
            "local_path": r["local_path"],
            "shared_with": json.loads(r["shared_with_json"]),
            "created_ms": r["created_ms"],
            "root_id": r["root_id"] if "root_id" in cols else None,
            "max_file_bytes": (
                r["max_file_bytes"] if "max_file_bytes" in cols else None
            ),
            "ignored_patterns": ignored,
            "conflict_policy": (
                r["conflict_policy"] if "conflict_policy" in cols else "latest-wins"
            ),
        }

    def share_folder_with(self, folder_name: str, peer_fp: str) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp in f["shared_with"]:
            return
        new = f["shared_with"] + [peer_fp]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET shared_with_json = ? WHERE name = ?",
                (json.dumps(new), folder_name),
            )
            self._set_folder_peer_permission_locked(folder_name, peer_fp, "rw")

    def unshare_folder_with(self, folder_name: str, peer_fp: str) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp not in f["shared_with"]:
            return
        new = [fp for fp in f["shared_with"] if fp != peer_fp]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET shared_with_json = ? WHERE name = ?",
                (json.dumps(new), folder_name),
            )
            self._delete_folder_peer_permission_locked(folder_name, peer_fp)

    def _folder_perm_key(self, folder_name: str, peer_fp: str) -> str:
        return f"folder_permission:{folder_name}:{peer_fp}"

    def _set_folder_peer_permission_locked(
        self, folder_name: str, peer_fp: str, mode: str
    ) -> None:
        if mode not in ("push", "pull", "rw"):
            raise ValueError("folder permission must be push, pull, or rw")
        self._conn.execute(
            """
            INSERT INTO settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (self._folder_perm_key(folder_name, peer_fp), mode),
        )

    def _delete_folder_peer_permission_locked(
        self, folder_name: str, peer_fp: str
    ) -> None:
        self._conn.execute(
            "DELETE FROM settings WHERE key = ?",
            (self._folder_perm_key(folder_name, peer_fp),),
        )

    def set_folder_peer_permission(
        self, folder_name: str, peer_fp: str, mode: str
    ) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp not in f["shared_with"]:
            raise KeyError(f"folder {folder_name!r} is not shared with {peer_fp!r}")
        with self._write_lock:
            self._set_folder_peer_permission_locked(folder_name, peer_fp, mode)

    def get_folder_peer_permission(self, folder_name: str, peer_fp: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (self._folder_perm_key(folder_name, peer_fp),),
        ).fetchone()
        if not row:
            return "rw" if peer_fp in (self.get_folder(folder_name) or {}).get("shared_with", []) else None
        mode = str(row["value"])
        return mode if mode in ("push", "pull", "rw") else None

    # ─── v0.7.2 sandbox policy setters + audit ──────────────────────

    def set_folder_max_file_bytes(
        self, folder_name: str, max_file_bytes: Optional[int],
    ) -> None:
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET max_file_bytes = ? WHERE name = ?",
                (
                    int(max_file_bytes) if max_file_bytes is not None else None,
                    folder_name,
                ),
            )

    def set_folder_ignored_patterns(
        self, folder_name: str, patterns: list[str],
    ) -> None:
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        clean = [str(p) for p in patterns if str(p).strip()]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET ignored_patterns_json = ? WHERE name = ?",
                (json.dumps(clean), folder_name),
            )

    def set_folder_conflict_policy(
        self, folder_name: str, policy: str,
    ) -> None:
        if policy not in ("latest-wins", "local-priority", "peer-priority"):
            raise ValueError(f"invalid conflict_policy: {policy!r}")
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET conflict_policy = ? WHERE name = ?",
                (policy, folder_name),
            )

    def has_known_file_by_blob(self, blob_hash: str) -> bool:
        """v0.21.x folder-send pre-flight: does the file_index_cache
        carry ANY row whose blob_hash matches? Used by the
        BLOB_INVENTORY_QUERY handler so files received via
        /api/send-file (which land in inbox/, not blob_store) still
        count as 'have' for dedup purposes.

        Returns True iff at least one cached file index has the
        given blob_hash. Fast: one SELECT 1 LIMIT 1.
        """
        if not isinstance(blob_hash, str) or not blob_hash:
            return False
        row = self._conn.execute(
            "SELECT 1 FROM file_index_cache WHERE blob_hash = ? LIMIT 1",
            (blob_hash,),
        ).fetchone()
        return row is not None

    def set_folder_local_path(
        self, folder_name: str, new_local_path: str,
    ) -> None:
        """v0.21.x: point an existing folder at a different on-disk
        location. Used when the original local_path is stale (renamed
        user account, deleted directory, folder imported from a
        different machine). Callers are responsible for restarting
        the folder watcher so the FS observer picks up the new root.
        """
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        if not isinstance(new_local_path, str) or not new_local_path.strip():
            raise ValueError("new_local_path must be a non-empty string")
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET local_path = ? WHERE name = ?",
                (new_local_path, folder_name),
            )

    def record_folder_audit_event(
        self,
        *,
        folder_name: str,
        peer_fp: str,
        action: str,
        file_path: str,
        blob_hash: Optional[str] = None,
        size: Optional[int] = None,
        note: Optional[str] = None,
    ) -> int:
        """v0.7.2: append an immutable audit row for any peer write
        attempt against a sandbox root. Action values:
          - 'write'           — accepted manifest entry update
          - 'delete'          — accepted tombstone
          - 'reject_size'     — declined: exceeds max_file_bytes
          - 'reject_pattern'  — declined: matches ignored pattern
          - 'reject_unshared' — declined: peer not on shared_with
          - 'reject_perm'     — declined: peer mode forbids write
        """
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        root_id = f.get("root_id") or ""
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO folder_audit(
                    ts_ms, folder_name, root_id, peer_fp, action,
                    file_path, blob_hash, size, note
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now_ms(), folder_name, root_id, peer_fp, action,
                    file_path,
                    blob_hash,
                    int(size) if size is not None else None,
                    note,
                ),
            )
            assert cur.lastrowid is not None, "INSERT did not return a rowid"
            return int(cur.lastrowid)

    # folder_audit retention. The table is BOTH an append-only record of
    # peer write attempts AND the blob->peer index for swarm-pull
    # fallback (list_peers_with_blob). Continuous folder sync appends an
    # event per file per cycle, so without a cap it grows unbounded —
    # observed at ~400k rows / 222 MB on a long-running two-machine pair,
    # which bloated the DB (and made the boot integrity check crawl).
    # Keep the newest MAX_FOLDER_AUDIT_ROWS; prune the oldest in bounded
    # batches so a single DELETE never holds the write lock for long
    # (secure_delete=ON zeroes every pruned row).
    MAX_FOLDER_AUDIT_ROWS = 20_000
    # Small batch so each DELETE's write-lock hold is short (~0.2s) and
    # never stalls the daemon's event loop long enough to drop a peer.
    # A backlog clears over several minutes of prune-loop ticks; steady
    # state deletes ~0 rows per tick (instant).
    _FOLDER_AUDIT_PRUNE_BATCH = 2_000

    def prune_folder_audit(
        self,
        keep_max: Optional[int] = None,
        batch: Optional[int] = None,
    ) -> int:
        """Trim folder_audit to at most keep_max rows, deleting up to
        ``batch`` of the oldest per call. Returns the number deleted.
        Call repeatedly (e.g. once per prune-loop tick) to clear a large
        backlog incrementally and then hold the cap cheaply. The newest
        rows are kept, so the swarm-pull blob->peer index stays warm for
        recently-synced blobs."""
        keep_max = self.MAX_FOLDER_AUDIT_ROWS if keep_max is None else keep_max
        batch = self._FOLDER_AUDIT_PRUNE_BATCH if batch is None else batch
        with self._write_lock:
            # id of the (keep_max+1)-th newest row; everything with id
            # <= cutoff is beyond the cap and prunable.
            row = self._conn.execute(
                "SELECT id FROM folder_audit ORDER BY id DESC "
                "LIMIT 1 OFFSET ?",
                (keep_max,),
            ).fetchone()
            if row is None:
                return 0  # at or below the cap; nothing to prune
            cutoff_id = row[0]
            cur = self._conn.execute(
                "DELETE FROM folder_audit WHERE id IN ("
                "  SELECT id FROM folder_audit WHERE id <= ? "
                "  ORDER BY id ASC LIMIT ?"
                ")",
                (cutoff_id, batch),
            )
            return cur.rowcount or 0

    def list_peers_with_blob(
        self,
        blob_hash: str,
        *,
        folder_name: Optional[str] = None,
    ) -> list[str]:
        """v0.21.x Ship 8: which paired peers have advertised this
        blob? Returns distinct peer_fps from folder_audit (which
        records every accepted write the peer pushed us; if a peer
        ever sent us a manifest entry for this blob, they had the
        blob at that time).

        Used by the swarm-pull path: when we want a blob and the
        original source peer is unreachable, this gives us the list
        of fallback peers to race fetches against.

        folder_name scopes to one folder; None = any folder where
        this blob has been advertised (cross-folder dedupe)."""
        if not blob_hash:
            return []
        sql = (
            "SELECT DISTINCT peer_fp FROM folder_audit"
            " WHERE blob_hash = ? AND peer_fp IS NOT NULL"
            " AND peer_fp != ''"
            " AND action IN ('write', 'renamed', 'restored')"
        )
        params: list[Any] = [blob_hash]
        if folder_name:
            sql += " AND folder_name = ?"
            params.append(folder_name)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [r["peer_fp"] for r in rows if r["peer_fp"]]

    def list_folder_file_history(
        self,
        *,
        folder_name: str,
        file_path: str,
        limit: int = 50,
    ) -> list[dict]:
        """v0.21.x Ship 5: per-file version history derived from the
        folder_audit log. Returns historical blob_hash values for a
        single (folder, path) in newest-first order, de-duped against
        consecutive same-hash rows so a watcher-bursts-then-settles
        sequence doesn't show 10 identical entries.

        Each row carries timestamp + peer_fp (who made the change)
        + blob_hash + size + action so the UI can show 'edited X
        ago by <device> · 4.2 KB · [Preview] [Restore]'."""
        rows = self._conn.execute(
            "SELECT id, ts_ms, peer_fp, action, blob_hash, size, note"
            " FROM folder_audit"
            " WHERE folder_name = ? AND file_path = ?"
            " ORDER BY ts_ms DESC, id DESC LIMIT ?",
            (folder_name, file_path, int(limit) * 3),  # pull extra for de-dup
        ).fetchall()
        out: list[dict] = []
        last_hash: Optional[str] = None
        for r in rows:
            bh = r["blob_hash"]
            # Skip consecutive duplicates of the same blob hash —
            # a manifest reapply or tombstone-then-restore burst
            # would otherwise show as 5 identical rows.
            if bh == last_hash:
                continue
            last_hash = bh
            out.append({
                "id": int(r["id"]),
                "ts_ms": int(r["ts_ms"]),
                "peer_fp": r["peer_fp"],
                "action": r["action"],
                "blob_hash": bh,
                "size": int(r["size"]) if r["size"] is not None else None,
                "note": r["note"],
            })
            if len(out) >= limit:
                break
        return out

    def list_folder_audit(
        self,
        *,
        folder_name: Optional[str] = None,
        peer_fp: Optional[str] = None,
        actions: Optional[Iterable[str]] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT id, ts_ms, folder_name, root_id, peer_fp, action,"
            " file_path, blob_hash, size, note FROM folder_audit"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if folder_name is not None:
            clauses.append("folder_name = ?")
            params.append(folder_name)
        if peer_fp is not None:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        action_list = list(actions or [])
        if action_list:
            clauses.append("action IN (" + ",".join("?" for _ in action_list) + ")")
            params.extend(action_list)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": int(r["id"]),
                "ts_ms": int(r["ts_ms"]),
                "folder_name": r["folder_name"],
                "root_id": r["root_id"],
                "peer_fp": r["peer_fp"],
                "action": r["action"],
                "file_path": r["file_path"],
                "blob_hash": r["blob_hash"],
                "size": r["size"],
                "note": r["note"],
            }
            for r in rows
        ]

    # ─── pending folder offers (v25) ──────────────────────────────────

    def upsert_pending_folder_offer(
        self,
        *,
        peer_fp: str,
        folder_name: str,
        merkle_root: Optional[str],
        entries: list[dict],
        offered_ms: Optional[int] = None,
    ) -> dict:
        """Cache an incoming folder-share proposal so the UI can
        surface it. UNIQUE(peer_fp, folder_name) → re-offers from
        the same peer update the existing row.

        Resets state to 'pending' on re-offer (a refresh from the
        sender after we declined SHOULD give the user the choice
        again, since the act of re-proposing is fresh user intent
        on the sender's side)."""
        if offered_ms is None:
            offered_ms = int(time.time() * 1000)
        import json as _json
        entries_json = _json.dumps(list(entries or []))
        entry_count = len(entries or [])
        total_bytes = sum(
            int(e.get("size") or 0) for e in (entries or [])
            if e.get("blob_hash")
        )
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO pending_folder_offers(
                    peer_fp, folder_name, merkle_root,
                    entries_json, entry_count, total_bytes,
                    offered_ms, state, decided_ms, local_path
                ) VALUES(?,?,?,?,?,?,?, 'pending', NULL, NULL)
                ON CONFLICT(peer_fp, folder_name) DO UPDATE SET
                    merkle_root  = excluded.merkle_root,
                    entries_json = excluded.entries_json,
                    entry_count  = excluded.entry_count,
                    total_bytes  = excluded.total_bytes,
                    offered_ms   = excluded.offered_ms,
                    state        = 'pending',
                    decided_ms   = NULL,
                    local_path   = NULL
                """,
                (peer_fp, folder_name, merkle_root,
                 entries_json, entry_count, total_bytes,
                 offered_ms),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT id FROM pending_folder_offers"
                " WHERE peer_fp=? AND folder_name=?",
                (peer_fp, folder_name),
            ).fetchone()
            offer_id = int(row["id"]) if row else int(cur.lastrowid or 0)
        return self.get_folder_offer(offer_id) or {
            "id": offer_id,
            "peer_fp": peer_fp,
            "folder_name": folder_name,
            "merkle_root": merkle_root,
            "entry_count": entry_count,
            "total_bytes": total_bytes,
            "offered_ms": offered_ms,
            "state": "pending",
        }

    def get_folder_offer(self, offer_id: int) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id, peer_fp, folder_name, merkle_root, entries_json,"
            " entry_count, total_bytes, offered_ms, state, decided_ms,"
            " local_path FROM pending_folder_offers WHERE id=?",
            (int(offer_id),),
        ).fetchone()
        if not row:
            return None
        import json as _json
        try:
            entries = _json.loads(row["entries_json"] or "[]")
        except Exception:
            entries = []
        return {
            "id": int(row["id"]),
            "peer_fp": row["peer_fp"],
            "folder_name": row["folder_name"],
            "merkle_root": row["merkle_root"],
            "entries": entries,
            "entry_count": int(row["entry_count"] or 0),
            "total_bytes": int(row["total_bytes"] or 0),
            "offered_ms": int(row["offered_ms"] or 0),
            "state": row["state"] or "pending",
            "decided_ms": int(row["decided_ms"]) if row["decided_ms"] else None,
            "local_path": row["local_path"],
        }

    def list_folder_offers(
        self, *, state_filter: Optional[str] = "pending", limit: int = 50,
    ) -> list[dict]:
        sql = (
            "SELECT id, peer_fp, folder_name, merkle_root, entry_count,"
            " total_bytes, offered_ms, state, decided_ms, local_path"
            " FROM pending_folder_offers"
        )
        params: list[Any] = []
        if state_filter:
            sql += " WHERE state = ?"
            params.append(state_filter)
        sql += " ORDER BY offered_ms DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": int(r["id"]),
                "peer_fp": r["peer_fp"],
                "folder_name": r["folder_name"],
                "merkle_root": r["merkle_root"],
                "entry_count": int(r["entry_count"] or 0),
                "total_bytes": int(r["total_bytes"] or 0),
                "offered_ms": int(r["offered_ms"] or 0),
                "state": r["state"] or "pending",
                "decided_ms": int(r["decided_ms"]) if r["decided_ms"] else None,
                "local_path": r["local_path"],
            }
            for r in rows
        ]

    def mark_folder_offer_accepted(
        self, offer_id: int, *, local_path: str,
    ) -> Optional[dict]:
        now = int(time.time() * 1000)
        with self._write_lock:
            self._conn.execute(
                "UPDATE pending_folder_offers"
                " SET state='accepted', decided_ms=?, local_path=?"
                " WHERE id=? AND state='pending'",
                (now, local_path, int(offer_id)),
            )
            self._conn.commit()
        return self.get_folder_offer(offer_id)

    def mark_folder_offer_declined(self, offer_id: int) -> Optional[dict]:
        now = int(time.time() * 1000)
        with self._write_lock:
            self._conn.execute(
                "UPDATE pending_folder_offers"
                " SET state='declined', decided_ms=?"
                " WHERE id=? AND state='pending'",
                (now, int(offer_id)),
            )
            self._conn.commit()
        return self.get_folder_offer(offer_id)

    # ── folder lifecycle audit (v26) ─────────────────────────────
    _FOLDER_LIFECYCLE_EVENTS = frozenset({
        "offer_sent", "offer_received",
        "offer_accepted", "offer_declined",
        "send_started", "send_complete",
        "send_failed", "send_cancelled",
        "send_retry", "mode_selected",
    })

    def record_folder_lifecycle_event(
        self,
        *,
        event: str,
        direction: str,
        folder_name: str,
        peer_fp: Optional[str] = None,
        mode: Optional[str] = None,
        file_count: Optional[int] = None,
        total_bytes: Optional[int] = None,
        sent_bytes: Optional[int] = None,
        dedup_bytes: Optional[int] = None,
        duration_ms: Optional[int] = None,
        severity: str = "info",
        error_msg: Optional[str] = None,
        metadata: Optional[dict] = None,
        ts_ms: Optional[int] = None,
    ) -> int:
        """v0.21.x: append a row to folder_lifecycle_audit and return
        its id. Used by daemon/server at every folder-level transition
        so the activity sidecar can surface folder operations
        end-to-end (sender + receiver, all modes, every outcome).

        Validates event + direction so a typo can't silently land a
        row the UI then has no labels for."""
        if event not in self._FOLDER_LIFECYCLE_EVENTS:
            raise ValueError(
                f"unknown folder lifecycle event: {event!r}"
            )
        if direction not in ("in", "out"):
            raise ValueError(
                f"direction must be 'in' or 'out', got {direction!r}"
            )
        if severity not in ("info", "good", "warn", "bad"):
            raise ValueError(
                f"unknown severity: {severity!r}"
            )
        now = int(ts_ms) if ts_ms is not None else int(time.time() * 1000)
        meta_blob = (
            json.dumps(metadata, separators=(",", ":"), sort_keys=True)
            if metadata else None
        )
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO folder_lifecycle_audit(
                    ts_ms, direction, event, folder_name, peer_fp,
                    mode, file_count, total_bytes, sent_bytes,
                    dedup_bytes, duration_ms, severity, error_msg,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now, direction, event, folder_name, peer_fp,
                    mode,
                    int(file_count) if file_count is not None else None,
                    int(total_bytes) if total_bytes is not None else None,
                    int(sent_bytes) if sent_bytes is not None else None,
                    int(dedup_bytes) if dedup_bytes is not None else None,
                    int(duration_ms) if duration_ms is not None else None,
                    severity, error_msg, meta_blob,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def list_folder_lifecycle_events(
        self,
        *,
        since_ms: Optional[int] = None,
        peer_fp: Optional[str] = None,
        folder_name: Optional[str] = None,
        events: Optional[Iterable[str]] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Read helper for activity_feed + tests. Newest-first.
        ``events`` filter is the set of event-name strings to keep."""
        limit = max(1, min(int(limit), 2000))
        wclauses: list[str] = []
        params: list[Any] = []
        if since_ms is not None:
            wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
        if peer_fp is not None:
            wclauses.append("peer_fp = ?"); params.append(peer_fp)
        if folder_name is not None:
            wclauses.append("folder_name = ?"); params.append(folder_name)
        if events:
            ev_list = [e for e in events if e in self._FOLDER_LIFECYCLE_EVENTS]
            if ev_list:
                placeholders = ",".join("?" * len(ev_list))
                wclauses.append(f"event IN ({placeholders})")
                params.extend(ev_list)
        sql = (
            "SELECT id, ts_ms, direction, event, folder_name, peer_fp,"
            " mode, file_count, total_bytes, sent_bytes, dedup_bytes,"
            " duration_ms, severity, error_msg, metadata_json"
            " FROM folder_lifecycle_audit"
        )
        if wclauses:
            sql += " WHERE " + " AND ".join(wclauses)
        sql += " ORDER BY ts_ms DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        out: list[dict] = []
        for r in rows:
            md = r["metadata_json"]
            try:
                md_parsed = json.loads(md) if md else {}
            except (TypeError, ValueError):
                md_parsed = {}
            out.append({
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "direction": r["direction"],
                "event": r["event"],
                "folder_name": r["folder_name"],
                "peer_fp": r["peer_fp"],
                "mode": r["mode"],
                "file_count": r["file_count"],
                "total_bytes": r["total_bytes"],
                "sent_bytes": r["sent_bytes"],
                "dedup_bytes": r["dedup_bytes"],
                "duration_ms": r["duration_ms"],
                "severity": r["severity"],
                "error_msg": r["error_msg"],
                "metadata": md_parsed,
            })
        return out

    def find_folder_offer_for(
        self, peer_fp: str, folder_name: str,
    ) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id FROM pending_folder_offers"
            " WHERE peer_fp=? AND folder_name=?",
            (peer_fp, folder_name),
        ).fetchone()
        if not row:
            return None
        return self.get_folder_offer(int(row["id"]))

    @staticmethod
    def folder_path_matches_ignored(
        file_path: str, patterns: Iterable[str],
    ) -> bool:
        """Does the given relative path match any of the glob patterns?
        Uses fnmatch over both the full path and the basename — same
        semantics as gitignore-style ignores for typical use."""
        from fnmatch import fnmatch
        norm = (file_path or "").replace("\\", "/").lstrip("/")
        base = norm.split("/")[-1] if norm else ""
        for raw in patterns or []:
            p = str(raw).strip()
            if not p:
                continue
            if fnmatch(norm, p) or fnmatch(base, p):
                return True
        return False

    def folder_peer_allows(self, folder_name: str, peer_fp: str, action: str) -> bool:
        mode = self.get_folder_peer_permission(folder_name, peer_fp)
        if action == "push":
            return mode in ("push", "rw")
        if action == "pull":
            return mode in ("pull", "rw")
        raise ValueError("folder action must be push or pull")

    # ─── manifest (CRDT entries per file) ─────────────────────────────

    @staticmethod
    def _validate_pending_apply_artifact_name(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        name = str(value)
        if (
            not name
            or len(name.encode("utf-8")) > 160
            or Path(name).name != name
            or "/" in name
            or "\\" in name
            or not name.startswith(".one-link-")
            or not name.endswith(".tmp")
        ):
            raise ValueError("invalid pending-apply artifact leaf name")
        return name

    @staticmethod
    def _validate_pending_apply_hash(
        value: object,
        *,
        nullable: bool,
    ) -> Optional[str]:
        if value is None and nullable:
            return None
        if not isinstance(value, str) or (
            len(value) != 64
            or any(ch not in _LOWER_HEX_CHARS for ch in value)
        ):
            raise ValueError("pending-apply hash must be canonical lower hex")
        return value

    @classmethod
    def _normalize_folder_pending_apply(
        cls,
        *,
        folder_name: str,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        apply_id = str(value.get("apply_id") or "")
        if len(apply_id) != 32 or any(
            ch not in _LOWER_HEX_CHARS for ch in apply_id
        ):
            raise ValueError("pending apply_id must be 128-bit lower hex")
        file_path = str(value.get("file_path") or "")
        if (
            not file_path
            or len(file_path.encode("utf-8")) > 16 * 1024
            or "\x00" in file_path
        ):
            raise ValueError("invalid pending-apply file path")
        operation = str(value.get("operation") or "")
        if operation not in _FOLDER_PENDING_APPLY_OPERATIONS:
            raise ValueError("invalid pending-apply operation")
        target_hash = cls._validate_pending_apply_hash(
            value.get("target_blob_hash"),
            nullable=operation == "delete",
        )
        if operation == "delete" and target_hash is not None:
            raise ValueError("delete pending apply cannot have a target hash")
        baseline_hash = cls._validate_pending_apply_hash(
            value.get("baseline_blob_hash"),
            nullable=True,
        )
        raw_evidence = value.get("baseline_evidence")
        baseline_evidence: tuple[int, int, int, int, int] | None = None
        if raw_evidence is not None:
            if (
                not isinstance(raw_evidence, (list, tuple))
                or len(raw_evidence) != 5
                or any(type(item) is not int or item < 0 for item in raw_evidence)
            ):
                raise ValueError("invalid pending-apply baseline evidence")
            baseline_evidence = tuple(raw_evidence)  # type: ignore[assignment]
        if (baseline_hash is None) != (baseline_evidence is None):
            raise ValueError("baseline hash and evidence must be present together")
        target_size_raw = value.get("target_size")
        target_size = None
        if target_size_raw is not None:
            if type(target_size_raw) is not int or target_size_raw < 0:
                raise ValueError("invalid pending-apply target size")
            target_size = int(target_size_raw)
        if operation == "materialize" and target_size is None:
            raise ValueError("materialize pending apply requires target size")
        target_mtime_raw = value.get("target_mtime_ms")
        target_mtime = None
        if target_mtime_raw is not None:
            if type(target_mtime_raw) is not int or target_mtime_raw < 0:
                raise ValueError("invalid pending-apply target mtime")
            target_mtime = int(target_mtime_raw)
        raw_vclock = value.get("target_vclock")
        if not isinstance(raw_vclock, dict):
            raise ValueError("pending apply requires a target vector clock")
        target_vclock: dict[str, int] = {}
        if len(raw_vclock) > 65_536:
            raise ValueError("pending-apply vector clock exceeds safety bound")
        for key, counter in raw_vclock.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key.encode("utf-8")) > 512
                or type(counter) is not int
                or counter < 0
            ):
                raise ValueError("invalid pending-apply vector clock")
            target_vclock[key] = counter
        phase = str(value.get("phase") or "planned")
        if phase not in _FOLDER_PENDING_APPLY_PHASES:
            raise ValueError("invalid pending-apply phase")
        return {
            "apply_id": apply_id,
            "folder_name": str(folder_name),
            "file_path": file_path,
            "operation": operation,
            "target_blob_hash": target_hash,
            "target_size": target_size,
            "target_mtime_ms": target_mtime,
            "target_vclock": target_vclock,
            "baseline_blob_hash": baseline_hash,
            "baseline_evidence": baseline_evidence,
            "phase": phase,
            "staging_name": cls._validate_pending_apply_artifact_name(
                value.get("staging_name"),
            ),
            "recovery_name": cls._validate_pending_apply_artifact_name(
                value.get("recovery_name"),
            ),
        }

    @classmethod
    def _row_to_folder_pending_apply(
        cls,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        raw_clock = json.loads(str(row["target_vclock_json"]))
        raw_evidence = (
            json.loads(str(row["baseline_evidence_json"]))
            if row["baseline_evidence_json"] is not None
            else None
        )
        if not isinstance(raw_clock, dict):
            raise ValueError("corrupt pending-apply vector clock")
        if raw_evidence is not None and (
            not isinstance(raw_evidence, list) or len(raw_evidence) != 5
        ):
            raise ValueError("corrupt pending-apply baseline evidence")
        normalized = cls._normalize_folder_pending_apply(
            folder_name=str(row["folder_name"]),
            value={
            "apply_id": str(row["apply_id"]),
            "file_path": str(row["file_path"]),
            "operation": str(row["operation"]),
            "target_blob_hash": row["target_blob_hash"],
            "target_size": row["target_size"],
            "target_mtime_ms": row["target_mtime_ms"],
            "target_vclock": {
                str(key): int(counter) for key, counter in raw_clock.items()
            },
            "baseline_blob_hash": row["baseline_blob_hash"],
            "baseline_evidence": (
                tuple(int(item) for item in raw_evidence)
                if raw_evidence is not None
                else None
            ),
            "phase": str(row["phase"]),
            "staging_name": row["staging_name"],
            "recovery_name": row["recovery_name"],
            },
        )
        normalized.update({
            "attempts": int(row["attempts"]),
            "last_error": row["last_error"],
            "created_ms": int(row["created_ms"]),
            "updated_ms": int(row["updated_ms"]),
        })
        return normalized

    def get_folder_pending_apply(
        self,
        folder_name: str,
        file_path: str,
    ) -> Optional[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM folder_pending_applies "
            "WHERE folder_name=? AND file_path=?",
            (folder_name, file_path),
        ).fetchone()
        return self._row_to_folder_pending_apply(row) if row is not None else None

    def list_folder_pending_applies(
        self,
        *,
        folder_name: Optional[str] = None,
        limit: int = MAX_FOLDER_PENDING_APPLIES,
    ) -> list[dict[str, Any]]:
        bounded = max(0, min(int(limit), MAX_FOLDER_PENDING_APPLIES))
        if folder_name is None:
            rows = self._conn.execute(
                "SELECT * FROM folder_pending_applies "
                "ORDER BY created_ms, apply_id LIMIT ?",
                (bounded,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM folder_pending_applies WHERE folder_name=? "
                "ORDER BY created_ms, apply_id LIMIT ?",
                (folder_name, bounded),
            ).fetchall()
        return [self._row_to_folder_pending_apply(row) for row in rows]

    def transition_folder_pending_apply(
        self,
        *,
        apply_id: str,
        phase: str,
        staging_name: Optional[str],
        recovery_name: Optional[str],
        last_error: Optional[str] = None,
        increment_attempts: bool = False,
    ) -> bool:
        """Durably publish a journal phase before its filesystem mutation."""

        if phase not in _FOLDER_PENDING_APPLY_PHASES:
            raise ValueError("invalid pending-apply phase")
        staging = self._validate_pending_apply_artifact_name(staging_name)
        recovery = self._validate_pending_apply_artifact_name(recovery_name)
        error = None if last_error is None else str(last_error)[:2048]
        with self._write_lock:
            previous_row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous = int(previous_row[0]) if previous_row else 1
            sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
            self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                cur = self._conn.execute(
                    "UPDATE folder_pending_applies SET phase=?, staging_name=?, "
                    "recovery_name=?, last_error=?, attempts=attempts+?, "
                    "updated_ms=? WHERE apply_id=?",
                    (
                        phase,
                        staging,
                        recovery,
                        error,
                        1 if increment_attempts else 0,
                        _now_ms(),
                        apply_id,
                    ),
                )
                self._conn.execute("COMMIT")
                return int(cur.rowcount or 0) == 1
            except BaseException:
                with contextlib.suppress(*DB_ERRORS):
                    self._conn.execute("ROLLBACK")
                raise
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous={sync_names.get(previous, 'NORMAL')}"
                )

    def delete_folder_pending_apply(
        self,
        *,
        folder_name: str,
        file_path: str,
        apply_id: Optional[str] = None,
    ) -> bool:
        """Durably retire exactly one completed/superseded journal row."""

        with self._write_lock:
            previous_row = self._conn.execute("PRAGMA synchronous").fetchone()
            previous = int(previous_row[0]) if previous_row else 1
            sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
            self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                if apply_id is None:
                    cur = self._conn.execute(
                        "DELETE FROM folder_pending_applies "
                        "WHERE folder_name=? AND file_path=?",
                        (folder_name, file_path),
                    )
                else:
                    cur = self._conn.execute(
                        "DELETE FROM folder_pending_applies "
                        "WHERE folder_name=? AND file_path=? AND apply_id=?",
                        (folder_name, file_path, apply_id),
                    )
                self._conn.execute("COMMIT")
                return int(cur.rowcount or 0) == 1
            except BaseException:
                with contextlib.suppress(*DB_ERRORS):
                    self._conn.execute("ROLLBACK")
                raise
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous={sync_names.get(previous, 'NORMAL')}"
                )

    def upsert_manifest_entry(
        self,
        *,
        folder_name: str,
        file_path: str,
        blob_hash: Optional[str],
        size: Optional[int],
        mtime_ms: Optional[int],
        vclock: dict[str, int],
        clear_pending_apply: bool = False,
    ) -> None:
        with self._write_lock:
            if clear_pending_apply:
                self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """
                    INSERT INTO folder_manifest(
                        folder_name, file_path, blob_hash, size, mtime_ms,
                        vclock_json, updated_ms
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(folder_name, file_path) DO UPDATE SET
                        blob_hash    = excluded.blob_hash,
                        size         = excluded.size,
                        mtime_ms     = excluded.mtime_ms,
                        vclock_json  = excluded.vclock_json,
                        updated_ms   = excluded.updated_ms
                    """,
                    (
                        folder_name, file_path, blob_hash, size, mtime_ms,
                        json.dumps(vclock, sort_keys=True), _now_ms(),
                    ),
                )
                if clear_pending_apply:
                    self._conn.execute(
                        "DELETE FROM folder_pending_applies "
                        "WHERE folder_name=? AND file_path=?",
                        (folder_name, file_path),
                    )
                    self._conn.execute("COMMIT")
            except BaseException:
                if clear_pending_apply:
                    with contextlib.suppress(*DB_ERRORS):
                        self._conn.execute("ROLLBACK")
                raise

    def get_manifest_entry(
        self, folder_name: str, file_path: str
    ) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM folder_manifest WHERE folder_name = ? AND file_path = ?",
            (folder_name, file_path),
        ).fetchone()
        return self._row_to_manifest(row) if row else None

    def list_manifest(self, folder_name: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM folder_manifest WHERE folder_name = ? ORDER BY file_path",
            (folder_name,),
        ).fetchall()
        return [self._row_to_manifest(r) for r in rows]

    def list_manifest_entries_by_blob(
        self,
        blob_hash: str,
        *,
        limit: int = 4096,
        after: Optional[tuple[str, str]] = None,
    ) -> list[dict]:
        """Return one keyset-paginated page addressed by an arrived blob."""

        canonical = self._validate_pending_apply_hash(blob_hash, nullable=False)
        bounded = max(0, min(int(limit), MAX_FOLDER_PENDING_APPLIES))
        if after is None:
            rows = self._conn.execute(
                "SELECT * FROM folder_manifest WHERE blob_hash=? "
                "ORDER BY folder_name, file_path LIMIT ?",
                (canonical, bounded),
            ).fetchall()
        else:
            after_folder, after_path = str(after[0]), str(after[1])
            rows = self._conn.execute(
                "SELECT * FROM folder_manifest WHERE blob_hash=? AND "
                "(folder_name>? OR (folder_name=? AND file_path>?)) "
                "ORDER BY folder_name, file_path LIMIT ?",
                (
                    canonical,
                    after_folder,
                    after_folder,
                    after_path,
                    bounded,
                ),
            ).fetchall()
        return [self._row_to_manifest(row) for row in rows]

    def _row_to_manifest(self, row: sqlite3.Row) -> dict:
        return {
            "folder_name": row["folder_name"],
            "file_path":   row["file_path"],
            "blob_hash":   row["blob_hash"],
            "size":        row["size"],
            "mtime_ms":    row["mtime_ms"],
            "vclock":      json.loads(row["vclock_json"]),
            "updated_ms":  row["updated_ms"],
        }

    # ─── manifest conflicts (v0.8.9) ──────────────────────────────────

    def record_manifest_conflict(
        self,
        *,
        folder_name: str,
        file_path: str,
        peer_fp: Optional[str],
        local_blob_hash: Optional[str],
        local_size: Optional[int],
        local_mtime_ms: Optional[int],
        local_vclock: dict,
        remote_blob_hash: Optional[str],
        remote_size: Optional[int],
        remote_mtime_ms: Optional[int],
        remote_vclock: dict,
        applied_choice: str,
    ) -> int:
        """v0.8.9: log a CRDT-detected concurrent edit. Returns the
        new row id. The merge has ALREADY been applied by the caller —
        this row exists so the user can override that auto-decision
        via the Conflicts UI.

        Idempotency: if an unresolved conflict for the same
        (folder_name, file_path) with identical local + remote vclocks
        already exists, return that id instead of creating a duplicate.
        Avoids the manifest-resync flood scenario logging the same
        conflict 50 times."""
        if applied_choice not in ("local", "remote", "tombstone"):
            raise ValueError(
                f"applied_choice must be local|remote|tombstone, got {applied_choice!r}"
            )
        local_vc_json = json.dumps(local_vclock, separators=(",", ":"), sort_keys=True)
        remote_vc_json = json.dumps(remote_vclock, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id FROM manifest_conflicts"
                " WHERE folder_name = ? AND file_path = ?"
                " AND local_vclock_json = ? AND remote_vclock_json = ?"
                " AND resolved_ms IS NULL"
                " LIMIT 1",
                (folder_name, file_path, local_vc_json, remote_vc_json),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cur = self._conn.execute(
                """
                INSERT INTO manifest_conflicts(
                    folder_name, file_path, detected_ms, peer_fp,
                    local_blob_hash, local_size, local_mtime_ms, local_vclock_json,
                    remote_blob_hash, remote_size, remote_mtime_ms, remote_vclock_json,
                    applied_choice
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    folder_name, file_path, _now_ms(), peer_fp,
                    local_blob_hash, local_size, local_mtime_ms, local_vc_json,
                    remote_blob_hash, remote_size, remote_mtime_ms, remote_vc_json,
                    applied_choice,
                ),
            )
            assert cur.lastrowid is not None, "INSERT did not return a rowid"
            return int(cur.lastrowid)

    def list_manifest_conflicts(
        self,
        *,
        folder_name: Optional[str] = None,
        unresolved_only: bool = False,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT * FROM manifest_conflicts"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if folder_name is not None:
            clauses.append("folder_name = ?")
            params.append(folder_name)
        if unresolved_only:
            clauses.append("resolved_ms IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY detected_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        out: list[dict] = []
        for r in rows:
            out.append({
                "id":                 r["id"],
                "folder_name":        r["folder_name"],
                "file_path":          r["file_path"],
                "detected_ms":        r["detected_ms"],
                "peer_fp":            r["peer_fp"],
                "local_blob_hash":    r["local_blob_hash"],
                "local_size":         r["local_size"],
                "local_mtime_ms":     r["local_mtime_ms"],
                "local_vclock":       json.loads(r["local_vclock_json"]),
                "remote_blob_hash":   r["remote_blob_hash"],
                "remote_size":        r["remote_size"],
                "remote_mtime_ms":    r["remote_mtime_ms"],
                "remote_vclock":      json.loads(r["remote_vclock_json"]),
                "applied_choice":     r["applied_choice"],
                "resolved_ms":        r["resolved_ms"],
                "resolution":         r["resolution"],
                "resolved_by":        r["resolved_by"],
            })
        return out

    def get_manifest_conflict(self, conflict_id: int) -> Optional[dict]:
        rows = self.list_manifest_conflicts(limit=1)
        for r in self._conn.execute(
            "SELECT * FROM manifest_conflicts WHERE id = ?", (int(conflict_id),),
        ).fetchall():
            return {
                "id":                 r["id"],
                "folder_name":        r["folder_name"],
                "file_path":          r["file_path"],
                "detected_ms":        r["detected_ms"],
                "peer_fp":            r["peer_fp"],
                "local_blob_hash":    r["local_blob_hash"],
                "local_size":         r["local_size"],
                "local_mtime_ms":     r["local_mtime_ms"],
                "local_vclock":       json.loads(r["local_vclock_json"]),
                "remote_blob_hash":   r["remote_blob_hash"],
                "remote_size":        r["remote_size"],
                "remote_mtime_ms":    r["remote_mtime_ms"],
                "remote_vclock":      json.loads(r["remote_vclock_json"]),
                "applied_choice":     r["applied_choice"],
                "resolved_ms":        r["resolved_ms"],
                "resolution":         r["resolution"],
                "resolved_by":        r["resolved_by"],
            }
        return None

    def mark_manifest_conflict_resolved(
        self,
        conflict_id: int,
        *,
        resolution: str,
        resolved_by: str = "ui",
    ) -> bool:
        """Stamp a conflict resolved. Returns True iff the row was
        previously unresolved (so the caller can avoid double-applying
        a side-effect like 'write the conflict-suffix file')."""
        if resolution not in ("mine", "theirs", "both", "auto"):
            raise ValueError(
                f"resolution must be mine|theirs|both|auto, got {resolution!r}"
            )
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE manifest_conflicts"
                " SET resolved_ms = ?, resolution = ?, resolved_by = ?"
                " WHERE id = ? AND resolved_ms IS NULL",
                (_now_ms(), resolution, resolved_by, int(conflict_id)),
            )
            return cur.rowcount > 0

    def count_unresolved_manifest_conflicts(
        self, folder_name: Optional[str] = None,
    ) -> int:
        if folder_name is None:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM manifest_conflicts WHERE resolved_ms IS NULL"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM manifest_conflicts"
                " WHERE folder_name = ? AND resolved_ms IS NULL",
                (folder_name,),
            ).fetchone()
        return int(row["n"]) if row else 0

    # ─── blobs index ──────────────────────────────────────────────────

    def record_blob(self, hash_hex: str, size: int) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO blobs(hash, size, received_ms)
                VALUES(?, ?, ?)
                """,
                (hash_hex, size, _now_ms()),
            )

    def has_blob(self, hash_hex: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM blobs WHERE hash = ?", (hash_hex,)
        ).fetchone()
        return bool(row)

    def list_blobs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT hash, size, received_ms FROM blobs ORDER BY received_ms DESC"
        ).fetchall()
        return [{"hash": r["hash"], "size": r["size"], "received_ms": r["received_ms"]} for r in rows]

    # ─── settings (kv) ────────────────────────────────────────────────

    def record_chunk_available(
        self,
        chunk_hash: str,
        size: int,
        *,
        blob_hash: Optional[str] = None,
        chunk_index: Optional[int] = None,
        source: str = "local",
    ) -> None:
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO chunk_availability(
                    chunk_hash, size, blob_hash, chunk_index, source, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_hash) DO UPDATE SET
                    size = excluded.size,
                    blob_hash = COALESCE(excluded.blob_hash, chunk_availability.blob_hash),
                    chunk_index = COALESCE(excluded.chunk_index, chunk_availability.chunk_index),
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                (
                    chunk_hash,
                    int(size),
                    blob_hash,
                    chunk_index,
                    str(source or "local"),
                    now,
                ),
            )

    def record_chunks_available_batch(
        self,
        records: "list[dict]",
    ) -> int:
        """Batched cousin of :meth:`record_chunk_available`. Wraps
        all inserts in a single explicit transaction so a
        thousand-chunk transfer pays one commit instead of one
        thousand. Returns the number of rows written.

        Each record is a dict with keys ``chunk_hash`` (required),
        ``size`` (required), ``blob_hash`` (optional),
        ``chunk_index`` (optional), ``source`` (optional, default
        ``"local"``). Unknown keys are dropped silently so the
        caller can over-supply.

        Bench gain: at 256 MiB / 256 KiB chunks = 1024 records,
        one transaction commit replaces 1024. Wall-time saving
        scales with chunk count; SQLite WAL log churn drops
        proportionally too.
        """
        if not records:
            return 0
        now = _now_ms()
        rows = []
        for r in records:
            try:
                rows.append((
                    str(r["chunk_hash"]),
                    int(r["size"]),
                    r.get("blob_hash"),
                    r.get("chunk_index"),
                    str(r.get("source") or "local"),
                    now,
                ))
            except (KeyError, TypeError, ValueError):
                # Skip malformed entries — don't poison the batch.
                continue
        if not rows:
            return 0
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.execute("BEGIN IMMEDIATE")
                c.executemany(
                    """
                    INSERT INTO chunk_availability(
                        chunk_hash, size, blob_hash, chunk_index, source, updated_ms
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    ON CONFLICT(chunk_hash) DO UPDATE SET
                        size = excluded.size,
                        blob_hash = COALESCE(excluded.blob_hash, chunk_availability.blob_hash),
                        chunk_index = COALESCE(excluded.chunk_index, chunk_availability.chunk_index),
                        source = excluded.source,
                        updated_ms = excluded.updated_ms
                    """,
                    rows,
                )
                c.execute("COMMIT")
            except Exception:
                with contextlib.suppress(Exception):
                    c.execute("ROLLBACK")
                raise
        return len(rows)

    def forget_chunk_available(self, chunk_hash: str) -> None:
        """Drop a chunk_availability row. Called by the cache GC
        after the on-disk cache file has been unlinked so a future
        ``has_chunk`` query doesn't falsely claim we still hold it.

        Idempotent when the row is already absent. Database failures are
        propagated so the caller can report the stale availability index;
        silently retaining the row would make ``has_chunk`` lie.
        """
        with self._write_lock:
            self._conn.execute(
                "DELETE FROM chunk_availability WHERE chunk_hash = ?",
                (str(chunk_hash),),
            )

    def has_chunk(self, chunk_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM chunk_availability WHERE chunk_hash = ?",
            (chunk_hash,),
        ).fetchone()
        return row is not None

    def chunks_available(self, chunk_hashes: Iterable[str]) -> list[str]:
        clean = [str(h) for h in chunk_hashes if str(h)]
        if not clean:
            return []
        out: list[str] = []
        for i in range(0, len(clean), 500):
            batch = clean[i:i + 500]
            rows = self._conn.execute(
                "SELECT chunk_hash FROM chunk_availability "
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",  # nosec B608
                tuple(batch),
            ).fetchall()
            out.extend(str(r["chunk_hash"]) for r in rows)
        have = set(out)
        return [h for h in clean if h in have]

    def record_chunk_source(
        self,
        chunk_hash: str,
        *,
        path: str,
        start: int,
        size: int,
        mtime_ms: int,
        file_size: int,
        source: str = "prior",
    ) -> None:
        now = _now_ms()
        # v0.20.7 (M30): wrap path before persisting.
        wrapped_path = self._seal_field(CHUNK_SOURCE_PATH, str(path))
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO chunk_sources(
                    chunk_hash, path, start, size, mtime_ms, file_size,
                    source, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_hash, path, start) DO UPDATE SET
                    size = excluded.size,
                    mtime_ms = excluded.mtime_ms,
                    file_size = excluded.file_size,
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                (
                    str(chunk_hash),
                    wrapped_path,
                    int(start),
                    int(size),
                    int(mtime_ms),
                    int(file_size),
                    str(source or "prior"),
                    now,
                ),
            )
        self.record_chunk_available(
            str(chunk_hash),
            int(size),
            source=str(source or "prior"),
        )

    def record_chunk_sources_for_file(
        self,
        *,
        path: str,
        file_size: int,
        mtime_ms: int,
        chunks: Iterable[dict],
        source: str = "file_index",
    ) -> int:
        """Record many chunk sources for one stable file in one write pass.

        Live file sends already have a deterministic manifest for the source
        file. Recording path+offset sources lets future CHUNK_PULL requests
        read directly from that file instead of eagerly copying every chunk
        into One Link's cache during the send hot path.
        """

        now = _now_ms()
        # v0.20.7 (M30): wrap path once for the whole batch — same
        # plaintext path → same ciphertext (AES-SIV deterministic),
        # so the existing PRIMARY KEY de-duplication still works.
        wrapped_path = self._seal_field(CHUNK_SOURCE_PATH, str(path))
        clean: list[tuple[str, str, int, int, int, int, str, int]] = []
        avail: list[tuple[str, int, str, int]] = []
        for index, c in enumerate(chunks):
            try:
                chunk_hash = str(c["hash"])
                start = int(c["start"])
                # A dict.get default is evaluated eagerly: writing this as
                # c.get("size", int(c["end"]) - start) raised KeyError for a
                # chunk that carries only `size`, and the chunk was skipped.
                size = int(c["size"]) if "size" in c else int(c["end"]) - start
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                log.warning(
                    "record_chunk_sources_for_file: skipping malformed "
                    "chunk index=%d (%s)",
                    index,
                    type(exc).__name__,
                )
                continue
            if not chunk_hash or start < 0 or size <= 0:
                continue
            clean.append((
                chunk_hash,
                wrapped_path,
                start,
                size,
                int(mtime_ms),
                int(file_size),
                str(source or "file_index"),
                now,
            ))
            avail.append((chunk_hash, size, str(source or "file_index"), now))
        if not clean:
            return 0
        with self._write_lock:
            self._conn.executemany(
                """
                INSERT INTO chunk_sources(
                    chunk_hash, path, start, size, mtime_ms, file_size,
                    source, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_hash, path, start) DO UPDATE SET
                    size = excluded.size,
                    mtime_ms = excluded.mtime_ms,
                    file_size = excluded.file_size,
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                clean,
            )
            self._conn.executemany(
                """
                INSERT INTO chunk_availability(
                    chunk_hash, size, blob_hash, chunk_index, source, updated_ms
                ) VALUES(?, ?, NULL, NULL, ?, ?)
                ON CONFLICT(chunk_hash) DO UPDATE SET
                    size = excluded.size,
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                avail,
            )
        return len(clean)

    def get_chunk_sources(self, chunk_hash: str, *, limit: int = 8) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT chunk_hash, path, start, size, mtime_ms, file_size,
                   source, updated_ms
            FROM chunk_sources
            WHERE chunk_hash = ?
            ORDER BY updated_ms DESC
            LIMIT ?
            """,
            (str(chunk_hash), int(limit)),
        ).fetchall()
        return [
            {
                "chunk_hash": r["chunk_hash"],
                # v0.20.7 (M30): unwrap on read; legacy cleartext rows
                # pass through untouched via PathPIIEncryptor.unwrap.
                "path": self._open_field(CHUNK_SOURCE_PATH, r["path"]),
                "start": int(r["start"]),
                "size": int(r["size"]),
                "mtime_ms": int(r["mtime_ms"]),
                "file_size": int(r["file_size"]),
                "source": r["source"],
                "updated_ms": int(r["updated_ms"]),
            }
            for r in rows
        ]

    def forget_chunk_source(
        self,
        chunk_hash: str,
        *,
        path: str,
        start: int,
    ) -> None:
        """Forget one stale lazy-source claim.

        Source rows are only advisory: files can be deleted, replaced, or
        modified after they were indexed.  Readers call this after proving a
        row no longer identifies the promised chunk so future availability
        checks do not repeatedly reopen the same invalid source.
        """
        wrapped_path = self._seal_field(CHUNK_SOURCE_PATH, str(path))
        with self._write_lock:
            self._conn.execute(
                "DELETE FROM chunk_sources "
                "WHERE chunk_hash = ? AND path = ? AND start = ?",
                (str(chunk_hash), wrapped_path, int(start)),
            )
            remaining = self._conn.execute(
                "SELECT 1 FROM chunk_sources WHERE chunk_hash = ? LIMIT 1",
                (str(chunk_hash),),
            ).fetchone()
            if remaining is None:
                self._conn.execute(
                    "DELETE FROM chunk_availability "
                    "WHERE chunk_hash = ? AND source != 'local'",
                    (str(chunk_hash),),
                )

    def find_complete_source_file(
        self,
        chunks: "list[dict]",
        *,
        max_candidates: int = 8,
    ) -> "Optional[dict]":
        """Find a local file that already contains every chunk in
        the manifest at its declared offset.

        Used by the hardlink warm-dedup path: when every chunk a
        new CDC FILE_OFFER asks for has already been recorded as
        sourced from one specific file, we can hardlink that file
        as the new transfer's output instead of re-reading every
        chunk through the cache and writing them out again. Wave
        2a — pulls warm-dedup latency at 16 MiB from ~100 ms down
        to milliseconds.

        ``chunks`` is the CDC manifest: list of dicts with at
        least ``hash``, ``start``, ``size`` keys, in any order.
        Returns a dict with ``path``, ``file_size``, ``mtime_ms``
        when a match is found, ``None`` otherwise.

        The match is strict: every chunk must be sourced from the
        SAME file at the SAME offset. If even one chunk is missing
        or has a different recorded start, we bail. The receiver
        does its own existence + size + mtime verification before
        hardlinking; this is just the index lookup.
        """
        if not chunks:
            return None
        # Pick the first chunk's candidate paths; intersect against
        # subsequent chunks' candidate paths to converge on the set
        # of files that hold all of them. Fail-fast when the
        # intersection becomes empty.
        try:
            first_hash = str(chunks[0]["hash"])
            first_start = int(chunks[0]["start"])
        except (KeyError, TypeError, ValueError):
            return None
        rows = self._conn.execute(
            """
            SELECT path, file_size, mtime_ms
            FROM chunk_sources
            WHERE chunk_hash = ? AND start = ?
            ORDER BY updated_ms DESC
            LIMIT ?
            """,
            (first_hash, first_start, int(max_candidates)),
        ).fetchall()
        # Map of wrapped-path -> (unwrapped_path, file_size, mtime_ms)
        # so the rest of the loop matches on the wrapped form (cheap,
        # avoids unwrap-per-row) and only unwraps the winner.
        candidates: dict[str, tuple[str, int, int]] = {}
        for r in rows:
            wrapped = str(r["path"])
            candidates[wrapped] = (
                wrapped,
                int(r["file_size"]),
                int(r["mtime_ms"]),
            )
        if not candidates:
            return None
        # Walk the remaining chunks; keep only candidates that
        # still contain each one. SQL constraints (chunk_hash,
        # start) ensure each row is uniquely matchable.
        for c in chunks[1:]:
            try:
                h = str(c["hash"])
                s = int(c["start"])
            except (KeyError, TypeError, ValueError):
                return None
            placeholders = ",".join("?" * len(candidates))
            sql = (
                "SELECT path FROM chunk_sources "
                "WHERE chunk_hash = ? AND start = ? "
                f"AND path IN ({placeholders})"  # nosec B608
            )
            params = (h, s, *candidates.keys())
            hits = {
                str(r["path"]) for r in self._conn.execute(sql, params).fetchall()
            }
            # Drop any candidate that doesn't have this chunk.
            candidates = {
                wrapped: meta for wrapped, meta in candidates.items()
                if wrapped in hits
            }
            if not candidates:
                return None
        # Survivor wins. Unwrap and return.
        wrapped, (_w, file_size, mtime_ms) = next(iter(candidates.items()))
        try:
            unwrapped = self._open_field(CHUNK_SOURCE_PATH, wrapped)
        except Exception:
            return None
        return {
            "path": unwrapped,
            "file_size": file_size,
            "mtime_ms": mtime_ms,
        }

    def chunks_sourced(self, chunk_hashes: Iterable[str]) -> list[str]:
        clean = [str(h) for h in chunk_hashes if str(h)]
        if not clean:
            return []
        out: list[str] = []
        for i in range(0, len(clean), 500):
            batch = clean[i:i + 500]
            rows = self._conn.execute(
                "SELECT DISTINCT chunk_hash FROM chunk_sources "
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",  # nosec B608
                tuple(batch),
            ).fetchall()
            out.extend(str(r["chunk_hash"]) for r in rows)
        have = set(out)
        return [h for h in clean if h in have]

    def list_chunks_for_blob(self, blob_hash: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT chunk_hash, size, blob_hash, chunk_index, source, updated_ms
            FROM chunk_availability
            WHERE blob_hash = ?
            ORDER BY chunk_index ASC, updated_ms DESC
            """,
            (blob_hash,),
        ).fetchall()
        return [
            {
                "chunk_hash": r["chunk_hash"],
                "size": int(r["size"]),
                "blob_hash": r["blob_hash"],
                "chunk_index": r["chunk_index"],
                "source": r["source"],
                "updated_ms": int(r["updated_ms"]),
            }
            for r in rows
        ]

    def record_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        blob_hash: str,
        index_kind: str,
        chunks: Iterable[dict],
        dev: int | str = 0,
        ino: int | str = 0,
        file_id: str = "",
        change_ns: int | str = 0,
        index_mode: str = "",
    ) -> None:
        clean_chunks: list[dict] = []
        for c in chunks:
            clean_chunks.append({
                "index": int(c["index"]),
                "start": int(c["start"]),
                "end": int(c["end"]),
                "size": int(c.get("size", int(c["end"]) - int(c["start"]))),
                "hash": str(c["hash"]),
            })
        # v0.20.7 (M30): wrap path before persisting.
        wrapped_path = self._seal_field(FILE_INDEX_PATH, str(path))
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO file_index_cache(
                    path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                    chunks_json, updated_ms, device_id, inode_id, file_id,
                    change_ns, index_mode
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    size = excluded.size,
                    mtime_ns = excluded.mtime_ns,
                    ctime_ns = excluded.ctime_ns,
                    blob_hash = excluded.blob_hash,
                    index_kind = excluded.index_kind,
                    chunks_json = excluded.chunks_json,
                    updated_ms = excluded.updated_ms,
                    device_id = excluded.device_id,
                    inode_id = excluded.inode_id,
                    file_id = excluded.file_id,
                    change_ns = excluded.change_ns,
                    index_mode = excluded.index_mode
                """,
                (
                    wrapped_path,
                    int(size),
                    int(mtime_ns),
                    int(ctime_ns),
                    str(blob_hash),
                    str(index_kind or "unknown"),
                    json.dumps(clean_chunks, separators=(",", ":")),
                    _now_ms(),
                    str(dev),
                    str(ino),
                    str(file_id or ""),
                    str(change_ns),
                    str(index_mode or index_kind or "unknown"),
                ),
            )

    def upsert_manifest_entries_atomic(
        self,
        *,
        folder_name: str,
        entries: Iterable[dict[str, Any]],
        pending_applies: Optional[Iterable[dict[str, Any]]] = None,
    ) -> None:
        """Commit one reconciled manifest generation atomically and durably.

        Receipt-critical folder merge rows must never become visible as a
        prefix when a later row fails.  FULL synchronous mode is scoped to
        this transaction so a positive durable receipt is backed by the WAL
        commit rather than the process cache alone.
        """

        rows = list(entries)
        if not rows:
            return
        if len(rows) > MAX_FOLDER_PENDING_APPLIES:
            raise ValueError("manifest generation exceeds the durable safety bound")
        normalized_pending = None
        if pending_applies is not None:
            normalized_pending = [
                self._normalize_folder_pending_apply(
                    folder_name=folder_name,
                    value=dict(value),
                )
                for value in pending_applies
            ]
            entry_paths = {str(row["file_path"]) for row in rows}
            pending_paths = {row["file_path"] for row in normalized_pending}
            if len(pending_paths) != len(normalized_pending):
                raise ValueError("duplicate pending apply path in manifest generation")
            if not pending_paths.issubset(entry_paths):
                raise ValueError("pending apply path is outside manifest generation")
        with self._write_lock:
            previous_sync_row = self._conn.execute(
                "PRAGMA synchronous",
            ).fetchone()
            previous_sync = int(previous_sync_row[0]) if previous_sync_row else 1
            sync_names = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}
            self._conn.execute("PRAGMA synchronous=FULL")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                updated_ms = _now_ms()
                self._conn.executemany(
                    """
                    INSERT INTO folder_manifest(
                        folder_name, file_path, blob_hash, size, mtime_ms,
                        vclock_json, updated_ms
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(folder_name, file_path) DO UPDATE SET
                        blob_hash    = excluded.blob_hash,
                        size         = excluded.size,
                        mtime_ms     = excluded.mtime_ms,
                        vclock_json  = excluded.vclock_json,
                        updated_ms   = excluded.updated_ms
                    """,
                    [
                        (
                            folder_name,
                            str(entry["file_path"]),
                            entry.get("blob_hash"),
                            entry.get("size"),
                            entry.get("mtime_ms"),
                            json.dumps(
                                dict(entry.get("vclock") or {}),
                                sort_keys=True,
                            ),
                            updated_ms,
                        )
                        for entry in rows
                    ],
                )
                if normalized_pending is not None:
                    self._conn.executemany(
                        "DELETE FROM folder_pending_applies "
                        "WHERE folder_name=? AND file_path=?",
                        [
                            (folder_name, str(entry["file_path"]))
                            for entry in rows
                        ],
                    )
                    self._conn.executemany(
                        """
                        INSERT INTO folder_pending_applies(
                            apply_id, folder_name, file_path, operation,
                            target_blob_hash, target_size, target_mtime_ms,
                            target_vclock_json, baseline_blob_hash,
                            baseline_evidence_json, phase, staging_name,
                            recovery_name, attempts, last_error, created_ms,
                            updated_ms
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
                        """,
                        [
                            (
                                pending["apply_id"],
                                folder_name,
                                pending["file_path"],
                                pending["operation"],
                                pending["target_blob_hash"],
                                pending["target_size"],
                                pending["target_mtime_ms"],
                                json.dumps(
                                    pending["target_vclock"],
                                    separators=(",", ":"),
                                    sort_keys=True,
                                ),
                                pending["baseline_blob_hash"],
                                (
                                    json.dumps(
                                        pending["baseline_evidence"],
                                        separators=(",", ":"),
                                    )
                                    if pending["baseline_evidence"] is not None
                                    else None
                                ),
                                pending["phase"],
                                pending["staging_name"],
                                pending["recovery_name"],
                                updated_ms,
                                updated_ms,
                            )
                            for pending in normalized_pending
                        ],
                    )
                self._conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(*DB_ERRORS):
                    self._conn.execute("ROLLBACK")
                raise
            finally:
                self._conn.execute(
                    f"PRAGMA synchronous={sync_names.get(previous_sync, 'NORMAL')}"
                )

    def get_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        dev: int | str = 0,
        ino: int | str = 0,
        file_id: str = "",
        change_ns: int | str = 0,
    ) -> Optional[dict]:
        # v0.20.7 (M30): wrap query path so the SELECT matches the
        # deterministic-encrypted row written in record_file_index_cache.
        # Same plaintext + AAD → same ciphertext (AES-SIV), so the
        # index lookup still works.
        wrapped_path = self._seal_field(FILE_INDEX_PATH, str(path))
        row = self._conn.execute(
            """
            SELECT path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                   chunks_json, updated_ms, device_id, inode_id, file_id,
                   change_ns, index_mode
            FROM file_index_cache
            WHERE path = ? AND size = ? AND mtime_ns = ? AND ctime_ns = ?
              AND device_id = ? AND inode_id = ? AND file_id = ?
              AND change_ns = ?
            """,
            (
                wrapped_path,
                int(size),
                int(mtime_ns),
                int(ctime_ns),
                str(dev),
                str(ino),
                str(file_id or ""),
                str(change_ns),
            ),
        ).fetchone()
        # If the wrapped lookup missed but we have an encryptor, also
        # try the legacy cleartext path so pre-v0.20.7 rows still hit.
        if row is None and self._path_pii is not None and wrapped_path != str(path):
            row = self._conn.execute(
                """
                SELECT path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                       chunks_json, updated_ms, device_id, inode_id, file_id,
                       change_ns, index_mode
                FROM file_index_cache
                WHERE path = ? AND size = ? AND mtime_ns = ? AND ctime_ns = ?
                  AND device_id = ? AND inode_id = ? AND file_id = ?
                  AND change_ns = ?
                """,
                (
                    str(path),
                    int(size),
                    int(mtime_ns),
                    int(ctime_ns),
                    str(dev),
                    str(ino),
                    str(file_id or ""),
                    str(change_ns),
                ),
            ).fetchone()
        if row is None:
            return None
        try:
            chunks = json.loads(row["chunks_json"] or "[]")
        except Exception:
            chunks = []
        if not isinstance(chunks, list):
            chunks = []
        return {
            "path": self._open_field(FILE_INDEX_PATH, row["path"]),
            "size": int(row["size"]),
            "mtime_ns": int(row["mtime_ns"]),
            "ctime_ns": int(row["ctime_ns"]),
            "dev": row["device_id"],
            "ino": row["inode_id"],
            "file_id": row["file_id"],
            "change_ns": row["change_ns"],
            "blob_hash": row["blob_hash"],
            "index_kind": row["index_kind"],
            "index_mode": row["index_mode"],
            "chunks": chunks,
            "updated_ms": int(row["updated_ms"]),
        }

    # ── ui_sessions (v27): persistent UI session cookies ─────────
    @staticmethod
    def _hash_user_agent(ua: Optional[str]) -> Optional[str]:
        if not ua:
            return None
        return hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest()[:16]

    @staticmethod
    def _label_user_agent(ua: Optional[str]) -> Optional[str]:
        """Best-effort short label for the 'Active sessions' UI list.
        We never send the UA off the box; this is pure local display."""
        if not ua:
            return None
        ua_l = ua.lower()
        browser = "Browser"
        if "edg/" in ua_l or "edge/" in ua_l:
            browser = "Edge"
        elif "chrome/" in ua_l and "edg/" not in ua_l and "edge/" not in ua_l:
            browser = "Chrome"
        elif "firefox/" in ua_l:
            browser = "Firefox"
        elif "safari/" in ua_l and "chrome/" not in ua_l:
            browser = "Safari"
        elif "curl/" in ua_l:
            browser = "curl"
        os_name = "Unknown OS"
        if "windows" in ua_l:
            os_name = "Windows"
        elif "mac os" in ua_l or "macintosh" in ua_l:
            os_name = "macOS"
        elif "iphone" in ua_l or "ipad" in ua_l or "ios " in ua_l:
            os_name = "iOS"
        elif "android" in ua_l:
            os_name = "Android"
        elif "linux" in ua_l:
            os_name = "Linux"
        return f"{browser} on {os_name}"

    _UI_SESSION_HASH_DOMAIN = b"OL/ui-session/token/v1\0"

    @classmethod
    def ui_session_token_id(cls, session_token: object) -> Optional[str]:
        """Return the non-replayable database key for a cookie token.

        Only canonical 256-bit lowercase-hex tokens are accepted. Keeping the
        token grammar exact avoids ambiguous encodings and ensures a value read
        from the database cannot itself be replayed as a cookie (it hashes to a
        different key).
        """
        if not isinstance(session_token, str) or len(session_token) != 64:
            return None
        if any(char not in "0123456789abcdef" for char in session_token):
            return None
        return hashlib.sha256(
            cls._UI_SESSION_HASH_DOMAIN + session_token.encode("ascii")
        ).hexdigest()

    def create_ui_session(
        self,
        *,
        user_agent: Optional[str] = None,
        remote: Optional[str] = None,
    ) -> dict:
        """Mint a persistent UI session and return its bearer token once.

        The raw ``session_uuid`` return value is planted in an HttpOnly,
        SameSite=Strict cookie. Only its domain-separated SHA-256 record key is
        persisted, so copying ``state.db`` does not disclose a replayable
        credential.
        """
        now = int(time.time() * 1000)
        sid = secrets.token_hex(32)
        record_key = self.ui_session_token_id(sid)
        if record_key is None:  # pragma: no cover - token_hex contract
            raise RuntimeError("failed to generate a canonical UI session token")
        ua_hash = self._hash_user_agent(user_agent)
        label = self._label_user_agent(user_agent)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO ui_sessions(
                    session_uuid, created_ms, last_seen_ms,
                    user_agent_hash, label, remote_first
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (record_key, now, now, ua_hash, label, remote),
            )
            self._conn.commit()
        return {
            "session_uuid": sid,
            "created_ms": now,
            "last_seen_ms": now,
            "user_agent_hash": ua_hash,
            "label": label,
            "remote_first": remote,
        }

    def touch_ui_session(self, session_uuid: str) -> bool:
        """Update last_seen_ms for an active session. Returns True if
        the session exists + is not revoked; False otherwise. Cheap
        because it's a single UPDATE on an indexed column.

        The bearer token is hashed before the indexed lookup; the raw token is
        never compared with, or stored in, SQLite."""
        record_key = self.ui_session_token_id(session_uuid)
        if record_key is None:
            return False
        now = int(time.time() * 1000)
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE ui_sessions SET last_seen_ms=?"
                " WHERE session_uuid=? AND revoked_ms IS NULL",
                (now, record_key),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def lookup_ui_session(self, session_uuid: str) -> Optional[dict]:
        """Return the session row iff valid + not revoked. Does NOT
        touch last_seen_ms (auth path uses touch_ui_session for that
        atomically). Read-only helper for the Sessions list UI."""
        record_key = self.ui_session_token_id(session_uuid)
        if record_key is None:
            return None
        row = self._conn.execute(
            "SELECT * FROM ui_sessions"
            " WHERE session_uuid=? AND revoked_ms IS NULL",
            (record_key,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "session_uuid": row["session_uuid"],
            "created_ms": row["created_ms"],
            "last_seen_ms": row["last_seen_ms"],
            "user_agent_hash": row["user_agent_hash"],
            "label": row["label"],
            "remote_first": row["remote_first"],
        }

    def list_ui_sessions(self, *, include_revoked: bool = False) -> list[dict]:
        sql = "SELECT * FROM ui_sessions"
        if not include_revoked:
            sql += " WHERE revoked_ms IS NULL"
        sql += " ORDER BY last_seen_ms DESC"
        rows = self._conn.execute(sql).fetchall()
        return [
            {
                "id": r["id"],
                "session_uuid": r["session_uuid"],
                "created_ms": r["created_ms"],
                "last_seen_ms": r["last_seen_ms"],
                "revoked_ms": r["revoked_ms"],
                "user_agent_hash": r["user_agent_hash"],
                "label": r["label"],
                "remote_first": r["remote_first"],
            }
            for r in rows
        ]

    def revoke_ui_session(self, session_uuid: str) -> bool:
        """Mark a specific session revoked. Returns True if a row was
        actually flipped (i.e. it existed + was active)."""
        record_key = self.ui_session_token_id(session_uuid)
        if record_key is None:
            return False
        now = int(time.time() * 1000)
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE ui_sessions SET revoked_ms=?"
                " WHERE session_uuid=? AND revoked_ms IS NULL",
                (now, record_key),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def revoke_ui_session_by_id(self, session_id: int) -> bool:
        """Revoke a management-list row without exposing its bearer token."""
        if isinstance(session_id, bool) or not isinstance(session_id, int):
            return False
        if session_id <= 0:
            return False
        now = int(time.time() * 1000)
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE ui_sessions SET revoked_ms=?"
                " WHERE id=? AND revoked_ms IS NULL",
                (now, session_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def revoke_all_ui_sessions(self) -> int:
        """Revoke EVERY active session — the 'Sign out all browsers'
        button calls this. Returns the count revoked so the UI can
        echo 'Signed out 3 browsers.'"""
        now = int(time.time() * 1000)
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE ui_sessions SET revoked_ms=?"
                " WHERE revoked_ms IS NULL",
                (now,),
            )
            self._conn.commit()
            return cur.rowcount

    def strip_ui_session_labels(self) -> int:
        """Clear the label + UA hash columns on every ui_sessions row.
        Called when the user flips the 'Show browser labels' toggle
        OFF — privacy-first mode forgets the historical UA strings
        immediately instead of waiting for revoke/prune. Returns
        the count of rows updated."""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE ui_sessions SET label=NULL, user_agent_hash=NULL"
                " WHERE label IS NOT NULL OR user_agent_hash IS NOT NULL"
            )
            self._conn.commit()
            return cur.rowcount

    def wipe_ui_sessions(self) -> int:
        """Hard-delete every row in ui_sessions. Used when the user
        flips persistence OFF or hits 'Forget all session data'.
        Returns the count of rows removed. Note: this does NOT
        clear the browser-side cookies — the auth handler does that
        on the response. After wipe, even a legitimate cookie from
        a still-open tab will fail to auth (the uuid is gone)."""
        with self._write_lock:
            cur = self._conn.execute("DELETE FROM ui_sessions")
            self._conn.commit()
            return cur.rowcount

    def prune_expired_ui_sessions(self, *, older_than_ms: int) -> int:
        """Delete sessions that haven't been touched since ``older_than_ms``
        AND were revoked / inactive. Called on a slow background cadence
        so the table doesn't grow unbounded from forgotten browsers."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM ui_sessions"
                " WHERE last_seen_ms < ?",
                (int(older_than_ms),),
            )
            self._conn.commit()
            return cur.rowcount

    def set_setting(self, key: str, value: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def apply_settings_batch(
        self,
        *,
        upserts: Mapping[str, str],
        deletes: Iterable[str] = (),
    ) -> None:
        """Atomically apply one validated settings request.

        A settings screen saves many independent controls in one HTTP request.
        Applying those rows one at a time made a late validation or storage
        failure leave an internally inconsistent half-save.  Callers must
        normalize and validate first; this method provides the durable SQLite
        commit boundary and rejects ambiguous delete/upsert plans.
        """
        normalized_upserts = {
            str(key): str(value)
            for key, value in upserts.items()
        }
        normalized_deletes = {str(key) for key in deletes}
        overlap = normalized_deletes.intersection(normalized_upserts)
        if overlap:
            names = ", ".join(sorted(overlap))
            raise ValueError(f"settings batch deletes and upserts the same key: {names}")
        if not normalized_upserts and not normalized_deletes:
            return

        with self.durable_write_transaction():
            if normalized_deletes:
                self._conn.executemany(
                    "DELETE FROM settings WHERE key = ?",
                    ((key,) for key in sorted(normalized_deletes)),
                )
            if normalized_upserts:
                self._conn.executemany(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    sorted(normalized_upserts.items()),
                )

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def all_settings(self) -> dict[str, str]:
        rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def delete_setting(self, key: str) -> None:
        with self._write_lock:
            self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # ─── rendezvous (v0.5.1) ──────────────────────────────────────────
    # Stored as a JSON list under the `rendezvous_urls` setting key.
    # The daemon registers its presence with each on startup and uses
    # them for cross-internet peer lookup when mDNS doesn't have the
    # peer.

    def get_rendezvous_urls(self) -> list[str]:
        raw = self.get_setting("rendezvous_urls")
        if not raw:
            return []
        try:
            v = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(v, list):
            return []
        return [str(u) for u in v if isinstance(u, str) and u]

    def set_rendezvous_urls(self, urls: Iterable[str]) -> None:
        clean = sorted({u.strip().rstrip("/") for u in urls if u and u.strip()})
        # Light validation — protocol prefix only.
        for u in clean:
            if not (u.startswith("http://") or u.startswith("https://")):
                raise ValueError(f"rendezvous URL must be http(s): {u!r}")
        self.set_setting("rendezvous_urls", json.dumps(clean))

    # ─── lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        with self._write_lock:
            self._conn.close()
        # Clean-shutdown marker: its presence at the next open means the
        # DB was closed cleanly, so the next boot can skip the expensive
        # full-file integrity check. Written LAST, after the connection
        # is closed and all pages are flushed. A crash never reaches
        # here, so the marker stays absent and the next boot verifies.
        with contextlib.suppress(Exception):
            self._clean_marker.write_text("ok", encoding="utf-8")
