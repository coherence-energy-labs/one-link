"""The state database is not opened across a schema boundary carelessly."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from one_link import state as state_module
from one_link import state_encryption
from one_link.state import State, StateSchemaTooNewError

LATEST = State.LATEST_SCHEMA_VERSION


def _fresh(tmp_path: Path) -> Path:
    db = tmp_path / "state.db"
    state = State(db_path=db)
    state.upsert_peer(fingerprint="ab" * 32, short_id="abababab", pubkey=b"\x01" * 32)
    state.close()
    return db


def _raw(db: Path) -> sqlite3.Connection:
    return sqlite3.connect(str(db), isolation_level=None)


def _stamp(db: Path) -> int:
    conn = _raw(db)
    try:
        return conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    finally:
        conn.close()


def _snapshots(db: Path) -> list[Path]:
    return sorted(db.parent.glob(f"{db.name}.pre-migration-v*.bak"))


def test_declared_versions_agree() -> None:
    assert LATEST == state_encryption.STATE_SCHEMA_VERSION_CURRENT


def test_new_database_takes_no_snapshot(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    assert _stamp(db) == LATEST
    assert _snapshots(db) == []


def test_reopening_a_current_database_takes_no_snapshot(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    State(db_path=db).close()
    assert _snapshots(db) == []


def test_database_from_a_newer_release_is_refused_untouched(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    conn = _raw(db)
    conn.execute("INSERT INTO schema_version(version) VALUES(?)", (LATEST + 5,))
    conn.execute("CREATE TABLE from_the_future (x TEXT)")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    before = db.read_bytes()

    with pytest.raises(StateSchemaTooNewError, match=f"schema version {LATEST + 5}"):
        State(db_path=db)

    assert db.read_bytes() == before
    assert _snapshots(db) == []


def _downgrade_stamp(db: Path, to: int) -> None:
    conn = _raw(db)
    conn.execute("DELETE FROM schema_version WHERE version > ?", (to,))
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def test_upgrade_saves_the_database_as_it_was(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    _downgrade_stamp(db, LATEST - 1)

    State(db_path=db).close()

    assert _stamp(db) == LATEST
    (snapshot,) = _snapshots(db)
    assert snapshot.name == f"state.db.pre-migration-v{LATEST - 1}.bak"
    # The snapshot is the pre-upgrade database: old stamp, same data.
    assert _stamp(snapshot) == LATEST - 1
    conn = _raw(snapshot)
    try:
        assert conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()
    if os.name == "posix":
        assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600


def test_existing_snapshot_for_the_same_upgrade_is_kept(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    _downgrade_stamp(db, LATEST - 1)
    earlier = db.with_name(f"{db.name}.pre-migration-v{LATEST - 1}.bak")
    earlier.write_bytes(b"taken before the first attempt")

    State(db_path=db).close()

    assert earlier.read_bytes() == b"taken before the first attempt"


def test_only_the_snapshot_of_the_latest_upgrade_is_retained(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    stale = db.with_name(f"{db.name}.pre-migration-v3.bak")
    stale.write_bytes(b"from long ago")
    _downgrade_stamp(db, LATEST - 1)

    State(db_path=db).close()

    assert [p.name for p in _snapshots(db)] == [f"state.db.pre-migration-v{LATEST - 1}.bak"]


def test_snapshot_is_synced_through_a_writable_handle(tmp_path: Path, monkeypatch) -> None:
    """Windows refuses ``os.fsync`` on a handle opened for reading (EBADF).

    POSIX accepts it, so a read-only handle passes every Linux and macOS run
    and stops every schema upgrade on Windows. This holds the Windows rule on
    the platforms that would otherwise not notice.
    """
    fcntl = pytest.importorskip("fcntl", reason="Windows enforces this itself")
    real_fsync = os.fsync
    synced_files: list[int] = []

    def windows_like_fsync(fd: int) -> None:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
                raise OSError(errno.EBADF, "Bad file descriptor")
            synced_files.append(fd)
        real_fsync(fd)

    db = _fresh(tmp_path)
    _downgrade_stamp(db, LATEST - 1)
    monkeypatch.setattr(state_module.os, "fsync", windows_like_fsync)
    State(db_path=db).close()
    monkeypatch.undo()

    assert [p.name for p in _snapshots(db)] == [f"state.db.pre-migration-v{LATEST - 1}.bak"]
    assert synced_files, "the snapshot was renamed into place without being synced"
    assert _stamp(db) == LATEST


def test_upgrade_does_not_proceed_when_the_snapshot_cannot_be_written(
    tmp_path: Path, monkeypatch
) -> None:
    db = _fresh(tmp_path)
    _downgrade_stamp(db, LATEST - 1)

    def no_space(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state_module.os, "replace", no_space)
    with pytest.raises(RuntimeError, match="could not save a snapshot"):
        State(db_path=db)
    monkeypatch.undo()

    # Nothing was migrated and nothing was left behind.
    assert _stamp(db) == LATEST - 1
    assert _snapshots(db) == []
    assert list(db.parent.glob("*.partial")) == []


def test_operator_can_explicitly_upgrade_without_a_snapshot(
    tmp_path: Path, monkeypatch
) -> None:
    db = _fresh(tmp_path)
    _downgrade_stamp(db, LATEST - 1)
    real_replace = os.replace

    def no_space(src, dst, *args, **kwargs):
        if str(dst).endswith(".bak"):
            raise OSError(28, "No space left on device")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(state_module.os, "replace", no_space)
    monkeypatch.setenv("ONE_LINK_ALLOW_UNSNAPSHOTTED_MIGRATION", "1")
    State(db_path=db).close()
    assert _stamp(db) == LATEST
    assert _snapshots(db) == []


# ─── a migration step runs once unless it says otherwise ────────────


def test_every_existing_step_keeps_its_boot_behaviour() -> None:
    assert State._REAPPLIED_EVERY_BOOT == frozenset(range(2, LATEST + 1)) - {28}
    assert State._EXACTLY_ONCE_MIGRATIONS == frozenset({28})


def test_a_step_added_later_runs_exactly_once_by_default(tmp_path: Path) -> None:
    db = _fresh(tmp_path)
    state = State(db_path=db)
    try:
        applied: list[int] = []
        future = LATEST + 1
        assert future not in State._REAPPLIED_EVERY_BOOT
        for _boot in range(3):
            cursor = state._conn.cursor()
            state._run_atomic_migration(
                cursor,
                target_version=future,
                apply=lambda _c: applied.append(1),
                exactly_once=future not in State._REAPPLIED_EVERY_BOOT,
            )
            cursor.close()
        assert applied == [1]
    finally:
        # Leave the stamp as this build expects it.
        state._conn.execute("DELETE FROM schema_version WHERE version > ?", (LATEST,))
        state.close()
