"""Opening the database again must not change what is in it.

The schema runner re-applies every migration step on every daemon start, so
that idempotent backfills keep healing rows. One step was not idempotent: v28
replaces each stored browser-session bearer with its SHA-256 record key, and a
record key has the same shape as a bearer. Re-applied, it hashed the key again.

That ran on every start from 2026-07-25 until 2026-11-25. Every daemon restart,
and so every update, signed every open window out; "Stay signed in across
daemon restarts" could not work, and no test restarted anything to notice. It
was found from one window left stranded by an update restart.

Three kinds of test here:

  * the behaviour a person relies on: a session minted before a restart still
    authenticates after it, however many restarts follow;
  * the upgrade the step exists for: a raw v27 token is still converted, once;
  * the general rule, so the next one-way step is caught without anyone
    remembering this one: re-opening a populated database changes no row.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from one_link.state import State


def _reopen(db: Path) -> State:
    return State(db_path=db)


def _session_keys(state: State) -> list[str]:
    return [row["session_uuid"] for row in state.list_ui_sessions(include_revoked=True)]


def test_a_session_minted_before_a_restart_still_authenticates_after_it(tmp_path: Path):
    db = tmp_path / "state.db"
    first = _reopen(db)
    bearer = first.create_ui_session(user_agent="Mozilla/5.0", remote="127.0.0.1")["session_uuid"]
    assert first.lookup_ui_session(bearer) is not None
    stored = _session_keys(first)
    assert stored == [State.ui_session_token_id(bearer)]
    first.close()

    # Not one restart: an install restarts for every update, for as long as
    # the session lives. The defect compounded with each one.
    for restart in range(1, 6):
        state = _reopen(db)
        try:
            assert _session_keys(state) == stored, f"restart {restart} rewrote the stored session key"
            row = state.lookup_ui_session(bearer)
            assert row is not None, f"restart {restart} signed the browser out"
            assert state.touch_ui_session(bearer) is True
        finally:
            state.close()


def test_a_revoked_session_stays_revoked_and_the_others_stay_valid_across_a_restart(tmp_path: Path):
    db = tmp_path / "state.db"
    first = _reopen(db)
    kept = first.create_ui_session()["session_uuid"]
    revoked = first.create_ui_session()["session_uuid"]
    assert first.revoke_ui_session(revoked) is True
    first.close()

    state = _reopen(db)
    try:
        assert state.lookup_ui_session(kept) is not None
        assert state.lookup_ui_session(revoked) is None
        assert state.touch_ui_session(revoked) is False
    finally:
        state.close()


def _plain_connection(state: State):
    """The database's own connection, for arranging a pre-migration layout."""
    return state._conn


def test_the_upgrade_from_v27_still_converts_a_raw_token_and_does_it_once(tmp_path: Path):
    db = tmp_path / "state.db"
    seed = _reopen(db)
    raw = "ab" * 32  # a v27 row held the bearer itself
    malformed = "not-a-token"
    conn = _plain_connection(seed)
    with seed._write_lock:
        conn.execute("DELETE FROM ui_sessions")
        for token in (raw, malformed):
            conn.execute(
                "INSERT INTO ui_sessions(session_uuid, created_ms, last_seen_ms) VALUES(?, ?, ?)",
                (token, 1_700_000_000_000, 4_000_000_000_000),
            )
        # Put the database back before the step: v27 is the newest stamp.
        conn.execute("DELETE FROM schema_version WHERE version >= 28")
        conn.commit()
    assert seed.schema_version() == 27
    seed.close()

    upgraded = _reopen(db)
    try:
        assert upgraded.schema_version() >= 28
        # The raw token became its record key; the malformed row was dropped.
        assert _session_keys(upgraded) == [State.ui_session_token_id(raw)]
        assert upgraded.lookup_ui_session(raw) is not None
    finally:
        upgraded.close()

    for restart in range(1, 4):
        state = _reopen(db)
        try:
            assert _session_keys(state) == [State.ui_session_token_id(raw)], (
                f"restart {restart} after the upgrade hashed the record key again"
            )
            assert state.lookup_ui_session(raw) is not None
        finally:
            state.close()


def test_the_runner_skips_an_exactly_once_step_only_after_its_version(tmp_path: Path):
    """The guard itself, both ways: applied when crossing, skipped after."""
    state = _reopen(tmp_path / "state.db")
    try:
        calls: list[str] = []
        # A version no real step uses, so the crossing can write its stamp.
        probe = 9001
        cursor = state._conn.cursor()
        try:
            state._run_atomic_migration(
                cursor, target_version=probe, current_version=probe - 1,
                apply=lambda _c: calls.append("crossing"), exactly_once=True,
            )
            assert state.schema_version() == probe, "the crossing did not stamp its version"
            state._run_atomic_migration(
                cursor, target_version=probe, current_version=probe,
                apply=lambda _c: calls.append("at"), exactly_once=True,
            )
            state._run_atomic_migration(
                cursor, target_version=probe, current_version=probe + 2,
                apply=lambda _c: calls.append("past"), exactly_once=True,
            )
            # Read from the database when the caller does not pass a version.
            state._run_atomic_migration(
                cursor, target_version=probe,
                apply=lambda _c: calls.append("looked-up"), exactly_once=True,
            )
            # An ordinary step is still re-applied every time (backfills).
            state._run_atomic_migration(
                cursor, target_version=probe, current_version=probe + 2,
                apply=lambda _c: calls.append("ordinary"), exactly_once=False,
            )
        finally:
            cursor.close()
        assert calls == ["crossing", "ordinary"]
        assert 28 in State._EXACTLY_ONCE_MIGRATIONS
    finally:
        state.close()


def _dump(state: State) -> dict[str, list[tuple]]:
    """Every row of every ordinary table, in a stable order."""
    conn = state._conn
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    dump: dict[str, list[tuple]] = {}
    for table in tables:
        try:
            rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()  # noqa: S608 - names from sqlite_master
        except sqlite3.DatabaseError:
            # Full-text shadow tables cannot always be read directly; the
            # content tables they index are in the dump.
            continue
        dump[table] = sorted((tuple(row) for row in rows), key=repr)
    return dump


def _populate(state: State) -> None:
    """Rows in the tables migrations are known to rewrite, plus settings.

    This is a floor, not a census: a migration that rewrites a table left
    empty here is not exercised. The session table is the one with a history.
    """
    state.create_ui_session(user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/130", remote="127.0.0.1")
    state.create_ui_session(user_agent=None, remote=None)
    revoked = state.create_ui_session()["session_uuid"]
    state.revoke_ui_session(revoked)
    state.set_setting("download_folder", "somewhere")
    state.set_setting("sovereignty_preset", "just_works")
    conn = state._conn
    with state._write_lock:
        # No "insert if the columns exist" here. The first version of this
        # helper guarded its folder row on a column the table does not have,
        # so the row was never written and the check below ran on two tables
        # while claiming more (found by independent review). If the schema
        # moves, these statements fail and the helper is updated on purpose.
        #
        # A folder without a root id is what v2's boot-time backfill heals:
        # after the first re-open it has one and must keep it.
        conn.execute(
            "INSERT INTO folders(name, local_path, shared_with_json, created_ms, root_id)"
            " VALUES(?, ?, ?, ?, NULL)",
            ("rerun-probe", "probe-path", "[]", 1_700_000_000_000),
        )
        # A device whose legacy flag says revoked while its safety state does
        # not is what v21's boot-time backfill heals, once.
        conn.execute(
            "INSERT INTO self_mesh_devices(root_pub, device_pub, device_kind, revoked, added_ms, updated_ms)"
            " VALUES(?, ?, ?, 1, ?, ?)",
            (b"r" * 32, b"d" * 32, "desktop", 1_700_000_000_000, 1_700_000_000_000),
        )
        conn.commit()


# The tables _populate writes. The no-change check is a statement about these.
_POPULATED = ("folders", "self_mesh_devices", "settings", "ui_sessions")


def test_reopening_a_populated_database_changes_no_row(tmp_path: Path):
    db = tmp_path / "state.db"
    seed = _reopen(db)
    _populate(seed)
    seed.close()

    # The first re-open may legitimately heal rows (that is what the
    # backfills are for). From then on the database is at rest.
    settled = _reopen(db)
    before = _dump(settled)
    settled.close()
    for table in _POPULATED:
        assert before[table], f"{table} is empty: the check would say nothing about it"
    assert len(before) > 10
    # The first re-open did its healing, and only that: the folder has a root
    # id, the revoked device's safety state says so.
    probe = [row for row in before["folders"] if row[0] == "rerun-probe"]
    assert len(probe) == 1
    root_id = probe[0][4]  # folders: name, local_path, shared_with_json, created_ms, root_id, ...
    assert isinstance(root_id, str) and root_id, f"the folder was not given a root id: {probe}"
    assert any("revoked" in row for row in before["self_mesh_devices"]), (
        "the revoked device's safety state was not brought in line with its flag"
    )

    for reopen in range(1, 4):
        state = _reopen(db)
        try:
            after = _dump(state)
        finally:
            state.close()
        changed = sorted(table for table in before if after.get(table) != before[table])
        assert not changed, f"re-open {reopen} changed rows in: {changed}"
        assert sorted(after) == sorted(before)


def test_the_populated_dump_can_see_a_rewritten_session_key(tmp_path: Path):
    """The general check above is only worth having if it fails on the real defect."""
    db = tmp_path / "state.db"
    seed = _reopen(db)
    _populate(seed)
    before = _dump(seed)
    cursor = seed._conn.cursor()
    try:
        # What every boot used to do: apply v28 to already-migrated rows.
        seed._run_atomic_migration(
            cursor, target_version=28, current_version=30,
            apply=seed._migrate_v28_ui_session_token_hashes, exactly_once=False,
        )
    finally:
        cursor.close()
    after = _dump(seed)
    seed.close()
    assert after["ui_sessions"] != before["ui_sessions"]
    assert [table for table in before if after[table] != before[table]] == ["ui_sessions"]


@pytest.mark.parametrize("version", sorted(State._EXACTLY_ONCE_MIGRATIONS))
def test_every_exactly_once_step_is_a_real_step(version: int):
    assert hasattr(State, "_migrate"), "the runner moved; re-anchor this test"
    names = [name for name in dir(State) if name.startswith(f"_migrate_v{version}_")]
    assert len(names) == 1, f"v{version} is listed as exactly-once but has no single migration"
