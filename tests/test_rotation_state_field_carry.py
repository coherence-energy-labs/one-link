"""Identity rotation must not split an install across two data keys.

In silent mode the data key is ``derive_drk(seed)``, so rotating the seed
rotates the data key.  The rotation transaction carries every LockBox-wrapped
value it replaces the key under: whole-file envelopes and the State fields
registered in ``state.LOCKBOX_WRAPPED_FIELDS``.  These tests drive the real
rotation (stage on the live daemon, apply at the boot boundary, finalize after
State opens) and then read every registered field through a State opened the
way the next boot opens it.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import (
    identity,
    identity_rotation,
    lockbox,
    master_seed,
    mnemonic,
    paths,
    recovery_api,
)
from one_link.key_material import KeyMaterialPersistenceError
from one_link.state import KEY_PROTECTED_FIELDS, State

GROUP_ID = b"g" * 16
SENDER = b"s" * 32
TRANSFER_ID = "out:" + "ab" * 32 + ":0123456789ab"
CHUNK_HASH = "cd" * 32
PRIVATE_PATH = "C:/Users/someone/Documents/Confidential/Plan.pdf"


@pytest.fixture(autouse=True)
def _fast_scrypt(monkeypatch):
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)


def _install(tmp_path: Path, monkeypatch, *, passphrase: str | None):
    data = tmp_path / "data"
    config = tmp_path / "config"
    data.mkdir()
    config.mkdir()
    identity_path = config / "identity.key"
    monkeypatch.setattr(paths, "data_dir", lambda: data)
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    if passphrase is None:
        monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    else:
        monkeypatch.setenv(lockbox.PASSPHRASE_ENV, passphrase)
    seed, created = master_seed.provision_seed_before_derived_authority(
        data, identity_path=identity_path,
    )
    assert created
    identity.load_or_create(identity_path)  # the daemon's next bootstrap step
    assert master_seed.inspect_derived_authority(
        data, identity_path=identity_path, seed=seed,
    ) == {"identity": True, "data_root": True}
    return data, identity_path, seed


def _write_wrapped_fields(state: State) -> dict[str, bytes]:
    """Exercise every registered writer once; return the plaintexts."""
    chain_key = os.urandom(32)
    state.upsert_sender_chain(
        group_id=GROUP_ID, sender_pub=SENDER, direction="out",
        epoch=3, chain_key=chain_key, counter=7,
    )
    root_seed = os.urandom(32)
    root_pub = Ed25519PrivateKey.from_private_bytes(root_seed).public_key().public_bytes_raw()
    state.upsert_self_mesh_root(root_pub=root_pub, label="mesh", root_seed=root_seed)
    # Seed-keyed path-PII columns (audit M30): the durable intent a paused
    # transfer resumes from, and a lazy chunk source.
    state.upsert_transfer(
        id=TRANSFER_ID, direction="out", peer_fp="aa" * 32, kind="file",
        name="Plan.pdf", size=10, status="paused", progress_bytes=0,
        total_bytes=10, chunks_done=0, chunks_total=1,
        metadata={"path": PRIVATE_PATH, "next_retry_ms": 0},
    )
    state.record_chunk_source(
        CHUNK_HASH, path=PRIVATE_PATH, start=0, size=10, mtime_ms=1, file_size=10,
    )
    return {"chain_key": chain_key, "root_seed": root_seed, "root_pub": root_pub}


def _undecryptable_fields(state: State, written: dict[str, bytes]) -> list[str]:
    """Read every registered field the way the daemon does; name the ones that fail."""
    failures = []
    transfer = state.get_transfer(TRANSFER_ID)
    if transfer is None or transfer.metadata.get("path") != PRIVATE_PATH:
        failures.append("transfers.metadata_json.path")
    sources = state.get_chunk_sources(CHUNK_HASH)
    if [s["path"] for s in sources] != [PRIVATE_PATH]:
        failures.append("chunk_sources.path")
    try:
        chain = state.get_sender_chain(
            group_id=GROUP_ID, sender_pub=SENDER, direction="out", epoch=3,
        )
        if chain is None or chain["chain_key"] != written["chain_key"]:
            failures.append("group_sender_chains.chain_key")
    except lockbox.LockBoxError:
        failures.append("group_sender_chains.chain_key")
    try:
        root = state.get_self_mesh_root(written["root_pub"], include_seed=True)
        if root is None or root.get("root_seed") != written["root_seed"]:
            failures.append("self_mesh_roots.root_seed")
    except lockbox.LockBoxError:
        failures.append("self_mesh_roots.root_seed")
    return failures


def _next_boot_state(data: Path) -> State:
    """Open State and attach its keys exactly as Daemon.start does."""
    from one_link.path_pii import PathPIIEncryptor

    state = State(data / "state.db")
    state.set_lockbox(lockbox.acquire_lockbox(data))
    seed = master_seed.load_seed(data)
    if seed is not None:
        state.set_path_pii_encryptor(PathPIIEncryptor(seed))
    return state


def _rotate(data: Path, identity_path: Path, state: State, seed: bytes):
    result = identity_rotation.perform_local_rotation(
        data_dir=data,
        old_priv=master_seed.derive_identity_priv(seed),
        pinned_peer_fingerprints=["aa" * 32],
        state=state,
    )
    state.close()  # the live daemon exits; the next boot applies the stage
    return result


def _apply_at_boot(data: Path, identity_path: Path) -> State:
    recovery_api.complete_pending_recovery(data_dir=data, identity_path=identity_path)
    state = _next_boot_state(data)
    recovery_api.finalize_pending_rotation(
        data_dir=data, state=state, identity_path=identity_path,
    )
    return state


@pytest.mark.parametrize("passphrase", [None, "passphrase-mode control"], ids=["silent", "passphrase"])
def test_every_wrapped_state_field_decrypts_after_identity_rotation(
    tmp_path, monkeypatch, passphrase,
):
    data, identity_path, seed = _install(tmp_path, monkeypatch, passphrase=passphrase)
    state = _next_boot_state(data)
    written = _write_wrapped_fields(state)
    assert _undecryptable_fields(state, written) == []
    drk_before = (data / lockbox.DRK_FILENAME).read_bytes()

    result = _rotate(data, identity_path, state, seed)
    rotated = _apply_at_boot(data, identity_path)
    try:
        assert master_seed.load_seed(data) == mnemonic.decode(result.new_phrase)
        assert recovery_api.has_pending_recovery(data) is False
        if passphrase is None:
            # The silent data key really changed: the old seed's DRK is gone.
            assert (data / lockbox.DRK_FILENAME).read_bytes() != drk_before
        failures = _undecryptable_fields(rotated, written)
        assert not failures, f"undecryptable after rotation: {failures}"
    finally:
        rotated.close()


# ─── interruption: every crash point replays to one key ─────────────────────


def _silent_rotation_staged(tmp_path, monkeypatch):
    data, identity_path, seed = _install(tmp_path, monkeypatch, passphrase=None)
    state = _next_boot_state(data)
    written = _write_wrapped_fields(state)
    result = _rotate(data, identity_path, state, seed)
    return data, identity_path, seed, written, mnemonic.decode(result.new_phrase)


def _fields_under(data: Path, seed: bytes, written) -> list[str]:
    """Undecryptable fields when State is keyed for ``seed`` (silent mode)."""
    from one_link.path_pii import PathPIIEncryptor

    state = State(data / "state.db")
    try:
        state.set_lockbox(lockbox.LockBox(master_seed.derive_drk(seed)))
        state.set_path_pii_encryptor(PathPIIEncryptor(seed))
        return _undecryptable_fields(state, written)
    finally:
        state.close()


ALL_FIELDS = [
    "transfers.metadata_json.path",
    "chunk_sources.path",
    "group_sender_chains.chain_key",
    "self_mesh_roots.root_seed",
]


def test_crash_between_rekey_and_key_publish_replays_to_one_key(tmp_path, monkeypatch):
    data, identity_path, seed, written, new_seed = _silent_rotation_staged(
        tmp_path, monkeypatch,
    )

    def crash(*_args, **_kwargs):
        raise KeyMaterialPersistenceError("power lost before the new seed was published")

    real_store_seed = master_seed.store_seed
    monkeypatch.setattr(master_seed, "store_seed", crash)
    with pytest.raises(KeyMaterialPersistenceError):
        recovery_api.complete_pending_recovery(data_dir=data, identity_path=identity_path)
    # The re-key committed; no key was published.  Every field is already
    # under the new keys and none under the old ones: never both.
    assert master_seed.load_seed(data) == seed
    assert _fields_under(data, new_seed, written) == []
    assert _fields_under(data, seed, written) == ALL_FIELDS

    monkeypatch.setattr(master_seed, "store_seed", real_store_seed)
    rotated = _apply_at_boot(data, identity_path)
    try:
        assert master_seed.load_seed(data) == new_seed
        assert _undecryptable_fields(rotated, written) == []
    finally:
        rotated.close()


def test_crash_inside_the_rekey_transaction_rolls_back_and_replays(tmp_path, monkeypatch):
    data, identity_path, seed, written, new_seed = _silent_rotation_staged(
        tmp_path, monkeypatch,
    )
    from one_link import path_pii

    real_wrap = path_pii.PathPIIEncryptor.wrap
    calls = {"n": 0}

    def crash_on_second_reseal(self, value, *, aad=b""):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("process killed mid-transaction")
        return real_wrap(self, value, aad=aad)

    monkeypatch.setattr(path_pii.PathPIIEncryptor, "wrap", crash_on_second_reseal)
    with pytest.raises(OSError, match="mid-transaction"):
        recovery_api.complete_pending_recovery(data_dir=data, identity_path=identity_path)
    assert calls["n"] == 2  # the first path WAS re-sealed inside the transaction
    # SQLite rolled all of it back: everything still opens under the old keys.
    assert master_seed.load_seed(data) == seed
    assert _fields_under(data, seed, written) == []

    monkeypatch.setattr(path_pii.PathPIIEncryptor, "wrap", real_wrap)
    rotated = _apply_at_boot(data, identity_path)
    try:
        assert _undecryptable_fields(rotated, written) == []
    finally:
        rotated.close()


def test_replaying_a_completed_authority_install_is_a_no_op(tmp_path, monkeypatch):
    """A crash after every key was published but before the journal advanced
    re-enters the install: nothing re-keys twice, nothing is lost."""
    data, identity_path, seed, written, new_seed = _silent_rotation_staged(
        tmp_path, monkeypatch,
    )
    recovery_api.complete_pending_recovery(data_dir=data, identity_path=identity_path)
    counted: list[dict] = []
    real = State.rekey_protected_fields

    def recording(self, **kwargs):
        report = real(self, **kwargs)
        counted.append(report)
        return report

    monkeypatch.setattr(State, "rekey_protected_fields", recording)
    master_seed.install_seed_derived_authority(
        data, identity_path=identity_path, seed=new_seed, previous_seed=new_seed,
    )
    # Same seed and same DRK: no key changes, so State is not even opened.
    assert counted == []
    rotated = _next_boot_state(data)
    try:
        recovery_api.finalize_pending_rotation(
            data_dir=data, state=rotated, identity_path=identity_path,
        )
        assert _undecryptable_fields(rotated, written) == []
    finally:
        rotated.close()


def test_rekey_is_idempotent_and_never_touches_foreign_or_cleartext_values(tmp_path):
    from one_link.path_pii import PathPIIEncryptor

    old_seed, new_seed, foreign_seed = os.urandom(32), os.urandom(32), os.urandom(32)
    state = State(tmp_path / "state.db")
    try:
        state.set_lockbox(lockbox.LockBox(master_seed.derive_drk(foreign_seed)))
        state.set_path_pii_encryptor(PathPIIEncryptor(foreign_seed))
        state.upsert_sender_chain(
            group_id=b"f" * 16, sender_pub=SENDER, direction="in", epoch=1,
            chain_key=b"F" * 32, counter=0,
        )
        state.set_lockbox(None)
        state.set_path_pii_encryptor(None)
        state.upsert_sender_chain(  # legacy cleartext row
            group_id=b"c" * 16, sender_pub=SENDER, direction="in", epoch=1,
            chain_key=b"C" * 32, counter=0,
        )
        state.set_lockbox(lockbox.LockBox(master_seed.derive_drk(old_seed)))
        state.set_path_pii_encryptor(PathPIIEncryptor(old_seed))
        written = _write_wrapped_fields(state)
        before = {
            row[0]: bytes(row[1])
            for row in state._conn.execute(
                "SELECT group_id, chain_key FROM group_sender_chains"
            ).fetchall()
        }
        kwargs = dict(
            previous_data_key=master_seed.derive_drk(old_seed),
            target_data_key=master_seed.derive_drk(new_seed),
            previous_seed=old_seed,
            target_seed=new_seed,
        )
        first = state.rekey_protected_fields(**kwargs)
        assert first["group_sender_chains.chain_key"] == {"rekeyed": 1, "current": 0, "unopenable": 1}
        assert first["self_mesh_roots.root_seed"]["rekeyed"] == 1
        assert first["transfers.metadata_json.path"]["rekeyed"] == 1
        assert first["chunk_sources.path"]["rekeyed"] == 1
        second = state.rekey_protected_fields(**kwargs)
        assert all(counts["rekeyed"] == 0 for counts in second.values())
        assert second["group_sender_chains.chain_key"] == {"rekeyed": 0, "current": 1, "unopenable": 1}
        after = {
            row[0]: bytes(row[1])
            for row in state._conn.execute(
                "SELECT group_id, chain_key FROM group_sender_chains"
            ).fetchall()
        }
        assert after[b"f" * 16] == before[b"f" * 16]  # foreign: byte-identical
        assert after[b"c" * 16] == b"C" * 32  # cleartext: untouched
        state.set_lockbox(lockbox.LockBox(master_seed.derive_drk(new_seed)))
        state.set_path_pii_encryptor(PathPIIEncryptor(new_seed))
        assert _undecryptable_fields(state, written) == []
    finally:
        state.close()


# ─── the field registry is complete ─────────────────────────────────────────


@pytest.mark.parametrize("field", KEY_PROTECTED_FIELDS, ids=lambda field: field.name)
def test_registered_rekey_statements_target_only_the_declared_column(field):
    """The literal statements and field metadata must describe the same cells.

    Give each entry only its declared table and column, then exercise cursor
    paging, null exclusion and bound replacement/row-ID parameters against
    SQLite itself. A statement aimed at another registry entry cannot pass.
    """
    import sqlite3

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(f'CREATE TABLE "{field.table}" ("{field.column}", untouched)')
        connection.executemany(
            f'INSERT INTO "{field.table}" (rowid, "{field.column}", untouched) VALUES (?, ?, ?)',
            [(1, "old", "keep"), (2, None, "null row"), (3, "next", "also keep")],
        )
        assert connection.execute(field.rekey_select_sql, (1,)).fetchall() == [(3, "next")]
        replacement = "value'); DROP TABLE unrelated; --"
        connection.execute(field.rekey_update_sql, (replacement, 1))
        assert connection.execute(field.rekey_select_sql, (0,)).fetchall() == [
            (1, replacement), (3, "next"),
        ]
        assert connection.execute(
            f'SELECT rowid, untouched FROM "{field.table}" ORDER BY rowid'
        ).fetchall() == [(1, "keep"), (2, "null row"), (3, "also keep")]
        connection.executemany(
            f'INSERT INTO "{field.table}" (rowid, "{field.column}") VALUES (?, ?)',
            [(rowid, "paged") for rowid in range(4, 604)],
        )
        first_page = connection.execute(field.rekey_select_sql, (0,)).fetchall()
        assert len(first_page) == 512
        assert first_page[0] == (1, replacement)
        assert first_page[-1] == (513, "paged")
        assert connection.execute(field.rekey_select_sql, (513,)).fetchall() == [
            (rowid, "paged") for rowid in range(514, 604)
        ]
    finally:
        connection.close()


_PRIMITIVES = {"_wrap_path", "_unwrap_path", "maybe_wrap", "maybe_unwrap"}


def _state_seal_calls() -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """(primitive calls outside the two registry helpers, _seal/_open calls
    whose field argument is not a registered constant)."""
    import ast

    from one_link import state as state_module

    tree = ast.parse(Path(state_module.__file__).read_text(encoding="utf-8"))
    registered = {
        name for name, value in vars(state_module).items()
        if isinstance(value, state_module.KeyProtectedField)
    }
    stray, unregistered = [], []

    def visit(node, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            name = owner
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name
            if isinstance(child, ast.Call):
                func = child.func
                called = (
                    func.attr if isinstance(func, ast.Attribute)
                    else func.id if isinstance(func, ast.Name) else ""
                )
                receiver = ast.unparse(func.value) if isinstance(func, ast.Attribute) else ""
                primitive = called in _PRIMITIVES or (
                    called in {"wrap", "unwrap"}
                    and receiver in {"self._lockbox", "self._path_pii"}
                )
                if primitive and owner not in {
                    "_seal_field", "_open_field", "_wrap_path", "_unwrap_path",
                }:
                    stray.append((called, child.lineno))
                if called in {"_seal_field", "_open_field"}:
                    first = child.args[0] if child.args else None
                    if not (isinstance(first, ast.Name) and first.id in registered):
                        if owner != "rekey_protected_fields":
                            unregistered.append((called, child.lineno))
            visit(child, name)

    visit(tree, "<module>")
    return stray, unregistered


# Well-formed statements for constructing probe entries: the tests below are
# about which identifiers and families a registry entry accepts.
_PROBE_SELECT = (
    "SELECT rowid, path FROM transfers WHERE rowid > ? AND path IS NOT NULL ORDER BY rowid LIMIT 512"
)
_PROBE_UPDATE = "UPDATE OR REPLACE transfers SET path = ? WHERE rowid = ?"


@pytest.mark.parametrize(
    "table,column",
    [
        ("transfers; DROP TABLE transfers", "path"),
        ("transfers", "path = path --"),
        ('"transfers"', "path"),
        ("transfers", "metadata_json, rowid"),
        ("Transfers", "path"),
        ("transfers", ""),
        ("tränsfers", "path"),
        ("1transfers", "path"),
    ],
)
def test_a_registry_entry_admits_only_plain_sql_identifiers(table, column):
    """A registry entry names its cells with plain identifiers; nothing else is accepted."""
    from one_link import state as state_module

    with pytest.raises(ValueError, match="not a plain SQL identifier"):
        state_module.KeyProtectedField(
            "probe", table, column, state_module.FIELD_FAMILY_DATA_KEY, label="probe",
            rekey_select_sql=_PROBE_SELECT, rekey_update_sql=_PROBE_UPDATE,
        )


def test_a_registry_entry_refuses_an_unknown_key_family():
    from one_link import state as state_module

    with pytest.raises(ValueError, match="unknown key family"):
        state_module.KeyProtectedField(
            "probe", "transfers", "path", "plaintext", label="probe",
            rekey_select_sql=_PROBE_SELECT, rekey_update_sql=_PROBE_UPDATE,
        )
    # The same arguments with a known family are accepted: the refusals above
    # are about the identifier and the family, not about the probe itself.
    accepted = state_module.KeyProtectedField(
        "probe", "transfers", "path", state_module.FIELD_FAMILY_PATH_PII, label="probe",
        rekey_select_sql=_PROBE_SELECT, rekey_update_sql=_PROBE_UPDATE,
    )
    assert accepted.table == "transfers"
    for field in state_module.KEY_PROTECTED_FIELDS:
        assert field.table.isidentifier() and field.column.isidentifier()


def test_every_state_seal_goes_through_the_registry():
    stray, unregistered = _state_seal_calls()
    assert stray == [], f"key-protected values sealed/opened outside the registry: {stray}"
    assert unregistered == [], f"seal/open of an unregistered field: {unregistered}"


def test_the_static_census_can_fail(monkeypatch, tmp_path):
    """Point the census at a copy of state.py with one bypassing writer."""
    from one_link import state as state_module

    source = Path(state_module.__file__).read_text(encoding="utf-8")
    planted = source + (
        "\n\nclass _Planted:\n"
        "    def leak(self, value):\n"
        "        return self._lockbox.wrap(value)\n"
        "    def unregistered(self, value):\n"
        "        return self._seal_field(SOME_OTHER_FIELD, value)\n"
    )
    copy = tmp_path / "state.py"
    copy.write_text(planted, encoding="utf-8")
    monkeypatch.setattr(state_module, "__file__", str(copy))
    stray, unregistered = _state_seal_calls()
    assert [name for name, _line in stray] == ["wrap"]
    assert [name for name, _line in unregistered] == ["_seal_field"]


def test_real_writers_leave_key_protected_values_only_in_registered_fields(tmp_path):
    """Run every registered writer, then census every cell of every table:
    a LockBox envelope the install key opens, or a path-PII ciphertext, may
    only appear in a registered (table, column[, json member])."""
    import json

    from one_link import state as state_module
    from one_link.path_pii import PATH_PII_MARKER, PathPIIEncryptor

    seed = os.urandom(32)
    box = lockbox.LockBox(master_seed.derive_drk(seed))
    state = State(tmp_path / "state.db")
    try:
        state.set_lockbox(box)
        state.set_path_pii_encryptor(PathPIIEncryptor(seed))
        _write_wrapped_fields(state)
        batch_path = PRIVATE_PATH + ".batch"
        assert state.record_chunk_sources_for_file(
            path=batch_path, file_size=10, mtime_ms=1,
            chunks=[{"hash": "ef" * 32, "start": 0, "end": 10, "size": 10}],
        ) == 1
        state.record_file_index_cache(
            path=PRIVATE_PATH, size=10, mtime_ns=1, ctime_ns=1, blob_hash="ab" * 32,
            index_kind="fixed", chunks=[{"index": 0, "start": 0, "end": 10, "hash": "ef" * 32}],
        )
        registered = {
            (f.table, f.column, f.json_key) for f in state_module.KEY_PROTECTED_FIELDS
        }
        observed: set[tuple[str, str, str]] = set()
        tables = [
            row[0] for row in state._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        ]
        for table in tables:
            columns = [row[1] for row in state._conn.execute(f"PRAGMA table_info({table})")]
            for column in columns:
                for (value,) in state._conn.execute(f"SELECT {column} FROM {table}"):
                    if isinstance(value, bytes):
                        if lockbox.is_wrapped(value):
                            try:
                                box.unwrap(value)
                            except lockbox.LockBoxError:
                                continue
                            observed.add((table, column, ""))
                    elif isinstance(value, str) and PATH_PII_MARKER in value:
                        if value.startswith(PATH_PII_MARKER):
                            observed.add((table, column, ""))
                            continue
                        document = json.loads(value)
                        for key, member in document.items():
                            if isinstance(member, str) and member.startswith(PATH_PII_MARKER):
                                observed.add((table, column, key))
        assert observed - registered == set(), observed - registered
        assert observed == registered, f"registered but never produced: {registered - observed}"
    finally:
        state.close()


def test_embedded_dek_artifacts_name_their_carrier():
    import importlib

    by_name = {a.name: a for a in lockbox.DEK_PROTECTED_ARTIFACTS}
    for artifact in lockbox.DEK_PROTECTED_ARTIFACTS:
        if artifact.protection != lockbox.PROTECTION_EMBEDDED:
            continue
        assert artifact.carried_by, artifact.name
        if ":" in artifact.carried_by:
            module, function = artifact.carried_by.split(":")
            assert callable(getattr(importlib.import_module(module), function))
        else:
            assert by_name[artifact.carried_by].carried_by.count(":") == 1


# ─── a bundle-restored state.db is already the target's ─────────────────────


def test_encrypted_bundle_restore_over_another_identity_completes_and_opens(
    tmp_path, monkeypatch,
):
    """Production shape: SQLCipher on, the bundle's database key sealed to the
    bundle seed, restored over an install that has a different seed and its
    own state.db.  The restored database must not be opened before that seed
    is stored (its key cannot be unsealed yet), and every sealed field in it
    must open under the converged keys when the daemon opens State."""
    from one_link import backup_bundle, keychain, state_encryption
    from one_link.path_pii import PathPIIEncryptor

    if not state_encryption._have_sqlcipher():
        pytest.skip("sqlcipher3 not installed")
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)

    def _home(name: str) -> tuple[Path, Path]:
        home = (tmp_path / name).resolve()
        monkeypatch.setenv("ONE_LINK_HOME", str(home))
        data = home / "data"
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity_path = home / "config" / "identity.key"
        monkeypatch.setattr(paths, "data_dir", lambda: data)
        monkeypatch.setattr(paths, "key_path", lambda: identity_path)
        return data, identity_path

    source, source_identity = _home("source")
    source_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        source, identity_path=source_identity, seed=source_seed,
    )
    state = _next_boot_state(source)
    try:
        written = _write_wrapped_fields(state)
        assert state.is_encrypted
    finally:
        state.close()
    # The bundle is restored on ANOTHER machine: its master.seed and DRK
    # members are DPAPI-bound to the source and cannot be opened here.  Only
    # the phrase can produce the seed, and it is stored by the transaction.
    for machine_bound in (master_seed.SEED_FILENAME, lockbox.DRK_FILENAME):
        (source / machine_bound).write_bytes(os.urandom(64))
    bundle = backup_bundle.create_bundle(seed=source_seed, data_dir=source)

    target, target_identity = _home("target")
    master_seed.install_seed_derived_authority(
        target, identity_path=target_identity, seed=os.urandom(32),
    )
    _next_boot_state(target).close()  # the target's own encrypted state.db
    recovery_api.restore_from_bundle(
        data_dir=target,
        phrase=mnemonic.encode(source_seed),
        bundle_bytes=bundle,
        delete_identity_files=True,
        overwrite=True,
    )
    completed = recovery_api.complete_pending_recovery(
        data_dir=target, identity_path=target_identity,
    )
    assert completed["completed"] is True
    assert master_seed.load_seed(target) == source_seed
    restored = State(target / "state.db")
    try:
        assert restored.is_encrypted
        restored.set_lockbox(lockbox.acquire_lockbox(target))
        restored.set_path_pii_encryptor(PathPIIEncryptor(source_seed))
        failures = _undecryptable_fields(restored, written)
        assert not failures, f"undecryptable after restore: {failures}"
    finally:
        restored.close()
