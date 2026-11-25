"""`one-link recovery set-passphrase` / `remove-passphrase`: the migration the
explicit-migration refusal names.

Production shape throughout: SQLCipher on, the state database key in a local
key file (the OS keyring is patched out, never touched), a seeded install
with every DEK_PROTECTED_ARTIFACTS envelope and every KEY_PROTECTED_FIELDS
value present.  Every check reads through the daemon's own readers in the
mode the install is in.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import (
    capsule_store,
    identity,
    keychain,
    lockbox,
    master_seed,
    paths,
    recovery_api,
    state_encryption,
    update_transaction,
)
from one_link.key_material import KeyMaterialProtectionError
from one_link.path_pii import PathPIIEncryptor
from one_link.state import State
from tests.test_rotation_state_field_carry import (
    _undecryptable_fields,
    _write_wrapped_fields,
)

PASSPHRASE = "a long passphrase nobody else knows"
SET = "set_passphrase"
REMOVE = "remove_passphrase"


@pytest.fixture(autouse=True)
def _production_shaped_keys(monkeypatch):
    if not state_encryption._have_sqlcipher():
        pytest.skip("sqlcipher3 not installed")
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    # The local key file is the database key store; the real OS keyring is
    # never reached.
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)


class _Crash(Exception):
    pass


def _crash_at(point: str):
    def fault(reached: str) -> None:
        if reached == point:
            raise _Crash(point)

    return fault


def _install():
    """A converged seeded silent install holding every protected kind."""
    root = paths.data_dir()
    id_path = paths.key_path()
    seed, created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=id_path,
    )
    assert created
    identity.load_or_create(id_path)
    box = lockbox.acquire_lockbox(root)
    written: dict = {
        "capsule": capsule_store.load_or_create_capsule_master_seed(root, box),
        "update": update_transaction.acquire_update_state_authority(root / "updates", box),
        "tls": os.urandom(48),
    }
    (root / "peer_https").mkdir()
    (root / "peer_https" / "root_ca_key.pem").write_bytes(box.wrap(written["tls"]))
    state = State(root / "state.db")
    try:
        assert state.is_encrypted
        state.set_lockbox(box)
        state.set_path_pii_encryptor(PathPIIEncryptor(seed))
        written["fields"] = _write_wrapped_fields(state)
    finally:
        state.close()
    return root, id_path, seed, written


def _undecryptable_everything(monkeypatch, root, seed, written, *, passphrase):
    """Open everything as the daemon would in this mode; name what fails."""
    if passphrase:
        monkeypatch.setenv(lockbox.PASSPHRASE_ENV, passphrase)
    else:
        monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    try:
        box = lockbox.acquire_lockbox(root)
        failures = []
        try:
            if capsule_store.load_or_create_capsule_master_seed(root, box) != written["capsule"]:
                failures.append("capsule-master-key.bin")
        except capsule_store.CapsuleStoreError:
            failures.append("capsule-master-key.bin")
        try:
            if update_transaction.acquire_update_state_authority(
                root / "updates", box,
            ) != written["update"]:
                failures.append("update-authority.key.wrapped")
        except update_transaction.UpdateStateError:
            failures.append("update-authority.key.wrapped")
        try:
            if box.unwrap((root / "peer_https" / "root_ca_key.pem").read_bytes()) != written["tls"]:
                failures.append("root_ca_key.pem")
        except lockbox.LockBoxError:
            failures.append("root_ca_key.pem")
        state = State(root / "state.db")  # SQLCipher key from this mode's source
        try:
            state.set_lockbox(box)
            state.set_path_pii_encryptor(PathPIIEncryptor(seed))
            failures += _undecryptable_fields(state, written["fields"])
        finally:
            state.close()
        assert master_seed.inspect_derived_authority(
            root, identity_path=paths.key_path(), seed=seed,
        ) == {"identity": True, "data_root": True}
        return failures
    finally:
        monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)


def _no_migration_leftovers(root: Path) -> None:
    for name in (
        lockbox.MIGRATION_INTENT_FILENAME,
        lockbox.STAGED_ENVELOPE_FILENAME,
        lockbox.STAGED_SALT_FILENAME,
        lockbox.RETIRED_ENVELOPE_FILENAME,
        lockbox.RETIRED_SALT_FILENAME,
    ):
        assert not (root / name).exists(), name


def _migrate(kind: str, root: Path, passphrase: str = PASSPHRASE, **kwargs):
    fn = (
        recovery_api.set_data_key_passphrase
        if kind == SET
        else recovery_api.remove_data_key_passphrase
    )
    return fn(data_dir=root, passphrase=passphrase, **kwargs)


# ─── the round trip ──────────────────────────────────────────────────────────


def test_silent_to_passphrase_to_silent_keeps_everything_readable(monkeypatch):
    root, _id_path, seed, written = _install()
    phrase_seed = master_seed.load_seed(root)
    identity_before = paths.key_path().read_bytes()
    database_key = keychain._configured_passphrase_at(root)
    assert database_key and state_encryption.database_accepts_passphrase(
        root / "state.db", database_key,
    )
    assert _undecryptable_everything(monkeypatch, root, seed, written, passphrase=None) == []

    report = _migrate(SET, root)
    assert report["changed"] is True and report["mode"] == "passphrase"
    assert sorted(report["artifacts"]["carried"]) == [
        "capsule_master_key", "tls_root_authority", "update_state_authority",
    ]
    assert report["fields"]["group_sender_chains.chain_key"]["rekeyed"] == 1
    assert report["fields"]["self_mesh_roots.root_seed"]["rekeyed"] == 1
    assert report["database"] == "rekeyed"
    _no_migration_leftovers(root)
    # Passphrase mode: the passphrase is the SQLCipher key; the envelope's
    # seed slot keeps the paper phrase sufficient for bundle recovery.
    assert state_encryption.database_accepts_passphrase(root / "state.db", PASSPHRASE)
    assert not state_encryption.database_accepts_passphrase(root / "state.db", database_key)
    assert lockbox.recovery_envelope_matches_seed(root, seed) is True
    assert master_seed.load_seed(root) == phrase_seed
    assert paths.key_path().read_bytes() == identity_before
    assert _undecryptable_everything(
        monkeypatch, root, seed, written, passphrase=PASSPHRASE,
    ) == []
    # The silent key no longer opens anything: the install is on ONE key.
    silent = lockbox.LockBox(master_seed.derive_drk(seed))
    assert {a.name for a in lockbox.dek_artifacts_unopenable_by(root, silent)} == {
        "capsule_master_key", "tls_root_authority", "update_state_authority",
    }

    report = _migrate(REMOVE, root)
    assert report["changed"] is True and report["mode"] == "silent"
    assert report["database"] == "rekeyed"
    _no_migration_leftovers(root)
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    assert not (root / lockbox.SALT_FILENAME).exists()
    assert state_encryption.database_accepts_passphrase(root / "state.db", database_key)
    assert master_seed.load_seed(root) == phrase_seed
    assert _undecryptable_everything(monkeypatch, root, seed, written, passphrase=None) == []


def test_the_passphrase_may_come_from_the_environment_in_both_directions(monkeypatch):
    """A passphrase in the migrating process's environment says nothing about
    the mode the install is in; every proof is judged as the daemon of the
    relevant mode would judge it."""
    root, _id_path, seed, written = _install()
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    assert _migrate(SET, root)["changed"] is True
    assert _migrate(REMOVE, root)["changed"] is True
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert _undecryptable_everything(monkeypatch, root, seed, written, passphrase=None) == []


def test_each_direction_is_a_verified_no_op_when_already_there(monkeypatch):
    root, _id_path, seed, written = _install()
    assert _migrate(REMOVE, root) == {"changed": False, "mode": "silent"}
    _migrate(SET, root)
    assert _migrate(SET, root) == {"changed": False, "mode": "passphrase"}
    with pytest.raises(KeyMaterialProtectionError, match="does not open"):
        _migrate(SET, root, passphrase="not the passphrase")
    assert _undecryptable_everything(
        monkeypatch, root, seed, written, passphrase=PASSPHRASE,
    ) == []


# ─── a crash at every step boundary, then replay ─────────────────────────────


@pytest.mark.parametrize(
    "kind,point",
    [(k, p) for k, points in recovery_api.MIGRATION_FAULT_POINTS.items() for p in points],
)
def test_a_crash_at_every_step_boundary_replays_to_one_key(monkeypatch, kind, point):
    root, _id_path, seed, written = _install()
    if kind == REMOVE:
        _migrate(SET, root)
    with pytest.raises(_Crash):
        _migrate(kind, root, _fault=_crash_at(point))

    # The window between carrying and publishing is fail-closed: nothing may
    # use either key, and every refusal names the command that finishes it.
    command = lockbox.MIGRATION_COMMANDS[kind]
    with pytest.raises(KeyMaterialProtectionError, match=command):
        lockbox.acquire_lockbox(root)
    with pytest.raises(KeyMaterialProtectionError, match=command):
        master_seed.provision_seed_before_derived_authority(
            root, identity_path=paths.key_path(),
        )

    _migrate(kind, root)  # the replay
    _no_migration_leftovers(root)
    final = PASSPHRASE if kind == SET else None
    assert _undecryptable_everything(monkeypatch, root, seed, written, passphrase=final) == []


def test_replay_with_a_different_passphrase_refuses_and_publishes_nothing(monkeypatch):
    root, _id_path, seed, written = _install()
    with pytest.raises(_Crash):
        _migrate(SET, root, _fault=_crash_at("files_carried"))
    with pytest.raises(KeyMaterialProtectionError, match="does not open"):
        _migrate(SET, root, passphrase="a different passphrase")
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    _migrate(SET, root)
    assert _undecryptable_everything(
        monkeypatch, root, seed, written, passphrase=PASSPHRASE,
    ) == []


# ─── refusals ────────────────────────────────────────────────────────────────


def test_refuses_while_a_daemon_holds_the_instance_lock():
    from one_link.daemon import Daemon

    root, _id_path, _seed, _written = _install()
    daemon = object.__new__(Daemon)
    daemon._lock_file = None
    daemon._acquire_instance_lock()
    try:
        with pytest.raises(recovery_api.DataKeyMigrationError, match="stop One Link first"):
            _migrate(SET, root)
    finally:
        daemon._release_instance_lock()
    _no_migration_leftovers(root)
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()


def test_a_wrong_passphrase_on_remove_changes_nothing(monkeypatch):
    root, _id_path, seed, written = _install()
    _migrate(SET, root)
    envelope = (root / lockbox.DEK_ENVELOPE_FILENAME).read_bytes()
    with pytest.raises(KeyMaterialProtectionError, match="passphrase does not open"):
        _migrate(REMOVE, root, passphrase="wrong")
    _no_migration_leftovers(root)
    assert (root / lockbox.DEK_ENVELOPE_FILENAME).read_bytes() == envelope
    assert _undecryptable_everything(
        monkeypatch, root, seed, written, passphrase=PASSPHRASE,
    ) == []


def test_a_damaged_install_is_refused_before_anything_changes():
    root, _id_path, _seed, _written = _install()
    (root / capsule_store.CAPSULE_KEY_FILENAME).write_bytes(
        lockbox.LockBox(os.urandom(32)).wrap(os.urandom(32))
    )
    with pytest.raises(recovery_api.DataKeyMigrationError, match="capsule-master-key.bin"):
        _migrate(SET, root)
    _no_migration_leftovers(root)
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()


def test_an_unseeded_install_is_pointed_at_backup_init():
    root = paths.data_dir()
    lockbox.acquire_or_create_silent_drk(root)
    with pytest.raises(recovery_api.DataKeyMigrationError, match="one-link backup init"):
        _migrate(SET, root)


def test_a_backup_export_cannot_run_inside_an_unfinished_migration():
    from one_link import backup_bundle

    root, _id_path, seed, _written = _install()
    with pytest.raises(_Crash):
        _migrate(SET, root, _fault=_crash_at("fields_carried"))
    with pytest.raises(KeyMaterialProtectionError, match="one-link recovery set-passphrase"):
        backup_bundle.create_bundle(seed=seed, data_dir=root)


def test_no_recovery_can_be_staged_on_an_unfinished_migration():
    """Otherwise each would block the other forever: the recovery replay is
    refused by the migration journal, and the migration refuses while a
    recovery is pending."""
    root, _id_path, _seed, _written = _install()
    with pytest.raises(_Crash):
        _migrate(SET, root, _fault=_crash_at("staged"))
    with pytest.raises(recovery_api.RecoveryTransactionError, match="set-passphrase"):
        recovery_api.stage_seed_authority_replacement(
            data_dir=root, seed=os.urandom(32), allow_replace=True,
        )
    assert recovery_api.has_pending_recovery(root) is False
    _migrate(SET, root)


def test_the_refusal_names_the_command_that_now_exists(monkeypatch):
    """H1's explicit-migration refusal names the real command, and it works."""
    root, _id_path, seed, written = _install()
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    with pytest.raises(KeyMaterialProtectionError) as refused:
        master_seed.provision_seed_before_derived_authority(
            root, identity_path=paths.key_path(),
        )
    assert "explicit recovery migration is required" in str(refused.value)
    assert "one-link recovery set-passphrase" in str(refused.value)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    _migrate(SET, root)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    assert master_seed.provision_seed_before_derived_authority(
        root, identity_path=paths.key_path(),
    )[0] == seed
    assert _undecryptable_everything(
        monkeypatch, root, seed, written, passphrase=PASSPHRASE,
    ) == []


def test_seeded_legacy_passphrase_rows_get_their_envelope_byte_preserved(monkeypatch):
    """The one unconverged state set-passphrase repairs: a seeded install with
    legacy scrypt(passphrase, salt) rows and no envelope, which the bootstrap
    refuses.  Their key is kept; only its dual-slot envelope is published."""
    root = paths.data_dir()
    seed, _created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=paths.key_path(),
    )
    identity.load_or_create(paths.key_path())
    salt = lockbox.load_or_create_salt(root)
    legacy = lockbox.LockBox.from_passphrase(PASSPHRASE.encode(), salt)
    key = os.urandom(32)
    (root / capsule_store.CAPSULE_KEY_FILENAME).write_bytes(legacy.wrap(key))
    before = (root / capsule_store.CAPSULE_KEY_FILENAME).read_bytes()

    report = _migrate(SET, root)
    assert report == {"changed": True, "mode": "passphrase", "legacy_envelope": True}
    assert (root / capsule_store.CAPSULE_KEY_FILENAME).read_bytes() == before
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key
    assert master_seed.inspect_derived_authority(
        root, identity_path=paths.key_path(), seed=seed,
    ) == {"identity": True, "data_root": True}


# ─── the CLI ─────────────────────────────────────────────────────────────────


def test_cli_takes_the_passphrase_from_a_hidden_prompt_or_the_environment(monkeypatch):
    from click.testing import CliRunner

    from one_link.cli import cli

    root, _id_path, seed, written = _install()
    runner = CliRunner()
    as_argument = runner.invoke(cli, ["recovery", "set-passphrase", PASSPHRASE])
    assert as_argument.exit_code == 2  # no positional argument exists
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()

    mismatch = runner.invoke(
        cli, ["recovery", "set-passphrase"], input=f"{PASSPHRASE}\nsomething else\n",
    )
    assert mismatch.exit_code != 0
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()

    prompted = runner.invoke(
        cli, ["recovery", "set-passphrase"], input=f"{PASSPHRASE}\n{PASSPHRASE}\n",
    )
    assert prompted.exit_code == 0, prompted.output
    assert PASSPHRASE not in prompted.output
    assert "ONE_LINK_PASSPHRASE set" in prompted.output

    removed = runner.invoke(
        cli, ["recovery", "remove-passphrase"], env={lockbox.PASSPHRASE_ENV: PASSPHRASE},
    )
    assert removed.exit_code == 0, removed.output
    assert PASSPHRASE not in removed.output
    assert _undecryptable_everything(monkeypatch, root, seed, written, passphrase=None) == []
