"""No code path may publish a new data-key authority while an existing one
protects data, and "data protected by the current key" comes from ONE registry.

H1: an install with no master seed whose data key is its silent DRK must
refuse ``ONE_LINK_PASSPHRASE`` instead of switching to scrypt(passphrase), and
the mirror image (a legacy passphrase install booted without it) must refuse
to mint a silent DRK.

M2: the bootstrap/backup/acquire envelope mints consult
``lockbox.DEK_PROTECTED_ARTIFACTS``, not a hand-kept list of ``state.db``
names, so the capsule key, the TLS root authority and the update authority
count as existing data.  The registry is held complete by a static census of
every LockBox wrap site in the package and a dynamic census of what the real
writers put on disk.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from one_link import capsule_store, lockbox, master_seed
from one_link.key_material import KeyMaterialProtectionError

SRC = Path(lockbox.__file__).resolve().parent
MIGRATION = "explicit recovery migration"


@pytest.fixture(autouse=True)
def _fast_scrypt(monkeypatch):
    # Format v1 fixes the production parameters; only this process's work
    # factor is reduced so the authority semantics stay fast to exercise.
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)


def _authority_files(root: Path) -> dict[str, bool]:
    return {
        name: (root / name).exists()
        for name in (
            lockbox.DRK_FILENAME,
            lockbox.SALT_FILENAME,
            lockbox.DEK_ENVELOPE_FILENAME,
            master_seed.SEED_FILENAME,
        )
    }


def _seeded_silent_install(root: Path) -> bytes:
    seed, created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=root.parent / "identity.key",
    )
    assert seed is not None and created
    return seed


def _plant(root: Path, artifact: lockbox.DekProtectedArtifact, box: lockbox.LockBox) -> bytes:
    path = artifact.path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        box.wrap(os.urandom(32))
        if artifact.protection in lockbox.ENVELOPE_PROTECTIONS
        else b"existing application rows"
    )
    path.write_bytes(payload)
    return payload


# ─── H1: unseeded installs keep the key that already protects them ───────────


def test_passphrase_on_unseeded_silent_install_refuses_and_keeps_rows(
    tmp_path, monkeypatch,
):
    root = tmp_path / "data"
    lockbox.acquire_or_create_silent_drk(root)  # legacy random DRK, no seed
    (root / "state.db").write_bytes(b"legacy rows")
    row = lockbox.acquire_lockbox(root).wrap(b"row wrapped under the silent DRK")
    before = _authority_files(root)

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "a passphrase set later")
    # The bootstrap still classifies this as a legacy install ...
    assert master_seed.provision_seed_before_derived_authority(
        root, identity_path=tmp_path / "identity.key",
    ) == (None, False)
    # ... and the key-minting step itself refuses to replace the DRK, naming
    # the commands that perform the migration on an unseeded install.
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION) as refused:
        lockbox.acquire_lockbox(root)
    assert "`one-link backup init`" in str(refused.value)
    assert "`one-link recovery set-passphrase`" in str(refused.value)
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        lockbox.lockbox_from_env(root)
    assert _authority_files(root) == before
    assert not (root / lockbox.SALT_FILENAME).exists()

    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert lockbox.acquire_lockbox(root).unwrap(row) == b"row wrapped under the silent DRK"


def test_unseeded_silent_drk_is_issuance_evidence_even_without_rows(
    tmp_path, monkeypatch,
):
    """An unseeded DRK exists only because a silent LockBox was handed out.
    Allowing a salt next to it would create two keys with no envelope to
    arbitrate between them: the next silent boot writes under the DRK and the
    next passphrase boot cannot read it (H1 in two steps)."""
    root = tmp_path / "data"
    lockbox.acquire_lockbox(root)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "no rows written yet")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        lockbox.acquire_lockbox(root)
    assert not (root / lockbox.SALT_FILENAME).exists()


def test_unsetting_passphrase_on_unseeded_passphrase_install_refuses(
    tmp_path, monkeypatch,
):
    root = tmp_path / "data"
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "legacy direct scrypt")
    row = lockbox.acquire_lockbox(root).wrap(b"row under the passphrase key")
    assert (root / lockbox.SALT_FILENAME).exists()

    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    with pytest.raises(KeyMaterialProtectionError, match="ONE_LINK_PASSPHRASE"):
        lockbox.acquire_lockbox(root)
    with pytest.raises(KeyMaterialProtectionError, match="ONE_LINK_PASSPHRASE"):
        lockbox.acquire_or_create_silent_drk(root)
    assert not (root / lockbox.DRK_FILENAME).exists()

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "legacy direct scrypt")
    assert lockbox.acquire_lockbox(root).unwrap(row) == b"row under the passphrase key"


def test_split_legacy_install_mints_nothing_in_either_mode(tmp_path, monkeypatch):
    """An install the old swap already split holds rows under both keys.
    Neither boot may publish a third authority; each keeps opening its own."""
    root = tmp_path / "data"
    silent_row = lockbox.acquire_lockbox(root).wrap(b"silent era")
    salt = lockbox.load_or_create_salt(root)
    passphrase_row = lockbox.LockBox.from_passphrase(b"split", salt).wrap(b"passphrase era")
    before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}

    assert lockbox.acquire_lockbox(root).unwrap(silent_row) == b"silent era"
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "split")
    assert lockbox.acquire_lockbox(root).unwrap(passphrase_row) == b"passphrase era"
    after = {
        p.name: p.read_bytes()
        for p in root.iterdir()
        if p.is_file() and p.name != lockbox.DEK_ENVELOPE_LOCK_FILENAME
    }
    before.pop(lockbox.DEK_ENVELOPE_LOCK_FILENAME, None)
    assert after == before


# ─── M2: the registry decides what "existing data" means ─────────────────────


@pytest.mark.parametrize(
    "artifact",
    [a for a in lockbox.DEK_PROTECTED_ARTIFACTS if not a.regenerable],
    ids=lambda a: a.name,
)
def test_bootstrap_refuses_passphrase_over_every_registered_artifact(
    tmp_path, monkeypatch, artifact,
):
    root = tmp_path / "data"
    seed = _seeded_silent_install(root)
    silent = lockbox.acquire_lockbox(root)
    payload = _plant(root, artifact, silent)
    assert not (root / "state.db").exists() or artifact.relpath.startswith("state.db")

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "must not orphan the silent data")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION) as refused:
        master_seed.provision_seed_before_derived_authority(
            root, identity_path=root.parent / "identity.key",
        )
    assert artifact.relpath in str(refused.value)
    assert not (root / lockbox.SALT_FILENAME).exists()
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    assert artifact.path(root).read_bytes() == payload

    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    if artifact.protection in lockbox.ENVELOPE_PROTECTIONS:
        lockbox.acquire_lockbox(root).unwrap(payload)
    assert master_seed.inspect_derived_authority(
        root, identity_path=root.parent / "identity.key", seed=seed,
    )["data_root"] is True


def test_probe_arm_b_capsule_key_without_state_db_is_existing_data(
    tmp_path, monkeypatch,
):
    """The reviewer's witness, arm B, as a regression test."""
    root = tmp_path / "data"
    _seeded_silent_install(root)
    silent = lockbox.acquire_lockbox(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, silent)
    assert not (root / "state.db").exists()

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "probe passphrase")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION) as refused:
        master_seed.provision_seed_before_derived_authority(
            root, identity_path=root.parent / "identity.key",
        )
    # A seeded install is pointed straight at the command that migrates it.
    assert "`one-link recovery set-passphrase`" in str(refused.value)
    assert "backup init" not in str(refused.value)
    # The library entry point refuses the same mint, not only the bootstrap.
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        lockbox.acquire_lockbox(root)
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key


def test_a_missing_seeded_drk_still_protects_its_data(tmp_path, monkeypatch):
    """A seeded install re-derives a deleted DRK on its next silent boot, so
    the data under it is still the install's data: no passphrase mint."""
    root = tmp_path / "data"
    _seeded_silent_install(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, lockbox.acquire_lockbox(root))
    (root / lockbox.DRK_FILENAME).unlink()
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "after the DRK file was lost")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        lockbox.acquire_lockbox(root)
    assert not (root / lockbox.SALT_FILENAME).exists()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key


def test_backup_export_with_passphrase_cannot_swap_a_silent_install(
    tmp_path, monkeypatch,
):
    """``backup export`` runs offline; with the variable set in that shell it
    used to publish a scrypt envelope that every later boot (silent too, via
    the seed slot) would treat as the data key."""
    from one_link import backup_bundle

    root = tmp_path / "data"
    seed = _seeded_silent_install(root)
    silent = lockbox.acquire_lockbox(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, silent)
    (root / "state.db").write_bytes(b"silent rows")

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "set in the exporting shell")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        backup_bundle.create_bundle(seed=seed, data_dir=root)
    assert not (root / lockbox.SALT_FILENAME).exists()
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key
    backup_bundle.create_bundle(seed=seed, data_dir=root)


def test_legacy_passphrase_rows_still_migrate_byte_preserving(tmp_path, monkeypatch):
    """Positive control for the witness: a pre-existing salt whose scrypt key
    opens the envelope artifacts is the legacy data key, so the dual-wrap
    migration proceeds and nothing is rewritten."""
    root = tmp_path / "data"
    passphrase = "legacy passphrase"
    seed = _seeded_silent_install(root)
    salt = lockbox.load_or_create_salt(root)
    legacy = lockbox.LockBox.from_passphrase(passphrase.encode(), salt)
    capsule_path = root / capsule_store.CAPSULE_KEY_FILENAME
    capsule_path.write_bytes(legacy.wrap(b"k" * 32))
    original = capsule_path.read_bytes()

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, passphrase)
    migrated = lockbox.acquire_lockbox(root)
    assert migrated.unwrap(original) == b"k" * 32
    assert lockbox.recovery_envelope_matches_seed(root, seed) is True
    assert capsule_path.read_bytes() == original


def test_interrupted_bootstrap_salt_over_silent_rows_is_refused(tmp_path, monkeypatch):
    """A salt left by an interrupted passphrase bootstrap, followed by silent
    boots that wrote data, is indistinguishable from a legacy passphrase salt
    by file names.  The whole-file witness proves which key protects the data."""
    root = tmp_path / "data"
    _seeded_silent_install(root)
    lockbox.load_or_create_salt(root)
    silent = lockbox.acquire_lockbox(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, silent)

    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "resumed bootstrap")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION) as refused:
        lockbox.acquire_lockbox(root)
    assert capsule_store.CAPSULE_KEY_FILENAME in str(refused.value)
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key


def test_fresh_seeded_passphrase_install_still_bootstraps(tmp_path, monkeypatch):
    root = tmp_path / "data"
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "fresh install")
    seed, created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=tmp_path / "identity.key",
    )
    assert created
    assert lockbox.recovery_envelope_matches_seed(root, seed) is True


def test_recovery_and_seed_minting_count_every_registered_artifact(tmp_path):
    from one_link import recovery_api

    root = tmp_path / "data"
    root.mkdir()
    box = lockbox.LockBox(os.urandom(32))
    for artifact in lockbox.DEK_PROTECTED_ARTIFACTS:
        if artifact.regenerable:
            continue
        _plant(root, artifact, box)
        evidence = recovery_api.restore_artifact_evidence(
            root, identity_path=tmp_path / "identity.key",
        )
        assert evidence[f"{artifact.name}_artifact"] == 1
        with pytest.raises(Exception, match="refusing to mint an unrelated recovery seed"):
            master_seed.load_or_create_seed(root, identity_path=tmp_path / "identity.key")
        artifact.path(root).unlink()
    assert not any(
        recovery_api.restore_artifact_evidence(
            root, identity_path=tmp_path / "identity.key",
        ).values()
    )


# ─── registry completeness ───────────────────────────────────────────────────


def _wrap_lines(source: str) -> list[int]:
    """Line numbers of every call in ``source`` that produces LockBox ciphertext.

    A wrap is a ``.wrap(...)``/``.maybe_wrap(...)`` call on an expression that
    names a LockBox (``lockbox``, ``lb``, ``*lockbox*`` such as
    ``self._lockbox`` or ``acquire_lockbox(base)``), or a call of the
    ``maybe_wrap`` helper under any import alias.
    """
    tree = ast.parse(source)
    helper_aliases = {"maybe_wrap"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "one_link.lockbox":
            for alias in node.names:
                if alias.name == "maybe_wrap":
                    helper_aliases.add(alias.asname or alias.name)
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in helper_aliases:
            lines.append(node.lineno)
        elif isinstance(func, ast.Attribute) and func.attr in {"wrap", "maybe_wrap"}:
            receiver = ast.unparse(func.value).lower()
            if "lockbox" in receiver or receiver == "lb":
                lines.append(node.lineno)
    return sorted(lines)


def _wrap_sites() -> dict[str, list[int]]:
    sites: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        module = "one_link." + ".".join(path.relative_to(SRC).with_suffix("").parts)
        lines = _wrap_lines(path.read_text(encoding="utf-8"))
        if lines:
            sites[module] = lines
    return sites


def test_every_lockbox_wrap_site_writes_a_registered_artifact():
    sites = _wrap_sites()
    writers = {artifact.writer for artifact in lockbox.DEK_PROTECTED_ARTIFACTS}
    unregistered = {
        module: lines
        for module, lines in sites.items()
        if module not in writers and module != "one_link.lockbox"
    }
    assert unregistered == {}, (
        "these modules produce LockBox ciphertext but persist no artifact in "
        "lockbox.DEK_PROTECTED_ARTIFACTS; register what they write so a key "
        f"mint can see it: {unregistered}"
    )
    # No stale entries: each registered writer still wraps something.
    assert writers <= set(sites), writers - set(sites)


def test_the_census_detector_sees_every_recognised_form_and_nothing_else():
    """The census must be able to fail: each wrap form in use in the package
    is detected, and an unrelated ``wrap`` is not."""
    sample = (
        "from one_link.lockbox import maybe_wrap as _w\n"   # 1
        "def a(lockbox, lb, self, p):\n"                    # 2
        "    lockbox.wrap(b'x')\n"                          # 3
        "    lb.wrap(b'x')\n"                               # 4
        "    self._lockbox.wrap(b'x')\n"                    # 5
        "    acquire_lockbox(p).wrap(b'x')\n"               # 6
        "    _w(b'x', lb)\n"                                # 7
        "    textwrap.wrap('not a lockbox')\n"              # 8
        "    self.label.wrap('not a lockbox')\n"            # 9
    )
    assert _wrap_lines(sample) == [3, 4, 5, 6, 7]
    # And it finds the package's real wrap sites, so an empty census cannot
    # pass the completeness test vacuously.
    assert {"one_link.capsule_store", "one_link.state"} <= set(_wrap_sites())


def test_registry_paths_are_the_writers_own_constants():
    from one_link import peer_https, server, state, update_helper, update_transaction

    expected = {
        "state_db": state.DB_FILE,
        "state_wal": state.DB_FILE + "-wal",
        "state_shm": state.DB_FILE + "-shm",
        "capsule_master_key": capsule_store.CAPSULE_KEY_FILENAME,
        "tls_root_authority": f"{peer_https.HTTPS_DIR}/{peer_https.ROOT_CA_KEY_FILE}",
        "update_state_authority": (
            f"{update_helper.HELPER_STATE_DIRECTORY}/{update_transaction.AUTHORITY_FILENAME}"
        ),
        "ui_token": server.TOKEN_FILE,
    }
    assert {a.name: a.relpath for a in lockbox.DEK_PROTECTED_ARTIFACTS} == expected
    names = [a.name for a in lockbox.DEK_PROTECTED_ARTIFACTS]
    assert len(names) == len(set(names))


def test_real_writers_land_only_in_registered_paths(tmp_path):
    """Run every writer against one data root, then census the disk: each file
    whose bytes are a LockBox envelope the install key opens must be a
    registered envelope artifact, and the registry must see each one."""
    from one_link import peer_https, update_helper, update_transaction
    from one_link.state import State

    root = tmp_path / "data"
    root.mkdir()
    box = lockbox.acquire_lockbox(root)
    capsule_store.load_or_create_capsule_master_seed(root, box)
    update_transaction.acquire_update_state_authority(
        root / update_helper.HELPER_STATE_DIRECTORY, box,
    )
    peer_https.ensure_cert(root, short_id="census")
    state = State(db_path=root / "state.db")
    try:
        state.set_lockbox(box)
    finally:
        state.close()

    registered = {a.relpath: a for a in lockbox.DEK_PROTECTED_ARTIFACTS}
    opened_by_install_key = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        blob = path.read_bytes()
        if lockbox.is_wrapped(blob):
            try:
                box.unwrap(blob)
            except lockbox.LockBoxError:
                continue
            opened_by_install_key.append(rel)
            assert rel in registered, f"unregistered DEK envelope on disk: {rel}"
            assert registered[rel].protection in lockbox.ENVELOPE_PROTECTIONS
    assert sorted(opened_by_install_key) == sorted(
        a.relpath for a in lockbox.DEK_PROTECTED_ARTIFACTS
        if a.protection in lockbox.ENVELOPE_PROTECTIONS
    )
    present = {a.name for a in lockbox.present_dek_protected_artifacts(root)}
    assert {"capsule_master_key", "tls_root_authority", "update_state_authority", "state_db"} <= present


# ─── a confirmed key replacement carries what the old key protected ──────────

_ENVELOPES = [a for a in lockbox.DEK_PROTECTED_ARTIFACTS if a.protection in lockbox.ENVELOPE_PROTECTIONS]


def _plant_envelopes(root: Path, box: lockbox.LockBox) -> dict[str, bytes]:
    plaintexts = {}
    for artifact in _ENVELOPES:
        plaintext = os.urandom(32)
        path = artifact.path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(box.wrap(plaintext))
        plaintexts[artifact.name] = plaintext
    return plaintexts


def test_silent_seed_replacement_carries_every_envelope_artifact(tmp_path):
    """Identity rotation and phrase restore install derive_drk(new seed) as the
    silent data key.  Measured before this change: the capsule key no longer
    opened afterwards.  Every registered envelope must survive the switch."""
    root = tmp_path / "data"
    ident = tmp_path / "identity.key"
    seed = _seeded_silent_install(root)
    plaintexts = _plant_envelopes(root, lockbox.acquire_lockbox(root))

    master_seed.install_seed_derived_authority(
        root, identity_path=ident, seed=os.urandom(32), previous_seed=seed,
    )

    converged = lockbox.acquire_lockbox(root)
    for artifact in _ENVELOPES:
        assert converged.unwrap(artifact.path(root).read_bytes()) == plaintexts[artifact.name]
    assert lockbox.dek_artifacts_unopenable_by(root, converged) == ()
    assert not (root / lockbox.RETIRED_ARTIFACTS_DIRNAME).exists()


def test_interrupted_replacement_replays_without_losing_an_artifact(tmp_path, monkeypatch):
    """Crash after the envelopes were re-wrapped but before the old DRK was
    replaced: both keys still exist, and the replay must converge."""
    from one_link.key_material import KeyMaterialPersistenceError

    root = tmp_path / "data"
    ident = tmp_path / "identity.key"
    seed = _seeded_silent_install(root)
    plaintexts = _plant_envelopes(root, lockbox.acquire_lockbox(root))
    target = os.urandom(32)
    real_store_seed = master_seed.store_seed

    def crash(*_args, **_kwargs):
        raise KeyMaterialPersistenceError("power lost before the seed was replaced")

    monkeypatch.setattr(master_seed, "store_seed", crash)
    with pytest.raises(KeyMaterialPersistenceError):
        master_seed.install_seed_derived_authority(
            root, identity_path=ident, seed=target, previous_seed=seed,
        )
    assert master_seed.load_seed(root) == seed  # nothing past the carry ran
    monkeypatch.setattr(master_seed, "store_seed", real_store_seed)
    master_seed.install_seed_derived_authority(
        root, identity_path=ident, seed=target, previous_seed=seed,
    )
    converged = lockbox.acquire_lockbox(root)
    for artifact in _ENVELOPES:
        assert converged.unwrap(artifact.path(root).read_bytes()) == plaintexts[artifact.name]


def test_confirmed_restore_retires_what_no_held_key_opens(tmp_path):
    """Artifacts under a key the transaction does not hold (left by a previous
    life of this data root) are moved aside with what they protect, never
    deleted, except the update authority, whose loss would reset the rollback
    floor; it stays exactly where and as it was."""
    root = tmp_path / "data"
    ident = tmp_path / "identity.key"
    seed = _seeded_silent_install(root)
    foreign = lockbox.LockBox(os.urandom(32))
    _plant_envelopes(root, foreign)
    (root / "capsules" / "sealed").mkdir(parents=True)
    (root / "capsules" / "sealed" / "c1.bin").write_bytes(b"sealed under the old capsule key")
    (root / "peer_https" / "root_ca.pem").write_bytes(b"public projection of the old root")
    update = next(a for a in _ENVELOPES if a.name == "update_state_authority")
    update_bytes = update.path(root).read_bytes()

    master_seed.install_seed_derived_authority(
        root, identity_path=ident, seed=os.urandom(32), previous_seed=seed,
    )

    retired_runs = list((root / lockbox.RETIRED_ARTIFACTS_DIRNAME).iterdir())
    assert len(retired_runs) == 1
    retired = retired_runs[0]
    assert (retired / "capsule-master-key.bin").is_file()
    assert (retired / "capsules" / "sealed" / "c1.bin").read_bytes() == (
        b"sealed under the old capsule key"
    )
    assert (retired / "peer_https" / "root_ca_key.pem").is_file()
    assert (retired / "peer_https" / "root_ca.pem").is_file()
    assert not (root / "capsule-master-key.bin").exists()
    assert not (root / "capsules").exists()
    assert update.path(root).read_bytes() == update_bytes
    # The converged install mints a fresh capsule key and starts cleanly.
    converged = lockbox.acquire_lockbox(root)
    capsule_store.load_or_create_capsule_master_seed(root, converged)
    assert [a.name for a in lockbox.dek_artifacts_unopenable_by(root, converged)] == [
        "update_state_authority"
    ]


def test_damaged_envelope_is_retired_not_accepted_and_not_a_boot_loop(tmp_path):
    """A capsule key that is not a LockBox envelope opens under no key.  The
    replacement neither trusts it nor fails on every replay because of it."""
    root = tmp_path / "data"
    seed = _seeded_silent_install(root)
    (root / capsule_store.CAPSULE_KEY_FILENAME).write_bytes(b"truncated garbage")
    master_seed.install_seed_derived_authority(
        root, identity_path=tmp_path / "identity.key", seed=os.urandom(32),
        previous_seed=seed,
    )
    retired = next((root / lockbox.RETIRED_ARTIFACTS_DIRNAME).iterdir())
    assert (retired / capsule_store.CAPSULE_KEY_FILENAME).read_bytes() == b"truncated garbage"
    assert not (root / capsule_store.CAPSULE_KEY_FILENAME).exists()


def test_restoring_a_silent_bundle_with_a_passphrase_set_refuses(tmp_path, monkeypatch):
    """Data the seed's own DRK protects survives the recovery, so minting a
    scrypt envelope over it would orphan the very backup being restored."""
    root = tmp_path / "data"
    seed = _seeded_silent_install(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, lockbox.acquire_lockbox(root))
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "set while restoring")
    with pytest.raises(KeyMaterialProtectionError, match=MIGRATION):
        master_seed.install_seed_derived_authority(
            root, identity_path=tmp_path / "identity.key", seed=seed,
        )
    assert not (root / lockbox.SALT_FILENAME).exists()
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key


def test_phrase_restore_over_another_identity_with_passphrase_carries_envelopes(
    tmp_path, monkeypatch,
):
    """A different seed replaces the old DRK regardless, so the passphrase may
    mint the new data key -- and the envelopes are carried to it."""
    from one_link.state import State

    root = tmp_path / "data"
    old_seed = _seeded_silent_install(root)
    silent = lockbox.acquire_lockbox(root)
    key = capsule_store.load_or_create_capsule_master_seed(root, silent)
    chain_key = os.urandom(32)
    state = State(db_path=root / "state.db")
    try:
        state.set_lockbox(silent)
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in",
            epoch=1, chain_key=chain_key, counter=0,
        )
    finally:
        state.close()
    new_seed = os.urandom(32)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "the restored install's passphrase")
    master_seed.install_seed_derived_authority(
        root, identity_path=tmp_path / "identity.key", seed=new_seed,
        previous_seed=old_seed,
    )
    assert lockbox.recovery_envelope_matches_seed(root, new_seed) is True
    converged = lockbox.acquire_lockbox(root)
    assert capsule_store.load_or_create_capsule_master_seed(root, converged) == key
    # Reopened the way a passphrase-mode daemon opens it (the passphrase also
    # keys SQLCipher, so it must be set for this open, as at every boot).
    reopened = State(db_path=root / "state.db")
    try:
        reopened.set_lockbox(converged)
        assert reopened.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in", epoch=1,
        )["chain_key"] == chain_key
    finally:
        reopened.close()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert capsule_store.load_or_create_capsule_master_seed(
        root, lockbox.acquire_lockbox(root),
    ) == key


def test_unopenable_state_db_keeps_the_replacement_pending(tmp_path):
    """Re-keying cannot be skipped: publishing the new key while state.db is
    unreadable would orphan its sealed rows once it becomes readable."""
    from one_link.key_material import KeyMaterialProtectionError

    root = tmp_path / "data"
    seed = _seeded_silent_install(root)
    (root / "state.db").write_bytes(b"not a database")
    drk_before = (root / lockbox.DRK_FILENAME).read_bytes()
    with pytest.raises(KeyMaterialProtectionError, match="stays pending"):
        master_seed.install_seed_derived_authority(
            root, identity_path=tmp_path / "identity.key", seed=os.urandom(32),
            previous_seed=seed,
        )
    assert master_seed.load_seed(root) == seed
    assert (root / lockbox.DRK_FILENAME).read_bytes() == drk_before


# ─── Daemon.start: an existing capsule key the data key cannot open is fatal ──


class _StopAfterCapsuleAuthority(BaseException):
    """Raised past every ``except Exception`` to end start() at a known point."""


async def _start_until_capsule_repository(monkeypatch, tmp_path):
    from one_link import capsule_store as capsule_module
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ONE_LINK_QUIC_TRANSPORT", "0")

    def _stop(*_args, **_kwargs):
        raise _StopAfterCapsuleAuthority()

    monkeypatch.setattr(capsule_module, "CapsuleRepository", _stop)
    daemon = Daemon(load_or_create())
    return daemon


def _cleanup(daemon) -> None:
    state = getattr(daemon, "state", None)
    if state is not None:
        state.close()
    daemon._release_instance_lock()


@pytest.mark.asyncio
async def test_daemon_refuses_to_start_when_existing_capsule_key_is_foreign(
    tmp_path, monkeypatch,
):
    from one_link import paths

    daemon = await _start_until_capsule_repository(monkeypatch, tmp_path)
    data = paths.data_dir()
    data.mkdir(parents=True, exist_ok=True)
    foreign = lockbox.LockBox(os.urandom(32)).wrap(os.urandom(32))
    (data / capsule_store.CAPSULE_KEY_FILENAME).write_bytes(foreign)
    try:
        with pytest.raises(KeyMaterialProtectionError, match="capsule master key"):
            await daemon.start()
    finally:
        _cleanup(daemon)
    assert (data / capsule_store.CAPSULE_KEY_FILENAME).read_bytes() == foreign


@pytest.mark.asyncio
async def test_daemon_opens_its_own_capsule_key_and_proceeds(tmp_path, monkeypatch):
    """Control for the refusal: same boot, capsule key under the install's own
    data key, reaches the repository construction that follows it."""
    from one_link import paths

    daemon = await _start_until_capsule_repository(monkeypatch, tmp_path)
    data = paths.data_dir()
    data.mkdir(parents=True, exist_ok=True)
    capsule_store.load_or_create_capsule_master_seed(data, lockbox.acquire_lockbox(data))
    try:
        with pytest.raises(_StopAfterCapsuleAuthority):
            await daemon.start()
    finally:
        _cleanup(daemon)


@pytest.mark.asyncio
async def test_daemon_degrades_only_when_a_new_capsule_key_cannot_be_created(
    tmp_path, monkeypatch, caplog,
):
    """Nothing exists to orphan, so the documented policy stands: capture is
    disabled rather than written without encryption, and startup continues."""
    import sys
    import types

    from one_link import capsule_store as capsule_module

    daemon = await _start_until_capsule_repository(monkeypatch, tmp_path)

    def _disk_full(*_args, **_kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(capsule_module, "_atomic_private_write", _disk_full)
    # The block right after the capsule handler imports path_pii; stop there.
    stopper = types.ModuleType("one_link.path_pii")

    def _getattr(_name):
        raise _StopAfterCapsuleAuthority()

    stopper.__getattr__ = _getattr  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "one_link.path_pii", stopper)
    try:
        with pytest.raises(_StopAfterCapsuleAuthority):
            await daemon.start()
    finally:
        _cleanup(daemon)
    assert daemon._capsule_store is None
    assert "capsule capture is disabled" in caplog.text
