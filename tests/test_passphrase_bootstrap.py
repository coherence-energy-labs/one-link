"""First-boot ordering and interrupted-publication regression contracts."""
from __future__ import annotations

import os

import pytest

from one_link import identity, lockbox, master_seed, paths
from one_link.key_material import (
    KeyMaterialIntegrityError,
    KeyMaterialPersistenceError,
    KeyMaterialProtectionError,
)


def test_interrupted_envelope_publication_reuses_seed_and_salt(monkeypatch):
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "bootstrap publication replay")
    root = paths.data_dir()
    publish = lockbox._publish_new_envelope

    def interrupted(*args, **kwargs):
        raise KeyMaterialPersistenceError("simulated interrupted publication")

    monkeypatch.setattr(lockbox, "_publish_new_envelope", interrupted)
    with pytest.raises(KeyMaterialPersistenceError):
        master_seed.provision_seed_before_derived_authority(
            root, identity_path=paths.key_path(),
        )
    seed = master_seed.load_seed(root)
    salt = (root / lockbox.SALT_FILENAME).read_bytes()
    assert seed is not None
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()

    monkeypatch.setattr(lockbox, "_publish_new_envelope", publish)
    resumed_seed, created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=paths.key_path(),
    )
    identity.load_or_create()
    assert resumed_seed == seed
    assert not created
    assert (root / lockbox.SALT_FILENAME).read_bytes() == salt
    assert master_seed.inspect_derived_authority(
        root, identity_path=paths.key_path(), seed=seed,
    ) == {"identity": True, "data_root": True}


def test_bootstrap_does_not_rebind_an_existing_envelope(monkeypatch):
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "preserve published authority")
    root = paths.data_dir()
    seed = os.urandom(32)
    assert lockbox.prepare_bootstrap_recovery_envelope(root, seed=seed)
    envelope_path = root / lockbox.DEK_ENVELOPE_FILENAME
    original = envelope_path.read_bytes()
    with pytest.raises(KeyMaterialIntegrityError, match="does not match"):
        lockbox.prepare_bootstrap_recovery_envelope(root, seed=os.urandom(32))
    assert envelope_path.read_bytes() == original
    assert lockbox.prepare_bootstrap_recovery_envelope(root, seed=seed)
    assert envelope_path.read_bytes() == original


@pytest.mark.parametrize("artifact", ["state.db", "state.db-wal", "state.db-shm"])
def test_existing_data_without_envelope_requires_explicit_migration(
    monkeypatch, artifact,
):
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "must not orphan existing data")
    root = paths.data_dir()
    (root / artifact).write_bytes(b"existing application state")
    with pytest.raises(KeyMaterialProtectionError, match="explicit recovery migration"):
        lockbox.prepare_bootstrap_recovery_envelope(root, seed=os.urandom(32))
    assert not (root / lockbox.SALT_FILENAME).exists()
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    assert (root / artifact).read_bytes() == b"existing application state"


def test_silent_bootstrap_keeps_envelope_absent(monkeypatch):
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    root = paths.data_dir()
    assert lockbox.prepare_bootstrap_recovery_envelope(root, seed=os.urandom(32)) is False
    assert not (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
