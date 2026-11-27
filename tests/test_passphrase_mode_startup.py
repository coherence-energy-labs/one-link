"""A passphrase-protected install refuses to start without its passphrase.

Before: State() raised, Daemon.start's general fallback logged "continuing
without persistence" and served an empty app.  Now State raises
KeyMaterialProtectionError (Daemon.start's existing refuse-and-clean-up
class) naming both fixes, and nothing on disk changes.  Every case drives the
real `daemon.run()` -> bootstrap -> `Daemon.start()` path, with SQLCipher on
and the database key in a local key file (the OS keyring is patched out).
"""
from __future__ import annotations

import asyncio
import hashlib
import os

import pytest

from one_link import (
    daemon as daemon_mod,
    identity,
    keychain,
    lockbox,
    master_seed,
    paths,
    recovery_api,
    state_encryption,
)
from one_link.key_material import KeyMaterialError
from one_link.state import State
from tests.test_data_key_migration import PASSPHRASE, _install
from tests.test_rotation_state_field_carry import _undecryptable_fields, _write_wrapped_fields

FIXES = ("ONE_LINK_PASSPHRASE", "`one-link recovery remove-passphrase`")


@pytest.fixture(autouse=True)
def _production_shaped_keys(monkeypatch):
    if not state_encryption._have_sqlcipher():
        pytest.skip("sqlcipher3 not installed")
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)
    monkeypatch.setenv("ONE_LINK_QUIC_TRANSPORT", "0")


class _Started(BaseException):
    """Raised at the end of start()'s authority block: the daemon got that far."""


def _authority_and_data_files() -> list:
    root = paths.data_dir()
    names = [a.relpath for a in lockbox.DEK_PROTECTED_ARTIFACTS] + [
        lockbox.DEK_ENVELOPE_FILENAME, lockbox.SALT_FILENAME, lockbox.DRK_FILENAME,
        master_seed.SEED_FILENAME, keychain.LOCAL_KEY_FILENAME,
    ]
    return [root.joinpath(*name.split("/")) for name in names] + [paths.key_path()]


def _snapshot() -> dict:
    return {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        for path in _authority_and_data_files()
    }


async def _refused_start(monkeypatch) -> str:
    async def forbidden(*_args, **_kwargs):
        pytest.fail("a refused start reached a listener or full shutdown")

    monkeypatch.setattr(asyncio, "start_server", forbidden)
    monkeypatch.setattr(daemon_mod.Daemon, "stop", forbidden)
    with pytest.raises(KeyMaterialError) as refused:
        await daemon_mod.run()
    return str(refused.value)


async def _started(monkeypatch, written) -> None:
    """Run until start() finished its authority block; read the saved state."""
    seen = {}

    def stop_here(self):
        try:
            assert self.state is not None, "started without persistence"
            seen["failures"] = _undecryptable_fields(self.state, written)
        finally:
            self.state.close()
            self.state = None
            if self._capsule_store is not None:
                self._capsule_store.close()
        raise _Started()

    monkeypatch.setattr(daemon_mod.Daemon, "_apply_settings_at_boot", stop_here)
    with pytest.raises(_Started):
        await daemon_mod.run()
    assert seen["failures"] == []


def _passphrase_install(monkeypatch):
    root, _id, seed, written = _install()
    recovery_api.set_data_key_passphrase(data_dir=root, passphrase=PASSPHRASE)
    return root, seed, written["fields"]


@pytest.mark.asyncio
async def test_started_without_the_passphrase_refuses_and_touches_nothing(monkeypatch):
    _root, _seed, _fields = _passphrase_install(monkeypatch)
    before = _snapshot()
    message = await _refused_start(monkeypatch)
    assert all(fix in message for fix in FIXES), message
    assert "started without ONE_LINK_PASSPHRASE" in message
    assert _snapshot() == before


@pytest.mark.asyncio
async def test_a_wrong_passphrase_refuses_and_touches_nothing(monkeypatch):
    _root, _seed, _fields = _passphrase_install(monkeypatch)
    before = _snapshot()
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "not the passphrase")
    message = await _refused_start(monkeypatch)
    assert all(fix in message for fix in FIXES), message
    assert "is not the passphrase that protects this installation" in message
    # In particular the envelope's passphrase slot was not rewrapped to it.
    assert _snapshot() == before


@pytest.mark.asyncio
async def test_the_right_passphrase_starts_and_reads_the_saved_state(monkeypatch):
    _root, _seed, fields = _passphrase_install(monkeypatch)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    await _started(monkeypatch, fields)


@pytest.mark.asyncio
async def test_a_fresh_passphrase_install_refuses_before_minting_a_database_key(monkeypatch):
    """Created with ONE_LINK_PASSPHRASE from the first boot: no stored database
    key exists, and a start without the passphrase must not mint one."""
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    root = paths.data_dir()
    seed, created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=paths.key_path(),
    )
    assert created
    identity.load_or_create(paths.key_path())
    state = State(root / "state.db")
    try:
        state.set_lockbox(lockbox.acquire_lockbox(root))
        _write_wrapped_fields(state)
    finally:
        state.close()
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert not (root / keychain.LOCAL_KEY_FILENAME).exists()
    before = _snapshot()
    message = await _refused_start(monkeypatch)
    assert all(fix in message for fix in FIXES), message
    assert _snapshot() == before
    assert not (root / keychain.LOCAL_KEY_FILENAME).exists()


@pytest.mark.asyncio
async def test_an_envelope_install_whose_database_key_is_stored_starts_without_it(monkeypatch):
    """No code path creates an envelope without a passphrase.  The real case
    of an envelope install that runs WITHOUT ONE_LINK_PASSPHRASE is a
    passphrase bundle restored without it: recovery adopts the bundle's
    database key into the keychain.  Modeled by moving the database back to
    the stored key; the data key is still the envelope's (seed slot)."""
    root, seed, fields = _passphrase_install(monkeypatch)
    stored = keychain.get_passphrase()
    assert stored
    state_encryption.replace_encrypted_database_key_atomic(
        db_path=root / "state.db", source_passphrase=PASSPHRASE, destination_passphrase=stored,
    )
    # Recovery stores the seed-derived identity under the start's own
    # protection: none, without ONE_LINK_PASSPHRASE.
    identity.store_seed_derived_identity(paths.key_path(), seed)
    assert (root / lockbox.DEK_ENVELOPE_FILENAME).exists()
    await _started(monkeypatch, fields)


@pytest.mark.asyncio
async def test_a_silent_install_still_starts_normally(monkeypatch):
    _root, _id, _seed, written = _install()
    await _started(monkeypatch, written["fields"])


@pytest.mark.asyncio
async def test_after_remove_passphrase_a_start_with_it_set_refuses_naming_both_fixes(monkeypatch):
    root, _seed, _fields = _passphrase_install(monkeypatch)
    recovery_api.remove_data_key_passphrase(data_dir=root, passphrase=PASSPHRASE)
    before = _snapshot()
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, PASSPHRASE)
    message = await _refused_start(monkeypatch)
    assert "start One Link without ONE_LINK_PASSPHRASE" in message
    assert "`one-link recovery set-passphrase`" in message
    assert _snapshot() == before
    assert not os.path.exists(root / lockbox.DEK_ENVELOPE_FILENAME)
