"""Production proofs for portable SQLCipher .olbak recovery.

These tests deliberately opt out of the suite-wide plaintext isolation flag.
They exercise real SQLCipher files and fresh ``ONE_LINK_HOME`` roots; no test
uses or mutates the developer's credential store.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from one_link import backup_bundle, keychain, lockbox, master_seed, state_encryption
from one_link.key_material import KeyMaterialIntegrityError
from one_link.state import State


pytestmark = pytest.mark.skipif(
    not state_encryption._have_sqlcipher(),
    reason="sqlcipher3 not installed",
)


class _MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, user: str) -> str | None:
        return self.values.get((service, user))

    def set_password(self, service: str, user: str, value: str) -> None:
        self.values[(service, user)] = value

    def delete_password(self, service: str, user: str) -> None:
        self.values.pop((service, user), None)

    def get_keyring(self):
        return self


def _enable_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)


def _data_root(monkeypatch: pytest.MonkeyPatch, home: Path) -> Path:
    monkeypatch.setenv("ONE_LINK_HOME", str(home.resolve()))
    root = home / "data"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _make_live_source(
    *,
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    seed: bytes,
) -> tuple[Path, State]:
    root = _data_root(monkeypatch, home)
    master_seed.store_seed(root, seed)
    # Bootstrap the source the way the daemon does before State opens: an
    # explicit-passphrase install publishes its LockBox recovery envelope
    # first (a no-op in silent mode).  Without it, a passphrase in the
    # environment at export time would be minting a new data key over an
    # existing state.db, which create_bundle refuses (test_dek_authority_registry).
    lockbox.prepare_bootstrap_recovery_envelope(root, seed=seed)
    state = State(db_path=root / "state.db")
    state.set_setting("portable-proof", "exact-row-value")
    return root, state


def _extract_into_fresh_root(
    *,
    monkeypatch: pytest.MonkeyPatch,
    bundle: bytes,
    seed: bytes,
    home: Path,
) -> tuple[Path, list[str]]:
    target = _data_root(monkeypatch, home)
    _header, plaintext = backup_bundle.open_bundle(
        seed=seed,
        bundle_bytes=bundle,
    )
    written = backup_bundle.extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=target,
    )
    # Model phrase recovery on the target, including a new machine's DPAPI
    # wrapping rather than trusting a source-machine master.seed blob.
    master_seed.store_seed(target, seed)
    return target, written


def test_fresh_home_local_key_round_trip_uses_coherent_live_wal_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_encryption(monkeypatch)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    seed = b"L" * 32
    source, state = _make_live_source(
        monkeypatch=monkeypatch,
        home=tmp_path / "source-local",
        seed=seed,
    )
    assert (source / keychain.LOCAL_KEY_FILENAME).is_file()

    stop = threading.Event()
    writer_errors: list[BaseException] = []

    def _writer() -> None:
        counter = 0
        try:
            while not stop.is_set():
                state.set_setting("concurrent-wal-counter", str(counter))
                counter += 1
        except BaseException as exc:  # pragma: no cover - assertion payload
            writer_errors.append(exc)

    writer = threading.Thread(target=_writer, daemon=True)
    writer.start()
    try:
        bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)
    finally:
        stop.set()
        writer.join(timeout=10)
        state.close()
    assert not writer.is_alive()
    assert writer_errors == []

    _header, plaintext = backup_bundle.open_bundle(
        seed=seed,
        bundle_bytes=bundle,
    )
    names = backup_bundle.inspect_bundle_archive(plaintext=plaintext)
    assert "state.db" in names
    assert keychain.RECOVERY_KEY_FILENAME in names
    assert keychain.LOCAL_KEY_FILENAME not in names
    assert "state.db-wal" not in names
    assert "state.db-shm" not in names

    target, written = _extract_into_fresh_root(
        monkeypatch=monkeypatch,
        bundle=bundle,
        seed=seed,
        home=tmp_path / "target-local",
    )
    assert keychain.RECOVERY_KEY_FILENAME in written
    assert not (target / keychain.LOCAL_KEY_FILENAME).exists()
    restored = State(db_path=target / "state.db")
    try:
        assert restored.is_encrypted is True
        assert restored.get_setting("portable-proof") == "exact-row-value"
        assert restored.get_setting("concurrent-wal-counter") is not None
    finally:
        restored.close()
    assert (target / keychain.LOCAL_KEY_FILENAME).is_file()
    assert not (target / keychain.RECOVERY_KEY_FILENAME).exists()


def test_fresh_home_os_keyring_round_trip_installs_exact_recovered_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_encryption(monkeypatch)
    memory = _MemoryKeyring()
    monkeypatch.setattr(keychain, "_load_keyring", lambda: memory)
    seed = b"K" * 32
    source, state = _make_live_source(
        monkeypatch=monkeypatch,
        home=tmp_path / "source-keyring",
        seed=seed,
    )
    source_key = memory.get_password(*keychain.keychain_target(source))
    assert source_key
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)
    state.close()

    # A genuinely fresh computer has no source machine credential entry.
    memory.values.clear()
    target, _written = _extract_into_fresh_root(
        monkeypatch=monkeypatch,
        bundle=bundle,
        seed=seed,
        home=tmp_path / "target-keyring",
    )
    restored = State(db_path=target / "state.db")
    try:
        assert restored.get_setting("portable-proof") == "exact-row-value"
    finally:
        restored.close()
    assert memory.get_password(*keychain.keychain_target(target)) == source_key
    assert not (target / keychain.LOCAL_KEY_FILENAME).exists()
    assert not (target / keychain.RECOVERY_KEY_FILENAME).exists()


def test_explicit_target_passphrase_is_honored_by_atomic_rekey(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_encryption(monkeypatch)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    seed = b"E" * 32
    monkeypatch.setenv(keychain.ENV_VAR, "source-explicit-passphrase")
    source, state = _make_live_source(
        monkeypatch=monkeypatch,
        home=tmp_path / "source-env",
        seed=seed,
    )
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)
    state.close()

    monkeypatch.setenv(keychain.ENV_VAR, "target-explicit-passphrase")
    target, _written = _extract_into_fresh_root(
        monkeypatch=monkeypatch,
        bundle=bundle,
        seed=seed,
        home=tmp_path / "target-env",
    )
    restored = State(db_path=target / "state.db")
    try:
        assert restored.get_setting("portable-proof") == "exact-row-value"
    finally:
        restored.close()
    assert state_encryption.database_accepts_passphrase(
        target / "state.db",
        "target-explicit-passphrase",
    )
    assert not (target / keychain.LOCAL_KEY_FILENAME).exists()
    assert not (target / keychain.RECOVERY_KEY_FILENAME).exists()


@pytest.mark.parametrize("mutation", ["wrong-seed", "tamper", "truncate"])
def test_seed_wrapped_database_key_rejects_wrong_seed_tamper_and_truncation(
    mutation: str,
) -> None:
    seed = b"S" * 32
    artifact = keychain.seal_state_passphrase_for_recovery(
        seed=seed,
        passphrase="never-plaintext-in-the-archive",
    )
    if mutation == "wrong-seed":
        candidate_seed = b"W" * 32
        candidate = artifact
    elif mutation == "tamper":
        candidate_seed = seed
        damaged = bytearray(artifact)
        damaged[-1] ^= 0x80
        candidate = bytes(damaged)
    else:
        candidate_seed = seed
        candidate = artifact[:-9]
    with pytest.raises(KeyMaterialIntegrityError):
        keychain.unseal_state_passphrase_for_recovery(
            seed=candidate_seed,
            artifact=candidate,
        )


def test_failed_recovery_rekey_leaves_original_database_and_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_encryption(monkeypatch)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    seed = b"F" * 32
    source_key = "source-key-for-failure-proof"
    target_key = "target-key-for-failure-proof"
    root = _data_root(monkeypatch, tmp_path / "rekey-failure")
    master_seed.store_seed(root, seed)
    conn = state_encryption.open_encrypted_connection(root / "state.db", source_key)
    conn.execute("CREATE TABLE proof(value TEXT NOT NULL)")
    conn.execute("INSERT INTO proof(value) VALUES ('preserved')")
    conn.close()
    artifact = keychain.seal_state_passphrase_for_recovery(
        seed=seed,
        passphrase=source_key,
    )
    (root / keychain.RECOVERY_KEY_FILENAME).write_bytes(artifact)
    monkeypatch.setenv(keychain.ENV_VAR, target_key)

    real_replace = state_encryption.os.replace

    def _fail_final_replace(source, destination) -> None:
        if Path(destination) == (root / "state.db"):
            raise OSError("injected final rekey boundary failure")
        real_replace(source, destination)

    monkeypatch.setattr(state_encryption.os, "replace", _fail_final_replace)
    with pytest.raises(OSError, match="injected final rekey"):
        keychain.adopt_recovery_passphrase_for_database(root / "state.db")
    assert (root / keychain.RECOVERY_KEY_FILENAME).read_bytes() == artifact
    original = state_encryption.open_encrypted_connection(
        root / "state.db",
        source_key,
    )
    try:
        assert original.execute("SELECT value FROM proof").fetchone()[0] == "preserved"
    finally:
        original.close()


def test_constructor_and_wrong_key_failures_release_database_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_encryption(monkeypatch)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setenv(keychain.ENV_VAR, "constructor-handle-key")
    root = _data_root(monkeypatch, tmp_path / "handle-proof")
    db = root / "state.db"

    def _raise_after_open(self) -> None:
        raise RuntimeError("injected constructor failure")

    monkeypatch.setattr(State, "_migrate", _raise_after_open)
    with pytest.raises(RuntimeError, match="injected constructor failure"):
        State(db_path=db)
    moved = root / "state-after-constructor-failure.db"
    os.replace(db, moved)

    with pytest.raises(Exception):
        state_encryption.open_encrypted_connection(moved, "definitely-wrong-key")
    returned = root / "state-after-wrong-key.db"
    os.replace(moved, returned)
    assert returned.is_file()
