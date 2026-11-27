from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link import (
    backup_bundle,
    identity,
    lockbox,
    master_seed,
    mnemonic,
    paths,
    recovery_api,
)
from one_link.key_material import KeyMaterialIntegrityError


def test_v1_pending_restore_intent_replays_after_journal_upgrade(
    tmp_path, monkeypatch,
):
    """Already-published v1 recovery journals remain boot-replayable."""
    import hashlib

    data = tmp_path / "data"
    config = tmp_path / "config"
    data.mkdir()
    config.mkdir()
    identity_path = config / "identity.key"
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    seed = os.urandom(master_seed.SEED_LEN_BYTES)
    (data / recovery_api.RECOVERY_SEED_STAGE_FILENAME).write_bytes(
        master_seed._encode_seed(seed)
    )
    intent = {
        "version": 1,
        "phase": "prepared",
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "bundle_sha256": None,
        "created_ms": 1,
    }
    (data / recovery_api.RECOVERY_INTENT_FILENAME).write_bytes(
        (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )

    result = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert result["completed"] is True
    assert master_seed.load_seed(data) == seed
    assert recovery_api.has_pending_recovery(data) is False


def _zero_safety_counts() -> dict[str, int]:
    return {
        "pinned_peers": 0,
        "messages": 0,
        "group_messages": 0,
        "groups": 0,
        "shared_folders": 0,
        "self_mesh_devices": 0,
        "pending_transfers": 0,
        "pending_outbox": 0,
        "pending_folder_offers": 0,
        "pending_rotation_announcements": 0,
        "held_recovery_shares": 0,
    }


class _EmptyState:
    def recovery_safety_counts(self) -> dict[str, int]:
        return _zero_safety_counts()


def _install_authority(root: Path, seed: bytes) -> tuple[bytes, bytes]:
    data = root / "data"
    config = root / "config"
    data.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    identity_path = config / "identity.key"
    master_seed.install_seed_derived_authority(
        data,
        identity_path=identity_path,
        seed=seed,
    )
    public = master_seed.derive_identity_priv(seed).public_key().public_bytes_raw()
    drk = lockbox.acquire_or_create_silent_drk(data)
    return public, drk


def test_blank_boot_phrase_destroy_restore_recovers_live_identity_and_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_home = tmp_path / "original"
    monkeypatch.setenv("ONE_LINK_HOME", str(original_home))
    original_data = paths.data_dir()
    original_identity_path = paths.key_path()

    seed, created = master_seed.provision_seed_before_derived_authority(
        original_data,
        identity_path=original_identity_path,
    )
    assert created is True
    assert seed is not None
    live_original = identity.load_or_create()
    original_drk = lockbox.acquire_or_create_silent_drk(original_data)
    assert live_original.private.private_bytes_raw() == (
        master_seed.derive_identity_priv(seed).private_bytes_raw()
    )
    assert original_drk == master_seed.derive_drk(seed)

    phrase = mnemonic.encode(seed)
    verification = recovery_api.test_phrase_against_current_seed(
        data_dir=original_data,
        phrase=phrase,
    )
    assert verification["matches_current_seed"] is True
    assert verification["matches_current_identity"] is True
    assert verification["matches_current_data_root"] is True

    # A distinct empty home represents the original disk/install being gone.
    restored_home = tmp_path / "restored-after-loss"
    monkeypatch.setenv("ONE_LINK_HOME", str(restored_home))
    restored_data = paths.data_dir()
    recovery_api.restore_seed_from_phrase(
        data_dir=restored_data,
        phrase=phrase,
        delete_identity_files=False,
    )
    live_restored = identity.load_or_create()
    restored_drk = lockbox.acquire_or_create_silent_drk(restored_data)

    assert live_restored.public_bytes == live_original.public_bytes
    assert live_restored.private.private_bytes_raw() == (
        live_original.private.private_bytes_raw()
    )
    assert restored_drk == original_drk
    assert recovery_api.has_pending_recovery(restored_data) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("passphrase_mode", [False, True])
async def test_real_daemon_run_establishes_seed_before_constructing_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    passphrase_mode: bool,
) -> None:
    from one_link import daemon as daemon_module

    home = tmp_path / "daemon-blank"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    if passphrase_mode:
        monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "audit first boot and restart")
    else:
        monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)
    observations: dict[str, object] = {}

    async def no_socket_start(self) -> None:
        assert self._lock_file is not None
        seed = master_seed.load_seed(paths.data_dir())
        assert seed is not None
        observations["public"] = self.me.public_bytes
        observations["derived_public"] = (
            master_seed.derive_identity_priv(seed).public_key().public_bytes_raw()
        )
        observations["drk"] = lockbox.acquire_or_create_silent_drk(
            paths.data_dir()
        )
        observations["derived_drk"] = master_seed.derive_drk(seed)
        assert master_seed.inspect_derived_authority(
            paths.data_dir(), identity_path=paths.key_path(), seed=seed,
        ) == {"identity": True, "data_root": True}
        assert lockbox.recovery_envelope_matches_seed(paths.data_dir(), seed) is (
            True if passphrase_mode else None
        )

    async def no_socket_serve(_self) -> None:
        return None

    async def no_socket_stop(self) -> None:
        self._release_instance_lock()

    monkeypatch.setattr(daemon_module.Daemon, "start", no_socket_start)
    monkeypatch.setattr(daemon_module.Daemon, "serve_forever", no_socket_serve)
    monkeypatch.setattr(daemon_module.Daemon, "stop", no_socket_stop)
    monkeypatch.setattr(daemon_module, "_check_previous_heartbeat", lambda: None)
    monkeypatch.setattr(daemon_module.crash_log, "install_loop_hook", lambda _loop: None)

    await daemon_module.run()

    assert observations["public"] == observations["derived_public"]
    assert observations["drk"] == observations["derived_drk"]
    assert master_seed.has_seed(paths.data_dir()) is True

    # A second boot must converge using exactly the persisted authority.
    first_seed = master_seed.load_seed(paths.data_dir())
    first_identity = paths.key_path().read_bytes()
    await daemon_module.run()
    assert master_seed.load_seed(paths.data_dir()) == first_seed
    assert paths.key_path().read_bytes() == first_identity


@pytest.mark.asyncio
async def test_second_daemon_cannot_apply_restore_before_instance_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link import daemon as daemon_module

    home = tmp_path / "locked-home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity_path = paths.key_path()
    old_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        data,
        identity_path=identity_path,
        seed=old_seed,
    )
    old_identity = identity_path.read_bytes()
    old_drk = (data / lockbox.DRK_FILENAME).read_bytes()
    recovery_api.restore_seed_from_phrase(
        data_dir=data,
        phrase=mnemonic.encode(os.urandom(32)),
        delete_identity_files=True,
    )

    holder = object.__new__(daemon_module.Daemon)
    holder._lock_file = None
    holder._acquire_instance_lock()
    monkeypatch.setattr(daemon_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_module, "_check_previous_heartbeat", lambda: None)
    monkeypatch.setattr(daemon_module.crash_log, "install_loop_hook", lambda _loop: None)
    try:
        with pytest.raises(RuntimeError, match="already running"):
            await daemon_module.run()
    finally:
        holder._release_instance_lock()

    assert master_seed.load_seed(data) == old_seed
    assert identity_path.read_bytes() == old_identity
    assert (data / lockbox.DRK_FILENAME).read_bytes() == old_drk
    assert recovery_api.has_pending_recovery(data) is True


def test_destructive_restore_stages_without_mutating_live_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity_path = paths.key_path()
    old_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        data, identity_path=identity_path, seed=old_seed
    )
    before = {
        data / master_seed.SEED_FILENAME: (data / master_seed.SEED_FILENAME).read_bytes(),
        data / lockbox.DRK_FILENAME: (data / lockbox.DRK_FILENAME).read_bytes(),
        identity_path: identity_path.read_bytes(),
    }
    recovered_seed = os.urandom(32)

    recovery_api.restore_seed_from_phrase(
        data_dir=data,
        phrase=mnemonic.encode(recovered_seed),
        delete_identity_files=True,
    )

    assert recovery_api.has_pending_recovery(data) is True
    for path, payload in before.items():
        assert path.read_bytes() == payload
    assert master_seed.load_seed(data) == old_seed


def test_crash_mid_commit_remains_fail_stop_and_replays_to_exact_convergence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity_path = paths.key_path()
    _install_authority(home, os.urandom(32))
    recovered_seed = os.urandom(32)
    recovery_api.restore_seed_from_phrase(
        data_dir=data,
        phrase=mnemonic.encode(recovered_seed),
        delete_identity_files=True,
    )

    real_store_identity = identity.store_seed_derived_identity

    def injected_crash(*_args, **_kwargs):
        raise OSError("injected crash after seed publication")

    monkeypatch.setattr(identity, "store_seed_derived_identity", injected_crash)
    with pytest.raises(OSError, match="injected crash"):
        recovery_api.complete_pending_recovery(
            data_dir=data,
            identity_path=identity_path,
        )
    assert recovery_api.has_pending_recovery(data) is True

    # The marker is the fail-stop boundary: daemon startup calls completion
    # before it can load this temporarily split on-disk hierarchy.
    monkeypatch.setattr(identity, "store_seed_derived_identity", real_store_identity)
    result = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=identity_path,
    )
    assert result["completed"] is True
    assert master_seed.load_seed(data) == recovered_seed
    assert master_seed.inspect_derived_authority(
        data,
        identity_path=identity_path,
        seed=recovered_seed,
    ) == {"identity": True, "data_root": True}
    assert recovery_api.has_pending_recovery(data) is False


def test_intent_publication_failure_preserves_all_live_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity_path = paths.key_path()
    _install_authority(home, os.urandom(32))
    before = {
        data / master_seed.SEED_FILENAME: (data / master_seed.SEED_FILENAME).read_bytes(),
        data / lockbox.DRK_FILENAME: (data / lockbox.DRK_FILENAME).read_bytes(),
        identity_path: identity_path.read_bytes(),
    }

    def fail_intent(_path: Path, _payload: bytes, *, label: str) -> None:
        assert label == "recovery intent"
        raise OSError("injected intent fsync failure")

    monkeypatch.setattr(recovery_api, "_atomic_small_private_file", fail_intent)
    with pytest.raises(OSError, match="intent fsync"):
        recovery_api.restore_seed_from_phrase(
            data_dir=data,
            phrase=mnemonic.encode(os.urandom(32)),
            delete_identity_files=True,
        )
    assert recovery_api.has_pending_recovery(data) is False
    for path, payload in before.items():
        assert path.read_bytes() == payload


def test_tampered_intent_fails_before_any_authority_is_loaded_or_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity_path = paths.key_path()
    old_seed = os.urandom(32)
    _install_authority(home, old_seed)
    recovery_api.restore_seed_from_phrase(
        data_dir=data,
        phrase=mnemonic.encode(os.urandom(32)),
        delete_identity_files=True,
    )
    intent_path = data / recovery_api.RECOVERY_INTENT_FILENAME
    raw = json.loads(intent_path.read_text(encoding="utf-8"))
    raw["seed_sha256"] = "0" * 64
    intent_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(recovery_api.RecoveryTransactionError):
        recovery_api.complete_pending_recovery(
            data_dir=data,
            identity_path=identity_path,
        )
    assert master_seed.load_seed(data) == old_seed


def test_legacy_authority_is_not_silently_given_an_unrelated_master_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "legacy"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    legacy_identity = identity.load_or_create()
    legacy_drk = lockbox.acquire_or_create_silent_drk(data)

    seed, created = master_seed.provision_seed_before_derived_authority(
        data,
        identity_path=paths.key_path(),
    )
    assert seed is None
    assert created is False
    assert master_seed.load_seed(data) is None
    assert identity.load_or_create().public_bytes == legacy_identity.public_bytes
    assert lockbox.acquire_or_create_silent_drk(data) == legacy_drk
    with pytest.raises(KeyMaterialIntegrityError, match="explicit transactional migration"):
        master_seed.load_or_create_seed(data)


def test_existing_seed_mismatch_with_identity_fails_closed_at_boot_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "split"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    identity.load_or_create()
    master_seed.store_seed(data, os.urandom(32))

    with pytest.raises(KeyMaterialIntegrityError, match="Ed25519 identity"):
        master_seed.provision_seed_before_derived_authority(
            data,
            identity_path=paths.key_path(),
        )


def test_restore_cleanliness_includes_identity_drk_seed_and_sqlite_artifacts(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    identity_path = tmp_path / "config" / "identity.key"
    data.mkdir(parents=True)
    identity_path.parent.mkdir(parents=True)
    identity_path.write_bytes(b"legacy-identity")
    (data / lockbox.DRK_FILENAME).write_bytes(b"d" * 32)
    (data / "state.db").write_bytes(b"SQLite format 3\x00")

    clean, evidence = recovery_api.is_install_clean_for_restore(
        _EmptyState(),
        data_dir=data,
        identity_path=identity_path,
    )
    assert clean is False
    assert evidence["identity_key_artifact"] == 1
    assert evidence["data_root_key_artifact"] == 1
    assert evidence["state_db_artifact"] == 1


@pytest.mark.asyncio
async def test_phrase_handler_returns_409_for_legacy_identity_without_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from one_link.server import UIServer

    home = tmp_path / "legacy-web"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    identity.load_or_create()
    assert master_seed.load_seed(paths.data_dir()) is None

    class _Request:
        transport = None
        remote = "127.0.0.1"

        async def json(self):
            return {
                "phrase": mnemonic.encode(os.urandom(32)),
                "force": False,
                "confirmed_replace": False,
            }

    server = UIServer(SimpleNamespace(state=_EmptyState(), peer_rtc=None))
    response = await server.api_recovery_restore_phrase(_Request())
    payload = json.loads(response.body)
    assert response.status == 409
    assert payload["error"] == "destructive_restore_requires_confirmation"
    assert payload["evidence"]["identity_key_artifact"] == 1


def test_bundle_restore_is_deferred_until_offline_boot_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_data = tmp_path / "source-data"
    source_config = tmp_path / "source-config"
    source_data.mkdir()
    source_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        source_data,
        identity_path=source_config / "identity.key",
        seed=source_seed,
    )
    (source_data / "state.db").write_bytes(b"new-restored-state")
    bundle = backup_bundle.create_bundle(seed=source_seed, data_dir=source_data)

    target_home = tmp_path / "target"
    monkeypatch.setenv("ONE_LINK_HOME", str(target_home))
    target_data = paths.data_dir()
    target_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        target_data,
        identity_path=paths.key_path(),
        seed=target_seed,
    )
    (target_data / "state.db").write_bytes(b"live-old-state")
    old_identity = paths.key_path().read_bytes()
    old_drk = (target_data / lockbox.DRK_FILENAME).read_bytes()

    result = recovery_api.restore_from_bundle(
        data_dir=target_data,
        phrase=mnemonic.encode(source_seed),
        bundle_bytes=bundle,
        delete_identity_files=True,
        overwrite=True,
    )
    assert result["written"] == []
    assert "state.db" in result["validated_members"]
    assert result["pending_restart"] is True
    assert (target_data / "state.db").read_bytes() == b"live-old-state"
    assert paths.key_path().read_bytes() == old_identity
    assert (target_data / lockbox.DRK_FILENAME).read_bytes() == old_drk

    completed = recovery_api.complete_pending_recovery(
        data_dir=target_data,
        identity_path=paths.key_path(),
    )
    assert completed["completed"] is True
    assert (target_data / "state.db").read_bytes() == b"new-restored-state"
    assert master_seed.load_seed(target_data) == source_seed
    assert master_seed.inspect_derived_authority(
        target_data,
        identity_path=paths.key_path(),
        seed=source_seed,
    ) == {"identity": True, "data_root": True}


def test_bundle_cannot_overwrite_the_recovery_journal_that_authorizes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "malicious-source"
    source.mkdir()
    seed = os.urandom(32)
    reserved = recovery_api.RECOVERY_INTENT_FILENAME
    (source / reserved).write_bytes(b"attacker-controlled-intent")
    bundle = backup_bundle.create_bundle(
        seed=seed,
        data_dir=source,
        extra_allowlist=(reserved,),
    )

    home = tmp_path / "target-home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    with pytest.raises(ValueError, match="transaction metadata"):
        recovery_api.restore_from_bundle(
            data_dir=paths.data_dir(),
            phrase=mnemonic.encode(seed),
            bundle_bytes=bundle,
            delete_identity_files=False,
            overwrite=False,
        )
    assert recovery_api.has_pending_recovery(paths.data_dir()) is False


def test_clean_restore_journal_refuses_a_target_that_races_into_existence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clean-target proof remains binding across staging and replay."""
    source = tmp_path / "source"
    source.mkdir()
    seed = os.urandom(32)
    master_seed.store_seed(source, seed)
    (source / "state.db").write_bytes(b"authenticated-backup-state")
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)

    target = tmp_path / "clean-target"
    identity_path = target / "identity.key"
    real_extract = backup_bundle.extract_bundle_to_dir
    collision = target / "state.db"

    def inject_racing_file(**kwargs):
        target.mkdir(parents=True, exist_ok=True)
        collision.write_bytes(b"independent-racing-writer")
        return real_extract(**kwargs)

    monkeypatch.setattr(
        backup_bundle,
        "extract_bundle_to_dir",
        inject_racing_file,
    )
    with pytest.raises(FileExistsError, match="already exists"):
        recovery_api.restore_from_bundle(
            data_dir=target,
            identity_path=identity_path,
            phrase=mnemonic.encode(seed),
            bundle_bytes=bundle,
            delete_identity_files=False,
            overwrite=False,
        )

    # Neither the independently published file nor authority is replaced.
    assert collision.read_bytes() == b"independent-racing-writer"
    assert master_seed.load_seed(target) is None
    assert not identity_path.exists()
    intent = recovery_api._load_recovery_intent(target)
    assert intent is not None
    assert intent["phase"] == "prepared"
    assert intent["overwrite_files"] is False

    # Removing the collision lets the exact authenticated journal replay.
    monkeypatch.setattr(
        backup_bundle,
        "extract_bundle_to_dir",
        real_extract,
    )
    collision.unlink()
    result = recovery_api.complete_pending_recovery(
        data_dir=target,
        identity_path=identity_path,
    )
    assert result["completed"] is True
    assert collision.read_bytes() == b"authenticated-backup-state"
    assert master_seed.load_seed(target) == seed
    assert recovery_api.has_pending_recovery(target) is False


def test_applied_phase_recovers_from_crash_after_bundle_stage_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    seed = os.urandom(32)
    master_seed.store_seed(source, seed)
    (source / "state.db").write_bytes(b"restored-once")
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)

    home = tmp_path / "target"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data = paths.data_dir()
    recovery_api.restore_from_bundle(
        data_dir=data,
        phrase=mnemonic.encode(seed),
        bundle_bytes=bundle,
        delete_identity_files=True,
        overwrite=True,
    )

    real_unlink = recovery_api._durable_unlink

    def crash_after_bundle_removed(path: Path, *, label: str) -> None:
        if label == "recovery bundle stage":
            real_unlink(path, label=label)
            return
        raise OSError("injected cleanup crash")

    monkeypatch.setattr(recovery_api, "_durable_unlink", crash_after_bundle_removed)
    with pytest.raises(OSError, match="cleanup crash"):
        recovery_api.complete_pending_recovery(
            data_dir=data,
            identity_path=paths.key_path(),
        )
    intent = recovery_api._load_recovery_intent(data)
    assert intent is not None and intent["phase"] == "applied"
    assert not (data / recovery_api.RECOVERY_BUNDLE_STAGE_FILENAME).exists()

    monkeypatch.setattr(recovery_api, "_durable_unlink", real_unlink)
    replay = recovery_api.complete_pending_recovery(
        data_dir=data,
        identity_path=paths.key_path(),
    )
    assert replay["completed"] is True
    assert (data / "state.db").read_bytes() == b"restored-once"
    assert recovery_api.has_pending_recovery(data) is False
