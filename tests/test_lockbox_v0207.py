"""v0.20.7 lockbox: at-rest wrap of group chain_keys when
ONE_LINK_PASSPHRASE is set.

Pins the security audit H21 fix:
  - Cleartext writes survive when no lockbox is attached.
  - Wrapped writes round-trip via length-based detection.
  - Mid-life passphrase opt-in: legacy cleartext rows remain readable
    after a lockbox is attached.
  - Tag-mismatch on wrap fails the unwrap (no silent acceptance).
"""
from __future__ import annotations

import pytest

from one_link import lockbox as lb
from one_link.lockbox import LockBox, LockBoxError, is_wrapped, maybe_wrap, maybe_unwrap
from one_link.state import State


def _new_state(tmp_path) -> State:
    return State(db_path=tmp_path / "state.db")


def test_lockbox_wrap_unwrap_round_trip():
    box = LockBox.from_passphrase(b"hunter2", b"X" * 16)
    blob = box.wrap(b"\x00" * 32)
    assert is_wrapped(blob)
    assert len(blob) == 1 + 12 + 32 + 16
    assert box.unwrap(blob) == b"\x00" * 32


def test_lockbox_unwrap_tampered_fails():
    box = LockBox.from_passphrase(b"hunter2", b"X" * 16)
    blob = bytearray(box.wrap(b"the cat sat on the mat"))
    # Flip one byte of the ciphertext.
    blob[20] ^= 0xff
    with pytest.raises(LockBoxError):
        box.unwrap(bytes(blob))


def test_lockbox_unwrap_wrong_passphrase_fails():
    blob = LockBox.from_passphrase(b"correct", b"X" * 16).wrap(b"secret")
    other = LockBox.from_passphrase(b"wrong", b"X" * 16)
    with pytest.raises(LockBoxError):
        other.unwrap(blob)


def test_state_chain_key_cleartext_when_no_lockbox(tmp_path):
    """No lockbox attached → chain_key stored cleartext, read back
    byte-equal. Same posture as before this fix."""
    state = _new_state(tmp_path)
    try:
        secret = b"k" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=1, chain_key=secret, counter=0,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
        # Verify it's actually cleartext on disk (32 bytes, no marker).
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains LIMIT 1"
        ).fetchone()["chain_key"]
        assert len(raw) == 32
        assert raw == secret
    finally:
        state.close()


def test_state_chain_key_wrapped_when_lockbox_set(tmp_path):
    """Lockbox attached → chain_key on disk is AES-GCM wrapped, but
    reads back unwrapped value byte-equal."""
    state = _new_state(tmp_path)
    try:
        state.set_lockbox(LockBox.from_passphrase(b"hunter2", b"X" * 16))
        secret = bytes(range(32))
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="in", epoch=2, chain_key=secret, counter=5,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in",
        )
        assert row["chain_key"] == secret
        # Disk is wrapped (61 bytes, marker prefix).
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains LIMIT 1"
        ).fetchone()["chain_key"]
        assert len(raw) == 61
        assert raw[0:1] == lb.WRAP_MARKER
        assert raw != secret  # cleartext doesn't appear in storage
    finally:
        state.close()


def test_state_chain_key_legacy_cleartext_readable_after_lockbox_attached(tmp_path):
    """Mid-life passphrase opt-in: rows written before set_lockbox
    are still readable. The length-based detection path knows that
    a 32-byte stored value is cleartext regardless of lockbox state."""
    state = _new_state(tmp_path)
    try:
        # Phase 1: write cleartext (no lockbox).
        secret = b"\xaa" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=3, chain_key=secret, counter=0,
        )
        # Phase 2: attach a lockbox; legacy row stays readable.
        state.set_lockbox(LockBox.from_passphrase(b"hunter2", b"X" * 16))
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
        # Phase 3: write a NEW chain — gets wrapped.
        secret2 = b"\xbb" * 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="in", epoch=4, chain_key=secret2, counter=1,
        )
        row2 = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="in",
        )
        assert row2["chain_key"] == secret2
        # And the new chain on disk is the wrapped form.
        raw = state._conn.execute(
            "SELECT chain_key FROM group_sender_chains "
            "WHERE direction = 'in'"
        ).fetchone()["chain_key"]
        assert len(raw) == 61
    finally:
        state.close()


def test_state_chain_key_first_byte_collision_is_safe(tmp_path):
    """Defends the length-based detection rule: a cleartext chain_key
    that happens to start with the wrap-marker byte must not be
    misdetected as wrapped. Without length disambiguation a generic
    is_wrapped check would mis-fire here ~1/256 of the time."""
    state = _new_state(tmp_path)
    try:
        # Construct a cleartext 32-byte key starting with the wrap marker.
        secret = lb.WRAP_MARKER + b"x" * 31
        assert len(secret) == 32
        state.upsert_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32,
            direction="out", epoch=5, chain_key=secret, counter=0,
        )
        row = state.get_sender_chain(
            group_id=b"g" * 16, sender_pub=b"s" * 32, direction="out",
        )
        assert row["chain_key"] == secret
    finally:
        state.close()


def test_state_chain_key_rejects_invalid_storage_envelope_length(tmp_path):
    state = _new_state(tmp_path)
    try:
        state.upsert_sender_chain(
            group_id=b"g" * 16,
            sender_pub=b"s" * 32,
            direction="out",
            epoch=6,
            chain_key=b"k" * 32,
            counter=0,
        )
        state._conn.execute(
            "UPDATE group_sender_chains SET chain_key = ?",
            (lb.WRAP_MARKER + b"x" * 32,),
        )

        with pytest.raises(ValueError, match="invalid stored chain_key length"):
            state.get_sender_chain(
                group_id=b"g" * 16,
                sender_pub=b"s" * 32,
                direction="out",
            )
    finally:
        state.close()


def test_lockbox_top_level_helpers_passthrough_when_none():
    assert maybe_wrap(b"hello", None) == b"hello"
    assert maybe_unwrap(b"hello", None) == b"hello"


def test_silent_drk_round_trips(tmp_path):
    """Silent-mode DRK acquisition returns the same 32 bytes across
    process restarts. On Windows DPAPI wraps it; on POSIX it's 32
    raw bytes with 0o600 — either way load == mint."""
    from one_link.lockbox import acquire_or_create_silent_drk
    drk1 = acquire_or_create_silent_drk(tmp_path)
    assert len(drk1) == 32
    drk2 = acquire_or_create_silent_drk(tmp_path)
    assert drk1 == drk2


def test_silent_drk_persists_to_disk(tmp_path):
    """The silent DRK actually lands on disk under the canonical
    filename. On Windows the on-disk blob is DPAPI-wrapped (>32
    bytes); on POSIX it's raw 32 bytes."""
    import os
    from one_link.lockbox import acquire_or_create_silent_drk, DRK_FILENAME
    drk = acquire_or_create_silent_drk(tmp_path)
    drk_file = tmp_path / DRK_FILENAME
    assert drk_file.is_file()
    if os.name == "nt":
        # DPAPI wrap adds metadata — exact size varies with the user
        # SID + master key version, but it's always > 32.
        assert drk_file.stat().st_size > 32
    else:
        assert drk_file.stat().st_size == 32


def test_acquire_lockbox_returns_a_working_lockbox(tmp_path, monkeypatch):
    """When ONE_LINK_PASSPHRASE is unset, acquire_lockbox returns a
    silent-mode LockBox (no user prompt). It wraps + unwraps."""
    monkeypatch.delenv("ONE_LINK_PASSPHRASE", raising=False)
    from one_link.lockbox import acquire_lockbox
    lb = acquire_lockbox(tmp_path)
    assert lb is not None
    plain = b"\xab" * 32
    wrapped = lb.wrap(plain)
    assert lb.unwrap(wrapped) == plain


def test_acquire_lockbox_passphrase_takes_precedence(tmp_path, monkeypatch):
    """When ONE_LINK_PASSPHRASE is set on an install with no data key yet,
    acquire_lockbox uses the scrypt path, an independent derivation from the
    silent DRK.  On an install whose silent key was already handed out, the
    passphrase must NOT take precedence: switching keys would orphan every
    value wrapped under the DRK (audit H1), so it refuses and the silent
    value stays readable."""
    from one_link.key_material import KeyMaterialProtectionError
    from one_link.lockbox import acquire_lockbox
    monkeypatch.delenv("ONE_LINK_PASSPHRASE", raising=False)
    lb_silent = acquire_lockbox(tmp_path / "silent-install")
    monkeypatch.setenv("ONE_LINK_PASSPHRASE", "hunter2")
    lb_passphrase = acquire_lockbox(tmp_path / "passphrase-install")
    assert lb_passphrase.is_silent is False
    plain = b"x" * 32
    blob_silent = lb_silent.wrap(plain)
    # The passphrase-derived lockbox cannot unwrap the silent-derived
    # blob and vice versa — independent key derivations.
    with pytest.raises(LockBoxError):
        lb_passphrase.unwrap(blob_silent)
    with pytest.raises(LockBoxError):
        lb_silent.unwrap(lb_passphrase.wrap(plain))

    with pytest.raises(KeyMaterialProtectionError, match="explicit recovery migration"):
        acquire_lockbox(tmp_path / "silent-install")
    monkeypatch.delenv("ONE_LINK_PASSPHRASE")
    assert acquire_lockbox(tmp_path / "silent-install").unwrap(blob_silent) == plain


def test_silent_drk_does_not_leak_in_cleartext_on_windows(tmp_path):
    """On Windows the on-disk DRK file must NOT contain the raw 32
    bytes — the daemon process holds the unwrapped key in memory,
    but DPAPI wrapping ensures stolen-disk attackers see only
    DPAPI-wrapped ciphertext."""
    import os
    from one_link.lockbox import (
        acquire_or_create_silent_drk, DRK_FILENAME,
    )
    if os.name != "nt":
        pytest.skip("DPAPI wrap is Windows-only")
    drk = acquire_or_create_silent_drk(tmp_path)
    on_disk = (tmp_path / DRK_FILENAME).read_bytes()
    assert drk not in on_disk, (
        "raw DRK leaked into the on-disk file; DPAPI wrap is not "
        "active or fell through to the raw-write path"
    )
