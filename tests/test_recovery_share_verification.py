"""Share recovery refuses a result it cannot prove is the original seed."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import recovery_api, threshold
from one_link import social_recovery as sr
from one_link.identity import fingerprint_of


def _guardian() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _setup(k: int = 3, n: int = 5):
    seed = os.urandom(32)
    guardians = [_guardian() for _ in range(n)]
    wrapped = sr.split_and_wrap(
        seed=seed, contact_ed_pubs=[g[1] for g in guardians], threshold_k=k, total_n=n
    )
    opened = [
        sr.unwrap_share(wrapped=w.encoded, my_ed_priv_seed=g[0])
        for w, g in zip(wrapped, guardians)
    ]
    return seed, wrapped, opened


def _dir_is_untouched(path: Path) -> bool:
    return not any(path.iterdir())


def test_precheck_passes_for_a_full_threshold(tmp_path: Path) -> None:
    _seed, _wrapped, opened = _setup()
    result = recovery_api.test_shares_against_current_seed(data_dir=tmp_path, shares=opened[:3])
    assert result["valid_recovery"] is True
    assert result["integrity_verified"] is True
    assert result["unverifiable_legacy_shares"] is False
    assert result["error"] == ""


def test_precheck_fails_below_the_threshold(tmp_path: Path) -> None:
    _seed, _wrapped, opened = _setup()
    result = recovery_api.test_shares_against_current_seed(data_dir=tmp_path, shares=opened[:2])
    # Two of three used to report valid_recovery: True for garbage.
    assert result["valid_recovery"] is False
    assert "do not reconstruct the original seed" in result["error"]


def test_precheck_fails_for_shares_from_two_setups(tmp_path: Path) -> None:
    _a, _wa, opened_a = _setup()
    _b, _wb, opened_b = _setup()
    mixed = [opened_a[0], opened_a[1], opened_b[2]]
    result = recovery_api.test_shares_against_current_seed(data_dir=tmp_path, shares=mixed)
    assert result["valid_recovery"] is False


def test_precheck_flags_legacy_shares_as_unverifiable(tmp_path: Path) -> None:
    seed = os.urandom(32)
    legacy = [(s.x, s.y) for s in threshold.split(secret=seed, threshold=3, num_shares=5)]
    result = recovery_api.test_shares_against_current_seed(data_dir=tmp_path, shares=legacy[:3])
    assert result["valid_recovery"] is False
    assert result["unverifiable_legacy_shares"] is True
    assert "no integrity check" in result["error"]


def test_restore_stages_nothing_for_a_wrong_reconstruction(tmp_path: Path) -> None:
    _seed, _wrapped, opened = _setup()
    with pytest.raises(ValueError, match="do not reconstruct the original seed"):
        recovery_api.restore_from_shares(
            data_dir=tmp_path, shares=opened[:2], delete_identity_files=False
        )
    assert _dir_is_untouched(tmp_path)


def test_restore_refuses_legacy_shares_unless_told_otherwise(tmp_path: Path) -> None:
    seed = os.urandom(32)
    legacy = [(s.x, s.y) for s in threshold.split(secret=seed, threshold=3, num_shares=5)]
    with pytest.raises(sr.UnverifiableSharesError):
        recovery_api.restore_from_shares(
            data_dir=tmp_path, shares=legacy[:3], delete_identity_files=False
        )
    assert _dir_is_untouched(tmp_path)


def test_guardian_can_see_who_created_a_share() -> None:
    from one_link import master_seed

    seed, wrapped, _opened = _setup()
    owner = master_seed.derive_identity_priv(seed).public_key().public_bytes_raw()
    assert recovery_api.held_share_creator_fingerprint(wrapped[0].encoded) == fingerprint_of(owner)
    parsed = recovery_api.parse_held_share_blob(wrapped[0].encoded)
    assert parsed["threshold_k"] == 3 and parsed["total_n"] == 5


def test_forged_share_cannot_be_imported() -> None:
    _seed, wrapped, _opened = _setup()
    blob = bytearray(wrapped[0].encoded)
    blob[-1] ^= 0x01
    with pytest.raises(ValueError, match="signature is invalid"):
        recovery_api.parse_held_share_blob(bytes(blob))
