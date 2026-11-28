"""A hybrid public key received from a peer is checked before it is used."""

from __future__ import annotations

import pytest

from one_link import pqkem_native

pytestmark = pytest.mark.skipif(
    not pqkem_native.runtime_is_usable(), reason="native PQ KEM not available"
)

# An ML-KEM-768 encapsulation key is 1152 bytes of 12-bit coefficients (which
# must each be below q = 3329) followed by a 32-byte seed.
T_HAT_LEN = 1152
Q = 3329


def _public_bytes() -> bytes:
    public, _secret = pqkem_native.keypair()
    return bytes(public.to_bytes())


def _with_first_coefficient(raw: bytes, value: int) -> bytes:
    out = bytearray(raw)
    out[0] = value & 0xFF
    out[1] = (out[1] & 0xF0) | ((value >> 8) & 0x0F)
    return bytes(out)


def test_honest_key_round_trips_and_encapsulates() -> None:
    public, secret = pqkem_native.keypair()
    again = pqkem_native.public_key_from_bytes(bytes(public.to_bytes()))
    ciphertext, shared = pqkem_native.encapsulate(again)
    assert pqkem_native.decapsulate(secret, ciphertext) == shared


@pytest.mark.parametrize("value", [Q, Q + 1, 4095])
def test_key_with_an_unreduced_coefficient_is_rejected(value: int) -> None:
    forged = _with_first_coefficient(_public_bytes(), value)
    with pytest.raises(Exception, match="encapsulation key"):
        pqkem_native.public_key_from_bytes(forged)


def test_largest_legal_coefficient_is_accepted() -> None:
    edge = _with_first_coefficient(_public_bytes(), Q - 1)
    pqkem_native.public_key_from_bytes(edge)


def test_all_ones_key_is_rejected() -> None:
    with pytest.raises(Exception, match="encapsulation key"):
        pqkem_native.public_key_from_bytes(b"\xff" * pqkem_native.HYBRID_PUBLIC_KEY_LEN)


def test_seed_bytes_are_not_range_checked() -> None:
    raw = bytearray(_public_bytes())
    raw[T_HAT_LEN : T_HAT_LEN + 32] = b"\xff" * 32
    pqkem_native.public_key_from_bytes(bytes(raw))
