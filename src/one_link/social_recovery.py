"""Social recovery — your social graph IS your recovery layer.

The 24-word BIP-39 phrase (master_seed + mnemonic) is the canonical
sovereignty backup: paper, in a drawer, restored by typing 24 words
on a new device. It works, but it has well-known UX failure modes:

  - The user doesn't write it down (most common failure, by far)
  - The user writes it down on the device they're backing up
    (defeats the purpose)
  - The user writes it down on a sticky note that gets thrown out
  - The paper is destroyed (fire, flood, divorce, child with crayon)

Social recovery is a complementary backup layer that uses the user's
existing trust graph (paired peers — friends, family, an old laptop
on the same network) instead of paper. It works like this:

  - SETUP: split the 32-byte master seed into 5 Shamir shares with
    threshold 3 (any 3 of 5 reconstruct the seed; 2 cannot). Each
    share is encrypted with a key derived from the recipient peer's
    Ed25519 identity, so only that specific peer can decrypt their
    share. Distribute the encrypted shares to 5 trusted contacts
    via the existing One Link channel — which the contacts already
    have because they're paired peers.

  - RECOVERY: on a fresh device, the user contacts 3 of their 5
    guardians (ideally in person). Each guardian's daemon decrypts
    their share with the guardian's private key and surrenders it
    via QR code (in-person flow, fully offline) or back over the
    channel (online flow). The recovering daemon collects 3 shares,
    runs Shamir combine, and reconstructs the original seed.

This combines well with the BIP-39 paper backup — they aren't
exclusive. A paranoid user runs both. A typical user runs social
recovery and skips the paper. The user is in charge.

Trust model
-----------

The user trusts that 3 of their 5 chosen guardians won't all collude
against them. With threshold 3-of-5, up to 2 malicious guardians
gain nothing (they can't reconstruct the seed without a third
honest share). Different from custodial recovery (Apple iCloud,
Google account) where ONE entity holds everything; here no single
guardian — and no single platform — can lock the user out.

Wire format for an encrypted share
----------------------------------

Each share that lands on a guardian's daemon is a self-describing
blob the guardian can store + ship later:

  ``OLSR1`` (5 bytes magic) + ``\\x01`` (version)
  + ``share_index`` (1 byte)              # 1..total
  + ``threshold`` (1 byte)                 # K (e.g. 3)
  + ``total`` (1 byte)                     # N (e.g. 5)
  + ``setup_ms`` (8 bytes BE)              # ts when share was minted
  + ``ephemeral_x25519_pub`` (32 bytes)    # for ECDH wrap
  + ``nonce`` (12 bytes)                   # AES-GCM IV
  + ``ciphertext+tag`` (dynamic)           # AES-GCM(ephemeral_dh, share_bytes)

Where ``share_bytes`` is the 32-byte share output of
``threshold.split`` over GF(256).

The wrap uses ECDH(ephemeral_x25519, contact_x25519_from_ed25519_pub)
→ HKDF-SHA256 → 32-byte AES-GCM key. The sender generates a fresh
ephemeral X25519 keypair per share, derives the shared secret, then
discards the ephemeral private. Forward-secrecy hygiene: a future
compromise of the sender's long-term key cannot decrypt any past
share that's still in a guardian's drawer.

The Ed25519 → X25519 conversion uses the standard Edwards-to-
Montgomery curve map (the same trick libsodium and Signal both
use): every Ed25519 public key has a unique X25519 equivalent
that produces the same X-coordinate as the Edwards point's
y-coordinate transformed via (1+y)/(1-y) mod p.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from one_link import threshold

# Row 9 wiring: use the native Rust Shamir implementation when
# available (45-84x faster reconstruct per F1.1 polish benches).
# Falls back to pure-Python `threshold` module if the native crate
# isn't installed.
try:
    from one_link import threshold_recovery_native as _native_tr

    _NATIVE_AVAILABLE = bool(_native_tr.HAS_NATIVE)
except ImportError:
    _NATIVE_AVAILABLE = False
    _native_tr = None  # type: ignore[assignment]


SHARE_MAGIC = b"OLSR1"
# Version 2 changes two things, both so that a recovery can tell when it has
# gone wrong:
#
#   * The Shamir secret is ``seed || check`` instead of the bare seed, where
#     ``check`` is a 16-byte digest of the seed. Shamir reconstruction always
#     returns *some* bytes: too few shares, shares from two different setups
#     or one damaged share used to produce a wrong seed that looked exactly
#     like a right one. Now the digest fails to match.
#   * Each wrapped share ends with the Ed25519 public key that created it and
#     that key's signature, so a guardian can see whose share it is holding
#     and a forged or altered share is refused before it is stored.
#
# Version 1 shares are still read. They reconstruct a bare seed that cannot
# be checked, and callers are told so.
SHARE_VERSION = 2
LEGACY_SHARE_VERSION = 1
SUPPORTED_SHARE_VERSIONS = (LEGACY_SHARE_VERSION, SHARE_VERSION)
CHECK_LEN = 16
CHECK_DOMAIN = b"OL/social-recovery/secret-check|v2"
SIGNATURE_DOMAIN = b"OL/social-recovery/share-signature|v2"
SIGNER_TRAILER_LEN = 32 + 64  # creator public key + signature
HEADER_LEN = 5 + 1 + 1 + 1 + 1 + 8 + 32 + 12  # 61 bytes
NONCE_LEN = 12
HKDF_INFO = b"OL/social-recovery/share-wrap|v1"
DEFAULT_THRESHOLD = 3
DEFAULT_TOTAL = 5
SEED_LEN = 32  # master seed bytes


@dataclass(frozen=True)
class WrappedShare:
    """A guardian-deliverable encrypted share. ``encoded`` is the
    bytes the guardian stores + ships; everything else is metadata
    parsed from the header for UX (display "share 2 of 5 from
    Alice's iPad")."""
    share_index: int
    threshold: int
    total: int
    setup_ms: int
    encoded: bytes
    #: Ed25519 public key that created and signed the share. ``None`` for a
    #: version 1 share, which carries no signature.
    creator_ed_pub: Optional[bytes] = None

    @property
    def version(self) -> int:
        return self.encoded[5]

    @classmethod
    def parse(cls, blob: bytes) -> "WrappedShare":
        """Parse a wrapped share and, for version 2, verify its signature.

        The AEAD tag is not checked here; that needs the guardian's private
        key and happens in :func:`unwrap_share`.
        """
        if len(blob) < HEADER_LEN:
            raise ValueError(
                f"share too short: {len(blob)} < {HEADER_LEN}"
            )
        if blob[:5] != SHARE_MAGIC:
            raise ValueError("not a One Link social-recovery share (bad magic)")
        if blob[5] not in SUPPORTED_SHARE_VERSIONS:
            raise ValueError(f"unsupported share version {blob[5]}")
        share_index = blob[6]
        threshold_k = blob[7]
        total_n = blob[8]
        setup_ms = struct.unpack(">Q", blob[9:17])[0]
        creator = None
        if blob[5] == SHARE_VERSION:
            _body, creator = _verify_share_signature(blob)
        return cls(
            share_index=share_index,
            threshold=threshold_k,
            total=total_n,
            setup_ms=setup_ms,
            encoded=blob,
            creator_ed_pub=creator,
        )


def _secret_check(seed: bytes) -> bytes:
    return hashlib.sha256(CHECK_DOMAIN + seed).digest()[:CHECK_LEN]


def _verify_share_signature(blob: bytes) -> tuple[bytes, bytes]:
    """Split a version 2 share into ``(header + ciphertext, creator_pub)``.

    Raises ``ValueError`` unless the trailer's signature verifies under the
    trailer's own public key. That proves the share was not altered after
    its creator signed it; whether that creator is who the guardian thinks
    it is, the guardian decides by comparing the key with the owner's.
    """
    if len(blob) < HEADER_LEN + 16 + SIGNER_TRAILER_LEN:
        raise ValueError("signed share too short")
    body = blob[:-SIGNER_TRAILER_LEN]
    creator = blob[-SIGNER_TRAILER_LEN:-64]
    signature = blob[-64:]
    try:
        Ed25519PublicKey.from_public_bytes(creator).verify(
            signature, SIGNATURE_DOMAIN + creator + body
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("share signature is invalid; the share was altered or forged") from exc
    return body, creator


# ── Ed25519 → X25519 conversion ──────────────────────────────────────
#
# Every Ed25519 keypair has a deterministic X25519 equivalent. The
# *public* key conversion is the Edwards-to-Montgomery `u = (1+y)/(1-y)
# mod p` formula on Curve25519. The *private* key conversion derives
# the X25519 secret from the SHA-512 hash of the Ed25519 secret seed
# and applies RFC 7748 clamping. This lets a peer use one keypair
# for both signatures (Ed25519) and key agreement (X25519) without
# storing a second private key.
#
# Reference: libsodium ``crypto_sign_ed25519_pk_to_curve25519`` +
# ``crypto_sign_ed25519_sk_to_curve25519``. Pure Python here so we
# don't add a libsodium dep.


_P25519 = 2**255 - 19


def _modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


def ed25519_pub_to_x25519(ed_pub: bytes) -> bytes:
    """Map an Ed25519 32-byte public key to its X25519 equivalent.

    The Ed25519 public key encodes a point ``(x, y)`` on the twisted
    Edwards curve as ``y || sign-bit-of-x``. The X25519 (Montgomery)
    u-coordinate of the equivalent point is ``(1 + y) / (1 - y) mod p``
    (the birational map between the two curve forms)."""
    if len(ed_pub) != 32:
        raise ValueError("ed_pub must be 32 bytes")
    # Decode y (little-endian). The high bit is the sign of x — we
    # don't need the x sign for the u-coordinate map; mask it off.
    y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)
    # u = (1 + y) / (1 - y) mod p
    one_plus_y = (1 + y) % _P25519
    one_minus_y = (1 - y) % _P25519
    u = (one_plus_y * _modinv(one_minus_y, _P25519)) % _P25519
    return u.to_bytes(32, "little")


def ed25519_priv_to_x25519(ed_priv_seed: bytes) -> bytes:
    """Derive the X25519 32-byte private key from an Ed25519 32-byte
    private SEED (the value passed to Ed25519PrivateKey.from_private_bytes).

    Per libsodium's convention: take SHA-512 of the seed, keep the
    first 32 bytes, apply RFC 7748 clamping (clear bit 0,1,2 of byte
    0; clear bit 7 of byte 31; set bit 6 of byte 31)."""
    if len(ed_priv_seed) != 32:
        raise ValueError("ed_priv_seed must be 32 bytes")
    import hashlib
    digest = hashlib.sha512(ed_priv_seed).digest()[:32]
    hb = bytearray(digest)
    hb[0] &= 248
    hb[31] &= 127
    hb[31] |= 64
    return bytes(hb)


# ── share wrap / unwrap ──────────────────────────────────────────────


def _derive_aead_key(shared: bytes, *, info_extra: bytes = b"") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO + info_extra,
    ).derive(shared)


def split_and_wrap(
    *,
    seed: bytes,
    contact_ed_pubs: list[bytes],
    threshold_k: int = DEFAULT_THRESHOLD,
    total_n: int = DEFAULT_TOTAL,
    setup_ms: Optional[int] = None,
    signing_key: Optional[Ed25519PrivateKey] = None,
) -> list[WrappedShare]:
    """Split ``seed`` into Shamir shares + encrypt each share to one
    contact's Ed25519 identity. Returns ``total_n`` WrappedShare
    objects ready to ship to the corresponding contact.

    ``contact_ed_pubs`` MUST have length ``total_n``. The share at
    index i is wrapped for contact_ed_pubs[i].

    Every share is signed. ``signing_key`` defaults to the identity key the
    seed itself derives, so the same key that a successful recovery restores
    is the one guardians see as the creator.
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    if not (2 <= threshold_k <= total_n <= 255):
        raise ValueError(
            f"invalid threshold_k={threshold_k} / total_n={total_n} "
            "(need 2 ≤ k ≤ n ≤ 255)"
        )
    if len(contact_ed_pubs) != total_n:
        raise ValueError(
            f"contact_ed_pubs length {len(contact_ed_pubs)} != total_n {total_n}"
        )
    for i, p in enumerate(contact_ed_pubs):
        if not isinstance(p, (bytes, bytearray)) or len(p) != 32:
            raise ValueError(f"contact_ed_pubs[{i}] must be 32 bytes")
    if len({bytes(p) for p in contact_ed_pubs}) != total_n:
        # Two shares for one guardian would let fewer than k people recover.
        raise ValueError("contact_ed_pubs must not repeat a guardian")
    if setup_ms is None:
        setup_ms = int(time.time() * 1000)
    if signing_key is None:
        from one_link import master_seed

        signing_key = master_seed.derive_identity_priv(bytes(seed))
    creator_pub = signing_key.public_key().public_bytes_raw()

    # What is split is the seed followed by a digest of the seed, so that a
    # reconstruction can be recognised as right or wrong.
    secret = bytes(seed) + _secret_check(bytes(seed))

    # Row 9 wiring: prefer the native Rust Shamir impl when available
    # (45-84x faster reconstruct). Both paths produce the same share
    # bytes for the same secret + the same set of x-values.
    if _NATIVE_AVAILABLE:
        native_shares = _native_tr.split_compat(
            secret, threshold=threshold_k, num_shares=total_n
        )
        raw_shares = [
            threshold.Share(x=x, y=y) for x, y in native_shares
        ]
    else:
        raw_shares = threshold.split(
            secret=secret, threshold=threshold_k, num_shares=total_n,
        )
    out: list[WrappedShare] = []
    for i, share in enumerate(raw_shares):
        share_idx = share.x
        share_bytes = share.y
        contact_ed_pub = bytes(contact_ed_pubs[i])
        contact_x_pub = ed25519_pub_to_x25519(contact_ed_pub)
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key().public_bytes_raw()
        try:
            shared = eph_priv.exchange(
                X25519PublicKey.from_public_bytes(contact_x_pub),
            )
        except Exception as e:
            raise ValueError(
                f"contact_ed_pubs[{i}] is not a valid Ed25519→X25519 "
                f"convertible pubkey: {e}"
            ) from None
        if shared == b"\x00" * 32:
            raise ValueError(
                f"contact_ed_pubs[{i}] yielded zero shared secret "
                "(small-order point); refuse to wrap"
            )
        key = _derive_aead_key(shared)
        nonce = secrets.token_bytes(NONCE_LEN)
        header = (
            SHARE_MAGIC
            + bytes([SHARE_VERSION, share_idx, threshold_k, total_n])
            + struct.pack(">Q", setup_ms)
            + eph_pub
            + nonce
        )
        # Plaintext is the full Shamir output: 1-byte index + share bytes.
        # We re-include the index inside the AEAD so a guardian can't
        # be tricked into shipping a renumbered share.
        plaintext = bytes([share_idx]) + share_bytes
        # The creator's key is part of the associated data, so the trailer
        # cannot be replaced with another key's signature over the same
        # ciphertext: the share would no longer decrypt.
        ct = AESGCM(key).encrypt(nonce, plaintext, header + creator_pub)
        body = header + ct
        signature = signing_key.sign(SIGNATURE_DOMAIN + creator_pub + body)
        encoded = body + creator_pub + signature
        out.append(WrappedShare(
            share_index=share_idx,
            threshold=threshold_k,
            total=total_n,
            setup_ms=setup_ms,
            encoded=encoded,
            creator_ed_pub=creator_pub,
        ))
    return out


def unwrap_share(
    *,
    wrapped: bytes,
    my_ed_priv_seed: bytes,
) -> tuple[int, bytes]:
    """Decrypt a wrapped share with the recipient's Ed25519 private
    seed. Returns ``(share_index, share_bytes)`` ready to feed back
    into ``threshold.combine`` along with K-1 other shares.

    Raises ValueError on tamper, wrong key, or version mismatch."""
    if len(my_ed_priv_seed) != 32:
        raise ValueError("my_ed_priv_seed must be 32 bytes")
    if len(wrapped) < HEADER_LEN + 16:  # +16 for AEAD tag minimum
        raise ValueError("wrapped share too short")
    if wrapped[:5] != SHARE_MAGIC:
        raise ValueError("not a One Link social-recovery share")
    if wrapped[5] not in SUPPORTED_SHARE_VERSIONS:
        raise ValueError(f"unsupported version {wrapped[5]}")
    aad_suffix = b""
    if wrapped[5] == SHARE_VERSION:
        wrapped, aad_suffix = _verify_share_signature(wrapped)
    share_idx = wrapped[6]
    threshold_k = wrapped[7]
    total_n = wrapped[8]
    setup_ms = struct.unpack(">Q", wrapped[9:17])[0]
    eph_pub = wrapped[17:49]
    nonce = wrapped[49:61]
    ct = wrapped[HEADER_LEN:]
    header = wrapped[:HEADER_LEN]

    my_x_priv_bytes = ed25519_priv_to_x25519(my_ed_priv_seed)
    my_x_priv = X25519PrivateKey.from_private_bytes(my_x_priv_bytes)
    try:
        shared = my_x_priv.exchange(
            X25519PublicKey.from_public_bytes(eph_pub),
        )
    except Exception as e:
        raise ValueError(f"shared-secret derive failed: {e}") from None
    if shared == b"\x00" * 32:
        raise ValueError("ECDH yielded zero shared secret")
    key = _derive_aead_key(shared)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, header + aad_suffix)
    except Exception as e:
        raise ValueError(
            f"share decrypt failed (wrong key or tamper): {e}"
        ) from None
    if len(plaintext) < 1 + 1:  # share_idx + at least 1 byte of payload
        raise ValueError("decrypted share too short")
    inner_idx = plaintext[0]
    if inner_idx != share_idx:
        raise ValueError(
            f"AEAD-bound share index mismatch: header says {share_idx}, "
            f"plaintext says {inner_idx}"
        )
    share_bytes = plaintext[1:]
    return inner_idx, share_bytes


class UnverifiableSharesError(ValueError):
    """Version 1 shares reconstructed a seed that cannot be checked."""


def combine_shares_checked(shares: list[tuple[int, bytes]]) -> tuple[bytes, bool]:
    """Reconstruct the seed and say whether the result is proven correct.

    Each tuple is ``(share_index, share_bytes)``, the shape
    :func:`unwrap_share` returns. Returns ``(seed, verified)``.

    ``verified`` is ``True`` for version 2 shares, whose secret carries a
    digest of the seed: a wrong reconstruction (too few shares, shares from
    different setups, a damaged share) raises ``ValueError`` instead of
    returning. It is ``False`` for version 1 shares, which reconstruct a
    bare seed with nothing to check it against; the caller must confirm the
    result some other way before relying on it.
    """
    if not shares:
        raise ValueError("need at least one share")
    indexes = [int(idx) for idx, _payload in shares]
    if len(set(indexes)) != len(indexes):
        raise ValueError("the same share was supplied more than once")
    lengths = {len(payload) for _idx, payload in shares}
    if len(lengths) != 1:
        raise ValueError("shares have different lengths; they are from different setups")
    # Row 9 wiring: uses the native Rust Shamir reconstruct when
    # available (45-84x faster than pure-Python per F1.1 benches).
    if _NATIVE_AVAILABLE:
        share_tuples = [(int(idx), bytes(payload)) for idx, payload in shares]
        secret = _native_tr.combine_compat(share_tuples, threshold=len(shares))
    else:
        threshold_shares = [
            threshold.Share(x=int(idx), y=bytes(payload))
            for idx, payload in shares
        ]
        secret = threshold.combine(threshold_shares)
    if len(secret) == SEED_LEN + CHECK_LEN:
        seed, check = secret[:SEED_LEN], secret[SEED_LEN:]
        if not hmac.compare_digest(check, _secret_check(seed)):
            raise ValueError(
                "these shares do not reconstruct the original seed: there are "
                "fewer of them than the threshold, they come from different "
                "setups, or one of them is damaged"
            )
        return seed, True
    if len(secret) == SEED_LEN:
        return secret, False
    raise ValueError(
        f"reconstructed secret has wrong length {len(secret)}; "
        f"expected {SEED_LEN}. Did you mix shares from different "
        "setups?"
    )


def combine_shares(
    shares: list[tuple[int, bytes]], *, allow_unverified: bool = False
) -> bytes:
    """Reconstruct the original seed from K shares.

    Raises :class:`UnverifiableSharesError` for version 1 shares unless
    ``allow_unverified`` is set, because their result cannot be told apart
    from a wrong one. See :func:`combine_shares_checked`.
    """
    seed, verified = combine_shares_checked(shares)
    if not verified and not allow_unverified:
        raise UnverifiableSharesError(
            "these shares were created by an older version and carry no "
            "integrity check, so a wrong result cannot be detected"
        )
    return seed


# ── high-level recovery flow helpers ─────────────────────────────────


def setup_social_recovery(
    *,
    seed: bytes,
    guardians: list[tuple[str, bytes]],
    threshold_k: int = DEFAULT_THRESHOLD,
    signing_key: Optional[Ed25519PrivateKey] = None,
) -> list[tuple[str, WrappedShare]]:
    """Convenience: pair guardians (display_name, ed_pub) with their
    respective wrapped shares. Returns ``[(display_name, WrappedShare),
    ...]`` in input order — caller delivers each pair to its named
    guardian via whatever transport (channel, QR, USB stick, sky-
    writing — the wrap is sealed; the medium doesn't matter)."""
    total_n = len(guardians)
    pubs = [pub for _, pub in guardians]
    shares = split_and_wrap(
        seed=seed,
        contact_ed_pubs=pubs,
        threshold_k=threshold_k,
        total_n=total_n,
        signing_key=signing_key,
    )
    return [(name, share) for (name, _pub), share in zip(guardians, shares)]


def reconstruct_from_decrypted_shares(
    decrypted: list[tuple[int, bytes]],
) -> bytes:
    """Final step in the recovery ceremony: K guardians each shipped
    their decrypted (share_index, share_bytes) tuple back to the
    recovering device; combine them into the original seed."""
    return combine_shares(decrypted)
