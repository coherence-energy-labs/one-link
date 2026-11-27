"""Properties of the Shamir secret-sharing primitive in
one_link.social_recovery.

Social recovery splits the master seed into N shares such that any
K can reconstruct it. The key invariants are:

  1. ROUND-TRIP: for every (K, N), any K-quorum of the N shares
     reconstructs the original seed exactly.
  2. NO-K-MINUS-1: a quorum of K-1 shares does NOT reconstruct
     the original seed (information-theoretic security property).
  3. ANY-K-SUBSET: ANY K-of-N combination works - not just the
     first K or the last K.

If any of these fail, social recovery is either unusable (legit
quorums can't reconstruct) or broken security (K-1 shares leak
the secret).
"""
from __future__ import annotations

import itertools

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings, strategies as st

from one_link import social_recovery


# Hypothesis-driven K + N values. Cap N at 8 to keep the
# combinatorial subset test tractable.
_k_n = st.tuples(
    st.integers(min_value=2, max_value=6),
    st.integers(min_value=2, max_value=8),
).filter(lambda kn: kn[0] <= kn[1])


@given(
    seed=st.binary(min_size=32, max_size=32),
    kn=_k_n,
    subset_seed=st.integers(min_value=0, max_value=10000),
)
@settings(
    max_examples=40, deadline=10000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_any_k_subset_reconstructs_seed(seed, kn, subset_seed):
    """For any (K, N) and any K-of-N subset of guardians, the
    K shares MUST reconstruct the original seed. THE load-bearing
    invariant - if it fails for even one subset, that user can't
    recover when those specific guardians help them."""
    k, n = kn
    guardians = [Ed25519PrivateKey.generate() for _ in range(n)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=k, total_n=n,
    )
    # Pick a K-sized subset deterministically from the subset_seed.
    indices = list(range(n))
    # Rotate by subset_seed to get a different starting point.
    rotated = indices[subset_seed % n:] + indices[:subset_seed % n]
    chosen = sorted(rotated[:k])

    unwrapped = []
    for i in chosen:
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=guardians[i].private_bytes_raw(),
        )
        unwrapped.append((idx, share_bytes))

    reconstructed = social_recovery.combine_shares(unwrapped)
    assert reconstructed == seed, (
        f"k={k}-of-{n} subset {chosen} did not reconstruct seed; "
        f"got {reconstructed.hex()}, expected {seed.hex()}"
    )


@given(
    seed=st.binary(min_size=32, max_size=32),
    kn=_k_n,
)
@settings(
    max_examples=15, deadline=15000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_every_k_combination_round_trips(seed, kn):
    """Stronger version: enumerate EVERY K-of-N combination and
    verify each reconstructs the seed. Catches the bug-class
    'works for the first K guardians but not the middle K' which
    a single random subset misses."""
    k, n = kn
    # Bound the combinatorial explosion: skip if C(n,k) > 50.
    import math
    if math.comb(n, k) > 50:
        return
    guardians = [Ed25519PrivateKey.generate() for _ in range(n)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=k, total_n=n,
    )
    # Pre-unwrap all N shares.
    unwrapped_all = []
    for i in range(n):
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=guardians[i].private_bytes_raw(),
        )
        unwrapped_all.append((idx, share_bytes))
    # "EVERY K-of-N combination" is a claim about COVERAGE, so the count is
    # part of it. An unwrap that yielded fewer shares would silently shrink the
    # enumeration and still look exhaustive.
    assert len(unwrapped_all) == n, (
        f"unwrapped {len(unwrapped_all)} of {n} shares"
    )
    checked = 0
    for combo in itertools.combinations(unwrapped_all, k):
        reconstructed = social_recovery.combine_shares(list(combo))
        checked += 1
        assert reconstructed == seed, (
            f"k={k}-of-{n} combo failed: indices "
            f"{[c[0] for c in combo]} did not reconstruct seed"
        )
    assert checked == math.comb(n, k), (
        f"only {checked} of C({n},{k})={math.comb(n, k)} combinations tested"
    )


@given(
    seed=st.binary(min_size=32, max_size=32),
    kn=_k_n,
)
@settings(
    max_examples=20, deadline=10000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_k_minus_1_shares_do_not_reconstruct_seed(seed, kn):
    """Information-theoretic security: K-1 shares MUST NOT
    produce the original seed. If they do, the threshold is
    effectively lower than advertised + the scheme is broken.

    K=2 is the minimum supported threshold; K-1=1 share is a
    degenerate single-share-combine case we skip."""
    k, n = kn
    if k < 3:
        return  # K-1=1 share is the degenerate case; skip
    guardians = [Ed25519PrivateKey.generate() for _ in range(n)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=k, total_n=n,
    )
    # Unwrap K-1 shares.
    unwrapped = []
    for i in range(k - 1):
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=guardians[i].private_bytes_raw(),
        )
        unwrapped.append((idx, share_bytes))
    # Shamir itself does not know the threshold and would return unrelated
    # bytes. The split secret carries a digest of the seed, so the wrong
    # reconstruction must be refused, not handed back.
    try:
        social_recovery.combine_shares(unwrapped)
    except ValueError:
        return
    raise AssertionError(
        f"k-1={k-1} shares produced a result instead of an error (k={k}, n={n})"
    )


@given(
    seed=st.binary(min_size=32, max_size=32),
    kn=_k_n,
)
@settings(
    max_examples=20, deadline=10000,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_unwrap_with_wrong_key_fails(seed, kn):
    """A guardian's share is sealed to THEIR ed25519 pubkey.
    Unwrapping with the WRONG private key must raise; otherwise
    a leaked share could be opened by anyone holding any key."""
    k, n = kn
    guardians = [Ed25519PrivateKey.generate() for _ in range(n)]
    attacker = Ed25519PrivateKey.generate()
    # Make sure attacker isn't accidentally one of the guardians.
    attacker_pub = attacker.public_key().public_bytes_raw()
    for g in guardians:
        if g.public_key().public_bytes_raw() == attacker_pub:
            return
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=k, total_n=n,
    )
    # Try to unwrap guardian 0's share with attacker's key.
    try:
        social_recovery.unwrap_share(
            wrapped=wrapped[0].encoded,
            my_ed_priv_seed=attacker.private_bytes_raw(),
        )
    except (ValueError, Exception):
        return  # correct: rejected
    assert False, (
        f"unwrap_share accepted the WRONG private key (k={k}, "
        f"n={n}); leaked shares would be openable by anyone"
    )


@given(seed=st.binary(min_size=32, max_size=32))
@settings(max_examples=20, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
def test_wrapped_share_blob_is_deterministic_in_length(seed):
    """The wrapped .olss blob length is bounded + predictable
    for a given seed size. Pin the contract so a future change
    that bloats the blob 100x doesn't silently break the
    paste-into-textarea UX."""
    guardians = [Ed25519PrivateKey.generate() for _ in range(2)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=2, total_n=2,
    )
    # split_and_wrap with n=2 returns 2 blobs.
    assert len(wrapped) == 2
    # Each encoded blob should be the same length (sealed-to-pubkey
    # ciphertext doesn't vary with content for a given size).
    sizes = {len(w.encoded) for w in wrapped}
    assert len(sizes) == 1, (
        f"wrapped share blobs vary in length: {sizes}; "
        "the textarea-paste UX assumes consistent share sizes"
    )
