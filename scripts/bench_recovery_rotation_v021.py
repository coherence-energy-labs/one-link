"""Micro-benchmarks for v0.21.x recovery + rotation primitives.

Pins the per-op cost on every cryptographic + state-cascade path
shipped in the 32-commit Phase D chain. Mirrors the structure of
scripts/bench_audit_2026_05_21.py so the same reproducibility +
output shape applies.

Reported surfaces:

  Cryptographic primitives
  ------------------------
  * mint_certificate            — Ed25519 sign over canonical JSON.
  * verify_certificate          — Ed25519 verify + schema check.
  * apply_certificate_to_peer   — verify + chain/replay checks.
  * mnemonic.encode             — 32 bytes -> 24 words + SHA-256 checksum.
  * mnemonic.decode             — 24 words -> 32 bytes + checksum verify.
  * backup_bundle.create_bundle — gzip + AES-GCM encrypt of a small tar.
  * backup_bundle.open_bundle   — AES-GCM decrypt + length check.

  Social-recovery primitives
  --------------------------
  * social_recovery.split_and_wrap — Shamir(K,N) + N ECDH wraps.
  * social_recovery.unwrap_share   — ECDH unwrap + AEAD decrypt.
  * social_recovery.combine_shares — Shamir combine of K shares.

  State cascade (the load-bearing piece)
  --------------------------------------
  * transition_peer_fingerprint — cascade across 15+ peer-keyed tables.

  Non-destructive verification (user-facing latency)
  --------------------------------------------------
  * test_phrase_against_current_seed
  * test_bundle_against_phrase

Run: python scripts/bench_recovery_rotation_v021.py

The benchmark is dependency-light + deterministic. Reference
numbers go in PHASE_D_RECOVERY_BENCHMARKS.md once captured.
"""
from __future__ import annotations

import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

# Force UTF-8 stdout so an exception whose str() carries a non-cp1252
# glyph (e.g. social_recovery's "k <= n <= 255" with a real <= sign)
# does not crash the bench printer on Windows consoles.
import contextlib as _contextlib
with _contextlib.suppress(Exception):
    stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(stdout_reconfigure):
        stdout_reconfigure(encoding="utf-8", errors="replace")

# Add src/ so we can run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _bench(name: str, fn: Callable[[], object], iters: int = 1_000) -> dict:
    """Run fn iters times in a tight loop, repeat 5 times for
    median and worst batch-average. Defaults to fewer iters than the audit bench
    because some of these primitives (Shamir wrap of 5 guardians)
    cost orders of magnitude more per op."""
    if iters < 1:
        raise ValueError("iters must be positive")
    # Warmup so per-op caches are hot.
    for _ in range(min(50, iters)):
        fn()
    durations: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter_ns()
        for _ in range(iters):
            fn()
        t1 = time.perf_counter_ns()
        durations.append((t1 - t0) / iters)
    median = statistics.median(durations)
    worst_batch_average = max(durations)
    return {
        "name": name,
        "iters": iters,
        "ns_per_op_median": median,
        "ns_per_op_worst_batch_average": worst_batch_average,
        "batch_mean_ns_per_op_samples": durations,
        "sample_kind": "batch means; not individual-operation tail latency",
        "ops_per_sec_median": 1e9 / median if median > 0 else float("inf"),
    }


# ── cryptographic primitives ────────────────────────────────────────


def _bench_mint_certificate() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import identity_rotation
    old_priv = Ed25519PrivateKey.generate()
    new_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    counter = {"i": 0}

    def step() -> None:
        # ts varies so the canonical bytes vary; otherwise the
        # signature is deterministic + cached at lower layers.
        identity_rotation.mint_certificate(
            old_priv=old_priv, new_pub=new_pub, ts_ms=counter["i"],
        )
        counter["i"] += 1

    return _bench("mint_certificate", step, iters=500)


def _bench_verify_certificate() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import identity_rotation
    old_priv = Ed25519PrivateKey.generate()
    new_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = identity_rotation.mint_certificate(old_priv=old_priv, new_pub=new_pub)
    old_pub_bytes = old_priv.public_key().public_bytes_raw()

    def step() -> None:
        identity_rotation.verify_certificate(
            cert=cert, expected_old_pubkey=old_pub_bytes,
        )

    return _bench("verify_certificate", step, iters=1_000)


def _bench_apply_certificate_to_peer() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import identity_rotation
    old_priv = Ed25519PrivateKey.generate()
    new_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = identity_rotation.mint_certificate(old_priv=old_priv, new_pub=new_pub)
    old_pub_bytes = old_priv.public_key().public_bytes_raw()

    def step() -> None:
        identity_rotation.apply_certificate_to_peer(
            cert=cert,
            expected_old_pubkey=old_pub_bytes,
            current_pinned_fp=cert.old_fp,
        )

    return _bench("apply_certificate_to_peer", step, iters=1_000)


def _bench_mnemonic_encode() -> dict:
    from one_link import mnemonic
    seeds = [os.urandom(32) for _ in range(50)]
    counter = {"i": 0}

    def step() -> None:
        mnemonic.encode(seeds[counter["i"] % len(seeds)])
        counter["i"] += 1

    return _bench("mnemonic.encode", step, iters=2_000)


def _bench_mnemonic_decode() -> dict:
    from one_link import mnemonic
    phrases = [mnemonic.encode(os.urandom(32)) for _ in range(50)]
    counter = {"i": 0}

    def step() -> None:
        mnemonic.decode(phrases[counter["i"] % len(phrases)])
        counter["i"] += 1

    return _bench("mnemonic.decode", step, iters=2_000)


def _bench_backup_bundle_create() -> dict:
    """Create a small (~2 KiB plaintext) backup bundle. Real bundles
    are typically tens of KiB; this isolates the AEAD + gzip cost
    on a representative tiny case."""
    from one_link import backup_bundle
    tmp = Path(tempfile.mkdtemp(prefix="ol_bench_create_"))
    try:
        (tmp / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(1024))
        (tmp / "master.seed").write_bytes(os.urandom(32))
        seed = os.urandom(32)

        def step() -> None:
            backup_bundle.create_bundle(seed=seed, data_dir=tmp)

        return _bench("backup_bundle.create_bundle (~1KB)", step, iters=500)
    finally:
        with _contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def _bench_backup_bundle_open() -> dict:
    """Open + decrypt a pre-built bundle. AES-GCM verify + length
    check are the dominant cost."""
    from one_link import backup_bundle
    tmp = Path(tempfile.mkdtemp(prefix="ol_bench_open_"))
    try:
        (tmp / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(1024))
        (tmp / "master.seed").write_bytes(os.urandom(32))
        seed = os.urandom(32)
        bundle = backup_bundle.create_bundle(seed=seed, data_dir=tmp)

        def step() -> None:
            backup_bundle.open_bundle(seed=seed, bundle_bytes=bundle)

        return _bench("backup_bundle.open_bundle", step, iters=500)
    finally:
        with _contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ── social recovery ─────────────────────────────────────────────────


def _bench_split_and_wrap_3_of_5() -> dict:
    """Shamir(3,5) + 5 ECDH wraps. The 5 wraps dominate."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import social_recovery
    seed = os.urandom(32)
    guardian_pubs = [
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for _ in range(5)
    ]

    def step() -> None:
        social_recovery.split_and_wrap(
            seed=seed, contact_ed_pubs=guardian_pubs,
            threshold_k=3, total_n=5,
        )

    return _bench("social_recovery.split_and_wrap (3-of-5)", step, iters=100)


def _bench_unwrap_share() -> dict:
    """One ECDH unwrap + AEAD decrypt + 32-byte plaintext check.
    Uses a 2-of-2 split so split_and_wrap's k>=2 invariant holds;
    we then time unwrap of share[0] only."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import social_recovery
    seed = os.urandom(32)
    guardian = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[
            guardian.public_key().public_bytes_raw(),
            other.public_key().public_bytes_raw(),
        ],
        threshold_k=2, total_n=2,
    )
    blob = wrapped[0].encoded
    priv_seed = guardian.private_bytes_raw()

    def step() -> None:
        social_recovery.unwrap_share(
            wrapped=blob, my_ed_priv_seed=priv_seed,
        )

    return _bench("social_recovery.unwrap_share", step, iters=500)


def _bench_combine_shares_3_of_5() -> dict:
    """Shamir combine of 3 shares from a 3-of-5 split."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link import social_recovery
    seed = os.urandom(32)
    guardians = [Ed25519PrivateKey.generate() for _ in range(5)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=3, total_n=5,
    )
    # Pre-unwrap 3 shares so the bench only times the combine.
    unwrapped = [
        social_recovery.unwrap_share(
            wrapped=w.encoded, my_ed_priv_seed=g.private_bytes_raw(),
        )
        for w, g in list(zip(wrapped, guardians))[:3]
    ]

    def step() -> None:
        social_recovery.combine_shares(unwrapped)

    return _bench("social_recovery.combine_shares (3-of-5)", step, iters=500)


# ── state cascade ───────────────────────────────────────────────────


def _bench_transition_peer_fingerprint() -> dict:
    """Atomic cascade across every peer-keyed table. Per-call cost
    is dominated by the SQLite UPDATE across 15+ tables in one
    transaction. The benchmark prepares a fresh peer + ping-pongs
    its fingerprint between two values so we measure steady-state
    cost rather than first-call schema warmup."""
    from one_link.state import State
    tmp = Path(tempfile.mkdtemp(prefix="ol_bench_xition_"))
    state = State(tmp / "bench.db")
    try:
        fp_a = "aa" * 32
        fp_b = "bb" * 32
        pubkey_a = b"\x01" * 32
        pubkey_b = b"\x02" * 32
        state.upsert_peer(
            fingerprint=fp_a, short_id="bench",
            pubkey=pubkey_a, hostname="bench.lan",
        )
        state.set_peer_trust(fp_a, "pinned")
        cur = {"current_fp": fp_a, "current_pub": pubkey_a}

        def step() -> None:
            if cur["current_fp"] == fp_a:
                state.transition_peer_fingerprint(
                    old_fp=fp_a, new_fp=fp_b, new_pubkey=pubkey_b,
                )
                cur["current_fp"] = fp_b
                cur["current_pub"] = pubkey_b
            else:
                state.transition_peer_fingerprint(
                    old_fp=fp_b, new_fp=fp_a, new_pubkey=pubkey_a,
                )
                cur["current_fp"] = fp_a
                cur["current_pub"] = pubkey_a

        return _bench("transition_peer_fingerprint", step, iters=200)
    finally:
        # SQLite on Windows holds the file open until close(); skip
        # the auto-cleanup TemporaryDirectory path that races us.
        with _contextlib.suppress(Exception):
            state.close()
        with _contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ── non-destructive verification ────────────────────────────────────


def _bench_test_phrase_against_current_seed() -> dict:
    from one_link import master_seed, mnemonic, recovery_api
    tmp = Path(tempfile.mkdtemp(prefix="ol_bench_phrase_"))
    try:
        seed = master_seed.load_or_create_seed(tmp)[0]
        phrase = mnemonic.encode(seed)

        def step() -> None:
            recovery_api.test_phrase_against_current_seed(
                data_dir=tmp, phrase=phrase,
            )

        return _bench("test_phrase_against_current_seed", step, iters=200)
    finally:
        with _contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def _bench_test_bundle_against_phrase() -> dict:
    from one_link import backup_bundle, mnemonic, recovery_api
    tmp = Path(tempfile.mkdtemp(prefix="ol_bench_bundle_test_"))
    try:
        (tmp / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(1024))
        (tmp / "master.seed").write_bytes(os.urandom(32))
        seed = (tmp / "master.seed").read_bytes()
        phrase = mnemonic.encode(seed)
        bundle = backup_bundle.create_bundle(seed=seed, data_dir=tmp)

        def step() -> None:
            recovery_api.test_bundle_against_phrase(
                phrase=phrase, bundle_bytes=bundle,
            )

        return _bench("test_bundle_against_phrase", step, iters=500)
    finally:
        with _contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ── entrypoint ──────────────────────────────────────────────────────


def main() -> int:
    benchmarks = [
        _bench_mint_certificate,
        _bench_verify_certificate,
        _bench_apply_certificate_to_peer,
        _bench_mnemonic_encode,
        _bench_mnemonic_decode,
        _bench_backup_bundle_create,
        _bench_backup_bundle_open,
        _bench_split_and_wrap_3_of_5,
        _bench_unwrap_share,
        _bench_combine_shares_3_of_5,
        _bench_transition_peer_fingerprint,
        _bench_test_phrase_against_current_seed,
        _bench_test_bundle_against_phrase,
    ]
    print("v0.21.x recovery + rotation primitives")
    print(f"{'name':<46} {'ns/op (med)':>14} {'worst batch avg':>14} {'ops/sec':>14}")
    print("-" * 92)
    results: list[dict] = []
    for b in benchmarks:
        try:
            r = b()
        except Exception as exc:
            print(f"{b.__name__:<46} FAILED: {exc}")
            continue
        results.append(r)
        print(
            f"{r['name']:<46}"
            f" {r['ns_per_op_median']:>14,.0f}"
            f" {r['ns_per_op_worst_batch_average']:>14,.0f}"
            f" {r['ops_per_sec_median']:>14,.0f}"
        )
    # JSON dump for regression tracking.
    import json
    out_path = Path("bench_recovery_rotation_v021.json")
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nJSON written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
