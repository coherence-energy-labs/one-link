//! Duress gate: passphrase → volume unlock + covert signaling.

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of a volume secret.
pub const VOLUME_SECRET_LEN: usize = 32;
/// Length of the covert duress signal embedded in ratchet headers.
pub const SIGNAL_LEN: usize = 32;

/// Errors the duress gate's `open()` can produce.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GateError {
    /// Presented passphrase matched neither the real check-hash nor
    /// the duress check-hash. No volume unlocked, no covert signal.
    #[error("passphrase did not match real or duress key")]
    Rejected,
    /// Empty passphrase or other invalid input shape.
    #[error("invalid input length")]
    InvalidInput,
}

/// A 32-byte volume secret (key material). Zeroized on drop.
pub type Volume = Zeroizing<[u8; VOLUME_SECRET_LEN]>;

/// Outcome of [`DuressGate::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuressOutcome {
    /// Real-key path; nothing covertly signaled.
    Real(Volume),
    /// Duress-key path; caller MUST embed `covert_signal` in the
    /// next ratchet header so paired peers see the coercion event.
    Duress {
        /// The decoy volume secret. Looks identical-on-the-wire to
        /// the real volume secret.
        volume: Volume,
        /// 32-byte covert signal the caller MUST embed in the next
        /// ratchet header so paired peers detect the coercion event.
        covert_signal: [u8; SIGNAL_LEN],
    },
}

/// Stateless gate that classifies a presented passphrase. Holds the
/// per-account roots: `real_root` + `duress_root` + a paired-secret used
/// to derive covert signals that only paired peers can decode.
#[derive(Debug, Clone)]
pub struct DuressGate {
    real_root: [u8; 32],
    duress_root: [u8; 32],
    pair_secret: [u8; 32],
}

impl DuressGate {
    /// Build a gate from three independent 32-byte secrets:
    ///
    /// - `real_root` — derives the real volume's key from a presented
    ///   passphrase.
    /// - `duress_root` — derives the decoy volume's key from a presented
    ///   passphrase.
    /// - `pair_secret` — derives the covert "I am under coercion"
    ///   signal that paired peers can verify.
    #[must_use]
    pub fn new(real_root: [u8; 32], duress_root: [u8; 32], pair_secret: [u8; 32]) -> Self {
        Self {
            real_root,
            duress_root,
            pair_secret,
        }
    }

    /// Open a volume given a presented passphrase.
    ///
    /// The gate computes BOTH potential volume secrets in constant
    /// time (so a timing-side-channel doesn't reveal which root the
    /// passphrase derives from). The returned outcome tells the
    /// caller what to do with the unlocked secret.
    ///
    /// **Caller invariant**: pass the SAME `passphrase_bytes` for both
    /// the real and duress passphrase paths. The decision of which
    /// passphrase a user typed is the operator's secret — this gate
    /// only knows whether a presented bytes matches one of the two
    /// derivations.
    ///
    /// Implementation: derive_key("ol-duress-real-v1", root||passphrase)
    /// for the real candidate, derive_key("ol-duress-decoy-v1", root||
    /// passphrase) for the duress candidate. The gate's input is a
    /// 32-byte "expected real" and "expected duress" hash that the
    /// account setup precomputed; this `open()` compares against both
    /// in constant time.
    pub fn open(
        &self,
        passphrase_bytes: &[u8],
        expected_real_check: &[u8; 32],
        expected_duress_check: &[u8; 32],
    ) -> Result<DuressOutcome, GateError> {
        if passphrase_bytes.is_empty() {
            return Err(GateError::InvalidInput);
        }
        // ─── Constant-time hardened path ───────────────────────────────
        // All four BLAKE3 derive_key calls (real_check, duress_check,
        // real_volume, duress_volume, covert_signal) run UNCONDITIONALLY
        // regardless of which branch is taken. The branch decision uses
        // subtle::ConstantTimeEq for the comparisons + a final
        // pattern-match that only selects which precomputed value to
        // return — no early returns inside the BLAKE3 chain.
        //
        // This closes a real timing side-channel found by the gate's
        // constant-time test: the previous implementation did 1 derive
        // on real-path, 2 on duress-path, 0 on reject — measurable at
        // ≈1.45× variance.
        let real_check = blake3::derive_key(
            "ol-duress-real-check-v1",
            &concat(&self.real_root, passphrase_bytes),
        );
        let duress_check = blake3::derive_key(
            "ol-duress-decoy-check-v1",
            &concat(&self.duress_root, passphrase_bytes),
        );
        // Always compute both candidate volume secrets + the covert
        // signal. Total cost: 5 derive_key calls. Identical across all
        // three branches.
        let real_volume = blake3::derive_key(
            "ol-duress-real-volume-v1",
            &concat(&self.real_root, passphrase_bytes),
        );
        let decoy_volume = blake3::derive_key(
            "ol-duress-decoy-volume-v1",
            &concat(&self.duress_root, passphrase_bytes),
        );
        let covert = blake3::derive_key("ol-duress-covert-signal-v1", &self.pair_secret);
        // Constant-time compare against expected.
        let real_match = real_check.ct_eq(expected_real_check).unwrap_u8() == 1;
        let duress_match = duress_check.ct_eq(expected_duress_check).unwrap_u8() == 1;
        // Every derivation above runs on every call; only the classification
        // below is the gate's output.
        // ct-audit: declassify (real/duress/rejected verdict)
        match (real_match, duress_match) {
            (true, _) => Ok(DuressOutcome::Real(Zeroizing::new(real_volume))),
            (false, true) => Ok(DuressOutcome::Duress {
                volume: Zeroizing::new(decoy_volume),
                covert_signal: covert,
            }),
            (false, false) => Err(GateError::Rejected),
        }
    }

    /// Compute the covert signal a peer would expect from this gate.
    /// Paired peers call this to compare against an inbound ratchet
    /// header's nonce slot — match = coercion event signaled.
    #[must_use]
    pub fn signal_in_ratchet_header(&self) -> [u8; SIGNAL_LEN] {
        blake3::derive_key("ol-duress-covert-signal-v1", &self.pair_secret)
    }
}

/// Decode a 32-byte ratchet-header nonce slot: returns true iff the
/// nonce matches the gate's covert signal (constant-time check).
#[must_use]
pub fn decode_covert_signal(gate: &DuressGate, nonce_slot: &[u8; SIGNAL_LEN]) -> bool {
    gate.signal_in_ratchet_header()
        .ct_eq(nonce_slot)
        .unwrap_u8()
        == 1
}

fn concat(a: &[u8; 32], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_gate() -> DuressGate {
        DuressGate::new([0x01u8; 32], [0x02u8; 32], [0x03u8; 32])
    }

    fn expected_checks(g: &DuressGate, pw: &[u8]) -> ([u8; 32], [u8; 32]) {
        let real = blake3::derive_key("ol-duress-real-check-v1", &concat(&g.real_root, pw));
        let decoy = blake3::derive_key("ol-duress-decoy-check-v1", &concat(&g.duress_root, pw));
        (real, decoy)
    }

    #[test]
    fn real_passphrase_unlocks_real_volume() {
        let g = fixed_gate();
        let real_pw = b"real-secret-passphrase";
        let (real_check, decoy_check) = expected_checks(&g, real_pw);
        match g.open(real_pw, &real_check, &decoy_check).unwrap() {
            DuressOutcome::Real(_) => {} // expected
            DuressOutcome::Duress { .. } => panic!("expected real path"),
        }
    }

    #[test]
    fn duress_passphrase_unlocks_decoy_volume() {
        let g = fixed_gate();
        let duress_pw = b"duress-coercion-passphrase";
        // Real-check is for a DIFFERENT pw, so won't match. Duress-
        // check is for the duress pw, matches.
        let real_pw = b"real-secret";
        let (real_check, _) = expected_checks(&g, real_pw);
        let (_, duress_check) = expected_checks(&g, duress_pw);
        match g.open(duress_pw, &real_check, &duress_check).unwrap() {
            DuressOutcome::Real(_) => panic!("expected duress path"),
            DuressOutcome::Duress { covert_signal, .. } => {
                // Covert signal matches expected.
                assert_eq!(covert_signal, g.signal_in_ratchet_header());
            }
        }
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let g = fixed_gate();
        let real_pw = b"real";
        let duress_pw = b"duress";
        let (real_check, _) = expected_checks(&g, real_pw);
        let (_, duress_check) = expected_checks(&g, duress_pw);
        // Present a passphrase that's neither.
        let err = g
            .open(b"wrong-passphrase", &real_check, &duress_check)
            .unwrap_err();
        assert_eq!(err, GateError::Rejected);
    }

    #[test]
    fn empty_passphrase_rejected() {
        let g = fixed_gate();
        let err = g.open(b"", &[0u8; 32], &[0u8; 32]).unwrap_err();
        assert_eq!(err, GateError::InvalidInput);
    }

    #[test]
    fn covert_signal_deterministic_per_gate() {
        let g = fixed_gate();
        let s1 = g.signal_in_ratchet_header();
        let s2 = g.signal_in_ratchet_header();
        assert_eq!(s1, s2);
        // Different pair_secret → different signal.
        let g2 = DuressGate::new([0x01u8; 32], [0x02u8; 32], [0xFFu8; 32]);
        assert_ne!(g.signal_in_ratchet_header(), g2.signal_in_ratchet_header());
    }

    #[test]
    fn decode_covert_signal_matches() {
        let g = fixed_gate();
        let s = g.signal_in_ratchet_header();
        assert!(decode_covert_signal(&g, &s));
        let mut tampered = s;
        tampered[0] ^= 0x01;
        assert!(!decode_covert_signal(&g, &tampered));
    }

    #[test]
    fn real_and_decoy_volumes_are_distinct() {
        let g = fixed_gate();
        let real_pw = b"real";
        let duress_pw = b"duress";
        let (r_check, _) = expected_checks(&g, real_pw);
        let (_, d_check) = expected_checks(&g, duress_pw);
        let DuressOutcome::Real(real_vol) = g.open(real_pw, &r_check, &d_check).unwrap() else {
            panic!("expected real path");
        };
        let DuressOutcome::Duress {
            volume: decoy_vol, ..
        } = g.open(duress_pw, &r_check, &d_check).unwrap()
        else {
            panic!("expected duress path");
        };
        assert_ne!(*real_vol, *decoy_vol);
    }
}
