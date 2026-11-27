//! Duress gate: passphrase → volume unlock + covert signaling.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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

/// What the gate decided, as a plain value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutcomeKind {
    /// The real passphrase was presented.
    Real = 0,
    /// The duress passphrase was presented.
    Duress = 1,
    /// The passphrase matched neither enrolment.
    Rejected = 2,
}

/// The gate's decision in one uniform shape (see [`DuressGate::decide`]).
///
/// Every field is always written, whatever the outcome:
///
/// | outcome | `volume` | `covert_signal` |
/// |---|---|---|
/// | real | real-volume secret | zeros |
/// | duress | decoy-volume secret | the covert signal |
/// | rejected | zeros | zeros |
///
/// The accessors do not branch. Only [`Self::kind`] and
/// [`Self::into_outcome`] turn the outcome into control flow, and they are
/// where a caller chooses to reveal it. Secrets are zeroized on drop and
/// never printed.
pub struct GateDecision {
    kind_code: u8,
    volume: Volume,
    covert_signal: [u8; SIGNAL_LEN],
}

impl GateDecision {
    /// The outcome as its numeric code ([`OutcomeKind`] as `u8`), read
    /// without branching.
    #[must_use]
    pub fn kind_code(&self) -> u8 {
        self.kind_code
    }

    /// The outcome. Matching on it reveals the outcome to control flow.
    #[must_use]
    pub fn kind(&self) -> OutcomeKind {
        // ct-audit: declassify (the caller asks for the real/duress/rejected verdict)
        match self.kind_code {
            0 => OutcomeKind::Real,
            1 => OutcomeKind::Duress,
            _ => OutcomeKind::Rejected,
        }
    }

    /// The selected volume secret (zeros when rejected).
    #[must_use]
    pub fn volume(&self) -> &[u8; VOLUME_SECRET_LEN] {
        &self.volume
    }

    /// The covert signal for a duress open; zeros otherwise.
    #[must_use]
    pub fn covert_signal(&self) -> &[u8; SIGNAL_LEN] {
        &self.covert_signal
    }

    /// Classify into a [`DuressOutcome`]. This branches on the outcome and
    /// its arms build different payloads, so it is not timing-uniform across
    /// outcomes; see [`DuressGate::open`].
    ///
    /// # Errors
    ///
    /// [`GateError::Rejected`] when the passphrase matched neither enrolment.
    pub fn into_outcome(self) -> Result<DuressOutcome, GateError> {
        // ct-audit: declassify (real/duress/rejected verdict)
        match self.kind_code {
            0 => Ok(DuressOutcome::Real(Zeroizing::new(*self.volume))),
            1 => Ok(DuressOutcome::Duress {
                volume: Zeroizing::new(*self.volume),
                covert_signal: self.covert_signal,
            }),
            _ => Err(GateError::Rejected),
        }
    }
}

impl Drop for GateDecision {
    fn drop(&mut self) {
        // `volume` zeroizes itself; the signal and the outcome are cleared too.
        self.covert_signal.zeroize();
        self.kind_code.zeroize();
    }
}

impl std::fmt::Debug for GateDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the secrets nor the outcome are printed.
        f.debug_struct("GateDecision").finish_non_exhaustive()
    }
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

    /// Classify a presented passphrase without revealing the outcome through
    /// control flow, memory access or the shape of the result.
    ///
    /// This is the gate's timing-uniform API. Every derivation runs on every
    /// call, both comparisons are constant-time, and the result is selected
    /// with constant-time selects into ONE record whose every field is always
    /// written: a real open, a duress open and a rejection execute the same
    /// instructions. `ol_ct_audit` proves no branch or memory index depends on
    /// any secret here, and its statistical timing test compares the outcomes
    /// directly.
    ///
    /// A caller that must not reveal the outcome through timing keeps
    /// treating the record uniformly (for example: always installs
    /// [`GateDecision::volume`], always writes
    /// [`GateDecision::covert_signal`]) and only later lets the outcome
    /// influence anything observable.
    ///
    /// **Caller invariant**: pass the SAME `passphrase_bytes` for both the
    /// real and duress passphrase paths. Which passphrase a user typed is the
    /// operator's secret; the gate only learns whether the presented bytes
    /// match one of the two enrolled derivations.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidInput`] for an empty passphrase. Its length is
    /// public; nothing else about the input reaches control flow. A
    /// passphrase that matches neither enrolment is NOT an error here: it is
    /// a decision of kind [`OutcomeKind::Rejected`] carrying zeroed fields.
    pub fn decide(
        &self,
        passphrase_bytes: &[u8],
        expected_real_check: &[u8; 32],
        expected_duress_check: &[u8; 32],
    ) -> Result<GateDecision, GateError> {
        if passphrase_bytes.is_empty() {
            return Err(GateError::InvalidInput);
        }
        // Five derivations, unconditionally. (An earlier implementation
        // derived 1, 2 or 0 values depending on the outcome, measurable at
        // about 1.45x.) The keyed inputs and every intermediate are
        // zeroized when they go out of scope.
        let real_input = Zeroizing::new(concat(&self.real_root, passphrase_bytes));
        let duress_input = Zeroizing::new(concat(&self.duress_root, passphrase_bytes));
        let real_check = Zeroizing::new(blake3::derive_key("ol-duress-real-check-v1", &real_input));
        let duress_check = Zeroizing::new(blake3::derive_key(
            "ol-duress-decoy-check-v1",
            &duress_input,
        ));
        let real_volume =
            Zeroizing::new(blake3::derive_key("ol-duress-real-volume-v1", &real_input));
        let decoy_volume = Zeroizing::new(blake3::derive_key(
            "ol-duress-decoy-volume-v1",
            &duress_input,
        ));
        let covert = Zeroizing::new(blake3::derive_key(
            "ol-duress-covert-signal-v1",
            &self.pair_secret,
        ));

        let real_match: Choice = real_check.ct_eq(expected_real_check);
        let duress_match: Choice = duress_check.ct_eq(expected_duress_check);
        // The real passphrase wins if a passphrase matches both enrolments.
        let duress_selected = !real_match & duress_match;
        let rejected = !real_match & !duress_match;

        let mut volume = Zeroizing::new([0u8; VOLUME_SECRET_LEN]);
        let mut covert_signal = [0u8; SIGNAL_LEN];
        for i in 0..VOLUME_SECRET_LEN {
            volume[i] = u8::conditional_select(&0, &real_volume[i], real_match);
            volume[i].conditional_assign(&decoy_volume[i], duress_selected);
        }
        for i in 0..SIGNAL_LEN {
            covert_signal[i] = u8::conditional_select(&0, &covert[i], duress_selected);
        }
        let mut kind_code = OutcomeKind::Real as u8;
        kind_code.conditional_assign(&(OutcomeKind::Duress as u8), duress_selected);
        kind_code.conditional_assign(&(OutcomeKind::Rejected as u8), rejected);
        Ok(GateDecision {
            kind_code,
            volume,
            covert_signal,
        })
    }

    /// Open a volume given a presented passphrase: [`Self::decide`] followed
    /// by [`GateDecision::into_outcome`].
    ///
    /// Everything up to the classification is timing-uniform (it is
    /// `decide`). Turning the decision into a [`DuressOutcome`] is NOT: a
    /// Rust enum can only be built by branching on its variant, and the
    /// variants carry different payloads. Measured with the statistical
    /// timing test (2026-11-25, Core Ultra 9 275HX): a duress `open` took
    /// about 1 to 6 TSC ticks longer than a real one. Use `decide` wherever
    /// the outcome itself must not be observable through timing; `open` is
    /// the convenience for callers that act on the outcome immediately.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidInput`] for an empty passphrase;
    /// [`GateError::Rejected`] when it matches neither enrolment.
    pub fn open(
        &self,
        passphrase_bytes: &[u8],
        expected_real_check: &[u8; 32],
        expected_duress_check: &[u8; 32],
    ) -> Result<DuressOutcome, GateError> {
        self.decide(passphrase_bytes, expected_real_check, expected_duress_check)?
            .into_outcome()
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

    #[test]
    fn decision_fields_follow_the_documented_table_for_every_outcome() {
        let g = fixed_gate();
        let (real_pw, duress_pw, wrong_pw) = (
            b"real".as_slice(),
            b"duress".as_slice(),
            b"neither".as_slice(),
        );
        let (r_check, _) = expected_checks(&g, real_pw);
        let (_, d_check) = expected_checks(&g, duress_pw);
        let zero = [0u8; 32];

        let real = g.decide(real_pw, &r_check, &d_check).unwrap();
        assert_eq!((real.kind_code(), real.kind()), (0, OutcomeKind::Real));
        assert_ne!(real.volume(), &zero);
        assert_eq!(real.covert_signal(), &zero, "a real open signals nothing");

        let duress = g.decide(duress_pw, &r_check, &d_check).unwrap();
        assert_eq!(
            (duress.kind_code(), duress.kind()),
            (1, OutcomeKind::Duress)
        );
        assert_ne!(duress.volume(), &zero);
        assert_ne!(duress.volume(), real.volume());
        assert_eq!(duress.covert_signal(), &g.signal_in_ratchet_header());

        let rejected = g.decide(wrong_pw, &r_check, &d_check).unwrap();
        assert_eq!(
            (rejected.kind_code(), rejected.kind()),
            (2, OutcomeKind::Rejected)
        );
        assert_eq!(
            rejected.volume(),
            &zero,
            "a rejection returns no key material"
        );
        assert_eq!(rejected.covert_signal(), &zero);

        assert_eq!(
            g.decide(b"", &r_check, &d_check).unwrap_err(),
            GateError::InvalidInput
        );
    }

    #[test]
    fn decide_and_open_agree_on_every_outcome() {
        let g = fixed_gate();
        let (real_pw, duress_pw) = (b"real".as_slice(), b"duress".as_slice());
        let (r_check, _) = expected_checks(&g, real_pw);
        let (_, d_check) = expected_checks(&g, duress_pw);
        for pw in [real_pw, duress_pw, b"neither".as_slice()] {
            let decision = g.decide(pw, &r_check, &d_check).unwrap();
            let (volume, signal) = (*decision.volume(), *decision.covert_signal());
            match (decision.into_outcome(), g.open(pw, &r_check, &d_check)) {
                (Ok(DuressOutcome::Real(a)), Ok(DuressOutcome::Real(b))) => {
                    assert_eq!((*a, *b), (volume, volume));
                }
                (
                    Ok(DuressOutcome::Duress {
                        volume: a,
                        covert_signal: sa,
                    }),
                    Ok(DuressOutcome::Duress {
                        volume: b,
                        covert_signal: sb,
                    }),
                ) => {
                    assert_eq!((*a, *b), (volume, volume));
                    assert_eq!((sa, sb), (signal, signal));
                }
                (Err(GateError::Rejected), Err(GateError::Rejected)) => {}
                other => panic!("decide and open disagree: {other:?}"),
            }
        }
    }

    #[test]
    fn a_passphrase_enrolled_as_both_opens_the_real_volume() {
        // Same precedence as before the uniform core: real wins.
        let g = fixed_gate();
        let pw = b"shared";
        let (r_check, d_check) = expected_checks(&g, pw);
        let decision = g.decide(pw, &r_check, &d_check).unwrap();
        assert_eq!(decision.kind(), OutcomeKind::Real);
        assert_eq!(decision.covert_signal(), &[0u8; 32]);
        assert!(matches!(
            g.open(pw, &r_check, &d_check),
            Ok(DuressOutcome::Real(_))
        ));
    }

    #[test]
    fn a_decision_never_prints_its_secrets_or_its_outcome() {
        let g = fixed_gate();
        let (r_check, d_check) = expected_checks(&g, b"real");
        let shown = format!("{:?}", g.decide(b"real", &r_check, &d_check).unwrap());
        assert_eq!(shown, "GateDecision { .. }");
    }
}
