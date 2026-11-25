//! Constant-time check of the PRODUCTION fingerprint comparison in `ol_quic`.
//!
//! When this node dials a peer, [`IdentityBoundServerVerifier`] accepts the
//! peer's certificate only if `BLAKE3(SPKI pubkey)` equals the fingerprint the
//! dialer expects (`ol_quic::tls::verify_identity_cert`, which calls the
//! private `ct_eq`). The expected fingerprint is the dialer's secret in that
//! exchange: a machine in the middle can present certificates and time the
//! rejection, so a comparison that stopped at the first differing byte would
//! reveal how much of the expected fingerprint a presented one matched.
//!
//! These tests drive the real verifier. An earlier version of this file
//! timed a comparator that the test defined itself, which no production path
//! ran, while its header described the end-to-end test written here.
//!
//! What each instrument establishes:
//!
//! * the proof that no branch or memory index depends on the expected
//!   fingerprint, on the release code, is `ol_ct_audit`'s Valgrind case
//!   `quic_server_cert_fingerprint`;
//! * the statistical timing test with stated power is the same crate's
//!   `--dudect` target of that name;
//! * the wall-clock check below is a coarse smoke of the same property. A
//!   verification is dominated by X.509 parsing, so it cannot resolve a
//!   32-byte comparison on its own and does not claim to.

use std::hint::black_box;
use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_quic::{Identity, IdentityBoundServerVerifier, PeerFingerprint};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

fn verify(
    verifier: &IdentityBoundServerVerifier,
    cert: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let name = ServerName::try_from("peer.invalid").expect("a valid DNS name");
    verifier
        .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

fn expecting(
    fingerprint: PeerFingerprint,
    flipped_byte: Option<usize>,
) -> IdentityBoundServerVerifier {
    let mut expected = fingerprint;
    if let Some(index) = flipped_byte {
        expected[index] ^= 0xFF;
    }
    IdentityBoundServerVerifier::new(expected)
}

/// The dialer's rejection must take the same time whether the presented
/// fingerprint first differs from the expected one at byte 0 or at byte 31.
#[test]
fn fingerprint_ct_compare_timing_uniform() {
    let identity = Identity::generate().unwrap();
    let cert = identity.cert_der().into_owned();
    let differs_first = expecting(identity.fingerprint(), Some(0));
    let differs_last = expecting(identity.fingerprint(), Some(31));
    assert!(verify(&differs_first, &cert).is_err());
    assert!(verify(&differs_last, &cert).is_err());

    let iters_per_burst: u32 = 2_000;
    let bursts: u32 = 20;
    for _ in 0..iters_per_burst {
        let _ = black_box(verify(black_box(&differs_first), black_box(&cert)));
        let _ = black_box(verify(black_box(&differs_last), black_box(&cert)));
    }

    // Alternate short bursts so drift and frequency changes hit both arms.
    let mut t_first = Duration::ZERO;
    let mut t_last = Duration::ZERO;
    for _ in 0..bursts {
        let started = Instant::now();
        for _ in 0..iters_per_burst {
            let _ = black_box(verify(black_box(&differs_first), black_box(&cert)));
        }
        t_first += started.elapsed();

        let started = Instant::now();
        for _ in 0..iters_per_burst {
            let _ = black_box(verify(black_box(&differs_last), black_box(&cert)));
        }
        t_last += started.elapsed();
    }

    let calls = f64::from(iters_per_burst * bursts);
    let avg_first = t_first.as_secs_f64() * 1_000_000_000.0 / calls;
    let avg_last = t_last.as_secs_f64() * 1_000_000_000.0 / calls;
    let ratio = avg_first.max(avg_last) / avg_first.min(avg_last);
    eprintln!("reject, differs at byte 0:  {avg_first:.1} ns/verification");
    eprintln!("reject, differs at byte 31: {avg_last:.1} ns/verification");
    eprintln!("ratio: {ratio:.4}");

    timing_gate!(
        ratio < 1.20,
        "server-certificate rejection diverges {ratio:.3}x by mismatch position"
    );
}

/// Semantic guard for the timing test: the real verifier accepts the
/// matching certificate and rejects a mismatch at every byte position, with
/// the fingerprint error (so the timing test compares like with like).
#[test]
fn fingerprint_ct_compare_semantic() {
    let identity = Identity::generate().unwrap();
    let cert = identity.cert_der().into_owned();
    assert!(verify(&expecting(identity.fingerprint(), None), &cert).is_ok());
    for index in 0..32 {
        let error = verify(&expecting(identity.fingerprint(), Some(index)), &cert)
            .expect_err("a fingerprint differing in any byte must be rejected");
        assert!(
            error.to_string().contains("peer fingerprint mismatch"),
            "byte {index}: unexpected error {error}"
        );
    }
}

/// A verifier that expects one identity rejects another identity's valid,
/// correctly self-signed certificate.
#[test]
fn verifier_rejects_a_valid_certificate_of_another_identity() {
    let expected = Identity::generate().unwrap();
    let presented = Identity::generate().unwrap();
    let verifier = IdentityBoundServerVerifier::new(expected.fingerprint());
    assert!(verify(&verifier, &presented.cert_der().into_owned()).is_err());
    assert!(verify(&verifier, &expected.cert_der().into_owned()).is_ok());
}
