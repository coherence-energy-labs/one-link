//! Identity-bound TLS verifiers per [ADR-0010].
//!
//! Standard rustls verifiers walk an X.509 chain to a public-CA root.
//! That model is incompatible with One Link's sovereignty stance and
//! with our fingerprint-based peer identification. We replace the
//! verifier with one that:
//!
//! 1. Parses the presented cert just enough to extract the
//!    `SubjectPublicKeyInfo`'s raw pubkey bytes.
//! 2. Verifies the cert's algorithm OID is Ed25519 (1.3.101.112).
//! 3. Computes `BLAKE3(raw_pubkey_bytes)` and compares it to the
//!    expected `peer_fingerprint` (constant time).
//! 4. Verifies the cert's self-signature against the same pubkey
//!    (proves the holder of the cert ALSO holds the corresponding
//!    private key).
//!
//! Server-side verifiers (for client cert, mTLS) use the same logic
//! against an `is_paired_peer(fingerprint) -> bool` predicate.
//!
//! [ADR-0010]: ../../../docs/decisions/0010-identity-bound-tls.md

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};

use crate::identity::{PeerFingerprint, FINGERPRINT_LEN};

/// ALPN protocol identifier for the One Link daemon-to-daemon QUIC
/// transport. Sent in the TLS `ClientHello` / `ServerHello` so connections
/// from non-One-Link clients (or wrong-version clients) fail at the TLS
/// layer rather than after a partial handshake.
pub const ALPN: &[u8] = b"ol/1";

/// Ed25519 public key OID (1.3.101.112) per RFC 8410.
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

// ──────────────────────────────────────────────────────────────────────
// Server-cert verifier (client side)
// ──────────────────────────────────────────────────────────────────────

/// Client-side verifier: when WE are dialing OUT to a peer, this
/// verifies their server cert. The expected fingerprint is whatever
/// the peer registry knows us to expect.
#[derive(Debug)]
pub struct IdentityBoundServerVerifier {
    expected: PeerFingerprint,
}

impl IdentityBoundServerVerifier {
    /// Construct a verifier that accepts only certs whose pubkey hashes
    /// to `expected_fingerprint`.
    #[must_use]
    pub fn new(expected_fingerprint: PeerFingerprint) -> Self {
        Self {
            expected: expected_fingerprint,
        }
    }
}

impl ServerCertVerifier for IdentityBoundServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        verify_identity_cert(end_entity, &self.expected)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // We negotiate TLS 1.3 only — see Endpoint config. If a client
        // somehow ends up at a TLS 1.2 path, refuse.
        Err(RustlsError::General(
            "TLS 1.2 path not supported; engine negotiates TLS 1.3 only".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_ed25519_handshake_signature(cert, message, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

// ──────────────────────────────────────────────────────────────────────
// Client-cert verifier (server side, mTLS)
// ──────────────────────────────────────────────────────────────────────

/// Predicate: "is this fingerprint a paired peer?" — supplied by the
/// daemon's peer registry.
pub trait PeerRegistry: Send + Sync + std::fmt::Debug {
    /// Return true iff the daemon has previously paired with the peer
    /// owning this fingerprint and is willing to accept connections
    /// from them right now.
    fn is_paired_peer(&self, fingerprint: &PeerFingerprint) -> bool;
}

/// Server-side verifier: when WE are accepting an inbound connection,
/// this verifies the client's cert against an external [`PeerRegistry`].
#[derive(Debug)]
pub struct IdentityBoundClientVerifier {
    registry: Arc<dyn PeerRegistry>,
}

impl IdentityBoundClientVerifier {
    /// Construct a verifier backed by the given peer registry.
    #[must_use]
    pub fn new(registry: Arc<dyn PeerRegistry>) -> Self {
        Self { registry }
    }
}

impl ClientCertVerifier for IdentityBoundClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // We do not advertise CA hints — we don't use a CA chain at all.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // Extract fingerprint from the cert; check against the registry.
        let fp = extract_pubkey_fingerprint(end_entity)?;
        verify_self_signature_and_alg(end_entity)?;
        if !self.registry.is_paired_peer(&fp) {
            return Err(RustlsError::General(
                "client cert fingerprint not in paired peer set".into(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "TLS 1.2 path not supported; engine negotiates TLS 1.3 only".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_ed25519_handshake_signature(cert, message, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

// ──────────────────────────────────────────────────────────────────────
// Shared verification helpers
// ──────────────────────────────────────────────────────────────────────

fn verify_identity_cert(
    cert_der: &CertificateDer<'_>,
    expected: &PeerFingerprint,
) -> Result<(), RustlsError> {
    let presented = extract_pubkey_fingerprint(cert_der)?;
    // Constant-time fingerprint compare: a dialer must not reveal, through
    // how long a rejection takes, how much of the fingerprint it expects a
    // presented certificate matched.
    // ct-audit: declassify (accept/reject of the presented certificate)
    if !ct_eq(&presented, expected) {
        return Err(RustlsError::General("peer fingerprint mismatch".into()));
    }
    verify_self_signature_and_alg(cert_der)?;
    Ok(())
}

pub(crate) fn extract_pubkey_fingerprint(
    cert_der: &CertificateDer<'_>,
) -> Result<PeerFingerprint, RustlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
        .map_err(|e| RustlsError::General(format!("x509 parse: {e:?}")))?;
    let raw_pubkey = cert.public_key().subject_public_key.data.as_ref();
    Ok(*blake3::hash(raw_pubkey).as_bytes())
}

fn verify_self_signature_and_alg(cert_der: &CertificateDer<'_>) -> Result<(), RustlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
        .map_err(|e| RustlsError::General(format!("x509 parse: {e:?}")))?;
    // Algorithm OID check: Ed25519 only.
    // x509-parser strips the OID tag/length headers, leaving only the
    // content bytes. ED25519_OID_DER content is `[0x2B, 0x65, 0x70]`.
    let alg_oid_bytes = cert.public_key().algorithm.algorithm.as_bytes();
    if alg_oid_bytes != &ED25519_OID_DER[2..] {
        return Err(RustlsError::General("non-Ed25519 cert".into()));
    }
    // Self-signature verification.
    //
    // x509-parser's `verify_signature` is feature-gated and pulls in
    // additional crypto libraries; we avoid that dep by verifying
    // manually with ed25519-dalek using the TBS-bytes / signature-bytes
    // already exposed by x509-parser's parser.
    let pubkey_raw = cert.public_key().subject_public_key.data.as_ref();
    if pubkey_raw.len() != 32 {
        return Err(RustlsError::General(
            "Ed25519 SubjectPublicKey must be 32 bytes".into(),
        ));
    }
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(pubkey_raw.try_into().expect("32 bytes"))
        .map_err(|e| RustlsError::General(format!("Ed25519 pubkey: {e}")))?;
    let sig_bytes = cert.signature_value.as_ref();
    if sig_bytes.len() != 64 {
        return Err(RustlsError::General(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            sig_bytes.len(),
        )));
    }
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().expect("64 bytes"));
    let tbs = cert.tbs_certificate.as_ref();
    pubkey
        .verify_strict(tbs, &sig)
        .map_err(|e| RustlsError::General(format!("cert self-signature invalid: {e}")))?;
    Ok(())
}

fn verify_tls13_ed25519_handshake_signature(
    cert: &CertificateDer<'_>,
    message: &[u8],
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(RustlsError::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    // Pull the raw 32-byte Ed25519 pubkey from the cert.
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| RustlsError::General(format!("x509 parse: {e:?}")))?;
    let raw = parsed.public_key().subject_public_key.data.as_ref();
    if raw.len() != 32 {
        return Err(RustlsError::General(
            "Ed25519 pubkey is not 32 bytes".into(),
        ));
    }
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(raw.try_into().expect("32 bytes"))
        .map_err(|e| RustlsError::General(format!("Ed25519 pubkey: {e}")))?;
    let sig_bytes: [u8; 64] = dss.signature().as_ref().try_into().map_err(|_| {
        RustlsError::General(format!(
            "Ed25519 signature wrong length: {}",
            dss.signature().as_ref().len()
        ))
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    pubkey
        .verify_strict(message, &sig)
        .map_err(|e| RustlsError::General(format!("Ed25519 verify: {e}")))?;
    Ok(HandshakeSignatureValid::assertion())
}

/// Constant-time fingerprint equality.
///
/// A hand-written OR-fold ending in `diff == 0` is branchless only in
/// source: the optimiser may recognise the boolean and reintroduce an early
/// exit. `subtle` routes the result through an optimisation barrier, and
/// `ol_ct_audit` checks the emitted code (case `quic_server_cert_fingerprint`).
#[inline]
fn ct_eq(a: &[u8; FINGERPRINT_LEN], b: &[u8; FINGERPRINT_LEN]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[derive(Debug)]
    struct AlwaysAcceptRegistry;

    impl PeerRegistry for AlwaysAcceptRegistry {
        fn is_paired_peer(&self, _fp: &PeerFingerprint) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct EmptyRegistry;

    impl PeerRegistry for EmptyRegistry {
        fn is_paired_peer(&self, _fp: &PeerFingerprint) -> bool {
            false
        }
    }

    #[test]
    fn server_verifier_accepts_matching_fingerprint() {
        let id = Identity::generate().unwrap();
        let verifier = IdentityBoundServerVerifier::new(id.fingerprint());
        let der = id.cert_der().into_owned();
        let result = verifier.verify_server_cert(
            &der,
            &[],
            &ServerName::try_from("test.invalid").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_ok(), "should accept matching cert: {result:?}");
    }

    #[test]
    fn server_verifier_rejects_mismatched_fingerprint() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let verifier = IdentityBoundServerVerifier::new(alice.fingerprint());
        let bobs_cert = bob.cert_der().into_owned();
        let result = verifier.verify_server_cert(
            &bobs_cert,
            &[],
            &ServerName::try_from("test.invalid").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err(), "should reject mismatched fingerprint");
    }

    #[test]
    fn client_verifier_accepts_paired_peer() {
        let id = Identity::generate().unwrap();
        let verifier = IdentityBoundClientVerifier::new(Arc::new(AlwaysAcceptRegistry));
        let der = id.cert_der().into_owned();
        let result = verifier.verify_client_cert(&der, &[], UnixTime::now());
        assert!(result.is_ok());
    }

    #[test]
    fn client_verifier_rejects_unpaired_peer() {
        let id = Identity::generate().unwrap();
        let verifier = IdentityBoundClientVerifier::new(Arc::new(EmptyRegistry));
        let der = id.cert_der().into_owned();
        let result = verifier.verify_client_cert(&der, &[], UnixTime::now());
        assert!(result.is_err());
    }

    #[test]
    fn ct_eq_constant_time() {
        let a = [0x42u8; FINGERPRINT_LEN];
        let mut b = a;
        assert!(ct_eq(&a, &b));
        b[0] ^= 0x01;
        assert!(!ct_eq(&a, &b));
    }
}
