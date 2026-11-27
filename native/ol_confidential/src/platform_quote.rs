//! Cross-platform verifier for the TPM-backed `platform_quote`
//! field of [`crate::AttestationDoc`].
//!
//! On the issuing side (Windows + `windows-tpm` feature), the quote
//! is produced by the TPM via `NCrypt` and the bytes have layout
//!
//! ```text
//! platform_quote := u16(pub_len) || ecc_pub_blob || u16(sig_len) || raw_r_s_sig
//! ```
//!
//! On the verifying side (ANY platform), this module:
//! 1. Parses the wire bytes.
//! 2. Reads the `BCRYPT_ECCKEY_BLOB` public key into a p256-friendly
//!    `Sec1Point` (SEC1 uncompressed: `0x04 || X || Y`).
//! 3. Reads the 64-byte `r || s` ECDSA signature.
//! 4. Computes `BLAKE3` over the sub-transcript and verifies the sig
//!    against the parsed public key.
//!
//! Verifier-side has NO dependency on the `windows` crate, so this
//! works on macOS / Linux / WSL peers verifying a doc minted on a
//! Windows TPM-bound issuer.

use blake3::Hasher;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::Sec1Point;

use crate::attestation::AttestationNonce;
use crate::errors::{ConfidentialError, ConfidentialResult};
use crate::provider::ProviderTag;

/// Domain-separation prefix for the TPM sub-transcript that the
/// `platform_quote` signature commits to. Distinct from the master's
/// attestation transcript so the TPM sig can't be lifted into the
/// master-sig position (cross-protocol replay defense).
pub const PLATFORM_QUOTE_DOMAIN: &[u8] = b"OL-confidential-platform-quote-v1";

/// Magic byte the CNG header carries for ECDSA-P256 public keys.
const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345; // 'ECS1' little-endian → 'ECS1'

/// Build the canonical sub-transcript the TPM signs over.
///
/// The sub-transcript is strictly SHORTER than the master's full
/// attestation transcript (it intentionally excludes `platform_quote`
/// itself, since that's what the TPM is producing). The master sig
/// over the full transcript then transitively commits to the TPM sig
/// via the `platform_quote` bytes inside that full transcript.
#[must_use]
pub fn canonical_platform_quote_subtranscript(
    provider_tag: ProviderTag,
    master_vk_bytes: &[u8],
    peer_nonce: &AttestationNonce,
    issued_unix: u64,
    deadline_unix: u64,
    field_witness_commitment: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PLATFORM_QUOTE_DOMAIN);
    h.update(&[provider_tag.as_u8()]);
    h.update(master_vk_bytes);
    h.update(peer_nonce);
    h.update(&issued_unix.to_be_bytes());
    h.update(&deadline_unix.to_be_bytes());
    match field_witness_commitment {
        None => {
            h.update(&[0u8]);
        }
        Some(c) => {
            h.update(&[1u8]);
            h.update(c);
        }
    }
    *h.finalize().as_bytes()
}

/// Parse a `platform_quote` envelope into its `(pub_blob, sig)` parts.
///
/// # Errors
/// Returns `Internal` on truncated buffers or impossible length prefixes.
pub fn parse_platform_quote(quote: &[u8]) -> ConfidentialResult<(Vec<u8>, Vec<u8>)> {
    if quote.len() < 4 {
        return Err(ConfidentialError::Internal("platform_quote too short"));
    }
    let pub_len = u16::from_be_bytes([quote[0], quote[1]]) as usize;
    if quote.len() < 2 + pub_len + 2 {
        return Err(ConfidentialError::Internal(
            "platform_quote truncated at pub_blob",
        ));
    }
    let pub_blob = quote[2..2 + pub_len].to_vec();
    let after_pub = 2 + pub_len;
    let sig_len = u16::from_be_bytes([quote[after_pub], quote[after_pub + 1]]) as usize;
    if quote.len() < after_pub + 2 + sig_len {
        return Err(ConfidentialError::Internal(
            "platform_quote truncated at sig",
        ));
    }
    let sig = quote[after_pub + 2..after_pub + 2 + sig_len].to_vec();
    Ok((pub_blob, sig))
}

/// Convert a CNG `BCRYPT_ECCKEY_BLOB` public-key payload into a
/// p256 `Sec1Point` (uncompressed SEC1).
fn cng_public_blob_to_sec1(blob: &[u8]) -> ConfidentialResult<Sec1Point> {
    if blob.len() < 8 + 32 + 32 {
        return Err(ConfidentialError::Internal(
            "BCRYPT_ECCKEY_BLOB too short for ECDSA-P256",
        ));
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
        return Err(ConfidentialError::Internal(
            "BCRYPT_ECCKEY_BLOB wrong magic for ECDSA-P256",
        ));
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if cb_key != 32 {
        return Err(ConfidentialError::Internal(
            "BCRYPT_ECCKEY_BLOB unexpected key size",
        ));
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&blob[8..40]);
    sec1[33..65].copy_from_slice(&blob[40..72]);
    Sec1Point::from_bytes(sec1)
        .map_err(|_| ConfidentialError::Internal("p256 Sec1Point::from_bytes failed"))
}

/// Verify a TPM-issued `platform_quote` against the sub-transcript
/// the issuer signed. Caller has parsed the [`crate::AttestationDoc`]
/// and knows the issuer's `master_vk`, `peer_nonce`, etc.
///
/// Returns the parsed `pub_blob` on success so the caller can pin
/// the TPM identity for trust-on-first-use binding.
///
/// # Errors
/// Returns a typed error if the quote parses cleanly but the
/// signature doesn't verify, or if any blob shape is wrong.
pub fn verify_platform_quote(
    quote: &[u8],
    provider_tag: ProviderTag,
    master_vk_bytes: &[u8],
    peer_nonce: &AttestationNonce,
    issued_unix: u64,
    deadline_unix: u64,
    field_witness_commitment: Option<&[u8; 32]>,
) -> ConfidentialResult<Vec<u8>> {
    let (pub_blob, sig_bytes) = parse_platform_quote(quote)?;
    let point = cng_public_blob_to_sec1(&pub_blob)?;
    let vk = VerifyingKey::from_sec1_point(&point)
        .map_err(|_| ConfidentialError::Internal("p256 VerifyingKey decode failed"))?;
    // The TPM produces a raw r||s ECDSA signature. p256 expects the
    // same layout via `Signature::from_slice`.
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| ConfidentialError::Internal("p256 Signature decode failed"))?;
    let digest = canonical_platform_quote_subtranscript(
        provider_tag,
        master_vk_bytes,
        peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment,
    );
    // The TPM signs the 32-byte digest directly (no further hashing
    // inside the chip), so we must use the prehash verifier to match.
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| ConfidentialError::AttestationMasterSigFail)?;
    Ok(pub_blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_independent_p256_cng_wire_fixture() {
        // Software-generated compatibility fixture: P-256 test private scalar 1,
        // signed with Python cryptography/OpenSSL over the BLAKE3 prehash.
        // This checks CNG wire-format verification after a dependency upgrade;
        // it does not assert TPM issuance or hardware-backed key storage.
        let quote: [u8; 140] = [
            0x00, 0x48, 0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x6b, 0x17, 0xd1, 0xf2,
            0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03,
            0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5, 0x00, 0x40, 0xdf, 0x74, 0x04, 0x74, 0x2e, 0x51, 0xf0, 0x89,
            0x6b, 0xaa, 0xd7, 0x4d, 0x58, 0x5d, 0x8b, 0x23, 0xd2, 0xec, 0x94, 0xb4, 0xb4, 0xee,
            0xf7, 0xa6, 0xe2, 0x66, 0x4e, 0xb2, 0x16, 0xb1, 0x0d, 0x1b, 0xc2, 0xf0, 0x68, 0xbe,
            0x97, 0x4f, 0x98, 0x29, 0xf3, 0xf1, 0xc0, 0xa3, 0x22, 0xfb, 0xc2, 0x4b, 0x85, 0x40,
            0x3b, 0x25, 0x0a, 0xe2, 0xa5, 0x5f, 0x62, 0x4f, 0x46, 0xe1, 0x3a, 0xb7, 0x41, 0x6c,
        ];
        let expected_digest: [u8; 32] = [
            0xc8, 0x8a, 0xe5, 0xef, 0x91, 0xab, 0x31, 0xd9, 0x5f, 0x9b, 0xbf, 0x0d, 0x99, 0xe3,
            0x99, 0x30, 0xcb, 0x27, 0xea, 0x93, 0x95, 0x66, 0x3e, 0x70, 0x60, 0xd9, 0x27, 0x1a,
            0xd8, 0x0c, 0x13, 0xd6,
        ];
        assert_eq!(
            canonical_platform_quote_subtranscript(
                ProviderTag::WindowsTpm,
                &[0u8; 1984],
                &[0u8; 32],
                100,
                120,
                None,
            ),
            expected_digest,
        );
        let public_blob = verify_platform_quote(
            &quote,
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[0u8; 32],
            100,
            120,
            None,
        )
        .expect("independent P-256 prehash signature must remain compatible");
        assert_eq!(public_blob, quote[2..74]);
    }

    #[test]
    fn parse_rejects_short_input() {
        assert!(parse_platform_quote(&[0u8; 3]).is_err());
    }

    #[test]
    fn parse_rejects_bad_pub_len() {
        // 1000-byte pub_blob promised but only 10 bytes follow.
        let mut bytes = 1000u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 10]);
        assert!(parse_platform_quote(&bytes).is_err());
    }

    #[test]
    fn sub_transcript_changes_with_each_field() {
        let base = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[0u8; 32],
            100,
            120,
            None,
        );
        let alt_tag = canonical_platform_quote_subtranscript(
            ProviderTag::Software,
            &[0u8; 1984],
            &[0u8; 32],
            100,
            120,
            None,
        );
        let alt_vk = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[1u8; 1984],
            &[0u8; 32],
            100,
            120,
            None,
        );
        let alt_nonce = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[1u8; 32],
            100,
            120,
            None,
        );
        let alt_issued = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[0u8; 32],
            101,
            120,
            None,
        );
        let alt_deadline = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[0u8; 32],
            100,
            121,
            None,
        );
        let alt_witness = canonical_platform_quote_subtranscript(
            ProviderTag::WindowsTpm,
            &[0u8; 1984],
            &[0u8; 32],
            100,
            120,
            Some(&[2u8; 32]),
        );
        for other in [
            alt_tag,
            alt_vk,
            alt_nonce,
            alt_issued,
            alt_deadline,
            alt_witness,
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn cng_blob_to_sec1_rejects_wrong_magic() {
        // Wrong magic byte 0 (anything other than ECS1).
        let mut blob = vec![0u8; 8 + 64];
        blob[0] = 0xFF;
        let r = cng_public_blob_to_sec1(&blob);
        assert!(r.is_err());
    }
}
