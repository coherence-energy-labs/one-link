//! Hybrid KEM implementation per ADR-0017.
//!
//! Wraps `ml-kem` (NIST FIPS 203 ML-KEM-768) and `x25519-dalek` with a
//! BLAKE3 combiner that produces a 32-byte shared secret suitable for
//! direct use as an AEAD key.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

/// Type aliases for the ML-KEM-768 encoded forms. Using these by name
/// is cleaner than inlining the trait projections.
type MlKem768EkEncoded = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
type MlKem768DkEncoded = <<MlKem768 as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;
type MlKem768CtSize = <MlKem768 as KemCore>::CiphertextSize;
use rand_core::CryptoRng;
use rand_core::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::PqKemError;

/// Length of an ML-KEM-768 encapsulation key (FIPS 203 §6.3.1).
const ML_KEM_EK_LEN: usize = 1184;
/// Length of an ML-KEM-768 decapsulation key (FIPS 203 §6.3.1).
const ML_KEM_DK_LEN: usize = 2400;
/// Length of an ML-KEM-768 ciphertext (FIPS 203 §6.3.1).
const ML_KEM_CT_LEN: usize = 1088;
/// Length of an X25519 public key / secret key / shared secret.
const X25519_LEN: usize = 32;

/// Length of the serialized hybrid public key.
pub const HYBRID_PUBLIC_KEY_LEN: usize = ML_KEM_EK_LEN + X25519_LEN;
/// Length of the serialized hybrid secret key.
pub const HYBRID_SECRET_KEY_LEN: usize = ML_KEM_DK_LEN + X25519_LEN;
/// Length of the serialized hybrid ciphertext.
pub const HYBRID_CIPHERTEXT_LEN: usize = ML_KEM_CT_LEN + X25519_LEN;
/// Length of the derived shared secret in bytes (AEAD-key sized).
pub const SHARED_SECRET_LEN: usize = 32;

/// BLAKE3 `derive_key` context for the hybrid KEM combiner (ADR-0006 registry).
const COMBINER_CONTEXT: &str = "ol-pqkem-hybrid-v1";

/// The ML-KEM modulus q (FIPS 203 section 2.4).
const ML_KEM_Q: u16 = 3329;
/// Bytes of an ML-KEM-768 encapsulation key that encode the vector t-hat:
/// 3 polynomials of 256 coefficients at 12 bits each. The remaining 32
/// bytes are the matrix seed rho, which may hold any value.
const ML_KEM_EK_T_HAT_LEN: usize = 3 * 256 * 12 / 8;

/// FIPS 203 section 7.2 "modulus check" for an encapsulation key.
///
/// Every 12-bit coefficient of t-hat must already be reduced modulo q. The
/// `ml-kem` 0.2 decoder accepts unreduced coefficients and reduces them
/// silently, so two different byte strings would act as the same key and a
/// peer could send a key no honest key generation produces. The key is
/// public, so this check does not need to be constant-time.
fn encapsulation_key_is_reduced(ek: &[u8; ML_KEM_EK_LEN]) -> bool {
    ek[..ML_KEM_EK_T_HAT_LEN].chunks_exact(3).all(|triple| {
        let low = u16::from(triple[0]) | (u16::from(triple[1] & 0x0F) << 8);
        let high = u16::from(triple[1] >> 4) | (u16::from(triple[2]) << 4);
        low < ML_KEM_Q && high < ML_KEM_Q
    })
}

/// A hybrid 32-byte shared secret derived from the BLAKE3 combiner.
/// Zeroized on drop.
pub type SharedSecret = Zeroizing<[u8; SHARED_SECRET_LEN]>;

/// Hybrid public key: ML-KEM-768 encapsulation key + X25519 public key.
///
/// Serialized as `ek_ml_kem || pk_x25519` for 1216 bytes total.
#[derive(Clone)]
pub struct HybridPublicKey {
    ml_kem_ek_bytes: [u8; ML_KEM_EK_LEN],
    x25519_pk: X25519PublicKey,
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("ml_kem_ek_len", &ML_KEM_EK_LEN)
            .field("x25519_pk_len", &X25519_LEN)
            .finish_non_exhaustive()
    }
}

impl HybridPublicKey {
    /// Serialize to wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HYBRID_PUBLIC_KEY_LEN] {
        let mut out = [0u8; HYBRID_PUBLIC_KEY_LEN];
        out[..ML_KEM_EK_LEN].copy_from_slice(&self.ml_kem_ek_bytes);
        out[ML_KEM_EK_LEN..].copy_from_slice(self.x25519_pk.as_bytes());
        out
    }

    /// Parse from wire bytes.
    ///
    /// # Errors
    ///
    /// [`PqKemError::InvalidWireLength`] if `bytes.len() != HYBRID_PUBLIC_KEY_LEN`.
    /// [`PqKemError::InvalidEncapsulationKey`] if the ML-KEM half fails the
    /// FIPS 203 modulus check. A `HybridPublicKey` can only be obtained from
    /// here or from [`keypair`], so every key [`encapsulate`] sees is checked.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqKemError> {
        if bytes.len() != HYBRID_PUBLIC_KEY_LEN {
            return Err(PqKemError::InvalidWireLength {
                expected: HYBRID_PUBLIC_KEY_LEN,
                got: bytes.len(),
            });
        }
        let mut ml_kem_ek_bytes = [0u8; ML_KEM_EK_LEN];
        ml_kem_ek_bytes.copy_from_slice(&bytes[..ML_KEM_EK_LEN]);
        if !encapsulation_key_is_reduced(&ml_kem_ek_bytes) {
            return Err(PqKemError::InvalidEncapsulationKey);
        }
        let mut x25519_bytes = [0u8; X25519_LEN];
        x25519_bytes.copy_from_slice(&bytes[ML_KEM_EK_LEN..]);
        Ok(Self {
            ml_kem_ek_bytes,
            x25519_pk: X25519PublicKey::from(x25519_bytes),
        })
    }
}

/// Hybrid secret key. Holds the secret material for both KEMs.
///
/// Zeroized on drop via the inner X25519 / ML-KEM byte arrays.
#[derive(Clone)]
pub struct HybridSecretKey {
    ml_kem_dk_bytes: Zeroizing<[u8; ML_KEM_DK_LEN]>,
    x25519_sk: X25519StaticSecret,
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print secret material.
        f.debug_struct("HybridSecretKey")
            .field("ml_kem_dk_len", &ML_KEM_DK_LEN)
            .field("x25519_sk_len", &X25519_LEN)
            .finish_non_exhaustive()
    }
}

impl HybridSecretKey {
    /// Serialize to wire bytes. Callers should zeroize the result after
    /// use (the inner `Zeroizing` on the struct itself only protects
    /// the in-memory copy).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SECRET_KEY_LEN]> {
        // Filled in place inside the wiping wrapper, so no unwiped copy of
        // the key is left behind on this stack frame.
        let mut out = Zeroizing::new([0u8; HYBRID_SECRET_KEY_LEN]);
        out[..ML_KEM_DK_LEN].copy_from_slice(&self.ml_kem_dk_bytes[..]);
        let x25519_bytes = Zeroizing::new(self.x25519_sk.to_bytes());
        out[ML_KEM_DK_LEN..].copy_from_slice(&x25519_bytes[..]);
        out
    }

    /// Parse from wire bytes.
    ///
    /// # Errors
    ///
    /// [`PqKemError::InvalidWireLength`] if `bytes.len() != HYBRID_SECRET_KEY_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqKemError> {
        if bytes.len() != HYBRID_SECRET_KEY_LEN {
            return Err(PqKemError::InvalidWireLength {
                expected: HYBRID_SECRET_KEY_LEN,
                got: bytes.len(),
            });
        }
        let mut ml_kem_dk_bytes = Zeroizing::new([0u8; ML_KEM_DK_LEN]);
        ml_kem_dk_bytes[..].copy_from_slice(&bytes[..ML_KEM_DK_LEN]);
        let mut x25519_bytes = Zeroizing::new([0u8; X25519_LEN]);
        x25519_bytes.copy_from_slice(&bytes[ML_KEM_DK_LEN..]);
        let x25519_sk = X25519StaticSecret::from(*x25519_bytes);
        Ok(Self {
            ml_kem_dk_bytes,
            x25519_sk,
        })
    }
}

/// Hybrid ciphertext: ML-KEM-768 CT + X25519 ephemeral public key.
#[derive(Clone, Debug)]
pub struct HybridCiphertext {
    ml_kem_ct_bytes: [u8; ML_KEM_CT_LEN],
    x25519_eph_pk: X25519PublicKey,
}

impl HybridCiphertext {
    /// Serialize to wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HYBRID_CIPHERTEXT_LEN] {
        let mut out = [0u8; HYBRID_CIPHERTEXT_LEN];
        out[..ML_KEM_CT_LEN].copy_from_slice(&self.ml_kem_ct_bytes);
        out[ML_KEM_CT_LEN..].copy_from_slice(self.x25519_eph_pk.as_bytes());
        out
    }

    /// Parse from wire bytes.
    ///
    /// # Errors
    ///
    /// [`PqKemError::InvalidWireLength`] if `bytes.len() != HYBRID_CIPHERTEXT_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqKemError> {
        if bytes.len() != HYBRID_CIPHERTEXT_LEN {
            return Err(PqKemError::InvalidWireLength {
                expected: HYBRID_CIPHERTEXT_LEN,
                got: bytes.len(),
            });
        }
        let mut ml_kem_ct_bytes = [0u8; ML_KEM_CT_LEN];
        ml_kem_ct_bytes.copy_from_slice(&bytes[..ML_KEM_CT_LEN]);
        let mut x25519_bytes = [0u8; X25519_LEN];
        x25519_bytes.copy_from_slice(&bytes[ML_KEM_CT_LEN..]);
        Ok(Self {
            ml_kem_ct_bytes,
            x25519_eph_pk: X25519PublicKey::from(x25519_bytes),
        })
    }
}

/// Generate a fresh hybrid keypair.
///
/// The responder calls this at session setup; the public key is sent
/// to the initiator who then encapsulates against it.
pub fn keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
    // ML-KEM-768.
    let (dk, ek) = MlKem768::generate(rng);
    let encoded_public = ek.as_bytes();
    let mut public_key_bytes = [0u8; ML_KEM_EK_LEN];
    public_key_bytes.copy_from_slice(&encoded_public);

    // `dk` wipes itself on drop (ml-kem's `zeroize` feature). Its encoded
    // form is a separate copy and is wiped here once it has been moved into
    // the wiping wrapper.
    let mut encoded_secret = dk.as_bytes();
    let mut secret_key_bytes = Zeroizing::new([0u8; ML_KEM_DK_LEN]);
    secret_key_bytes[..].copy_from_slice(&encoded_secret);
    encoded_secret.zeroize();

    // X25519.
    let responder_dh_secret = X25519StaticSecret::random_from_rng(&mut *rng);
    let responder_dh_public = X25519PublicKey::from(&responder_dh_secret);

    (
        HybridPublicKey {
            ml_kem_ek_bytes: public_key_bytes,
            x25519_pk: responder_dh_public,
        },
        HybridSecretKey {
            ml_kem_dk_bytes: secret_key_bytes,
            x25519_sk: responder_dh_secret,
        },
    )
}

/// Encapsulate a fresh shared secret against `pk`. The initiator
/// produces the ciphertext + shared secret here; the ciphertext is
/// sent to the responder, who decapsulates to get the same secret.
pub fn encapsulate<R: RngCore + CryptoRng>(
    pk: &HybridPublicKey,
    rng: &mut R,
) -> Result<(HybridCiphertext, SharedSecret), PqKemError> {
    // ML-KEM side. The `ml-kem` 0.2 API uses a typed `Array<u8, N>` for
    // the encoded key; convert from our fixed-size byte array via
    // `Array::from(arr)` (re-exported as `hybrid_array::Array`).
    let ek_bytes_arr: hybrid_array::Array<u8, MlKem768EkEncoded> =
        hybrid_array::Array::from(pk.ml_kem_ek_bytes);
    let ek = <ml_kem::MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes_arr);
    let (ct, mut mlkem_ss) = ek.encapsulate(rng).map_err(|()| PqKemError::MlKemFailed {
        reason: "encapsulate",
    })?;
    let mut ml_kem_ct_bytes = [0u8; ML_KEM_CT_LEN];
    ml_kem_ct_bytes.copy_from_slice(&ct);
    let mut mlkem_ss_bytes = Zeroizing::new([0u8; X25519_LEN]);
    mlkem_ss_bytes[..].copy_from_slice(&mlkem_ss);
    mlkem_ss.zeroize();

    // X25519 side: ephemeral keypair, DH against the responder's static pk.
    let sender_ephemeral_secret = X25519StaticSecret::random_from_rng(&mut *rng);
    let sender_ephemeral_public = X25519PublicKey::from(&sender_ephemeral_secret);
    let x25519_ss = sender_ephemeral_secret.diffie_hellman(&pk.x25519_pk);

    let ciphertext = HybridCiphertext {
        ml_kem_ct_bytes,
        x25519_eph_pk: sender_ephemeral_public,
    };

    let shared = combine(
        &ml_kem_ct_bytes,
        &mlkem_ss_bytes,
        sender_ephemeral_public.as_bytes(),
        x25519_ss.as_bytes(),
    );
    Ok((ciphertext, shared))
}

/// Decapsulate `ct` with `sk` and return the same shared secret the
/// initiator derived.
pub fn decapsulate(
    sk: &HybridSecretKey,
    ct: &HybridCiphertext,
) -> Result<SharedSecret, PqKemError> {
    // ML-KEM side. The typed copy of the encoded key is wiped as soon as the
    // key object has been built from it; the key object wipes itself on drop.
    let mut dk_bytes_arr: hybrid_array::Array<u8, MlKem768DkEncoded> =
        hybrid_array::Array::default();
    dk_bytes_arr.copy_from_slice(&sk.ml_kem_dk_bytes[..]);
    let dk = <ml_kem::MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_bytes_arr);
    dk_bytes_arr.zeroize();
    let ct_bytes_arr: hybrid_array::Array<u8, MlKem768CtSize> =
        hybrid_array::Array::from(ct.ml_kem_ct_bytes);
    let mut mlkem_ss = dk
        .decapsulate(&ct_bytes_arr)
        .map_err(|()| PqKemError::MlKemFailed {
            reason: "decapsulate",
        })?;
    let mut mlkem_ss_bytes = Zeroizing::new([0u8; X25519_LEN]);
    mlkem_ss_bytes[..].copy_from_slice(&mlkem_ss);
    mlkem_ss.zeroize();

    // X25519 side.
    let x25519_ss = sk.x25519_sk.diffie_hellman(&ct.x25519_eph_pk);

    let shared = combine(
        &ct.ml_kem_ct_bytes,
        &mlkem_ss_bytes,
        ct.x25519_eph_pk.as_bytes(),
        x25519_ss.as_bytes(),
    );
    Ok(shared)
}

/// BLAKE3-based hybrid combiner. Input layout per ADR-0017:
///
/// `derive_key(COMBINER_CONTEXT, mlkem_ct || mlkem_ss || x25519_eph_pk || x25519_ss)`
///
/// The inputs are streamed into the hasher. Concatenating them first put
/// both shared secrets into a heap buffer that was freed without being
/// wiped; streaming produces the identical key and leaves no such copy.
///
/// # What this combiner does not bind
///
/// The recipient's public key is not an input. ML-KEM binds its own half
/// (the encapsulation key is hashed into the ML-KEM shared secret), but the
/// X25519 half is bound only to the ephemeral key. Used alone, this is not
/// a key-binding KEM. One Link never uses it alone: the channel handshake
/// feeds this output into HKDF together with a transcript hash that covers
/// both identities, the full hybrid public key and the ciphertext
/// (`channel.py`, and `tests/test_channel_pq_handshake.py` proves a changed
/// key changes the session). Adding the recipient key here would change
/// every derived key, so it has to arrive as a new negotiated suite, not
/// as an edit to "v1".
fn combine(
    ml_kem_ct: &[u8; ML_KEM_CT_LEN],
    ml_kem_ss: &[u8; X25519_LEN],
    x25519_eph_pk: &[u8; X25519_LEN],
    x25519_ss: &[u8; X25519_LEN],
) -> SharedSecret {
    let mut hasher = blake3::Hasher::new_derive_key(COMBINER_CONTEXT);
    hasher.update(ml_kem_ct);
    hasher.update(ml_kem_ss);
    hasher.update(x25519_eph_pk);
    hasher.update(x25519_ss);
    let key = Zeroizing::new(*hasher.finalize().as_bytes());
    hasher.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn encap_decap_round_trip_single() {
        let mut rng = StdRng::seed_from_u64(0xCAFE);
        let (pk, sk) = keypair(&mut rng);
        let (ct, ss_initiator) = encapsulate(&pk, &mut rng).unwrap();
        let ss_responder = decapsulate(&sk, &ct).unwrap();
        assert_eq!(*ss_initiator, *ss_responder);
        assert_eq!(ss_initiator.len(), SHARED_SECRET_LEN);
    }

    #[test]
    fn wire_round_trip_pk_sk_ct() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let (pk, sk) = keypair(&mut rng);
        let pk_bytes = pk.to_bytes();
        assert_eq!(pk_bytes.len(), HYBRID_PUBLIC_KEY_LEN);
        let pk_again = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
        // Round-trip the pk through encap/decap to confirm correctness.
        let (ct, ss1) = encapsulate(&pk_again, &mut rng).unwrap();
        let ct_bytes = ct.to_bytes();
        assert_eq!(ct_bytes.len(), HYBRID_CIPHERTEXT_LEN);
        let ct_again = HybridCiphertext::from_bytes(&ct_bytes).unwrap();
        let ss2 = decapsulate(&sk, &ct_again).unwrap();
        assert_eq!(*ss1, *ss2);

        // sk round trip.
        let sk_bytes = sk.to_bytes();
        let sk_again = HybridSecretKey::from_bytes(&sk_bytes[..]).unwrap();
        let ss3 = decapsulate(&sk_again, &ct_again).unwrap();
        assert_eq!(*ss1, *ss3);
    }

    #[test]
    fn distinct_keypairs_yield_distinct_secrets() {
        let mut rng = StdRng::seed_from_u64(0xDEAD);
        let (pk_a, _) = keypair(&mut rng);
        let (pk_b, _) = keypair(&mut rng);
        let (_, ss_a) = encapsulate(&pk_a, &mut rng).unwrap();
        let (_, ss_b) = encapsulate(&pk_b, &mut rng).unwrap();
        assert_ne!(*ss_a, *ss_b);
    }

    /// The combiner must keep producing exactly what it produced when its
    /// inputs were concatenated, or peers on different builds stop agreeing.
    #[test]
    fn streamed_combiner_matches_the_concatenated_definition() {
        let ct = [0x11u8; ML_KEM_CT_LEN];
        let mlkem_ss = [0x22u8; X25519_LEN];
        let eph = [0x33u8; X25519_LEN];
        let dh = [0x44u8; X25519_LEN];
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&ct);
        concatenated.extend_from_slice(&mlkem_ss);
        concatenated.extend_from_slice(&eph);
        concatenated.extend_from_slice(&dh);
        let expected = blake3::derive_key(COMBINER_CONTEXT, &concatenated);
        assert_eq!(*combine(&ct, &mlkem_ss, &eph, &dh), expected);
    }

    #[test]
    fn honest_keys_pass_the_modulus_check() {
        let mut rng = StdRng::seed_from_u64(0x0A11);
        for _ in 0..16 {
            let (pk, _) = keypair(&mut rng);
            assert!(HybridPublicKey::from_bytes(&pk.to_bytes()).is_ok());
        }
    }

    #[test]
    fn unreduced_coefficient_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x0BAD);
        let (pk, _) = keypair(&mut rng);
        let honest = pk.to_bytes();

        // First coefficient = 0xFFF (4095 >= q).
        let mut low = honest;
        low[0] = 0xFF;
        low[1] |= 0x0F;
        assert!(matches!(
            HybridPublicKey::from_bytes(&low),
            Err(PqKemError::InvalidEncapsulationKey)
        ));

        // Second coefficient of the last triple = q exactly (0xD01).
        let mut high = honest;
        let last = ML_KEM_EK_T_HAT_LEN - 3;
        high[last + 1] = (high[last + 1] & 0x0F) | 0x10;
        high[last + 2] = 0xD0;
        assert!(matches!(
            HybridPublicKey::from_bytes(&high),
            Err(PqKemError::InvalidEncapsulationKey)
        ));

        // q - 1 is the largest legal value and must still be accepted.
        let mut edge = honest;
        edge[0] = 0x00;
        edge[1] = (edge[1] & 0xF0) | 0x0D;
        assert!(HybridPublicKey::from_bytes(&edge).is_ok());
    }

    #[test]
    fn the_seed_bytes_of_a_key_are_not_range_checked() {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        let (pk, _) = keypair(&mut rng);
        let mut bytes = pk.to_bytes();
        for b in &mut bytes[ML_KEM_EK_T_HAT_LEN..ML_KEM_EK_LEN] {
            *b = 0xFF;
        }
        assert!(HybridPublicKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(HybridPublicKey::from_bytes(&[0u8; 100]).is_err());
        assert!(HybridSecretKey::from_bytes(&[0u8; 100]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 100]).is_err());
    }
}
