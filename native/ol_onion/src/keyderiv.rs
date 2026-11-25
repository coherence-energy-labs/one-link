//! Per-layer key derivation.
//!
//! Each onion layer derives its symmetric material from one X25519
//! ECDH exchange: the sender's ephemeral key vs the relay's
//! long-term key. From the resulting 32-byte shared secret, BLAKE3
//! in keyed-derive mode produces a single 32-byte ChaCha20-Poly1305
//! AEAD key.
//!
//! The derivation is bound to a domain string + the layer's
//! ephemeral pubkey so that the SAME shared-secret bytes (which
//! cannot in practice repeat — ephemeral keys are fresh per circuit)
//! cannot produce identical layer keys across protocols.

use blake3::Hasher;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PROTOCOL_DOMAIN;

/// Length of the AEAD key derived per layer.
pub const LAYER_KEY_LEN: usize = 32;

/// A derived per-layer AEAD key. Zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LayerKey {
    inner: [u8; LAYER_KEY_LEN],
}

impl LayerKey {
    /// Construct from raw bytes (used by tests + KAT generators).
    pub fn from_bytes(b: [u8; LAYER_KEY_LEN]) -> Self {
        Self { inner: b }
    }

    /// View as 32 bytes.
    pub fn as_bytes(&self) -> &[u8; LAYER_KEY_LEN] {
        &self.inner
    }
}

impl std::fmt::Debug for LayerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak the key bytes via debug formatting.
        f.debug_struct("LayerKey").finish_non_exhaustive()
    }
}

impl PartialEq for LayerKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.inner.ct_eq(&other.inner).into()
    }
}
impl Eq for LayerKey {}

/// Sender-side: derive this layer's AEAD key.
///
/// `sender_ephemeral_sk` is the sender's per-layer ephemeral X25519
/// secret. `relay_static_pk` is the relay's long-term X25519
/// pubkey. Both sides will derive the same [`LayerKey`] (the relay
/// runs [`derive_layer_key_relay`] with reversed roles).
pub fn derive_layer_key_sender(
    sender_ephemeral_sk: &StaticSecret,
    relay_static_pk: &PublicKey,
) -> LayerKey {
    let shared = sender_ephemeral_sk.diffie_hellman(relay_static_pk);
    let ephemeral_public = PublicKey::from(sender_ephemeral_sk);
    finalize(&shared, &ephemeral_public)
}

/// Relay-side: derive this layer's AEAD key.
///
/// `relay_static_sk` is the relay's long-term X25519 secret.
/// `sender_ephemeral_pk` is the X25519 pubkey carried in this
/// layer's packet header.
pub fn derive_layer_key_relay(
    relay_static_sk: &StaticSecret,
    sender_ephemeral_pk: &PublicKey,
) -> LayerKey {
    let shared = relay_static_sk.diffie_hellman(sender_ephemeral_pk);
    finalize(&shared, sender_ephemeral_pk)
}

/// Check if a [`SharedSecret`]'s bytes are all-zero (small-order
/// pubkey defense). Both `x25519-dalek` paths fold small-order
/// inputs to zero, so this check catches them downstream.
///
/// Constant-time in the secret bytes: see [`is_all_zero_ct`].
pub fn is_zero_shared(shared: &SharedSecret) -> bool {
    is_all_zero_ct(shared.as_bytes())
}

/// Constant-time all-zero test for secret bytes (shared secrets, compressed
/// shared points).
///
/// `bytes.iter().all(|&b| b == 0)` stops at the first non-zero byte, so its
/// running time depends on the secret; whether the compiler keeps that
/// early exit depends on the call site (`ol_ct_audit` found it kept in the
/// Sphinx and obfs paths). This folds every byte with OR, so no branch or
/// address depends on the data, and converts once through `subtle`. Only
/// the returned verdict (small-order input or not) is public, and callers
/// branch on it at a line marked for the constant-time audit.
#[must_use]
pub fn is_all_zero_ct(bytes: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let folded = bytes.iter().fold(0u8, |acc, &b| acc | b);
    bool::from(folded.ct_eq(&0u8))
}

fn finalize(shared: &SharedSecret, sender_ephemeral_pk: &PublicKey) -> LayerKey {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-layer-key-v1");
    h.update(shared.as_bytes());
    h.update(sender_ephemeral_pk.as_bytes());
    let digest = h.finalize();
    let mut k = [0u8; LAYER_KEY_LEN];
    k.copy_from_slice(digest.as_bytes());
    let key = LayerKey::from_bytes(k);
    // `shared` and `k` are zeroized on drop via dalek's Zeroize +
    // our explicit array. Nothing else holds these bytes.
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn sender_and_relay_derive_same_key() {
        let sender_secret = StaticSecret::from([7u8; 32]);
        let relay_secret = StaticSecret::from([42u8; 32]);
        let relay_public = PublicKey::from(&relay_secret);

        let k_sender = derive_layer_key_sender(&sender_secret, &relay_public);

        let sender_public = PublicKey::from(&sender_secret);
        let k_relay = derive_layer_key_relay(&relay_secret, &sender_public);

        assert_eq!(k_sender, k_relay);
    }

    #[test]
    fn different_ephemerals_yield_different_keys() {
        let relay_secret = StaticSecret::from([42u8; 32]);
        let relay_public = PublicKey::from(&relay_secret);
        let esk1 = StaticSecret::from([1u8; 32]);
        let esk2 = StaticSecret::from([2u8; 32]);

        let k1 = derive_layer_key_sender(&esk1, &relay_public);
        let k2 = derive_layer_key_sender(&esk2, &relay_public);
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_relays_yield_different_keys() {
        let esk = StaticSecret::from([7u8; 32]);
        let r1 = PublicKey::from(&StaticSecret::from([1u8; 32]));
        let r2 = PublicKey::from(&StaticSecret::from([2u8; 32]));
        assert_ne!(
            derive_layer_key_sender(&esk, &r1),
            derive_layer_key_sender(&esk, &r2)
        );
    }

    #[test]
    fn layer_key_debug_does_not_leak_bytes() {
        let k = LayerKey::from_bytes([0xAB; LAYER_KEY_LEN]);
        let s = format!("{k:?}");
        // Should not contain the raw byte sequence.
        assert!(!s.contains("171"));
        assert!(!s.contains("ab"));
    }

    #[test]
    fn layer_key_partial_eq_constant_time_path() {
        let a = LayerKey::from_bytes([7u8; LAYER_KEY_LEN]);
        let b = LayerKey::from_bytes([7u8; LAYER_KEY_LEN]);
        let c = LayerKey::from_bytes([8u8; LAYER_KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
