//! T1.2 — PQ-hybrid blinding for Sphinx Coherence.
//!
//! The first relay in the circuit has an ML-KEM-768 long-term key
//! pair alongside its Ristretto255 key. The sender encapsulates to
//! the entry relay's PQ pubkey and mixes the resulting shared
//! secret into hop 0's BLAKE3 key derivation:
//!
//! ```text
//!   classical_shared = (eph_sk * cumulative_blind) * relay_x_pk
//!   pq_shared        = ML-KEM-768.Encap(relay_pq_pk).shared
//!   hybrid_shared    = BLAKE3("hybrid" || classical_shared || pq_shared || alpha)
//! ```
//!
//! The hybrid binding flows down the chain via `cumulative_blind`:
//! every subsequent `alpha_i` is `b_0 * b_1 * ... * b_{i-1} * alpha_0`
//! where `b_0` is derived from `hybrid_shared`. Under the security of
//! ML-KEM-768 and the hybrid composition, recovering only the classical
//! component is insufficient to reproduce this KDF input. The tests in
//! this module establish input binding and round trips, not quantum-
//! adversary resistance or a proof of the complete protocol.
//!
//! ## Wire format addition
//!
//! The PQ-hybrid Sphinx packet inserts an 1088-byte ML-KEM ciphertext
//! between alpha and `header_mac`. Total packet size:
//!
//! ```text
//!   1 + 32 + 1088 + 16 + 240 + 1024 = 2401 bytes
//! ```
//!
//! ## Relay modes
//!
//! - **Entry relay**: holds an ML-KEM decapsulation key. Decapsulates
//!   the carried ciphertext and uses hybrid derivation.
//! - **Intermediate relay**: ignores the carried ciphertext (it was
//!   encapsulated for the entry relay only). Uses classical
//!   Ristretto255-only derivation.
//!
//! The daemon's transport layer knows whether the packet arrived
//! directly from the sender (entry mode) or via a forwarded peel
//! (intermediate mode), so it calls the appropriate peel function.

use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hybrid_array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::errors::{OnionError, OnionResult};
use crate::hop::HopId;
use crate::keyderiv::is_all_zero_ct;
#[cfg(test)]
use crate::sphinx::core::generate_static_keypair;
use crate::sphinx::core::RISTRETTO_POINT_LEN;
use crate::sphinx::header::{build_header, peel_header, HeaderPeelOutcome, DESTINATION_MARKER};
use crate::sphinx::primitives::{
    chacha20_xor_in_place, derive_hop_keys, HopKeys, HEADER_LEN, MAX_HOPS, PAYLOAD_LEN,
    SLOT_ID_LEN, SLOT_LEN, SLOT_MAC_LEN,
};
use crate::PROTOCOL_DOMAIN;

/// ML-KEM-768 ciphertext length (FIPS 203 §6.3.1).
pub const ML_KEM_CT_LEN: usize = 1088;

/// ML-KEM-768 encapsulation-key length.
pub const ML_KEM_EK_LEN: usize = 1184;

/// PQ Sphinx wire protocol version. Distinct from classical `SPHINX_VERSION`.
pub const PQ_SPHINX_VERSION: u8 = 4;

/// Total fixed PQ-hybrid Sphinx packet size:
/// version(1) + alpha(32) + `pq_ct`(1088) + mac(16) + header(240) + payload(1024).
pub const PQ_SPHINX_PACKET_LEN: usize =
    1 + RISTRETTO_POINT_LEN + ML_KEM_CT_LEN + SLOT_MAC_LEN + HEADER_LEN + PAYLOAD_LEN;

/// Type alias for the ML-KEM-768 encapsulation key.
type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
/// Type alias for the ML-KEM-768 decapsulation key.
type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemCtSize = <MlKem768 as KemCore>::CiphertextSize;

/// PQ-hybrid Sphinx hop: classical Ristretto255 + ML-KEM-768 pubkey.
#[derive(Clone)]
pub struct PqSphinxHop {
    pub id: HopId,
    pub static_x_pk: RistrettoPoint,
    /// ML-KEM-768 encapsulation key. Only the ENTRY hop needs to
    /// carry one; intermediate hops use empty bytes (skip PQ).
    /// `None` means classical-only (intermediate hops).
    pub static_pq_pk: Option<MlKemEk>,
}

impl std::fmt::Debug for PqSphinxHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqSphinxHop")
            .field("id", &self.id)
            .field("has_pq_pk", &self.static_pq_pk.is_some())
            .finish_non_exhaustive()
    }
}

/// Generate a fresh ML-KEM-768 keypair.
pub fn generate_pq_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (MlKemDk, MlKemEk) {
    MlKem768::generate(rng)
}

/// Combine classical X25519/Ristretto ECDH output with an ML-KEM-768
/// shared secret via BLAKE3 to produce a hybrid shared secret.
///
/// `classical_shared`: 32-byte Ristretto255 ECDH output.
/// `pq_shared`: 32-byte ML-KEM-768 shared key.
/// `alpha`: 32-byte hop ephemeral pubkey (binds the derivation to
/// this specific packet).
pub fn combine_hybrid_shared(
    classical_shared: &[u8; 32],
    pq_shared: &[u8; 32],
    alpha: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(b"-sphinx-pq-hybrid-v1");
    h.update(classical_shared);
    h.update(pq_shared);
    h.update(alpha);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// PQ-hybrid Sphinx packet.
#[derive(Clone)]
pub struct PqSphinxPacket {
    bytes: Vec<u8>,
}

impl PqSphinxPacket {
    /// Wrap raw wire bytes.
    pub fn from_bytes(b: &[u8]) -> OnionResult<Self> {
        if b.len() != PQ_SPHINX_PACKET_LEN {
            return Err(OnionError::BadFrameSize {
                got: b.len(),
                expected: PQ_SPHINX_PACKET_LEN,
            });
        }
        if b[0] != PQ_SPHINX_VERSION {
            return Err(OnionError::UnsupportedVersion {
                got: b[0],
                supported: PQ_SPHINX_VERSION,
            });
        }
        Ok(Self { bytes: b.to_vec() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn alpha(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.bytes[1..33]);
        a
    }

    fn pq_ct(&self) -> &[u8] {
        &self.bytes[33..33 + ML_KEM_CT_LEN]
    }

    fn mac(&self) -> [u8; SLOT_MAC_LEN] {
        let start = 33 + ML_KEM_CT_LEN;
        let mut m = [0u8; SLOT_MAC_LEN];
        m.copy_from_slice(&self.bytes[start..start + SLOT_MAC_LEN]);
        m
    }

    fn header(&self) -> &[u8] {
        let start = 33 + ML_KEM_CT_LEN + SLOT_MAC_LEN;
        &self.bytes[start..start + HEADER_LEN]
    }

    fn payload(&self) -> &[u8] {
        let start = 33 + ML_KEM_CT_LEN + SLOT_MAC_LEN + HEADER_LEN;
        &self.bytes[start..start + PAYLOAD_LEN]
    }
}

impl std::fmt::Debug for PqSphinxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqSphinxPacket")
            .field("len", &self.bytes.len())
            .field("version", &self.bytes.first().copied().unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl PartialEq for PqSphinxPacket {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}
impl Eq for PqSphinxPacket {}

/// Outcome of a PQ-hybrid Sphinx peel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqSphinxPeelOutcome {
    Forward {
        next_hop: HopId,
        next_packet: PqSphinxPacket,
    },
    Deliver {
        payload: Vec<u8>,
    },
}

/// Build a PQ-hybrid Sphinx packet.
///
/// `circuit[0]` MUST have `static_pq_pk = Some(_)` (the entry hop).
/// Subsequent hops MAY have `None` — the PQ binding propagates via
/// cumulative blinding.
pub fn build_pq_sphinx_onion<R: RngCore + CryptoRng>(
    sender_eph_sk: &Scalar,
    circuit: &[PqSphinxHop],
    payload: &[u8],
    rng: &mut R,
) -> OnionResult<PqSphinxPacket> {
    if circuit.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    if circuit.len() > MAX_HOPS {
        return Err(OnionError::TooManyHops {
            got: circuit.len(),
            max: MAX_HOPS,
        });
    }
    if payload.len() > PAYLOAD_LEN - 2 {
        return Err(OnionError::PayloadOversize {
            got: payload.len(),
            max: PAYLOAD_LEN - 2,
        });
    }
    // Entry hop must have a PQ pubkey.
    let entry_pq_pk = circuit[0]
        .static_pq_pk
        .as_ref()
        .ok_or(OnionError::Internal("first hop must have an ML-KEM pubkey"))?;

    // ── Step 1: ML-KEM encapsulation to entry hop.
    let (pq_ct, pq_shared) = entry_pq_pk
        .encapsulate(rng)
        .map_err(|()| OnionError::Internal("ML-KEM encapsulation failed"))?;
    let pq_ct_bytes: &Array<u8, MlKemCtSize> = &pq_ct;
    let pq_shared_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        s.copy_from_slice(&pq_shared);
        s
    };

    // ── Step 2: precompute alpha chain + shared secrets + hop keys.
    let n = circuit.len();
    let alpha_0 = sender_eph_sk * RISTRETTO_BASEPOINT_TABLE;
    let mut cumulative_blind = Scalar::ONE;
    let mut hop_keys: Vec<HopKeys> = Vec::with_capacity(n);
    let mut alpha_i = alpha_0;

    for (i, hop) in circuit.iter().enumerate() {
        let alpha_bytes = alpha_i.compress().to_bytes();
        let classical_shared_point = (sender_eph_sk * cumulative_blind) * hop.static_x_pk;
        let classical_shared = classical_shared_point.compress().to_bytes();
        // ct-audit: declassify (small-order verdict is the public result)
        if is_all_zero_ct(&classical_shared) {
            return Err(OnionError::SmallOrderPubkey);
        }
        let derive_input = if i == 0 {
            // Entry hop: hybrid derivation.
            combine_hybrid_shared(&classical_shared, &pq_shared_bytes, &alpha_bytes)
        } else {
            classical_shared
        };
        let keys = derive_hop_keys(&derive_input, &alpha_bytes);
        // Audit L1 May 2026: wide reduction from 64-byte seed.
        let b_i = Scalar::from_bytes_mod_order_wide(&keys.blinding_seed);
        hop_keys.push(keys);
        cumulative_blind *= b_i;
        alpha_i = b_i * alpha_i;
    }

    // ── Step 3: build header.
    let mut next_hop_ids: Vec<[u8; SLOT_ID_LEN]> =
        circuit.iter().skip(1).map(|h| *h.id.as_bytes()).collect();
    next_hop_ids.push(DESTINATION_MARKER);

    let n_relays = n - 1;
    let filler_len = n_relays * SLOT_LEN;
    let pad_len = HEADER_LEN - SLOT_LEN - filler_len;
    let mut random_pad = vec![0u8; pad_len];
    rng.fill_bytes(&mut random_pad);

    let built = build_header(&hop_keys, &next_hop_ids, &random_pad)?;

    // ── Step 4: build encrypted payload — in-place, no per-hop Vec.
    let mut payload_buf = [0u8; PAYLOAD_LEN];
    // Payload length is bounded above by SPHINX_MAX_USER_PAYLOAD
    // (≤ u16::MAX) — enforced by the entry-time check. Cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let plen_u16 = payload.len() as u16;
    payload_buf[..2].copy_from_slice(&plen_u16.to_be_bytes());
    payload_buf[2..2 + payload.len()].copy_from_slice(payload);
    for keys in hop_keys.iter().rev() {
        chacha20_xor_in_place(&keys.payload_stream, &mut payload_buf);
    }

    // ── Step 5: assemble outer packet.
    let mut bytes = vec![0u8; PQ_SPHINX_PACKET_LEN];
    bytes[0] = PQ_SPHINX_VERSION;
    bytes[1..33].copy_from_slice(&alpha_0.compress().to_bytes());
    bytes[33..33 + ML_KEM_CT_LEN].copy_from_slice(pq_ct_bytes);
    let mac_start = 33 + ML_KEM_CT_LEN;
    bytes[mac_start..mac_start + SLOT_MAC_LEN].copy_from_slice(&built.mac);
    let hdr_start = mac_start + SLOT_MAC_LEN;
    bytes[hdr_start..hdr_start + HEADER_LEN].copy_from_slice(&built.header);
    bytes[hdr_start + HEADER_LEN..].copy_from_slice(&payload_buf);

    // Zeroize sensitive material.
    for mut k in hop_keys {
        k.header_stream.zeroize();
        k.payload_stream.zeroize();
        k.mac_key.zeroize();
        k.blinding_seed.zeroize();
    }
    payload_buf.zeroize();

    Ok(PqSphinxPacket { bytes })
}

/// Peel one layer of a PQ-hybrid Sphinx packet at the ENTRY relay.
///
/// Decapsulates the carried ML-KEM ciphertext with the entry relay's
/// PQ decapsulation key, then derives the hybrid shared secret +
/// peels the header + payload.
///
/// After this peel, the OUTPUT packet still carries the original
/// ML-KEM ciphertext for wire-format uniformity, but downstream
/// relays will use `peel_pq_sphinx_intermediate` which ignores it.
pub fn peel_pq_sphinx_entry(
    relay_x_sk: &Scalar,
    relay_pq_sk: &MlKemDk,
    packet: &PqSphinxPacket,
) -> OnionResult<PqSphinxPeelOutcome> {
    let alpha_bytes = packet.alpha();
    if alpha_bytes.iter().all(|&b| b == 0) {
        return Err(OnionError::SmallOrderPubkey);
    }
    let alpha_point = CompressedRistretto::from_slice(&alpha_bytes)
        .map_err(|_| OnionError::SmallOrderPubkey)?
        .decompress()
        .ok_or(OnionError::SmallOrderPubkey)?;

    // Classical ECDH.
    let classical_shared = (relay_x_sk * alpha_point).compress().to_bytes();
    // ct-audit: declassify (small-order verdict is the public result)
    if is_all_zero_ct(&classical_shared) {
        return Err(OnionError::SmallOrderPubkey);
    }
    // PQ decapsulation.
    let pq_ct_slice = packet.pq_ct();
    let ct_arr: Array<u8, MlKemCtSize> =
        Array::try_from(pq_ct_slice).map_err(|_| OnionError::Internal("ML-KEM ciphertext size"))?;
    let pq_shared = relay_pq_sk
        .decapsulate(&ct_arr)
        .map_err(|()| OnionError::AeadFail)?;
    let pq_shared_bytes: [u8; 32] = {
        let mut s = [0u8; 32];
        s.copy_from_slice(&pq_shared);
        s
    };

    // Hybrid combine.
    let hybrid_shared = combine_hybrid_shared(&classical_shared, &pq_shared_bytes, &alpha_bytes);
    let keys = derive_hop_keys(&hybrid_shared, &alpha_bytes);

    finish_peel(&keys, packet, alpha_point)
}

/// Peel one layer of a PQ-hybrid Sphinx packet at an INTERMEDIATE
/// relay (downstream of the entry hop). Uses classical Ristretto255-
/// only derivation. The PQ binding still flows through alpha via
/// cumulative blinding.
pub fn peel_pq_sphinx_intermediate(
    relay_x_sk: &Scalar,
    packet: &PqSphinxPacket,
) -> OnionResult<PqSphinxPeelOutcome> {
    let alpha_bytes = packet.alpha();
    if alpha_bytes.iter().all(|&b| b == 0) {
        return Err(OnionError::SmallOrderPubkey);
    }
    let alpha_point = CompressedRistretto::from_slice(&alpha_bytes)
        .map_err(|_| OnionError::SmallOrderPubkey)?
        .decompress()
        .ok_or(OnionError::SmallOrderPubkey)?;
    let classical_shared = (relay_x_sk * alpha_point).compress().to_bytes();
    // ct-audit: declassify (small-order verdict is the public result)
    if is_all_zero_ct(&classical_shared) {
        return Err(OnionError::SmallOrderPubkey);
    }
    let keys = derive_hop_keys(&classical_shared, &alpha_bytes);
    finish_peel(&keys, packet, alpha_point)
}

fn finish_peel(
    keys: &HopKeys,
    packet: &PqSphinxPacket,
    alpha_point: RistrettoPoint,
) -> OnionResult<PqSphinxPeelOutcome> {
    let mac = packet.mac();
    let outcome = peel_header(keys, packet.header(), &mac).map_err(|()| OnionError::AeadFail)?;

    let mut payload = vec![0u8; PAYLOAD_LEN];
    payload.copy_from_slice(packet.payload());
    chacha20_xor_in_place(&keys.payload_stream, &mut payload);

    match outcome {
        HeaderPeelOutcome::Deliver => {
            let plen = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
            if plen > PAYLOAD_LEN - 2 {
                return Err(OnionError::Internal("destination payload length oversize"));
            }
            let mut user_payload = vec![0u8; plen];
            user_payload.copy_from_slice(&payload[2..2 + plen]);
            Ok(PqSphinxPeelOutcome::Deliver {
                payload: user_payload,
            })
        }
        HeaderPeelOutcome::Forward {
            next_hop_id,
            next_header,
            next_mac,
        } => {
            // Audit L1 May 2026: wide reduction.
            let b_scalar = Scalar::from_bytes_mod_order_wide(&keys.blinding_seed);
            let next_alpha = b_scalar * alpha_point;
            let next_alpha_bytes = next_alpha.compress().to_bytes();

            // Assemble next packet — keep the ORIGINAL pq_ct field
            // intact for wire-format uniformity (intermediate peel
            // ignores it).
            let mut bytes = vec![0u8; PQ_SPHINX_PACKET_LEN];
            bytes[0] = PQ_SPHINX_VERSION;
            bytes[1..33].copy_from_slice(&next_alpha_bytes);
            bytes[33..33 + ML_KEM_CT_LEN].copy_from_slice(packet.pq_ct());
            let mac_start = 33 + ML_KEM_CT_LEN;
            bytes[mac_start..mac_start + SLOT_MAC_LEN].copy_from_slice(&next_mac);
            let hdr_start = mac_start + SLOT_MAC_LEN;
            bytes[hdr_start..hdr_start + HEADER_LEN].copy_from_slice(&next_header);
            bytes[hdr_start + HEADER_LEN..].copy_from_slice(&payload);

            Ok(PqSphinxPeelOutcome::Forward {
                next_hop: HopId::from_bytes(next_hop_id),
                next_packet: PqSphinxPacket { bytes },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_entry_relay() -> (Scalar, MlKemDk, PqSphinxHop) {
        let (relay_secret, relay_public) = generate_static_keypair(&mut OsRng);
        let (pq_receiver_key, pq_sender_key) = generate_pq_keypair(&mut OsRng);
        (
            relay_secret,
            pq_receiver_key,
            PqSphinxHop {
                // 32 INDEPENDENT random bytes; `[rand::random(); N]` would
                // copy one byte and collide with DESTINATION_MARKER 1/256.
                id: HopId::from_bytes(rand::random::<[u8; SLOT_ID_LEN]>()),
                static_x_pk: relay_public,
                static_pq_pk: Some(pq_sender_key),
            },
        )
    }

    fn make_intermediate_relay() -> (Scalar, PqSphinxHop) {
        let (relay_secret, relay_public) = generate_static_keypair(&mut OsRng);
        (
            relay_secret,
            PqSphinxHop {
                // 32 INDEPENDENT random bytes; `[rand::random(); N]` would
                // copy one byte and collide with DESTINATION_MARKER 1/256.
                id: HopId::from_bytes(rand::random::<[u8; SLOT_ID_LEN]>()),
                static_x_pk: relay_public,
                static_pq_pk: None,
            },
        )
    }

    #[test]
    fn one_hop_pq_hybrid_round_trip() {
        let (entry_sk, entry_pq_sk, entry) = make_entry_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet = build_pq_sphinx_onion(
            &eph_sk,
            std::slice::from_ref(&entry),
            b"pq-hybrid",
            &mut OsRng,
        )
        .unwrap();
        // The entry IS the destination here (1-hop circuit).
        let outcome = peel_pq_sphinx_entry(&entry_sk, &entry_pq_sk, &packet).unwrap();
        match outcome {
            PqSphinxPeelOutcome::Deliver { payload } => assert_eq!(payload, b"pq-hybrid"),
            PqSphinxPeelOutcome::Forward { .. } => panic!(),
        }
    }

    #[test]
    fn three_hop_pq_hybrid_round_trip() {
        let (entry_sk, entry_pq_sk, entry) = make_entry_relay();
        let (mid_sk, mid) = make_intermediate_relay();
        let (dest_sk, dest) = make_intermediate_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let circuit = vec![entry.clone(), mid.clone(), dest.clone()];
        let packet = build_pq_sphinx_onion(&eph_sk, &circuit, b"three-hop pq", &mut OsRng).unwrap();

        // Entry peels with hybrid.
        let outcome = peel_pq_sphinx_entry(&entry_sk, &entry_pq_sk, &packet).unwrap();
        let next = match outcome {
            PqSphinxPeelOutcome::Forward {
                next_hop,
                next_packet,
            } => {
                assert_eq!(next_hop, mid.id);
                next_packet
            }
            PqSphinxPeelOutcome::Deliver { .. } => panic!(),
        };

        // Mid peels with classical-only.
        let outcome = peel_pq_sphinx_intermediate(&mid_sk, &next).unwrap();
        let next = match outcome {
            PqSphinxPeelOutcome::Forward {
                next_hop,
                next_packet,
            } => {
                assert_eq!(next_hop, dest.id);
                next_packet
            }
            PqSphinxPeelOutcome::Deliver { .. } => panic!(),
        };

        // Dest peels with classical-only.
        let outcome = peel_pq_sphinx_intermediate(&dest_sk, &next).unwrap();
        match outcome {
            PqSphinxPeelOutcome::Deliver { payload } => assert_eq!(payload, b"three-hop pq"),
            PqSphinxPeelOutcome::Forward { .. } => panic!(),
        }
    }

    #[test]
    fn wrong_pq_key_at_entry_fails() {
        let (entry_sk, _, entry) = make_entry_relay();
        let (wrong_pq_dk, _wrong_pq_ek) = generate_pq_keypair(&mut OsRng);
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_pq_sphinx_onion(&eph_sk, std::slice::from_ref(&entry), b"x", &mut OsRng).unwrap();
        // Wrong PQ decap key — ML-KEM has implicit rejection, so
        // decap succeeds but with a DIFFERENT shared, breaking
        // the hybrid derivation → MAC fails.
        let err = peel_pq_sphinx_entry(&entry_sk, &wrong_pq_dk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn wrong_x25519_key_at_entry_fails() {
        let (_, entry_pq_sk, entry) = make_entry_relay();
        let (wrong_x_sk, _) = generate_static_keypair(&mut OsRng);
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_pq_sphinx_onion(&eph_sk, std::slice::from_ref(&entry), b"x", &mut OsRng).unwrap();
        let err = peel_pq_sphinx_entry(&wrong_x_sk, &entry_pq_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn packet_size_constant() {
        let (entry_sk, entry_pq_sk, entry) = make_entry_relay();
        let (_, mid) = make_intermediate_relay();
        let (_, dest) = make_intermediate_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet = build_pq_sphinx_onion(&eph_sk, &[entry, mid, dest], b"x", &mut OsRng).unwrap();
        assert_eq!(packet.as_bytes().len(), PQ_SPHINX_PACKET_LEN);
        let PqSphinxPeelOutcome::Forward {
            next_packet: next, ..
        } = peel_pq_sphinx_entry(&entry_sk, &entry_pq_sk, &packet).unwrap()
        else {
            panic!();
        };
        assert_eq!(next.as_bytes().len(), PQ_SPHINX_PACKET_LEN);
    }

    #[test]
    fn combine_hybrid_shared_deterministic() {
        let cs = [0x11; 32];
        let ps = [0x22; 32];
        let a = [0x33; 32];
        let h1 = combine_hybrid_shared(&cs, &ps, &a);
        let h2 = combine_hybrid_shared(&cs, &ps, &a);
        assert_eq!(h1, h2);
    }

    #[test]
    fn combine_hybrid_shared_different_pq_yields_different() {
        let cs = [0x11; 32];
        let a = [0x33; 32];
        let h1 = combine_hybrid_shared(&cs, &[0x22; 32], &a);
        let h2 = combine_hybrid_shared(&cs, &[0x23; 32], &a);
        assert_ne!(h1, h2);
    }

    /// Input-binding regression: replacing the ML-KEM shared-secret
    /// input changes the hybrid output. This deliberately does not
    /// model a quantum adversary or prove cryptographic security.
    #[test]
    fn changing_pq_component_changes_hybrid_output() {
        let cs = [0xAA; 32];
        let a = [0xBB; 32];
        // The "true" pq shared.
        let pq_true = [0xCC; 32];
        // A deliberately different PQ input.
        let pq_guess = [0u8; 32];
        let hybrid_true = combine_hybrid_shared(&cs, &pq_true, &a);
        let hybrid_guess = combine_hybrid_shared(&cs, &pq_guess, &a);
        assert_ne!(hybrid_true, hybrid_guess);
    }
}
