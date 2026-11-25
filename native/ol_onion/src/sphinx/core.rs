//! Sphinx Coherence core — packet build + peel with Ristretto255
//! alpha blinding.
//!
//! Ties together [`primitives`] (key derivation, filler, `ChaCha20`)
//! and [`header`] (slot construction + shift) with the Ristretto255
//! group operations. Each hop's `alpha` is blinded so a global
//! passive adversary sees uncorrelated random group elements at
//! every relay.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::errors::{OnionError, OnionResult};
use crate::hop::HopId;
use crate::keyderiv::is_all_zero_ct;
use crate::sphinx::header::{build_header, peel_header, HeaderPeelOutcome, DESTINATION_MARKER};
use crate::sphinx::primitives::{
    chacha20_xor_in_place, derive_hop_keys, HopKeys, HEADER_LEN, MAX_HOPS, PAYLOAD_LEN,
    SLOT_ID_LEN, SLOT_LEN, SLOT_MAC_LEN,
};

/// Sphinx wire protocol version.
pub const SPHINX_VERSION: u8 = 3;

/// Length of a Ristretto255 compressed point.
pub const RISTRETTO_POINT_LEN: usize = 32;

/// Total fixed packet size:
/// version(1) + alpha(32) + mac(16) + header(`HEADER_LEN`) + payload(`PAYLOAD_LEN`).
pub const SPHINX_PACKET_LEN: usize =
    1 + RISTRETTO_POINT_LEN + SLOT_MAC_LEN + HEADER_LEN + PAYLOAD_LEN;

/// Maximum user payload length. Two bytes reserved for length prefix.
pub const SPHINX_MAX_USER_PAYLOAD: usize = PAYLOAD_LEN - 2;

/// Hop descriptor for Sphinx Coherence circuits.
///
/// Each hop has:
/// - a [`HopId`] used by upstream relays to forward the packet.
/// - a Ristretto255 static public key used for ECDH key agreement.
#[derive(Debug, Clone)]
pub struct SphinxHop {
    pub id: HopId,
    pub static_pk: RistrettoPoint,
}

impl SphinxHop {
    /// Construct from raw bytes. Refuses invalid Ristretto255 encodings.
    pub fn new(id: [u8; SLOT_ID_LEN], static_pk_bytes: [u8; 32]) -> OnionResult<Self> {
        let pk = CompressedRistretto::from_slice(&static_pk_bytes)
            .map_err(|_| OnionError::SmallOrderPubkey)?
            .decompress()
            .ok_or(OnionError::SmallOrderPubkey)?;
        if pk == RistrettoPoint::identity() {
            return Err(OnionError::SmallOrderPubkey);
        }
        Ok(Self {
            id: HopId::from_bytes(id),
            static_pk: pk,
        })
    }

    /// Compress the static pubkey to wire bytes.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.static_pk.compress().to_bytes()
    }
}

/// Generate a fresh Sphinx static secret + corresponding public key.
///
/// Audit I1 May 2026 (defense-in-depth): rejects the scalar-zero
/// case so the returned pubkey is never the Ristretto255 identity
/// point. Probability of hitting this naturally is ~2^-252 — an
/// adversary cannot grind it — but the trivial early-exit costs
/// nothing and removes the "identity scalar leaks every shared
/// secret as zero" footgun. Re-rolls on the astronomically rare
/// hit; bounded retry count keeps the function total.
pub fn generate_static_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Scalar, RistrettoPoint) {
    // 64 retries gives 2^-(252*64) probability of failure — beyond
    // any thermodynamic bound. The loop is purely structural.
    for _ in 0..64 {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        if scalar == Scalar::ZERO {
            continue;
        }
        let point = &scalar * RISTRETTO_BASEPOINT_TABLE;
        return (scalar, point);
    }
    // Unreachable in any universe with a working RNG. If the RNG is
    // broken (all-zeros), the daemon should fail loudly rather than
    // silently return a zero-scalar keypair — panic preserves the
    // invariant that callers never observe a zero scalar.
    panic!("generate_static_keypair: RNG returned 64 consecutive zero scalars (broken RNG)")
}

/// Sphinx Coherence wire packet (fixed [`SPHINX_PACKET_LEN`] bytes).
#[derive(Clone)]
pub struct SphinxPacket {
    bytes: [u8; SPHINX_PACKET_LEN],
}

impl SphinxPacket {
    /// Wrap raw wire bytes after validating length + version.
    pub fn from_bytes(b: &[u8]) -> OnionResult<Self> {
        if b.len() != SPHINX_PACKET_LEN {
            return Err(OnionError::BadFrameSize {
                got: b.len(),
                expected: SPHINX_PACKET_LEN,
            });
        }
        if b[0] != SPHINX_VERSION {
            return Err(OnionError::UnsupportedVersion {
                got: b[0],
                supported: SPHINX_VERSION,
            });
        }
        let mut bytes = [0u8; SPHINX_PACKET_LEN];
        bytes.copy_from_slice(b);
        Ok(Self { bytes })
    }

    /// View the wire bytes.
    pub fn as_bytes(&self) -> &[u8; SPHINX_PACKET_LEN] {
        &self.bytes
    }

    fn alpha(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.bytes[1..33]);
        a
    }

    fn mac(&self) -> [u8; SLOT_MAC_LEN] {
        let mut m = [0u8; SLOT_MAC_LEN];
        m.copy_from_slice(&self.bytes[33..33 + SLOT_MAC_LEN]);
        m
    }

    fn header(&self) -> &[u8] {
        let start = 33 + SLOT_MAC_LEN;
        &self.bytes[start..start + HEADER_LEN]
    }

    fn payload(&self) -> &[u8] {
        let start = 33 + SLOT_MAC_LEN + HEADER_LEN;
        &self.bytes[start..start + PAYLOAD_LEN]
    }
}

impl std::fmt::Debug for SphinxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SphinxPacket")
            .field("version", &self.bytes[0])
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for SphinxPacket {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}
impl Eq for SphinxPacket {}

/// Outcome of [`peel_sphinx_layer`].
///
/// The `Forward` variant carries a full `SphinxPacket` (the dominant
/// size). Boxing it to equalize variant sizes would force a heap
/// allocation on every relay hop — the hot path — for a value that is
/// constructed and consumed immediately, so we keep it inline.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SphinxPeelOutcome {
    /// Forward to the next hop with the new packet.
    Forward {
        next_hop: HopId,
        next_packet: SphinxPacket,
    },
    /// This relay is the destination — deliver the payload.
    Deliver { payload: Vec<u8> },
    /// Audit M4: authenticated cover-traffic packet. The destination's
    /// cryptographic check matched the per-circuit cover-trailer MAC,
    /// so this is a Row-6 cover packet — drop silently without
    /// surfacing the payload to the application.
    ///
    /// Replaces the pre-M4 plaintext-sentinel detection, which was
    /// forgeable: a network attacker could bit-flip the first 8 bytes
    /// of any real payload to look like the sentinel and cause the
    /// destination to drop a legitimate packet. The MAC binding makes
    /// the cover claim unforgeable without the per-hop shared key.
    Cover,
}

/// Build a Sphinx Coherence onion packet for delivery along the
/// chosen circuit.
///
/// - `sender_eph_sk`: a fresh per-circuit ephemeral Ristretto255 secret
///   (generated via [`generate_static_keypair`] then discarded after build).
/// - `circuit`: ordered hops, last is the destination.
/// - `payload`: user payload bytes (up to [`SPHINX_MAX_USER_PAYLOAD`]).
/// - `rng`: source of random pad bytes for the destination header.
pub fn build_sphinx_onion<R: RngCore + CryptoRng>(
    sender_eph_sk: &Scalar,
    circuit: &[SphinxHop],
    payload: &[u8],
    rng: &mut R,
) -> OnionResult<SphinxPacket> {
    if circuit.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    if circuit.len() > MAX_HOPS {
        return Err(OnionError::TooManyHops {
            got: circuit.len(),
            max: MAX_HOPS,
        });
    }
    if payload.len() > SPHINX_MAX_USER_PAYLOAD {
        return Err(OnionError::PayloadOversize {
            got: payload.len(),
            max: SPHINX_MAX_USER_PAYLOAD,
        });
    }

    // ── Step 1: precompute the alpha chain + shared secrets + hop keys.
    let n = circuit.len();
    let alpha_0 = sender_eph_sk * RISTRETTO_BASEPOINT_TABLE;
    let mut cumulative_blind = Scalar::ONE;
    let mut hop_keys: Vec<HopKeys> = Vec::with_capacity(n);
    let mut alpha_i = alpha_0;

    for hop in circuit {
        let alpha_bytes = alpha_i.compress().to_bytes();
        // Shared secret: sender_eph_sk * cumulative_blind * hop.pk.
        let shared_point = (sender_eph_sk * cumulative_blind) * hop.static_pk;
        let shared_bytes = shared_point.compress().to_bytes();
        // ct-audit: declassify (small-order verdict is the public result)
        if is_all_zero_ct(&shared_bytes) {
            return Err(OnionError::SmallOrderPubkey);
        }
        let keys = derive_hop_keys(&shared_bytes, &alpha_bytes);
        // Compute blinding scalar for next hop. Audit L1 May 2026:
        // wide reduction from 64-byte seed → bias-free scalar.
        let b_i = Scalar::from_bytes_mod_order_wide(&keys.blinding_seed);
        hop_keys.push(keys);
        // Update for next iter.
        cumulative_blind *= b_i;
        alpha_i = b_i * alpha_i;
    }
    // alpha_i is now the alpha that the destination's "next" hop
    // would receive — unused (no next hop after destination).

    // ── Step 2: build the routing-info header.
    let mut next_hop_ids: Vec<[u8; SLOT_ID_LEN]> =
        circuit.iter().skip(1).map(|h| *h.id.as_bytes()).collect();
    next_hop_ids.push(DESTINATION_MARKER);
    debug_assert_eq!(next_hop_ids.len(), n);

    let n_relays = n - 1;
    let filler_len = n_relays * SLOT_LEN;
    let pad_len = HEADER_LEN - SLOT_LEN - filler_len;
    let mut random_pad = vec![0u8; pad_len];
    rng.fill_bytes(&mut random_pad);

    let built = build_header(&hop_keys, &next_hop_ids, &random_pad)?;

    // ── Step 3: build the encrypted payload (right-to-left).
    let mut payload_buf = [0u8; PAYLOAD_LEN];
    // Length prefix (2 bytes) + payload. The length is bounded above by
    // SPHINX_MAX_USER_PAYLOAD (= PAYLOAD_LEN - 2 ≤ u16::MAX), enforced
    // by the early-return check above, so the cast is invariant-safe.
    #[allow(clippy::cast_possible_truncation)]
    let plen_u16 = payload.len() as u16;
    payload_buf[..2].copy_from_slice(&plen_u16.to_be_bytes());
    payload_buf[2..2 + payload.len()].copy_from_slice(payload);
    // Encrypt in-place with each hop's payload stream, innermost first.
    // No per-hop Vec allocation — chacha20 XORs directly into payload_buf.
    for keys in hop_keys.iter().rev() {
        chacha20_xor_in_place(&keys.payload_stream, &mut payload_buf);
    }

    // ── Step 4: assemble outermost packet.
    let mut bytes = [0u8; SPHINX_PACKET_LEN];
    bytes[0] = SPHINX_VERSION;
    bytes[1..33].copy_from_slice(&alpha_0.compress().to_bytes());
    bytes[33..33 + SLOT_MAC_LEN].copy_from_slice(&built.mac);
    bytes[33 + SLOT_MAC_LEN..33 + SLOT_MAC_LEN + HEADER_LEN].copy_from_slice(&built.header);
    bytes[33 + SLOT_MAC_LEN + HEADER_LEN..].copy_from_slice(&payload_buf);

    // Zeroize hop keys explicitly (they zeroize on drop, but be defensive).
    for mut k in hop_keys {
        k.header_stream.zeroize();
        k.payload_stream.zeroize();
        k.mac_key.zeroize();
        k.blinding_seed.zeroize();
    }
    payload_buf.zeroize();

    Ok(SphinxPacket { bytes })
}

/// Walk the Sphinx blinding chain to compute the FINAL-HOP shared
/// secret without building the full packet.
///
/// Used by the cover-traffic builder (audit M4) to derive the
/// destination's per-circuit shared key, which seeds the
/// authenticated cover trailer that replaces the pre-M4 plaintext
/// sentinel. Returning only the final-hop key (not the intermediates)
/// keeps callers from accidentally accessing a relay's session
/// material — they only see what the destination would derive itself.
pub fn compute_final_hop_shared_key(
    sender_eph_sk: &Scalar,
    circuit: &[SphinxHop],
) -> OnionResult<[u8; 32]> {
    if circuit.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    if circuit.len() > MAX_HOPS {
        return Err(OnionError::TooManyHops {
            got: circuit.len(),
            max: MAX_HOPS,
        });
    }
    let mut cumulative_blind = Scalar::ONE;
    let mut alpha_i = sender_eph_sk * RISTRETTO_BASEPOINT_TABLE;
    let last_idx = circuit.len() - 1;
    for (idx, hop) in circuit.iter().enumerate() {
        let alpha_bytes = alpha_i.compress().to_bytes();
        let shared_point = (sender_eph_sk * cumulative_blind) * hop.static_pk;
        let shared_bytes = shared_point.compress().to_bytes();
        // ct-audit: declassify (small-order verdict is the public result)
        if is_all_zero_ct(&shared_bytes) {
            return Err(OnionError::SmallOrderPubkey);
        }
        if idx == last_idx {
            return Ok(shared_bytes);
        }
        let keys = derive_hop_keys(&shared_bytes, &alpha_bytes);
        // Wide reduction (audit L1) — must match build_sphinx_onion.
        let b_i = Scalar::from_bytes_mod_order_wide(&keys.blinding_seed);
        cumulative_blind *= b_i;
        alpha_i = b_i * alpha_i;
    }
    // Unreachable: empty-circuit caught above; last_idx always reached.
    Err(OnionError::Internal(
        "compute_final_hop_shared_key: chain walk did not terminate",
    ))
}

/// Peel one layer of a Sphinx Coherence packet at this relay.
///
/// # Replay defense (audit L2 May 2026)
///
/// **This function does NOT provide replay protection by itself.**
/// A passive observer who captured an old packet can re-inject it
/// here, and `peel_sphinx_layer` will happily process it again and
/// produce the same `SphinxPeelOutcome::Forward` (or `Deliver`)
/// result. This is standard Sphinx behavior — replay detection is
/// the daemon's responsibility, not the packet primitive's.
///
/// Daemons that route this primitive MUST maintain a recently-seen
/// bloom filter (or set) keyed on the per-packet `shared_secret`
/// digest (or equivalently the encrypted MAC field) and drop any
/// packet whose digest is already in the filter. Tor and Loopix
/// both apply this same defense at the relay level.
///
/// A practical recipe:
/// 1. Compute `tag = BLAKE3("ol-sphinx-replay-tag-v1" || shared_secret)`
///    after the relay decapsulates `alpha`.
/// 2. Check `tag` against a circular bloom filter sized for the
///    relay's expected packets-per-window (e.g. 1M slots, 1% FPR,
///    rotate every 10 min).
/// 3. If tag is present → drop the packet, return without
///    forwarding. Otherwise → insert `tag` and proceed.
///
/// The relay's drop on replay is silent — replaying a known-good
/// packet does not yield any usable oracle signal because the bloom
/// check happens before any wire-visible side-effect.
pub fn peel_sphinx_layer(
    relay_sk: &Scalar,
    packet: &SphinxPacket,
) -> OnionResult<SphinxPeelOutcome> {
    let alpha_bytes = packet.alpha();
    if alpha_bytes.iter().all(|&b| b == 0) {
        return Err(OnionError::SmallOrderPubkey);
    }
    let alpha_point = CompressedRistretto::from_slice(&alpha_bytes)
        .map_err(|_| OnionError::SmallOrderPubkey)?
        .decompress()
        .ok_or(OnionError::SmallOrderPubkey)?;
    let shared_point = relay_sk * alpha_point;
    let shared_bytes = shared_point.compress().to_bytes();
    // ct-audit: declassify (small-order verdict is the public result)
    if is_all_zero_ct(&shared_bytes) {
        return Err(OnionError::SmallOrderPubkey);
    }
    let keys = derive_hop_keys(&shared_bytes, &alpha_bytes);

    // Verify + peel header.
    let mac = packet.mac();
    let outcome = peel_header(&keys, packet.header(), &mac).map_err(|()| OnionError::AeadFail)?;

    // Decrypt one payload layer in-place — no separate keystream Vec.
    let mut payload = vec![0u8; PAYLOAD_LEN];
    payload.copy_from_slice(packet.payload());
    chacha20_xor_in_place(&keys.payload_stream, &mut payload);

    // ct-audit: declassify (deliver-or-forward is the relay's routing output)
    match outcome {
        HeaderPeelOutcome::Deliver => {
            // Extract user payload via length prefix.
            let plen = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
            if plen > SPHINX_MAX_USER_PAYLOAD {
                return Err(OnionError::Internal("destination payload length oversize"));
            }
            let user_payload = &payload[2..2 + plen];
            // Audit M4: authenticated cover-traffic detection. The
            // sender, knowing its own ephemeral key and this hop's
            // static key, can derive the same shared_bytes we just
            // derived above — and only the sender can produce the
            // matching MAC trailer. A network attacker bit-flipping
            // the payload to forge cover status can't compute a valid
            // tag without the shared key, so a forged "cover" status
            // is rejected at probability 1 - 2^-128.
            if crate::sphinx::cover::is_cover_payload_authenticated(&shared_bytes, user_payload) {
                return Ok(SphinxPeelOutcome::Cover);
            }
            let mut user_payload_owned = vec![0u8; plen];
            user_payload_owned.copy_from_slice(user_payload);
            Ok(SphinxPeelOutcome::Deliver {
                payload: user_payload_owned,
            })
        }
        HeaderPeelOutcome::Forward {
            next_hop_id,
            next_header,
            next_mac,
        } => {
            // Blind alpha for the next hop. Audit L1: wide reduction.
            let b_scalar = Scalar::from_bytes_mod_order_wide(&keys.blinding_seed);
            let next_alpha = b_scalar * alpha_point;
            let next_alpha_bytes = next_alpha.compress().to_bytes();

            // Assemble next packet.
            let mut bytes = [0u8; SPHINX_PACKET_LEN];
            bytes[0] = SPHINX_VERSION;
            bytes[1..33].copy_from_slice(&next_alpha_bytes);
            bytes[33..33 + SLOT_MAC_LEN].copy_from_slice(&next_mac);
            bytes[33 + SLOT_MAC_LEN..33 + SLOT_MAC_LEN + HEADER_LEN].copy_from_slice(&next_header);
            bytes[33 + SLOT_MAC_LEN + HEADER_LEN..].copy_from_slice(&payload);

            Ok(SphinxPeelOutcome::Forward {
                next_hop: HopId::from_bytes(next_hop_id),
                next_packet: SphinxPacket { bytes },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_relay() -> (Scalar, SphinxHop) {
        let (sk, pk) = generate_static_keypair(&mut OsRng);
        (
            sk,
            SphinxHop {
                // 32 INDEPENDENT random bytes. `[rand::random::<u8>(); N]`
                // evaluates the byte ONCE and copies it, yielding an
                // all-same-byte id that collides with DESTINATION_MARKER
                // ([0u8; 32]) 1/256 of the time → an upstream hop delivers
                // early and the round-trip fails (the ~1-2% flake).
                id: HopId::from_bytes(rand::random::<[u8; SLOT_ID_LEN]>()),
                static_pk: pk,
            },
        )
    }

    #[test]
    fn one_hop_round_trip() {
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_sphinx_onion(&eph_sk, std::slice::from_ref(&dest), b"hello", &mut OsRng).unwrap();
        let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
        match outcome {
            SphinxPeelOutcome::Deliver { payload } => assert_eq!(payload, b"hello"),
            _ => panic!(),
        }
    }

    #[test]
    fn two_hop_round_trip() {
        let (r0_sk, r0) = make_relay();
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_sphinx_onion(&eph_sk, &[r0.clone(), dest.clone()], b"two-hop", &mut OsRng)
                .unwrap();
        let outcome = peel_sphinx_layer(&r0_sk, &packet).unwrap();
        let next_packet = match outcome {
            SphinxPeelOutcome::Forward {
                next_hop,
                next_packet,
            } => {
                assert_eq!(next_hop, dest.id);
                next_packet
            }
            _ => panic!(),
        };
        let outcome = peel_sphinx_layer(&dest_sk, &next_packet).unwrap();
        match outcome {
            SphinxPeelOutcome::Deliver { payload } => assert_eq!(payload, b"two-hop"),
            _ => panic!(),
        }
    }

    #[test]
    fn three_hop_round_trip() {
        let (r0_sk, r0) = make_relay();
        let (r1_sk, r1) = make_relay();
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let circuit = vec![r0.clone(), r1.clone(), dest.clone()];
        let packet = build_sphinx_onion(&eph_sk, &circuit, b"three-hop test", &mut OsRng).unwrap();

        let o1 = peel_sphinx_layer(&r0_sk, &packet).unwrap();
        let next = match o1 {
            SphinxPeelOutcome::Forward {
                next_hop,
                next_packet,
            } => {
                assert_eq!(next_hop, r1.id);
                next_packet
            }
            _ => panic!(),
        };
        let o2 = peel_sphinx_layer(&r1_sk, &next).unwrap();
        let next = match o2 {
            SphinxPeelOutcome::Forward {
                next_hop,
                next_packet,
            } => {
                assert_eq!(next_hop, dest.id);
                next_packet
            }
            _ => panic!(),
        };
        let o3 = peel_sphinx_layer(&dest_sk, &next).unwrap();
        match o3 {
            SphinxPeelOutcome::Deliver { payload } => {
                assert_eq!(payload, b"three-hop test");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn max_hops_round_trip() {
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let pairs: Vec<(Scalar, SphinxHop)> = (0..MAX_HOPS).map(|_| make_relay()).collect();
        let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
        let mut packet = build_sphinx_onion(&eph_sk, &circuit, b"max-hops", &mut OsRng).unwrap();
        for (i, (sk, _)) in pairs.iter().enumerate() {
            match peel_sphinx_layer(sk, &packet).unwrap() {
                SphinxPeelOutcome::Forward { next_packet, .. } => {
                    assert!(i + 1 < pairs.len());
                    packet = next_packet;
                }
                SphinxPeelOutcome::Deliver { payload } => {
                    assert_eq!(payload, b"max-hops");
                    assert_eq!(i, pairs.len() - 1);
                    return;
                }
                SphinxPeelOutcome::Cover => {
                    panic!("real packet mis-classified as cover");
                }
            }
        }
    }

    #[test]
    fn packet_size_constant_across_peels() {
        let (r0_sk, r0) = make_relay();
        let (r1_sk, r1) = make_relay();
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_sphinx_onion(&eph_sk, &[r0.clone(), r1.clone(), dest], b"x", &mut OsRng).unwrap();
        assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);
        let SphinxPeelOutcome::Forward {
            next_packet: next, ..
        } = peel_sphinx_layer(&r0_sk, &packet).unwrap()
        else {
            panic!();
        };
        assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
        let SphinxPeelOutcome::Forward {
            next_packet: next, ..
        } = peel_sphinx_layer(&r1_sk, &next).unwrap()
        else {
            panic!();
        };
        assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
    }

    #[test]
    fn alpha_changes_at_each_hop() {
        let (r0_sk, r0) = make_relay();
        let (r1_sk, r1) = make_relay();
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let p0 = build_sphinx_onion(&eph_sk, &[r0, r1, dest], b"x", &mut OsRng).unwrap();
        let a0 = p0.alpha();
        let SphinxPeelOutcome::Forward {
            next_packet: p1, ..
        } = peel_sphinx_layer(&r0_sk, &p0).unwrap()
        else {
            panic!();
        };
        let a1 = p1.alpha();
        let SphinxPeelOutcome::Forward {
            next_packet: p2, ..
        } = peel_sphinx_layer(&r1_sk, &p1).unwrap()
        else {
            panic!();
        };
        let a2 = p2.alpha();
        assert_ne!(a0, a1, "alpha must change after r0");
        assert_ne!(a1, a2, "alpha must change after r1");
        assert_ne!(a0, a2, "alpha at r0 differs from alpha at r2");
    }

    #[test]
    fn wrong_relay_key_rejected() {
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
        let (wrong_sk, _) = generate_static_keypair(&mut OsRng);
        let err = peel_sphinx_layer(&wrong_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn tampered_mac_rejected() {
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
        packet.bytes[40] ^= 0x01;
        let err = peel_sphinx_layer(&dest_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }

    #[test]
    fn empty_payload_works() {
        let (dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet = build_sphinx_onion(&eph_sk, &[dest], b"", &mut OsRng).unwrap();
        let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
        match outcome {
            SphinxPeelOutcome::Deliver { payload } => assert!(payload.is_empty()),
            _ => panic!(),
        }
    }

    #[test]
    fn payload_oversize_rejected() {
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let huge = vec![0u8; SPHINX_MAX_USER_PAYLOAD + 1];
        let err = build_sphinx_onion(&eph_sk, &[dest], &huge, &mut OsRng).unwrap_err();
        assert!(matches!(err, OnionError::PayloadOversize { .. }));
    }
}
