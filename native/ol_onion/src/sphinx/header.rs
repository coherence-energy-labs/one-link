//! Sphinx header build + peel.
//!
//! Pure-byte algorithm — no elliptic curves. The header is the
//! load-bearing part of Sphinx: a fixed-size structure that each
//! relay decrypts + shifts + appends-keystream-tail without
//! changing total size, and which the destination's MAC verifies
//! against the cumulative output of all upstream relays.
//!
//! ## Header layout (`HEADER_LEN` bytes per hop)
//!
//! Each relay's view after decrypt:
//! ```text
//!   slot[0]               : (next_hop_id || next_mac)        [48 bytes]
//!   slot[1..n_remaining]  : encrypted inner-layer bytes      [decrypted-or-filler]
//! ```
//!
//! ## Build algorithm
//!
//! ```text
//! 1. Compute filler from upstream relays' header_stream keys.
//! 2. Destination's pre-encryption header:
//!    bytes[..SLOT_LEN]              = [0u8; SLOT_LEN]  (destination marker)
//!    bytes[SLOT_LEN..HEADER_LEN-FL] = random pad (FL = filler.len())
//!    bytes[HEADER_LEN-FL..]         = filler            (the "raw" trailing portion)
//! 3. ChaCha20-encrypt ONLY bytes[..HEADER_LEN-FL] with destination's stream key.
//!    Trailing FL bytes (which are filler) stay raw.
//!    Compute destination's MAC over the resulting encrypted+raw bytes.
//! 4. For each preceding relay (right-to-left in the circuit):
//!    pre = (next_hop_id || prev_mac || prev_header[..HEADER_LEN-SLOT_LEN])
//!    encrypted = pre XOR chacha20(this_hop.header_stream, HEADER_LEN bytes)
//!    new_mac = HMAC(this_hop.mac_key, encrypted)
//! 5. The outermost-layer's (encrypted, mac) is what the sender hands
//!    to the first relay.
//! ```
//!
//! ## Peel algorithm
//!
//! ```text
//! 1. Verify packet.mac == HMAC(my_mac_key, packet.header). Drop on miss.
//! 2. Generate keystream of length HEADER_LEN + SLOT_LEN.
//! 3. Decrypt: decrypted = packet.header XOR keystream[..HEADER_LEN].
//! 4. Read slot 0: (next_hop_id, next_mac).
//! 5. If next_hop_id == [0u8; SLOT_ID_LEN]: destination — deliver.
//! 6. Else (relay):
//!    forwarded[..HEADER_LEN-SLOT_LEN] = decrypted[SLOT_LEN..]
//!    forwarded[HEADER_LEN-SLOT_LEN..] = keystream[HEADER_LEN..HEADER_LEN+SLOT_LEN]
//!    forward (forwarded, next_mac) to next_hop_id.
//! ```

use crate::sphinx::primitives::{
    build_filler, chacha20_keystream_into, chacha20_xor_in_place, header_mac, verify_header_mac,
    HopKeys, HEADER_KEYSTREAM_LEN, HEADER_LEN, SLOT_ID_LEN, SLOT_LEN, SLOT_MAC_LEN,
};
use crate::{OnionError, OnionResult};

/// Special destination marker: a slot whose `hop_id` is all zero
/// signals "this hop is the destination, deliver the payload."
pub const DESTINATION_MARKER: [u8; SLOT_ID_LEN] = [0u8; SLOT_ID_LEN];

/// Per-hop routing slot the sender embeds in the header.
#[derive(Debug, Clone, Copy)]
pub struct RoutingSlot {
    /// Hop-id of the next hop (or `DESTINATION_MARKER` for the
    /// destination's slot).
    pub next_hop_id: [u8; SLOT_ID_LEN],
}

/// Output of [`build_header`]: the encrypted outermost header + its
/// MAC, ready to ship to the first relay.
#[derive(Debug, Clone)]
pub struct BuiltHeader {
    /// The encrypted header bytes (length [`HEADER_LEN`]).
    pub header: Vec<u8>,
    /// The MAC the FIRST relay verifies.
    pub mac: [u8; SLOT_MAC_LEN],
}

/// Build the Sphinx onion header right-to-left.
///
/// `hop_keys[i]` is the per-hop key material for the i-th hop in
/// the circuit (0 = first relay, last = destination).
/// `next_hop_ids[i]` is the routing identifier the i-th relay uses
/// to forward the packet to the (i+1)-th hop. The LAST hop is the
/// destination, so `next_hop_ids[n-1]` is unused at the destination
/// (it's the marker that triggers Deliver).
///
/// `random_pad` is a slice of random bytes used to fill the
/// destination's "middle" header bytes (between the marker slot
/// and the filler). Length must equal `HEADER_LEN - SLOT_LEN - (n-1) * SLOT_LEN`.
pub fn build_header(
    hop_keys: &[HopKeys],
    next_hop_ids: &[[u8; SLOT_ID_LEN]],
    random_pad: &[u8],
) -> OnionResult<BuiltHeader> {
    if hop_keys.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    if hop_keys.len() > crate::sphinx::primitives::MAX_HOPS {
        return Err(OnionError::TooManyHops {
            got: hop_keys.len(),
            max: crate::sphinx::primitives::MAX_HOPS,
        });
    }
    if hop_keys.len() != next_hop_ids.len() {
        return Err(OnionError::InvalidParameter(
            "hop_keys and next_hop_ids lengths differ",
        ));
    }
    let n = hop_keys.len();
    let n_relays = n - 1;
    let filler_len = n_relays * SLOT_LEN;
    let pad_len = HEADER_LEN - SLOT_LEN - filler_len;
    if random_pad.len() != pad_len {
        return Err(OnionError::BadFrameSize {
            got: random_pad.len(),
            expected: pad_len,
        });
    }

    // ── Step 1: build cumulative filler from upstream-relay streams.
    let relay_streams: Vec<[u8; 32]> = hop_keys
        .iter()
        .take(n_relays)
        .map(|k| k.header_stream)
        .collect();
    let filler = build_filler(&relay_streams);
    debug_assert_eq!(filler.len(), filler_len);

    // ── Step 2: destination's encrypted header.
    let dest_keys = hop_keys.last().ok_or(OnionError::EmptyCircuit)?;
    // Stack-array header buffer (HEADER_LEN = 240 bytes).
    let mut header = [0u8; HEADER_LEN];
    // Marker slot (first SLOT_LEN bytes: all zero hop_id || zero mac).
    // Already zero.
    // Random pad (next pad_len bytes).
    header[SLOT_LEN..SLOT_LEN + pad_len].copy_from_slice(random_pad);
    // Filler (last filler_len bytes). Set raw (NOT XOR'd later).
    header[HEADER_LEN - filler_len..].copy_from_slice(&filler);
    // ChaCha20-encrypt ONLY the first (HEADER_LEN - filler_len) bytes
    // with destination's stream key. The trailing filler stays raw.
    let visible_end = HEADER_LEN - filler_len;
    chacha20_xor_in_place(&dest_keys.header_stream, &mut header[..visible_end]);
    let mut prev_mac = header_mac(&dest_keys.mac_key, &header);

    // ── Step 3: wrap upstream relays right-to-left.
    let mut pre = [0u8; HEADER_LEN];
    for i in (0..n_relays).rev() {
        let keys = &hop_keys[i];
        let next_hop_id = &next_hop_ids[i];
        // Build pre-encryption header in the stack buffer:
        //   pre[..SLOT_ID_LEN]       = next_hop_id
        //   pre[SLOT_ID_LEN..SLOT_LEN] = prev_mac
        //   pre[SLOT_LEN..]          = header[..HEADER_LEN - SLOT_LEN]
        pre[..SLOT_ID_LEN].copy_from_slice(next_hop_id);
        pre[SLOT_ID_LEN..SLOT_LEN].copy_from_slice(&prev_mac);
        pre[SLOT_LEN..].copy_from_slice(&header[..HEADER_LEN - SLOT_LEN]);
        // ChaCha20-encrypt the full HEADER_LEN bytes with this hop's stream.
        chacha20_xor_in_place(&keys.header_stream, &mut pre);
        // Swap pre into header for the next iteration.
        header.copy_from_slice(&pre);
        prev_mac = header_mac(&keys.mac_key, &header);
    }

    Ok(BuiltHeader {
        header: header.to_vec(),
        mac: prev_mac,
    })
}

/// Outcome of a single peel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderPeelOutcome {
    /// Forward to `next_hop_id` with the new header + MAC.
    Forward {
        /// Routing id of the next hop.
        next_hop_id: [u8; SLOT_ID_LEN],
        /// Encrypted header bytes for the next hop.
        next_header: Vec<u8>,
        /// MAC the next hop verifies.
        next_mac: [u8; SLOT_MAC_LEN],
    },
    /// This relay is the destination — deliver the user payload.
    Deliver,
}

/// Peel one layer of a Sphinx header.
///
/// Returns `Err(())` if MAC verification fails. The error is
/// deliberately unit-typed: a relay must learn nothing about *why* a
/// header failed to verify (length vs MAC mismatch), so we surface no
/// detail that could become a decryption-oracle side channel.
#[allow(clippy::result_unit_err)]
pub fn peel_header(
    keys: &HopKeys,
    received_header: &[u8],
    received_mac: &[u8; SLOT_MAC_LEN],
) -> Result<HeaderPeelOutcome, ()> {
    if received_header.len() != HEADER_LEN {
        return Err(());
    }
    // 1. Verify MAC.
    // ct-audit: declassify (MAC verdict: drop or process)
    if !verify_header_mac(&keys.mac_key, received_header, received_mac) {
        return Err(());
    }
    // 2. Generate extended keystream into a stack buffer.
    let mut keystream = [0u8; HEADER_KEYSTREAM_LEN];
    chacha20_keystream_into(&keys.header_stream, &mut keystream);
    // 3. Decrypt into a stack buffer.
    let mut decrypted = [0u8; HEADER_LEN];
    decrypted.copy_from_slice(received_header);
    for i in 0..HEADER_LEN {
        decrypted[i] ^= keystream[i];
    }
    // 4. Read slot 0.
    let mut next_hop_id = [0u8; SLOT_ID_LEN];
    next_hop_id.copy_from_slice(&decrypted[..SLOT_ID_LEN]);
    let mut next_mac = [0u8; SLOT_MAC_LEN];
    next_mac.copy_from_slice(&decrypted[SLOT_ID_LEN..SLOT_LEN]);

    // 5. Destination check. The relay reveals this slot by acting on it
    // (deliver here, or forward to `next_hop_id`), so the comparison is a
    // public routing verdict.
    // ct-audit: declassify (deliver-or-forward routing verdict)
    if next_hop_id == DESTINATION_MARKER {
        return Ok(HeaderPeelOutcome::Deliver);
    }

    // 6. Build forwarded header — only allocates the final Vec at
    // return time, no intermediate Vecs.
    let mut forwarded = vec![0u8; HEADER_LEN];
    forwarded[..HEADER_LEN - SLOT_LEN].copy_from_slice(&decrypted[SLOT_LEN..]);
    forwarded[HEADER_LEN - SLOT_LEN..]
        .copy_from_slice(&keystream[HEADER_LEN..HEADER_LEN + SLOT_LEN]);

    Ok(HeaderPeelOutcome::Forward {
        next_hop_id,
        next_header: forwarded,
        next_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphinx::primitives::derive_hop_keys;

    fn make_hop_keys(shared_byte: u8) -> HopKeys {
        let shared = [shared_byte; 32];
        let alpha = [0xAA; 32];
        derive_hop_keys(&shared, &alpha)
    }

    fn random_pad_for(n_hops: usize) -> Vec<u8> {
        let pad_len = HEADER_LEN - SLOT_LEN - (n_hops - 1) * SLOT_LEN;
        (0..pad_len)
            .map(|i| i.to_le_bytes()[0].wrapping_mul(31))
            .collect()
    }

    // ── 1-hop ─────────────────────────────────────────────────────

    #[test]
    fn one_hop_round_trip() {
        let dest_keys = make_hop_keys(0x11);
        let next_hop_ids = vec![DESTINATION_MARKER];
        let built = build_header(
            std::slice::from_ref(&dest_keys),
            &next_hop_ids,
            &random_pad_for(1),
        )
        .unwrap();
        let outcome = peel_header(&dest_keys, &built.header, &built.mac).unwrap();
        assert_eq!(outcome, HeaderPeelOutcome::Deliver);
    }

    // ── 2-hop ─────────────────────────────────────────────────────

    #[test]
    fn two_hop_round_trip() {
        let r0 = make_hop_keys(0x21);
        let dest = make_hop_keys(0x22);
        let next_hop_ids = vec![[0x22; SLOT_ID_LEN], DESTINATION_MARKER];
        let built = build_header(
            &[r0.clone(), dest.clone()],
            &next_hop_ids,
            &random_pad_for(2),
        )
        .unwrap();

        // r0 peels first.
        let outcome = peel_header(&r0, &built.header, &built.mac).unwrap();
        let (next_id, next_header, next_mac) = match outcome {
            HeaderPeelOutcome::Forward {
                next_hop_id,
                next_header,
                next_mac,
            } => (next_hop_id, next_header, next_mac),
            HeaderPeelOutcome::Deliver => panic!("r0 should forward"),
        };
        assert_eq!(next_id, [0x22; SLOT_ID_LEN]);

        // dest peels.
        let outcome = peel_header(&dest, &next_header, &next_mac).unwrap();
        assert_eq!(outcome, HeaderPeelOutcome::Deliver);
    }

    // ── 3-hop ─────────────────────────────────────────────────────

    #[test]
    fn three_hop_round_trip() {
        let r0 = make_hop_keys(0x31);
        let r1 = make_hop_keys(0x32);
        let dest = make_hop_keys(0x33);
        let next_hop_ids = vec![[0x32; SLOT_ID_LEN], [0x33; SLOT_ID_LEN], DESTINATION_MARKER];
        let built = build_header(
            &[r0.clone(), r1.clone(), dest.clone()],
            &next_hop_ids,
            &random_pad_for(3),
        )
        .unwrap();

        // r0 → r1
        let outcome = peel_header(&r0, &built.header, &built.mac).unwrap();
        let HeaderPeelOutcome::Forward {
            next_hop_id: next_id,
            next_header,
            next_mac,
        } = outcome
        else {
            panic!();
        };
        assert_eq!(next_id, [0x32; SLOT_ID_LEN]);

        // r1 → dest
        let outcome = peel_header(&r1, &next_header, &next_mac).unwrap();
        let HeaderPeelOutcome::Forward {
            next_hop_id: next_id,
            next_header,
            next_mac,
        } = outcome
        else {
            panic!();
        };
        assert_eq!(next_id, [0x33; SLOT_ID_LEN]);

        // dest delivers
        let outcome = peel_header(&dest, &next_header, &next_mac).unwrap();
        assert_eq!(outcome, HeaderPeelOutcome::Deliver);
    }

    // ── Max hops ──────────────────────────────────────────────────

    #[test]
    fn max_hops_round_trip() {
        use crate::sphinx::primitives::MAX_HOPS;
        let keys: Vec<HopKeys> = (0..MAX_HOPS)
            .map(|i| make_hop_keys(u8::try_from(i).unwrap() + 1))
            .collect();
        let mut next_hop_ids: Vec<[u8; SLOT_ID_LEN]> = (0..MAX_HOPS - 1)
            .map(|i| [u8::try_from(i).unwrap() + 2; SLOT_ID_LEN])
            .collect();
        next_hop_ids.push(DESTINATION_MARKER);
        let built = build_header(&keys, &next_hop_ids, &random_pad_for(MAX_HOPS)).unwrap();

        let mut current_header = built.header.clone();
        let mut current_mac = built.mac;
        for (i, hop) in keys.iter().enumerate() {
            let outcome = peel_header(hop, &current_header, &current_mac).unwrap();
            match outcome {
                HeaderPeelOutcome::Forward {
                    next_hop_id,
                    next_header,
                    next_mac,
                } => {
                    assert_eq!(next_hop_id, [u8::try_from(i).unwrap() + 2; SLOT_ID_LEN]);
                    current_header = next_header;
                    current_mac = next_mac;
                    assert!(i < MAX_HOPS - 1);
                }
                HeaderPeelOutcome::Deliver => {
                    assert_eq!(i, MAX_HOPS - 1);
                    return;
                }
            }
        }
    }

    // ── Adversarial ───────────────────────────────────────────────

    #[test]
    fn wrong_mac_rejected() {
        let dest = make_hop_keys(0x41);
        let built = build_header(
            std::slice::from_ref(&dest),
            &[DESTINATION_MARKER],
            &random_pad_for(1),
        )
        .unwrap();
        let mut bad_mac = built.mac;
        bad_mac[0] ^= 0x01;
        let err = peel_header(&dest, &built.header, &bad_mac);
        assert!(err.is_err());
    }

    #[test]
    fn tampered_header_byte_rejected() {
        let dest = make_hop_keys(0x42);
        let built = build_header(
            std::slice::from_ref(&dest),
            &[DESTINATION_MARKER],
            &random_pad_for(1),
        )
        .unwrap();
        let mut bad_header = built.header.clone();
        bad_header[0] ^= 0x01;
        let err = peel_header(&dest, &bad_header, &built.mac);
        assert!(err.is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let dest = make_hop_keys(0x43);
        let other = make_hop_keys(0x44);
        let built = build_header(&[dest], &[DESTINATION_MARKER], &random_pad_for(1)).unwrap();
        let err = peel_header(&other, &built.header, &built.mac);
        assert!(err.is_err());
    }
}
