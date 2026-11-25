//! Shamir (k, n) secret sharing over GF(2^8).
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTIONS 3-5.
//! Identical share format to `OneField` (each share is (x: u8, y: u8)) so
//! shares produced by either implementation reconstruct under the other.

use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::gf256::{gf_add, gf_div_fast, gf_mul, gf_mul_fast};
use crate::prng::PrngState;

/// One share: (x, y) with x != 0. x == 0 reserved for the secret itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Share {
    /// Evaluation point (1..=255).
    pub x: u8,
    /// Polynomial value at x.
    pub y: u8,
}

/// Maximum secret length accepted by the threshold-recovery primitive.
///
/// The scheme is designed for master keys and recovery tokens, not bulk
/// files. At the maximum 255 participants this bounds aggregate share output
/// to 16 MiB per call.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

impl Share {
    /// Construct a share.
    #[must_use]
    pub const fn new(x: u8, y: u8) -> Self {
        Self { x, y }
    }
}

/// Errors from share operations.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ShareError {
    /// k must be >= 1 and <= n; n must be <= 255 (GF(2^8) limit excluding 0).
    #[error("invalid (k, n) threshold parameters: k={k}, n={n}; require 1 <= k <= n <= 255")]
    InvalidParams {
        /// Threshold.
        k: u32,
        /// Total shares.
        n: u32,
    },
    /// Fewer than k shares supplied to reconstruct.
    #[error("not enough shares: have {have}, need at least {need}")]
    NotEnoughShares {
        /// Shares supplied.
        have: usize,
        /// Threshold required.
        need: u32,
    },
    /// Two shares share the same x; reconstruction is undefined.
    #[error("duplicate share x-values; each share must have a unique x")]
    DuplicateShareX,
    /// Share with x == 0 supplied; x == 0 is reserved for the secret.
    #[error("share x == 0 is reserved for the secret value")]
    InvalidShareX,

    /// A secret/share stream exceeded the per-operation safety ceiling.
    #[error("secret/share stream too large: {actual} bytes (max {max})")]
    SecretTooLarge {
        /// Actual byte length.
        actual: usize,
        /// Maximum accepted byte length.
        max: usize,
    },

    /// The operating system CSPRNG was unavailable.
    #[error("secure randomness unavailable: {0}")]
    RandomnessUnavailable(String),

    /// Supplied share streams had inconsistent lengths.
    #[error("share stream {index} has {actual} bytes; expected {expected}")]
    StreamLengthMismatch {
        /// Stream index.
        index: usize,
        /// Reference stream length.
        expected: usize,
        /// Offending stream length.
        actual: usize,
    },

    /// A share set did not contain the declared number of participants.
    #[error("share count mismatch: expected {expected}, got {actual}")]
    ShareCountMismatch {
        /// Declared/required count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },

    /// Two refresh share sets were not aligned at an index.
    #[error("share x mismatch at index {index}: {left} != {right}")]
    ShareXMismatch {
        /// Misaligned position.
        index: usize,
        /// Original x value.
        left: u8,
        /// Delta x value.
        right: u8,
    },
}

/// Max number of participants in a single-byte GF(2^8) scheme: 255
/// (256 - 1 reserved for the secret at x = 0).
#[must_use]
pub const fn max_participants() -> u32 {
    255
}

/// Are these (k, n) parameters valid for the scheme?
#[must_use]
pub const fn params_valid(k: u32, n: u32) -> bool {
    k >= 1 && k <= n && n <= max_participants()
}

/// Split a single secret byte `s` into `n` shares with threshold `k`.
/// Returns the n shares; the PRNG state is advanced in-place so the
/// caller can use the same state for the next byte.
///
/// # Errors
/// Returns [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn share_byte(s: u8, k: u32, n: u32, state: &mut PrngState) -> Result<Vec<Share>, ShareError> {
    if !params_valid(k, n) {
        return Err(ShareError::InvalidParams { k, n });
    }
    // Build coefficient vector: a_0 = s, a_1..a_{k-1} = random.
    let mut coeffs: Vec<u32> = Vec::with_capacity(k as usize);
    coeffs.push(u32::from(s) & 0xFF);
    // Every coefficient, the top one included, is uniform over the whole
    // field: see `share_bytes_with_next` for why a non-zero top coefficient
    // must NOT be forced.
    for _ in 1..k {
        coeffs.push(u32::from(state.next_byte()));
    }
    // Evaluate p(j) for j = 1..=n. x == 0 is the secret, never a share.
    let mut shares = Vec::with_capacity(n as usize);
    for j in 1..=n {
        let y = poly_eval(&coeffs, j) as u8;
        shares.push(Share::new(j as u8, y));
    }
    Ok(shares)
}

/// Split a multi-byte secret. Output is a Vec of N share-streams; each
/// share-stream i has length `secret.len()` and represents the y-values
/// of share i across every secret byte.
///
/// `share_streams[i][b]` is the byte for share x = i+1, secret byte b.
///
/// # Errors
/// Returns [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn share_bytes(
    secret: &[u8],
    k: u32,
    n: u32,
    state: &mut PrngState,
) -> Result<Vec<Vec<u8>>, ShareError> {
    share_bytes_with_next(secret, k, n, || Ok(state.next_byte()))
}

/// Split a multi-byte secret using fresh operating-system CSPRNG entropy.
///
/// This is the production API. [`share_bytes`] remains available only for
/// reproducible vectors and migrations where deterministic output is an
/// explicit requirement.
pub fn share_bytes_secure(secret: &[u8], k: u32, n: u32) -> Result<Vec<Vec<u8>>, ShareError> {
    let mut rng = OsRng;
    share_bytes_with_next(secret, k, n, || {
        let mut byte = [0u8; 1];
        rng.try_fill_bytes(&mut byte)
            .map_err(|error| ShareError::RandomnessUnavailable(error.to_string()))?;
        Ok(byte[0])
    })
}

fn share_bytes_with_next<F>(
    secret: &[u8],
    k: u32,
    n: u32,
    mut next_byte: F,
) -> Result<Vec<Vec<u8>>, ShareError>
where
    F: FnMut() -> Result<u8, ShareError>,
{
    if !params_valid(k, n) {
        return Err(ShareError::InvalidParams { k, n });
    }
    if secret.len() > MAX_SECRET_BYTES {
        return Err(ShareError::SecretTooLarge {
            actual: secret.len(),
            max: MAX_SECRET_BYTES,
        });
    }

    let mut streams: Vec<Vec<u8>> = (0..n).map(|_| Vec::with_capacity(secret.len())).collect();
    let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
    for &secret_byte in secret {
        coeffs[0] = secret_byte;
        // Perfect secrecy requires a_1..a_{k-1} uniform over ALL of GF(2^8),
        // zero included. Given k-1 shares and any candidate secret s', exactly
        // one polynomial of degree <= k-1 passes through them, and its top
        // coefficient is an affine function of s' with a non-zero slope (the
        // x^{k-1} coefficient of the Lagrange basis polynomial for x = 0). So
        // exactly one s' corresponds to a zero top coefficient. Forcing that
        // coefficient non-zero (the previous re-roll loop) let anyone holding
        // k-1 shares rule that s' out, and its loop branched on a secret.
        // Uniform draws restore perfect secrecy and fix the timing at k-1
        // draws per byte. The `perfect_secrecy_*` unit tests check it
        // exhaustively.
        for coefficient in &mut coeffs[1..] {
            *coefficient = next_byte()?;
        }
        for (index, stream) in streams.iter_mut().enumerate() {
            let x = (index + 1) as u32;
            let coeffs_u32 = coeffs.iter().map(|byte| u32::from(*byte));
            // Horner directly over bytes avoids allocating N temporary Share
            // objects for every byte of the secret.
            let mut acc = 0u32;
            for coefficient in coeffs_u32.rev() {
                acc = gf_add(gf_mul(acc, x), coefficient);
            }
            stream.push((acc & 0xFF) as u8);
        }
    }
    Ok(streams)
}

/// Reconstruct one secret byte from at least `k` shares via Lagrange
/// interpolation at x = 0.
///
/// Implementation note: basis construction uses the table-based fast path
/// only for public x-coordinates. The final `y * basis` operation uses the
/// constant-time multiplier because share y-values are secret material.
///
/// # Errors
/// - [`ShareError::NotEnoughShares`] when `shares.len() < k`.
/// - [`ShareError::DuplicateShareX`] when two shares share an x.
/// - [`ShareError::InvalidShareX`] when any share has x == 0.
pub fn reconstruct_byte(shares: &[Share], k: u32) -> Result<u8, ShareError> {
    if k == 0 || k > max_participants() || shares.len() > max_participants() as usize {
        return Err(ShareError::InvalidParams {
            k,
            n: u32::try_from(shares.len()).unwrap_or(u32::MAX),
        });
    }
    let kk = k as usize;
    if shares.len() < kk {
        return Err(ShareError::NotEnoughShares {
            have: shares.len(),
            need: k,
        });
    }
    for sh in &shares[..kk] {
        if sh.x == 0 {
            return Err(ShareError::InvalidShareX);
        }
    }
    for i in 0..kk {
        for j in (i + 1)..kk {
            if shares[i].x == shares[j].x {
                return Err(ShareError::DuplicateShareX);
            }
        }
    }
    let basis = lagrange_basis_at_zero(&shares[..kk]);
    let mut acc: u32 = 0;
    for i in 0..kk {
        acc = gf_add(acc, gf_mul(u32::from(shares[i].y), u32::from(basis[i])));
    }
    Ok((acc & 0xFF) as u8)
}

/// Precompute Lagrange basis values `L_i(0)` for the given share
/// x-coordinates. Returns a Vec the same length as `shares`. The
/// caller then evaluates `p(0) = sum_i y_i * basis[i]` over GF(2^8).
///
/// Key optimization: when reconstructing a multi-byte secret, this
/// computation is done ONCE per share-set (not once per byte) — the
/// basis depends only on the x-values, which are constant across
/// every byte of the secret. This turns the per-byte reconstruction
/// cost from O(K^2) gf multiplications down to O(K) (just the
/// final inner-product step).
///
/// Uses table-based fast path (public-value operands).
fn lagrange_basis_at_zero(shares: &[Share]) -> Vec<u8> {
    let kk = shares.len();
    let mut out = Vec::with_capacity(kk);
    for i in 0..kk {
        let xi = shares[i].x;
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = share_j.x;
            num = gf_mul_fast(num, xj);
            // gf_sub == XOR in GF(2^8).
            den = gf_mul_fast(den, xi ^ xj);
        }
        out.push(gf_div_fast(num, den));
    }
    out
}

/// Reconstruct a multi-byte secret from `k` share-streams. Each stream is
/// keyed by its x-value via the parallel `xs` vector — `xs[i]` is the x
/// value for `streams[i]`. Streams must all have the same length.
///
/// # Errors
/// Same as [`reconstruct_byte`], plus length-mismatch errors.
pub fn reconstruct_bytes(xs: &[u8], streams: &[&[u8]], k: u32) -> Result<Vec<u8>, ShareError> {
    if xs.len() != streams.len() {
        return Err(ShareError::NotEnoughShares {
            have: xs.len().min(streams.len()),
            need: k,
        });
    }
    if (xs.len() as u32) < k {
        return Err(ShareError::NotEnoughShares {
            have: xs.len(),
            need: k,
        });
    }
    if k == 0 || k > max_participants() || xs.len() > max_participants() as usize {
        return Err(ShareError::InvalidParams {
            k,
            n: u32::try_from(xs.len()).unwrap_or(u32::MAX),
        });
    }
    let n_bytes = streams[0].len();
    if n_bytes > MAX_SECRET_BYTES {
        return Err(ShareError::SecretTooLarge {
            actual: n_bytes,
            max: MAX_SECRET_BYTES,
        });
    }
    for (index, s) in streams.iter().enumerate() {
        if s.len() != n_bytes {
            return Err(ShareError::StreamLengthMismatch {
                index,
                expected: n_bytes,
                actual: s.len(),
            });
        }
    }
    // Optimization: the Lagrange basis depends only on x-values,
    // which are constant across every byte of the secret. Compute
    // once, reuse for every byte. Turns the per-byte cost from
    // O(K^2) GF muls down to O(K) muls — a big win for multi-byte
    // secrets like the 32-byte identity master key (typical case).
    let kk = k as usize;
    // Reuse validation + basis-prep logic from the single-byte path.
    let zero_b_shares: Vec<Share> = xs[..kk].iter().map(|&x| Share::new(x, 0)).collect();
    // Validate share x-values once.
    for sh in &zero_b_shares {
        if sh.x == 0 {
            return Err(ShareError::InvalidShareX);
        }
    }
    for i in 0..kk {
        for j in (i + 1)..kk {
            if zero_b_shares[i].x == zero_b_shares[j].x {
                return Err(ShareError::DuplicateShareX);
            }
        }
    }
    let basis = lagrange_basis_at_zero(&zero_b_shares);
    let mut out = Vec::with_capacity(n_bytes);
    // `b` is a column index addressed across every share's byte stream
    // (streams[i][b] for all i), so it can't iterate a single container.
    #[allow(clippy::needless_range_loop)]
    for b in 0..n_bytes {
        let mut acc: u32 = 0;
        for i in 0..kk {
            acc = gf_add(acc, gf_mul(u32::from(streams[i][b]), u32::from(basis[i])));
        }
        out.push((acc & 0xFF) as u8);
    }
    Ok(out)
}

/// Horner's method polynomial evaluation in GF(2^8).
/// `coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...`
fn poly_eval(coeffs: &[u32], x: u32) -> u32 {
    if coeffs.is_empty() {
        return 0;
    }
    let mut acc = coeffs[coeffs.len() - 1] & 0xFF;
    for i in (0..coeffs.len() - 1).rev() {
        let c = coeffs[i] & 0xFF;
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc & 0xFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Split one secret byte with a scripted coefficient stream; returns the
    /// share y-values and how many coefficient bytes were drawn.
    fn split_scripted(secret: u8, k: u32, n: u32, script: &[u8]) -> (Vec<u8>, usize) {
        let mut drawn = 0usize;
        let streams = share_bytes_with_next(&[secret], k, n, || {
            let byte = script
                .get(drawn)
                .copied()
                .ok_or(ShareError::RandomnessUnavailable(
                    "scripted coefficient stream exhausted".to_string(),
                ))?;
            drawn += 1;
            Ok(byte)
        })
        .expect("valid parameters and enough scripted bytes");
        (streams.iter().map(|stream| stream[0]).collect(), drawn)
    }

    #[test]
    fn perfect_secrecy_exhaustive_k2_single_share() {
        // k = 2: one share must carry no information about the secret.
        // Over every coefficient a_1 in GF(2^8), each share value must occur
        // exactly once, for every secret. A forced non-zero a_1 makes the
        // share at x = 1 never equal the secret: an observer could rule out
        // s = y, and this test fails.
        for secret in 0..=255u8 {
            for x_index in 0..3usize {
                let mut seen = [0u16; 256];
                for a1 in 0..=255u8 {
                    let (ys, drawn) = split_scripted(secret, 2, 3, &[a1]);
                    assert_eq!(drawn, 1, "exactly k-1 coefficient draws per byte");
                    seen[usize::from(ys[x_index])] += 1;
                }
                assert!(
                    seen.iter().all(|&count| count == 1),
                    "share x={} is not uniform for secret {secret:#04x}",
                    x_index + 1
                );
            }
        }
    }

    #[test]
    fn perfect_secrecy_exhaustive_k3_two_shares() {
        // k = 3: any two shares must be jointly uniform and independent of
        // the secret. Over every (a_1, a_2) in GF(2^8)^2, each (y_i, y_j) pair
        // must occur exactly once. A sample of secrets keeps this fast while
        // still covering 0, 1, 0xFF and arbitrary values.
        let secrets = [
            0x00u8, 0x01, 0x02, 0x1B, 0x42, 0x53, 0x80, 0xAA, 0xC1, 0xCA, 0xFE, 0xFF,
        ];
        for &secret in &secrets {
            for (i, j) in [(0usize, 1usize), (0, 2), (1, 2)] {
                let mut seen = vec![0u8; 65536];
                for a1 in 0..=255u8 {
                    for a2 in 0..=255u8 {
                        let (ys, drawn) = split_scripted(secret, 3, 3, &[a1, a2]);
                        assert_eq!(drawn, 2, "exactly k-1 coefficient draws per byte");
                        let slot = usize::from(ys[i]) << 8 | usize::from(ys[j]);
                        seen[slot] = seen[slot].saturating_add(1);
                    }
                }
                assert!(
                    seen.iter().all(|&count| count == 1),
                    "shares ({}, {}) are not jointly uniform for secret {secret:#04x}",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    #[test]
    fn zero_top_coefficient_is_accepted_and_still_reconstructs() {
        // a_{k-1} = 0 is a legitimate uniform draw: k shares still
        // reconstruct, and no extra coefficient byte is consumed.
        let (ys, drawn) = split_scripted(0x42, 3, 4, &[0x17, 0x00]);
        assert_eq!(drawn, 2);
        let shares: Vec<Share> = ys
            .iter()
            .enumerate()
            .map(|(index, &y)| Share::new(u8::try_from(index + 1).expect("small"), y))
            .collect();
        assert_eq!(reconstruct_byte(&shares[..3], 3).unwrap(), 0x42);
        assert_eq!(reconstruct_byte(&shares[1..], 3).unwrap(), 0x42);
    }

    #[test]
    fn params_valid_bounds() {
        assert!(params_valid(2, 3));
        assert!(params_valid(1, 1));
        assert!(!params_valid(0, 3));
        assert!(!params_valid(4, 3));
        assert!(!params_valid(1, 256));
    }

    #[test]
    fn max_participants_255() {
        assert_eq!(max_participants(), 255);
    }

    #[test]
    fn share_byte_then_reconstruct_2_of_3() {
        let mut st = PrngState::new(0xA5A5_A5A5_A5A5_A5A5);
        let shares = share_byte(0x42, 2, 3, &mut st).unwrap();
        assert_eq!(shares.len(), 3);
        let pairs = [(0, 1), (0, 2), (1, 2)];
        for (i, j) in pairs {
            let sub = vec![shares[i], shares[j]];
            assert_eq!(reconstruct_byte(&sub, 2).unwrap(), 0x42);
        }
    }

    #[test]
    fn share_byte_3_of_5() {
        let mut st = PrngState::new(0x1234_5678_90AB_CDEF);
        let shares = share_byte(0xDE, 3, 5, &mut st).unwrap();
        // Sample three subsets.
        for picks in [[0, 1, 2], [0, 3, 4], [2, 3, 4]] {
            let sub: Vec<Share> = picks.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct_byte(&sub, 3).unwrap(), 0xDE);
        }
    }

    #[test]
    fn k_eq_1_is_broadcast() {
        let mut st = PrngState::new(0xCAFE_BABE_CAFE_BABE);
        let shares = share_byte(0x7F, 1, 4, &mut st).unwrap();
        // Every single share IS the secret (degree-0 polynomial == constant).
        for sh in &shares {
            assert_eq!(sh.y, 0x7F);
        }
        assert_eq!(reconstruct_byte(&[shares[0]], 1).unwrap(), 0x7F);
    }

    #[test]
    fn multi_byte_roundtrip() {
        let secret = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let mut st = PrngState::new(0xF00D_FACE_0000_0001);
        let streams = share_bytes(secret, 3, 5, &mut st).unwrap();
        assert_eq!(streams.len(), 5);
        // Reconstruct from shares 1, 3, 5 (indices 0, 2, 4).
        let xs = vec![1u8, 3, 5];
        let refs: Vec<&[u8]> = vec![
            streams[0].as_slice(),
            streams[2].as_slice(),
            streams[4].as_slice(),
        ];
        let recovered = reconstruct_bytes(&xs, &refs, 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn rejects_invalid_params() {
        let mut st = PrngState::new(0);
        assert_eq!(
            share_byte(0, 0, 3, &mut st).unwrap_err(),
            ShareError::InvalidParams { k: 0, n: 3 }
        );
        assert_eq!(
            share_byte(0, 4, 3, &mut st).unwrap_err(),
            ShareError::InvalidParams { k: 4, n: 3 }
        );
    }

    #[test]
    fn rejects_duplicate_x_at_reconstruct() {
        let s = [Share::new(1, 0xAA), Share::new(1, 0xBB)];
        assert_eq!(
            reconstruct_byte(&s, 2).unwrap_err(),
            ShareError::DuplicateShareX
        );
    }

    #[test]
    fn rejects_zero_x_at_reconstruct() {
        let s = [Share::new(0, 0xAA), Share::new(1, 0xBB)];
        assert_eq!(
            reconstruct_byte(&s, 2).unwrap_err(),
            ShareError::InvalidShareX
        );
    }

    #[test]
    fn subset_independence() {
        // Any K shares reconstruct the same secret, regardless of which K.
        let mut st = PrngState::new(0x5A5A_5A5A_5A5A_5A5A);
        let shares = share_byte(0xAB, 4, 7, &mut st).unwrap();
        for picks in [[0, 1, 2, 3], [3, 4, 5, 6], [0, 2, 4, 6]] {
            let sub: Vec<Share> = picks.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct_byte(&sub, 4).unwrap(), 0xAB);
        }
    }

    #[test]
    fn secure_split_roundtrips_and_is_fresh() {
        let secret = b"production recovery key material";
        let first = share_bytes_secure(secret, 3, 5).unwrap();
        let second = share_bytes_secure(secret, 3, 5).unwrap();
        assert_ne!(first, second, "independent CSPRNG splits must be fresh");
        let refs: Vec<&[u8]> = first[..3].iter().map(Vec::as_slice).collect();
        assert_eq!(reconstruct_bytes(&[1, 2, 3], &refs, 3).unwrap(), secret);
    }

    #[test]
    fn secret_length_and_zero_threshold_are_rejected_before_allocation() {
        let mut state = PrngState::new(1);
        assert!(matches!(
            share_bytes(&vec![0u8; MAX_SECRET_BYTES + 1], 2, 3, &mut state),
            Err(ShareError::SecretTooLarge { .. })
        ));
        assert!(matches!(
            reconstruct_bytes(&[], &[], 0),
            Err(ShareError::InvalidParams { k: 0, .. })
        ));
        assert!(matches!(
            reconstruct_byte(&[], 0),
            Err(ShareError::InvalidParams { k: 0, .. })
        ));
    }
}
