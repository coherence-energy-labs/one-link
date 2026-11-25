//! Constant-time GF(2^8) arithmetic using the AES primitive polynomial
//! x^8 + x^4 + x^3 + x + 1 = 0x11B.
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTION 1.
//! Identical bit-pattern outputs so encoded shares interoperate with
//! the `OneField` mesh nodes byte-for-byte.

use subtle::{Choice, ConditionallySelectable};

/// GF(2^8) primitive polynomial (AES standard). Low byte 0x1B is what
/// gets `XORed` during the reduce step after a left-shift overflow.
pub const GF_PRIMITIVE: u32 = 0x11B;

/// GF(2^8) addition is XOR (characteristic 2).
#[inline]
#[must_use]
pub const fn gf_add(a: u32, b: u32) -> u32 {
    (a ^ b) & 0xFF
}

/// GF(2^8) subtraction equals addition (characteristic 2).
#[inline]
#[must_use]
pub const fn gf_sub(a: u32, b: u32) -> u32 {
    (a ^ b) & 0xFF
}

/// GF(2^8) multiplication via Russian-peasant shift-and-reduce.
/// Constant-time wrt operand values: operand-independent control flow, fixed
/// 8 iterations, and optimization-barrier-protected conditional selection
/// instead of secret-dependent branches.
///
/// The [`Choice`] barriers are security-critical.  Plain arithmetic masks are
/// source-level branchless, but LLVM can recognize them as booleans and turn
/// them back into conditional jumps.  `Choice::from` deliberately hides that
/// boolean refinement before [`ConditionallySelectable`] constructs the mask.
#[inline]
#[must_use]
pub fn gf_mul(multiplicand: u32, multiplier: u32) -> u32 {
    let mut shifted_multiplicand: u32 = multiplicand & 0xFF;
    let mut shifted_multiplier: u32 = multiplier & 0xFF;
    let mut product: u32 = 0;
    let mut round: u32 = 0;
    while round < 8 {
        let add_multiplicand = Choice::from((shifted_multiplier & 1) as u8);
        product ^= u32::conditional_select(&0, &shifted_multiplicand, add_multiplicand);

        let reduce = Choice::from(((shifted_multiplicand >> 7) & 1) as u8);
        shifted_multiplicand = (shifted_multiplicand << 1) & 0xFF;
        shifted_multiplicand ^= u32::conditional_select(&0, &0x1B, reduce);
        shifted_multiplier >>= 1;
        round += 1;
    }
    product & 0xFF
}

/// GF(2^8) power: a^e via square-and-multiply. Not constant-time wrt e
/// (e is typically the public exponent 254 in [`gf_inv`] so this is fine).
#[inline]
#[must_use]
pub fn gf_pow(base: u32, exp: u32) -> u32 {
    let mut b = base & 0xFF;
    let mut e = exp;
    let mut r: u32 = 1;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, b);
        }
        b = gf_mul(b, b);
        e >>= 1;
    }
    r
}

/// GF(2^8) multiplicative inverse via Fermat: a^(2^8 - 2) = a^254.
/// Returns 0 for input 0 (undefined; caller must avoid by construction).
///
/// Constant-time in `a`: the exponent 254 is public, every multiply is the
/// constant-time [`gf_mul`], and 0^254 = 0 already, so no zero test (which
/// would be a branch on the secret) is needed. `ol_ct_audit` checks this.
#[inline]
#[must_use]
pub fn gf_inv(a: u32) -> u32 {
    gf_pow(a & 0xFF, 254)
}

/// GF(2^8) division a / b = a * b^{-1}. Returns 0 when b == 0.
///
/// Constant-time in both operands: `gf_inv(0) = 0` and `gf_mul(a, 0) = 0`,
/// so the b == 0 convention needs no branch.
#[inline]
#[must_use]
pub fn gf_div(a: u32, b: u32) -> u32 {
    gf_mul(a, gf_inv(b))
}

// ── Optimized table-based multiplication ────────────────────────────
//
// The constant-time `gf_mul` above runs an 8-iter protected loop per
// multiply. For NON-SECURITY-CRITICAL paths (e.g., Lagrange basis
// evaluation, where operand values are derived from public share
// x-coordinates), a 64KB precomputed table gives ~5-10x speedup with
// a single load.
//
// Use `gf_mul_fast` ONLY when:
//   - The operands are public (share x-values, not secret bytes)
//   - The 64KB LUT fits in L1/L2 cache (modern CPUs comfortably)
//
// `gf_mul` (the constant-time default) is what `share_byte` and other
// code that handles secret bytes should call. `gf_mul_fast` is for
// reconstruction where x-values are public.

/// Precomputed 256x256 GF(2^8) multiplication table. ~64KB of static
/// memory; built at first access via `OnceLock` so non-fast callers
/// pay no cost.
fn gf_mul_table() -> &'static [[u8; 256]] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Box<[[u8; 256]]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = vec![[0u8; 256]; 256].into_boxed_slice();
        for a in 0..256usize {
            for b in 0..256usize {
                table[a][b] = gf_mul(a as u32, b as u32) as u8;
            }
        }
        table
    })
}

/// Fast non-constant-time GF(2^8) multiplication via precomputed
/// table. ~5-10x faster than `gf_mul`. Use ONLY with public-value
/// operands (e.g., share x-coordinates during Lagrange basis eval).
///
/// # Side-channel warning
/// Table-based multiplication is NOT constant-time wrt cache state.
/// A precise attacker measuring L1 cache eviction patterns can
/// recover operand bits. This function is safe ONLY when operand
/// values are public.
#[inline]
#[must_use]
pub fn gf_mul_fast(a: u8, b: u8) -> u8 {
    gf_mul_table()[a as usize][b as usize]
}

/// Precomputed 256-byte multiplicative-inverse LUT for GF(2^8).
/// `INV_LUT[a] = a^-1` for a in 1..256; `INV_LUT[0] = 0` (undefined
/// in field; conventional sentinel). Built once on first access.
fn gf_inv_lut() -> &'static [u8; 256] {
    use std::sync::OnceLock;
    static LUT: OnceLock<Box<[u8; 256]>> = OnceLock::new();
    LUT.get_or_init(|| {
        let mut t = Box::new([0u8; 256]);
        // gf_inv via Fermat (a^254) for each a; LUT it once.
        for a in 1u32..256 {
            t[a as usize] = gf_inv(a) as u8;
        }
        t
    })
}

/// Fast non-constant-time GF(2^8) inverse via 256-byte LUT.
/// ~8× faster than [`gf_inv`] (which does 8 multiplications via
/// `a^254`). Use ONLY with public-value operands (share x-coords
/// during Lagrange basis evaluation).
///
/// Returns 0 for input 0 (sentinel; caller must avoid by construction).
///
/// # Side-channel warning
/// Same as [`gf_mul_fast`]: NOT constant-time wrt cache state. Use
/// only with public-value operands.
#[inline]
#[must_use]
pub fn gf_inv_fast(a: u8) -> u8 {
    gf_inv_lut()[a as usize]
}

/// Fast non-constant-time GF(2^8) division via LUT.
/// Equivalent to `gf_mul_fast(a, gf_inv_fast(b))`. Returns 0 when b=0.
///
/// # Side-channel warning
/// Cache-timing-leakable. Use only with public-value operands.
#[inline]
#[must_use]
pub fn gf_div_fast(a: u8, b: u8) -> u8 {
    if b == 0 {
        0
    } else {
        gf_mul_fast(a, gf_inv_fast(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_identity() {
        assert_eq!(gf_add(0x57, 0), 0x57);
    }

    #[test]
    fn self_inverse_under_add() {
        assert_eq!(gf_add(0x57, 0x57), 0);
    }

    #[test]
    fn multiplicative_identity() {
        assert_eq!(gf_mul(0x57, 1), 0x57);
    }

    #[test]
    fn zero_annihilation() {
        assert_eq!(gf_mul(0x57, 0), 0);
    }

    #[test]
    fn aes_vector() {
        // Standard AES test vector: 0x57 * 0x83 = 0xC1.
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
    }

    #[test]
    fn inverse_roundtrip_every_nonzero() {
        for a in 1u32..256 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a={a}");
        }
    }

    #[test]
    fn pow_consistency() {
        // 3^2 in GF(2^8): (x+1)*(x+1) = x^2 + 1 = 5.
        assert_eq!(gf_pow(3, 2), 5);
        // a^0 = 1, a^1 = a.
        assert_eq!(gf_pow(0x42, 0), 1);
        assert_eq!(gf_pow(0x42, 1), 0x42);
    }

    #[test]
    fn division_roundtrip() {
        for a in 0u32..256 {
            for b in 1u32..256 {
                let q = gf_div(a, b);
                assert_eq!(gf_mul(q, b), a, "a={a} b={b}");
            }
        }
    }

    #[test]
    fn gf_mul_fast_matches_constant_time() {
        // The optimized table-based gf_mul_fast must produce
        // bit-identical output to the constant-time gf_mul across
        // every (a, b) pair. This is the safety property.
        for a in 0u32..256 {
            for b in 0u32..256 {
                let slow = gf_mul(a, b) as u8;
                let fast = gf_mul_fast(a as u8, b as u8);
                assert_eq!(slow, fast, "mismatch at a=0x{a:02X} b=0x{b:02X}");
            }
        }
    }
}
