//! Adaptive binary range coder (LZMA family): 11-bit probabilities, shift-5
//! adaptation, carry-propagating 33-bit low. Used by ONE Memory's grid codec
//! to entropy-code sensor residuals near their information floor.

const TOP: u32 = 1 << 24;
const BITS: u32 = 11;
const ONE: u16 = 1 << BITS;
const MOVE: u32 = 3;
/// Initial probability of a 0 bit: one half.
pub const HALF: u16 = ONE / 2;

/// Range encoder writing to an owned buffer.
#[derive(Debug)]
pub struct Encoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// A fresh encoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || self.low >= 1 << 32 {
            let carry = u8::from(self.low >= 1 << 32);
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add(carry));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    /// Code one bit against an adaptive probability.
    pub fn bit(&mut self, prob: &mut u16, bit: bool) {
        let bound = (self.range >> BITS) * u32::from(*prob);
        if bit {
            self.low += u64::from(bound);
            self.range -= bound;
            *prob -= *prob >> MOVE;
        } else {
            self.range = bound;
            *prob += (ONE - *prob) >> MOVE;
        }
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// Code `count` raw bits of `value` (most significant first), probability 1/2.
    pub fn direct(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.range >>= 1;
            if (value >> i) & 1 == 1 {
                self.low += u64::from(self.range);
            }
            while self.range < TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    /// Code `value` (`depth` bits) through a binary tree of probabilities
    /// (`tree.len() == 1 << depth`; index 0 unused).
    pub fn tree(&mut self, tree: &mut [u16], depth: u32, value: u32) {
        let mut node = 1usize;
        for i in (0..depth).rev() {
            let bit = (value >> i) & 1 == 1;
            self.bit(&mut tree[node], bit);
            node = (node << 1) | usize::from(bit);
        }
    }

    /// Flush and return the coded bytes: the final `low`, in full.
    ///
    /// The coder's first byte is always 0 (the coded value lies below the
    /// initial range, 2^32 - 1, so no carry can reach it); it is not written.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        debug_assert_eq!(self.out.first(), Some(&0));
        self.out.remove(0);
        self.out
    }
}

/// Range decoder over a byte slice; reading past the end yields zeros.
///
/// The encoding is canonical: [`Decoder::finished_exactly`] holds only for the
/// exact bytes [`Encoder::finish`] produced for the decoded symbols, so damage
/// anywhere in a stream -- including bytes no decision reads -- is detected.
#[derive(Debug)]
pub struct Decoder<'a> {
    code: u32,
    range: u32,
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Start decoding `input` (as produced by [`Encoder::finish`]).
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        let mut d = Self {
            code: 0,
            range: u32::MAX,
            input,
            pos: 0,
        };
        for _ in 0..4 {
            d.code = (d.code << 8) | u32::from(d.next());
        }
        d
    }

    fn next(&mut self) -> u8 {
        let b = self.input.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    /// True when decoding consumed more bytes than the input holds.
    #[must_use]
    pub fn overran(&self) -> bool {
        self.pos > self.input.len()
    }

    /// After the last symbol: true iff the input is exactly the encoder's
    /// output for the symbols decoded. The encoder writes the final `low` in
    /// full, so the decoder must have read every byte and stand at `code == 0`.
    #[must_use]
    pub fn finished_exactly(&self) -> bool {
        self.pos == self.input.len() && self.code == 0
    }

    /// Decode one bit against an adaptive probability.
    pub fn bit(&mut self, prob: &mut u16) -> bool {
        let bound = (self.range >> BITS) * u32::from(*prob);
        let bit = if self.code < bound {
            self.range = bound;
            *prob += (ONE - *prob) >> MOVE;
            false
        } else {
            self.code -= bound;
            self.range -= bound;
            *prob -= *prob >> MOVE;
            true
        };
        while self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.next());
        }
        bit
    }

    /// Decode `count` raw bits.
    pub fn direct(&mut self, count: u32) -> u32 {
        let mut value = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            let bit = self.code >= self.range;
            if bit {
                self.code -= self.range;
            }
            value = (value << 1) | u32::from(bit);
            while self.range < TOP {
                self.range <<= 8;
                self.code = (self.code << 8) | u32::from(self.next());
            }
        }
        value
    }

    /// Decode a `depth`-bit value through a probability tree.
    pub fn tree(&mut self, tree: &mut [u16], depth: u32) -> u32 {
        let mut node = 1usize;
        for _ in 0..depth {
            let bit = self.bit(&mut tree[node]);
            node = (node << 1) | usize::from(bit);
        }
        // depth <= 8 by construction, so the leaf index fits u32 exactly
        u32::try_from(node - (1 << depth)).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_trees_and_direct_bits_round_trip_under_skewed_and_flat_statistics() {
        let mut x: u64 = 0xDEAD_BEEF_1234_5678;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let n = 200_000;
        let ops: Vec<(u8, u32)> = (0..n)
            .map(|i| {
                let r = rnd();
                match i % 3 {
                    0 => (0, u32::from(r % 100 < 3)), // a very skewed bit
                    1 => (1, (r % 7) as u32 + if r % 4 == 0 { 40 } else { 0 }), // tree, 6 bits
                    _ => (2, (r & 0x3FF) as u32),     // 10 raw bits
                }
            })
            .collect();
        let mut enc = Encoder::new();
        let (mut p, mut tree) = (HALF, vec![HALF; 64]);
        for &(kind, v) in &ops {
            match kind {
                0 => enc.bit(&mut p, v == 1),
                1 => enc.tree(&mut tree, 6, v),
                _ => enc.direct(v, 10),
            }
        }
        let bytes = enc.finish();
        let mut dec = Decoder::new(&bytes);
        let (mut p, mut tree) = (HALF, vec![HALF; 64]);
        for &(kind, v) in &ops {
            let got = match kind {
                0 => u32::from(dec.bit(&mut p)),
                1 => dec.tree(&mut tree, 6),
                _ => dec.direct(10),
            };
            assert_eq!(got, v);
        }
        assert!(!dec.overran());
        assert!(dec.finished_exactly());
        // the skewed stream really is compressed (entropy ~0.19 bits for 1/3 of ops)
        assert!(bytes.len() * 8 < n * 6);
    }

    /// Decode `count` skewed bits; `Some(bits)` only for an exact encoding.
    fn decode_bits(bytes: &[u8], count: usize) -> Option<Vec<bool>> {
        let mut dec = Decoder::new(bytes);
        let mut p = HALF;
        let bits: Vec<bool> = (0..count).map(|_| dec.bit(&mut p)).collect();
        dec.finished_exactly().then_some(bits)
    }

    #[test]
    fn every_damaged_byte_and_every_length_change_is_detected() {
        // the encoding is canonical: any other byte string either decodes to
        // different symbols or fails the exactness check -- including the
        // flush bytes, which no decision reads
        for (n, every) in [(0usize, 1usize), (1, 1), (7, 1), (300, 1), (5_000, 37)] {
            let bits: Vec<bool> = (0..n).map(|i| (i * 7919) % 13 < 3).collect();
            let mut enc = Encoder::new();
            let mut p = HALF;
            for &b in &bits {
                enc.bit(&mut p, b);
            }
            let bytes = enc.finish();
            assert_eq!(decode_bits(&bytes, n).as_deref(), Some(&bits[..]));
            for i in (0..bytes.len()).step_by(every) {
                for flip in [0x01u8, 0x10, 0x80, 0xFF] {
                    let mut bad = bytes.clone();
                    bad[i] ^= flip;
                    assert_ne!(
                        decode_bits(&bad, n).as_deref(),
                        Some(&bits[..]),
                        "n {n} byte {i} ^ {flip:#x}"
                    );
                }
            }
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(decode_bits(&longer, n).is_none());
            if !bytes.is_empty() {
                assert!(decode_bits(&bytes[..bytes.len() - 1], n).is_none());
            }
        }
    }

    #[test]
    fn carries_propagate_through_runs_of_ff() {
        // probabilities driven to the extremes force long 0xFF runs and carries
        let mut enc = Encoder::new();
        let mut p = HALF;
        let bits: Vec<bool> = (0..50_000).map(|i| i % 997 == 0).collect();
        for &b in &bits {
            enc.bit(&mut p, b);
        }
        let bytes = enc.finish();
        let mut dec = Decoder::new(&bytes);
        let mut p = HALF;
        for &b in &bits {
            assert_eq!(dec.bit(&mut p), b);
        }
    }
}
