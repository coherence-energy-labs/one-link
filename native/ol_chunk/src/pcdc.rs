//! Parallel `FastCDC` (v2020, normalization level 1, seed 0) with boundaries
//! byte-identical to the serial `fastcdc::v2020::FastCDC` iterator.
//!
//! Why it can be parallel: v2020 rolls two bytes per step, but both of its
//! checks reduce to one per-byte gear hash `R(p) = (R(p-1) << 1) + GEAR[b_p]`
//! (`GEAR_LS = GEAR << 1` and no mask uses bit 63), tested as `R(p) & mask
//! == 0`. `R` starts at 0 at `chunk_start + min_size`, and a 64-bit shift
//! register forgets a byte after 64 steps -- so from 63 bytes past that start
//! on, `R(p)` equals a GLOBAL rolling hash `G(p)` over the last 64 bytes,
//! independent of where the chunk began.
//!
//! Phase 1 (parallel, all cores): compute `G` over the whole buffer and record
//! the positions where it satisfies each mask -- a few dozen per MiB.
//! Phase 2 (serial, O(chunks)): walk the chunks; recompute `R` exactly over
//! each chunk's first 63 hashed bytes, then binary-search the candidate lists
//! for the first cut, honoring v2020's min/normal/max regions and its
//! two-bytes-per-step parity. ONE Memory measured the serial scan at
//! 0.36-0.74 ms/MiB, its largest remaining serial ingest cost.

use crate::cdc::CdcParams;
use fastcdc::v2020::{get_gear_with_seed, logarithm2, MASKS};
use rayon::prelude::*;

const SEGMENT: usize = 1 << 20;
const WINDOW: usize = 63;

/// Byte ranges `[start, end)` of every chunk, identical to the serial scanner.
#[must_use]
pub fn chunk_ranges(buffer: &[u8], params: CdcParams) -> Vec<(usize, usize)> {
    let (gear, _gear_ls) = get_gear_with_seed(0);
    let bits = logarithm2(params.avg_size);
    let mask_s = MASKS[(bits + 1) as usize];
    let mask_l = MASKS[(bits - 1) as usize];
    let n = buffer.len();
    let starts: Vec<usize> = (0..n).step_by(SEGMENT).collect();
    let parts: Vec<(Vec<usize>, Vec<usize>)> = starts
        .par_iter()
        .map(|&lo| {
            let hi = (lo + SEGMENT).min(n);
            let mut h: u64 = 0;
            for &b in &buffer[lo.saturating_sub(WINDOW)..lo] {
                h = (h << 1).wrapping_add(gear[b as usize]);
            }
            let (mut s, mut l) = (Vec::new(), Vec::new());
            for (p, &b) in buffer[lo..hi].iter().enumerate() {
                h = (h << 1).wrapping_add(gear[b as usize]);
                if h & mask_l == 0 {
                    l.push(lo + p);
                }
                if h & mask_s == 0 {
                    s.push(lo + p);
                }
            }
            (s, l)
        })
        .collect();
    let mut cand_s = Vec::new();
    let mut cand_l = Vec::new();
    for (s, l) in parts {
        cand_s.extend(s);
        cand_l.extend(l);
    }
    let sizes = (
        params.min_size as usize,
        params.avg_size as usize,
        params.max_size as usize,
    );
    let mut out = Vec::with_capacity(n / sizes.1 + 1);
    let mut start = 0;
    while start < n {
        let count = cut(
            buffer,
            start,
            n - start,
            sizes,
            (mask_s, mask_l),
            &gear,
            (&cand_s, &cand_l),
        );
        out.push((start, start + count));
        start += count;
    }
    out
}

/// BLAKE3 chunk addresses for `ranges` of `buffer`, computed in parallel.
#[must_use]
pub fn address_ranges(buffer: &[u8], ranges: &[(usize, usize)]) -> Vec<crate::cdc::Boundary> {
    ranges
        .par_iter()
        .map(|&(start, end)| crate::cdc::Boundary {
            start,
            end,
            raw_address: crate::blake3_wrap::chunk_address_raw(&buffer[start..end]),
        })
        .collect()
}

/// First candidate position in `[lo, hi)`, if any.
fn first_in(cands: &[usize], lo: usize, hi: usize) -> Option<usize> {
    let i = cands.partition_point(|&x| x < lo);
    cands.get(i).copied().filter(|&p| p < hi)
}

/// `fastcdc::v2020::cut_gear` for the chunk starting at `start`: the chunk length.
fn cut(
    buffer: &[u8],
    start: usize,
    available: usize,
    (min, avg, max): (usize, usize, usize),
    (mask_s, mask_l): (u64, u64),
    gear: &[u64; 256],
    (cand_s, cand_l): (&[usize], &[usize]),
) -> usize {
    let mut remaining = available;
    if remaining <= min {
        return remaining;
    }
    let mut center = avg;
    if remaining > max {
        remaining = max;
    } else if remaining < center {
        center = remaining;
    }
    // v2020 hashes two bytes per step from index min/2: byte positions are
    // checked from `first`, with mask_s below `switch`, mask_l up to `end`.
    let first = (min / 2) * 2;
    let switch = ((center / 2) * 2).max(first);
    let end = (remaining / 2) * 2;
    // Region A: R differs from the global hash until 63 bytes have rolled in.
    let a_end = (first + WINDOW).min(end);
    let mut h: u64 = 0;
    for p in first..a_end {
        h = (h << 1).wrapping_add(gear[buffer[start + p] as usize]);
        let mask = if p < switch { mask_s } else { mask_l };
        if h & mask == 0 {
            return p;
        }
    }
    // Region B: R(p) == G(p); use the precomputed candidates.
    let b_switch = switch.max(a_end);
    if a_end < b_switch {
        if let Some(p) = first_in(cand_s, start + a_end, start + b_switch) {
            return p - start;
        }
    }
    if b_switch < end {
        if let Some(p) = first_in(cand_l, start + b_switch, start + end) {
            return p - start;
        }
    }
    remaining
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serial(buffer: &[u8], p: CdcParams) -> Vec<(usize, usize)> {
        fastcdc::v2020::FastCDC::new(buffer, p.min_size, p.avg_size, p.max_size)
            .map(|c| (c.offset, c.offset + c.length))
            .collect()
    }

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24).to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn the_derivation_assumptions_hold() {
        let (gear, gear_ls) = get_gear_with_seed(0);
        for i in 0..256 {
            assert_eq!(gear_ls[i], gear[i] << 1, "GEAR_LS must be GEAR << 1");
        }
        for m in MASKS {
            assert_eq!(m >> 63, 0, "no mask may use bit 63");
        }
    }

    #[test]
    fn identical_to_serial_on_noise_of_many_lengths() {
        let p = CdcParams::default();
        for (i, n) in [
            0,
            1,
            63,
            64,
            8191,
            8192,
            8193,
            65_537,
            262_145,
            1 << 20,
            (3 << 20) + 7,
            9_000_001,
        ]
        .into_iter()
        .enumerate()
        {
            let buf = noise(n, 0x9E37_79B9 + i as u64);
            assert_eq!(chunk_ranges(&buf, p), serial(&buf, p), "length {n}");
        }
    }

    #[test]
    fn identical_to_serial_for_every_length_near_the_chunk_size() {
        // v2020's parity rules (two bytes per step) only matter at a final
        // chunk of odd length below the average: a single position per case,
        // hit ~1 time in 2^7 with this profile. Every length, many seeds.
        let p = CdcParams {
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };
        for seed in 0..6u64 {
            let buf = noise(2048, 0xC0FF_EE00 + seed);
            for n in 64..2048 {
                assert_eq!(
                    chunk_ranges(&buf[..n], p),
                    serial(&buf[..n], p),
                    "seed {seed} len {n}"
                );
            }
        }
    }

    #[test]
    fn identical_to_serial_across_profiles_and_pathological_data() {
        let profiles = [
            CdcParams {
                min_size: 64,
                avg_size: 256,
                max_size: 1024,
            },
            CdcParams {
                min_size: 2048,
                avg_size: 8192,
                max_size: 32_768,
            },
            CdcParams {
                min_size: 16_384,
                avg_size: 65_536,
                max_size: 262_144,
            },
            CdcParams {
                min_size: 65_536,
                avg_size: 524_288,
                max_size: 2_097_152,
            },
        ];
        let mut zeros = vec![0u8; 3 << 20];
        let mut runs = noise(3 << 20, 7);
        for (i, b) in runs.iter_mut().enumerate() {
            if (i / 5000) % 3 == 0 {
                *b = 0xAA;
            }
        }
        zeros[1_000_000] = 1;
        for p in profiles {
            for buf in [noise(5 << 20, 42), zeros.clone(), runs.clone()] {
                assert_eq!(chunk_ranges(&buf, p), serial(&buf, p), "{p:?}");
            }
        }
    }
}
