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
//!
//! One hash chain costs a shift and an add per byte, each waiting on the
//! last, so a core spends two cycles a byte however wide it is. The same
//! 64-byte memory that lets segments be hashed independently lets a segment
//! be cut into `LANES` equal lanes hashed side by side: each lane starts
//! from the 63 bytes before it, the chains do not depend on one another, and
//! the core overlaps them. The lanes are a fixed length so that the four
//! bytes of a step sit at constant offsets from one pointer; with lanes of a
//! length decided at run time the loop ran out of registers and reloaded its
//! pointers from the stack on every step. The positions found are the same
//! ones, in the same order.
//!
//! Phase 2 (serial, O(chunks)): walk the chunks; recompute `R` exactly over
//! each chunk's first 63 hashed bytes, then binary-search the candidate lists
//! for the first cut, honoring v2020's min/normal/max regions and its
//! two-bytes-per-step parity. ONE Memory measured the serial scan at
//! 0.36-0.74 ms/MiB, its largest remaining serial ingest cost.
//!
//! The candidate lists are the one thing here whose size the input decides.
//! On ordinary bytes they are a few dozen positions per MiB. A two-byte
//! pattern repeated through a file can satisfy a mask at every other byte,
//! and the lists then outweigh the input several times over. Phase 1
//! therefore stops recording in a lane that reaches `dense_limit`, and
//! the buffer is cut by hashing each chunk directly instead: the same
//! boundaries (it is the definition phase 2 shortcuts), one core, and no
//! memory that grows with the input.

use crate::cdc::CdcParams;
use crate::error::ChunkError;
use fastcdc::v2020::{get_gear_with_seed, logarithm2, MASKS};
use rayon::prelude::*;

const SEGMENT: usize = 1 << 20;
const WINDOW: usize = 63;
/// Hash chains advanced together within one full segment.
const LANES: usize = 4;
/// Bytes each chain covers.
const LANE: usize = SEGMENT / LANES;
/// Phase 1 tests one mask per byte instead of two when the two masks share
/// at least this many bits: a hash that is zero on the shared bits is then
/// rare enough (at most one byte in 256 on unstructured data) for the exact
/// tests to move out of the loop.
const SHARED_MASK_MIN_BITS: u32 = 8;

/// Positions where the global gear hash satisfies `mask_s` and `mask_l`,
/// each list ascending.
#[derive(Debug, Default, PartialEq, Eq)]
struct Candidates {
    s: Vec<usize>,
    l: Vec<usize>,
    /// A list reached its limit and positions after it were not recorded:
    /// the lists are incomplete and must not be used.
    dense: bool,
}

/// The two masks and how many positions one lane may record for each.
#[derive(Debug, Clone, Copy)]
struct Masks {
    s: u64,
    l: u64,
    limit_s: usize,
    limit_l: usize,
}

impl Masks {
    fn new(mask_s: u64, mask_l: u64) -> Self {
        Self {
            s: mask_s,
            l: mask_l,
            limit_s: dense_limit(mask_s),
            limit_l: dense_limit(mask_l),
        }
    }
}

/// How many positions one lane may record for `mask` before the input is
/// treated as built to satisfy it: sixteen times what unstructured bytes
/// produce over a lane (one position in `2^bits`), and never fewer than 256.
///
/// That bounds the lists by the profile instead of by the bytes: with the
/// default profile 16 KiB of positions per MiB of input, with the smallest
/// average (256 bytes, where unstructured input already yields a position
/// every 128 bytes) 1.25 MiB per MiB.
fn dense_limit(mask: u64) -> usize {
    ((LANE >> mask.count_ones().min(usize::BITS - 1)) * 16).max(256)
}

impl Candidates {
    /// Record `position` under each mask its hash satisfies. Out of line:
    /// phase 1 reaches this a few dozen times per MiB.
    #[cold]
    #[inline(never)]
    fn record(&mut self, h: u64, position: usize, masks: &Masks) {
        if h & masks.l == 0 {
            if self.l.len() < masks.limit_l {
                self.l.push(position);
            } else {
                self.dense = true;
            }
        }
        if h & masks.s == 0 {
            if self.s.len() < masks.limit_s {
                self.s.push(position);
            } else {
                self.dense = true;
            }
        }
    }

    fn append(&mut self, mut later: Self) {
        self.s.append(&mut later.s);
        self.l.append(&mut later.l);
        self.dense |= later.dense;
    }
}

/// The global gear hash as it stands before byte `at`: the `WINDOW` bytes
/// before it rolled in, fewer at the start of the buffer.
fn hash_before(buffer: &[u8], at: usize, gear: &[u64; 256]) -> u64 {
    let mut h: u64 = 0;
    for &b in &buffer[at.saturating_sub(WINDOW)..at] {
        h = (h << 1).wrapping_add(gear[usize::from(b)]);
    }
    h
}

/// Phase 1 for the segment `buffer[lo..hi]`. `may_match` is a cheap test
/// that no matching hash fails; [`Candidates::record`] applies the exact
/// ones. Every `LANE` bytes record up to the limit on their own, so a
/// segment holds at most `LANES` times that however its bytes were chosen.
fn segment_candidates<F: Fn(u64) -> bool>(
    buffer: &[u8],
    (lo, hi): (usize, usize),
    gear: &[u64; 256],
    masks: &Masks,
    may_match: F,
) -> Candidates {
    let mut all = Candidates::default();
    let (lanes, _) = buffer[lo..hi].as_chunks::<LANE>();
    if let [lane0, lane1, lane2, lane3] = lanes {
        // A full segment: four chains side by side.
        let mut found: [Candidates; LANES] = Default::default();
        let mut h0 = hash_before(buffer, lo, gear);
        let mut h1 = hash_before(buffer, lo + LANE, gear);
        let mut h2 = hash_before(buffer, lo + 2 * LANE, gear);
        let mut h3 = hash_before(buffer, lo + 3 * LANE, gear);
        for i in 0..LANE {
            h0 = (h0 << 1).wrapping_add(gear[usize::from(lane0[i])]);
            h1 = (h1 << 1).wrapping_add(gear[usize::from(lane1[i])]);
            h2 = (h2 << 1).wrapping_add(gear[usize::from(lane2[i])]);
            h3 = (h3 << 1).wrapping_add(gear[usize::from(lane3[i])]);
            if may_match(h0) {
                found[0].record(h0, lo + i, masks);
            }
            if may_match(h1) {
                found[1].record(h1, lo + LANE + i, masks);
            }
            if may_match(h2) {
                found[2].record(h2, lo + 2 * LANE + i, masks);
            }
            if may_match(h3) {
                found[3].record(h3, lo + 3 * LANE + i, masks);
            }
        }
        // The lanes are consecutive, so joined in order they are ascending.
        for lane in found {
            all.append(lane);
        }
    } else {
        // The last, shorter segment of a buffer: one chain, in pieces of a
        // lane so that the same limit applies to the same number of bytes.
        let mut h = hash_before(buffer, lo, gear);
        for (piece, bytes) in buffer[lo..hi].chunks(LANE).enumerate() {
            let start = lo + piece * LANE;
            let mut found = Candidates::default();
            for (i, &b) in bytes.iter().enumerate() {
                h = (h << 1).wrapping_add(gear[usize::from(b)]);
                if may_match(h) {
                    found.record(h, start + i, masks);
                }
            }
            all.append(found);
        }
    }
    all
}

/// Phase 1 over the whole buffer: every position where the global gear hash
/// satisfies `mask_s`, and every position where it satisfies `mask_l`.
///
/// `None` when some segment is dense in candidates. The lists a dense
/// segment would need are the memory this refuses to spend, and no later
/// segment is started once one is found.
fn candidates(buffer: &[u8], gear: &[u64; 256], masks: &Masks) -> Option<Candidates> {
    let n = buffer.len();
    // A hash can satisfy either mask only if it is zero on the bits both have.
    let shared = masks.s & masks.l;
    let starts: Vec<usize> = (0..n).step_by(SEGMENT).collect();
    let parts: Option<Vec<Candidates>> = starts
        .par_iter()
        .map(|&lo| {
            let span = (lo, (lo + SEGMENT).min(n));
            let found = if shared.count_ones() >= SHARED_MASK_MIN_BITS {
                segment_candidates(buffer, span, gear, masks, |h| h & shared == 0)
            } else {
                segment_candidates(buffer, span, gear, masks, |h| {
                    h & masks.l == 0 || h & masks.s == 0
                })
            };
            (!found.dense).then_some(found)
        })
        .collect();
    let mut all = Candidates::default();
    for part in parts? {
        all.append(part);
    }
    Some(all)
}

/// Byte ranges `[start, end)` of every chunk, identical to the serial scanner.
///
/// # Errors
///
/// The [`CdcParams::validate`] error for an invalid profile, before any byte
/// is hashed; [`ChunkError::NoProgress`] if a cut fails to advance (not
/// reachable with validated parameters).
pub fn chunk_ranges(buffer: &[u8], params: CdcParams) -> Result<Vec<(usize, usize)>, ChunkError> {
    params.validate()?;
    unvalidated_chunk_ranges(buffer, params)
}

/// v2020 normalization-level-1 masks `(mask_s, mask_l)` for `avg_size`, or
/// `None` when the average has no entry in [`MASKS`] (only outside
/// [`CdcParams::AVG_SIZE_RANGE`]).
fn level1_masks(avg_size: u32) -> Option<(u64, u64)> {
    let bits = usize::try_from(logarithm2(avg_size)).ok()?;
    Some((
        *MASKS.get(bits.checked_add(1)?)?,
        *MASKS.get(bits.checked_sub(1)?)?,
    ))
}

/// The kernel behind [`chunk_ranges`] without the parameter gate. It stays
/// total on any profile: an average with no mask is an error, and so is a
/// cut that does not advance, which is what `(1, 2, 4)` produced (`avg = 2`
/// selects the all-zero masks, so every position is a cut and the first
/// candidate is offset 0; the loop then pushed `(0, 0)` until allocation
/// failed). Separate so the guard can be tested with those very parameters.
fn unvalidated_chunk_ranges(
    buffer: &[u8],
    params: CdcParams,
) -> Result<Vec<(usize, usize)>, ChunkError> {
    let (mask_s, mask_l) = level1_masks(params.avg_size).ok_or(ChunkError::InvalidParameters(
        "avg_size has no FastCDC mask",
    ))?;
    let (gear, _gear_ls) = get_gear_with_seed(0);
    let found = candidates(buffer, &gear, &Masks::new(mask_s, mask_l));
    walk(buffer, params, (mask_s, mask_l), &gear, found.as_ref())
}

/// Phase 2: the chunks in order, each cut with the candidate lists when
/// there are any and by hashing it directly when there are none.
fn walk(
    buffer: &[u8],
    params: CdcParams,
    masks: (u64, u64),
    gear: &[u64; 256],
    found: Option<&Candidates>,
) -> Result<Vec<(usize, usize)>, ChunkError> {
    let n = buffer.len();
    let sizes = (
        params.min_size as usize,
        params.avg_size as usize,
        params.max_size as usize,
    );
    // `level1_masks` has no entry below avg = 2, so the divisor is non-zero.
    let mut out = Vec::with_capacity(n / sizes.1 + 1);
    let mut start = 0;
    while start < n {
        let count = cut(buffer, start, n - start, sizes, masks, gear, found);
        // `cut` never returns more than the `n - start` bytes it was given
        // (its region-A positions are below `remaining` and its candidates
        // are buffer positions), for any profile; zero is the one way this
        // loop could fail to terminate.
        if count == 0 {
            return Err(ChunkError::NoProgress {
                offset: start,
                len: n,
            });
        }
        out.push((start, start + count));
        start += count;
    }
    Ok(out)
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
///
/// Without `found`, every position is hashed from the start of the chunk,
/// which is what v2020 itself does. With it, only the first `WINDOW`
/// positions are, and the rest is looked up.
fn cut(
    buffer: &[u8],
    start: usize,
    available: usize,
    (min, avg, max): (usize, usize, usize),
    (mask_s, mask_l): (u64, u64),
    gear: &[u64; 256],
    found: Option<&Candidates>,
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
    // With no candidate lists it is the whole chunk.
    let a_end = if found.is_some() {
        (first + WINDOW).min(end)
    } else {
        end
    };
    let mut h: u64 = 0;
    for p in first..a_end {
        h = (h << 1).wrapping_add(gear[buffer[start + p] as usize]);
        let mask = if p < switch { mask_s } else { mask_l };
        if h & mask == 0 {
            return p;
        }
    }
    let Some(found) = found else {
        return remaining;
    };
    // Region B: R(p) == G(p); use the precomputed candidates.
    let b_switch = switch.max(a_end);
    if a_end < b_switch {
        if let Some(p) = first_in(&found.s, start + a_end, start + b_switch) {
            return p - start;
        }
    }
    if b_switch < end {
        if let Some(p) = first_in(&found.l, start + b_switch, start + end) {
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
    fn a_cut_that_does_not_advance_is_an_error_not_a_loop() {
        // The witnessed profile: avg = 2 selects the all-zero masks, so the
        // first position the kernel tests (offset 0, as min / 2 == 0) is a
        // cut. Before the guard this pushed (0, 0) until allocation failed.
        let witness = CdcParams {
            min_size: 1,
            avg_size: 2,
            max_size: 4,
        };
        assert_eq!(level1_masks(witness.avg_size), Some((0, 0)));
        let buf = noise(100, 0x5EED);
        assert!(matches!(
            unvalidated_chunk_ranges(&buf, witness),
            Err(ChunkError::NoProgress {
                offset: 0,
                len: 100
            })
        ));
        // The public entry point never reaches the kernel with it.
        assert!(matches!(
            chunk_ranges(&buf, witness),
            Err(ChunkError::SizeOutOfRange {
                field: "min_size",
                value: 1,
                ..
            })
        ));
        // An empty buffer has no cut to make, so the guard cannot misfire.
        assert_eq!(unvalidated_chunk_ranges(&[], witness).unwrap(), vec![]);
    }

    #[test]
    fn the_unvalidated_kernel_refuses_an_average_without_a_mask() {
        for avg_size in [0, 1, (1 << 25) - 1, u32::MAX] {
            let p = CdcParams {
                min_size: 0,
                avg_size,
                max_size: u32::MAX,
            };
            assert_eq!(level1_masks(avg_size), None, "avg {avg_size}");
            assert!(
                matches!(
                    unvalidated_chunk_ranges(&[7; 64], p),
                    Err(ChunkError::InvalidParameters(_))
                ),
                "avg {avg_size}"
            );
        }
    }

    #[test]
    fn every_valid_average_selects_two_non_zero_masks() {
        // With non-zero masks and min_size >= 64 the first cut the kernel can
        // make is at byte 64, so a validated profile cannot stall the loop.
        for avg_size in CdcParams::AVG_SIZE_RANGE {
            let (mask_s, mask_l) = level1_masks(avg_size).expect("valid average has masks");
            assert!(mask_s != 0 && mask_l != 0, "avg {avg_size}");
        }
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

    /// Phase 1 as one chain from the first byte to the last: the definition
    /// the laned scan has to reproduce.
    fn one_chain(buffer: &[u8], gear: &[u64; 256], masks: &Masks) -> Candidates {
        let mut all = Candidates::default();
        let mut h: u64 = 0;
        for (p, &b) in buffer.iter().enumerate() {
            h = (h << 1).wrapping_add(gear[usize::from(b)]);
            if h & masks.l == 0 {
                all.l.push(p);
            }
            if h & masks.s == 0 {
                all.s.push(p);
            }
        }
        all
    }

    /// Noise broken by runs of one repeated byte. Within a run the hash
    /// settles to a constant after 64 bytes, so a run either satisfies a
    /// mask at every position or at none: candidates arrive in bursts, at
    /// lane and segment edges included.
    fn dense(n: usize, seed: u64) -> Vec<u8> {
        let mut out = noise(n, seed);
        for (i, b) in out.iter_mut().enumerate() {
            if (i / 97) % 2 == 0 {
                *b = (i / 97).to_le_bytes()[0];
            }
        }
        out
    }

    /// The masks of a profile with the limits production uses.
    fn limited(avg_size: u32) -> Masks {
        let (mask_s, mask_l) = level1_masks(avg_size).expect("valid average has masks");
        Masks::new(mask_s, mask_l)
    }

    /// The same masks with no limit, so the lists can be compared whole even
    /// on input that production would call dense.
    fn unlimited(avg_size: u32) -> Masks {
        Masks {
            limit_s: usize::MAX,
            limit_l: usize::MAX,
            ..limited(avg_size)
        }
    }

    /// Bytes chosen to satisfy the masks as often as bytes can: at each
    /// position, the byte (if one of the 256 exists) that brings the global
    /// hash to zero on `mask_l`, else on `mask_s`, else noise. With the
    /// default profile that is a candidate every hundred bytes or so instead
    /// of one in tens of thousands, so a hash that is wrong for even the
    /// first position of a lane shows up as a missing or an extra candidate.
    fn crowded(n: usize, seed: u64, gear: &[u64; 256], masks: &Masks) -> Vec<u8> {
        let fill = noise(n, seed);
        let mut out = Vec::with_capacity(n);
        let mut h: u64 = 0;
        for &random in &fill {
            let next = |b: u8| (h << 1).wrapping_add(gear[usize::from(b)]);
            let chosen = (0..=u8::MAX)
                .find(|&b| next(b) & masks.l == 0)
                .or_else(|| (0..=u8::MAX).find(|&b| next(b) & masks.s == 0))
                .unwrap_or(random);
            h = next(chosen);
            out.push(chosen);
        }
        out
    }

    /// A two-byte pattern which, repeated, satisfies a mask at every other
    /// byte: what a file written to exhaust the candidate lists looks like.
    fn exhausting_pattern(gear: &[u64; 256], masks: &Masks) -> [u8; 2] {
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                let mut h: u64 = 0;
                let mut hits = 0;
                for i in 0..130 {
                    let byte = if i % 2 == 0 { a } else { b };
                    h = (h << 1).wrapping_add(gear[usize::from(byte)]);
                    if i >= 128 && (h & masks.l == 0 || h & masks.s == 0) {
                        hits += 1;
                    }
                }
                if hits > 0 {
                    return [a, b];
                }
            }
        }
        panic!("no two-byte pattern satisfies these masks");
    }

    /// Noise in which every one of `targets` satisfies `mask`: the three
    /// bytes ending at a target are searched for a combination that brings
    /// the global hash there to zero on the mask. Targets ascend and stand
    /// at least 67 bytes apart, so one does not disturb another.
    fn planted(n: usize, seed: u64, gear: &[u64; 256], mask: u64, targets: &[usize]) -> Vec<u8> {
        let roll = |h: u64, b: u8| (h << 1).wrapping_add(gear[usize::from(b)]);
        let mut out = noise(n, seed);
        for &at in targets {
            let before = hash_before(&out, at - 2, gear);
            let (a, b, c) = (0..=u8::MAX)
                .flat_map(|a| (0..=u8::MAX).map(move |b| (a, b)))
                .find_map(|(a, b)| {
                    let h = roll(roll(before, a), b);
                    (0..=u8::MAX)
                        .find(|&c| roll(h, c) & mask == 0)
                        .map(|c| (a, b, c))
                })
                .expect("three free bytes can zero any mask of at most 24 bits");
            out[at - 2..=at].copy_from_slice(&[a, b, c]);
        }
        out
    }

    #[test]
    fn laned_phase_one_is_exact_at_every_lane_edge() {
        // A lane begins from the 63 bytes before it and ends where the next
        // begins. A candidate planted on each side of every such edge, and
        // at the distances the hash's memory makes special, has to be found
        // at exactly that position: this is where a wrong start, a wrong
        // base or a short warm-up would show, and noise alone puts a
        // candidate there about once in a hundred thousand lanes.
        let (gear, _) = get_gear_with_seed(0);
        let n = 2 * SEGMENT + 3 * LANE + 99;
        let edges: Vec<usize> = (LANE..n).step_by(LANE).collect();
        for avg in [256, 65_536] {
            let masks = unlimited(avg);
            for (which, mask) in [("l", masks.l), ("s", masks.s)] {
                for offset in [-1isize, 0, 1, 2, 3, 46, 47, 62, 63, 64] {
                    let targets: Vec<usize> = edges
                        .iter()
                        .map(|&edge| edge.checked_add_signed(offset).expect("inside the buffer"))
                        .collect();
                    let buf = planted(
                        n,
                        0x5EED + offset.unsigned_abs() as u64,
                        &gear,
                        mask,
                        &targets,
                    );
                    let found = candidates(&buf, &gear, &masks).expect("no limit, so never dense");
                    assert_eq!(
                        found,
                        one_chain(&buf, &gear, &masks),
                        "avg {avg} mask_{which} offset {offset}"
                    );
                    let list = if which == "l" { &found.l } else { &found.s };
                    for target in &targets {
                        assert!(
                            list.binary_search(target).is_ok(),
                            "avg {avg} mask_{which} offset {offset}: {target} was planted"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn both_forms_of_the_phase_one_test_are_in_use() {
        // The default profile takes the one-test loop, the smallest profile
        // the two-test loop; the tests below run both.
        let shared = |avg: u32| {
            let masks = limited(avg);
            (masks.s & masks.l).count_ones()
        };
        assert!(shared(CdcParams::default().avg_size) >= SHARED_MASK_MIN_BITS);
        assert!(shared(256) < SHARED_MASK_MIN_BITS);
        // A hash that satisfies either mask is zero on the shared bits, for
        // every average a validated profile can name.
        for avg_size in CdcParams::AVG_SIZE_RANGE.step_by(251) {
            let masks = limited(avg_size);
            let shared = masks.s & masks.l;
            assert_eq!(shared & !masks.s, 0);
            assert_eq!(shared & !masks.l, 0);
        }
    }

    #[test]
    fn laned_phase_one_finds_exactly_what_one_chain_finds() {
        let (gear, _) = get_gear_with_seed(0);
        let whole = |buf: &[u8], masks: &Masks| {
            candidates(buf, &gear, masks).expect("no limit, so never dense")
        };
        // Every short length: a buffer smaller than a segment is one chain.
        for avg in [256, 8192, 65_536, 1 << 20] {
            let masks = unlimited(avg);
            for buf in [
                dense(700, u64::from(avg)),
                crowded(1500, u64::from(avg), &gear, &masks),
            ] {
                for n in 0..buf.len() {
                    assert_eq!(
                        whole(&buf[..n], &masks),
                        one_chain(&buf[..n], &gear, &masks),
                        "avg {avg} len {n}"
                    );
                }
            }
        }
        // Around the segment size, where the last segment is a few bytes
        // long, and across several segments.
        let big = dense((3 << 20) + 9, 0xD1CE);
        let packed = crowded((2 << 20) + 300, 0xFACE, &gear, &unlimited(65_536));
        let zeros = vec![0u8; (2 << 20) + 5];
        let ones = vec![0xFFu8; (1 << 20) + 3];
        let lengths = [
            LANE - 1,
            LANE,
            LANE + 1,
            2 * LANE + 5,
            3 * LANE + 1,
            SEGMENT - 5,
            SEGMENT - 1,
            SEGMENT,
            SEGMENT + 1,
            SEGMENT + 2,
            SEGMENT + 3,
            SEGMENT + 4,
            SEGMENT + 67,
            2 * SEGMENT,
            2 * SEGMENT + 255,
            big.len(),
        ];
        for avg in [256, 4096, 65_536, 524_288, 4 << 20] {
            let masks = unlimited(avg);
            for n in lengths {
                assert_eq!(
                    whole(&big[..n], &masks),
                    one_chain(&big[..n], &gear, &masks),
                    "avg {avg} len {n}"
                );
            }
            for buf in [&zeros, &ones, &packed] {
                assert_eq!(
                    whole(buf, &masks),
                    one_chain(buf, &gear, &masks),
                    "avg {avg} whole buffer"
                );
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// Arbitrary bytes folded into an alphabet of arbitrary size: with
        /// few distinct bytes the hash repeats and the masks are satisfied
        /// often, with many it is noise. Any length, any valid average.
        #[test]
        fn laned_phase_one_agrees_with_one_chain_on_arbitrary_bytes(
            raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..6000),
            alphabet in 1u8..=255,
            avg_bits in 8u32..=22,
        ) {
            let (gear, _) = get_gear_with_seed(0);
            let data: Vec<u8> = raw.iter().map(|b| b % alphabet).collect();
            let masks = unlimited(1 << avg_bits);
            proptest::prop_assert_eq!(
                candidates(&data, &gear, &masks),
                Some(one_chain(&data, &gear, &masks))
            );
            // The same length again, crowded with candidates for these masks.
            let packed = crowded(data.len(), u64::from(alphabet), &gear, &masks);
            proptest::prop_assert_eq!(
                candidates(&packed, &gear, &masks),
                Some(one_chain(&packed, &gear, &masks))
            );
        }

        /// With the limits production uses, on the same kinds of input: the
        /// boundaries are the serial scanner's whichever way they are found.
        #[test]
        fn boundaries_match_serial_on_arbitrary_bytes_dense_or_not(
            raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..20_000),
            alphabet in 1u8..=255,
            avg_bits in 8u32..=14,
        ) {
            let (gear, _) = get_gear_with_seed(0);
            let avg_size = 1u32 << avg_bits;
            let p = CdcParams { min_size: avg_size / 4, avg_size, max_size: avg_size * 4 };
            let data: Vec<u8> = raw.iter().map(|b| b % alphabet).collect();
            proptest::prop_assert_eq!(chunk_ranges(&data, p).unwrap(), serial(&data, p));
            let packed = crowded(data.len(), u64::from(alphabet), &gear, &limited(avg_size));
            proptest::prop_assert_eq!(chunk_ranges(&packed, p).unwrap(), serial(&packed, p));
        }
    }

    #[test]
    fn laned_phase_one_is_ascending_and_inside_the_buffer() {
        let (gear, _) = get_gear_with_seed(0);
        for avg in [256, 65_536] {
            let masks = unlimited(avg);
            let buf = crowded((2 << 20) + 77, 0xA5A5, &gear, &masks);
            let found = candidates(&buf, &gear, &masks).expect("no limit, so never dense");
            for list in [&found.s, &found.l] {
                assert!(list.windows(2).all(|w| w[0] < w[1]), "avg {avg}");
                assert!(list.last().is_none_or(|&p| p < buf.len()), "avg {avg}");
            }
            // The data is only a test of the scan if it is crowded.
            assert!(found.l.len() > buf.len() / 1000, "avg {avg}");
        }
    }

    #[test]
    fn ordinary_input_is_never_treated_as_dense() {
        // The limit is sixteen times what unstructured bytes produce; noise
        // must stay clear of it for every profile, small averages included,
        // where candidates are thousands per MiB.
        let (gear, _) = get_gear_with_seed(0);
        for avg in [256, 512, 1024, 8192, 65_536, 1 << 20, 4 << 20] {
            let masks = limited(avg);
            for seed in 0..3 {
                let buf = noise((2 << 20) + 13, 0xBEEF + seed);
                let found = candidates(&buf, &gear, &masks);
                assert_eq!(
                    found,
                    Some(one_chain(&buf, &gear, &masks)),
                    "avg {avg} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn input_built_to_fill_the_lists_is_cut_directly_with_the_same_boundaries() {
        let (gear, _) = get_gear_with_seed(0);
        let p = CdcParams::default();
        let masks = limited(p.avg_size);
        let pattern = exhausting_pattern(&gear, &masks);
        let n = (3 << 20) + 11;
        let crafted: Vec<u8> = pattern.iter().copied().cycle().take(n).collect();
        // Half a million candidates per MiB, where noise has a few dozen.
        let unbounded = one_chain(&crafted, &gear, &masks);
        assert!(unbounded.s.len().max(unbounded.l.len()) > n / 3);
        assert_eq!(candidates(&crafted, &gear, &masks), None);
        assert_eq!(chunk_ranges(&crafted, p).unwrap(), serial(&crafted, p));

        // One such stretch inside an ordinary file is enough.
        let mut mixed = noise(n, 3);
        mixed[SEGMENT + 5000..SEGMENT + 300_000].copy_from_slice(&crafted[..295_000]);
        assert_eq!(candidates(&mixed, &gear, &masks), None);
        assert_eq!(chunk_ranges(&mixed, p).unwrap(), serial(&mixed, p));

        // Every profile, on input crowded for its own masks: dense or not,
        // the boundaries are the serial scanner's.
        for p in [
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
            p,
            CdcParams {
                min_size: 65_536,
                avg_size: 1 << 20,
                max_size: 4 << 20,
            },
        ] {
            let masks = limited(p.avg_size);
            let buf = crowded((2 << 20) + 9, u64::from(p.avg_size), &gear, &masks);
            if let Some(found) = candidates(&buf, &gear, &masks) {
                assert_eq!(found, one_chain(&buf, &gear, &masks), "{p:?}");
            }
            assert_eq!(chunk_ranges(&buf, p).unwrap(), serial(&buf, p), "{p:?}");
        }
    }

    /// The chunks as found with no candidate lists at all.
    fn direct(buffer: &[u8], p: CdcParams) -> Vec<(usize, usize)> {
        let (gear, _) = get_gear_with_seed(0);
        let masks = level1_masks(p.avg_size).expect("valid average has masks");
        walk(buffer, p, masks, &gear, None).expect("validated profile")
    }

    #[test]
    fn cutting_directly_is_identical_to_serial() {
        // The path dense input takes, on its own, over the same ground the
        // candidate path is held to: every length near the chunk size (the
        // last position a chunk may be cut at, the odd final chunk), the
        // profiles, and the pathological buffers.
        let small = CdcParams {
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };
        for seed in 0..6u64 {
            let buf = noise(2048, 0xD1EC_7000 + seed);
            for n in 0..2048 {
                assert_eq!(
                    direct(&buf[..n], small),
                    serial(&buf[..n], small),
                    "seed {seed} len {n}"
                );
            }
        }
        let mut runs = noise(3 << 20, 7);
        for (i, b) in runs.iter_mut().enumerate() {
            if (i / 5000) % 3 == 0 {
                *b = 0xAA;
            }
        }
        let zeros = vec![0u8; (1 << 20) + 17];
        for p in [
            small,
            CdcParams {
                min_size: 2048,
                avg_size: 8192,
                max_size: 32_768,
            },
            CdcParams::default(),
            CdcParams {
                min_size: 65_536,
                avg_size: 524_288,
                max_size: 2_097_152,
            },
        ] {
            for buf in [&noise((5 << 20) + 3, 42), &runs, &zeros] {
                assert_eq!(direct(buf, p), serial(buf, p), "{p:?}");
            }
        }
    }

    #[test]
    fn one_dense_lane_makes_its_segment_dense() {
        // Three lanes with nothing to record and one that fills its list:
        // the segment holds exactly as many positions as it is allowed, so
        // only the lane's own report says some were dropped. Treating these
        // lists as complete would move a chunk boundary.
        let (gear, _) = get_gear_with_seed(0);
        let p = CdcParams::default();
        let masks = limited(p.avg_size);
        let pattern = exhausting_pattern(&gear, &masks);
        let quiet = (0..=u8::MAX)
            .find(|&b| {
                let flat = vec![b; SEGMENT];
                let found = one_chain(&flat, &gear, &masks);
                found.s.is_empty() && found.l.is_empty()
            })
            .expect("some repeated byte satisfies neither mask");
        let mut segment = vec![quiet; SEGMENT];
        for (i, b) in segment[3 * LANE..].iter_mut().enumerate() {
            *b = pattern[i % 2];
        }
        let shared = masks.s & masks.l;
        let found = segment_candidates(&segment, (0, SEGMENT), &gear, &masks, |h| h & shared == 0);
        assert!(found.dense, "a lane dropped positions");
        assert!(
            found.s.len() <= masks.limit_s && found.l.len() <= masks.limit_l,
            "the lists alone are within the limit, so only the flag can tell"
        );
        assert_eq!(candidates(&segment, &gear, &masks), None);
        assert_eq!(chunk_ranges(&segment, p).unwrap(), serial(&segment, p));
    }

    #[test]
    fn a_segment_records_no_more_than_its_limit_allows() {
        // The memory bound itself: however many positions satisfy a mask, a
        // segment keeps at most the limit per lane and says it is dense.
        let (gear, _) = get_gear_with_seed(0);
        let masks = limited(CdcParams::default().avg_size);
        let pattern = exhausting_pattern(&gear, &masks);
        let crafted: Vec<u8> = pattern.iter().copied().cycle().take(SEGMENT).collect();
        let shared = masks.s & masks.l;
        let found = segment_candidates(&crafted, (0, SEGMENT), &gear, &masks, |h| h & shared == 0);
        assert!(found.dense);
        assert!(found.s.len() <= LANES * masks.limit_s);
        assert!(found.l.len() <= LANES * masks.limit_l);
        // For the default profile that is kilobytes for a megabyte of input.
        let bytes = (found.s.capacity() + found.l.capacity()) * size_of::<usize>();
        assert!(bytes < SEGMENT / 8, "{bytes} bytes of candidates");
        // The limits scale with what the mask produces on ordinary bytes.
        assert_eq!(dense_limit(0x7f), 16 * (LANE >> 7));
        assert_eq!(dense_limit(u64::MAX >> 16), 256);
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
            assert_eq!(
                chunk_ranges(&buf, p).unwrap(),
                serial(&buf, p),
                "length {n}"
            );
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
                    chunk_ranges(&buf[..n], p).unwrap(),
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
                assert_eq!(chunk_ranges(&buf, p).unwrap(), serial(&buf, p), "{p:?}");
            }
        }
    }
}
