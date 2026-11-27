//! Format-aware chunking v2: which structural candidates become chunk cuts.
//!
//! A container walker yields candidate cut positions `c_0 < c_1 < ...` (record,
//! box, local-file-header or keyframe starts). Unit `i` is `[c_i, c_{i+1})`; the
//! last unit ends at the end of the input. `L_i` is its length.
//!
//! **v1** kept every candidate, then dropped any closer than `min_size` to the
//! previously accepted cut. Where candidates are denser than `min_size` that is
//! a chain anchored only on the previous cut, i.e. fixed-size chunking at record
//! granularity: one inserted record shifts every later chunk. A 64 MiB log of
//! 32-byte records re-sent 100% of itself after a one-record insertion, where
//! plain `FastCDC` re-sent 0.1%.
//!
//! **v2** decides every candidate from local facts, then applies v1's absorption
//! unchanged:
//!
//! * **Structural** -- `max(L_{i-1}, L_i) >= min_size`: kept. Absorption only
//!   chains through gaps shorter than `min_size`, so wherever every unit is at
//!   least `min_size` long v2 is exactly v1 (sparse containers chunk as before).
//! * **Dense** -- both neighbouring units shorter than `min_size`. With
//!   `fp_i = unit_fingerprint(unit i)`, the candidate *survives* iff
//!   `fp_i * avg_size < L_i * 16 * 2^64` (exact `u128`; about 16 survivors per
//!   `avg_size` bytes), and is kept iff it survives and `fp_i` is strictly
//!   greater than the fingerprint of every other surviving dense candidate less
//!   than `h = max(avg_size / 2, min_size)` bytes away: local-maximum
//!   content-defined chunking over the thinned candidates. Structural
//!   candidates are kept anyway and do not compete.
//!
//! What this buys (derivations in ADR-0014's v2 amendment):
//!
//! 1. Two kept dense cuts are at least `h >= min_size` apart, so absorption can
//!    never chain inside a dense run; it converges at every kept dense cut.
//! 2. An insertion, deletion or edit at byte `p` can change decisions only for
//!    candidates within `h` of `p` (plus the structural class of the two units
//!    beside it); everything farther away chunks identically.
//! 3. Ties keep nothing: a run whose candidates all fingerprint alike (identical
//!    heads and lengths) gets no dense cut and falls back to plain `FastCDC`,
//!    which resynchronises on content. (A probability-per-candidate rule keeps
//!    either none or all of such candidates, and "all" is the v1 chain again.)
//! 4. In a uniform dense run a candidate is a local maximum with probability
//!    about `r / 2h` for unit length `r`, so kept cuts are about `2h = avg_size`
//!    apart, whatever the record size.
//!
//! Streaming: `L_i` needs one candidate of lookahead, and a decision needs every
//! candidate within `h` on both sides. The selector keeps only a monotonic
//! deque of dense candidates within the last `h` bytes (at most `h / 4 + 1`;
//! record starts are at least 4 bytes apart in every walker) and the structural
//! cuts waiting behind them, and does O(1) amortised work per candidate. The
//! in-memory and seekable scanners feed it the same candidates and head bytes,
//! which is what makes their cuts identical.

use std::collections::VecDeque;

use crate::cdc::CdcParams;

/// Bytes at the start of a unit that its fingerprint covers.
pub(crate) const HEAD_BYTES: usize = 32;

const SECRET: [u64; 4] = [
    0xa076_1d64_78bd_642f,
    0xe703_7ed1_a0b4_28db,
    0x8ebc_6af0_9c88_c6e3,
    0x5899_65cc_7537_4cc3,
];

/// The 128-bit product of `a` and `b`, folded to 64 bits (wyhash's `mum`).
#[allow(clippy::cast_possible_truncation)] // deliberate: the low and high halves of the product
fn mum(a: u64, b: u64) -> u64 {
    let product = u128::from(a) * u128::from(b);
    (product as u64) ^ ((product >> 64) as u64)
}

/// Fingerprint of the unit `[c, c + unit_len)` given its first bytes: a fixed
/// 64-bit mix of the first `min(HEAD_BYTES, unit_len)` bytes and `unit_len`.
///
/// A pure function of the unit's own bytes: not of its position, the file, or
/// any other unit. `head` must hold at least `min(HEAD_BYTES, unit_len)` bytes;
/// any bytes beyond that are ignored. The byte-level statement of
/// [`fingerprint_words`], which the selector computes; tests and the rule
/// comparison use this form.
#[cfg(test)]
pub(crate) fn unit_fingerprint(head: &[u8], unit_len: usize) -> u64 {
    let head = &head[..head.len().min(HEAD_BYTES)];
    fingerprint_words(head_words(head), head.len(), unit_len)
}

/// The first `HEAD_BYTES` bytes of `head` as little-endian words, zero-padded.
#[inline]
fn head_words(head: &[u8]) -> [u64; 4] {
    let mut words = [0u64; 4];
    if let Ok(full) = <&[u8; HEAD_BYTES]>::try_from(head) {
        // The common case, without per-word length handling.
        for (word, bytes) in words.iter_mut().zip(full.chunks_exact(8)) {
            *word = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
        }
    } else {
        for (word, bytes) in words.iter_mut().zip(head.chunks(8)) {
            let mut le = [0u8; 8];
            le[..bytes.len()].copy_from_slice(bytes);
            *word = u64::from_le_bytes(le);
        }
    }
    words
}

/// The unit fingerprint from [`head_words`] of the `head_len` bytes available
/// at the unit's start: only the first `min(HEAD_BYTES, unit_len)` of them
/// enter the mix, with `unit_len`. Part of the v2 chunk-boundary definition:
/// changing it changes format-aware boundaries (see the pinned vectors in
/// `tests/dense_resync.rs`).
#[inline]
fn fingerprint_words(mut words: [u64; 4], head_len: usize, unit_len: usize) -> u64 {
    let used = head_len.min(unit_len);
    if used < HEAD_BYTES {
        for (i, word) in words.iter_mut().enumerate() {
            // Bytes of this word that belong to the unit: 0..=8.
            let keep = used.saturating_sub(8 * i).min(8);
            *word &= if keep == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * keep)) - 1
            };
        }
    }
    let unit_len = u64::try_from(unit_len).unwrap_or(u64::MAX);
    let a = mum(words[0] ^ SECRET[0], words[1] ^ SECRET[1]);
    let b = mum(words[2] ^ SECRET[2], words[3] ^ SECRET[3]);
    mum(a ^ unit_len ^ SECRET[1], b ^ SECRET[0])
}

/// The local-maximum horizon `h = max(avg_size / 2, min_size)`.
pub(crate) fn horizon(params: CdcParams) -> usize {
    (params.avg_size as usize / 2).max(params.min_size as usize)
}

/// Expected dense survivors per `avg_size` bytes. Thinning by this rate before
/// the local maximum leaves about `SURVIVORS_PER_AVG` survivors in each `2h`
/// window, enough that the maximum lands about `avg_size` apart, while only
/// `SURVIVORS_PER_AVG * L / avg_size` of the candidates (0.8% for 32-byte
/// records under the default profile) reach the branchy monotonic deque.
pub(crate) const SURVIVORS_PER_AVG: u64 = 16;

/// Whether a dense unit of `unit_len` bytes with fingerprint `fp` survives the
/// thinning: `fp * avg_size < unit_len * rate * 2^64`, exactly. A probability
/// proportional to the unit's length keeps the survivor density per byte the
/// same whatever the record sizes.
fn survives(fp: u64, unit_len: usize, avg_size: u64, rate: u64) -> bool {
    let weight = u64::try_from(unit_len)
        .unwrap_or(u64::MAX)
        .saturating_mul(rate);
    if weight >= avg_size {
        return true;
    }
    // weight < avg_size <= 2^22, so the shift cannot overflow.
    u128::from(fp) * u128::from(avg_size) < u128::from(weight) << 64
}

/// A finalised dense candidate whose decision may still change.
#[derive(Debug, Clone, Copy)]
struct Dense {
    pos: usize,
    fp: u64,
    /// An earlier dense candidate within the horizon has a fingerprint at
    /// least as large.
    dominated: bool,
}

/// The latest offered candidate, whose unit length is not yet known.
#[derive(Debug, Clone, Copy)]
struct Pending {
    pos: usize,
    before: usize,
    /// [`head_words`] of the bytes offered with it.
    words: [u64; 4],
    head_len: usize,
}

/// Online v2 cut selection with absorption. Offer candidates in increasing
/// position order, call [`CutSelector::finish`] after the last, and drain the
/// accepted cuts with [`CutSelector::pop_accepted`] at any point; they come out
/// in increasing order, each at least `min_size` after the previous (and after
/// 0) and at most `len - min_size`.
///
/// The monotonic deque `maxima` is the whole decision structure: it holds the
/// dense candidates that could still be kept, plus left-dominated ones that can
/// still dominate later arrivals, with strictly decreasing fingerprints. An
/// entry popped from the back is dominated by a newer candidate within the
/// horizon and is dropped; an entry leaving the front has seen its whole
/// horizon on both sides and is final. Structural candidates are final on
/// arrival and wait in `held` only until every earlier dense one is decided.
#[derive(Debug)]
pub(crate) struct CutSelector {
    len: usize,
    min: usize,
    avg: u64,
    horizon: usize,
    /// [`SURVIVORS_PER_AVG`]; `u64::MAX` (every dense candidate survives) is
    /// the unthinned rule, used only to measure what the thinning changes.
    survivor_rate: u64,
    /// Position of the latest offered candidate (meaningful once `offered`).
    previous: usize,
    offered: bool,
    /// The latest offered candidate (`offered` says whether there is one).
    pending: Pending,
    maxima: VecDeque<Dense>,
    /// Structural cuts, ascending, waiting for earlier dense decisions.
    held: VecDeque<usize>,
    last_accepted: usize,
    accepted: VecDeque<usize>,
}

impl CutSelector {
    /// A selector for an input of `len` bytes chunked with `params`.
    pub(crate) fn new(len: usize, params: CdcParams) -> Self {
        Self {
            len,
            min: params.min_size as usize,
            avg: u64::from(params.avg_size),
            horizon: horizon(params),
            survivor_rate: SURVIVORS_PER_AVG,
            previous: 0,
            offered: false,
            pending: Pending {
                pos: 0,
                before: 0,
                words: [0; 4],
                head_len: 0,
            },
            maxima: VecDeque::new(),
            held: VecDeque::new(),
            last_accepted: 0,
            accepted: VecDeque::new(),
        }
    }

    /// Offer the candidate at `pos` with the bytes available there (the first
    /// `min(HEAD_BYTES, len - pos)` of them suffice). A position not after the
    /// previous candidate, or not inside the input, is ignored: the walkers
    /// never produce one, and accepting it would break the unit lengths.
    #[inline]
    pub(crate) fn offer(&mut self, pos: usize, head: &[u8]) {
        if pos >= self.len || (self.offered && pos <= self.previous) {
            return;
        }
        if self.offered {
            let pending = self.pending;
            self.finalise(&pending, pos - pending.pos);
        }
        let head = &head[..head.len().min(HEAD_BYTES)];
        self.pending = Pending {
            pos,
            before: pos - if self.offered { self.previous } else { 0 },
            words: head_words(head),
            head_len: head.len(),
        };
        self.previous = pos;
        self.offered = true;
    }

    /// No more candidates: the last unit runs to the end of the input, and
    /// every remaining decision is final.
    pub(crate) fn finish(&mut self) {
        if self.offered {
            let pending = self.pending;
            self.finalise(&pending, self.len - pending.pos);
            self.offered = false;
            // A later offer must still be after this candidate.
            self.previous = self.len;
        }
        while let Some(front) = self.maxima.front().copied() {
            self.emit_dense(front);
        }
        while let Some(cut) = self.held.pop_front() {
            self.absorb(cut);
        }
    }

    /// The next accepted cut, if one has been decided.
    pub(crate) fn pop_accepted(&mut self) -> Option<usize> {
        self.accepted.pop_front()
    }

    /// The same selector with a different thinning rate (`u64::MAX`: none).
    #[cfg(test)]
    fn with_survivor_rate(mut self, rate: u64) -> Self {
        self.survivor_rate = rate;
        self
    }

    #[inline]
    fn finalise(&mut self, pending: &Pending, unit_len: usize) {
        // Dense candidates a horizon or more to the left have seen their whole
        // horizon: every candidate before this one is finalised.
        while let Some(front) = self.maxima.front().copied() {
            if pending.pos - front.pos < self.horizon {
                break;
            }
            self.emit_dense(front);
        }
        if pending.before.max(unit_len) >= self.min {
            self.held.push_back(pending.pos);
        } else {
            let fp = fingerprint_words(pending.words, pending.head_len, unit_len);
            if survives(fp, unit_len, self.avg, self.survivor_rate) {
                let mut dominated = false;
                while let Some(back) = self.maxima.back() {
                    if back.fp > fp {
                        dominated = true;
                        break;
                    }
                    // Within the horizon and no larger than this one: never kept.
                    dominated |= back.fp == fp;
                    self.maxima.pop_back();
                }
                self.maxima.push_back(Dense {
                    pos: pending.pos,
                    fp,
                    dominated,
                });
            }
        }
        if !self.held.is_empty() {
            self.release_held();
        }
    }

    /// Decide the oldest dense candidate (`front`, already final), emitting
    /// any structural cut before it first.
    fn emit_dense(&mut self, front: Dense) {
        while let Some(&cut) = self.held.front() {
            if cut > front.pos {
                break;
            }
            self.held.pop_front();
            self.absorb(cut);
        }
        self.maxima.pop_front();
        if !front.dominated {
            self.absorb(front.pos);
        }
    }

    /// Emit the structural cuts that no undecided dense candidate precedes.
    fn release_held(&mut self) {
        let oldest_undecided = self.maxima.front().map_or(usize::MAX, |d| d.pos);
        while let Some(&cut) = self.held.front() {
            if cut > oldest_undecided {
                break;
            }
            self.held.pop_front();
            self.absorb(cut);
        }
    }

    /// v1's absorption: keep a cut at least `min_size` after the previous
    /// accepted one (or the start) that leaves at least `min_size` after it.
    fn absorb(&mut self, cut: usize) {
        if cut >= self.last_accepted.saturating_add(self.min)
            && cut <= self.len.saturating_sub(self.min)
        {
            self.accepted.push_back(cut);
            self.last_accepted = cut;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: CdcParams = CdcParams {
        min_size: 64,
        avg_size: 256,
        max_size: 1024,
    };

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
    }

    fn select(len: usize, params: CdcParams, cands: &[(usize, Vec<u8>)]) -> Vec<usize> {
        let mut selector = CutSelector::new(len, params);
        let mut out = Vec::new();
        for (pos, head) in cands {
            selector.offer(*pos, head);
            while let Some(cut) = selector.pop_accepted() {
                out.push(cut);
            }
        }
        selector.finish();
        while let Some(cut) = selector.pop_accepted() {
            out.push(cut);
        }
        out
    }

    /// The rule as stated, in O(n^2), with no streaming state.
    fn brute_force(len: usize, params: CdcParams, cands: &[(usize, Vec<u8>)]) -> Vec<usize> {
        let (min, h) = (params.min_size as usize, horizon(params));
        let ends: Vec<usize> = cands.iter().skip(1).map(|c| c.0).chain([len]).collect();
        let fps: Vec<u64> = cands
            .iter()
            .zip(&ends)
            .map(|((pos, head), end)| unit_fingerprint(head, end - pos))
            .collect();
        let structural: Vec<bool> = cands
            .iter()
            .enumerate()
            .map(|(i, (pos, _))| {
                let before = pos - if i == 0 { 0 } else { cands[i - 1].0 };
                before.max(ends[i] - pos) >= min
            })
            .collect();
        let survivor: Vec<bool> = (0..cands.len())
            .map(|i| {
                // fp * avg < L * rate * 2^64, the rule as stated.
                let unit_len = u128::from(u64::try_from(ends[i] - cands[i].0).unwrap());
                !structural[i]
                    && u128::from(fps[i]) * u128::from(params.avg_size)
                        < unit_len * u128::from(SURVIVORS_PER_AVG) * (1u128 << 64)
            })
            .collect();
        let mut out = Vec::new();
        let mut last = 0;
        for (i, (pos, _)) in cands.iter().enumerate() {
            let local_max = survivor[i]
                && cands.iter().enumerate().all(|(j, (other, _))| {
                    j == i || !survivor[j] || other.abs_diff(*pos) >= h || fps[j] < fps[i]
                });
            if (structural[i] || local_max) && *pos >= last + min && *pos + min <= len {
                out.push(*pos);
                last = *pos;
            }
        }
        out
    }

    #[test]
    fn the_fingerprint_is_a_pure_function_of_the_units_own_bytes() {
        let mut rng = Rng(1);
        let unit: Vec<u8> = (0..100).map(|_| rng.next().to_le_bytes()[0]).collect();
        let fp = unit_fingerprint(&unit, unit.len());
        // Anywhere in any input, and whatever follows the head.
        for (prefix, suffix) in [(0, 0), (1, 7), (4096, 33)] {
            let mut buf = vec![0xEE; prefix];
            buf.extend_from_slice(&unit);
            buf.extend(std::iter::repeat_n(0x11, suffix));
            assert_eq!(unit_fingerprint(&buf[prefix..], unit.len()), fp);
        }
        let mut tail_edit = unit.clone();
        tail_edit[HEAD_BYTES + 5] ^= 1;
        assert_eq!(
            unit_fingerprint(&tail_edit, unit.len()),
            fp,
            "bytes past the head"
        );
        // Every head byte and the length are covered.
        for i in 0..HEAD_BYTES {
            let mut edit = unit.clone();
            edit[i] ^= 0x80;
            assert_ne!(unit_fingerprint(&edit, unit.len()), fp, "head byte {i}");
        }
        assert_ne!(unit_fingerprint(&unit, unit.len() + 1), fp);
        // A unit shorter than the head covers only its own bytes.
        let short = &unit[..9];
        assert_eq!(unit_fingerprint(short, 9), unit_fingerprint(&unit, 9));
    }

    #[test]
    fn the_streaming_selector_equals_the_rule_stated_in_quadratic_form() {
        // Random candidate sets mixing dense runs, structural edges, repeated
        // heads (ties) and lengths: the deque must agree with brute force.
        let mut rng = Rng(0x005E_1EC7);
        for case in 0..400 {
            let mut cands = Vec::new();
            let mut pos = rng.below(100);
            let tie_head = vec![0xAB; HEAD_BYTES];
            for _ in 0..rng.below(120) {
                let head = if rng.below(4) == 0 {
                    tie_head.clone()
                } else {
                    (0..HEAD_BYTES)
                        .map(|_| rng.next().to_le_bytes()[0])
                        .collect()
                };
                cands.push((pos, head));
                pos += match rng.below(10) {
                    0 => 64 + rng.below(400),
                    1 => 8,
                    _ => 4 + rng.below(40),
                };
            }
            let len = pos + rng.below(200);
            assert_eq!(
                select(len, P, &cands),
                brute_force(len, P, &cands),
                "case {case}"
            );
        }
    }

    #[test]
    fn kept_dense_cuts_are_at_least_the_horizon_apart() {
        // 20-byte units, far below min_size: every candidate is dense.
        let mut rng = Rng(9);
        let cands: Vec<(usize, Vec<u8>)> = (0..20_000)
            .map(|i| (i * 20, rng.next().to_le_bytes().to_vec()))
            .collect();
        let cuts = select(400_000, P, &cands);
        assert!(cuts.len() > 1000, "{}", cuts.len());
        assert!(cuts.windows(2).all(|w| w[1] - w[0] >= horizon(P)));
        // About one cut per 2h = avg_size bytes.
        let mean = (cuts[cuts.len() - 1] - cuts[0]) / (cuts.len() - 1);
        assert!((200..320).contains(&mean), "mean spacing {mean}");
    }

    #[test]
    fn candidates_that_all_fingerprint_alike_keep_no_dense_cut() {
        let cands: Vec<(usize, Vec<u8>)> = (0..5_000).map(|i| (i * 20, vec![7; 20])).collect();
        assert_eq!(select(100_000, P, &cands), Vec::<usize>::new());
    }

    #[test]
    fn units_of_at_least_min_size_keep_every_cut_as_v1_did() {
        let mut rng = Rng(3);
        let mut cands = Vec::new();
        let mut pos = 0;
        for _ in 0..500 {
            cands.push((pos, vec![0; 4]));
            pos += 64 + rng.below(2000);
        }
        let expected: Vec<usize> = cands
            .iter()
            .map(|c| c.0)
            .filter(|&c| c >= 64 && c + 64 <= pos)
            .collect();
        assert_eq!(select(pos, P, &cands), expected);
    }

    #[test]
    fn out_of_order_and_out_of_range_offers_are_ignored() {
        let mut selector = CutSelector::new(1000, P);
        for pos in [100, 100, 50, 300, 1000, 5000, 700] {
            selector.offer(pos, &[1; HEAD_BYTES]);
        }
        selector.finish();
        let mut cuts = Vec::new();
        while let Some(cut) = selector.pop_accepted() {
            cuts.push(cut);
        }
        assert_eq!(cuts, vec![100, 300, 700]);
    }
}

#[cfg(test)]
mod rule_comparison;
