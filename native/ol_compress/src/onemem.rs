//! ONE Memory's chunk codec, native and batched.
//!
//! Byte-identical to the Python reference in `one_mind/one_storage/codec.py`
//! (`encode_chunk`, unencrypted, One Link codecs) and
//! `one_mind/one_storage/gridcodec.py`. Python is the specification and the
//! test oracle; this is the fast path. ONE Memory ingest measured its
//! per-chunk work holding the GIL (8 threads ran at 0.3-0.8x of one), so a
//! window of chunks is hashed and encoded here, in parallel, with the
//! interpreter detached.
//!
//! Every decision is integer-exact or IEEE-exact (f32 -> f64 -> round half to
//! even -> f64 division -> f32), so both implementations choose the same grid,
//! phase and stride and emit the same bytes.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)] // Byte-format code: every cast below is range-checked or bit-reinterpreting by design.

use crate::dispatcher::{Algorithm, Dispatcher, MAX_DECOMPRESSED_BYTES};
use crate::error::CompressError;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const MAGIC_V2: &[u8; 5] = b"ONES2";
const FLAG_COMPRESSED: u8 = 0x01;
const CODEC_NONE: u8 = 0;
const CODEC_LZ4: u8 = 2;
const CODEC_ZSTD_BALANCED: u8 = 3;
const CODEC_ZSTD_AGGRESSIVE: u8 = 4;
const CODEC_GRID_ZSTD: u8 = 5;
const CODEC_GRID_LZ4: u8 = 7;
const CODEC_GRID_RC: u8 = 8;

const GRID_MAGIC: &[u8; 4] = b"GRD1";
const GRID_RC_MAGIC: &[u8; 4] = b"GRR1";
const GRID_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 4 + 1 + 4 + 4 + 4;
const DECIMAL: u8 = 0;
const BINARY: u8 = 1;
const MAX_LANES: usize = 32;
const MIN_VALUES: usize = 256;
const SAMPLE: usize = 512;
const Q_LIMIT: f64 = (1u64 << 30) as f64;
const DECIMAL_SCALES: [f64; 7] = [1.0, 10.0, 100.0, 1e3, 1e4, 1e5, 1e6];

/// What the caller asked for; mirrors `encode_chunk(compression_algorithm=...)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Grid codec, else lz4-sampled zstd/lz4/none (base station).
    Auto,
    /// Grid codec with lz4 inside, else lz4/none (robot hot path).
    AutoFast,
    /// Grid codec with the range-coded residual model, else zstd level 9
    /// (base station / cold tier: maximum compression; native only).
    AutoArchive,
    /// Never compress.
    None,
    /// lz4 if it saves 5%.
    Lz4,
    /// zstd level 3 if it saves 5%.
    ZstdBalanced,
    /// zstd level 9 if it saves 5%.
    ZstdAggressive,
}

impl Mode {
    /// Parse the Python algorithm name; `None` for names this path does not run
    /// (zlib), which stay on the Python path.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "auto_fast" => Some(Self::AutoFast),
            "auto_archive" => Some(Self::AutoArchive),
            "none" => Some(Self::None),
            "lz4" => Some(Self::Lz4),
            "zstd_balanced" => Some(Self::ZstdBalanced),
            "zstd_aggressive" => Some(Self::ZstdAggressive),
            _ => None,
        }
    }
}

/// SHA-256 of one chunk.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of many chunks, in parallel.
#[must_use]
pub fn sha256_many(chunks: &[&[u8]]) -> Vec<[u8; 32]> {
    chunks.par_iter().map(|c| sha256(c)).collect()
}

/// Encode many chunks in parallel; result `i` is chunk `i`'s V2 encoding.
#[must_use]
pub fn encode_many(
    chunks: &[&[u8]],
    mode: Mode,
    precompressed: bool,
    compress: bool,
) -> Vec<Result<Vec<u8>, CompressError>> {
    chunks
        .par_iter()
        .map(|c| encode_chunk(c, mode, precompressed, compress))
        .collect()
}

/// One chunk in ONE Memory's V2 format (unencrypted): `encode_chunk` in codec.py.
pub fn encode_chunk(
    plaintext: &[u8],
    mode: Mode,
    precompressed: bool,
    compress: bool,
) -> Result<Vec<u8>, CompressError> {
    let n = plaintext.len();
    let accept = |encoded_len: usize| encoded_len + 32 < (n as f64 * 0.95) as usize;
    if compress && matches!(mode, Mode::Auto | Mode::AutoFast | Mode::AutoArchive) && !precompressed
    {
        let (codec, inner) = match mode {
            Mode::AutoFast => (CODEC_GRID_LZ4, Inner::Codec(Algorithm::Lz4)),
            Mode::AutoArchive => (CODEC_GRID_RC, Inner::Rc),
            _ => (CODEC_GRID_ZSTD, Inner::Codec(Algorithm::ZstdBalanced)),
        };
        if let Some(plan) = grid_plan(plaintext) {
            let mut best = grid_encode(plaintext, plan, inner)?.map(|p| (codec, p));
            if mode == Mode::AutoArchive {
                // Neither coder dominates: the residual model wins 23% on real
                // KITTI, byte planes + LZ win on strictly periodic signals.
                // Archive mode keeps the smaller of the two.
                let planes = Inner::Codec(Algorithm::ZstdAggressive);
                if let Some(p) = grid_encode(plaintext, plan, planes)? {
                    if best.as_ref().is_none_or(|(_, b)| p.len() < b.len()) {
                        best = Some((CODEC_GRID_ZSTD, p));
                    }
                }
            }
            if let Some((codec, payload)) = best {
                if accept(payload.len()) {
                    return Ok(frame(codec, n, &payload));
                }
            }
        }
    }
    let selected = if compress {
        resolve_algorithm(plaintext, mode, precompressed)
    } else {
        None
    };
    if let Some((codec, algo)) = selected {
        if n >= 1024 {
            let candidate = Dispatcher::new().compress(algo, plaintext)?;
            if accept(candidate.len()) {
                return Ok(frame(codec, n, &candidate));
            }
        }
    }
    Ok(frame(CODEC_NONE, n, plaintext))
}

/// Decode one V2 chunk (unencrypted, One Link codecs) and verify its SHA-256.
///
/// `None` means "not this path": an encrypted chunk, a zlib codec, a
/// malformed header, a failed decode or a digest mismatch. The caller then
/// runs ONE Memory's Python decoder, which owns the error semantics (it
/// raises, and marks the chunk CORRUPT only for bytes that fail verification).
#[must_use]
pub fn decode_chunk(encoded: &[u8], expected: &[u8; 32]) -> Option<Vec<u8>> {
    if encoded.len() < 16 || &encoded[..5] != MAGIC_V2 {
        return None;
    }
    let flags = encoded[5];
    let codec = encoded[6];
    let plain_size = usize::try_from(u64::from_be_bytes(encoded[7..15].try_into().ok()?)).ok()?;
    if flags & !FLAG_COMPRESSED != 0 || encoded[15] != 0 {
        return None; // encrypted (or unknown flags): the Python path
    }
    if (flags & FLAG_COMPRESSED != 0) != (codec != CODEC_NONE) {
        return None;
    }
    let payload = &encoded[16..];
    let d = Dispatcher::new();
    let plain = match codec {
        CODEC_NONE => payload.to_vec(),
        CODEC_LZ4 | CODEC_ZSTD_BALANCED | CODEC_ZSTD_AGGRESSIVE => {
            d.decompress(payload, plain_size).ok()?
        }
        CODEC_GRID_ZSTD | CODEC_GRID_LZ4 | CODEC_GRID_RC => {
            grid_decode(payload, plain_size).ok()?
        }
        _ => return None, // zlib family: the Python path
    };
    if plain.len() != plain_size || sha256(&plain) != *expected {
        return None;
    }
    Some(plain)
}

/// [`decode_chunk`] over many chunks, in parallel.
#[must_use]
pub fn decode_many(chunks: &[&[u8]], expected: &[[u8; 32]]) -> Vec<Option<Vec<u8>>> {
    chunks
        .par_iter()
        .zip(expected.par_iter())
        .map(|(c, e)| decode_chunk(c, e))
        .collect()
}

fn frame(codec: u8, plain_size: usize, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(MAGIC_V2);
    out.push(if codec == CODEC_NONE {
        0
    } else {
        FLAG_COMPRESSED
    });
    out.push(codec);
    out.extend_from_slice(&(plain_size as u64).to_be_bytes());
    out.push(0); // nonce length: this path never encrypts
    out.extend_from_slice(payload);
    out
}

fn resolve_algorithm(plaintext: &[u8], mode: Mode, precompressed: bool) -> Option<(u8, Algorithm)> {
    match mode {
        Mode::None => None,
        Mode::Lz4 => Some((CODEC_LZ4, Algorithm::Lz4)),
        Mode::ZstdBalanced => Some((CODEC_ZSTD_BALANCED, Algorithm::ZstdBalanced)),
        Mode::ZstdAggressive => Some((CODEC_ZSTD_AGGRESSIVE, Algorithm::ZstdAggressive)),
        Mode::Auto | Mode::AutoFast | Mode::AutoArchive => {
            if precompressed || plaintext.len() < 1024 {
                return None;
            }
            let savings = sample_lz4_savings(plaintext);
            if savings < 0.05 {
                None
            } else if mode == Mode::AutoArchive {
                Some((CODEC_ZSTD_AGGRESSIVE, Algorithm::ZstdAggressive))
            } else if mode == Mode::AutoFast || savings >= 0.60 {
                Some((CODEC_LZ4, Algorithm::Lz4))
            } else {
                Some((CODEC_ZSTD_BALANCED, Algorithm::ZstdBalanced))
            }
        }
    }
}

fn sample_lz4_savings(plaintext: &[u8]) -> f64 {
    let n = plaintext.len();
    let parts: Vec<&[u8]> = if n <= 6144 {
        vec![plaintext]
    } else {
        let width = 2048;
        let middle = (n / 2).saturating_sub(width / 2);
        vec![
            &plaintext[..width],
            &plaintext[middle..middle + width],
            &plaintext[n - width..],
        ]
    };
    let raw: usize = parts.iter().map(|p| p.len()).sum();
    if raw == 0 {
        return 0.0;
    }
    let d = Dispatcher::new();
    let compressed: usize = parts
        .iter()
        .map(|p| {
            d.compress(Algorithm::Lz4, p)
                .map_or(p.len() + 5, |c| c.len())
        })
        .sum();
    1.0 - compressed as f64 / raw as f64
}

// ───── grid codec (gridcodec.py) ─────────────────────────────────────────

/// A detected grid: byte phase, record stride, scale kind and exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridPlan {
    /// Byte offset of the first float32 (0..=3).
    pub phase: usize,
    /// Record stride in values.
    pub lanes: usize,
    /// 0 = decimal (10^exp), 1 = binary (2^exp).
    pub kind: u8,
    /// Scale exponent.
    pub exp: i8,
}

impl GridPlan {
    fn scale(self) -> f64 {
        scale_value(self.kind, self.exp)
    }
}

fn scale_value(kind: u8, exp: i8) -> f64 {
    if kind == DECIMAL {
        DECIMAL_SCALES[exp as usize]
    } else {
        (1u64 << exp) as f64
    }
}

fn word_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn floats(data: &[u8], phase: usize, count: usize) -> Vec<f32> {
    let n = ((data.len() - phase) / 4).min(count);
    (0..n)
        .map(|i| f32::from_bits(word_at(data, phase + 4 * i)))
        .collect()
}

fn screen_phase(data: &[u8], phase: usize) -> bool {
    let words = (data.len() - phase) / 4;
    if words < 48 {
        return false;
    }
    let mut insane = 0;
    for first in [0, words / 2 - 8, words - 16] {
        for i in 0..16 {
            let word = word_at(data, phase + 4 * (first + i));
            let exponent = (word >> 23) & 0xFF;
            if (word & 0x7FFF_FFFF) != 0 && !(104..=150).contains(&exponent) {
                insane += 1;
                if insane > 4 {
                    return false;
                }
            }
        }
    }
    true
}

fn binary_scale_exp(finite: &[f32]) -> Option<i8> {
    let mut k_max: Option<i64> = None;
    for v in finite {
        let bits = v.to_bits() as i64;
        let exponent = (bits >> 23) & 0xFF;
        let mantissa = (bits & 0x7F_FFFF) | if exponent > 0 { 0x80_0000 } else { 0 };
        if mantissa == 0 {
            continue;
        }
        let tz = i64::from(mantissa.trailing_zeros());
        let k = 150 - exponent.max(1) - tz;
        k_max = Some(k_max.map_or(k, |m| m.max(k)));
    }
    match k_max {
        None => Some(0),
        Some(k) if k <= 20 => Some(k.max(0) as i8),
        Some(_) => None,
    }
}

fn on_grid(v: &[f32], scale: f64) -> (Vec<i64>, Vec<bool>) {
    let mut q = Vec::with_capacity(v.len());
    let mut exact = Vec::with_capacity(v.len());
    for &x in v {
        let r = (f64::from(x) * scale).round_ties_even();
        let qi = if r.is_finite() && r.abs() < Q_LIMIT {
            r as i64
        } else {
            0
        };
        let back = (qi as f64 / scale) as f32;
        q.push(qi);
        exact.push(back.to_bits() == x.to_bits());
    }
    (q, exact)
}

fn scale_for(sample: &[f32]) -> Option<(u8, i8)> {
    let n = sample.len();
    let finite: Vec<f32> = sample.iter().copied().filter(|x| x.is_finite()).collect();
    if (n - finite.len()) * 64 > n {
        return None;
    }
    let mut candidates: Vec<(u8, i8, f64)> = Vec::new();
    if let Some(b) = binary_scale_exp(&finite) {
        candidates.push((BINARY, b, scale_value(BINARY, b)));
    }
    for (k, &s) in DECIMAL_SCALES.iter().enumerate() {
        // Non-finite values are misses by definition (gridcodec._scale_for).
        let hits = sample
            .iter()
            .filter(|x| {
                x.is_finite()
                    && (((f64::from(**x) * s).round_ties_even() / s) as f32).to_bits()
                        == x.to_bits()
            })
            .count();
        if (n - hits) * 64 <= n {
            candidates.push((DECIMAL, k as i8, s));
            break;
        }
    }
    // min by scale, first wins on ties (binary is listed first, as in Python)
    let mut best: Option<(u8, i8, f64)> = None;
    for c in candidates {
        if best.is_none_or(|b| c.2 < b.2) {
            best = Some(c);
        }
    }
    best.map(|(kind, exp, _)| (kind, exp))
}

fn bitlen(x: i64) -> u64 {
    u64::from(64 - x.unsigned_abs().leading_zeros())
}

fn stride_costs(q: &[i64]) -> Vec<u64> {
    let window = MAX_LANES.min(q.len() / 4);
    let rows = q.len() - window;
    (1..=window)
        .map(|lane| (0..rows).map(|i| bitlen(q[i + lane] - q[i])).sum())
        .collect()
}

fn best_stride(costs: &[u64]) -> usize {
    let best = *costs.iter().min().unwrap_or(&0);
    costs
        .iter()
        .position(|&c| c * 100 <= best * 102)
        .map_or(1, |i| i + 1)
}

/// `gridcodec.plan`: the producer's grid for a chunk, or `None`.
#[must_use]
pub fn grid_plan(data: &[u8]) -> Option<GridPlan> {
    if data.len() < MIN_VALUES * 4 {
        return None;
    }
    let mut best: Option<(u64, GridPlan)> = None;
    for phase in 0..4 {
        if !screen_phase(data, phase) {
            continue;
        }
        let sample = floats(data, phase, SAMPLE);
        let Some((kind, exp)) = scale_for(&sample) else {
            continue;
        };
        let (q, _) = on_grid(&sample, scale_value(kind, exp));
        let costs = stride_costs(&q);
        let lanes = best_stride(&costs);
        let cost = costs[lanes - 1];
        if best.is_none_or(|(c, _)| cost < c) {
            best = Some((
                cost,
                GridPlan {
                    phase,
                    lanes,
                    kind,
                    exp,
                },
            ));
        }
    }
    best.map(|(_, p)| p)
}

fn zigzag(d: i64) -> u64 {
    ((d << 1) ^ (d >> 63)) as u64
}

fn unzigzag(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}

// ───── residual entropy coding (grid_rc) ──────────────────────────────────

/// Mantissa bits below a residual's leading one that are modeled adaptively;
/// lower bits are near-uniform and coded raw.
const MANT_TOP: u32 = 8;

/// Per-lane adaptive model: the bit length of each zig-zag residual, coded
/// with the previous bit length of the same lane as context (lengths are
/// autocorrelated along a scan), then the top mantissa bits with the bit
/// length as context. Its entropy on real KITTI residuals is below the
/// order-0 entropy of the residuals themselves.
struct LaneModel {
    lengths: Vec<u16>,       // 33 contexts x 64-node tree
    mantissa: Vec<Vec<u16>>, // per bit length: tree over its top bits
    signs: [u16; 4],         // context: previous sign (+, -) x previous length small/large
    prev: usize,
    prev_negative: bool,
}

impl LaneModel {
    fn new() -> Self {
        Self {
            lengths: vec![crate::rc::HALF; 33 * 64],
            mantissa: (0..=32u32)
                .map(|b| vec![crate::rc::HALF; 1 << b.saturating_sub(1).min(MANT_TOP)])
                .collect(),
            signs: [crate::rc::HALF; 4],
            prev: 0,
            prev_negative: false,
        }
    }

    fn sign_ctx(&self) -> usize {
        usize::from(self.prev_negative) * 2 + usize::from(self.prev >= 4)
    }

    /// Codes the delta as sign + magnitude: along a scan, consecutive deltas
    /// mostly share their sign, which zig-zag would hide in the low bit.
    fn encode(&mut self, enc: &mut crate::rc::Encoder, z: u32) {
        let negative = z & 1 == 1;
        let mag = (z >> 1) + u32::from(negative); // |d|: zig-zag 2|d|-1 for d < 0
        let b = 32 - mag.leading_zeros();
        let ctx = self.prev * 64;
        enc.tree(&mut self.lengths[ctx..ctx + 64], 6, b);
        if b >= 2 {
            let m = b - 1;
            let top = m.min(MANT_TOP);
            let mant = mag & ((1 << m) - 1);
            enc.tree(&mut self.mantissa[b as usize], top, mant >> (m - top));
            enc.direct(mant & ((1 << (m - top)) - 1), m - top);
        }
        if mag != 0 {
            let s = self.sign_ctx();
            enc.bit(&mut self.signs[s], negative);
            self.prev_negative = negative;
        }
        self.prev = b as usize;
    }

    fn decode(&mut self, dec: &mut crate::rc::Decoder<'_>) -> Option<u32> {
        let ctx = self.prev * 64;
        let b = dec.tree(&mut self.lengths[ctx..ctx + 64], 6);
        if b > 32 {
            return None;
        }
        let mag = if b < 2 {
            b
        } else {
            let m = b - 1;
            let top = m.min(MANT_TOP);
            let hi = dec.tree(&mut self.mantissa[b as usize], top);
            let lo = dec.direct(m - top);
            (1 << m) | (hi << (m - top)) | lo
        };
        let z = if mag == 0 {
            0
        } else {
            let s = self.sign_ctx();
            let negative = dec.bit(&mut self.signs[s]);
            self.prev_negative = negative;
            if negative {
                // zig-zag of -mag is 2*mag-1; written as 2*(mag-1)+1 so that
                // mag = 2^31 (z = u32::MAX) cannot overflow on the way
                (mag - 1).checked_mul(2)?.checked_add(1)?
            } else {
                mag.checked_mul(2)?
            }
        };
        self.prev = b as usize;
        Some(z)
    }
}

fn rc_encode_residuals(z: &[u32]) -> Vec<u8> {
    let mut model = LaneModel::new();
    let mut enc = crate::rc::Encoder::new();
    for &value in z {
        model.encode(&mut enc, value);
    }
    enc.finish()
}

fn rc_decode_residuals(bytes: &[u8], count: usize) -> Option<Vec<u32>> {
    let mut model = LaneModel::new();
    let mut dec = crate::rc::Decoder::new(bytes);
    let mut out = Vec::with_capacity(count.min(bytes.len().saturating_mul(64)));
    for i in 0..count {
        // a header claiming more values than the stream holds is refused as
        // soon as the decoder runs past the input, not after `count` steps
        if i % 4096 == 0 && dec.overran() {
            return None;
        }
        out.push(model.decode(&mut dec)?);
    }
    dec.finished_exactly().then_some(out)
}

// ───── per-lane predictors (grid_rc) ──────────────────────────────────────
//
// A lane's residual is its value minus a prediction. Delta (`x[i-1]`) fits
// scan-ordered geometry; a lane of noise around a level is coded smaller
// around a constant, since differencing white noise doubles its variance and
// anti-correlates consecutive signs. Each lane carries the predictor that
// coded it smallest.
//
// Measured on KITTI (35.2 MiB, 2,584 lane-chunks), residual bytes best-of:
// delta 6,025,903; +center 5,989,743 (-0.60%, the reflectance lane); +linear
// (2x[i-1]-x[i-2]) 6,024,900 and +an online delta/linear switch 6,024,731
// (-0.02% each, dropped: the length and sign contexts already carry the
// trend). Picking by the sum of residual bit lengths instead of coded size
// was 2.7% WORSE than delta alone -- it cannot see the sign/length contexts.

/// `x[i-1]`: the grid codec's original predictor.
const PRED_DELTA: u8 = 0;
/// The lane's median: noise around a level.
const PRED_CENTER: u8 = 1;

/// One lane's zig-zag residuals under `mode`; `None` if one does not fit u32.
fn lane_residuals(lane: &[i64], mode: u8, center: i64) -> Option<Vec<u32>> {
    let mut z = Vec::with_capacity(lane.len());
    let mut previous = 0i64;
    for &x in lane {
        let prediction = if mode == PRED_CENTER {
            center
        } else {
            previous
        };
        let d = x - prediction;
        if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&d) {
            return None;
        }
        z.push(zigzag(d) as u32);
        previous = x;
    }
    Some(z)
}

/// Rows of a lane both predictors are trial-coded on before the full lane is
/// coded once with the winner. Neither the sum of residual bit lengths (picked
/// center 0 times in 2,584 KITTI lane-chunks where it wins 570) nor order-0
/// entropy predicts this coder's size: only coding does.
const TRIAL_ROWS: usize = 512;

/// One lane's record: mode, center, and the lane coded under the predictor
/// that coded its first `TRIAL_ROWS` rows smaller (ties: delta). `None` if a
/// residual does not fit u32 -- impossible for grid values, |q| < 2^30.
fn rc_encode_lane(lane: &[i64]) -> Option<(u8, i64, Vec<u8>)> {
    let mut sorted = lane.to_vec();
    let center = *sorted.select_nth_unstable(lane.len() / 2).1;
    let center = i64::from(i32::try_from(center).ok()?);
    let trial = &lane[..lane.len().min(TRIAL_ROWS)];
    let delta = rc_encode_residuals(&lane_residuals(trial, PRED_DELTA, 0)?);
    let centered = rc_encode_residuals(&lane_residuals(trial, PRED_CENTER, center)?);
    let (mode, sample) = if centered.len() < delta.len() {
        (PRED_CENTER, centered)
    } else {
        (PRED_DELTA, delta)
    };
    let bytes = if trial.len() == lane.len() {
        sample
    } else {
        rc_encode_residuals(&lane_residuals(lane, mode, center)?)
    };
    Some((mode, center, bytes))
}

/// Each lane record: mode (u8), center (i32 LE, CENTER only), length (u32 LE),
/// the lane's range-coded residuals. `None` if some lane fits no predictor.
///
/// Lanes are independent streams, so they are coded in parallel: a file of a
/// few chunks still uses one core per lane.
fn rc_encode_lanes(q: &[i64], rows: usize, lanes: usize) -> Option<Vec<u8>> {
    let records: Vec<Option<(u8, i64, Vec<u8>)>> = (0..lanes)
        .into_par_iter()
        .map(|l| {
            let lane: Vec<i64> = (0..rows).map(|r| q[r * lanes + l]).collect();
            rc_encode_lane(&lane)
        })
        .collect();
    let mut out = Vec::new();
    for record in records {
        let (mode, center, bytes) = record?;
        out.push(mode);
        if mode == PRED_CENTER {
            out.extend_from_slice(&(center as i32).to_le_bytes());
        }
        out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    Some(out)
}

/// Inverse of [`rc_encode_lanes`]: the quantized values in row-major order and
/// the number of bytes the lane records occupied. Records are parsed in order,
/// then the lanes decode in parallel.
fn rc_decode_lanes(inner: &[u8], rows: usize, lanes: usize) -> Option<(Vec<i64>, usize)> {
    let mut cursor = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let slice = inner.get(cursor..cursor.checked_add(n)?)?;
        cursor += n;
        Some(slice)
    };
    let mut records = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let mode = take(1)?[0];
        let center = match mode {
            PRED_DELTA => 0,
            PRED_CENTER => i64::from(i32::from_le_bytes(take(4)?.try_into().ok()?)),
            _ => return None,
        };
        let len = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        records.push((mode, center, take(len)?));
    }
    let decoded: Vec<Option<Vec<i64>>> = records
        .into_par_iter()
        .map(|(mode, center, bytes)| {
            let z = rc_decode_residuals(bytes, rows)?;
            // wrapping: a corrupt stream must not panic (it fails verification)
            let mut previous = 0i64;
            Some(
                z.iter()
                    .map(|&zz| {
                        let prediction = if mode == PRED_CENTER {
                            center
                        } else {
                            previous
                        };
                        previous = prediction.wrapping_add(unzigzag(u64::from(zz)));
                        previous
                    })
                    .collect(),
            )
        })
        .collect();
    let mut q = vec![0i64; rows * lanes];
    for (l, lane) in decoded.into_iter().enumerate() {
        for (r, x) in lane?.into_iter().enumerate() {
            q[r * lanes + l] = x;
        }
    }
    Some((q, cursor))
}

/// How a grid payload codes its residuals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inner {
    /// Per-lane byte planes through a general compressor (`gridcodec.py`'s format).
    Codec(Algorithm),
    /// Per-lane predictors and the adaptive residual model through the range
    /// coder (native only).
    Rc,
}

/// `gridcodec.encode`: `None` unless the payload decodes to `data` exactly.
pub fn grid_encode(
    data: &[u8],
    plan: GridPlan,
    inner: Inner,
) -> Result<Option<Vec<u8>>, CompressError> {
    let n_values = (data.len() - plan.phase) / 4;
    let rows = n_values / plan.lanes;
    if rows < 2 {
        return Ok(None);
    }
    let lanes = plan.lanes;
    let body_end = plan.phase + rows * lanes * 4;
    let head = &data[..plan.phase];
    let tail = &data[body_end..];
    let v = floats(data, plan.phase, rows * lanes);
    let (q, exact) = on_grid(&v, plan.scale());
    let exceptions: Vec<u32> = exact
        .iter()
        .enumerate()
        .filter(|(_, ok)| !**ok)
        .map(|(i, _)| i as u32)
        .collect();
    if exceptions.len() * 64 > v.len() {
        return Ok(None);
    }
    let mut exception_records = Vec::with_capacity(exceptions.len() * 8);
    for e in &exceptions {
        exception_records.extend_from_slice(&e.to_le_bytes());
    }
    for e in &exceptions {
        exception_records.extend_from_slice(&v[*e as usize].to_bits().to_le_bytes());
    }
    let (magic, inner_bytes) = match inner {
        Inner::Codec(algo) => {
            let mut z = vec![0u32; rows * lanes];
            for r in 0..rows {
                for l in 0..lanes {
                    let prev = if r == 0 { 0 } else { q[(r - 1) * lanes + l] };
                    let zz = zigzag(q[r * lanes + l] - prev);
                    if zz >= 1 << 32 {
                        return Ok(None);
                    }
                    z[r * lanes + l] = zz as u32;
                }
            }
            let mut raw = vec![0u8; rows * lanes * 4];
            for r in 0..rows {
                for l in 0..lanes {
                    let bytes = z[r * lanes + l].to_le_bytes();
                    for (b, byte) in bytes.iter().enumerate() {
                        raw[(l * 4 + b) * rows + r] = *byte;
                    }
                }
            }
            raw.extend_from_slice(&exception_records);
            (GRID_MAGIC, Dispatcher::new().compress(algo, &raw)?)
        }
        Inner::Rc => {
            // An exception's slot is overwritten on decode, so it may carry any
            // value: the midpoint of its lane neighbours keeps both residuals
            // typical (a zero, or a jump to 0 and back, upsets the length
            // context). Exceptions are ascending, so earlier slots are final.
            let mut q = q;
            for &e in &exceptions {
                let e = e as usize;
                let prev = if e >= lanes { q[e - lanes] } else { 0 };
                let next = e + lanes;
                let next_is_value =
                    next < q.len() && exceptions.binary_search(&(next as u32)).is_err();
                q[e] = if next_is_value {
                    prev + (q[next] - prev) / 2
                } else {
                    prev
                };
            }
            let Some(mut bytes) = rc_encode_lanes(&q, rows, lanes) else {
                return Ok(None);
            };
            bytes.extend_from_slice(&exception_records);
            (GRID_RC_MAGIC, bytes)
        }
    };
    let mut payload =
        Vec::with_capacity(GRID_HEADER_LEN + head.len() + tail.len() + inner_bytes.len());
    payload.extend_from_slice(magic);
    payload.push(plan.phase as u8);
    payload.push(lanes as u8);
    payload.push(plan.kind);
    payload.push(plan.exp as u8);
    payload.extend_from_slice(&(rows as u32).to_le_bytes());
    payload.push(head.len() as u8);
    payload.extend_from_slice(&(tail.len() as u32).to_le_bytes());
    payload.extend_from_slice(&(exceptions.len() as u32).to_le_bytes());
    payload.extend_from_slice(&(inner_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(head);
    payload.extend_from_slice(tail);
    payload.extend_from_slice(&inner_bytes);
    match grid_decode(&payload, data.len()) {
        Ok(back) if back == data => Ok(Some(payload)),
        _ => Ok(None),
    }
}

fn bad(msg: &str) -> CompressError {
    CompressError::Zstd(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        msg.to_owned(),
    ))
}

/// `gridcodec.decode`: exact inverse of [`grid_encode`].
pub fn grid_decode(payload: &[u8], plain_size: usize) -> Result<Vec<u8>, CompressError> {
    // `plain_size` and the row count come from untrusted headers: the same
    // output cap as every other decode, before anything is allocated
    if plain_size > MAX_DECOMPRESSED_BYTES {
        return Err(CompressError::OutputTooLarge {
            decompressed: plain_size,
            max: MAX_DECOMPRESSED_BYTES,
        });
    }
    if payload.len() < GRID_HEADER_LEN
        || (&payload[..4] != GRID_MAGIC && &payload[..4] != GRID_RC_MAGIC)
    {
        return Err(bad("invalid grid header"));
    }
    let entropy_coded = &payload[..4] == GRID_RC_MAGIC;
    let phase = payload[4] as usize;
    let lanes = payload[5] as usize;
    let kind = payload[6];
    let exp = payload[7] as i8;
    let u32_at = |o: usize| {
        u32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]) as usize
    };
    let rows = u32_at(8);
    let head_len = payload[12] as usize;
    let tail_len = u32_at(13);
    let n_exc = u32_at(17);
    let inner_len = u32_at(21);
    let valid_exp = if kind == DECIMAL {
        (0..=6).contains(&exp)
    } else {
        (0..=20).contains(&exp)
    };
    if (kind != DECIMAL && kind != BINARY) || !valid_exp || !(1..=MAX_LANES).contains(&lanes) {
        return Err(bad("invalid grid header"));
    }
    if head_len != phase || phase > 3 {
        return Err(bad("invalid grid phase"));
    }
    let body_values = rows * lanes;
    if head_len + body_values * 4 + tail_len != plain_size || n_exc > body_values {
        return Err(bad("grid geometry does not match the chunk size"));
    }
    let mut cursor = GRID_HEADER_LEN;
    if payload.len() != cursor + head_len + tail_len + inner_len {
        return Err(bad("truncated grid payload"));
    }
    let head = &payload[cursor..cursor + head_len];
    cursor += head_len;
    let tail = &payload[cursor..cursor + tail_len];
    cursor += tail_len;
    let inner = &payload[cursor..];
    // Quantized values in row-major order, and the raw exception records.
    let (q, exc): (Vec<i64>, Vec<u8>) = if entropy_coded {
        let (q, used) = rc_decode_lanes(inner, rows, lanes)
            .ok_or_else(|| bad("grid residual stream is corrupt"))?;
        if used.checked_add(n_exc * 8) != Some(inner.len()) {
            return Err(bad("grid residual stream has the wrong size"));
        }
        (q, inner[used..].to_vec())
    } else {
        let expected_inner = body_values * 4 + n_exc * 8;
        let raw = Dispatcher::new().decompress(inner, expected_inner)?;
        if raw.len() != expected_inner {
            return Err(bad("grid planes have the wrong size"));
        }
        let mut q = vec![0i64; body_values];
        for l in 0..lanes {
            let mut acc: i64 = 0;
            for r in 0..rows {
                let mut bytes = [0u8; 4];
                for (b, byte) in bytes.iter_mut().enumerate() {
                    *byte = raw[(l * 4 + b) * rows + r];
                }
                acc += unzigzag(u64::from(u32::from_le_bytes(bytes)));
                q[r * lanes + l] = acc;
            }
        }
        (q, raw[body_values * 4..].to_vec())
    };
    let scale = scale_value(kind, exp);
    let mut values: Vec<u32> = q
        .iter()
        .map(|&x| ((x as f64 / scale) as f32).to_bits())
        .collect();
    let exc_at = |i: usize, base: usize| {
        let o = base + 4 * i;
        u32::from_le_bytes([exc[o], exc[o + 1], exc[o + 2], exc[o + 3]])
    };
    for i in 0..n_exc {
        let position = exc_at(i, 0) as usize;
        if position >= body_values {
            return Err(bad("grid exception position out of range"));
        }
        values[position] = exc_at(i, n_exc * 4);
    }
    let mut out = Vec::with_capacity(plain_size);
    out.extend_from_slice(head);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(tail);
    Ok(out)
}

/// Test support: 40-90 KB chunk ranges at arbitrary offsets, deterministic.
#[cfg(test)]
pub(crate) fn tests_support_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut x: u64 = 3;
    let mut pos = 5;
    loop {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let size = 40_000 + (x % 50_000) as usize;
        if pos + size > data.len() {
            break;
        }
        out.push((pos, pos + size));
        pos += size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lidar(points: usize, phase: usize) -> Vec<u8> {
        let mut out = vec![0xAB; phase];
        for i in 0..points {
            let a = i as f64 * 0.01;
            for v in [
                ((8.0 + 30.0 * (a * 3.0).sin().abs()) * a.cos() * 1000.0).round_ties_even()
                    / 1000.0,
                ((8.0 + 30.0 * (a * 3.0).sin().abs()) * a.sin() * 1000.0).round_ties_even()
                    / 1000.0,
                -1.7,
                ((i % 100) as f64) / 100.0,
            ] {
                out.extend_from_slice(&(v as f32).to_le_bytes());
            }
        }
        out
    }

    #[test]
    fn grid_round_trips_at_every_phase_and_compresses() {
        for phase in 0..4 {
            let data = lidar(4096, phase);
            let enc = encode_chunk(&data, Mode::Auto, false, true).unwrap();
            assert_eq!(enc[6], CODEC_GRID_ZSTD, "phase {phase}");
            assert!(enc.len() * 3 < data.len());
            let back = grid_decode(&enc[16..], data.len()).unwrap();
            assert_eq!(back, data);
        }
    }

    #[test]
    fn negative_zero_takes_the_side_channel() {
        let mut data = lidar(4096, 0);
        data[64..68].copy_from_slice(&(-0.0f32).to_le_bytes());
        let plan = grid_plan(&data).unwrap();
        let payload = grid_encode(&data, plan, Inner::Codec(Algorithm::ZstdBalanced))
            .unwrap()
            .unwrap();
        assert_eq!(grid_decode(&payload, data.len()).unwrap(), data);
    }

    #[test]
    fn an_exception_costs_its_side_record_not_a_jump_in_the_residuals() {
        // NaNs in the x lane (values ~ +-38,000 on the grid): each is an
        // 8-byte side record; its slot must not also cost a jump to 0 and back
        let clean = lidar(8192, 0);
        let mut holed = clean.clone();
        let n_holes = 96; // < 1/64 of the 32,768 values
        for k in 0..n_holes {
            let o = (40 + k * 83) * 16; // row (40 + 83k), lane 0
            holed[o..o + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        }
        let plan = grid_plan(&clean).unwrap();
        assert_eq!(grid_plan(&holed), Some(plan));
        let size = |data: &[u8]| grid_encode(data, plan, Inner::Rc).unwrap().unwrap().len();
        let (clean_size, holed_size) = (size(&clean), size(&holed));
        assert_eq!(
            grid_decode(
                &grid_encode(&holed, plan, Inner::Rc).unwrap().unwrap(),
                holed.len()
            )
            .unwrap(),
            holed
        );
        // a hole costs its side record and nothing more (a slot left at 0
        // cost 12.7 B; one carrying the previous value, 9.2 B)
        assert!(
            holed_size <= clean_size + n_holes * 8,
            "{holed_size} vs {clean_size} + {n_holes} holes"
        );
    }

    #[test]
    fn random_bytes_are_never_grid() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let data: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(grid_plan(&data).is_none());
        let enc = encode_chunk(&data, Mode::Auto, false, true).unwrap();
        assert_eq!(enc[6], CODEC_NONE);
        assert_eq!(&enc[16..], &data[..]);
    }

    #[test]
    fn corrupt_payloads_error_instead_of_returning_wrong_bytes() {
        let data = lidar(2048, 1);
        let plan = grid_plan(&data).unwrap();
        let payload = grid_encode(&data, plan, Inner::Codec(Algorithm::ZstdBalanced))
            .unwrap()
            .unwrap();
        for i in (0..payload.len()).step_by(7) {
            let mut bad = payload.clone();
            bad[i] ^= 0x10;
            if let Ok(out) = grid_decode(&bad, data.len()) {
                // a flipped bit in tail/head bytes is a different chunk: the
                // caller's SHA-256 check rejects it; it must still be well-formed
                assert_eq!(out.len(), data.len());
            }
        }
        assert!(grid_decode(&payload, data.len() + 4).is_err());
    }

    #[test]
    fn decode_inverts_every_encoding_and_refuses_what_it_does_not_own() {
        let mut x: u64 = 0x1234_5678_9ABC_DEF1;
        let random: Vec<u8> = (0..20_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        let inputs = [lidar(3000, 2), b"telemetry,ok,12.5\n".repeat(900), random];
        for data in &inputs {
            let digest = sha256(data);
            for mode in [
                Mode::Auto,
                Mode::AutoFast,
                Mode::None,
                Mode::Lz4,
                Mode::ZstdBalanced,
            ] {
                let enc = encode_chunk(data, mode, false, true).unwrap();
                assert_eq!(decode_chunk(&enc, &digest).as_deref(), Some(&data[..]));
                // a wrong expected digest is never served
                assert_eq!(decode_chunk(&enc, &[0u8; 32]), None);
                // a flipped payload byte is never served
                let mut bad = enc.clone();
                let last = bad.len() - 1;
                bad[last] ^= 0x40;
                assert_eq!(decode_chunk(&bad, &digest), None);
            }
            // encrypted and zlib chunks belong to the Python path
            let mut enc = encode_chunk(data, Mode::None, false, true).unwrap();
            enc[5] |= 0x02;
            assert_eq!(decode_chunk(&enc, &digest), None);
            let mut zl = encode_chunk(data, Mode::None, false, true).unwrap();
            zl[5] |= FLAG_COMPRESSED;
            zl[6] = 1;
            assert_eq!(decode_chunk(&zl, &digest), None);
        }
    }

    #[test]
    fn archive_mode_entropy_codes_grids_smaller_and_round_trips() {
        for phase in 0..4 {
            let data = lidar(6000, phase);
            let digest = sha256(&data);
            let auto = encode_chunk(&data, Mode::Auto, false, true).unwrap();
            let archive = encode_chunk(&data, Mode::AutoArchive, false, true).unwrap();
            // this fixture is strictly periodic, where byte planes + LZ win:
            // archive mode must never be worse than auto, whichever coder wins
            assert!(
                archive.len() <= auto.len(),
                "archive {} vs auto {}",
                archive.len(),
                auto.len()
            );
            assert_eq!(decode_chunk(&archive, &digest).as_deref(), Some(&data[..]));
            // and the residual coder itself must round-trip and refuse damage
            let plan = grid_plan(&data).unwrap();
            let rc = grid_encode(&data, plan, Inner::Rc).unwrap().unwrap();
            assert_eq!(&rc[..4], GRID_RC_MAGIC);
            let archive = frame(CODEC_GRID_RC, data.len(), &rc);
            assert_eq!(decode_chunk(&archive, &digest).as_deref(), Some(&data[..]));
            // every damaged byte of the residual stream is refused, never served
            for i in (16..archive.len()).step_by(11) {
                let mut bad = archive.clone();
                bad[i] ^= 0x08;
                assert_ne!(decode_chunk(&bad, &digest).as_deref(), Some(&data[..]));
                assert!(decode_chunk(&bad, &digest).is_none());
            }
        }
        // non-grid data in archive mode: zstd level 9, still exact
        let text = b"robot,ok,12.5,ACTIVE\n".repeat(3000);
        let enc = encode_chunk(&text, Mode::AutoArchive, false, true).unwrap();
        assert_eq!(enc[6], CODEC_ZSTD_AGGRESSIVE);
        assert_eq!(
            decode_chunk(&enc, &sha256(&text)).as_deref(),
            Some(&text[..])
        );
    }

    #[test]
    fn residual_coder_round_trips_and_beats_raw_on_scan_like_residuals() {
        let mut x: u64 = 7;
        let mut z = Vec::new();
        for i in 0..40_000u32 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // mostly small, autocorrelated magnitudes with rare large jumps
            let scale = if i % 997 == 0 {
                1 << 20
            } else {
                1 << ((i / 50) % 9)
            };
            z.push((x as u32) % scale);
        }
        z.extend([0, 1, 2, 3, u32::MAX, u32::MAX - 1, 1 << 31]);
        let bytes = rc_encode_residuals(&z);
        assert_eq!(
            rc_decode_residuals(&bytes, z.len()).as_deref(),
            Some(&z[..])
        );
        assert!(bytes.len() < z.len() * 4 / 2, "{} bytes", bytes.len());
        // truncated input is detected, never silently accepted
        assert!(rc_decode_residuals(&bytes[..bytes.len() / 2], z.len()).is_none());
    }

    /// Values of one lane under a named shape, on a 1/1000 grid.
    fn lane_shape(shape: u8, rows: usize, seed: u64) -> Vec<i64> {
        let mut x = seed | 1;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        (0..rows)
            .map(|i| {
                let noise = (rnd() % 41) as i64 - 20;
                let t = i as f64 / 300.0;
                match shape {
                    0 => (t.sin() * 40_000.0) as i64 + noise / 8, // smooth arc
                    1 => -1_700 + noise,                          // noise around a level
                    _ => ((i / 97) as i64 % 5) * 3_000,           // steps
                }
            })
            .collect()
    }

    #[test]
    fn each_lane_takes_the_predictor_that_fits_its_shape() {
        let rows = 6000;
        let shapes = [0u8, 1, 2];
        let lanes: Vec<Vec<i64>> = shapes
            .iter()
            .map(|&s| lane_shape(s, rows, 11 + u64::from(s)))
            .collect();
        let mut q = vec![0i64; rows * lanes.len()];
        for (l, lane) in lanes.iter().enumerate() {
            for (r, &v) in lane.iter().enumerate() {
                q[r * lanes.len() + l] = v;
            }
        }
        let inner = rc_encode_lanes(&q, rows, lanes.len()).unwrap();
        let (back, used) = rc_decode_lanes(&inner, rows, lanes.len()).unwrap();
        assert_eq!(back, q);
        assert_eq!(used, inner.len());
        // read each lane record's mode
        let mut modes = Vec::new();
        let mut cursor = 0;
        for _ in 0..lanes.len() {
            let mode = inner[cursor];
            modes.push(mode);
            cursor += 1 + if mode == PRED_CENTER { 4 } else { 0 };
            let len = u32::from_le_bytes(inner[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4 + len;
        }
        assert_eq!(
            modes,
            [PRED_DELTA, PRED_CENTER, PRED_DELTA],
            "arc, noise at a level, steps"
        );
        // the choice is real: the noise lane coded around its level beats its
        // delta coding by more than a tenth (white noise, differenced, doubles
        // its variance)
        let noise = &lanes[1];
        let (mode, center, bytes) = rc_encode_lane(noise).unwrap();
        assert_eq!((mode, center), (PRED_CENTER, -1_700));
        let delta = rc_encode_residuals(&lane_residuals(noise, PRED_DELTA, 0).unwrap());
        assert!(
            bytes.len() * 10 < delta.len() * 9,
            "{} vs {}",
            bytes.len(),
            delta.len()
        );
        // the widest grid lane (|q| < 2^30, alternating extremes) still codes
        // exactly, under both predictors; a lane beyond the grid's range refuses
        let wide: Vec<i64> = (0..64)
            .map(|i| {
                if i % 2 == 0 {
                    1 - (1 << 30)
                } else {
                    (1 << 30) - 1
                }
            })
            .collect();
        for mode in [PRED_DELTA, PRED_CENTER] {
            assert!(lane_residuals(&wide, mode, 0).is_some());
        }
        let two_lanes: Vec<i64> = (0..64).flat_map(|r| [wide[r], wide[r]]).collect();
        let inner = rc_encode_lanes(&two_lanes, 64, 2).unwrap();
        assert_eq!(rc_decode_lanes(&inner, 64, 2).unwrap().0, two_lanes);
        let unfit: Vec<i64> = vec![i64::from(i32::MIN) - 1, 1 << 40, -(1 << 40)];
        assert!(rc_encode_lane(&unfit).is_none());
        // a lane longer than the trial is coded in full with the trial's winner
        let long = lane_shape(1, 5 * TRIAL_ROWS + 7, 3);
        let (mode, center, bytes) = rc_encode_lane(&long).unwrap();
        assert_eq!(mode, PRED_CENTER);
        assert_eq!(
            rc_decode_residuals(&bytes, long.len()),
            lane_residuals(&long, PRED_CENTER, center)
        );
    }

    #[test]
    fn a_damaged_lane_record_is_refused() {
        let data = lidar(4000, 1);
        let plan = grid_plan(&data).unwrap();
        let payload = grid_encode(&data, plan, Inner::Rc).unwrap().unwrap();
        // header + head + tail precede the lane records; corrupt the first mode byte
        let first_record = GRID_HEADER_LEN + plan.phase;
        let mut bad = payload.clone();
        bad[first_record] = 9; // not a predictor
        assert!(grid_decode(&bad, data.len()).is_err());
        let mut bad = payload.clone();
        bad[first_record + 1] ^= 0x80; // a lane length (or center) far off
        assert_ne!(grid_decode(&bad, data.len()).ok(), Some(data.clone()));
        assert!(grid_decode(&payload[..payload.len() - 1], data.len()).is_err());
    }

    /// A forged GRR1 payload: one delta lane of `rows` values whose stream is
    /// `stream`, declaring `plain_size = 4 * rows`.
    fn forged_rc_payload(rows: usize, stream: &[u8]) -> Vec<u8> {
        let mut record = vec![PRED_DELTA];
        record.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        record.extend_from_slice(stream);
        let mut p = GRID_RC_MAGIC.to_vec();
        p.extend_from_slice(&[0, 1, DECIMAL, 3]); // phase, lanes, kind, exp
        p.extend_from_slice(&(rows as u32).to_le_bytes());
        p.push(0); // head
        p.extend_from_slice(&0u32.to_le_bytes()); // tail
        p.extend_from_slice(&0u32.to_le_bytes()); // exceptions
        p.extend_from_slice(&(record.len() as u32).to_le_bytes());
        p.extend_from_slice(&record);
        p
    }

    #[test]
    fn forged_sizes_are_refused_before_the_work_they_claim() {
        // past the output cap: refused before any allocation
        let rows = MAX_DECOMPRESSED_BYTES / 4 + 1;
        assert!(matches!(
            grid_decode(&forged_rc_payload(rows, &[0; 4]), rows * 4),
            Err(CompressError::OutputTooLarge { .. })
        ));
        // at the cap, a 4-byte stream claiming 16M values is refused
        let rows = MAX_DECOMPRESSED_BYTES / 4;
        assert!(grid_decode(&forged_rc_payload(rows, &[0; 4]), rows * 4).is_err());
        // the residual decoder stops once it runs past its input: 2^28
        // claimed values from 4 zero bytes (all-zero input decodes as zero
        // residuals at ~0.01 bits each, so only the overrun can stop it)
        let clock = std::time::Instant::now();
        assert!(rc_decode_residuals(&[0; 4], 1 << 28).is_none());
        let elapsed = clock.elapsed();
        assert!(elapsed.as_millis() < 200, "took {elapsed:?}");
        // and the forger's honest twin decodes
        let honest = forged_rc_payload(3, &rc_encode_residuals(&[2, 0, 1]));
        assert_eq!(
            grid_decode(&honest, 12).unwrap(),
            [0.001f32, 0.001, 0.0]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>()
        );
    }

    /// Measurement, not a gate: set `ONE_MEMORY_KITTI_DIR` to a directory of
    /// KITTI velodyne `.bin` scans and run with `--ignored --nocapture`.
    #[test]
    #[ignore = "needs a local KITTI corpus in ONE_MEMORY_KITTI_DIR"]
    fn measure_residual_coder_on_kitti() {
        let Some(dir) = std::env::var_os("ONE_MEMORY_KITTI_DIR") else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut lidar = Vec::new();
        let mut files: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
        files.sort();
        let mut scans = Vec::new();
        for file in files {
            let start = lidar.len();
            lidar.extend(std::fs::read(file).unwrap());
            scans.push((start, lidar.len()));
        }
        measure_scan_sized_chunks(&lidar, &scans);
        measure_small_chunks(&lidar);
    }

    /// ONE Memory's chunks average 1 MiB: one ~1.9 MB KITTI scan per chunk.
    fn measure_scan_sized_chunks(lidar: &[u8], scans: &[(usize, usize)]) {
        let (mut scan_raw, mut scan_delta, mut scan_shipped) = (0usize, 0usize, 0usize);
        let mut t_scan = 0f64;
        for &(start, end) in scans {
            let chunk = &lidar[start..end];
            let plan = grid_plan(chunk).unwrap();
            scan_raw += chunk.len();
            let clock = std::time::Instant::now();
            scan_shipped += grid_encode(chunk, plan, Inner::Rc).unwrap().unwrap().len();
            t_scan += clock.elapsed().as_secs_f64();
            let rows = ((chunk.len() - plan.phase) / 4) / plan.lanes;
            let (q, _) = on_grid(&floats(chunk, plan.phase, rows * plan.lanes), plan.scale());
            scan_delta += GRID_HEADER_LEN + chunk.len() - rows * plan.lanes * 4;
            for l in 0..plan.lanes {
                let lane: Vec<i64> = (0..rows).map(|r| q[r * plan.lanes + l]).collect();
                scan_delta +=
                    5 + rc_encode_residuals(&lane_residuals(&lane, PRED_DELTA, 0).unwrap()).len();
            }
        }
        println!(
            "KITTI scan-sized chunks ({} x ~1.9 MB): grid+rc delta-only {:.3}x | shipped {:.3}x ({:.2}% smaller) | shipped grid_encode incl. verify-decode, lanes in parallel, {:.0} MiB/s",
            scans.len(),
            scan_raw as f64 / scan_delta as f64,
            scan_raw as f64 / scan_shipped as f64,
            100.0 * (1.0 - scan_shipped as f64 / scan_delta as f64),
            scan_raw as f64 / f64::from(1u32 << 20) / t_scan
        );
    }

    /// 40-90 KB chunks at arbitrary offsets: the cold-model regime, with the
    /// zstd baseline, the exhaustive predictor choice and the coder's speeds.
    fn measure_small_chunks(lidar: &[u8]) {
        let ranges = crate::onemem::tests_support_ranges(lidar);
        let (mut raw, mut zstd, mut delta_rc, mut rc) = (0usize, 0usize, 0usize, 0usize);
        let (mut t_zstd, mut t_rc, mut t_rcd, mut t_delta) = (0f64, 0f64, 0f64, 0f64);
        let mut modes = [0usize; 2];
        let mut exhaustive = 0usize; // lane records, best of delta and center, both always coded
        let mut shipped_lanes = 0usize; // lane records as the screened encoder wrote them
        for (start, end) in ranges {
            let chunk = &lidar[start..end];
            let Some(plan) = grid_plan(chunk) else {
                continue;
            };
            raw += chunk.len();
            let clock = std::time::Instant::now();
            let planes = grid_encode(chunk, plan, Inner::Codec(Algorithm::ZstdBalanced))
                .unwrap()
                .unwrap();
            t_zstd += clock.elapsed().as_secs_f64();
            zstd += planes.len();
            let clock = std::time::Instant::now();
            let payload = grid_encode(chunk, plan, Inner::Rc).unwrap().unwrap();
            t_rc += clock.elapsed().as_secs_f64();
            let clock = std::time::Instant::now();
            let back = grid_decode(&payload, chunk.len()).unwrap();
            t_rcd += clock.elapsed().as_secs_f64();
            assert_eq!(back, chunk);
            rc += payload.len();
            // the same chunk with the grid codec's original predictor on every lane
            let rows = ((chunk.len() - plan.phase) / 4) / plan.lanes;
            let (q, _) = on_grid(&floats(chunk, plan.phase, rows * plan.lanes), plan.scale());
            delta_rc += GRID_HEADER_LEN + chunk.len() - rows * plan.lanes * 4;
            for l in 0..plan.lanes {
                let lane: Vec<i64> = (0..rows).map(|r| q[r * plan.lanes + l]).collect();
                let mut sorted = lane.clone();
                let center = *sorted.select_nth_unstable(rows / 2).1;
                let size = |mode| {
                    lane_residuals(&lane, mode, center)
                        .map_or(usize::MAX, |z| rc_encode_residuals(&z).len())
                };
                let clock = std::time::Instant::now();
                let delta = size(PRED_DELTA);
                t_delta += clock.elapsed().as_secs_f64();
                let centered = size(PRED_CENTER);
                delta_rc += 5 + delta;
                exhaustive += 5 + delta.min(centered.saturating_add(4));
            }
            let mut cursor = GRID_HEADER_LEN + chunk.len() - rows * plan.lanes * 4;
            let records_start = cursor;
            for _ in 0..plan.lanes {
                let mode = payload[cursor];
                modes[mode as usize] += 1;
                cursor += 1 + if mode == PRED_CENTER { 4 } else { 0 };
                cursor += 4 + u32::from_le_bytes(payload[cursor..cursor + 4].try_into().unwrap())
                    as usize;
            }
            shipped_lanes += cursor - records_start;
        }
        let mib = raw as f64 / f64::from(1u32 << 20);
        println!(
            "KITTI {mib:.1} MiB: grid+zstd {:.2}x | grid+rc delta-only {:.2}x | grid+rc shipped {:.2}x ({:.2}% smaller than delta-only, {:.1}% than zstd; trial-selection regret {} B vs always coding both) | lane modes delta/center {modes:?} | per chunk: zstd-grid encode {:.0} MiB/s (one core), rc encode {:.0} MiB/s (lanes in parallel; one delta lane alone, one core, {:.0} MiB/s), rc decode {:.0} MiB/s (lanes in parallel)",
            raw as f64 / zstd as f64,
            raw as f64 / delta_rc as f64,
            raw as f64 / rc as f64,
            100.0 * (1.0 - rc as f64 / delta_rc as f64),
            100.0 * (1.0 - rc as f64 / zstd as f64),
            shipped_lanes as i64 - exhaustive as i64,
            mib / t_zstd,
            mib / t_rc,
            mib / t_delta,
            mib / t_rcd
        );
    }

    #[test]
    fn batch_matches_single_calls() {
        let chunks: Vec<Vec<u8>> = (0..16).map(|i| lidar(1000 + i * 37, i % 4)).collect();
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let many = encode_many(&refs, Mode::Auto, false, true);
        for (c, m) in refs.iter().zip(many) {
            assert_eq!(
                m.unwrap(),
                encode_chunk(c, Mode::Auto, false, true).unwrap()
            );
        }
        assert_eq!(sha256_many(&refs)[3], sha256(refs[3]));
    }
}
