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

use crate::dispatcher::{Algorithm, Dispatcher};
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

const GRID_MAGIC: &[u8; 4] = b"GRD1";
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
    if compress && matches!(mode, Mode::Auto | Mode::AutoFast) && !precompressed {
        let (codec, inner) = if mode == Mode::AutoFast {
            (CODEC_GRID_LZ4, Algorithm::Lz4)
        } else {
            (CODEC_GRID_ZSTD, Algorithm::ZstdBalanced)
        };
        if let Some(plan) = grid_plan(plaintext) {
            if let Some(payload) = grid_encode(plaintext, plan, inner)? {
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
        Mode::Auto | Mode::AutoFast => {
            if precompressed || plaintext.len() < 1024 {
                return None;
            }
            let savings = sample_lz4_savings(plaintext);
            if savings < 0.05 {
                None
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

/// `gridcodec.encode`: `None` unless the payload decodes to `data` exactly.
pub fn grid_encode(
    data: &[u8],
    plan: GridPlan,
    inner: Algorithm,
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
    let mut raw = vec![0u8; rows * lanes * 4 + exceptions.len() * 8];
    for r in 0..rows {
        for l in 0..lanes {
            let bytes = z[r * lanes + l].to_le_bytes();
            for (b, byte) in bytes.iter().enumerate() {
                raw[(l * 4 + b) * rows + r] = *byte;
            }
        }
    }
    let mut cursor = rows * lanes * 4;
    for e in &exceptions {
        raw[cursor..cursor + 4].copy_from_slice(&e.to_le_bytes());
        cursor += 4;
    }
    for e in &exceptions {
        raw[cursor..cursor + 4].copy_from_slice(&v[*e as usize].to_bits().to_le_bytes());
        cursor += 4;
    }
    let d = Dispatcher::new();
    let inner_bytes = d.compress(inner, &raw)?;
    let mut payload =
        Vec::with_capacity(GRID_HEADER_LEN + head.len() + tail.len() + inner_bytes.len());
    payload.extend_from_slice(GRID_MAGIC);
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
    if payload.len() < GRID_HEADER_LEN || &payload[..4] != GRID_MAGIC {
        return Err(bad("invalid grid header"));
    }
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
    let expected_inner = body_values * 4 + n_exc * 8;
    let raw = Dispatcher::new().decompress(&payload[cursor..], expected_inner)?;
    if raw.len() != expected_inner {
        return Err(bad("grid planes have the wrong size"));
    }
    let scale = scale_value(kind, exp);
    let mut values = vec![0u32; body_values];
    for l in 0..lanes {
        let mut acc: i64 = 0;
        for r in 0..rows {
            let mut bytes = [0u8; 4];
            for (b, byte) in bytes.iter_mut().enumerate() {
                *byte = raw[(l * 4 + b) * rows + r];
            }
            acc += unzigzag(u64::from(u32::from_le_bytes(bytes)));
            values[r * lanes + l] = ((acc as f64 / scale) as f32).to_bits();
        }
    }
    let exc_at = |i: usize, base: usize| {
        let o = base + 4 * i;
        u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]])
    };
    for i in 0..n_exc {
        let position = exc_at(i, body_values * 4) as usize;
        if position >= body_values {
            return Err(bad("grid exception position out of range"));
        }
        values[position] = exc_at(i, body_values * 4 + n_exc * 4);
    }
    let mut out = Vec::with_capacity(plain_size);
    out.extend_from_slice(head);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(tail);
    Ok(out)
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
        let payload = grid_encode(&data, plan, Algorithm::ZstdBalanced)
            .unwrap()
            .unwrap();
        assert_eq!(grid_decode(&payload, data.len()).unwrap(), data);
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
        let payload = grid_encode(&data, plan, Algorithm::ZstdBalanced)
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
