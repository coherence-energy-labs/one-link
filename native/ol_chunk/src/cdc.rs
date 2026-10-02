//! Content-defined chunking via `FastCDC` + Gear-256.
//!
//! Implements the kernel chosen in [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md):
//! `FastCDC` with 8 KiB min / 64 KiB avg / 256 KiB max chunk size, using the
//! reference Gear-256 hash table. SIMD acceleration is dispatched at runtime
//! by the underlying `fastcdc` crate's v2020 implementation; the scalar
//! fallback never falls below 1.2 GiB/s/core on commodity hardware.
//!
//! This module also computes a BLAKE3 hash per chunk while iterating, so
//! callers receive `(start, end, blake3_hash)` triples ready for use as
//! content-addressed identifiers per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
//!
//! ## Determinism
//!
//! Two scans of the same input on any platform produce identical
//! `Boundary` sequences. SIMD changes microarchitecture, not byte output.
//! The `tests/cross_platform.rs` fixture pins a known boundary set against
//! a fixed input; CI runs it on Linux x86-64, macOS arm64, and Windows
//! x86-64 to guarantee no cross-platform divergence.
//!
//! ## Throughput
//!
//! Phase A1 verification gate ([ADR-0001]): ≥ 2 GiB/s/core scalar,
//! ≥ 5 GiB/s/core with SIMD. Measured by `benches/cdc_bench.rs` against
//! a 1 GiB pseudo-random buffer.

use crate::blake3_wrap;
use crate::error::ChunkError;
use rayon::prelude::*;

/// `FastCDC` chunk size parameters fixed by [ADR-0001].
///
/// Minimum 8 KiB: chunks below this floor incur metadata overhead
/// (32-byte BLAKE3 + 16-byte ratchet-key-id + bloom slot) that exceeds
/// the savings of dedup. Maximum 256 KiB: above this ceiling, FUSE read
/// amplification gets bad. Average 64 KiB: matches the `FastCDC` paper's
/// recommended parameter for general-purpose dedup, and matches `OneField`
/// Mesh `transport/cdc_dedup.cl` family.
#[derive(Debug, Clone, Copy)]
pub struct CdcParams {
    /// Minimum chunk size in bytes. Default 8 KiB.
    pub min_size: u32,
    /// Average chunk size in bytes. Default 64 KiB.
    pub avg_size: u32,
    /// Maximum chunk size in bytes. Default 256 KiB.
    pub max_size: u32,
}

impl Default for CdcParams {
    fn default() -> Self {
        Self {
            min_size: 8 * 1024,
            avg_size: 64 * 1024,
            max_size: 256 * 1024,
        }
    }
}

impl CdcParams {
    /// Validate `FastCDC` invariants: min < avg < max, none zero, all within
    /// reasonable bounds (max ≤ 16 MiB for sanity).
    ///
    /// # Errors
    ///
    /// Returns `ChunkError::InvalidParameters` if any invariant is violated.
    pub fn validate(self) -> Result<(), ChunkError> {
        if self.min_size == 0 || self.avg_size == 0 || self.max_size == 0 {
            return Err(ChunkError::InvalidParameters(
                "min/avg/max sizes must be positive",
            ));
        }
        if self.min_size >= self.avg_size {
            return Err(ChunkError::InvalidParameters(
                "min_size must be strictly less than avg_size",
            ));
        }
        if self.avg_size >= self.max_size {
            return Err(ChunkError::InvalidParameters(
                "avg_size must be strictly less than max_size",
            ));
        }
        if self.max_size > 16 * 1024 * 1024 {
            return Err(ChunkError::InvalidParameters("max_size must be ≤ 16 MiB"));
        }
        Ok(())
    }
}

/// One CDC boundary: a single chunk's range and its BLAKE3 raw address.
///
/// `start..end` is the half-open byte range within the input buffer.
/// `length()` returns `end - start`. `raw_address` is the BLAKE3-256 of the
/// chunk plaintext per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md)
/// rule 1 (raw chunk addressing).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Boundary {
    /// Inclusive start offset within the input buffer.
    pub start: usize,
    /// Exclusive end offset within the input buffer.
    pub end: usize,
    /// BLAKE3-256 hash of `input[start..end]`.
    pub raw_address: [u8; 32],
}

impl Boundary {
    /// Length of this chunk in bytes.
    #[inline]
    pub fn length(&self) -> usize {
        self.end - self.start
    }
}

/// Streaming CDC scanner over a byte slice.
///
/// Iterates chunk boundaries lazily; per-iteration cost is dominated by
/// the underlying `FastCDC` scan plus a single BLAKE3 hash of the discovered
/// chunk. Callers consume `(start, end, blake3_hash)` triples without
/// holding the whole boundary list in memory.
pub struct ChunkScanner<'a> {
    inner: fastcdc::v2020::FastCDC<'a>,
    buffer: &'a [u8],
}

impl std::fmt::Debug for ChunkScanner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkScanner")
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

impl<'a> ChunkScanner<'a> {
    /// Create a scanner over `buffer` with the default ADR-0001 parameters.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self::with_params(buffer, CdcParams::default()).expect("default CdcParams are always valid")
    }

    /// Create a scanner over `buffer` with custom CDC parameters.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError::InvalidParameters` if `params` violates
    /// `FastCDC` invariants.
    pub fn with_params(buffer: &'a [u8], params: CdcParams) -> Result<Self, ChunkError> {
        params.validate()?;
        let inner =
            fastcdc::v2020::FastCDC::new(buffer, params.min_size, params.avg_size, params.max_size);
        Ok(Self { inner, buffer })
    }
}

impl Iterator for ChunkScanner<'_> {
    type Item = Boundary;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.inner.next()?;
        let start = chunk.offset;
        let end = chunk.offset + chunk.length;
        debug_assert!(end <= self.buffer.len());
        let raw_address = blake3_wrap::chunk_address_raw(&self.buffer[start..end]);
        Some(Boundary {
            start,
            end,
            raw_address,
        })
    }
}

/// Convenience: scan a buffer and collect all boundaries into a Vec.
///
/// Equivalent to `ChunkScanner::new(buffer).collect()`. Useful for tests
/// and one-shot ingest paths that don't need streaming.
#[must_use]
pub fn scan_to_vec(buffer: &[u8]) -> Vec<Boundary> {
    ChunkScanner::new(buffer).collect()
}

/// Threshold above which `scan_to_vec_parallel` parallelizes BLAKE3
/// hashing across the discovered boundaries via Rayon. Below this size
/// the threadpool dispatch overhead dominates the win.
const PARALLEL_HASH_MIN_BYTES: usize = 1024 * 1024;

/// Scan a buffer and collect boundaries, hashing chunks in parallel
/// via Rayon for buffers ≥ 1 MiB.
///
/// `FastCDC` boundary discovery is inherently sequential (the rolling
/// hash carries state across bytes), but BLAKE3 of each discovered
/// chunk is independent and dominates the cycles/byte budget on multi-
/// core hosts. We split the work into two passes:
///
///  1. Sequential: walk the input via `FastCDC`, emit `(start, end)` ranges.
///  2. Parallel: hash each `(start, end)` slice via Rayon's work-stealing
///     pool. The output preserves boundary order.
///
/// Below `PARALLEL_HASH_MIN_BYTES`, falls back to the single-threaded
/// path.
#[must_use]
pub fn scan_to_vec_parallel(buffer: &[u8]) -> Vec<Boundary> {
    scan_to_vec_parallel_with_params(buffer, CdcParams::default())
        .expect("default CdcParams are always valid")
}

/// Parameterized parallel scanner used by workload-aware callers.
///
/// The caller chooses the `FastCDC` profile, while boundary determinism and
/// parallel BLAKE3 addressing remain identical to the default scanner.
pub fn scan_to_vec_parallel_with_params(
    buffer: &[u8],
    params: CdcParams,
) -> Result<Vec<Boundary>, ChunkError> {
    params.validate()?;
    if buffer.len() < PARALLEL_HASH_MIN_BYTES {
        return Ok(ChunkScanner::with_params(buffer, params)?.collect());
    }
    let ranges: Vec<(usize, usize)> =
        fastcdc::v2020::FastCDC::new(buffer, params.min_size, params.avg_size, params.max_size)
            .map(|c| (c.offset, c.offset + c.length))
            .collect();

    Ok(ranges
        .par_iter()
        .map(|&(start, end)| Boundary {
            start,
            end,
            raw_address: blake3_wrap::chunk_address_raw(&buffer[start..end]),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_yields_no_boundaries() {
        let scanner = ChunkScanner::new(b"");
        assert_eq!(scanner.count(), 0);
    }

    #[test]
    fn small_buffer_yields_single_chunk() {
        // Buffer well below min_size: FastCDC emits a single trailing chunk.
        let buf = vec![0xABu8; 4096];
        let scanner = ChunkScanner::new(&buf);
        let boundaries: Vec<_> = scanner.collect();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].start, 0);
        assert_eq!(boundaries[0].end, 4096);
        // Raw address must equal BLAKE3 of the full buffer.
        let expected = blake3::hash(&buf);
        assert_eq!(boundaries[0].raw_address, *expected.as_bytes());
    }

    #[test]
    fn one_megabyte_yields_multiple_chunks_in_size_range() {
        // 1 MiB of pseudo-random content via deterministic xorshift.
        let mut rng_state: u64 = 0x1234_5678_DEAD_BEEF;
        let mut buf = vec![0u8; 1024 * 1024];
        for byte in &mut buf {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            *byte = (rng_state & 0xFF) as u8;
        }

        let boundaries = scan_to_vec(&buf);
        assert!(
            !boundaries.is_empty(),
            "1 MiB random buffer should produce at least one boundary",
        );

        // Every chunk respects min/max bounds (except possibly the last one,
        // which may be smaller than min_size when it's the remainder).
        let params = CdcParams::default();
        for (i, b) in boundaries.iter().enumerate() {
            let len = b.length();
            let is_last = i == boundaries.len() - 1;
            assert!(
                len <= params.max_size as usize,
                "chunk {i} exceeds max: {len}",
            );
            if !is_last {
                assert!(
                    len >= params.min_size as usize,
                    "interior chunk {i} below min: {len}",
                );
            }
        }

        // Coverage: chunks tile the buffer exactly.
        assert_eq!(boundaries[0].start, 0);
        assert_eq!(boundaries.last().unwrap().end, buf.len());
        for w in boundaries.windows(2) {
            assert_eq!(w[0].end, w[1].start, "boundaries not contiguous");
        }
    }

    #[test]
    fn invalid_params_rejected() {
        let buf = vec![0u8; 1024];
        let bad = CdcParams {
            min_size: 1024,
            avg_size: 1024, // not strictly greater than min
            max_size: 4096,
        };
        let result = ChunkScanner::with_params(&buf, bad);
        assert!(matches!(result, Err(ChunkError::InvalidParameters(_))));
    }

    #[test]
    fn deterministic_across_runs() {
        let buf = vec![0xCDu8; 200_000];
        let a = scan_to_vec(&buf);
        let b = scan_to_vec(&buf);
        assert_eq!(a, b, "CDC must be deterministic across runs");
    }

    #[test]
    fn boundary_addresses_match_blake3() {
        let buf = (0u8..255).cycle().take(150_000).collect::<Vec<_>>();
        for boundary in scan_to_vec(&buf) {
            let expected = blake3::hash(&buf[boundary.start..boundary.end]);
            assert_eq!(
                boundary.raw_address,
                *expected.as_bytes(),
                "raw_address must equal BLAKE3 of chunk content",
            );
        }
    }
}
