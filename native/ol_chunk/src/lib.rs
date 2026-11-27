//! `ol_chunk` — content-defined chunking and content-addressed identifiers
//! for One Link's file engine v2.
//!
//! This crate implements the foundational chunk-layer primitives:
//!
//! 1. **`FastCDC` kernel** with parameters fixed by [ADR-0001]: 8 KiB minimum,
//!    64 KiB average, 256 KiB maximum chunk size. Gear-256 rolling hash
//!    with the standard `FastCDC` published mask parameters.
//!
//! 2. **BLAKE3 chunk addressing** in two flavours per [ADR-0006]:
//!    - **raw address**: plain `BLAKE3.hash(plaintext)` — content-addressed
//!      identifier for chunks under non-convergent encryption.
//!    - **convergent address**: `BLAKE3.derive_key("ol-chunk-addr-convergent-v1", plaintext)`
//!      — content-addressed identifier for chunks under convergent
//!      encryption. Cross-sender deduplication holds: same plaintext → same
//!      address from any peer.
//!
//! 3. **Domain-separated subkey derivation** for downstream crates per
//!    [ADR-0006]. The full registered context list is in `blake3_wrap`.
//!
//! 4. **Pure-Rust API**. Pyo3 bindings live in the `one_link_native` umbrella
//!    crate which depends on this crate; this crate has no Python coupling.
//!
//! ## Throughput target
//!
//! Per [ADR-0001] verification gate: ≥ 2 GiB/s/core scalar; ≥ 5 GiB/s/core
//! with AVX-512 / NEON dispatch via the underlying `fastcdc` crate's SIMD
//! features. BLAKE3 hashing is ≥ 3 GiB/s/core via the reference SIMD impl.
//! Joint throughput target: ≥ 1 GiB/s end-to-end ingest on the engine's
//! Phase A1 acceptance hardware.
//!
//! ## Determinism
//!
//! Same input → same chunk boundaries on every architecture. SIMD changes
//! microarchitecture, not byte-output. Cross-platform property tests in
//! `tests/cross_platform.rs` validate this.
//!
//! [ADR-0001]: ../../../docs/decisions/0001-cdc-kernel.md
//! [ADR-0006]: ../../../docs/decisions/0006-blake3-derive-scheme.md

#![doc(html_root_url = "https://docs.rs/ol_chunk/0.21.0")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod blake3_wrap;
pub mod cdc;
pub mod error;
pub mod format_aware;
pub mod frame;
pub mod pcdc;
mod select;
pub mod stream;
mod walk;

pub use blake3_wrap::{
    chunk_address_convergent, chunk_address_raw, derive_aead_key, derive_ratchet_key_id,
    derive_stripe_seed, DerivationContext,
};
pub use cdc::{
    scan_to_vec, scan_to_vec_parallel, scan_to_vec_parallel_with_params, Boundary, CdcParams,
    ChunkScanner,
};
pub use error::ChunkError;
pub use format_aware::{
    detect_format, scan_format_aware, zip_lfh_offsets, ContainerFormat, FormatAwareChunkSet,
    ZIP_LFH_FIXED_LEN, ZIP_LFH_MAGIC,
};
pub use frame::{frame_count_for_plaintext, AEAD_FRAME_PLAINTEXT_LEN, AEAD_TAG_LEN};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the format-aware chunk-boundary definition.
///
/// A store may record this next to a manifest. Two manifests chunked under
/// the same value and the same [`CdcParams`] have identical boundaries for
/// identical bytes; across values they share boundaries only where the rules
/// agree (for 1 and 2: containers whose records are all at least `min_size`).
/// Content addressing stays correct either way; only deduplication between
/// the two differs. It is deliberately independent of the crate version,
/// which changes for reasons that do not move a boundary.
///
/// * `1`: every structural candidate, then min-size absorption. On records
///   denser than `min_size` that degenerates to fixed-size chunking.
/// * `2`: local, content-defined candidate selection, then the same
///   absorption (see `select.rs` and ADR-0014 amendment 1).
///
/// Plain CDC ([`scan_to_vec_parallel`], `cdc_file`) is not versioned by this
/// constant; its boundaries are pinned by `tests/fixtures/cdc_golden_v1.txt`.
pub const FORMAT_AWARE_CHUNKING_VERSION: u32 = 2;
