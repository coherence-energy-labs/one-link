//! `ol_compress` — payload-aware compression dispatcher.
//!
//! Decision point D14 from `intergration map.txt`. Replaces the
//! daemon's static zstd-everywhere with a per-payload choice:
//!
//!   - tiny msgs (< 4 KiB)              → none (overhead > savings)
//!   - already-compressed (zip/mp4/jpg) → none
//!   - sync ops < 8 KiB                 → lz4 (fast, ~3 GiB/s decode)
//!   - bulk file > 1 MiB                → zstd level 3 (balanced)
//!   - background sync                  → zstd level 9 (more CPU OK)
//!
//! ## Why this matters
//!
//! Static zstd on a small chat msg adds ~10-20 bytes of header overhead
//! for a payload that's already barely compressible. Worse, zstd's
//! CPU cost for the round-trip exceeds the byte savings on most chat
//! messages — net throughput goes DOWN.
//!
//! lz4 has lower CPU overhead but compresses worse than zstd. For
//! sync operations (CRDT diffs, ACKs) the speed matters more than
//! ratio, so lz4 wins there.
//!
//! For bulk files, zstd at level 3 (default) gives ~2-3x ratio at
//! ~500 MiB/s on modern CPUs. Level 9 is for background tasks where
//! the extra ~10% ratio is worth the ~2x CPU.
//!
//! ## Surface
//!
//! - [`Algorithm`] — enum of supported codecs
//! - [`Dispatcher::pick`] — choose codec from `(kind, size, hint)`
//! - [`Dispatcher::compress`] / [`Dispatcher::decompress`] — codec-tagged round-trip
//! - [`CompressError`] — for invalid inputs / round-trip failures

#![doc(html_root_url = "https://docs.rs/ol_compress/0.21.0")]

pub mod dispatcher;
pub mod error;
pub mod onemem;
pub mod rc;

pub use dispatcher::{
    Algorithm, Dispatcher, EventKind, PreCompressed, MAX_COMPRESSED_PAYLOAD_BYTES,
    MAX_DECOMPRESSED_BYTES,
};
pub use error::CompressError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
