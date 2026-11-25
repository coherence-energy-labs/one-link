//! Error types for `ol_chunk`.
//!
//! Pyo3 bindings in `one_link_native` map these to Python exceptions per
//! [ADR-0008](../../../docs/decisions/0008-ffi-contract.md).

use thiserror::Error;

/// Errors produced by chunk-layer operations.
#[derive(Debug, Error)]
pub enum ChunkError {
    /// CDC scan was given a buffer that is too small to chunk safely.
    /// This is not necessarily an error in itself (a 0-byte buffer is
    /// trivially a single empty chunk) but it can indicate a caller bug.
    #[error("buffer too small for CDC scan: got {got} bytes, minimum {min}")]
    BufferTooSmall {
        /// Buffer length received.
        got: usize,
        /// Minimum length required (typically the CDC min chunk size).
        min: usize,
    },

    /// CDC parameters violate an ordering invariant (`min < avg < max`) or
    /// cannot be used by the chunk kernel. Range violations are reported as
    /// [`ChunkError::SizeOutOfRange`].
    #[error("invalid CDC parameters: {0}")]
    InvalidParameters(&'static str),

    /// A CDC size lies outside the range the `FastCDC` v2020 kernel accepts.
    ///
    /// The kernel `assert!`s these ranges; the bounds are its own exported
    /// constants (`fastcdc::v2020::MINIMUM_MIN` ... `MAXIMUM_MAX`), so they
    /// cannot drift from the library. Under the release profile's
    /// `panic = "abort"` a size that passed validation but failed the
    /// kernel's assertion terminated the host process.
    #[error(
        "invalid CDC parameters: {field} = {value} is outside the FastCDC range {min}..={max}"
    )]
    SizeOutOfRange {
        /// The offending field: `min_size`, `avg_size` or `max_size`.
        field: &'static str,
        /// The value supplied.
        value: u32,
        /// Smallest value the kernel accepts for this field.
        min: u32,
        /// Largest value the kernel accepts for this field.
        max: u32,
    },

    /// The chunk kernel produced a cut that does not advance. Unreachable
    /// with validated parameters; it is reported instead of looping, which
    /// is what a zero-length cut did (the boundary vector doubled until the
    /// allocator gave up).
    #[error("CDC kernel made no progress at offset {offset} of a {len}-byte buffer")]
    NoProgress {
        /// Offset at which the zero-length cut was produced.
        offset: usize,
        /// Length of the buffer being chunked.
        len: usize,
    },

    /// AEAD frame size requested is incompatible with the chunk size
    /// distribution. Frame size must divide the maximum chunk size cleanly.
    #[error("AEAD frame size {frame} incompatible with chunk size {chunk}")]
    FrameSizeMismatch {
        /// Frame size in bytes.
        frame: usize,
        /// Chunk size in bytes.
        chunk: usize,
    },
}
