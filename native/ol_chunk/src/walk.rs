//! Record-header walkers for the length-framed containers (ISO BMFF, MCAP,
//! RIFF/WAV), written once and run over two byte sources: an in-memory slice
//! ([`Memory`], behind `format_aware::{mp4_box_offsets, mcap_record_offsets,
//! wav_data_offset}` and the in-memory scanner) and a seekable reader's header
//! window (`stream::Headers`, behind the `*_seekable` functions and the file
//! scanner).
//!
//! Sharing one walker is what makes the file API equal the in-memory API on
//! every input. Two hand-maintained copies had drifted: the seekable MP4
//! walker used checked arithmetic, the in-memory copy evaluated `pos + 8` after
//! a 64-bit box size had moved `pos` to within 8 bytes of `usize::MAX`, so the
//! sum wrapped, the loop condition held and the header read indexed out of
//! bounds (16 bytes, `0000000166747970fffffffffffffffc`, aborted the host
//! under `panic = "abort"`).
//!
//! Every size field is attacker-controlled. The walkers never add to a
//! position unchecked: a byte range is requested as `(pos, n)` and the source
//! refuses one whose end overflows or passes the end, and each advance is a
//! `u64` converted with `usize::try_from` and added with `checked_add`. Each
//! advance is at least 8 bytes, so every walk terminates.
//!
//! The walkers are pull-style: [`RecordWalk::next`] returns the next record
//! start together with the first `min(HEAD_BYTES, len - pos)` bytes there,
//! borrowed from the source, from the same window access that read the record
//! header. The caller can therefore hand the head to the cut selector without
//! a copy and then use the source itself (to write segments) before pulling
//! the next record.

use crate::format_aware::MCAP_MAGIC;
use crate::select::HEAD_BYTES;
use std::convert::Infallible;

/// Read access by absolute offset to a container of known length.
pub(crate) trait ByteSource {
    /// What a read can fail with: [`Infallible`] in memory, `io::Error` for a file.
    type Error;

    /// Total length of the container in bytes.
    fn len(&self) -> usize;

    /// The `n` bytes at `pos`, or `None` if `pos + n` overflows or exceeds [`Self::len`].
    fn at(&mut self, pos: usize, n: usize) -> Result<Option<&[u8]>, Self::Error>;
}

/// A whole container held in memory.
pub(crate) struct Memory<'a>(pub(crate) &'a [u8]);

impl ByteSource for Memory<'_> {
    type Error = Infallible;

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn at(&mut self, pos: usize, n: usize) -> Result<Option<&[u8]>, Infallible> {
        Ok(pos.checked_add(n).and_then(|end| self.0.get(pos..end)))
    }
}

/// `pos + advance`, or `None` when it is not a representable position.
#[inline]
fn advance_by(pos: usize, advance: u64) -> Option<usize> {
    pos.checked_add(usize::try_from(advance).ok()?)
}

const MCAP_RECORD_HEADER: usize = 9;

/// A walk over the top-level records of one container format.
#[derive(Debug)]
pub(crate) enum RecordWalk {
    /// ISO BMFF top-level boxes from offset 0.
    Mp4 {
        /// Offset of the next box header to read.
        pos: usize,
    },
    /// MCAP v0 records; the magic, Header opcode and trailing magic are
    /// checked on the first pull.
    McapStart,
    /// MCAP records within `[pos, data_end)`.
    Mcap {
        /// Offset of the next record header to read.
        pos: usize,
        /// End of the record area (the trailing magic, when present, excluded).
        data_end: usize,
    },
    /// The walk has stopped.
    Done,
}

impl RecordWalk {
    /// A walk over top-level ISO BMFF boxes.
    ///
    /// A header is `[size: u32 BE][type: 4 bytes]`; `size == 1` means a 64-bit
    /// size follows (a 16-byte header) and `size == 0` means the box runs to
    /// the end of the file, so it is the last one returned. The walk stops at
    /// a type that is not four ASCII alphanumerics/spaces, at a size below 8
    /// (which could not advance), at a header that does not fit in the source,
    /// and at a size whose end is not a representable position.
    pub(crate) fn mp4() -> Self {
        Self::Mp4 { pos: 0 }
    }

    /// A walk over complete top-level MCAP v0 records.
    ///
    /// Records are `[opcode: u8][content_len: u64 LE][content]` after the
    /// 8-byte magic, and the first must be a Header (opcode `0x01`). A trailing
    /// magic, when present, is excluded from the record area; a crashed
    /// recording without one still yields its complete prefix records. The walk
    /// stops at opcode 0 and at a record that does not end within the record
    /// area. Reads happen in the order leading header, trailing magic, records.
    pub(crate) fn mcap() -> Self {
        Self::McapStart
    }

    /// The next record start and the first `min(HEAD_BYTES, len - pos)` bytes
    /// there, or `None` once the walk has stopped.
    #[inline]
    pub(crate) fn next<'s, S: ByteSource>(
        &mut self,
        src: &'s mut S,
    ) -> Result<Option<(usize, &'s [u8])>, S::Error> {
        let len = src.len();
        match *self {
            Self::Mp4 { pos } => {
                let n = HEAD_BYTES.min(len.saturating_sub(pos));
                let Some(head) = src.at(pos, n)? else {
                    *self = Self::Done;
                    return Ok(None);
                };
                if n < 8
                    || !head[4..8]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
                {
                    *self = Self::Done;
                    return Ok(None);
                }
                let advance = match u32::from_be_bytes([head[0], head[1], head[2], head[3]]) {
                    // Runs to the end of the file: the last box.
                    0 => None,
                    // A 64-bit size needs the full 16-byte header.
                    1 if n < 16 => None,
                    1 => Some(u64::from_be_bytes([
                        head[8], head[9], head[10], head[11], head[12], head[13], head[14],
                        head[15],
                    ])),
                    short => Some(u64::from(short)),
                };
                *self = match advance
                    .filter(|&advance| advance >= 8)
                    .and_then(|advance| advance_by(pos, advance))
                {
                    Some(next) => Self::Mp4 { pos: next },
                    None => Self::Done,
                };
                Ok(Some((pos, head)))
            }
            Self::McapStart => {
                const MAGIC_LEN: usize = MCAP_MAGIC.len();
                *self = Self::Done;
                if len < MAGIC_LEN + MCAP_RECORD_HEADER {
                    return Ok(None);
                }
                match src.at(0, MAGIC_LEN + 1)? {
                    Some(head) if head[..MAGIC_LEN] == MCAP_MAGIC && head[MAGIC_LEN] == 0x01 => {}
                    _ => return Ok(None),
                }
                let data_end = if len >= 2 * MAGIC_LEN
                    && src
                        .at(len - MAGIC_LEN, MAGIC_LEN)?
                        .is_some_and(|tail| tail == MCAP_MAGIC)
                {
                    len - MAGIC_LEN
                } else {
                    len
                };
                *self = Self::Mcap {
                    pos: MAGIC_LEN,
                    data_end,
                };
                self.next(src)
            }
            Self::Mcap { pos, data_end } => {
                *self = Self::Done;
                if pos
                    .checked_add(MCAP_RECORD_HEADER)
                    .is_none_or(|end| end > data_end)
                {
                    return Ok(None);
                }
                // pos + 9 <= data_end <= len, so the head holds the record header.
                let n = HEAD_BYTES.min(len - pos);
                let Some(head) = src.at(pos, n)? else {
                    return Ok(None);
                };
                if head[0] == 0 {
                    return Ok(None);
                }
                let content_len = u64::from_le_bytes([
                    head[1], head[2], head[3], head[4], head[5], head[6], head[7], head[8],
                ]);
                let Some(next) = pos
                    .checked_add(MCAP_RECORD_HEADER)
                    .and_then(|body| advance_by(body, content_len))
                    .filter(|&next| next <= data_end)
                else {
                    return Ok(None);
                };
                *self = Self::Mcap {
                    pos: next,
                    data_end,
                };
                Ok(Some((pos, head)))
            }
            Self::Done => Ok(None),
        }
    }
}

/// Offset of the `data` sub-chunk header of a RIFF/WAVE container.
///
/// Sub-chunks after the 12-byte `RIFF....WAVE` preamble are
/// `[id: 4][size: u32 LE][payload][pad byte if size is odd]`. The walk stops
/// at a sub-chunk header that does not fit in the source.
pub(crate) fn find_wav_data<S: ByteSource>(src: &mut S) -> Result<Option<usize>, S::Error> {
    match src.at(0, 12)? {
        Some(head) if &head[0..4] == b"RIFF" && &head[8..12] == b"WAVE" => {}
        _ => return Ok(None),
    }
    let mut pos = 12usize;
    while let Some(chunk) = src.at(pos, 8)? {
        if &chunk[0..4] == b"data" {
            return Ok(Some(pos));
        }
        let size = u64::from(u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]));
        // At most 8 + (2^32 - 1) + 1: no u64 overflow, and always >= 8.
        let Some(next) = advance_by(pos, 8 + size + (size & 1)) else {
            break;
        };
        pos = next;
    }
    Ok(None)
}
