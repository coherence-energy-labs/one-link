//! Record-header walkers for the length-framed containers (ISO BMFF, MCAP,
//! RIFF/WAV), written once and run over two byte sources: an in-memory slice
//! ([`Memory`], behind `format_aware::{mp4_box_offsets, mcap_record_offsets,
//! wav_data_offset}`) and a seekable reader's header window (`stream::Headers`,
//! behind the `*_seekable` functions and the file scanner).
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

use crate::format_aware::MCAP_MAGIC;
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

    fn len(&self) -> usize {
        self.0.len()
    }

    fn at(&mut self, pos: usize, n: usize) -> Result<Option<&[u8]>, Infallible> {
        Ok(pos.checked_add(n).and_then(|end| self.0.get(pos..end)))
    }
}

/// `pos + advance`, or `None` when it is not a representable position.
fn advance_by(pos: usize, advance: u64) -> Option<usize> {
    pos.checked_add(usize::try_from(advance).ok()?)
}

/// Visit the start offset of every top-level ISO BMFF box, in order.
///
/// A header is `[size: u32 BE][type: 4 bytes]`; `size == 1` means a 64-bit
/// size follows (a 16-byte header) and `size == 0` means the box runs to the
/// end of the file, so it is the last one visited. The walk stops at a type
/// that is not four ASCII alphanumerics/spaces, at a size below 8 (which could
/// not advance), at a header that does not fit in the source, and at a size
/// whose end is not a representable position.
pub(crate) fn walk_mp4_boxes<S: ByteSource>(
    src: &mut S,
    mut visit: impl FnMut(&mut S, usize) -> Result<(), S::Error>,
) -> Result<(), S::Error> {
    let mut pos = 0usize;
    while let Some(header) = src.at(pos, 8)? {
        let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        if !header[4..8]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
        {
            break;
        }
        visit(src, pos)?;
        let advance = match size {
            0 => break,
            1 => {
                let Some(extended) = src.at(pos, 16)? else {
                    break;
                };
                let mut be = [0u8; 8];
                be.copy_from_slice(&extended[8..16]);
                u64::from_be_bytes(be)
            }
            n => u64::from(n),
        };
        if advance < 8 {
            break;
        }
        let Some(next) = advance_by(pos, advance) else {
            break;
        };
        pos = next;
    }
    Ok(())
}

/// Visit the start offset of every complete top-level MCAP v0 record.
///
/// Records are `[opcode: u8][content_len: u64 LE][content]` after the 8-byte
/// magic, and the first must be a Header (opcode `0x01`). A trailing magic,
/// when present, is excluded from the record area; a crashed recording without
/// one still yields its complete prefix records. The walk stops at opcode 0 and
/// at a record that does not end within the record area. Reads happen in the
/// order leading header, trailing magic, records: the seekable scanner's
/// read-ahead pattern depends on it.
pub(crate) fn walk_mcap_records<S: ByteSource>(
    src: &mut S,
    mut visit: impl FnMut(&mut S, usize) -> Result<(), S::Error>,
) -> Result<(), S::Error> {
    const RECORD_HEADER: usize = 9;
    const MAGIC_LEN: usize = MCAP_MAGIC.len();
    let len = src.len();
    if len < MAGIC_LEN + RECORD_HEADER {
        return Ok(());
    }
    match src.at(0, MAGIC_LEN + 1)? {
        Some(head) if head[..MAGIC_LEN] == MCAP_MAGIC && head[MAGIC_LEN] == 0x01 => {}
        _ => return Ok(()),
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
    let mut pos = MAGIC_LEN;
    while pos
        .checked_add(RECORD_HEADER)
        .is_some_and(|end| end <= data_end)
    {
        let Some(header) = src.at(pos, RECORD_HEADER)? else {
            break;
        };
        if header[0] == 0 {
            break;
        }
        let mut raw_len = [0u8; 8];
        raw_len.copy_from_slice(&header[1..RECORD_HEADER]);
        let content_len = u64::from_le_bytes(raw_len);
        let Some(next) = pos
            .checked_add(RECORD_HEADER)
            .and_then(|body| advance_by(body, content_len))
        else {
            break;
        };
        if next > data_end {
            break;
        }
        visit(src, pos)?;
        pos = next;
    }
    Ok(())
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
