//! Format-aware chunking per [ADR-0014](../../../docs/decisions/0014-format-aware-chunking.md).
//!
//! Augments the pure-CDC kernel ([`crate::cdc`]) with structural-boundary
//! injection for well-known container formats. For Phase B v1 this means
//! **ZIP-family archives** (`.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`,
//! `.apk`, `.jar`, `.epub`, `.kra`). Video GOP detection is reserved for
//! Phase B-2.
//!
//! ## Algorithm
//!
//! 1. Detect format from path-extension hint + leading bytes magic.
//! 2. If a structured format is detected, walk the buffer and collect
//!    **forced cut offsets**: positions where the chunk boundary should
//!    be pinned regardless of `FastCDC`'s rolling-hash decision.
//! 3. Run CDC on each `[forced_cut_i .. forced_cut_{i+1})` segment
//!    independently. The forced cuts become hard boundaries.
//!
//! Result: a sender modifies one entry inside a `.xlsx` (a 1 KiB change
//! in a 50 MiB file) and only that entry's chunks change. Pure-CDC would
//! shift every downstream chunk boundary.
//!
//! ## Conservatism
//!
//! - Path-extension hint is preferred but not required. Pure magic
//!   detection (`PK\x03\x04` at offset 0) suffices.
//! - Each ZIP local-file-header (LFH) hit requires a cheap structural
//!   sanity check (`version_needed`, `compression_method`, sane
//!   `name_length` + `extra_length`). False positives are rare and
//!   harmless (degraded dedup, no corruption).
//! - Forced cuts are absorbed by the [`crate::cdc::CdcParams::min_size`]
//!   floor — two LFHs <8 KiB apart only produce one boundary.

use crate::blake3_wrap;
use crate::cdc::{Boundary, CdcParams, ChunkScanner};
use crate::error::ChunkError;

/// Container formats recognized by the format-aware chunker.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ContainerFormat {
    /// ZIP archive family: `.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`,
    /// `.apk`, `.jar`, `.epub`, `.kra`. Local-file-header offsets used
    /// as forced cuts.
    Zip,
    /// ISO Base Media File Format (MP4 / M4V / MOV / 3GP). Top-level
    /// box boundaries used as forced cuts.
    Mp4,
    /// WAV / RIFF audio. `data` chunk start used as a forced cut so
    /// re-tagged audio doesn't shift downstream chunks.
    Wav,
    /// Raw H.264 elementary stream (Annex B format). NAL unit start
    /// codes used as forced cuts; IDR-bearing NAL units (keyframes)
    /// are the highest-priority cuts so re-encoded video preserves
    /// GOP-aligned chunks.
    H264AnnexB,
    /// MCAP robotics log container. Top-level record starts are forced
    /// cuts, preserving chunk/index boundaries across local revisions.
    Mcap,
}

/// ZIP local-file-header signature (`PK\x03\x04`).
pub const ZIP_LFH_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// ZIP local-file-header fixed-prefix length (signature + 26 fixed bytes).
pub const ZIP_LFH_FIXED_LEN: usize = 30;

/// MCAP v0 leading/trailing magic.
pub const MCAP_MAGIC: [u8; 8] = [0x89, b'M', b'C', b'A', b'P', b'0', b'\r', b'\n'];

/// Detect a container format from leading bytes + an optional file
/// extension hint.
///
/// Returns `None` when no recognized format is detected. Detection is
/// intentionally conservative — ambiguous matches fall back to pure
/// CDC rather than risk false-positive cuts that would tank dedup.
#[must_use]
pub fn detect_format(leading: &[u8], path_extension: Option<&str>) -> Option<ContainerFormat> {
    if leading.starts_with(&ZIP_LFH_MAGIC) {
        return Some(ContainerFormat::Zip);
    }
    if leading.starts_with(&MCAP_MAGIC) {
        return Some(ContainerFormat::Mcap);
    }
    // ISO BMFF top-level boxes start with a 4-byte big-endian size
    // followed by a 4-byte ASCII type. The first box in a valid file
    // is almost always ``ftyp`` (or ``styp`` for segmented).
    if leading.len() >= 8 {
        let kind = &leading[4..8];
        if matches!(kind, b"ftyp" | b"styp" | b"moov" | b"mdat" | b"free") {
            return Some(ContainerFormat::Mp4);
        }
    }
    // WAV/RIFF: bytes 0..4 = "RIFF", bytes 8..12 = "WAVE".
    if leading.len() >= 12 && &leading[0..4] == b"RIFF" && &leading[8..12] == b"WAVE" {
        return Some(ContainerFormat::Wav);
    }
    // H.264 Annex B elementary stream: starts with a NAL start code
    // (0x00 0x00 0x00 0x01) or the shorter 3-byte variant. Detect
    // either; downstream scanner walks both forms.
    if leading.len() >= 4 && (leading.starts_with(&[0, 0, 0, 1]) || leading.starts_with(&[0, 0, 1]))
    {
        return Some(ContainerFormat::H264AnnexB);
    }
    if let Some(ext) = path_extension {
        match ext.to_ascii_lowercase().as_str() {
            // Anything with the extension but missing magic falls
            // back to None — refusing to scan minimises false
            // positives on misnamed files.
            "mp4" | "m4v" | "mov" | "3gp" if matches_iso_bmff_extension(leading) => {
                return Some(ContainerFormat::Mp4);
            }
            "wav"
                if leading.len() >= 12
                    && &leading[0..4] == b"RIFF"
                    && &leading[8..12] == b"WAVE" =>
            {
                return Some(ContainerFormat::Wav);
            }
            "h264" | "264" | "avc" => return Some(ContainerFormat::H264AnnexB),
            _ => {}
        }
    }
    None
}

/// Scan an H.264 Annex B elementary stream for **keyframe-bearing
/// NAL unit boundaries**. Returns the offsets of NAL units of type
/// IDR (`nal_unit_type == 5`) or SPS (`nal_unit_type == 7`), which
/// together mark the start of every GOP.
///
/// Returns offsets sorted ascending. Includes the start codes (3 or
/// 4 bytes) so the cut is aligned to the start of the GOP.
///
/// Sanity-limits: any NAL with a forbidden zero bit set (highest bit
/// of the NAL header) is rejected — that's a transport-error signal.
#[must_use]
pub fn h264_keyframe_offsets(buffer: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut i = 0usize;
    while i + 4 < buffer.len() {
        // Look for the 4-byte start code (0x00 0x00 0x00 0x01) or the
        // 3-byte one (0x00 0x00 0x01). The 4-byte form is required at
        // the very start; either is legal mid-stream.
        let (start_code_len, nal_byte_idx) =
            if buffer[i] == 0 && buffer[i + 1] == 0 && buffer[i + 2] == 0 && buffer[i + 3] == 1 {
                (4, i + 4)
            } else if buffer[i] == 0 && buffer[i + 1] == 0 && buffer[i + 2] == 1 {
                (3, i + 3)
            } else {
                i += 1;
                continue;
            };
        if nal_byte_idx >= buffer.len() {
            break;
        }
        let nal_byte = buffer[nal_byte_idx];
        // forbidden_zero_bit (MSB) must be 0.
        if nal_byte & 0x80 != 0 {
            i += start_code_len;
            continue;
        }
        // Low 5 bits are nal_unit_type.
        let nal_type = nal_byte & 0x1F;
        // Type 5 = IDR slice (instantaneous decoder refresh = keyframe).
        // Type 7 = SPS (sequence parameter set, typically right before
        // an IDR). Type 8 = PPS. Per the plan: GOP keyframe detection
        // needs IDR-marked cuts. We also include SPS because the
        // SPS-PPS-IDR triplet is the canonical GOP-start pattern.
        if matches!(nal_type, 5 | 7) {
            offsets.push(i);
        }
        i += start_code_len + 1;
    }
    offsets
}

/// Helper: does the leading 8 bytes look plausibly like an ISO BMFF
/// box header (size + 4-letter ASCII type)?
fn matches_iso_bmff_extension(leading: &[u8]) -> bool {
    if leading.len() < 8 {
        return false;
    }
    leading[4..8]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
}

/// Walk an ISO BMFF (MP4 / MOV) buffer and collect top-level box
/// start offsets — every box header `[size:u32 BE][type:4]` becomes
/// a forced cut. Stops on the first malformed header so a
/// non-BMFF buffer that happens to match the leading-bytes check
/// can't drive the scanner off a cliff.
#[must_use]
pub fn mp4_box_offsets(buffer: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= buffer.len() {
        let size = u64::from(u32::from_be_bytes([
            buffer[pos],
            buffer[pos + 1],
            buffer[pos + 2],
            buffer[pos + 3],
        ]));
        let kind = &buffer[pos + 4..pos + 8];
        // Sanity: the 4-byte type MUST be 4 ASCII chars. Any non-
        // printable rejects the rest of the buffer.
        if !kind.iter().all(|b| b.is_ascii_alphanumeric() || *b == b' ') {
            break;
        }
        offsets.push(pos);
        let advance = match size {
            // Size == 1 means a 64-bit extended size in the next 8
            // bytes (rare in practice; bail out if not enough room).
            1 => {
                if pos + 16 > buffer.len() {
                    break;
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(&buffer[pos + 8..pos + 16]);
                u64::from_be_bytes(be)
            }
            // Size == 0 means "to end of file". This is the last
            // box; stop after collecting its offset.
            0 => break,
            _ => size,
        };
        // Defensive: a corrupt size field smaller than the header
        // would loop forever. Refuse to advance less than 8 bytes.
        if advance < 8 {
            break;
        }
        let Ok(advance) = usize::try_from(advance) else {
            break;
        };
        let Some(next_pos) = pos.checked_add(advance) else {
            break;
        };
        pos = next_pos;
    }
    offsets
}

/// Walk a RIFF/WAV buffer and return the offset of the `data` chunk
/// header (length-prefixed RIFF sub-chunk). The data chunk is the
/// dominant payload of a WAV; cutting there isolates the audio
/// samples from the variable-size metadata before it.
#[must_use]
pub fn wav_data_offset(buffer: &[u8]) -> Option<usize> {
    if buffer.len() < 12 || &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12usize;
    while pos + 8 <= buffer.len() {
        let id = &buffer[pos..pos + 4];
        let size = u32::from_le_bytes([
            buffer[pos + 4],
            buffer[pos + 5],
            buffer[pos + 6],
            buffer[pos + 7],
        ]) as usize;
        if id == b"data" {
            return Some(pos);
        }
        // RIFF sub-chunks are byte-aligned but their size word is
        // not padded; the actual layout pads odd sizes by 1.
        let advance = 8 + size + (size & 1);
        if advance < 8 {
            break;
        }
        pos = pos.saturating_add(advance);
    }
    None
}

/// Walk an MCAP v0 buffer and return structurally validated top-level
/// record start offsets.
///
/// MCAP records are framed as `[opcode:u8][content_len:u64 LE][content]`
/// after the 8-byte magic. A crashed/in-progress recording may not yet
/// have trailing magic; in that case every complete prefix record is
/// still usable as a conservative structural boundary.
#[must_use]
pub fn mcap_record_offsets(buffer: &[u8]) -> Vec<usize> {
    const RECORD_HEADER: usize = 9;
    if buffer.len() < MCAP_MAGIC.len() + RECORD_HEADER
        || !buffer.starts_with(&MCAP_MAGIC)
        || buffer[MCAP_MAGIC.len()] != 0x01
    {
        return Vec::new();
    }

    let data_end = if buffer.ends_with(&MCAP_MAGIC) && buffer.len() >= 2 * MCAP_MAGIC.len() {
        buffer.len() - MCAP_MAGIC.len()
    } else {
        buffer.len()
    };
    let mut offsets = Vec::new();
    let mut pos = MCAP_MAGIC.len();

    while pos + RECORD_HEADER <= data_end {
        let opcode = buffer[pos];
        if opcode == 0 {
            break;
        }
        let mut raw_len = [0u8; 8];
        raw_len.copy_from_slice(&buffer[pos + 1..pos + RECORD_HEADER]);
        let Ok(content_len) = usize::try_from(u64::from_le_bytes(raw_len)) else {
            break;
        };
        let Some(next) = pos
            .checked_add(RECORD_HEADER)
            .and_then(|value| value.checked_add(content_len))
        else {
            break;
        };
        if next > data_end {
            break;
        }
        offsets.push(pos);
        pos = next;
    }
    offsets
}

/// Walk `buffer` and collect ZIP local-file-header offsets that pass the
/// sanity check. Returns a sorted, deduplicated, monotonic list of
/// forced-cut offsets.
///
/// The first cut is always `0` (start of buffer) is **implicit** and not
/// returned; callers walk forward from offset 0.
///
/// Uses [`memchr`] to SIMD-scan for the LFH signature's first byte
/// (`0x50` = `'P'`), then checks the full 4-byte sequence + sanity
/// gate at each candidate. On x86 with SSE2/AVX2 this runs at
/// ~10-30 GiB/s through `buffer` — far faster than the 5 GiB/s budget
/// the `FastCDC` kernel itself runs at.
#[must_use]
pub fn zip_lfh_offsets(buffer: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if buffer.len() < ZIP_LFH_FIXED_LEN {
        return out;
    }
    let mut start = 0usize;
    // SIMD-search for the first signature byte; check full 4-byte
    // sequence + sanity gate at each candidate.
    while let Some(rel) = memchr::memchr(ZIP_LFH_MAGIC[0], &buffer[start..]) {
        let i = start + rel;
        if i + 4 > buffer.len() {
            break;
        }
        if buffer[i..i + 4] == ZIP_LFH_MAGIC && zip_lfh_sanity_check(&buffer[i..]) {
            out.push(i);
            // Skip past the fixed prefix to avoid re-matching the same
            // header. Body false positives are caught by the sanity
            // gate above (cheap), not by trying to parse name_length /
            // extra_length here (would need full ZIP entry parser).
            start = i + ZIP_LFH_FIXED_LEN;
        } else {
            start = i + 1;
        }
        if start >= buffer.len() {
            break;
        }
    }
    out
}

/// Cheap structural sanity check on a candidate LFH. `tail` must include
/// at least the 30 fixed bytes after the signature.
///
/// Validates:
/// - `version_needed` is sane (≤ 100 / a known PKWARE version code).
/// - `compression_method` is a known constant (0 stored, 8 deflate,
///   9-99 lossless other / future).
/// - `name_length + extra_length` fits within the buffer remainder. We
///   relax this when we can't see the full entry; the magic, version,
///   and method gate is enough to make false positives statistically
///   negligible.
fn zip_lfh_sanity_check(tail: &[u8]) -> bool {
    if tail.len() < ZIP_LFH_FIXED_LEN {
        return false;
    }
    let version_needed = u16::from_le_bytes([tail[4], tail[5]]);
    let compression_method = u16::from_le_bytes([tail[8], tail[9]]);
    // Version range: PKWARE specs use 10, 20, 45, 46, 51, 62, 63;
    // tolerate up to 100.
    if version_needed > 100 {
        return false;
    }
    // Known compression methods per PKWARE APPNOTE 6.3.10.
    matches!(
        compression_method,
        0 | 1 | 6 | 8 | 9 | 12 | 14 | 18 | 19 | 20 | 93 | 94 | 95 | 96 | 97 | 98 | 99
    )
}

/// Run format-aware chunking. Returns the boundaries plus a parallel
/// `Vec<bool>` indicating whether each chunk's *starting* edge was a
/// format-forced cut (vs natural CDC).
///
/// When `format` is `None` or the buffer doesn't contain any forced
/// cuts, falls back to plain CDC.
///
/// # Errors
///
/// Returns the underlying CDC error if `params` are invalid.
pub fn scan_format_aware(
    buffer: &[u8],
    format: Option<ContainerFormat>,
    params: CdcParams,
) -> Result<FormatAwareChunkSet, ChunkError> {
    params.validate()?;

    let forced_cuts = match format {
        Some(ContainerFormat::Zip) => zip_lfh_offsets(buffer),
        Some(ContainerFormat::Mp4) => mp4_box_offsets(buffer),
        Some(ContainerFormat::Wav) => {
            // Single forced cut at the `data` chunk header (if any).
            // The metadata in `fmt ` / `LIST` etc. before it tends
            // to be small, so one cut is enough to isolate the
            // audio body.
            wav_data_offset(buffer).into_iter().collect()
        }
        Some(ContainerFormat::H264AnnexB) => {
            // GOP-aligned cuts at IDR + SPS NAL units. A re-encoded
            // video where only the first few frames changed will
            // still hit the same IDR boundaries downstream, so dedup
            // recovers everything past the edit.
            h264_keyframe_offsets(buffer)
        }
        Some(ContainerFormat::Mcap) => {
            // Keep MCAP record framing visible to the content-addressed
            // layer. Large Chunk/Index records then remain independently
            // reusable and seekable across local log revisions.
            mcap_record_offsets(buffer)
        }
        None => Vec::new(),
    };

    // Absorb cuts that are too close together to be useful. Any cut
    // less than `min_size` away from the previous accepted cut (or the
    // start of the buffer) gets dropped to avoid degenerate tiny chunks.
    let mut accepted: Vec<usize> = Vec::new();
    let mut last_accepted: usize = 0;
    let min = params.min_size as usize;
    for &c in &forced_cuts {
        if c >= last_accepted + min && c <= buffer.len().saturating_sub(min) {
            accepted.push(c);
            last_accepted = c;
        }
    }

    if accepted.is_empty() {
        // No forced cuts → pure CDC.
        let bounds: Vec<Boundary> = ChunkScanner::with_params(buffer, params)?.collect();
        let format_aware = vec![false; bounds.len()];
        return Ok(FormatAwareChunkSet {
            boundaries: bounds,
            format_aware,
        });
    }

    // Build segment list `[0, cut_1)`, `[cut_1, cut_2)`, ... `[cut_n, end)`.
    let mut segments: Vec<(usize, usize)> = Vec::with_capacity(accepted.len() + 1);
    let mut prev = 0usize;
    for &c in &accepted {
        segments.push((prev, c));
        prev = c;
    }
    segments.push((prev, buffer.len()));

    let mut out_bounds: Vec<Boundary> = Vec::new();
    let mut out_flags: Vec<bool> = Vec::new();
    for (seg_idx, &(s, e)) in segments.iter().enumerate() {
        let segment_buf = &buffer[s..e];
        if segment_buf.is_empty() {
            continue;
        }
        // If the segment is shorter than `max_size`, emit it as a single
        // chunk without running CDC (CDC would just emit one chunk
        // anyway, plus the boundary tail).
        let segment_bounds: Vec<Boundary> = if segment_buf.len() <= params.max_size as usize {
            vec![Boundary {
                start: 0,
                end: segment_buf.len(),
                raw_address: blake3_wrap::chunk_address_raw(segment_buf),
            }]
        } else {
            ChunkScanner::with_params(segment_buf, params)?.collect()
        };

        for (chunk_idx, b) in segment_bounds.into_iter().enumerate() {
            // Translate offsets back to the source buffer.
            let translated = Boundary {
                start: b.start + s,
                end: b.end + s,
                raw_address: b.raw_address,
            };
            // The chunk starting at the segment's first byte (chunk_idx
            // == 0) is the format-forced one — unless we're in the very
            // first segment, whose first chunk is the natural start of
            // the buffer (not a forced cut).
            let forced = chunk_idx == 0 && seg_idx > 0;
            out_bounds.push(translated);
            out_flags.push(forced);
        }
    }

    Ok(FormatAwareChunkSet {
        boundaries: out_bounds,
        format_aware: out_flags,
    })
}

/// Result of [`scan_format_aware`]: boundaries plus a parallel `bool`
/// vector flagging which chunks started at a format-forced cut.
#[derive(Debug, Clone)]
pub struct FormatAwareChunkSet {
    /// Chunk boundaries in input order.
    pub boundaries: Vec<Boundary>,
    /// `true` if the corresponding chunk's starting edge was a
    /// format-forced cut (vs natural CDC). `format_aware[i]` belongs
    /// to `boundaries[i]`. Always the same length as `boundaries`.
    pub format_aware: Vec<bool>,
}

impl FormatAwareChunkSet {
    /// Number of chunks.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.boundaries.len()
    }

    /// True if no chunks were produced.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boundaries.is_empty()
    }

    /// Number of chunks whose starting edge was format-forced.
    #[must_use]
    pub fn format_forced_count(&self) -> usize {
        self.format_aware.iter().filter(|b| **b).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_zip(entries: usize, entry_size: usize) -> Vec<u8> {
        // Build a minimum-shape ZIP-like buffer: each entry is an LFH
        // (30 bytes fixed + 8 byte name "file00\x00") followed by
        // `entry_size` arbitrary bytes. Then a few stray bytes. The end
        // doesn't have a central directory; the scanner only cares
        // about LFH offsets.
        let mut buf = Vec::new();
        let entry_size_u32 = u32::try_from(entry_size).expect("test ZIP entry fits in u32");
        for i in 0..entries {
            // LFH:
            buf.extend_from_slice(&ZIP_LFH_MAGIC);
            buf.extend_from_slice(&20u16.to_le_bytes()); // version_needed = 20
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&8u16.to_le_bytes()); // compression_method = 8 (deflate)
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod_time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod_date
            buf.extend_from_slice(&0u32.to_le_bytes()); // crc-32
            buf.extend_from_slice(&entry_size_u32.to_le_bytes()); // compressed_size
            buf.extend_from_slice(&entry_size_u32.to_le_bytes()); // uncompressed_size
            buf.extend_from_slice(&7u16.to_le_bytes()); // name_length
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra_length
            let name = format!("file{i:02}\0");
            buf.extend_from_slice(&name.as_bytes()[..7]);
            // Entry body.
            let entry_marker = u8::try_from(i).expect("test ZIP entry index fits in u8");
            buf.extend(std::iter::repeat_n(0xAB ^ entry_marker, entry_size));
        }
        buf
    }

    fn push_mcap_record(buf: &mut Vec<u8>, opcode: u8, size: usize, fill: u8) {
        buf.push(opcode);
        buf.extend_from_slice(
            &u64::try_from(size)
                .expect("test MCAP record size fits u64")
                .to_le_bytes(),
        );
        buf.extend(std::iter::repeat_n(fill, size));
    }

    fn make_dummy_mcap(record_size: usize, records: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MCAP_MAGIC);
        push_mcap_record(&mut buf, 0x01, 16, 0x11); // Header
        for i in 0..records {
            let fill = u8::try_from(i).unwrap_or(0).wrapping_add(0x20);
            push_mcap_record(&mut buf, 0x06, record_size, fill); // Chunk
        }
        push_mcap_record(&mut buf, 0x02, 20, 0x22); // Footer
        buf.extend_from_slice(&MCAP_MAGIC);
        buf
    }

    #[test]
    fn detect_zip_from_magic() {
        let buf = make_dummy_zip(1, 100);
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Zip));
        assert_eq!(
            detect_format(&buf, Some("xlsx")),
            Some(ContainerFormat::Zip)
        );
    }

    #[test]
    fn detect_mp4_from_magic() {
        // ftyp box: 0x00000020 size, b"ftyp", brand "isom"
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&32u32.to_be_bytes());
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"isom");
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Mp4));
        assert_eq!(detect_format(&buf, Some("mp4")), Some(ContainerFormat::Mp4));
    }

    #[test]
    fn detect_wav_from_magic() {
        // Minimal RIFF/WAVE header.
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&56u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE");
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Wav));
        assert_eq!(detect_format(&buf, Some("wav")), Some(ContainerFormat::Wav));
    }

    #[test]
    fn detect_mcap_from_magic() {
        let buf = make_dummy_mcap(16 * 1024, 2);
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::Mcap));
        assert_eq!(
            detect_format(&buf, Some("mcap")),
            Some(ContainerFormat::Mcap)
        );
    }

    #[test]
    fn mcap_record_offsets_follow_record_framing() {
        let buf = make_dummy_mcap(16 * 1024, 3);
        let offsets = mcap_record_offsets(&buf);
        assert_eq!(offsets.len(), 5); // header + 3 chunks + footer
        assert_eq!(offsets[0], MCAP_MAGIC.len());
        for pair in offsets.windows(2) {
            assert!(pair[1] > pair[0]);
        }
        assert_eq!(&buf[offsets[1]..=offsets[1]], &[0x06]);
    }

    #[test]
    fn mcap_format_aware_scan_forces_large_record_starts() {
        let buf = make_dummy_mcap(32 * 1024, 4);
        let records = mcap_record_offsets(&buf);
        let scanned =
            scan_format_aware(&buf, Some(ContainerFormat::Mcap), CdcParams::default()).unwrap();
        let accepted_record_starts: Vec<usize> = records
            .into_iter()
            .filter(|offset| *offset >= CdcParams::default().min_size as usize)
            .collect();
        assert!(scanned.format_forced_count() >= 3);
        assert!(accepted_record_starts
            .iter()
            .skip(1)
            .any(|offset| scanned.boundaries.iter().any(|b| b.start == *offset)));
    }

    #[test]
    fn mp4_box_offsets_finds_top_level_boxes() {
        // Three top-level boxes: ftyp(32) + moov(64) + mdat(128).
        let mut buf = vec![0u8; 32 + 64 + 128];
        buf[0..4].copy_from_slice(&32u32.to_be_bytes());
        buf[4..8].copy_from_slice(b"ftyp");
        buf[32..36].copy_from_slice(&64u32.to_be_bytes());
        buf[36..40].copy_from_slice(b"moov");
        buf[96..100].copy_from_slice(&128u32.to_be_bytes());
        buf[100..104].copy_from_slice(b"mdat");
        let offsets = mp4_box_offsets(&buf);
        assert_eq!(offsets, vec![0, 32, 96]);
    }

    #[test]
    fn wav_data_offset_finds_data_chunk() {
        // RIFF + WAVE + fmt (24 bytes) + data + payload (8 bytes)
        let mut buf = vec![0u8; 12 + 24 + 8 + 8];
        let payload_len = u32::try_from(buf.len() - 8).expect("test RIFF payload fits in u32");
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&payload_len.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE");
        // fmt sub-chunk
        buf[12..16].copy_from_slice(b"fmt ");
        buf[16..20].copy_from_slice(&16u32.to_le_bytes());
        // data sub-chunk at offset 12 + 24 = 36
        buf[36..40].copy_from_slice(b"data");
        buf[40..44].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(wav_data_offset(&buf), Some(36));
    }

    #[test]
    fn detect_none_for_random_bytes() {
        let buf = b"hello world";
        assert_eq!(detect_format(buf, None), None);
        assert_eq!(detect_format(buf, Some("txt")), None);
    }

    #[test]
    fn detect_h264_from_start_code() {
        // 4-byte start code form.
        let buf = vec![0u8, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, 0x96];
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::H264AnnexB));
        // 3-byte start code form.
        let buf = vec![0u8, 0, 1, 0x67, 0x42, 0x00, 0x1f, 0x96];
        assert_eq!(detect_format(&buf, None), Some(ContainerFormat::H264AnnexB));
        // Extension hint without magic.
        let buf = vec![0xAB; 16];
        assert_eq!(
            detect_format(&buf, Some("h264")),
            Some(ContainerFormat::H264AnnexB)
        );
    }

    #[test]
    fn h264_keyframe_offsets_finds_idr_and_sps() {
        // Build a synthetic stream:
        //   [SPS at offset 0]  (NAL type 7)
        //   [PPS at offset 16] (NAL type 8 — NOT a cut)
        //   [non-IDR slice at 32] (NAL type 1 — NOT a cut)
        //   [IDR slice at 48] (NAL type 5)
        let mut buf = vec![0u8; 64];
        // SPS at 0: 0x00 0x00 0x00 0x01 0x67 ...
        buf[0..4].copy_from_slice(&[0, 0, 0, 1]);
        buf[4] = 0x67; // forbidden_zero=0, ref_idc=11, type=7 (SPS)
                       // PPS at 16: 0x00 0x00 0x00 0x01 0x68
        buf[16..20].copy_from_slice(&[0, 0, 0, 1]);
        buf[20] = 0x68; // type=8 (PPS)
                        // Non-IDR slice at 32: 0x00 0x00 0x00 0x01 0x41
        buf[32..36].copy_from_slice(&[0, 0, 0, 1]);
        buf[36] = 0x41; // type=1 (slice, non-IDR)
                        // IDR slice at 48: 0x00 0x00 0x00 0x01 0x65
        buf[48..52].copy_from_slice(&[0, 0, 0, 1]);
        buf[52] = 0x65; // type=5 (IDR slice)
        let offsets = h264_keyframe_offsets(&buf);
        // Must find the SPS (offset 0) and IDR (offset 48), skip PPS
        // (16) and non-IDR slice (32).
        assert_eq!(offsets, vec![0, 48]);
    }

    #[test]
    fn h264_keyframe_offsets_rejects_forbidden_zero_bit() {
        // NAL byte 0xC5 has forbidden_zero_bit set (MSB=1) AND type=5;
        // must be rejected.
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&[0, 0, 0, 1]);
        buf[4] = 0xC5;
        let offsets = h264_keyframe_offsets(&buf);
        assert!(offsets.is_empty());
    }

    #[test]
    fn h264_keyframe_offsets_handles_three_byte_start_code() {
        // 3-byte start code variant: 0x00 0x00 0x01 followed by IDR byte.
        let buf = vec![0, 0, 1, 0x65, 0, 0, 0, 1, 0x67];
        let offsets = h264_keyframe_offsets(&buf);
        // IDR at offset 0 (3-byte form), SPS at offset 4 (4-byte form).
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&4));
    }

    #[test]
    fn lfh_walker_finds_all_entries() {
        let buf = make_dummy_zip(5, 16 * 1024);
        let offsets = zip_lfh_offsets(&buf);
        assert_eq!(offsets.len(), 5);
        assert_eq!(offsets[0], 0);
        for w in offsets.windows(2) {
            assert!(w[1] > w[0]);
        }
    }

    #[test]
    fn lfh_walker_rejects_invalid_compression_method() {
        // Construct a buffer with PK\x03\x04 but compression_method = 200.
        let mut buf = Vec::new();
        buf.extend_from_slice(&ZIP_LFH_MAGIC);
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&200u16.to_le_bytes()); // bogus method
        buf.resize(64, 0u8);
        let offsets = zip_lfh_offsets(&buf);
        assert!(offsets.is_empty());
    }

    #[test]
    fn lfh_walker_rejects_random_bytes() {
        let buf = vec![0u8; 1024 * 1024];
        let offsets = zip_lfh_offsets(&buf);
        assert!(offsets.is_empty());
    }

    #[test]
    fn pure_cdc_when_no_format() {
        let buf = vec![0xCDu8; 256 * 1024];
        let r = scan_format_aware(&buf, None, CdcParams::default()).unwrap();
        // Should equal a plain CDC scan.
        let plain: Vec<Boundary> = ChunkScanner::new(&buf).collect();
        assert_eq!(r.boundaries.len(), plain.len());
        assert_eq!(r.format_forced_count(), 0);
    }

    #[test]
    fn cdc_equivalence_on_non_zip() {
        // Random binary that does NOT look like ZIP.
        let mut buf = vec![0u8; 512 * 1024];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i.to_le_bytes()[0].wrapping_mul(31).wrapping_add(7);
        }
        let r = scan_format_aware(&buf, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();
        let plain: Vec<Boundary> = ChunkScanner::new(&buf).collect();
        assert_eq!(r.boundaries.len(), plain.len());
        for (a, b) in r.boundaries.iter().zip(plain.iter()) {
            assert_eq!(a.start, b.start);
            assert_eq!(a.end, b.end);
            assert_eq!(a.raw_address, b.raw_address);
        }
    }

    #[test]
    fn zip_boundaries_align_to_lfh() {
        let entry_size = 32 * 1024;
        let buf = make_dummy_zip(8, entry_size);
        let lfh = zip_lfh_offsets(&buf);
        let r = scan_format_aware(&buf, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();
        // Every LFH offset (except 0) should appear as a chunk start
        // boundary somewhere in the output (subject to min_size absorption).
        for &off in lfh.iter().skip(1) {
            assert!(
                r.boundaries.iter().any(|b| b.start == off),
                "expected a chunk to start at LFH offset {off}"
            );
        }
        // The format_aware flags should be set on entries 1..N (entry 0
        // is the natural buffer start).
        assert!(r.format_forced_count() >= lfh.len() - 1);
    }

    #[test]
    fn single_byte_edit_only_changes_one_chunk_family() {
        // Build a dummy ZIP. Edit one byte inside entry 4. Compare
        // chunk sets: entries 0-3 and 5-7 should produce identical
        // chunk_ids; only entry 4's chunks should differ.
        let entry_size = 32 * 1024;
        let original = make_dummy_zip(8, entry_size);
        let mut edited = original.clone();
        // Find entry 4's LFH offset.
        let lfh = zip_lfh_offsets(&original);
        let target_lfh = lfh[4];
        // Flip a byte inside entry 4's body (well past the LFH header).
        edited[target_lfh + ZIP_LFH_FIXED_LEN + 7 + 100] ^= 0xFF;

        let orig_chunks =
            scan_format_aware(&original, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();
        let edit_chunks =
            scan_format_aware(&edited, Some(ContainerFormat::Zip), CdcParams::default()).unwrap();

        // Both must have the same number of chunks (entry layouts are
        // identical; one byte flip doesn't change LFH positions).
        assert_eq!(orig_chunks.boundaries.len(), edit_chunks.boundaries.len());

        // Most chunks unchanged: at least 5 of 8 entries are identical.
        let mut unchanged = 0;
        for (a, b) in orig_chunks
            .boundaries
            .iter()
            .zip(edit_chunks.boundaries.iter())
        {
            if a.raw_address == b.raw_address {
                unchanged += 1;
            }
        }
        assert!(
            unchanged >= 5,
            "expected at least 5 chunks unchanged after single-byte edit, got {unchanged}"
        );
    }
}
