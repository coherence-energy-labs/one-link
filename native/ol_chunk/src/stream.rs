//! Bounded-memory chunking of files: plain `FastCDC` and format-aware.
//!
//! [`scan_stream`] chunks `len` bytes read from any [`Read`] holding at most
//! one window, with boundaries equal to [`crate::ChunkScanner`]'s over the same
//! bytes (parallel two-phase scan per window, a chunk accepted only once its
//! cut has seen `max_size` bytes or the end).
//!
//! [`scan_format_aware_seekable`] is [`scan_format_aware`] for a seekable
//! source too large to hold: for record-framed containers (MCAP, ISO BMFF,
//! RIFF/WAV) the forced cuts are found by walking record HEADERS -- a seek and
//! a few bytes per record -- and every segment between cuts is chunked by
//! [`scan_stream`] over its byte range. The result equals `scan_format_aware`
//! on the whole file's bytes. Containers whose cuts need a full byte scan (ZIP,
//! H.264 Annex B) are read whole up to `in_memory_limit`; above it the scan
//! reports [`StreamScanError::NeedsWholeFile`] and the caller decides.

use std::io::{self, Read, Seek, SeekFrom};

use crate::blake3_wrap;
use crate::cdc::{Boundary, CdcParams};
use crate::format_aware::{scan_format_aware, ContainerFormat, FormatAwareChunkSet, MCAP_MAGIC};
use crate::pcdc;

/// The window [`scan_stream`] holds (never more than the source's length).
pub const STREAM_WINDOW: usize = 32 << 20;

/// Read-ahead used to walk record headers.
const HEADER_READ_AHEAD: usize = 64 << 10;

/// Why a seekable format-aware scan did not produce boundaries.
#[derive(Debug)]
pub enum StreamScanError {
    /// Reading the source failed.
    Io(io::Error),
    /// The `CdcParams` are invalid.
    Params(crate::ChunkError),
    /// The format's cuts need a byte scan of the whole source, which is larger
    /// than the caller's in-memory limit.
    NeedsWholeFile {
        /// Source length in bytes.
        len: usize,
        /// The caller's limit.
        limit: usize,
    },
}

impl std::fmt::Display for StreamScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "read failed: {err}"),
            Self::Params(err) => write!(f, "invalid CDC parameters: {err}"),
            Self::NeedsWholeFile { len, limit } => write!(
                f,
                "this format's cuts need the whole file in memory ({len} bytes > limit {limit})"
            ),
        }
    }
}

impl std::error::Error for StreamScanError {}

impl From<io::Error> for StreamScanError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// `FastCDC` over the `len` bytes `reader` yields, holding at most one window.
/// Boundaries are relative to the reader's start.
pub fn scan_stream<R: Read>(reader: R, len: usize, params: CdcParams) -> io::Result<Vec<Boundary>> {
    scan_stream_windowed(reader, len, params, STREAM_WINDOW)
}

fn scan_stream_windowed<R: Read>(
    mut reader: R,
    len: usize,
    params: CdcParams,
    window: usize,
) -> io::Result<Vec<Boundary>> {
    params
        .validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let max_size = params.max_size as usize;
    // Sized to the source when it is small (a fixed window was zero-filled
    // for every small file once, halving ingest).
    let mut window_cap = window.max(4 * max_size).min(len.max(1));
    let mut buffer: Vec<u8> = Vec::with_capacity(window_cap);
    let mut base = 0usize;
    let mut eof = false;
    let mut out = Vec::new();
    loop {
        while buffer.len() < window_cap && !eof {
            let wanted = (window_cap - buffer.len()) as u64;
            let read = (&mut reader).take(wanted).read_to_end(&mut buffer)?;
            eof = read == 0;
        }
        if buffer.is_empty() {
            break;
        }
        let ranges: Vec<(usize, usize)> = pcdc::chunk_ranges(&buffer, params)
            .into_iter()
            .take_while(|&(s, _)| eof || s + max_size <= buffer.len())
            .collect();
        let consumed = ranges.last().map_or(0, |&(_, e)| e);
        if consumed == 0 {
            if eof {
                return Err(io::Error::other("stream scan made no progress"));
            }
            // A window that exactly fits the source fills before EOF is seen:
            // its last chunk cannot be final yet, so grow and read on.
            window_cap = window_cap.saturating_mul(2).max(4 * max_size);
            continue;
        }
        for b in pcdc::address_ranges(&buffer, &ranges) {
            let start = base
                .checked_add(b.start)
                .ok_or_else(|| io::Error::other("offset overflow"))?;
            out.push(Boundary {
                start,
                end: start + (b.end - b.start),
                raw_address: b.raw_address,
            });
        }
        base += consumed;
        buffer.copy_within(consumed.., 0);
        buffer.truncate(buffer.len() - consumed);
        if eof && buffer.is_empty() {
            break;
        }
    }
    // The source must hold exactly the bytes it was declared to: a file that
    // shrank or grew while it was scanned is an error, never a chunk set that
    // silently describes other bytes.
    if base != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("source holds {base} bytes, declared {len}"),
        ));
    }
    Ok(out)
}

/// Random access to a seekable source through a forward read-ahead window.
struct Headers<'a, R> {
    source: &'a mut R,
    len: usize,
    window: Vec<u8>,
    window_start: usize,
}

impl<'a, R: Read + Seek> Headers<'a, R> {
    fn new(source: &'a mut R, len: usize) -> Self {
        Self {
            source,
            len,
            window: Vec::new(),
            window_start: 0,
        }
    }

    /// The `n` bytes at `pos`, or `None` if they run past the source.
    fn at(&mut self, pos: usize, n: usize) -> io::Result<Option<&[u8]>> {
        let Some(end) = pos.checked_add(n) else {
            return Ok(None);
        };
        if end > self.len {
            return Ok(None);
        }
        let held = pos >= self.window_start && end <= self.window_start + self.window.len();
        if !held {
            let want = HEADER_READ_AHEAD.max(n).min(self.len - pos);
            self.source.seek(SeekFrom::Start(pos as u64))?;
            self.window.clear();
            (&mut *self.source)
                .take(want as u64)
                .read_to_end(&mut self.window)?;
            self.window_start = pos;
            if self.window.len() < n {
                return Ok(None);
            }
        }
        let offset = pos - self.window_start;
        Ok(Some(&self.window[offset..offset + n]))
    }
}

/// [`crate::format_aware::mcap_record_offsets`] over a seekable source of
/// `len` bytes, reading only record headers.
pub fn mcap_record_offsets_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Vec<usize>> {
    const RECORD_HEADER: usize = 9;
    let magic_len = MCAP_MAGIC.len();
    let mut h = Headers::new(source, len);
    if len < magic_len + RECORD_HEADER {
        return Ok(Vec::new());
    }
    match h.at(0, magic_len + 1)? {
        Some(head) if head[..magic_len] == MCAP_MAGIC && head[magic_len] == 0x01 => {}
        _ => return Ok(Vec::new()),
    }
    let data_end = if len >= 2 * magic_len
        && h.at(len - magic_len, magic_len)?
            .is_some_and(|tail| tail == MCAP_MAGIC)
    {
        len - magic_len
    } else {
        len
    };
    let mut offsets = Vec::new();
    let mut pos = magic_len;
    while pos + RECORD_HEADER <= data_end {
        let Some(header) = h.at(pos, RECORD_HEADER)? else {
            break;
        };
        if header[0] == 0 {
            break;
        }
        let mut raw_len = [0u8; 8];
        raw_len.copy_from_slice(&header[1..RECORD_HEADER]);
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
    Ok(offsets)
}

/// [`crate::format_aware::mp4_box_offsets`] over a seekable source.
pub fn mp4_box_offsets_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Vec<usize>> {
    let mut h = Headers::new(source, len);
    let mut offsets = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= len {
        let Some(header) = h.at(pos, 8)? else {
            break;
        };
        let size = u64::from(u32::from_be_bytes([
            header[0], header[1], header[2], header[3],
        ]));
        if !header[4..8]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
        {
            break;
        }
        offsets.push(pos);
        let advance = match size {
            1 => {
                let Some(large) = h.at(pos + 8, 8)? else {
                    break;
                };
                let mut be = [0u8; 8];
                be.copy_from_slice(large);
                u64::from_be_bytes(be)
            }
            0 => break,
            _ => size,
        };
        if advance < 8 {
            break;
        }
        let Ok(advance) = usize::try_from(advance) else {
            break;
        };
        let Some(next) = pos.checked_add(advance) else {
            break;
        };
        pos = next;
    }
    Ok(offsets)
}

/// [`crate::format_aware::wav_data_offset`] over a seekable source.
pub fn wav_data_offset_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Option<usize>> {
    let mut h = Headers::new(source, len);
    match h.at(0, 12)? {
        Some(head) if &head[0..4] == b"RIFF" && &head[8..12] == b"WAVE" => {}
        _ => return Ok(None),
    }
    let mut pos = 12usize;
    while pos + 8 <= len {
        let Some(chunk) = h.at(pos, 8)? else {
            break;
        };
        if &chunk[0..4] == b"data" {
            return Ok(Some(pos));
        }
        let size = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as usize;
        let advance = 8 + size + (size & 1);
        pos = pos.saturating_add(advance);
    }
    Ok(None)
}

/// [`scan_format_aware`] over a seekable source of `len` bytes with bounded
/// memory (see the module documentation). Equal to `scan_format_aware` on the
/// source's bytes.
pub fn scan_format_aware_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
    format: Option<ContainerFormat>,
    params: CdcParams,
    in_memory_limit: usize,
) -> Result<FormatAwareChunkSet, StreamScanError> {
    params.validate().map_err(StreamScanError::Params)?;
    let forced_cuts = match format {
        Some(ContainerFormat::Mcap) => mcap_record_offsets_seekable(source, len)?,
        Some(ContainerFormat::Mp4) => mp4_box_offsets_seekable(source, len)?,
        Some(ContainerFormat::Wav) => wav_data_offset_seekable(source, len)?.into_iter().collect(),
        None => Vec::new(),
        Some(ContainerFormat::Zip | ContainerFormat::H264AnnexB) => {
            if len > in_memory_limit {
                return Err(StreamScanError::NeedsWholeFile {
                    len,
                    limit: in_memory_limit,
                });
            }
            let mut bytes = Vec::with_capacity(len);
            source.seek(SeekFrom::Start(0))?;
            (&mut *source).take(len as u64).read_to_end(&mut bytes)?;
            return scan_format_aware(&bytes, format, params).map_err(StreamScanError::Params);
        }
    };

    // The absorption rule of scan_format_aware, verbatim.
    let mut accepted: Vec<usize> = Vec::new();
    let mut last_accepted = 0usize;
    let min = params.min_size as usize;
    for &c in &forced_cuts {
        if c >= last_accepted + min && c <= len.saturating_sub(min) {
            accepted.push(c);
            last_accepted = c;
        }
    }

    if accepted.is_empty() {
        source.seek(SeekFrom::Start(0))?;
        let boundaries = scan_stream(&mut *source, len, params)?;
        let format_aware = vec![false; boundaries.len()];
        return Ok(FormatAwareChunkSet {
            boundaries,
            format_aware,
        });
    }

    let mut segments = Vec::with_capacity(accepted.len() + 1);
    let mut prev = 0usize;
    for &c in &accepted {
        segments.push((prev, c));
        prev = c;
    }
    segments.push((prev, len));

    let mut boundaries = Vec::new();
    let mut format_aware = Vec::new();
    let mut segment_bytes = Vec::new();
    for (seg_idx, &(s, e)) in segments.iter().enumerate() {
        if s == e {
            continue;
        }
        source.seek(SeekFrom::Start(s as u64))?;
        let local: Vec<Boundary> = if e - s <= params.max_size as usize {
            segment_bytes.clear();
            (&mut *source)
                .take((e - s) as u64)
                .read_to_end(&mut segment_bytes)?;
            if segment_bytes.len() != e - s {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "source shrank").into());
            }
            vec![Boundary {
                start: 0,
                end: e - s,
                raw_address: blake3_wrap::chunk_address_raw(&segment_bytes),
            }]
        } else {
            scan_stream((&mut *source).take((e - s) as u64), e - s, params)?
        };
        for (chunk_idx, b) in local.into_iter().enumerate() {
            boundaries.push(Boundary {
                start: b.start + s,
                end: b.end + s,
                raw_address: b.raw_address,
            });
            format_aware.push(chunk_idx == 0 && seg_idx > 0);
        }
    }
    Ok(FormatAwareChunkSet {
        boundaries,
        format_aware,
    })
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // fixtures: PRNG bytes and small sizes, truncation intended
mod tests {
    use super::*;
    use crate::cdc::ChunkScanner;
    use crate::format_aware::{mcap_record_offsets, mp4_box_offsets, wav_data_offset};
    use std::io::Cursor;

    fn bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn small() -> CdcParams {
        CdcParams {
            min_size: 1024,
            avg_size: 4096,
            max_size: 16384,
        }
    }

    #[test]
    fn stream_scan_equals_the_in_memory_scanner_across_windows() {
        for (n, window) in [
            (0, 64),
            (1, 64),
            (900, 64),
            (70_000, 65_536),
            (300_000, 65_536),
            (1_000_003, 100_000),
        ] {
            let data = bytes(n, n as u64 + 7);
            let want: Vec<Boundary> = ChunkScanner::with_params(&data, small()).unwrap().collect();
            let got = scan_stream_windowed(Cursor::new(&data), n, small(), window).unwrap();
            assert_eq!(got, want, "n={n} window={window}");
        }
    }

    /// A synthetic MCAP: magic, a header record, then records of the given
    /// content sizes, optionally the trailing magic.
    fn mcap(sizes: &[usize], trailing_magic: bool, seed: u64) -> Vec<u8> {
        let mut out = MCAP_MAGIC.to_vec();
        out.push(0x01);
        out.extend_from_slice(&4u64.to_le_bytes());
        out.extend_from_slice(b"ros2");
        for (i, &size) in sizes.iter().enumerate() {
            out.push(if i % 7 == 6 { 0x06 } else { 0x05 });
            out.extend_from_slice(&(size as u64).to_le_bytes());
            out.extend_from_slice(&bytes(size, seed + i as u64));
        }
        if trailing_magic {
            out.extend_from_slice(&MCAP_MAGIC);
        }
        out
    }

    fn mcap_cases() -> Vec<Vec<u8>> {
        let big = 70_000;
        let mut cases = vec![
            mcap(&[10, 20, 30], true, 1),
            mcap(&[5_000, 40_000, big, 200, 3, 900_000], true, 2),
            mcap(&[5_000, 40_000, big], false, 3), // crashed recording: no trailing magic
            mcap(&[1; 30_000], true, 4),           // dense tiny records past the read-ahead
            mcap(&[2_000_000, 1_500, 2_000_000], true, 5),
            mcap(&[], true, 6),
        ];
        let mut truncated = mcap(&[5_000, 40_000, big], false, 7);
        truncated.truncate(truncated.len() - 1_000); // last record cut short
        cases.push(truncated);
        let mut zero_opcode = mcap(&[5_000, 6_000], false, 8);
        zero_opcode.extend_from_slice(&[0u8; 20]);
        zero_opcode.extend_from_slice(&mcap(&[9_000], true, 9));
        cases.push(zero_opcode);
        let mut huge_len = mcap(&[5_000], false, 10);
        huge_len.push(0x05);
        huge_len.extend_from_slice(&u64::MAX.to_le_bytes());
        huge_len.extend_from_slice(&bytes(100, 11));
        cases.push(huge_len);
        cases.push(b"not an mcap at all".to_vec());
        cases
    }

    #[test]
    fn mcap_header_walk_equals_the_in_memory_walk() {
        for (i, data) in mcap_cases().iter().enumerate() {
            let want = mcap_record_offsets(data);
            let got = mcap_record_offsets_seekable(&mut Cursor::new(data), data.len()).unwrap();
            assert_eq!(got, want, "case {i}");
        }
    }

    fn mp4(boxes: &[(&[u8; 4], usize)], tail_to_end: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (kind, size)) in boxes.iter().enumerate() {
            if *size > 100_000 {
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(*kind);
                out.extend_from_slice(&((*size + 16) as u64).to_be_bytes());
            } else {
                out.extend_from_slice(&((*size + 8) as u32).to_be_bytes());
                out.extend_from_slice(*kind);
            }
            out.extend_from_slice(&bytes(*size, i as u64 + 3));
        }
        if tail_to_end {
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(b"mdat");
            out.extend_from_slice(&bytes(50_000, 99));
        }
        out
    }

    #[test]
    fn mp4_and_wav_header_walks_equal_the_in_memory_walks() {
        let cases = [
            mp4(
                &[
                    (b"ftyp", 24),
                    (b"moov", 30_000),
                    (b"mdat", 400_000),
                    (b"free", 10),
                ],
                false,
            ),
            mp4(&[(b"ftyp", 24), (b"mdat", 2_000_000)], true),
            mp4(&[(b"ftyp", 24), (b"m\x01ov", 100)], false),
        ];
        for (i, data) in cases.iter().enumerate() {
            assert_eq!(
                mp4_box_offsets_seekable(&mut Cursor::new(data), data.len()).unwrap(),
                mp4_box_offsets(data),
                "mp4 case {i}"
            );
        }
        let mut wav = b"RIFF\0\0\0\0WAVE".to_vec();
        for (id, size) in [(b"fmt ", 16usize), (b"LIST", 301), (b"data", 200_000)] {
            wav.extend_from_slice(id);
            wav.extend_from_slice(&(size as u32).to_le_bytes());
            wav.extend_from_slice(&bytes(size + (size & 1), size as u64));
        }
        assert_eq!(
            wav_data_offset_seekable(&mut Cursor::new(&wav), wav.len()).unwrap(),
            wav_data_offset(&wav)
        );
        assert!(wav_data_offset(&wav).is_some());
    }

    fn equal_scans(data: &[u8], format: Option<ContainerFormat>, params: CdcParams) {
        let want = scan_format_aware(data, format, params).unwrap();
        let got = scan_format_aware_seekable(
            &mut Cursor::new(data),
            data.len(),
            format,
            params,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(got.boundaries, want.boundaries, "{format:?}");
        assert_eq!(got.format_aware, want.format_aware, "{format:?}");
    }

    #[test]
    fn seekable_format_aware_scan_equals_scan_format_aware() {
        for data in mcap_cases() {
            for params in [small(), CdcParams::default()] {
                equal_scans(&data, Some(ContainerFormat::Mcap), params);
                equal_scans(&data, None, params);
            }
        }
        let video = mp4(
            &[(b"ftyp", 24), (b"moov", 30_000), (b"mdat", 900_000)],
            false,
        );
        equal_scans(&video, Some(ContainerFormat::Mp4), small());
        // byte-scan formats are read whole under the limit...
        let mut zip = Vec::new();
        for i in 0..20u64 {
            zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 20, 0, 0, 0, 8, 0]);
            zip.extend_from_slice(&bytes(20, i));
            zip.extend_from_slice(&bytes(30_000, i + 100));
        }
        equal_scans(&zip, Some(ContainerFormat::Zip), small());
        // ...and refused, not silently degraded, above it
        let refused = scan_format_aware_seekable(
            &mut Cursor::new(&zip),
            zip.len(),
            Some(ContainerFormat::Zip),
            small(),
            1000,
        );
        assert!(matches!(
            refused,
            Err(StreamScanError::NeedsWholeFile { .. })
        ));
    }

    #[test]
    fn a_source_that_shrinks_mid_scan_is_an_error_not_a_wrong_answer() {
        let data = mcap(&[5_000, 40_000, 70_000], true, 12);
        let claimed = data.len() + 50_000; // the file was truncated after its length was read
        let result = scan_format_aware_seekable(
            &mut Cursor::new(&data),
            claimed,
            Some(ContainerFormat::Mcap),
            small(),
            usize::MAX,
        );
        if let Ok(set) = result {
            // any boundaries it did return cover only bytes that exist
            assert!(set.boundaries.iter().all(|b| b.end <= data.len()));
            panic!("a shrunken source must not produce a complete chunk set");
        }
    }
}
