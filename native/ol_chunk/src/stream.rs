//! Chunking of files with bounded input workspace: plain `FastCDC` and
//! format-aware. Returned boundary/hash vectors still grow with chunk count.
//!
//! [`scan_stream`] chunks `len` bytes read from any [`Read`] holding at most
//! one payload window, with boundaries equal to [`crate::ChunkScanner`]'s over the same
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
//! reports [`StreamScanError::NeedsWholeFile`] and the caller decides. Header
//! candidates are consumed online: dense records do not create an auxiliary
//! vector proportional to record count. Header read-ahead is 64 KiB. The
//! parallel CDC kernel has additional candidate workspace bounded by the
//! payload window, not by the file length. This is not a constant-total-memory
//! API: its returned boundaries and format flags occupy O(output chunks).
//!
//! Declared lengths are checked, including short reads and growth. Callers
//! must nevertheless keep the contents immutable: a same-length concurrent
//! rewrite cannot be detected reliably without a filesystem snapshot.

use std::io::{self, Read, Seek, SeekFrom};

use crate::blake3_wrap;
use crate::cdc::{Boundary, CdcParams};
use crate::error::ChunkError;
use crate::format_aware::{scan_format_aware, ContainerFormat, FormatAwareChunkSet};
use crate::pcdc;
use crate::select::{CutSelector, HEAD_BYTES};
use crate::walk::{find_wav_data, ByteSource, RecordWalk};
use rayon::prelude::*;

/// Default payload window for [`scan_stream`]. Custom parameters use at least
/// four maximum chunks; the allocation never exceeds the declared source length.
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

/// `FastCDC` over exactly the `len` bytes `reader` yields, holding one payload
/// window plus bounded kernel workspace and O(output chunks) boundaries.
/// Boundaries are relative to the reader's start. Short input is an
/// `UnexpectedEof`; extra input is `InvalidData`. At most one extra byte is
/// consumed to detect growth. For a range within a larger reader use `take(len)`.
pub fn scan_stream<R: Read>(reader: R, len: usize, params: CdcParams) -> io::Result<Vec<Boundary>> {
    scan_stream_windowed(reader, len, params, STREAM_WINDOW)
}

/// A chunk-layer error as an `io::Error` that keeps it as the source: an
/// invalid profile is `InvalidInput`, a kernel that stalled is `Other`.
fn kernel_error(err: ChunkError) -> io::Error {
    let kind = match err {
        ChunkError::InvalidParameters(_) | ChunkError::SizeOutOfRange { .. } => {
            io::ErrorKind::InvalidInput
        }
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err)
}

fn scan_stream_windowed<R: Read>(
    mut reader: R,
    len: usize,
    params: CdcParams,
    window: usize,
) -> io::Result<Vec<Boundary>> {
    params.validate().map_err(kernel_error)?;
    let max_size = params.max_size as usize;
    // Sized to the source when it is small (a fixed window was zero-filled
    // for every small file once, halving ingest).
    let window_cap = window.max(4 * max_size).min(len);
    let mut buffer: Vec<u8> = Vec::with_capacity(window_cap);
    let mut base = 0usize;
    let mut out = Vec::new();
    while base < len {
        let held = buffer.len();
        let wanted = window_cap.min(len - base);
        buffer.resize(wanted, 0);
        reader.read_exact(&mut buffer[held..])?;
        let final_window = wanted == len - base;
        let ranges: Vec<(usize, usize)> = pcdc::chunk_ranges(&buffer, params)
            .map_err(kernel_error)?
            .into_iter()
            .take_while(|&(s, _)| final_window || s + max_size <= buffer.len())
            .collect();
        let consumed = ranges.last().map_or(0, |&(_, e)| e);
        if consumed == 0 {
            return Err(io::Error::other("stream scan made no progress"));
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
    }
    // Do not follow an unbounded/growing source beyond the declared snapshot.
    // read_exact already rejected shrinkage; one byte suffices to reject growth.
    loop {
        match reader.read(&mut [0u8; 1]) {
            Ok(0) => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "source grew beyond its declared length",
                ))
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(out)
}

/// Random access to a seekable source through a forward read-ahead window.
///
/// A walk that jumps (sparse records) refills a 64 KiB window at each jump. A
/// walk that runs off the end of the window (dense records) instead slides it:
/// the bytes from `retain_from` on are kept and the next `SEQUENTIAL_READ`
/// bytes appended, so the segment writer can hash short segments from the
/// window rather than read the source a second time. Retention is an
/// optimisation only: whatever is not held is read from the source.
struct Headers<'a, R> {
    source: &'a mut R,
    len: usize,
    window: Vec<u8>,
    window_start: usize,
    /// First byte still wanted by the segment writer (`usize::MAX`: none).
    retain_from: usize,
    /// Most bytes a slide keeps behind the window end (the unhashed span).
    retain_limit: usize,
}

/// Bytes appended when a dense walk slides the window.
const SEQUENTIAL_READ: usize = 16 << 20;

impl<'a, R: Read + Seek> Headers<'a, R> {
    fn new(source: &'a mut R, len: usize) -> Self {
        Self {
            source,
            len,
            window: Vec::new(),
            window_start: 0,
            retain_from: usize::MAX,
            retain_limit: 0,
        }
    }

    /// `[start, end)` if the window holds it.
    fn held(&self, start: usize, end: usize) -> Option<&[u8]> {
        let from = start.checked_sub(self.window_start)?;
        let to = end.checked_sub(self.window_start)?;
        self.window.get(from..to)
    }
}

impl<R: Read + Seek> ByteSource for Headers<'_, R> {
    type Error = io::Error;

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    /// The `n` bytes at `pos`, or `None` if they run past the source.
    #[inline]
    fn at(&mut self, pos: usize, n: usize) -> io::Result<Option<&[u8]>> {
        // Fast path: inside the window (which never extends past the source).
        if let Some(offset) = pos.checked_sub(self.window_start) {
            if offset
                .checked_add(n)
                .is_some_and(|end| end <= self.window.len())
            {
                return Ok(Some(&self.window[offset..offset + n]));
            }
        }
        self.refill(pos, n)
    }
}

impl<R: Read + Seek> Headers<'_, R> {
    /// Make the window hold `[pos, pos + n)` and return those bytes.
    #[cold]
    #[inline(never)]
    fn refill(&mut self, pos: usize, n: usize) -> io::Result<Option<&[u8]>> {
        let Some(end) = pos.checked_add(n).filter(|&end| end <= self.len) else {
            return Ok(None);
        };
        let window_end = self.window_start + self.window.len();
        // A sequential walk (it ran off the end of the window rather than
        // jumping past it) whose unhashed span is bounded slides the window.
        let slide = !self.window.is_empty()
            && (self.window_start..=window_end).contains(&pos)
            && self.retain_from <= pos
            && window_end.max(pos) - self.retain_from <= self.retain_limit;
        if slide {
            let new_end = (window_end + SEQUENTIAL_READ).max(end).min(self.len);
            // Keep what the window already holds from `retain_from` on; when
            // it lost that prefix (the walk read the trailing magic first, or
            // jumped), reload it once: at most one window is read again.
            let append_from = if self.retain_from >= self.window_start {
                self.window.drain(..self.retain_from - self.window_start);
                window_end
            } else {
                self.window.clear();
                self.retain_from
            };
            self.window_start = self.retain_from;
            let held = self.window.len();
            self.source.seek(SeekFrom::Start(append_from as u64))?;
            // Read into spare capacity: no zero-fill of the appended block.
            (&mut *self.source)
                .take((new_end - append_from) as u64)
                .read_to_end(&mut self.window)?;
            if self.window.len() - held != new_end - append_from {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source shrank while its record headers were read",
                ));
            }
        } else {
            let want = HEADER_READ_AHEAD.max(n).min(self.len - pos);
            self.source.seek(SeekFrom::Start(pos as u64))?;
            self.window.resize(want, 0);
            self.source.read_exact(&mut self.window)?;
            self.window_start = pos;
        }
        let offset = pos - self.window_start;
        Ok(Some(&self.window[offset..offset + n]))
    }
}

/// [`crate::format_aware::mcap_record_offsets`] over a seekable source of
/// `len` bytes, reading only record headers. This explicit list API returns
/// O(records) offsets; the chunk scanner consumes the walk online instead.
pub fn mcap_record_offsets_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Vec<usize>> {
    collect_offsets(source, len, RecordWalk::mcap())
}

/// [`crate::format_aware::mp4_box_offsets`] over a seekable source. This list
/// API retains O(boxes) offsets; the chunk scanner consumes the walk online.
pub fn mp4_box_offsets_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Vec<usize>> {
    collect_offsets(source, len, RecordWalk::mp4())
}

/// Every record start the shared walker yields over the header window.
fn collect_offsets<R: Read + Seek>(
    source: &mut R,
    len: usize,
    mut walk: RecordWalk,
) -> io::Result<Vec<usize>> {
    let mut headers = Headers::new(source, len);
    let mut offsets = Vec::new();
    while let Some((pos, _)) = walk.next(&mut headers)? {
        offsets.push(pos);
    }
    Ok(offsets)
}

/// [`crate::format_aware::wav_data_offset`] over a seekable source.
pub fn wav_data_offset_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
) -> io::Result<Option<usize>> {
    find_wav_data(&mut Headers::new(source, len))
}

/// Verify the declared whole-source size before and after scanning. This
/// detects growth even when segment readers are deliberately capped by `take`.
fn verify_source_length<R: Seek>(source: &mut R, len: usize) -> io::Result<()> {
    let actual = source.seek(SeekFrom::End(0))?;
    let declared = u64::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source length exceeds u64"))?;
    if actual != declared {
        return Err(io::Error::new(
            if actual < declared {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::InvalidData
            },
            format!("source holds {actual} bytes, declared {len}"),
        ));
    }
    Ok(())
}

/// Short segments (at most `max_size`) are hashed together, in parallel, once
/// this many bytes of them are pending.
const SEGMENT_BATCH: usize = 8 << 20;

/// Turns accepted cuts into chunks over a seekable source, in order. Short
/// segments are batched and hashed in parallel, from the header window when it
/// holds them and otherwise after one read of the batch (at most
/// `SEGMENT_BATCH + max_size` bytes); a segment longer than `max_size` is
/// chunked by [`scan_stream`] over its own byte range.
struct SegmentWriter {
    params: CdcParams,
    /// End of the last segment handed over (the last accepted cut).
    last: usize,
    /// Start of the pending batch of short segments.
    batch_start: usize,
    /// Ends of the pending short segments, in order.
    batch_ends: Vec<usize>,
    buffer: Vec<u8>,
    out: FormatAwareChunkSet,
}

impl SegmentWriter {
    fn new(params: CdcParams) -> Self {
        Self {
            params,
            last: 0,
            batch_start: 0,
            batch_ends: Vec::new(),
            buffer: Vec::new(),
            out: FormatAwareChunkSet {
                boundaries: Vec::new(),
                format_aware: Vec::new(),
            },
        }
    }

    /// The segment `[last, end)` is complete.
    fn segment_to<R: Read + Seek>(
        &mut self,
        headers: &mut Headers<'_, R>,
        end: usize,
    ) -> io::Result<()> {
        if end - self.last <= self.params.max_size as usize {
            self.batch_ends.push(end);
            if end - self.batch_start >= SEGMENT_BATCH {
                self.flush(headers)?;
            }
        } else {
            self.flush(headers)?;
            let start = self.last;
            headers.source.seek(SeekFrom::Start(start as u64))?;
            let chunks = scan_stream(
                (&mut *headers.source).take((end - start) as u64),
                end - start,
                self.params,
            )?;
            for (i, b) in chunks.into_iter().enumerate() {
                self.out.boundaries.push(Boundary {
                    start: b.start + start,
                    end: b.end + start,
                    raw_address: b.raw_address,
                });
                self.out.format_aware.push(i == 0 && start != 0);
            }
            self.batch_start = end;
        }
        self.last = end;
        // Everything before the pending batch has been hashed.
        headers.retain_from = self.batch_start;
        Ok(())
    }

    /// Hash the pending short segments in parallel.
    fn flush<R: Read + Seek>(&mut self, headers: &mut Headers<'_, R>) -> io::Result<()> {
        let Some(&end) = self.batch_ends.last() else {
            return Ok(());
        };
        let start = self.batch_start;
        let bytes = if let Some(held) = headers.held(start, end) {
            held
        } else {
            self.buffer.resize(end - start, 0);
            headers.source.seek(SeekFrom::Start(start as u64))?;
            headers.source.read_exact(&mut self.buffer)?;
            &self.buffer
        };
        let ranges: Vec<(usize, usize)> = std::iter::once(start)
            .chain(self.batch_ends.iter().copied())
            .zip(self.batch_ends.iter().copied())
            .collect();
        let addresses: Vec<[u8; 32]> = ranges
            .par_iter()
            .map(|&(s, e)| blake3_wrap::chunk_address_raw(&bytes[s - start..e - start]))
            .collect();
        for (&(s, e), raw_address) in ranges.iter().zip(addresses) {
            self.out.boundaries.push(Boundary {
                start: s,
                end: e,
                raw_address,
            });
            self.out.format_aware.push(s != 0);
        }
        self.batch_start = end;
        self.batch_ends.clear();
        headers.retain_from = end;
        Ok(())
    }
}

/// [`scan_format_aware`] over an immutable seekable source of exactly `len`
/// bytes. Boundaries and format flags equal the in-memory scanner's. Shrinkage,
/// growth and read/seek failures are errors, never a successful partial result.
///
/// Record headers feed the same v2 cut selector as the in-memory scanner
/// (`select.rs`), online: no candidate, accepted-cut or segment list is
/// retained. Held workspace is the header window (64 KiB for a walk that jumps;
/// for a dense walk, the unhashed bytes, at most 8 MiB + `max_size` + the
/// horizon + 64 KiB, plus a 16 MiB read-ahead block), the selector's horizon of
/// candidates (at most `max(avg_size / 2, min_size) / 4 + 1`), a short-segment
/// batch buffer used only when the window does not hold the batch (at most
/// 8 MiB + `max_size`) and the plain-CDC window for long segments, all
/// independent of source size; returned boundaries and flags still require
/// O(output chunks) memory. ZIP/H264 retain the explicit whole-file limit (see
/// the module documentation).
pub fn scan_format_aware_seekable<R: Read + Seek>(
    source: &mut R,
    len: usize,
    format: Option<ContainerFormat>,
    params: CdcParams,
    in_memory_limit: usize,
) -> Result<FormatAwareChunkSet, StreamScanError> {
    params.validate().map_err(StreamScanError::Params)?;
    if matches!(
        format,
        Some(ContainerFormat::Zip | ContainerFormat::H264AnnexB)
    ) {
        if len > in_memory_limit {
            return Err(StreamScanError::NeedsWholeFile {
                len,
                limit: in_memory_limit,
            });
        }
        verify_source_length(source, len)?;
        let mut bytes = vec![0; len];
        source.seek(SeekFrom::Start(0))?;
        source.read_exact(&mut bytes)?;
        verify_source_length(source, len)?;
        return scan_format_aware(&bytes, format, params).map_err(StreamScanError::Params);
    }

    verify_source_length(source, len)?;
    let mut selector = CutSelector::new(len, params);
    let mut writer = SegmentWriter::new(params);
    let mut headers = Headers::new(source, len);
    headers.retain_from = 0;
    headers.retain_limit = SEGMENT_BATCH
        + 2 * params.max_size as usize
        + 2 * crate::select::horizon(params)
        + HEADER_READ_AHEAD;
    let walk = match format {
        Some(ContainerFormat::Mcap) => Some(RecordWalk::mcap()),
        Some(ContainerFormat::Mp4) => Some(RecordWalk::mp4()),
        _ => None,
    };
    if let Some(mut walk) = walk {
        // A cut is written as soon as it is decided, once the walk is a
        // horizon past it.
        while let Some((pos, head)) = walk.next(&mut headers)? {
            selector.offer(pos, head);
            while let Some(cut) = selector.pop_accepted() {
                writer.segment_to(&mut headers, cut)?;
            }
        }
    } else if format == Some(ContainerFormat::Wav) {
        if let Some(pos) = find_wav_data(&mut headers)? {
            let n = HEAD_BYTES.min(len - pos);
            if let Some(head) = headers.at(pos, n)? {
                selector.offer(pos, head);
            }
        }
    }
    selector.finish();
    while let Some(cut) = selector.pop_accepted() {
        writer.segment_to(&mut headers, cut)?;
    }
    let out = if writer.last == 0 {
        // No accepted cut: plain CDC of the whole source, including natural
        // cuts in inputs shorter than max_size (a forced segment that short is
        // one chunk, matching the in-memory scanner).
        headers.source.seek(SeekFrom::Start(0))?;
        let boundaries = scan_stream(&mut *headers.source, len, params)?;
        let format_aware = vec![false; boundaries.len()];
        FormatAwareChunkSet {
            boundaries,
            format_aware,
        }
    } else {
        writer.segment_to(&mut headers, len)?;
        writer.flush(&mut headers)?;
        writer.out
    };
    verify_source_length(headers.source, len)?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // fixtures: PRNG bytes and small sizes, truncation intended
mod tests {
    use super::*;
    use crate::cdc::ChunkScanner;
    use crate::format_aware::{mcap_record_offsets, mp4_box_offsets, wav_data_offset, MCAP_MAGIC};
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
