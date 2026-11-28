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
//! the same windowed CDC kernel over its byte range, with a smaller payload
//! window for record-format fallbacks. The result equals `scan_format_aware`
//! on the whole file's bytes. Containers whose cuts need a full byte scan (ZIP,
//! H.264 Annex B) are read whole up to `in_memory_limit`; above it the scan
//! reports [`StreamScanError::NeedsWholeFile`] and the caller decides. Header
//! candidates are consumed online: dense records do not create an auxiliary
//! vector proportional to record count. Header read-ahead and short-segment
//! batches are 64 KiB; dense walks also retain a bounded unhashed span. The
//! parallel CDC kernel has additional candidate workspace bounded by the
//! payload window and the profile, whatever the bytes are: about a sixtieth
//! of the window with the default profile, at most about one and a quarter
//! times the window with the smallest average. On input built to fill it,
//! `pcdc` stops recording and hashes each chunk directly. This is not a
//! constant-total-memory API: its returned boundaries and format flags
//! occupy O(output chunks).
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

/// Record formats can contain a long identical run with no selected cuts.
/// Keep its fallback payload window small rather than allocating the whole
/// run alongside the header workspace. The kernel still uses at least four
/// maximum chunks for custom profiles; ordinary plain CDC retains its window.
const RECORD_STREAM_WINDOW: usize = 1 << 20;

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
const SEQUENTIAL_READ: usize = 64 << 10;

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

    fn for_segments(source: &'a mut R, len: usize, params: CdcParams) -> Self {
        let mut headers = Self::new(source, len);
        headers.retain_from = 0;
        headers.retain_limit = SEGMENT_BATCH
            + 2 * params.max_size as usize
            + 2 * crate::select::horizon(params)
            + HEADER_READ_AHEAD;
        headers
    }

    fn release_window(&mut self) {
        self.window = Vec::new();
        self.window_start = 0;
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
            // Reserve the bounded capacity once, without Vec's geometric
            // growth. read_to_end can grow even at the end of a Take reader;
            // an exact-sized initialized slice avoids that extra allocation.
            let needed = held + (new_end - append_from);
            let bound = self
                .retain_limit
                .saturating_add(SEQUENTIAL_READ)
                .min(self.len - self.window_start);
            let capacity = needed.max(bound);
            if self.window.capacity() < capacity {
                self.window.reserve_exact(capacity - held);
            }
            self.window.resize(new_end - self.window_start, 0);
            self.source.seek(SeekFrom::Start(append_from as u64))?;
            self.source.read_exact(&mut self.window[held..])?;
        } else {
            let want = HEADER_READ_AHEAD.max(n).min(self.len - pos);
            self.source.seek(SeekFrom::Start(pos as u64))?;
            if self.window.capacity() < want {
                self.window.reserve_exact(want - self.window.len());
            }
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

/// Flush short segments (at most `max_size`) after this many pending bytes.
/// A small batch lets dense walks retain their input without a large payload
/// allocation that sparse header walks do not need.
const SEGMENT_BATCH: usize = 64 << 10;

/// Small batches cost less to hash directly than to dispatch to the pool.
const PARALLEL_HASH_BYTES: usize = 1 << 20;

/// Turns accepted cuts into chunks over a seekable source, in order. Short
/// segments are batched and hashed from the header window when it
/// holds them and otherwise after one read of the batch (at most
/// `SEGMENT_BATCH + max_size` bytes); a segment longer than `max_size` uses
/// the windowed CDC kernel with a 1 MiB default payload window.
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
            let chunks = scan_stream_windowed(
                (&mut *headers.source).take((end - start) as u64),
                end - start,
                self.params,
                RECORD_STREAM_WINDOW,
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

    /// Hash pending short segments, using the pool only for large profiles.
    fn flush<R: Read + Seek>(&mut self, headers: &mut Headers<'_, R>) -> io::Result<()> {
        let Some(&end) = self.batch_ends.last() else {
            return Ok(());
        };
        let start = self.batch_start;
        let bytes = if let Some(held) = headers.held(start, end) {
            held
        } else {
            let capacity = (SEGMENT_BATCH + self.params.max_size as usize).min(headers.len);
            if self.buffer.capacity() < capacity {
                self.buffer.reserve_exact(capacity - self.buffer.len());
            }
            self.buffer.resize(end - start, 0);
            headers.source.seek(SeekFrom::Start(start as u64))?;
            headers.source.read_exact(&mut self.buffer)?;
            &self.buffer
        };
        let ranges: Vec<(usize, usize)> = std::iter::once(start)
            .chain(self.batch_ends.iter().copied())
            .zip(self.batch_ends.iter().copied())
            .collect();
        let address =
            |&(s, e): &(usize, usize)| blake3_wrap::chunk_address_raw(&bytes[s - start..e - start]);
        let addresses: Vec<[u8; 32]> = if bytes.len() < PARALLEL_HASH_BYTES {
            ranges.iter().map(address).collect()
        } else {
            ranges.par_iter().map(address).collect()
        };
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
/// for a dense walk, at most 192 KiB + `2 * max_size` + twice the horizon,
/// including the unhashed bytes and 64 KiB read-ahead), the selector's horizon of
/// candidates (at most `max(avg_size / 2, min_size) / 4 + 1`), a short-segment
/// batch buffer used only when the window does not hold the batch (at most
/// 64 KiB + `max_size`) and a payload window of at most
/// `max(1 MiB, 4 * max_size)` for record-format fallbacks, all independent of
/// source size; returned boundaries and flags still require
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
    let mut headers = Headers::for_segments(source, len, params);
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
        // The completed header walk will not use its allocation again.
        headers.release_window();
        headers.source.seek(SeekFrom::Start(0))?;
        let window = if format.is_some() {
            RECORD_STREAM_WINDOW
        } else {
            STREAM_WINDOW
        };
        let boundaries = scan_stream_windowed(&mut *headers.source, len, params, window)?;
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
    fn dense_header_capacity_stays_small_through_reuse_and_jumps() {
        let params = CdcParams::default();
        for len in [2 << 20, 8 << 20] {
            let data = bytes(len, 3);
            let mut source = Cursor::new(&data);
            let mut headers = Headers::for_segments(&mut source, len, params);
            // Keep a pending batch plus a maximum segment and the selector's
            // lookahead. Repeated slides must reuse a small allocation, even
            // when the logical window grows a little beyond its last length.
            let pending =
                SEGMENT_BATCH - 1 + params.max_size as usize + crate::select::horizon(params);
            let mut peak = 0;
            for pos in (0..len - HEAD_BYTES).step_by(HEAD_BYTES) {
                headers.retain_from = pos.saturating_sub(pending);
                assert_eq!(
                    headers.at(pos, HEAD_BYTES).unwrap().unwrap(),
                    &data[pos..pos + HEAD_BYTES]
                );
                peak = peak.max(headers.window.capacity());
                assert!(peak <= 768 << 10, "{len}-byte source retained {peak} bytes");
            }
            assert!(peak > HEADER_READ_AHEAD, "the dense sliding path ran");
            for pos in [0, len - HEAD_BYTES, len / 2] {
                assert_eq!(
                    headers.at(pos, HEAD_BYTES).unwrap().unwrap(),
                    &data[pos..pos + HEAD_BYTES]
                );
                assert!(headers.window.capacity() <= 768 << 10);
            }
            // No-cut fallback must be able to release this workspace before
            // allocating its plain-CDC payload window. A later refill still
            // has a coherent start offset and returns the requested bytes.
            headers.release_window();
            assert_eq!(headers.window.capacity(), 0);
            assert_eq!(
                headers.at(123, HEAD_BYTES).unwrap().unwrap(),
                &data[123..123 + HEAD_BYTES]
            );
        }
    }

    #[test]
    fn segment_buffer_capacity_is_bounded_across_larger_reused_batches() {
        let data = bytes(8 << 20, 7);
        for max_size in [256 << 10, 2 << 20] {
            let params = CdcParams {
                max_size,
                ..CdcParams::default()
            };
            let mut source = Cursor::new(&data);
            let mut headers = Headers::for_segments(&mut source, data.len(), params);
            let mut writer = SegmentWriter::new(params);
            let limit = (64 << 10) + max_size as usize;
            let mut end = 0;
            for tail in [128, 64, 0] {
                // The prefix alone does not flush; the next segment creates
                // a successively larger fallback batch. Geometric resize
                // growth used to retain nearly twice the needed capacity.
                end += SEGMENT_BATCH - 1;
                writer.segment_to(&mut headers, end).unwrap();
                end += max_size as usize - tail;
                writer.segment_to(&mut headers, end).unwrap();
                assert!(
                    writer.buffer.capacity() <= limit,
                    "{} > {limit}",
                    writer.buffer.capacity()
                );
                assert!(writer.batch_ends.is_empty());
            }
            // A long segment uses plain CDC after draining the batch. The
            // old batch allocation remains small through this transition.
            writer.segment_to(&mut headers, data.len()).unwrap();
            writer.flush(&mut headers).unwrap();
            assert!(writer.buffer.capacity() <= limit);
            assert_eq!(writer.out.boundaries.first().unwrap().start, 0);
            assert_eq!(writer.out.boundaries.last().unwrap().end, data.len());
            for boundary in writer.out.boundaries {
                assert_eq!(
                    boundary.raw_address,
                    *blake3::hash(&data[boundary.start..boundary.end]).as_bytes()
                );
            }
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

    /// A seekable source of zeros that holds no bytes of its own, so the
    /// test's memory cannot be mistaken for the window's.
    struct Zeros {
        len: u64,
        pos: u64,
    }

    impl Read for Zeros {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = (self.len - self.pos).min(buf.len() as u64) as usize;
            buf[..n].fill(0);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for Zeros {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.pos = match to {
                SeekFrom::Start(pos) => pos,
                SeekFrom::End(delta) => self.len.checked_add_signed(delta).unwrap(),
                SeekFrom::Current(delta) => self.pos.checked_add_signed(delta).unwrap(),
            };
            Ok(self.pos)
        }
    }

    /// The dense walk's window is documented as the retained span plus one
    /// read-ahead block (`FILE_SCANNING.md`, "Memory behavior"). Its buffer
    /// must be allocated once, at that size: a buffer left to grow on demand
    /// doubles past the bound and can briefly hold two copies of itself.
    #[test]
    fn a_dense_walk_allocates_its_window_once_within_the_documented_bound() {
        let params = CdcParams::default();
        let len = (2 << 20) + 5 * SEQUENTIAL_READ + 12_345;
        let mut source = Zeros {
            len: len as u64,
            pos: 0,
        };
        let mut headers = Headers::for_segments(&mut source, len, params);
        let bound = headers.retain_limit + SEQUENTIAL_READ;
        let trail = SEGMENT_BATCH + params.max_size as usize + crate::select::horizon(params);
        let mut capacities = Vec::new();
        let mut pos = 0;
        while pos + 32 <= len {
            assert!(headers.at(pos, 32).unwrap().is_some());
            headers.retain_from = pos.saturating_sub(trail);
            let capacity = headers.window.capacity();
            if capacities.last() != Some(&capacity) {
                capacities.push(capacity);
            }
            assert!(
                capacity <= bound,
                "window capacity {capacity} exceeds its bound {bound}"
            );
            pos += 32;
        }
        // First the 64 KiB header window, then the one allocation the first
        // slide makes; all later slides reuse it.
        assert_eq!(capacities, vec![HEADER_READ_AHEAD, bound]);
    }

    /// A dense MCAP generated on demand whose records repeat with a period of
    /// exactly `period` bytes: 32-byte Message records (9-byte header, 23-byte
    /// payload drawn from the record's index within the period).
    struct PeriodicDense {
        len: usize,
        pos: usize,
        period_records: usize,
        bytes_read: usize,
    }

    const PERIODIC_RECORD: usize = 32;
    const PERIODIC_HEAD: usize = 8 + 13;

    impl PeriodicDense {
        fn new(records: usize, period: usize) -> Self {
            Self {
                len: PERIODIC_HEAD + records * PERIODIC_RECORD + 8,
                pos: 0,
                period_records: period / PERIODIC_RECORD,
                bytes_read: 0,
            }
        }

        fn byte(&self, p: usize) -> u8 {
            if p < 8 {
                return MCAP_MAGIC[p];
            }
            if p >= self.len - 8 {
                return MCAP_MAGIC[p - (self.len - 8)];
            }
            if p < PERIODIC_HEAD {
                return [1, 4, 0, 0, 0, 0, 0, 0, 0, b'r', b'o', b's', b'2'][p - 8];
            }
            let record = (p - PERIODIC_HEAD) / PERIODIC_RECORD;
            let at = (p - PERIODIC_HEAD) % PERIODIC_RECORD;
            match at {
                0 => 5,
                1 => 23,
                2..=8 => 0,
                _ => {
                    // splitmix64 of the record's index within the period
                    let mut x = ((record % self.period_records) as u64)
                        .wrapping_add(1)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
                    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                    x ^= x >> 31;
                    x.to_le_bytes()[(at - 9) % 8] ^ ((at - 9) / 8) as u8
                }
            }
        }
    }

    impl Read for PeriodicDense {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = buf.len().min(self.len.saturating_sub(self.pos));
            for (i, out) in buf[..count].iter_mut().enumerate() {
                *out = self.byte(self.pos + i);
            }
            self.pos += count;
            self.bytes_read += count;
            Ok(count)
        }
    }

    impl Seek for PeriodicDense {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.pos = match to {
                SeekFrom::Start(pos) => usize::try_from(pos).unwrap(),
                SeekFrom::End(delta) => self.len.checked_add_signed(delta as isize).unwrap(),
                SeekFrom::Current(delta) => self.pos.checked_add_signed(delta as isize).unwrap(),
            };
            Ok(self.pos as u64)
        }
    }

    /// Content that repeats with the scanner's own batch size, or out
    /// of step with it, is still read once. With such a period every slide of
    /// the window meets the pending batch at the same phase, so a boundary
    /// case in what the window retains would repeat for the whole source and
    /// send every batch back to the source for a second read.
    #[test]
    fn a_dense_source_that_repeats_with_the_batch_period_is_read_once() {
        // Keep the original 8 MiB period cases as well as the smaller current
        // batch period. Both aligned and misaligned layouts remain read-once.
        for period in [
            SEGMENT_BATCH,
            SEGMENT_BATCH + 4096,
            5 << 20,
            8 << 20,
            (8 << 20) + 4096,
        ] {
            let records = (72usize << 20) / PERIODIC_RECORD;
            let mut source = PeriodicDense::new(records, period);
            let len = source.len;
            let set = scan_format_aware_seekable(
                &mut source,
                len,
                Some(ContainerFormat::Mcap),
                CdcParams::default(),
                0,
            )
            .unwrap();
            // Once, plus the first 64 KiB header window twice and the 8-byte
            // trailing magic (the same constant as the two-million-record
            // contract test in tests/stream_contracts.rs).
            assert_eq!(
                source.bytes_read,
                len + 2 * HEADER_READ_AHEAD + 8,
                "period {period}: bytes read from a {len}-byte source"
            );
            assert_eq!(set.boundaries.last().unwrap().end, len);
            assert!(
                (len / (128 << 10)..len / (32 << 10)).contains(&set.boundaries.len()),
                "period {period}: {} chunks",
                set.boundaries.len()
            );
        }
    }

    /// A source shorter than the bound never reserves more than it holds.
    #[test]
    fn a_short_dense_walk_does_not_reserve_past_the_source() {
        let len = HEADER_READ_AHEAD + 300_000;
        let mut source = Zeros {
            len: len as u64,
            pos: 0,
        };
        let mut headers = Headers::for_segments(&mut source, len, CdcParams::default());
        let mut pos = 0;
        while pos + 32 <= len {
            assert!(headers.at(pos, 32).unwrap().is_some());
            assert!(headers.window.capacity() <= len);
            pos += 32;
        }
    }
}
