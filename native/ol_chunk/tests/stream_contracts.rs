//! Reader, length, format and workspace contracts of the public file scanner.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use ol_chunk::format_aware::MCAP_MAGIC;
use ol_chunk::stream::{scan_format_aware_seekable, scan_stream, StreamScanError};
use ol_chunk::{scan_format_aware, CdcParams, ContainerFormat};

fn formats() -> [Option<ContainerFormat>; 6] {
    [
        None,
        Some(ContainerFormat::Zip),
        Some(ContainerFormat::H264AnnexB),
        Some(ContainerFormat::Mcap),
        Some(ContainerFormat::Mp4),
        Some(ContainerFormat::Wav),
    ]
}

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn all_formats_reject_both_short_and_long_declared_sources() {
    for format in formats() {
        for (actual, declared) in [(0, 1), (3, 5), (3, 0), (33_000, 32_999), (33_000, 33_001)] {
            let mut source = Cursor::new(noise(actual));
            let result = scan_format_aware_seekable(
                &mut source,
                declared,
                format,
                CdcParams::default(),
                usize::MAX,
            );
            let expected = if actual < declared {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::InvalidData
            };
            assert!(
                matches!(result, Err(StreamScanError::Io(ref err)) if err.kind() == expected),
                "format={format:?}, actual={actual}, declared={declared}, result={result:?}"
            );
        }
    }
}

/// Simulates normal fragmented reads, an interrupted read, or a file changing
/// length after its metadata was read. It never changes the declared metadata
/// artificially: `SeekFrom::End` always reports the actual current length.
struct Reader {
    inner: Cursor<Vec<u8>>,
    limit: usize,
    interrupted: bool,
    resize_on_read: Option<usize>,
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(len) = self.resize_on_read.take() {
            self.inner.get_mut().resize(len, 0);
        }
        let count = buf.len().min(self.limit);
        self.inner.read(&mut buf[..count])
    }
}

impl Seek for Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn fragmented_and_interrupted_reads_preserve_every_boundary_hash_and_flag() {
    let data = noise(400_007);
    for format in formats() {
        let expected = scan_format_aware(&data, format, CdcParams::default()).unwrap();
        let mut source = Reader {
            inner: Cursor::new(data.clone()),
            limit: 7,
            interrupted: true,
            resize_on_read: None,
        };
        let actual = scan_format_aware_seekable(
            &mut source,
            data.len(),
            format,
            CdcParams::default(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(actual.boundaries, expected.boundaries, "format={format:?}");
        assert_eq!(
            actual.format_aware, expected.format_aware,
            "format={format:?}"
        );
    }
}

#[test]
fn length_changes_after_the_initial_size_check_are_rejected() {
    let data = noise(100_001);
    for format in formats() {
        for new_len in [0, data.len() - 1, data.len() + 1] {
            let mut source = Reader {
                inner: Cursor::new(data.clone()),
                limit: 8192,
                interrupted: false,
                resize_on_read: Some(new_len),
            };
            let actual = scan_format_aware_seekable(
                &mut source,
                data.len(),
                format,
                CdcParams::default(),
                usize::MAX,
            );
            let expected = if new_len < data.len() {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::InvalidData
            };
            assert!(
                matches!(actual, Err(StreamScanError::Io(ref err)) if err.kind() == expected),
                "format={format:?}, new_len={new_len}, actual={actual:?}"
            );
        }
    }
}

#[test]
fn plain_stream_rejects_growth_after_reading_at_most_one_extra_byte() {
    // An infinite source used to be followed until EOF, violating the declared
    // snapshot and permitting unbounded work. Capped source instrumentation
    // converts such a regression into an ordinary error rather than a hang.
    struct Growing {
        read: usize,
        cap: usize,
    }
    impl Read for Growing {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.read + buf.len() > self.cap {
                return Err(io::Error::other("read beyond length + one"));
            }
            buf.fill(0);
            self.read += buf.len();
            Ok(buf.len())
        }
    }
    for len in [0, 1, 1024, 300_000] {
        let mut source = Growing {
            read: 0,
            cap: len + 1,
        };
        let err = scan_stream(&mut source, len, CdcParams::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(source.read, len + 1);
    }
}

#[test]
fn byte_scan_limit_is_explicit_and_inclusive() {
    let data = noise(32_000);
    for format in [ContainerFormat::Zip, ContainerFormat::H264AnnexB] {
        let err = scan_format_aware_seekable(
            &mut Cursor::new(&data),
            data.len(),
            Some(format),
            CdcParams::default(),
            data.len() - 1,
        )
        .unwrap_err();
        assert!(
            matches!(err, StreamScanError::NeedsWholeFile { len, limit } if len == data.len() && limit == data.len() - 1)
        );
        let result = scan_format_aware_seekable(
            &mut Cursor::new(&data),
            data.len(),
            Some(format),
            CdcParams::default(),
            data.len(),
        )
        .unwrap();
        let expected = scan_format_aware(&data, Some(format), CdcParams::default()).unwrap();
        assert_eq!(result.boundaries, expected.boundaries);
        assert_eq!(result.format_aware, expected.format_aware);
    }
}

#[test]
fn invalid_parameters_and_io_errors_preserve_their_error_categories() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    impl Seek for Broken {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    let bad = CdcParams {
        min_size: 4096,
        avg_size: 1024,
        max_size: 8192,
    };
    assert!(matches!(
        scan_format_aware_seekable(&mut Broken, 10, None, bad, 100),
        Err(StreamScanError::Params(_))
    ));
    assert!(
        matches!(scan_format_aware_seekable(&mut Broken, 10, None, CdcParams::default(), 100), Err(StreamScanError::Io(ref e)) if e.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        scan_stream(Broken, 10, CdcParams::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

/// A dense MCAP source generated on demand, without a file-sized input vector:
/// 17-byte Message records whose 8-byte body is the record's sequence number,
/// so every record's head differs (format-aware v2 selects among them; records
/// that all looked alike would, correctly, get no structural cut at all).
struct DenseMcap {
    pos: u64,
    len: usize,
    bytes_read: usize,
    largest_read: usize,
}

const DENSE_RECORD: usize = 17;

impl DenseMcap {
    fn new(records: usize) -> Self {
        Self {
            pos: 0,
            len: 8 + 13 + records * DENSE_RECORD + 8,
            bytes_read: 0,
            largest_read: 0,
        }
    }
    fn byte(&self, p: usize) -> u8 {
        if p < 8 {
            return MCAP_MAGIC[p];
        }
        if p >= self.len - 8 {
            return MCAP_MAGIC[p - (self.len - 8)];
        }
        if p < 21 {
            return [1, 4, 0, 0, 0, 0, 0, 0, 0, b'r', b'o', b's', b'2'][p - 8];
        }
        let (record, at) = ((p - 21) / DENSE_RECORD, (p - 21) % DENSE_RECORD);
        match at {
            0 => 5,
            1 => 8,
            2..=8 => 0,
            _ => (record as u64).to_le_bytes()[at - 9],
        }
    }
}

impl Read for DenseMcap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = usize::try_from(self.pos).unwrap();
        let count = buf.len().min(self.len.saturating_sub(pos));
        self.largest_read = self.largest_read.max(count);
        self.bytes_read += count;
        for (i, out) in buf[..count].iter_mut().enumerate() {
            *out = self.byte(pos + i);
        }
        self.pos += count as u64;
        Ok(count)
    }
}

impl Seek for DenseMcap {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let value = match pos {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::Current(p) => i128::from(self.pos) + i128::from(p),
            SeekFrom::End(p) => self.len as i128 + i128::from(p),
        };
        self.pos =
            u64::try_from(value).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

#[test]
fn millions_of_dense_records_are_chunked_online_reading_the_source_once() {
    // Two million records, 34 MB. The scanner holds a bounded header window
    // and hashes short segments from it as their cuts are decided, so the
    // source is read once. Collecting candidates or segments first and
    // hashing afterwards would read the payload a second time (about 2x len)
    // and fail the read-once assertion.
    let records = 2_000_000;
    let mut source = DenseMcap::new(records);
    let len = source.len;
    let result = scan_format_aware_seekable(
        &mut source,
        len,
        Some(ContainerFormat::Mcap),
        CdcParams::default(),
        0,
    )
    .unwrap();
    // Exactly once, plus a derived constant: the first 64 KiB header window
    // (leading magic check), the 8-byte trailing magic (which replaces that
    // window), and the first window again when the slide reloads the bytes
    // the writer still needs from offset 0.
    assert_eq!(
        source.bytes_read,
        len + 2 * (64 << 10) + 8,
        "bytes read from a {len}-byte source"
    );
    // A dense refill can reload the header window once (starting just past
    // the magic) and append its 64 KiB block. Later reads append one block.
    assert!(
        source.largest_read <= 2 * (64 << 10) + MCAP_MAGIC.len(),
        "{}",
        source.largest_read
    );
    // About one chunk per avg_size bytes, each forced chunk on a record start.
    assert!(
        (len / (128 << 10)..len / (32 << 10)).contains(&result.boundaries.len()),
        "{} chunks",
        result.boundaries.len()
    );
    assert_eq!(result.boundaries.first().unwrap().start, 0);
    assert_eq!(result.boundaries.last().unwrap().end, len);
    assert!(!result.format_aware[0]);
    let forced = result.format_aware.iter().filter(|f| **f).count();
    assert!(
        forced * 10 >= result.boundaries.len() * 9,
        "{forced} forced"
    );
    for (b, f) in result.boundaries.iter().zip(&result.format_aware) {
        if *f {
            assert_eq!(
                (b.start - 21) % DENSE_RECORD,
                0,
                "forced cut at {}",
                b.start
            );
        }
    }
    for pair in result.boundaries.windows(2) {
        assert_eq!(pair[0].end, pair[1].start);
    }
    // Verify every address independently from the synthetic source definition.
    for boundary in result.boundaries {
        let bytes: Vec<u8> = (boundary.start..boundary.end)
            .map(|p| source.byte(p))
            .collect();
        assert_eq!(boundary.raw_address, *blake3::hash(&bytes).as_bytes());
    }
}

/// A dense MCAP of 17-byte sequence-numbered records, materialised.
fn dense_mcap_bytes(records: usize) -> Vec<u8> {
    let mut out = MCAP_MAGIC.to_vec();
    out.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0, 0, b'r', b'o', b's', b'2']);
    for k in 0..records as u64 {
        out.push(5);
        out.extend_from_slice(&8u64.to_le_bytes());
        out.extend_from_slice(&k.to_le_bytes());
    }
    out.extend_from_slice(&MCAP_MAGIC);
    out
}

fn mcap_record(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![opcode];
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn every_payload_path_of_the_file_scanner_equals_the_in_memory_scanner() {
    // The seekable scanner hashes short segments from its header window when
    // a dense walk has slid the window over them, and reads them itself when
    // the walk jumped (sparse records) or a segment outgrew the retention
    // (one huge record inside a dense run). Each layout below exercises one of
    // those paths, past the 64 KiB slide and batch sizes, through
    // fragmented and interrupted reads; the in-memory scanner is the oracle.
    let dense = dense_mcap_bytes(2_500_000); // 42.5 MB: several slides and batches
    let mut sparse = MCAP_MAGIC.to_vec();
    sparse.extend(mcap_record(1, b"ros2"));
    for i in 0..400usize {
        // Large records the walk jumps over, with short ones between them.
        let big = 70_000 + (i * 7_919) % 200_000;
        sparse.extend(mcap_record(5, &noise(big)));
        sparse.extend(mcap_record(6, &noise(100 + i % 3_000)));
    }
    sparse.extend_from_slice(&MCAP_MAGIC);
    let mut interrupted = dense_mcap_bytes(400_000);
    let tail = interrupted.split_off(interrupted.len() - 8);
    interrupted.extend(mcap_record(5, &noise(20 << 20))); // retention exceeded
    let more = dense_mcap_bytes(400_000);
    interrupted.extend_from_slice(&more[21..more.len() - 8]);
    interrupted.extend(tail);
    for (name, data) in [
        ("dense", &dense),
        ("sparse", &sparse),
        ("interrupted", &interrupted),
    ] {
        let expected =
            scan_format_aware(data, Some(ContainerFormat::Mcap), CdcParams::default()).unwrap();
        assert!(
            expected.format_forced_count() > 10,
            "{name}: {} forced",
            expected.format_forced_count()
        );
        for (limit, interrupt) in [(usize::MAX, false), (4093, true)] {
            let mut source = Reader {
                inner: Cursor::new(data.clone()),
                limit,
                interrupted: interrupt,
                resize_on_read: None,
            };
            let actual = scan_format_aware_seekable(
                &mut source,
                data.len(),
                Some(ContainerFormat::Mcap),
                CdcParams::default(),
                0,
            )
            .unwrap();
            assert_eq!(actual.boundaries, expected.boundaries, "{name} {limit}");
            assert_eq!(actual.format_aware, expected.format_aware, "{name} {limit}");
        }
    }
}

#[test]
fn identical_dense_records_use_plain_cdc_after_the_header_walk() {
    let mut data = MCAP_MAGIC.to_vec();
    data.extend(mcap_record(1, b"ros2"));
    let record = mcap_record(5, &[0; 8]);
    for _ in 0..2_000_000 {
        data.extend_from_slice(&record);
    }
    data.extend_from_slice(&MCAP_MAGIC);
    // Equal fingerprints do not select a dense cut. This exercises the
    // completed dense walk followed by a full plain-CDC window, without
    // retaining the header payload during that fallback.
    let expected = scan_format_aware(&data, None, CdcParams::default()).unwrap();
    let actual = scan_format_aware_seekable(
        &mut Cursor::new(&data),
        data.len(),
        Some(ContainerFormat::Mcap),
        CdcParams::default(),
        0,
    )
    .unwrap();
    assert_eq!(actual.boundaries, expected.boundaries);
    assert!(actual.format_aware.iter().all(|forced| !forced));
}

/// Truncates itself during a forward payload read, not the initial trailing
/// magic probe beyond `new_len`.
struct ShrinksMidway {
    inner: Cursor<Vec<u8>>,
    at: u64,
    new_len: usize,
}

impl Read for ShrinksMidway {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inner.position() > self.at
            && self.inner.position() < self.new_len as u64
            && self.inner.get_ref().len() > self.new_len
        {
            self.inner.get_mut().truncate(self.new_len);
        }
        self.inner.read(buf)
    }
}

impl Seek for ShrinksMidway {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_source_that_shrinks_during_a_dense_slide_is_an_error() {
    // The header window slides forward in 64 KiB blocks. Truncation after
    // the first MiB must surface as UnexpectedEof when a later refill reaches
    // the new end, never as a successful short chunk set.
    let data = dense_mcap_bytes(2_000_000);
    let mut source = ShrinksMidway {
        inner: Cursor::new(data.clone()),
        at: 1 << 20,
        new_len: 20 << 20,
    };
    let result = scan_format_aware_seekable(
        &mut source,
        data.len(),
        Some(ContainerFormat::Mcap),
        CdcParams::default(),
        0,
    );
    assert!(
        matches!(result, Err(StreamScanError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof),
        "{result:?}"
    );
}
