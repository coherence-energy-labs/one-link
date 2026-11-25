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

/// A dense MCAP source generated on demand, without a file-sized input vector.
/// Each valid zero-body message record is only nine bytes. The read trace also
/// proves payload scanning begins while headers are still in the first window;
/// collecting a complete candidate vector before scanning fails this assertion.
struct DenseMcap {
    pos: u64,
    len: usize,
    header_windows: usize,
    headers_before_payload: Option<usize>,
    largest_read: usize,
}

impl DenseMcap {
    fn new(records: usize) -> Self {
        Self {
            pos: 0,
            len: 8 + 13 + records * 9 + 8,
            header_windows: 0,
            headers_before_payload: None,
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
        if (p - 21).is_multiple_of(9) {
            5
        } else {
            0
        }
    }
}

impl Read for DenseMcap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = usize::try_from(self.pos).unwrap();
        let count = buf.len().min(self.len.saturating_sub(pos));
        self.largest_read = self.largest_read.max(buf.len());
        if buf.len() == 64 << 10 {
            self.header_windows += 1;
        }
        if (8192..64 << 10).contains(&buf.len()) && self.headers_before_payload.is_none() {
            self.headers_before_payload = Some(self.header_windows);
        }
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
fn millions_of_dense_records_are_coalesced_online_without_candidate_vectors() {
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
    // Leading magic is checked before trailing magic; the footer may evict
    // the first read-ahead window. At most that one refill precedes payload.
    assert!(matches!(source.headers_before_payload, Some(1 | 2)));
    assert!(source.largest_read <= 64 << 10);
    assert!(result.boundaries.len() < records / 100);
    assert_eq!(result.boundaries.first().unwrap().start, 0);
    assert_eq!(result.boundaries.last().unwrap().end, len);
    assert!(!result.format_aware[0]);
    assert!(result.format_aware[1..].iter().all(|x| *x));
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
