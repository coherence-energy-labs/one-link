//! Record-walk fallbacks keep their payload window bounded even when dense
//! records stop selecting cuts. The in-memory scanner remains the oracle.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use ol_chunk::format_aware::MCAP_MAGIC;
use ol_chunk::stream::{scan_format_aware_seekable, StreamScanError};
use ol_chunk::{scan_format_aware, CdcParams, ContainerFormat};

const MIB: usize = 1 << 20;
const RECORD: usize = 32;
const BATCH: usize = 8 * MIB;

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

/// The preserved memory corpus writes whole 8 MiB batches, then repeats just
/// the first record to fill the remainder. At a power-of-two file length the
/// MCAP framing leaves an almost 8 MiB identical-record tail. Equal v2 unit
/// fingerprints intentionally select no cuts inside that tail.
fn periodic_log_with_identical_tail(size: usize, varied_prefix: bool) -> Vec<u8> {
    let random = noise(4 * MIB);
    let mut batch = Vec::with_capacity(BATCH);
    for i in 0..BATCH / RECORD {
        let at = (i * 7_919) % (random.len() - (RECORD - 9));
        batch.push(5);
        batch.extend_from_slice(&23u64.to_le_bytes());
        batch.extend_from_slice(&random[at..at + RECORD - 9]);
    }
    let mut out = MCAP_MAGIC.to_vec();
    out.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0, 0, b'r', b'o', b's', b'2']);
    let body_end = size - MCAP_MAGIC.len();
    if varied_prefix {
        while out.len() + batch.len() <= body_end {
            out.extend_from_slice(&batch);
        }
    }
    while out.len() + RECORD <= body_end {
        out.extend_from_slice(&batch[..RECORD]);
    }
    // Both test sizes leave fewer than nine bytes: an opcode-zero tail ends
    // the walker, just as in the original generator. It remains hashed.
    assert!(body_end - out.len() < 9);
    out.resize(body_end, 0);
    out.extend_from_slice(&MCAP_MAGIC);
    assert_eq!(out.len(), size);
    out
}

struct ObservedReader {
    inner: Cursor<Vec<u8>>,
    fragment: usize,
    interrupt_fallback: bool,
    resize_during_fallback: Option<isize>,
    changed: bool,
    largest_request: usize,
    fallback_reads: usize,
}

impl ObservedReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(data),
            fragment: usize::MAX,
            interrupt_fallback: false,
            resize_during_fallback: None,
            changed: false,
            largest_request: 0,
            fallback_reads: 0,
        }
    }
}

impl Read for ObservedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.largest_request = self.largest_request.max(buf.len());
        // Header reads are at most 128 KiB + framing. A larger read is an
        // actual payload fallback, not the initial trailing-magic probe.
        if buf.len() > 256 << 10 {
            self.fallback_reads += 1;
            if self.interrupt_fallback {
                self.interrupt_fallback = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if let Some(delta) = self.resize_during_fallback.take() {
                let new_len = self
                    .inner
                    .get_ref()
                    .len()
                    .checked_add_signed(delta)
                    .unwrap();
                self.inner.get_mut().resize(new_len, 0);
                self.changed = true;
            }
        }
        let count = buf.len().min(self.fragment);
        self.inner.read(&mut buf[..count])
    }
}

impl Seek for ObservedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[test]
fn periodic_dense_tail_keeps_payload_reads_small_and_matches_every_chunk() {
    for size in [16 * MIB, 24 * MIB] {
        let data = periodic_log_with_identical_tail(size, true);
        let expected =
            scan_format_aware(&data, Some(ContainerFormat::Mcap), CdcParams::default()).unwrap();
        assert!(expected.format_forced_count() > 10);
        assert!(
            expected
                .format_aware
                .iter()
                .filter(|forced| !**forced)
                .count()
                > 3
        );
        for fragment in [usize::MAX, 4_093] {
            let mut source = ObservedReader::new(data.clone());
            source.fragment = fragment;
            source.interrupt_fallback = true;
            let actual = scan_format_aware_seekable(
                &mut source,
                size,
                Some(ContainerFormat::Mcap),
                CdcParams::default(),
                0,
            )
            .unwrap();
            assert_eq!(actual.boundaries, expected.boundaries);
            assert_eq!(actual.format_aware, expected.format_aware);
            assert!(
                source.fallback_reads > 1,
                "long-tail fallback was exercised"
            );
            assert!(
                source.largest_request <= MIB,
                "{size}-byte log requested {} payload bytes at once",
                source.largest_request
            );
        }
    }
}

#[test]
fn no_cut_dense_log_uses_the_same_small_record_fallback() {
    let size = 16 * MIB;
    let data = periodic_log_with_identical_tail(size, false);
    let expected = scan_format_aware(&data, None, CdcParams::default()).unwrap();
    let mut source = ObservedReader::new(data);
    let actual = scan_format_aware_seekable(
        &mut source,
        size,
        Some(ContainerFormat::Mcap),
        CdcParams::default(),
        0,
    )
    .unwrap();
    assert_eq!(actual.boundaries, expected.boundaries);
    assert!(actual.format_aware.iter().all(|forced| !forced));
    assert!(
        source.largest_request <= MIB,
        "no-cut log requested {} payload bytes at once",
        source.largest_request
    );
    assert!(source.fallback_reads > 1);
}

#[test]
fn periodic_tail_fallback_still_rejects_shrinkage_and_growth() {
    let size = 16 * MIB;
    let data = periodic_log_with_identical_tail(size, true);
    for (delta, expected) in [
        (-1024, io::ErrorKind::UnexpectedEof),
        (1024, io::ErrorKind::InvalidData),
    ] {
        let mut source = ObservedReader::new(data.clone());
        source.resize_during_fallback = Some(delta);
        let result = scan_format_aware_seekable(
            &mut source,
            size,
            Some(ContainerFormat::Mcap),
            CdcParams::default(),
            0,
        );
        assert!(source.changed, "length changed during the actual fallback");
        assert!(
            matches!(result, Err(StreamScanError::Io(ref error)) if error.kind() == expected),
            "length delta {delta}: {result:?}"
        );
    }
}
