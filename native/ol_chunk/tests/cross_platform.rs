//! Cross-platform determinism test.
//!
//! Per [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md) verification
//! gate #2: same input must produce byte-identical chunk boundaries on
//! x86-64, ARM64 (Apple Silicon), and Windows. SIMD changes
//! microarchitecture, not byte output.
//!
//! The fixture below pins:
//!   - A deterministic 1 MiB pseudo-random buffer (xorshift seed = the
//!     value below).
//!   - The expected boundary offsets the `FastCDC` + Gear-256 kernel must
//!     produce on that buffer for the default ADR-0001 parameters
//!     (8 KiB / 64 KiB / 256 KiB).
//!
//! If this test fails after a Rust compiler upgrade, a `fastcdc` crate
//! upgrade, or a SIMD path enable, that is a determinism regression and
//! must be investigated immediately. The boundaries are part of the
//! engine's wire-format compatibility surface — changing them silently
//! breaks dedup with peers running older builds.

use ol_chunk::{scan_to_vec, scan_to_vec_parallel, stream::scan_stream, Boundary, CdcParams};
use std::io::Cursor;

/// Deterministic xorshift fill. Seed pinned for reproducibility.
fn pseudo_random_buf(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; len];
    for byte in &mut buf {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }
    buf
}

/// Frozen before the streaming remediation using the audited 0.22.1 native
/// build (1279a450). Exact starts, ends and hashes are committed; CI never
/// regenerates this file. The input hash also freezes the corpus generator.
const GOLDEN: &str = include_str!("fixtures/cdc_golden_v1.txt");

#[derive(Debug, Eq, PartialEq)]
struct GoldenFixture {
    input_len: usize,
    input_hash: [u8; 32],
    boundaries: Vec<Boundary>,
}

fn parse_golden_fixture(fixture: &str, name: &str) -> GoldenFixture {
    let marker = format!("[{name}]");
    // `lines` recognizes both LF and CRLF without changing the fixture values.
    let mut lines = fixture.lines();
    assert!(
        lines.any(|line| line == marker),
        "missing golden fixture section {name}"
    );
    let mut lines = lines.take_while(|line| !line.starts_with('['));
    let identity: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
    assert_eq!(identity.len(), 3);
    assert_eq!(identity[0], "input");
    let boundaries = lines
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 3);
            Boundary {
                start: fields[0].parse().unwrap(),
                end: fields[1].parse().unwrap(),
                raw_address: hex::decode(fields[2]).unwrap().try_into().unwrap(),
            }
        })
        .collect();
    GoldenFixture {
        input_len: identity[1].parse().unwrap(),
        input_hash: hex::decode(identity[2]).unwrap().try_into().unwrap(),
        boundaries,
    }
}

fn assert_golden(name: &str, buf: &[u8]) {
    let expected = parse_golden_fixture(GOLDEN, name);
    assert_eq!(expected.input_len, buf.len());
    assert_eq!(expected.input_hash, *blake3::hash(buf).as_bytes());
    for (engine, boundaries) in [
        ("serial", scan_to_vec(buf)),
        ("parallel", scan_to_vec_parallel(buf)),
        (
            "streamed",
            scan_stream(Cursor::new(buf), buf.len(), CdcParams::default()).unwrap(),
        ),
    ] {
        assert_eq!(
            boundaries, expected.boundaries,
            "fixture {name}, engine {engine}"
        );
        assert_eq!(boundaries.first().unwrap().start, 0);
        assert_eq!(boundaries.last().unwrap().end, buf.len());
        for b in &boundaries {
            assert_eq!(
                b.raw_address,
                *blake3::hash(&buf[b.start..b.end]).as_bytes()
            );
        }
        for pair in boundaries.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
    }
}

#[test]
fn frozen_fixture_parses_identically_with_lf_or_crlf() {
    // Git may check this text fixture out with CRLF on Windows. Exercise both
    // encodings on every host, comparing the full corpus identity and every
    // frozen start, end and hash rather than only checking section discovery.
    let lf = GOLDEN.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    for name in ["RANDOM", "ZEROS", "EDITED"] {
        assert_eq!(
            parse_golden_fixture(&crlf, name),
            parse_golden_fixture(&lf, name),
            "newline encoding changed fixture {name}"
        );
    }
}

#[test]
fn frozen_random_boundaries_and_hashes_match_all_engines() {
    assert_golden(
        "RANDOM",
        &pseudo_random_buf(0xDEAD_BEEF_CAFE_F00D, 1024 * 1024),
    );
}

#[test]
fn frozen_zero_boundaries_and_hashes_match_all_engines() {
    assert_golden("ZEROS", &vec![0; 640 * 1024]);
}

#[test]
fn frozen_edited_boundaries_and_hashes_match_all_engines() {
    let original = pseudo_random_buf(0xDEAD_BEEF_CAFE_F00D, 1024 * 1024);
    let mut edited = original[..512 * 1024].to_vec();
    for _ in 0..317 {
        edited.extend_from_slice(b"one-link-edit\0");
    }
    edited.extend_from_slice(&original[512 * 1024..]);
    assert_golden("EDITED", &edited);
}

#[test]
fn determinism_across_repeated_scans() {
    let buf = pseudo_random_buf(0x4242_4242_4242_4242, 256 * 1024);
    let a = scan_to_vec(&buf);
    let b = scan_to_vec(&buf);
    assert_eq!(a, b);
}

#[test]
fn distinct_inputs_produce_distinct_addresses() {
    // Two buffers differing in one byte must produce different chunk
    // addresses for any chunk that contains the differing byte. This is
    // the BLAKE3 collision-resistance property carried up to chunk level.
    let buf_a = pseudo_random_buf(0x1, 128 * 1024);
    let mut buf_b = buf_a.clone();
    let mid = buf_b.len() / 2;
    buf_b[mid] = buf_b[mid].wrapping_add(1);

    let bounds_a = scan_to_vec(&buf_a);
    let bounds_b = scan_to_vec(&buf_b);

    // Find a boundary in A that contains the modified byte.
    let modified = buf_a.len() / 2;
    let containing_a = bounds_a
        .iter()
        .find(|b| b.start <= modified && modified < b.end);
    let containing_b = bounds_b
        .iter()
        .find(|b| b.start <= modified && modified < b.end);
    assert!(containing_a.is_some());
    assert!(containing_b.is_some());

    // The chunk address that covers the modified byte MUST differ between
    // the two buffers.
    if let (Some(a), Some(b)) = (containing_a, containing_b) {
        assert_ne!(a.raw_address, b.raw_address);
    }
}
