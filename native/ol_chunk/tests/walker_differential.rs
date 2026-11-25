//! Container walkers: in memory, from a file, and against a reference.
//!
//! `format_aware::{mp4_box_offsets, mcap_record_offsets, wav_data_offset}` and
//! `stream::*_seekable` are one walker over two byte sources, so they agree by
//! construction. That is not evidence the walker is right, so every input here
//! is also walked by an independent reference written in `u128` arithmetic, in
//! which no position can wrap. The in-memory and file format-aware scans are
//! compared as well; for the record-framed formats they do NOT share code
//! (serial vs windowed parallel CDC, collected vs online cut absorption).
//!
//! Before the walkers were shared, the in-memory MP4 walker evaluated `pos + 8`
//! after a 64-bit box size had moved `pos` near `usize::MAX`: 16 bytes
//! (`0000000166747970fffffffffffffffc`) indexed out of bounds and aborted the
//! host, while the file walker returned one plain chunk for the same bytes.

use std::io::Cursor;

use ol_chunk::format_aware::{
    h264_keyframe_offsets, mcap_record_offsets, mp4_box_offsets, wav_data_offset, MCAP_MAGIC,
};
use ol_chunk::stream::{
    mcap_record_offsets_seekable, mp4_box_offsets_seekable, scan_format_aware_seekable,
    wav_data_offset_seekable,
};
use ol_chunk::{
    detect_format, scan_format_aware, zip_lfh_offsets, CdcParams, ContainerFormat, ZIP_LFH_MAGIC,
};

const TINY: CdcParams = CdcParams {
    min_size: 64,
    avg_size: 256,
    max_size: 1024,
};

const FORMATS: [ContainerFormat; 5] = [
    ContainerFormat::Mp4,
    ContainerFormat::Mcap,
    ContainerFormat::Wav,
    ContainerFormat::Zip,
    ContainerFormat::H264AnnexB,
];

// ---------------------------------------------------------------------------
// Reference walkers: the documented framing rules, in u128.
// ---------------------------------------------------------------------------

fn wide(n: usize) -> u128 {
    u128::try_from(n).unwrap()
}

fn narrow(n: u128) -> usize {
    usize::try_from(n).unwrap()
}

fn field<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    b[at..at + N].try_into().unwrap()
}

fn reference_mp4(b: &[u8]) -> Vec<usize> {
    let len = wide(b.len());
    let (mut pos, mut out) = (0u128, Vec::new());
    while pos + 8 <= len {
        let at = narrow(pos);
        if !b[at + 4..at + 8]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b' ')
        {
            break;
        }
        out.push(at);
        let advance = match u32::from_be_bytes(field(b, at)) {
            0 => break,
            1 if pos + 16 > len => break,
            1 => u128::from(u64::from_be_bytes(field(b, at + 8))),
            size => u128::from(size),
        };
        if advance < 8 {
            break;
        }
        pos += advance;
    }
    out
}

fn reference_mcap(b: &[u8]) -> Vec<usize> {
    let len = wide(b.len());
    if len < 17 || b[..8] != MCAP_MAGIC || b[8] != 0x01 {
        return Vec::new();
    }
    let data_end = if len >= 16 && b[b.len() - 8..] == MCAP_MAGIC {
        len - 8
    } else {
        len
    };
    let (mut pos, mut out) = (8u128, Vec::new());
    while pos + 9 <= data_end {
        let at = narrow(pos);
        if b[at] == 0 {
            break;
        }
        let next = pos + 9 + u128::from(u64::from_le_bytes(field(b, at + 1)));
        if next > data_end {
            break;
        }
        out.push(at);
        pos = next;
    }
    out
}

fn reference_wav(b: &[u8]) -> Option<usize> {
    let len = wide(b.len());
    if len < 12 || &b[0..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12u128;
    while pos + 8 <= len {
        let at = narrow(pos);
        if &b[at..at + 4] == b"data" {
            return Some(at);
        }
        let size = u128::from(u32::from_le_bytes(field(b, at + 4)));
        pos += 8 + size + (size & 1);
    }
    None
}

// ---------------------------------------------------------------------------
// Checks applied to every input.
// ---------------------------------------------------------------------------

/// Every walker, in memory and from a file, equals the reference. Returns the
/// reference results so callers can assert expected values and coverage.
fn check_walkers(b: &[u8], label: &str) -> (Vec<usize>, Vec<usize>, Option<usize>) {
    let len = b.len();
    let mp4 = reference_mp4(b);
    assert_eq!(mp4_box_offsets(b), mp4, "mp4 in memory, {label}");
    assert_eq!(
        mp4_box_offsets_seekable(&mut Cursor::new(b), len).unwrap(),
        mp4,
        "mp4 from a file, {label}"
    );
    let mcap = reference_mcap(b);
    assert_eq!(mcap_record_offsets(b), mcap, "mcap in memory, {label}");
    assert_eq!(
        mcap_record_offsets_seekable(&mut Cursor::new(b), len).unwrap(),
        mcap,
        "mcap from a file, {label}"
    );
    let wav = reference_wav(b);
    assert_eq!(wav_data_offset(b), wav, "wav in memory, {label}");
    assert_eq!(
        wav_data_offset_seekable(&mut Cursor::new(b), len).unwrap(),
        wav,
        "wav from a file, {label}"
    );
    // The byte-scan walkers have no size fields; they must stay in bounds
    // and ordered on anything.
    for offsets in [zip_lfh_offsets(b), h264_keyframe_offsets(b)] {
        assert!(offsets.iter().all(|&o| o < len), "{label}");
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "{label}");
    }
    for ext in [None, Some("mp4"), Some("wav"), Some("h264"), Some("mcap")] {
        let _ = detect_format(b, ext);
    }
    (mp4, mcap, wav)
}

/// The in-memory and file format-aware scans agree, for every format.
fn check_scans(b: &[u8], label: &str) {
    for format in FORMATS {
        for params in [TINY, CdcParams::default()] {
            let mem = scan_format_aware(b, Some(format), params).unwrap();
            let file = scan_format_aware_seekable(
                &mut Cursor::new(b),
                b.len(),
                Some(format),
                params,
                usize::MAX,
            )
            .unwrap();
            assert_eq!(
                file.boundaries, mem.boundaries,
                "{format:?} {params:?}, {label}"
            );
            assert_eq!(
                file.format_aware, mem.format_aware,
                "{format:?} {params:?}, {label}"
            );
            let mut expected_start = 0;
            for boundary in &mem.boundaries {
                assert_eq!(
                    boundary.start, expected_start,
                    "{format:?} {params:?}, {label}"
                );
                assert!(
                    boundary.end > boundary.start,
                    "{format:?} {params:?}, {label}"
                );
                expected_start = boundary.end;
            }
            assert_eq!(expected_start, b.len(), "{format:?} {params:?}, {label}");
        }
    }
}

// ---------------------------------------------------------------------------
// The witness.
// ---------------------------------------------------------------------------

#[test]
fn the_witnessed_16_byte_mp4_is_one_plain_chunk_in_memory_and_from_a_file() {
    let witness = hex::decode("0000000166747970fffffffffffffffc").unwrap();
    assert_eq!(detect_format(&witness, None), Some(ContainerFormat::Mp4));
    let (mp4, _, _) = check_walkers(&witness, "witness");
    // The ftyp box is visited; its 64-bit size (2^64 - 4) leaves the source.
    assert_eq!(mp4, vec![0]);
    let set =
        scan_format_aware(&witness, Some(ContainerFormat::Mp4), CdcParams::default()).unwrap();
    // What the Python binding's format_aware_boundaries(b, "mp4") returns:
    // [(0, 16, False)], addressed by the BLAKE3 of the whole input.
    let rows: Vec<(usize, usize, bool)> = set
        .boundaries
        .iter()
        .zip(&set.format_aware)
        .map(|(b, &forced)| (b.start, b.end, forced))
        .collect();
    assert_eq!(rows, vec![(0, 16, false)]);
    assert_eq!(
        set.boundaries[0].raw_address,
        *blake3::hash(&witness).as_bytes()
    );
    check_scans(&witness, "witness");
}

#[test]
fn every_64_bit_box_size_that_lands_near_the_end_of_the_address_space_is_total() {
    // 64-bit sizes 2^64 - 1 - k from box 0 (pos + size just below 2^64) and
    // from a box at offset 8 (pos + size on both sides of 2^64). Every value
    // that put pos within 8 bytes of usize::MAX wrapped `pos + 8` in the old
    // in-memory walker; k = 3 at box 0 is the witness.
    for k in 0..=24u64 {
        let size = u64::MAX - k;
        let at_zero = [&1u32.to_be_bytes()[..], b"ftyp", &size.to_be_bytes()].concat();
        assert_eq!(check_walkers(&at_zero, &format!("k {k}")).0, vec![0]);
        check_scans(&at_zero, &format!("k {k}"));
        let at_eight = [
            &8u32.to_be_bytes()[..],
            b"ftyp",
            &1u32.to_be_bytes(),
            b"mdat",
            &size.to_be_bytes(),
        ]
        .concat();
        assert_eq!(
            check_walkers(&at_eight, &format!("k {k} at 8")).0,
            vec![0, 8]
        );
        check_scans(&at_eight, &format!("k {k} at 8"));
    }
}

// ---------------------------------------------------------------------------
// Every boundary value of each format's length field.
// ---------------------------------------------------------------------------

/// `ftyp` (header only) at 0, the probed box at 8, a run-to-EOF `free` box,
/// then 8 trailing bytes.
fn mp4_probe(size_field: u32, largesize: Option<u64>) -> Vec<u8> {
    let mut b = [
        &8u32.to_be_bytes()[..],
        b"ftyp",
        &size_field.to_be_bytes(),
        b"moov",
    ]
    .concat();
    if let Some(large) = largesize {
        b.extend_from_slice(&large.to_be_bytes());
    }
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(b"free");
    b.extend_from_slice(&[0xAB; 8]);
    b
}

#[test]
fn every_boundary_mp4_box_size_walks_identically() {
    // 32-bit size field; the buffer is 32 bytes and `free` sits at 16.
    for (size, expected) in [
        (0, vec![0, 8]),        // runs to EOF: the last box
        (7, vec![0, 8]),        // smaller than its header: cannot advance
        (8, vec![0, 8, 16]),    // header only: `free` follows
        (24, vec![0, 8]),       // ends exactly at EOF
        (25, vec![0, 8]),       // one byte past the end
        (u32::MAX, vec![0, 8]), // far past the end
    ] {
        let b = mp4_probe(size, None);
        assert_eq!(
            check_walkers(&b, &format!("size {size}")).0,
            expected,
            "size {size}"
        );
        check_scans(&b, &format!("size {size}"));
    }
    // size == 1: a 64-bit size follows; the buffer is 40 bytes, `free` at 24.
    for (large, expected) in [
        (0, vec![0, 8]),
        (1, vec![0, 8]),
        (7, vec![0, 8]),
        (8, vec![0, 8]),      // lands on its own size field, whose type is not ASCII
        (16, vec![0, 8, 24]), // header only: `free` follows
        (32, vec![0, 8]),     // ends exactly at EOF
        (33, vec![0, 8]),     // one byte past the end
        (u64::from(u32::MAX), vec![0, 8]),
        (u64::MAX - 11, vec![0, 8]), // pos = usize::MAX - 3
        (u64::MAX - 8, vec![0, 8]),  // pos = usize::MAX
        (u64::MAX - 7, vec![0, 8]),  // pos + size = 2^64
        (u64::MAX, vec![0, 8]),
    ] {
        let b = mp4_probe(1, Some(large));
        assert_eq!(
            check_walkers(&b, &format!("large {large}")).0,
            expected,
            "large {large}"
        );
        check_scans(&b, &format!("large {large}"));
    }
    // A 64-bit size announced with no room for it.
    let truncated = [
        &8u32.to_be_bytes()[..],
        b"ftyp",
        &1u32.to_be_bytes(),
        b"mdat",
        &[0; 4],
    ]
    .concat();
    assert_eq!(
        check_walkers(&truncated, "truncated largesize").0,
        vec![0, 8]
    );
}

/// Header record at 8, the probed record at 21 with `body` content bytes, a
/// footer record, then the trailing magic (excluded from the record area).
fn mcap_probe(content_len: u64, body: usize) -> Vec<u8> {
    let mut b = MCAP_MAGIC.to_vec();
    b.push(0x01);
    b.extend_from_slice(&4u64.to_le_bytes());
    b.extend_from_slice(b"ros2");
    b.push(0x05);
    b.extend_from_slice(&content_len.to_le_bytes());
    b.extend(std::iter::repeat_n(0x5A, body));
    b.push(0x02);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&MCAP_MAGIC);
    b
}

#[test]
fn every_boundary_mcap_record_length_walks_identically() {
    for body in [0, 1, 7, 8] {
        let b = mcap_probe(u64::try_from(body).unwrap(), body);
        let expected = vec![8, 21, 30 + body];
        assert_eq!(check_walkers(&b, &format!("body {body}")).1, expected);
        check_scans(&b, &format!("body {body}"));
    }
    // With 8 content bytes the record area ends at 47 (footer included).
    for (content_len, expected) in [
        (17, vec![8, 21]), // swallows the footer, ends at the area's end
        (18, vec![8]),     // one byte past the record area
        (u64::from(u32::MAX), vec![8]),
        (u64::MAX - 30, vec![8]), // 21 + 9 + len = usize::MAX
        (u64::MAX - 29, vec![8]), // 21 + 9 + len = 2^64
        (u64::MAX, vec![8]),
    ] {
        let b = mcap_probe(content_len, 8);
        assert_eq!(check_walkers(&b, &format!("len {content_len}")).1, expected);
        check_scans(&b, &format!("len {content_len}"));
    }
}

/// `RIFF....WAVE`, a `LIST` sub-chunk declaring `size` with `body` bytes
/// (payload and any pad), then a `data` sub-chunk.
fn wav_probe(size: u32, body: usize) -> Vec<u8> {
    let mut b = b"RIFF\0\0\0\0WAVE".to_vec();
    b.extend_from_slice(b"LIST");
    b.extend_from_slice(&size.to_le_bytes());
    b.extend(std::iter::repeat_n(0x33, body));
    b.extend_from_slice(b"data");
    b.extend_from_slice(&4u32.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    b
}

#[test]
fn every_boundary_wav_chunk_size_walks_identically() {
    for (size, body, expected) in [
        (0, 0, Some(20)),
        (1, 2, Some(22)), // odd: one pad byte
        (7, 8, Some(28)),
        (8, 8, Some(28)),
        (20, 8, None), // ends exactly at EOF: `data` is skipped over
        (21, 8, None), // odd: with its pad byte, two past the end
        (22, 8, None), // past the end
        (u32::MAX, 0, None),
        (u32::MAX - 1, 0, None),
    ] {
        let b = wav_probe(size, body);
        assert_eq!(
            check_walkers(&b, &format!("size {size}")).2,
            expected,
            "size {size}"
        );
        check_scans(&b, &format!("size {size}"));
    }
}

// ---------------------------------------------------------------------------
// Walks that refill the seekable reader's 64 KiB header window.
// ---------------------------------------------------------------------------

#[test]
fn walks_that_cross_the_header_read_ahead_window_agree() {
    let mut rng = Rng(0x00C0_FFEE_D00D_F00D);
    let mut mp4 = Vec::new();
    for i in 0..64usize {
        let body = 2_731 + i % 7;
        if i % 5 == 0 {
            mp4.extend_from_slice(&1u32.to_be_bytes());
            mp4.extend_from_slice(b"mdat");
            mp4.extend_from_slice(&u64::try_from(body + 16).unwrap().to_be_bytes());
        } else {
            mp4.extend_from_slice(&u32::try_from(body + 8).unwrap().to_be_bytes());
            mp4.extend_from_slice(b"moov");
        }
        mp4.extend(rng.bytes(body));
    }
    let mut mcap = MCAP_MAGIC.to_vec();
    mcap.push(0x01);
    mcap.extend_from_slice(&0u64.to_le_bytes());
    for i in 0..80usize {
        let body = 1_999 + i % 3;
        mcap.push(0x05);
        mcap.extend_from_slice(&u64::try_from(body).unwrap().to_le_bytes());
        mcap.extend(rng.bytes(body));
    }
    mcap.extend_from_slice(&MCAP_MAGIC);
    let mut wav = b"RIFF\0\0\0\0WAVE".to_vec();
    for _ in 0..30 {
        wav.extend_from_slice(b"LIST");
        wav.extend_from_slice(&4_999u32.to_le_bytes());
        wav.extend(rng.bytes(5_000));
    }
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&4u32.to_le_bytes());
    wav.extend_from_slice(&[0; 4]);
    let (mp4_offsets, _, _) = check_walkers(&mp4, "mp4 across windows");
    assert_eq!(mp4_offsets.len(), 64);
    let (_, mcap_offsets, _) = check_walkers(&mcap, "mcap across windows");
    assert_eq!(mcap_offsets.len(), 81);
    let (_, _, wav_offset) = check_walkers(&wav, "wav across windows");
    assert_eq!(wav_offset, Some(12 + 30 * 5_008));
    for (b, label) in [(&mp4, "mp4"), (&mcap, "mcap"), (&wav, "wav")] {
        check_scans(b, label);
    }
}

// ---------------------------------------------------------------------------
// Seeded random and hostile headers.
// ---------------------------------------------------------------------------

/// `SplitMix64`: deterministic, so a failure names a reproducible case.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(u64::try_from(n).unwrap())).unwrap()
    }
    fn u32(&mut self) -> u32 {
        u32::try_from(self.next() >> 32).unwrap()
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

fn len64(b: &[u8]) -> u64 {
    u64::try_from(b.len()).unwrap()
}

/// Truncate inside the structure, append garbage, or leave it whole.
fn damage(rng: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    match rng.below(4) {
        0 => {
            let keep = rng.index(b.len() + 1);
            b.truncate(keep);
        }
        1 => {
            let extra = rng.index(17);
            b.extend(rng.bytes(extra));
        }
        _ => {}
    }
    b
}

// Each generator emits a chain of records, each honest half the time and
// otherwise hostile, so hostile sizes are met at every depth of a walk rather
// than mostly at the first header.

fn hostile_mp4(rng: &mut Rng) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.index(10) {
        let pos = len64(&b);
        let body = rng.index(48);
        let body64 = u64::try_from(body).unwrap();
        let honest = rng.chance(2);
        let kind: [u8; 4] = match rng.below(if honest { 5 } else { 9 }) {
            0 => *b"ftyp",
            1 => *b"moov",
            2 => *b"mdat",
            3 => *b"free",
            4 => *b"m ov",
            5 => [b'a', 0, b'c', b'd'],
            6 => [0xFF; 4],
            7 => [rng.byte(), rng.byte(), rng.byte(), rng.byte()],
            _ => *b"uuid",
        };
        let size: u32 = if honest {
            if rng.chance(4) {
                1
            } else {
                u32::try_from(body64 + 8).unwrap()
            }
        } else {
            match rng.below(7) {
                0 => 0,
                1 => 1,
                2 => 2 + rng.u32() % 6,
                3 => 8,
                4 => u32::MAX - rng.u32() % 32,
                5 => u32::try_from(body64 + 9 + rng.below(100)).unwrap(),
                _ => rng.u32(),
            }
        };
        b.extend_from_slice(&size.to_be_bytes());
        b.extend_from_slice(&kind);
        if size == 1 {
            let large: u64 = if honest {
                body64 + 16
            } else {
                match rng.below(5) {
                    0 => rng.below(17),
                    1 => u64::MAX - rng.below(32),
                    // pos + large within a few bytes of 2^64
                    2 => (u64::MAX - pos).wrapping_add(rng.below(9)).wrapping_sub(4),
                    3 => body64 + 17 + rng.below(1000),
                    _ => rng.next(),
                }
            };
            b.extend_from_slice(&large.to_be_bytes());
        }
        b.extend(rng.bytes(body));
    }
    damage(rng, b)
}

fn hostile_mcap(rng: &mut Rng) -> Vec<u8> {
    let mut b = MCAP_MAGIC.to_vec();
    if rng.chance(16) {
        let at = rng.index(8);
        b[at] ^= 0x20;
    }
    b.push(u8::from(!rng.chance(10))); // opcode 0x01, or 0 one time in ten
    b.extend_from_slice(&4u64.to_le_bytes());
    b.extend_from_slice(b"ros2");
    for _ in 0..rng.index(10) {
        let pos = len64(&b);
        let body = rng.index(40);
        let body64 = u64::try_from(body).unwrap();
        let honest = rng.chance(2);
        b.push(if !honest && rng.chance(5) {
            0
        } else {
            1 + rng.byte() % 0xFF
        });
        let content_len: u64 = if honest {
            body64
        } else {
            match rng.below(7) {
                0 => rng.below(9),
                1 => u64::from(u32::MAX) - rng.below(4),
                2 => u64::MAX - rng.below(32),
                // pos + 9 + len within a few bytes of 2^64
                3 => (u64::MAX - pos - 9)
                    .wrapping_add(rng.below(9))
                    .wrapping_sub(4),
                4 => body64 + 1 + rng.below(100),
                5 => body64.saturating_sub(1 + rng.below(4)),
                _ => rng.next(),
            }
        };
        b.extend_from_slice(&content_len.to_le_bytes());
        b.extend(rng.bytes(body));
    }
    if rng.chance(2) {
        b.extend_from_slice(&MCAP_MAGIC);
    }
    damage(rng, b)
}

fn hostile_wav(rng: &mut Rng) -> Vec<u8> {
    let mut b = b"RIFF".to_vec();
    b.extend_from_slice(&rng.u32().to_le_bytes());
    b.extend_from_slice(b"WAVE");
    if rng.chance(16) {
        let at = rng.index(12);
        b[at] ^= 0x01;
    }
    for _ in 0..rng.index(8) {
        let body = rng.index(40);
        let body32 = u32::try_from(body).unwrap();
        let honest = rng.chance(2);
        let id: [u8; 4] = match rng.below(6) {
            0 => *b"fmt ",
            1 => *b"LIST",
            2 => *b"data",
            3 => [0; 4],
            4 => [rng.byte(), rng.byte(), rng.byte(), rng.byte()],
            _ => *b"junk",
        };
        let size: u32 = if honest {
            body32
        } else {
            match rng.below(5) {
                0 => rng.u32() % 9,
                1 => u32::MAX - rng.u32() % 4,
                2 => body32 + 1 + rng.u32() % 100,
                3 => body32.saturating_sub(1),
                _ => rng.u32(),
            }
        };
        b.extend_from_slice(&id);
        b.extend_from_slice(&size.to_le_bytes());
        b.extend(rng.bytes(body));
        // An honest odd-sized sub-chunk carries its pad byte; a hostile one
        // may or may not.
        if body % 2 == 1 && (honest || rng.chance(2)) {
            b.push(0);
        }
    }
    damage(rng, b)
}

fn hostile_byte_scan(rng: &mut Rng) -> Vec<u8> {
    let n = rng.index(1024);
    let mut b = rng.bytes(n);
    for _ in 0..rng.index(12) {
        let at = rng.index(b.len() + 1);
        let insert: Vec<u8> = match rng.below(3) {
            0 => [&ZIP_LFH_MAGIC[..], &rng.bytes(26)].concat(),
            1 => vec![0, 0, 0, 1, rng.byte()],
            _ => vec![0, 0, 1, rng.byte()],
        };
        let tail = b.split_off(at);
        b.extend(insert);
        b.extend(tail);
    }
    b
}

#[test]
fn seeded_hostile_headers_walk_identically_in_memory_from_a_file_and_in_the_reference() {
    const SEED: u64 = 0x0001_2026_1124_0088;
    const CASES: usize = 6_000;
    let mut rng = Rng(SEED);
    let (mut mp4_multi, mut mcap_multi, mut wav_found) = (0, 0, 0);
    for case in 0..CASES {
        let data = match case % 5 {
            0 => hostile_mp4(&mut rng),
            1 => hostile_mcap(&mut rng),
            2 => hostile_wav(&mut rng),
            3 => hostile_byte_scan(&mut rng),
            _ => {
                let n = rng.index(256);
                rng.bytes(n)
            }
        };
        let label = format!("seed {SEED:#x} case {case} bytes {}", hex::encode(&data));
        // Every walker on every input, not only on its own format.
        let (mp4, mcap, wav) = check_walkers(&data, &label);
        check_scans(&data, &label);
        mp4_multi += usize::from(mp4.len() >= 2);
        mcap_multi += usize::from(mcap.len() >= 2);
        wav_found += usize::from(wav.is_some());
    }
    // The generators reach past the first header often enough to matter.
    assert!(
        mp4_multi > 300 && mcap_multi > 300 && wav_found > 200,
        "coverage: mp4 {mp4_multi}, mcap {mcap_multi}, wav {wav_found}"
    );
}
