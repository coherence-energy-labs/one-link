//! Format-aware chunking v2 resynchronises after an edit to a dense container.
//!
//! The witness (`dense_resync.py`, here as Rust): v1 is a valid 64 MiB MCAP of
//! equal 32-byte records, v2 is v1 with one record inserted after record 1000,
//! and "re-sent" is the bytes of v2's chunks whose BLAKE3 address is not among
//! v1's. Format-aware v1 chunking re-sent 100% (a cut chain anchored only on
//! the previous cut is fixed-size chunking at record granularity); plain
//! `FastCDC` re-sent 0.1%.
//!
//! The bound asserted for one edit of `L` bytes at byte `p`, with the horizon
//! `h = max(avg_size / 2, min_size)`, is
//!
//! ```text
//! re-sent <= 2h + L + 2 * max_size
//! ```
//!
//! Derivation: a dense candidate's decision depends only on the candidates
//! within `h` of it, so decisions differ only for candidates in
//! `[p - h, p + L + h]`. Kept dense cuts are at least `h >= min_size` apart, so
//! absorption keeps every one of them and the accepted cuts outside that
//! interval are the same in both versions (shifted by `L`). Every chunk lying
//! outside the interval and its two straddling chunks is therefore unchanged,
//! and each straddling chunk is at most `max_size`. (A segment longer than
//! `max_size` is split by `FastCDC`, which itself resynchronises within about a
//! chunk; the bound assumes it does so within the straddling chunk.) For the
//! default profile the bound is 576 KiB + `L`, under 1% of these logs; the
//! measured re-sent is about one average chunk.
//!
//! The mean over many edit positions is bounded by the expected length of that
//! region, `2h + L + E[S^2] / E[S]`, where `S` is the chunk size: a random point
//! lies a residual `E[S^2] / 2E[S]` into its chunk on each side.

use std::collections::HashSet;
use std::io::Cursor;

use ol_chunk::format_aware::{mcap_record_offsets, MCAP_MAGIC};
use ol_chunk::stream::scan_format_aware_seekable;
use ol_chunk::{
    scan_format_aware, zip_lfh_offsets, Boundary, CdcParams, ChunkScanner, ContainerFormat,
    FormatAwareChunkSet, ZIP_LFH_MAGIC,
};

const P: CdcParams = CdcParams {
    min_size: 8 * 1024,
    avg_size: 64 * 1024,
    max_size: 256 * 1024,
};

fn horizon() -> usize {
    (P.avg_size as usize / 2).max(P.min_size as usize)
}

fn edit_bound(edit_len: usize) -> usize {
    2 * horizon() + edit_len + 2 * P.max_size as usize
}

struct XorShift(u64);

impl XorShift {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0.to_le_bytes()[4]
            })
            .collect()
    }
    fn below(&mut self, n: usize) -> usize {
        let word = u64::from_le_bytes(self.bytes(8).try_into().unwrap());
        usize::try_from(word % u64::try_from(n).unwrap()).unwrap()
    }
}

/// A valid MCAP: magic, Header record, one Message-opcode record per payload,
/// trailing magic.
fn mcap(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut out = MCAP_MAGIC.to_vec();
    out.push(0x01);
    out.extend_from_slice(&4u64.to_le_bytes());
    out.extend_from_slice(b"ros2");
    for p in payloads {
        out.push(0x05);
        out.extend_from_slice(&u64::try_from(p.len()).unwrap().to_le_bytes());
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&MCAP_MAGIC);
    out
}

/// A ZIP of stored members (local file headers and data; the central
/// directory is not needed by the walker). Each member's name and CRC field
/// come from its own bytes, so inserting a member renames no other.
fn zip(members: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in members {
        let id = blake3::hash(m);
        let id = id.as_bytes();
        out.extend_from_slice(&ZIP_LFH_MAGIC);
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, stored, time, date
        out.extend_from_slice(&id[..4]); // crc-32 field
        let size = u32::try_from(m.len()).unwrap().to_le_bytes();
        out.extend_from_slice(&size);
        out.extend_from_slice(&size);
        let name = format!("word/part-{}.xml", hex::encode(&id[4..8]));
        out.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(m);
    }
    out
}

fn resent(v1: &[Boundary], v2: &[Boundary]) -> usize {
    let known: HashSet<[u8; 32]> = v1.iter().map(|b| b.raw_address).collect();
    v2.iter()
        .filter(|b| !known.contains(&b.raw_address))
        .map(|b| b.end - b.start)
        .sum()
}

/// Format-aware chunking v1, from the public candidate offsets: keep every
/// candidate, absorb any closer than `min_size` to the previously accepted one.
fn v1_chained(buf: &[u8], candidates: &[usize]) -> FormatAwareChunkSet {
    let min = P.min_size as usize;
    let mut cuts = Vec::new();
    let mut last = 0;
    for &c in candidates {
        if c >= last + min && c + min <= buf.len() {
            cuts.push(c);
            last = c;
        }
    }
    if cuts.is_empty() {
        return scan_format_aware(buf, None, P).unwrap();
    }
    let edges: Vec<usize> = std::iter::once(0).chain(cuts).chain([buf.len()]).collect();
    let mut out = FormatAwareChunkSet {
        boundaries: Vec::new(),
        format_aware: Vec::new(),
    };
    for (segment, w) in edges.windows(2).enumerate() {
        let (s, e) = (w[0], w[1]);
        let chunks: Vec<Boundary> = if e - s <= P.max_size as usize {
            vec![Boundary {
                start: 0,
                end: e - s,
                raw_address: *blake3::hash(&buf[s..e]).as_bytes(),
            }]
        } else {
            ChunkScanner::with_params(&buf[s..e], P).unwrap().collect()
        };
        for (i, b) in chunks.into_iter().enumerate() {
            out.boundaries.push(Boundary {
                start: b.start + s,
                end: b.end + s,
                raw_address: b.raw_address,
            });
            out.format_aware.push(i == 0 && segment > 0);
        }
    }
    out
}

fn fa(buf: &[u8], format: ContainerFormat) -> Vec<Boundary> {
    scan_format_aware(buf, Some(format), P).unwrap().boundaries
}

fn plain(buf: &[u8]) -> Vec<Boundary> {
    scan_format_aware(buf, None, P).unwrap().boundaries
}

/// Offset of record `k` in a [`dense_mcap`] log of `record`-byte records.
fn record_offset(record: usize, k: usize) -> usize {
    MCAP_MAGIC.len() + 13 + k * record
}

/// A valid MCAP of `count` equal `record`-byte Message records with
/// pseudo-random payloads, built flat (no per-record allocation).
fn dense_mcap(record: usize, count: usize, rng: &mut XorShift) -> Vec<u8> {
    let mut out = Vec::with_capacity(record_offset(record, count) + MCAP_MAGIC.len());
    out.extend_from_slice(&MCAP_MAGIC);
    out.push(0x01);
    out.extend_from_slice(&4u64.to_le_bytes());
    out.extend_from_slice(b"ros2");
    let header = u64::try_from(record - 9).unwrap().to_le_bytes();
    for _ in 0..count {
        out.push(0x05);
        out.extend_from_slice(&header);
        out.extend(rng.bytes(record - 9));
    }
    out.extend_from_slice(&MCAP_MAGIC);
    out
}

/// One Message record with a fresh payload.
fn fresh_record(record: usize, rng: &mut XorShift) -> Vec<u8> {
    let mut out = vec![0x05];
    out.extend_from_slice(&u64::try_from(record - 9).unwrap().to_le_bytes());
    out.extend(rng.bytes(record - 9));
    out
}

type DenseEdit = (
    &'static str,
    fn(&[u8], usize, usize, &mut XorShift) -> Vec<u8>,
);

/// Insert a record after record `k`, delete record `k`, or flip the last byte
/// of record `k`: byte splices on a flat dense log.
fn dense_edits() -> [DenseEdit; 3] {
    [
        ("insert", |log, record, k, rng| {
            let at = record_offset(record, k + 1);
            [&log[..at], &fresh_record(record, rng), &log[at..]].concat()
        }),
        ("delete", |log, record, k, _| {
            let at = record_offset(record, k);
            [&log[..at], &log[at + record..]].concat()
        }),
        ("edit", |log, record, k, _| {
            let mut out = log.to_vec();
            out[record_offset(record, k) + record - 1] ^= 0xFF;
            out
        }),
    ]
}

type MemberEdit = (&'static str, fn(&mut Vec<Vec<u8>>, usize, &mut XorShift));

fn member_edits() -> [MemberEdit; 3] {
    [
        ("insert", |v, at, rng| {
            let n = v[at].len();
            v.insert(at + 1, rng.bytes(n));
        }),
        ("delete", |v, at, _| {
            v.remove(at);
        }),
        ("edit", |v, at, _| {
            let last = v[at].len() - 1;
            v[at][last] ^= 0xFF;
        }),
    ]
}

/// Bytes of one stored member in [`zip`]: header, 22-byte name, data.
fn zip_entry_len(member: &[u8]) -> usize {
    30 + 22 + member.len()
}

#[test]
fn the_witnessed_64_mib_log_of_32_byte_records_resynchronises() {
    // dense_resync.py: equal 32-byte records, one inserted after record 1000.
    let mut rng = XorShift(0x0D15_EA5E_5EED_0007);
    let v1 = dense_mcap(32, (64 << 20) / 32, &mut rng);
    let v2 = (dense_edits()[0].1)(&v1, 32, 1000, &mut rng);
    assert_eq!(mcap_record_offsets(&v2).len(), (64 << 20) / 32 + 2);
    let format_aware = resent(
        &fa(&v1, ContainerFormat::Mcap),
        &fa(&v2, ContainerFormat::Mcap),
    );
    let plain_cdc = resent(&plain(&v1), &plain(&v2));
    assert!(
        format_aware <= edit_bound(32),
        "format-aware re-sent {format_aware} bytes, bound {} (plain FastCDC {plain_cdc})",
        edit_bound(32)
    );
    // The file API chunks v2 identically.
    let file = scan_format_aware_seekable(
        &mut Cursor::new(&v2),
        v2.len(),
        Some(ContainerFormat::Mcap),
        P,
        0,
    )
    .unwrap();
    assert_eq!(file.boundaries, fa(&v2, ContainerFormat::Mcap));
}

#[test]
fn dense_mcap_of_every_record_size_resynchronises_after_insert_delete_and_edit() {
    for record in [32usize, 100, 1024] {
        let mut rng = XorShift(0xACE0_0000 + u64::try_from(record).unwrap());
        let v1 = dense_mcap(record, (16 << 20) / record, &mut rng);
        let base = fa(&v1, ContainerFormat::Mcap);
        for (name, edit) in dense_edits() {
            let sent = resent(
                &base,
                &fa(&edit(&v1, record, 1000, &mut rng), ContainerFormat::Mcap),
            );
            assert!(
                sent <= edit_bound(record),
                "{record}-byte records, {name}: re-sent {sent}, bound {}",
                edit_bound(record)
            );
        }
    }
}

#[test]
fn a_zip_of_2000_small_members_resynchronises_after_insert_delete_and_edit() {
    let mut rng = XorShift(0x0000_2000_F11E);
    let members: Vec<Vec<u8>> = (0..2000)
        .map(|_| {
            let n = 500 + rng.below(6000);
            rng.bytes(n)
        })
        .collect();
    let v1 = zip(&members);
    assert_eq!(zip_lfh_offsets(&v1).len(), 2000);
    let base = fa(&v1, ContainerFormat::Zip);
    for at in [100, 1000, 1900] {
        for (name, edit) in member_edits() {
            let mut changed = members.clone();
            edit(&mut changed, at, &mut rng);
            let edit_len = zip_entry_len(&changed[at]).max(zip_entry_len(&members[at]));
            let sent = resent(&base, &fa(&zip(&changed), ContainerFormat::Zip));
            assert!(
                sent <= edit_bound(edit_len),
                "member {at}, {name}: re-sent {sent}, bound {}",
                edit_bound(edit_len)
            );
        }
    }
}

#[test]
fn the_mean_resent_over_many_edit_positions_stays_within_its_expectation() {
    let mut rng = XorShift(0x0000_3E57_1A7E);
    let count = (16 << 20) / 32;
    let v1 = dense_mcap(32, count, &mut rng);
    let base = fa(&v1, ContainerFormat::Mcap);
    // E[S^2] / E[S] from v1's own chunks (rounded down): no constant assumed.
    let (sum, sum_sq) = base.iter().fold((0u128, 0u128), |(s, q), b| {
        let len = (b.end - b.start) as u128;
        (s + len, q + len * len)
    });
    let expected_bound = (2 * horizon() + 32) as u128 + sum_sq / sum;
    let positions = 16usize;
    let mut total = 0usize;
    for e in 0..positions {
        let k = count / 10 + e * (count * 8 / 10) / positions;
        let v2 = (dense_edits()[0].1)(&v1, 32, k, &mut rng);
        total += resent(&base, &fa(&v2, ContainerFormat::Mcap));
    }
    assert!(
        total as u128 <= positions as u128 * expected_bound,
        "mean re-sent {} bytes, expected-region bound {expected_bound}",
        total / positions
    );
}

#[test]
fn the_v1_chained_rule_fails_the_same_resync_bound() {
    // The negative control: the bound above is not vacuous. On the witness
    // shape (equal records, one inserted early) v1 re-sends nearly the whole log.
    let mut rng = XorShift(0x0D15_EA5E_5EED_0007);
    let v1 = dense_mcap(32, (16 << 20) / 32, &mut rng);
    let v2 = (dense_edits()[0].1)(&v1, 32, 1000, &mut rng);
    let chained = resent(
        &v1_chained(&v1, &mcap_record_offsets(&v1)).boundaries,
        &v1_chained(&v2, &mcap_record_offsets(&v2)).boundaries,
    );
    assert!(
        chained > edit_bound(32) && chained > v2.len() * 9 / 10,
        "v1 re-sent {chained} of {} bytes",
        v2.len()
    );
    // And v2 passes on these very bytes.
    let v2_resent = resent(
        &fa(&v1, ContainerFormat::Mcap),
        &fa(&v2, ContainerFormat::Mcap),
    );
    assert!(v2_resent <= edit_bound(32), "v2 re-sent {v2_resent}");
}

#[test]
fn sparse_containers_chunk_exactly_as_v1_did() {
    let min = P.min_size as usize;
    let mut rng = XorShift(0x5BA_25E);
    // MCAP records of at least min_size, and logs where small records only
    // ever sit between large ones: no candidate has two sub-min neighbours.
    let large: Vec<Vec<u8>> = (0..120)
        .map(|_| {
            let n = min + rng.below(4 * P.avg_size as usize);
            rng.bytes(n)
        })
        .collect();
    let interleaved: Vec<Vec<u8>> = (0..240)
        .map(|i| {
            let n = if i % 2 == 0 {
                min + rng.below(3 * P.avg_size as usize)
            } else {
                1 + rng.below(min - 1)
            };
            rng.bytes(n)
        })
        .collect();
    for (name, payloads) in [("large", &large), ("interleaved", &interleaved)] {
        let buf = mcap(payloads);
        let v2 = scan_format_aware(&buf, Some(ContainerFormat::Mcap), P).unwrap();
        let v1 = v1_chained(&buf, &mcap_record_offsets(&buf));
        assert_eq!(v2.boundaries, v1.boundaries, "{name}");
        assert_eq!(v2.format_aware, v1.format_aware, "{name}");
    }
    let members: Vec<Vec<u8>> = (0..150)
        .map(|_| {
            let n = min + rng.below(2 * P.avg_size as usize);
            rng.bytes(n)
        })
        .collect();
    let buf = zip(&members);
    let v2 = scan_format_aware(&buf, Some(ContainerFormat::Zip), P).unwrap();
    let v1 = v1_chained(&buf, &zip_lfh_offsets(&buf));
    assert_eq!(v2.boundaries, v1.boundaries);
    assert_eq!(v2.format_aware, v1.format_aware);
}

#[test]
fn records_of_at_least_avg_size_start_a_format_forced_chunk() {
    let mut rng = XorShift(0xB16_2EC0);
    let payloads: Vec<Vec<u8>> = (0..80)
        .map(|_| {
            let n = P.avg_size as usize + rng.below(3 * P.avg_size as usize);
            rng.bytes(n)
        })
        .collect();
    let buf = mcap(&payloads);
    let set = scan_format_aware(&buf, Some(ContainerFormat::Mcap), P).unwrap();
    let forced: HashSet<usize> = set
        .boundaries
        .iter()
        .zip(&set.format_aware)
        .filter(|(_, f)| **f)
        .map(|(b, _)| b.start)
        .collect();
    let records = mcap_record_offsets(&buf);
    // Every record starts a forced chunk, except where absorption drops any
    // cut (as v1 did): within min_size of the start or of the end.
    let min = P.min_size as usize;
    let mut checked = 0;
    for &r in &records {
        if r >= min && r + min <= buf.len() {
            assert!(forced.contains(&r), "record at {r}");
            checked += 1;
        }
    }
    assert!(
        checked >= records.len() - 3,
        "{checked} of {}",
        records.len()
    );
}

/// BLAKE3 over every `(start, end, address, flag)` of a chunk set.
fn digest(set: &FormatAwareChunkSet) -> String {
    let mut h = blake3::Hasher::new();
    for (b, f) in set.boundaries.iter().zip(&set.format_aware) {
        h.update(&u64::try_from(b.start).unwrap().to_le_bytes());
        h.update(&u64::try_from(b.end).unwrap().to_le_bytes());
        h.update(&b.raw_address);
        h.update(&[u8::from(*f)]);
    }
    h.finalize().to_hex().to_string()
}

#[test]
fn format_aware_v2_boundaries_are_pinned() {
    // Frozen vectors for format-aware chunking v2, like cdc_golden_v1 for plain
    // CDC. They pin the definition (fingerprint, thinning, horizon, absorption)
    // against silent drift; they are not evidence of correctness. A deliberate
    // change needs a new chunking version and an ADR-0014 amendment: these
    // vectors and FORMAT_AWARE_CHUNKING_VERSION move together.
    assert_eq!(
        ol_chunk::FORMAT_AWARE_CHUNKING_VERSION,
        2,
        "the pinned vectors below define version 2; re-pin them with the new version"
    );
    let mut rng = XorShift(0x0F1_2E2E_0002);
    let dense: Vec<Vec<u8>> = (0..(4 << 20) / 40).map(|_| rng.bytes(31)).collect();
    let members: Vec<Vec<u8>> = (0..600)
        .map(|_| {
            let n = 200 + rng.below(4000);
            rng.bytes(n)
        })
        .collect();
    let mut fragmented = Vec::new();
    for _ in 0..3000 {
        for (kind, n) in [
            (b"moof", 40 + rng.below(80)),
            (b"mdat", 200 + rng.below(2000)),
        ] {
            fragmented.extend_from_slice(&u32::try_from(n + 8).unwrap().to_be_bytes());
            fragmented.extend_from_slice(kind);
            fragmented.extend(rng.bytes(n));
        }
    }
    let cases = [
        (mcap(&dense), ContainerFormat::Mcap),
        (zip(&members), ContainerFormat::Zip),
        (fragmented, ContainerFormat::Mp4),
    ];
    let got: Vec<String> = cases
        .iter()
        .map(|(buf, format)| digest(&scan_format_aware(buf, Some(*format), P).unwrap()))
        .collect();
    assert_eq!(
        got,
        [
            "20682fdca687f5a419e628479e7a591c14901cd80378adb36369ee13d9f42978".to_string(),
            "b024505143396a09ded4176f3187b4fd94c45d34db441d827c9e48e8b713f095".to_string(),
            "6efb41d5d984794f4d292613adf82747eee3e703d22e2d7ca62d1600fec72a4d".to_string()
        ]
    );
}
