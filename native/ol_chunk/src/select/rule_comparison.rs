//! Instrument, not a check: the v2 rule against the alternatives it was chosen
//! over, on the same candidates, fingerprints, absorption and segment chunking.
//!
//! ```sh
//! cargo test -p ol_chunk --release --lib rule_comparison -- --ignored --nocapture
//! ```
//!
//! Rules: `v1-chain` (keep every candidate), `S1 p=L/avg` (structural if a
//! neighbour unit is at least `avg_size`, else keep iff `fp * avg < L * 2^64`),
//! `local-max` (v2 without thinning) and `v2` (thinned local maximum, shipped).
//! Workloads: dense MCAP logs and a ZIP of 2,000 small members, each with one
//! record inserted, deleted or edited; and two degenerate logs whose records
//! share their first 32 bytes, or alternate between two such heads.
#![allow(clippy::cast_precision_loss)] // byte counts shown as KiB

use std::collections::HashSet;
use std::fmt::Write as _;

use super::{unit_fingerprint, CutSelector, HEAD_BYTES};
use crate::blake3_wrap::chunk_address_raw;
use crate::cdc::{CdcParams, ChunkScanner};
use crate::format_aware::{mcap_record_offsets, zip_lfh_offsets, MCAP_MAGIC, ZIP_LFH_MAGIC};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next().to_le_bytes()[2]).collect()
    }
}

#[derive(Clone, Copy)]
enum Rule {
    Chain,
    Probabilistic,
    LocalMax,
    V2,
}

fn heads(buf: &[u8], cands: &[usize]) -> Vec<(usize, Vec<u8>)> {
    cands
        .iter()
        .map(|&c| (c, buf[c..buf.len().min(c + HEAD_BYTES)].to_vec()))
        .collect()
}

fn absorb(cuts: impl IntoIterator<Item = usize>, len: usize, min: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut last = 0;
    for c in cuts {
        if c >= last + min && c + min <= len {
            out.push(c);
            last = c;
        }
    }
    out
}

fn select(rule: Rule, buf: &[u8], cands: &[usize], p: CdcParams) -> Vec<usize> {
    let (len, min, avg) = (buf.len(), p.min_size as usize, p.avg_size as usize);
    match rule {
        Rule::Chain => absorb(cands.iter().copied(), len, min),
        Rule::Probabilistic => {
            let ends: Vec<usize> = cands.iter().skip(1).copied().chain([len]).collect();
            let kept = cands.iter().enumerate().filter_map(|(i, &c)| {
                let unit = ends[i] - c;
                let before = c - if i == 0 { 0 } else { cands[i - 1] };
                let fp = unit_fingerprint(&buf[c..len.min(c + HEAD_BYTES)], unit);
                let keep = before.max(unit) >= avg
                    || u128::from(fp) * (avg as u128) < (unit as u128) << 64;
                keep.then_some(c)
            });
            absorb(kept, len, min)
        }
        Rule::LocalMax | Rule::V2 => {
            let mut selector = CutSelector::new(len, p);
            if matches!(rule, Rule::LocalMax) {
                selector = selector.with_survivor_rate(u64::MAX);
            }
            let mut out = Vec::new();
            for (pos, head) in heads(buf, cands) {
                selector.offer(pos, &head);
                while let Some(cut) = selector.pop_accepted() {
                    out.push(cut);
                }
            }
            selector.finish();
            while let Some(cut) = selector.pop_accepted() {
                out.push(cut);
            }
            out
        }
    }
}

/// `(address, length)` of every chunk: one per segment up to `max_size`, else CDC.
fn chunks(buf: &[u8], cuts: &[usize], p: CdcParams) -> Vec<([u8; 32], usize)> {
    let bounds: Vec<usize> = std::iter::once(0)
        .chain(cuts.iter().copied())
        .chain([buf.len()])
        .collect();
    let mut out = Vec::new();
    for w in bounds.windows(2) {
        let seg = &buf[w[0]..w[1]];
        if seg.len() <= p.max_size as usize {
            out.push((chunk_address_raw(seg), seg.len()));
        } else {
            out.extend(
                ChunkScanner::with_params(seg, p)
                    .unwrap()
                    .map(|b| (b.raw_address, b.length())),
            );
        }
    }
    out
}

fn mcap(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut b = MCAP_MAGIC.to_vec();
    b.push(1);
    b.extend_from_slice(&4u64.to_le_bytes());
    b.extend_from_slice(b"ros2");
    for p in payloads {
        b.push(5);
        b.extend_from_slice(&(p.len() as u64).to_le_bytes());
        b.extend_from_slice(p);
    }
    b.extend_from_slice(&MCAP_MAGIC);
    b
}

fn zip(members: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    for m in members {
        let crc = chunk_address_raw(m);
        b.extend_from_slice(&ZIP_LFH_MAGIC);
        b.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&crc[..4]);
        let size = u32::try_from(m.len()).unwrap().to_le_bytes();
        b.extend_from_slice(&size);
        b.extend_from_slice(&size);
        // A member's name belongs to the member, not to its position.
        let name = format!(
            "doc/part{:08x}.xml",
            u32::from_le_bytes([crc[4], crc[5], crc[6], crc[7]])
        );
        b.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(m);
    }
    b
}

type Edit = fn(&mut Vec<Vec<u8>>, usize, &mut Rng);

/// Edits are applied at `EDITS` positions spread over the log; each cell
/// reports the mean and the worst re-sent bytes over them.
const EDITS: usize = 24;

fn report(name: &str, items: &[Vec<u8>], build: fn(&[Vec<u8>]) -> Vec<u8>, zip_format: bool) {
    let p = CdcParams::default();
    let edits: [(&str, Edit); 3] = [
        ("insert", |v, at, r| {
            let n = v[at].len();
            v.insert(at + 1, r.bytes(n));
        }),
        ("delete", |v, at, _| {
            v.remove(at);
        }),
        ("edit", |v, at, _| {
            let last = v[at].len() - 1;
            v[at][last] ^= 0xFF;
        }),
    ];
    let v1 = build(items);
    let cands = |b: &[u8]| {
        if zip_format {
            zip_lfh_offsets(b)
        } else {
            mcap_record_offsets(b)
        }
    };
    let c1 = cands(&v1);
    for (rule_name, rule) in [
        ("v1-chain", Rule::Chain),
        ("S1 p=L/avg", Rule::Probabilistic),
        ("local-max", Rule::LocalMax),
        ("v2", Rule::V2),
    ] {
        let k1 = chunks(&v1, &select(rule, &v1, &c1, p), p);
        let known: HashSet<[u8; 32]> = k1.iter().map(|c| c.0).collect();
        let mean = v1.len() / k1.len();
        let mut line = format!(
            "  {name:26} {rule_name:11} chunks={:6} mean={:7.1}KiB",
            k1.len(),
            mean as f64 / 1024.0
        );
        for (edit_name, edit) in edits {
            let (mut total, mut worst) = (0usize, 0usize);
            for e in 0..EDITS {
                // Spread over the middle 80% of the log.
                let at = items.len() / 10 + e * (items.len() * 8 / 10) / EDITS;
                let mut items2 = items.to_vec();
                edit(&mut items2, at, &mut Rng(77 + e as u64));
                let v2 = build(&items2);
                let k2 = chunks(&v2, &select(rule, &v2, &cands(&v2), p), p);
                let sent: usize = k2
                    .iter()
                    .filter(|c| !known.contains(&c.0))
                    .map(|c| c.1)
                    .sum();
                total += sent;
                worst = worst.max(sent);
            }
            write!(
                line,
                "  {edit_name} {:7.1}/{:8.1}",
                total as f64 / EDITS as f64 / 1024.0,
                worst as f64 / 1024.0
            )
            .unwrap();
        }
        println!("{line}");
    }
}

#[test]
#[ignore = "instrument: prints the rule comparison"]
fn rule_comparison() {
    let mut rng = Rng(0x0D15_EA5E);
    println!(
        "re-sent KiB after one edit, mean/worst over {EDITS} edit positions \
         (default profile 8/64/256 KiB); logs of 16 MiB"
    );
    for record in [32usize, 100, 1024] {
        let payloads: Vec<Vec<u8>> = (0..(16 << 20) / record)
            .map(|_| rng.bytes(record - 9))
            .collect();
        report(&format!("MCAP {record} B records"), &payloads, mcap, false);
    }
    let members: Vec<Vec<u8>> = (0..2000)
        .map(|i| rng.bytes(1000 + (i * 7919) % 5000))
        .collect();
    report("ZIP 2000 small members", &members, zip, true);
    // Identical first 32 bytes (opcode, length, 23-byte constant prefix),
    // random tails: every unit fingerprints alike.
    let prefix = rng.bytes(23);
    let same_head: Vec<Vec<u8>> = (0..(16 << 20) / 100)
        .map(|_| [prefix.clone(), rng.bytes(91 - 23)].concat())
        .collect();
    report("MCAP identical heads", &same_head, mcap, false);
    let other = rng.bytes(23);
    let alternating: Vec<Vec<u8>> = (0..(16 << 20) / 100)
        .map(|i| {
            let head = if i % 2 == 0 { &prefix } else { &other };
            [head.clone(), rng.bytes(91 - 23)].concat()
        })
        .collect();
    report("MCAP alternating heads", &alternating, mcap, false);
    // S1's failure witness: a shared head that S1 keeps (fp * avg < L * 2^64,
    // probability L / avg per head, so found by search). S1 then keeps every
    // record: the v1 chain again. v2 ties on it and keeps none.
    let avg = u128::from(CdcParams::default().avg_size);
    // Expected after about avg / L = 655 tries; the bound only makes it total.
    let kept_head = (0u64..1_000_000)
        .map(|seed| Rng(seed + 1).bytes(23))
        .find(|prefix| {
            let mut head = vec![5u8];
            head.extend_from_slice(&91u64.to_le_bytes());
            head.extend_from_slice(prefix);
            u128::from(unit_fingerprint(&head, 100)) * avg < 100u128 << 64
        })
        .unwrap();
    let s1_witness: Vec<Vec<u8>> = (0..(16 << 20) / 100)
        .map(|_| [kept_head.clone(), rng.bytes(91 - 23)].concat())
        .collect();
    report("MCAP head S1 keeps", &s1_witness, mcap, false);
}
