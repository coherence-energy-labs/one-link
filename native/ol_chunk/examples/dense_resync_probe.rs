//! Dense-record format-aware probe: resynchronisation after one inserted record,
//! and throughput, for format-aware and plain chunking over the same bytes.
//!
//! ```sh
//! cargo run --release -p ol_chunk --example dense_resync_probe -- [scratch_dir]
//! ```
//!
//! Part 1 mirrors the dense-resync witness: v1 is a valid 64 MiB MCAP of equal
//! records with pseudo-random payloads, v2 is v1 with one record inserted after
//! record 1000, and "re-sent" is the bytes of v2's chunks whose BLAKE3 address
//! is not among v1's. Part 2 times every scan path over a 256 MiB dense MCAP of
//! 32-byte records (best of three runs). With a `scratch_dir` the seekable
//! paths are also timed over a real file written there (page-cache warm).
//! Only public API is used, so the same probe runs against any build.
#![allow(clippy::cast_precision_loss)] // byte counts shown as MiB and MiB/s

use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Write as _};
use std::path::PathBuf;
use std::time::Instant;

use ol_chunk::format_aware::MCAP_MAGIC;
use ol_chunk::stream::{scan_format_aware_seekable, scan_stream};
use ol_chunk::{scan_format_aware, scan_to_vec_parallel, Boundary, CdcParams, ContainerFormat};

const MIB: f64 = 1_048_576.0;

struct XorShift(u64);

impl XorShift {
    fn fill(&mut self, out: &mut Vec<u8>, n: usize) {
        for _ in 0..n {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            out.push(self.0.to_le_bytes()[5]);
        }
    }
}

/// A dense MCAP: magic, Header record, `count` Message-opcode records of
/// `record` bytes each (9-byte framing + payload), trailing magic. One extra
/// record is inserted after record `insert_after` when given.
fn dense_mcap(record: usize, count: usize, insert_after: Option<usize>) -> Vec<u8> {
    let payload = record - 9;
    let mut out = Vec::with_capacity(record * (count + 1) + 64);
    out.extend_from_slice(&MCAP_MAGIC);
    out.push(0x01);
    out.extend_from_slice(&4u64.to_le_bytes());
    out.extend_from_slice(b"ros2");
    let mut rng = XorShift(0x0D15_EA5E_5EED_0007);
    let mut extra = XorShift(0x1BAD_B002_CAFE_F00D);
    for i in 0..count {
        out.push(0x05);
        out.extend_from_slice(&(payload as u64).to_le_bytes());
        rng.fill(&mut out, payload);
        if Some(i) == insert_after {
            out.push(0x05);
            out.extend_from_slice(&(payload as u64).to_le_bytes());
            extra.fill(&mut out, payload);
        }
    }
    out.extend_from_slice(&MCAP_MAGIC);
    out
}

fn resent(v1: &[Boundary], v2: &[Boundary]) -> usize {
    let known: HashSet<[u8; 32]> = v1.iter().map(|b| b.raw_address).collect();
    v2.iter()
        .filter(|b| !known.contains(&b.raw_address))
        .map(|b| b.end - b.start)
        .sum()
}

fn best_of_three(label: &str, bytes: usize, mut run: impl FnMut() -> usize) {
    let mut best = f64::INFINITY;
    let mut chunks = 0;
    for _ in 0..3 {
        let t = Instant::now();
        chunks = run();
        best = best.min(t.elapsed().as_secs_f64());
    }
    println!(
        "  {label:44} {:9.1} MiB/s  chunks={chunks:8}  best={:.3}s",
        bytes as f64 / MIB / best,
        best
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = CdcParams::default();
    let scratch = std::env::args().nth(1).map(PathBuf::from);

    println!("resync after one inserted record (64 MiB dense MCAP):");
    for record in [32usize, 100, 1024] {
        let count = (64 << 20) / record;
        let v1 = dense_mcap(record, count, None);
        let v2 = dense_mcap(record, count, Some(1000));
        for (name, format) in [
            ("format_aware(mcap)", Some(ContainerFormat::Mcap)),
            ("plain FastCDC", None),
        ] {
            let a = scan_format_aware(&v1, format, params)?.boundaries;
            let b = scan_format_aware(&v2, format, params)?.boundaries;
            let sent = resent(&a, &b);
            println!(
                "  record={record:5}B  {name:20} chunks={:7}  resent={:8.2} MiB ({:5.1}%)",
                b.len(),
                sent as f64 / MIB,
                100.0 * sent as f64 / v2.len() as f64
            );
        }
    }

    let record = 32;
    let data = dense_mcap(record, (256 << 20) / record, None);
    let n = data.len();
    println!("throughput, 256 MiB dense MCAP of {record}-byte records:");
    best_of_three("in-memory scan_format_aware(Mcap)", n, || {
        scan_format_aware(&data, Some(ContainerFormat::Mcap), params)
            .unwrap()
            .len()
    });
    best_of_three("in-memory scan_format_aware(None)", n, || {
        scan_format_aware(&data, None, params).unwrap().len()
    });
    best_of_three("in-memory scan_to_vec_parallel (cdc_iter)", n, || {
        scan_to_vec_parallel(&data).len()
    });
    best_of_three("seekable(Cursor) format_aware(Mcap)", n, || {
        scan_format_aware_seekable(
            &mut Cursor::new(&data),
            n,
            Some(ContainerFormat::Mcap),
            params,
            usize::MAX,
        )
        .unwrap()
        .len()
    });
    best_of_three("seekable(Cursor) scan_stream (cdc_file)", n, || {
        scan_stream(Cursor::new(&data), n, params).unwrap().len()
    });
    if let Some(dir) = scratch {
        let path = dir.join("dense_resync_probe.mcap");
        File::create(&path)?.write_all(&data)?;
        best_of_three("file format_aware(Mcap) (format_aware_file)", n, || {
            let mut f = File::open(&path).unwrap();
            scan_format_aware_seekable(&mut f, n, Some(ContainerFormat::Mcap), params, 0)
                .unwrap()
                .len()
        });
        best_of_three("file scan_stream (cdc_file)", n, || {
            scan_stream(File::open(&path).unwrap(), n, params)
                .unwrap()
                .len()
        });
        std::fs::remove_file(&path)?;
    }
    let mem = scan_format_aware(&data, Some(ContainerFormat::Mcap), params)?;
    let file = scan_format_aware_seekable(
        &mut Cursor::new(&data),
        n,
        Some(ContainerFormat::Mcap),
        params,
        usize::MAX,
    )?;
    let mut digest = blake3::Hasher::new();
    for (b, forced) in mem.boundaries.iter().zip(&mem.format_aware) {
        digest.update(&(b.start as u64).to_le_bytes());
        digest.update(&(b.end as u64).to_le_bytes());
        digest.update(&b.raw_address);
        digest.update(&[u8::from(*forced)]);
    }
    println!(
        "in-memory == seekable: {}  output_digest={}",
        mem.boundaries == file.boundaries && mem.format_aware == file.format_aware,
        digest.finalize().to_hex()
    );
    Ok(())
}
