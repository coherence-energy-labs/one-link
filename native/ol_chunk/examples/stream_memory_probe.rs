//! Reproducible dense-record resource probe. Input is a virtual MCAP source,
//! so RSS does not include a materialized corpus. Run the same probe against
//! baseline and candidate builds, compare `output_digest`, and measure process
//! RSS externally. This is a header-coalescing workload, not a disk benchmark.
use std::fmt::Write as _;
use std::io::{self, Read, Seek, SeekFrom};
use std::time::Instant;

use ol_chunk::format_aware::MCAP_MAGIC;
use ol_chunk::{blake3_wrap, stream::scan_format_aware_seekable, CdcParams, ContainerFormat};

struct DenseMcap {
    pos: u64,
    len: usize,
}
impl DenseMcap {
    fn byte(&self, pos: usize) -> u8 {
        if pos < 8 {
            return MCAP_MAGIC[pos];
        }
        if pos >= self.len - 8 {
            return MCAP_MAGIC[pos - (self.len - 8)];
        }
        if pos < 21 {
            return [1, 4, 0, 0, 0, 0, 0, 0, 0, b'r', b'o', b's', b'2'][pos - 8];
        }
        if (pos - 21).is_multiple_of(9) {
            5
        } else {
            0
        }
    }
}
impl Read for DenseMcap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos =
            usize::try_from(self.pos).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let count = buf.len().min(self.len.saturating_sub(pos));
        for (i, byte) in buf[..count].iter_mut().enumerate() {
            *byte = self.byte(pos + i);
        }
        self.pos += count as u64;
        Ok(count)
    }
}
impl Seek for DenseMcap {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let value = match pos {
            SeekFrom::Start(pos) => i128::from(pos),
            SeekFrom::Current(pos) => i128::from(self.pos) + i128::from(pos),
            SeekFrom::End(pos) => self.len as i128 + i128::from(pos),
        };
        self.pos =
            u64::try_from(value).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let records: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1000000".to_owned())
        .parse()?;
    if records > 10_000_000 {
        return Err("probe limit is 10 million records".into());
    }
    let len = 8 + 13 + records * 9 + 8;
    let mut source = DenseMcap { pos: 0, len };
    let started = Instant::now();
    let result = scan_format_aware_seekable(
        &mut source,
        len,
        Some(ContainerFormat::Mcap),
        CdcParams::default(),
        0,
    )?;
    let elapsed = started.elapsed().as_secs_f64();
    let mut canonical = Vec::with_capacity(result.boundaries.len() * 49);
    for (b, forced) in result.boundaries.iter().zip(&result.format_aware) {
        canonical.extend_from_slice(&(b.start as u64).to_le_bytes());
        canonical.extend_from_slice(&(b.end as u64).to_le_bytes());
        canonical.extend_from_slice(&b.raw_address);
        canonical.push(u8::from(*forced));
    }
    let mut digest = String::with_capacity(64);
    for byte in blake3_wrap::chunk_address_raw(&canonical) {
        write!(digest, "{byte:02x}")?;
    }
    // Linux's address-space high-water mark excludes a Python benchmark
    // launcher's inherited pre-exec high-water RSS. Other OSes report null;
    // use a platform-native process sampler there instead of inventing a value.
    let peak = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<u64>()
                .ok()
        });
    let peak_json = peak.map_or_else(|| "null".to_owned(), |value| value.to_string());
    println!("{{\"records\":{records},\"bytes\":{len},\"chunks\":{},\"seconds\":{elapsed},\"output_digest\":\"{digest}\",\"linux_vm_hwm_kib\":{peak_json}}}", result.boundaries.len());
    Ok(())
}
