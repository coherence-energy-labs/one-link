# File-scanning contracts

`stream::scan_stream(reader, len, params)` and
`stream::scan_format_aware_seekable(source, len, format, params, limit)` scan an
**immutable input** with an explicit byte length. Their boundaries and raw
BLAKE3 addresses match the corresponding in-memory FastCDC implementation. This
is the native FastCDC format; the application's historical Python/C Gear-CDC
format is a separate compatibility contract.

## Length and error behavior

- `scan_stream` consumes exactly the declared bytes, then at most one extra byte
  to check EOF. A short source returns `UnexpectedEof`; extra data returns
  `InvalidData`. Use `reader.take(range_len)` to scan a range of a larger source.
- The seekable format scanner addresses the whole source from offset zero and
  verifies its length before and after scanning. Truncation and growth are
  errors for **all** formats, including ZIP and H.264. A caller must prevent
  same-length rewrites, including truncate-and-regrow races, through snapshot or
  file-lifecycle ownership; length checks alone do not establish immutability.
- Fragmented reads and `Interrupted` reads are supported. Other read/seek errors
  are propagated. Invalid CDC parameters are rejected before scanning (see
  "Parameter validation").
- ZIP/H.264 need whole-buffer scanning. The Rust caller supplies a limit. The
  Python file API permits at most 256 MiB and raises `ValueError` above that;
  algorithm fallback is an explicit caller choice.
- Python file I/O/length failures raise `OSError`, invalid sizing/format names
  raise `ValueError`. Names `none`, the empty string, and the historical `auto`
  alias select plain CDC; they do not perform magic detection in this API.

## Parameter validation

`CdcParams::validate` accepts a profile exactly when the `FastCDC` v2020 kernel's
constructor accepts it and `min_size < avg_size < max_size`:

| Size | Accepted range (bytes) | Source |
| --- | --- | --- |
| `min_size` | 64 ..= 1,048,576 | `fastcdc::v2020::{MINIMUM_MIN, MINIMUM_MAX}` |
| `avg_size` | 256 ..= 4,194,304 | `fastcdc::v2020::{AVERAGE_MIN, AVERAGE_MAX}` |
| `max_size` | 1,024 ..= 16,777,216 | `fastcdc::v2020::{MAXIMUM_MIN, MAXIMUM_MAX}` |

The ranges are the library's exported constants, re-exported as
`CdcParams::{MIN,AVG,MAX}_SIZE_RANGE`, so they cannot drift from the kernel. A
size outside its range is `ChunkError::SizeOutOfRange { field, value, min, max }`
(checked first, in field order); a violated ordering is
`ChunkError::InvalidParameters`. Every scan entry point (`ChunkScanner::with_params`,
`scan_to_vec_parallel_with_params`, `pcdc::chunk_ranges`, `scan_format_aware`,
`scan_stream`, `scan_format_aware_seekable`) validates before any byte reaches
a kernel. The stream APIs report an invalid profile as `io::ErrorKind::InvalidInput`
(the seekable format scanner as `StreamScanError::Params`) and keep the
`ChunkError` as the `io::Error`'s source. The Python binding validates first and
raises `ValueError`.

Earlier validation required only non-zero, ordered sizes with `max_size <= 16
MiB`. Profiles such as `(1, 2, 4)`, `(63, 256, 1024)` and `(1 MiB + 1, 2 MiB, 4
MiB)` then reached the kernel's `assert!`s, which abort the process under the
release profile's `panic = "abort"`, or, in the parallel kernel the file
scanner uses, made a zero-length cut: `avg_size = 2` selects all-zero masks, so
offset 0 is a cut and the loop pushed `(0, 0)` until a 100-byte file's scan
requested 27,380,416,512 bytes.

Defence in depth: the parallel kernel returns `ChunkError::NoProgress` for a cut
that does not advance (in the stream APIs, `io::ErrorKind::Other`) and refuses
an average with no mask, instead of looping or indexing out of bounds. Neither
is reachable with a validated profile: every valid average selects two non-zero
masks and `min_size >= 64` puts the first possible cut at byte 64.

## Container walkers

The record-framed formats (ISO BMFF, MCAP, RIFF/WAV) are walked by one
implementation per format (`src/walk.rs`) over two byte sources: an in-memory
slice (`format_aware::{mp4_box_offsets, mcap_record_offsets, wav_data_offset}`)
and the seekable reader's header window (`stream::*_seekable` and the file
scanner). The file API therefore equals the in-memory API on every input. When
these were two copies, the in-memory MP4 walker evaluated `pos + 8` after a
64-bit box size had moved `pos` near `usize::MAX`; the sum wrapped and the
16-byte input `0000000166747970fffffffffffffffc` indexed out of bounds, while
the file walker returned `[(0, 16, False)]`. Both now return that.

Every length field is untrusted. A byte range is requested as `(pos, n)` and
refused if `pos + n` overflows or passes the end; each advance is widened to
`u64`, converted with `usize::try_from` and added with `checked_add`. Each walk
stops, keeping the offsets found so far, at:

| Format | Stop conditions |
| --- | --- |
| ISO BMFF | box type not 4 ASCII alphanumerics/spaces; size 0 (box runs to EOF; its offset is kept); size below 8; size 1 without room for the 64-bit size; a box end that is not a representable position or lies past the end |
| MCAP | missing leading magic or Header opcode; opcode 0; a record that does not end within the record area (trailing magic excluded) |
| RIFF/WAV | missing `RIFF....WAVE`; a sub-chunk header that does not fit; the `data` header (the result) |

ZIP and H.264 Annex B cuts come from byte scans with no length arithmetic on
untrusted fields; the seekable scanner reads those formats whole and runs the
in-memory scanner.

The walkers are pull-style (`RecordWalk::next`) and return each record start
with the first `min(32, len - pos)` bytes there, from the same window access
that read the record header: the cut selector needs those bytes, and the
seekable scan never seeks per record to get them.

## Format-aware chunking v2: which candidates become cuts

**This changes format-aware boundaries** (ADR-0014, v2 amendment). Plain CDC
boundaries, including `tests/fixtures/cdc_golden_v1.txt`, are unchanged.

Every structural candidate (record, box, local-file-header or keyframe start)
is a candidate cut; unit `i` is `[c_i, c_{i+1})` of length `L_i`. Format-aware
v1 kept every candidate and dropped any closer than `min_size` to the previously
accepted cut. On a dense container that is a cut chain anchored only on the
previous cut, fixed-size chunking at record granularity: one inserted record
shifted every later chunk, and a 64 MiB MCAP of 32-byte records re-sent 100% of
itself (plain `FastCDC`: 0.1%). v2 decides each candidate from local facts and
then applies v1's absorption unchanged (`src/select.rs`, one implementation for
the in-memory and seekable scanners):

- **Structural**, `max(L_{i-1}, L_i) >= min_size`: kept. Where every unit is at
  least `min_size` long, v2 equals v1 exactly; records of at least `avg_size`
  still start a format-forced chunk.
- **Dense**, both neighbouring units shorter than `min_size`: with a fixed 64-bit
  fingerprint `fp_i` of the unit's first `min(32, L_i)` bytes and `L_i`, the
  candidate survives iff `fp_i * avg_size < L_i * 16 * 2^64` (exact `u128`), and
  is kept iff it survives and `fp_i` is strictly greater than every other
  surviving dense candidate's within `h = max(avg_size / 2, min_size)` bytes.

Consequences: kept dense cuts are at least `h >= min_size` apart, so absorption
cannot chain inside a dense run; an edit changes decisions only within `h` of
itself; candidates that all fingerprint alike (identical heads and lengths) tie
and get no dense cut, so plain `FastCDC` chunks them; kept cuts fall about
`avg_size` apart whatever the record size. One edit of `L` bytes re-sends at most
`2h + L + 2 * max_size` (576 KiB + `L` with the default profile), assuming that
inside a segment longer than `max_size` plain `FastCDC` resynchronises within one
chunk, and on average about one chunk; the derivation is in
`tests/dense_resync.rs`.

Measured (default profile, release build, one inserted record):

| 64 MiB MCAP, record size | v1 re-sent | v2 re-sent | plain FastCDC |
| --- | --- | --- | --- |
| 32 B | 63.98 MiB (100%) | 0.03 MiB | 0.08 MiB |
| 100 B | 63.91 MiB (99.9%) | 0.05 MiB | 0.10 MiB |
| 1,024 B | 63.02 MiB (98.5%) | 0.12 MiB | 0.13 MiB |

The tradeoff: in a dense region v1's chain made `min_size` chunks, so an
in-place edit there re-sent about 8 KiB; v2 makes `avg_size`-scale chunks
(plain `FastCDC`'s granularity, one eighth as many chunks), so it re-sends about
64 KiB. Sparse containers are unaffected.

## Memory behavior

| Component | Bound |
| --- | --- |
| Plain CDC payload window | `min(file_length, max(32 MiB, 4 * max_size))` |
| Header window for MCAP/MP4/WAV, walk that jumps (sparse records) | 64 KiB |
| Header window, sequential walk (dense records) | the unhashed span, at most `8 MiB + 2 * max_size + 2h + 64 KiB`, plus one 16 MiB read-ahead block; short segments are hashed from it, so a dense source is read once |
| v2 cut selector | dense candidates within the last `h = max(avg_size / 2, min_size)` bytes (at most `h / 4 + 1`) and the structural cuts waiting behind them |
| Forced-cut candidate/accepted/segment lists in the seekable scanner | None: online selection and immediate segment hashing |
| Parallel CDC candidate workspace | O(payload window); depends on bytes and sizing, not total file length |
| Short-segment batch buffer, used only when the header window does not hold the batch | At most `8 MiB + max_size` |
| Returned boundaries/hashes/format flags | O(output chunks), including corresponding Python objects |
| ZIP/H.264 whole-buffer path | Input up to the explicit limit, plus in-memory scanner/output workspace |

The API does **not** promise constant total RAM or a 32 MiB total process RSS
ceiling. A low minimum chunk size can produce a large output. The separate
`mcap_record_offsets_seekable` and `mp4_box_offsets_seekable` list APIs
intentionally return every record/box offset and require O(records/boxes)
space; the file chunk scanner does not use those list-returning APIs.

Python exposes `CDC_FILE_WINDOW_BYTES` and `FORMAT_AWARE_IN_MEMORY_LIMIT` so
callers can inspect the declared limits. These are payload limits, not full
process memory budgets.

## Compatibility and verification

`tests/fixtures/cdc_golden_v1.txt` pins exact input hashes, starts, ends and chunk
hashes from the audited 0.22.1 reference build (`1279a450`). Random, repeated and
edited inputs run through serial, parallel and streaming scanners. CI must not
regenerate expected outputs automatically. A deliberate boundary change needs
explicit compatibility review and versioning.

`tests/stream_contracts.rs` covers short/growing sources, read fragmentation,
interruption and error propagation, whole-file limits and dense-record online
behavior. Its two-million-record MCAP reader generates bytes on demand and
asserts the source is read exactly once plus a derived 128 KiB + 8 bytes (the
first header window twice and the trailing magic): collecting candidates or
segments before hashing would read the payload a second time. It also checks
every payload path of the file scanner (hashed from the header window, read by
the writer after a jump, retention exceeded by one huge record) against the
in-memory scanner under fragmented and interrupted reads, and truncation during
a 16 MiB slide.

`tests/dense_resync.rs` is the dense-resync witness as a Rust test (64 MiB of
32-byte records, one inserted) plus insert, delete and edit on dense MCAP of
32, 100 and 1,024-byte records and on a ZIP of 2,000 small members, each against
the derived per-edit bound; the mean over 16 edit positions against
`2h + L + E[S^2]/E[S]` computed from the log's own chunks; the v1 rule failing the
same bound on the same bytes (the negative control); sparse containers
chunking exactly as v1; and pinned v2 digests for dense MCAP, ZIP and fragmented
MP4 (drift detection, not evidence of correctness). `src/select.rs` checks the
streaming selector against the rule stated in quadratic form on 400 random
candidate sets, the fingerprint's purity, the spacing bound and the tie rule.
`cargo test -p ol_chunk --release --lib rule_comparison -- --ignored --nocapture`
prints the measured comparison of v2 with the alternatives in ADR-0014.

`tests/param_validation.rs` checks every kernel limit (one past it rejected, the
limit and one inside accepted), the witnessed profiles, agreement with the
`FastCDC` constructor itself (caught panics) on all 24^3 combinations of limit
and extreme values, an error from every entry point for invalid profiles, and
identical output from every entry point at the extreme valid profiles.

`tests/walker_differential.rs` compares the in-memory walkers, the seekable
walkers and an independent reference written in `u128` arithmetic (no position
can wrap) on the 16-byte witness, on 64-bit sizes whose end lands on either side
of 2^64, on every boundary value of each length field (0, 1, 7, 8, header-only,
exactly to EOF, one past EOF, `u32::MAX`, `u64::MAX`), on walks that refill the
64 KiB header window, and on 6,000 seeded hostile inputs across all formats. It
also requires the in-memory and file format-aware scans to return identical
boundaries and flags; for the record-framed formats these run different code
(serial `FastCDC` and collected cuts versus the windowed parallel kernel and
online cut absorption).

Repository `tests/test_native_format_aware_file.py` exercises the installed
Python exports for every format, custom profiles, aliases, path/error mapping,
a true 32 MiB window crossing and sparse-file limit refusal. These binding
checks qualify the exported API; they do not establish that a production daemon
route selects that API or that mutable-path access satisfies descriptor-bound
application requirements.

For bounded resource measurements run:

```sh
cargo run --release -p ol_chunk --example stream_memory_probe -- 1000000
```

The probe generates a virtual dense MCAP of 17-byte records whose 8-byte body is
the record's sequence number (identical records would, by design, get no v2
dense cut), emits scan time, chunk count and a digest over every
start/end/hash/flag, and caps input at ten million records. Compare identical
probe binaries linked against baseline and candidate libraries, preserve each
observation, and collect peak RSS in separate processes. Matching
`output_digest` is required before interpreting a resource difference. This
synthetic measurement does not claim disk, network or general file-transfer
throughput.

For dense-log resync and throughput across every scan path run:

```sh
cargo run --release -p ol_chunk --example dense_resync_probe -- <scratch_dir>
```

It prints the witness table above and best-of-three MiB/s over a 256 MiB MCAP
of 32-byte records for the in-memory, `Cursor` and real-file paths, format-aware
and plain, and checks in-memory == seekable. Compare builds only within one
batch, interleaved: load from other processes moved unchanged code by 2x
between runs. Measured that way (three interleaved rounds, medians, v1 -> v2):
in-memory format-aware 1,073 -> 2,341 MiB/s; real file (`format_aware_file`)
754 -> 1,207 MiB/s; seekable over a `Cursor` 2,041 -> 1,759 MiB/s. That last
path is 14% slower: v1 did no per-record work beyond the walk (its cut choice
was the defect), v2 spends about 6 ns per record on the fingerprint and
selection, and a `Cursor` source has no read-syscall cost for v2's read-once
window to save.
