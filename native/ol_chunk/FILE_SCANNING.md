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

## Memory behavior

| Component | Bound |
| --- | --- |
| Plain CDC payload window | `min(file_length, max(32 MiB, 4 * max_size))` |
| Header read-ahead for MCAP/MP4/WAV | 64 KiB |
| Forced-cut candidate/accepted/segment lists in the seekable scanner | None: online coalescing and immediate segment scanning |
| Parallel CDC candidate workspace | O(payload window); depends on bytes and sizing, not total file length |
| Scratch for a short forced segment | At most `max_size` |
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
asserts payload scanning begins before the header walk completes. This detects
regression to collecting a full record-offset vector without materializing a
large test corpus.

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

The probe generates a virtual dense MCAP with zero-length record bodies, emits
scan time, chunk count and a digest over every start/end/hash/flag, and caps
input at ten million records. Compare identical probe binaries linked against
baseline and candidate libraries, preserve each observation, and collect peak
RSS in separate processes. Matching `output_digest` is required before
interpreting a resource difference. This synthetic measurement does not claim
disk, network or general file-transfer throughput.
