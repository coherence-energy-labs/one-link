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
  are propagated. Invalid CDC parameters are rejected before scanning.
- ZIP/H.264 need whole-buffer scanning. The Rust caller supplies a limit. The
  Python file API permits at most 256 MiB and raises `ValueError` above that;
  algorithm fallback is an explicit caller choice.
- Python file I/O/length failures raise `OSError`, invalid sizing/format names
  raise `ValueError`. Names `none`, the empty string, and the historical `auto`
  alias select plain CDC; they do not perform magic detection in this API.

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
