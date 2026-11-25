# ADR-0014: Format-Aware Chunking — ZIP entry boundaries + video GOP boundaries

**Status:** ACCEPTED (Phase B acceptance number)
**Phase:** B
**Depends on:** ADR-0001 (CDC kernel), ADR-0003 (chunk_record `format_aware` flag)
**Augments, does not replace:** ADR-0001

---

## Context

Pure content-defined chunking (FastCDC + Gear-256) is content-blind: it finds boundaries by rolling-hash patterns, no matter what bytes flow through it. That's the right default — it gives ~30-60% dedup on heterogeneous corpora and survives unknown formats gracefully. It's not the right *only* answer for files whose structural boundaries are misaligned with FastCDC's hash boundaries:

- **ZIP archives (`.zip`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.apk`, `.jar`, `.epub`, `.kra`).** A ZIP file is a sequence of local-file-header + compressed-payload + central-directory entries. When the user edits one file inside an `.xlsx` (the most common "small ops" workflow), only that entry's bytes change. Pure FastCDC sees the whole ZIP as a byte stream and slides its hash window, so a 1 KiB edit in a 50 MiB archive can shift every chunk boundary downstream of the edit. Dedup drops to ~0%.
- **Video (Matroska / MP4 / WebM).** Group-of-Pictures (GOP) boundaries are the natural sync points: each GOP starts with an I-frame, then has P/B-frames that depend on it. Trimming the head of a video or replacing the soundtrack changes specific GOPs; pure CDC misses the structure.
- **Premiere / Logic / Resolve project files.** Already mostly XML-or-JSON + binary asset references; structural boundaries are well-defined.

Phase A1 already wired a `FORMAT_AWARE` flag into the chunk_record flags byte (ADR-0003) precisely so this layer could slot in without a format break.

## Decision

**Augment the CDC kernel with a format detector + boundary injector.**

The boundary injector runs *before* the CDC kernel and emits **forced boundary offsets** based on the detected format. The CDC kernel then runs over each segment between forced boundaries independently, never crossing them. Result: a ZIP entry that changes never affects the chunk boundaries of any other ZIP entry.

### Detection (cheap, conservative)

Format detection runs on the leading bytes of each input stream + path-extension hint:

| Format | Magic | Path hint | Action |
|---|---|---|---|
| ZIP-family | `PK\x03\x04` at offset 0 | `.zip` / `.docx` / `.xlsx` / `.pptx` / `.odt` / `.apk` / `.jar` / `.epub` / `.kra` | Inject one forced boundary at the start of every local-file-header. |
| MP4 / Matroska | `ftyp` box / EBML header | `.mp4` / `.m4v` / `.mkv` / `.webm` | Inject one forced boundary at the start of every track-encoded GOP (where the demuxer signals a sync sample). |
| Everything else | — | — | Pure CDC. |

**Conservative principle:** if format detection is ambiguous (e.g. a file claims `.zip` extension but the leading bytes don't match), fall back to pure CDC. False-positive format-aware chunking is worse than missing a structural boundary — it can shred dedup in the wrong direction.

### ZIP boundary injection

ZIP local-file-header signature is `0x04034B50` (little-endian `PK\x03\x04`). Walk the input forward; at every occurrence, emit a forced-boundary at that byte offset. Constraints:

- **Cap minimum chunk size** at 8 KiB (ADR-0001 min). If two LFH signatures are <8 KiB apart, only the first becomes a boundary; the second is absorbed into the larger CDC region. This keeps tiny-entry archives (some `.epub` per-chapter splits) from producing degenerate ~100-byte chunks.
- **Don't trust LFH signatures inside compressed payloads.** A compressed payload can contain the byte sequence `PK\x03\x04` by chance. We require the LFH parse to also have plausible (`version_needed`, `compression_method`, `last_mod_time`) — a cheap 8-byte sanity check. False positives on this gate are rare (~10^-9 per byte) and the worst case is a missed dedup, not corruption.
- **Path-extension hint optional but preferred.** If the file extension doesn't suggest ZIP, we still try the magic match but skip the deep scan unless the hit rate looks promising (first 256 KiB has ≥2 valid-looking LFHs).

### Video GOP boundary injection

For Phase B v1 we ship ZIP-family only. **Video GOP detection is deferred to Phase B-2** because:

- Robust GOP detection needs a real demuxer (Matroska EBML parser, MP4 box parser, H.264 NAL unit parser). Each adds 3-10K LoC of attack surface and bumps the supply-chain footprint.
- Open-source demuxers (matroska-rs, mp4parse-rust) exist and are credible, but adding three of them in one phase is over-scoping per stress-test #1.
- Pure CDC on video already achieves ~70% dedup on the small-ops workload (podcaster edits the last 30 seconds → only the last GOP changes). GOP-awareness lifts this to ~95%; the gap matters less than ZIP-family does (where pure CDC is closer to 0% on insertions).

Phase B v1 ships with a placeholder `VideoFormatScanner` trait whose default implementation returns no boundaries. Phase B-2 plugs in the demuxer-backed implementation.

### Wire compatibility

When a format-aware boundary was used, the resulting `ChunkRecord` sets the `FORMAT_AWARE` flag bit. Receivers don't have to understand the format to read the chunk — the boundary is already chosen on the sender side and the chunk's bytes are self-describing.

The `ChunkRecord.chunk_id` is still `BLAKE3(plaintext)` (or convergent-derived) — the BLAKE3 hash doesn't care how the boundary was chosen. So a peer that already has the chunk (regardless of how *it* was chunked) gets a clean dedup hit. **This is the core property: format-aware sender + format-blind receiver still benefit from dedup.**

### Falsifiable acceptance number

**Bytes-on-wire reduction ≥80% for the canonical "1 KiB edit in 50 MiB .xlsx" workload.**

Test corpus: starting `.xlsx` of size 50 MiB. Apply a single-cell edit that touches ~1 KiB of one inner XML. Pure-CDC engine transfers ~50 MiB of fresh chunks (the edit cascades). Format-aware engine transfers ≤10 MiB (the one entry's chunks + a tiny number of CDC follow-up chunks).

This is the verification gate. Phase B doesn't ship without it.

## Consequences

**Positive:**
- Restores dedup on the "edit one file in a ZIP" workflow that dominates small-ops file sharing (every Office doc, every Android `.apk` upload, every `.epub`).
- Conservative detection (magic + path hint, conservative fallback) protects against false positives shredding dedup the wrong way.
- The `FORMAT_AWARE` flag is informational; receivers without format awareness still dedup correctly.

**Negative:**
- ZIP-LFH walking is O(N) on input bytes; adds ~1 cycle per byte on the ingest hot path. Negligible against CDC + BLAKE3 + AEAD.
- Misdetection on a binary file that happens to look ZIP-shaped → degraded dedup on that file (no corruption, just missed opportunity). Acceptable.
- Adds ~200 LoC of ZIP parser to Rust supply chain. We do *not* depend on a full ZIP library — only the LFH walker, ~80 LoC. The full ZIP library footprint (`zip` crate, ~3K LoC) is rejected.

## Verification

1. **Pure-CDC equivalence on non-ZIP input**: feed a 100 MiB random binary; format-aware path must produce byte-identical chunk boundaries to pure CDC.
2. **ZIP-LFH detection on real archives**: 100 random `.zip`/`.docx`/`.xlsx` files from a public corpus → each LFH signature in the file becomes a forced boundary (or is absorbed by the 8 KiB min).
3. **Single-cell-edit dedup**: starting `.xlsx` size 50 MiB; edit one cell; rebuild; measure unique-bytes between the two runs. **Target: ≤10 MiB unique bytes.**
4. **Wire-flag round-trip**: encode a format-aware chunk with the flag set; decode → flag preserved.
5. **Falsified-magic resilience**: random bytes that *contain* `PK\x03\x04` at non-LFH positions → conservative parser rejects them (no spurious boundary, no corruption).
6. **Fuzz**: 24h `cargo-fuzz` on the LFH walker → zero crashes.

## References

- ZIP spec (PKWARE APPNOTE 6.3.10): https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- ADR-0001 (CDC kernel) — the kernel format-aware chunking augments.
- ADR-0003 (on-disk format) — the `FORMAT_AWARE` flag bit.

---

## Amendment 1 (2026-11-25): format-aware chunking v2 -- local, content-defined cut selection

**Status:** ACCEPTED. **Changes format-aware chunk boundaries** (format-aware chunking v2). Plain CDC boundaries
(ADR-0001, `ol_chunk/tests/fixtures/cdc_golden_v1.txt`) are byte-identical.

### Context: the measured defect

The injector above keeps every structural boundary unless it lies within `min_size` of the previously accepted one.
On a container whose records are denser than `min_size` that rule is a chain anchored only on the previous accepted
cut, i.e. fixed-size chunking at record granularity, with no content-defined resynchronisation. Witness (MEASURED,
`dense_resync.py`, release build): a valid 64 MiB MCAP of equal records with one record inserted after record 1000.
Bytes of v2 whose chunk address is not among v1's:

| Record size | Format-aware v1 | Plain FastCDC |
| --- | --- | --- |
| 32 B | 63.98 MiB (100%) | 0.08 MiB |
| 100 B | 63.91 MiB (99.9%) | 0.10 MiB |
| 1,024 B | 63.02 MiB (98.5%) | 0.13 MiB |

A 4 GiB dense MCAP gave 524,287 chunks, every one exactly `min_size`. The same holds for a ZIP of many small members
and for dense H.264. The real 50 MB MCAP corpus never showed it because its records are large. (Measured nuance: with
strongly varying record sizes the chain does converge, as FastCDC's own min-size skip does; with equal or periodic
record sizes, common in robotics logs, it never does.)

### Decision

Each candidate `c_i` (unit `i` = `[c_i, c_{i+1})`, length `L_i`; the last unit ends at EOF) is decided from local
facts, then the v1 absorption is applied unchanged:

1. **Structural** if `max(L_{i-1}, L_i) >= min_size`: kept. Absorption only chains through gaps shorter than
   `min_size`, so wherever every unit is at least `min_size` long v2 equals v1 exactly, and records of at least
   `avg_size` still start a format-forced chunk.
2. **Dense** otherwise. `fp_i` is a fixed 64-bit mix (wyhash-style 128-bit multiply-fold) of the unit's first
   `min(32, L_i)` bytes and `L_i`: a pure function of the unit's own bytes. The candidate *survives* iff
   `fp_i * avg_size < L_i * 16 * 2^64` (exact `u128`), and is kept iff it survives and `fp_i` is strictly greater
   than the fingerprint of every other surviving dense candidate within `h = max(avg_size / 2, min_size)` bytes.

This is local-maximum content-defined chunking (Bjørner, Blass, Gurevich, "Content-dependent chunking for
differential compression: the local maximum approach") applied over structural candidates, after a size-weighted
thinning. One implementation (`ol_chunk/src/select.rs`) serves the in-memory and seekable scanners, fed the same
candidates and head bytes by the shared pull-style walkers; in-memory == file == seekable holds by construction and
is tested.

### Why this rule (DERIVED; each property is tested)

- **No chain.** Two kept dense cuts are at least `h >= min_size` apart (two survivors within `h` cannot both be the
  strict maximum), so absorption keeps every kept dense cut and converges at each one.
- **Locality.** A dense decision depends only on candidates within `h`, so an insertion, deletion or edit of `L`
  bytes at `p` changes decisions only in `[p - h, p + L + h]`. Every chunk outside that interval and its two
  straddling chunks is unchanged: **re-sent <= 2h + L + 2 * max_size** (576 KiB + `L` for 8/64/256 KiB), and in
  expectation `<= 2h + L + E[S^2]/E[S]` for chunk size `S`.
- **Degenerate input falls back to plain CDC.** Candidates that fingerprint alike tie, and ties keep nothing, so a
  run of identical heads gets no dense cut and plain FastCDC (which resynchronises on content) chunks it.
- **Target granularity.** In a uniform dense run about 16 survivors fall in each `2h` window, so kept cuts are about
  `avg_size` apart whatever the record size, plain FastCDC's granularity.
- **Cost.** One compare per candidate decides survival; only `16 L / avg_size` of the candidates (0.8% for 32-byte
  records) reach the branchy monotonic deque. Selector state is the dense survivors within `h` (bounded by `h / 4`).

### Alternatives measured

`cargo test -p ol_chunk --release --lib rule_comparison -- --ignored --nocapture` (16 MiB logs, default profile,
24 edit positions each; re-sent KiB, mean / worst, after one inserted record):

| Workload | v1 chain | S1: keep iff `fp * avg < L * 2^64` (structural at `>= avg`) | local maximum, unthinned | **v2** |
| --- | --- | --- | --- | --- |
| MCAP, 32 B records | 8,469 / 14,752 | 97 / 203 | 74 / 131 | **75 / 125** |
| MCAP, 100 B records | 8,468 / 14,751 | 119 / 252 | 72 / 132 | **74 / 153** |
| MCAP, 1,024 B records | 8,470 / 14,753 | 105 / 241 | 74 / 150 | **67 / 138** |
| ZIP, 2,000 members of 1-6 KB | 35 / 110 | 115 / 244 | 71 / 164 | **79 / 158** |
| MCAP, all heads identical | 8,468 / 14,751 | 95 / 217 | 103 / 217 | **95 / 217** |
| MCAP, a shared head S1 keeps | 8,468 / 14,751 | **6,763 / 14,751** | 148 / 275 | **99 / 174** |

- **S1** (keep each dense candidate with probability `L / avg`, as first proposed) is KILLED by a constructive
  witness: records sharing a head that S1 keeps (found by search; probability `L / avg` per head) make S1 keep
  every record, which is the v1 chain again. Its mean re-sent on random dense logs is also 1.3-1.6x v2's.
- **Unthinned local maximum** matches v2 within about 10% on random logs, is worse on degenerate insertions
  (identical or alternating heads), and costs 12 ns per candidate for the deque against v2's thinned path.
- **Structural threshold `avg_size` instead of `min_size`** would change chunking of logs whose records are between
  `min_size` and `avg_size` for no resync gain (absorption cannot chain through gaps of at least `min_size`); it was
  not adopted.

### Consequences

- Format-aware boundaries change for containers with runs of two or more consecutive sub-`min_size` units, and only
  there. Peers chunking with v1 and v2 dedup each other only where the boundaries agree (sparse containers). A
  deliberate future change needs a new version and amendment; `ol_chunk/tests/dense_resync.rs` pins v2 digests for
  dense MCAP, ZIP and fragmented MP4.
- In dense regions chunks are about `avg_size` instead of `min_size`: one eighth as many chunks, and an in-place
  edit there re-sends about 64 KiB instead of about 8 KiB (plain FastCDC's behaviour).
- Throughput, 256 MiB dense MCAP of 32-byte records, three interleaved rounds, medians (v1 -> v2): in-memory
  1,073 -> 2,341 MiB/s; real file (`format_aware_file`) 754 -> 1,207 MiB/s; the seekable API over an in-memory
  `Cursor` 2,041 -> 1,759 MiB/s (-14%: v1 did no per-record selection work, and a `Cursor` has no read syscalls for
  v2's read-once window to save). The seekable scanner now slides its header window over dense records and hashes
  short segments from it, reading a dense source once.

### Verification

`ol_chunk/tests/dense_resync.rs` (the witness as a Rust test; insert/delete/edit on dense MCAP of 32, 100 and
1,024-byte records and on a ZIP of 2,000 small members against the per-edit bound; the mean against the expected
bound; the v1 rule failing the same bound on the same bytes; sparse containers equal to v1; pinned v2 digests),
`ol_chunk/src/select.rs` (streaming selector equal to the rule in quadratic form; fingerprint purity; spacing; ties),
`ol_chunk/tests/stream_contracts.rs` and `ol_chunk/tests/walker_differential.rs` (file == in-memory on every payload
path, dense logs of every format, fragmented and interrupted reads, read-once).
