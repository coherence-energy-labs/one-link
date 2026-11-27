# One Link CHANGELOG

Per-release notes for One Link. Each entry summarises the ADRs landed
in that release; full architectural rationale lives in
[`docs/decisions/`](docs/decisions/).

The version scheme is semver-aligned but pre-1.0: 0.x.y means alpha,
breaking wire changes allowed between minor versions. Wire-format
compatibility with prior peers is preserved via capability negotiation
where practical (`NATIVE_TRANSFER_V1`, `DOUBLE_RATCHET_V1`).

---

## Unreleased — production-readiness hardening (2026-11-26)

Changes an operator or a peer can observe. Internal refactors are in the
commit history.

**Compatibility**

- Recovery shares are now version 2: the split secret carries a digest of
  the seed and each share is signed by its creator. Version 1 shares still
  combine, but `recovery restore` refuses them unless
  `--allow-unverified-legacy-shares` is given, because a wrong result from
  them cannot be detected. Re-issue shares to get checked ones. A release
  older than this one cannot read version 2 shares.
- A passphrase-protected identity key is re-sealed with scrypt the first
  time it is loaded with the passphrase. A release older than this one
  cannot read the re-sealed file.
- `state.db` from a newer release is refused instead of opened. A schema
  upgrade first saves `state.db.pre-migration-vN.bak` next to the database.
- A peer that is not paired may send frames of at most 256 KiB and is
  disconnected when its frame allowance is spent. Paired peers are
  unaffected. Handshake frames are capped at 16 KiB.
- The native library is built with `panic = "unwind"` and without aws-lc-rs.
- `/dr_test` answers 404 unless `ONE_LINK_SERVE_DEV_PAGES=1`.

**Security**

- Unpaired peers: bounded frame size, frame volume, owner prompts and stored
  records; `PAIR_REJECT` is honoured only inside a live pairing.
- Handshake replay cache entries are written only after the signature
  verifies.
- The identity key is sealed with scrypt (N=2^17) instead of 2,048 rounds of
  PBKDF2; `ONE_LINK_PASSPHRASE_FILE` supplies the passphrase from a file.
- Share recovery detects too few shares, mixed setups and damaged shares.
- ML-KEM encapsulation keys are range-checked (FIPS 203 section 7.2) and KEM
  secrets are wiped after use.
- Peer names resolve only when they name exactly one peer.
- Received file names lose bidi-override characters.
- The owner page may connect only to its own daemon.
- Rendezvous: one source address may hold at most 16 connection slots.

**Performance**

- Finding content-defined chunk boundaries is about twice as fast, and a
  whole chunk scan (boundaries plus BLAKE3 addresses) about one and a half
  times as fast, measured on one x86-64 machine. The boundaries are
  unchanged.
- A file made of a repeated two-byte pattern no longer makes the chunk scan
  allocate several times the file's size: 64 MiB of it took about 550 MiB of
  working memory and 0.4 s, and now takes under 1 MiB and under 0.1 s.
- Building the native library with `panic = "unwind"` costs paths that are
  mostly call overhead a few percent: the chunk-store lookup benchmark
  measured 3.4% and 3.6% slower in two CI runs.

**Privacy**

- `docs/NETWORK_CONTACTS.md` lists everything a default install contacts.
- The Quiet preset announces only the short ID and public key on the LAN.

**Tooling**

- `THIRD_PARTY_NOTICES.md` and a license allow list, generated from the lock
  files; `REUSE.toml` declares the license of every file.
- Gates that only allow improvement: HTML sinks in the UI, broad exception
  handlers, tests that match UI source text, and the size of `Daemon` and
  `UIServer`.
- The linter now also enforces flake8-bugbear, pylint errors and unreferenced
  asyncio tasks.

---

## [0.21.0-alpha] — 2026-05-11 — File engine v2

**Headline**: implementation of the shipped scope in
[`FILE_ENGINE_V2_PLAN.md`](docs/FILE_ENGINE_V2_PLAN.md) across Phase A1 + A2 +
B + C + D, plus the Coherence ↔ Rust codegen scaffold. Deferred hardware gates
and non-route bandit controllers are called out explicitly below and in the
plan scorecard.
16 Rust crates were present in `native/` at that milestone. The native
chunk-store transport gained daemon integration, but this alpha changelog does
not establish production readiness, full platform parity, or a verified
release.

### 2026-07-26 public download refreshed, and two defects that could stop a real install

- The public download channel had been serving artifacts built on 2026-05-18
  while every fix since then landed on master unseen. It is now published from
  a commit whose `tests`, `security`, and platform-build gates were all green,
  and every artifact carries a GitHub build-provenance attestation verifiable
  with `gh attestation verify <file> --repo coherence-energy-labs/one-link`.
  Read that narrowly: it binds the bytes to the publishing workflow, so a third
  party cannot substitute an upload. It is not a code signature, and it is not
  reproducible-build evidence. There is still no signed, reproducible,
  tagged release; `release.yml` remains the only channel intended for that and
  has not yet been run.
- The daemon could not start at all on a host whose Python is
  group-writable. `process_security` refuses to execute a group/world-writable
  binary, which is correct for a binary we choose to launch and meaningless for
  the interpreter already executing us: if it had been tampered with, the
  tampered code is what asks the question. The waiver is now scoped to that one
  case and applies wherever the running interpreter is resolved. Every other
  executable, including the containment-checked system-tool path, keeps the
  rejection.
- A folder-archive commit could abort with `folder_archive_source_changed`
  after correctly defending itself. The final integrity check compared the
  source inode's `ctime`, and POSIX `rename(2)`/`unlink(2)` update `ctime`
  without touching content, so a pathname swap -- exactly the attack the
  descriptor binding defeats -- failed the commit it had just protected. Content
  integrity is unchanged: the whole file is still re-hashed through the bound
  descriptor, and `dev`/`ino`/`size`/`mtime` remain hard rejects.

### 2026-07-23 live post-quantum daemon-channel handshake

- Current daemon channels use a distinct v3 wire handshake with a signed,
  canonical suite offer/selection for X25519 + ML-KEM-768, full transcript
  binding, an independent X25519 contribution, and mutual key confirmation
  before the channel is returned to application code.
- The native PQ capability is advertised only after the exact ABI passes an
  in-process encapsulation/decapsulation self-test. Missing or unhealthy native
  code fails closed before the initiator emits a handshake frame.
- Legacy/classical channels are rejected by default. Migration requires an
  explicit downgrade policy and those channels report `pq_protected=False`.
- This protects daemon session establishment against harvest-now-decrypt-later;
  it is not a claim that Ed25519 identity signatures, browser/WebRTC channels,
  or every shipped platform artifact are post-quantum qualified.

### 2026-07-21 large-transfer reliability and storage closure

- Desktop and phone uploads now mint stable idempotency keys, durably stage
  before returning `202 Accepted`, and replay the exact admitted result after
  response loss. Browser retries coalesce; completed phone retries re-hash
  content before replay so equal name/size cannot impersonate different bytes.
- Receiver completion is proven by an authenticated, durable `FILE_COMMIT`
  receipt. Sender retries preserve one delivery nonce and reconcile ambiguous
  legacy outcomes without emitting another offer.
- Chunk receipt replay, restart-safe resume ownership, exact staged-file
  identity, and bounded adaptive high-RTT windows eliminate duplicate writes
  and the 250 KiB/16-chunk bandwidth-delay-product collapse seen on the
  reported 596 ms route.
- Relay forwarding now has an exact 512 MiB process-wide payload budget plus a
  protected 4 MiB control reserve. Browser DataChannel work and phone uploads
  are likewise bounded, tracked, and drained before shutdown.
- Folder equality probes no longer create transfer/activity rows. Storage
  lifecycle tooling now performs content-verified graph audit, recoverable
  quarantine, rollback, and a separately approved 30-day-grace purge.
- Added adversarial lost-ACK, duplicate-init, concurrent-finalization,
  malformed-frame, crash-recovery, relay-overload, storage-orphan, browser
  call, media-soak, and 385 MiB transfer regression gates.

### Phase A1: chunk store foundation (ADRs 0001–0008)

- `ol_chunk` — content-addressed FastCDC v2020 (8/64/256 KiB) + BLAKE3
  chunk addressing + chunk envelope.
- `ol_chunk_store` — LSM-indexed content-addressed chunk log + bloom-
  filter front + WAL-coupled durability.
- `ol_aead` — per-chunk multi-frame AEAD (AES-256-GCM / ChaCha20-
  Poly1305) backed by `ring` (BoringSSL-derived assembly).
- `ol_wal` — crash-only write-ahead log with CRC32-Castagnoli per-
  record + tail-truncation recovery.
- `one_link_native` — pyo3 binding crate exposing every native crate
  as `one_link_native.<submodule>` (abi3-py311+).

### Phase A2: transport (ADR-0009, ADR-0010)

- `ol_quic` — QUIC transport via `quinn` 0.11. Self-signed identity-
  bound TLS via `rustls` + `aws-lc-rs`. The current daemon uses
  capability- and runtime-gated QUIC file lanes with authenticated peer
  binding. Multi-stream, 0-RTT, and connection-migration support in the
  transport primitive do not establish a whole-session cutover: daemon
  control/message traffic retains its authenticated channel, and WebRTC is
  retained for browser-as-peer.

### Phase B: genius layer (ADRs 0011–0016)

- `ol_bloom` — Bloom-filter transfer init. Receiver sends Bloom of
  chunk hashes; sender XORs against manifest; ships only the true delta.
- `ol_fountain` — LT (Luby Transform) fountain codes using the robust
  soliton distribution (ADR-0015). RaptorQ (RFC 6330) remains deferred
  pending IPR review and a versioned wire-format upgrade.
- `ol_fec` — Reed-Solomon FEC over GF(2^8) with SSSE3 PSHUFB SIMD.
- `ol_erasure` — Erasure-coded durability with stripe descriptor
  metadata.

### Phase C: multi-axis baseline (ADRs 0017–0027)

- **ADR-0017** PQ-hybrid KEM (ML-KEM-768 + X25519 via BLAKE3 X-Wing
  combiner). `ol_pqkem` crate.
- **ADR-0019** Multi-armed bandit route selection (Beta-Bernoulli
  Thompson sampling). `ol_bandit` is generic, but only route selection
  is production-active; chunk-size, parallelism, FEC, prefetch, pacing,
  and compression controllers remain deferred.
- **ADR-0020** Per-chunk forward-secret ratchet (BLAKE3 keyed-hash
  chain). `ol_ratchet` crate.
- **ADR-0021** Capability layer — macaroon-style HMAC-chained caveats
  over BLAKE3. `ol_capability` crate. **1M-iter attenuation soundness
  gate** (`child.accepts(ctx) ⇒ parent.accepts(ctx)`) passes in
  5.94 s with 0 violations.
- **ADR-0022** CRDT shared folders — vector clock + OR-set + LWW
  register composition. `ol_crdt` crate. **1M-iter lattice-laws gate**
  (commutativity + associativity + idempotency) passes in 7.46 s.
- **ADR-0023** Hardware-bound keys, TOFU-degrading. `ol_hwkey` crate.
- **ADR-0024** Phase C-3 wiring status — shadow / dual-issue posture
  for the 5 daemon migration primitives.
- **ADR-0025** Chunk-store transport pipeline — composed
  `NativeTransferSession` (KEM + ratchet + CDC + AEAD + ChunkStore).
  Bench: native is **1.14–1.44× faster than legacy** at every size
  16 KiB → 64 MiB after the BoringSSL fast-path default.
- **ADR-0026** `NATIVE_TRANSFER_V1` capability + `FILE_NATIVE_CHUNK`
  wire format. The current indexed native file lane is capability-gated and
  default-on only when the native runtime and peer negotiation qualify it
  (rollback via `ONE_LINK_NATIVE_TRANSFER=0`); it is not a universal session
  transport claim.
- **ADR-0027** Shadow → authoritative cutovers: bandit drives route
  picks in `AdaptiveTransferBrain.decide()`; folder mirror active
  cross-check + divergence counter; macaroon advertised on
  `CAPABILITY_GRANT` wire as `macaroon_b64`.

### Phase D: visionary layer (ADRs 0028, 0033)

- **ADR-0028 #1** Tau-field routing — `ol_routing` crate. τ_c-
  weighted Dijkstra + hysteresis-gated next-hop swap. Harvest from
  `OneField/onefield/mesh/routing.cl`. **Acceptance gate**: 100%
  chunk-loss reduction on fragile-graph benchmark (plan: ≥20%).
- **#2** Byzantine-tolerant tau — `ol_routing::byzantine` module.
  BFT thresholds (`floor((N-1)/3)`) + random-geometric graph density
  + `tau_claim_corroborated` (catches malicious peers reporting fake
  high τ_c).
- **#3** Active inference prefetch — `ol_prefetch` crate. Time-
  weighted co-occurrence predictor over (peer, file_id) access
  traces. **Acceptance gate**: cold-start convergence ≤50 iters;
  cohort prior transfer converges in 1 iter.
- **#4** Persistent homology durability — `ol_homology` crate. H0
  components + bridge detection via DFS; composite `fragility_score`
  for replication priority. **Acceptance gate**: partition flag in 1
  round, 0% FP on 100 random 4-regular graphs (plan: ≤5% FP).
- **#5** Grammar compression — `ol_grammar` crate. Re-Pair on byte
  streams.
- **#6** Plausibly deniable storage — `ol_duress` crate. `DuressGate`
  with constant-time real-vs-decoy decision + covert ratchet-header
  signal. **CT timing gate**: 1.014× wall-clock variance (plan:
  <1.20×). The validation pass caught + fixed a real side-channel
  (1.448× → 1.014×).
- **#7** Formal verification — TLA+ specification at
  `docs/formal/Capability.tla` modelling the capability grant + revoke
  + attenuation state machine. Verified safety invariants:
  `NoKeyReuse`, `NoDoubleGrant`, `NoReplay`, `ClockMonotonic`.
- **Coherence ↔ Rust codegen scaffold** — `ol_codegen` crate. Minimal
  CL `struct` grammar parser + Rust struct + canonical-LE encoder
  emitter. **Byte-equivalence CI gate**: 1M random struct shapes
  round-trip in 1.79 s.

### Python adapters

Every native crate the daemon needs to call surfaces as
`one_link_native.<submodule>` + a thin `*_native.py` wrapper:

- `chunk_native.py`, `chunk_store_native.py`, `wal_native.py`,
  `aead_native.py`, `quic_native.py` (Phase A1+A2)
- `fountain_native.py`, `fec_native.py`, `bloom_native.py`,
  `pqkem_native.py`, `erasure_native.py`, `bandit_native.py`,
  `ratchet_native.py` (Phase B+C)
- `capability_native.py`, `crdt_native.py`, `hwkey_native.py` (Phase C-3)
- `routing_native.py`, `prefetch_native.py`, `homology_native.py`
  (Phase D, new in 0.21.0)

PEP 561 type stubs ship from the canonical inline `native/one_link_native/` package.

### Daemon integrations in this development milestone

- `Daemon._observe_prefetch(peer_fp, blob_hex)` hook in `send_file()`
  success path + receiver-side ACK so the prefetch predictor sees
  both ends of every transfer.
- `Daemon.native_diagnostics()` returns prefetch/routing/homology
  availability + native-transfer-v1 advertisement + macaroon-dual-
  issue state for operator inspection.
- `Daemon._pick_best_relay()` sorts relay candidates by τ_c-weighted
  cost (no-op pass-through until per-relay metrics surface lands).

### Testing & verification

- **506 Rust workspace tests** pass / 0 failed
- **107 Python unit tests** pass / 0 failed
- **2,952 Python daemon regression tests** pass / 0 failed
- **Total: 3,565 / 0 failed**
- 9 fuzz targets cover wire formats + state machines + Phase D
  primitives (auto-discovered by nightly CI workflow)
- Property tests via `proptest` across every Phase D crate

### Backward compatibility

- Legacy peers (no `NATIVE_TRANSFER_V1` in caps) transparently stay
  on `FILE_CHUNK` / `FILE_BIN_CHUNK`.
- All daemon migrations are additive — `pq_hybrid.HybridKEM`,
  `caps_grants.encode_grant`, `crdt.merge_manifest_entries`,
  `transfer_brain.AdaptiveTransferBrain` legacy paths all stay
  authoritative or available as fallbacks.

### Rollback flags

- `ONE_LINK_NATIVE_TRANSFER=0` — disable FILE_NATIVE_CHUNK, force
  legacy FILE_CHUNK / FILE_BIN_CHUNK.
- `ONE_LINK_BANDIT_ROUTE_PICKER=0` — disable bandit-driven route
  selection in `AdaptiveTransferBrain.decide()`, fall back to legacy
  multi-route Pareto.

### Batch 2: production-readiness wiring (2026-05-11)

Post-0.21.0-alpha hardening pass landed as commit `5d89838`:

- **Relay metrics surface** — `Daemon.record_relay_observation()` EWMA-
  smooths per-relay `rtt_ms` + `loss_rate` (α=0.2) on every
  `open_relay_outbound` success/failure; `_pick_best_relay()` consumes
  the recorded dict via `_relay_metrics_for()`.
- **ol_codegen enum grammar** — `parse_enum` / `parse_decl` /
  `emit_rust_enum` recognise single-payload + unit variants; u8
  discriminant + variant-payload canonical encoding; 10k-iter byte-
  equivalence property gate.
- **Foldersync native reconciliation** — `FolderEngine.
  _native_reconcile_check()` runs the OR-set add-wins lattice
  decision alongside `merge_manifest_entries` and counts
  disagreements per `receive_remote_manifest` entry; counters surface
  via `native_mirror_stats()` so operators see the diff budget before
  the authoritative-bit flip.
- **Soak test harness** — `tests/test_native_pipeline_soak.py` drives
  2k-iter randomized add/remove/concurrent-edit workload (designed
  for 50k nightly via `ONE_LINK_SOAK_ITERS`); asserts zero native
  mirror divergence + <5% reconcile disagreement budget.
- **ol_fuse scaffold** — `FilesystemBackend` trait + `MemoryBackend`
  reference impl + `mount()` entry point with `MountOptions` /
  `MountError`. Real `fuser::mount2` Linux wiring deferred behind
  `cfg(target_os = "linux")` so Windows / macOS workspace stays clean.

**Hardening pass on batch 2 (this entry's polish)**:
- Native workspace warning sweep: **zero warnings** across the
  `cargo build --release` graph (was 60 pre-sweep; fixed unused
  imports, dead methods, cfg(gil-refs) macro noise via crate-level
  allow, missing-Debug on pyo3 wrapper types).
- Test-build warning sweep: deprecated `rand::Rng::gen` →
  `rand::Rng::random` in `ol_erasure`, `ol_fec`, `ol_bandit` test
  surfaces; dead-code field `identity` in `ol_transfer::engine_e2e`
  renamed `_identity`.
- Criterion benches added for `ol_codegen` (parse + emit on small +
  wide structs + mixed enums) and `ol_fuse` (getattr / read / readdir
  / write on MemoryBackend). Baselines: codegen 213–551 ns parse,
  456 ns emit; FUSE backend 52 ns / 4KiB read, 88 ns getattr-hit,
  53 µs readdir-of-200.
- `out` field annotation fix in `FolderEngine.native_mirror_stats()`
  (mypy clean on the modified surface).
- 8 version-pin regexes + 2 version-floor int-parse tests updated to
  tolerate PEP-440 pre-release suffixes (`0.21.0-alpha`).

**Final test sweep**: 3,069 Python tests passed / 4 skipped /
0 failed (5m32s). Per-crate Rust builds clean across the 21
member crates excluding `one_link_native` + `ol_transfer` (latter
two compile clean when WDAC propagation allows; tests pass at
89 sections / 0 failed.

---

## [0.20.6] — 2026-05-08

iOS Configuration Profile (.mobileconfig) endpoint for self-signed
cert trust. Unblocks iPhone HTTPS pair flow.

## [0.20.5] — 2026-05-09

Multi-agent security audit — 5 CRITICAL + 21 HIGH + 24 MED findings.
Documented in `docs/SECURITY_AUDIT_v0.20.5.md`.

## [Earlier history]

See git log for v0.7.0 through v0.20.4. Highlights:
- v0.7.0–v0.7.6: Linked mesh + security pass + per-device drawer +
  transfer resume + reply/quote + reactions + read receipts.
- v0.8.x: CRDT shared folders, group events, social recovery.
- v0.10.x: System tray, dashboard, performance lab.
- v0.14.x: Phone tier.
- v0.15.x–v0.20.x: PWA pivot architecture.
