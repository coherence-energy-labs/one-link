# One Link

**Peer-to-peer chat, file sync, and live voice + video.** No required user
account or central message store. Devices connect directly where routes permit;
optional rendezvous and relay services support cross-network discovery and
fallback. Peer sessions are end-to-end encrypted and mutually authenticated.

Built on the Coherence Language ecosystem (CRDT runtime, identity primitives,
effect tracking) with a Python host harness and a Rust native fast path.

**Project home:** [weareone-link.org](https://weareone-link.org) - product and
release information plus explicitly labelled in-browser demonstrations of
selected primitives (pair-by-QR, Sphinx onion, PQ-hybrid signing, Shamir
threshold recovery, per-chunk ratchet, TOFU device recognition, and streaming
verification). A local demo proves that demo's stated contract; it is not a
claim that every repository primitive is wired into every shipping path.

I am One. You are One. We are One.

---

## Current install status

> **Published release; production qualification incomplete.** The
> [v0.21.0 release](https://github.com/coherence-energy-labs/one-link/releases/tag/v0.21.0)
> was published on 2026-08-01 with 30 assets, including platform archives,
> native/Python wheels, Sigstore bundles, an SBOM and checksum/update metadata.
> The 2026-11-24 review found that publication succeeded while its independent
> reproducibility comparison failed. Asset presence is not independent signature
> or provenance verification. See the dated [release evidence ledger](docs/RELEASE_EVIDENCE.json).
> The current source is 0.22.1; neither it nor mutable `auto-latest` is a completed
> high-assurance production qualification.

For development evaluation, run a reviewed source commit with the frozen lock:

```bash
git clone https://github.com/coherence-energy-labs/one-link
cd one-link
git checkout <reviewed-commit-sha>
# Requires uv >=0.13.4, Rust 1.96.0 and a platform C compiler.
python scripts/bootstrap_source.py
uv run --no-sync one-link app
```

The bootstrap builds the matching native backend, verifies its package/module
versions and live ML-KEM ABI, and records the loaded binary hash. Use
`python scripts/bootstrap_source.py --check-only` to diagnose an existing source
environment. A source build is an evaluation path; production sign-off additionally
requires the exact artifact checks in the release checklist.

## Releases

The table below describes the portable archive formats published for v0.21.0
and retained in the current build contract. Publication and qualification are
separate records. Evaluate one exact release using `SHA256SUMS`, per-artifact
Sigstore bundles, provenance, its SBOM, independent rebuild evidence for the
Linux native wheel, and fresh-device smoke tests. The dated evidence ledger
identifies the checks that have and have not been independently completed.

Per-platform install notes:

| Platform | Architecture | File | What you do |
|---|---|---|---|
| Windows | x86_64 (Intel/AMD) | **`one-link-windows-x86_64.zip`** | Extract the complete folder, then double-click `one-link/one-link.exe`. First run may need “More info -> Run anyway” until platform code-signing is configured. |
| Windows | arm64 (Snapdragon X / Surface Pro X) | **`one-link-windows-arm64.zip`** | Extract, then double-click `one-link/one-link.exe`; this is a native ARM build. |
| macOS | arm64 (Apple Silicon) | **`one-link-macos-arm64.zip`** | Extract the complete `one-link.app` bundle, then run `chmod +x one-link.app/Contents/MacOS/one-link && open ./one-link.app`; first launch may require approval in Privacy & Security. |
| Linux | x86_64 | **`one-link-linux-x86_64.zip`** | Extract, then run `chmod +x one-link/one-link && ./one-link/one-link`. |
| Linux | arm64 (Raspberry Pi 4/5 64-bit, ARM cloud) | **`one-link-linux-arm64.zip`** | Extract, then run `chmod +x one-link/one-link && ./one-link/one-link`. |

For an exact tagged release, download the artifact plus
`SHA256SUMS`, `SHA256SUMS.sigstore`, and `<artifact>.sigstore`, then run the
repository's fail-closed verifier with that exact immutable tag:

```bash
bash scripts/verify-release.sh ./<artifact> vX.Y.Z
```

The verifier must succeed on the downloaded bytes; published filenames alone do not authenticate them.
Never substitute `latest`, `master`, or `auto-latest` for the exact tag.

---

## What it does

- **Chat.** Direct messages, group threads. Edit, react, delete.
- **Files & folders.** Drag-drop send. Synced folders that update both ways.
- **Voice & video calls.** Living Presence aims to survive bad
  networks - when the WiFi drops, it becomes a voice note and resumes
  when you reconnect. The development tree also contains an experimental
  Tier ζ semantic-codec path; benchmark numbers are not a production-release
  guarantee.
- **Identity that's yours.** Identity key material is generated and stored on
  your devices; no hosted login is required.
  Pair with people by QR and compare the active flow's transcript-bound
  five-word safety phrase. A numeric value remains visible only for pairing
  with older One Link clients that cannot render the word protocol.
- **Cryptographic provenance** is attached and verified on supported frame and
  file paths; release qualification must prove coverage for each advertised
  surface.

### Current advanced security paths and their boundaries

- **Hybrid daemon channels.** When the authenticated native ABI self-test
  passes, current daemon peers require a signed, transcript-bound X25519 +
  FIPS-203 ML-KEM-768 handshake with mutual key confirmation and refuse a
  classical downgrade by default. Identity authentication is still Ed25519,
  and browser/WebRTC channels are not covered by this post-quantum KEM claim.
- **Blinded native relay first flights.** The default v2 relay route uses
  rotating pairwise route tags and recipient-seals both identity-bearing
  channel first flights. This puts neither identity public key on that relay
  wire, but it is not sender anonymity or traffic-analysis resistance: one
  relay still observes endpoint sockets/IPs, timing, size, count, and
  rotating-tag linkage. The explicit legacy migration override exposes
  identities and is reported as such.
- **Direct browser peers.** Real Chromium and Firefox profiles complete signed
  WebRTC offer/answer, open DataChannels, and exchange data with outside STUN
  disabled. WebKit/iOS, physical two-machine NAT/TURN, and cellular-handoff
  qualification remain open.
- **Onion/Sphinx boundary.** Packet and cover-frame primitives are tested, but
  no live message/file path uses onion routing, no mix-net is deployed, and no
  onion-anonymity claim is made.
- **Updater boundary.** Explicit owner-confirmed, one-click transactional
  installation is implemented for a locally proven frozen standalone bundle.
  It is offered only when the exact executable, the complete
  `BUNDLE_SHA256SUMS` tree, and the fixed external helper validate; that helper
  independently authenticates the exact release, performs A/B activation and
  health checks, and rolls back on failure. Source, pip, development,
  incomplete, moved, or modified installs fail closed. Unattended/background
  automatic installation remains disabled. Published v0.21.0 assets still require
  independent exact-artifact verification and the qualification ledger above.

---

## Run from source

For developers, or to run the daemon as a service:

```bash
git clone https://github.com/coherence-energy-labs/one-link
cd one-link
git checkout <reviewed-commit-sha>
python scripts/bootstrap_source.py
uv run --frozen one-link daemon --open
```

`--open` auto-launches your browser to the local UI when the daemon is
ready. Drop `--open` if you're running on a server. The loopback UI prefers
`http://127.0.0.1:7117`; if that port is occupied, it tries the rest of its
bounded fallback range and then an operating-system-assigned port. Use the URL
opened by the launcher or the daemon's reported status rather than assuming a
fixed port.

On Windows you can drop a Desktop shortcut:

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install_desktop_shortcut.ps1
```

---

## Use

`one-link app` starts the daemon (if not already running) and opens
the desktop UI in your browser. The window has:

- **Sidebar** - every peer One_link finds on your LAN, with hostname,
  short_id, and an online indicator
- **Conversation pane** - pick a peer; chat with bubbles + timestamps
- **Drag-drop file zone** - drop any file anywhere on the window to send
- **Files panel** - toggle `Files` to see everything you've received
- **Folders panel** - add local sync folders and push Merkle/CDC folder
  drift rounds to paired peers
- **Mesh panel** - see recent transfers with durable progress and
  completion/failure state
- **Peer controls** - allow/deny chat, file transfer, or folder sync per
  paired device
- **Live updates** - while the authenticated WebSocket is connected, incoming
  messages and files appear without a manual refresh

There is no product-configured upload quota. Practical file size and route
limits still depend on disk, memory, filesystem, transport, and peer policy;
relay fallback introduces infrastructure but cannot decrypt end-to-end content.

### Lower-level commands (still available)

```bash
one-link daemon            # headless service mode
one-link chat              # terminal REPL alternative to the GUI
one-link whoami            # show this device's identity
one-link peers             # list discovered devices
one-link send <peer> "hi"
one-link send-file <peer> /path/to/file.zip
one-link tail              # stream events as JSON lines
```

---

## How it works

```
                       [ LAN ]
   computer A  <─── mDNS discovery ───>  computer B
   one-link                _onelink._tcp     one-link

   per authenticated peer session:
     1. discover or select a verified route to the peer
     2. exchange Ed25519 identities + transcript signatures (mutual authn)
     3. mutually capable native peers use signed X25519 + ML-KEM-768;
        an explicit reported migration override uses X25519-only
     4. negotiate runtime capabilities and, for mutually capable peers,
        activate the transcript-bound Double Ratchet cutover
     5. multiplex bounded encrypted messages, receipts, calls, and transfers;
        reconnect and replay only durable idempotent work after failure
```

The owner UI binds to `127.0.0.1` by default. The launcher passes a
process-scoped bootstrap token once, the page scrubs it from the URL, and plain
loopback HTTP authenticates API calls with an origin-scoped Bearer rather than
a host-wide cookie. Owner cookies are accepted only when the live request
transport is TLS. Explicit `one-link app --lan` mode binds the HTTP/HTTPS
listeners to the LAN for phone pairing; remote plaintext requests cannot use
owner Bearer/session credentials, and the deliberately public pairing routes
use their own short-lived signed or high-entropy credentials and rate limits.

- **Identity:** long-term Ed25519 keypair, BLAKE3 fingerprint = device ID
- **Encryption:** per-connection ephemeral X25519, plus ML-KEM-768 on the
  verified current daemon path, feeds HKDF and ChaCha20-Poly1305 with a 64-bit
  counter nonce and AAD. Ed25519 remains the identity signature, so this is a
  hybrid session-confidentiality claim rather than a product-wide
  post-quantum identity claim.
- **Discovery:** `_onelink._tcp.local.` mDNS. TXT record carries
  the Ed25519 public-key hex
- **Files:** BLAKE3 verified end-to-end. Related files use
  content-defined chunking so receivers ask only for missing chunks; the
  transfer ledger survives UI refreshes and reports live progress.

---

## Architecture

```
src/one_link/
├── __main__.py    `python -m one_link` entry
├── identity.py    Ed25519 keypair, BLAKE3 fingerprint, persistence
├── wire.py        length-prefixed frame protocol + JSON envelopes
├── channel.py     X25519 handshake + ChaCha20-Poly1305 stream
├── discovery.py   mDNS via async zeroconf
├── daemon.py      asyncio peer + control + UI servers
├── server.py      aiohttp HTTP + WebSocket UI API
├── web/index.html the desktop UI (single-file application, no build step)
├── app.py         `one-link app` launcher
├── chat.py        terminal REPL (legacy, still useful)
├── cli.py         click-based CLI dispatch
├── state.py       (v0.2) sqlite persistent state
├── cdc.py         content-defined chunking + dedup transfer planning
├── merkle.py      Merkle drift detection for manifests/blob indexes
├── capabilities.py per-peer feature/capability names
├── sessions.py    explicit peer session-protocol catalog
├── sovereign.py   mission/principles/capability audit surface
└── paths.py       cross-platform config/data dirs
```

Coherence / OneField ecosystem hooks:
- `coherence_lang.bootstrap.runtime.crdt.VectorClock` inspired the active
  `one_link.crdt.VectorClock` folder-sync primitive
- OneField Mesh `cdc_dedup.cl` inspired live `FILE_WANTS` /
  `FILE_CDC_CHUNK` transfer skipping
- OneField Mesh `merkle_drift_sync.cl` inspired live manifest root checks
- Session-protocol and capability concepts now ship as `one_link.sessions`
  and `one_link.capabilities`

---

## Security notes

- **Default-loopback owner UI.** The owner HTTP/WebSocket listener binds to
  127.0.0.1 by default. Explicit LAN pairing mode adds network listeners, but
  remote plaintext requests cannot use owner credentials. Neither mode makes
  the UI immune to malicious local processes or browser-origin attacks;
  authentication remains required.
- **Rotating bootstrap plus revocable browser sessions.** Every daemon start
  rotates a 256-bit bootstrap secret. After identity-possession and origin
  checks, browsers receive independently revocable, expiry-bound sessions;
  revocation, peer deletion, and Guardian-epoch changes invalidate the matching
  authority and close active channels. Deliberately public pairing/bootstrap
  routes use separate short-lived signed or high-entropy credentials and rate
  limits.
- **Path-traversal defense in two layers** (verified across 7 wire-level
  vectors and 7 HTTP-level vectors): basename-only writes to inbox, raw
  HTTP requests with `..` in the URL get rejected.
- **AEAD-protected wire protocol.** Tampering with any frame after
  the handshake closes the connection.
- **Trust on first use with pairing upgrade.** New peers start as pending;
  SAS pairing lets you pin or reject devices, and rejected peers are blocked
  in both outbound and inbound directions.
- **Identity key at rest.** The default PKCS#8 file is protected by mode 0600
  on Unix and a verified user-only ACL on Windows. Optional passphrase
  encryption is available through `ONE_LINK_PASSPHRASE`; losing that
  passphrase makes the identity unrecoverable unless you have a valid backup.

This is alpha software. Don't use it for anything you wouldn't be okay
losing or having someone else read if your device were compromised.

---

## Development

```bash
pip install -e .[dev]
python -m pytest tests/ --ignore=tests/smoke_loopback.py -v
python scripts/build_binary.py     # produces the complete dist/one-link/ onedir
python scripts/build_native_cdc.py # optional: prebuild the native CDC scanner
python scripts/bench_transfer_primitives.py
python scripts/perf_lab.py --scale quick
```

The default standalone build follows the stable artifact contract and
deliberately omits the semantic-model research stack. Engineers can build an
explicitly preview-only substrate with `--include-preview-ml` after installing
the locked `preview-ml` extra; this does not activate or advertise a call
capability.

The smoke test (`tests/smoke_loopback.py`) starts two daemons in temp
directories and runs a complete end-to-end round-trip including a
multi-chunk file. The pytest suite covers everything in much greater
depth - see `TESTING.md`.

### Performance Lab

Use the repeatable local perf lab to see whether transfer work is getting
faster or slower:

```bash
python scripts/perf_lab.py --scale quick
python scripts/perf_lab.py --scale standard
```

Reports are written under `benchmarks/results/` as JSON and ignored by git.
The lab measures hash-only manifests, fixed manifests, CDC indexing,
prior-knowledge bandwidth savings, swarm scheduler throughput, the never-lose
torture simulator, SQLite transfer ledger pressure, compression throughput,
and the adaptive transfer brain. The transfer brain is the local Coherence
planner that decides when a file should use the simple fast lane, CDC, or
swarm CDC based on measured route health and prior knowledge.

One Link can use a bundled native CDC scanner for prior-knowledge transfers.
When present, the perf lab reports `engine=ctypes-c`; otherwise it falls back
to the pure-Python scanner with the same chunk hashes and wire format.

### Running multiple daemons on one machine

Set `ONE_LINK_HOME` to override config + data dirs:

```bash
ONE_LINK_HOME=/tmp/ol-A one-link app
ONE_LINK_HOME=/tmp/ol-B one-link app    # different port, different identity
```

---

## Troubleshooting

If something feels off, open **Settings → Advanced → One Link Doctor**
and click **Run health check**. It runs ~14 checks against the
current state (daemon reachable, peer version compatibility,
browser secure context, WebRTC support, mic + camera permission,
service worker registration, pending outbox depth, etc.) and
renders pass / warn / fail per surface with a one-line fix hint.

Common issues:

| Symptom | Likely cause | What to do |
|---|---|---|
| Messages sit as "Queued" while the peer is online | The other device is on an older build. Wire-version mismatch. | During alpha evaluation, run the same reviewed commit on both devices. Once verified releases exist, use the same immutable tag. |
| Calls connect but no audio / video | Browser blocked mic / camera permission. | Site settings → reset permissions → reload, accept on the next call. |
| Welcome wizard re-appears every launch | localStorage blocked or cleared by privacy mode. | Check browser settings; allow site data for `127.0.0.1`. |
| "Can't reach One Link. Is it running?" | The tray daemon stopped. | Restart by double-clicking the `one-link` binary again. |
| Files arrive but don't open | Daemon doesn't auto-open; this is by design. | Click the file bubble; image / PDF previews open in the lightbox, others open in a new tab. |

To file a bug: **Settings → Advanced → Report a bug on GitHub**
pre-fills an issue with a redacted diagnostic snapshot (no
fingerprints, no message bodies, no paths — only counts +
versions + recent error severities).

---

## Roadmap

Live status: see the **Truth Dashboard** in **Settings → About** — the daemon
reports every major feature across four axes (primitive proven / daemon wired /
UI exposed / archived physical soak evidence). Only all-four-green means fully
qualified; source or simulation evidence is never promoted to physical-release
proof.

Present in the alpha development tree (not release-qualified):
- Chat (1:1 + groups) with edit / react / delete / disappearing messages
- File transfer (native chunk store + AEAD, 10 MiB+ verified in soak)
- Voice + video calls (Living Presence Tier α-pre, signed offers, missed-call entries, audible ringtone)
- Pairing with Ed25519-authenticated channels and a transcript-bound five-word
  safety phrase across daemon and direct-browser ceremonies. The native
  pair-by-QR state machine remains a separate primitive; this is not a claim
  that the current pairing path uses ML-DSA.
- Personal device mesh (multi-device on same identity)
- Folder sync with CRDT conflict resolution
- Confidential-compute attestation (software provider; TPM in flight)
- Pinned + archived conversations, slash commands, image markup before send

What's queued:
- Exact-commit release qualification of Double Ratchet activation, downgrade,
  legacy-peer, revocation, and crash-recovery behavior
- Service Worker pinned-pubkey signature verification (closes the update channel)
- Argon2id-wrapped identity key + OS-keyring passphrase (replaces PBKDF2 + env var)
- `server.py` modularization (12K → many smaller files for review)
- CSP nonce migration + TrustedTypes
- Group calls (3+ participants)
- Code-signed installers (Authenticode + Apple notarization)

See [`docs/UX_AUDIT_2026-05-17.md`](docs/UX_AUDIT_2026-05-17.md) for the
full audit list and recommended ordering.

---

## License

Copyright (c) 2026 One Link contributors (weareone@oneunity.earth).
Released under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). The full text is in [LICENSE](LICENSE); the copyright, SPDX identifier
and MIT-era history are in [LICENSE-NOTICE](LICENSE-NOTICE).

AGPL is a deliberate, for-the-people choice: it keeps One Link free and
open even when run as a network service — anyone who offers it to others
must share their source, so it can't be quietly taken closed. (Versions
before commit `87d1b98` / v0.20.7 were MIT; this README previously still
said MIT, which was a stale inconsistency with LICENSE and pyproject.)
