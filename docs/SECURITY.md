# Security — threat model + hardening contract

Status: living document. The companion to
[`SOVEREIGNTY.md`](./SOVEREIGNTY.md): where Sovereignty says
"don't trust corporations," Security says "match or exceed every
real security primitive corporations provide, and document every
threat model with the countermeasure that addresses it."

Last release-evidence review: 2026-11-24; see `RELEASE_EVIDENCE.json`.

## Evidence boundary

This is a threat model and hardening plan, not a security certification. The
published v0.21.0 release includes Sigstore bundles, an SBOM and checksum assets.
The 2026-11-24 review observed successful publication but a failed independent
reproducibility run; no independent production sign-off is asserted. Mutable
`auto-latest` remains outside the trust baseline. Workflow source is an intended
control; authenticated exact artifacts, provenance and completed qualification are
the proof.

Unless a section explicitly says **current implementation**, its defenses are
design requirements or roadmap targets. A check mark in an older version of
this document must not be used as release evidence. Before trusting binary
bytes, require an immutable version tag, green tag-scoped gates, a signed
checksum manifest, per-artifact Sigstore bundles, provenance, an SBOM, and a
fresh-device smoke result. The dated release ledger records which of these
checks were observed and which remain unverified.

---

## Storage tiers and where each defense applies

The threat-model statuses below distinguish two implementation tiers,
because the same product ships in two shapes that have very different
at-rest stories. Mixing the two created false-positive ✅ cells in
earlier revisions of this doc; the audit on 2026-05-09 corrected them.

**Tier A — Browser PWA (planned, partial).** The PWA shell described
in `ARCHITECTURE.md` v0.16+ is the load-bearing target for OPFS at-rest
encryption, Argon2id passphrase derivation, plausibly deniable storage,
and Service-Worker signature verification of update bundles. As of
v0.20.7 the PWA shell renders, browser-as-peer transport is alive over
WebRTC, but the at-rest encryption + signature verification primitives
are still in flight (sw.js does not yet pin or verify a release pubkey;
OPFS encryption is on the v0.21+ track). T2 / T4 / T5 cells that read
✅ in earlier revisions of this doc were forward-looking commitments,
not currently shipped guarantees.

**Tier B — Desktop daemon (development tree).** The Python daemon is the most
complete implementation shape, but there is no verified PyPI or bundled
production release today. As of 2026-06-16 (external-audit remediation) the SQLite state
file is **encrypted at rest by default** (SQLCipher AES-256). The key
is obtained from the OS keychain (Windows Credential Manager / macOS
Keychain / Linux Secret Service) when available, and from a local
`0600` key file in the data dir as a fallback so encryption stays on
even where no OS keychain exists. The daemon **refuses to run with a
plaintext state DB** unless the operator explicitly opts in with
`ONE_LINK_ALLOW_PLAINTEXT=1` — there is no longer a *silent* plaintext
fallback, and the migration's temporary plaintext backup is securely
deleted once the encrypted DB is verified (no lingering cleartext
copy). Honest caveat: a local key file sitting beside the DB is weaker
than the OS keychain against an attacker who already has read access
to the data dir; the OS keychain (plus OS full-disk encryption) is the
strong configuration, and the daemon logs which key store is in use.
The blob store and UI bearer token remain on the at-rest roadmap;
`ONE_LINK_PASSPHRASE` still lets you supply the DB key explicitly.

**What this means for each threat status below.** Status cells that
explicitly call out browser-PWA-only mechanisms (OPFS, Web Crypto
non-extractable keys, Service Worker pinning) should be read as
"defended in Tier A once those primitives ship; defended in Tier B
only by user-account isolation today." Where this distinction matters,
the threat row notes it inline.

---

## The tension this document resolves

Corporations provide some real security:

- **Hardware-backed key storage.** Apple's Secure Enclave and
  Google/Samsung's StrongBox keep key material in tamper-resistant
  silicon, never visible to JavaScript or even to the OS proper.
- **Hardware RNG.** Dedicated entropy sources on modern phone
  chipsets are good (modulo the perennial "is it backdoored"
  question, which we hedge with multi-source mixing).
- **OS-level patching.** Apple and Google fix CVEs in WebKit,
  Blink, the kernel, the driver stack. We benefit by running on
  patched OSes.
- **App Store review.** Imperfect, but it does catch some malware
  before it reaches users.
- **Corporate CAs.** Globally trusted certificate authorities
  underpin HTTPS. Without them, every connection is an
  authentication problem.

Stripping corporate substrate without engineering equivalents
would degrade real security. That's not what `SOVEREIGNTY.md`
asks for. The contract is:

> **Defang corporate influence over our users; preserve and
> exceed corporate security primitives.**

This document specifies what we accept from the substrate
(because it's real security), what we replace because we can do
better, and what we add that no corporation provides.

---

## Threat model

The following adversary classes define required defenses, in increasing order
of capability. Historical "tier passed" labels record source-level assessments;
they are not current production certification. Hardened and air-gap tiers are
design targets unless exact-commit evidence says otherwise.

### T1 — Casual snoop (network-adjacent, passive)

**Capabilities:** can read packets on the same Wi-Fi, on the
same coffee-shop hotspot, or as the user's ISP. Cannot inject;
cannot break TLS.

**Current source controls:** daemon channels use a mutually authenticated
ephemeral X25519 handshake and AEAD framing. Compatible peers advertise and
activate the Double Ratchet after CAPS negotiation. Legacy compatibility paths
do not provide the same post-compromise properties. The existence of TreeKEM,
sealed-sender, and pseudonym primitives is not evidence that every group,
relay, or browser path uses them. Rendezvous and network observers may still
learn metadata.

**Status:** partial source-level mitigation for payload confidentiality; no
production release or complete metadata-resistance claim.

### T2 — Active network attacker (MITM)

**Capabilities:** can inject, replay, and manipulate packets.
Can attempt to MITM the TLS connection to our CDN.

**Target and current controls:**
- Service Worker release-key pinning is planned, not current. The existing PWA
  cache path and mutable prerelease do not provide a cryptographically verified
  update channel.
- WebRTC DataChannel carries SCTP over DTLS; audio/video media uses SRTP.
  See [RFC 8831, section 1](https://www.rfc-editor.org/rfc/rfc8831.html#section-1).
  DTLS establishes the channel certificate; signed signaling binds the intended
  peer identity and certificate fingerprints. *The 2026-05-09 audit found unsigned-answer and SDP-fingerprint
  binding gaps. The current development tree contains signed/bound signaling
  changes, but those changes still need exact-commit hostile-network evidence
  and a verified release.*
- Wire frames carry HMAC over content + sequence; replay attacks
  fail. *Daemon-to-daemon channel: solid (transcript-bound AEAD
  AAD plus required CAPS channel_bind as of v0.20.7 fix H1).*
- Any future external script must be pinned and integrity-checked; the preferred
  current posture is to load no third-party script at all.

**Status:** daemon-to-daemon source paths have transcript-bound AEAD and CAPS
controls. The development tree also contains signed WebRTC signaling and
fingerprint-binding work, but this document does not substitute for a fresh
hostile-network proof at an exact commit. Service Worker update integrity and
verified production distribution are unavailable; no release process
compensates for that gap today.

### T3 — Compromised peer (a "friend" turns)

**Capabilities:** holds valid pairing credentials, can send
arbitrary messages claiming to be themselves, can read everything
the user sent them historically.

**Current controls and historical gaps:**
- Forward secrecy via Double Ratchet: even compromise of the
  peer's CURRENT keys doesn't expose old messages, because old
  ratchet keys are deleted. *The Double Ratchet primitive ships
  at `src/one_link/double_ratchet.py` and the activation pathway
  is wired into the channel. Audit 2026-05-09 finding C4: the
  daemon historically filtered `double_ratchet_v1` out of advertised CAPS.
  The current development tree advertises the capability and activates after
  mutual negotiation; legacy peers can still remain on the session AEAD path.*
- Post-compromise security: future messages between user and a
  not-yet-compromised peer recover security after the ratchet
  steps forward. *Same caveat as above; PCS depends on DR being
  active in the channel.*
- Block / unpair: cryptographic cutoff is the goal; today
  `revoke_peer` is app-state only (drops the outbound session and
  the DB trust flag). Once DR activates, a forced ratchet step
  on block will give the documented "old session keys are useless"
  guarantee. Audit 2026-05-09 finding H14.
- Capability gate: as of v0.20.7 fix C3, SAS-pair finalize
  installs a deny-by-default per-peer capability policy
  (chat-only). A compromised paired peer cannot drive file
  transfer, folder sync, or group operations without explicit
  user consent for each capability.
- Verifiable revocation log (planned): users would publish a
  revocation that propagates through the network; their other
  contacts cryptographically refuse messages from the revoked
  peer key.

**Status:** partial. The capability policy constrains authorized operations,
and mutually capable current peers activate the Double Ratchet. Those facts do
not establish a universal post-compromise guarantee for legacy sessions,
already-delivered plaintext, compromised endpoints, group paths, or revoked
peers. Each path needs exact-commit adversarial evidence before release.

### T4 — Lost / stolen device

**Capabilities:** physical possession of a locked phone. Cannot
break Secure Enclave but may attempt brute-force on the screen
lock.

**Defenses (Tier A — browser PWA, planned for v0.16+):**
- Device-bound storage encryption: OPFS + IDB at-rest AES-GCM
  with a key derived (Argon2id, ≥256MB memory, ≥3 iterations) from
  a passphrase the user sets at install. A physical exfiltration
  of OPFS yields ciphertext indistinguishable from random.
- The passphrase is required on each app session start; the
  derived key never persists to disk.
- Optional Touch ID / Face ID protected unlock (when Secure
  Enclave present): the enclave protects a second symmetric key
  that decrypts the on-disk key; biometric unlock on the device
  is the only way to access it. **This IS using corporate
  hardware as a security primitive — it's free security with no
  privacy cost, since the enclave doesn't phone home.**
- Threshold-of-N device cluster (v0.17.0+): a lost device is
  signed-out remotely from any 2 of the user's other devices.
  Its share of the master secret is revoked; the cluster reseals.

**Defenses (Tier B — desktop daemon, alive at v0.20.7):**
- The SQLite state file, blob store, and UI bearer token live
  cleartext on disk under the user-account directory. The
  user-account isolation provided by the OS is the primary
  defense. As of v0.20.7 (audit fix H22) `PRAGMA secure_delete=ON`
  makes the disappearing-messages reaper actually scrub plaintext
  from freed pages + WAL.
- The Ed25519 identity key is unencrypted PEM by default, protected
  only by file permissions; the startup security report and the Privacy
  panel say so. Supplying a passphrase seals it with ChaCha20-Poly1305
  under a scrypt-derived key (N=2^17, r=8, p=1, about 128 MiB per
  guess), the same cost as the lockbox. Supply the passphrase with
  `ONE_LINK_PASSPHRASE_FILE` (a file only the service can read: a
  systemd credential, a Docker or Kubernetes secret) or with
  `ONE_LINK_PASSPHRASE`. An unencrypted key, and a key written by an
  older release with PKCS#8 PBKDF2 encryption (2,048 rounds), is
  re-sealed on the next successful load with a passphrase.
- File-mode 0600 on POSIX (audit fix H19 makes the write atomic).
  On Windows, `os.chmod` is a partial story; the inherited
  `%APPDATA%` ACL is the practical defense until the explicit
  user-only DACL ships (audit finding H3).

**Status:** 🔄 contained for Tier A once OPFS encryption ships
(planned v0.16+). Partially contained for Tier B at v0.20.7: the
disappearing-messages contract is honored, identity-key passphrase
is opt-in via `ONE_LINK_PASSPHRASE`, but the at-rest story for
chat bodies + group chain keys + UI token is still user-account
isolation rather than ciphertext-on-disk. Audit 2026-05-09
finding C5 tracks the gap.

### T5 — Compromised CDN / mirror

**Capabilities:** controls the bytes served at the user's
canonical install URL. Could push a backdoored bundle.

**Current implementation controls:**
- Release and verification workflows are present in source and pin their
  intended workflow identity and immutable tag.
- The verification script fails closed when a checksum manifest, manifest
  signature, artifact signature, or exact tag binding is missing.
- v0.21.0 published signature/SBOM/checksum assets; their existence does not
  replace independent verification of the downloaded release bytes.

**Required release controls:** signed checksum manifest, per-artifact Sigstore
bundles, provenance, published SBOM, independently compared Linux native wheel,
and pinned-update verification. Mirror diversity remains a roadmap item. Whole-product
byte-for-byte reproducibility is not claimed.

**Status:** ⚠️ not currently defeated for public binary distribution. The
mutable `auto-latest` prerelease is not trusted or supported. There is no
production binary download until an immutable tag publishes and passes the
full evidence contract.

### T6 — Compromised maintainer key

**Capabilities:** has a valid release-signing key; can sign a
backdoored release.

**Current controls:** the proposed release workflow uses short-lived GitHub
OIDC identity for Sigstore rather than a long-lived project signing key. At the
audit date there is no enforced multi-maintainer threshold signature, no
published project release key, and no repository tag ruleset preventing a
`v*` tag from being moved or deleted.

**Planned controls:** immutable protected version tags, least-privilege release
approval, multi-maintainer authorization, transparency-log monitoring, and
independent rebuild evidence scoped only to artifacts actually compared.

**Status:** ⚠️ not defeated. Threshold signing is a roadmap control, not a
current release property.

### T7 — Compromised browser engine (RCE in WebKit / Blink)

**Capabilities:** arbitrary code execution within the browser's
sandbox (e.g., via a 0-day in WebKit). Cannot escape the OS sandbox
without an additional escape vuln.

**Defenses (default tier):**
- Content Security Policy headers: `default-src 'self'; script-src
  'self' 'wasm-unsafe-eval'; connect-src 'self' wss: https:;
  style-src 'self' 'unsafe-inline'`. No third-party JS / CSS / fonts.
- Trusted Types policy where supported.
- All sensitive crypto runs in a Web Worker for isolation; the
  main thread can't read worker memory.
- Identity key material lives in non-extractable Web Crypto
  CryptoKey objects when possible (AES-GCM keys are extractable
  by spec, but Ed25519 / ML-KEM private keys can be marked
  non-extractable). Even RCE in the main thread can't read them.
- OPFS-stored data is encrypted; even read access via RCE yields
  ciphertext.

**Status:** mitigated. RCE in the browser engine is out-of-scope
for us to fix (that's Apple/Google/Mozilla's job), but our
hardening reduces the blast radius significantly. v0.20.7 audit
fixes H9 (CSP on `/`) and H10 (Host + Origin checks defending
against DNS-rebinding) shipped; Trusted Types is still aspirational
and many of the worker-isolation primitives are part of the
Tier A browser PWA roadmap rather than the Tier B daemon today.

### T7b — Unprivileged local process (an app running as you)

**Capabilities:** ordinary user-level code execution on the desktop
machine, with **no elevation**. Cannot read protected files owned by
other users, cannot install drivers — but *can* enumerate processes
and read the **full command line** of any process running as the same
user.

That last capability was measured, not assumed (Windows, 2026-08-06): a
marker planted in a child process's `argv` came back complete to an
unprivileged `Get-CimInstance Win32_Process` reader owned by the same
user. No debug privilege, no elevation.

**Why this row exists.** The model previously jumped from T7 (RCE inside
the browser sandbox) to T8 (root). It skipped the attacker a downloaded
desktop app most often actually meets: a second app the user installed
themselves, running with exactly the user's own rights. The daemon
already assumes this attacker elsewhere — `$BROWSER` is refused, `PATH`
is replaced with trusted roots, and executables are validated as
absolute registered images — so leaving the threat unnamed made the
posture inconsistent rather than absent.

**The defect this found.** The desktop launcher opened the UI as
`msedge.exe --app=http://127.0.0.1:PORT/?t=TOKEN`, and `t` was the UI
server's bearer — a credential granting a full owner session for the
daemon's entire lifetime. Because `_load_or_create_token` mints a fresh
per-process value and persists nothing at rest, that command line was
the **only** place the token left process memory: the exposure was not
"one of several", it was the whole of it.

**And it was four sites, not one.** The app-mode launcher is simply
where it was noticed. Auditing for the *class* rather than the instance
found the same bearer in the CLI auto-open, in the tray's stored click
URL, and in the `one-link://` deep-link handler — all of which reach a
browser, and `os.startfile(url)` puts the URL on the **browser's**
command line just as surely as `--app=` puts it on ours. Fixing only the
reported one would have left three live. Every browser-bound URL is now
built in one place (`cli._ui_launch_url`) so there is a single site to
audit rather than four to remember.

**Defenses (default tier):**
- **Single-use launch nonce.** The URL handed to the browser now carries
  a credential minted per launch, redeemable **once**, expiring in
  ~2 minutes (`UIServer.mint_launch_nonce`). A secret on a command line
  cannot be hidden, so the countermeasure is to put something there that
  stops being a secret. An `argv` snapshot is useful only to an attacker
  who wins a race against the browser *and* acts inside the window — and
  winning it makes the legitimate window **fail visibly** rather than
  silently share a session.
- The long-lived bearer stays an `Authorization` header on the
  authenticated control channel and never reaches `argv`.
- Redemption compares constant-time against every live nonce; a dict
  lookup would be an early-exit comparison on attacker-supplied text.
- The tray mints **per click** rather than caching. A stored single-use
  credential would open the app once and leave every later click dead,
  and that pressure is exactly how a nonce quietly becomes reusable
  again. With no provider wired it opens *unauthenticated* — a worse
  click, never a replayed secret.

**Residual risk, stated plainly:**
- The loopback `lan_url` export still embeds the long-lived token in a
  URL shown to the user (and encoded into the pairing QR). That is a
  different exposure with a different threat model — user-visible rather
  than machine-readable by a background process — and it is not closed
  by this change.
- A same-user process can also open a handle to the daemon and read its
  memory directly. Nothing here prevents that; the nonce removes the
  *easy, logged, and passively-collected* path (process listings, EDR
  telemetry, crash dumps), not the determined one.

**Status:** mitigated for the `argv` path, which was the measured leak.
Not claimed as immunity to a local attacker — see the residual above.

### T8 — Compromised OS

**Capabilities:** root access to the phone OS; can inspect any
process memory; can extract Secure Enclave-protected data only via
the legitimate API (the enclave itself remains tamper-resistant).

**Defenses (hardened tier):**
- Secure Enclave-backed keys are still safe — the enclave's whole
  purpose is to defeat OS root access.
- For the parts of state that aren't enclave-protected: OPFS at
  rest is encrypted; the in-memory derived key is wiped on app
  background. A snapshot of the OS state at lock-screen yields
  ciphertext.
- Plausibly deniable storage: outer file headers don't identify
  content type. A forensic exfiltrator without the unlock secret
  sees opaque bytes.

**Status:** partially mitigated. A compromised OS during an
active session is a hard problem; we minimize live memory exposure
(crypto in workers, key material non-extractable where possible)
but don't claim full immunity.

### T9 — State-actor adversary

**Capabilities:** can compel CAs to issue fake certs; can monitor
all internet traffic globally; can compel app store removal; can
compel cloud providers to disclose stored data.

**Target defenses (hardened tier + air-gap tier):**
- All applicable current defenses above, plus these unfinished targets:
- Tor-routed signaling (hardened tier).
- `.onion` mirror distribution (no DNS, no clearnet visible).
- Cover traffic + mix-net (hardened tier default-on): traffic
  shape uninformative to bulk surveillance.
- IPFS distribution: content-addressed, no canonical CDN.
- Air-gap tier: no internet at all. BLE/LAN/USB pairing only.
- Threshold-of-N identity: no single compelled-disclosure target.
- AGPLv3 license + non-profit trademark holding +
  refuse-acquisition charter (`GOVERNANCE.md`): no corporate entity
  can be compelled to ship a backdoor on our behalf.

**Status:** not established. Tor signaling, `.onion`/IPFS release
distribution, constant-rate cover, an independent mix-net, browser air-gap
transport coverage, and threshold release/identity authority are not deployed
as one verified product path. The native v2 single-relay path blinds pairwise
route tags and seals identity first flights, but still exposes endpoints,
timing, sizes, counts, and tag linkage. No state-actor resistance claim follows
from that narrower control.

---

## What we accept from corporate substrate (because it's real security)

We use these hardware/OS-level primitives as **opt-in security
upgrades**, never as the only line of defense, and never letting
them communicate with us back-side:

1. **Secure Enclave / StrongBox for key wrapping.** When Touch ID /
   Face ID protected key storage is available, we offer it as a
   convenience. The enclave protects a key that wraps our OPFS
   encryption key. **The enclave doesn't talk to Apple's servers
   about our key — it's a local primitive.** Free security.

2. **Hardware RNG via `crypto.getRandomValues()`.** Mixed with
   multi-source entropy (touch coordinates, audio noise floor,
   network jitter, accelerometer) via HKDF. The product is secure
   if any one source is non-adversarial. The hardware RNG is one
   of the better sources; we use it but never alone.

3. **OS-level CVE patching.** Out of our control; we benefit when
   the user keeps their OS up to date. We surface a hint in
   diagnostics when the OS is on a known-vulnerable version, but
   we can't force.

4. **Sandboxing (browser, OS).** The browser sandbox is a real
   defense against malicious websites. We benefit by running in
   it. Our CSP further restricts our own attack surface within
   the sandbox.

5. **WebRTC transport encryption.** DataChannels use SCTP over DTLS and
   media uses SRTP. Browser signaling and pairing add application
   identity checks, but browser/WebRTC paths do not inherit the daemon's
   ML-KEM or Double-Ratchet claim unless that exact session reports it.

6. **TLS to the rendezvous.** TLS protects the client-to-service hop. Native
   peer payloads remain inside the authenticated end-to-end channel. The v2
   relay additionally uses rotating pairwise tags and seals both identity
   first flights; that keeps identity keys off its relay wire but does not hide
   endpoint/timing/size/count metadata or make the operator unable to perform
   correlation.

What we **don't** accept:
- iCloud Keychain / Google Password Manager **default** sync of
  identity. (Opt-in only; default is OPFS.)
- Apple Push Notification Service **default** routing of message
  alerts. (Opt-in only.)
- Single corporate CA as the **only** trust root. (Pinned release
  key supplements.)

---

## Cryptographic correctness

This is where security engineering gets surgical. Every primitive
we ship has to be correct.

### Constant-time requirements and limits

Secret-dependent comparisons and native cryptographic primitives should use
constant-time implementations. Python/JavaScript wrappers, allocations,
parsing, and protocol control flow cannot honestly be described as globally
constant-time or constant-memory. Timing tests detect regressions within their
noise model; they are not a side-channel proof.

- AES-GCM via Web Crypto: browser-provided; assumed correct (modulo
  CVEs we can't fix). Wrapper code (key wrap/unwrap, IV generation)
  must be constant-time.
- ChaCha20-Poly1305: same.
- Ed25519 + X25519: Web Crypto where available; selected browser paths use
  `@noble/curves`. Library choice is not proof that wrapper behavior is
  constant-time.
- ML-KEM and ML-DSA paths use reviewed libraries where wired; runtime and
  integration side channels remain in scope.
- HMAC and HKDF use platform/library primitives. Wrapper control flow must be
  reviewed separately.

### Nonce / IV uniqueness

The single most common cryptographic failure. Defenses:

- AES-GCM nonces: 96-bit, deterministic counter for sequential
  ratchet keys, random for one-shot. Counter is per-key, not
  per-message. Reuse → game over for that key, so we abort if
  counter wraps.
- ChaCha20-Poly1305 takes a 96-bit nonce. The daemon channel encodes its bounded
  sequence counter into that nonce; Double Ratchet message keys are fresh and
  use the message number in the nonce. Reuse under one key is forbidden.
- WebRTC DataChannel sequence numbers: tracked per session.
- Tests: a "nonce reuse detector" that tracks (key, nonce) pairs
  in a test database and fails any message that reuses one.

### Forward secrecy + post-compromise security

- Current mutually capable daemon peers negotiate and activate the Double
  Ratchet after the initial session handshake. Legacy compatibility paths may
  stay on per-session AEAD and must not inherit the ratchet claim.
- A TreeKEM primitive exists, but full RFC 9420 MLS behavior on every group path
  is not claimed without integration and interoperability evidence.
- Tests cover ratchet transitions and key erasure at the application level.
  Python runtime copies, crash dumps, swap, endpoint compromise, and delivered
  plaintext remain outside a strict zeroization guarantee.

### Key separation

Distinct protocol contexts are required to derive distinct keys via HKDF with
registered context-binding labels. The inventory and collision tests are
release gates; this paragraph is not proof that an unregistered path cannot
reuse a key. Intended separations include:

- Identity signing key (Ed25519) ≠ identity encryption key (X25519).
- Identity encryption key ≠ session ratchet key.
- Session ratchet key ≠ chunk encryption key.
- Per-conversation, per-direction, per-purpose subkeys via HKDF.

### Post-quantum hybrid

Current daemon-to-daemon `channel.py` sessions use a distinct v3 handshake that:

- signs the exact version, ordered suite offer/selection, identities, nonces,
  X25519 shares, ML-KEM hybrid public key/ciphertext, and prior-flight hash;
- extracts an independent channel X25519 secret together with the verified
  native ML-KEM-768/X25519 KEM secret into the full transcript;
- requires mutual HMAC key confirmation before either endpoint returns a
  usable channel; and
- rejects legacy/classical handshakes by default. Migration requires an
  explicit downgrade flag/environment policy and the resulting `Channel`
  reports `pq_protected=False`.

The native capability is not advertised unless its exact ABI sizes and a live
encapsulation/decapsulation self-test pass. A missing or unhealthy native wheel
fails closed before the initiator writes a handshake frame.

This is a session-confidentiality/HNDL claim, not a blanket post-quantum product
claim. The handshake authentication signature remains Ed25519, browser/WebRTC
paths are separate, and `ol_pqsig`/ML-DSA is not yet authoritative on every
identity, recovery, update, and transport path. A verified release and
cross-platform/two-device qualification remain required. The broader design reuses
[`std/crypto/quantum_safe.cl`](../../coherence_lang/coherence_lang/bootstrap/stdlib/std/crypto/quantum_safe.cl)
where mature, else `@noble/post-quantum`.

---

## Runtime hardening

Beyond cryptographic correctness, the running app needs to be
hard to exploit even given a vulnerability.

### Content Security Policy

The application serves a CSP header and related browser hardening. The policy
shape under review is:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
connect-src 'self' wss: https:;
worker-src 'self' blob:;
frame-src 'none';
object-src 'none';
base-uri 'self';
form-action 'none';
```

This policy reduces browser attack surface but still permits inline styles,
WASM evaluation, selected connection targets, data/blob content, and product
frames where explicitly allowed by endpoint policy. CSP does not make a
successful XSS harmless or prevent access to data already available to the UI.

### Trusted Types

Trusted Types enforcement is a roadmap hardening gate. Source-level sanitizer
helpers are not equivalent to browser-enforced Trusted Types on every sink.

### Subresource Integrity

If a third-party resource is introduced, release review must either remove it
or pin its exact bytes with an appropriate integrity and origin policy.

### Memory safety

JavaScript reduces common memory-corruption exposure, while WebAssembly and
native Rust extensions still require their own memory-safety review (including
`unsafe` and FFI boundaries). Memory safety does not prevent logic errors,
resource exhaustion, side channels, or compromised dependencies.

### Sensitive material lifecycle

Non-extractable browser keys, worker-only handling, prompt-on-resume, and
reliable zeroization are target properties, not blanket current guarantees.
The desktop Python process necessarily handles key bytes in ordinary process
memory, where copies and interpreter lifetime cannot be proven erased. The UI
should expose fingerprints rather than private key material; this remains a
regression-test requirement.

### Worker isolation

Worker isolation is a Tier A design control. It is useful only for operations
whose keys are actually created and retained in that worker; it does not
describe the desktop daemon or prove that an XSS cannot request authorized
operations through the worker API.

### Dependency hygiene

- The project has third-party runtime dependencies, including:
  `cryptography`, `aiohttp`, `zeroconf`, `click`, `blake3`,
  `platformdirs`, and `watchdog`. Open-source availability does not itself
  establish that a dependency or the integration has been independently audited.
- Browser paths also reference `@noble/curves`, `@noble/hashes`,
  `@noble/post-quantum`, and `yjs`. Their licenses, versions, advisories, and
  integration behavior need verification at the release commit.
- The universal lock records resolved registry versions and hashes; project
  declarations intentionally use bounded compatibility ranges.
- Configured CI runs lock-drift checks, Python/Rust/JavaScript advisory scans,
  secret scanning, workflow linting, SAST, and SBOM generation. A workflow's
  presence is not evidence that every historical or future run is green.
- End-to-end byte-for-byte reproducibility is not established. The configured
  reproducibility check is intentionally limited to two Linux native-wheel
  builds and needs successful tag-run evidence.

---

## Supply chain security

Where the bytes come from is as important as how they're written.

**Current evidence (2026-11-24):** source and frozen dependency locks are
available. Published v0.21.0 completed the release workflow and exposes Sigstore,
SBOM and checksum assets. Its independent reproducibility comparison failed;
artifact signature/provenance validation and fresh-device qualification remain
unverified by that audit. See `RELEASE_EVIDENCE.json` for exact identities.

**Release gate (not yet satisfied):** an immutable `v*` tag must run the full
tag-scoped gates and publish exact-byte checksums, signed manifest and artifact
bundles, build provenance, an SBOM, and fresh-device smoke evidence. The
release workflow requires an independent rebuild of its actual Linux native
wheel before signing and publishing. The separate diagnostic workflow also
compares Linux native-wheel bytes. Neither establishes reproducibility of
Windows, macOS, standalone archives, or
the entire product.

**Roadmap, not current guarantees:** SLSA-level certification,
multi-maintainer threshold signing, a pinned release key in the Service Worker,
and GitLab/Codeberg/IPFS/Tor mirror diversity. These controls become claims
only after their enforcement and public evidence are independently verified.

---

## Vulnerability response

- **Coordinated disclosure.** A `SECURITY.md` at repo root (separate
  from this design doc) tells researchers how to report. No authenticated
  project PGP disclosure key is currently published.
- **CVE response process.** A documented runbook: triage → patch →
  ship → backport → publish advisory → update warrant canary if
  applicable.
- **Bug bounty (planned).** No funded bounty is currently offered; the root
  policy describes the present recognition-only arrangement.
- **Penetration testing (planned).** An annual independent assessment is a
  target, not current evidence of external certification.
- **Cryptographic review (required before production).** Major crypto changes
  need external review before they can support a production-readiness claim.

---

## What we promise vs. what we can't promise

**Evidence-backed statements about the current development tree:**
- The source and dependency locks are public and can be reviewed at an exact
  commit. Public source is not proof that every path has been independently
  audited.
- The desktop state database is configured to use SQLCipher by default and to
  refuse silent plaintext fallback; an operator can explicitly opt into
  plaintext. Identity keys, received blobs, runtime memory, and OS account
  security have separate limits documented above.
- Automated test, security, release, and verification workflows exist. The
  published v0.21.0 evidence set and its unresolved qualification gaps are
  recorded in `RELEASE_EVIDENCE.json`; publication alone is not sign-off.

**We do not promise:**
- Production readiness, independent security certification, complete code-path
  coverage, or that the development tree is suitable for sensitive data.
- Whole-product reproducible builds, a SLSA level, threshold release signing,
  signed updates, or signatures/SBOM/provenance on every download. Those are
  gates or roadmap targets until public artifacts prove otherwise.
- Immunity from browser or OS zero-days, a compromised OS during an active
  session, or malicious software already running as the user.
- Network-metadata anonymity in the default tier, or availability against a
  capable denial-of-service adversary.
- That no bug will ship. Security-sensitive use requires independent review,
  a verified immutable release, and the user's patched, trustworthy OS.

---

## Threat-model coverage matrix

This matrix is a historical implementation assessment, not production-release
evidence or a fresh audit of every feature at current `master`. ✅ means the
named source-level defense had evidence at the cited audit; 🔄 means a design or
implementation was incomplete; ⚠️ means a known gap. Any row not reverified at
an exact commit must be treated as unknown by a release reviewer. Tier A =
browser PWA path; Tier B = desktop daemon path; "Default" sums them (where a
threat applies to both, the worse status wins).

| Threat | Default | Hardened | Air-gap |
|---|---|---|---|
| T1 Casual snoop | ✅ | ✅ | N/A |
| T2 Active MITM (daemon channel) | ✅ | ✅ | N/A |
| T2 Active MITM (browser-as-peer) | partial: signed signaling, identity-possession and live Chromium/Firefox direct probes; physical route matrix open | partial | N/A |
| T3 Compromised peer (chat only) | ✅ (cap policy C3) | ✅ | ✅ |
| T3 Compromised peer (FS / PCS) | partial: mutually capable daemon peers activate DR; legacy/browser boundaries remain | partial | partial |
| T4 Lost device (Tier A — browser PWA) | 🔄 (OPFS + Argon2id v0.16+) | 🔄 (plausibly deniable) | 🔄 |
| T4 Lost device (Tier B — daemon) | partial: SQLCipher state DB default; identity/blob/runtime/OS limits remain | partial | partial |
| T5 Compromised CDN/mirror | ⚠️ no verified public binary release; SW pinning planned | 🔄 (.onion / IPFS planned) | ✅ (no fetch ever) |
| T6 Compromised maintainer key | ⚠️ no threshold signing or protected version-tag ruleset | ⚠️ | ✅ |
| T7 Compromised browser engine | mitigated (CSP on `/` + `/peer` at v0.20.7) | mitigated (Trusted Types aspirational) | mitigated |
| T8 Compromised OS (Tier A) | mitigated (Secure Enclave on) | mitigated (no Secure Enclave reliance) | mitigated |
| T8 Compromised OS (Tier B) | ⚠️ keys swappable to disk; no mlock yet | ⚠️ same | ⚠️ same |
| T9 State actor (passive global obs) | partial payload secrecy; v2 relay identity blinding still leaks correlatable metadata | 🔄 (Tor + cover/mix planned) | target only; whole-product air-gap proof absent |
| T9 State actor (active disruption) | ⚠️ signed updates and verified production distribution unavailable | 🔄 | ✅ |

The cells that read ✅ in the 2026-05-08 revision of this doc and
now read 🔄 / ⚠️ were not regressions in the code; they were
overstated promises. The 2026-05-09 audit identified five critical
gaps (C1-C5 in the audit findings file) and the project is shipping
fixes for all of them across the v0.20.7 → v0.21 cycle. Bundles 1-6
of those fixes landed in source on 2026-05-09 (commits `8857bcf`, `cd64bd6`,
`e56e7ce`, `9a880f7`, `9f5a137`, `8a2cb1d` — 32 audit findings closed).

---

## Audit cadence

Per `PRINCIPLES.md`, every quarter:

1. Re-read this document. Has the threat model expanded? (New
   adversary capabilities, new attack patterns published, new CVE
   classes.)
2. Re-test the cryptographic primitives. Run nonce-reuse detector
   over recent code. Verify constant-time tests still pass.
3. If a verified tagged release exists, reproduce only the artifacts covered
   by an explicit comparison gate and record the exact hashes. Do not use
   `latest` or a mutable prerelease as a reproducibility reference.
4. Re-publish the warrant canary (also tracked in `GOVERNANCE.md`).
5. External pentest: annual. Cryptographic review: per-major-crypto-
   change.
6. Publish a quarterly "Security state" summary on the project
   website. What we patched, what threats we updated against, what
   was found in the last pentest.

A security document that doesn't get audited becomes
decoration. **Audit this with religious discipline.** This is the
floor of the user trust we asked for; we honor it by checking the
floor regularly.
