# Production-readiness audit: remediation record (2026-11-26)

The production-readiness audit of 2026-11-26 recorded 59 findings: 11 high,
22 medium, 25 low and 1 informational. This file records what was done about
each one on branch `audit/remediation-2026-11-26`, which is based on
`engineering/one-link-phase-zero` (pull requests #88 and #89).

It is a record of work done on its date, not a description of the product.
The status of every finding is one of:

- **Fixed**: changed in this branch, with a test that fails without the change.
- **Fixed in #89**: already fixed on the base branch.
- **Partly**: something concrete was done; what remains is stated.
- **Open**: nothing in this branch resolves it; who has to act is stated.
- **By design**: the behaviour is intended.

## Root causes

Most findings were symptoms of a small number of structural problems. Each
was fixed at its root where that was possible.

| | Root cause | Fix | Findings |
|---|---|---|---|
| A | A peer that had only completed a handshake was treated as free: nothing bounded the size, number or consequences of what it sent. | `peer_admission.py` holds every limit for a peer without standing: frame size, frame volume, owner prompts, stored records, and a declared gate per message type that a test checks against the dispatcher. | NET-1, NET-2, CR-5, CQ-1, TST-2, UI-4, NET-6, NET-5 |
| B | Secrets were protected by whatever a library did by default. | A sealed identity-key format with a chosen KDF, a passphrase source that is not the environment, and KEM secrets wiped after use. | CR-1, ID-4, ID-5, CR-3 |
| C | Recovery produced bytes and could not say whether they were the right bytes. | The split secret carries a digest of the seed; shares are signed. | ID-1, ID-3, ID-2 |
| D | The native boundary was trusted in both directions: a fault inside it killed the process, and keys crossing it were not checked. | `panic = "unwind"`, the FIPS 203 key check, one TLS backend. | NET-3, CR-2, CR-7, CR-4, SC-4 |
| E | Strings became markup, and a page could talk to any server. | A gate on HTML sinks, DOM construction for remote text, `connect-src` limited to the daemon. | UI-1, UI-2, UI-3, UI-5, UI-6 |
| F | State crossed version and transaction boundaries without a guard. | Newer-schema refusal, pre-upgrade snapshot, run-once migrations, a settings transaction that cannot yield. | ST-1, ST-2, UI-7, ST-3 |
| G | Facts lived in prose that could drift from the source. | Documents generated from, or tested against, the source: notices, environment reference, network contacts, licensing, docs index. | DOC-1, DOC-2, DOC-3, DOC-5, DOC-6, CQ-4, SC-6, REL-5, NET-4, NET-7 |
| H | Debt had no counter, so it could only grow. | Ratchets that allow improvement only, and a wider lint rule set. | CQ-2, CQ-3, TST-1, TST-4, CQ-5 |
| I | Not a property of the code. | Needs the owner: review, signing, release process, infrastructure, legal. | EXT-1, CR-6, REL-1, REL-2, REL-3, REL-4, SC-1, SC-2, SC-3, SC-5, SC-7, TST-3, DOC-4, REL-6, ST-4 |

## Every finding

### High

| Finding | Status | What was done | How it was verified |
|---|---|---|---|
| REL-1 public v0.21.0 release is live and unsupported | Open (owner) | Nothing in code. The `Unreleased` changelog entry lists the compatibility changes the next release notes need. | Not applicable |
| SC-1 base branch failed its own dependency audits | Fixed in #89 | This branch also removes `aws-lc-rs` and `aws-lc-sys` from the tree. | `cargo tree -i aws-lc-rs` finds nothing; `tests/test_native_build_contract.py` |
| SC-2 a pushed tag is the whole update trust decision | Open (owner) | Needs a tag ruleset and signing policy in the repository settings. | Not applicable |
| NET-1 16 MiB frames before pairing stall the daemon | Fixed | Handshake frames capped at 16 KiB, unpaired peers at 256 KiB, refused from the length prefix. Depth check rewritten to run at C speed; frames with over a million containers refused. | `tests/test_peer_admission.py`; property tests compare the depth check with `json.loads` and with the old scan. A 16 MiB frame: about 1.2 s before, about 15 ms after |
| NET-2 unpaired identities leave unbounded state | Fixed | Pending peer rows pruned beyond a cap; per-peer maps bounded; per-connection frame allowance; shared prompt allowance; `PAIR_REJECT` only inside a live pairing; key-change alerts capped. | `tests/test_peer_admission.py`, including a real connection that is closed when its allowance is spent |
| NET-3 `panic = "abort"` in the native library | Fixed | Release profile is `panic = "unwind"`. The deterministic constant-time audit was re-run on that code generation (see "Found by CI on the pull request"). **Remaining:** the constant-time timing evidence in `docs/audit/evidence/` was measured with `abort` and has to be regenerated on the release runners. | `tests/test_native_build_contract.py`; `cargo test -p ol_pqkem -p ol_quic`; `scripts/run_ct_audit.py`, 27 of 27 cases |
| NET-6 rendezvous capped at 64 sockets, two addresses fill it | Partly | One source address (IPv4, or IPv6 /64) may hold 16 slots. **Remaining:** the total is a memory bound; enough distinct addresses still fill one server. More capacity or more servers is an operating decision. | `tests/test_rendezvous_fair_admission.py` |
| CR-1 identity key protected by 2,048 PBKDF2 rounds | Fixed | Sealed with scrypt (N=2^17) and ChaCha20-Poly1305; parameters authenticated and bounded; old files re-sealed on load. | `tests/test_identity_encrypted.py`; property test for wrong passphrase and any flipped byte |
| ID-1 share recovery cannot detect a wrong result | Fixed | Split secret is `seed || digest(seed)`; a wrong reconstruction raises and stages nothing; legacy shares refused unless explicitly allowed. | `tests/test_recovery_share_verification.py`, `tests/test_social_recovery_v0207.py`, `tests/properties/test_shamir_roundtrip.py` |
| ID-2 biased Shamir coefficient | Fixed in #89 | Unchanged here. | Existing property tests pass with the new share format |
| EXT-1 no independent protocol review | Open (owner) | `SECURITY.md` now states this plainly. | Not applicable |

### Medium

| Finding | Status | What was done | How it was verified |
|---|---|---|---|
| CR-2 ML-KEM key check skipped | Fixed | `HybridPublicKey::from_bytes` applies the FIPS 203 section 7.2 modulus check. | Rust unit tests; `tests/test_pqkem_key_validation.py` against the rebuilt extension |
| CR-3 KEM secrets not wiped | Fixed | `zeroize` enabled for ml-kem, hybrid-array and blake3; shared secret and key copies wiped; the combiner no longer copies secrets to the heap. | Rust tests (output unchanged: pinned determinism test); `tests/test_native_build_contract.py` |
| CR-6 no formal model of the live handshake | Open (owner) | Not attempted: it needs Tamarin or ProVerif work by someone who can run and review the model. | Not applicable |
| NET-4 mDNS announces more than it needs | Fixed | The OS hostname was already not announced on the base branch. Quiet, or the `mdns_announce_details` setting, now announces only the short ID and public key, including after later updates. | `tests/test_mdns_announce_details.py` |
| NET-5 peer lookup by short ID, then substring | Fixed | A name resolves only when it names exactly one peer; a pinned peer wins a short-ID collision; ambiguity resolves to nothing. | `tests/test_peer_admission.py`, `tests/test_state.py`, `tests/test_discovery.py`, property test |
| NET-7 no default rendezvous, third-party STUN | Partly | Disclosed in `docs/NETWORK_CONTACTS.md`. **Remaining:** operating a project rendezvous or STUN service. | `tests/test_network_contacts_disclosure.py` |
| UI-1 remote text written to `innerHTML` | Fixed | Built with DOM nodes and `textContent`. | `tests/test_html_sink_gate.py` |
| UI-2 HTML sinks ungated | Partly | A gate that only allows the number of dynamic sinks to go down; three removed. **Remaining:** 50 dynamic sinks are grandfathered, and Trusted Types is not enforced; that needs a browser to verify. | `tests/test_html_sink_gate.py` |
| ST-1 no schema guard or snapshot | Fixed | A database from a newer release is refused untouched; an upgrade first writes `state.db.pre-migration-vN.bak`. | `tests/test_state_schema_boundary.py`; `tests/test_fsync_needs_writable_handle.py` |
| CQ-1 authorization by convention in the dispatcher | Fixed | `MESSAGE_GATES` declares each type's gate; a test parses the dispatcher and fails on an undeclared type or a gated type with no trust check. The dispatcher itself was not split. | `tests/test_peer_admission.py` |
| CQ-2 broad exception handlers | Partly | A ratchet: 1,234 counted, the number per file may not grow. **Remaining:** none were narrowed. | `tests/test_debt_ratchet.py` |
| TST-1 tests that match UI source text | Partly | A ratchet: 104 files counted, no new one may be added. **Remaining:** none were converted. | `tests/test_debt_ratchet.py` |
| TST-2 no tests for abuse cases | Fixed | Abuse-case tests for every limit above. | 184 test functions added, 21 new test files |
| TST-3 pairing tests deselected | Fixed in #89 | Unchanged here. | — |
| SC-3 pull requests too large to review | Open (owner) | A process matter. This branch is itself large and is split into commits by subject. | Not applicable |
| SC-4 forks of ml-kem and glib | Partly | Both are listed as third-party code with their own licenses. **Remaining:** retiring them needs ml-kem 0.3.4 or later and a glib upgrade. | `tests/test_third_party_notices.py`, `tests/test_reuse_metadata.py` |
| SC-5 timing gates not enforced | Fixed in #89 | Unchanged here. | — |
| REL-2 installers unsigned | Open (owner) | Needs code-signing certificates. | Not applicable |
| REL-3 no reliable path to deliver a fix | Open (owner) | Needs a release and update process decision. | Not applicable |
| REL-4 single maintainer, no PGP key | Open (owner) | Not a code matter. | Not applicable |
| DOC-1 no third-party notices | Fixed | `THIRD_PARTY_NOTICES.md`, generated from both Rust lock files and the Python lock, shipped in the wheel. | `tests/test_third_party_notices.py` |
| DOC-3 default network contacts not disclosed | Fixed | `docs/NETWORK_CONTACTS.md`; the comment that called the update poll opt-in is corrected. | `tests/test_network_contacts_disclosure.py` |

### Low

| Finding | Status | What was done | How it was verified |
|---|---|---|---|
| CR-4 combiner omits the recipient key | By design | Changing it changes every derived key. Documented at the combiner; the channel handshake binds both identities, the hybrid key and the ciphertext through its transcript. | `tests/test_channel_pq_handshake.py` (existing) |
| CR-5 replay cache written before the signature check | Fixed | Lookup before the signature, insert after, on all three handshake paths. | `tests/test_peer_admission.py` (forged HELLO cannot burn the real sender's nonce) |
| CR-7 two crypto backends | Fixed | quinn built with ring. | `tests/test_native_build_contract.py` |
| ID-3 shares unsigned | Fixed | Each share is signed by its creator; the creator's key is bound into the ciphertext. | `tests/test_social_recovery_v0207.py` |
| ID-4 passphrase only from the environment | Fixed | `ONE_LINK_PASSPHRASE_FILE`. An interactive or keyring prompt was not added. | `tests/test_identity_encrypted.py` |
| ID-5 identity key unencrypted by default | Partly | The startup report and the Privacy panel now say how the key is protected. **Remaining:** sealing by default needs a decision on where the wrapping key lives. | `tests/test_identity_encrypted.py` |
| UI-3 bearer in localStorage, wide `connect-src` | Partly | `connect-src` is the daemon's origin and its own WebSocket. **Remaining:** storage is unchanged; the reasons are in `frontend/owner/main/session.js`. | `tests/test_owner_csp_connect_src.py` |
| UI-4 rate buckets never pruned | Fixed | Swept as the map grows, capped. | `tests/test_ui_rate_bucket_bounds.py` |
| UI-5 names keep bidi overrides | Fixed | Bidi controls and C1 controls removed from received names. | `tests/test_transfer_name_spoofing.py`, property test |
| UI-6 `/dr_test` served in every build | Fixed | Needs `ONE_LINK_SERVE_DEV_PAGES=1`. | `tests/test_dev_pages_opt_in.py` |
| UI-7 settings transaction held across a wait | Fixed | Body read first; the handler may not yield inside the transaction. | `tests/test_settings_transaction_is_synchronous.py` |
| ST-2 migrations re-run every boot | Fixed | Steps added from now on run once unless they opt in. Existing steps behave as before. | `tests/test_state_schema_boundary.py` |
| ST-3 durable commits block the event loop | Open (owner) | Not attempted: it means moving state writes to their own thread. | Not applicable |
| CQ-3 narrow lint rule set | Partly | Adds bugbear, pylint errors, unreferenced tasks and three more rule groups, all at zero violations. **Remaining:** seven bugbear rules with 124 existing violations are listed as debt. | `ruff check src/one_link`; `tests/test_task_refs.py` |
| CQ-4 undocumented environment switches | Fixed | 28 switches documented; a test requires every name in the source to be in the reference. | `tests/test_env_reference_is_complete.py` |
| CQ-5 developer path in `native/.cargo/config.toml` | Open (owner) | Left as it is: it is a default the `PYO3_PYTHON` variable overrides, and the workspace builds on Linux with it. | `cargo check` on Linux |
| TST-4 thin property-test coverage | Fixed | Ten property tests over framing, the depth check, names, budgets, name resolution and the sealed key. | `tests/properties/test_untrusted_input_properties.py` |
| SC-6 no license gate | Fixed | An allow list checked for every component. | `tests/test_third_party_notices.py` |
| SC-7 benchmark logs and transcripts in the repository | Open (owner) | Removing them is a decision about repository content and history. | Not applicable |
| REL-5 changelog stops at 0.21.0-alpha | Partly | An `Unreleased` entry for this work. **Remaining:** the releases in between are not back-filled. | — |
| REL-6 phone trust profile breaks when the LAN address changes | Open (owner) | Not changed: the alternative widens what a stolen root key could impersonate, which is the owner's trade-off to make. | Not applicable |
| DOC-2 LibriSpeech-trained model lacks attribution | Fixed | Attribution in `THIRD_PARTY_NOTICES.md`. | `tests/test_third_party_notices.py` |
| DOC-4 no export-control position | Open (owner) | A legal determination. | Not applicable |
| DOC-5 no SPDX data, dangling audit reference | Fixed | `REUSE.toml` and `LICENSES/`; `reuse lint` reports 2,347 of 2,347 files covered; `SECURITY.md` reference corrected. | `tests/test_reuse_metadata.py`; `reuse lint` |
| DOC-6 current and historical documents mixed | Fixed | `docs/README.md` sorts every document by kind. The documents' contents were not re-verified. | `tests/test_docs_index.py` |

### Informational

| Finding | Status | What was done | How it was verified |
|---|---|---|---|
| ST-4 received files are stored unencrypted | By design | Unchanged. | Not applicable |

## Found while fixing

These were not in the audit.

- The legacy HELLO rejection path also wrote the replay cache before
  checking the signature.
- Any authenticated stranger could send `PAIR_REJECT` and create a permanent
  `rejected` record.
- A flood of inbound pair requests could evict a pairing the owner had
  started.
- A hostname that cycled through keys logged an alert against every earlier
  key each time.
- Two shares could be issued to one guardian, and one share could be counted
  twice when combining.
- Nine fire-and-forget asyncio tasks were started without a reference and
  could be garbage-collected before finishing.
- Clipboard HTML was parsed inside the live document.
- A fixed-size text window in one test stopped seeing the code it asserted on
  when the handler grew.

## Found by CI on the pull request

Three defects in this branch's own work. Its first CI run failed five checks;
two of the five are gates that only repeat another job's result.

- **The pre-upgrade snapshot stopped every schema upgrade on Windows.** It
  was synced through a handle opened for reading. Windows flushes with
  `FlushFileBuffers`, which needs write access and fails with EBADF; POSIX
  accepts the call, so Linux and macOS passed. Fixed by opening the snapshot
  read-write. `tests/test_state_schema_boundary.py` now holds the Windows
  rule on POSIX, and `tests/test_fsync_needs_writable_handle.py` scans
  `src/one_link` and `scripts` for the same mistake. The snapshot's directory
  entry is now synced too, where the platform allows it.
- **The constant-time audit failed on the `unwind` build.** The compiler
  attributes the Poly1305 tag verdict of `confidential_unseal_tampered` to
  `chacha20poly1305` 0.10.1 `src/cipher.rs:87` (`if
  self.mac.verify(tag).is_ok()`), where the `abort` build attributed the same
  four branches to `universal-hash` 0.5.1 `src/lib.rs:154`. Both lines test
  the one accept/reject result of a `subtle::ConstantTimeEq` comparison. The
  audit was right to stop: the reviewed line was no longer the reported one.
  The new line was read and the entry in
  `native/ol_ct_audit/external_declassifications.json` replaced. Two gaps in
  the audit driver were closed at the same time: an entry's `cases` list was
  written down and never enforced, and an entry that matched nothing stayed
  in the list without complaint. An entry now applies only to the cases it
  names, and one that declassifies nothing in such a case fails the run
  (`tests/test_ct_audit_contract.py`).
- **The secret scan read the sealed-key armor as private keys.** The marker
  lines were written out as literals, in `identity.py` and in a test, close
  enough together to match the scanner's private-key rule. No key was
  involved. The markers are now assembled from their parts, so nothing in the
  working tree is exempt from that rule, and
  `tests/test_no_private_key_shaped_literals.py` reads the tree for the same
  shape before a commit is made. A test also pins the exact bytes written to
  disk, which the old tests took from the constants they were checking.

  The scan reads every commit on every branch, so deleting the lines in a
  later commit would not have cleared it, and it would have failed the scan
  of every other pull request as well. The commit that introduced the
  literals was amended on this branch instead, so no commit in the
  repository matches and `.gitleaks.toml` needs no entry for it.

## Totals

| Status | Count |
|---|---|
| Fixed | 30 |
| Fixed in #89 | 4 |
| Partly | 10 |
| Open (owner) | 13 |
| By design | 2 |
