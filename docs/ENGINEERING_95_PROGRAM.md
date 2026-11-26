# One Link 95+ engineering program

Status: proposed acceptance contract and execution sequence, **not a scored or
qualified release**. Baseline: c679803a812f3f55860c27a8a5d0cd2ba865bf7f.
Companion sources: ROADMAP.md, docs/WE_ARE_ONE_MASTER_PLAN.md,
docs/SOVEREIGN_NETWORK_BLUEPRINT.md, docs/ONE_LINK_VALIDATION_GATES.md,
docs/RELEASE_CHECKLIST.md, docs/RELEASE_PROTECTION.md, and the dated remediation ledger.

## Decision rule

A 95+ target is a requirement, not an award. No arithmetic average may hide
a hard failure. The nine dimensions below are separately evaluated, with
versioned claims, named measurements, independent reviewers, and exact artifact
identities. Missing evidence is UNKNOWN, not PASS. Simulated, same-host,
physical cross-host, and independently reproduced evidence remain distinct.
Any security-critical failure, silent corruption/loss, unqualified installer,
or falsely promoted capability blocks release irrespective of other results.
Scores cannot be compared against the previous informal opinion without a
defined scoring instrument and measured evidence. Do not publish a score until
the individual criteria are agreed and independently reviewed.

## Nine acceptance dimensions

| Dimension | Qualification target (proposed, not measured) |
|---|---|
| Architecture | Every production route has an explicit typed contract, ownership boundary, ADR, compatibility contract, resource budget and threat model. Extract orchestration services incrementally with equivalence tests; no duplicate authority or divergent implementations. |
| Engineering | Complete existing runtime paths, qualify native kernels and fallback behavior, use field-guided transport only as advisory selection under hard invariants. Measure p50/p95/p99 latency, goodput, bytes on wire, CPU, RSS, energy and fault recovery; no correctness regressions. |
| Security | Independent protocol and implementation review; zero unresolved critical/high findings; threat-model-scoped PQ migration, key rotation/revocation, downgrade refusal, group isolation, parser/resource bounds, supply-chain controls, and endpoint/metadata limitations. Security release gates must be unbypassable by candidate code. |
| Verification | Every shipping claim linked to source, artifact and independent verification method; property, fuzz, mutation, model, live and physical tests with negative controls. All required checks executed and passing on exact release source. Skips are enumerated and cannot stand in for claims. |
| Differentiation | Pre-register comparisons with Syncthing, LocalSend, Tailscale/Taildrop, and other relevant tools per workload. Show at least one material, independently reproduced advantage in qualified user-relevant workloads, while reporting unfavorable results and feature gaps. |
| Scalability | Measure one-to-one, family, team and large-mesh workload curves at increasing concurrency; run 24 h then 7 d soaks, churn, fault injection, saturation and recovery; publish sustainable operating envelopes, not untested peer-count promises. |
| Production readiness | Exact source/build/install identity; complete platform matrix, independent reproducibility scope, verified provenance, protected release governance, transactional rollback, clean-device install/update/uninstall, recovery and public-download parity. No production promotion while PR #88/release gates remain blocked. |
| UX | Proposed targets: >=95% unassisted success on critical install/pair/send/receive/recover tasks in representative sessions; median first verified transfer <=90 seconds on supported healthy networks; comprehensible status, keyboard and screen-reader navigation, contrast and localization validation. Physical mobile and accessibility tests required. |
| Commercial readiness | Validate real customer jobs and voluntary repeat use through consented pilots; document support load, relay/storage cost, deployment time, pricing and unit economics; signed-off support/privacy processes and repeatable onboarding. Adoption and retention cannot be awarded by code or internal testing. |

Targets must be refined with actual workload definitions, sample sizes,
confidence intervals, supported devices and review owners before promotion.
A failed target remains open; do not tune thresholds after observing a result.

## Stage 0: stabilize and ship the current product

- Keep PR #88 separate from new platform work. Obtain the required independent
  review, resolve remaining ledger items, and qualify the actual master commit.
- Apply tag/environment protection with maintainer-selected independent
  reviewers, not bypasses. Confirm platform-specific signing/distribution policy
  against the current sovereignty doctrine; do not silently choose paid
  gatekeepers or ask users to weaken OS security.
- Complete source and release qualification, including public website download
  hashes, artifact identity, cold install, migration/rollback, and supported
  updater paths. A rolling prerelease remains a different trust tier.
- Reproduce and close FLD-03's disconnected-sender acceptance and parked
  delivery cases, including admission failure, exact consent matching,
  revocation/decline, and crash recovery. Preserve partial ownership, receipt
  uniqueness, quotas, and user choice; never grant consent across identities,
  content, size, destination or presentation. No production changes solely
  to make a test green.
- Resolve intermittent hosted disk and live network tests by paired measurement
  and root-cause evidence, not looser gates. Controlled timing requires
  quiet hardware. Qualify both owner devices separately.
- Reconcile source/capability, docs, UI, website and release ledgers.

## Stage 1: finish existing foundations

- Native filesystem surface: ol_fuse has a read-only Linux adapter; qualify
  the packaged /dev/fuse path, 24 h fsx and adverse filesystem tests. Implement
  ol_winfs (WinFsp or Dokan, after interface/license choice) and ol_fskit
  (Apple-supported FSKit or documented alternative) using the verified blob
  reader contract; refuse unverified bytes; initially read-only, explicit
  mounts, bounded queues, path/symlink/permission checks, safe unmount,
  corruption and crash tests. Driver/platform privileges require approval;
  do not advertise them until native device qualification.
- Transport facade: scoped audit observed 8 facade and 216 raw channel send
  references (a textual indicator, not a measured coverage ratio). Inventory
  each call by wire semantics. Preserve handshake/control framing and migrate
  eligible application data routes incrementally; protocol-equivalence and
  fallback tests must distinguish deliberate raw boundaries from accidental
  bypass. Require resource bounds, idempotence, fairness and cancellation.
- Identity and trust: enrollment, scoped delegation, device revocation,
  tested recovery and migration, hardware-backed storage where supported,
  distinct browser/native guarantees. Versioned PQ identity migration requires
  independent cryptographic review and downgrade/interop tests.
- Groups and calls: complete membership transitions and key epochs, authenticated
  media, call reconnect, offline delivery semantics, multi-party admission and
  bandwidth control. Keep research codecs and onion primitives behind
  experimental capability gates; do not promote anonymity claims by analogy.
- Mobile: native or platform-supported clients sharing protocol fixtures and
  threat model, physical Android/iOS testing, lifecycle, permissions,
  background transfer, notifications, constrained battery/network budgets.
  Respect platform distribution restrictions and the sovereignty doctrine.
- First-run and accessibility: one obvious pairing flow, recovery without
  exposing secrets, actionable errors, verified presentation, keyboard,
  screen-reader and localization gates, honest connection and capability badges.

## Stage 2: sovereign network expansion (separate capabilities)

Reuse existing estate components only after inspecting exact versions, licenses,
authority boundaries and end-to-end contracts. Avoid moving research code into
the trusted computing base wholesale.

| System | Concrete deliverable and release gate |
|---|---|
| Personal device mesh | User-authorized enrollment and revocation, per-device keys, offline continuity, explicit replication policy; lost-device and revoked-device adversarial tests. |
| Distributed storage / ONE Memory | Content-addressed encrypted object store, manifest receipts, bounded replication/erasure policies, deterministic conflict semantics, recovery and GC. Measure bytes, latency and repair. Demonstrate restore from simulated and physical device loss, plus deletion/retention behavior. |
| Distributed execution | One Desktop Connection integration via least-privilege scoped capability grants, explicit job identity, resource/deadline limits, cancellation, durable results, owner-visible audit and fail-closed replay. No ambient remote shell authority; test denial, revocation and replay. |
| Verified execution | Interface to the Coherence covenant, existing exact-computation and proof systems. Bind inputs, program revision, outputs, environment, scope and evidence level. Re-execution is not hardware attestation. Independent verifier refuses malformed, replayed or overclaimed receipts. |
| Sovereign AI | Integrate ACE/ONE Mind through scoped, consented data and execution interfaces; local inference where supported, encrypted personal memory, clear tool approvals and no authority inheritance from untrusted content. Demonstrate separation, recovery, and measurable task value. |
| Physical / laboratory network | Read-only inventory and authenticated sensor streams first; isolated, explicit device-control grants, local physical interlocks, safe failure states, domain-specific hazard review. Never equate software simulation with hardware qualification. |
| Enterprise operation | Self-hosted discovery/relay, optional deployment management, policies, auditable access, backup/restore, integration API, operational SLOs, transparent pricing; no mandatory centralized account or covert telemetry. |

## Stage 3: independent evidence and commercialization

Use existing perf_lab, bench_gate, live_suite, formal models, and release
verification before writing replacements. Define a reproducible cross-product
benchmark harness: matched hardware/link conditions, pinned competitor and
candidate versions, equal payloads and security settings, randomized run order,
warm/cold cases, separate preparation and transfer timings, repeated seeds,
uncertainty, failure accounting, raw artifacts. Include no-internet LAN,
WAN/NAT/relay, loss/reorder/latency, disk-full, abrupt termination, restart,
sleep/wake, concurrent transfers and incompatible-version cases. Do not
cherry-pick workloads. Run real clean-device tests on all claimed platforms.

Use consented external pilots with clear usage tasks and privacy-preserving
measurement. Product design, commercial viability and user trust are separate
from source quality. Retain the open-source product promise, and assess paid
optional services (enterprise support, managed relays, backup, appliances)
only after real cost/benefit and legal/license review.

## Evidence checkpoint

The scoped file-engine audit executed against the baseline on Windows with
the compatible previously built native extension: 19/19 expected native
modules importable, 20/20 daemon methods present, 8/8 required diagnostic
blocks, 32 advertised capabilities, 6/6 scoped blocking gates passing.
This does not establish that every method executes successfully, that every
capability is qualified, or that Windows/macOS mount adapters exist.

All other claims remain tied to the dated source/release ledgers. The
isolated engineering branch must be rebased/reviewed after the current
release remediation merges. No new feature is enabled for the running user
profile by this document.

## First reliability increment

The accepted-held-offer path previously equated a pending accepted context
with a failed reply, even during async reply delivery or after partial data
had arrived. The new guard requires an explicitly failed reply, actual
transfer consent, and no stream or staged chunk progress before superseding a
different delivery. Partial ownership is preserved rather than erased.
Focused Windows qualification: 49 passed, zero skipped/failed; the new
two-daemon reconnect test passed before and after the correction. The six
targeted negative controls all failed against the exact baseline guard and
passed with the fix. The first live test attempt used an invalid disconnect
log-count assumption, which was corrected without weakening product assertions.
The live test exercises sender process shutdown, offline acceptance, rejection
of a changed presentation, then exactly one delivery of the original content
with a new delivery ID. It does not qualify a physical two-machine link,
parked-sidecar consent migration, or admission-failure consent retention.
Full hosted checks and independent review remain pending for this increment.
