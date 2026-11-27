# Phase Zero: baseline integrity and release protection checkpoint

Date: 2026-11-26. Status: **in progress; not release qualified**.

This branch starts from remediation PR #88 at 4a0dffe6e9ed4a454448b627b4689edfb532f0c0 and carries the previously tested consent-safe reconnect increment as cherry-pick 9126e4a8e139920d2d29480f422eaef57b371286. Benchmark corrections were committed as c693d835afdd397ad3c41252f507985aff05c451. No production installation, default-branch merge, or public artifact replacement was performed.

## Measurement defects closed in the benchmark harness

- RSS is collected from the authenticated serving daemon, not a virtualenv launcher. The process must belong to the disposable daemon's spawned process tree, with matching profile and peer identity. PID creation time, instance identity and source fingerprint must agree before and after.
- The sampler uses constant-size aggregates instead of storing an unbounded list. Missing observations, sampler errors and changed identity cannot produce a successful memory verdict. Reported RSS is explicitly a sampled lower bound, not an OS high-water or whole-tree bound.
- Forced transport comparisons validate the accounting scope, unit, attempt/transfer windows, route labels, explicit fallback counters and per-route sums. Contradictory and missing evidence is inconclusive.
- Recovery experiments must kill the authenticated serving process, observe launcher and daemon exit, reject an already-completed transfer, and authenticate a new instance with the same peer identity.
- A missing or unrecognized scenario verdict is inconclusive, never implicitly successful.

These are harness changes, not a claimed application throughput improvement. The recovered consent guard is a product change from the earlier engineering branch and remains subject to full exact-revision qualification.

## Executed evidence

| Study | Passed | Skipped | Failures | Scope |
|---|---:|---:|---:|---|
| Combined candidate focused regressions, after RSS correction | 292 | 3 | 0 | Windows; ACK batching, shutdown, rotation, consent and benchmark contracts |
| Final benchmark-contract regressions | 187 | 2 | 0 | Windows; route, recovery and RSS measurement contracts |
| Pre-fix negative controls | 13 detected / 13 | 0 | 0 infrastructure errors | Expected assertion failures against the exact original benchmark code |

The two passing suites overlap; their counts must not be added as unique tests.
Python source imported from the isolated candidate. The native extension was reused from the already built 86f0020cbbbd571485e6ece5ad4c83b1757b1370 wheel; comparison of native/lock/build inputs found only native/ol_chunk/FILE_SCANNING.md changed. Loaded binary SHA256: 77e39d9edc9c8a7338f8d660895049df3e8dfcce40200c360c48b65a3abd4d0f. This is not an independent fresh build of the final candidate.

Skipped tests in the first suite: test_paired_runner_preserves_virtual_environment_python_symlink, test_actual_linux_high_water_reset_rejects_an_old_peak, test_a_stop_does_not_wait_for_bytes_a_client_will_never_read.
Skipped tests in the second suite: test_paired_runner_preserves_virtual_environment_python_symlink, test_actual_linux_high_water_reset_rejects_an_old_peak.

## Dependency alert reconciliation

Retrieved all 88 open default-branch Dependabot alerts: 7 critical, 43 high, 31 medium, 7 low. Compared each alert to the candidate's manifest and package versions. All 83 Python alert records fall outside the candidate lock's reported affected range using package-normalized PEP 440 range comparison. Four Rust alerts concern rustls and the candidate lock contains 0.23.46, their stated patched version. Rust semantics and final artifact inventories still require native advisory qualification. The fifth Rust alert is GLib 0.18.5 in the shell lock, inside the published affected range; the maintained upstream-source backport must remain independently validated through the existing vendor patch/advisory gates. This snapshot is not grounds to dismiss alerts, certify all dependencies, or skip packaged SBOM checks.

## Repository settings applied and verified

- Active version tag ruleset: 28202878; refs/tags/v* creation, update, deletion, and force-update restrictions; only the repository-admin role has the documented bypass.
- Release environment: required reviewer CoherenceEnergyLabs (the eligible account already requested for PR #88); prevent self review; administrator bypass disabled; only v* tag deployment policy.
- Existing master branch ruleset 20516627 was unchanged on read-back.
- A tag ruleset cannot alone prove that an administrator selects reviewed source, and a tagged workflow can omit environment declarations. The existing independent review and exact protected-master/release-workflow requirements still apply. No tag was created, no PR approval was submitted, no release was dispatched.

## Diagnostic campaign

The study declared a minimum of 1.5 GiB available RAM and 5 GiB free disk before each workload. All 16 stages were **not executed** because available RAM was below the declared floor; observed CPU load was high. No performance or recovery number is inferred from skipped stages. The earlier pre-fix negative controls did run. Do not lower the floor retroactively or present a later opportunistic run as the same study.

Planned stages: wiring, perf-quick, field-snapshot, receiver-memory, sender-memory, cold-unique, warm, related, many-small, mixed-tree, concurrent, sidecar, cache, share-link, route-control, resume.

Reproduce on an isolated, sufficiently provisioned host with matching native build and locked dependencies. Use the existing commands (see bench_baselines/README.md), retain full reports, all attempts and logs, and distinguish diagnostic, controlled, physical and independent evidence. Use private test profiles only. Start with the quick component and file-engine scenarios; then pre-register a controlled paired native study, multi-size physical LAN/WAN and recovery tests, resource/energy measurements, and long-duration soaks.

## Retained evidence digests

Raw logs and reports are retained in the private operator evidence directory; paths and machine data are intentionally not published here.

| Evidence file | SHA256 |
|---|---|
| phase-zero-focused.xml | 044880f21a944801d3370609fb0d696ebe59ac93cde2010b9c831abfd006b199 |
| benchmark-contracts-final.xml | 5bc228596d5aca8180cd7971d8c426d26772c689b14d8d7e135451e251488333 |
| pre-fix-negative-controls.xml | 551c93fb89d7e039201fd5e54ac33a8d249d8f6fe8dcc6c2ec3c4a49248040d7 |
| default-branch-open-dependabot-inventory.json | 037ac169c82cc1469bdabb48eab3f961233aeaf3e7cdf9d296a47412ff54f643 |
| candidate-lock-alert-reconciliation.json | c6b9c77231111891d11bea888d2bc8eef82fce59f2bfe7111758ccf0eaf9418c |
| repository-release-protections-20261126.json | a30a51d8733fcac8ae043e5d2e14fb6ce15004fd1bf0e90ffbdca5d6cf84fc70 |
| campaign.json | 668134aeba975202b36a805610e861e1fb2ba867d5fa8f71789efeccba4c8d33 |

## Still blocking completion

1. Full hosted correctness/security/browser/native checks and final packaging for the combined revision; the release PR has an independent review requirement. No approval bypass.
2. Live Windows and other-platform measurements of the corrected benchmark harness; actual controlled benchmark values and optimizations against the measured baseline.
3. Review remaining remediation findings (including parked-delivery consent, admission failure, ACK/rotation cases, controlled timing, intermittent hosted disk/startup variability and service boundaries) against exact new evidence.
4. Physical multi-host and mobile qualification, repeated fault/recovery studies, energy measurement, representative long-duration operation, competitive results, independent reproducibility and real user validation.
5. Protected merge, exact release builds, installer verification and public-download parity, clean-device install/update/rollback and safe owner-device rollout.

Phase Zero remains open. Do not advance the larger architecture on a fabricated or partially measured baseline.

## Diagnostic campaign follow-up (2026-11-26 local)

All 16 planned stages actually executed. 15 passed and one was inconclusive.
Source revision: c04496eec8313c93d08d857e04a4576d621249d5. Native revision: 86f0020cbbbd571485e6ece5ad4c83b1757b1370.
Native artifact SHA-256: 77e39d9edc9c8a7338f8d660895049df3e8dfcce40200c360c48b65a3abd4d0f. The native source-input difference was documentation only.
Same-host Windows diagnostic, not a controlled hardware or independent release qualification. CPU contention remained visible and source storage was OS-cache warm. No LAN/WAN, mobile, packet-capture, or competitive superiority claims follow.

| Stage | Exit | Evidence result | Report SHA-256 |
|---|---:|---|---|
| wiring | 0 | None | 7aab9898869f56755b2d7004a6a2f475930b8d28d94ec25b6209c929ffcfcbdf |
| perf-quick | 0 | None | 55272af7cf3767b208e94358e44c28547675d05c6ce9cdf846760fb88909e3fa |
| field-snapshot | 0 | None | 585fd56adc82a7e80824647262b53797a449f218086de41b869cbae8c7e617b3 |
| receiver-memory | 0 | passed | eeece616bb4d9b7842dd7c2f8455d11e04c513ba9d40e853e293339a226bb2e5 |
| sender-memory | 0 | passed | 82f97a5e494b6f554f7cb737847a1b1ed0d47fd6c91b7ed8e2ac549ed0e9777b |
| cold-unique | 0 | passed | 529826ed60c1735c5b98871bfe0cf9753e762eb054f093d819989754c3f02c68 |
| warm | 0 | passed | 9e62401836db42298bee18a946a87e1515512dc0a9d4ea4b5035b3e564a0a828 |
| related | 0 | passed | 40091955aa895148a89db1545efe5e965949194a0aafd64a4008bffb2a496173 |
| many-small | 0 | passed | 2257775ba43c83b02554608c73dd5245e355aa604a1f8abf867f618a1f4dceeb |
| mixed-tree | 0 | passed | 7d4fa414fa9013426ea3fbc36a1d1bf6dd6e06fff7bf75dfb53f3795e2eda0da |
| concurrent | 0 | passed | 20dac58ba0836d159c8f8413b857ac18da917575c96027ca4751475ef50efbf8 |
| sidecar | 0 | passed | a74c573f1bfcb717f2bd2c9cce9272b6042a4157d507aefb47a9e5bf30e9057a |
| cache | 0 | passed | a1b346878c4c55bb52d991df700c7dae6fbd91f3cbef7e715e561dc394f8ee14 |
| share-link | 0 | passed | 5333bbedb7323493bbc348cdf1083ea05f4b18f74390e7e73304b5908794702f |
| route-control | 2 | inconclusive | e78eea8357fe5b2b6a90b4fccbc0befb5d198668acdbadb6c44fff557eabcd6a |
| resume | 0 | passed | ab4c1f2b84ee3623fc438c8465ca7d38a5b75e9b7bbe6733adefbd42a8877910 |

Campaign manifest SHA-256: 083de62b2a7a8089f2e1281e7fc19bdcf3206a70aa058b63be31bc161893a522.

Selected measurements: 64 MiB sender/receiver RSS growth was 8,462,336 and 10,788,864 bytes, respectively (sampled serving-process RSS, not a guaranteed high-water bound). Cold random 16 MiB verified completion was approximately 0.669 s, one observation. Many-small and mixed-tree sends were 10/10 each, concurrent 4/4, and warm/related sends 2/2 each. The 16 MiB interruption/restart case completed with independently verified receiver content, fresh authenticated instance and abrupt serving-process termination observed; elapsed after restart was 16.975 s. The route comparison verified TCP and refused to qualify the unavailable QUIC arm. It did not pass overall. Coherence-field snapshot passed its absolute SLO checks.

## Consent and recovery follow-up

Source commits: 59beb1349f422e4913586978b878e4eb7bc5e31c and 78538b5987bdab9a4053fee1046d070090413b1c.

- Six reproduced consent/reaper races fixed: revoke locally before awaiting a decline response; prevent stale or duplicate acceptance from mutating newer state; guard reply correlation and partial ownership; bind reaping to the actual delivery and peer.
- Six parked-contract negative controls fixed for modern and legacy peers. A failed consent persistence no longer authorizes content requests or accept-all on that attempt. Exact private-sidecar name, size, destination and kind now participate in admission.
- Two authenticated cancellation negative controls fixed: modern parked records are removed rather than stranded by peer-resume matching, and malformed fingerprints are rejected. A separate positive failure-injection test requires an explicit error if persisted sidecar removal fails.
- Six archive fixture failures reproduced against the unchanged baseline on a low-headroom volume. Narrow test-only capacity snapshots isolate commit/publication tests; no production reserve weakened. A separate constrained-volume regression verifies refusal and preservation of the original archive.

| Test evidence | Tests | Failures | Errors | Skipped | SHA-256 |
|---|---:|---:|---:|---:|---|
| before.xml | 6 | 6 | 0 | 0 | c4ea401cde65d44f2477a9fd8d84948b6a26e3de6165a896df8ed22f6785fd4a |
| archive-baseline.xml | 6 | 6 | 0 | 0 | 0ffacd4bce5cce1901626c270a346a1031b1e5bfe9cf86c838a656eb57c0e93e |
| final-broad.xml | 163 | 0 | 0 | 1 | 212b4f59599124a7f222adfeee4c773e38c079624d04b37e12e221ef0e861eb0 |
| live-reconnect.xml | 1 | 0 | 0 | 0 | 372e381c6b9acbaa9fcfd623208da96511313423371efcacdcb7ba77dfa6aba2 |
| parked-before.xml | 7 | 7 | 0 | 0 | a6a682be1dfbf12c1e3d04ea3aba64aae449eb3ec9fa25a9a777bccc494842ab |
| parked-after.xml | 196 | 0 | 0 | 1 | 288209d7ae49b7a8de2bb198d19297477038f6747f3790dc72a8d82f67b1d49d |
| cancel-before.xml | 2 | 2 | 0 | 0 | 9414936b30617575ccf9c6941181bea4c2a7f1181b591b0a287c7bdb46fcd4b0 |
| recovery-final.xml | 230 | 0 | 0 | 1 | e6057027adc9aa2a1196180e310b17dfec109db75e1e6ae880919781fced0409 |
| cancel-final.xml | 3 | 0 | 0 | 0 | 1280550cc47a15ce8a90a826157d6ecb8ee8c9eea051fd464f1fa5866c4f6b42 |

The before/negative-control reports deliberately reproduce failures; overlapping positive suites are not added together. Ruff passed for changed files; mypy checked all 243 source files without issues. The real two-daemon reconnect test passed on 59beb13; full exact-revision hosted gates still required.

Remaining gaps: cross-delivery parked-consent supersession and grant retention after a new-delivery admission failure are not closed by the exact-contract guard. Durable cancellation across failed namespace operations, pre-existing active-cancel and finalization edge cases, full crash-point matrix, independent review, and physical/long-duration performance qualification remain distinct gates. This evidence does not supersede the original audit findings by assertion. The protected release and existing live installation remain unchanged.
