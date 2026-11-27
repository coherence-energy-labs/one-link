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
