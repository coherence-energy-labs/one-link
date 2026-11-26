# One Link remediation report

**Audit date:** 24 November 2026  
**Evidence update:** 24 November 2026, 11:37 PM America/New_York  
**State:** Draft for review; final candidate and hosted acceptance remain open  
**Repository:** [coherence-energy-labs/one-link](https://github.com/coherence-energy-labs/one-link)  
**Draft pull request:** [#88](https://github.com/coherence-energy-labs/one-link/pull/88)  
**Original audited source:** `1279a450c74e0fdc745cf36e4a51d146d0b2f442`  
**Evidence cutoff source:** `7df40a371bdcb01e5d3f5f8764e87a5542120763`  
**Evidence cutoff time:** `2026-11-25T04:37:49.364140+00:00`

## Outcome and scope

Substantial remediation is implemented across runtime correctness, native scanning, performance measurement, dependency inventory, delivery controls and software structure. The work repairs concrete failures, adds checks that exercise the repaired behavior, and narrows claims to the execution evidence available. **It does not close every audit finding or establish a fully qualified production release.**

Later final-head CI results will be recorded in the pull request; this dated report does not automatically inherit them.

This report maps all 27 findings from the original audit to actual changes, commits, tests and remaining acceptance work. An independent review on 2026-11-25 added eleven findings of its own and changed several statuses; they are in the last section, and the table below counts all 38. Its companion [machine-readable ledger](remediation-2026-11-24.json) contains the complete file and test lists, full commit identities, evidence paths, local artifact hashes and qualifications. Evidence IDs in this report refer to that ledger. The report consolidates implementation and verification already performed; it is not a supplemental adversarial assessment.

The source revisions of individual runs matter. The broad local Linux execution used frozen source `3674060`; initial hosted execution used the tree of `dbb2f52`; the later Linux public bootstrap and completed Windows UI rerun used `d2de862`; full-checkout Python distribution validation used `f5fb842`. Subsequent browser, delivery and workflow changes require their own final acceptance. A passing focused selection on one revision is not substituted for a complete passing result on another.

### Status model

“Verified” is limited to the specific repaired defect and cited checks. It does not mean every platform, transport, artifact, security property or product claim is certified. “Partially remediated” identifies a remaining implementation or architecture gap; “qualification pending” identifies substantial implementation whose required execution evidence is incomplete.

| Status | Findings | Meaning |
| --- | ---: | --- |
| Partially remediated | 3 | A substantive portion is repaired, while a material implementation/architecture or production-integration gap remains. Do not mark closed. |
| Implemented; qualification pending | 10 | Implementation and focused verification exist, but a material acceptance step such as hosted, platform, artifact, realistic-workload or controlled-run qualification remains pending. |
| Prepared; not applied | 1 | A concrete change payload and validation exist, but the external control has not been applied or read back. Do not describe it as enforced. |
| Implemented and verified | 28 | The stated code/documentation defect has an implemented repair and relevant executed checks. This is bounded to cited evidence; it is not final CI, release, formal-security or all-platform certification. |

No overall maturity score is assigned from test counts, line reductions or the presence of advanced primitives. The judgment rests on operational behavior, exercised boundaries, credible measurements and accurately stated limitations.

## What changed and why it matters

### Recoverable startup and honest transfer completion

Fresh passphrase startup now creates its required recovery envelope inside the protected bootstrap phase, before the final convergence check. Existing-authority protections remain strict. Thirty focused bootstrap and recovery cases passed. Three separate fresh Windows passphrase startups then completed 16 MiB transfers over explicitly selected TCP, with receiver content hashes and application commit verification. These directly exercise the initialization-order repair and successful transfer completion. [E_BOOT, E_WIN_TRANSFER]

The transfer path now reports its actual payload route and durable receipt contract. A benchmark that requests a transport must verify that route in the result. Unsupported bulk QUIC or WebRTC comparisons return an explicit inconclusive outcome. The protocol catalogue also describes the durable completion and failure states used by the implementation. These changes prevent a successful connection, transport negotiation or submitted send from being presented as verified delivery. [E_RECEIPTS, E_ROUTES, E_PERF_CONTRACT]

### Native correctness, bounded intermediate storage and compatible acceleration

Declared-length native file scans reject both shrinkage and growth. ZIP and H264 scans use exact reads; fragmented readers, interrupted reads, premature EOF and I/O errors have focused coverage. Format-aware streaming coalesces record boundaries as it reads them and immediately scans accepted segments, avoiding accumulated vectors of every candidate record boundary. The public all-offset compatibility APIs still deliberately return results proportional to the number of records. [E_NATIVE_CHUNK, E_NATIVE_BINDING]

A synthetic dense-record comparison retained 18 observations across nine pairs with exact matching output digests. At four million virtual MCAP records, native Linux peak resident high-water measurements decreased from a median 32,832 KiB to 1,936 KiB, a 94.1% reduction. This demonstrates removal of that intermediate metadata accumulation. It does not establish constant total memory: returned chunks require space proportional to output, and realistic multi-gigabyte files and other platforms remain unqualified. [E_NATIVE_MEMORY]

The existing production Gear CDC path separately gained native C scanning through the already verified open descriptor. Its boundary semantics and descriptor/path mutation protections are preserved. This is distinct from the new Rust format-aware pathname API. The latter now has installed-binding tests, but an in-product consumer and corresponding end-to-end production evidence remain absent. Treating the two APIs as the same implementation would overstate BRANCH-03. [E_CDC, E_SERVICE_INTEGRATION, E_CDC_PREP]

### Performance evidence with explicit scope and uncertainty

Benchmarks now cover deterministic random, already-compressed, repetitive, related-file and mixed-tree corpora. They retain every delivery attempt, require independently verified receiver content and application completion for success, report the actual engine and route, and preserve raw observations and source/native identities. The native relative gate uses paired estimates with pass, fail and inconclusive outcomes. It no longer accepts a large median loss merely because uncertainty intervals overlap. [E_PERF_CONTRACT, E_PERF_HARNESS]

Five alternating pairs measured actual preparation of an 8 MiB file through the daemon. Exact chunks and hashes matched. The median paired preparation improvement was 112.4 times, with pooled medians of about 1.440 seconds and 0.013 seconds. This is a single-host, operating-system-cache-warm preparation result; it is not a network transfer speedup, device-wide improvement, sustained throughput or latency guarantee. [E_CDC_PREP]

A follow-up investigated a possible regression after extracting preparation services. Across five fresh-process pairs and 130 verified samples, steady medians were 8.324 ms and 8.416 ms, with a paired process-median ratio of 0.99683. First-call medians were 8.819 ms and 17.533 ms. The latter correlated with additional minor page faults despite identical read counts, bytes, identity probes and unchanged fixed-index logic. Instrumentation changed allocation history, so the evidence does not establish a responsible source line. Both the cold cost and steady observations remain recorded; no speculative warm-up was added. [E_FIXED_PREP]

The initial hosted paired gate then **failed as inconclusive** after five pairs. Its ten timed processes took 28 seconds in total; the 16 KiB QUIC batch lasted roughly 5.5–6.1 ms. Disk, WAL and QUIC intervals crossed the five-percent boundary. The 16 KiB QUIC result was slower in all five pairs, with median ratio 0.94758 and 95% interval 0.90089–0.99181. This observation cannot be dismissed as noise, nor does that small study isolate its cause. The candidate also updates QUIC, UDP, Tokio and Rustls dependencies. The original failed acceptance remains retained. [E_HOSTED_BENCH]

The follow-up profile is predeclared: exactly 20 balanced pairs, 31 measured storage and QUIC batches, three same-connection QUIC warmup batches, and at least 16 MiB of response payload per measured batch. It retains the existing five-percent general and twelve-percent named-crypto tolerances and the pass/fail/inconclusive rules. No result-dependent stopping or retries were added. A 236-case selection passed, and a real orchestration smoke retained 28 metrics and 203,516 timing observations. These validate measurement execution; the final comparative acceptance result remains separate. [E_NATIVE_SAMPLING, E_NATIVE_SAMPLING_SMOKE]

### Services and source structure with remaining ownership limits

Preparation and retry accounting now belong to `DescriptorFileSource`, `FilePreparationService` and `RemoteCommitGuard`, with typed cache, indexer, policy, ledger and durability dependencies. Offline courier behavior has separate filesystem, ledger and use-case services. These services can be tested without constructing the daemon or HTTP server, and they do not import the daemon's global namespace. The changes also repair courier temporary-file cleanup and exclusive-create rollback ownership. Existing send, receipt, public route and authentication behavior remains exercised through compatibility adapters. [E_RUNTIME, E_RUNTIME_UI, E_COURIER]

The first extraction removed 556 net lines from `daemon.py`; the courier extraction removed 654 net lines from `server.py`. The daemon and server still contain exceptionally large classes and broad orchestration responsibilities. Their size and remaining state coupling keep MNT-01 open. The architecture documents identify further boundaries and the courier service's current serialized execution model. [Transfer service design](../architecture/transfer_services.md); [courier service design](../architecture/courier_services.md).

Owner authoring now uses 106 source modules and six isolated service factories. Peer authoring uses 60 modules and four factories for encoding, state, public ICE configuration and bounded pairing progress. Deterministic offline assembly preserves standalone distribution artifacts; canonical sources reside outside the shipped asset directory. The largest owner and peer modules are 1,173 and 374 lines respectively. The peer comparison preserved all 311 original named function bodies. Feature modules still share legacy page closures, so source organization and the new isolated factories improve maintainability without completing state separation. [E_OWNER, E_PEER, E_DIST_FINAL]

## Verification record

The following are separate scoped executions. **They must not be added into one total**, because several select the same tests or run earlier source revisions. Skips, missing execution, environmental blocks and inconclusive measurements remain visible.

| Execution and source scope | Observed outcome | Qualification |
| --- | --- | --- |
| Frozen local Linux selection, `3674060` | 9,621 passed; 42 skipped; 24 failed across all 9,687 selected cases | First run stopped at 20 failures; a continuation ran only previously unexecuted cases. No failed case was retried. This snapshot remains failed. E_LINUX_FULL. |
| Initial hosted Linux acceptance, tree of `dbb2f52` | 9,683 passed; 47 skipped; 5 failed; 152 live cases deselected; 371.38 s | Failures concern later-corrected controlled-lab wording, landing text and workflow-count contracts. Final-head acceptance is pending. E_HOSTED_INITIAL. |
| Initial hosted Windows acceptance, same tree | 9,696 passed; 32 skipped; 7 failed; 152 live cases deselected; 1,392.57 s | Five stale documentation/contracts and two UTF-8/newline test portability issues. Original failures are retained; later corrections do not rewrite this outcome. E_HOSTED_WINDOWS_FULL_INITIAL. |
| Initial hosted Linux live lane, same tree | All 152 cases passed; no skips or failures; shards of 42, 47, 42 and 21 | Actual execution of the 139 declared live functions after parametrization. E_HOSTED_INITIAL. |
| Initial hosted Windows live and browser lanes, same tree | All 152 live cases passed without skips or retries; Chromium 63 passed; Firefox 3 passed | Exact shard and browser artifact links are retained in E_HOSTED_WINDOWS_INITIAL. Windows full acceptance and final candidate outcomes remain separate. |
| Initial hosted Linux browsers, same tree | Chromium 63 passed; Firefox 3 passed | Source-level hosted browser execution; final extracted-UI candidate remains separate. E_HOSTED_INITIAL. |
| Integrated native Linux release library tests | 1,427 passed; 0 failed; 1 ignored across 44 crate summaries | Ignored KITTI measurement requires its external corpus. This does not represent every feature, target or timing diagnostic. E_NATIVE_WORKSPACE. |
| Native chunk and installed binding selections | 75 Rust cases; 107 installed-wheel cases passed | The same 107 binding cases also passed inside the frozen Linux selection; they are not additional to that selection. Strict Clippy passed. E_NATIVE_CHUNK, E_NATIVE_BINDING. |
| Runtime, UI and courier selections | 243 runtime passes; 86 UI/queue passes; 168 courier passes with 35 skips | Includes focused service contracts. Courier skips include gated live and Windows-only cases. E_RUNTIME, E_RUNTIME_UI, E_COURIER. |
| Bootstrap, transfer and protocol selections | 30 bootstrap passes; 285 transfer passes with 5 skips; 86 receipt/protocol passes | Separate selections with overlap; no combined total. E_BOOT, E_TRANSFER, E_RECEIPTS. |
| Delivery and follow-up contracts | 192 delivery cases; 60 public-bootstrap CI cases; 145 shell/SBOM follow-up cases passed | Includes negative and incomplete-result contracts, not a performed release publication. E_DELIVERY, E_BOOTSTRAP_CI, E_SHELL_TESTS. |
| Performance contracts and harness | 81 cases passed; 28 native metrics with 203,244 observations per arm | The native harness smoke used the same binary in both arms and establishes no speedup. E_PERF_CONTRACT, E_PERF_HARNESS. |
| Windows exact Firefox identity case | One case passed in 70.21 s | Source `0731ae5`; explicit required identity, owner request and immediate revoke. E_WIN_FIREFOX_EXACT. |
| Windows integrated browser attempt, `dcf9e5c` | Firefox 3 passed in 81.58 s; Chromium 62 passed and 1 timed out in 761.99 s | The original Chromium five-second HTTP timeout remains retained; a readiness correction and later rerun are separate. E_WIN_BROWSERS. |
| Windows browser run after both UI extractions, `d2de862` | Chromium 63 passed; Firefox 3 passed; zero failures or skips | Process elapsed times were 638.375 s and 70.0 s respectively. The source remained unchanged, and the HTTP readiness correction was included. E_WIN_BROWSERS_D2DE862. |
| Windows fresh passphrase transfers, `dcf9e5c` | All three fresh startups and 16 MiB forced TCP transfers verified | Receiver hash and commit checked. The 0.774, 0.906 and 1.524 s durations were concurrent with browser work and are correctness observations. E_WIN_TRANSFER. |
| Exact public bootstrap | Linux at `d2de862`: 56.102 s; Windows at `dbb2f52`: 48.281 s | Each records 944 hashed inputs, matching 0.22.1 versions and a passed KEM self-test. E_LINUX_BOOTSTRAP, E_WIN_BOOTSTRAP. |
| Full-checkout Python wheel and source distribution, `f5fb842` | Independent clean-install, exact payload, RECORD and source-distribution-derived wheel validation passed | 232 Python files; 255 payload files; 215 stable modules; 23 assets. This does not establish byte reproducibility or whole standalone-release qualification. E_PYTHON_DIST_REVIEW. |
| Clean-snapshot static analysis, `b7a3ca2` | Ruff passed; mypy with Windows platform passed all 232 source files | Later source changes require exact-candidate gates. E_STATIC. |
| Windows portability, `8bbb9c8` then `9a8475a` | First selection: 176 Python passes and two illegal-path fixture failures; all six Rust golden-vector cases passed. Corrected scope selection: all 70 passed in 84.10 s. | Real Windows filenames use legal names; separate injected NUL-delimited diff cases retain embedded-newline decoding coverage. No implementation or golden output was weakened. E_WIN_PORTABILITY_ATTEMPT, E_WIN_SCOPE_PORTABILITY. |
| Verified GLib source backport, integrated as `314e797` | 181 focused contracts; 11 original upstream iterator tests; five ongoing regression tests passed at optimization level 3. Live ancestor-advisory check and strict SBOM validation passed. | Tests used actual GLib/GObject/GIO 2.84.4 runtimes. The local host lacks GTK/WebKit development SDKs; full shell/window qualification remains hosted. E_GLIB_BACKPORT. |

The frozen Linux failures classify as seven host `getifaddrs` restrictions, three QR fixture or cache behavior deltas, nine packaging or module inventory deltas, one historical benchmark wording contract and four stale landing or workflow contracts. Subsequent fixes are represented by their commits and focused checks; the failed original result has not been rewritten. Counting unique selected IDs is necessary: five collection-level skips also appear in the first XML but are not additional selected cases. [E_LINUX_FULL]

Distribution corrections likewise preserve their earlier 201-pass/eight-failure and 219-pass/one-failure attempts. The final exact source and asset selection passed 12 cases. Canonical browser authoring files now remain outside shipped runtime assets, while extracted Python services are included in source fingerprints and distribution manifests. [E_DIST_PRIOR, E_DIST_V2, E_DIST_FINAL]

The later full-checkout build at `f5fb842` produced an actual application wheel and source distribution. Independent validation passed direct clean installation, source-distribution-derived wheel installation, exact payload checks and RECORD integrity. It verified 232 Python files, 255 payload files, 215 stable runtime modules and 23 assets. Artifact hashes are retained in the ledger. This establishes the Python distribution contract; byte reproducibility, native artifacts, standalone application packaging and release signing remain separate. [E_PYTHON_DIST_REVIEW]

The initial hosted merge revision `2927a0f57d1eee6e0f1ddfd4acbdbeb8219f17d2` and branch revision `dbb2f5221ffcc70d09a42b69aed03976b3b266e4` have the same verified Git tree, `39163ef7c1b99cbf502f5f63141a3625087eab18`. This connects that hosted result to the stated source tree without implying acceptance of later changes. [Hosted run](https://github.com/coherence-energy-labs/one-link/actions/runs/45538106208); [retained acceptance artifact](https://github.com/coherence-energy-labs/one-link/actions/runs/45538106208/artifacts/14988128402).

### Native artifact identities

| Observation | Version and executed check | Native binary SHA256 |
| --- | --- | --- |
| Linux public bootstrap at `d2de862` | Source, module and distribution 0.22.1; KEM self-test passed | `cc00549c0d0de6603df8e8827c360691e6348443f55996b465d3d750732ba1be` |
| Windows public bootstrap at `dbb2f52` | Source, module and distribution 0.22.1; KEM self-test passed; 6,274,560 bytes | `030b5743bd9f8550382b40b7b6379ea2d7ad59ce9dbf4a80521e9b4d54702ac2` |

The first Windows bootstrap attempt was blocked by the installed uv 0.11.23. That attempt remains retained; the later successful command used isolated uv 0.13.10. Platform binaries are expected to differ. Identity records qualify their specific executions and do not substitute for testing every intended released artifact. [E_WIN_BOOTSTRAP, E_LINUX_BOOTSTRAP]

## Finding-by-finding disposition

Each entry states its repair, representative source and tests, and the work still needed. The JSON ledger retains the full lists, original acceptance language and evidence hashes.

### Release and supply chain

#### RLS-01 — Current dependency checks fail against the committed locks

**Implemented; qualification pending · Original priority: High.** Updated Python declarations and universal lock, all three Cargo lockfiles, the P256 API and fixture, and locked container inputs. Complete source graph inventories and independent audit reports are retained. The remaining GLib iterator issue now has the official two-line source fix backported to the exact original 0.18.5 package, with unchanged version and license, complete provenance verification and continuing upstream advisory checks. Commits include d6df3d3, d90aa78, 48990e4, d2de862 and 314e797; full identities are in the ledger.

Source: [pyproject.toml](../../pyproject.toml), [uv.lock](../../uv.lock), [native/Cargo.toml](../../native/Cargo.toml). Representative tests: [tests/test_delivery_evidence.py](../../tests/test_delivery_evidence.py), [tests/test_container_appimage_supply_chain.py](../../tests/test_container_appimage_supply_chain.py).

Python, rendezvous, npm, workspace and fuzz scans have no reported vulnerabilities in the retained checks. Before the backport, 87 of 88 observed default-branch alerts were outside the candidate's affected ranges; the remaining GLib issue was still affected. The backport now verifies all 121 original files and the exact two-line upstream diff, and the live OSV gate retains the two exact identifiers for that issue while rejecting any new affected advisory or incomplete query. Optimized regression, failure-path and source-provenance checks passed. The source-union SBOM contains 957 components and 958 dependency records. Evidence: E_DEP_PY, E_DEP_RUST, E_DEP_SHELL, E_DEP_NPM, E_CONTAINER, E_SBOM, E_DEP_ALERTS, E_GLIB_BACKPORT.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: pip-audit + bandit + sbom; RustSec cargo-audit; Gitleaks full-history scan passed.

**Remaining qualification:** No release artifact was built from this branch, so the dependency inventory of the intended release artifacts is not verified. The glib and ml-kem fixes are project-maintained backports; the registry versions stay in the advisories' affected ranges and the ancestor checks must keep running. RUSTSEC-2024-0370 (proc-macro-error, unmaintained) remains, exempted by exact id.

#### RLS-02 — Release publication does not wait for reproducibility verification

**Implemented; qualification pending · Original priority: High.** Signing/publication now depend on same-release native-wheel reproducibility verification; comparison checks complete bytes and retains member-level mismatch evidence. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e).

Source: [.github/workflows/release.yml](../../.github/workflows/release.yml), [.github/workflows/reproducible_release.yml](../../.github/workflows/reproducible_release.yml), [scripts/verify_reproducible_wheels.py](../../scripts/verify_reproducible_wheels.py). Representative tests: [tests/test_delivery_evidence.py::test_release_signing_and_publication_require_the_actual_artifact_rebuild](../../tests/test_delivery_evidence.py), [tests/test_delivery_evidence.py::test_rebuild_failure_cli_still_writes_machine_readable_evidence](../../tests/test_delivery_evidence.py).

Local negative comparison, artifact-identity and workflow ancestry contracts passed. Evidence: E_DELIVERY, E_RELEASE_LEDGER.

**Update 2026-11-25 (independent review):** Workflow contract tests only; the release workflow was not executed.

**Remaining qualification:** No release was cut: the two-builder comparison and the refusal to publish on a mismatch have not been observed on a real candidate. Windows and macOS wheels, the standalone archives and the SBOM have no independent rebuild.

#### RLS-03 — The observed ruleset does not require approving review or named status checks

**Partially remediated · Original priority: Medium.** Prepared a strict desired ruleset with ten named producer-bound checks, one approving review, no bypass actors and preserved existing controls. Native correctness, performance and shell contexts are included; the external policy remains unapplied. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [876857f](https://github.com/coherence-energy-labs/one-link/commit/876857fbc389c2d486f8f99a4ad4ec33be13de9d), [d6594c8](https://github.com/coherence-energy-labs/one-link/commit/d6594c8d59aec0ba44277e0c9ca074f89a8cb030).

Source: [.github/repository-policy.json](../../.github/repository-policy.json), [scripts/repository_policy.py](../../scripts/repository_policy.py), [docs/REPOSITORY_POLICY.md](../../docs/REPOSITORY_POLICY.md). Representative tests: [tests/test_delivery_evidence.py::test_ruleset_proposal_preserves_existing_controls_and_requires_real_producer](../../tests/test_delivery_evidence.py), [tests/test_delivery_evidence.py::test_required_contexts_are_defined_by_unfiltered_pr_workflows](../../tests/test_delivery_evidence.py).

Proposal, source applicability and required-context contracts passed in the integrated 213-case selection. The shell follow-up passed 218 cases and requires its complete three-OS matrix whenever applicable. A fresh authenticated read confirms the original external policy still requires zero approvals and no named checks. No remote policy mutation has been applied at this snapshot. Evidence: E_POLICY, E_POLICY_DESIRED, E_DELIVERY, E_GATE_INTEGRATION, E_NATIVE_SHELL_GATE, E_POLICY_BEFORE_FINAL.

**Update 2026-11-25 (independent review):** The default-branch ruleset is active and was read back: one approving review and ten required status checks, no bypass actors.

**Remaining qualification:** No tag ruleset exists and the 'release' environment does not exist; both payloads are prepared in docs/RELEASE_PROTECTION.md and neither is applied (see REV-S1). One approving review is required and there are no bypass actors, so this pull request needs an approver other than its author.

#### RLS-04 — A failed Python dependency gate prevents later analysis and report upload

**Implemented and verified · Original priority: Medium.** Independent advisory/SAST/SBOM steps continue after a prior analyzer failure when tool setup succeeded; evidence upload is unconditional and enforcing commands still fail the job. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [27cc28b](https://github.com/coherence-energy-labs/one-link/commit/27cc28be750027a8663893b5dacd5616188bf435).

Source: [.github/workflows/security.yml](../../.github/workflows/security.yml), [.gitleaksignore](../../.gitleaksignore). Representative tests: [tests/test_delivery_evidence.py::test_independent_supply_chain_steps_and_evidence_survive_a_prior_failure](../../tests/test_delivery_evidence.py).

Workflow evidence-retention contracts passed. Full-history Gitleaks revalidation at d2de862 passed with zero findings using the one reviewed exact historical fingerprint exception, without changing source or environment. The original failed scan remains retained. Evidence: E_DELIVERY, E_SHELL_TESTS, E_HOSTED_SECRET_SCAN, E_SECRET_REVALIDATION.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: pip-audit + bandit + sbom; RustSec cargo-audit; Gitleaks full-history scan passed. Reports are uploaded whether or not a scanner fails.

**Remaining qualification:** Two historical type-only and comment fingerprints stay documented; neither is a detector-wide or path-wide suppression.

#### RLS-05 — A green native workflow includes an incomplete optional strict test pass

**Implemented; qualification pending · Original priority: Medium.** Separated required native correctness from explicit controlled timing diagnostics on a dedicated runner; timeout/failure/incomplete outcomes and raw logs are retained. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e).

Source: [.github/workflows/native_build.yml](../../.github/workflows/native_build.yml), [.github/workflows/native_timing.yml](../../.github/workflows/native_timing.yml), [scripts/run_native_timing.py](../../scripts/run_native_timing.py). Representative tests: [tests/test_delivery_evidence.py::test_controlled_timing_is_separate_from_required_correctness](../../tests/test_delivery_evidence.py), [tests/test_delivery_evidence.py::test_timing_attempts_retain_success_failure_and_timeout_logs](../../tests/test_delivery_evidence.py).

The native correctness library run recorded 1,427 passes and one explicit corpus-dependent ignore. Timing success, failure and timeout result-state contracts passed. Evidence: E_DELIVERY, E_NATIVE_WORKSPACE.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: constant-time dataflow audit (valgrind) passed. 27 cases, including three negative controls. Statistical timing: 20 of 20 constant-time targets pass on Linux and on Windows with both leak controls detected.

**Remaining qualification:** The dedicated timing runner is not provisioned, so the controlled-machine run the acceptance names has not happened. It is one manual dispatch of native_timing.yml on a runner labelled one-link-timing. Memcheck does not model variable-latency instructions, and the statistical runs were made on a loaded shared workstation. Neither is a proof of constant-time execution.

#### RLS-06 — The documented source quickstart omits the required secure-channel native backend

**Implemented and verified · Original priority: Medium.** One documented bootstrap command resolves frozen dependencies, builds/installs matching native code and verifies version/binary/KEM ABI before supported source use; CI invokes that public path. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [93a5d0d](https://github.com/coherence-energy-labs/one-link/commit/93a5d0d6e2c98d34760c01e6548232f0a9663fb1).

Source: [scripts/bootstrap_source.py](../../scripts/bootstrap_source.py), [scripts/verify_native_runtime.py](../../scripts/verify_native_runtime.py), [README.md](../../README.md). Representative tests: [tests/test_delivery_evidence.py::test_native_runtime_checks_versions_binary_and_executed_abi](../../tests/test_delivery_evidence.py), [tests/test_delivery_evidence.py::test_bootstrap_source_identity_detects_edits_to_already_dirty_inputs](../../tests/test_delivery_evidence.py).

Fresh public bootstrap commands passed on Linux at d2de862 and Windows at dbb2f52, with matching 0.22.1 versions, recorded native hashes and executed KEM self-tests. Sixty bootstrap and CI contract cases also passed. Independently validated full-checkout Python wheel and source-distribution builds at f5fb842 passed clean installations and exact payload checks; native backend qualification remains separately recorded. Evidence: E_BOOTSTRAP_SOURCE, E_BOOTSTRAP_CI, E_LINUX_BOOTSTRAP, E_WIN_BOOTSTRAP, E_HOSTED_INITIAL, E_PYTHON_DIST_REVIEW.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: build acceptance native runtime / ubuntu-latest; build acceptance native runtime / windows-latest; full pytest suite / ubuntu-latest / py3.12; full pytest suite / windows-latest / py3.12 passed. Each job builds the native wheel from this source, installs exactly that wheel and verifies its identity before the suite runs.

**Remaining qualification:** Packaged-device qualification is separate from a source bootstrap. macOS runs the native workspace tests and the picker smoke, not the full Python suite.

#### RLS-07 — The release-status narrative is stale

**Implemented and verified · Original priority: Low.** Replaced stale release posture with a dated evidence ledger, explicit observed-versus-verified distinctions and historical test-count labels. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [aa37b9d](https://github.com/coherence-energy-labs/one-link/commit/aa37b9dd7f8f226c0129e438538022094f7a3dc5), [d2de862](https://github.com/coherence-energy-labs/one-link/commit/d2de862013f157e5a61ef5b32a07120f547b439e).

Source: [docs/RELEASE_EVIDENCE.json](../../docs/RELEASE_EVIDENCE.json), [docs/RELEASE_CHECKLIST.md](../../docs/RELEASE_CHECKLIST.md), [docs/LAUNCH_CHECKLIST.md](../../docs/LAUNCH_CHECKLIST.md). Representative tests: [tests/test_release_documentation_truth.py](../../tests/test_release_documentation_truth.py), [tests/test_delivery_evidence.py](../../tests/test_delivery_evidence.py).

Documentation truth contracts passed. Historical v0.21.0 publication and its independent reproducibility failure remain visible. Evidence: E_RELEASE_LEDGER, E_DELIVERY.

**Remaining qualification:** Finalize this remediation ledger with exact candidate SHA and hosted outcomes. Downloaded final release bytes/signatures/attestations and fresh-device verification remain incomplete.

#### RLS-08 — The installed Windows native package identity differs from the checked-out source version

**Implemented; qualification pending · Original priority: Medium.** Added source, native module and distribution compatibility checks, executed KEM ABI testing and binary hash records. Isolated matching 0.22.1 environments replace reliance on the older installed Windows package. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [93a5d0d](https://github.com/coherence-energy-labs/one-link/commit/93a5d0d6e2c98d34760c01e6548232f0a9663fb1).

Source: [scripts/verify_native_runtime.py](../../scripts/verify_native_runtime.py), [scripts/bootstrap_source.py](../../scripts/bootstrap_source.py), [.github/workflows/full_suite_and_e2e.yml](../../.github/workflows/full_suite_and_e2e.yml). Representative tests: [tests/test_delivery_evidence.py::test_native_runtime_checks_versions_binary_and_executed_abi](../../tests/test_delivery_evidence.py), [tests/test_native_format_aware_file.py](../../tests/test_native_format_aware_file.py).

Linux and Windows public bootstrap executions have matching versions and explicit binary hashes. The 107 installed file-binding cases also passed on the fresh integrated Linux binary. The subsequent Windows browser execution at d2de862 passed all 63 Chromium and three Firefox cases. Evidence: E_NATIVE_RUNTIME, E_LINUX_BOOTSTRAP, E_WIN_BOOTSTRAP, E_LINUX_FULL, E_WIN_BROWSERS, E_WIN_BROWSERS_D2DE862.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: build acceptance native runtime / ubuntu-latest; build acceptance native runtime / windows-latest; full pytest suite / ubuntu-latest / py3.12; full pytest suite / windows-latest / py3.12; e2e (playwright) / ubuntu-latest; e2e (playwright) / windows-latest passed. The binding and browser suites run against the wheel built in the same run, after scripts/verify_native_runtime.py accepts it. 6 of 8 live shards passed against it.

**Remaining qualification:** Linux and Windows only; released artifacts on other devices are not covered by a source run. Not every live shard passed on this revision (see MNT-02); the live half of the acceptance is therefore not complete.

### Observed runtime failures

#### RUN-01 — Firefox required-identity browser-to-daemon pairing did not complete in the live test

**Implemented and verified · Original priority: Medium.** Bounded pairing lifecycle stages and diagnostics; retained exact required-identity flow; added authenticated HTTP fixture readiness after a separate Chromium read timeout. Commits: [0731ae5](https://github.com/coherence-energy-labs/one-link/commit/0731ae5c9ba39460769dfd6c6ef63ce7a157a3a4), [dcf9e5c](https://github.com/coherence-energy-labs/one-link/commit/dcf9e5c74d7e1a552c7a3362b122eb02d2b237b8), [dbb2f52](https://github.com/coherence-energy-labs/one-link/commit/dbb2f5221ffcc70d09a42b69aed03976b3b266e4).

Source: [src/one_link/web/peer.html](../../src/one_link/web/peer.html), [tests/e2e/test_browser_identity_possession_live.py](../../tests/e2e/test_browser_identity_possession_live.py), [tests/e2e/conftest.py](../../tests/e2e/conftest.py). Representative tests: [tests/e2e/test_browser_identity_possession_live.py::test_required_mode_live_pair_owner_request_and_immediate_revoke](../../tests/e2e/test_browser_identity_possession_live.py), [tests/test_peer_pairing_progress.py](../../tests/test_peer_pairing_progress.py).

The exact local Windows Firefox case passed in 70.21 seconds and its integrated three-case selection passed in 81.58 seconds. Initial hosted Linux and Windows each passed 63 Chromium and three Firefox cases at the tree of dbb2f52. The older local Chromium timeout remains retained. The later Windows d2de862 run also passed all 63 Chromium and three Firefox cases, with zero skips, after both browser source extractions and the HTTP readiness correction. Evidence: E_BROWSER_FOCUSED, E_WIN_FIREFOX_EXACT, E_WIN_BROWSERS, E_HOSTED_INITIAL, E_HOSTED_WINDOWS_INITIAL, E_WIN_BROWSERS_D2DE862.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: e2e (playwright) / ubuntu-latest; e2e (playwright) / windows-latest passed. The Firefox lane runs the gate's own contract and the three pairing cases. On a loaded Windows workstation (median 86% CPU): 19 of 20 consecutive Firefox lane runs passed with no navigation stall; the one failure was the page defect fixed in 95403be. Without the change the same pairing case failed 4 of 10 runs.

**Remaining qualification:** Released artifacts, other browsers and networks, and long-duration runs remain separate. macOS Firefox was not checked for the cache setting (Linux and Windows were).

#### RUN-02 — Fresh passphrase-mode startup checks for a recovery envelope before creating it

**Implemented and verified · Original priority: High.** Creates the required recoverable passphrase envelope within protected fresh bootstrap before convergence verification; existing-authority checks remain strict. Commits: [2f57b98](https://github.com/coherence-energy-labs/one-link/commit/2f57b9800a388afa59dab7a84ff0aed3e74637fc).

Source: [src/one_link/master_seed.py](../../src/one_link/master_seed.py), [src/one_link/lockbox.py](../../src/one_link/lockbox.py), [tests/test_passphrase_bootstrap.py](../../tests/test_passphrase_bootstrap.py). Representative tests: [tests/test_passphrase_bootstrap.py](../../tests/test_passphrase_bootstrap.py), [tests/test_recovery_authority_transaction.py](../../tests/test_recovery_authority_transaction.py).

Thirty focused bootstrap and recovery cases passed. Three fresh Windows passphrase startup attempts each completed a verified 16 MiB forced TCP transfer. Evidence: E_BOOT, E_WIN_TRANSFER, E_LINUX_TRANSFER_BLOCK.

**Remaining qualification:** Linux live discovery is environment-blocked by EPERM; it is not a pass or a passphrase regression. Final packaged-install/platform/long-duration qualification remains separate from this verified initialization-order fix.

### Performance validity

#### PERF-01 — File-engine benchmark corpus is highly compressible and repetitive

**Implemented and verified · Original priority: High.** Added deterministic random, already-compressed, repetitive, controlled-related and mixed-tree corpora; preserved logical/skipped/framed payload accounting and declared scope. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed).

Source: [src/one_link/benchmark_contract.py](../../src/one_link/benchmark_contract.py), [scripts/bench_file_engine.py](../../scripts/bench_file_engine.py), [docs/FILE_ENGINE_BENCHMARKS.md](../../docs/FILE_ENGINE_BENCHMARKS.md). Representative tests: [tests/test_benchmark_measurement_contract.py::test_default_corpus_does_not_repeat_blocks_or_collapse_under_compression](../../tests/test_benchmark_measurement_contract.py), [tests/test_benchmark_measurement_contract.py::test_related_corpus_preserves_all_bytes_except_the_declared_edit](../../tests/test_benchmark_measurement_contract.py).

Corpus and completion contracts passed; historical repetitive-corpus tables explicitly remain unqualified historical observations. Evidence: E_PERF_CONTRACT, E_WIN_TRANSFER.

**Remaining qualification:** Run a controlled representative corpus matrix on target storage/network/hardware before publishing general transfer rates.

#### PERF-02 — QUIC-versus-WebRTC scenario does not isolate the two transports

**Implemented and verified · Original priority: High.** Explicit requested transport must match actual payload-route receipts; unsupported QUIC/WebRTC bulk paths return inconclusive instead of a fabricated speedup. TCP is correctly identified. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed), [0731ae5](https://github.com/coherence-energy-labs/one-link/commit/0731ae5c9ba39460769dfd6c6ef63ce7a157a3a4), [084ed38](https://github.com/coherence-energy-labs/one-link/commit/084ed38a1f95e8cf6219e2153b3eb2a7ee61528c), [ee9e51e](https://github.com/coherence-energy-labs/one-link/commit/ee9e51e01ad7d74df594ffa186d1f25ebdc81e77).

Source: [src/one_link/transfer_routes.py](../../src/one_link/transfer_routes.py), [src/one_link/daemon.py](../../src/one_link/daemon.py), [src/one_link/benchmark_contract.py](../../src/one_link/benchmark_contract.py). Representative tests: [tests/test_transfer_routes.py](../../tests/test_transfer_routes.py), [tests/test_benchmark_measurement_contract.py::test_transport_comparison_alternates_without_publishing_partial_speedup](../../tests/test_benchmark_measurement_contract.py).

Forced route, payload accounting and completion contracts passed. Three live transfers explicitly used TCP and verified receiver content and application commit. Evidence: E_ROUTES, E_PERF_CONTRACT, E_WIN_TRANSFER.

**Remaining qualification:** An actual isolated end-to-end QUIC-versus-WebRTC file comparison remains unavailable/unqualified. Payload/framing counters are not link-layer packet captures or complete network overhead measurements.

#### PERF-03 — Cold-transfer benchmark silently drops missing deliveries

**Implemented and verified · Original priority: High.** Every attempted delivery gets a result row; success requires fresh receiver bytes/hash and application completion; missing/failed attempts prevent a successful-only headline or zero-status CLI result. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed).

Source: [scripts/bench_file_engine.py](../../scripts/bench_file_engine.py), [src/one_link/benchmark_contract.py](../../src/one_link/benchmark_contract.py). Representative tests: [tests/test_benchmark_measurement_contract.py::test_audit_missing_delivery_fixture_keeps_both_failed_attempts](../../tests/test_benchmark_measurement_contract.py), [tests/test_benchmark_measurement_contract.py::test_cli_returns_nonzero_and_writes_empty_scenario_failure](../../tests/test_benchmark_measurement_contract.py).

Original missing-delivery reproduction now retains both failures; observed blocked live attempts are retained as failed rows. Evidence: E_PERF_CONTRACT, E_LINUX_TRANSFER_BLOCK.

**Remaining qualification:** Completion rates and successful latency must remain separate in future product reports.

#### PERF-04 — Primitive benchmarks bypass meaningful current daemon costs

**Implemented and verified · Original priority: High.** Benchmarks exercise actual Daemon.prepare_file_for_transfer and report actual engine/stage scope; descriptor-safe native Gear CDC removes the Python byte loop without changing boundary semantics. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed), [74ae074](https://github.com/coherence-energy-labs/one-link/commit/74ae0742ca433118f4c0d4c52bcc731e569ca898), [ee9e51e](https://github.com/coherence-energy-labs/one-link/commit/ee9e51e01ad7d74df594ffa186d1f25ebdc81e77), [5344ee9](https://github.com/coherence-energy-labs/one-link/commit/5344ee9387c2f6da87b4064f01c2d17c56cfeaa9).

Source: [src/one_link/perf_lab.py](../../src/one_link/perf_lab.py), [src/one_link/perf_lab_native.py](../../src/one_link/perf_lab_native.py), [src/one_link/cdc.py](../../src/one_link/cdc.py). Representative tests: [tests/test_cdc_descriptor_native.py](../../tests/test_cdc_descriptor_native.py), [tests/test_benchmark_measurement_contract.py](../../tests/test_benchmark_measurement_contract.py).

Five paired 8 MiB production preparation observations showed a median paired improvement of 112.4 times with exact hashes and boundaries. The fixed 16 MiB follow-up retained 130 verified samples, including its higher first-call page-fault cost. Evidence: E_CDC_PREP, E_FIXED_PREP, E_CDC, E_SERVICE_INTEGRATION.

**Remaining qualification:** These are preparation measurements, not full-transfer speedups. Cold first-call allocation sensitivity remains recorded; no speculative warm-up or redundant-read fix was justified.

#### PERF-05 — Overlap rule can pass a large median throughput loss

**Implemented and verified · Original priority: Medium.** Replaced permissive overlap acceptance with paired median/bootstrap uncertainty and pass/fail/inconclusive outcomes; matched runs alternate and retain raw samples. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed).

Source: [scripts/bench_gate.py](../../scripts/bench_gate.py), [scripts/bench_paired_native.py](../../scripts/bench_paired_native.py), [bench_baselines/README.md](../../bench_baselines/README.md). Representative tests: [tests/test_bench_gate_compares_like_for_like.py](../../tests/test_bench_gate_compares_like_for_like.py), [tests/test_benchmark_measurement_contract.py](../../tests/test_benchmark_measurement_contract.py).

Contract tests reject the former large-median-regression pass and incompatible comparisons. The initial hosted run correctly failed as inconclusive when intervals crossed its acceptance boundary. Evidence: E_PERF_CONTRACT, E_PERF_HARNESS, E_HOSTED_BENCH.

**Remaining qualification:** A sufficiently precise comparable final-candidate and baseline timing result remains required. The same-binary harness smoke validates measurement plumbing and supplies no implementation speedup evidence.

#### PERF-06 — Legacy Python CDC comparison may actually use native C

**Implemented and verified · Original priority: Medium.** Forces the reference Python engine and identifies native engines; equivalent Gear implementations compare exact boundaries/hashes while distinct algorithms are labeled separately. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed), [74ae074](https://github.com/coherence-energy-labs/one-link/commit/74ae0742ca433118f4c0d4c52bcc731e569ca898).

Source: [src/one_link/perf_lab.py](../../src/one_link/perf_lab.py), [src/one_link/perf_lab_native.py](../../src/one_link/perf_lab_native.py), [src/one_link/cdc.py](../../src/one_link/cdc.py). Representative tests: [tests/test_benchmark_measurement_contract.py::test_python_legacy_comparator_cannot_invoke_native](../../tests/test_benchmark_measurement_contract.py), [tests/test_benchmark_measurement_contract.py::test_equivalent_gear_pair_checks_hashes_and_boundaries](../../tests/test_benchmark_measurement_contract.py).

Explicit-engine and output-equivalence contracts passed; actual scanner call observation retained in production comparison. Evidence: E_PERF_CONTRACT, E_CDC_PREP.

**Remaining qualification:** Do not label format-aware Rust CDC and legacy Gear CDC as identical algorithms or infer transport speed from either primitive.

#### PERF-07 — Provenance, repetitions and latency statistics need consistent contracts

**Implemented and verified · Original priority: Medium.** Records source/native binary identity, raw timings, engine and workload/scope; incompatible results become inconclusive; batch averages are named accurately rather than advertised as per-operation percentile latency. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed).

Source: [src/one_link/benchmark_contract.py](../../src/one_link/benchmark_contract.py), [src/one_link/perf_lab_native.py](../../src/one_link/perf_lab_native.py), [scripts/bench_recovery_rotation_v021.py](../../scripts/bench_recovery_rotation_v021.py). Representative tests: [tests/test_benchmark_measurement_contract.py::test_native_benchmark_preserves_raw_observations](../../tests/test_benchmark_measurement_contract.py), [tests/test_benchmark_measurement_contract.py::test_native_benchmark_rejects_changing_work](../../tests/test_benchmark_measurement_contract.py).

Raw samples, identities and verification are retained in representative harness and production-preparation runs. Evidence: E_PERF_CONTRACT, E_PERF_HARNESS, E_FIXED_PREP.

**Remaining qualification:** Small local samples do not establish tail latency, network variability, hardware coverage or user-facing SLOs.

#### PERF-08 — Benchmark workflow path filters and acceptance descriptions are incomplete

**Implemented; qualification pending · Original priority: Medium.** Expanded benchmark-dependent triggers and separate head and baseline builds using a common harness. Five alternating pairs and the documented five-percent and twelve-percent policies distinguish relative drift from absolute goals. Historical coherence timing remains limited to its dedicated runner. Stable required native contexts now emit with verified source applicability, so unrelated changes can be reported explicitly without leaving a required check missing. Commits: [c1686ca](https://github.com/coherence-energy-labs/one-link/commit/c1686ca50989f70b4b71c173a2b19ea55304a2ed), [1164ed9](https://github.com/coherence-energy-labs/one-link/commit/1164ed9ba3bc4716acdbb8ff3472c5c8e9144340), [876857f](https://github.com/coherence-energy-labs/one-link/commit/876857fbc389c2d486f8f99a4ad4ec33be13de9d).

Source: [.github/workflows/native_bench_gate.yml](../../.github/workflows/native_bench_gate.yml), [scripts/bench_paired_native.py](../../scripts/bench_paired_native.py), [bench_baselines/README.md](../../bench_baselines/README.md). Representative tests: [tests/test_bench_gate_compares_like_for_like.py](../../tests/test_bench_gate_compares_like_for_like.py), [tests/test_coherence_field_perf_slo.py](../../tests/test_coherence_field_perf_slo.py).

Runner and gate contracts passed, and the execution transcript reports 23 coherence-field SLO and documentation cases passed. The initial hosted gate failed as INCONCLUSIVE after five pairs; no tolerance was relaxed. The follow-up profile is implemented in 3acb6fc, with 236 passed sampling contracts and a real 28-metric orchestration smoke. Windows scope portability passes all 70 cases after 9a8475a. Evidence: E_PERF_CONTRACT, E_PERF_HARNESS, E_HOSTED_BENCH, E_GATE_INTEGRATION, E_NATIVE_SAMPLING, E_NATIVE_SAMPLING_SMOKE, E_WIN_SCOPE_PORTABILITY.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: the twenty-pair benchmark gate was INCONCLUSIVE, not passed. Three hosted twenty-pair studies were compared (c7d57a1, 64495c4, c3cd967). On every QUIC metric in every study the candidate is slower than the default branch: median ratios 0.976 to 0.990, 0.981 to 0.986 and 0.959 to 0.999. Two studies are inside the 5% limit; in the third, two round-trip metrics (0.964 [0.950, 0.985] and 0.959 [0.948, 0.976]) have an interval that reaches the limit.

**Remaining qualification:** QUIC round trips are 1 to 4% slower than the default branch. No QUIC code of this project changed; the arms differ by the tokio and quinn-proto updates, and quinn-proto 0.11.19 is the security update RLS-01 requires. Which of the two costs the time has not been measured. The owner decides whether to accept that cost and re-baseline after merge. The same candidate code measured 0.981 to 0.986 in one study and 0.959 to 0.973 in the next: the between-run spread is larger than each study's own interval, so a 5% limit will sometimes be reached by a difference this size. The two chunk-store write metrics are disk-bound and bimodal on hosted runners (about 221 MB/s or about 1.1 GB/s in either arm, a runner disk cap); the study at 64495c4 was inconclusive on them for that reason alone. They should be measured against memory-backed storage or left out of the hosted gate. A relative benchmark result does not establish any absolute network throughput target.

### Maintainability and test coverage

#### MNT-01 — Core runtime is concentrated into exceptionally large classes and stateful handlers

**Partially remediated · Original priority: Medium.** Extracted descriptor identity/preparation/commit retry and courier ledger/catalog/monitor/use cases through typed ports and owned state; no daemon-global bridge or mixin rewrite. Fixed assembly rollback ownership and temporary-file cleanup. Commits: [5344ee9](https://github.com/coherence-energy-labs/one-link/commit/5344ee9387c2f6da87b4064f01c2d17c56cfeaa9), [aac9f83](https://github.com/coherence-energy-labs/one-link/commit/aac9f834855cf0f9fcd388d9579c4465178a61df), [b7a3ca2](https://github.com/coherence-energy-labs/one-link/commit/b7a3ca298510ba7f2819616b35153786eb692905).

Source: [src/one_link/file_source.py](../../src/one_link/file_source.py), [src/one_link/file_preparation.py](../../src/one_link/file_preparation.py), [src/one_link/transfer_commit_guard.py](../../src/one_link/transfer_commit_guard.py). Representative tests: [tests/test_file_preparation_service.py](../../tests/test_file_preparation_service.py), [tests/test_transfer_commit_guard_service.py](../../tests/test_transfer_commit_guard_service.py).

The runtime, UI and courier selections passed 243, 86 and 168 cases respectively. These are separate overlapping runs. The preparation extraction removed 556 net daemon lines; courier extraction removed 654 net server lines while preserving send, receipt, authentication and public route contracts. Full-checkout Python distribution validation at f5fb842 includes the extracted services in the exact 232-file Python inventory. Evidence: E_RUNTIME, E_RUNTIME_UI, E_COURIER, E_FIXED_PREP, E_PYTHON_DIST_REVIEW.

**Update 2026-11-25 (independent review):** Daemon 506 methods / 35,162 lines to 499 / 33,200; UIServer 450 / 25,683 to 445 / 25,032 (two merged methods recorded as growth with a written reason).

**Remaining qualification:** Still in Daemon: the transfer domain (about 9,900 lines), the peer dispatcher (4,400), the rest of folder sync (3,200), groups and mesh. Still in UIServer: peer, folder and recovery routes. Courier imports remain serialized on the event loop; concurrent workers need a synchronization design first.

#### MNT-02 — Many existing live-daemon tests are omitted from normal push/PR execution

**Implemented; qualification pending · Original priority: Medium.** Explicit live markers/manifests drive four bounded shards per acceptance OS, enforce collection/execution counts and preserve incomplete/failed first attempts; only two live pairing tests leave hermetic execution. Commits: [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e), [93a5d0d](https://github.com/coherence-energy-labs/one-link/commit/93a5d0d6e2c98d34760c01e6548232f0a9663fb1).

Source: [tests/live_daemon_manifest.json](../../tests/live_daemon_manifest.json), [scripts/live_suite.py](../../scripts/live_suite.py), [tests/harness.py](../../tests/harness.py). Representative tests: [tests/test_delivery_evidence.py::test_live_manifest_detects_stale_or_empty_selection_and_stable_shards](../../tests/test_delivery_evidence.py), [tests/test_delivery_evidence.py::test_live_acceptance_rejects_pytest_success_with_a_skipped_case](../../tests/test_delivery_evidence.py).

Collection accounts for 139 functions and 152 parameter cases. Twenty-one hermetic pairing cases passed. The initial hosted Linux and Windows lanes each executed all 152 live cases with no failures or skips; exact-final-source acceptance remains pending. Evidence: E_LIVE_MANIFEST, E_HERMETIC_PAIRING, E_DELIVERY, E_LINUX_FULL, E_HOSTED_INITIAL, E_HOSTED_WINDOWS_INITIAL.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: 6 of 8 live shards passed; not passed: live daemon acceptance / windows-latest / shard 1; live daemon acceptance / windows-latest / shard 3. 142 registered live tests run in four shards per platform, and an unregistered live test fails before it spawns a daemon.

**Remaining qualification:** Linux and Windows only. On hosted Windows runners single live cases fail intermittently: across the last runs on this branch, a daemon that took more than 20 to 30 s to start (a class the repository has carried diagnostics for since July), a folder send that did not land within 30 s, and two folder-sync tests whose expected counts depended on which delivery path won. The count race is fixed in the tests; the slow start and the folder send are not explained. Each now arrives with the daemons' logs and the startup step that was slow. The same cases passed 8 of 8 and 9 of 9 on a workstation.

#### MNT-03 — Browser application logic remains concentrated in huge inline scripts

**Partially remediated · Original priority: Low.** Owner authoring now has 106 modules and six service factories, and peer authoring has 60 modules and four service factories. Sources live outside shipped runtime assets; deterministic offline assembly retains the existing standalone HTML distribution and markup. Commits: [3674060](https://github.com/coherence-energy-labs/one-link/commit/3674060956c22caa40a74eaf3f4f58c1c5e768a1), [8a9fe28](https://github.com/coherence-energy-labs/one-link/commit/8a9fe2839959febb17457e1ef7ed90b8695e4eb2), [eab2337](https://github.com/coherence-energy-labs/one-link/commit/eab2337e48067f84634553a3bc0a4946e5a46188), [296c721](https://github.com/coherence-energy-labs/one-link/commit/296c721b3205deb9d6d4a7864ed172ecc9790a6e).

Source: [frontend/owner/manifest.json](../../frontend/owner/manifest.json), [frontend/peer/manifest.json](../../frontend/peer/manifest.json), [scripts/build_owner_ui.py](../../scripts/build_owner_ui.py). Representative tests: [tests/test_owner_ui_build.py](../../tests/test_owner_ui_build.py), [tests/test_peer_ui_build.py](../../tests/test_peer_ui_build.py).

Execution transcripts record 11 owner source cases and eight owner Node cases passed, plus 593 peer source cases passed, three skipped and six peer Node cases passed. All 311 original named peer function bodies were retained. The peer change is integrated as 296c721. Windows browser acceptance at d2de862 passed all 63 Chromium and three Firefox cases. Full-checkout Python distribution validation at f5fb842 also confirmed exact packaged assets and clean installations. Evidence: E_OWNER, E_PEER, E_DIST_FINAL, E_WIN_BROWSERS, E_WIN_BROWSERS_D2DE862, E_PYTHON_DIST_REVIEW.

**Update 2026-11-25 (independent review):** Cross-module writes 844 to 336; the six named features 508 to 0; references from one closure to another's names 34 to 0. Hosted on c3cd967: e2e (playwright) / ubuntu-latest; e2e (playwright) / windows-latest passed.

**Remaining qualification:** 336 cross-module writes remain outside the six named features, each listed with a rationale and held by the ratchet. Screenshots are captured for review; there is no pixel-level layout gate.

#### MNT-04 — Protocol catalogue omits current completion states and historical test audit is not current evidence

**Implemented and verified · Original priority: Low.** Protocol catalogue now names durable file/folder completion, failure and capability conditions; historical skip audit is labeled historical and exact-run manifests report current execution. Commits: [c2f6e0a](https://github.com/coherence-energy-labs/one-link/commit/c2f6e0a57b5159a1fd045ca23965b7741177dc6a), [aa37b9d](https://github.com/coherence-energy-labs/one-link/commit/aa37b9dd7f8f226c0129e438538022094f7a3dc5), [48990e4](https://github.com/coherence-energy-labs/one-link/commit/48990e4469ed81520dd539d5fe2bf0741afbf33e).

Source: [src/one_link/sessions.py](../../src/one_link/sessions.py), [tests/test_capabilities_sessions.py](../../tests/test_capabilities_sessions.py), [docs/TEST_SUITE_SKIP_AUDIT.md](../../docs/TEST_SUITE_SKIP_AUDIT.md). Representative tests: [tests/test_capabilities_sessions.py](../../tests/test_capabilities_sessions.py), [tests/test_delivery_evidence.py](../../tests/test_delivery_evidence.py).

86 protocol/receipt cases passed and live collection accounting retained; historical counts no longer imply current runtime evidence. Evidence: E_RECEIPTS, E_LIVE_MANIFEST.

**Remaining qualification:** Append exact-final-source hosted skip/xfail/execution results; do not add overlapping suite counts.

### Native file-scanning branch

#### BRANCH-01 — ZIP/H264 whole-buffer path accepts a short read as a successful complete scan

**Implemented and verified · Original priority: Medium.** All declared-length paths reject shrinkage/growth; ZIP/H264 use exact reads and post-read length validation. Fragmented/interrupted readers and explicit IO error categories are covered. Commits: [8b42802](https://github.com/coherence-energy-labs/one-link/commit/8b42802bf883cb0eed2f017d0cca274b81e83b9d).

Source: [native/ol_chunk/src/stream.rs](../../native/ol_chunk/src/stream.rs), [native/ol_chunk/tests/stream_contracts.rs](../../native/ol_chunk/tests/stream_contracts.rs), [native/one_link_native/src/chunk.rs](../../native/one_link_native/src/chunk.rs). Representative tests: [native/ol_chunk/tests/stream_contracts.rs](../../native/ol_chunk/tests/stream_contracts.rs), [tests/test_native_format_aware_file.py](../../tests/test_native_format_aware_file.py).

Seventy-five Rust package cases and 107 installed-wheel cases passed. The same 107 binding cases also passed with the fresh integrated native binary. Evidence: E_NATIVE_CHUNK, E_NATIVE_BINDING, E_LINUX_FULL.

**Remaining qualification:** Supported-platform/final-artifact matrix results remain to be attached; no claim covers arbitrary concurrent filesystem mutation beyond the documented contract.

#### BRANCH-02 — Bounded payload buffering does not bound dense-record metadata memory

**Implemented and verified · Original priority: Medium.** Online record visitors absorb dense boundaries during traversal and scan accepted segments immediately, removing production candidate/accepted-cut/segment materialization. Commits: [8b42802](https://github.com/coherence-energy-labs/one-link/commit/8b42802bf883cb0eed2f017d0cca274b81e83b9d).

Source: [native/ol_chunk/src/stream.rs](../../native/ol_chunk/src/stream.rs), [native/ol_chunk/examples/stream_memory_probe.rs](../../native/ol_chunk/examples/stream_memory_probe.rs), [native/ol_chunk/tests/stream_contracts.rs](../../native/ol_chunk/tests/stream_contracts.rs). Representative tests: [native/ol_chunk/tests/stream_contracts.rs](../../native/ol_chunk/tests/stream_contracts.rs), [native/ol_chunk/examples/stream_memory_probe.rs](../../native/ol_chunk/examples/stream_memory_probe.rs).

A two-million-record reader contract and 18 paired memory observations verify online behavior. At four million records, median native VmHWM decreased by 94.1 percent while exact output digests matched. Evidence: E_NATIVE_CHUNK, E_NATIVE_MEMORY.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: scan memory qualification (ubuntu-latest); scan memory qualification (windows-latest); scan memory qualification (macos-latest) passed. Dense, sparse and plain logs of 256 MiB and 1 GiB on each platform: every workspace within its declared bound, per-record slope at most 0.05 bytes.

**Remaining qualification:** Hosted sizes stop at 1 GiB; larger logs were measured on one Windows workstation only. The smaller buffers cost speed: about 15 to 30% on dense logs and up to a third on sparse ones (hosted runners and a 14-round workstation sweep agree on the direction; the workstation is too noisy to pick an optimum). A larger hashing batch with a small read-ahead should keep the memory limit and restore parallel hashing; that needs a quiet machine. Returned output remains O(chunks), and the explicit offset-list APIs keep their O(records) result by design.

#### BRANCH-03 — New file APIs have no binding-level tests or in-repository runtime integration evidence

**Implemented; qualification pending · Original priority: Low.** Installed exports now have format/profile/path/error/window/limit tests. Separately accelerated the existing descriptor-bound production Gear CDC path without substituting the distinct pathname/format-aware Rust semantics. Commits: [8b42802](https://github.com/coherence-energy-labs/one-link/commit/8b42802bf883cb0eed2f017d0cca274b81e83b9d), [74ae074](https://github.com/coherence-energy-labs/one-link/commit/74ae0742ca433118f4c0d4c52bcc731e569ca898).

Source: [native/one_link_native/src/chunk.rs](../../native/one_link_native/src/chunk.rs), [native/one_link_native/chunk.pyi](../../native/one_link_native/chunk.pyi), [tests/test_native_format_aware_file.py](../../tests/test_native_format_aware_file.py). Representative tests: [tests/test_native_format_aware_file.py](../../tests/test_native_format_aware_file.py), [tests/test_cdc_file_windows.py](../../tests/test_cdc_file_windows.py).

The 107 binding and export cases passed, including a real 32 MiB window crossing and 256 MiB refusal. Production Gear acceleration has exact-boundary evidence. Evidence: E_NATIVE_BINDING, E_LINUX_FULL, E_CDC_PREP.

**Update 2026-11-25 (independent review):** The format-aware file API has a production caller, and its suite passes on this branch's wheel.

**Remaining qualification:** No end-to-end benchmark with the real caller is recorded. One Link's own transfer path stays on plain content-defined chunking on purpose: a deduplication experiment on its corpus did not favour format-aware cuts.

#### BRANCH-04 — cdc_file documentation still describes a 512 KiB buffer despite a 32 MiB window

**Implemented and verified · Original priority: Low.** Corrected Rust and Python documentation and exported constants: the default payload window is 32 MiB, or four times the maximum chunk size when larger. Kernel workspace and output or metadata growth are described separately. Commits: [8b42802](https://github.com/coherence-energy-labs/one-link/commit/8b42802bf883cb0eed2f017d0cca274b81e83b9d).

Source: [native/ol_chunk/FILE_SCANNING.md](../../native/ol_chunk/FILE_SCANNING.md), [native/ol_chunk/src/stream.rs](../../native/ol_chunk/src/stream.rs), [native/one_link_native/chunk.pyi](../../native/one_link_native/chunk.pyi). Representative tests: [tests/test_native_format_aware_file.py](../../tests/test_native_format_aware_file.py), [native/ol_chunk/tests/stream_contracts.rs](../../native/ol_chunk/tests/stream_contracts.rs).

Runtime limit constants and window/refusal contracts are exercised by installed-wheel tests. Evidence: E_NATIVE_BINDING, E_NATIVE_CHUNK, E_NATIVE_MEMORY.

**Remaining qualification:** No constant-total-memory claim; output size and explicit all-offset APIs remain proportional to their result counts.

#### BRANCH-05 — Cross-platform determinism fixture does not yet pin exact boundary outputs

**Implemented and verified · Original priority: Medium.** Pinned exact pre-change starts/ends/hashes and corpus hashes for random/zero/edited fixtures; serial/parallel/streamed kernels share reviewed golden outputs. Commits: [8b42802](https://github.com/coherence-energy-labs/one-link/commit/8b42802bf883cb0eed2f017d0cca274b81e83b9d).

Source: [native/ol_chunk/tests/fixtures/cdc_golden_v1.txt](../../native/ol_chunk/tests/fixtures/cdc_golden_v1.txt), [native/ol_chunk/tests/cross_platform.rs](../../native/ol_chunk/tests/cross_platform.rs), [.github/workflows/native_build.yml](../../.github/workflows/native_build.yml). Representative tests: [native/ol_chunk/tests/cross_platform.rs](../../native/ol_chunk/tests/cross_platform.rs).

Frozen vectors passed in local Linux package tests. Initial hosted all-targets/all-features Linux x86_64, Linux ARM64 and macOS jobs passed. Windows exposed a fixture parser that assumed LF. Commit 8bbb9c8 parses sections with portable line handling; the golden corpus and exact expected outputs are unchanged. The new LF/CRLF equivalence test fails against the old parser and passes against the repair. All six golden-vector tests then passed on actual Windows. Evidence: E_NATIVE_CHUNK, E_NATIVE_GOLDEN_PORTABILITY, E_WIN_PORTABILITY_ATTEMPT.

**Update 2026-11-25 (independent review):** Hosted on c3cd967: cargo test (workspace) (ubuntu-latest); cargo test (workspace) (ubuntu-24.04-arm); cargo test (workspace) (windows-latest); cargo test (workspace) (macos-latest) passed. The pinned boundary and hash vectors, including the v2 format-aware vectors, run on x86_64 and ARM64 Linux, Windows and macOS.

**Remaining qualification:** Format-aware boundaries changed definition (version 2); stores that mix versions deduplicate only where the definitions agree.

## Dependency coverage and remaining supply-chain issues

The retained Python, rendezvous, npm, native workspace and fuzz checks report no known vulnerabilities in their reviewed graphs. The earlier shell RustSec report had an empty `vulnerabilities` list but still reported GLib unsoundness as RUSTSEC-2024-0429; GitHub identifies the same issue as GHSA-wrw7-89jp-8q8g. Its warning category did not make the defect harmless. A read-only comparison mapped all 88 observed default-branch alerts at `27cc28b`: 87 were outside the candidate's affected ranges and GLib remained affected. No alerts were dismissed. Those original reports remain retained. [E_DEP_PY, E_DEP_RUST, E_DEP_SHELL, E_DEP_NPM, E_CONTAINER, E_DEP_ALERTS]

The integrated backport preserves all 121 files of the official GLib 0.18.5 crate and changes only the two lines in the [upstream iterator fix](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34). It preserves the original version and MIT license. CI verifies the original archive checksum, the complete local tree and the exact reviewed diff; a real `core.autocrlf=true` checkout test verifies Windows byte preservation. Eleven original iterator tests and five continuing regression tests passed with optimization level 3. [E_GLIB_BACKPORT; dependency qualification](../DEPENDENCY_QUALIFICATION.md)

Because Cargo audit omits local path packages, a separate required live OSV query covers the original registry identity. Its retained replies still contain both known advisory IDs; only that exact issue receives the verified-source-backport disposition. New identifiers, failed requests, invalid responses or incomplete pagination fail the gate. This avoids hiding future advisories behind vendoring. The separate `proc-macro-error 1.0.4` maintenance warning, RUSTSEC-2024-0370, remains visible. The backport is a project maintenance responsibility; full hosted shell/window and intended released-artifact qualification remain separate from the local optimized tests. [E_GLIB_BACKPORT]

The final source-union SBOM contains 957 components and 958 dependency entries including its root. The earlier inventory had 956 components: the additional component is the first-party GLib regression harness. The GLib entry explicitly identifies modified source, the original registry ancestor, license, complete tree hash and upstream patch pedigree. Separate graph references preserve resolved Cargo edges even when the same package appears in more than one lock. The six-graph inventory includes build and test dependencies; a per-artifact inventory is still required before claiming exactly what ships on each platform. [E_SBOM, E_GLIB_BACKPORT]

The initial hosted full-history Gitleaks check reported one item. Independent inspection found a type-only dataclass field annotation with no assigned secret value. Commit `27cc28b` added its exact historical fingerprint and redacted report retention. A later explanatory comment repeated the annotation and triggered another historical match; commit `366d58e` removes the literal and adds that second exact fingerprint. Neither exception suppresses a detector or a path. The original findings and earlier zero-finding full-history revalidation at `d2de862` remain retained. A scan of all 139 staged backport files also returned zero findings; final combined-candidate full-history hosted acceptance remains separate. [E_HOSTED_SECRET_SCAN, E_SECRET_REVALIDATION, E_GLIB_BACKPORT]

Release signing and publication now depend on the selected native-wheel reproducibility comparison, and negative comparison tests confirm failure semantics and retained diagnostics. A fresh executed release DAG, independently built final artifacts, downloaded-byte signature and provenance verification, and supported-device qualification are still required. Historical v0.21.0 publication and its failed independent reproducibility workflow remain explicit in the release ledger. [E_DELIVERY, E_RELEASE_LEDGER]

## Product claims and their present support

| Claim | Present support | Limit |
| --- | --- | --- |
| Supported fresh passphrase bootstrap reaches recoverable authority | Verified in focused tests and three Windows fresh startup/transfer attempts (E_BOOT, E_WIN_TRANSFER) | Final packaged platforms and long soak remain separate. The local Linux host blocks discovery; the hosted Linux live suite passed all 152 cases. |
| Reported file completion is backed by receiver content and application commit | Scoped receipt contracts and three forced TCP live transfers verify this behavior. (E_RECEIPTS, E_ROUTES, E_WIN_TRANSFER) | Does not qualify every transport/device/crash scenario or link-layer wire-byte totals. |
| Production descriptor Gear CDC is accelerated without changing boundaries | Exact outputs and five paired 8 MiB preparation measurements support this scoped claim. (E_CDC_PREP, E_CDC, E_SERVICE_INTEGRATION) | 112.4x is preparation on one host/workload, not an end-to-end network speedup. |
| Format-aware scanner uses bounded payload/intermediate storage | Online coalescing and declared memory contract verified (E_NATIVE_MEMORY, E_NATIVE_BINDING) | Output O(chunks), all-offset compatibility O(records); realistic multi-GB/platform and production format-aware use remain unqualified. |
| Firefox required-identity pairing and immediate revoke work | The exact case and later Windows d2de862 run passed, including all three Firefox cases and both extracted UIs. (E_WIN_FIREFOX_EXACT, E_WIN_BROWSERS, E_WIN_BROWSERS_D2DE862) | Final combined-candidate hosted acceptance, the intended released artifact and broader platform or network conditions remain pending. |
| QUIC is faster than WebRTC for the current file path | Not established; unsupported comparisons are now inconclusive (E_PERF_CONTRACT, E_ROUTES) | Require isolated real payload routes, verified completion, repeated matching artifacts and controlled environment. |
| Native package matches source and executes its KEM ABI | Public bootstrap commands verified matching 0.22.1 versions, hashes and executed KEM self-tests on Linux and Windows. (E_LINUX_BOOTSTRAP, E_WIN_BOOTSTRAP) | Observed source revisions differ; final supported-platform and released-artifact identities remain to be qualified. |
| Dependency and release controls make a fully qualified secure release | Not established; the known GLib source defect has a verified upstream backport and continuing advisory coverage (E_DEP_PY, E_DEP_RUST, E_GLIB_BACKPORT, E_POLICY, E_RELEASE_LEDGER, E_DEP_ALERTS, E_SECRET_REVALIDATION) | Project maintenance of the backport, an unmaintained macro dependency, unapplied branch policy, final hosted CI, release artifact verification and controlled timing or formal qualification remain open. |
| Runtime/browser maintainability is fully remediated | Substantial boundaries implemented, residual monolith/shared closures remain (E_RUNTIME, E_COURIER, E_OWNER, E_PEER, E_WIN_BROWSERS_D2DE862, E_PYTHON_DIST_REVIEW) | No complete-decomposition or design-quality score is assigned from file/line counts. |

## Remaining acceptance and finalization

The immediate remaining decisions are based on evidence, not on a target percentage of findings to mark closed:

1. Run the final combined source through required hosted correctness, browser, live, native, packaging and security jobs. Record each source or verified equivalent tree, exact artifact identity, result and unresolved skip. Retain the original failed and inconclusive attempts.
2. Retain final combined-candidate hosted security conclusions alongside the original secret-scan findings and scoped revalidation. Complete native shell/window qualification of the verified GLib backport, continue live original-version advisory checks, and verify dependencies in intended release artifacts. The separate unmaintained macro dependency remains a maintenance obligation.
3. Obtain sufficiently precise comparable benchmark acceptance. The initial inconclusive gate cannot be relabeled a pass, and local preparation gains cannot become general network claims.
4. Observe actual required check names, regenerate and apply the reviewed ten-check and one-review repository policy, and retain effective-policy readback. The policy is currently prepared only.
5. Attach supported-platform executions of the frozen native boundary vectors, exact-final-source hosted browser outcomes and a freshly verified release artifact set. The completed Windows d2de862 browser run and f5fb842 Python distribution validation retain their specific scope. Validate selected reproducibility, signatures and provenance on the downloaded bytes.
6. Provision and execute controlled timing work where claimed, and conduct representative physical-device, multi-gigabyte, storage, LAN/WAN and long-duration reliability qualification. No new formal proof or side-channel certification is supplied by these functional checks.
7. Continue cohesive service and state ownership work in the remaining large daemon, server and browser feature closures. Qualify a real product consumer before describing the distinct Rust format-aware file API as fully integrated.

The final source SHA, final-head hosted run identities, effective repository-policy readback, final browser summary and released-artifact verification are intentionally open fields in the JSON ledger. This draft neither merges the pull request nor publishes a release or grants production signoff.

## Evidence locations and interpretation

The companion JSON is the authoritative index of evidence IDs and complete paths. It distinguishes archived local reports, execution-transcript summaries, and observations made on Windows. Local evidence files are session artifacts and are not implicitly published with the repository documentation. SHA256 entries in the ledger identify the retained files actually present at drafting time; absent Windows files do not receive invented hashes.

| Evidence root | Location | Contents |
| --- | --- | --- |
| Remediation | `/workspace/scratch/61eba8217325/one-link-remediation-evidence/` | Integrated test XML and logs, native identity, paired preparation measurements, public bootstrap and initial hosted summary |
| Delivery | `/workspace/scratch/61eba8217325/one-link-delivery-evidence/` | Advisory reports, frozen Linux selection and continuation, SBOM, policy proposal and delivery contract checks |
| Performance | `/workspace/scratch/61eba8217325/one-link-performance-validation/` | Retained native paired harness smoke artifacts |
| Focused native and service work | `/workspace/scratch/61eba8217325/` | Named native memory, binding, runtime-service and courier reports indexed in the JSON |
| Windows | `C:\Users\Josh\Projects\OneDesktopConnection\test-results\one-link-remediation-20261124` | Original Windows bootstrap, browser and verified transfer evidence; aggregate counts and public test IDs are summarized here |

The performance 81-case, owner source/Node and peer source/Node results were recorded in execution transcripts; no standalone pytest XML was retained for those local runs. They are labeled accordingly and must not be presented as archived raw result logs. The Windows XML remains on the Windows host; this report uses approved aggregate counts and public test identities. All reported measurements carry their workload, platform and source limits. There is no blanket security, performance, formal-verification or all-platform certification.

## Independent review and follow-up (2026-11-25)

After the report above was written, the pull request was reviewed adversarially by a second party: one reviewer per area (constant-time behaviour, native scanners, recovery and key authority, supply chain and CI, browser state, performance evidence), each asked to break a claim and to bring a witness. The findings below were confirmed by a witness before they were fixed, and each fix has a test that fails without it. Statuses in this document and in the ledger were updated from hosted results on `c3cd967a61cbdeb4e875c155344b564ffe08d29d`; the commit that records them changes documentation only.

### What the review found that the first pass had not

| Finding | What was wrong | Status |
|---|---|---|
| REV-CT1 | Shamir sharing re-rolled the top coefficient until it was non-zero. With k-1 shares that rules out one secret value per byte, and the loop branched on a secret. | Implemented and verified |
| REV-CT2 | Secret-dependent branches or table lookups in the onion code (nine early-exit zero tests), in ml-kem 0.2.3 decapsulation, in the duress gate, and a QUIC timing test that never called the shipped comparison. | Implemented and verified |
| REV-N1 | Chunk profiles that FastCDC refuses aborted the process or looped (a 100-byte file tried to allocate 27 GB); a 16-byte MP4 indexed past the end. | Implemented and verified |
| REV-N2 | Format-aware chunking did not resynchronise on dense records: one inserted record re-sent 100% of a 64 MiB log of 32-byte records. | Implemented and verified |
| REV-R1 | Setting or unsetting `ONE_LINK_PASSPHRASE` replaced the key that protected an install's rows; identity rotation orphaned state fields; key failures degraded to a stateless daemon instead of stopping startup. | Implemented and verified |
| REV-R2 | A resumed transfer dropped the requested transport and its ledger row counted only the last attempt. | Implemented and verified |
| REV-S1 | No tag ruleset and no protected release environment. | Prepared; not applied |
| REV-S2 | Required native gates could pass without running, and a pull request could edit the policy that decided so. | Implemented; qualification pending |
| REV-U1 | Ending an inbound call threw before media teardown, so capture could outlive the call. | Implemented and verified |
| REV-P1 | A QUIC throughput regression in the five-pair study was read as a pass. | Implemented; qualification pending |
| REV-D1 | A ledger that disagreed with its own report; a timing report that would have published machine details; a memory gate that reported growth for a flat scanner. | Implemented and verified |

### What changed for the original findings

- **RLS-05 (constant time).** The required check is now deterministic: production code built with release codegen runs under Valgrind with each secret marked undefined, and every secret-dependent branch or index must sit on a marked, reasoned verdict line; three negative controls must be flagged or the run fails. A statistical timing test with a stated power requirement was added beside it. On Linux and on Windows, 20 of 20 constant-time targets passed with both planted leaks detected; the same test, run before the fix, is what found the duress-gate leak. Both hosts were a loaded shared workstation and the reports say so. One wall-clock test had still been able to fail required CI on a shared runner: the GF(256) multiply gate, which reported a 10.13% spread against a 5% limit on hosted macOS with unchanged code. It now reports like the other eleven timing sites and fails only in strict mode on the controlled runner (8944380); the dataflow audit case for that function is what blocks. The controlled-runner run the audit asked for has still not happened: it is one manual dispatch of `native_timing.yml` on a runner labelled `one-link-timing`.
- **RUN-01 (Firefox pairing).** The cause was measured, then measured again when the first fix proved incomplete. A freshly launched Firefox writes its startup cache 2 to 10 s after launch, again at about 120 s and at shutdown, and each write holds its parent process (7 to 175 s observed) as soon as that process touches the cache; the daemon answered in 15 to 312 ms throughout. Waiting for one write, the first fix, could not cover the second. The test browsers now run with that cache disabled, which removes the cause, and a gate proves it for every Firefox the tests launch and fails as a browser condition, never as a pairing verdict. Nineteen of twenty consecutive lane runs passed on a loaded workstation; the one failure was a real page defect (a connection-state update replaced the instruction to send a signal), now fixed with its own test. On the page itself, every held pairing step races the 90 s deadline, and two request paths that blocked the daemon's event loop for 600 to 700 ms moved to a worker thread. macOS Firefox was not checked.
- **BRANCH-02 (scanner memory).** Three things were wrong, found in this order. The qualification reported per-record growth for a scanner whose memory was flat (its model gave dense and sparse logs one shared workspace). Its test logs repeated with the scanner's own batch size, which made the measured peak depend on where the first cut fell. And the dense header window grew by doubling: macOS measured 48.7 MiB against a 24.1 MiB bound. The window is now allocated once. The dense walk's read-ahead and hashing batch were then cut from 16 MiB and 8 MiB to 64 KiB, so a dense log needs about 2.4 MiB, no more than a sparse one, and the original limit on the dense-minus-sparse difference is enforced again. That last change costs speed, roughly 15 to 30% on dense logs and up to a third on sparse ones; each run now reports scan speed relative to its plain-log control so the trade is visible. Choosing better sizes needs a quiet machine.
- **BRANCH-03 (format-aware API in use).** The API has a production caller, ONE Memory's `store.put_file`, and its suite passes on this branch's wheel. Descriptor-bound exports (`cdc_fd`, `format_aware_fd`) close the pathname-replacement race for callers that verify a file before scanning it. One Link's own transfer path stays on plain content-defined chunking: a deduplication experiment on its corpus did not favour format-aware cuts.
- **MNT-01 (large classes).** Three services left the two orchestration classes behind typed interfaces, and a census is a ratchet against regrowth. This is an increment: the transfer domain, the peer dispatcher and most routes are still in those classes.
- **MNT-03 (browser state).** The six named features have owners; cross-module writes went from 844 to 336, and the remaining 336 are listed with a rationale and held by a ratchet.
- **RLS-03 (branch policy).** Read back on 2026-11-25: the default-branch ruleset is active with one required approval, ten required checks and no bypass actors. There is no tag ruleset and no `release` environment (REV-S1).

### What is still open, and who decides

1. **An approver.** The ruleset requires one approving review and has no bypass actors. This pull request cannot merge on its author's approval.
2. **Tag ruleset and release environment.** The payloads are in `docs/RELEASE_PROTECTION.md`. Applying them is the repository owner's decision; this review changed no setting.
3. **The controlled timing run (RLS-05).** Needs a dedicated runner. Until then the evidence is a deterministic dataflow audit plus statistical tests on a noisy host.
4. **A release has not been cut.** RLS-02 (publication waits for reproducibility) and the release-artifact half of RLS-01 can only be observed on a real candidate.
5. **MNT-01 and MNT-03 are increments.** What remains is listed in the ledger.
6. **Benchmark gate.** On the revision these results are from, the hosted twenty-pair benchmark gate was inconclusive. Across three hosted studies the candidate is 1 to 4% slower than the default branch on every QUIC metric; the arms differ by the tokio and quinn-proto updates, and quinn-proto 0.11.19 is the security update the audit required. Which of the two costs the time has not been measured. Accept the cost and re-baseline after merge, or bisect it on a quiet machine.
7. **Hosted Windows live suite.** Two of eight live shards failed on that revision. One was a test that bet on which delivery path reached the receiver first (fixed in def8556, after the run). The other, a folder send that did not land within 30 s, failed on two consecutive hosted runs and passed 8 of 8 on a workstation; it is not explained. A daemon on a hosted Windows runner is also intermittently slow to start, which the repository has carried diagnostics for since July. Live failures now arrive with both daemons' logs and the startup step that was slow.
8. **Scanner speed.** The dense scanner's smaller buffers cost roughly 15 to 30% of scan speed on dense logs and up to a third on sparse ones. Each qualification run now reports speed beside memory. Choosing better sizes needs a quiet machine.

On the next revision (`072027f`) the hosted run passed 47 checks and failed 2: all eight live shards, both browser suites and the benchmark gate passed, and the failures were the macOS native test job and its aggregate gate, on the wall-clock gate described under RLS-05 above. So the Windows live failures and the inconclusive benchmark result are intermittent on hosted runners: one run each way is not a fix, and items 6 and 7 stay open.

### Corrections to this document

- The status table above is regenerated from the ledger; `tests/test_remediation_ledger.py` fails if the two disagree.
- An earlier headline for this pull request said 22 findings were verified while the committed ledger said 12. The ledger was right.

## Field findings from a running install (2026-11-25)

After the review above, one running install showed two things the audit and the review had not looked for. Its owner window, left open across an update restart, displayed two status banners printed over each other and stayed that way for hours. A second device sending files to it was refused for sixteen minutes. Both were read from that install's daemon log and then reproduced with real daemons and a real browser.

| Finding | What was wrong | Status |
| --- | --- | --- |
| FLD-01 | Every daemon start re-applied a one-way database migration that replaces each stored sign-in with its hash, so each restart (each update) hashed the stored values again and signed every open window out. In master since 2026-07-25; "Stay signed in across daemon restarts" could not work, and no test restarted a daemon with a session. | Implemented and verified |
| FLD-02 | The window's session banner was a second element fixed exactly where its status line sits, so the two overlapped. Recovery was attempted at most twice per page and then never again, so the window stayed stranded. The page said the key had "expired" when the daemon had only failed to answer. | Implemented and verified |
| FLD-03 | A file waiting for the owner's acceptance was treated as a transfer in progress: the same file sent again was refused, a fourth file was refused as over quota, and the receiver closed the waiting session after 120 seconds although the sender waits 300. | Implemented; qualification pending |
| FLD-04 | A daemon asked to stop kept running while any connection stayed open. Since Python 3.12 a closed asyncio server waits for every connection it accepted, and the stop path predates that: it waited for each peer session to go quiet and, indefinitely, for any message-tail subscriber. Found while preparing to restart the install for FLD-01 to FLD-03. | Implemented and verified |

### What changed

- **FLD-01** (`5621199`). One-way migration steps are listed and run only on the start that first crosses their version. Measured on a real daemon: the window's sign-in answered 200 before a restart and 401 after it before the fix, 200 both times after. A test now re-opens a database with rows in four tables (sessions, settings, folders, devices) and fails on any of those rows a re-open changes, so the next one-way step on those tables is caught without anyone remembering this one. A refused owner request also leaves one log line saying what was presented, never the credential (`0875392`, `c171699`); its first use is what pointed at the migration.
- **FLD-02** (`0a720cc`). One service owns the window's link to the daemon and the single status line. It keeps retrying for as long as the credential is not disproved, forgets the credential only after two consecutive refusals, and treats the event socket as connected when the daemon greets it. The first version of this fix used the socket's `open` event; a real daemon showed that to be wrong, because it accepts an unauthenticated socket and then closes it.
- **FLD-03** (`6eb2af7`). A second send of a held file, files beyond the per-device limit while earlier ones are unanswered, and the session carrying a held offer are all told to wait instead of being refused or closed. An acceptance that could not be delivered is inherited by the same file sent again.
- **FLD-04** (`4e73895`). The daemon registers every connection its two servers accept and ends them itself when it stops, whether the stop is requested or the serving task is interrupted. Measured on scratch daemons: before, a daemon with a message-tail client or one quiet peer session was still running 45 seconds after acknowledging a stop (with nothing connected it stopped in 1.8 seconds); after, 0.2 to 1.5 seconds and a clean exit in every case, including a held file offer. This is also why the update on 2026-11-25 took 90 seconds to stop and why the next start reported an unclean shutdown.

### What is still open

1. **The owner's second device has not been rolled.** The install where these were found was rolled to `4621947` on 2026-11-26 (see below). Until the second device is updated, each of its restarts signs its own windows out, and a file waiting for acceptance there still blocks the sender's later files.
2. Sign-ins already invalidated cannot be restored; the hash is one-way. Each window signs in once more after the fix.
3. What first answered 401 to the window was not recorded. FLD-01 explains a 401 after the restart; the new log line will explain the next one.
4. Inheriting an undeliverable acceptance is unit-tested but has not been exercised between two real daemons. It also covers only the first minutes: read from the code, not measured, once the stall deadline parks such an offer, a different delivery of the same file is refused as `resume_owned_by_another_delivery`, even when the parked copy holds no bytes.
5. "Accept all from this device" lasts only until the daemon restarts. Whether that choice should persist is a decision for the owner, not something this change makes.
6. If a delivery inherits an acceptance and is then refused for another reason (disk space, say), the acceptance is not kept and the owner is asked again. Read from the code; not exercised.
7. A build older than the sign-in migration writing into a database already past it leaves a row the migration will not convert; that browser signs in once more.
8. FLD-04: an explicit stop now interrupts a transfer or a command in progress instead of waiting for it, as it did before Python 3.12; the updater's drain still refuses to begin while transfers are active. The interrupt path is tested against real asyncio servers, not with a real daemon. FLD-04 has not had an independent read.

### Hosted results and independent review

On `6eb2af7` the hosted run passed 59 checks, failed none and skipped 2: both full suites, all eight live shards and both browser lanes. The real-restart browser test is named as passed in the Linux and Windows browser logs. The live shards report totals, not test names: they split a manifest of 147 functions that includes the four two-daemon tests and the daemon-restart test, and every shard passed on both systems. The push before it (`0a720cc`) had failed two tests of the class-size ratchet: a method was added to a class the ratchet keeps from growing, and that push was made without running the ratchet's test. `c171699` moves the logic into a module.

A reviewer that did not write these changes then read `5621199` and `6eb2af7` adversarially. Against the migration guard it executed its attacks and could not make the step apply twice (two processes opening at once, twenty crash points, every starting version). It found one defect, one dead test probe and three statements that claimed more than was checked, all addressed in `2729992`:

- An inherited acceptance did not compare the declared size. Admission reserves the declared size and receives up to it before the content hash can be checked, so the same hash re-offered with a larger size would have been given storage the owner never agreed to. The size now has to match.
- The re-open test's helper guarded one of its rows on a column the table does not have, so the check covered two tables while claiming more. It now covers four and asserts each is populated.

The reviewer read the held-offer change without executing it, and did not read the decline path or the rest of the offer handler after a superseded offer. FLD-01 and FLD-02 are marked verified on the hosted run above. On `9428729`, which contains that fix, the hosted run again passed 59 checks, failed none and skipped 2. FLD-03 stays pending for a different reason: inheriting an undeliverable acceptance has not been exercised between two real daemons, and the independent read of that change was by reading, not execution.

### Rolled onto the install (2026-11-26)

The install where these were found was rolled from `f55576f` to `4621947`. The procedure, with what it found, is in `docs/ROLLING_A_SOURCE_INSTALL.md`.

- Hosted run on `4621947` before the roll: 55 passed, 4 failed, 2 skipped. Both full suites, all eight live shards, both browser lanes and the four unit lanes passed. The four failures are the scan-memory per-record model on Linux (0.0501 fitted against a limit of 0.05; Windows and macOS passed) with its roll-up, and one inconclusive disk-write benchmark with its roll-up. Neither is part of the daemon runtime. Both are open.
- Downtime was 71 seconds. The daemon running the old code could not finish stopping while a message tail was attached (FLD-04) and exited within 0.2 seconds of the tail ending.
- FLD-01, measured there: the stored record keys of the four saved sign-ins were identical before and after the restart.
- FLD-02: the native window opened signed in on the fixed page, after being rebuilt for it. The window binary pins the hash of the page it renders, so the binary from before the roll would have refused the fixed page.
- FLD-03 was not exercised there: nothing was waiting for acceptance after the roll.
- A database backup from before the first start of the new code is kept beside the install's data folder.
