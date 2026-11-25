# Benchmark evidence and acceptance policy

## Relative native component gate

The `file-engine v2 bench gate` builds the candidate and comparison revision
into **separate virtual environments**. For a pull request the comparison is
the merge base; on master it is the commit in `DRIFT_ANCHOR`. Both native
artifacts run on one host under the candidate's **same Python measurement
harness and adapters**. Five pairs run in alternating order: candidate/base,
base/candidate, and so on. Building does not occur between timed observations.
Native wheel hashes, native source revisions, harness revision, host identity,
measurement session, pair index, input contract and all raw timings are retained.
This comparison includes changes to the native artifact and its environment;
it does not measure historical Python-adapter behavior or entire user transfers.

`scripts/bench_gate.py` validates every repetition before comparing. Missing
files, duplicate/missing metrics, non-finite/zero throughput, unlike workloads,
changed builds within an arm and mismatched paired identities are **inconclusive**.
A same-class CPU/OS description by itself is insufficient proof of one host;
CI additionally requires the paired session and recorded host identity.

The effect estimate is the median of matched candidate/base throughput ratios.
A deterministic 4,000-resample percentile bootstrap retains paired observations
and estimates a 95% interval. This is an uncertainty estimate for these samples,
not a distribution-free guarantee, causal proof, or correction for testing many
metrics. The outcomes are:

- **PASS (exit 0):** the interval's lower bound meets the allowed ratio for every metric.
- **FAIL (exit 1):** a metric's upper bound is below its allowed ratio.
- **INCONCLUSIVE (exit 2):** an interval crosses the allowed ratio, or the measurement
  contract is incomplete. This is not a successful CI gate.

The default limit is a **5% throughput reduction**. The explicitly configured
`native_aead_*`, `native_blake3_*` and `native_derive_*` classes permit **12%**.
A result accepted only by a wider class limit is printed as `TOLERATED`.
These are documented relative acceptance limits, not universal performance
requirements. Production completion rates, latency and resource budgets remain
separate SLOs for specified devices, networks and workloads.

A single-observation local comparison is supported for diagnosis but has no
statistical interpretation; CI requires five complete pairs. Never collect
runs repeatedly until one passes. Retain an inconclusive or failed study,
investigate workload/host variability or the implementation, then capture a new
complete study with its own identity. Changing a limit or `DRIFT_ANCHOR` requires
an explicit rationale and review of the preserved measurements.

## Full transfer measurements

```text
python scripts/bench_file_engine.py --scenario cold --corpus all --repeat 3 --quick --json cold.json
python scripts/bench_file_engine.py --scenario mixed_tree --json tree.json
python scripts/bench_file_engine.py --scenario related --json related.json
python scripts/bench_file_engine.py --scenario quic_vs_webrtc --transports quic tcp --repeat 3 --json routes.json
```

The input families are unique seeded random bytes, independently compressed
blocks, deliberately repetitive bytes, and controlled related-file edits. Input
creation occurs before timing. Sources are newly written and OS-cache warm;
these are not cold-disk measurements. Cold-transfer runs start fresh daemons
and chunk caches. Every attempt, including setup failures, rejected requests,
timeouts and missing files, remains in the report.

Successful transfer timing ends only after an independently verified receiver
file and matching application commit/hash/size response. Reports preserve
logical bytes separately from application payload counters. Those counters do
not include every packet/header and are not packet-capture wire measurements.
Warm/related runs require a new delivered file, so a pre-existing inbox copy
cannot satisfy the second observation. Mixed-tree and concurrent profiles
report per-file outcomes and calculate aggregate throughput only after all
requested deliveries verify.

Transport labels come from an explicit request and actual payload accounting,
never from peer trust or endpoint availability. A route which is disabled,
unavailable, falls back or lacks a receipt makes that comparison inconclusive;
no speedup is published. The historical `quic_vs_webrtc` scenario name remains
as a CLI alias and must not be read as a claim that both file payload routes are
currently supported. The shipped QUIC file gate remains intact until its own
qualification is complete. A normal peer channel may use authenticated TCP.

## Local component and production-preparation profiles

`one_link.perf_lab` preserves repeated timing samples and checks every indexing
result's whole-file hash and coverage. `daemon_source_preparation` calls the
actual descriptor-verified `Daemon.prepare_file_for_transfer` path with no
persistent index cache, including its size-based fixed/CDC choice. Its scope
excludes daemon startup, persistence-cache cost and network transfer. Native
scanner calls are observed, and the small observer overhead is included in the
timed region. Engine availability alone is never reported as actual dispatch.
Report comparisons suppress ratios when workload, host or engine identities
are missing or incompatible.

`one_link.perf_lab_native` records every iteration and native binary identity.
The legacy Gear benchmark explicitly forces Python. The separate equivalent
Gear pair verifies exact native-C/Python boundaries and hashes on every
iteration. Rust FastCDC and Gear-CDC have different algorithm contracts; their
numbers are not an equivalent-algorithm Python-to-Rust speedup. Native QUIC
microbenchmarks measure component helpers, not the daemon's end-to-end route.
The two dated primitive benchmark scripts label the maximum of batch-average
latencies as `ns_per_op_worst_batch_average`, not an individual-operation p95.

## Historical artifacts and the drift anchor

`native_chunk.json` and `coherence_field.json` are historical workstation
measurements. Neither is the portable native CI gate. A missing baseline is
inconclusive, never a command to commit the candidate's measured numbers as a
passing reference. `DRIFT_ANCHOR` names a source commit which is built and
measured afresh; changing it does not alter or delete older evidence.

The coherence-field snapshot has its own provenance contract and absolute
five-second-tick-derived SLO gate in `scripts/coherence_field_slo_gate.py`.
Relative coherence-field comparisons with `scripts/bench_gate.py` are
**dedicated-runner tooling only**; the historical JSON is not a portable release
threshold. **Do not rebase this file from a busy workstation** to make a
regression disappear. A new controlled-lab reference must be a separately dated
artifact with matching workload and complete runner/build provenance, preserving
the historical snapshot and the measured failures.
Native solver regressions still require a controlled Criterion runner. OS,
CPU model/power state, Python/native ABI, compiler flags, storage and competing
load all affect measurement; a JSON report does not make unlike hosts comparable.
