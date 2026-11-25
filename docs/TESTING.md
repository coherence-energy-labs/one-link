# Testing strategy

One Link's testing layers are designed to catch different bug classes.
Knowing which layer catches what helps you write the right test for
the bug you just fixed (and helps reviewers spot when a fix is missing
its regression test).

## The layers

```
                                   what each layer catches
                                   ──────────────────────────────────
   ┌─────────────────────────┐
   │  Real-user clicking     │  Bugs that need a human to see
   │  (manual smoke)         │  ("this looks wrong", "this feels slow")
   └─────────────────────────┘
              ▲
              │ feeds bugs into ↓
   ┌─────────────────────────┐
   │  Browser E2E            │  Pixel overlap, iframe headers, click
   │  (Chromium + Firefox    │  handler hijacks, dialog z-order,
   │   transport authority)  │  and cross-engine ICE regressions,
   │                         │  multi-state UI combos, security headers
   └─────────────────────────┘
              ▲
              │ if E2E catches it but no unit test does ↓
   ┌─────────────────────────┐
   │  Integration            │  Cross-module behavior, real subprocess
   │  (tests/test_*_v021,    │  daemon interactions, wire protocol
   │   tests/harness.py)     │  round-trips, FTS5 query semantics
   └─────────────────────────┘
              ▲
              │ if integration catches it ↓
   ┌─────────────────────────┐
   │  Unit + source-text     │  Single-function correctness,
   │  (tests/test_*.py)      │  contract pinning, fail-closed shape
   │                         │  invariants, doctrine compliance
   └─────────────────────────┘
              ▲
              │ if any specific platform/OS-only ↓
   ┌─────────────────────────┐
   │  Platform probes        │  Real-Windows COM, real-macOS osascript,
   │  (CI matrix)            │  real-Linux zenity, CLSID registration
   └─────────────────────────┘
```

## CI workflows

| Workflow | Trigger | What it gates |
|---|---|---|
| `tests.yml` | every push + PR | Focused unit/integration subset on Linux + Windows for fast feedback. |
| `full_suite_and_e2e.yml` | every push + PR | Main pytest suite, manifest-checked live-daemon shards, separate browser E2E on Linux + Windows, and real-OS probes. One source-matched native wheel per OS is shared by its acceptance lanes. |
| `release.yml` | `v*` tag + manual | Tag-scoped quality gates, mandatory independent rebuild of the actual Linux native wheel, exact-byte checksums, Sigstore bundles, provenance, and publication. It is a release-candidate mechanism, not evidence by itself. |
| `reproducible_release.yml` | `v*` tag + manual | Unsigned comparison evidence; byte equality is enforced only for two Linux native-wheel builds. |
| `security.yml` | every push/PR + weekly | Lock drift, secret/history scan, workflow lint, Python/Rust advisories, SAST, and SBOM generation. JavaScript advisories are checked by `lint.yml`. |
| `fuzz_nightly.yml` | daily + manual | Budgeted native parser/state-machine fuzz targets and crash-artifact upload. |
| `native_timing.yml` | manual | Bounded strict timing diagnostics on a separately provisioned, controlled Linux runner; retains failures/timeouts and raw target logs. This does not certify constant-time execution. |

The `tests.yml` matrix is intentionally narrow for fast PR feedback.
`full_suite_and_e2e.yml` is the broad source-level gate. Neither workflow can
prove that every UI, platform, timing, hardware, or network regression is
covered.

The live lane checks `tests/live_daemon_manifest.json` against explicit
`@pytest.mark.live_daemon` declarations and records collection counts, every
parameterized case, phase outcomes, elapsed time, and JUnit. A skipped,
uncollected, retried, failed or incomplete selected case fails this lane.
New real-daemon tests must carry the marker; regenerate the manifest with
`python scripts/live_suite.py --write-manifest`. `tests/harness.py` rejects
unregistered live calls within pytest. The main lane retains ordinary platform
skips and excludes only this declared live set, including the hermetic pairing
tests in its regular coverage.

`continuous acceptance gate` requires all of these source-level acceptance
lanes to finish successfully. See [`REPOSITORY_POLICY.md`](REPOSITORY_POLICY.md)
for the exact required-check configuration and its separate live-enforcement
verification procedure. A checked-in ruleset proposal is not an enforced rule.

## Current release-evidence status

The 2026-11-24 review observed the published v0.21.0 release and its Sigstore,
SBOM and checksum assets. Its publication workflow succeeded while the separate
reproducibility comparison failed. Independent signature/provenance verification
and full fresh-device qualification remain incomplete. See
[`RELEASE_EVIDENCE.json`](RELEASE_EVIDENCE.json). The workflow table above
describes required mechanisms, not a claim that their latest runs are green.
Mutable `auto-latest` is not a qualification baseline.

Do not use the presence of a workflow file, a passing local subset, or the
`auto-latest` entry as production-readiness evidence. Release evaluation must
use one exact immutable tag and the completed checklist in
[`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md).

## When to write which test

You fixed a bug. Which layer needs a regression?

**The bug was visible to the user in a browser.** Write a Playwright
test in `tests/e2e/` that exercises the same flow the user did.
Examples: PDF preview iframe blank, search input visual overlap,
Details click also opens the file, no-matches state showing welcome
screen. These bugs are categorically invisible to source reading.

**The bug was in code logic.** Write a unit test in `tests/test_*.py`
that calls the affected function with the inputs that broke. Examples:
`search_messages("k")` returns 0 results, `mint_certificate` produces
the wrong fingerprint, `transition_peer_fingerprint` misses a table.

**The bug was in a multi-module interaction.** Write an integration
test that exercises the whole flow with a real subprocess daemon.
Examples: rotation cert sent from A applies on B, recovery wizard
endpoint round-trips with realistic state.

**The bug was platform-specific.** Add a probe to the Windows /
macOS / Linux job in `full_suite_and_e2e.yml`. Example: the modern
Windows folder picker CLSID being unregistered on certain Win11
builds — invisible to all Linux CI and all mocked unit tests, but
caught by `scripts/ci_probe_modern_folder_picker.py` against a real
Windows runner.

**The bug was a security-header / response-shape regression.** Add
both: a unit test against the handler function, and an E2E test that
hits the live endpoint via `requests` and asserts the headers. The
production middleware can override what the handler sets; only a
live-daemon assertion catches that case.

## Running tests locally

```bash
# One-time source build with the locked matching native backend.
python scripts/bootstrap_source.py --e2e

# Fast: the same subset CI runs first.
uv run --no-sync python -m pytest \
  tests/test_identity.py tests/test_wire.py tests/test_paths.py \
  tests/test_channel.py tests/test_discovery.py tests/test_cli.py

# Main unit + integration suite (matches the full-suite exclusions).
uv run --no-sync python -m pytest tests/ \
  -p no:playwright \
  --ignore=tests/e2e \
  --ignore=tests/test_call_reliability_soak.py \
  -m "not live_daemon" \
  -q --tb=short --maxfail=20

# Complete live acceptance lane (every attempt, no skipped success).
uv run --no-sync python scripts/live_suite.py --run

# Browser E2E (the bootstrap above installs its locked Python packages).
uv run --no-sync playwright install chromium firefox
ONE_LINK_RUN_BROWSER_E2E=1 \
  uv run --no-sync python -m pytest tests/e2e/ -q --browser chromium \
  --output=test-results/playwright-chromium --junitxml=test-results/browser-chromium.xml
ONE_LINK_RUN_BROWSER_E2E=1 \
  uv run --no-sync python -m pytest \
  tests/e2e/test_browser_readiness_gate.py \
  tests/e2e/test_peer_live_transport.py::test_two_isolated_peer_pages_complete_manual_webrtc_and_exchange_probe \
  tests/e2e/test_browser_identity_possession_live.py::test_required_mode_live_pair_owner_request_and_immediate_revoke \
  tests/e2e/test_call_local_candidate_live.py::test_call_media_local_candidate_augmentation_uses_real_browser_ice \
  -q --browser firefox --output=test-results/playwright-firefox \
  --junitxml=test-results/browser-firefox.xml

# Windows-only: real folder-picker COM probe.
uv run --no-sync python scripts/ci_probe_modern_folder_picker.py
```

**IMPORTANT — invocation isolation:** `pytest tests/e2e/` and
`pytest tests/` (anything else) MUST run as separate invocations.
pytest-playwright starts a session-scoped event loop that
conflicts with the async fixtures in the integration tests
(`Cannot run the event loop while another loop is running`).
The CI `full_suite_and_e2e.yml` workflow runs them as separate
jobs for this reason. If you see that error locally, you ran
both in one `pytest` command.

Playwright deletes its configured output directory at the start of a test
session. Use a distinct leaf directory for each browser invocation as above;
do not use the common `test-results` root for browser output. The live runner
disables that unrelated plugin so its native identity and partial outcome
evidence remain available after a failure.

### Browser review captures

`tests/e2e/test_visual_regression.py` is a named screenshot capture suite for
human review; it does not compare pixels and must not be described as visual
regression proof. By default it writes only to the ignored
`test-results/screenshots/` artifact directory. CI retains that directory for
review. Set `ONE_LINK_VISUAL_CAPTURE_DIR` to choose another artifact directory.

Checked-in reference images under `tests/e2e/screenshots/` are write-protected
by the test harness. Refreshing them requires the explicit
`ONE_LINK_UPDATE_VISUAL_BASELINES=1` environment flag. Without that flag,
baseline paths, other repository source paths, empty overrides, filesystem
roots, and ambiguous flag values fail before Playwright can write a file.

## What NOT to do

- **Don't write source-text gates as a replacement for behavioral
  tests.** A regex that asserts `"raise" not in body` catches code
  shape, not runtime behavior. Pair it with an actual call.
- **Don't mock the thing you're trying to test.** The picker test
  fixture sets `ONE_LINK_DISABLE_NATIVE_PICKER=1` so no real dialog
  ever pops in CI — that's the right call for test hygiene, but it
  means the real picker code path has zero unit coverage. The
  Windows CI probe is what fills that gap.
- **Don't skip the test you can't get to pass.** Either delete it
  (with a written reason in the commit message) or fix the underlying
  problem. Skipped tests rot in place + the bug-class they cover
  silently degrades.
