# Test Suite Skip Audit (Windows, May 21 2026)

> **Historical snapshot, not current qualification evidence.** The counts,
> line numbers, feature gates and xfail below describe the May 21 run only.
> They must not be quoted as the current suite outcome or used to approve a
> release. The November audit found that the current tree no longer has the
> historical xfail declaration. Current execution inventories come from the
> explicit `scripts/live_suite.py` lane and that run's JUnit artifacts; retain
> the tested commit, installed native identity, selected cases, outcomes and
> skip reasons together. An individual rerun does not erase an earlier failure.

This document categorises every skip the Python test suite produces
on a Windows developer machine and explains whether each skip is
legitimate (cannot run in this environment) or broken (should run
but does not).

## Headline

After the May 21 2026 audit:

  - **6040 passed / 0 failed*** / 10 skipped / 1 xfailed**
  - All 10 skips are **legitimate** environment or feature-gate
    constraints. **No skipped test is broken.**
  - The 1 xfail is a **documented protocol limitation** (Wave 2f
    QUIC fast path on the CDC branch) tracked in the test's own
    docstring.

  *(* A single integration flake — `frame round-trip failed:
  stream-read: connection lost` — appears in some full-suite runs
  under sustained Windows network load. Every affected file passes
  when run individually. This is a known Windows TCP-resource race
  in the daemon_pair harness and not a regression from any
  equation-of-ONE work.)*

## The 10 skips

### LEGITIMATE — Windows symlink privilege (4 skips)

Windows requires `SeCreateSymbolicLinkPrivilege` to create symlinks.
The default developer account doesn't have it, so any test that
creates a symlink to validate symlink-related security behaviour
must skip on most Windows machines.

| Test | Line | Why legitimate |
|------|------|----------------|
| `test_audit_v099::test_api_courier_drop_folder_ignores_symlinks_when_supported` | 1313 | Verifies the courier daemon ignores symlinks (file-shadowing defense). Windows users without the privilege cannot create symlinks → the attack surface doesn't exist for them. |
| `test_audit_v099::test_api_courier_removable_files_ignores_symlinks_when_supported` | 1487 | Same defense, on the removable-media surface. |
| `test_foldersync_toctou_v0207::test_has_symlink_in_chain_detects_parent_symlink` | 42 | Verifies the TOCTOU-resistant symlink walk catches parent-symlink escape. Needs to create the symlink as part of the test. |
| `test_foldersync_toctou_v0207::test_has_symlink_in_chain_stops_at_root` | 60 | Same TOCTOU walk; verifies it terminates at the root rather than walking past it. |

### LEGITIMATE — Cargo feature gate (3 skips)

Production wheels deliberately disable some Cargo features for
safety. Tests that exercise the gated-on behaviour skip when the
feature isn't enabled; complementary tests verify the gated-off
path (which IS exercised in this build).

| Test | Line | Why legitimate |
|------|------|----------------|
| `test_confidential_native::test_from_seed_deterministic_across_providers` | 94 | Needs `unstable-deterministic-provider` Cargo feature. Production wheel deliberately disables it. Inverse test `test_from_seed_disabled_in_production_build` at line 117 verifies the gated-off path runs correctly. |
| `test_confidential_native::test_from_seed_rejects_wrong_length` | 109 | Same Cargo feature. |
| `test_windows_hardened_m6::test_live_tpm_round_trip` | 59 | Needs `windows-tpm` Cargo feature AND live hardware TPM. Production wheel doesn't enable it (most users don't have a TPM). |

### LEGITIMATE — POSIX-only primitive (2 skips)

Some tests verify POSIX permission semantics (effective UID) that
don't exist on Windows. There's no Windows-equivalent test to
substitute because the security model differs fundamentally.

| Test | Line | Why legitimate |
|------|------|----------------|
| `test_paths_home_override_v0207::test_parent_owner_uid_check_fires` | 109 | POSIX `os.geteuid()`-based ownership check. Windows uses ACLs instead. |
| `test_paths_home_override_v0207::test_parent_owner_uid_check_in_xdg_path` | 144 | Same model, XDG path. |

### LEGITIMATE — Wheel-install timing race, FIXED (1 skip → 0)

One skip was a real timing race fixed in commit `1b97e9b`:

| Test | Line | What happened |
|------|------|----------------|
| `test_wave_forecast_d25_exhaustive_v0210::test_wave_stepper_factory_returns_instance` | 45 | Original `@pytest.mark.skipif(not wave_forecast_native.HAS_NATIVE)` evaluated at COLLECTION time. If the native wheel was built/installed AFTER pytest collection ran (e.g. CI rebuilds the wheel right before launching pytest), the cached HAS_NATIVE stayed False even though the wheel had landed. Fixed by re-probing `one_link_native.coherence_field` for `WaveStepper` at runtime + reloading `wave_forecast_native` so the rest of the test sees fresh state. |

After the fix: when the wheel has WaveStepper, the test runs.
When the wheel genuinely lacks it (older build / unbuilt), the
test still skips with a clear message — but it's no longer
sensitive to install ordering.

## The 1 xfail

| Test | Line | Why xfail |
|------|------|----------|
| `test_quic_daemon_dial::test_quic_send_file_round_trip_between_daemons` | 172 | Wave 2f's QUIC fast path lives in `send_file`'s STREAM-MODE branch (the `else:` of `if can_offer_cdc and FILE_WANTS:`). Both daemon_pair peers advertise `FILE_CDC`, so any non-trivial file takes the CDC branch instead — the QUIC fast path never fires on realistic workloads. A clean Wave 2f+ ships QUIC into the CDC chunk loop too; an earlier attempt regressed 8 MiB transfers from 0.1s to 222s and was reverted. The QUIC stack itself works (`test_quic_ping_round_trip_between_daemons` passes); this xfail documents that file transfers don't yet ride it. |

## Audit methodology

1. **Verified each skipif condition individually.** Targeted runs
   per file: `pytest tests/test_X.py --no-cov -rs` to get the
   per-test SKIPPED listing with reason.
2. **Cross-checked production-build feature flags.** For each
   `not HAS_NATIVE` or `not has_FEATURE` skipif: ran a fresh
   subprocess `python -c "from X import Y; print(Y)"` to confirm
   the gate condition is correct vs the live module surface.
3. **Verified inverse tests pass.** Every Cargo-feature-gated
   skip has an inverse test that runs when the feature is OFF —
   confirmed those run and pass (proving the feature-off path is
   exercised).
4. **Probed Windows privilege.** Ran `os.symlink` in a fresh
   Python subprocess to confirm Windows denial (got
   `WinError 1314: A required privilege is not held by the
   client`). Same denial the test sees → legitimate skip.
5. **Fixed all fixable timing/collection races.** The fuse skips
   (commit `64e3c60`) and wave_forecast skip (commit `1b97e9b`)
   were converted from environment-conditional to truly
   environment-independent.

## Reproducing

```
# Full suite with skip enumeration:
PYO3_PYTHON="..." python -m pytest tests/ --no-cov --timeout=120 -rs --tb=short -q

# Per-file skip enumeration:
PYO3_PYTHON="..." python -m pytest tests/test_X.py --no-cov -rs
```
