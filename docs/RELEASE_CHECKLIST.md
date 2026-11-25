# Release sign-off checklist

`release.yml` is configured as the sole signing and publication authority for
`v*` tags. It is intended to re-run the locked native, Python, browser,
performance, and security gates against the tagged commit before building or
signing anything. Its `verify_reproducibility` job rebuilds the actual Linux
native wheel on a fresh runner and is a direct prerequisite of both signing
and publication. `reproducible_release.yml` separately uploads unsigned,
narrow diagnostic comparison evidence; it does not sign or publish.

> **Current qualification status (reviewed 2026-11-24): incomplete.**
> Published v0.21.0 completed `release.yml` and has Sigstore/SBOM/checksum assets.
> The independent reproducibility run failed, and publication did not wait for
> it. Signature/provenance validation of downloaded assets and fresh-device
> qualification were not completed in that review. See `RELEASE_EVIDENCE.json`.
> The mutable `auto-latest` prerelease remains outside the trust baseline.
> The checklist below must be completed for each future candidate.

This checklist defines a future release decision. Its presence is not evidence
that any release has passed it.

## Pre-tag (run on the source you're about to tag)

- [ ] **Default-branch policy is enforced by GitHub.** Read back the active
      ruleset and verify it with `scripts/repository_policy.py`; preserve the
      result with exact-commit check runs. See `REPOSITORY_POLICY.md` for the
      required contexts and conservative update procedure. A local policy file
      does not prove review/check enforcement.

- [ ] **`tests.yml` green on the target SHA.** The fast subset
      (~200 tests, ~2 min). Quick sanity.

- [ ] **`full_suite_and_e2e.yml` green on the target SHA.** The
      full pytest suite and Playwright E2E run on Linux + Windows. The native
      picker smoke runs separately on Linux + Windows + macOS. macOS does not
      currently run the full pytest suite or browser E2E in this workflow.
      Every manifest-selected live-daemon case must execute successfully in
      the dedicated lane; skipped or incomplete selections fail acceptance.

- [ ] **`security.yml` green on the target SHA.** `uv lock --check`,
      pip-audit against the frozen lock export, bandit SAST, and SBOM generation.
      Any medium-or-higher Bandit finding or known dependency vulnerability
      blocks release. Main native and fuzz RustSec warnings also fail the gate.
      The shell's two upstream GTK warnings remain explicit qualification gaps
      in [DEPENDENCY_QUALIFICATION.md](DEPENDENCY_QUALIFICATION.md); a green
      vulnerability gate does not resolve or approve those warnings.

- [ ] **`synthetic_monitor.yml` green for the past 7 days.**
      No transient failures in the morning + evening runs - if
      the monitor has been flaky, the symptom is in production
      too.

- [ ] **`fuzz_nightly.yml` green for the past 7 days.** No new
      proptest failures on the crypto / onion / Sphinx primitives.

- [ ] **A complete install-content rollup is published as a separately
      checksummed, Sigstore-signed release asset.** A plain release-note value
      is not an authenticated baseline. Auditors pass the authenticated value
      to `one-link verify-this-install --expected-rollup <hash>`; the command
      fails on missing files or mismatch and still states that it did not
      authenticate the baseline itself.

## Tag + push

- [ ] **Repository `v*` tag ruleset blocks updates and deletion.** Keep bypass
      authority limited to the smallest maintainer set. The publisher also
      resolves the tag before staging and immediately before publication, and
      refuses any target other than the workflow's triggering commit; the
      server-side rule prevents a later move after the workflow exits. Verify
      the live server policy at release time; a committed policy proposal is
      not proof of enforcement.

- [ ] **Tag name exactly matches the `pyproject.toml` version**
      (`vX.Y.Z` / the project's declared pre-release spelling). Annotated tags
      are recommended for human context, but Sigstore authenticates the
      workflow identity and tagged commit rather than relying on tag type.

- [ ] **Tag commit message names every breaking change.** A user
      reading `git log v(N-1)..vN` should see what they need to
      do (or what they should re-test) before upgrading.

- [ ] **Tag pushed to origin.** Triggers both the authoritative `release.yml`
      pipeline and the unsigned reproducibility verifier automatically.

## Post-tag

- [ ] **`release.yml` green end to end.** Both tagged-commit quality jobs,
      every platform build, Sigstore signing/provenance, and the final minimal
      publisher must succeed. The publisher directly depends on
      `release_quality_gate` and `verify_reproducibility`.

- [ ] **The required `release.yml::verify_reproducibility` job is green.**
      The fresh Linux build must be byte-identical to the exact native wheel
      selected by this release run, not merely to another diagnostic candidate.
      Windows, macOS, and standalone artifacts are not claimed to be
      byte-identical; their exact published bytes must instead be covered by
      provenance, Sigstore bundles, and `SHA256SUMS`.

- [ ] **`SHA256SUMS` validates every downloaded artifact.** The manifest is a
      checksum of this release's exact bytes, not proof that an independent
      rebuild will produce the same bytes.

- [ ] **Sigstore bundle attached to the release.** Verify with:

      ```
      python -m sigstore verify identity \
        --bundle <artifact>.sigstore \
        --cert-identity 'https://github.com/coherence-energy-labs/one-link/.github/workflows/release.yml@refs/tags/<tag>' \
        --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
        <artifact>
      ```

- [ ] **Manual smoke on a fresh device.** Download the release
      artifact, install it on a machine that wasn't part of CI,
      authenticate the install-content manifest, run
      `one-link verify-this-install --expected-rollup <hash>`, and confirm the
      complete installed-package inventory matches.

## Rollback

If a release ships and a user-affecting regression surfaces
within 24h:

1. Do not delete or reuse the bad tag; its published transparency evidence is
   immutable.
2. Bump `pyproject.toml` to a new higher patch version, apply or revert to the
   previous-good source, and cut the matching new `v*` tag through the normal
   gated pipeline.
3. Let the successful new tagged release become `latest`; never move release
   assets between tags manually.
4. Write a postmortem in `docs/incidents/<date>.md` describing
   what shipped, what broke, what the new tests are that would
   have caught it.

## Why this checklist exists

A release is a public statement: "these exact bytes were built from this
quality-gated tag by the declared workflow, have these published hashes, and
carry verifiable provenance." Byte-for-byte independent rebuild evidence is
designed to cover only the explicitly compared Linux native wheel. No current
public release has yet supplied this complete evidence. The checklist is the
operational form of those precise promises.
