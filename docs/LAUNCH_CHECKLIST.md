# Launch checklist

This is the operational gate for taking One Link from "works on
my machine" to "ship to people who don't know me." Every current-release line
is a concrete thing a human (or CI workflow) verifies before pulling the
trigger on a public release. Items explicitly labeled **future packaging
gate** are inactive until that artifact format is added to the authoritative
release contract; their presence does not claim that format ships.

Companion to `docs/RELEASE_CHECKLIST.md` (which covers the
tag-and-sign mechanics). This one covers the user-facing
surfaces a release needs to be ready in.

---

## A. "Can the user actually get it?"

- [ ] **Website download page resolves to a real artifact.** Visit
      `https://weareone-link.org/download/` on a phone + a laptop.
      Each "Download for {OS}" button MUST lead to a current,
      signed artifact - not a 404, not a stale tarball, not a
      placeholder.

- [ ] **Per-OS download buttons auto-detect or are clearly
      labeled.** A first-time user on Windows / Mac / Linux sees
      THEIR OS as the prominent button. No "click here for all
      builds" generic page that makes them guess.

- [ ] **The download is verifiable in one command.** The download page uses
      `scripts/verify-release.sh <artifact> <exact-tag>` so the checksum
      manifest, artifact bundle, OIDC issuer, and exact tagged-workflow identity
      are all checked. No wildcard certificate identity is permitted.

- [ ] **No promise the daemon can't keep.** Every capability
      claimed on the download page (chat, files, voice calls,
      recovery) is in the ROADMAP capability table as ✅ for the
      OS the user is downloading. Aspirational features go under
      a clearly-labeled "Coming soon" section, not in the headline.

## B. "Does the current portable bundle just work?"

The authoritative `release.yml` contract is configured to package the complete
PyInstaller onedir output as architecture-labeled portable ZIP archives:
Windows x86_64/ARM64, macOS ARM64, and Linux x86_64/ARM64. Published v0.21.0
includes these five formats; its qualification gaps are recorded in
`RELEASE_EVIDENCE.json`. The contract does **not** include a Windows
installer, macOS DMG/PKG, or Linux AppImage.

- [ ] **Portable ZIP extraction and launch works on every advertised OS and
      architecture.** Verify the exact tagged archive before extraction,
      extract the complete bundle, and launch `one-link.exe`, `one-link.app`,
      or `one-link` from that bundle on a fresh physical device. The executable
      must not be separated from its onedir support files. The download page
      documents any SmartScreen, Gatekeeper, executable-bit, or quarantine
      steps actually observed for these ZIP artifacts; each instruction is
      re-tested against the exact release bytes.

### Future packaging gates (not current shipping claims)

These checks become mandatory only when the authoritative release workflow
publishes, signs, and lists the corresponding format. Auto-build artifacts or
roadmap text do not make a format supported.

- [ ] **Future packaging gate — Windows installer (.exe/MSI).** Validate
      install, upgrade, uninstall, architecture selection, code signing, and
      the exact SmartScreen flow on a fresh Windows device before advertising
      an installer. No Windows installer currently ships under the production
      release contract.

- [ ] **Future packaging gate — macOS DMG/PKG.** Validate installation,
      upgrade, removal, code signing, notarization, and the exact Gatekeeper
      flow on a fresh macOS device before advertising a DMG or installer. No
      DMG or PKG currently ships under the production release contract.

- [ ] **Future packaging gate — Linux AppImage.** Validate executable-bit
      preservation, launch behavior, desktop integration, update behavior,
      and supported distributions before advertising an AppImage. No AppImage
      currently ships under the production release contract.

- [ ] **iOS Safari mobileconfig flow.** Walked end-to-end on a
      real iPhone:
      - The QR scan opens Safari (not Chrome/Brave) - both work
        but only Safari can install mobileconfigs.
      - The install page sets honest time expectations + has
        per-step troubleshooting `<details>` (verified by
        `tests/test_plain_english_v021.py`).
      - The trust-switch step (3) has the "why this extra step?"
        explainer so users don't skip it.
      - After all 3 steps, the pair URL loads with no "Not
        Private" warning.

- [ ] **Cold-install stopwatch is under 60s on a real fresh box.**
      Per `tests/e2e/test_cold_install_stopwatch.py`. CI gates
      this on every push but a release run also verifies on a
      VM that hasn't ever installed One Link.

## C. "Does the first-launch UX read like a finished product?"

- [ ] **Boot-error states use plain English, not jargon.** Per
      `tests/test_plain_english_v021.py`. "OPFS unavailable" /
      "no web crypto" / "insecure context" pill labels must
      say "browser too old" / "needs https" instead.

- [ ] **Every loading spinner says what it's loading.** Per the
      same test file. "Loading…" alone is forbidden in user-
      visible HTML. Each instance must say "Reading your
      identity…" / "Counting your files…" / etc.

- [ ] **Every error toast names a next action.** Vague "Try
      again" without context is a polish bug. Each error
      ends with either (a) what the user can do or (b) "this
      is being investigated" + a link to status.

- [ ] **Every button label is a verb.** Noun-only labels
      ("Identity", "Trust", "Archive") confuse users. Each
      button says what will HAPPEN when they click it.

- [ ] **No engineer-jargon strings reach the user.** Per
      `test_plain_english_v021.py`. Forbidden in user-visible
      HTML: BLAKE3, SHA-256, PBKDF2, AES-GCM, OPFS, SAS,
      "Device Guardian", "Rotate identity key", API path
      names ("recoveryRotate failed").

## D. "Does it actually work end-to-end?"

- [ ] **`full_suite_and_e2e.yml` green on the target SHA.** Full
      pytest suite + Playwright E2E + Windows native picker probe.

- [ ] **`reliability_harness.yml` 50-pair soak green Linux +
      Windows.** Per `scripts/reliability_harness.py`. No flake
      in the past 7 days.

- [ ] **`synthetic_monitor.yml` green twice-daily.** Per-step
      pass rate visible in the artifact.

- [ ] **Manual walk-through on each supported OS.** A human does
      the cold-install → pair phone → send text → send photo
      flow on each platform. Records timing. Compares to the
      stopwatch budget.

- [ ] **Recovery audit triangle works.** A human runs:
      - `one-link backup test [WORDS...]` (verify-phrase)
      - `one-link backup test-bundle BUNDLE_PATH [WORDS...]`
      - `one-link recovery test-shares PORTABLE_SHARES...`
      All three return the right exit code on a real install.

## E. "If something breaks, can users tell us?"

- [ ] **Debug pane "Copy error report" works.** Per
      `tests/test_error_report_bundle_v021.py`. A user hits a
      bug, clicks one button, gets a sanitized JSON blob in
      their clipboard.

- [ ] **GitHub issues link is in the UI.** Either in the Debug
      pane or in Settings → About. Users have a discoverable
      way to file a report.

- [ ] **`one-link verify-this-install --expected-rollup <hash>` matches an
      independently authenticated install-content manifest.** A plain release
      note or local hash is not an authenticity proof. Per
      `tests/test_verify_this_install_v021.py`.

- [ ] **Daemon logs to a discoverable location.** Per
      `one-link verify-this-install --json --inventory-only` output's package_root,
      the log directory is documented + reachable via Files
      Explorer / Finder.

## F. "Can someone else maintain this if you disappear?"

- [ ] **`RELEASE_CHECKLIST.md` lists the named co-signer.** Per
      `docs/RELEASE_CHECKLIST.md`. At least one other human has
      a verified Sigstore identity for releases.

- [ ] **`docs/GOVERNANCE.md` documents the succession plan.**
      Who has commit access? Who has the website + DNS? Who
      can publish a release if the primary maintainer is gone?

- [ ] **`docs/TESTING.md` documents the test pyramid.** Every
      layer + which one catches which bug-class. Already shipped.

- [ ] **The release publisher requires its exact Linux wheel rebuild to pass
      before signing/publication.** `release.yml` retains the compared artifacts
      and result; `reproducible_release.yml` is a separate diagnostic workflow.
      Authenticate the published Sigstore bundles as described in
      `docs/RELEASE_CHECKLIST.md`.

---

## Pre-flight: am I actually ready to launch?

You are ready when every **current-release** box above is checked. Future
packaging gates are not portable-ZIP release requirements, but become hard
gates before their formats can be advertised or published. Anything unchecked
inside the active contract is a promise you're breaking on day one. Better to
delay the launch than to ship a build that breaks the trust the project's
whole premise depends on.

If a box can't be checked + can't be fixed:
- Mark it explicitly "out of scope for vN.N.N" in the release
  notes.
- Add it to the next release's checklist as a hard gate.
- Tell users about it in the download page in plain English
  ("Recovery from lost phone is CLI-only in this release;
  GUI restore lands in the next one.").

Public trust is what this project trades on. Earning it is the
only marketing.
