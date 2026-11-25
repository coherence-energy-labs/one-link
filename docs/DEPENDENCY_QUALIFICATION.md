# Dependency qualification

Reviewed on **2026-11-24 (America/New_York)**. This is a dated dependency inventory and maintenance
record. A vulnerability scan describes the advisories known to its database at
that time; it does not prove that a package or product has no vulnerabilities.
Production release qualification remains incomplete as recorded in
[RELEASE_EVIDENCE.json](RELEASE_EVIDENCE.json).

## Graph coverage

| Graph | Authoritative input | Continuous gate and evidence |
| --- | --- | --- |
| Python application, extras and tooling | `pyproject.toml`, `uv.lock`; native Python packaging in `native/pyproject.toml` | Frozen universal export; PyPI and OSV audit reports; complete Python SBOM dependency graph |
| Native runtime workspace | `native/Cargo.toml`, member manifests, `native/Cargo.lock` | RustSec vulnerabilities **and warnings** fail the gate; JSON retained |
| Native fuzz tooling | `native/fuzz/Cargo.toml`, `native/fuzz/Cargo.lock` | RustSec vulnerabilities **and warnings** fail the gate; JSON retained |
| Native window shell | `native/ol_shell/Cargo.toml`, `native/ol_shell/Cargo.lock` | RustSec's vulnerability category fails the gate; its unsound/unmaintained categories remain in output and JSON. A known medium glib advisory remains unresolved, as detailed below. |
| Rendezvous container | `deploy/rendezvous/requirements.in`, `requirements.lock`, `Dockerfile` | Separately audited hashed requirements, constrained to reviewed root-lock versions; pinned container inputs |
| JavaScript test tools | `tests/js/package.json`, `package-lock.json` | Locked npm install and dependency audit in the JavaScript contract gate |

The release and continuous SBOMs include all three Cargo lockfiles. Independent
Cargo graphs use separate component references, preserving their exact resolved
edges even when the same package/version occurs in several lockfiles. Each graph
has its own lock hash, manifest hash, package count and member count. The SBOM
includes build and test dependencies; it is not a per-platform assertion that
every listed package is reachable in every shipped artifact. The npm test-tool
graph has its own audit and is not represented as a shipped release dependency.

## Compatible fixes completed

The reviewed Python lock, rendezvous subset, main native graph and fuzz graph
were updated through their real dependency resolvers. The shell graph also
required compatible patches: `cookie` **0.18.1 → 0.18.3**, `url`
**2.5.8 → 2.5.9**, and its required `form_urlencoded` **1.2.2 → 1.2.3**.
These address [RUSTSEC-2026-0594](https://rustsec.org/advisories/RUSTSEC-2026-0594.html)
and [RUSTSEC-2026-0592](https://rustsec.org/advisories/RUSTSEC-2026-0592.html).
No dependency hash or resolved version was invented manually.

The local post-update Python and npm scans reported no known vulnerabilities
in their selected graphs. The main native and fuzz RustSec reports contained
neither vulnerability entries nor warnings. The shell RustSec report had zero
entries in its `vulnerabilities` category, but retained the known glib issue
under `warnings.unsound` and the unmaintained macro dependency under
`warnings.unmaintained`. GitHub classifies the same glib issue as a **medium
security advisory**. It is an unresolved known risk, not a clean result. The
RustSec database used for that shell result contained 1,567 advisories at commit
`10db6998b5d74ec438bcf0763125bd425a068a8f`. Future CI scans query the then-current
database and may correctly produce a different result.

## Default-branch alerts versus candidate status

A read-only GitHub Dependabot snapshot at **2026-11-25 03:33:58 UTC** contained
88 open default-branch alerts: 7 critical, 43 high, 31 medium and 7 low. Every
alert was compared with all matching package versions in the corresponding
candidate lockfile at commit `27cc28be750027a8663893b5dacd5616188bf435`.
**87 alerts were outside their affected ranges; one remained affected.** The
remaining alert is #1, `glib 0.18.5` in `native/ol_shell/Cargo.lock`,
GHSA-wrw7-89jp-8q8g, medium, affected `>=0.15.0, <0.20.0`.

Those 88 alerts describe the unchanged default branch. They are not 88 failures
in the candidate, and the 87 resolved version comparisons do not dismiss them
on GitHub. No alert was dismissed. The candidate still has the one known medium
advisory plus the separate unmaintained-dependency warning.

## Open Linux shell advisory and maintenance warning

| Advisory / warning | Resolved package | Upstream remedy and current limit |
| --- | --- | --- |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) / [GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g), medium, unsound `VariantStrIter` | `glib 0.18.5` | The advisory specifies a fix in **glib ≥0.20.0**. The selected GTK 0.18 stack remains below that boundary. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html), unmaintained dependency | `proc-macro-error 1.0.4` | No patched version is listed. An upstream migration or separately reviewed replacement is needed. |

At review, the manifests for [tao 0.37.3](https://docs.rs/crate/tao/0.37.3)
and [wry 0.57.3](https://docs.rs/crate/wry/0.57.3) still required GTK 0.18,
despite [GTK 0.19](https://docs.rs/crate/gtk/0.19.0) having moved to a newer
glib family. Simply updating this project's tao/wry version bounds therefore
does not establish that the warnings are resolved. Forcing a transitive major
version or substituting a fork without a compatible upstream migration would
require additional API and platform qualification.

### Official backport feasibility

A bounded review of official source and registry metadata on 2026-11-25 found
no published compatible 0.18 backport. The [registry's glib versions](https://crates.io/api/v1/crates/glib/versions)
still end at **0.18.5** for that series. The [official 0.18 source](https://github.com/gtk-rs/gtk-rs-core/blob/0.18/glib/src/variant_iter.rs)
still contains the affected out-argument handling; the observed source blob
was `b4061728a4411c660fce776da67cdc4bc637e757`.

The [upstream fix, PR #1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343),
merged as `05dff0ee696f9bcd8617cd48c4b812d046d440cb`, changes two lines in
`VariantStrIter::impl_get`: the pointer becomes mutable and is passed as a
mutable out-argument. It changes no public signature. That narrow diff makes
a backport technically plausible; it does not establish a maintained release
or complete platform qualification. No fork, vendored patch, forced incompatible
GTK version, or misleading package-version substitution was introduced.

The supported migration work remains concrete:

1. Prefer an official compatible backport if one is released. Otherwise adopt
   a mutually compatible released tao/wry/GTK stack that resolves glib at or
   above the advisory's patched boundary. At review, the official
   [tao GTK4 port #1104](https://github.com/tauri-apps/tao/pull/1104) was still a
   draft and [wry GTK4/WebKit6 migration #1767](https://github.com/tauri-apps/wry/pull/1767)
   remained open and unmerged.
2. Resolve the shell lock normally, review the complete changed graph, repeat
   RustSec and GitHub advisory-range comparisons, and regenerate the SBOM.
   Verify that the macro-maintenance warning is also resolved rather than
   assuming it disappears with the GTK change.
3. Qualify optimized upstream iterator tests and the actual Linux shell build,
   window load, navigation boundary, picker and lifecycle behavior; include
   X11/Wayland coverage appropriate to the new stack. Repeat Windows and macOS
   shell packaging checks for any cross-platform API changes.

If a project-maintained backport becomes necessary before those releases, its
source pin, upstream patch provenance, patch review, optimized tests, platform
coverage and ongoing maintenance obligation must be recorded separately. A
custom patched source must not be labeled as an official fixed release merely
to change a scanner result.

The project has no direct `VariantStrIter` use. The affected API can cause
undefined behavior and optimized-build crashes when invoked, as described by
the advisory. Absence of a direct first-party call does **not** establish
that vulnerable code is unreachable through dependencies. A separate Cargo
workspace also does not isolate the shipped UI from security consequences.
No advisory IDs are globally ignored. The shell gate preserves RustSec's
classification; it does not override GitHub's medium severity or resolve the
underlying issue. It **does not grant advisory-free or production qualification
to the Linux shell**. Release review must reassess the known advisory and the
maintenance warning, their platform applicability and the replacement
plan before claiming that qualification.

Linux WebKitGTK build prerequisites belong in the standalone binary builder,
where the shell is compiled. The independent native Python-wheel builders do
not need the GTK stack. Installing those prerequisites proves neither that the
window launches correctly nor that its upstream warnings are resolved; the
separate native-window runtime job supplies launch evidence.
