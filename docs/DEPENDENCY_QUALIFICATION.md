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
| Native runtime workspace | `native/Cargo.toml`, member manifests, `native/Cargo.lock`, `native/patches/ml-kem-0.2.3.json` | RustSec vulnerabilities **and warnings** fail the gate; JSON retained. The local ml-kem backport has exact source verification and the live registry-ancestor advisory gate. |
| Native fuzz tooling | `native/fuzz/Cargo.toml`, `native/fuzz/Cargo.lock` | RustSec vulnerabilities **and warnings** fail the gate; JSON retained |
| Native window shell | `native/ol_shell/Cargo.toml`, `native/ol_shell/Cargo.lock`, `native/ol_shell/patches/glib-0.18.5.json` | RustSec vulnerabilities **and warnings** fail the gate, with exactly one dispositioned exception (`--ignore RUSTSEC-2024-0370`, below); JSON retained without the exception. The reviewed local GLib backport also has exact source verification, optimized regressions and a required live registry-ancestor advisory gate, detailed below. |
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
security advisory**. That pre-backport result was an unresolved known risk,
not a clean result; the original reports are retained. The
RustSec database used for that shell result contained 1,567 advisories at commit
`10db6998b5d74ec438bcf0763125bd425a068a8f`. Future CI scans query the then-current
database and may correctly produce a different result.

### RustSec gate discipline (2026-11-25)

Every Cargo graph now fails on vulnerabilities **and on every warning class**
(unsound, unmaintained, yanked, notice): `cargo audit --deny warnings`. Before
this, the shell gate ran without `--deny warnings`, so an unsound,
unmaintained or yanked shell dependency could never fail it. The only
exception is exact and recorded here:

| Graph | Exception | Disposition |
| --- | --- | --- |
| `native/ol_shell/Cargo.lock` | `--ignore RUSTSEC-2024-0370` | `proc-macro-error 1.0.4` is unmaintained and has no patched release. It is a compile-time proc-macro helper, used only by `glib-macros 0.18.5` and `gtk3-macros 0.18.2` in the GTK 0.18 stack (verified from the lockfile). The migration below is the remedy. Any other or new warning fails. |
| `native/Cargo.lock`, `native/fuzz/Cargo.lock` | none | — |

The archived JSON reports are produced without any `--ignore`, so the
dispositioned warning stays visible in the evidence of every run.

What was verified locally on 2026-11-25 with the pinned cargo-audit **0.22.2**
against the RustSec database at commit `b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4`
(1,568 advisories): the main and fuzz lockfiles reported no vulnerability and
no warning. The shell lockfile reported no vulnerability and exactly one
warning, `RUSTSEC-2024-0370` (`unmaintained`, `proc-macro-error 1.0.4`).
`--deny warnings --ignore RUSTSEC-2024-0370` exited 0. The same command with a
different `--ignore` ID exited 1. The glib unsound advisory no longer appears
in cargo-audit's shell result because cargo-audit omits local path packages.
That is exactly why the live registry-ancestor gate below exists.

### Repository-wide source-override verification

`scripts/verify_vendor_patches.py` checks every Cargo manifest and every
`.cargo/config` / `.cargo/config.toml` that Git would build from, tracked or
untracked-but-not-ignored. It no longer reads only the shell manifest.

- A `[patch.crates-io]` entry is accepted only when it is exactly
  `{ path = "..." }`, is declared in that manifest's
  `[package|workspace.metadata.one-link.vendored-patches]`, and is selected as
  a source-less package by the `Cargo.lock` beside it. Its bytes must match
  the reviewed provenance and, with `--fetch-upstream`, the original crates.io
  archive plus the committed diff.
- Git patches, other-source patches, renaming or version-only patches,
  `[replace]`, and any `[patch]`, `[source]`, `paths` or `registry.index` in a
  Cargo config fail.
- Every `Cargo.lock` must agree. A lockfile that resolves a backported package
  version from the registry fails, because that graph silently builds the
  unpatched code.

`scripts/audit_vendor_advisories.py` queries the registry ancestor of every
backport found this way. Each provenance record must list the exact advisory
IDs its backport covers. An empty list declares that it covers none, so any
returned finding fails.

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
on GitHub. No alert was dismissed. The comparison predates the local source
backport below. GLib's original version remains inside the affected range by
design: the later source fix is documented by exact bytes and provenance,
not by inventing a registry version or removing the package from the inventory.

## Linux shell backport and remaining maintenance warning

| Advisory / warning | Resolved package | Upstream remedy and current limit |
| --- | --- | --- |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) / [GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g), medium, unsound `VariantStrIter` | Locally patched `glib 0.18.5`, original MIT license | The registry remedy is **glib ≥0.20.0**. One Link backports only the official two-line fix to the compatible 0.18 source; provenance and scoped regression qualification are below. This is not an official maintained 0.18 release. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html), unmaintained dependency | `proc-macro-error 1.0.4` | No patched version is listed. An upstream migration or separately reviewed replacement is needed. |

At review, the manifests for [tao 0.37.3](https://docs.rs/crate/tao/0.37.3)
and [wry 0.57.3](https://docs.rs/crate/wry/0.57.3) still required GTK 0.18,
despite [GTK 0.19](https://docs.rs/crate/gtk/0.19.0) having moved to a newer
glib family. Simply updating this project's tao/wry version bounds therefore
does not establish that the warnings are resolved. Forcing a transitive major
version or substituting a fork without a compatible upstream migration would
require additional API and platform qualification.

### Exact official fix and source provenance

A bounded review of official source and registry metadata on 2026-11-25 found
no published compatible 0.18 backport. The [registry's glib versions](https://crates.io/api/v1/crates/glib/versions)
still end at **0.18.5** for that series. The [official 0.18 source](https://github.com/gtk-rs/gtk-rs-core/blob/0.18/glib/src/variant_iter.rs)
still contains the affected out-argument handling; the observed source blob
was `b4061728a4411c660fce776da67cdc4bc637e757`.

The [upstream fix, PR #1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343),
commit `b5a4071e439bef2b5eea76c3aa25e5ae84839e34`, merged as
`05dff0ee696f9bcd8617cd48c4b812d046d440cb`, changes two lines in
`VariantStrIter::impl_get`: the pointer becomes mutable and is passed as a
mutable out-argument. It changes no public signature. That exact change is now
applied to the original **121-file** registry package under
`native/ol_shell/vendor/glib-0.18.5`. No upstream file was added or removed;
only `src/variant_iter.rs` differs. The version, MIT license, copyright and
upstream manifest remain unchanged. Cargo's normal path-patch mechanism selects
these bytes, and its generated lockfile correctly omits a registry checksum
for the local package.

The reviewable diff and provenance are committed as
[`glib-0.18.5-variant-str-iter.patch`](../native/ol_shell/patches/glib-0.18.5-variant-str-iter.patch)
and [`glib-0.18.5.json`](../native/ol_shell/patches/glib-0.18.5.json).
The provenance contains each original and patched file's SHA-256, the canonical
registry archive hash, source-tree hashes, official commit IDs and maintenance
scope. `scripts/verify_vendor_patches.py --fetch-upstream` downloads the original
archive, verifies its pinned hash, compares every original file, verifies the
actual local files and checks that their complete difference equals the reviewed
patch. The `.gitattributes` rule disables text conversion only for the vendor
tree; Windows checkouts preserve all original binary and text bytes.

The release SBOM retains the standard `pkg:cargo/glib@0.18.5` advisory identity
while marking the component as modified. It includes the exact local source-tree
hash, the original registry artifact as its ancestor, the backport diff and
official provenance. The original archive SHA-256 is
`233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`;
the reviewed patched tree SHA-256 is
`8e3f189a32a9abdfbaeeff42db1a520669d9789e40a56ca11422e4cbf64cdc3a`.
The tree digest's precise canonical format is recorded in the provenance and
SBOM properties; it is not represented as the registry archive's hash.

### Regression and ongoing advisory qualification

All **11 original upstream variant-iterator unit tests** passed in an optimized
build with this patch. A small first-party regression member then provides the
ongoing gate using the final shell lock, without adding upstream benchmark and
UI-test development dependencies to that graph. Its **five tests** passed at
optimization level 3 and cover forward/reverse iteration, `nth`, `nth_back`,
`last`, Unicode and long strings, borrowed string lifetime, empty/exhausted
arrays and index overflow boundaries.

The local runs used the actual installed GLib/GObject/GIO **2.84.4** shared
libraries. Development metadata was unavailable, so explicitly test-only
pkg-config descriptors supplied the verified runtime paths. This qualifies the
Rust FFI regressions; it does not qualify the full GTK/WebKit build or a real
window. `native_shell.yml` and the release binary builder install genuine GTK
and WebKit development packages, repeat the optimized regressions and verify
the source on their actual platforms. The native-shell workflow separately
builds the window and tests real window loading. Their evidence is required
before extending the scoped local result to full shell qualification.

**Cargo-audit omits local path packages.** Therefore a clean RustSec result
alone cannot qualify this backport. The required
`scripts/audit_vendor_advisories.py` gate verifies the original archive and
exact patch, then queries live OSV for registry **glib 0.18.5** during continuous,
weekly and release checks. It retains every raw response, source identity and
advisory disposition, including both returned records for the known
GHSA/RUSTSEC alias pair. Only those two exact advisory IDs are covered by this
verified source backport. Any new/unrecognized affected advisory, failed query,
invalid/incomplete response or failed source verification fails the gate.
Alias overlap alone does not authorize a new advisory ID. This is an explicit
source-based disposition; neither the original advisory nor the original
version is suppressed. Retained failures and focused tests cover the success,
new-advisory, query-failure and paginated-result cases.

### Upstream migration responsibility

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

One Link owns this temporary backport's maintenance. A supported upstream
release should replace it once the compatible stack is available and qualified.
The local source must never be relabeled as an official fixed release merely
to change a scanner result.

The project has no direct `VariantStrIter` use. The affected API can cause
undefined behavior and optimized-build crashes when invoked, as described by
the advisory. Absence of a direct first-party call does **not** establish
that vulnerable code is unreachable through dependencies. A separate Cargo
workspace also does not isolate the shipped UI from security consequences.
No advisory ID is ignored globally. The shell RustSec gate ignores exactly
RUSTSEC-2024-0370, for the reason recorded above. The source fix addresses the specified
iterator defect; the original medium advisory remains visible in the live
ancestor query. The `proc-macro-error` maintenance warning is still open.
These scoped results **do not grant complete production qualification to the
Linux shell**. Release review must assess full platform evidence, any new
advisories, the maintenance warning and the replacement plan before claiming
that qualification.

Linux WebKitGTK build prerequisites belong in the standalone binary builder,
where the shell is compiled. The independent native Python-wheel builders do
not need the GTK stack. Installing those prerequisites proves neither that the
window launches correctly nor that its upstream warnings are resolved; the
separate native-window runtime job supplies launch evidence.
