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
| Native window shell | `native/ol_shell/Cargo.toml`, `native/ol_shell/Cargo.lock` | RustSec vulnerabilities fail the gate; all upstream warnings remain in output and JSON, with the limitations below |
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

The local post-update scans found no known vulnerabilities in the root Python
graph, rendezvous subset, npm test graph, or any of the three Cargo graphs.
The main native and fuzz RustSec reports also contained no warnings. The shell
report retained the two upstream warnings below. The RustSec database used for
that shell result contained 1,567 advisories at commit
`10db6998b5d74ec438bcf0763125bd425a068a8f`. Future CI scans query the then-current
database and may correctly produce a different result.

## Open Linux shell warnings

| Warning | Resolved package | Upstream remedy and current limit |
| --- | --- | --- |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), unsound `VariantStrIter` | `glib 0.18.5` | The advisory specifies a fix in **glib ≥0.20.0**. The selected GTK 0.18 stack remains below that boundary. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html), unmaintained dependency | `proc-macro-error 1.0.4` | No patched version is listed. An upstream migration or separately reviewed replacement is needed. |

At review, the manifests for [tao 0.37.3](https://docs.rs/crate/tao/0.37.3)
and [wry 0.57.3](https://docs.rs/crate/wry/0.57.3) still required GTK 0.18,
despite [GTK 0.19](https://docs.rs/crate/gtk/0.19.0) having moved to a newer
glib family. Simply updating this project's tao/wry version bounds therefore
does not establish that the warnings are resolved. Forcing a transitive major
version or substituting a fork without a compatible upstream migration would
require additional API and platform qualification.

The project has no direct `VariantStrIter` use. That fact does **not** establish
that vulnerable code is unreachable through dependencies. A separate Cargo
workspace also does not isolate the shipped UI from security consequences.
No advisory IDs are globally ignored. The shell gate deliberately distinguishes
known vulnerabilities from these retained warnings, and **does not grant
warning-free or production qualification to the Linux shell**. Release review
must reassess both warnings, their platform applicability and the replacement
plan before claiming that qualification.

Linux WebKitGTK build prerequisites belong in the standalone binary builder,
where the shell is compiled. The independent native Python-wheel builders do
not need the GTK stack. Installing those prerequisites proves neither that the
window launches correctly nor that its upstream warnings are resolved; the
separate native-window runtime job supplies launch evidence.
