# Required repository checks

The desired default-branch policy is recorded in
[`repository-policy.json`](../.github/repository-policy.json). This is a
configuration proposal. A fresh authenticated GitHub API readback is required
to establish that the server enforces it.

The proposed policy requires one approving review, dismisses stale approvals
after a push, resolves review threads before merging, and requires the branch
to be up to date with every required check. It preserves the existing ban on
deletion and force pushes, default-branch scope, empty bypass list, and the
existing pull-request parameters. If a current ruleset has stronger review
requirements or additional checks, the preparation script retains them.

| Required check context | What must finish successfully |
| --- | --- |
| `continuous acceptance gate` | Native runtime builds; full Python suites; Chromium and Firefox gates; every explicitly selected live-daemon case on Linux and Windows; native picker probes on Linux, Windows and macOS |
| `ruff (gate)` | Python correctness lint |
| `mypy (gate)` | The canonical Windows type-checking lane |
| `browser JavaScript static contracts + dependency audit` | Generated owner and peer UI consistency, exact JavaScript dependency audit and static contracts |
| `Gitleaks full-history scan` | The configured redacted full-history scan |
| `pip-audit + bandit + sbom` | Locked Python dependency checks, workflow/source checks and SBOM generation |
| `RustSec cargo-audit` | Native workspace and fuzz locks with warnings treated as failures; shell vulnerability gate with warnings retained; live registry-ancestor advisories for exact verified vendor backports |
| `native correctness gate` | Applicable Rust workspace and Python binding matrices, or an explicitly verified not-applicable source diff |
| `native performance gate` | Applicable complete paired native benchmark study and its uncertainty-aware decision, or an explicitly verified not-applicable source diff |
| `native shell gate` | Applicable Linux, macOS and Windows shell builds, exact vendor verification, compiled UI pin and real-window page-load smoke checks; optimized GLib regression on Linux; or an explicitly verified not-applicable source diff |

Every context is defined by a workflow that runs on every pull request without
a path filter. The acceptance gate explicitly fails if an upstream lane is
failed, skipped or cancelled. It does not turn a skipped matrix into a passing
branch check. The three native gates use the complete source diff and preserve
the event base/head and exact tested merge identity. An absent or failed
applicability proof fails the gate; an applicable change requires every selected
matrix job to succeed. The shell scope includes its independent Cargo workspace
and vendored dependencies, served web assets, owner authoring sources and
builder, smoke/build helpers, provenance/advisory verifiers, attributes, shared
Cargo/toolchain configuration and workflow inputs. See the explicit policies in
[`native_ci_scope.py`](../scripts/native_ci_scope.py). Manual native runs always
execute the work. Not-applicable means only that the recorded source diff is
outside that policy; it does not qualify a changed external runner or OS library.

GitHub Actions integration ID `15368` was observed on the audited commit's check
runs and is the desired producer binding for all ten contexts. A newly added
context must itself be observed on the exact intended candidate before the
proposal is activated. Its presence in this file is not evidence of a completed
hosted run or an enforced repository rule. A successful native shell lane
establishes build/pin/window-fetch behavior; it does not establish correct page
rendering or a fully usable application.

## Prepare a reviewable update

An administrator first saves a complete current ruleset response, including
its bypass actors. The following commands only read the server and prepare
local files:

```sh
gh api repos/coherence-energy-labs/one-link/rulesets/20516627 > ruleset-before.json
python scripts/repository_policy.py --observed ruleset-before.json \
  --proposal ruleset-proposal.json --report ruleset-review.json
```

Review the complete `ruleset-proposal.json` against the original response and
verify that the named checks have reported on the exact intended candidate.
The script refuses a different ruleset and conflicting check producers. It
does not add bypass actors, remove stronger requirements, or contact GitHub.
This proposal does not change the separate `v*` tag ruleset.

An administrator who has authorized the reviewed update can apply the complete
body through the [GitHub ruleset API](https://docs.github.com/en/rest/repos/rules#update-a-repository-ruleset):

```sh
gh api --method PUT repos/coherence-energy-labs/one-link/rulesets/20516627 \
  --input ruleset-proposal.json > ruleset-update-response.json
gh api repos/coherence-energy-labs/one-link/rulesets/20516627 > ruleset-after.json
python scripts/repository_policy.py --observed ruleset-after.json \
  --report ruleset-enforcement.json
```

Keep the before/proposal/after responses, exact check-run evidence, and the
enforcement report with the release review. A zero exit code in verification
mode means the supplied readback meets the configured minimum; it does not
authenticate the origin or freshness of a supplied JSON file. Only a current
authorized server read provides that evidence.
