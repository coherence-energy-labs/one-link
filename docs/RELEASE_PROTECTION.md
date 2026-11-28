# Release and CI-gate protection

Prepared 2026-11-25. This records which protections live in the repository
and which ones only repository settings can provide. It also gives the exact
settings payloads for the maintainer to apply. **None of the settings below
has been applied.** Applying them is a maintainer action.

Read-only state observed on 2026-11-25 (`gh api`):

- `coherence-energy-labs/one-link` is public (repository id `1241721690`), in
  an organization on the `free` plan.
- One ruleset is active: `default-branch-protection` (id `20516627`, target
  `branch`, `~DEFAULT_BRANCH`). It requires one approving review, dismisses
  stale reviews on push, allows merge, squash and rebase merges, has no bypass
  actors, and requires ten status checks.
- There is **no tag ruleset.**
- The only environment is `github-pages`. There is **no `release` environment.**

## 1. Why YAML alone cannot protect a release

`release.yml` runs on `push: tags: v*`. GitHub runs the copy of `release.yml`
**in the tagged commit**. Anyone who can create or move a `v*` tag therefore
chooses the release workflow that runs, including one with every quality,
reproducibility and audit gate deleted. The Sigstore identity of that run is
still `.github/workflows/release.yml@refs/tags/vX`, so signatures and
provenance from a gutted workflow verify exactly like honest ones.

A YAML key cannot protect itself. `environment: release`, now set on the
`sign` and `publish` jobs, is part of the same tagged tree, so a hostile
tagged commit can delete it. Only settings stored outside the Git tree
constrain this:

1. A **tag ruleset** decides who may create, move or delete `v*` tags, and
   therefore who may select the release workflow at all.
2. The **`release` environment's protection rules** decide whether a job that
   names the environment may start: required reviewers, and a deployment
   policy that admits only `v*` tag refs. The second rule stops a
   `workflow_dispatch` run from a branch from reaching the signing or
   publishing job.

The two settings complement each other. The tag ruleset is the primary
control. The environment adds a human approval to every honest release, and
it will protect any environment-scoped secret added later. The signing
certificate does not record the deployment environment, so verifiers cannot
require it. That is why the tag ruleset cannot be skipped.

### What the YAML change does today

`sign` and `publish` now declare `environment: release`. GitHub creates an
environment named in a workflow on first use, without protection rules, in a
public repository. So this key cannot break a release before the settings
below exist. It becomes a gate the moment they are applied.

## 2. Tag ruleset: settings payload

Restrict creation, update (moving) and deletion of `refs/tags/v*`, and block
force updates. Only the built-in Repository admin role may bypass it.

`release-tags-ruleset.json`:

```json
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": {
    "ref_name": { "include": ["refs/tags/v*"], "exclude": [] }
  },
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
```

```bash
gh api --method POST repos/coherence-energy-labs/one-link/rulesets \
  --input release-tags-ruleset.json
```

`actor_id` 5 with `actor_type` `RepositoryRole` is the built-in Repository
admin role. After creating the ruleset, confirm that the UI lists exactly
"Repository admin" as the bypass actor, and nothing else:

```bash
gh api repos/coherence-energy-labs/one-link/rulesets \
  --jq '.[] | select(.target == "tag") | {id, name, enforcement}'
gh api repos/coherence-energy-labs/one-link/rulesets/<id> \
  --jq '{conditions, rules: [.rules[].type], bypass_actors}'
```

The workflow token (`github-actions[bot]`) holds no admin role, so it cannot
bypass this ruleset. That holds independently of the `--verify-tag` refusal
already in `publish`, which a hostile tagged commit could delete.

## 3. `release` environment: protection settings

`release-environment.json`:

```json
{
  "wait_timer": 0,
  "prevent_self_review": true,
  "can_admins_bypass": false,
  "reviewers": [
    { "type": "User", "id": 0 }
  ],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
```

The reviewer `id` must be the numeric id of a person chosen by the maintainer:
`gh api users/<login> --jq .id`. A team works too:
`{ "type": "Team", "id": <team id> }`. The `0` is a deliberate non-value:
replace it before applying, then confirm the reviewer with the verification
command below.

```bash
gh api --method PUT repos/coherence-energy-labs/one-link/environments/release \
  --input release-environment.json
gh api --method POST \
  repos/coherence-energy-labs/one-link/environments/release/deployment-branch-policies \
  -f name='v*' -f type=tag
```

- `prevent_self_review: true` requires an approver other than the person who
  pushed the tag. With a single maintainer, that person can never approve. In
  that case set it to `false`: every release still needs a deliberate
  approval and still runs only from a `v*` tag.
- `can_admins_bypass: false` applies the approval to administrators too.
- The deployment policy admits only `v*` tag refs. A branch-dispatched run
  stops before `sign`.

Verify:

```bash
gh api repos/coherence-energy-labs/one-link/environments/release \
  --jq '{protection_rules, deployment_branch_policy, can_admins_bypass}'
gh api repos/coherence-energy-labs/one-link/environments/release/deployment-branch-policies \
  --jq '.branch_policies[] | {name, type}'
```

Also recommended: enable **release immutability** (Settings → General →
Releases). A published release's assets and tag then cannot be replaced
afterwards. The REST field for this setting was not verified while preparing
this document, so use the UI.

## 4. Native CI gates: what the repository now enforces

`scripts/native_ci_scope.py` decides whether the native correctness,
performance and shell matrices apply to a pull request, and whether the
required gate passes.

- **Representation.** Every changed path is applicable unless a reviewed
  inert rule proves that no job of that kind reads it. New and unknown paths
  run the work. The rules, and the reason for each, are in the script.
- **Trust.** A pull request is judged by the policy **as it exists at the
  PR's BASE revision**. Each workflow extracts that copy with
  `git show <base>:scripts/native_ci_scope.py` and runs it from
  `$RUNNER_TEMP`, never from the PR's tree. The running policy re-derives
  which revision is trusted and verifies its own bytes against that revision.
  The proof records `policy_revision`, `policy_source` and
  `policy_script_sha256`, and the gate job checks them independently.
- **Self-modification.** A PR that changes `scripts/native_ci_scope.py` is
  always applicable, under the base policy. It may add a job to an aggregate
  only if that job succeeds. It can never remove a job the base policy
  requires.
- **Bootstrap.** When the base revision predates the policy (the PR that
  introduces it), the candidate's copy runs and is recorded as
  `policy_source: bootstrap`. It can skip nothing, because its own file is part
  of the diff.
- **Pushes and manual runs** always run the native work, using the tested
  checkout's own policy. The push `paths:` filters were removed. GitHub's
  filter sees at most 300 changed files and uses its own glob dialect, so it
  cannot express "applicable unless proven inert".

### What a pull request can still do

**A pull request can still edit the workflow YAML itself.** For
`pull_request` events GitHub runs the workflow files from the PR's merge
commit. So a PR can rewrite the loader to execute its own policy, change the
gate job, or add a job named `native correctness gate` to any workflow file.
Required status checks match by context name and app (`integration_id`
15368, GitHub Actions), not by workflow file. The base-revision policy closes
the "edit the script, not the YAML" route. It cannot close the YAML route.
The remaining defences are:

1. **Required review.** This is in force today: one approving review, stale
   approvals dismissed on push. A reviewer must treat any change under
   `.github/workflows/` or to `scripts/native_ci_scope.py` as a change to the
   gates themselves. A `.github/CODEOWNERS` entry for those paths, with
   `require_code_owner_review: true` in `default-branch-protection`, makes
   that review mandatory for a named owner. Both are maintainer changes.
2. **Ruleset-level required workflows.** A ruleset rule of type `workflows`
   runs the named workflow files from a fixed ref of a fixed repository, not
   from the PR. A PR cannot edit those files. This is an organization-ruleset
   feature, and plan availability for this `free` organization was not
   verified; the API refuses if it is unavailable. Payload, to be applied by
   the maintainer:

```json
{
  "name": "required-native-gates",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "repository_id": { "repository_ids": [1241721690] },
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    {
      "type": "workflows",
      "parameters": {
        "do_not_enforce_on_create": false,
        "workflows": [
          { "repository_id": 1241721690, "path": ".github/workflows/native_build.yml", "ref": "refs/heads/master" },
          { "repository_id": 1241721690, "path": ".github/workflows/native_bench_gate.yml", "ref": "refs/heads/master" },
          { "repository_id": 1241721690, "path": ".github/workflows/native_shell.yml", "ref": "refs/heads/master" },
          { "repository_id": 1241721690, "path": ".github/workflows/security.yml", "ref": "refs/heads/master" }
        ]
      }
    }
  ]
}
```

```bash
gh api --method POST orgs/coherence-energy-labs/rulesets --input required-native-gates.json
```

## 5. Independent rebuild coverage of release artifacts

Each of these is rebuilt by `release.yml` on a fresh runner of the same OS
image and compared with the artifact selected for publication. `sign`, and
through it `publish`, require every comparison.

| Artifact | Job | Comparison |
| --- | --- | --- |
| `native-wheel-linux-x86_64` | `verify_reproducibility` (ubuntu-latest) | exact bytes |
| `native-wheel-linux-arm64` | `verify_reproducibility_linux_arm64` (ubuntu-24.04-arm) | exact bytes |
| pure-Python wheel `one_link-*-py3-none-any.whl` | `verify_reproducibility_python` (ubuntu-latest) | exact bytes |
| sdist `one_link-*.tar.gz` | `verify_reproducibility_python` | every member's name, order, type, mode, size, link target and content. **Not the archive bytes.** |

The sdist's archive bytes are not reproducible with the current backend. Two
builds of one commit on 2026-11-25 (setuptools 84.2.1, build 1.5.0, the build
job's `SOURCE_DATE_EPOCH` and `PYTHONHASHSEED`) produced an identical wheel.
The two sdists had identical members, but different gzip header MTIME values
(the build time) and different tar member mtimes (checkout and build times):
setuptools does not apply `SOURCE_DATE_EPOCH` to sdists. A byte-level sdist
claim would need a backend that writes deterministic archive metadata, or a
deterministic repack in the build job. Both change the release build, and
neither was made here.

**Artifacts with no independent rebuild:**

- native wheels `native-wheel-windows-x86_64`, `native-wheel-windows-arm64`
  and `native-wheel-macos-arm64`;
- all five standalone binary archives (`one-link-linux-x86_64.zip`,
  `one-link-linux-arm64.zip`, `one-link-macos-arm64.zip`,
  `one-link-windows-x86_64.zip`, `one-link-windows-arm64.zip`);
- the derived files `sbom.cdx.json`, `UPDATE_MANIFEST.json` and `SHA256SUMS`,
  which hash the artifacts above, and the Sigstore bundles, which are
  non-deterministic by design.


## 2026-11-26 application checkpoint

The version-tag ruleset (28202878) and release environment described above
have now been applied through the authorized repository administrator and
read back: tag-only v* deployment, required reviewer CoherenceEnergyLabs,
self-review prohibited and environment administrator bypass disabled. The
existing default-branch ruleset (20516627) was unchanged. The admin-only
tag bypass remains as documented. No tag, release or PR approval was created
by this action. See the Phase Zero checkpoint for the retained evidence
digest and limits. This does not qualify a release or demonstrate enforcement
of the environment by every possible tagged workflow.
