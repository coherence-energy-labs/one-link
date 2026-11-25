"""v0.7.2 supply-chain gate tests (audit finding C).

These tests don't run pip-audit / bandit / cyclonedx for real (they
need internet + heavy install); they pin the *configuration* surface
so a future PR can't silently drop a security gate.

Pin:
  - pyproject.toml declares a `security` extra with all locked tools
    (pip-audit, bandit, cyclonedx-bom, uv, zizmor).
  - pyproject.toml has a [tool.bandit] section with `exclude_dirs`
    that skips tests while production code and executable automation scripts
    are fully scanned.
  - The bandit `skips` list contains only documented exemptions
    with a justification (B101/B404/B603 for assert + subprocess).
  - scripts/lock_deps.py and scripts/gen_sbom.py exist and are
    syntactically importable (so the GH Action can invoke them).
  - .github/workflows/security.yml exists and runs the four gates
    (pip-audit, bandit, cyclonedx-bom, lockfile drift check).
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


_REPO = Path(__file__).resolve().parent.parent
_WORKFLOWS = _REPO / ".github" / "workflows"


def _read_pyproject() -> dict:
    text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib.loads(text)
    import tomli  # type: ignore[import-not-found]
    return tomli.loads(text)


def _read_lock() -> dict:
    text = (_REPO / "uv.lock").read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib.loads(text)
    import tomli  # type: ignore[import-not-found]
    return tomli.loads(text)


def _workflow_documents() -> list[tuple[Path, dict]]:
    documents: list[tuple[Path, dict]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        assert isinstance(loaded, dict), f"{path.name}: workflow root must be a mapping"
        documents.append((path, loaded))
    return documents


def _assert_no_duplicate_yaml_keys(node: object, *, location: str) -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            assert isinstance(key_node, ScalarNode), (
                f"{location}: complex mapping keys are not supported"
            )
            key = key_node.value
            assert key not in seen, f"{location}: duplicate YAML key {key!r}"
            seen.add(key)
            _assert_no_duplicate_yaml_keys(
                value_node,
                location=f"{location}.{key}",
            )
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            _assert_no_duplicate_yaml_keys(
                child,
                location=f"{location}[{index}]",
            )


# ─── pyproject.toml: security extras ───────────────────────────────

def test_pyproject_declares_security_extras():
    p = _read_pyproject()
    extras = p["project"]["optional-dependencies"]
    assert "security" in extras, (
        "pyproject [project.optional-dependencies] must declare a"
        " `security` group covering pip-audit / bandit / cyclonedx-bom /"
        " uv (audit finding C, supply-chain gates)."
    )


def test_security_extras_includes_each_audit_tool():
    p = _read_pyproject()
    sec = p["project"]["optional-dependencies"]["security"]
    names = {dep.split(">=")[0].split("==")[0].split("[")[0].lower() for dep in sec}
    assert "pip-audit" in names
    assert "bandit" in names
    # cyclonedx-bom (the package) installs the cyclonedx_py module.
    assert "cyclonedx-bom" in names or "cyclonedx-py" in names
    assert "uv" in names
    assert "zizmor" in names


def test_dev_extra_includes_workflow_parser():
    p = _read_pyproject()
    dev = p["project"]["optional-dependencies"]["dev"]
    names = {dep.split(">=")[0].split("==")[0].split("[")[0].lower() for dep in dev}
    assert "pyyaml" in names


def test_uv_lock_registry_artifacts_are_hash_pinned_https():
    lock = _read_lock()
    assert lock["version"] == 1
    assert lock["revision"] >= 3
    assert lock["requires-python"] == ">=3.11"

    registry_packages = 0
    for package in lock["package"]:
        source = package.get("source", {})
        registry = source.get("registry")
        if registry is None:
            continue
        registry_packages += 1
        assert registry.startswith("https://"), package["name"]
        artifacts = []
        if package.get("sdist"):
            artifacts.append(package["sdist"])
        artifacts.extend(package.get("wheels", []))
        assert artifacts, f"{package['name']}: registry package has no locked artifact"
        for artifact in artifacts:
            assert artifact["url"].startswith("https://"), package["name"]
            digest = artifact.get("hash", "")
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), (
                f"{package['name']}: missing/invalid artifact hash"
            )
    assert registry_packages >= 100


def test_uv_lock_native_dependency_is_local_and_version_aligned():
    lock = _read_lock()
    packages = {package["name"]: package for package in lock["package"]}
    native = packages["one-link-native"]
    assert native["source"] == {"directory": "native"}
    # Alignment means the LOCKED native version is the PEP 440 normalization
    # of the real project version -- derive it, so a release bump cannot
    # leave this asserting a stale literal while claiming alignment.
    from packaging.version import Version

    from one_link import __version__ as core_version

    assert Version(native["version"]) == Version(core_version)


# ─── pyproject.toml: [tool.bandit] ─────────────────────────────────

def test_pyproject_has_bandit_config():
    p = _read_pyproject()
    bandit = p.get("tool", {}).get("bandit")
    assert bandit is not None, "pyproject must include a [tool.bandit] section"


def test_bandit_excludes_tests_but_scans_automation_scripts():
    p = _read_pyproject()
    excludes = p["tool"]["bandit"]["exclude_dirs"]
    assert "tests" in excludes
    assert "scripts" not in excludes


def test_bandit_skips_are_only_documented_exemptions():
    """Each skip is allowed only if listed below; new skips need
    justification. Audit doc treats this as a security boundary —
    don't widen silently."""
    p = _read_pyproject()
    skips = set(p["tool"]["bandit"].get("skips", []))
    # Each entry below has a documented reason in pyproject.toml.
    # B104 (2026-06-04): hardcoded bind to 0.0.0.0 IS the intentional,
    # documented `--lan` feature (binding all interfaces is how a phone
    # on your Wi-Fi reaches the UI); justified in pyproject.toml.
    allowed = {"B101", "B404", "B603", "B104"}
    extra = skips - allowed
    assert not extra, (
        f"bandit skips include undocumented entries: {sorted(extra)}. "
        "Add them to the allowed set with a justification comment."
    )


# ─── scripts ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["lock_deps.py", "gen_sbom.py"])
def test_security_scripts_exist_and_parse(name: str):
    p = _REPO / "scripts" / name
    assert p.is_file(), f"scripts/{name} missing"
    # Must parse — catches broken edits before CI runs.
    ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_lock_deps_script_uses_universal_uv_lock_and_frozen_export():
    text = (_REPO / "scripts" / "lock_deps.py").read_text(encoding="utf-8")
    assert '"uv", "lock"' in text
    assert '"uv", "export"' in text
    assert '"--frozen"' in text


def test_gen_sbom_script_invokes_cyclonedx():
    text = (_REPO / "scripts" / "gen_sbom.py").read_text(encoding="utf-8")
    assert "cyclonedx_py" in text


# ─── .github/workflows/security.yml ────────────────────────────────

def test_security_workflow_exists():
    p = _REPO / ".github" / "workflows" / "security.yml"
    assert p.is_file(), (
        ".github/workflows/security.yml missing — supply-chain gates"
        " are unwired in CI."
    )


def test_security_workflow_runs_pip_audit():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "pip_audit" in text or "pip-audit" in text
    assert "uv export --frozen --all-extras --all-groups" in text
    assert "--no-extra native" in text
    assert "--no-deps --disable-pip" in text
    assert "--vulnerability-service osv" in text


def test_security_workflow_runs_bandit():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "bandit" in text
    assert "-r src/one_link scripts" in text


def test_security_workflow_hard_gates_pedantic_zizmor():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    gate_lines = [line for line in text.splitlines() if "--pedantic" in line]
    assert gate_lines
    assert "--strict-collection .github" in text
    assert all("|| true" not in line for line in gate_lines)


def test_security_workflow_generates_sbom():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "gen_sbom.py" in text or "cyclonedx" in text


def test_security_workflow_uploads_artifacts():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    # The supply-chain artifact bundle must include at least the SBOM
    # and the audit JSONs so consumers can re-verify.
    assert "upload-artifact" in text
    assert "sbom" in text.lower()
    assert "pip-audit.json" in text
    assert "pip-audit-osv.json" in text
    assert "bandit.json" in text


def test_security_workflow_runs_on_schedule():
    """Weekly schedule catches newly-published OSV records against
    deps that haven't otherwise changed in the repo."""
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "schedule:" in text
    assert "cron:" in text


def test_every_workflow_parses_without_duplicate_keys():
    paths = sorted(_WORKFLOWS.glob("*.yml"))
    assert len(paths) >= 16
    for path in paths:
        node = yaml.compose(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        assert node is not None, f"{path.name}: empty workflow"
        _assert_no_duplicate_yaml_keys(node, location=path.name)


def test_every_remote_action_is_immutable_sha_pinned():
    use_pattern = re.compile(r"^\s*-\s+uses:\s*([^\s#]+)", re.MULTILINE)
    seen = 0
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        for target in use_pattern.findall(path.read_text(encoding="utf-8")):
            if target.startswith("./"):
                continue
            seen += 1
            action, separator, ref = target.rpartition("@")
            assert separator and "/" in action, f"{path.name}: invalid action {target}"
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"{path.name}: action is not commit-SHA pinned: {target}"
            )
    assert seen >= 40


def test_checkout_never_persists_job_credentials():
    checkout_count = 0
    for path, workflow in _workflow_documents():
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    checkout_count += 1
                    assert step.get("with", {}).get("persist-credentials") == "false", (
                        f"{path.name}: checkout must set persist-credentials: false"
                    )
    assert checkout_count >= 20


def test_write_scoped_jobs_execute_only_first_party_actions():
    write_jobs: list[tuple[str, str]] = []
    for path, workflow in _workflow_documents():
        workflow_permissions = workflow.get("permissions", {})
        for job_name, job in workflow.get("jobs", {}).items():
            permissions = job.get("permissions", workflow_permissions)
            if not isinstance(permissions, dict) or permissions.get("contents") != "write":
                continue
            write_jobs.append((path.name, job_name))
            for step in job.get("steps", []):
                action = str(step.get("uses", ""))
                if action:
                    assert action.startswith("actions/"), (
                        f"{path.name}:{job_name}: third-party action has write token: {action}"
                    )
    # EXACT allowlist: granting a job write authority must be a deliberate,
    # reviewed act, not something that accretes. Both entries are bounded by
    # dedicated tests below.
    #   release.yml:publish        -- the tagged, reproducible, signed channel.
    #   publish_rolling.yml:publish -- refreshes the `auto-latest` prerelease
    #     the website's download button resolves. It exists because continuous
    #     builds correctly hold no release authority, which had frozen the
    #     public download on a months-old commit while every fix landed on
    #     master unseen; shipping users stale binaries is not a safer default.
    assert write_jobs == [
        ("publish_rolling.yml", "publish"),
        ("release.yml", "publish"),
    ]


def test_rolling_publisher_is_deliberate_gated_and_unsigned():
    """The rolling publisher may refresh a prerelease, and nothing more.

    It holds write authority, so its blast radius is pinned here rather than
    left to reviewer memory: never automatic, never publishing a commit CI
    rejected, never claiming the signed-release tier.
    """
    workflows = dict(_workflow_documents())
    path = _WORKFLOWS / "publish_rolling.yml"
    workflow = workflows[path]
    text = path.read_text(encoding="utf-8")

    # Deliberate: dispatch only. A push trigger would make the public download
    # move on every commit, which is exactly what the continuous-build policy
    # forbids.
    triggers = workflow[True] if True in workflow else workflow["on"]
    assert set(triggers) == {"workflow_dispatch"}

    # Gated: it must verify the gating workflows concluded successfully for
    # the exact commit before the public download moves.
    assert "conclusion" in text and "refusing to publish" in text
    for gate in ('"tests"', '"security"', '"auto-build standalone binary"'):
        assert gate in text, f"rolling publisher does not require {gate}"

    # Unsigned tier, honestly labelled: prerelease, no code-signing primitive,
    # and it must not touch a tagged release.
    assert "--prerelease" in text
    # Forbid INVOKING a signing tool, not naming one: the release notes must
    # stay free to say "this is not a Sigstore-signed release", which is the
    # very disclaimer that keeps the tier honest.
    for signing_primitive in ("codesign", "signtool", "notarytool", "cosign", "sigstore"):
        invocation = re.compile(
            rf"(?mi)^\s*(?:-\s*)?(?:run:\s*)?{signing_primitive}\b[^:]*$"
        )
        assert not invocation.search(text), (
            f"rolling publisher appears to invoke {signing_primitive}"
        )
        assert f"uses: {signing_primitive}" not in text.lower()
    assert "auto-latest" in text
    assert "gh release create v" not in text


def test_rolling_publisher_never_empties_the_release_before_uploading():
    """The download button must never see a release with no assets.

    The first version of this workflow deleted every existing asset and THEN
    uploaded the new set. An upload that failed part-way -- a network blip on a
    2 GB transfer -- would leave the prerelease empty and every website
    /download/* route returning 404, which is the exact outage the workflow
    exists to prevent. Upload (with --clobber) must therefore come first, and
    the prune of no-longer-produced assets second.
    """
    text = (_WORKFLOWS / "publish_rolling.yml").read_text(encoding="utf-8")
    upload_at = text.find("gh release upload")
    delete_at = text.find("gh release delete-asset")
    assert upload_at != -1, "the publisher must upload the new asset set"
    assert delete_at != -1, "the publisher must prune assets it no longer builds"
    assert upload_at < delete_at, (
        "publish_rolling.yml deletes assets before uploading: a failed upload "
        "would strand the public download with an empty release"
    )
    # --clobber is what makes upload-first correct: without it, uploading over
    # an existing asset name fails and the refresh silently keeps stale bytes.
    assert "--clobber" in text


def test_workflows_use_frozen_uv_and_explicit_root_for_native_builds():
    sync_count = 0
    nested_maturin_workflows = set()
    for path, workflow in _workflow_documents():
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.search(r"\buv sync\b", line):
                sync_count += 1
                assert "--frozen" in line, f"{path.name}: non-frozen uv sync: {line}"
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                run = str(step.get("run", ""))
                # Builders may set cwd in YAML or enter either the candidate
                # or separate baseline workspace explicitly inside the shell.
                native_transition = re.search(
                    r"(?m)^\s*cd\s+(?:[\"']?[^\n]*/)?native[\"']?\s*$", run
                )
                nested_native = step.get("working-directory") == "native" or (
                    native_transition is not None
                    and native_transition.start() < run.find("maturin")
                )
                if nested_native and "maturin" in run:
                    nested_maturin_workflows.add(path.name)
                    assert any(command in run for command in (
                        "uv run --project .. --frozen", "uv run --project .. --no-sync")), (
                        f"{path.name}: nested maturin build would discover native/pyproject "
                        "instead of the root uv.lock"
                    )
                    if "uv run --project .. --no-sync" in run:
                        earlier = job["steps"][:job["steps"].index(step)]
                        assert any("uv sync --frozen" in item.get("run", "") for item in earlier), (
                            f"{path.name}: no-sync requires an earlier frozen environment install"
                        )
    assert sync_count >= 15
    # Check every discovered invocation, plus the important explicit builders.
    # The acceptance matrix now consumes one source-bootstrap wheel per OS;
    # counting old duplicated builds would reject that supported design.
    assert {"release.yml", "native_build.yml", "native_bench_gate.yml"} <= nested_maturin_workflows
    acceptance = dict(_workflow_documents())[_WORKFLOWS / "full_suite_and_e2e.yml"]
    commands = "\n".join(step.get("run", "")
                         for step in acceptance["jobs"]["native_runtime"]["steps"])
    assert "python scripts/bootstrap_source.py --report" in commands


def test_windows_native_binding_uses_shell_matching_its_commands():
    workflows = dict(_workflow_documents())
    binding = workflows[_WORKFLOWS / "native_build.yml"]["jobs"]["python_binding"]
    assert "windows-latest" in binding["strategy"]["matrix"]["os"]
    assert binding["defaults"]["run"]["shell"] == "bash"
    assert any("\\\n" in str(step.get("run", "")) for step in binding["steps"])


def test_rust_toolchains_and_cargo_installs_are_reproducibly_pinned():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(_WORKFLOWS.glob("*.yml"))
    )
    assert "rustup toolchain install stable" not in combined
    assert not re.search(r"rustup toolchain install nightly(?:\s|$)", combined)
    assert "rustup toolchain install 1.96.0" in combined
    assert "nightly-2026-05-13" in combined
    for line in combined.splitlines():
        if "cargo install" in line and not line.lstrip().startswith("#"):
            assert "--locked" in line and "--version" in line, line


def test_windows_arm_openssl_uses_pinned_vcpkg_baseline():
    commit = "cd61e1e26a038e82d6550a3ebbe0fbbfe7da78e3"
    for name in ("auto_build.yml", "release.yml"):
        text = (_WORKFLOWS / name).read_text(encoding="utf-8")
        assert f"VCPKG_COMMIT: {commit}" in text
        assert "git -C $vcpkg checkout --detach $env:VCPKG_COMMIT" in text
        assert '"$vcpkg\\bootstrap-vcpkg.bat" -disableMetrics' in text
        assert "vcpkg commit mismatch" in text
    auto = (_WORKFLOWS / "auto_build.yml").read_text(encoding="utf-8")
    assert f"vcpkg-openssl-arm64-windows-static-v3-{commit}" in auto


def test_dependabot_covers_every_dependency_ecosystem():
    text = (_REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for ecosystem in ("uv", "cargo", "npm", "github-actions"):
        assert f'package-ecosystem: "{ecosystem}"' in text
    assert 'directory: "/native/fuzz"' in text


def test_release_workflow_keeps_job_token_out_of_third_party_actions():
    """Release mutation uses the hosted runner's audited GitHub CLI.

    A marketplace release action would receive ``contents: write`` and
    therefore sit directly on the artifact-publication trust boundary.
    """
    text = (_REPO / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert "softprops/action-gh-release" not in text
    assert "gh release upload" in text
    assert "GH_TOKEN: ${{ github.token }}" in text


def test_tagged_release_artifact_contract_and_complete_bundle_staging():
    text = (_WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "pattern: native-wheel-*" in text
    assert "pattern: binary-*" in text
    assert text.count("merge-multiple: true") >= 2
    assert "scripts/package_standalone_bundle.py" in text
    # The matrix carries the platform-specific onedir root (including the
    # macOS .app layout); the packaging invocation must consume that exact
    # value instead of hard-coding one platform's path.
    assert 'bundle_path: dist/one-link' in text
    assert 'bundle_path: dist/one-link.app' in text
    assert '--bundle "${BUNDLE_PATH}"' in text
    assert "bundle_executable: one-link.exe" in text
    assert "cp dist/one-link.exe" not in text
    assert "if: matrix.os == 'windows-latest'" not in text
    assert "Swatinem/rust-cache" not in text


def test_tagged_release_refuses_version_mismatched_tags():
    text = (_WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert 'project_version="$(python - <<\'PY\'' in text
    assert '"$RELEASE_REF_TYPE" != "tag"' in text
    assert 'tag_version="${RELEASE_REF_NAME#v}"' in text
    assert '"$tag_version" != "$project_version"' in text
    assert "Release tag $RELEASE_REF_NAME does not match pyproject version" in text
    assert "--verify-tag" in text

    reproducible = (_WORKFLOWS / "reproducible_release.yml").read_text(
        encoding="utf-8"
    )
    assert '"$RELEASE_REF_TYPE" != "tag"' in reproducible
    assert '"${RELEASE_REF_NAME#v}" != "$project_version"' in reproducible


def test_tagged_release_separates_signing_from_release_mutation():
    workflows = dict(_workflow_documents())
    release = workflows[_WORKFLOWS / "release.yml"]
    sign = release["jobs"]["sign"]
    publish = release["jobs"]["publish"]
    assert sign["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert publish["permissions"] == {"contents": "write"}
    assert set(publish["needs"]) == {"release_quality_gate", "build", "sign", "verify_reproducibility"}
    publish_actions = [
        step["uses"]
        for step in publish["steps"]
        if "uses" in step
    ]
    assert publish_actions
    assert all(action.startswith("actions/") for action in publish_actions)
    assert any(
        step.get("with", {}).get("name") == "signed-release-dist"
        for step in publish["steps"]
    )


def test_continuous_builds_are_ephemeral_and_have_no_release_authority():
    workflows = dict(_workflow_documents())
    for name in ("auto_build.yml", "auto_build_macos_intel.yml"):
        workflow = workflows[_WORKFLOWS / name]
        assert workflow["permissions"] == {"contents": "read"}
        text = (_WORKFLOWS / name).read_text(encoding="utf-8").lower()
        assert "gh release" not in text
        assert "gh_token:" not in text
        assert "contents: write" not in text
        assert "id-token: write" not in text
        assert "attestations: write" not in text
        assert "secrets." not in text
        for signing_primitive in ("codesign", "signtool", "notarytool"):
            assert signing_primitive not in text

        uploads = []
        for job_name, job in workflow["jobs"].items():
            permissions = job.get("permissions", workflow["permissions"])
            assert permissions.get("contents") == "read", job_name
            # `if: always()` may preserve partial diagnostic artifacts, but it
            # must never sit on a release/signing authority path.
            if "always()" in str(job.get("if", "")):
                assert permissions == {"contents": "read"}
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                    uploads.append(step)
        assert uploads, f"{name}: continuous build retained no CI evidence"
        for upload in uploads:
            retention = upload.get("with", {}).get("retention-days")
            assert retention is not None and 1 <= int(retention) <= 30, (
                f"{name}: CI artifact is not explicitly ephemeral: {upload}"
            )

    intel = workflows[_WORKFLOWS / "auto_build_macos_intel.yml"]
    assert set(intel["jobs"]) == {"build-intel"}
    intel_text = (_WORKFLOWS / "auto_build_macos_intel.yml").read_text(
        encoding="utf-8"
    )
    assert "schedule:" not in intel_text
    assert "runs-on: macos-13" not in intel_text
    assert "runs-on: [self-hosted, macOS, X64, one-link-intel]" in intel_text


def test_rolling_archives_have_noncolliding_archive_sidecars():
    text = (_WORKFLOWS / "auto_build.yml").read_text(encoding="utf-8")
    # The in-archive member manifest and the archive-level sidecar must stay
    # distinct files. The manifest is no longer written inline here -- it goes
    # through scripts/write_bundle_manifest.py, the single writer that emits
    # the format the product actually parses. The inline version wrote classic
    # sha256sum output with no header, so every bundle built here failed
    # validate_installed_bundle and the in-app updater was dead. What this
    # test cares about is unchanged: the manifest lands INSIDE the final bundle,
    # the .zip.sha256 sidecar is separate, and neither name collides.
    assert "scripts/write_bundle_manifest.py" in text
    assert '--bundle "${BUNDLE_PATH}"' in text
    assert '"${ARTIFACT_NAME}.zip.sha256"' in text
    assert "dist/${{ matrix.artifact-name }}.zip.sha256" in text
    assert "dist/one-link.sha256" not in text
    assert "| sort -z" not in text


@pytest.mark.parametrize("runner", ["ubuntu-latest", "macos-latest"])
@pytest.mark.parametrize("helper_kind", ["file", "missing", "directory", "symlink"])
def test_continuous_zip_step_preserves_stamps_and_framework_links(tmp_path, runner, helper_kind):
    """Archive the finalized layout, including its helper and framework chain."""
    import hashlib
    import os
    import shutil
    import stat
    import subprocess
    import zipfile

    if os.name == "nt" or shutil.which("bash") is None:
        pytest.skip("executes the Bash workflow fixture on a POSIX host")
    workflows = dict(_workflow_documents())
    build_job = workflows[_WORKFLOWS / "auto_build.yml"]["jobs"]["build"]
    steps = build_job["steps"]
    matrix = next(row for row in build_job["strategy"]["matrix"]["include"] if row["os"] == runner)
    root = "one-link.app" if runner == "macos-latest" else "one-link"
    executable_relative = "Contents/MacOS/one-link" if runner == "macos-latest" else "one-link"
    assert matrix["bundle-path"] == "dist/" + root
    assert matrix["bundle-root"] == root
    assert matrix["exe-name"] == executable_relative
    matches = [step for step in steps
               if "scripts/package_standalone_bundle.py" in step.get("run", "")]
    assert len(matches) == 1
    step = matches[0]
    assert step["shell"] == "bash"
    assert step.get("env", {}).get("EXE_NAME") == "${{ matrix.exe-name }}"
    assert "if" not in step and "continue-on-error" not in step
    command = step["run"]
    assert command.index("package_standalone_bundle.py") < command.index("write_bundle_manifest.py")
    assert "zip -r" not in command and "Compress-Archive -Path" not in command

    bundle = tmp_path / matrix["bundle-path"]
    runtime = bundle / ("Contents/Frameworks" if runner == "macos-latest" else "_internal")
    framework = runtime / "Python.framework" / "Versions"
    (framework / "3.12").mkdir(parents=True)
    (framework / "3.12" / "Python").write_bytes(b"framework binary fixture")
    (framework / "Current").symlink_to("3.12", target_is_directory=True)
    (runtime / "Python").symlink_to("Python.framework/Versions/Current/Python")
    executable = bundle / executable_relative
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"launcher fixture")
    executable.chmod(0o755)
    helper = executable.with_name("one-link-update-helper")
    if helper_kind == "file":
        helper.write_bytes(b"required finished helper")
    elif helper_kind == "directory":
        helper.mkdir()
        (helper / "not-a-helper").write_bytes(b"directory with content")
    elif helper_kind == "symlink":
        helper.symlink_to(executable.name)
    stamp = runtime / "one_link_build_stamp.json"
    stamp.write_text(json.dumps({"schema": 1, "commit": "a" * 40, "channel": "rolling"}))
    if runner == "macos-latest":
        intermediate = tmp_path / "dist" / "one-link"
        intermediate.mkdir()
        (intermediate / "one-link").write_bytes(b"unfinalized COLLECT intermediate")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("package_standalone_bundle.py", "write_bundle_manifest.py"):
        shutil.copyfile(_REPO / "scripts" / name, scripts / name)
    shims = tmp_path / "tools"
    shims.mkdir()
    (shims / "uv").write_text(
        '#!/bin/sh\nset -eu\n[ "$1 $2 $3 $4 $5" = "run --frozen --extra release python" ]\n'
        'shift 5\nexec "$ONE_LINK_TEST_PYTHON" "$@"\n'
    )
    (shims / "git").write_text(
        '#!/bin/sh\nset -eu\n[ "$*" = "show -s --format=%ct HEAD" ]\n'
        'printf "%s\\n" 1700000001\n'
    )
    for shim in shims.iterdir():
        shim.chmod(0o755)
    env = dict(os.environ, PATH=str(shims) + os.pathsep + os.environ["PATH"],
               PYTHONPATH=str(_REPO / "src"), ONE_LINK_TEST_PYTHON=sys.executable,
               GITHUB_SHA="a" * 40, GITHUB_REF="refs/heads/test", GITHUB_RUN_ID="123")
    step_names = ["stamp build metadata", "compute SHA-256 of the bundle", step["name"]]
    for step_name in step_names:
        current = next(item for item in steps if item.get("name") == step_name)
        step_env = {key: matrix[value.removeprefix("${{ matrix.").removesuffix(" }}")]
                    for key, value in current["env"].items()}
        completed = subprocess.run(["bash", "-c", current["run"]], cwd=tmp_path, env=env | step_env,
                                   text=True, capture_output=True, check=False)
        if step_name == step["name"] and helper_kind != "file":
            assert completed.returncode != 0
            assert not (tmp_path / "dist" / (matrix["artifact-name"] + ".zip")).exists()
            return
        assert completed.returncode == 0, completed.stdout + completed.stderr
    archive_path = tmp_path / "dist" / (matrix["artifact-name"] + ".zip")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    assert (archive_path.with_suffix(".zip.sha256")).read_text().split() == [digest, archive_path.name]
    with zipfile.ZipFile(archive_path) as archive:
        assert all(not member.is_dir() and "\\" not in member.filename for member in archive.infolist())
        assert {name.split("/", 1)[0] for name in archive.namelist()} == {root}
        build_info = archive.read(root + "/BUILD_INFO.txt").decode()
        assert f"commit: {'a' * 40}\n" in build_info and "run_id: 123\n" in build_info
        assert f"runner: {runner}\n" in build_info
        assert archive.read(root + "/" + stamp.relative_to(bundle).as_posix()) == stamp.read_bytes()
        helper_member = root + "/" + helper.relative_to(bundle).as_posix()
        assert archive.read(helper_member) == b"required finished helper"
        launcher_member = root + "/" + executable_relative
        assert archive.read(launcher_member + ".sha256").decode().split() == [
            hashlib.sha256(executable.read_bytes()).hexdigest(), launcher_member,
        ]
        link = archive.getinfo(root + "/" + runtime.relative_to(bundle).as_posix() + "/Python")
        assert stat.S_ISLNK(link.external_attr >> 16)
        assert archive.read(link) == b"Python.framework/Versions/Current/Python"
        from one_link.update_transaction import _validate_zip_index

        _, _, rows = _validate_zip_index(
            archive, expected_executable=executable_relative, expected_bundle_root=root,
        )
        assert rows[helper_member].digest == hashlib.sha256(helper.read_bytes()).hexdigest()
    assert (bundle / "BUNDLE_SHA256SUMS").is_file()


def test_continuous_aggregate_never_mutates_a_public_release():
    text = (_WORKFLOWS / "auto_build.yml").read_text(encoding="utf-8")
    assert "bundle-ephemeral-artifacts:" in text
    assert "if: always()" in text
    assert "retain consolidated CI bundle" in text
    assert "retention-days: 7" in text
    assert "gh release" not in text.lower()
    assert "contents: write" not in text.lower()


def test_javascript_gate_uses_exact_node_and_clean_install():
    text = (_WORKFLOWS / "lint.yml").read_text(encoding="utf-8")
    assert "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020" in text
    assert 'node-version: "24.18.0"' in text
    assert "npm ci --ignore-scripts" in text
    assert "npm audit --audit-level=moderate" in text
    assert "npm test" in text
    assert text.count("working-directory: tests/js") >= 3


def test_browser_e2e_job_explicitly_opts_into_executable_suite():
    """The isolated Playwright job must not exit green after skipping all tests."""
    workflows = dict(_workflow_documents())
    job = workflows[_WORKFLOWS / "full_suite_and_e2e.yml"]["jobs"]["e2e_browser"]
    e2e_steps = [
        step
        for step in job["steps"]
        if step.get("name") == "e2e tests (browser-driven)"
    ]
    assert len(e2e_steps) == 1
    step = e2e_steps[0]
    assert step.get("env", {}).get("ONE_LINK_RUN_BROWSER_E2E") == "1"
    command = step.get("run", "")
    assert "python -m pytest tests/e2e/" in command
    assert "--browser chromium" in command


def test_javascript_lock_has_exact_versions_and_integrity_hashes():
    package = json.loads((_REPO / "tests/js/package.json").read_text(encoding="utf-8"))
    lock = json.loads((_REPO / "tests/js/package-lock.json").read_text(encoding="utf-8"))
    assert package["dependencies"] == {
        "acorn": "8.17.0",
        "acorn-walk": "8.3.5",
    }
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["dependencies"] == package["dependencies"]
    for path, entry in lock["packages"].items():
        if not path:
            continue
        assert re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", entry["integrity"]), path
        assert entry["resolved"].startswith("https://registry.npmjs.org/"), path


def test_security_workflow_pip_audit_is_a_hard_gate():
    """2026-06-16 (external-audit remediation): pip-audit must FAIL the
    build on a known CVE — it was previously report-only (`|| true`),
    which the audit flagged as 'supply-chain not enforceable'."""
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    # The committed universal lock is checked, exported, then audited.
    assert "uv lock --check" in text
    assert "uv export --frozen" in text
    assert "pip_audit --requirement requirements.lock" in text
    # The GATE line (audit on the lock) must NOT be neutered with `|| true`.
    gate_lines = [
        ln for ln in text.splitlines()
        if "pip_audit --requirement requirements.lock" in ln
        and "--format json" not in ln  # that line is the artifact writer
    ]
    assert gate_lines, "expected a pip-audit gate line"
    for ln in gate_lines:
        assert "|| true" not in ln, (
            "pip-audit gate must be HARD (no '|| true') — known CVEs "
            "must fail the build"
        )
    assert any("--vulnerability-service osv" in ln for ln in gate_lines)


def test_release_gate_audits_both_pypi_and_osv_sources():
    text = (_REPO / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    audit_lines = [
        line for line in text.splitlines()
        if "pip_audit" in line or "--vulnerability-service osv" in line
    ]
    assert sum("pip_audit" in line for line in audit_lines) == 2
    assert sum("--vulnerability-service osv" in line for line in audit_lines) == 1


def test_security_workflow_rustsec_audit_is_pinned_and_hard_gated():
    """The native dependency graph is an equal release boundary.

    Keep the scanner version reproducible, retain a machine-readable report,
    and make the terminal invocation fail on vulnerabilities, unmaintained or
    unsound crates, and yanked releases.
    """
    # A `--locked` build or explicit `cargo audit --file` is only reproducible
    # when both independent Rust workspaces actually commit their lockfiles.
    # Keep this guard beside the workflow assertions so deleting either lock
    # cannot turn every security/fuzz run permanently red again.
    assert (_REPO / "native" / "Cargo.lock").is_file()
    assert (_REPO / "native" / "fuzz" / "Cargo.lock").is_file()

    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    assert "cargo install --locked --version 0.22.2 cargo-audit" in text
    assert "cargo audit --file native/Cargo.lock --deny warnings --json" in text
    assert "cargo audit --file native/fuzz/Cargo.lock --deny warnings --json" in text
    gate_lines = [
        line
        for line in text.splitlines()
        if "cargo audit --file native/Cargo.lock --deny warnings" in line
        and "--json" not in line
    ]
    assert gate_lines, "expected a hard RustSec gate"
    assert all("|| true" not in line for line in gate_lines)
    assert "cargo-audit.json" in text
    assert "cargo-audit-fuzz.json" in text


def test_security_workflow_scans_full_history_with_checksummed_gitleaks():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    assert 'GITLEAKS_VERSION: "8.30.1"' in text
    assert (
        'GITLEAKS_SHA256: '
        '"551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"'
        in text
    )
    assert "sha256sum --check --strict" in text
    assert "fetch-depth: 0" in text
    gate_lines = [line for line in text.splitlines() if "./gitleaks git" in line]
    assert gate_lines
    assert all("|| true" not in line for line in gate_lines)
    assert "--redact=100" in text
    assert (_REPO / ".gitleaksignore").is_file()


def test_nightly_fuzz_runs_every_target_in_a_locked_parallel_matrix():
    text = (_REPO / ".github" / "workflows" / "fuzz_nightly.yml").read_text(
        encoding="utf-8"
    )
    assert "fromJSON(needs.discover.outputs.targets)" in text
    assert "fail-fast: false" in text
    assert "cargo install --locked --version 0.13.2 cargo-fuzz" in text
    assert "fetch --locked --manifest-path fuzz/Cargo.toml" in text
    assert 'CARGO_NET_OFFLINE: "true"' in text
    assert "git diff --exit-code -- fuzz/Cargo.lock" in text
    assert "for target in" not in text
