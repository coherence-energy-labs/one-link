"""Structural tests for .github/workflows/release.yml.

A tagged-release run must produce:
    1. A pure-Python sdist + wheel (existing).
    2. A native wheel per OS (Linux, macOS, Windows), built via maturin
       and shipping the Rust hot-path crates.
    3. A SHA256SUMS manifest covering every file attached to the release.
    4. A frozen-graph CycloneDX SBOM covered by SHA256SUMS and Sigstore.
    5. Sigstore-signed bundles for every artifact, sealed as an immutable
       workflow artifact before a minimal write-scoped job publishes them.

The workflow is the single point of truth for "what gets uploaded to a
GitHub Release," so we lock in its structural contract here. If a future
edit drops the native_wheels job, or breaks the dependency chain, the
suite fails before the YAML ever fires in CI.

These tests do NOT actually run GitHub Actions; they parse the YAML and
assert invariants. The next time anyone tags a release we'll see the
real run, but the gate here keeps the foot-gun off the workflow itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest


WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
TESTS_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "tests.yml"
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def workflow():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_pre_release_audit_runs_on_legacy_windows_console_encodings():
    """The operator gate must not crash before executing on CP-1252 consoles."""
    audit = REPO / "scripts" / "pre_release_audit.py"
    source = audit.read_text(encoding="utf-8")
    # `"".encode("ascii")` succeeds, so a missing or emptied gate would pass
    # this "runs on CP-1252" check having verified nothing.
    assert len(source) > 1000, f"pre_release_audit.py is {len(source)} bytes"
    source.encode("ascii")


# ─── trigger contract ──────────────────────────────────────────────────


def test_release_fires_on_version_tag_push(workflow):
    """The workflow must trigger when a `v*` tag is pushed. If someone
    accidentally narrows the trigger (e.g. to a specific branch), releases
    silently stop happening; this test catches that."""
    # PyYAML parses YAML `on:` as Python `True` because YAML treats `on`/`off`
    # as boolean aliases. Look up via the boolean key as well as the string.
    on = workflow.get("on") or workflow.get(True)
    assert on is not None, "workflow has no trigger block"
    push = on.get("push", {})
    tags = push.get("tags", [])
    assert "v*" in tags, f"v*-tag trigger missing; got tags={tags!r}"


# ─── jobs that must exist ──────────────────────────────────────────────


def test_workflow_has_required_jobs(workflow):
    """Build, sign, and separately publish every tagged release."""
    jobs = workflow["jobs"]
    for name in (
        "release_quality_linux",
        "release_quality_windows",
        "formal_verification",
        "release_quality_gate",
        "build",
        "native_wheels",
        "sign",
        "publish",
    ):
        assert name in jobs, f"missing job: {name!r}"


def test_tagged_release_quality_gate_is_fail_closed(workflow):
    """A v* tag cannot bypass the checks normally enforced on branches."""
    jobs = workflow["jobs"]
    linux = jobs["release_quality_linux"]
    windows = jobs["release_quality_windows"]
    formal = jobs["formal_verification"]
    gate = jobs["release_quality_gate"]

    assert linux["permissions"] == {"contents": "read"}
    assert windows["permissions"] == {"contents": "read"}
    assert formal["permissions"] == {"contents": "read"}
    assert formal["uses"] == "./.github/workflows/formal_verification.yml"
    assert gate["permissions"] == {"contents": "read"}
    assert set(gate["needs"]) == {
        "release_quality_linux",
        "release_quality_windows",
        "formal_verification",
    }
    assert str(gate["if"]) == "${{ always() }}"
    gate_run = "\n".join(str(step.get("run", "")) for step in gate["steps"])
    assert 'test "$LINUX_RESULT" = "success"' in gate_run
    assert 'test "$WINDOWS_RESULT" = "success"' in gate_run
    assert 'test "$FORMAL_RESULT" = "success"' in gate_run

    for job_name in ("build", "sign", "publish"):
        needs = jobs[job_name]["needs"]
        if isinstance(needs, str):
            needs = [needs]
        assert "release_quality_gate" in needs, (
            f"{job_name} can run without tagged release quality authority"
        )


def test_tagged_release_quality_replays_canonical_gates(workflow):
    jobs = workflow["jobs"]
    linux_text = "\n".join(
        str(step.get("run", "")) for step in jobs["release_quality_linux"]["steps"]
    )
    windows_text = "\n".join(
        str(step.get("run", "")) for step in jobs["release_quality_windows"]["steps"]
    )
    combined = linux_text + "\n" + windows_text

    for required in (
        "uv lock --check",
        "maturin develop --release --locked",
        "cargo fmt --all -- --check",
        "cargo clippy --locked --workspace --all-targets",
        "cargo test --locked --workspace --all-targets --all-features --exclude one_link_native --release",
        "ruff check src/one_link",
        "mypy src/one_link",
        "scripts/pre_release_audit.py --skip-cargo --skip-pytest",
        "python -m pytest tests/",
        "python -m pip_audit",
        "bandit -c pyproject.toml -r src/one_link scripts --severity-level medium",
        "cargo audit --file native/Cargo.lock --deny warnings",
        "cargo audit --file native/fuzz/Cargo.lock --deny warnings",
        "cargo audit --file native/ol_shell/Cargo.lock",
        "./gitleaks git .",
        "npm audit --audit-level=moderate",
        "npm test",
    ):
        assert required in combined, f"tagged release omits quality gate: {required}"
    assert "uv export --frozen --all-extras --all-groups" in linux_text
    assert "--no-extra native" in linux_text
    assert '--requirement "$RUNNER_TEMP/requirements.lock"' in linux_text
    assert "--no-deps --disable-pip" in linux_text


def test_live_daemon_workflow_lanes_cannot_silently_skip(workflow):
    """Named integration and tagged-release lanes must opt into real daemons."""
    yaml = pytest.importorskip("yaml")
    tests_workflow = yaml.safe_load(TESTS_WORKFLOW.read_text(encoding="utf-8"))
    integration_steps = [
        step
        for step in tests_workflow["jobs"]["test"]["steps"]
        if step.get("name") == "integration tests (two-daemon, mDNS)"
    ]
    assert len(integration_steps) == 1
    assert integration_steps[0].get("env", {}).get("ONE_LINK_RUN_LIVE_INTEGRATION") == "1"

    for job_name in ("release_quality_linux", "release_quality_windows"):
        release_steps = [
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step.get("name") == "full Python suite for tagged source"
        ]
        assert len(release_steps) == 1
        step = release_steps[0]
        assert step.get("env", {}).get("ONE_LINK_RUN_LIVE_INTEGRATION") == "1"
        assert "python -m pytest tests/" in step["run"]
        assert "--deselect tests/test_pairing.py" not in step["run"]


def test_tagged_release_browser_e2e_cannot_silently_skip(workflow):
    jobs = workflow["jobs"]
    for job_name in ("release_quality_linux", "release_quality_windows"):
        steps = [
            step
            for step in jobs[job_name]["steps"]
            if step.get("name") == "install browser and run non-skippable E2E gate"
        ]
        assert len(steps) == 1
        step = steps[0]
        assert step.get("env", {}).get("ONE_LINK_RUN_BROWSER_E2E") == "1"
        assert "python -m pytest tests/e2e/" in step["run"]
        assert "--browser chromium" in step["run"]
        assert not step.get("continue-on-error", False)


def test_release_workflow_is_the_only_tag_triggered_trust_authority():
    """No parallel v* workflow may mint signatures or mutate a release."""
    yaml = pytest.importorskip("yaml")
    authority_jobs: list[tuple[str, str]] = []

    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        triggers = document.get("on") or document.get(True) or {}
        push = triggers.get("push", {}) if isinstance(triggers, dict) else {}
        tags = push.get("tags", []) if isinstance(push, dict) else []
        if isinstance(tags, str):
            tags = [tags]
        if not tags:
            continue

        workflow_permissions = document.get("permissions", {})
        for job_name, job in document.get("jobs", {}).items():
            permissions = job.get("permissions", workflow_permissions)
            if not isinstance(permissions, dict):
                permissions = {}
            steps_text = "\n".join(
                str(step.get("uses", "")) + "\n" + str(step.get("run", ""))
                for step in job.get("steps", [])
            ).lower()
            has_authority = (
                permissions.get("contents") == "write"
                or permissions.get("id-token") == "write"
                or permissions.get("attestations") == "write"
                or "sigstore sign" in steps_text
                or "gh-action-sigstore" in steps_text
                or "attest-build-provenance" in steps_text
                or "gh release" in steps_text
            )
            if not has_authority:
                continue

            authority_jobs.append((path.name, job_name))
            assert path.name == "release.yml", (
                f"{path.name}:{job_name} is a second tag-triggered trust authority"
            )
            needs = job.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            assert "release_quality_gate" in needs, (
                f"release.yml:{job_name} bypasses tagged release quality authority"
            )

    assert set(authority_jobs) == {("release.yml", "sign"), ("release.yml", "publish")}


def test_reproducibility_workflow_is_explicitly_non_signing():
    text = (
        (REPO / ".github" / "workflows" / "reproducible_release.yml")
        .read_text(encoding="utf-8")
        .lower()
    )
    for forbidden in (
        "id-token: write",
        "attestations: write",
        "contents: write",
        "sigstore sign",
        "gh-action-sigstore",
        "attest-build-provenance",
        "gh release",
    ):
        assert forbidden not in text


def test_release_materials_scope_reproducibility_claims_to_proven_linux_artifact():
    release_text = WORKFLOW.read_text(encoding="utf-8")
    checklist = (REPO / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    combined_lower = (release_text + "\n" + checklist).lower()

    for overclaim in (
        "anyone can rebuild from source and get the same binary",
        "reproducible-build artifacts",
        "must be byte-identical linux",
        "reproducible by any auditor",
        "rebuild from source with that env var set to verify byte-equal",
    ):
        assert overclaim not in combined_lower

    assert "locked, quality-gated artifacts" in release_text.lower()
    assert "sha256sums` verifies the exact published bytes" in release_text.lower()
    assert (
        "linux native wheel reproducibility verified"
        in (REPO / ".github" / "workflows" / "reproducible_release.yml")
        .read_text(encoding="utf-8")
        .lower()
    )
    normalized_checklist = " ".join(checklist.lower().split())
    assert "not claimed to be byte-identical" in normalized_checklist
    assert "checksum of this release's exact bytes" in checklist.lower()


def test_release_verifier_requires_explicit_tag_and_never_bootstraps_latest_code():
    verifier = (REPO / "scripts" / "verify-release.sh").read_text(encoding="utf-8")
    release = WORKFLOW.read_text(encoding="utf-8")
    assert 'RELEASE_TAG="$2"' in verifier
    assert 'EXPECTED_REF="refs/tags/${RELEASE_TAG}"' in verifier
    assert "refs/heads/master" not in verifier
    assert "infer version" not in verifier.lower()
    assert "pip install" not in verifier
    assert "--frozen --only-group release-tools" in verifier
    assert "sigstore.__version__ == '4.4.0'" in verifier
    assert "expected exactly one manifest entry" in verifier
    assert "signed-manifest bundle not found" in verifier
    assert "verify-release.sh dist/<artifact> v${{ needs.build.outputs.version }}" in release
    attributes = (REPO / ".gitattributes").read_text(encoding="utf-8")
    assert "*.sh text eol=lf" in attributes


def test_build_validates_exact_universal_python_distributions_before_upload(workflow):
    """Only independently validated wheel/sdist bytes may leave the build job."""
    steps = workflow["jobs"]["build"]["steps"]
    build_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "build sdist + wheel from locked tooling"
    )
    validate_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "validate exact Python wheel and sdist contract"
    )
    upload_index = next(
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert build_index < validate_index < upload_index
    command = steps[validate_index]["run"]
    assert "scripts/validate_python_distributions.py" in command
    assert "--dist-dir dist" in command
    assert "--source-root ." in command
    assert "--frozen --only-group release-tools" in command
    assert not steps[validate_index].get("continue-on-error", False)


# ─── native_wheels job structure ───────────────────────────────────────


def test_native_wheels_matrix_covers_all_three_oses(workflow):
    """A native wheel must be produced on each supported platform.
    Dropping any one of these means users on that OS can't install
    one-link[native] from the release page."""
    matrix = workflow["jobs"]["native_wheels"]["strategy"]["matrix"]["include"]
    oses = {entry["os"] for entry in matrix}
    assert oses >= {"ubuntu-latest", "macos-latest", "windows-latest"}, (
        f"native wheel matrix is missing an OS: {oses}"
    )


def test_native_wheels_uploads_one_artifact_per_os(workflow):
    """Each matrix leg uploads under a unique artifact name so the sign
    job can download all three independently. If two legs use the same
    artifact name the second upload silently overwrites the first."""
    matrix = workflow["jobs"]["native_wheels"]["strategy"]["matrix"]["include"]
    names = [entry["artifact"] for entry in matrix]
    assert len(names) == len(set(names)), f"duplicate artifact names: {names}"
    for name in names:
        assert name.startswith("native-wheel-"), (
            f"artifact name should start with native-wheel-: {name!r}"
        )


def test_native_wheels_uses_maturin_release_strip(workflow):
    """We build with `maturin build --release --strip` so the wheel is
    optimized AND strip()s debug symbols (cuts ~10-20MB on Linux). If
    someone changes this to `maturin develop` (venv-only) or drops
    --release, the workflow stops producing real distribution artifacts.
    """
    steps = workflow["jobs"]["native_wheels"]["steps"]
    build_step = next(
        (s for s in steps if "maturin build" in s.get("run", "")),
        None,
    )
    assert build_step is not None, "no `maturin build` step in native_wheels"
    cmd = build_step["run"]
    assert "--release" in cmd, "native_wheels must use --release"
    assert "build" in cmd, "must use `maturin build`, not `develop`"


def test_native_wheels_runs_after_build_so_versions_align(workflow):
    """We pass SOURCE_DATE_EPOCH from the build job into the maturin
    build for reproducibility. native_wheels therefore must declare a
    dependency on build, or the env-var passthrough will resolve to
    empty and the wheels won't be bit-identical across rebuilds."""
    needs = workflow["jobs"]["native_wheels"].get("needs")
    assert needs == "build" or needs == ["build"] or "build" in (needs or []), (
        f"native_wheels.needs must include 'build': got {needs!r}"
    )


# ─── sign job: must consume + sign all artifacts ──────────────────────


def test_sign_waits_for_both_build_and_native_wheels(workflow):
    """If sign starts before native_wheels finishes, the release will be
    cut without native wheels attached. The Phase-1 contract is that
    `pip install one_link_native --find-links <release>` works the
    moment the release is published."""
    needs = workflow["jobs"]["sign"]["needs"]
    if isinstance(needs, str):
        needs = [needs]
    assert "build" in needs
    assert "native_wheels" in needs


def test_sign_downloads_native_wheels_into_dist(workflow):
    """The sign job downloads every native-wheel-* artifact into dist/
    so sigstore-sign picks them up without maintaining a stale list of
    platform-specific artifact names."""
    steps = workflow["jobs"]["sign"]["steps"]
    download_steps = [
        s
        for s in steps
        if isinstance(s.get("uses"), str) and s["uses"].startswith("actions/download-artifact")
    ]
    native_download = next(
        (
            step
            for step in download_steps
            if step.get("with", {}).get("pattern") == "native-wheel-*"
        ),
        None,
    )
    assert native_download is not None, "sign job must consume the complete native-wheel-* matrix"
    options = native_download["with"]
    assert options.get("path") == "dist/"
    assert options.get("merge-multiple") is True


def test_sign_seals_signed_payload_for_publish(workflow):
    """Publication may consume only the payload produced by sign."""
    steps = workflow["jobs"]["sign"]["steps"]
    sealed_upload = next(
        (
            step
            for step in steps
            if isinstance(step.get("uses"), str)
            and step["uses"].startswith("actions/upload-artifact")
            and step.get("with", {}).get("name") == "signed-release-dist"
        ),
        None,
    )
    assert sealed_upload is not None, "sign job must seal signed-release-dist for the publisher"
    options = sealed_upload["with"]
    assert options.get("path") == "dist/"
    assert options.get("if-no-files-found") == "error"


def test_sign_computes_sha256sums_after_every_artifact_and_sbom_arrive(workflow):
    """The only checksum boundary must cover the complete release payload."""
    build_text = "\n".join(str(step.get("run", "")) for step in workflow["jobs"]["build"]["steps"])
    assert "SHA256SUMS" not in build_text

    steps = workflow["jobs"]["sign"]["steps"]
    download_indices = [
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/download-artifact")
    ]
    sbom_index = next(
        index for index, step in enumerate(steps) if "scripts/gen_sbom.py" in step.get("run", "")
    )
    checksum_index = next(
        index
        for index, step in enumerate(steps)
        if "sha256sum" in step.get("run", "") and "SHA256SUMS" in step.get("run", "")
    )
    assert max(download_indices) < sbom_index < checksum_index
    checksum_command = steps[checksum_index]["run"]
    assert "find . -maxdepth 1 -type f" in checksum_command
    assert "! -name 'SHA256SUMS' ! -name '*.sigstore'" in checksum_command
    assert "grep -c '  sbom.cdx.json$' SHA256SUMS" in checksum_command
    assert "grep -c '  UPDATE_MANIFEST.json$' SHA256SUMS" in checksum_command


def test_sign_generates_update_authority_inside_release_trust_boundary(workflow):
    steps = workflow["jobs"]["sign"]["steps"]
    commands = [str(step.get("run", "")) for step in steps]
    sbom_index = next(i for i, command in enumerate(commands) if "gen_sbom.py" in command)
    update_index = next(
        i for i, command in enumerate(commands) if "generate_update_manifest.py" in command
    )
    checksum_index = next(i for i, command in enumerate(commands) if "sha256sum" in command)
    command = commands[update_index]
    environment = steps[update_index].get("env", {})
    assert sbom_index < update_index < checksum_index
    assert "--dist-dir dist" in command
    assert environment == {
        "UPDATE_TAG": "v${{ needs.build.outputs.version }}",
        "UPDATE_COMMIT_SHA": "${{ github.sha }}",
        "UPDATE_SOURCE_DATE_EPOCH": "${{ needs.build.outputs.source_date_epoch }}",
    }
    assert '--tag "$UPDATE_TAG"' in command
    assert '--commit-sha "$UPDATE_COMMIT_SHA"' in command
    assert '--source-date-epoch "$UPDATE_SOURCE_DATE_EPOCH"' in command
    assert "--minimum-source-version 0.20.0" in command


def test_publish_waits_for_build_and_signed_payload(workflow):
    """The write-scoped publisher must not run before signing completes."""
    needs = workflow["jobs"]["publish"]["needs"]
    if isinstance(needs, str):
        needs = [needs]
    assert "build" in needs
    assert "sign" in needs


def test_publish_downloads_only_sealed_release_payload(workflow):
    """The publisher obtains the complete payload from the sign job."""
    steps = workflow["jobs"]["publish"]["steps"]
    downloads = [
        step
        for step in steps
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/download-artifact")
    ]
    assert len(downloads) == 1, (
        f"publisher should have one sealed-payload download; got {downloads!r}"
    )
    options = downloads[0].get("with", {})
    assert options.get("name") == "signed-release-dist"
    assert options.get("path") == "dist/"


def test_release_generates_signs_attests_and_publishes_sbom(workflow):
    """The complete SBOM is assembled and sealed inside one trust boundary."""
    build_text = "\n".join(str(step.get("run", "")) for step in workflow["jobs"]["build"]["steps"])
    sign_text = "\n".join(
        str(step.get("run", "")) + "\n" + str(step.get("with", {}).get("subject-path", ""))
        for step in workflow["jobs"]["sign"]["steps"]
    )
    publish_text = "\n".join(
        str(step.get("run", "")) for step in workflow["jobs"]["publish"]["steps"]
    )

    assert "scripts/gen_sbom.py" not in build_text
    assert "sbom.cdx.json" not in build_text
    for required in (
        "uv export --frozen --all-extras --all-groups --no-extra native --no-emit-project",
        "scripts/gen_sbom.py",
        "--from requirements",
        '--requirements "$RUNNER_TEMP/one-link-release-requirements.lock"',
        "--python-lock uv.lock",
        "--exclude-python-extra native",
        "--cargo-lock native/Cargo.lock",
        "--cargo-workspace native/Cargo.toml",
        "--additional-cargo shell native/ol_shell/Cargo.toml",
        "--additional-cargo fuzz native/fuzz/Cargo.toml",
        "--artifacts-dir dist",
        "--artifact-pattern 'one_link-*.whl'",
        "--artifact-pattern 'one_link-*.tar.gz'",
        "--artifact-pattern 'one_link_native-*.whl'",
        "--artifact-pattern 'one-link-*.zip'",
        "--output dist/sbom.cdx.json",
    ):
        assert required in sign_text
    assert "--output-reproducible" in (REPO / "scripts" / "gen_sbom.py").read_text(encoding="utf-8")
    assert "python -m sigstore sign" in sign_text
    assert "dist/sbom.cdx.json" in sign_text
    assert "dist/UPDATE_MANIFEST.json" in sign_text
    assert "dist/SHA256SUMS" in sign_text
    assert "--verify-release-sbom dist/sbom.cdx.json" in sign_text
    assert "--checksum-auxiliary UPDATE_MANIFEST.json" in sign_text
    assert "--checksum-manifest dist/SHA256SUMS" in sign_text
    assert "sbom.cdx.json" in publish_text
    assert "UPDATE_MANIFEST.json" in publish_text


def test_release_sbom_precedes_checksums_signatures_and_attestation(workflow):
    steps = workflow["jobs"]["sign"]["steps"]
    commands = [str(step.get("run", "")) for step in steps]
    sbom_index = next(index for index, command in enumerate(commands) if "gen_sbom.py" in command)
    update_index = next(
        index for index, command in enumerate(commands) if "generate_update_manifest.py" in command
    )
    checksum_index = next(index for index, command in enumerate(commands) if "sha256sum" in command)
    verification_index = next(
        index for index, command in enumerate(commands) if "--verify-release-sbom" in command
    )
    signature_index = next(
        index for index, command in enumerate(commands) if "sigstore sign" in command
    )
    attestation_index = next(
        index
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/attest-build-provenance")
    )
    assert (
        sbom_index
        < update_index
        < checksum_index
        < verification_index
        < signature_index
        < attestation_index
    )


def test_release_signs_every_assembled_file_without_a_stale_extension_list(workflow):
    sign_step = next(
        step
        for step in workflow["jobs"]["sign"]["steps"]
        if "sigstore sign" in str(step.get("run", ""))
    )
    command = sign_step["run"]
    assert "find . -maxdepth 1 -type f ! -name '*.sigstore'" in command
    assert 'for f in "${unsigned_assets[@]}"' in command
    assert '--bundle "$f.sigstore" "$f"' in command


def test_only_publish_job_has_contents_write(workflow):
    """Signing has OIDC authority; only publishing gets repository writes."""
    assert workflow.get("permissions", {}).get("contents") == "read"
    assert workflow["jobs"]["sign"]["permissions"]["contents"] == "read"
    assert workflow["jobs"]["publish"]["permissions"]["contents"] == "write"
    for name, job in workflow["jobs"].items():
        if name == "publish":
            continue
        assert job.get("permissions", {}).get("contents") != "write", (
            f"contents:write leaked into non-publisher job {name!r}"
        )


def test_publish_attaches_wheels_to_release(workflow):
    """The publisher uploads every pure-Python and native wheel."""
    steps = workflow["jobs"]["publish"]["steps"]
    release_step = next(
        (s for s in steps if "gh release upload" in s.get("run", "")),
        None,
    )
    assert release_step is not None, "no GitHub CLI release upload step"
    command = release_step["run"]
    assert "-name '*.whl'" in command, f"release upload doesn't include dist/*.whl: {command!r}"


# ─── pyproject.toml: declares the native optional dep ─────────────────


def test_workflow_has_binaries_job(workflow):
    """End-users download .exe / mac binary / linux binary from the
    website. The binaries job is what produces those — without it,
    the website's download button 404s."""
    assert "binaries" in workflow["jobs"]


def test_binaries_matrix_covers_all_three_oses(workflow):
    matrix = workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    oses = {entry["os"] for entry in matrix}
    assert oses >= {"ubuntu-latest", "macos-latest", "windows-latest"}


def test_binaries_asset_names_match_landing_page_expectations(workflow):
    """The landing-page JS expects assets named exactly:
        one-link-windows-x86_64.zip
        one-link-macos-arm64.zip
        one-link-linux-x86_64.zip
    If the workflow changes the asset name, the website's download
    button breaks. This test pins the contract on both ends."""
    matrix = workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    names = {entry["asset_name"] for entry in matrix}
    required = {
        "one-link-windows-x86_64.zip",
        "one-link-macos-arm64.zip",
        "one-link-linux-x86_64.zip",
    }
    assert required <= names, (
        f"binaries job is missing required asset name(s); have {names}, need {required}"
    )


def test_binaries_job_installs_native_wheel_before_pyinstaller(workflow):
    """For the bundled binary to include the Rust hot-path, the
    matching native wheel must be installed in the build env BEFORE
    `python scripts/build_binary.py` runs. The script's auto-detect
    only finds one_link_native via the active site-packages."""
    steps = workflow["jobs"]["binaries"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    # The install-native-wheel step must come before the
    # build-standalone-binary step.
    try:
        install_idx = next(
            i for i, n in enumerate(step_names) if "install native wheel" in n.lower()
        )
        build_idx = next(i for i, n in enumerate(step_names) if "build standalone" in n.lower())
    except StopIteration:
        pytest.fail(f"binaries job missing required steps; got {step_names!r}")
    assert install_idx < build_idx, (
        f"native wheel install must precede binary build, got "
        f"install at {install_idx}, build at {build_idx}"
    )


def test_standalone_release_installs_tray_runtime_before_pyinstaller(workflow):
    """The default-on tray must have both pystray and Pillow in Analysis."""
    steps = workflow["jobs"]["binaries"]["steps"]
    install = next(step for step in steps if step.get("name") == "install build deps")
    command = str(install.get("run", ""))
    assert "uv sync --frozen --python python" in command
    assert "--extra release" in command
    assert "--extra tray" in command


def test_publish_attaches_binaries_to_release(workflow):
    """The standalone binaries must end up on the GitHub Release
    page so the website's download links resolve."""
    steps = workflow["jobs"]["publish"]["steps"]
    release_step = next(
        (s for s in steps if "gh release upload" in s.get("run", "")),
        None,
    )
    assert release_step is not None
    command = release_step["run"]
    assert "-name 'one-link-*'" in command, (
        f"release upload doesn't include one-link-* binaries: {command!r}"
    )


def test_binaries_package_complete_onedir_instead_of_orphan_launcher(workflow):
    job = workflow["jobs"]["binaries"]
    matrix = job["strategy"]["matrix"]["include"]
    assert all(str(row["asset_name"]).endswith(".zip") for row in matrix)
    assert {row["bundle_path"] for row in matrix} == {
        "dist/one-link",
        "dist/one-link.app",
    }
    assert {row["bundle_executable"] for row in matrix} == {
        "one-link",
        "one-link.exe",
        "Contents/MacOS/one-link",
    }
    macos_row = next(row for row in matrix if row["os"] == "macos-latest")
    assert macos_row["bundle_path"] == "dist/one-link.app"
    assert macos_row["bundle_executable"] == "Contents/MacOS/one-link"
    command = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert "scripts/package_standalone_bundle.py" in command
    assert '--bundle "${BUNDLE_PATH}"' in command
    assert '--executable "${BUNDLE_EXECUTABLE}"' in command
    assert "cp dist/one-link.exe" not in command
    assert "cp dist/one-link " not in command


def test_binaries_fail_closed_on_stable_preview_ml_artifact_contract(workflow):
    steps = workflow["jobs"]["binaries"]["steps"]
    commands = [str(step.get("run", "")) for step in steps]
    build_idx = next(i for i, command in enumerate(commands) if "build_binary.py" in command)
    validate_idx = next(
        i for i, command in enumerate(commands) if "validate_packaged_artifact.py" in command
    )
    package_idx = next(
        i for i, command in enumerate(commands) if "package_standalone_bundle.py" in command
    )
    assert build_idx < validate_idx < package_idx
    assert '--artifact "${BUNDLE_PATH}"' in commands[validate_idx]
    assert "--spec build/one-link.spec" in commands[validate_idx]


def test_binaries_revalidate_and_execute_the_final_downloadable_zip(workflow):
    commands = [
        str(step.get("run", ""))
        for step in workflow["jobs"]["binaries"]["steps"]
    ]
    final_gate = next(
        command
        for command in commands
        if "package_standalone_bundle.py" in command
        and "--release-archive" in command
    )
    package_index = final_gate.index("package_standalone_bundle.py")
    release_gate_index = final_gate.index("--release-archive")
    assert package_index < release_gate_index
    assert '--release-archive "staged/${ASSET_NAME}"' in final_gate
    assert "--frozen-e2e" in final_gate


def test_publish_uses_builtin_gh_cli_with_job_token(workflow):
    """Release authority must not be delegated to a third-party action."""
    steps = workflow["jobs"]["publish"]["steps"]
    release_step = next(
        (s for s in steps if "gh release upload" in s.get("run", "")),
        None,
    )
    assert release_step is not None
    assert release_step.get("env", {}).get("GH_TOKEN") == "${{ github.token }}"
    assert all(
        "softprops/action-gh-release" not in str(step.get("uses", ""))
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    )


def test_publish_is_draft_until_every_remote_asset_is_verified(workflow):
    """A failed upload must never expose a partial executable release."""
    release_step = next(
        step
        for step in workflow["jobs"]["publish"]["steps"]
        if "gh release upload" in str(step.get("run", ""))
    )
    command = str(release_step["run"])
    guard_idx = command.index("assert_release_is_draft\n")
    upload_idx = command.index('gh release upload "$RELEASE_TAG"')
    verify_idx = command.index("Remote release asset is missing or truncated")
    publish_idx = command.index("--draft=false")
    assert guard_idx < upload_idx < verify_idx < publish_idx
    assert command.count("--draft=false") == 1
    assert "--draft=true" not in command
    assert "--clobber" not in command
    # The guard still refuses anything that is not a draft; the wording widened
    # to name WHICH failure occurred, because "absent" and "already public" are
    # different problems and the operator needs to know which one they have.
    assert "Refusing to modify a release that is absent or already public" in command
    assert "Existing draft asset differs; refusing destructive replacement" in command
    assert command.count("assert_release_is_draft") >= 4
    # A DRAFT release is NOT addressable by tag: GitHub binds the tag only on
    # publication, so `releases/tags/<tag>` 404s on the very draft this job
    # just created (its URL still reads `untagged-<hash>`). This assertion used
    # to pin that by-tag call, which is how the defect survived review -- the
    # test encoded it. Pin the working lookup instead.
    assert 'gh api "repos/$GH_REPO/releases?per_page=100"' in command, (
        "the draft guard must resolve through the releases list"
    )
    assert "releases/tags/$RELEASE_TAG" not in command, (
        "releases/tags/<tag> only resolves PUBLISHED releases; it cannot see "
        "the draft this job creates"
    )
    assert '(.digest // "MISSING")' in command
    assert 'local_digest="sha256:' in command
    assert "expected exactly ${#assets[@]}" in command
    assert "repos/$GH_REPO/git/ref/tags/$RELEASE_TAG" in command
    assert "repos/$GH_REPO/git/tags/$object_sha" in command
    assert 'resolved_commit" != "$RELEASE_TARGET' in command
    first_binding_idx = command.index("assert_release_tag_binding")
    final_binding_idx = command.rindex("assert_release_tag_binding")
    assert first_binding_idx < guard_idx
    assert verify_idx < final_binding_idx < publish_idx


def test_sign_signs_binaries_with_sigstore(workflow):
    """The standalone binaries are the highest-stakes artifact
    (they're what end users execute). They must be sigstore-signed
    so anyone can verify the .exe was built by Actions from the
    matching tag."""
    steps = workflow["jobs"]["sign"]["steps"]
    sign_step = next(
        (s for s in steps if "sigstore sign" in s.get("run", "")),
        None,
    )
    assert sign_step is not None
    cmd = sign_step["run"]
    assert "find . -maxdepth 1 -type f ! -name '*.sigstore'" in cmd
    assert 'for f in "${unsigned_assets[@]}"' in cmd


def test_pyproject_declares_native_optional_dependency():
    """`pip install one-link[native]` must resolve a real package name
    so users have a single-command install path. The Phase-1 contract
    is that the [native] extra exists and points at one_link_native."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    # Lightweight check that doesn't pull in tomllib for older test
    # configurations: search for the section + dep name in raw text.
    assert "[project.optional-dependencies]" in text
    # The extra is on its own line as `native = [...]`.
    assert "native = [" in text or "\nnative =[" in text, "no [native] optional dependency declared"
    assert "one_link_native" in text, "[native] extra exists but doesn't list one_link_native"
