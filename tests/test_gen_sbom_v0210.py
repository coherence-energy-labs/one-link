"""Adversarial coverage for the complete release SBOM generator."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from scripts import gen_sbom


@pytest.mark.parametrize(
    "value,expected",
    [
        ("MIT", [{"license": {"id": "MIT"}}]),
        ("AGPL-3.0-or-later", [{"license": {"id": "AGPL-3.0-or-later"}}]),
        ("Apache-2.0 OR MIT", [{"expression": "Apache-2.0 OR MIT"}]),
        ("MIT AND Unicode-3.0", [{"expression": "MIT AND Unicode-3.0"}]),
        ("GPL-2.0-only WITH Classpath-exception-2.0", [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}]),
        ("(MIT OR Apache-2.0) AND BSD-3-Clause", [{"expression": "(MIT OR Apache-2.0) AND BSD-3-Clause"}]),
    ],
)
def test_compound_spdx_licenses_use_the_expression_form(value, expected):
    # CycloneDX `license.id` takes one SPDX identifier; an expression there
    # fails schema validation (found with the dual-licensed ml-kem backport).
    assert gen_sbom._license_choice(value) == expected


def test_every_vendored_backport_license_validates_in_the_generated_sbom():
    for record in sorted(REPO.glob("native/**/patches/*.json")):
        proof = json.loads(record.read_text(encoding="utf-8"))
        if proof.get("schema") != "one-link-vendored-cargo-patch/v1":
            continue
        choice = gen_sbom._license_choice(proof["package"]["license"])
        compound = any(word in proof["package"]["license"].split() for word in ("OR", "AND", "WITH"))
        assert ("expression" in choice[0]) is compound, record.name


REPO = Path(__file__).resolve().parent.parent
ARTIFACT_PATTERNS = (
    "one_link-*.whl",
    "one_link-*.tar.gz",
    "one_link_native-*.whl",
    "one-link-*.zip",
)


def _write_cargo_fixture(root: Path, *, broken_dependency: bool = False) -> tuple[Path, Path]:
    workspace = root / "native"
    member = workspace / "one_link_native"
    member.mkdir(parents=True)
    manifest = workspace / "Cargo.toml"
    manifest.write_text(
        '[workspace]\nresolver = "2"\nmembers = ["one_link_native"]\n',
        encoding="utf-8",
    )
    (member / "Cargo.toml").write_text(
        """[package]
name = "one_link_native"
version = "0.21.0-alpha.0"
license = "AGPL-3.0-or-later"
description = "fixture native binding"
""",
        encoding="utf-8",
    )
    dependency = "missing 9.9.9" if broken_dependency else "dep 1.2.3"
    lock = workspace / "Cargo.lock"
    lock.write_text(
        f"""version = 4

[[package]]
name = "one_link_native"
version = "0.21.0-alpha.0"
dependencies = ["{dependency}"]

[[package]]
name = "dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{'ab' * 32}"
""",
        encoding="utf-8",
    )
    return lock, manifest


def _write_artifacts(root: Path) -> Path:
    artifacts = root / "dist"
    artifacts.mkdir()
    payloads = {
        "one_link-0.21.0a0-py3-none-any.whl": b"python-wheel",
        "one_link-0.21.0a0.tar.gz": b"source-archive",
        "one_link_native-0.21.0a0-cp311-abi3-win_amd64.whl": b"native-wheel",
        "one-link-windows-x86_64.zip": b"standalone-bundle",
    }
    for name, content in payloads.items():
        (artifacts / name).write_bytes(content)
    return artifacts


def _write_python_lock(root: Path) -> Path:
    lock = root / "uv.lock"
    lock.write_text(
        """version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "example"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "one-link"
version = "0.21.0a0"
source = { editable = "." }
dependencies = [{ name = "example" }]

[package.optional-dependencies]
native = [{ name = "one-link-native" }]

[[package]]
name = "one-link-native"
version = "0.21.0a0"
source = { directory = "native" }
""",
        encoding="utf-8",
    )
    return lock


def _write_checksums(artifacts: Path, sbom: Path) -> Path:
    files = sorted(
        [path for path in artifacts.iterdir() if path.is_file() and path != sbom],
        key=lambda path: path.name,
    )
    files.append(sbom)
    manifest = artifacts / "SHA256SUMS"
    manifest.write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files),
        encoding="utf-8",
    )
    return manifest


def _base_bom() -> dict[str, object]:
    root_ref = "pkg:pypi/one-link@0.21.0a0"
    python_ref = "pkg:pypi/example@1.0.0"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "one-link",
                "version": "0.21.0a0",
                "purl": root_ref,
            }
        },
        "components": [
            {
                "type": "library",
                "bom-ref": python_ref,
                "name": "example",
                "version": "1.0.0",
                "purl": python_ref,
            }
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [python_ref]},
            {"ref": python_ref, "dependsOn": []},
        ],
    }


def _property_map(owner: dict[str, object]) -> dict[str, str]:
    properties = owner.get("properties", [])
    assert isinstance(properties, list)
    return {
        str(item["name"]): str(item["value"])
        for item in properties
        if isinstance(item, dict)
    }


def test_complete_inventory_merges_python_cargo_workspace_and_exact_artifacts(tmp_path: Path):
    requirements = tmp_path / "requirements.lock"
    requirements.write_text(
        f"example==1.0.0 --hash=sha256:{'cd' * 32}\n",
        encoding="utf-8",
    )
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    python_lock = _write_python_lock(tmp_path)
    artifacts = _write_artifacts(tmp_path)
    output = artifacts / "sbom.cdx.json"

    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        requirements_lock=requirements,
        python_lock=python_lock,
        excluded_python_extras=("native",),
        cargo_lock=cargo_lock,
        cargo_workspace=workspace,
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=output,
    )

    components = merged["components"]
    assert isinstance(components, list)
    by_name = {component["name"]: component for component in components}
    assert {"example", "dep", "one_link_native"} <= set(by_name)
    assert by_name["dep"]["hashes"] == [{"alg": "SHA-256", "content": "ab" * 32}]
    native_properties = _property_map(by_name["one_link_native"])
    assert native_properties["one-link:cargo:workspace-member"] == "true"
    assert native_properties["one-link:cargo:workspace-path"] == "one_link_native"
    assert by_name["one_link_native"]["licenses"] == [
        {"license": {"id": "AGPL-3.0-or-later"}}
    ]

    artifact = by_name["one-link-windows-x86_64.zip"]
    expected_hash = hashlib.sha256(b"standalone-bundle").hexdigest()
    assert artifact["hashes"] == [{"alg": "SHA-256", "content": expected_hash}]
    assert _property_map(artifact)["one-link:release:size-bytes"] == str(
        len(b"standalone-bundle")
    )

    metadata = merged["metadata"]
    assert isinstance(metadata, dict)
    metadata_properties = _property_map(metadata)
    assert metadata_properties["one-link:sbom:release-artifact-count"] == "4"
    assert metadata_properties["one-link:sbom:cargo-package-count"] == "2"
    assert metadata_properties["one-link:sbom:cargo-workspace-member-count"] == "1"
    assert metadata_properties["one-link:sbom:python-requirements-sha256"] == hashlib.sha256(
        requirements.read_bytes()
    ).hexdigest()

    cargo_ref = by_name["one_link_native"]["bom-ref"]
    dep_ref = by_name["dep"]["bom-ref"]
    dependencies = {entry["ref"]: entry["dependsOn"] for entry in merged["dependencies"]}
    assert dependencies[cargo_ref] == [dep_ref]
    assert str(merged["serialNumber"]).startswith("urn:uuid:")


def test_augmentation_is_byte_deterministic(tmp_path: Path):
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    artifacts = _write_artifacts(tmp_path)
    output = artifacts / "sbom.cdx.json"
    first = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        cargo_lock=cargo_lock,
        cargo_workspace=workspace,
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=output,
    )
    second = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        cargo_lock=cargo_lock,
        cargo_workspace=workspace,
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=output,
    )
    assert gen_sbom._canonical_json(first) == gen_sbom._canonical_json(second)


def test_real_workspace_lock_is_fully_resolvable_and_marks_every_member():
    components, dependencies, metadata = gen_sbom._cargo_inventory(
        REPO / "native" / "Cargo.lock",
        REPO / "native" / "Cargo.toml",
    )
    assert len(components) == len(dependencies)
    assert len(components) >= 300
    assert int(metadata["one-link:sbom:cargo-workspace-member-count"]) >= 40
    assert sum(
        _property_map(component).get("one-link:cargo:workspace-member") == "true"
        for component in components
    ) == int(metadata["one-link:sbom:cargo-workspace-member-count"])
    known = {component["bom-ref"] for component in components}
    assert all(dependency["ref"] in known for dependency in dependencies)
    assert all(
        target in known
        for dependency in dependencies
        for target in dependency["dependsOn"]
    )


def test_unresolved_cargo_edge_fails_closed(tmp_path: Path):
    cargo_lock, workspace = _write_cargo_fixture(tmp_path, broken_dependency=True)
    with pytest.raises(gen_sbom.SbomError, match="resolved to 0 packages"):
        gen_sbom._cargo_inventory(cargo_lock, workspace)


def test_workspace_member_missing_from_lock_fails_closed(tmp_path: Path):
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    text = cargo_lock.read_text(encoding="utf-8")
    cargo_lock.write_text(text.replace("one_link_native", "different_local"), encoding="utf-8")
    with pytest.raises(gen_sbom.SbomError, match="workspace members absent"):
        gen_sbom._cargo_inventory(cargo_lock, workspace)


def test_artifact_inventory_requires_every_class_and_rejects_unknown_files(tmp_path: Path):
    artifacts = _write_artifacts(tmp_path)
    (artifacts / "one_link_native-0.21.0a0-cp311-abi3-win_amd64.whl").unlink()
    with pytest.raises(gen_sbom.SbomError, match="matched no file"):
        gen_sbom._artifact_inventory(
            artifacts,
            artifacts / "sbom.cdx.json",
            ARTIFACT_PATTERNS,
        )

    (artifacts / "one_link_native-0.21.0a0-cp311-abi3-win_amd64.whl").write_bytes(b"native")
    (artifacts / "unclassified.bin").write_bytes(b"unknown")
    with pytest.raises(gen_sbom.SbomError, match="unclassified release artifacts"):
        gen_sbom._artifact_inventory(
            artifacts,
            artifacts / "sbom.cdx.json",
            ARTIFACT_PATTERNS,
        )


@pytest.mark.parametrize("late_file", ["SHA256SUMS", "asset.whl.sigstore"])
def test_artifact_inventory_refuses_post_checksum_or_post_signature_state(
    tmp_path: Path,
    late_file: str,
):
    artifacts = _write_artifacts(tmp_path)
    (artifacts / late_file).write_bytes(b"late")
    with pytest.raises(gen_sbom.SbomError, match="before checksums/signatures"):
        gen_sbom._artifact_inventory(
            artifacts,
            artifacts / "sbom.cdx.json",
            ARTIFACT_PATTERNS,
        )


def test_artifact_inventory_refuses_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifacts = _write_artifacts(tmp_path)
    original_is_symlink = Path.is_symlink

    def report_fixture_as_symlink(path: Path) -> bool:
        return path.name == "one-link-windows-x86_64.zip" or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_fixture_as_symlink)
    with pytest.raises(gen_sbom.SbomError, match="symlinked release artifact"):
        gen_sbom._artifact_inventory(
            artifacts,
            artifacts / "sbom.cdx.json",
            ARTIFACT_PATTERNS,
        )


def test_frozen_requirements_requires_exact_versions_hashes_and_complete_lines(tmp_path: Path):
    valid = tmp_path / "valid.lock"
    valid.write_text(
        "demo==1.2.3 ; python_version >= '3.11' "
        + "\\"
        + "\n    --hash=sha256:"
        + "12" * 32
        + "\n",
        encoding="utf-8",
    )
    gen_sbom._validate_frozen_requirements(valid)

    unpinned = tmp_path / "unpinned.lock"
    unpinned.write_text(f"demo>=1.2 --hash=sha256:{'12' * 32}\n", encoding="utf-8")
    with pytest.raises(gen_sbom.SbomError, match="not exactly pinned"):
        gen_sbom._validate_frozen_requirements(unpinned)

    unhashed = tmp_path / "unhashed.lock"
    unhashed.write_text("demo==1.2.3\n", encoding="utf-8")
    with pytest.raises(gen_sbom.SbomError, match="no SHA-256"):
        gen_sbom._validate_frozen_requirements(unhashed)

    unfinished = tmp_path / "unfinished.lock"
    unfinished.write_text("demo==1.2.3 " + "\\", encoding="utf-8")
    with pytest.raises(gen_sbom.SbomError, match="unfinished continuation"):
        gen_sbom._validate_frozen_requirements(unfinished)


def test_cyclonedx_base_command_is_reproducible_and_schema_pinned(tmp_path: Path):
    command = gen_sbom._cyclonedx_command(
        "requirements",
        tmp_path / "requirements.lock",
        tmp_path / "pyproject.toml",
        tmp_path / "base.json",
    )
    assert command[:4] == [gen_sbom.sys.executable, "-m", "cyclonedx_py", "requirements"]
    assert "--output-reproducible" in command
    assert command[command.index("--spec-version") + 1] == "1.6"
    assert "--validate" not in command  # validation is already the CLI default
    assert "pip" not in command


def test_complete_document_passes_locked_cyclonedx_schema(tmp_path: Path):
    if importlib.util.find_spec("cyclonedx") is None:
        pytest.skip("locked release-tools dependency is not installed in this test environment")
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    artifacts = _write_artifacts(tmp_path)
    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        cargo_lock=cargo_lock,
        cargo_workspace=workspace,
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=artifacts / "sbom.cdx.json",
    )
    rendered = gen_sbom._canonical_json(merged)
    gen_sbom._strict_schema_validate(rendered)
    assert json.loads(rendered)["bomFormat"] == "CycloneDX"


def test_real_native_workspace_inventory_passes_locked_cyclonedx_schema(tmp_path: Path):
    if importlib.util.find_spec("cyclonedx") is None:
        pytest.skip("locked release-tools dependency is not installed in this test environment")
    artifacts = _write_artifacts(tmp_path)
    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        cargo_lock=REPO / "native" / "Cargo.lock",
        cargo_workspace=REPO / "native" / "Cargo.toml",
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=artifacts / "sbom.cdx.json",
    )
    gen_sbom._strict_schema_validate(gen_sbom._canonical_json(merged))


def test_independent_cargo_graphs_preserve_separate_resolutions(tmp_path: Path):
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    shell = tmp_path / "shell"
    shell.mkdir()
    manifest = shell / "Cargo.toml"
    manifest.write_text('[package]\nname="ol_shell"\nversion="0.1.0"\n[workspace]\n')
    (shell / "Cargo.lock").write_text(
        cargo_lock.read_text().replace("one_link_native", "ol_shell").replace("0.21.0-alpha.0", "0.1.0")
        + '\ndependencies = ["leaf"]\n\n[[package]]\nname="leaf"\nversion="2.0.0"\n'
    )
    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()), cargo_lock=cargo_lock, cargo_workspace=workspace,
        additional_cargo=[("shell", manifest)], output_path=tmp_path / "sbom.json",
    )
    deps = {row["ref"]: row["dependsOn"] for row in merged["dependencies"]}
    duplicate = [row for row in merged["components"] if row["purl"] == "pkg:cargo/dep@1.2.3"]
    assert len(duplicate) == 2
    main = next(row for row in duplicate if "one-link:cargo:graph" not in _property_map(row))
    other = next(row for row in duplicate if _property_map(row).get("one-link:cargo:graph") == "shell")
    assert deps[main["bom-ref"]] == []
    assert len(deps[other["bom-ref"]]) == 1
    assert deps[other["bom-ref"]][0].startswith("urn:one-link:cargo-graph:shell:")
    metadata = _property_map(merged["metadata"])
    assert metadata["one-link:sbom:cargo-graph:shell:workspace-member-count"] == "1"
    assert metadata["one-link:sbom:cargo-graph:shell:lock-sha256"] == hashlib.sha256(
        (shell / "Cargo.lock").read_bytes()
    ).hexdigest()


def test_all_three_real_cargo_graphs_are_complete_and_schema_valid(tmp_path: Path):
    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()), cargo_lock=REPO / "native/Cargo.lock",
        cargo_workspace=REPO / "native/Cargo.toml",
        additional_cargo=[("shell", REPO / "native/ol_shell/Cargo.toml"),
                          ("fuzz", REPO / "native/fuzz/Cargo.toml")],
        output_path=tmp_path / "sbom.json",
    )
    for name, path in [("shell", "native/ol_shell"), ("fuzz", "native/fuzz")]:
        expected = gen_sbom._parse_cargo_packages(REPO / path / "Cargo.lock")
        actual = [row for row in merged["components"]
                  if _property_map(row).get("one-link:cargo:graph") == name]
        assert {(row["name"], row["version"]) for row in actual} == {
            (package.name, package.version) for package in expected}
        assert all(row["purl"].startswith("pkg:cargo/") for row in actual)
        assert _property_map(merged["metadata"])[f"one-link:sbom:cargo-graph:{name}:package-count"] == str(len(expected))
    if importlib.util.find_spec("cyclonedx") is not None:
        gen_sbom._strict_schema_validate(gen_sbom._canonical_json(merged))


def test_vendored_glib_sbom_identifies_actual_bytes_and_original_advisory_identity(tmp_path: Path):
    merged = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        additional_cargo=[("shell", REPO / "native/ol_shell/Cargo.toml")],
        output_path=tmp_path / "sbom.json",
    )
    glib = next(row for row in merged["components"] if row["name"] == "glib")
    proof = json.loads((REPO / "native/ol_shell/patches/glib-0.18.5.json").read_text(encoding="utf-8"))
    assert glib["version"] == "0.18.5"
    assert glib["purl"] == "pkg:cargo/glib@0.18.5"
    assert glib["modified"] is True
    assert glib["licenses"] == [{"license": {"id": "MIT"}}]
    assert _property_map(glib)["one-link:cargo:source"] == "vendored"
    assert glib["hashes"][0]["content"] == proof["source_tree_sha256"]
    assert glib["pedigree"]["ancestors"][0]["hashes"][0]["content"] == proof["upstream"]["crate_sha256"]
    assert glib["pedigree"]["patches"][0]["type"] == "backport"
    if importlib.util.find_spec("cyclonedx") is not None:
        gen_sbom._strict_schema_validate(gen_sbom._canonical_json(merged))


@pytest.mark.parametrize("names", [("native",), ("shell", "shell"), ("bad graph",)])
def test_additional_cargo_graph_names_are_unambiguous(tmp_path: Path, names):
    with pytest.raises(gen_sbom.SbomError, match="Cargo graph name"):
        gen_sbom.augment_sbom(
            copy.deepcopy(_base_bom()),
            additional_cargo=[(name, tmp_path / "Cargo.toml") for name in names],
            output_path=tmp_path / "sbom.json",
        )


def test_cli_builds_atomic_reproducible_complete_document(tmp_path: Path):
    if importlib.util.find_spec("cyclonedx") is None:
        pytest.skip("locked release-tools dependency is not installed in this test environment")
    requirements = tmp_path / "requirements.lock"
    requirements.write_text(
        f"example==1.0.0 --hash=sha256:{'34' * 32}\n",
        encoding="utf-8",
    )
    cargo_lock, workspace = _write_cargo_fixture(tmp_path)
    python_lock = _write_python_lock(tmp_path)
    artifacts = _write_artifacts(tmp_path)
    output = artifacts / "sbom.cdx.json"
    arguments = [
        "--from",
        "requirements",
        "--requirements",
        str(requirements),
        "--python-lock",
        str(python_lock),
        "--exclude-python-extra",
        "native",
        "--cargo-lock",
        str(cargo_lock),
        "--cargo-workspace",
        str(workspace),
        "--artifacts-dir",
        str(artifacts),
        *[
            value
            for pattern in ARTIFACT_PATTERNS
            for value in ("--artifact-pattern", pattern)
        ],
        "--output",
        str(output),
    ]

    assert gen_sbom.main(arguments) == 0
    first = output.read_bytes()
    assert gen_sbom.main(arguments) == 0
    assert output.read_bytes() == first
    document = json.loads(first)
    names = {component["name"] for component in document["components"]}
    assert "one_link_native" in names
    assert "one-link-windows-x86_64.zip" in names
    root_ref = document["metadata"]["component"]["bom-ref"]
    root_dependency = next(item for item in document["dependencies"] if item["ref"] == root_ref)
    assert len(root_dependency["dependsOn"]) == 1
    metadata_properties = _property_map(document["metadata"])
    assert metadata_properties["one-link:sbom:python-package-count"] == "1"
    assert metadata_properties["one-link:sbom:python-excluded-root-extras"] == "native"

    checksum_manifest = _write_checksums(artifacts, output)
    verify_arguments = [
        "--verify-release-sbom",
        str(output),
        "--artifacts-dir",
        str(artifacts),
        *[
            value
            for pattern in ARTIFACT_PATTERNS
            for value in ("--artifact-pattern", pattern)
        ],
        "--checksum-manifest",
        str(checksum_manifest),
    ]
    assert gen_sbom.main(verify_arguments) == 0


def test_release_verification_detects_artifact_and_manifest_drift(tmp_path: Path):
    if importlib.util.find_spec("cyclonedx") is None:
        pytest.skip("locked release-tools dependency is not installed in this test environment")
    artifacts = _write_artifacts(tmp_path)
    output = artifacts / "sbom.cdx.json"
    document = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=output,
    )
    output.write_text(gen_sbom._canonical_json(document), encoding="utf-8", newline="\n")
    checksums = _write_checksums(artifacts, output)
    gen_sbom.verify_release_inventory(output, artifacts, ARTIFACT_PATTERNS, checksums)

    changed = artifacts / "one-link-windows-x86_64.zip"
    changed.write_bytes(b"tampered-after-sbom")
    with pytest.raises(gen_sbom.SbomError, match="changed=.*one-link-windows"):
        gen_sbom.verify_release_inventory(output, artifacts, ARTIFACT_PATTERNS, checksums)

    changed.write_bytes(b"standalone-bundle")
    checksums.write_text(
        checksums.read_text(encoding="utf-8") + f"{'00' * 32}  unexpected.zip\n",
        encoding="utf-8",
    )
    with pytest.raises(gen_sbom.SbomError, match="SHA256SUMS does not match"):
        gen_sbom.verify_release_inventory(output, artifacts, ARTIFACT_PATTERNS, checksums)


def test_release_verification_binds_non_circular_update_authority(tmp_path: Path):
    artifacts = _write_artifacts(tmp_path)
    output = artifacts / "sbom.cdx.json"
    document = gen_sbom.augment_sbom(
        copy.deepcopy(_base_bom()),
        artifact_dir=artifacts,
        artifact_patterns=ARTIFACT_PATTERNS,
        output_path=output,
    )
    output.write_text(gen_sbom._canonical_json(document), encoding="utf-8", newline="\n")
    update_manifest = artifacts / "UPDATE_MANIFEST.json"
    update_manifest.write_text('{"schema":"one-link-update-v1"}\n', encoding="utf-8")
    checksums = _write_checksums(artifacts, output)

    with pytest.raises(gen_sbom.SbomError, match="unclassified.*UPDATE_MANIFEST"):
        gen_sbom.verify_release_inventory(output, artifacts, ARTIFACT_PATTERNS, checksums)
    gen_sbom.verify_release_inventory(
        output,
        artifacts,
        ARTIFACT_PATTERNS,
        checksums,
        checksum_auxiliary=("UPDATE_MANIFEST.json",),
    )

    update_manifest.write_text('{"schema":"tampered"}\n', encoding="utf-8")
    with pytest.raises(gen_sbom.SbomError, match="changed=.*UPDATE_MANIFEST"):
        gen_sbom.verify_release_inventory(
            output,
            artifacts,
            ARTIFACT_PATTERNS,
            checksums,
            checksum_auxiliary=("UPDATE_MANIFEST.json",),
        )
