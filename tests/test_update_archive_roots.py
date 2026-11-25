"""Exercise canonical bundle roots through metadata and inert update transactions.

The fixtures contain data, never runnable payloads. Signature verification is
outside this module: parser calls model the already authenticated metadata
boundary while retaining the exact archive digest and layout binding.
"""

from __future__ import annotations

from copy import copy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import zipfile

import pytest

from one_link.update_metadata import (
    PLATFORM_CONTRACTS,
    StandaloneArtifact,
    UpdateMetadataError,
    canonical_update_metadata_bytes,
    parse_authenticated_update_manifest,
)
import one_link.update_transaction as transaction


REPO = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 23, 12, tzinfo=UTC)
KEY = bytes.fromhex("42" * 32)
MAC = "macos-arm64"
EXE = "Contents/MacOS/one-link"


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        f"_root_test_{name}", REPO / "scripts" / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _package(parent: Path, root: str, marker: bytes, *, executable: str = EXE):
    bundle = parent / root
    exe = bundle / executable
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"inert fixture: " + marker)
    exe.chmod(0o755)
    (bundle / "payload.dat").write_bytes(marker)
    archive = parent / "bundle.zip"
    _load_script("package_standalone_bundle").package_bundle(
        bundle,
        archive,
        executable=executable,
        epoch=1700000000,
    )
    return bundle, archive


def _artifact(archive: Path, root: str) -> StandaloneArtifact:
    return StandaloneArtifact(
        platform=MAC,
        filename=PLATFORM_CONTRACTS[MAC].filename,
        size=archive.stat().st_size,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        bundle_root=root,
        executable=EXE,
        kind="standalone-zip-v1",
    )


def _document(tmp_path: Path, *, root: str = "one-link.app"):
    dist = tmp_path / "dist"
    dist.mkdir()
    for platform, contract in PLATFORM_CONTRACTS.items():
        archive_root = root if platform == MAC else "one-link"
        _, archive = _package(
            tmp_path / "input" / platform,
            archive_root,
            f"new:{platform}".encode(),
            executable=contract.executable,
        )
        (dist / contract.filename).write_bytes(archive.read_bytes())
    (dist / "sbom.cdx.json").write_bytes(b'{"bomFormat":"CycloneDX"}\n')
    document = _load_script("generate_update_manifest").build_update_document(
        dist_dir=dist,
        tag="v0.22.0",
        commit_sha="a" * 40,
        source_date_epoch=int(datetime(2026, 7, 1, tzinfo=UTC).timestamp()),
        minimum_source_version="0.20.0",
    )
    return document, dist / PLATFORM_CONTRACTS[MAC].filename


def _parse(document):
    return parse_authenticated_update_manifest(
        canonical_update_metadata_bytes(document),
        verified_tag="v0.22.0",
        now=NOW,
    )


def _mac_entry(document):
    return next(entry for entry in document["artifacts"] if entry["platform"] == MAC)


def _prepared(tmp_path: Path, root: str):
    document, archive = _document(tmp_path, root=root)
    _mac_entry(document)["bundle_root"] = root
    manifest = _parse(document)
    install, old_archive = _package(tmp_path / "old", root, b"old")
    with zipfile.ZipFile(old_archive) as old:
        (install / "BUNDLE_SHA256SUMS").write_bytes(old.read(f"{root}/BUNDLE_SHA256SUMS"))
    state = tmp_path / "state"
    journal = transaction.prepare_update_transaction(
        manifest=manifest,
        platform_key=MAC,
        archive_path=archive,
        install_root=install,
        state_root=state,
        authority_key=KEY,
        current_version="0.21.0",
        now=NOW,
    )
    return install, state, journal


def _activate(state: Path, *, fault=lambda _point: None):
    return transaction.activate_prepared_update(
        state_root=state,
        authority_key=KEY,
        process_guard=transaction.ProcessGuard(123, "f" * 64, "/inert-fixture"),
        identity_reader=lambda _pid: None,
        process_timeout=0,
        now=NOW + timedelta(seconds=10),
        fault=fault,
    )


def test_release_metadata_names_the_canonical_root_for_each_platform(tmp_path: Path):
    document, archive = _document(tmp_path)
    expected = {key: "one-link.app" if key == MAC else "one-link" for key in PLATFORM_CONTRACTS}
    assert {entry["platform"]: entry["bundle_root"] for entry in document["artifacts"]} == expected
    manifest = _parse(document)
    assert {key: value.bundle_root for key, value in manifest.artifacts.items()} == expected
    assert manifest.artifact_for(MAC).sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()


@pytest.mark.parametrize("root", ["one-link", "one-link.app"])
def test_mac_metadata_retains_the_authenticated_root_including_legacy(root: str, tmp_path: Path):
    document, _ = _document(tmp_path, root=root)
    _mac_entry(document)["bundle_root"] = root
    assert _parse(document).artifact_for(MAC).bundle_root == root


@pytest.mark.parametrize(
    ("platform", "root"),
    [
        (MAC, "other"),
        (MAC, "../one-link.app"),
        (MAC, "one-link.app/child"),
        ("linux-x86_64", "one-link.app"),
        ("windows-arm64", "one-link.app"),
    ],
)
def test_metadata_rejects_noncanonical_or_wrong_platform_roots(platform, root, tmp_path: Path):
    document, _ = _document(tmp_path)
    next(entry for entry in document["artifacts"] if entry["platform"] == platform)[
        "bundle_root"
    ] = root
    with pytest.raises(UpdateMetadataError, match="standalone contract"):
        _parse(document)


@pytest.mark.parametrize("root", ["one-link", "one-link.app"])
def test_canonical_archive_passes_actual_index_extract_and_installed_checks(
    root: str, tmp_path: Path
):
    _, archive = _package(tmp_path / "input", root, b"candidate")
    packager = _load_script("package_standalone_bundle")
    packager.validate_bundle_archive(archive, expected_executable=f"{root}/{EXE}")
    with zipfile.ZipFile(archive) as opened:
        infos, raw, rows = transaction._validate_zip_index(opened, expected_executable=EXE)
        assert set(rows) == {f"{root}/{EXE}", f"{root}/payload.dat"}
        assert len(infos) == 3
    tree = transaction.extract_authenticated_bundle(
        archive, tmp_path / "stage", artifact=_artifact(archive, root)
    )
    assert tree.root == tmp_path / "stage" / root
    assert tree.manifest_sha256 == hashlib.sha256(raw).hexdigest()
    assert transaction.validate_installed_bundle(tree.root, expected_executable=EXE) == tree


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows symlink creation is not portable")
def test_app_framework_chain_survives_canonical_packaging_and_extraction(tmp_path: Path):
    bundle = tmp_path / "input" / "one-link.app"
    exe = bundle / EXE
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"inert launcher")
    exe.chmod(0o755)
    framework = bundle / "Contents" / "Frameworks" / "Python.framework"
    version = framework / "Versions" / "3.12"
    version.mkdir(parents=True)
    (version / "Python").write_bytes(b"inert framework")
    (framework / "Versions" / "Current").symlink_to("3.12", target_is_directory=True)
    (framework / "Python").symlink_to("Versions/Current/Python")
    archive = tmp_path / "framework.zip"
    _load_script("package_standalone_bundle").package_bundle(
        bundle, archive, executable=EXE, epoch=1700000000
    )
    tree = transaction.extract_authenticated_bundle(
        archive, tmp_path / "stage", artifact=_artifact(archive, "one-link.app")
    )
    assert (
        tree.root / "Contents/Frameworks/Python.framework/Python"
    ).read_bytes() == b"inert framework"
    assert transaction.validate_installed_bundle(tree.root, expected_executable=EXE) == tree


@pytest.mark.parametrize("root", ["one-link", "one-link.app"])
def test_archive_root_must_equal_signed_root_and_failure_retires_only_stage(
    root: str, tmp_path: Path
):
    _, archive = _package(tmp_path / "input", root, b"candidate")
    signed_root = "one-link" if root == "one-link.app" else "one-link.app"
    untouched = tmp_path / "keep.dat"
    untouched.write_bytes(b"outside stage")
    stage = tmp_path / "stage"
    with pytest.raises(transaction.UpdateArchiveError, match="root differs from signed"):
        transaction.extract_authenticated_bundle(
            archive, stage, artifact=_artifact(archive, signed_root)
        )
    assert not stage.exists()
    assert untouched.read_bytes() == b"outside stage"


@pytest.mark.parametrize(
    "bad_root", ["other", "../one-link.app", "/one-link.app", "one-link.app/.."]
)
def test_index_rejects_arbitrary_or_traversing_roots(bad_root: str, tmp_path: Path):
    _, archive = _package(tmp_path / "input", "one-link.app", b"candidate")
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(changed, "w") as output:
        for info in source.infolist():
            item = copy(info)
            item.filename = info.filename.replace("one-link.app/", f"{bad_root}/", 1)
            payload = source.read(info)
            if info.filename.endswith("/BUNDLE_SHA256SUMS"):
                payload = payload.replace(b"one-link.app/", f"{bad_root}/".encode())
            output.writestr(item, payload)
    with zipfile.ZipFile(changed) as opened, pytest.raises(transaction.UpdateArchiveError):
        transaction._validate_zip_index(opened, expected_executable=EXE)


@pytest.mark.parametrize("extra", ["one-link/extra", "ONE-LINK.APP/payload.dat"])
def test_index_rejects_mixed_or_portable_colliding_roots(extra: str, tmp_path: Path):
    _, archive = _package(tmp_path / "input", "one-link.app", b"candidate")
    with zipfile.ZipFile(archive, "a") as output:
        output.writestr(extra, b"extra")
    with zipfile.ZipFile(archive) as opened, pytest.raises(transaction.UpdateArchiveError):
        transaction._validate_zip_index(opened, expected_executable=EXE)


def test_installed_manifest_cannot_select_an_arbitrary_root(tmp_path: Path):
    bundle, archive = _package(tmp_path / "input", "one-link.app", b"candidate")
    with zipfile.ZipFile(archive) as opened:
        raw = opened.read("one-link.app/BUNDLE_SHA256SUMS")
    (bundle / "BUNDLE_SHA256SUMS").write_bytes(raw.replace(b"one-link.app/", b"other/"))
    with pytest.raises(transaction.UpdateArchiveError, match="root"):
        transaction.validate_installed_bundle(bundle, expected_executable=EXE)


def test_manifest_rows_cannot_switch_the_archive_root(tmp_path: Path):
    _, archive = _package(tmp_path / "input", "one-link.app", b"candidate")
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(changed, "w") as output:
        for info in source.infolist():
            payload = source.read(info)
            if info.filename.endswith("/BUNDLE_SHA256SUMS"):
                payload = payload.replace(b"one-link.app/", b"one-link/")
            output.writestr(info, payload)
    with (
        zipfile.ZipFile(changed) as opened,
        pytest.raises(transaction.UpdateArchiveError, match="unsafe archive member"),
    ):
        transaction._validate_zip_index(opened, expected_executable=EXE)


@pytest.mark.parametrize("root", ["one-link", "one-link.app"])
def test_full_inert_transaction_preserves_root_through_health_commit(root: str, tmp_path: Path):
    install, state, prepared = _prepared(tmp_path, root)
    assert prepared.bundle_root == root
    assert (
        (Path(prepared.stage_container) / root / EXE)
        .read_bytes()
        .startswith(b"inert fixture: new:")
    )
    assert (install / EXE).read_bytes() == b"inert fixture: old"
    assert transaction.AuthenticatedUpdateState(state, KEY).read_journal() == prepared
    active = _activate(state)
    assert active.phase == transaction.TransactionPhase.CANDIDATE_ACTIVE.value
    committed = transaction.mark_update_healthy(
        state_root=state,
        authority_key=KEY,
        running_executable=install / EXE,
        observed_version="0.22.0",
        health_probe=lambda path: path.read_bytes().startswith(b"inert fixture: new:"),
        now=NOW + timedelta(seconds=20),
    )
    assert committed.phase == transaction.TransactionPhase.COMMITTED.value
    assert committed.bundle_root == root
    assert not Path(committed.stage_container).exists()
    assert not Path(committed.backup_root).exists()
    assert (
        transaction.recover_update_transaction(state_root=state, authority_key=KEY, now=NOW).status
        == "committed"
    )


class _PowerLoss(BaseException):
    pass


@pytest.mark.parametrize("root", ["one-link", "one-link.app"])
@pytest.mark.parametrize(
    "point",
    ["prepared", "after_backup_rename_before_journal", "after_candidate_rename_before_journal"],
)
def test_inert_crash_recovery_uses_the_authenticated_root(root, point, tmp_path: Path):
    install, state, prepared = _prepared(tmp_path, root)
    if point != "prepared":

        def crash(observed):
            if observed == point:
                raise _PowerLoss(observed)

        with pytest.raises(_PowerLoss):
            _activate(state, fault=crash)
    result = transaction.recover_update_transaction(
        state_root=state, authority_key=KEY, now=NOW + timedelta(minutes=10)
    )
    assert result.status == "rolled_back"
    assert (install / EXE).read_bytes() == b"inert fixture: old"
    assert (
        transaction.validate_installed_bundle(install, expected_executable=EXE).manifest_sha256
        == prepared.previous_manifest_sha256
    )
    assert not Path(prepared.stage_container).exists()


def test_existing_authenticated_journal_without_root_uses_legacy_root(tmp_path: Path):
    install, state, prepared = _prepared(tmp_path, "one-link")
    store = transaction.AuthenticatedUpdateState(state, KEY)
    payload = asdict(prepared)
    payload.pop("bundle_root", None)
    store._write(transaction.JOURNAL_FILENAME, kind=transaction.JOURNAL_KIND, payload=payload)
    assert store.read_journal().bundle_root == "one-link"
    _activate(state)
    assert (install / EXE).read_bytes().startswith(b"inert fixture: new:")


@pytest.mark.parametrize(
    ("platform", "root"),
    [(MAC, "other"), (MAC, "../one-link.app"), ("linux-x86_64", "one-link.app")],
)
def test_journal_rejects_unsafe_or_wrong_platform_root(platform, root, tmp_path: Path):
    _, state, prepared = _prepared(tmp_path, "one-link")
    with pytest.raises(transaction.UpdateStateError, match="root"):
        transaction.AuthenticatedUpdateState(state, KEY).write_journal(
            replace(prepared, platform=platform, bundle_root=root)
        )
