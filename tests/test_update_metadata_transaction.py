"""Adversarial proof for signed standalone metadata and update transactions."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest

import one_link.update_transaction as transaction_module
from one_link.lockbox import LockBox

from one_link.update_metadata import (
    PLATFORM_CONTRACTS,
    AuthenticatedUpdateManifest,
    StandaloneArtifact,
    UpdateMetadataError,
    canonical_update_metadata_bytes,
    host_platform_key,
    parse_authenticated_update_manifest,
    rollback_index_for_version,
)
from one_link.update_transaction import (
    AuthenticatedUpdateState,
    HighWaterBinding,
    ProcessGuard,
    ProcessIdentity,
    TransactionPhase,
    UpdateArchiveError,
    UpdateHighWater,
    UpdatePathError,
    UpdateProcessStillRunning,
    UpdateRollbackError,
    UpdateStateError,
    UpdateTransactionError,
    acquire_update_state_authority,
    activate_prepared_update,
    capture_process_guard,
    extract_authenticated_bundle,
    mark_update_healthy,
    prepare_update_transaction,
    recover_update_transaction,
    require_guarded_process_exit,
    validate_installed_bundle,
)


NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)
AUTHORITY_KEY = bytes.fromhex("42" * 32)
PLATFORM_KEY = "linux-x86_64"
EXECUTABLE = PLATFORM_CONTRACTS[PLATFORM_KEY].executable


class SimulatedPowerLoss(BaseException):
    pass


def _manifest_bytes(files: dict[str, tuple[bytes, int]]) -> bytes:
    rows = ["# sha256\tkind\tbytes\tpath\ttarget"]
    for relative, (payload, _mode) in sorted(files.items()):
        rows.append(
            "\t".join(
                (
                    hashlib.sha256(payload).hexdigest(),
                    "FILE",
                    str(len(payload)),
                    f"one-link/{relative}",
                    "",
                )
            )
        )
    return ("\n".join(rows) + "\n").encode("utf-8")


def _write_bundle(root: Path, *, marker: bytes, executable: str = EXECUTABLE) -> Path:
    files = {
        executable: (b"#!/bin/sh\n" + marker + b"\n", 0o755),
        "_internal/runtime.bin": (b"runtime:" + marker, 0o644),
        "_internal/one_link/version.txt": (marker, 0o644),
    }
    root.mkdir(parents=True)
    for relative, (payload, mode) in files.items():
        path = root.joinpath(*Path(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        if os.name != "nt":
            path.chmod(mode)
    (root / "BUNDLE_SHA256SUMS").write_bytes(_manifest_bytes(files))
    if os.name != "nt":
        (root / "BUNDLE_SHA256SUMS").chmod(0o644)
    return root


def _write_bundle_zip(
    path: Path,
    *,
    marker: bytes,
    executable: str = EXECUTABLE,
) -> Path:
    files = {
        executable: (b"#!/bin/sh\n" + marker + b"\n", 0o755),
        "_internal/runtime.bin": (b"runtime:" + marker, 0o644),
        "_internal/one_link/version.txt": (marker, 0o644),
    }
    manifest = _manifest_bytes(files)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, (payload, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(f"one-link/{relative}")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
        info = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest)
    return path


def _artifact_for_archive(path: Path, *, platform_key: str = PLATFORM_KEY) -> StandaloneArtifact:
    contract = PLATFORM_CONTRACTS[platform_key]
    return StandaloneArtifact(
        platform=platform_key,
        filename=contract.filename,
        size=path.stat().st_size,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        bundle_root="one-link",
        executable=contract.executable,
        kind="standalone-zip-v1",
    )


def _document(
    artifact: StandaloneArtifact,
    *,
    version: str = "0.22.0",
    commit: str = "a" * 40,
    created_at: str = "2026-07-01T00:00:00Z",
    expires_at: str = "2026-12-01T00:00:00Z",
) -> dict[str, object]:
    entries = []
    for platform_key, contract in PLATFORM_CONTRACTS.items():
        selected = artifact if platform_key == artifact.platform else None
        entries.append(
            {
                "platform": platform_key,
                "filename": contract.filename,
                "size": selected.size if selected else 123,
                "sha256": selected.sha256 if selected else hashlib.sha256(platform_key.encode()).hexdigest(),
                "bundle_root": "one-link",
                "executable": contract.executable,
                "kind": "standalone-zip-v1",
            }
        )
    return {
        "schema": "one-link-update-manifest/v1",
        "tag": f"v{version}",
        "version": version,
        "rollback_index": rollback_index_for_version(version),
        "minimum_source_version": "0.20.0",
        "created_at": created_at,
        "expires_at": expires_at,
        "source": {
            "repository": "coherence-energy-labs/one-link",
            "workflow": ".github/workflows/release.yml",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "commit_sha": commit,
            "ref": f"refs/tags/v{version}",
        },
        "sbom": {
            "filename": "sbom.cdx.json",
            "size": 321,
            "sha256": hashlib.sha256(b"sbom").hexdigest(),
        },
        "artifacts": entries,
    }


def _parsed_manifest(
    artifact: StandaloneArtifact,
    *,
    version: str = "0.22.0",
    commit: str = "a" * 40,
) -> AuthenticatedUpdateManifest:
    document = _document(artifact, version=version, commit=commit)
    return parse_authenticated_update_manifest(
        canonical_update_metadata_bytes(document),
        verified_tag=f"v{version}",
        now=NOW,
    )


@pytest.fixture
def transaction_inputs(tmp_path: Path):
    install = _write_bundle(tmp_path / "installed-one-link", marker=b"old-0.21")
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new-0.22")
    artifact = _artifact_for_archive(archive)
    manifest = _parsed_manifest(artifact)
    state = tmp_path / "state"
    return install, archive, artifact, manifest, state


def _prepare(transaction_inputs, **overrides):
    install, archive, _artifact, manifest, state = transaction_inputs
    arguments = {
        "manifest": manifest,
        "platform_key": PLATFORM_KEY,
        "archive_path": archive,
        "install_root": install,
        "state_root": state,
        "authority_key": AUTHORITY_KEY,
        "current_version": "0.21.0",
        "now": NOW,
    }
    arguments.update(overrides)
    return prepare_update_transaction(**arguments)


def _stopped_guard() -> ProcessGuard:
    return ProcessGuard(pid=32123, instance_token="f" * 64, executable="/managed/one-link")


def _activate(state: Path, **overrides):
    arguments = {
        "state_root": state,
        "authority_key": AUTHORITY_KEY,
        "process_guard": _stopped_guard(),
        "identity_reader": lambda _pid: None,
        "process_timeout": 0,
        "now": NOW + timedelta(seconds=10),
    }
    arguments.update(overrides)
    return activate_prepared_update(**arguments)


# ── authenticated metadata ───────────────────────────────────────────


def test_authenticated_metadata_accepts_complete_exact_contract(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    artifact = _artifact_for_archive(archive)
    document = _document(artifact)
    raw = canonical_update_metadata_bytes(document)
    parsed = parse_authenticated_update_manifest(raw, verified_tag="v0.22.0", now=NOW)
    assert parsed.tag == "v0.22.0"
    assert str(parsed.version) == "0.22.0"
    assert parsed.commit_sha == "a" * 40
    assert parsed.artifact_for(PLATFORM_KEY) == artifact
    assert parsed.authenticated_metadata_sha256 == hashlib.sha256(raw).hexdigest()


def test_authenticated_metadata_rejects_noncanonical_json(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    document = _document(_artifact_for_archive(archive))
    raw = json.dumps(document, indent=2).encode() + b"\n"
    with pytest.raises(UpdateMetadataError, match="canonically"):
        parse_authenticated_update_manifest(raw, verified_tag="v0.22.0", now=NOW)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda d: d.update(extra=True), "fields differ"),
        (lambda d: d.update(schema="one-link-update-manifest/v2"), "unsupported"),
        (lambda d: d.update(tag="v0.22.1"), "verified Sigstore"),
        (lambda d: d.update(version="0.22.0rc1"), "stable"),
        (lambda d: d.update(rollback_index=0), "rollback_index"),
        (lambda d: d["source"].update(repository="attacker/repo"), "canonical repository"),
        (lambda d: d["source"].update(workflow=".github/workflows/evil.yml"), "release authority"),
        (lambda d: d["source"].update(commit_sha="a" * 39), "full lowercase"),
        (lambda d: d["source"].update(ref="refs/heads/master"), "release tag"),
        (lambda d: d["sbom"].update(filename="bill.json"), "SBOM filename"),
        (lambda d: d["artifacts"].pop(), "complete supported-platform"),
        (lambda d: d["artifacts"][0].update(bundle_root="../../escape"), "standalone contract"),
        (lambda d: d["artifacts"][0].update(kind="installer"), "standalone contract"),
    ],
)
def test_authenticated_metadata_rejects_authority_mutations(
    tmp_path: Path,
    mutation,
    message: str,
):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    document = _document(_artifact_for_archive(archive))
    mutation(document)
    with pytest.raises(UpdateMetadataError, match=message):
        parse_authenticated_update_manifest(
            canonical_update_metadata_bytes(document),
            verified_tag="v0.22.0",
            now=NOW,
        )


def test_authenticated_metadata_rejects_expired_and_future_authority(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    artifact = _artifact_for_archive(archive)
    expired = _document(
        artifact,
        created_at="2026-02-01T00:00:00Z",
        expires_at="2026-07-23T11:59:59Z",
    )
    with pytest.raises(UpdateMetadataError, match="expired"):
        parse_authenticated_update_manifest(
            canonical_update_metadata_bytes(expired), verified_tag="v0.22.0", now=NOW
        )
    future = _document(
        artifact,
        created_at="2026-07-23T13:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
    )
    with pytest.raises(UpdateMetadataError, match="future"):
        parse_authenticated_update_manifest(
            canonical_update_metadata_bytes(future), verified_tag="v0.22.0", now=NOW
        )


def test_authenticated_metadata_rejects_excessive_validity_window(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    document = _document(
        _artifact_for_archive(archive),
        created_at="2026-01-01T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
    )
    with pytest.raises(UpdateMetadataError, match="validity window"):
        parse_authenticated_update_manifest(
            canonical_update_metadata_bytes(document), verified_tag="v0.22.0", now=NOW
        )


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Windows", "AMD64", "windows-x86_64"),
        ("Windows", "ARM64", "windows-arm64"),
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "arm64", "macos-arm64"),
    ],
)
def test_host_platform_key_exact_matrix(system: str, machine: str, expected: str):
    assert host_platform_key(system=system, machine=machine) == expected


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Darwin", "x86_64"), ("FreeBSD", "x86_64"), ("Linux", "riscv64")],
)
def test_host_platform_key_rejects_unpublished_targets(system: str, machine: str):
    with pytest.raises(UpdateMetadataError, match="unsupported"):
        host_platform_key(system=system, machine=machine)


def test_rollback_index_is_monotonic_and_rejects_prereleases():
    assert rollback_index_for_version("1.2.4") > rollback_index_for_version("1.2.3")
    assert rollback_index_for_version("1.3.0") > rollback_index_for_version("1.2.65535")
    with pytest.raises(UpdateMetadataError, match="stable"):
        rollback_index_for_version("1.2.3rc1")


# ── archive and current-install validation ───────────────────────────


def test_extract_authenticated_bundle_rehashes_every_member(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    artifact = _artifact_for_archive(archive)
    tree = extract_authenticated_bundle(archive, tmp_path / "stage", artifact=artifact)
    assert tree.root == tmp_path / "stage" / "one-link"
    assert tree.file_count == 3
    assert tree.payload_bytes > 0
    assert len(tree.manifest_sha256) == 64
    assert validate_installed_bundle(tree.root, expected_executable=EXECUTABLE) == tree


def _write_framework_zip(path: Path, links: dict[str, str]) -> Path:
    """Archive links as target bytes, including hostile fixtures no OS can create."""
    files = {
        EXECUTABLE: b"launcher fixture",
        "_internal/Python.framework/Versions/3.12/Python": b"framework fixture",
    }
    rows = ["# sha256\tkind\tbytes\tpath\ttarget"]
    with zipfile.ZipFile(path, "w") as archive:
        for relative in sorted(set(files) | set(links)):
            target = links.get(relative, "")
            kind = "SYMLINK" if relative in links else "FILE"
            payload = target.encode("utf-8") if kind == "SYMLINK" else files[relative]
            info = zipfile.ZipInfo("one-link/" + relative)
            info.create_system = 3
            mode = stat.S_IFLNK | 0o777 if kind == "SYMLINK" else stat.S_IFREG | 0o755
            info.external_attr = mode << 16
            archive.writestr(info, payload)
            rows.append("\t".join((hashlib.sha256(payload).hexdigest(), kind,
                                    str(len(payload)), info.filename, target)))
        info = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, "\n".join(rows) + "\n")
    return path


def test_updater_index_accepts_framework_link_chain(tmp_path: Path):
    links = {
        "_internal/Python": "Python.framework/Python",
        "_internal/Python.framework/Python": "Versions/Current/Python",
        "_internal/Python.framework/Versions/Current": "3.12",
    }
    archive_path = _write_framework_zip(tmp_path / "framework.zip", links)
    with zipfile.ZipFile(archive_path) as archive:
        _, _, rows = transaction_module._validate_zip_index(archive, expected_executable=EXECUTABLE)
    assert len(rows) == 5


@pytest.mark.skipif(os.name == "nt", reason="Windows updates deliberately refuse symlink payloads")
def test_authenticated_framework_chain_extracts_and_revalidates(tmp_path: Path):
    links = {
        "_internal/Python": "Python.framework/Python",
        "_internal/Python.framework/Python": "Versions/Current/Python",
        "_internal/Python.framework/Versions/Current": "3.12",
    }
    archive_path = _write_framework_zip(tmp_path / "framework.zip", links)
    tree = extract_authenticated_bundle(archive_path, tmp_path / "stage",
                                        artifact=_artifact_for_archive(archive_path))
    assert tree.file_count == 5
    assert (tree.root / "_internal/Python").read_bytes() == b"framework fixture"
    for relative, target in links.items():
        assert (tree.root / relative).is_symlink()
        assert os.readlink(tree.root / relative) == target
    assert validate_installed_bundle(tree.root, expected_executable=EXECUTABLE) == tree


@pytest.mark.parametrize("links", [
    {"_internal/a": "b", "_internal/b": "a"},
    {"_internal/entry": "loop/Python", "_internal/loop": "loop"},
    {"_internal/entry": "directory/Python", "_internal/directory": "../../outside"},
    {"_internal/entry": "/outside"},
    {"_internal/entry": "missing/Python"},
    {"_internal": "elsewhere"},
], ids=["direct-cycle", "directory-cycle", "escaping-chain", "absolute", "dangling", "linked-ancestor"])
def test_updater_index_rejects_unsafe_link_chains_before_extraction(tmp_path: Path, links):
    archive_path = _write_framework_zip(tmp_path / "unsafe.zip", links)
    with zipfile.ZipFile(archive_path) as archive, pytest.raises(UpdateArchiveError):
        transaction_module._validate_zip_index(archive, expected_executable=EXECUTABLE)
    with pytest.raises(UpdateArchiveError):
        extract_authenticated_bundle(archive_path, tmp_path / "stage",
                                     artifact=_artifact_for_archive(archive_path))
    assert not (tmp_path / "stage").exists()
    assert not (tmp_path / "outside").exists()


def test_extract_rejects_outer_digest_mismatch(tmp_path: Path):
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new")
    artifact = _artifact_for_archive(archive)
    tampered = StandaloneArtifact(**{**asdict(artifact), "sha256": "0" * 64})
    with pytest.raises(UpdateArchiveError, match="differs from authenticated"):
        extract_authenticated_bundle(archive, tmp_path / "stage", artifact=tampered)
    assert not (tmp_path / "stage").exists()


def test_extract_rejects_member_manifest_digest_mismatch(tmp_path: Path):
    archive_path = tmp_path / "candidate.zip"
    payload = b"actual"
    bad_manifest = (
        "# sha256\tkind\tbytes\tpath\ttarget\n"
        + f"{'0' * 64}\tFILE\t{len(payload)}\tone-link/{EXECUTABLE}\t\n"
    ).encode()
    with zipfile.ZipFile(archive_path, "w") as archive:
        executable = zipfile.ZipInfo(f"one-link/{EXECUTABLE}")
        executable.create_system = 3
        executable.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(executable, payload)
        manifest = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, bad_manifest)
    with pytest.raises(UpdateArchiveError, match="differs from manifest"):
        extract_authenticated_bundle(
            archive_path,
            tmp_path / "stage",
            artifact=_artifact_for_archive(archive_path),
        )


def test_extract_rejects_portable_case_collision(tmp_path: Path):
    archive_path = tmp_path / "candidate.zip"
    files = {
        EXECUTABLE: (b"exe", 0o755),
        "Readme": (b"one", 0o644),
        "README": (b"two", 0o644),
    }
    with zipfile.ZipFile(archive_path, "w") as archive:
        for relative, (payload, mode) in files.items():
            info = zipfile.ZipInfo(f"one-link/{relative}")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, payload)
        manifest = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, _manifest_bytes(files))
    with pytest.raises(UpdateArchiveError, match="portable-colliding"):
        extract_authenticated_bundle(
            archive_path,
            tmp_path / "stage",
            artifact=_artifact_for_archive(archive_path),
        )


def test_extract_rejects_zip_slip_even_when_outer_digest_is_authenticated(tmp_path: Path):
    archive_path = tmp_path / "candidate.zip"
    member = "one-link/../outside"
    manifest_raw = (
        "# sha256\tkind\tbytes\tpath\ttarget\n"
        + f"{hashlib.sha256(b'x').hexdigest()}\tFILE\t1\t{member}\t\n"
    ).encode()
    with zipfile.ZipFile(archive_path, "w") as archive:
        info = zipfile.ZipInfo(member)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, b"x")
        exe = zipfile.ZipInfo(f"one-link/{EXECUTABLE}")
        exe.create_system = 3
        exe.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(exe, b"exe")
        manifest = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, manifest_raw)
    with pytest.raises(UpdateArchiveError, match="unsafe archive member"):
        extract_authenticated_bundle(
            archive_path,
            tmp_path / "stage",
            artifact=_artifact_for_archive(archive_path),
        )
    assert not (tmp_path / "outside").exists()


def test_validate_installed_bundle_rejects_extra_and_tampered_files(tmp_path: Path):
    root = _write_bundle(tmp_path / "bundle", marker=b"old")
    (root / "untracked.dll").write_bytes(b"surprise")
    with pytest.raises(UpdateArchiveError, match="file set"):
        validate_installed_bundle(root, expected_executable=EXECUTABLE)
    (root / "untracked.dll").unlink()
    (root / "_internal/runtime.bin").write_bytes(b"changed")
    with pytest.raises(UpdateArchiveError, match="size differs|digest differs"):
        validate_installed_bundle(root, expected_executable=EXECUTABLE)


def test_validate_installed_bundle_rejects_linked_root(tmp_path: Path):
    if os.name == "nt":
        pytest.skip("unprivileged Windows symlink creation is not portable")
    root = _write_bundle(tmp_path / "bundle", marker=b"old")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises((UpdatePathError, UpdateArchiveError), match="link"):
        validate_installed_bundle(alias, expected_executable=EXECUTABLE)


# ── process ownership ────────────────────────────────────────────────


def test_capture_process_guard_binds_exact_instance():
    identity = ProcessIdentity(77, "a" * 64, "/opt/one-link/one-link")
    guard = capture_process_guard(77, reader=lambda _pid: identity)
    assert guard == ProcessGuard(77, "a" * 64, "/opt/one-link/one-link")


def test_process_guard_wait_rejects_still_running_instance():
    guard = ProcessGuard(77, "a" * 64, "/opt/one-link/one-link")
    same = ProcessIdentity(77, "a" * 64, "/opt/one-link/one-link")
    with pytest.raises(UpdateProcessStillRunning):
        require_guarded_process_exit(
            guard,
            reader=lambda _pid: same,
            timeout=0,
            poll_interval=0.01,
        )


def test_process_guard_accepts_exit_or_pid_reuse():
    guard = ProcessGuard(77, "a" * 64, "/opt/one-link/one-link")
    require_guarded_process_exit(guard, reader=lambda _pid: None, timeout=0)
    reused = ProcessIdentity(77, "b" * 64, "/unrelated/process")
    require_guarded_process_exit(guard, reader=lambda _pid: reused, timeout=0)


# ── transaction lifecycle ────────────────────────────────────────────


def test_prepare_is_non_destructive_and_durable(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    before = validate_installed_bundle(install, expected_executable=EXECUTABLE)
    journal = _prepare(transaction_inputs)
    after = validate_installed_bundle(install, expected_executable=EXECUTABLE)
    assert before == after
    assert journal.phase == TransactionPhase.PREPARED.value
    assert Path(journal.stage_container).is_dir()
    assert not Path(journal.backup_root).exists()
    assert AuthenticatedUpdateState(state, AUTHORITY_KEY).read_journal() == journal


def test_prepare_rejects_overlapping_state_and_install(transaction_inputs):
    install, archive, _artifact, manifest, _state = transaction_inputs
    with pytest.raises(UpdatePathError, match="disjoint"):
        prepare_update_transaction(
            manifest=manifest,
            platform_key=PLATFORM_KEY,
            archive_path=archive,
            install_root=install,
            state_root=install / "state",
            authority_key=AUTHORITY_KEY,
            current_version="0.21.0",
            now=NOW,
        )


def test_prepare_rejects_tampered_current_install(transaction_inputs):
    install, _archive, _artifact, _manifest, _state = transaction_inputs
    (install / "_internal/runtime.bin").write_bytes(b"tampered")
    with pytest.raises(UpdateArchiveError):
        _prepare(transaction_inputs)


def test_prepare_failure_before_journal_retires_owned_stage(
    transaction_inputs,
    monkeypatch,
):
    install, _archive, _artifact, _manifest, _state = transaction_inputs

    def fail_journal(_self, _journal) -> None:
        raise UpdateStateError("simulated durable journal failure")

    monkeypatch.setattr(AuthenticatedUpdateState, "write_journal", fail_journal)
    with pytest.raises(UpdateStateError, match="simulated"):
        _prepare(transaction_inputs)
    assert list(install.parent.glob(f".{install.name}.update-*.stage")) == []


def test_prepare_rejects_broken_symlink_in_reserved_stage_without_following(
    transaction_inputs,
    tmp_path: Path,
    monkeypatch,
):
    if os.name == "nt":
        pytest.skip("unprivileged Windows symlink creation is not portable")
    install, _archive, _artifact, _manifest, _state = transaction_inputs
    txid = "1" * 32
    outside = tmp_path / "outside-does-not-exist"
    reserved = install.parent / f".{install.name}.update-{txid}.stage"
    reserved.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        transaction_module.secrets,
        "token_hex",
        lambda count: txid if count == 16 else "2" * (count * 2),
    )
    with pytest.raises(UpdatePathError, match="unexpectedly exists"):
        _prepare(transaction_inputs)
    assert reserved.is_symlink()
    assert not outside.exists()


def test_activation_refuses_live_guard_without_mutation(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    journal = _prepare(transaction_inputs)
    live = ProcessIdentity(32123, "f" * 64, "/managed/one-link")
    with pytest.raises(UpdateProcessStillRunning):
        activate_prepared_update(
            state_root=state,
            authority_key=AUTHORITY_KEY,
            process_guard=_stopped_guard(),
            identity_reader=lambda _pid: live,
            process_timeout=0,
            now=NOW,
        )
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        journal.previous_manifest_sha256
    )
    assert not Path(journal.backup_root).exists()


def test_full_transaction_commits_only_after_exact_health(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs)
    active = _activate(state)
    assert active.phase == TransactionPhase.CANDIDATE_ACTIVE.value
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        prepared.candidate_manifest_sha256
    )
    committed = mark_update_healthy(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        running_executable=install / EXECUTABLE,
        observed_version="0.22.0",
        health_probe=lambda executable: executable.is_file(),
        now=NOW + timedelta(seconds=20),
    )
    assert committed.phase == TransactionPhase.COMMITTED.value
    assert not Path(committed.backup_root).exists()
    assert not Path(committed.stage_container).exists()
    high_water = AuthenticatedUpdateState(state, AUTHORITY_KEY).read_high_water()
    assert high_water is not None
    assert high_water.maximum_version == "0.22.0"
    assert high_water.maximum_rollback_index == committed.rollback_index
    assert high_water.bindings[-1].artifact_sha256 == committed.artifact_sha256


def test_health_rejects_wrong_version_path_and_probe(transaction_inputs, tmp_path: Path):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    _prepare(transaction_inputs)
    _activate(state)
    with pytest.raises(UpdateStateError, match="different version"):
        mark_update_healthy(
            state_root=state,
            authority_key=AUTHORITY_KEY,
            running_executable=install / EXECUTABLE,
            observed_version="0.22.1",
            health_probe=lambda _path: True,
            now=NOW + timedelta(seconds=20),
        )
    outside = tmp_path / "outside"
    outside.write_bytes(b"not candidate")
    with pytest.raises(UpdatePathError, match="outside"):
        mark_update_healthy(
            state_root=state,
            authority_key=AUTHORITY_KEY,
            running_executable=outside,
            observed_version="0.22.0",
            health_probe=lambda _path: True,
            now=NOW + timedelta(seconds=20),
        )
    with pytest.raises(UpdateTransactionError, match="did not return exact success"):
        mark_update_healthy(
            state_root=state,
            authority_key=AUTHORITY_KEY,
            running_executable=install / EXECUTABLE,
            observed_version="0.22.0",
            health_probe=lambda _path: False,
            now=NOW + timedelta(seconds=20),
        )


def test_health_timeout_automatically_restores_previous_bundle(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs, health_window=timedelta(seconds=30))
    _activate(state)
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(minutes=1),
    )
    assert result.status == "rolled_back"
    restored = validate_installed_bundle(install, expected_executable=EXECUTABLE)
    assert restored.manifest_sha256 == prepared.previous_manifest_sha256


def test_recovery_keeps_exact_candidate_inside_health_window(transaction_inputs):
    _install, _archive, _artifact, _manifest, state = transaction_inputs
    _prepare(transaction_inputs)
    _activate(state)
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(seconds=30),
    )
    assert result.status == "awaiting_health"


@pytest.mark.parametrize(
    "point",
    [
        "after_backup_intent",
        "after_backup_rename_before_journal",
        "after_backup_created_journal",
        "after_activate_intent",
    ],
)
def test_activation_crashes_before_candidate_visibility_roll_back(transaction_inputs, point: str):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs)

    def crash(observed: str) -> None:
        if observed == point:
            raise SimulatedPowerLoss(point)

    with pytest.raises(SimulatedPowerLoss):
        _activate(state, fault=crash)
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(seconds=30),
    )
    assert result.status == "rolled_back"
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        prepared.previous_manifest_sha256
    )


def test_crash_after_candidate_rename_recovers_as_health_pending(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs)

    def crash(point: str) -> None:
        if point == "after_candidate_rename_before_journal":
            raise SimulatedPowerLoss(point)

    with pytest.raises(SimulatedPowerLoss):
        _activate(state, fault=crash)
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(seconds=30),
    )
    assert result.status == "awaiting_health"
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        prepared.candidate_manifest_sha256
    )


@pytest.mark.parametrize(
    "point",
    [
        "after_health_marker",
        "after_health_accepted_journal",
        "after_high_water_write_before_journal",
        "after_high_water_committed_journal",
        "after_backup_cleanup_before_commit_journal",
        "after_commit_journal",
    ],
)
def test_health_commit_crash_boundaries_replay_idempotently(transaction_inputs, point: str):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs)
    _activate(state)

    def crash(observed: str) -> None:
        if observed == point:
            raise SimulatedPowerLoss(point)

    with pytest.raises(SimulatedPowerLoss):
        mark_update_healthy(
            state_root=state,
            authority_key=AUTHORITY_KEY,
            running_executable=install / EXECUTABLE,
            observed_version="0.22.0",
            health_probe=lambda _path: True,
            now=NOW + timedelta(seconds=20),
            fault=crash,
        )
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(seconds=30),
    )
    assert result.status == "committed"
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        prepared.candidate_manifest_sha256
    )


def test_prepared_transaction_recovery_aborts_without_touching_active(transaction_inputs):
    install, _archive, _artifact, _manifest, state = transaction_inputs
    prepared = _prepare(transaction_inputs)
    result = recover_update_transaction(
        state_root=state,
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(seconds=5),
    )
    assert result.status == "rolled_back"
    assert validate_installed_bundle(install, expected_executable=EXECUTABLE).manifest_sha256 == (
        prepared.previous_manifest_sha256
    )
    assert not Path(prepared.stage_container).exists()


def test_authenticated_state_rejects_byte_tampering(transaction_inputs):
    _install, _archive, _artifact, _manifest, state = transaction_inputs
    _prepare(transaction_inputs)
    journal_path = state / "update-transaction.auth.json"
    raw = bytearray(journal_path.read_bytes())
    raw[len(raw) // 2] ^= 1
    journal_path.write_bytes(raw)
    with pytest.raises(UpdateStateError, match="MAC|strict JSON|canonical"):
        AuthenticatedUpdateState(state, AUTHORITY_KEY).read_journal()


def test_authenticated_state_rejects_wrong_authority_key(transaction_inputs):
    _install, _archive, _artifact, _manifest, state = transaction_inputs
    _prepare(transaction_inputs)
    with pytest.raises(UpdateStateError, match="MAC"):
        AuthenticatedUpdateState(state, bytes.fromhex("99" * 32)).read_journal()


def test_update_state_authority_is_stable_and_lockbox_protected(tmp_path: Path):
    state = tmp_path / "state"
    lockbox = LockBox(bytes.fromhex("12" * 32))
    first = acquire_update_state_authority(state, lockbox)
    second = acquire_update_state_authority(state, lockbox)
    assert len(first) == 32
    assert second == first
    wrapped = (state / "update-authority.key.wrapped").read_bytes()
    assert first not in wrapped
    with pytest.raises(UpdateStateError, match="authentication"):
        acquire_update_state_authority(state, LockBox(bytes.fromhex("34" * 32)))


def test_update_state_authority_corruption_never_mints_replacement(tmp_path: Path):
    state = tmp_path / "state"
    lockbox = LockBox(bytes.fromhex("12" * 32))
    acquire_update_state_authority(state, lockbox)
    authority_path = state / "update-authority.key.wrapped"
    corrupted = bytearray(authority_path.read_bytes())
    corrupted[-1] ^= 1
    authority_path.write_bytes(corrupted)
    before = authority_path.read_bytes()
    with pytest.raises(UpdateStateError, match="authentication"):
        acquire_update_state_authority(state, lockbox)
    assert authority_path.read_bytes() == before


def test_update_lock_excludes_concurrent_mutator(tmp_path: Path):
    first = AuthenticatedUpdateState(tmp_path / "state", AUTHORITY_KEY)
    second = AuthenticatedUpdateState(tmp_path / "state", AUTHORITY_KEY)
    with first.lock():
        with pytest.raises(UpdateStateError, match="another update transaction"):
            with second.lock():
                raise AssertionError("concurrent lock unexpectedly acquired")


def test_high_water_rejects_rollback_and_tag_reissue(transaction_inputs):
    install, archive, artifact, manifest, state = transaction_inputs
    store = AuthenticatedUpdateState(state, AUTHORITY_KEY)
    binding = HighWaterBinding(
        tag=manifest.tag,
        version=str(manifest.version),
        rollback_index=manifest.rollback_index,
        commit_sha=manifest.commit_sha,
        artifact_sha256=artifact.sha256,
        metadata_sha256=manifest.authenticated_metadata_sha256,
    )
    store.write_high_water(
        UpdateHighWater(
            maximum_version=binding.version,
            maximum_rollback_index=binding.rollback_index,
            bindings=(binding,),
        )
    )
    with pytest.raises(UpdateRollbackError, match="already committed"):
        prepare_update_transaction(
            manifest=manifest,
            platform_key=PLATFORM_KEY,
            archive_path=archive,
            install_root=install,
            state_root=state,
            authority_key=AUTHORITY_KEY,
            current_version="0.21.0",
            now=NOW,
        )
    changed_artifact = StandaloneArtifact(**{**asdict(artifact), "sha256": "1" * 64})
    changed_manifest = _parsed_manifest(changed_artifact)
    with pytest.raises(UpdateRollbackError, match="reissued"):
        prepare_update_transaction(
            manifest=changed_manifest,
            platform_key=PLATFORM_KEY,
            archive_path=archive,
            install_root=install,
            state_root=state,
            authority_key=AUTHORITY_KEY,
            current_version="0.21.0",
            now=NOW,
        )


def test_high_water_requires_monotonic_binding_history(tmp_path: Path):
    store = AuthenticatedUpdateState(tmp_path / "state", AUTHORITY_KEY)
    newer = HighWaterBinding(
        "v0.23.0",
        "0.23.0",
        rollback_index_for_version("0.23.0"),
        "b" * 40,
        "1" * 64,
        "2" * 64,
    )
    older = HighWaterBinding(
        "v0.22.0",
        "0.22.0",
        rollback_index_for_version("0.22.0"),
        "a" * 40,
        "3" * 64,
        "4" * 64,
    )
    with pytest.raises(UpdateStateError, match="non-monotonic"):
        store.write_high_water(
            UpdateHighWater(
                maximum_version="0.22.0",
                maximum_rollback_index=older.rollback_index,
                bindings=(newer, older),
            )
        )
