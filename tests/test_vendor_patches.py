"""Verify every selected local dependency source in the repository and the failure evidence contract."""

from __future__ import annotations

import difflib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

from scripts import verify_vendor_patches as vendor


ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / "native/ol_shell"
NATIVE = ROOT / "native"


def test_selected_glib_backport_preserves_upstream_identity_license_and_patch_scope():
    selected = vendor.inspect_patches(SHELL / "Cargo.toml")
    assert set(selected) == {("glib", "0.18.5")}
    proof = selected[("glib", "0.18.5")]["proof"]
    assert proof["package"]["license"] == "MIT"
    assert proof["files"]["LICENSE"] == proof["upstream_files"]["LICENSE"]
    assert proof["files"]["COPYRIGHT"] == proof["upstream_files"]["COPYRIGHT"]
    assert proof["backport"]["changed_files"] == ["src/variant_iter.rs"]
    assert proof["upstream"]["crate_sha256"] == "233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5"
    lines = selected[("glib", "0.18.5")]["patch_text"].splitlines()
    assert sum(line.startswith("+") and not line.startswith("+++") for line in lines) == 2
    assert sum(line.startswith("-") and not line.startswith("---") for line in lines) == 2


def test_workspace_metadata_declares_the_native_ml_kem_backport():
    # native/Cargo.toml has no [package]; its record lives in workspace.metadata.
    selected = vendor.inspect_patches(NATIVE / "Cargo.toml")
    assert set(selected) == {("ml-kem", "0.2.3")}
    proof = selected[("ml-kem", "0.2.3")]["proof"]
    assert proof["backport"]["changed_files"] == ["src/algebra.rs"]
    assert proof["package"]["path"] == "vendor/ml-kem-0.2.3"


def test_repository_discovery_covers_every_workspace_and_cargo_config():
    manifests, configs = vendor.discover_cargo_inputs(ROOT)
    for required in ("native/Cargo.toml", "native/fuzz/Cargo.toml", "native/ol_shell/Cargo.toml",
                     "native/ol_shell/regression/glib_variant_backport/Cargo.toml"):
        assert required in manifests
    assert "native/.cargo/config.toml" in configs


def test_every_repository_lockfile_builds_the_reviewed_backports():
    # The real gate: every workspace that resolves a backported version must
    # select the reviewed bytes, and the native and shell backports verify.
    inspected = vendor.inspect_repository(ROOT)
    assert {("glib", "0.18.5"), ("ml-kem", "0.2.3")} <= set(inspected["packages"])
    assert inspected["packages"][("ml-kem", "0.2.3")]["manifests"] == ["native/Cargo.toml", "native/fuzz/Cargo.toml"]
    assert set(inspected["lockfiles"]) >= {"native/Cargo.lock", "native/fuzz/Cargo.lock", "native/ol_shell/Cargo.lock"}


# --- crafted repositories: one synthetic backport, then every way to bypass it ---

UPSTREAM = {
    "Cargo.toml": b'[package]\nname = "demo"\nversion = "1.0.0"\nlicense = "MIT"\n',
    "src/lib.rs": b"pub fn f() -> u8 {\n    1\n}\n",
}
PATCHED = {**UPSTREAM, "src/lib.rs": b"pub fn f() -> u8 {\n    2\n}\n"}
WORKSPACE = """[workspace]
members = []

[patch.crates-io]
demo = { path = "vendor/demo-1.0.0" }

[workspace.metadata.one-link.vendored-patches]
demo = "patches/demo-1.0.0.json"
"""
LOCK = 'version = 4\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\n'
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _archive(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
        for name, data in files.items():
            info = tarfile.TarInfo(f"demo-1.0.0/{name}")
            info.size = len(data)
            stream.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _patch_text() -> bytes:
    return "".join(difflib.unified_diff(
        UPSTREAM["src/lib.rs"].decode().splitlines(keepends=True),
        PATCHED["src/lib.rs"].decode().splitlines(keepends=True),
        fromfile="a/src/lib.rs", tofile="b/src/lib.rs")).encode()


def _provenance(archive: bytes) -> dict:
    files = {name: _sha(data) for name, data in PATCHED.items()}
    original = {name: _sha(data) for name, data in UPSTREAM.items()}
    return {
        "schema": vendor.SCHEMA,
        "package": {"name": "demo", "version": "1.0.0", "license": "MIT", "path": "vendor/demo-1.0.0"},
        "files": files, "source_tree_sha256": vendor.tree_hash(files),
        "upstream": {"crate_url": "https://static.crates.io/crates/demo/demo-1.0.0.crate",
                     "crate_sha256": _sha(archive), "source_tree_sha256": vendor.tree_hash(original)},
        "upstream_files": original,
        "backport": {"changed_files": ["src/lib.rs"], "patch_path": "patches/demo-1.0.0.patch",
                     "patch_sha256": _sha(_patch_text()), "advisories": ["RUSTSEC-0000-0000"],
                     "upstream_fix_commit": "0" * 40},
        "maintenance": "synthetic fixture",
    }


def _write(root: Path, name: str, data: str | bytes) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _workspace(root: Path, prefix: str, archive: bytes) -> None:
    _write(root, f"{prefix}/Cargo.toml", WORKSPACE)
    _write(root, f"{prefix}/Cargo.lock", LOCK)
    for name, data in PATCHED.items():
        _write(root, f"{prefix}/vendor/demo-1.0.0/{name}", data)
    _write(root, f"{prefix}/patches/demo-1.0.0.json", json.dumps(_provenance(archive), indent=2))
    _write(root, f"{prefix}/patches/demo-1.0.0.patch", _patch_text())


@pytest.fixture
def crafted(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    archive = _archive(UPSTREAM)
    (tmp_path / "demo-1.0.0.crate").write_bytes(archive)
    _workspace(root, "ws", archive)
    _git(root, "add", "--all")
    return root


def verify(root: Path, tmp_path: Path, *extra: str) -> tuple[int, dict]:
    report = tmp_path / "verification.json"
    code = vendor.main(["--root", str(root), "--report", str(report), *extra])
    return code, json.loads(report.read_text(encoding="utf-8"))


def test_crafted_backport_verifies_offline_and_against_its_upstream_archive(crafted, tmp_path):
    code, report = verify(crafted, tmp_path)
    assert code == 0, report
    assert report["packages"][0]["manifests"] == ["ws/Cargo.toml"]
    assert report["packages"][0]["upstream_archive_verified"] is False
    code, report = verify(crafted, tmp_path, "--upstream-archive", f"demo@1.0.0={tmp_path / 'demo-1.0.0.crate'}")
    assert code == 0, report
    assert report["packages"][0]["upstream_archive_verified"] is True
    assert report["inputs"]["manifests"] == ["ws/Cargo.toml", "ws/vendor/demo-1.0.0/Cargo.toml"]
    assert report["inputs"]["workspace_manifests"] == ["ws/Cargo.toml"]


@pytest.mark.parametrize("prefix,path", [
    ("unchecked", "."),
    ("unchecked/nested", ".."),
    ("unchecked/nested", "../.."),
])
def test_unverified_self_or_ancestor_path_cannot_hide_a_tampered_workspace(crafted, tmp_path, prefix, path):
    archive_path = tmp_path / "demo-1.0.0.crate"
    _workspace(crafted, prefix, archive_path.read_bytes())
    _write(crafted, f"{prefix}/vendor/demo-1.0.0/src/lib.rs", b"unreviewed bytes\n")
    _write(crafted, f"{prefix}/Cargo.toml", WORKSPACE.replace(
        "[patch.crates-io]", f'[patch.crates-io]\nunchecked = {{ path = "{path}" }}'))
    _git(crafted, "add", "--all")
    # The separate valid ws backport prevents an empty-package check from
    # masking the exclusion bug: the bad workspace itself must be inspected.
    code, report = verify(crafted, tmp_path, "--upstream-archive", f"demo@1.0.0={archive_path}")
    assert code == 1 and report["status"] == "failed", report


def test_unverified_sibling_paths_cannot_exclude_each_other(crafted, tmp_path):
    for owner, target in (("one", "two"), ("two", "one")):
        _write(crafted, f"{owner}/Cargo.toml",
               f'[workspace]\n[patch.crates-io]\nunchecked = {{ path = "../{target}" }}\n')
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path)
    assert code == 1 and report["status"] == "failed", report
    assert "self-containing or cyclic vendor exclusion" in report["error"]


def _review_upstream_manifest(root: Path, manifest: bytes, archive_path: Path) -> None:
    """Make an inactive dependency [patch] part of this synthetic upstream crate."""
    archive = _archive({**UPSTREAM, "Cargo.toml": manifest})
    archive_path.write_bytes(archive)
    _write(root, "ws/vendor/demo-1.0.0/Cargo.toml", manifest)
    proof = _provenance(archive)
    for field in ("files", "upstream_files"):
        proof[field]["Cargo.toml"] = _sha(manifest)
    proof["source_tree_sha256"] = vendor.tree_hash(proof["files"])
    proof["upstream"]["source_tree_sha256"] = vendor.tree_hash(proof["upstream_files"])
    _write(root, "ws/patches/demo-1.0.0.json", json.dumps(proof))


@pytest.mark.parametrize("hidden", ["tampered-source", "registry-lock"])
def test_inactive_vendor_patch_cannot_hide_a_sibling_workspace(crafted, tmp_path, hidden):
    archive_path = tmp_path / "demo-1.0.0.crate"
    if hidden == "tampered-source":
        _workspace(crafted, "unchecked", archive_path.read_bytes())
        _write(crafted, "unchecked/vendor/demo-1.0.0/src/lib.rs", b"unreviewed bytes\n")
    else:
        _write(crafted, "unchecked/Cargo.toml", "[workspace]\n")
        _write(crafted, "unchecked/Cargo.lock", LOCK + f'source = "{REGISTRY}"\n')
    # This path is reviewed upstream data, but Cargo ignores it when demo is
    # a dependency. It cannot confer trust on a separate workspace or lock.
    _review_upstream_manifest(crafted, UPSTREAM["Cargo.toml"] +
                              b'\n[patch.crates-io]\nunchecked = { path = "../../../unchecked" }\n',
                              archive_path)
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path, "--upstream-archive", f"demo@1.0.0={archive_path}")
    assert code == 1 and report["status"] == "failed", report
    expected = "vendored source differs" if hidden == "tampered-source" else "unchecked/Cargo.lock resolves"
    assert expected in report["error"]


def test_verified_vendor_is_excluded_even_when_its_manifest_sorts_before_its_owner(crafted, tmp_path):
    archive_path = tmp_path / "demo-1.0.0.crate"
    _review_upstream_manifest(crafted, UPSTREAM["Cargo.toml"] +
                              b'\n[patch.crates-io]\nignored = { path = "unselected" }\n', archive_path)
    (crafted / "ws").rename(crafted / "zzz")
    (crafted / "zzz/vendor").rename(crafted / "aaa-vendor")
    _write(crafted, "zzz/Cargo.toml", WORKSPACE.replace("vendor/demo-1.0.0", "../aaa-vendor/demo-1.0.0"))
    proof_path = crafted / "zzz/patches/demo-1.0.0.json"
    proof = json.loads(proof_path.read_text())
    proof["package"]["path"] = "../aaa-vendor/demo-1.0.0"
    proof_path.write_text(json.dumps(proof))
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path, "--upstream-archive", f"demo@1.0.0={archive_path}")
    assert code == 0, report
    assert report["inputs"]["workspace_manifests"] == ["zzz/Cargo.toml"]
    assert report["packages"][0]["upstream_archive_verified"] is True


@pytest.mark.parametrize("name,content,message", [
    ("other/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { path = "foo" }\n', "provenance record"),
    ("other/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { git = "https://example.invalid/foo" }\n', "git patch"),
    ("other/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { path = "foo", package = "bar" }\n', "non-path patch"),
    ("other/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = "1.0"\n', "non-path patch"),
    ("other/Cargo.toml", '[workspace]\n[patch."https://github.com/x/y"]\nfoo = { path = "foo" }\n', "overrides source"),
    ("other/Cargo.toml", '[workspace]\n[replace]\n"foo:1.0.0" = { path = "foo" }\n', "replace"),
    ("Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { git = "https://example.invalid/foo", rev = "1" }\n', "git patch"),
    ("ws/member/Cargo.toml", '[package]\nname = "m"\nversion = "0.1.0"\n[patch.crates-io]\nfoo = { path = "f" }\n'
     '[package.metadata.one-link.vendored-patches]\nfoo = "p.json"\n', "no Cargo.lock beside it"),
    ("other/Cargo.toml", '[workspace]\n[workspace.metadata.one-link.vendored-patches]\nfoo = "p.json"\n', "provenance record"),
    (".cargo/config.toml", '[patch.crates-io]\nfoo = { path = "foo" }\n', "Cargo configuration [patch]"),
    ("ws/.cargo/config", '[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\ndirectory = "v"\n',
     "Cargo configuration [source]"),
    ("deep/dir/.cargo/config.toml", 'paths = ["../foo"]\n', "Cargo configuration [paths]"),
    ("deep/.cargo/config.toml", '[registry]\nindex = "https://example.invalid/index"\n', "registry.index"),
])
def test_any_undeclared_or_unverifiable_source_override_anywhere_fails(crafted, tmp_path, name, content, message):
    _write(crafted, name, content)
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path)
    assert code == 1
    assert report["status"] == "failed"
    assert message in report["error"], report["error"]


def test_untracked_inputs_are_discovered_and_ignored_ones_are_not(crafted, tmp_path):
    _write(crafted, ".gitignore", "ignored/\n")
    _write(crafted, "ignored/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { git = "x" }\n')
    assert verify(crafted, tmp_path)[0] == 0
    _write(crafted, "untracked/Cargo.toml", '[workspace]\n[patch.crates-io]\nfoo = { git = "x" }\n')
    code, report = verify(crafted, tmp_path)
    assert code == 1 and "untracked/Cargo.toml" in report["error"]


def test_a_harmless_cargo_config_is_accepted(crafted, tmp_path):
    _write(crafted, "ws/.cargo/config.toml", '[env]\nPYO3_PYTHON = "python3"\n[net]\nretry = 10\n')
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path)
    assert code == 0, report
    assert report["inputs"]["configs"] == ["ws/.cargo/config.toml"]


def test_another_workspace_resolving_the_backported_version_from_the_registry_fails(crafted, tmp_path):
    _write(crafted, "fuzz/Cargo.toml", '[workspace]\n[package]\nname = "fz"\nversion = "0.0.0"\n')
    _write(crafted, "fuzz/Cargo.lock", LOCK + f'source = "{REGISTRY}"\nchecksum = "{"0" * 64}"\n')
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path)
    assert code == 1
    assert "fuzz/Cargo.lock resolves demo 1.0.0" in report["error"]
    # A different registry version is a different package; cargo-audit covers it.
    _write(crafted, "fuzz/Cargo.lock", LOCK.replace("1.0.0", "2.0.0") + f'source = "{REGISTRY}"\n')
    assert verify(crafted, tmp_path)[0] == 0


SHARING_MEMBER = """[package]
name = "fz"
version = "0.0.0"

[workspace]

[package.metadata.one-link.vendored-patches]
demo = "{record}"

[patch.crates-io]
demo = {{ path = "{source}" }}
"""


def _sharing_workspace(root: Path, prefix: str, *, record: str, source: str) -> None:
    _write(root, f"{prefix}/Cargo.toml", SHARING_MEMBER.format(record=record, source=source))
    _write(root, f"{prefix}/Cargo.lock", LOCK)
    _git(root, "add", "--all")


def test_a_second_workspace_sharing_one_record_and_one_tree_passes(crafted, tmp_path):
    # The native/fuzz layout: a separate workspace below the record's owner.
    _sharing_workspace(crafted, "ws/fuzz", record="../patches/demo-1.0.0.json", source="../vendor/demo-1.0.0")
    code, report = verify(crafted, tmp_path, "--upstream-archive", f"demo@1.0.0={tmp_path / 'demo-1.0.0.crate'}")
    assert code == 0, report
    package = report["packages"][0]
    assert package["manifests"] == ["ws/Cargo.toml", "ws/fuzz/Cargo.toml"]
    assert package["sources"] == ["ws/vendor/demo-1.0.0", "ws/vendor/demo-1.0.0"]
    assert package["upstream_archive_verified"] is True


def test_a_workspace_whose_patch_and_record_name_different_directories_fails(crafted, tmp_path):
    # Byte-identical copy elsewhere: the record still describes ws/vendor, so
    # this manifest's selection is not the reviewed directory.
    shutil.copytree(crafted / "ws/vendor", crafted / "other/vendor")
    _sharing_workspace(crafted, "other", record="../ws/patches/demo-1.0.0.json", source="vendor/demo-1.0.0")
    code, report = verify(crafted, tmp_path)
    assert code == 1
    assert "does not match Cargo's selected path" in report["error"], report["error"]
    assert "other/Cargo.toml selects 'vendor/demo-1.0.0'" in report["error"]


@pytest.mark.parametrize("record,source,message", [
    ("../ws/patches/demo-1.0.0.json", "../../outside/demo-1.0.0", "escapes the repository"),
    ("../../outside/patches/demo-1.0.0.json", "../ws/vendor/demo-1.0.0", "escapes the repository"),
    ("../ws/patches/demo-1.0.0.json", "/abs/demo-1.0.0", "must be relative"),
    ("../ws/patches/demo-1.0.0.json", "C:/abs/demo-1.0.0", "must be relative"),
    ("records/demo-1.0.0.json", "../ws/vendor/demo-1.0.0", "must live in <workspace>/patches/"),
])
def test_shared_sources_stay_inside_the_repository_and_records_inside_a_patches_directory(
        crafted, tmp_path, record, source, message):
    if record.startswith("records/"):
        _write(crafted, "other/records/demo-1.0.0.json", (crafted / "ws/patches/demo-1.0.0.json").read_bytes())
    _sharing_workspace(crafted, "other", record=record, source=source)
    code, report = verify(crafted, tmp_path)
    assert code == 1
    assert message in report["error"], report["error"]


def test_a_source_reached_through_a_symbolic_link_fails(crafted, tmp_path):
    (crafted / "other").mkdir()
    link, target = crafted / "other/vendor", crafted / "ws/vendor"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        # Windows without the symlink privilege: a directory junction needs
        # none and is followed by path resolution the same way.
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    assert (link / "demo-1.0.0/src/lib.rs").is_file()
    _sharing_workspace(crafted, "other", record="../ws/patches/demo-1.0.0.json", source="vendor/demo-1.0.0")
    code, report = verify(crafted, tmp_path)
    assert code == 1
    assert "symbolic link" in report["error"], report["error"]


def test_native_and_fuzz_select_the_one_reviewed_ml_kem_tree():
    native = vendor.inspect_patches(NATIVE / "Cargo.toml")[("ml-kem", "0.2.3")]
    fuzz = vendor.inspect_patches(NATIVE / "fuzz/Cargo.toml")[("ml-kem", "0.2.3")]
    assert native["source_path"] == fuzz["source_path"] == (NATIVE / "vendor/ml-kem-0.2.3").resolve()
    assert native["proof_path"] == fuzz["proof_path"]


def test_the_same_backport_in_two_workspaces_must_be_byte_identical(crafted, tmp_path):
    archive = (tmp_path / "demo-1.0.0.crate").read_bytes()
    _workspace(crafted, "second", archive)
    _git(crafted, "add", "--all")
    code, report = verify(crafted, tmp_path)
    assert code == 0, report
    assert report["packages"][0]["manifests"] == ["second/Cargo.toml", "ws/Cargo.toml"]
    source = crafted / "second/vendor/demo-1.0.0/src/lib.rs"
    source.write_bytes(b"pub fn f() -> u8 {\n    3\n}\n")
    proof_path = crafted / "second/patches/demo-1.0.0.json"
    proof = json.loads(proof_path.read_text())
    proof["files"]["src/lib.rs"] = _sha(source.read_bytes())
    proof["source_tree_sha256"] = vendor.tree_hash(proof["files"])
    proof_path.write_text(json.dumps(proof))
    code, report = verify(crafted, tmp_path)
    assert code == 1


@pytest.mark.parametrize("changed", ["source", "patch", "lock", "archive", "unknown-archive"])
def test_modified_source_diff_registry_resolution_or_archive_fails_with_retained_report(crafted, tmp_path, changed):
    archive = tmp_path / "demo-1.0.0.crate"
    extra = ["--upstream-archive", f"demo@1.0.0={archive}"]
    if changed == "source":
        source = crafted / "ws/vendor/demo-1.0.0/src/lib.rs"
        source.write_bytes(source.read_bytes() + b"// unreviewed change\n")
    elif changed == "patch":
        patch = crafted / "ws/patches/demo-1.0.0.patch"
        patch.write_bytes(patch.read_bytes() + b"\n")
    elif changed == "lock":
        (crafted / "ws/Cargo.lock").write_text(LOCK + f'source = "{REGISTRY}"\n')
    elif changed == "archive":
        archive.write_bytes(_archive({**UPSTREAM, "src/lib.rs": b"pub fn f() -> u8 { 9 }\n"}))
    else:
        extra = ["--upstream-archive", f"other@1.0.0={archive}"]
    code, evidence = verify(crafted, tmp_path, *extra)
    assert code == 1
    assert evidence["status"] == "failed"
    assert evidence["error"]


def test_a_directory_git_cannot_enumerate_fails_closed(tmp_path):
    (tmp_path / "plain").mkdir()
    code, report = verify(tmp_path / "plain", tmp_path)
    assert code == 1 and "cannot enumerate" in report["error"]


def test_git_checkout_preserves_every_vendor_byte_with_windows_line_conversion(tmp_path):
    checkout = tmp_path / "source"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    shutil.copyfile(ROOT / ".gitattributes", checkout / ".gitattributes")
    for vendor_path in (Path("native/ol_shell/vendor/glib-0.18.5"), Path("native/vendor/ml-kem-0.2.3")):
        shutil.copytree(ROOT / vendor_path, checkout / vendor_path)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    converted = tmp_path / "windows-checkout"
    converted.mkdir()
    subprocess.run(["git", "-c", "core.autocrlf=true", "checkout-index", "--all",
                    f"--prefix={converted.as_posix()}/"], cwd=checkout, check=True)
    for vendor_path in (Path("native/ol_shell/vendor/glib-0.18.5"), Path("native/vendor/ml-kem-0.2.3")):
        assert vendor.source_files(converted / vendor_path) == vendor.source_files(checkout / vendor_path)


@pytest.mark.parametrize("name", ["security.yml", "release.yml", "native_shell.yml"])
def test_workflows_verify_the_whole_repository_not_one_manifest(name):
    text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    calls = [line for line in text.splitlines()
             if "verify_vendor_patches.py" in line or "audit_vendor_advisories.py" in line]
    calls = [line for line in calls if "python" in line]
    assert calls
    assert all("--manifest" not in line for line in calls)
