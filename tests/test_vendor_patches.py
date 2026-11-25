"""Verify selected local dependency bytes and the failure evidence contract."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts import verify_vendor_patches as vendor


ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / "native/ol_shell"


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


@pytest.mark.parametrize("changed", ["source", "patch", "lock"])
def test_modified_source_diff_or_registry_resolution_fails_with_retained_report(tmp_path, changed):
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(SHELL / name, tmp_path / name)
    for name in ("vendor", "patches"):
        shutil.copytree(SHELL / name, tmp_path / name)
    if changed == "source":
        source = tmp_path / "vendor/glib-0.18.5/src/variant_iter.rs"
        source.write_bytes(source.read_bytes() + b"\n// unreviewed change\n")
    elif changed == "patch":
        patch = tmp_path / "patches/glib-0.18.5-variant-str-iter.patch"
        patch.write_bytes(patch.read_bytes() + b"\n")
    else:
        lock = tmp_path / "Cargo.lock"
        lock.write_text(lock.read_text(encoding="utf-8").replace(
            'name = "glib"\nversion = "0.18.5"\n',
            'name = "glib"\nversion = "0.18.5"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
            1,
        ), encoding="utf-8")
    report = tmp_path / "verification.json"
    assert vendor.main(["--manifest", str(tmp_path / "Cargo.toml"), "--report", str(report)]) == 1
    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert evidence["status"] == "failed"
    assert evidence["error"]


def test_git_checkout_preserves_every_vendor_byte_with_windows_line_conversion(tmp_path):
    checkout = tmp_path / "source"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    shutil.copyfile(ROOT / ".gitattributes", checkout / ".gitattributes")
    vendor_path = Path("native/ol_shell/vendor/glib-0.18.5")
    shutil.copytree(SHELL / "vendor/glib-0.18.5", checkout / vendor_path)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    converted = tmp_path / "windows-checkout"
    converted.mkdir()
    subprocess.run(["git", "-c", "core.autocrlf=true", "checkout-index", "--all",
                    f"--prefix={converted.as_posix()}/"], cwd=checkout, check=True)
    assert vendor.source_files(converted / vendor_path) == vendor.source_files(checkout / vendor_path)
