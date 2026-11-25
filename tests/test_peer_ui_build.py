"""Offline peer artifact and service-boundary regression contracts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_browser_ui", ROOT / "scripts/build_owner_ui.py")
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def test_peer_artifact_is_current_and_canonical_sources_stay_outside_runtime() -> None:
    expected = builder.build(builder.PEER_SOURCE)
    assert expected == builder.PEER_OUTPUT.read_text(encoding="utf-8")
    assert builder.build(builder.PEER_SOURCE) == expected
    assert len(re.findall(r"<script>[\s\S]*?</script>", expected)) == 1
    assert "<!-- peer-ui:script " not in expected
    assert "Edit frontend/peer sources" in expected
    runtime = ROOT / "src" / "one_link"
    assert not builder.PEER_SOURCE.is_relative_to(runtime)
    assert not builder.SOURCE.is_relative_to(runtime)


def test_existing_ci_entry_point_checks_both_generated_pages() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_owner_ui.py"), "--check"],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "Owner UI generated HTML is current." in result.stdout
    assert "Peer UI generated HTML is current." in result.stdout


def test_peer_check_rejects_stale_output_without_rewriting(tmp_path: Path) -> None:
    output = tmp_path / "peer.html"
    output.write_text("stale peer\n")
    command = [
        sys.executable, str(ROOT / "scripts/build_owner_ui.py"),
        "--page", "peer", "--output", str(output),
    ]
    result = subprocess.run(command + ["--check"], capture_output=True, text=True, timeout=20)
    assert result.returncode == 1
    assert output.read_text() == "stale peer\n"
    built = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert built.returncode == 0, built.stderr
    assert output.read_bytes() == builder.PEER_OUTPUT.read_bytes()


def test_source_page_identity_cannot_be_overridden(tmp_path: Path) -> None:
    output = tmp_path / "wrong.html"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_owner_ui.py"),
         "--page", "owner", "--source", str(builder.PEER_SOURCE), "--output", str(output)],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 2
    assert "differs from --page" in result.stderr
    assert not output.exists()


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required for browser JavaScript execution")
def test_peer_modules_and_isolated_services_execute_in_javascript() -> None:
    result = subprocess.run(
        ["node", "--test", str(ROOT / "tests/js/test_peer_ui_services.cjs")],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
