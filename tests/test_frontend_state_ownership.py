"""MNT-03 state-ownership gates for the shipped browser pages, run from pytest.

The Node suites are the evidence; this module makes the Python test run
execute them too. The behavioural contracts need only Node. The ownership
census and the undefined-call gate also need the locked acorn parser
(``npm ci`` in tests/js); without it they are reported as skipped, and
``npm test`` in tests/js (the CI JavaScript job) runs them.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "tests" / "js"
NODE = shutil.which("node")


def _node_test(*files: str) -> None:
    if NODE is None:
        pytest.skip("Node is required for the browser state-ownership contracts")
    result = subprocess.run(
        [NODE, "--test", *files], cwd=JS, capture_output=True, encoding="utf-8", timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_feature_state_owner_contracts_in_real_javascript() -> None:
    _node_test(
        "test_owner_state_contracts.cjs",
        "test_peer_state_contracts.cjs",
        "test_call_driver_teardown.cjs",
    )


def test_ownership_census_ratchet_and_per_closure_call_gate() -> None:
    if not (JS / "node_modules" / "acorn" / "package.json").is_file():
        pytest.skip("run `npm ci --ignore-scripts` in tests/js for the acorn-based census")
    _node_test("test_ownership_census.cjs", "test_check_undefined_calls.cjs")
