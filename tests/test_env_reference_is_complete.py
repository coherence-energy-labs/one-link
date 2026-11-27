"""Every environment switch the shipped source names is in docs/ENVIRONMENT.md.

``test_no_dark_env_switches`` accepts a switch that is mentioned anywhere
outside ``src/``, including by a test, and it only sees reads spelled
``os.environ.get("ONE_LINK_...")``. A switch read through a constant
(``os.environ.get(DISABLE_ENV)``) and exercised by one test passed that gate
while no operator could read about it. This check is narrower and stricter:
the name has to be in the reference document.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "one_link"
REFERENCE = REPO / "docs" / "ENVIRONMENT.md"
_NAME = re.compile(r"ONE_LINK_[A-Z0-9_]+")


def _switches_named_in_source() -> dict[str, str]:
    """Every string literal that is exactly an ``ONE_LINK_*`` name."""
    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _NAME.fullmatch(node.value)
            ):
                found.setdefault(node.value, f"{path.relative_to(REPO).as_posix()}:{node.lineno}")
    return found


def test_scan_finds_the_switches_it_exists_for() -> None:
    names = _switches_named_in_source()
    # Read directly, read through a constant, and read by a validated reader.
    for expected in (
        "ONE_LINK_PASSPHRASE",
        "ONE_LINK_DISABLE_AT_REST_ENCRYPTION",
        "ONE_LINK_MAX_PEERS",
    ):
        assert expected in names
    assert len(names) > 60


def test_every_switch_is_in_the_reference() -> None:
    documented = set(_NAME.findall(REFERENCE.read_text(encoding="utf-8")))
    missing = {
        name: where
        for name, where in _switches_named_in_source().items()
        if name not in documented
    }
    assert missing == {}, (
        "environment switches named in the source but absent from "
        "docs/ENVIRONMENT.md"
    )
