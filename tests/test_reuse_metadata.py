"""Every file's license is declared (REUSE), and the texts are present."""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REUSE = tomllib.loads((REPO / "REUSE.toml").read_text(encoding="utf-8"))


def _identifiers(expression: str) -> set[str]:
    return {token for token in expression.replace("(", " ").replace(")", " ").split()
            if token not in {"OR", "AND", "WITH"}}


def test_everything_has_a_default_license_and_holder() -> None:
    default = next(a for a in REUSE["annotations"] if a["path"] == "**")
    assert default["SPDX-License-Identifier"] == "AGPL-3.0-or-later"
    assert "One Link contributors" in default["SPDX-FileCopyrightText"]
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == default["SPDX-License-Identifier"]


def test_vendored_third_party_code_keeps_its_own_license() -> None:
    by_path = {a["path"]: a for a in REUSE["annotations"]}
    for directory, manifest in (
        ("native/vendor/ml-kem-0.2.3", "native/vendor/ml-kem-0.2.3/Cargo.toml"),
        ("native/ol_shell/vendor/glib-0.18.5", "native/ol_shell/vendor/glib-0.18.5/Cargo.toml"),
    ):
        annotation = by_path[f"{directory}/**"]
        assert annotation["precedence"] == "override"
        declared = tomllib.loads((REPO / manifest).read_text(encoding="utf-8"))["package"]["license"]
        assert annotation["SPDX-License-Identifier"] == declared


def test_every_vendored_directory_has_an_annotation() -> None:
    annotated = {a["path"] for a in REUSE["annotations"]}
    for vendor in (REPO / "native" / "vendor", REPO / "native" / "ol_shell" / "vendor"):
        for crate in sorted(p for p in vendor.iterdir() if p.is_dir()):
            assert f"{crate.relative_to(REPO).as_posix()}/**" in annotated, crate.name


def test_license_texts_are_shipped_for_every_identifier_used() -> None:
    used: set[str] = set()
    for annotation in REUSE["annotations"]:
        used |= _identifiers(annotation["SPDX-License-Identifier"])
    present = {p.stem for p in (REPO / "LICENSES").glob("*.txt")}
    assert used == present
    assert (REPO / "LICENSES" / "AGPL-3.0-or-later.txt").read_bytes() == (REPO / "LICENSE").read_bytes()


def test_security_policy_does_not_point_outside_the_repository() -> None:
    text = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    assert "memory" not in text.lower().split("past advisories")[-1]
    assert "No independent third party has reviewed" in text
