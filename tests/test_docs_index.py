"""Every document is classified in docs/README.md."""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "docs"
INDEX = (DOCS / "README.md").read_text(encoding="utf-8")
_LINK = re.compile(r"\]\(([^)]+)\)")


def test_every_document_is_listed_exactly_once() -> None:
    linked = _LINK.findall(INDEX)
    documents = sorted(p.name for p in DOCS.glob("*.md") if p.name != "README.md")
    listed = sorted(target for target in linked if target.endswith(".md"))
    assert listed == documents


def test_every_subdirectory_is_listed() -> None:
    linked = set(_LINK.findall(INDEX))
    for directory in sorted(p for p in DOCS.iterdir() if p.is_dir()):
        if any(directory.rglob("*.md")):
            assert f"{directory.name}/" in linked, directory.name


def test_every_link_resolves() -> None:
    for target in _LINK.findall(INDEX):
        assert (DOCS / target).exists(), target
