"""A received file name cannot be drawn as something other than what it is."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.daemon import Daemon
from one_link.identity import load_or_create


@pytest.fixture
def daemon(tmp_path: Path) -> Daemon:
    return Daemon(load_or_create(tmp_path / "me.key"))


def test_right_to_left_override_is_removed(daemon: Daemon) -> None:
    # Drawn as "photoexe.png" by anything that honours U+202E.
    assert daemon._safe_transfer_name("photo‮gnp.exe") == "photognp.exe"


@pytest.mark.parametrize(
    "codepoint",
    [0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x2066, 0x2067, 0x2068, 0x2069, 0x0085, 0x009F],
)
def test_every_bidi_control_and_c1_control_is_removed(daemon: Daemon, codepoint: int) -> None:
    name = daemon._safe_transfer_name(f"a{chr(codepoint)}b.txt")
    assert name == "ab.txt"


def test_a_name_made_only_of_controls_gets_a_placeholder(daemon: Daemon) -> None:
    assert daemon._safe_transfer_name("‮‭") == "unnamed.bin"
    assert daemon._safe_transfer_name("‮.") == "unnamed.bin"


def test_ordinary_international_names_are_untouched(daemon: Daemon) -> None:
    for name in ("résumé.pdf", "отчёт.docx", "写真.jpg", "تقرير.pdf", "می‌خواهم.txt", "👨‍👩‍👧.png"):
        assert daemon._safe_transfer_name(name) == name


def test_reserved_name_hidden_behind_a_control_is_still_caught(daemon: Daemon) -> None:
    assert daemon._safe_transfer_name("CO‎N.txt") == "_CON.txt"
