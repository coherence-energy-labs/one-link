"""A received file name cannot be drawn as something other than what it is."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.daemon import Daemon
from one_link.identity import load_or_create

# Written as code points on purpose: a source file that contains the real
# characters is itself hard to read correctly.
RLO = chr(0x202E)  # right-to-left override
LRO = chr(0x202D)  # left-to-right override
LRM = chr(0x200E)  # left-to-right mark
ZWNJ = chr(0x200C)  # zero-width non-joiner (ordinary in Persian)
ZWJ = chr(0x200D)  # zero-width joiner (ordinary in emoji sequences)


@pytest.fixture
def daemon(tmp_path: Path) -> Daemon:
    return Daemon(load_or_create(tmp_path / "me.key"))


def test_right_to_left_override_is_removed(daemon: Daemon) -> None:
    # Drawn as "photoexe.png" by anything that honours the override.
    assert daemon._safe_transfer_name(f"photo{RLO}gnp.exe") == "photognp.exe"


@pytest.mark.parametrize(
    "codepoint",
    [0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x2066, 0x2067, 0x2068, 0x2069, 0x0085, 0x009F],
)
def test_every_bidi_control_and_c1_control_is_removed(daemon: Daemon, codepoint: int) -> None:
    name = daemon._safe_transfer_name(f"a{chr(codepoint)}b.txt")
    assert name == "ab.txt"


def test_a_name_made_only_of_controls_gets_a_placeholder(daemon: Daemon) -> None:
    assert daemon._safe_transfer_name(RLO + LRO) == "unnamed.bin"
    assert daemon._safe_transfer_name(RLO + ".") == "unnamed.bin"


def test_ordinary_international_names_are_untouched(daemon: Daemon) -> None:
    persian = "می" + ZWNJ + "خواهم.txt"
    family = "\U0001F468" + ZWJ + "\U0001F469" + ZWJ + "\U0001F467.png"
    for name in (
        "résumé.pdf",
        "отчёт.docx",
        "写真.jpg",
        "تقرير.pdf",
        persian,
        family,
    ):
        assert daemon._safe_transfer_name(name) == name


def test_reserved_name_hidden_behind_a_control_is_still_caught(daemon: Daemon) -> None:
    assert daemon._safe_transfer_name(f"CO{LRM}N.txt") == "_CON.txt"


def test_trailing_dot_exposed_by_removing_a_control_is_trimmed(daemon: Daemon) -> None:
    assert daemon._safe_transfer_name("report.pdf." + chr(0x01)) == "report.pdf"
