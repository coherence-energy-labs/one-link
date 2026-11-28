"""No tracked file contains text shaped like a PEM private key.

The required secret scan (``gitleaks git .`` in security.yml and release.yml)
reads every commit, so a private-key-shaped block that reaches a branch fails
that branch, and stays in its history after the lines are deleted. The scan
runs only in CI; this test reads the working tree for the same shape, so the
mistake is caught before it is committed.

It mirrors one rule and replaces nothing: the scan remains the gate. A real
key must never be committed. Armor markers that code needs (the sealed
identity key in ``one_link.identity``, test expectations) are assembled from
their parts instead of written out, so that nothing in the working tree
needs an exemption from the scan's default rule.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_DASHES = "-" * 5
# Gitleaks' default ``private-key`` rule, written so this file is not a match.
PRIVATE_KEY_SHAPE = re.compile(
    _DASHES
    + r"BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?"
    + _DASHES
    + r"[\s\S-]{64,}?KEY(?: BLOCK)?"
    + _DASHES,
    re.IGNORECASE,
)
_NEEDLE = b"PRIVATE KEY"


def _tracked_and_new_files() -> list[Path]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / name for name in raw.decode("utf-8", "surrogateescape").split("\0") if name]


def shaped_like_a_private_key(text: str) -> list[int]:
    """Line numbers where a private-key-shaped block starts."""
    return [text.count("\n", 0, match.start()) + 1 for match in PRIVATE_KEY_SHAPE.finditer(text)]


def test_no_tracked_file_is_shaped_like_a_private_key() -> None:
    files = _tracked_and_new_files()
    assert len(files) > 500, "the file listing did not find the repository"
    found = []
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue  # deleted in the working tree, or a broken link
        if _NEEDLE not in data.upper():
            continue
        text = data.decode("utf-8", "replace")
        found += [f"{path.relative_to(ROOT).as_posix()}:{line}" for line in shaped_like_a_private_key(text)]
    assert not found, (
        "text shaped like a PEM private key; the required secret scan will fail on the "
        "commit that adds it and on every later one. If this is armor that code needs, "
        "assemble the marker lines from parts (see one_link.identity._armor_line):\n" + "\n".join(found)
    )


def test_the_shape_matches_what_the_scan_matches() -> None:
    begin = _DASHES + "BEGIN {} PRIVATE KEY" + _DASHES
    end = _DASHES + "END {} PRIVATE KEY" + _DASHES
    body = "\n".join(["A" * 64] * 2)
    # A key block, whatever its label.
    for label in ("RSA", "EC", "OPENSSH", "ENCRYPTED", "ONE LINK ENCRYPTED"):
        block = f"{begin.format(label)}\n{body}\n{end.format(label)}\n"
        assert shaped_like_a_private_key("x = 1\n" + block) == [2], label
    assert shaped_like_a_private_key((_DASHES + "BEGIN PRIVATE KEY" + _DASHES) + "\n" + body + "\n" + (_DASHES + "END PRIVATE KEY" + _DASHES))
    # Two marker constants on neighbouring lines are a match too: this is the
    # case that needs no key at all, and the one the scan stopped on.
    constants = (
        f'BEGIN = b"{begin.format("ONE LINK ENCRYPTED")}"\n'
        f'END = b"{end.format("ONE LINK ENCRYPTED")}"\n'
        f'LEGACY = b"{begin.format("ENCRYPTED")}"\n'
    )
    assert shaped_like_a_private_key(constants) == [1]
    # One marker alone, a public key, or a marker built from parts is not.
    assert not shaped_like_a_private_key(f'BEGIN = b"{begin.format("ENCRYPTED")}"\n')
    public = (_DASHES + "BEGIN PUBLIC KEY" + _DASHES) + "\n" + body + "\n" + (_DASHES + "END PUBLIC KEY" + _DASHES)
    assert not shaped_like_a_private_key(public)
    assert not shaped_like_a_private_key('line = f"-----{edge} {label}-----"\nlabel = "ONE LINK ENCRYPTED PRIVATE KEY"\n' * 4)
