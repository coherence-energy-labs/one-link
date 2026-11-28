"""Counts of two kinds of known debt, so neither can grow unnoticed.

``broad_handlers``
    ``except Exception``, ``except BaseException`` and bare ``except`` in the
    shipped source. A broad handler is how a real fault turns into a quiet
    wrong answer. There are well over a thousand; narrowing them is slow,
    careful work, but adding more is free unless something counts.

``ui_source_tests``
    Test files that read the built ``index.html`` / ``peer.html`` and assert
    on their text. Such a test passes when a string is present, whether or
    not the feature works, and fails on a harmless rewrite. New UI tests
    belong in the service tests under ``frontend/`` or the browser tests.

``python -m tests.debt_ratchet --write`` records the current numbers in
``tests/debt_baseline.json``. The check in ``tests/test_debt_ratchet.py``
fails when a number goes up, and also when it goes down without the baseline
being rewritten, so every improvement is locked in.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "one_link"
TESTS = REPO / "tests"
BASELINE = TESTS / "debt_baseline.json"

_BROAD = {"Exception", "BaseException"}
_UI_FIXTURE = re.compile(r"\b(index_html|peer_html)\b")
_UI_READ = re.compile(r"""["'](?:index|peer)\.html["']""")


def _is_broad(handler: ast.ExceptHandler) -> bool:
    kind = handler.type
    if kind is None:
        return True
    names = kind.elts if isinstance(kind, ast.Tuple) else [kind]
    return any(isinstance(n, ast.Name) and n.id in _BROAD for n in names)


def broad_handlers() -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        n = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler) and _is_broad(node))
        if n:
            counts[path.relative_to(SRC).as_posix()] = n
    return counts


def ui_source_tests() -> list[str]:
    found = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if "e2e" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if _UI_FIXTURE.search(text) or (_UI_READ.search(text) and "read_text" in text):
            found.append(path.relative_to(TESTS).as_posix())
    return found


def measure() -> dict:
    handlers = broad_handlers()
    return {
        "broad_handlers": handlers,
        "broad_handlers_total": sum(handlers.values()),
        "ui_source_tests": ui_source_tests(),
    }


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def compare(current: dict, baseline: dict) -> list[str]:
    problems: list[str] = []
    now, was = current["broad_handlers"], baseline["broad_handlers"]
    for path in sorted(set(now) | set(was)):
        have, allowed = now.get(path, 0), was.get(path, 0)
        if have > allowed:
            problems.append(
                f"{path}: {have} broad exception handlers, baseline allows {allowed}. "
                "Catch the exceptions the code can actually handle."
            )
        elif have < allowed:
            problems.append(
                f"{path}: {have} broad exception handlers, baseline still says {allowed}. "
                "Run `python -m tests.debt_ratchet --write` to lock the reduction in."
            )
    new_tests = sorted(set(current["ui_source_tests"]) - set(baseline["ui_source_tests"]))
    gone = sorted(set(baseline["ui_source_tests"]) - set(current["ui_source_tests"]))
    for name in new_tests:
        problems.append(
            f"tests/{name} asserts on the text of the built UI pages. Test the "
            "behaviour instead (frontend service tests or browser tests)."
        )
    for name in gone:
        problems.append(
            f"tests/{name} no longer reads the built UI pages. "
            "Run `python -m tests.debt_ratchet --write` to lock that in."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", action="store_true", help="record the current numbers")
    args = parser.parse_args(argv)
    current = measure()
    if args.write:
        BASELINE.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"baseline written: {current['broad_handlers_total']} broad handlers in "
            f"{len(current['broad_handlers'])} files, "
            f"{len(current['ui_source_tests'])} UI source tests"
        )
        return 0
    problems = compare(current, load_baseline())
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
