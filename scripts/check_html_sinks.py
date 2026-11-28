#!/usr/bin/env python3
"""Gate on places where the browser UI turns a string into markup.

Assigning to ``innerHTML`` (and its relatives) parses a string as HTML. When
any part of that string came from a peer, a file name, a message or a server
reply, the assignment is a cross-site-scripting sink. The UI has a couple of
hundred such assignments, written over a long time, and nothing stopped a new
one from being added.

This script finds every sink in the authoring sources under ``frontend/`` and
sorts it into one of two kinds:

``static``
    the markup is spelled out in string literals with nothing interpolated;
    it cannot carry data.

``dynamic``
    anything else: a variable, a call, a template literal with ``${...}``.

The number of dynamic sinks in each file is recorded in
``frontend/html_sink_baseline.json``. The check fails when a file has more
dynamic sinks than its baseline, so new code has to build its nodes with DOM
APIs (``textContent``, ``createElement``, ``replaceChildren``) or the change
has to raise the baseline in the same diff, where a reviewer sees it. When a
file ends up with fewer, the check also fails until the baseline is lowered,
which keeps every removal locked in.

    python scripts/check_html_sinks.py            # check
    python scripts/check_html_sinks.py --update   # rewrite the baseline
    python scripts/check_html_sinks.py --list     # print every dynamic sink
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "frontend"
BASELINE = SOURCES / "html_sink_baseline.json"

# Property assignments that parse their right-hand side as markup.
_ASSIGN_SINK = re.compile(r"\.(innerHTML|outerHTML|srcdoc)\s*(\+?=)(?!=)")
# Calls whose named argument (0-based) is parsed as markup.
_CALL_SINKS = {
    "insertAdjacentHTML": 1,
    "createContextualFragment": 0,
    "setHTMLUnsafe": 0,
    "write": 0,
    "writeln": 0,
}
_CALL_SINK = re.compile(
    r"(?:\.(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe)"
    r"|\bdocument\.(write|writeln))\s*\("
)


@dataclass(frozen=True)
class Sink:
    path: str
    line: int
    kind: str  # "static" or "dynamic"
    code: str


def _skip_trivia(src: str, i: int) -> int:
    """Advance past whitespace and comments."""
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i += 1
        elif src.startswith("//", i):
            end = src.find("\n", i)
            i = n if end < 0 else end
        elif src.startswith("/*", i):
            end = src.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            break
    return i


def _read_quoted(src: str, i: int) -> int:
    """``src[i]`` opens a '...' or "..." literal. Return the index after it."""
    quote = src[i]
    i += 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
        elif c == quote or c == "\n":
            return i + 1
        else:
            i += 1
    return n


def _read_template(src: str, i: int) -> tuple[int, bool]:
    """``src[i]`` opens a template literal.

    Returns ``(index_after, interpolated)`` where ``interpolated`` says
    whether the literal contains a ``${...}`` substitution.
    """
    i += 1
    n = len(src)
    interpolated = False
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
        elif c == "`":
            return i + 1, interpolated
        elif src.startswith("${", i):
            interpolated = True
            i = _skip_balanced(src, i + 1)
        else:
            i += 1
    return n, interpolated


def _skip_balanced(src: str, i: int) -> int:
    """``src[i]`` is an opening bracket. Return the index after its match."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[src[i]]]
    i += 1
    n = len(src)
    while i < n and stack:
        i = _skip_trivia(src, i)
        if i >= n:
            break
        c = src[i]
        if c in "'\"":
            i = _read_quoted(src, i)
        elif c == "`":
            i, _ = _read_template(src, i)
        elif c in pairs:
            stack.append(pairs[c])
            i += 1
        elif c == stack[-1]:
            stack.pop()
            i += 1
        else:
            i += 1
    return i


def _expression_is_static(src: str, i: int, terminators: str) -> bool:
    """Is the expression starting at ``i`` nothing but string literals?

    Literals may be joined with ``+`` and wrapped in parentheses. The
    expression ends at the first character in ``terminators`` at depth zero.
    """
    n = len(src)
    saw_literal = False
    expect_operand = True
    depth = 0
    while True:
        i = _skip_trivia(src, i)
        if i >= n:
            return saw_literal and not expect_operand
        c = src[i]
        if depth == 0 and c in terminators and not expect_operand:
            return saw_literal
        if c in "'\"":
            if not expect_operand:
                return False
            i = _read_quoted(src, i)
            saw_literal, expect_operand = True, False
        elif c == "`":
            if not expect_operand:
                return False
            i, interpolated = _read_template(src, i)
            if interpolated:
                return False
            saw_literal, expect_operand = True, False
        elif c == "+" and not expect_operand:
            expect_operand = True
            i += 1
        elif c == "(" and expect_operand:
            depth += 1
            i += 1
        elif c == ")" and depth > 0 and not expect_operand:
            depth -= 1
            i += 1
        else:
            return False


def _argument_start(src: str, i: int, index: int) -> int | None:
    """``src[i]`` is just past a call's ``(``. Return where argument
    ``index`` starts, or ``None`` if the call has fewer arguments."""
    n = len(src)
    current = 0
    while current < index:
        while i < n:
            i = _skip_trivia(src, i)
            if i >= n:
                return None
            c = src[i]
            if c in "'\"":
                i = _read_quoted(src, i)
            elif c == "`":
                i, _ = _read_template(src, i)
            elif c in "([{":
                i = _skip_balanced(src, i)
            elif c == ",":
                i += 1
                break
            elif c == ")":
                return None
            else:
                i += 1
        current += 1
    return i


def _comment_spans(src: str) -> list[tuple[int, int]]:
    """Ranges of comments and quoted strings, where a sink is only mentioned."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"":
            end = _read_quoted(src, i)
            spans.append((i, end))
            i = end
        elif c == "`":
            i, _ = _read_template(src, i)
        elif src.startswith("//", i):
            end = src.find("\n", i)
            end = n if end < 0 else end
            spans.append((i, end))
            i = end
        elif src.startswith("/*", i):
            end = src.find("*/", i + 2)
            end = n if end < 0 else end + 2
            spans.append((i, end))
            i = end
        else:
            i += 1
    return spans


def scan_source(src: str, path: str) -> list[Sink]:
    comments = _comment_spans(src)

    def in_comment(pos: int) -> bool:
        return any(start <= pos < end for start, end in comments)

    def line_of(pos: int) -> int:
        return src.count("\n", 0, pos) + 1

    def snippet(pos: int) -> str:
        start = src.rfind("\n", 0, pos) + 1
        end = src.find("\n", pos)
        return src[start : len(src) if end < 0 else end].strip()[:140]

    sinks: list[Sink] = []
    for match in _ASSIGN_SINK.finditer(src):
        if in_comment(match.start()):
            continue
        # ``+=`` extends markup that is already in the element, so it is
        # dynamic no matter what is appended.
        static = match.group(2) == "=" and _expression_is_static(src, match.end(), ";,)}\n")
        sinks.append(
            Sink(path, line_of(match.start()), "static" if static else "dynamic", snippet(match.start()))
        )
    for match in _CALL_SINK.finditer(src):
        if in_comment(match.start()):
            continue
        name = match.group(1) or match.group(2)
        start = _argument_start(src, match.end(), _CALL_SINKS[name])
        static = start is not None and _expression_is_static(src, start, ",)")
        sinks.append(
            Sink(path, line_of(match.start()), "static" if static else "dynamic", snippet(match.start()))
        )
    sinks.sort(key=lambda s: s.line)
    return sinks


def scan_tree(root: Path = SOURCES) -> list[Sink]:
    sinks: list[Sink] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".js", ".html"} or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        sinks.extend(scan_source(path.read_text(encoding="utf-8"), rel))
    return sinks


def dynamic_counts(sinks: list[Sink]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sink in sinks:
        if sink.kind == "dynamic":
            counts[sink.path] = counts.get(sink.path, 0) + 1
    return dict(sorted(counts.items()))


def load_baseline(path: Path = BASELINE) -> dict[str, int]:
    return dict(json.loads(path.read_text(encoding="utf-8"))["dynamic_sinks"])


def compare(current: dict[str, int], baseline: dict[str, int]) -> list[str]:
    problems: list[str] = []
    for path in sorted(set(current) | set(baseline)):
        have, allowed = current.get(path, 0), baseline.get(path, 0)
        if have > allowed:
            problems.append(
                f"{path}: {have} dynamic HTML sinks, baseline allows {allowed}. "
                "Build the nodes with DOM APIs instead of a markup string."
            )
        elif have < allowed:
            problems.append(
                f"{path}: {have} dynamic HTML sinks, baseline still says {allowed}. "
                "Run `python scripts/check_html_sinks.py --update` to lock the reduction in."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--update", action="store_true", help="rewrite the baseline")
    parser.add_argument("--list", action="store_true", help="print every dynamic sink")
    args = parser.parse_args(argv)

    sinks = scan_tree()
    current = dynamic_counts(sinks)
    if args.list:
        for sink in sinks:
            if sink.kind == "dynamic":
                print(f"{sink.path}:{sink.line}: {sink.code}")
    if args.update:
        BASELINE.write_text(
            json.dumps(
                {
                    "comment": (
                        "Dynamic HTML sinks per file. Generated by "
                        "scripts/check_html_sinks.py --update. A number here may "
                        "only go down."
                    ),
                    "dynamic_sinks": current,
                    "total": sum(current.values()),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"baseline written: {sum(current.values())} dynamic sinks in {len(current)} files")
        return 0
    problems = compare(current, load_baseline())
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        static = sum(1 for s in sinks if s.kind == "static")
        print(f"html sinks: {sum(current.values())} dynamic (at baseline), {static} static")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
