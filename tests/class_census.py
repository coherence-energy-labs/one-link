"""AST census and ratchet for the two orchestration classes MNT-01 decomposes.

``Daemon`` (``src/one_link/daemon.py``) and ``UIServer``
(``src/one_link/server.py``) concentrate most runtime behavior. This module
measures them from source with :mod:`ast` (nothing is imported or executed) and
compares the measurement with the committed baseline in
``tests/class_census_baseline.json``.

The ratchet is exact in both directions:

* a class that GROWS past the baseline (more methods, more method lines, more
  self attributes, or more lines in any domain) fails with a ``grew`` violation;
* a class that SHRINKS below the baseline also fails, with a ``stale``
  violation, until the smaller census is written back. Every extraction must
  therefore lower the committed baseline in the same change, and the gain can
  never be silently given back later.

The baseline also keeps an append-only history of totals. Growth between two
history entries is a violation unless that entry records a ``growth_reason``.
``--write`` refuses to record growth without one, so raising the ceiling is a
reviewed, explicit act rather than a side effect of regenerating a file.

Definitions (stable; the classifier digest is pinned in the baseline):

* ``methods``: ``def``/``async def`` statements directly in the class body.
* ``method_lines``: sum of each method's physical span, decorators included.
* ``class_lines``: physical span of the ``class`` statement.
* ``self_attributes_assigned``: distinct attribute names a method assigns on
  ``self`` (``self.x = ``, ``self.x += ``, annotated assignment, tuple targets,
  ``setattr(self, "x", ...)``). It tracks how much mutable state the class
  owns directly.
* ``domains``: each method is assigned to exactly ONE domain, the first entry
  of :data:`DOMAINS` sharing a token with the method name (the name split on
  ``_``). Methods matching none are ``other``. Domain lines sum to
  ``method_lines``.

Usage::

    python -m tests.class_census                    # print census + diff
    python -m tests.class_census --write --label "extract X"
    python -m tests.class_census --write --label "..." --growth-reason "..."
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "one-link-class-census-v1"
REPO = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO / "tests" / "class_census_baseline.json"

#: (repository-relative source path, class name) pairs under the ratchet.
TARGETS: tuple[tuple[str, str], ...] = (
    ("src/one_link/daemon.py", "Daemon"),
    ("src/one_link/server.py", "UIServer"),
)

#: Ordered domain classifier. First matching domain wins.
DOMAINS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "call",
        frozenset({"call", "calls", "sdp", "ice", "recording", "immune", "capsule"}),
    ),
    ("folder", frozenset({"folder", "folders", "manifest", "fs"})),
    ("group", frozenset({"group", "groups", "room", "rooms"})),
    ("courier", frozenset({"courier"})),
    ("recovery", frozenset({"recovery", "backup", "restore"})),
    ("mesh", frozenset({"mesh"})),
    (
        "capability",
        frozenset({"cap", "caps", "capability", "capabilities", "grant", "grants"}),
    ),
    (
        "transfer",
        frozenset(
            {"file", "files", "chunk", "chunks", "blob", "blobs", "transfer", "transfers"}
        ),
    ),
    ("peer", frozenset({"peer", "peers"})),
    ("send", frozenset({"send"})),
)
OTHER_DOMAIN = "other"
DOMAIN_NAMES: tuple[str, ...] = tuple(name for name, _tokens in DOMAINS) + (OTHER_DOMAIN,)

#: Scalar metrics compared per class, in report order.
SCALAR_METRICS: tuple[str, ...] = (
    "methods",
    "method_lines",
    "class_lines",
    "self_attributes_assigned",
)


class CensusError(RuntimeError):
    """The census cannot be computed or the baseline is malformed."""


@dataclass(frozen=True)
class Violation:
    """One difference between a census and its baseline."""

    kind: str  # "grew" | "stale" | "missing" | "unexpected" | "classifier" | "history"
    target: str
    metric: str
    baseline: Any
    current: Any

    def render(self) -> str:
        if self.kind == "grew":
            return (
                f"{self.target}.{self.metric} GREW {self.baseline} -> {self.current}: "
                "extract instead of adding, or record a reviewed --growth-reason"
            )
        if self.kind == "stale":
            return (
                f"{self.target}.{self.metric} shrank {self.baseline} -> {self.current}: "
                "lock the gain in with `python -m tests.class_census --write --label ...`"
            )
        return f"{self.kind}: {self.target}.{self.metric} baseline={self.baseline!r} current={self.current!r}"


def classifier_digest() -> str:
    """Digest of the domain table, so reclassification invalidates a baseline."""

    material = json.dumps(
        [[name, sorted(tokens)] for name, tokens in DOMAINS] + [[OTHER_DOMAIN, []]],
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"one-link-class-census-classifier-v1\0" + material).hexdigest()


def domain_for(method_name: str) -> str:
    tokens = {token for token in method_name.strip("_").lower().split("_") if token}
    for name, keywords in DOMAINS:
        if tokens & keywords:
            return name
    return OTHER_DOMAIN


def _method_span(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    start = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    end = node.end_lineno
    if end is None:  # pragma: no cover - CPython always fills end_lineno
        raise CensusError(f"method {node.name} has no end line")
    return end - start + 1


def _self_targets(target: ast.expr) -> Iterable[str]:
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        if target.value.id == "self":
            yield target.attr
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _self_targets(element)
    elif isinstance(target, ast.Starred):
        yield from _self_targets(target.value)


def _assigned_self_attributes(method: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(method):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_self_targets(target))
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            names.update(_self_targets(node.target))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "self"
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            names.add(node.args[1].value)
    return names


def census_class_source(source: str, class_name: str, *, label: str = "<source>") -> dict[str, Any]:
    """Measure one top-level class in *source*."""

    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        raise CensusError(f"{label} does not parse: {exc}") from exc
    matches = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(matches) != 1:
        raise CensusError(f"{label} defines {len(matches)} top-level classes named {class_name}")
    cls = matches[0]
    domains = {name: {"methods": 0, "lines": 0} for name in DOMAIN_NAMES}
    methods = 0
    method_lines = 0
    attributes: set[str] = set()
    for item in cls.body:
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        span = _method_span(item)
        methods += 1
        method_lines += span
        bucket = domains[domain_for(item.name)]
        bucket["methods"] += 1
        bucket["lines"] += span
        attributes |= _assigned_self_attributes(item)
    if cls.end_lineno is None:  # pragma: no cover
        raise CensusError(f"class {class_name} has no end line")
    return {
        "methods": methods,
        "method_lines": method_lines,
        "class_lines": cls.end_lineno - cls.lineno + 1,
        "self_attributes_assigned": len(attributes),
        "domains": domains,
    }


def census_targets(
    repo: Path = REPO,
    targets: Sequence[tuple[str, str]] = TARGETS,
) -> dict[str, dict[str, Any]]:
    """Census every ratcheted class from the working tree."""

    out: dict[str, dict[str, Any]] = {}
    for relative, class_name in targets:
        path = repo / relative
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CensusError(f"cannot read {relative}: {exc}") from exc
        out[class_name] = census_class_source(source, class_name, label=relative)
    return out


def _compare_number(
    violations: list[Violation], target: str, metric: str, baseline: Any, current: Any
) -> None:
    if not isinstance(baseline, int) or isinstance(baseline, bool):
        violations.append(Violation("missing", target, metric, baseline, current))
    elif current > baseline:
        violations.append(Violation("grew", target, metric, baseline, current))
    elif current < baseline:
        violations.append(Violation("stale", target, metric, baseline, current))


def compare(
    baseline_classes: Mapping[str, Any],
    current_classes: Mapping[str, Mapping[str, Any]],
) -> list[Violation]:
    """Every difference between a baseline and a census; empty means equal."""

    violations: list[Violation] = []
    for target in sorted(set(baseline_classes) - set(current_classes)):
        violations.append(Violation("missing", target, "*", "present", None))
    for target in sorted(current_classes):
        current = current_classes[target]
        base = baseline_classes.get(target)
        if not isinstance(base, Mapping):
            violations.append(Violation("unexpected", target, "*", None, "present"))
            continue
        for metric in SCALAR_METRICS:
            _compare_number(violations, target, metric, base.get(metric), current[metric])
        base_domains = base.get("domains")
        if not isinstance(base_domains, Mapping) or set(base_domains) != set(DOMAIN_NAMES):
            violations.append(
                Violation("classifier", target, "domains", sorted(base_domains or ()), list(DOMAIN_NAMES))
            )
            continue
        for domain in DOMAIN_NAMES:
            base_bucket = base_domains[domain]
            current_bucket = current["domains"][domain]
            for metric in ("methods", "lines"):
                _compare_number(
                    violations,
                    target,
                    f"domains.{domain}.{metric}",
                    base_bucket.get(metric) if isinstance(base_bucket, Mapping) else None,
                    current_bucket[metric],
                )
    return violations


def _totals(classes: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        target: {"methods": int(record["methods"]), "method_lines": int(record["method_lines"])}
        for target, record in sorted(classes.items())
    }


def check_history(baseline: Mapping[str, Any]) -> list[Violation]:
    """The recorded history may only shrink, unless growth carries a reason."""

    violations: list[Violation] = []
    history = baseline.get("history")
    if not isinstance(history, list) or not history:
        return [Violation("history", "*", "history", history, "non-empty list")]
    previous: Mapping[str, Any] | None = None
    for index, entry in enumerate(history):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("totals"), Mapping):
            violations.append(Violation("history", "*", f"history[{index}]", entry, "entry"))
            previous = None
            continue
        if not isinstance(entry.get("label"), str) or not entry["label"].strip():
            violations.append(Violation("history", "*", f"history[{index}].label", entry.get("label"), "text"))
        totals = entry["totals"]
        reason = entry.get("growth_reason")
        if previous is not None and not (isinstance(reason, str) and reason.strip()):
            for target, record in totals.items():
                prior = previous.get(target)
                if not isinstance(prior, Mapping) or not isinstance(record, Mapping):
                    continue
                for metric in ("methods", "method_lines"):
                    if record.get(metric, 0) > prior.get(metric, 0):
                        violations.append(
                            Violation(
                                "history",
                                target,
                                f"history[{index}].{metric}",
                                prior.get(metric),
                                record.get(metric),
                            )
                        )
        previous = totals
    classes = baseline.get("classes")
    if isinstance(classes, Mapping) and isinstance(history[-1], Mapping):
        try:
            expected = _totals(classes)
        except (KeyError, TypeError, ValueError):
            expected = None
        if expected is not None and history[-1].get("totals") != expected:
            violations.append(
                Violation("history", "*", "history[-1].totals", history[-1].get("totals"), expected)
            )
    return violations


def check_baseline(
    baseline: Mapping[str, Any],
    current_classes: Mapping[str, Mapping[str, Any]],
) -> list[Violation]:
    """Full ratchet verdict: schema, classifier pin, exact census, history."""

    violations: list[Violation] = []
    if baseline.get("schema") != SCHEMA:
        violations.append(Violation("classifier", "*", "schema", baseline.get("schema"), SCHEMA))
    if baseline.get("classifier_digest") != classifier_digest():
        violations.append(
            Violation(
                "classifier",
                "*",
                "classifier_digest",
                baseline.get("classifier_digest"),
                classifier_digest(),
            )
        )
    classes = baseline.get("classes")
    if not isinstance(classes, Mapping):
        violations.append(Violation("missing", "*", "classes", classes, "mapping"))
        return violations
    violations.extend(compare(classes, current_classes))
    violations.extend(check_history(baseline))
    return violations


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CensusError(f"cannot load census baseline {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CensusError(f"census baseline {path} is not an object")
    return payload


def build_baseline(
    current_classes: Mapping[str, Mapping[str, Any]],
    *,
    label: str,
    previous: Mapping[str, Any] | None = None,
    growth_reason: str | None = None,
) -> dict[str, Any]:
    """Return the next baseline. Refuses unexplained growth."""

    if not label.strip():
        raise CensusError("a census baseline entry needs a label")
    history = list(previous.get("history") or []) if previous else []
    totals = _totals(current_classes)
    if history and not (growth_reason and growth_reason.strip()):
        prior = history[-1].get("totals", {}) if isinstance(history[-1], Mapping) else {}
        grown = [
            f"{target}.{metric} {prior[target][metric]} -> {record[metric]}"
            for target, record in totals.items()
            if isinstance(prior.get(target), Mapping)
            for metric in ("methods", "method_lines")
            if record[metric] > prior[target].get(metric, 0)
        ]
        if grown:
            raise CensusError(
                "refusing to raise the ratchet without --growth-reason: " + ", ".join(grown)
            )
    entry: dict[str, Any] = {"label": label.strip(), "totals": totals}
    if growth_reason and growth_reason.strip():
        entry["growth_reason"] = growth_reason.strip()
    history.append(entry)
    return {
        "schema": SCHEMA,
        "classifier_digest": classifier_digest(),
        "targets": [list(target) for target in TARGETS],
        "classes": {target: current_classes[target] for target in sorted(current_classes)},
        "history": history,
    }


def write_baseline(payload: Mapping[str, Any], path: Path = BASELINE_PATH) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)


def _format_census(classes: Mapping[str, Mapping[str, Any]]) -> str:
    lines: list[str] = []
    for target, record in sorted(classes.items()):
        lines.append(
            f"{target}: {record['methods']} methods, {record['method_lines']} method lines, "
            f"{record['class_lines']} class lines, "
            f"{record['self_attributes_assigned']} self attributes assigned"
        )
        for domain in DOMAIN_NAMES:
            bucket = record["domains"][domain]
            lines.append(f"  {domain:<11} {bucket['methods']:>4} methods {bucket['lines']:>6} lines")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--write", action="store_true", help="record the current census")
    parser.add_argument("--label", default="", help="history label for --write")
    parser.add_argument("--growth-reason", default=None, help="required when a total grows")
    args = parser.parse_args(argv)
    current = census_targets()
    print(_format_census(current))
    previous = load_baseline() if BASELINE_PATH.exists() else None
    if args.write:
        try:
            payload = build_baseline(
                current,
                label=args.label,
                previous=previous,
                growth_reason=args.growth_reason,
            )
        except CensusError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        write_baseline(payload)
        print(f"wrote {BASELINE_PATH.relative_to(REPO).as_posix()}")
        return 0
    if previous is None:
        print("no baseline recorded", file=sys.stderr)
        return 1
    violations = check_baseline(previous, current)
    for violation in violations:
        print(violation.render())
    return 1 if violations else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
