#!/usr/bin/env python3
"""Run the deterministic constant-time audit (native/ol_ct_audit) under Valgrind.

Every case of the ``ol_ct_audit`` binary marks its secret inputs undefined
and calls production code. Memcheck reports each conditional branch
(``UninitCondition``) and each memory address (``UninitValue``) computed
from a secret, attributed to the innermost source line of the code the
compiler emitted.

A report is *declassified* only when that innermost line is a repository
source line marked ``ct-audit: declassify`` (the one branch on a verdict the
function exists to publish): the marker sits in a comment on that line, or on
a comment-only line directly above it (the rustfmt-stable form). A marker any
further away does not count. Any other report is a
*violation*. Any other Memcheck error kind (invalid reads, leaks of
definedness into syscalls, ...) is always a violation.

Verdicts:
* ``clean`` cases pass with zero violations;
* ``flagged`` cases (negative controls) pass only with at least one
  violation, which proves the instrument can see a leak;
* a case that did not run to completion under Valgrind fails, whatever it
  reported, so a broken Valgrind cannot produce a vacuous pass.

Usage (Linux x86-64)::

    cargo build --locked --profile ct-audit -p ol_ct_audit   # in native/
    python scripts/run_ct_audit.py --binary native/target/ct-audit/ol_ct_audit \
        --source-root native --report test-results/ct-audit/report.json
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

MARKER = "ct-audit: declassify"
SECRET_KINDS = frozenset({"UninitCondition", "UninitValue"})
COMPLETE_PREFIX = "ct-audit-case-complete "


@dataclass(frozen=True)
class Frame:
    fn: str
    path: str | None
    line: int | None
    obj: str | None


@dataclass
class Report:
    unique: str
    kind: str
    what: str
    frames: list[Frame]
    count: int = 1
    classification: str = "violation"
    reason: str = ""

    def innermost(self) -> Frame | None:
        return self.frames[0] if self.frames else None


@dataclass
class CaseResult:
    name: str
    expect: str
    covers: list[str]
    what: str
    completed: bool = False
    under_valgrind: bool = False
    returncode: int | None = None
    reports: list[Report] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def violations(self) -> list[Report]:
        return [r for r in self.reports if r.classification == "violation"]

    @property
    def declassified(self) -> list[Report]:
        return [r for r in self.reports if r.classification == "declassified"]

    @property
    def passed(self) -> bool:
        if self.problems or not self.completed or not self.under_valgrind:
            return False
        if self.expect == "clean":
            return not self.violations
        if self.expect == "uniform":
            # No secret-dependent branch or address at all: a report at a
            # declassification marker fails a uniform case too.
            return not self.reports
        if self.expect == "flagged":
            return bool(self.violations)
        return False


def parse_dtd_free_xml(text: str) -> ET.Element:
    """Parse XML that carries no document type declaration; refuse any that does.

    Entity-expansion and external-entity attacks both need a DTD: an internal
    subset to declare entities, or an external one to fetch. A DTD can only be
    introduced by the literal ``<!DOCTYPE`` (XML is case-sensitive, and the
    input here is already-decoded text, so no encoding trick hides it).
    Memcheck's protocol never emits one. Without it, only the five predefined
    entities and character references exist, which cannot expand or resolve
    anything. The literal inside a comment or CDATA is refused too: fail
    closed.
    """
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ET.ParseError("document type and entity declarations are not accepted in Memcheck XML")
    return ET.fromstring(text)  # nosec B314 - DTD-free by the check above; see docstring


def parse_memcheck_xml(text: str) -> tuple[list[Report], str | None]:
    """Parse Memcheck protocol-4 XML into reports (with occurrence counts)."""
    root = parse_dtd_free_xml(text)
    status = None
    for st in root.iter("status"):
        state = st.findtext("state")
        if state:
            status = state
    reports: dict[str, Report] = {}
    order: list[str] = []
    for err in root.findall("error"):
        unique = err.findtext("unique") or str(len(order))
        kind = err.findtext("kind") or "unknown"
        what = err.findtext("what") or ""
        if not what:
            what = err.findtext("xwhat/text") or ""
        frames: list[Frame] = []
        stack = err.find("stack")
        if stack is not None:
            for fr in stack.findall("frame"):
                directory = fr.findtext("dir")
                filename = fr.findtext("file")
                path = None
                if filename:
                    path = str(pathlib.PurePosixPath(directory) / filename) if directory else filename
                line_text = fr.findtext("line")
                frames.append(
                    Frame(
                        fn=fr.findtext("fn") or "?",
                        path=path,
                        line=int(line_text) if line_text and line_text.isdigit() else None,
                        obj=fr.findtext("obj"),
                    )
                )
        reports[unique] = Report(unique=unique, kind=kind, what=what, frames=frames)
        order.append(unique)
    counts = root.find("errorcounts")
    if counts is not None:
        for pair in counts.findall("pair"):
            pair_unique = pair.findtext("unique")
            count = pair.findtext("count")
            if pair_unique is not None and pair_unique in reports and count and count.isdigit():
                reports[pair_unique].count = int(count)
    return [reports[u] for u in order], status


class SourceIndex:
    """Resolves report frames to repository lines and their markers."""

    def __init__(self, source_root: pathlib.Path):
        self.root = source_root.resolve()
        self._cache: dict[pathlib.Path, list[str]] = {}

    def resolve(self, path: str | None) -> pathlib.Path | None:
        if not path:
            return None
        candidate = pathlib.Path(path)
        try:
            resolved = candidate.resolve()
        except OSError:
            return None
        try:
            resolved.relative_to(self.root)
        except ValueError:
            return None
        return resolved if resolved.is_file() else None

    def line(self, path: pathlib.Path, number: int) -> str | None:
        lines = self._cache.get(path)
        if lines is None:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            self._cache[path] = lines
        if 1 <= number <= len(lines):
            return lines[number - 1]
        return None

    def relative(self, path: pathlib.Path) -> str:
        return path.relative_to(self.root).as_posix()


@dataclass(frozen=True)
class ExternalDeclassification:
    package: str
    version: str
    file: str
    line: int
    source_text: str
    reason: str

    def matches(self, frame: Frame) -> bool:
        if frame.path is None or frame.line != self.line:
            return False
        needle = f"/{self.package}-{self.version}/{self.file}"
        return pathlib.PurePosixPath(frame.path).as_posix().endswith(needle)


def load_external(path: pathlib.Path | None) -> list[ExternalDeclassification]:
    if path is None or not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "one-link/ct-audit-external-declassifications/v1":
        raise SystemExit(f"unsupported external declassification schema in {path}")
    entries = []
    for raw in data.get("entries", []):
        entries.append(
            ExternalDeclassification(
                package=raw["package"],
                version=raw["version"],
                file=raw["file"],
                line=int(raw["line"]),
                source_text=raw["source_text"].strip(),
                reason=raw["reason"],
            )
        )
    return entries


def external_line(frame: Frame) -> str | None:
    """Read the actual third-party source line Valgrind attributed the report to."""
    if frame.path is None or frame.line is None:
        return None
    try:
        lines = pathlib.Path(frame.path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return lines[frame.line - 1].strip() if 1 <= frame.line <= len(lines) else None


def classify(
    report: Report, index: SourceIndex, external: list[ExternalDeclassification] | None = None
) -> None:
    if report.kind not in SECRET_KINDS:
        report.classification = "violation"
        report.reason = f"memcheck error kind {report.kind} is never declassifiable"
        return
    frame = report.innermost()
    if frame is None or frame.path is None or frame.line is None:
        report.classification = "violation"
        report.reason = "innermost frame has no source line"
        return
    resolved = index.resolve(frame.path)
    if resolved is None:
        for entry in external or []:
            if entry.matches(frame):
                actual = external_line(frame)
                if actual == entry.source_text:
                    report.classification = "declassified"
                    report.reason = (
                        f"external {entry.package}@{entry.version} {entry.file}:{entry.line}: {entry.reason}"
                    )
                else:
                    report.classification = "violation"
                    report.reason = (
                        f"external declassification for {entry.package}@{entry.version} {entry.file}:"
                        f"{entry.line} no longer matches the reviewed source text (found {actual!r})"
                    )
                return
        report.classification = "violation"
        report.reason = f"innermost frame is outside the repository: {frame.path}:{frame.line}"
        return
    text = index.line(resolved, frame.line)
    above = index.line(resolved, frame.line - 1) if frame.line > 1 else None
    location = f"{index.relative(resolved)}:{frame.line}"
    marked_above = above is not None and above.lstrip().startswith("//") and MARKER in above
    if (text is not None and MARKER in text) or marked_above:
        report.classification = "declassified"
        report.reason = f"{location} carries the declassification marker"
    else:
        report.classification = "violation"
        report.reason = f"{location} has no declassification marker"


def list_cases(binary: pathlib.Path) -> list[dict]:
    out = subprocess.run([str(binary), "--list"], check=True, capture_output=True, text=True, timeout=60)
    cases = [json.loads(line) for line in out.stdout.splitlines() if line.strip()]
    if not cases:
        raise SystemExit("ol_ct_audit --list returned no cases")
    names = [c["name"] for c in cases]
    if len(names) != len(set(names)):
        raise SystemExit("ol_ct_audit --list returned duplicate case names")
    return cases


def memcheck_command(valgrind: list[str], xml_path: pathlib.Path, binary: pathlib.Path, case: str) -> list[str]:
    """The Memcheck invocation for one case.

    Leak kinds are switched off: this audit judges secret-dependent control
    flow and memory addresses, plus genuine memory errors (invalid reads and
    writes stay violations). Blocks still allocated when a short-lived audit
    process exits (process-wide state in the TLS and RNG libraries) say
    nothing about either. XML mode forces ``--leak-check=full`` whatever is
    asked (measured on Valgrind 3.22: ``--leak-check=no`` still reported
    ``Leak_PossiblyLost``), so the leak KINDS are deselected instead. Leak
    detection for shipped code belongs to the sanitizer and fuzz lanes.
    """
    return [
        *valgrind,
        "--tool=memcheck",
        "--show-leak-kinds=none",
        "--errors-for-leak-kinds=none",
        "--track-origins=yes",
        "--error-limit=no",
        "--xml=yes",
        f"--xml-file={xml_path}",
        str(binary),
        case,
    ]


def run_case(
    case: dict,
    binary: pathlib.Path,
    valgrind: list[str],
    work: pathlib.Path,
    index: SourceIndex,
    timeout: int,
    external: list[ExternalDeclassification] | None = None,
) -> CaseResult:
    result = CaseResult(
        name=case["name"], expect=case["expect"], covers=list(case.get("covers", [])), what=case.get("what", "")
    )
    xml_path = work / f"{case['name']}.xml"
    if xml_path.exists():
        xml_path.unlink()
    command = memcheck_command(valgrind, xml_path, binary, case["name"])
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result.problems.append(f"timed out after {timeout}s")
        return result
    result.returncode = proc.returncode
    (work / f"{case['name']}.stdout").write_text(proc.stdout, encoding="utf-8")
    (work / f"{case['name']}.stderr").write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        result.problems.append(f"exit status {proc.returncode}: {proc.stderr.strip()[-400:]}")
    for line in proc.stdout.splitlines():
        if line.startswith(COMPLETE_PREFIX):
            fields = dict(part.split("=", 1) for part in line[len(COMPLETE_PREFIX) :].split() if "=" in part)
            if fields.get("name") == case["name"]:
                result.completed = True
                result.under_valgrind = fields.get("valgrind") == "1"
    if not result.completed:
        result.problems.append("case did not report completion")
    elif not result.under_valgrind:
        result.problems.append("case did not run under Valgrind")
    if not xml_path.is_file():
        result.problems.append("Memcheck wrote no XML report")
        return result
    try:
        reports, status = parse_memcheck_xml(xml_path.read_text(encoding="utf-8", errors="replace"))
    except ET.ParseError as exc:
        result.problems.append(f"unparseable Memcheck XML: {exc}")
        return result
    if status != "FINISHED":
        result.problems.append(f"Memcheck status {status!r}, expected 'FINISHED'")
    for report in reports:
        classify(report, index, external)
    result.reports = reports
    return result


def frame_json(frame: Frame, index: SourceIndex) -> dict:
    resolved = index.resolve(frame.path)
    return {
        "fn": frame.fn,
        "location": f"{index.relative(resolved)}:{frame.line}" if resolved else (f"{frame.path}:{frame.line}" if frame.path else None),
        "object": frame.obj,
    }


def result_json(result: CaseResult, index: SourceIndex) -> dict:
    return {
        "name": result.name,
        "expect": result.expect,
        "what": result.what,
        "covers": result.covers,
        "passed": result.passed,
        "completed": result.completed,
        "under_valgrind": result.under_valgrind,
        "returncode": result.returncode,
        "problems": result.problems,
        "violations": len(result.violations),
        "declassified": len(result.declassified),
        "reports": [
            {
                "kind": r.kind,
                "what": r.what,
                "count": r.count,
                "classification": r.classification,
                "reason": r.reason,
                "frames": [frame_json(f, index) for f in r.frames[:6]],
            }
            for r in result.reports
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--valgrind", default=os.environ.get("CT_AUDIT_VALGRIND", "valgrind"))
    parser.add_argument("--valgrind-arg", action="append", default=[], help="extra argument for valgrind")
    parser.add_argument("--case", action="append", default=[], help="run only these cases")
    parser.add_argument("--timeout", type=int, default=900, help="per-case timeout in seconds")
    parser.add_argument("--explain", action="store_true", help="print every report")
    parser.add_argument(
        "--external-declassifications",
        type=pathlib.Path,
        default=None,
        help="reviewed third-party verdict lines (default: <source-root>/ol_ct_audit/external_declassifications.json)",
    )
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    index = SourceIndex(args.source_root)
    external_path = args.external_declassifications or (
        args.source_root / "ol_ct_audit" / "external_declassifications.json"
    )
    external = load_external(external_path)
    work = args.report.resolve().parent / "memcheck"
    work.mkdir(parents=True, exist_ok=True)
    cases = list_cases(binary)
    if args.case:
        unknown = sorted(set(args.case) - {c["name"] for c in cases})
        if unknown:
            raise SystemExit(f"unknown cases: {unknown}")
        cases = [c for c in cases if c["name"] in set(args.case)]
    valgrind = [args.valgrind, *args.valgrind_arg]

    results = [run_case(c, binary, valgrind, work, index, args.timeout, external) for c in cases]
    controls = [r for r in results if r.expect == "flagged"]
    failed = [r.name for r in results if not r.passed]
    if not args.case and not controls:
        failed.append("<no negative control: the instrument's sensitivity is unproven>")
    summary = {
        "schema": "one-link/ct-audit-report/v1",
        "binary": str(binary),
        "valgrind": valgrind,
        "cases": len(results),
        "passed": sum(r.passed for r in results),
        "failed": failed,
        "negative_controls": len(controls),
        "negative_controls_detected": sum(bool(r.violations) for r in controls),
        "external_declassifications": [
            f"{e.package}@{e.version} {e.file}:{e.line}" for e in external
        ],
        "results": [result_json(r, index) for r in results],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    for r in results:
        verdict = "PASS" if r.passed else "FAIL"
        print(
            f"{verdict} {r.name} expect={r.expect} violations={len(r.violations)} "
            f"declassified={len(r.declassified)}" + (f" problems={r.problems}" if r.problems else "")
        )
        if args.explain or not r.passed:
            for rep in r.reports:
                inner = rep.innermost()
                where = f"{inner.fn} @ {inner.path}:{inner.line}" if inner else "?"
                print(f"    [{rep.classification}] {rep.kind} x{rep.count}: {where}")
                if args.explain:
                    for fr in rep.frames[1:4]:
                        print(f"        from {fr.fn} @ {fr.path}:{fr.line}")
    print(f"ct-audit: {summary['passed']}/{summary['cases']} cases passed; report {args.report}")
    return 0 if not summary["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
