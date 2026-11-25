"""Contract tests for the deterministic constant-time audit (native/ol_ct_audit).

These run on every platform without Valgrind. They pin:

* the timing-site inventory: every wall-clock constant-time test in
  native/*/tests is classified, and every secret_dataflow site is covered by an
  ol_ct_audit case that names it (and vice versa);
* the declassification discipline: every ``ct-audit: declassify`` marker states
  its reason;
* the driver's verdict logic against synthetic Memcheck reports, including the
  ways it must FAIL (unmarked line, foreign frame, stale external entry,
  non-secret error kind, incomplete run, blind negative control).
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from scripts import run_ct_audit as audit

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
AUDIT_CRATE = NATIVE / "ol_ct_audit"
INVENTORY = json.loads((AUDIT_CRATE / "timing_inventory.json").read_text(encoding="utf-8"))
FN_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z0-9_]+)\s*\(", re.M)
TEST_RE = re.compile(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+([A-Za-z0-9_]+)")


def timing_sites() -> set[str]:
    sites: set[str] = set()
    for path in sorted(NATIVE.glob("*/tests/*.rs")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(NATIVE).as_posix()
        if re.search(r"(constant_time|ct_gate)", path.name):
            sites.update(f"{rel}::{name}" for name in TEST_RE.findall(text))
        fns = [(m.start(), m.group(1)) for m in FN_RE.finditer(text)]
        for macro in re.finditer(r"timing_gate!\(", text):
            prior = [name for pos, name in fns if pos < macro.start()]
            assert prior, f"timing_gate! outside a function in {rel}"
            sites.add(f"{rel}::{prior[-1]}")
    return sites


def audit_cases() -> dict[str, dict]:
    source = (AUDIT_CRATE / "src" / "main.rs").read_text(encoding="utf-8")
    table = source[source.index("const CASES: &[Case] = &[") :]
    cases = {}
    for block in re.finditer(
        r"Case \{\s*name: \"([a-z0-9_]+)\",\s*expect: Expect::(Clean|Flagged),\s*covers: &\[([^\]]*)\]", table
    ):
        covers = re.findall(r"\"([^\"]+)\"", block.group(3))
        cases[block.group(1)] = {"expect": block.group(2).lower(), "covers": covers}
    assert cases, "no ol_ct_audit cases parsed"
    return cases


def test_every_timing_site_is_classified_exactly_once():
    inventory_sites = [entry["site"] for entry in INVENTORY["sites"]]
    assert len(inventory_sites) == len(set(inventory_sites)), "duplicate inventory site"
    discovered = timing_sites()
    assert discovered, "no timing sites discovered; the enumerator is blind"
    assert set(inventory_sites) == discovered, {
        "unclassified": sorted(discovered - set(inventory_sites)),
        "stale": sorted(set(inventory_sites) - discovered),
    }


def test_inventory_classes_and_rationales_are_complete():
    allowed = set(INVENTORY["classes"])
    assert allowed == {"secret_dataflow", "public_inputs", "test_local_reference", "functional_guard"}
    for entry in INVENTORY["sites"]:
        assert entry["class"] in allowed, entry
        assert len(entry.get("rationale", "")) >= 20, entry
        if entry["class"] == "secret_dataflow":
            assert entry.get("audit_cases"), entry
        else:
            assert not entry.get("audit_cases"), entry


def test_secret_sites_and_audit_cases_cover_each_other():
    cases = audit_cases()
    for entry in INVENTORY["sites"]:
        if entry["class"] != "secret_dataflow":
            continue
        for name in entry["audit_cases"]:
            assert name in cases, f"{entry['site']} names missing case {name}"
            assert cases[name]["expect"] == "clean", name
            assert entry["site"] in cases[name]["covers"], f"case {name} does not list {entry['site']}"
    by_site = {entry["site"]: entry for entry in INVENTORY["sites"]}
    for name, case in cases.items():
        for site in case["covers"]:
            assert by_site.get(site, {}).get("class") == "secret_dataflow", f"case {name} covers {site}"
            assert name in by_site[site]["audit_cases"], f"{site} does not list case {name}"


def test_audit_keeps_negative_controls():
    cases = audit_cases()
    controls = [name for name, case in cases.items() if case["expect"] == "flagged"]
    assert len(controls) >= 3, controls
    assert all(not cases[name]["covers"] for name in controls)


def test_every_declassification_marker_states_a_reason():
    markers = 0
    for path in NATIVE.rglob("*.rs"):
        if "target" in path.parts or "vendor" in path.parts or AUDIT_CRATE in path.parents:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            if audit.MARKER in line:
                markers += 1
                tail = line.split(audit.MARKER, 1)[1].strip()
                assert re.fullmatch(r"\(.{12,}\)", tail), f"{path}:{number} marker needs a (reason)"
                assert line.lstrip().startswith("//"), f"{path}:{number} marker must be its own comment line"
                following = lines[number] if number < len(lines) else ""
                assert following.strip() and not following.lstrip().startswith("//"), (
                    f"{path}:{number} marker must sit directly above the branching statement"
                )
    assert markers >= 9, markers


def _xml(frames: list[tuple[str, str, int]], kind: str = "UninitCondition", state: str = "FINISHED") -> str:
    stack = "".join(
        f"<frame><ip>0x1</ip><obj>/bin/x</obj><fn>{fn}</fn><dir>{Path(path).parent.as_posix()}</dir>"
        f"<file>{Path(path).name}</file><line>{line}</line></frame>"
        for fn, path, line in frames
    )
    return (
        "<?xml version=\"1.0\"?><valgrindoutput><protocolversion>4</protocolversion>"
        f"<status><state>RUNNING</state></status><error><unique>0x0</unique><tid>1</tid><kind>{kind}</kind>"
        f"<what>synthetic</what><stack>{stack}</stack></error>"
        f"<status><state>{state}</state></status>"
        "<errorcounts><pair><count>3</count><unique>0x0</unique></pair></errorcounts></valgrindoutput>"
    )


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    src = tmp_path / "native" / "crate" / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text(
        "fn a() {}\n"
        "    if verdict { // ct-audit: declassify (accept/reject verdict)\n"
        "    if secret_byte == 0 {\n"
        "    // ct-audit: declassify (verdict on the line below)\n"
        "    if other_verdict {\n"
        "        let unrelated = secret[0];\n",
        encoding="utf-8",
    )
    return tmp_path


def _classify(tree: Path, frames, kind="UninitCondition", external=None):
    reports, status = audit.parse_memcheck_xml(_xml(frames, kind))
    assert status == "FINISHED"
    index = audit.SourceIndex(tree / "native")
    for report in reports:
        audit.classify(report, index, external)
    return reports


def test_marked_repository_line_is_declassified(tree: Path):
    lib = (tree / "native/crate/src/lib.rs").as_posix()
    [report] = _classify(tree, [("f", lib, 2)])
    assert report.classification == "declassified"
    assert report.count == 3


def test_unmarked_repository_line_is_a_violation(tree: Path):
    lib = (tree / "native/crate/src/lib.rs").as_posix()
    [report] = _classify(tree, [("f", lib, 3)])
    assert report.classification == "violation"


def test_marker_on_the_comment_line_directly_above_counts_but_no_further(tree: Path):
    lib = (tree / "native/crate/src/lib.rs").as_posix()
    [above] = _classify(tree, [("f", lib, 5)])
    assert above.classification == "declassified"
    [two_below] = _classify(tree, [("f", lib, 6)])
    assert two_below.classification == "violation"


def test_marker_in_a_caller_frame_does_not_excuse_the_callee(tree: Path):
    lib = (tree / "native/crate/src/lib.rs").as_posix()
    [report] = _classify(tree, [("inner", "/elsewhere/dep-1.0/src/x.rs", 9), ("f", lib, 2)])
    assert report.classification == "violation"


def test_non_secret_error_kind_is_never_declassified(tree: Path):
    lib = (tree / "native/crate/src/lib.rs").as_posix()
    [report] = _classify(tree, [("f", lib, 2)], kind="InvalidRead")
    assert report.classification == "violation"


def test_external_declassification_requires_exact_version_line_and_text(tree: Path):
    dep = tree / "registry" / "dep-1.2.3" / "src"
    dep.mkdir(parents=True)
    (dep / "lib.rs").write_text("x\n        if tag.ct_eq(expected).into() {\n", encoding="utf-8")
    entry = audit.ExternalDeclassification(
        package="dep", version="1.2.3", file="src/lib.rs", line=2,
        source_text="if tag.ct_eq(expected).into() {", reason="verdict",
    )
    frame = [("verify", (dep / "lib.rs").as_posix(), 2)]
    [ok] = _classify(tree, frame, external=[entry])
    assert ok.classification == "declassified"
    stale_text = audit.ExternalDeclassification(**{**entry.__dict__, "source_text": "if other {"})
    [stale] = _classify(tree, frame, external=[stale_text])
    assert stale.classification == "violation" and "no longer matches" in stale.reason
    bumped = audit.ExternalDeclassification(**{**entry.__dict__, "version": "1.2.4"})
    [other] = _classify(tree, frame, external=[bumped])
    assert other.classification == "violation"


def test_case_verdicts_fail_closed():
    complete = dict(completed=True, under_valgrind=True)
    clean = audit.CaseResult(name="c", expect="clean", covers=[], what="", **complete)
    assert clean.passed
    clean.reports = [audit.Report(unique="1", kind="UninitCondition", what="", frames=[])]
    assert not clean.passed
    control = audit.CaseResult(name="k", expect="flagged", covers=[], what="", **complete)
    assert not control.passed, "a negative control that reports nothing proves the instrument blind"
    control.reports = [audit.Report(unique="1", kind="UninitCondition", what="", frames=[])]
    assert control.passed
    for broken in (dict(completed=False, under_valgrind=True), dict(completed=True, under_valgrind=False)):
        assert not audit.CaseResult(name="b", expect="clean", covers=[], what="", **broken).passed
    with_problem = audit.CaseResult(name="p", expect="clean", covers=[], what="", **complete)
    with_problem.problems.append("Memcheck status 'RUNNING', expected 'FINISHED'")
    assert not with_problem.passed


@pytest.mark.parametrize("kind", [
    "InvalidRead", "InvalidWrite", "InvalidFree", "MismatchedFree", "Overlap",
    "SyscallParam", "Leak_DefinitelyLost", "Leak_IndirectlyLost", "Leak_PossiblyLost",
    "Leak_StillReachable", "FishyValue", "UnknownFutureError",
])
@pytest.mark.parametrize("secret_kind", [None, "UninitCondition", "UninitValue"])
def test_negative_control_rejects_unrelated_memcheck_error(kind, secret_kind):
    control = audit.CaseResult(
        name="control", expect="flagged", covers=[], what="",
        completed=True, under_valgrind=True, returncode=0,
    )
    control.reports = [audit.Report(unique="memory", kind=kind, what="", frames=[])]
    if secret_kind:
        control.reports.append(audit.Report(unique="secret", kind=secret_kind, what="", frames=[]))
    assert not control.passed, "unrelated errors cannot prove sensitivity or be excused by a real leak"


@pytest.mark.parametrize("kind", ["UninitCondition", "UninitValue"])
def test_negative_control_requires_undeclassified_secret_error_and_completion(kind):
    control = audit.CaseResult(
        name="control", expect="flagged", covers=[], what="",
        completed=True, under_valgrind=True, returncode=0,
    )
    report = audit.Report(unique="secret", kind=kind, what="", frames=[])
    control.reports = [report]
    assert control.passed
    report.classification = "declassified"
    assert not control.passed, "an allowed public verdict is not a detected secret leak"
    report.classification = "violation"
    control.completed = False
    assert not control.passed
    control.completed = True
    control.under_valgrind = False
    assert not control.passed
    control.under_valgrind = True
    control.problems.append("Memcheck status 'RUNNING', expected 'FINISHED'")
    assert not control.passed


def test_summary_counts_only_successful_secret_negative_controls(tmp_path, monkeypatch):
    def result(name, kinds, *, completed=True, expect="flagged", declassified=False):
        return audit.CaseResult(
            name=name, expect=expect, covers=[], what="",
            completed=completed, under_valgrind=True, returncode=0,
            reports=[
                audit.Report(
                    unique=str(i), kind=kind, what="", frames=[],
                    classification="declassified" if declassified else "violation",
                )
                for i, kind in enumerate(kinds)
            ],
        )

    results = [
        result("detected", ["UninitCondition", "UninitValue"]),
        result("memory-only", ["InvalidRead"]),
        result("mixed", ["UninitCondition", "InvalidWrite"]),
        result("allowed-verdict", ["UninitCondition"], declassified=True),
        result("incomplete", ["UninitValue"], completed=False),
        result("clean-allowed-verdict", ["UninitCondition"], expect="clean", declassified=True),
    ]
    cases = [{"name": r.name, "expect": r.expect} for r in results]
    by_name = {r.name: r for r in results}
    monkeypatch.setattr(audit, "list_cases", lambda _binary: cases)
    monkeypatch.setattr(audit, "run_case", lambda case, *_args: by_name[case["name"]])
    monkeypatch.setattr(audit, "load_external", lambda _path: [])
    report_path = tmp_path / "report.json"
    status = audit.main([
        "--binary", str(tmp_path / "unused-binary"),
        "--source-root", str(tmp_path / "native"),
        "--report", str(report_path),
    ])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert status == 1
    assert report["negative_controls"] == 5
    assert report["negative_controls_detected"] == 1
    assert report["passed"] == 2
    assert set(report["failed"]) == {"memory-only", "mixed", "allowed-verdict", "incomplete"}
