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
        r"Case \{\s*name: \"([a-z0-9_]+)\",\s*expect: Expect::(\w+),\s*covers: &\[([^\]]*)\]", table
    ):
        covers = re.findall(r"\"([^\"]+)\"", block.group(3))
        cases[block.group(1)] = {"expect": block.group(2).lower(), "covers": covers}
    assert cases, "no ol_ct_audit cases parsed"
    # The parse must see every case, whatever expectation it declares: a
    # pattern that named the expectations would silently skip a new kind.
    assert len(cases) == len(re.findall(r"\bCase \{", table)), "a Case entry did not parse"
    unknown = {case["expect"] for case in cases.values()} - {"clean", "uniform", "flagged"}
    assert not unknown, f"unknown expectation kinds: {unknown}"
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
            assert cases[name]["expect"] in ("clean", "uniform"), name
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
    for kind in ("InvalidRead", "InvalidWrite", "InvalidFree", "Leak_PossiblyLost", "SyscallParam"):
        [report] = _classify(tree, [("f", lib, 2)], kind=kind)
        assert report.classification == "violation", kind


def test_memcheck_runs_without_exit_time_leak_reports_but_keeps_memory_errors():
    command = audit.memcheck_command(["valgrind"], Path("case.xml"), Path("bin"), "some_case")
    # Exit-time leak summaries are out of this audit's scope and are switched
    # off at the source; a leak kind that still appeared would be a violation
    # (test above), so this cannot silently hide one.
    # XML mode forces --leak-check=full, so the kinds are deselected instead.
    assert "--show-leak-kinds=none" in command and "--errors-for-leak-kinds=none" in command
    assert "--leak-check=no" not in command, "XML mode ignores it; it would only look like protection"
    assert "--tool=memcheck" in command and "--xml=yes" in command
    assert command[-2:] == ["bin", "some_case"]
    # Nothing here suppresses memory errors or undefined-value reports.
    assert not any(arg.startswith(("--suppressions", "--undef-value-errors=no")) for arg in command)


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


def test_memcheck_xml_with_a_document_type_or_entity_declaration_is_refused():
    plain = _xml([("f", "/x/src/lib.rs", 1)])
    assert audit.parse_dtd_free_xml(plain).tag == "valgrindoutput"
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
        "<valgrindoutput><what>&lol2;</what></valgrindoutput>"
    )
    external = (
        '<?xml version="1.0"?><!DOCTYPE valgrindoutput SYSTEM "http://127.0.0.1:9/x.dtd">'
        "<valgrindoutput/>"
    )
    for hostile in (bomb, external, "<valgrindoutput><!ENTITY x 'y'></valgrindoutput>"):
        with pytest.raises(audit.ET.ParseError):
            audit.parse_dtd_free_xml(hostile)
        with pytest.raises(audit.ET.ParseError):
            audit.parse_memcheck_xml(hostile)
