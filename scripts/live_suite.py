"""Check and run the explicit live-daemon acceptance manifest in bounded shards.

The manifest is generated from @pytest.mark.live_daemon declarations, not a
hand-picked list of a few files. Every selected function must be collected and
every collected parameter case must execute successfully; skips and incomplete
outcomes remain failures of this acceptance lane. Ordinary pytest invocations
retain their normal platform skip behavior.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/live_daemon_manifest.json"


def marked_nodeids(root: Path) -> list[str]:
    result: list[str] = []
    for path in sorted((root / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        def visit(body: list[ast.stmt], parents: list[str]) -> None:
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, [*parents, node.name])
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    if any(ast.unparse(marker).split("(", 1)[0] == "pytest.mark.live_daemon"
                           for marker in node.decorator_list):
                        result.append("::".join([path.relative_to(root).as_posix(), *parents, node.name]))
        visit(tree.body, [])
    return sorted(result)


def checked_manifest(root: Path, manifest: Path) -> list[str]:
    expected = marked_nodeids(root)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    declared = document.get("nodeids")
    if document.get("schema") != "one-link-live-daemon-manifest/v1" or declared != expected or not expected:
        raise ValueError("live manifest is empty/stale; run python scripts/live_suite.py --write-manifest")
    return expected


def shard(nodeids: list[str], index: int, count: int) -> list[str]:
    if count < 1 or not 0 <= index < count:
        raise ValueError("shard index must be in [0, shard-count)")
    # Stable assignment avoids moving all tests when one new test is added.
    return [nodeid for nodeid in nodeids
            if int.from_bytes(hashlib.sha256(nodeid.encode()).digest()[:8], "big") % count == index]


class EvidencePlugin:
    def __init__(self, expected: list[str], path: Path):
        self.path = path
        self.expected = set(expected)
        self.report: dict = {"schema": "one-link-live-suite/v1", "status": "incomplete",
                             "expected_functions": sorted(expected), "collected": [],
                             "cases": {}, "collection_errors": []}
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def pytest_collection_finish(self, session) -> None:
        self.report["collected"] = [item.nodeid for item in session.items]
        actual = {item.nodeid.split("[", 1)[0] for item in session.items}
        self.report["missing_functions"] = sorted(self.expected - actual)
        self.report["unexpected_functions"] = sorted(actual - self.expected)
        self.save()

    def pytest_collectreport(self, report) -> None:
        if report.failed or report.skipped:
            self.report["collection_errors"].append({"nodeid": report.nodeid, "outcome": report.outcome})
            self.save()

    def pytest_runtest_logreport(self, report) -> None:
        phases = self.report["cases"].setdefault(report.nodeid, {})
        phases.setdefault(report.when, []).append({
            "outcome": report.outcome, "duration_seconds": report.duration,
        })
        self.save()

    def complete(self, pytest_exit: int) -> bool:
        cases = self.report["cases"]
        passed = bool(self.report["collected"]) and pytest_exit == 0 and not (
            self.report["collection_errors"] or self.report.get("missing_functions")
            or self.report.get("unexpected_functions")
        ) and set(cases) == set(self.report["collected"]) and all(
            set(phases) == {"setup", "call", "teardown"}
            # Preserve an initial failure even when a per-test flaky marker
            # overrides the CLI's zero-rerun setting. This lane qualifies one
            # complete successful attempt; retries are diagnostic evidence.
            and all(len(events) == 1 and events[0]["outcome"] == "passed"
                    for events in phases.values())
            for phases in cases.values()
        )
        self.report.update(status="passed" if passed else "failed", pytest_exit_code=int(pytest_exit),
                           collected_cases=len(self.report["collected"]),
                           completed_cases=sum(set(p) == {"setup", "call", "teardown"} for p in cases.values()))
        self.save()
        return passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--report", type=Path, default=ROOT / "test-results/live-suite.json")
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    args.report = args.report.resolve()
    if args.manifest is not None:
        args.manifest = args.manifest.resolve()
    manifest = args.manifest or args.root / "tests/live_daemon_manifest.json"
    if args.write_manifest:
        document = {"schema": "one-link-live-daemon-manifest/v1", "nodeids": marked_nodeids(args.root)}
        manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    try:
        nodeids = checked_manifest(args.root, manifest)
        selected = shard(nodeids, args.shard_index, args.shard_count)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"live manifest: {len(nodeids)} functions; shard {args.shard_index}/{args.shard_count}: {len(selected)}")
    if not args.run:
        return 0
    if not selected:
        parser.error("refusing an empty acceptance shard")
    import pytest
    os.environ["ONE_LINK_RUN_LIVE_INTEGRATION"] = "1"
    os.chdir(args.root)
    # Running a file under scripts/ must import this checkout's tests package,
    # not an unrelated site-packages package with the same generic name.
    sys.path.insert(0, str(args.root))
    plugin = EvidencePlugin(selected, args.report)
    started = time.monotonic()
    # pytest-playwright's session fixture deletes its output directory even
    # without a browser test. This lane must retain its native identity and
    # partial outcome JSON when a developer has the e2e extra installed.
    code = pytest.main([*selected, "-p", "no:playwright", "-q", "--tb=short",
                        "--timeout=240", "--timeout-method=thread",
                        "--reruns=0", "--junitxml=" + str(args.report.with_suffix(".xml"))], plugins=[plugin])
    plugin.report["elapsed_seconds"] = time.monotonic() - started
    return 0 if plugin.complete(code) else 1


if __name__ == "__main__":
    raise SystemExit(main())
