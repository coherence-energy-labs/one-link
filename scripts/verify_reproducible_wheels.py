"""Compare actual candidate wheels with an independent rebuild, retaining evidence.

An empty, incomplete, ambiguous or byte-different comparison fails. Archive
member diagnostics are recorded even when every uncompressed member matches:
ZIP metadata differences still mean that the distributed bytes differ.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _wheels(directory: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in sorted(directory.rglob("*.whl")):
        if path.name in result:
            raise ValueError(f"ambiguous duplicate wheel name: {path.name}")
        result[path.name] = path
    return result


def _members(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.filename in result:
                raise ValueError(f"duplicate ZIP member in {path.name}: {member.filename}")
            with archive.open(member) as stream:
                result[member.filename] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def compare(candidate: Path, rebuilt: Path, *, source_revision: str = "") -> dict:
    report: dict = {
        "schema": "one-link-reproducible-wheels/v1",
        "source_revision": source_revision,
        "scope": "exact bytes of the compared native wheels; not whole-product reproducibility",
        "hash_algorithm": "sha256",
        "passed": False,
        "wheels": [],
        "errors": [],
    }
    try:
        if candidate.resolve() == rebuilt.resolve():
            raise ValueError("candidate and rebuilt must be separate directories")
        first, second = _wheels(candidate), _wheels(rebuilt)
        if not first or not second:
            report["errors"].append("REPRODUCIBILITY VACUOUS: both builds must contain wheels")
        for name in sorted(first.keys() | second.keys()):
            left, right = first.get(name), second.get(name)
            row: dict = {"name": name, "equal": False}
            for label, path in (("candidate", left), ("rebuilt", right)):
                row[label] = None if path is None else {
                    "sha256": _sha256(path), "size_bytes": path.stat().st_size,
                }
            if left is None or right is None:
                row["reason"] = "wheel missing from one build"
            elif left.samefile(right):
                row["reason"] = "candidate and rebuilt refer to the same file"
            elif row["candidate"] == row["rebuilt"]:
                # Parse both archives too: corrupt/ambiguous archives must not
                # become accepted release inputs merely by matching each other.
                _members(left)
                _members(right)
                row["equal"] = True
            else:
                a, b = _members(left), _members(right)
                row["reason"] = "wheel bytes differ"
                row["members"] = [
                    {"name": member, "candidate_sha256": a.get(member),
                     "rebuilt_sha256": b.get(member)}
                    for member in sorted(a.keys() | b.keys()) if a.get(member) != b.get(member)
                ]
                if not row["members"]:
                    row["reason"] = "ZIP metadata/compression differs; member contents match"
            report["wheels"].append(row)
        report["passed"] = bool(report["wheels"]) and not report["errors"] and all(
            row["equal"] for row in report["wheels"]
        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--rebuilt", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-revision", default="")
    args = parser.parse_args(argv)
    report = compare(args.candidate, args.rebuilt, source_revision=args.source_revision)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
