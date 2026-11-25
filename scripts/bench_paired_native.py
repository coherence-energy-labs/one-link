#!/usr/bin/env python3
"""Alternate two already-built native artifacts under one benchmark harness.

Build each revision into its own virtual environment first. This runner never
checks out over an active tree or replaces an installed artifact between arms.
Both interpreters import this checkout's identical Python benchmark/adapters;
their separately installed native extensions and dependency sets are recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path


def paired_order(repeats: int) -> list[tuple[int, str]]:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    return [(i, arm) for i in range(repeats)
            for arm in (("candidate", "baseline") if i % 2 == 0 else ("baseline", "candidate"))]


def source_revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=5).strip()


def interpreter_path(path: Path) -> Path:
    # Resolving a venv's python symlink selects the *base* interpreter and
    # silently loses its installed native wheel/dependencies on POSIX.
    selected = path.absolute()
    if not selected.is_file():
        raise ValueError(f"interpreter is missing: {selected}")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ("candidate", "baseline"):
        parser.add_argument(f"--{arm}-python", type=Path, required=True)
        parser.add_argument(f"--{arm}-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--size-mib", type=int, default=128)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args(argv)
    if args.repeats < 1 or args.size_mib < 1 or args.timeout <= 0:
        parser.error("repeats, size and timeout must be positive")
    interpreters = {arm: interpreter_path(getattr(args, f"{arm}_python")) for arm in ("candidate", "baseline")}
    sources = {arm: getattr(args, f"{arm}_source").resolve(strict=True) for arm in interpreters}
    revisions = {arm: source_revision(path) for arm, path in sources.items()}
    harness = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        parser.error("output directory must be empty; preserve previous studies")
    session = uuid.uuid4().hex
    manifest = {"schema": "one-link-paired-benchmark-v1", "session_id": session,
                "harness_revision": source_revision(harness), "native_revisions": revisions,
                "requested_pairs": args.repeats, "size_mib": args.size_mib,
                "order": [], "status": "running"}
    manifest_path = args.output / "study.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for pair, arm in paired_order(args.repeats):
        env = dict(os.environ)
        env.update(PYTHONPATH=str(harness / "src"), ONE_LINK_BENCH_SESSION=session,
                   ONE_LINK_BENCH_PAIR=str(pair), ONE_LINK_BENCH_ARM=arm,
                   ONE_LINK_BENCH_NATIVE_REVISION=revisions[arm])
        filename = args.output / f"{arm}-{pair + 1}.json"
        stderr_path = args.output / f"{arm}-{pair + 1}.stderr.log"
        started = time.perf_counter()
        observation = {"pair_index": pair, "arm": arm, "filename": filename.name, "status": "failed"}
        try:
            with filename.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
                completed = subprocess.run(
                    [str(interpreters[arm]), "-m", "one_link.perf_lab_native", "--json", "--no-legacy", "--size-mib", str(args.size_mib)],
                    cwd=sources[arm], env=env, stdout=stdout, stderr=stderr,
                    timeout=args.timeout, check=False,
                )
            observation["exit_code"] = completed.returncode
            if completed.returncode == 0:
                payload = json.loads(filename.read_text(encoding="utf-8"))
                recorded = payload.get("provenance", {})
                if recorded.get("session_id") != session or recorded.get("native_source_revision") != revisions[arm]:
                    raise ValueError("benchmark child omitted its source/session provenance")
                observation["status"] = "completed"
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            observation["error"] = str(exc)
        observation["elapsed_seconds"] = time.perf_counter() - started
        manifest["order"].append(observation)
        if observation["status"] != "completed":
            manifest["status"] = "inconclusive"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            print(f"INCONCLUSIVE: {arm} pair {pair + 1} failed; partial evidence retained")
            return 2
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"completed pair {pair + 1}/{args.repeats}: {arm}", flush=True)
    manifest["status"] = "completed"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
