"""Run native timing targets separately from correctness on a controlled Linux host.

Every selected target gets a bounded attempt and a retained log. A failure,
timeout or empty selection fails this diagnostic job. Passing these particular
wall-clock checks is not a proof of general constant-time execution.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time


def timing_targets(root: Path) -> list[tuple[str, str]]:
    return sorted(
        (path.parent.parent.name, path.stem)
        for path in (root / "native").glob("*/tests/*.rs")
        if "timing_gate!(" in path.read_text(encoding="utf-8")
    )


def run_target(command: list[str], *, cwd: Path, log: Path, timeout: float,
               env: dict[str, str]) -> dict:
    started = time.monotonic()
    row: dict = {"command": command, "status": "incomplete", "exit_code": None}
    with log.open("wb") as output:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                row["exit_code"] = process.wait(timeout=timeout)
                row["status"] = "passed" if row["exit_code"] == 0 else "failed"
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The process exited at the timeout boundary.
                process.wait()
                row["status"] = "timeout"
        except OSError as exc:
            row.update(status="error", error=f"{type(exc).__name__}: {exc}")
    row["elapsed_seconds"] = time.monotonic() - started
    row["log"] = log.name
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--per-target-timeout", type=float, default=180)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    args.report = args.report.resolve()
    if platform.system() != "Linux":
        parser.error("this controlled-runner entry point requires Linux")
    if not 1 <= args.per_target_timeout <= 3600:
        parser.error("per-target timeout must be between 1 and 3600 seconds")
    targets = timing_targets(args.root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "schema": "one-link-native-timing/v1", "status": "incomplete",
        "scope": "selected wall-clock diagnostics; not a constant-time certification",
        "platform": platform.platform(), "selected_targets": len(targets),
        "mode": "build" if args.build_only else "strict-measurement", "results": [],
    }
    env = dict(os.environ, OL_TIMING_GATES="1")
    def save() -> None:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    save()
    for crate, target in targets:
        command = ["cargo", "test", "--locked", "--release", "-p", crate,
                   "--test", target]
        command += ["--no-run"] if args.build_only else ["--", "--nocapture", "--test-threads=1"]
        row = run_target(command, cwd=args.root / "native", env=env,
                         log=args.report.parent / f"{crate}-{target}.log",
                         timeout=args.per_target_timeout)
        row.update(crate=crate, target=target)
        report["results"].append(row)
        save()
        print(f"{crate}/{target}: {row['status']} ({row['elapsed_seconds']:.2f}s)", flush=True)
    passed = bool(targets) and all(row["status"] == "passed" for row in report["results"])
    report["status"] = "passed" if passed else "failed"
    save()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
