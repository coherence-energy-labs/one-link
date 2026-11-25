"""The live-daemon harness must explain its own failures.

An intermittent Windows CI failure ("port file did not appear:
...\\control.port") took three tests down in a single run and was
undiagnosable, because the harness reported only the missing filename -- not
whether the daemon was alive, not its exit status, not the log it had already
written. These tests pin the evidence contract so that never recurs.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.harness import _read_port


class _FakeProc:
    """Minimal Popen stand-in: poll() returns the configured exit code."""

    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode


def _home_with_log(tmp_path: Path, text: str) -> tuple[Path, Path]:
    home = tmp_path / "home"
    (home / "data").mkdir(parents=True)
    log = tmp_path / "daemon.log"
    log.write_text(text, encoding="utf-8")
    return home, log


def test_dead_daemon_reports_exit_code_and_log_instead_of_waiting(
    tmp_path: Path,
) -> None:
    home, log = _home_with_log(tmp_path, "boot failed: address already in use\n")
    started = time.monotonic()
    with pytest.raises(RuntimeError) as failure:
        # A 30 s budget the call must NOT spend: the child is already gone, so
        # no port file can ever appear.
        _read_port(home, "control.port", timeout=30.0, proc=_FakeProc(3), log=log)
    elapsed = time.monotonic() - started

    message = str(failure.value)
    assert "exited with code 3" in message
    assert "address already in use" in message, "the log tail must be included"
    assert elapsed < 5.0, f"should fail fast on a dead child, took {elapsed:.2f}s"


def test_timeout_reports_liveness_elapsed_and_log(tmp_path: Path) -> None:
    home, log = _home_with_log(tmp_path, "still starting up\n")
    with pytest.raises(RuntimeError) as failure:
        _read_port(home, "control.port", timeout=0.2, proc=_FakeProc(None), log=log)

    message = str(failure.value)
    assert "port file did not appear" in message
    assert "daemon alive" in message, "liveness must be stated, not guessed"
    assert "of 0.20s" in message, "the budget actually waited must be reported"
    assert "still starting up" in message


def test_partially_written_port_file_is_retried_not_rejected(tmp_path: Path) -> None:
    """A half-written port file must not be read as a failure."""

    home, log = _home_with_log(tmp_path, "")
    port_file = home / "data" / "control.port"
    # Exists but has no value yet -- exactly what the daemon leaves behind for
    # the instant between create and write.
    port_file.write_text("", encoding="utf-8")

    # Finish the write from another thread, the way the real daemon does,
    # rather than patching stdlib path lookups.
    completer = threading.Timer(0.3, port_file.write_text, args=("54321",))
    completer.start()
    try:
        assert (
            _read_port(home, "control.port", timeout=10.0, proc=_FakeProc(None), log=log)
            == 54321
        )
    finally:
        completer.cancel()


def test_real_subprocess_that_never_writes_a_port_file_is_reaped_as_dead(
    tmp_path: Path,
) -> None:
    """The same contract against a genuine Popen, not just a stand-in."""

    home, log = _home_with_log(tmp_path, "real child\n")
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", "raise SystemExit(7)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        proc.wait(timeout=30)
        with pytest.raises(RuntimeError, match="exited with code 7"):
            _read_port(home, "control.port", timeout=30.0, proc=proc, log=log)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_a_failing_live_test_carries_both_daemon_log_tails(tmp_path: Path) -> None:
    """A hosted failure must arrive with the daemons' own account, not just the assertion."""
    from tests.harness import _attach_daemon_logs

    a_log, b_log = tmp_path / "a.log", tmp_path / "b.log"
    a_log.write_text("A started\nA sent the offer\n", encoding="utf-8")
    b_log.write_text("x" * 9000 + "B never committed the file\n", encoding="utf-8")
    failure = AssertionError("a.txt didn't land on B within 30s after Accept")
    _attach_daemon_logs(failure, {"A": a_log, "B": b_log})
    notes = getattr(failure, "__notes__", [])
    assert len(notes) == 2
    assert notes[0].startswith("--- daemon A log tail ---") and "A sent the offer" in notes[0]
    assert "B never committed the file" in notes[1]
    assert len(notes[1]) < 4200, "only the tail travels, not the whole log"
    assert str(failure) == "a.txt didn't land on B within 30s after Accept", "the failure itself is unchanged"


def test_missing_logs_and_non_failures_never_mask_the_original_exception(tmp_path: Path) -> None:
    from tests.harness import _attach_daemon_logs

    failure = AssertionError("original")
    _attach_daemon_logs(failure, {"A": tmp_path / "absent.log"})
    assert failure.__notes__ == ["--- daemon A log tail ---\n<no log>"]
    closing = GeneratorExit()
    _attach_daemon_logs(closing, {"A": tmp_path / "absent.log"})
    assert not getattr(closing, "__notes__", [])


def test_pytest_prints_the_attached_logs_under_the_traceback(tmp_path: Path) -> None:
    """The note is part of what pytest renders for a failure, in both traceback styles a job log uses."""
    from tests.harness import _attach_daemon_logs

    log = tmp_path / "b.log"
    log.write_text("B: still in step data-key acquisition after 5.0 s", encoding="utf-8")
    try:
        raise AssertionError("did not land")
    except AssertionError as failure:
        _attach_daemon_logs(failure, {"B": log})
        info = pytest.ExceptionInfo.from_exception(failure)
    for style in ("short", "long"):
        rendered = str(info.getrepr(style=style))
        assert "--- daemon B log tail ---" in rendered, style
        assert "still in step data-key acquisition" in rendered, style
