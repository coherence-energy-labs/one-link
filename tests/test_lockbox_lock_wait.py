"""The envelope mutation lock waits (bounded) instead of failing immediately.

Real concurrent holders exist: `one-link backup export` runs beside a live
daemon without the instance lock and holds this lock while it ensures the
bundle's recovery envelope; the daemon takes it at every seeded boot
(bootstrap envelope, data-key acquisition) and from worker threads (TLS
authority minting, the in-daemon export API).  A waiter must get the lock
when the holder finishes, and must fail after a stated bound naming the
holder when it never does.
"""
from __future__ import annotations

import asyncio
import errno
import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from one_link import lockbox, master_seed
from one_link.key_material import KeyMaterialPersistenceError

REPO_SRC = Path(lockbox.__file__).resolve().parents[1]

# Runs in a separate interpreter: hold the lock the way `backup export` does.
_HOLDER = (
    "import os, sys, time\n"
    "from pathlib import Path\n"
    "from one_link import lockbox\n"
    "root, hold = Path(sys.argv[1]), float(sys.argv[2])\n"
    "try:\n"
    "    lock = lockbox._envelope_mutation_lock(root, purpose='one-link backup export')\n"
    "except TypeError:\n"
    "    lock = lockbox._envelope_mutation_lock(root)\n"
    "with lock:\n"
    "    print('held', os.getpid(), flush=True)\n"
    "    if hold < 0:\n"
    "        sys.stdin.readline()\n"
    "    else:\n"
    "        time.sleep(hold)\n"
)


@pytest.fixture(autouse=True)
def _fast_scrypt(monkeypatch):
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV, raising=False)


def _holder_process(root: Path, hold_s: float) -> tuple[subprocess.Popen, int]:
    """Start a holder; return it and the pid of the interpreter holding the
    lock (a venv launcher can sit between Popen and that interpreter)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_SRC) + os.pathsep + env.get("PYTHONPATH", "")
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(root), str(hold_s)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    word, _, pid = child.stdout.readline().strip().partition(" ")
    assert word == "held", child.stderr.read()
    return child, int(pid)


def _seeded_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    seed, _created = master_seed.provision_seed_before_derived_authority(
        root, identity_path=tmp_path / "identity.key",
    )
    assert seed is not None
    return root


def test_a_seeded_boot_waits_for_a_backup_export_in_another_process(tmp_path):
    root = _seeded_root(tmp_path)
    child, _holder_pid = _holder_process(root, hold_s=1.5)
    try:
        started = time.monotonic()
        box = lockbox.acquire_lockbox(root)  # what every seeded boot does
        waited = time.monotonic() - started
    finally:
        child.wait(timeout=30)
    assert child.returncode == 0, child.stderr.read()
    assert box.unwrap(box.wrap(b"x")) == b"x"
    assert 0.8 <= waited < lockbox.LOCK_WAIT_TIMEOUT_S


def test_a_holder_that_never_releases_fails_after_the_bound_naming_it(
    tmp_path, monkeypatch,
):
    root = _seeded_root(tmp_path)
    monkeypatch.setattr(lockbox, "LOCK_WAIT_TIMEOUT_S", 1.0)
    child, holder_pid = _holder_process(root, hold_s=-1)
    try:
        started = time.monotonic()
        with pytest.raises(KeyMaterialPersistenceError) as refused:
            lockbox.acquire_lockbox(root)
        waited = time.monotonic() - started
    finally:
        child.stdin.close()
        child.wait(timeout=30)
    message = str(refused.value)
    assert "one-link backup export" in message
    assert f"pid {holder_pid}" in message
    assert "1s" in message
    assert 1.0 <= waited < 5.0


def test_threads_of_one_process_wait_for_each_other(tmp_path, monkeypatch):
    """Two handles in one process conflict like two processes do (Windows
    byte-range locks and POSIX flock are per handle); a TLS-mint thread must
    wait for the export thread, not fail."""
    root = _seeded_root(tmp_path)
    holding = threading.Event()
    release = threading.Event()

    def export_thread() -> None:
        with lockbox._envelope_mutation_lock(root, purpose="backup export"):
            holding.set()
            release.wait(10)

    worker = threading.Thread(target=export_thread)
    worker.start()
    assert holding.wait(10)
    threading.Timer(0.6, release.set).start()
    started = time.monotonic()
    box = lockbox.acquire_lockbox(root)
    waited = time.monotonic() - started
    worker.join(10)
    assert box.unwrap(box.wrap(b"y")) == b"y"
    assert waited >= 0.4

    monkeypatch.setattr(lockbox, "LOCK_WAIT_TIMEOUT_S", 0.5)
    holding.clear()
    release.clear()
    worker = threading.Thread(target=export_thread)
    worker.start()
    assert holding.wait(10)
    try:
        with pytest.raises(KeyMaterialPersistenceError, match="backup export"):
            lockbox.acquire_lockbox(root)
    finally:
        release.set()
        worker.join(10)


def test_the_lock_is_reentrant_within_one_thread(tmp_path):
    """create_bundle holds the lock for the whole export and ensures the
    recovery envelope inside it; the nested acquisition must not wait on
    itself."""
    root = _seeded_root(tmp_path)
    started = time.monotonic()
    with lockbox._envelope_mutation_lock(root, purpose="backup export"):
        with lockbox._envelope_mutation_lock(root, purpose="nested"):
            pass
        box = lockbox.acquire_lockbox(root)
    assert time.monotonic() - started < 2.0
    assert box.unwrap(box.wrap(b"z")) == b"z"


# ─── one lock per FILE, however the directory is spelled ─────────────


def _second_spelling(real: Path, how: str) -> Path:
    """Another path that names the directory ``real``."""
    if how == "link":
        alias = real.parent / "alias"
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(real), str(alias))
        else:
            alias.symlink_to(real, target_is_directory=True)
        return alias
    if sys.platform != "win32":
        pytest.skip("8.3 short names are a Windows spelling")
    import ctypes

    size = ctypes.windll.kernel32.GetShortPathNameW(str(real), None, 0)
    buffer = ctypes.create_unicode_buffer(size)
    ctypes.windll.kernel32.GetShortPathNameW(str(real), buffer, size)
    if not buffer.value or os.path.normcase(buffer.value) == os.path.normcase(str(real)):
        pytest.skip("this volume generates no distinct 8.3 short name here")
    return Path(buffer.value)


@pytest.mark.parametrize("how", ["link", "short-name"])
def test_a_nested_acquisition_through_another_spelling_is_reentrant(
    tmp_path, monkeypatch, how,
):
    """Keyed by path string, a second spelling of one directory (a CI runner's
    ``RUNNER~1`` temp path beside its long form, a junction, a symlink) got a
    second process lock and a second handle; the nested acquisition then
    waited on its own thread's first handle for the whole bound and failed
    naming its own pid.  Keyed by the lock file's identity it is re-entrant."""
    root = _seeded_root(tmp_path)
    alias = _second_spelling(root, how)
    monkeypatch.setattr(lockbox, "LOCK_WAIT_TIMEOUT_S", 2.0)
    started = time.monotonic()
    with lockbox._envelope_mutation_lock(root, purpose="backup export"):
        with lockbox._envelope_mutation_lock(alias, purpose="nested"):
            pass
        box = lockbox.acquire_lockbox(alias)
    assert time.monotonic() - started < 1.0
    assert box.unwrap(box.wrap(b"a")) == b"a"


def test_another_thread_through_another_spelling_still_waits(tmp_path, monkeypatch):
    """Sharing one process lock per file must not hand re-entrancy to a
    DIFFERENT thread: it still waits, and is refused naming the holder."""
    root = _seeded_root(tmp_path)
    alias = _second_spelling(root, "link")
    holding = threading.Event()
    release = threading.Event()

    def export_thread() -> None:
        with lockbox._envelope_mutation_lock(root, purpose="backup export"):
            holding.set()
            release.wait(10)

    worker = threading.Thread(target=export_thread, name="exporter")
    worker.start()
    assert holding.wait(10)
    monkeypatch.setattr(lockbox, "LOCK_WAIT_TIMEOUT_S", 0.5)
    try:
        with pytest.raises(KeyMaterialPersistenceError) as refused:
            lockbox.acquire_lockbox(alias)
    finally:
        release.set()
        worker.join(10)
    message = str(refused.value)
    assert "backup export in this process" in message
    assert "thread exporter" in message


def test_two_descriptors_of_one_process_conflict(tmp_path):
    """The premise of the process lock, on THIS platform: a second
    descriptor of the lock file is refused while the first holds it (Windows
    byte-range locks and POSIX flock both belong to the descriptor), and is
    reported as contention -- not as an error -- so a waiter waits."""
    root = tmp_path / "data"
    root.mkdir()
    first = lockbox._open_envelope_lock_file(root)
    second = lockbox._open_envelope_lock_file(root)
    try:
        assert lockbox._try_lock_envelope_file(first) is True
        assert lockbox._try_lock_envelope_file(second) is False
        third = lockbox._open_envelope_lock_file(root)
        os.close(third)  # closing a non-holder releases nothing
        assert lockbox._try_lock_envelope_file(second) is False
        lockbox._release_envelope_file_lock(first)
        first = -1
        assert lockbox._try_lock_envelope_file(second) is True
    finally:
        if first >= 0:
            os.close(first)
        lockbox._release_envelope_file_lock(second)


def test_a_lock_refusal_that_is_not_contention_fails_at_once(tmp_path, monkeypatch):
    """Only contention is waited on.  msvcrt.locking reports EVERY LockFile
    failure as EACCES, so a refusal (access denied, a filter driver, a
    filesystem without locks) used to spin until the deadline."""
    root = _seeded_root(tmp_path)
    if sys.platform == "win32":
        real = lockbox._win32_byte_lock

        def refuse(fd: int, *, lock: bool) -> int:
            return 5 if lock else real(fd, lock=lock)  # ERROR_ACCESS_DENIED

        monkeypatch.setattr(lockbox, "_win32_byte_lock", refuse)
    else:
        import fcntl

        def refuse(fd: int, operation: int) -> None:
            if operation & fcntl.LOCK_EX:
                raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))

        monkeypatch.setattr(fcntl, "flock", refuse)
    started = time.monotonic()
    with pytest.raises(KeyMaterialPersistenceError, match="cannot lock") as refused:
        lockbox.acquire_lockbox(root)
    assert time.monotonic() - started < 0.5
    assert "in progress" not in str(refused.value)


# ─── a wait is never silent ──────────────────────────────────────────


def _lock_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "DEK envelope lock" in r.getMessage()]


def test_a_wait_is_announced_naming_the_holder_and_the_bound_then_its_end(
    tmp_path, caplog,
):
    root = _seeded_root(tmp_path)
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    child, holder_pid = _holder_process(root, hold_s=1.8)
    try:
        started = time.time()
        lockbox.acquire_lockbox(root)
    finally:
        child.wait(timeout=30)
    waiting, done = _lock_records(caplog)
    text = waiting.getMessage()
    assert "is waiting for the DEK envelope lock" in text
    assert "one-link backup export" in text and f"pid {holder_pid}" in text
    assert "bound 30s" in text
    assert 0.9 <= waiting.created - started < 1.8  # about one second in
    waited = float(re.search(r"after waiting (\d+\.\d)s", done.getMessage()).group(1))
    assert "acquired the DEK envelope lock" in done.getMessage()
    assert waited >= 1.0


def test_a_quick_acquisition_says_nothing(tmp_path, caplog):
    root = _seeded_root(tmp_path)
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    lockbox.acquire_lockbox(root)
    assert _lock_records(caplog) == []


def test_an_abandoned_wait_is_announced_with_the_time_waited(
    tmp_path, monkeypatch, caplog,
):
    root = _seeded_root(tmp_path)
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    monkeypatch.setattr(lockbox, "LOCK_WAIT_TIMEOUT_S", 1.5)
    child, holder_pid = _holder_process(root, hold_s=-1)
    try:
        with pytest.raises(KeyMaterialPersistenceError):
            lockbox.acquire_lockbox(root)
    finally:
        child.stdin.close()
        child.wait(timeout=30)
    waiting, gave_up = _lock_records(caplog)
    assert "is waiting" in waiting.getMessage()
    text = gave_up.getMessage()
    assert "gave up on the DEK envelope lock after waiting 1.5s" in text
    assert "one-link backup export" in text and f"pid {holder_pid}" in text


def test_an_in_process_wait_is_announced_too(tmp_path, caplog):
    root = _seeded_root(tmp_path)
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    holding = threading.Event()

    def export_thread() -> None:
        with lockbox._envelope_mutation_lock(root, purpose="backup export"):
            holding.set()
            time.sleep(1.4)

    worker = threading.Thread(target=export_thread, name="exporter")
    worker.start()
    assert holding.wait(10)
    lockbox.acquire_lockbox(root)
    worker.join(10)
    waiting, done = _lock_records(caplog)
    assert "backup export in this process" in waiting.getMessage()
    assert f"pid {os.getpid()}" in waiting.getMessage()
    assert "acquired" in done.getMessage()


# ─── an event-loop thread waits briefly ──────────────────────────────


def test_an_event_loop_thread_waits_only_the_short_bound(tmp_path):
    """Daemon.start acquires the data key on the event-loop thread.  It used
    to wait the full 30 s there: every coroutine stopped, and a supervisor's
    (or the e2e fixture's) 30 s readiness deadline expired first with nothing
    in the log.  Now it is refused after LOCK_WAIT_ON_EVENT_LOOP_S, naming
    the holder."""
    root = _seeded_root(tmp_path)
    child, holder_pid = _holder_process(root, hold_s=-1)

    async def boot() -> None:
        lockbox.acquire_lockbox(root)  # what Daemon.start does

    try:
        started = time.monotonic()
        with pytest.raises(KeyMaterialPersistenceError) as refused:
            asyncio.run(boot())
        waited = time.monotonic() - started
    finally:
        child.stdin.close()
        child.wait(timeout=30)
    assert lockbox.LOCK_WAIT_ON_EVENT_LOOP_S <= waited < lockbox.LOCK_WAIT_ON_EVENT_LOOP_S + 3
    message = str(refused.value)
    assert "one-link backup export" in message and f"pid {holder_pid}" in message
    assert f"bound {lockbox.LOCK_WAIT_ON_EVENT_LOOP_S:g}s" in message


def test_an_event_loop_thread_still_rides_out_a_short_holder(tmp_path):
    """The original defect -- a seeded boot failing at once while a backup
    export held the lock -- stays fixed on the event-loop thread itself."""
    root = _seeded_root(tmp_path)
    child, _holder_pid = _holder_process(root, hold_s=1.0)

    async def boot() -> lockbox.LockBox:
        return lockbox.acquire_lockbox(root)

    try:
        started = time.monotonic()
        box = asyncio.run(boot())
        waited = time.monotonic() - started
    finally:
        child.wait(timeout=30)
    assert box.unwrap(box.wrap(b"b")) == b"b"
    assert 0.5 <= waited < lockbox.LOCK_WAIT_ON_EVENT_LOOP_S


def test_worker_threads_and_offline_commands_keep_the_long_bound():
    async def bounds() -> tuple[float, float]:
        on_loop = lockbox._lock_wait_bound_s()
        in_worker = await asyncio.to_thread(lockbox._lock_wait_bound_s)
        return on_loop, in_worker

    on_loop, in_worker = asyncio.run(bounds())
    assert on_loop == lockbox.LOCK_WAIT_ON_EVENT_LOOP_S
    assert in_worker == lockbox.LOCK_WAIT_TIMEOUT_S
    assert lockbox._lock_wait_bound_s() == lockbox.LOCK_WAIT_TIMEOUT_S


# ─── a stalled boot step says where it is stalled, while it is ───────


def _stall_here(seconds: float) -> None:
    time.sleep(seconds)


def test_an_audible_step_names_the_stalled_call_while_it_stalls(caplog):
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    with lockbox.audible_step("probe step", after_s=0.2):
        _stall_here(0.8)
        during = [r.getMessage() for r in caplog.records]
    assert len(during) == 1, during  # logged before the step ended
    assert "probe step has been running for" in during[0]
    assert "_stall_here" in during[0]
    assert "probe step finished after" in caplog.records[-1].getMessage()


def test_a_prompt_audible_step_says_nothing(caplog):
    caplog.set_level(logging.WARNING, logger="one_link.lockbox")
    with lockbox.audible_step("quick step", after_s=0.5):
        pass
    time.sleep(0.7)  # past the threshold: a cancelled timer stays silent
    assert caplog.records == []
