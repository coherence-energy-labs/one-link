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

import os
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
