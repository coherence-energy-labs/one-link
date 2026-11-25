"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import atexit
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


# Install a disposable default before importing *any* one_link module or test
# module.  Function fixtures run too late to contain module import side effects
# and higher-scoped fixtures, both of which are allowed to construct Daemon or
# resolve data_dir().  Preserve the caller's environment so this guard remains
# a well-behaved pytest-process boundary rather than a permanent shell change.
_ONE_LINK_HOME_ENV = "ONE_LINK_HOME"
_ORIGINAL_ONE_LINK_HOME_PRESENT = _ONE_LINK_HOME_ENV in os.environ
_ORIGINAL_ONE_LINK_HOME = os.environ.get(_ONE_LINK_HOME_ENV)
_PYTEST_SESSION_HOME_OWNER = tempfile.TemporaryDirectory(
    prefix="one-link-pytest-session-",
)
_PYTEST_SESSION_ROOT = Path(_PYTEST_SESSION_HOME_OWNER.name).resolve()
_PYTEST_SESSION_HOME = _PYTEST_SESSION_ROOT / "home"
os.environ[_ONE_LINK_HOME_ENV] = str(_PYTEST_SESSION_HOME)

# NO REAL WINDOWS DURING A TEST RUN. `_open_browser_url` now prefers One Link's own window, which
# spawns a process and waits up to 20s for it to report ready. Several tests call that function
# directly to exercise the browser fallback; without this they would open GUI windows on the
# machine running the suite and pay the wait for each one. Tests that mean to exercise the shell
# unset this explicitly.
os.environ["ONE_LINK_NO_NATIVE_SHELL"] = "1"

from one_link.platform_guard import install_windows_platform_fastpath


install_windows_platform_fastpath()


# v0.7.x: process-wide gate so any subprocess daemon the test
# harness spawns inherits ONE_LINK_DISABLE_REVEAL=1. Without this,
# tests that exercise reveal endpoints (or anywhere the UI can
# trigger them) pop real File Explorer windows on the developer's
# machine. Set as early as possible — module-import time — so
# subprocess.Popen calls before any test runs already inherit it.
os.environ.setdefault("ONE_LINK_DISABLE_REVEAL", "1")

# v0.10.7: same idea for the native folder picker. Without this,
# any test that hits POST /api/fs/pick-folder without patching
# server._native_folder_picker would pop a real PowerShell /
# osascript / zenity folder dialog on the developer's screen.
os.environ.setdefault("ONE_LINK_DISABLE_NATIVE_PICKER", "1")

# disable at-rest SQLCipher encryption for the test suite by default.
# Unit tests construct thousands of throwaway State() objects; routing
# each through the OS keychain (keyring) would pollute the developer's
# real credential store AND exhaust keychain / file handles at scale
# (observed as a 500+ ERROR cascade in the full suite).
#
# IMPORTANT: this is a TEST-ISOLATION flag, NOT the product default.
# In PRODUCTION at-rest encryption is fail-CLOSED (2026-06-16
# external-audit remediation): State() encrypts by default using the
# OS keychain or a local 0600 key file, and REFUSES to run plaintext
# unless the operator explicitly sets ONE_LINK_ALLOW_PLAINTEXT=1. The
# encrypted path + the "no plaintext ever leaks to disk" guarantee
# have dedicated coverage in test_at_rest_encryption_v021.py
# (test_migration_securely_deletes_plaintext_backup,
# test_state_db_encrypted_via_local_key_file_no_keyring,
# test_plaintext_refused_without_optin), which opt back IN.
os.environ.setdefault("ONE_LINK_DISABLE_AT_REST_ENCRYPTION", "1")

# v0.21.x accept-first: a standalone incoming file is HELD pending the
# user's accept by DEFAULT in production. Most tests exercise the
# FILE_OFFER transfer mechanics and expect the receiver to proceed, so
# default the policy OFF for the suite. Tests that specifically cover
# accept-first delenv / setenv this to control it explicitly.
os.environ.setdefault("ONE_LINK_REQUIRE_FILE_ACCEPT", "0")

# Test daemons must never take the product's well-known UI ports. Without an
# override a daemon auto-discovers from 7117 upward, so while a developer's
# real daemon was restarting (2026-11-25) test daemons bound 7117/7118 and the
# open app window could reach a TEST daemon. 0 = an OS-assigned port; tests
# read the chosen port back from data/server.port. A test that covers the
# preferred-port policy itself sets or deletes this variable explicitly.
os.environ.setdefault("ONE_LINK_UI_PORT", "0")


_PYTEST_SESSION_HOME_CLEANED = False


def _restore_and_cleanup_pytest_session_home() -> None:
    """Restore the inherited environment and remove only our exact temp root."""

    global _PYTEST_SESSION_HOME_CLEANED
    if _PYTEST_SESSION_HOME_CLEANED:
        return
    _PYTEST_SESSION_HOME_CLEANED = True
    if _ORIGINAL_ONE_LINK_HOME_PRESENT:
        assert _ORIGINAL_ONE_LINK_HOME is not None
        os.environ[_ONE_LINK_HOME_ENV] = _ORIGINAL_ONE_LINK_HOME
    else:
        os.environ.pop(_ONE_LINK_HOME_ENV, None)
    _PYTEST_SESSION_HOME_OWNER.cleanup()


# pytest_unconfigure is late enough that test and plugin session-finish hooks
# can still resolve isolated product paths.  atexit is the fail-safe for an
# interrupted pytest lifecycle that never reaches pytest_unconfigure.
atexit.register(_restore_and_cleanup_pytest_session_home)


def pytest_unconfigure(config: pytest.Config) -> None:
    del config
    _restore_and_cleanup_pytest_session_home()


@pytest.fixture(scope="session", autouse=True)
def _hold_import_time_one_link_home_guard() -> Iterator[Path]:
    """Prove session/module fixtures inherit the import-time containment."""

    assert Path(os.environ[_ONE_LINK_HOME_ENV]).resolve() == _PYTEST_SESSION_HOME
    yield _PYTEST_SESSION_HOME


@pytest.fixture(autouse=True)
def _isolate_default_one_link_home(tmp_path: Path, monkeypatch) -> Path:
    """Fail closed against unit tests writing into the real user profile.

    ``Daemon`` resolves its chunk cache, inbox, resume metadata, runtime port
    files, and several key stores during construction. Requiring every test
    author to remember an isolation fixture proved unsafe: a mocked finalizer
    left hundreds of synthetic files in a developer's production inbox.

    Import-time code plus session/module fixtures are contained by the
    process-wide disposable home above. Every function-scoped test then gets
    a distinct disposable default. Tests that intentionally exercise
    platform-default path semantics must explicitly ``delenv("ONE_LINK_HOME")``
    in their own scope, making that exceptional authority visible in the test.
    """

    home = tmp_path / "one-link-pytest-home"
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    return home


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch) -> Path:
    """Point ONE_LINK_HOME at a fresh temp dir for the test."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # Force re-import of paths so any cached values reset (we don't cache, but
    # be defensive).
    return tmp_path


@pytest.fixture
def isolated_homes(tmp_path: Path):
    """Two isolated homes for two-daemon tests. NOT setting env — caller spawns
    subprocesses with explicit env."""
    a = tmp_path / "A"
    b = tmp_path / "B"
    a.mkdir()
    b.mkdir()
    return a, b
