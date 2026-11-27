"""CLI surface tests: invoke `one-link <cmd>` as a real subprocess."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import click
import pytest

import one_link.cli as cli_mod
from tests.harness import daemon_pair


def _cli(*args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "one_link.cli", *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
        timeout=30,
    )


def test_version_works():
    r = _cli("--version")
    assert r.returncode == 0
    assert "one-link" in r.stdout
    # match a semver-shaped token; specific value isn't the point
    import re
    assert re.search(r"\d+\.\d+\.\d+", r.stdout), r.stdout


def test_help_works():
    r = _cli("--help")
    assert r.returncode == 0
    assert "daemon" in r.stdout
    assert "send" in r.stdout
    assert "send-file" in r.stdout
    assert "peers" in r.stdout
    assert "native-status" in r.stdout


def test_native_status_works():
    r = _cli("native-status")
    assert r.returncode == 0
    assert "native_cdc:" in r.stdout
    assert "engine:" in r.stdout


def test_whoami_creates_identity(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("whoami", env=env)
    assert r.returncode == 0
    assert "short_id" in r.stdout
    assert "fingerprint" in r.stdout
    # key file should now exist
    assert (tmp_path / "config" / "identity.key").is_file()


def test_whoami_persistent(tmp_path: Path):
    """Running whoami twice yields the same identity."""
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r1 = _cli("whoami", env=env)
    r2 = _cli("whoami", env=env)
    assert r1.stdout == r2.stdout


def test_peers_clean_error_when_daemon_not_running(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("peers", env=env)
    assert r.returncode != 0
    # Should be a friendly click error, not a stack trace.
    combined = (r.stdout + r.stderr).lower()
    assert "daemon not running" in combined or "no control.port" in combined or "could not reach daemon" in combined
    assert "traceback" not in combined


def test_missing_control_port_does_not_scan_global_ports(monkeypatch, tmp_path: Path):
    """No control.port and no live lock means daemon-not-running. Do not
    enumerate every localhost listener; in big suites that recovery scan can
    hang behind unrelated processes and make a clean error take 30s."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr(cli_mod.daemon_mod, "_read_lock_pid", lambda: None)
    monkeypatch.setattr(
        cli_mod.daemon_mod,
        "_candidate_local_listen_ports",
        lambda: (_ for _ in ()).throw(AssertionError("global scan used")),
    )

    with pytest.raises(RuntimeError, match="no control.port"):
        cli_mod.daemon_mod.read_control_port()


def test_send_clean_error_when_daemon_not_running(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("send", "abcdef12", "hi", env=env)
    assert r.returncode != 0


def test_request_clean_error_when_daemon_drops_mid_command(monkeypatch):
    monkeypatch.setattr(
        cli_mod.daemon_mod,
        "read_control_port",
        lambda clear_stale=False: 12345,
    )
    monkeypatch.setattr(
        cli_mod.control_ipc,
        "read_control_secret",
        lambda: "test-secret",
    )
    monkeypatch.setattr(
        cli_mod.control_ipc,
        "request_control",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ConnectionResetError("reset by peer")
        ),
    )

    with pytest.raises(click.ClickException) as exc:
        cli_mod._request("send_file", timeout=0.1, peer="abc", path="x")

    msg = str(exc.value).lower()
    assert "daemon connection dropped" in msg
    assert "resume after restart" in msg


def test_windows_force_kill_uses_subprocess_not_shell(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cli_mod.os, "environ", {"SystemRoot": r"C:\Windows"})
    monkeypatch.setattr(
        cli_mod,
        "resolve_system_executable",
        lambda *_args, **_kwargs: r"C:\Windows\System32\taskkill.exe",
    )
    monkeypatch.setattr(cli_mod.subprocess, "run", fake_run)

    cli_mod._force_kill_windows_pid(1234)

    assert calls
    argv, kwargs = calls[0]
    assert argv[0].endswith(r"System32\taskkill.exe")
    assert argv[1:] == ["/F", "/PID", "1234"]
    assert kwargs["check"] is False
    assert kwargs["shell"] is False


def test_daemon_stop_never_kills_pid_after_control_auth_failure(monkeypatch):
    monkeypatch.setattr(cli_mod.daemon_mod, "read_control_port", lambda: 7117)
    monkeypatch.setattr(
        cli_mod,
        "_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            click.ClickException("control authentication failed")
        ),
    )
    monkeypatch.setattr(
        cli_mod.daemon_mod,
        "_pid_matches_one_link_daemon",
        lambda _pid: (_ for _ in ()).throw(
            AssertionError("an unauthenticated PID must never be trusted")
        ),
    )

    with pytest.raises(click.ClickException, match="could not stop daemon"):
        cli_mod.daemon_stop.callback()


def test_daemon_stop_revalidates_authenticated_pid_before_force_kill(monkeypatch):
    monkeypatch.setattr(cli_mod.daemon_mod, "read_control_port", lambda: 7117)

    def request(cmd, **_kwargs):
        if cmd == "status":
            return {"ok": True, "pid": 4242}
        raise ConnectionResetError("shutdown response lost")

    checked: list[int] = []
    monkeypatch.setattr(cli_mod, "_request", request)
    monkeypatch.setattr(
        cli_mod.daemon_mod,
        "_pid_matches_one_link_daemon",
        lambda pid: checked.append(pid) or False,
    )
    monkeypatch.setattr(
        cli_mod,
        "_force_kill_windows_pid",
        lambda _pid: (_ for _ in ()).throw(AssertionError("unverified kill")),
    )

    with pytest.raises(click.ClickException, match="could not stop daemon"):
        cli_mod.daemon_stop.callback()
    assert checked == [4242]


@pytest.mark.live_daemon
@pytest.mark.timeout(120)
def test_full_cli_round_trip():
    """Two daemons via the harness; drive A's CLI as a subprocess."""
    with daemon_pair(pin_trust=True) as p:
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(p.a.home)

        # `one-link peers` should now list B
        r = _cli("peers", env=env)
        assert r.returncode == 0, r.stderr
        assert p.b.short_id[:8] in r.stdout

        # `one-link send <peer> "hi"`
        r = _cli("send", p.b.short_id, "hi from CLI", env=env)
        assert r.returncode == 0, r.stderr
        assert "ack" in r.stdout.lower()

        time.sleep(0.5)
        from tests.harness import message_log
        bodies = [
            m.get("body")
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert "hi from CLI" in bodies, bodies


@pytest.mark.live_daemon
@pytest.mark.timeout(120)
def test_cli_send_file_round_trip():
    with daemon_pair(pin_trust=True) as p:
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(p.a.home)

        src = p.tmp / "cli_payload.bin"
        src.write_bytes(b"x" * 12345)

        r = _cli("send-file", p.b.short_id, str(src), env=env)
        assert r.returncode == 0, r.stderr
        assert "blob=" in r.stdout

        time.sleep(0.5)
        inbox = list((p.b.home / "data" / "inbox").iterdir())
        match = [f for f in inbox if "cli_payload.bin" in f.name]
        assert match
        assert match[0].read_bytes() == src.read_bytes()
