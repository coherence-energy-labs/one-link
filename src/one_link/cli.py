"""one-link CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional

import click

from one_link import __version__
from one_link import control_ipc
from one_link import crash_log
from one_link import daemon as daemon_mod
from one_link.identity import load_or_create
from one_link.fault_observability import report_best_effort_failure
from one_link.process_security import (
    hidden_creationflags,
    launch_loopback_url,
    resolve_system_executable,
    trusted_process_env,
)
from one_link.safe_http import validated_urlopen


def _flush_stdio() -> None:
    """Best-effort flush of every logging handler + stderr + stdout.

    The launcher redirects the spawned daemon's stdout/stderr to a file
    (block-buffered) and merges stderr into stdout via
    ``stderr=subprocess.STDOUT``. PYTHONUNBUFFERED=1 makes the child
    line-flush on every write, but a final paranoid flush here closes
    the residual window between the last log call and process exit on
    abrupt termination paths.
    """

    def _flush_one(target: Any) -> bool:
        try:
            target.flush()
            return True
        except Exception:
            # This helper runs from crash/exit paths. Logging here can recurse
            # through the very handler that failed, so failure is deliberately
            # represented by the return value instead of another log record.
            return False

    try:
        handlers = tuple(logging.getLogger().handlers)
    except Exception:
        # A third-party logging manager may be tearing itself down already.
        handlers = ()
    for handler in handlers:
        _flush_one(handler)
    _flush_one(sys.stderr)
    _flush_one(sys.stdout)


def _connect_control(timeout: float = 5.0) -> tuple[socket.socket, int]:
    try:
        port = daemon_mod.read_control_port()
    except RuntimeError as e:
        raise click.ClickException(f"daemon not running ({e}).\nstart it with:  one-link daemon")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(("127.0.0.1", port))
    except OSError as e:
        raise click.ClickException(
            f"could not reach daemon on 127.0.0.1:{port}: {e}\n"
            f"is the daemon running? try:  one-link daemon"
        )
    s.settimeout(timeout)
    return s, port


def _force_kill_windows_pid(pid: int) -> None:
    """Terminate a stale daemon process on Windows without invoking a shell."""
    if pid <= 0:
        raise ValueError("pid must be positive")
    taskkill = resolve_system_executable("taskkill.exe", platform_name="windows")
    subprocess.run(
        [taskkill, "/F", "/PID", str(int(pid))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
        creationflags=hidden_creationflags(),
        cwd=str(Path(taskkill).parent),
        env=trusted_process_env(platform_name="windows"),
        shell=False,
    )


def _request(cmd: str, *, timeout: float = 5.0, **kwargs) -> dict:
    """Single control-socket request/response round trip.

    Retries up to 4 times with exponential backoff (0.1, 0.4, 1.6s)
    on the documented Windows TCP control-socket churn pattern (EOF
    before service, or ConnectionRefusedError when the accept queue
    drains under suite-level subprocess churn). See
    ``tests/test_two_device_soak.py:85`` for the pattern's origin;
    the same retry policy lives in ``tests/harness.py``.
    Real daemon errors still surface as ClickException; only
    transient connection-churn cases retry.
    """
    import time as _time

    backoff_s = (0.1, 0.4, 1.6)
    max_attempts = len(backoff_s) + 1
    last_conn_exc: Exception | None = None
    try:
        control_port = daemon_mod.read_control_port(clear_stale=False)
    except RuntimeError as exc:
        raise click.ClickException(f"daemon not running ({exc})") from exc
    try:
        secret = control_ipc.read_control_secret()
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    for attempt in range(max_attempts):
        try:
            return control_ipc.request_control(
                control_port,
                {"cmd": cmd, **kwargs},
                timeout=timeout,
                secret=secret,
            )
        except (
            control_ipc.ControlAuthenticationError,
            control_ipc.ControlFrameTooLarge,
            control_ipc.ControlProtocolError,
        ) as exc:
            raise click.ClickException(
                f"daemon control authentication failed while handling {cmd}: {exc}"
            ) from exc
        except (ConnectionAbortedError, ConnectionResetError, OSError, RuntimeError) as exc:
            last_conn_exc = exc
        if attempt < len(backoff_s):
            _time.sleep(backoff_s[attempt])
    # All attempts exhausted.
    if last_conn_exc is not None:
        raise click.ClickException(
            f"daemon connection dropped while handling {cmd}; "
            "One Link will keep durable transfer work and resume after restart "
            f"({last_conn_exc})"
        )
    raise click.ClickException(f"daemon returned no response while handling {cmd}")


def _ui_launch_info(*, timeout: float = 5.0) -> tuple[int, str]:
    """Resolve a mutually authenticated control daemon and HTTP listener."""

    # Lazy import avoids the CLI/app import cycle during command registration.
    # The launcher verifies an HMAC instance proof and sends the bearer only on
    # that same keep-alive socket before returning the credential to callers.
    from one_link.app import _resolve_running_daemon

    info = _resolve_running_daemon(timeout=timeout)
    if info is None:
        raise click.ClickException("authenticated daemon UI is not available")
    return info.server_port, info.token


def _ui_launch_url(*, path: str = "/", timeout: float = 5.0) -> str:
    """A UI URL carrying a SINGLE-USE credential, safe to hand to a browser.

    EVERY url built for a browser must come from here. `_ui_launch_info` returns the
    long-lived bearer, which is correct for an `Authorization` header and WRONG for a
    URL: opening a URL hands it to the browser as a command-line argument, and a command
    line is readable by any process running as the same user with no elevation (measured;
    see `UIServer.mint_launch_nonce` and threat T7b in docs/SECURITY.md).

    This existed as three separate f-strings -- the auto-open, the tray, and the deep-link
    handler -- and fixing only the one that was found would have left two live. A guard on
    one of several paths is a coincidence, not a control.
    """
    from one_link.app import _resolve_running_daemon

    info = _resolve_running_daemon(timeout=timeout)
    if info is None:
        raise click.ClickException("authenticated daemon UI is not available")
    credential = info.launch_nonce or info.token
    if not info.launch_nonce:
        logging.getLogger("one_link.cli").warning(
            "daemon minted no launch nonce; the UI URL carries the long-lived token and "
            "is readable by any process running as you. This should be unreachable."
        )
    return f"http://127.0.0.1:{info.server_port}{path}?t={credential}"


def _resolve_running_daemon_for_url(*, timeout: float = 5.0) -> tuple[int, str]:
    """(port, single-use credential) for callers that must build their own URL shape."""
    from one_link.app import _resolve_running_daemon

    info = _resolve_running_daemon(timeout=timeout)
    if info is None:
        raise click.ClickException("authenticated daemon UI is not available")
    if not info.launch_nonce:
        logging.getLogger("one_link.cli").warning(
            "daemon minted no launch nonce; this URL carries the long-lived token."
        )
    return info.server_port, (info.launch_nonce or info.token)


@click.group()
@click.version_option(__version__, prog_name="one-link")
def cli() -> None:
    """One Link — peer-to-peer LAN chat + file sync."""


@cli.command()
@click.option("-v", "--verbose", is_flag=True)
@click.option(
    "--tray/--no-tray",
    default=True,
    help="Run a system tray icon alongside the daemon (default: on).",
)
@click.option(
    "--open/--no-open",
    "open_browser",
    default=False,
    help="Auto-open the web UI in the default browser after "
    "the local server is ready (default: off). Set ONE_LINK_AUTO_OPEN=1 to enable.",
)
def daemon(verbose: bool, tray: bool, open_browser: bool) -> None:
    """Run the One Link daemon (leave this in a terminal/service)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Plant crash visibility BEFORE any of our threads spin up. An
    # uncaught exception in the tray loader, URL pusher, or auto-open
    # helper would otherwise be eaten by Python's default
    # threading.excepthook (prints to stderr — but stderr is redirected
    # by the launcher and may be block-buffered, so we have lost real
    # crashes here before). crash_log mirrors every uncaught exception
    # to data_dir()/crashes/<utc>-<reason>.txt with a synchronous fsync,
    # so a forensic record survives even an abrupt process exit.
    crash_log.install_excepthooks()
    # Visibility banner — every daemon launch announces whether it is
    # under the supervisor. The supervisor sets
    # ONE_LINK_SUPERVISED=1 on the child env so we can tell
    # post-hoc, from the log alone, which spawn path this run came
    # from. Without this banner a "daemon died silently" log gives no
    # answer to "was it supposed to auto-restart?".
    _supervised = os.environ.get("ONE_LINK_SUPERVISED") == "1"
    logging.getLogger("one_link.daemon").info(
        "daemon launch: pid=%d supervised=%s python=%s",
        os.getpid(),
        "yes" if _supervised else "NO (bare; no auto-restart on crash)",
        sys.version.split()[0],
    )
    # Auto-open is on either via --open OR ONE_LINK_AUTO_OPEN=1 in env
    # (PyInstaller-built GUI binary sets the env var so end users get
    # the browser the moment the daemon binds the local port).
    if not open_browser and os.environ.get("ONE_LINK_AUTO_OPEN") == "1":
        open_browser = True
    # v0.10.5/v0.12.2: optional tray icon. Start it off the critical daemon
    # boot path so slow Windows/Pillow/pystray initialization cannot delay
    # discovery, the control socket, or the local web UI coming online.
    # ``Any`` so the threaded tray loader can park the TrayIcon
    # without forcing the top-level cli module to import the
    # pystray-pulling tray module at decl time.
    tray_icon_holder: dict[str, Any] = {"icon": None}

    def _start_tray_icon() -> None:
        try:
            from one_link.tray import TrayIcon
            from one_link.paths import inbox_dir

            tray_icon = TrayIcon(
                on_quit=lambda: os.kill(os.getpid(), signal.SIGINT),
                inbox_path=inbox_dir(),
                # Minted per click, never stored: a single-use credential cached in the
                # tray would open the app once and leave every later click dead.
                url_provider=_ui_launch_url,
            )
            tray_icon_holder["icon"] = tray_icon
            if tray_icon.available:
                tray_icon.start()
                if tray_icon.available:
                    logging.getLogger("one_link.tray").info(
                        "tray icon active. Right-click for menu; click to open UI."
                    )
                else:
                    logging.getLogger("one_link.tray").info(
                        "tray icon unavailable; daemon is running without tray controls."
                    )
        except Exception as e:
            logging.getLogger("one_link.tray").info(
                "tray init skipped: %s",
                e,
            )

    if tray:
        threading.Thread(
            target=_start_tray_icon,
            daemon=True,
            name="one-link-tray-loader",
        ).start()

    # Once the daemon binds, push an authenticated loopback owner URL into the
    # tray. Phone pairing has its own short-lived public invitation flow.
    def _push_tray_url_when_ready() -> None:
        import time as _t

        # Poll authenticated control IPC, up to 10 s. The tray always opens the
        # owner UI through loopback; it never publishes the owner bearer in a
        # LAN URL or hover title.
        deadline = _t.time() + 10.0
        launch: tuple[int, str] | None = None
        while _t.time() < deadline:
            try:
                launch = _ui_launch_info(timeout=1.0)
                break
            except Exception:
                launch = None
            _t.sleep(0.1)
        if launch is None:
            return
        port, _token = launch
        # The tray must NOT cache a credential: a single-use nonce would work once and
        # leave every later click dead. It holds a bare URL for display and mints a fresh
        # one at click time via `url_provider`.
        url = f"http://127.0.0.1:{port}/"
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try:
                tray_icon.set_url(url)
            except Exception as exc:
                report_best_effort_failure(
                    logging.getLogger("one_link.cli"),
                    "tray_url_update",
                    exc,
                    level=logging.DEBUG,
                )

    threading.Thread(
        target=_push_tray_url_when_ready,
        daemon=True,
        name="one-link-tray-url-pusher",
    ).start()

    if open_browser:
        # Open the UI ~2.5 s after daemon boot starts. Long enough for
        # the local HTTP server to bind, short enough that the user
        # doesn't wait. The UI itself handles "daemon not ready yet"
        # with a small splash that auto-retries.
        def _open_when_ready() -> None:
            import time as _t

            _t.sleep(2.5)
            url = "http://127.0.0.1:7117/"
            try:
                url = _ui_launch_url(timeout=5.0)
            except (OSError, RuntimeError, ValueError, click.ClickException) as exc:
                report_best_effort_failure(
                    logging.getLogger("one_link.cli"),
                    "authenticated_ui_launch_info",
                    exc,
                    interval_s=30.0,
                )
            try:
                launch_loopback_url(url)
                logging.getLogger("one_link.cli").info(
                    "opened authenticated browser UI on loopback"
                )
            except Exception as e:
                logging.getLogger("one_link.cli").info(
                    "could not auto-open browser: %s; visit the URL manually",
                    e,
                )

        threading.Thread(
            target=_open_when_ready,
            daemon=True,
            name="one-link-open-browser",
        ).start()

    try:
        asyncio.run(daemon_mod.run())
    except RuntimeError as e:
        if "already running" in str(e):
            raise click.ClickException(str(e))
        # Anything else fell out of run() — fall through to the broad
        # crash-dump branch below so the operator gets a traceback file.
        logging.getLogger("one_link.daemon").critical(
            "daemon exited with uncaught RuntimeError",
            exc_info=True,
        )
        crash_log.dump_crash("daemon-uncaught", e)
        _flush_stdio()
        raise
    except (KeyboardInterrupt, SystemExit):
        # Clean operator-initiated exit — do not dump a crash report.
        raise
    except BaseException as e:  # noqa: BLE001 — last-chance catcher
        # Every uncaught exception that reaches here is, by definition,
        # the daemon dying. Log the full traceback via the logging
        # system (reaches daemon-launch.err.log) AND mirror to a
        # forensic crash file (survives stderr-buffer loss). Then flush
        # everything we can before re-raising.
        logging.getLogger("one_link.daemon").critical(
            "daemon exited with uncaught exception",
            exc_info=True,
        )
        crash_log.dump_crash("daemon-uncaught", e)
        _flush_stdio()
        raise
    finally:
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try:
                tray_icon.stop()
            except Exception as exc:
                report_best_effort_failure(
                    logging.getLogger("one_link.cli"),
                    "tray_stop",
                    exc,
                    level=logging.DEBUG,
                )
        _flush_stdio()


@cli.command()
@click.option(
    "--max-crashes",
    default=5,
    show_default=True,
    type=click.IntRange(1, 100),
    help="Trip the supervisor's circuit breaker after this many "
    "crashes in --window-s seconds. A deterministic crash loop "
    "needs human attention, not infinite respawn.",
)
@click.option(
    "--window-s",
    default=60.0,
    show_default=True,
    type=click.FloatRange(1.0, 3600.0),
    help="Circuit-breaker rolling window in seconds.",
)
def supervisor(max_crashes: int, window_s: float) -> None:
    """Run the daemon under a watchdog that auto-restarts on crash.

    Spawns ``one-link daemon`` as a child, waits for exit, and on
    non-zero exit restarts with exponential backoff. Trips on too many
    crashes in the configured window so a broken build cannot
    spin-restart indefinitely. SIGINT/SIGTERM cleanly shuts the child
    down and exits without restart.
    """
    from one_link import supervisor as supervisor_mod

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    crash_log.install_excepthooks()
    rc = supervisor_mod.run(max_crashes=max_crashes, window_s=window_s)
    _flush_stdio()
    raise SystemExit(rc)


@cli.group()
def autostart():
    """Register / unregister One Link to start at user login.

    User-mode integration (no admin/root needed). Survives reboots,
    log-off, sleep + hibernate that the in-process supervisor cannot.
    Windows uses the HKCU Run key; macOS uses a LaunchAgent plist;
    Linux uses an XDG autostart .desktop entry.
    """


@autostart.command("status")
def autostart_status() -> None:
    """Print whether One Link is registered to start at login."""
    from one_link import autostart as autostart_mod

    enabled = autostart_mod.is_enabled()
    path = autostart_mod.artifact_path()
    click.echo("autostart: " + ("ENABLED" if enabled else "disabled"))
    if path is not None:
        click.echo(f"artifact:  {path}")
    click.echo("command:   " + " ".join(autostart_mod._launch_command()))


@autostart.command("enable")
def autostart_enable() -> None:
    """Register One Link to start at the next user login.

    Idempotent — calling again rewrites the artifact with the current
    launcher path (so upgrading the binary picks up the new path
    automatically when you re-enable)."""
    from one_link import autostart as autostart_mod

    path = autostart_mod.enable()
    click.echo(f"autostart enabled. Wrote: {path}")
    click.echo("One Link will start at your next login under the supervisor.")


@autostart.command("disable")
def autostart_disable() -> None:
    """Remove the auto-start registration."""
    from one_link import autostart as autostart_mod

    removed = autostart_mod.disable()
    if removed:
        click.echo("autostart disabled.")
    else:
        click.echo("autostart was not enabled — nothing to remove.")


@cli.command()
def whoami():
    """Show this device's identity."""
    me = load_or_create()
    click.echo(f"hostname:    {me.hostname}")
    click.echo(f"short_id:    {me.short_id}")
    click.echo(f"fingerprint: {me.fingerprint}")


@cli.group()
def backup():
    """Manage your 24-word recovery phrase.

    The phrase is your sovereign backup: write it down on paper,
    keep the paper somewhere safe. If you lose the device, type
    the phrase on a new install and your identity + at-rest
    data unlock — peers continue to recognize you.

    The phrase is NEVER transmitted off-device, NEVER synced to
    any cloud, NEVER stored in any third-party service. It exists
    only on your paper backup + the daemon's encrypted local state.
    """


@backup.command("show")
def backup_show():
    """Print the 24-word recovery phrase. Write it down on paper."""
    from one_link import master_seed, mnemonic
    from one_link.paths import data_dir

    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` to create one (seed + identity\n"
            "will rotate; existing peers will see this as a key change).",
            err=True,
        )
        raise click.exceptions.Exit(1)
    phrase = mnemonic.encode(seed)
    click.echo("=" * 64)
    click.echo("WRITE THESE 24 WORDS DOWN ON PAPER. KEEP THE PAPER SAFE.")
    click.echo("This is your paper recovery path if you lose this device.")
    click.echo("Trusted-contact shares are a separate recovery alternative.")
    click.echo("=" * 64)
    words = phrase.split()
    for row in range(0, len(words), 4):
        line_words = words[row : row + 4]
        numbered = [f"{i + row + 1:>2}. {w:<10}" for i, w in enumerate(line_words)]
        click.echo("  ".join(numbered))
    click.echo("=" * 64)
    click.echo("Anyone with these 24 words can take over your identity.")
    click.echo("Treat them like a physical bank PIN: paper-only, never typed")
    click.echo("into a website, never photographed, never sent to anyone.")
    click.echo("=" * 64)


@backup.command("init")
@click.option(
    "--force",
    is_flag=True,
    help="Rotate identity even if existing keys are in use.",
)
def backup_init(force):
    """Create a recoverable master seed for this install.

    Use this on an existing One Link install (which already has
    randomly-generated, non-recoverable keys) to switch to a
    seed-backed setup. After running this, your old identity is
    replaced — peers will see you as a "new" device with a
    different fingerprint and you'll need to re-pair with them.

    On a fresh install (no existing identity.key), the daemon
    auto-creates a seed on first launch. This command is for
    EXISTING installs that want to opt into recovery.
    """
    import secrets

    from one_link import master_seed, recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir, key_path

    if master_seed.has_seed(data_dir()):
        click.echo(
            "A master seed already exists. Run `one-link backup show`\n"
            "to view its 24-word phrase. Never delete authority files\n"
            "by hand; use an explicit recovery transaction if this\n"
            "identity must be replaced.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    root = data_dir()
    identity_path = key_path()
    try:
        evidence = recovery_api.restore_artifact_evidence(
            root,
            identity_path=identity_path,
        )
    except Exception as exc:
        raise click.ClickException(
            f"could not prove this install is safe to initialize: {exc}"
        ) from exc
    if any(evidence.values()) and not force:
        click.echo(
            "Existing authority or state is in use. Initializing a master\n"
            "seed will replace that identity after a controlled restart\n"
            "(peers will see a different device).\n"
            "Re-run with --force to confirm rotation.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    seed = secrets.token_bytes(master_seed.SEED_LEN_BYTES)
    try:
        result = recovery_api.stage_seed_authority_replacement(
            data_dir=root,
            identity_path=identity_path,
            seed=seed,
            allow_replace=force,
        )
    except (ValueError, KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(f"could not initialize recovery: {exc}") from exc
    if result["pending_restart"]:
        click.echo(
            "Recovery initialization staged durably. Existing keys were not\n"
            "deleted or changed. Stop every One Link process, start the daemon\n"
            "once to commit the transaction, then run `one-link backup show`."
        )
    else:
        click.echo(
            "Master seed, identity, and at-rest authority created and verified.\n"
            "Run `one-link backup show` and write the 24 words on paper."
        )


@backup.command("restore")
@click.argument("phrase_words", nargs=-1)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing identity even if one is present.",
)
def backup_restore(phrase_words, force):
    """Restore identity from a 24-word recovery phrase.

    Use on a NEW device that you want to be the same identity as
    your old (lost) device. Type the 24 words separated by spaces:

        one-link backup restore word1 word2 ... word24

    Or paste them when prompted (no arguments).

    Refuses to run if an identity already exists, unless --force.
    The seed file is created from the phrase; on next daemon
    launch the identity + DRK derive from it.
    """
    from one_link import recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir, key_path

    root = data_dir()
    identity_path = key_path()
    try:
        evidence = recovery_api.restore_artifact_evidence(
            root,
            identity_path=identity_path,
        )
    except Exception as exc:
        raise click.ClickException(
            f"could not prove this install is safe to restore: {exc}"
        ) from exc
    if any(evidence.values()) and not force:
        click.echo(
            "Existing authority or state is in use. Restoring will replace\n"
            "that identity after a controlled restart. Re-run with --force\n"
            "to confirm.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt(
            "phrase",
            hide_input=True,
            prompt_suffix="> ",
        )
    else:
        raw = " ".join(phrase_words)
    try:
        recovery_api.restore_seed_from_phrase(
            data_dir=root,
            phrase=raw,
            delete_identity_files=force,
        )
    except ValueError as exc:
        raise click.ClickException(f"invalid phrase: {exc}") from exc
    except (KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(f"restore could not be staged: {exc}") from exc
    if recovery_api.has_pending_recovery(root):
        click.echo(
            "Recovery staged durably; existing authority is unchanged. Stop\n"
            "every One Link process and start the daemon once to commit it."
        )
    else:
        click.echo(
            "Master seed, identity, and at-rest authority restored and verified.\n"
            "Peers paired with the original device will recognize you."
        )


@backup.command("test")
@click.argument("phrase_words", nargs=-1)
def backup_test(phrase_words):
    """Check whether a paper phrase matches the on-disk identity.

    Decodes the 24-word BIP-39 phrase and compares it (in constant
    time) to the master seed on this install. Writes nothing.

    Use BEFORE running `backup restore` to confirm you wrote the
    phrase down correctly. Useful as a periodic audit: every few
    months, type the phrase from your paper backup and confirm it
    still produces a green check.

    Exit codes mirror the UI's three colors:
      0 = green   (phrase matches the current identity)
      2 = amber   (valid phrase, no current identity OR different identity)
      1 = red     (phrase failed to decode)
    """
    from one_link import recovery_api
    from one_link.paths import data_dir

    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt("phrase", hide_input=True, prompt_suffix="> ")
    else:
        raw = " ".join(phrase_words)
    res = recovery_api.test_phrase_against_current_seed(
        data_dir=data_dir(),
        phrase=raw,
    )
    if not res["valid_checksum"]:
        click.echo(f"INVALID PHRASE: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    if not res["has_current_identity"]:
        click.echo("Valid 24-word phrase, but this device has no master seed to compare against.")
        raise click.exceptions.Exit(2)
    if res["matches_current_identity"]:
        click.echo("VERIFIED: this phrase matches your current identity.")
        return
    click.echo(
        "Valid 24-word phrase, but it does NOT match your current "
        "identity. This is a phrase for a different install.",
        err=True,
    )
    raise click.exceptions.Exit(2)


@backup.command("test-bundle")
@click.argument(
    "bundle_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument("phrase_words", nargs=-1)
def backup_test_bundle(bundle_path, phrase_words):
    """Check whether a .olbak file decrypts with a 24-word phrase.

    AEAD-decrypts the bundle in memory and reports the bundle's
    header timestamp + plaintext file count. Writes nothing to disk;
    the existing identity on this install is not touched.

    Use BEFORE running `backup import` to confirm the bundle + phrase
    pair is valid (e.g., after restoring a backup file from cold
    storage you haven't touched in months).

    Exit codes:
      0 = bundle decrypted + plaintext archive readable
      1 = phrase invalid OR bundle failed to decrypt
    """
    from one_link import backup_bundle, recovery_api

    try:
        bundle_bytes = backup_bundle.read_bundle_file_bounded(Path(bundle_path))
    except ValueError as exc:
        raise click.ClickException(f"bundle read failed: {exc}") from exc
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt("phrase", hide_input=True, prompt_suffix="> ")
    else:
        raw = " ".join(phrase_words)
    res = recovery_api.test_bundle_against_phrase(
        phrase=raw,
        bundle_bytes=bundle_bytes,
    )
    if not res["valid_phrase"]:
        click.echo(f"INVALID PHRASE: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    if not res["valid_bundle"]:
        click.echo(f"BUNDLE DECRYPT FAILED: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    created = res.get("bundle_created_ms", 0)
    files = res.get("file_count", 0)
    click.echo(
        f"VERIFIED: bundle decrypts cleanly with this phrase.\n"
        f"  created_ms: {created}\n"
        f"  file_count: {files}"
    )


@backup.command("export")
@click.argument("out_path", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--include-files",
    is_flag=True,
    help=(
        "Also include everything under inbox/. The encoded .olbak payload is "
        "capped at 256 MiB for bounded restore; use ordinary file backup for "
        "larger or poorly-compressing inboxes. By default only load-bearing "
        "state is bundled. Identity, chat history, groups, and folder configs "
        "are ALWAYS included regardless of this flag."
    ),
)
def backup_export(out_path, include_files):
    """Write an encrypted backup bundle to OUT_PATH (a .olbak file).

    The bundle is sealed with a key derived from your master seed
    (the same seed your 24-word phrase encodes). It can ONLY be
    decrypted by an install that knows the seed: either this same
    daemon, or a fresh install where you've typed the 24 words via
    `one-link backup restore`.

    Without the seed the bundle is ciphertext indistinguishable
    from random. Drop it on a USB stick, upload to any cloud, mail
    it to yourself — without the 24 words it's unintelligible.

    Refuses to run if no master seed has been provisioned (run
    `one-link backup init` first to create one).
    """
    from one_link import backup_bundle, master_seed
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir

    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    out_path = out_path.expanduser().resolve()
    if out_path.exists():
        click.echo(
            f"Refusing to overwrite existing file: {out_path}\n"
            "Pick a different path, or remove it first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    try:
        n = backup_bundle.create_bundle_to_file(
            seed=seed,
            data_dir=data_dir(),
            out_path=out_path,
            include_files=include_files,
        )
    except (OSError, ValueError, KeyMaterialError) as e:
        raise click.ClickException(f"export failed: {e}")
    click.echo(f"wrote {n} bytes -> {out_path}")
    click.echo(
        "This file is encrypted under your master seed. To restore it on a\n"
        "new device, restore the 24-word phrase first. If that command stages\n"
        "a restart, complete it; then run `one-link backup import <path>\n"
        "--overwrite` through the same safe recovery transaction."
    )


@backup.command("import")
@click.argument("bundle_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--overwrite",
    is_flag=True,
    help="Validate and stage replacement of the active install at restart.",
)
@click.option(
    "--target-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Override the install's data dir (advanced; default is correct).",
)
def backup_import(bundle_path, overwrite, target_dir):
    """Decrypt and unpack a .olbak bundle into this install's data dir.

    Requires a master seed already provisioned on this install (via
    `one-link backup restore <24 words>`). The seed must match the
    one that sealed the bundle, or decryption fails.

    The active install is never modified while a daemon may still hold its
    keys/database open. ``--overwrite`` validates and durably stages the bundle;
    singleton-locked daemon startup commits it. A custom ``--target-dir`` is an
    offline operation and must be a proven-empty directory; overwrite is never
    permitted there.
    """
    import stat

    from one_link import backup_bundle, master_seed, mnemonic, recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir, key_path

    active_root = data_dir().resolve()
    try:
        pending_recovery = recovery_api.has_pending_recovery(active_root)
        seed = master_seed.load_seed(active_root)
    except (OSError, KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(
            f"cannot inspect active recovery authority: {exc}"
        ) from exc
    if pending_recovery:
        raise click.ClickException(
            "another recovery is already pending; restart One Link to commit "
            "it before importing a backup"
        )
    if seed is None:
        click.echo(
            "No master seed on this install. Run\n"
            "  one-link backup restore <word1> <word2> ... <word24>\n"
            "first, using the 24-word phrase from the device this bundle came from.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    target = Path(target_dir).expanduser().resolve() if target_dir else active_root
    live_target = target == active_root
    if not live_target:
        if overwrite:
            raise click.ClickException(
                "--overwrite is not allowed with --target-dir; choose a new, "
                "empty offline directory"
            )
        if target.exists():
            try:
                observed = target.lstat()
                attrs = int(getattr(observed, "st_file_attributes", 0) or 0)
                reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                if (
                    stat.S_ISLNK(observed.st_mode)
                    or bool(attrs & reparse)
                    or not stat.S_ISDIR(observed.st_mode)
                ):
                    raise click.ClickException(
                        "custom restore target must be a real local directory, "
                        "not a file, link, or reparse point"
                    )
                if next(target.iterdir(), None) is not None:
                    raise click.ClickException(
                        "custom restore target is not empty; choose a new directory"
                    )
            except click.ClickException:
                raise
            except OSError as exc:
                raise click.ClickException(
                    f"could not prove custom restore target is clean: {exc}"
                ) from exc
    elif not overwrite:
        raise click.ClickException(
            "the active install contains authority/state; re-run with --overwrite "
            "to validate and stage replacement at the next controlled restart"
        )

    try:
        bundle_bytes = backup_bundle.read_bundle_file_bounded(
            Path(bundle_path).expanduser().resolve()
        )
        result = recovery_api.restore_from_bundle(
            data_dir=target,
            identity_path=key_path() if live_target else target / "identity.key",
            phrase=mnemonic.encode(seed),
            bundle_bytes=bundle_bytes,
            delete_identity_files=live_target,
            overwrite=live_target,
        )
    except FileExistsError as e:
        click.echo(
            f"Refusing to overwrite existing file: {e}\n"
            "Re-run with --overwrite to replace, or pick a clean --target-dir.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    except (ValueError, recovery_api.RecoveryTransactionError) as e:
        # Wrong seed, tampered file, bad magic, traversal attempt, etc.
        raise click.ClickException(f"import failed: {e}")
    except (OSError, KeyMaterialError) as e:
        raise click.ClickException(f"import failed: {e}")
    written = list(result.get("written") or [])
    if result.get("pending_restart"):
        click.echo(
            f"validated {result.get('file_count', 0)} backup file(s) and staged "
            f"the encrypted bundle for {target}"
        )
        click.echo(
            "Existing live files and keys are unchanged. Stop every One Link "
            "process and start the daemon once to commit the transaction."
        )
        return
    click.echo(f"restored and verified {len(written)} file(s) into {target}")
    if written:
        for name in written[:20]:
            click.echo(f"  - {name}")
        if len(written) > 20:
            click.echo(f"  ... and {len(written) - 20} more")


@cli.group()
def recovery():
    """Social recovery — your social graph IS your backup layer.

    Instead of keeping a 24-word phrase on paper (and hoping it's
    not lost / read by a thief / destroyed in a fire), split your
    master seed into 5 Shamir shares and hand each to a different
    trusted contact. ANY 3 of the 5 reconstruct your identity on a
    new device. Up to 2 contacts can be malicious or coerced and
    still gain nothing — Shamir's information-theoretic threshold
    holds.

    Trust model: you trust that 3 of your 5 chosen contacts won't
    all collude against you. Different from custodial recovery
    (Apple iCloud, Google account) where ONE entity holds every-
    thing; here no platform — and no single person — can lock you
    out of your own identity.

    Workflow:

      one-link recovery setup <name1> <ed_pub_hex_1> ... <name5> <ed_pub_hex_5>
        Mints 5 wrapped shares + writes each to ./shares/<name>.olshare
        ready to deliver to the named contact (USB stick, in-person
        QR, encrypted email, channel message — the medium is up to
        you, the wrap is sealed).

      one-link recovery unwrap <share_path>
        For a CONTACT who has received a share addressed to them:
        decrypt it with this device's identity and print the share
        bytes (also as a QR-friendly base64 string ready to scan
        back to the recovering user).

      one-link recovery restore <share_blob_1> ... <share_blob_K>
        On a fresh device: reconstruct the master seed from K
        decrypted shares (each is the base64 the unwrap step
        emitted) and stage it. On next daemon start, identity and
        seed-derived authority converge. Retained chats/settings require the
        matching encrypted backup and its wrapped application-key artifacts.
    """


@recovery.command("setup")
@click.argument("guardians", nargs=-1)
@click.option(
    "--threshold",
    "threshold_k",
    default=3,
    type=int,
    help="K in K-of-N (default 3)",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Where to write the wrapped shares (default ./shares/).",
)
def recovery_setup(
    guardians: tuple[str, ...],
    threshold_k: int,
    out_dir: Optional[Path],
) -> None:
    """Split this device's master seed into wrapped shares.

    GUARDIANS is a flat list of (name ed_pub_hex) pairs:

        one-link recovery setup \\
            mom    a1b2c3...64hex \\
            dad    11223344...64hex \\
            sister deadbeef...64hex \\
            old-laptop  abcdef...64hex \\
            backup-yubikey 99887766...64hex
    """
    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir

    if len(guardians) % 2 != 0 or len(guardians) < 4:
        raise click.ClickException(
            "GUARDIANS must be (name pub_hex) pairs; need at least 2 guardians.\n"
            "Example: one-link recovery setup mom abc... dad def... sister 123..."
        )
    parsed: list[tuple[str, bytes]] = []
    for i in range(0, len(guardians), 2):
        name = guardians[i]
        try:
            pub = bytes.fromhex(guardians[i + 1])
        except ValueError:
            raise click.ClickException(f"guardian {name!r}: pub_hex is not valid hex")
        if len(pub) != 32:
            raise click.ClickException(
                f"guardian {name!r}: pub_hex must be 32 bytes (64 hex chars), got {len(pub)} bytes"
            )
        parsed.append((name, pub))
    total_n = len(parsed)
    if not (2 <= threshold_k <= total_n):
        raise click.ClickException(
            f"--threshold must be 2 ≤ K ≤ N (got K={threshold_k}, N={total_n})"
        )
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        raise click.ClickException(
            "No master seed on this install. Run `one-link backup init` "
            "first to provision one (or `one-link backup restore <24 words>` "
            "to recover an existing identity)."
        )
    shares = social_recovery.setup_social_recovery(
        seed=seed,
        guardians=parsed,
        threshold_k=threshold_k,
    )
    target_dir = (
        Path(out_dir).expanduser().resolve() if out_dir else Path("./shares").expanduser().resolve()
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    for name, share in shares:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        out = target_dir / f"{safe_name}.olshare"
        out.write_bytes(share.encoded)
    click.echo(
        f"wrote {len(shares)} shares ({threshold_k}-of-{total_n}) -> {target_dir}\n"
        f"deliver each .olshare file to the named guardian. Any {threshold_k} "
        f"of the {total_n} reconstruct your seed."
    )


@recovery.command("unwrap")
@click.argument(
    "share_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def recovery_unwrap(share_path):
    """Decrypt a share addressed to this device.

    Run as a guardian who has received a .olshare file from someone
    asking you to be a recovery contact. Prints the decrypted share
    bytes (hex) and a QR-friendly base64 form. The recovering
    person will paste / scan that base64 along with K-1 others.
    """
    import base64

    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir, key_path

    seed = master_seed.load_seed(data_dir())
    if seed is None:
        # Fall back to the raw identity key — older daemons without a
        # master seed still have an Ed25519 priv on disk.
        if not key_path().is_file():
            raise click.ClickException(
                "no master seed AND no identity.key — this device has no "
                "private key to unwrap a share with"
            )
        # Best-effort load of the raw priv seed from PEM. Same env
        # var as the daemon's normal identity-load path so an
        # operator with a passphrase-protected key on disk can
        # decrypt for recovery without supplying it twice.
        from cryptography.hazmat.primitives import serialization
        from one_link.identity import PASSPHRASE_ENV

        pw_env = os.environ.get(PASSPHRASE_ENV)
        pw = pw_env.encode("utf-8") if pw_env else None
        try:
            priv_obj = serialization.load_pem_private_key(
                key_path().read_bytes(),
                password=pw,
            )
        except Exception as e:
            raise click.ClickException(f"identity key load failed: {e}")
        # Only Ed25519 keys carry a raw seed; identity.key on disk is
        # always Ed25519 (we minted it that way), so narrow.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if not isinstance(priv_obj, Ed25519PrivateKey):
            raise click.ClickException("identity key on disk is not Ed25519 — cannot recover.")
        ed_seed = priv_obj.private_bytes_raw()
    else:
        ed_seed = master_seed.derive_identity_priv(seed).private_bytes_raw()

    blob = Path(share_path).read_bytes()
    try:
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=blob,
            my_ed_priv_seed=ed_seed,
        )
    except ValueError as e:
        raise click.ClickException(f"unwrap failed: {e}")
    parsed = social_recovery.WrappedShare.parse(blob)
    click.echo(
        f"share index:  {idx}\n"
        f"threshold:    {parsed.threshold}-of-{parsed.total}\n"
        f"setup_ms:     {parsed.setup_ms}\n"
    )
    # Encode as base64 for in-person paste / QR.
    payload = bytes([idx]) + share_bytes
    portable = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    click.echo(
        "Send this single string to the person recovering. They will\n"
        "combine it with shares from K-1 other contacts to reconstruct\n"
        "their identity. Treat it as sensitive: anyone holding K shares\n"
        "can take over the original device's identity.\n"
    )
    click.echo(portable)


@recovery.command("restore")
@click.argument("portable_shares", nargs=-1)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing master seed on this device.",
)
def recovery_restore(portable_shares: tuple[str, ...], force: bool) -> None:
    """Reconstruct the master seed from K guardian shares.

    PORTABLE_SHARES is the list of base64 strings collected from the
    `recovery unwrap` step on each of K guardian devices.
    """
    import base64

    from one_link import recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir, key_path

    if len(portable_shares) < 2:
        raise click.ClickException(
            "need at least 2 portable shares (from `recovery unwrap` on each guardian device)"
        )
    root = data_dir()
    identity_path = key_path()
    try:
        evidence = recovery_api.restore_artifact_evidence(
            root,
            identity_path=identity_path,
        )
    except Exception as exc:
        raise click.ClickException(
            f"could not prove this install is safe to restore: {exc}"
        ) from exc
    if any(evidence.values()) and not force:
        click.echo(
            "Existing authority or state is in use. Re-run with --force to\n"
            "stage its replacement after a controlled daemon restart.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    decrypted: list[tuple[int, bytes]] = []
    for s in portable_shares:
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            payload = base64.urlsafe_b64decode((s + pad).encode("ascii"))
        except Exception as e:
            raise click.ClickException(f"share {s[:8]}…: not valid base64 ({e})")
        if len(payload) < 2:
            raise click.ClickException(f"share {s[:8]}…: too short")
        idx = payload[0]
        share_bytes = payload[1:]
        decrypted.append((idx, share_bytes))
    try:
        recovery_api.restore_from_shares(
            data_dir=root,
            shares=decrypted,
            delete_identity_files=force,
        )
    except ValueError as exc:
        raise click.ClickException(f"reconstruct failed: {exc}") from exc
    except (KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(f"restore could not be staged: {exc}") from exc
    if recovery_api.has_pending_recovery(root):
        click.echo(
            "Social recovery staged durably; existing authority is unchanged.\n"
            "Stop every One Link process and start the daemon once to commit it."
        )
    else:
        click.echo(
            "Master seed, identity, and at-rest authority reconstructed and\n"
            "verified. Peers paired with the original device will recognize you."
        )


def _data_key_passphrase(*, confirm: bool) -> str:
    """ONE_LINK_PASSPHRASE if set, otherwise a hidden prompt.

    Never a command-line argument (argv is visible to every local process and
    lands in shell history) and never logged or echoed.
    """
    import os

    from one_link import lockbox

    value = os.environ.get(lockbox.PASSPHRASE_ENV, "")
    if value:
        return value
    value = click.prompt(
        "passphrase",
        hide_input=True,
        confirmation_prompt=confirm,
        prompt_suffix="> ",
    )
    if not value:
        raise click.ClickException("an empty passphrase protects nothing")
    return value


@recovery.command("set-passphrase")
def recovery_set_passphrase() -> None:
    """Protect this install's data with a passphrase (One Link must be stopped).

    Re-wraps every protected file and database field from the silent data key
    to a new passphrase-protected data key, and moves the state database onto
    the passphrase, in one transaction that survives a crash: if it is
    interrupted, run this command again with the same passphrase to finish.

    The passphrase is read from ONE_LINK_PASSPHRASE, or prompted for (twice).
    Afterwards always start One Link with ONE_LINK_PASSPHRASE set.

    Your 24-word phrase does not change. With a backup bundle exported after
    this, the phrase alone still recovers everything; the passphrase is not
    needed for recovery.
    """
    from one_link import recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir

    passphrase = _data_key_passphrase(confirm=True)
    try:
        report = recovery_api.set_data_key_passphrase(
            data_dir=data_dir(), passphrase=passphrase,
        )
    except (ValueError, KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(f"set-passphrase did not complete: {exc}") from exc
    if not report["changed"]:
        click.echo("This install is already protected by that passphrase; nothing changed.")
        return
    click.echo(
        "The data key is now protected by your passphrase and every protected\n"
        "file and field was re-wrapped and verified. Start One Link with\n"
        "ONE_LINK_PASSPHRASE set from now on, and export a fresh backup."
    )


@recovery.command("remove-passphrase")
def recovery_remove_passphrase() -> None:
    """Return this install to the silent data key (One Link must be stopped).

    The passphrase being removed must be supplied (ONE_LINK_PASSPHRASE or a
    prompt); a wrong one changes nothing. Every protected file and field is
    re-wrapped to the seed-derived data key and the state database moves to
    a stored key, in one crash-replayable transaction. Afterwards start One
    Link WITHOUT ONE_LINK_PASSPHRASE.
    """
    from one_link import recovery_api
    from one_link.key_material import KeyMaterialError
    from one_link.paths import data_dir

    passphrase = _data_key_passphrase(confirm=False)
    try:
        report = recovery_api.remove_data_key_passphrase(
            data_dir=data_dir(), passphrase=passphrase,
        )
    except (ValueError, KeyMaterialError, recovery_api.RecoveryTransactionError) as exc:
        raise click.ClickException(f"remove-passphrase did not complete: {exc}") from exc
    if not report["changed"]:
        click.echo("This install has no passphrase; nothing changed.")
        return
    click.echo(
        "The passphrase was removed: every protected file and field was\n"
        "re-wrapped to the silent data key and verified. Start One Link\n"
        "without ONE_LINK_PASSPHRASE from now on, and export a fresh backup."
    )


@recovery.command("test-shares")
@click.argument("portable_shares", nargs=-1)
def recovery_test_shares(portable_shares: tuple[str, ...]) -> None:
    """Check whether K guardian shares still reconstruct your identity.

    Non-destructive verification: combines the supplied portable
    shares in memory and compares the reconstructed seed against the
    on-disk master.seed in constant time. Writes nothing. The current
    identity on this device is not touched.

    Use as a periodic recovery audit: every few months, ask K
    guardians to send you their `recovery unwrap` output, paste them
    here, and confirm a green check. Catches guardians who lost their
    share BEFORE you actually need to recover.

    PORTABLE_SHARES are the base64 strings produced by
    `one-link recovery unwrap` on each guardian device (the same
    format `recovery restore` accepts).

    Exit codes mirror the UI's three colors:
      0 = green   (shares reconstruct your current identity)
      2 = amber   (valid quorum, no current identity OR different identity)
      1 = red     (shares failed to combine / not enough shares)
    """
    import base64

    from one_link import recovery_api
    from one_link.paths import data_dir

    if len(portable_shares) < 2:
        raise click.ClickException(
            "need at least 2 portable shares (from `recovery unwrap` on each guardian device)"
        )
    decrypted: list[tuple[int, bytes]] = []
    for s in portable_shares:
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            payload = base64.urlsafe_b64decode((s + pad).encode("ascii"))
        except Exception as e:
            raise click.ClickException(f"share {s[:8]}...: not valid base64 ({e})")
        if len(payload) < 2:
            raise click.ClickException(f"share {s[:8]}...: too short")
        idx = payload[0]
        share_bytes = payload[1:]
        decrypted.append((idx, share_bytes))
    res = recovery_api.test_shares_against_current_seed(
        data_dir=data_dir(),
        shares=decrypted,
    )
    if not res["valid_recovery"]:
        click.echo(f"COMBINE FAILED: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    n = res["share_count"]
    if not res["has_current_identity"]:
        click.echo(
            f"Valid quorum ({n} shares), but this device has no master seed to compare against."
        )
        raise click.exceptions.Exit(2)
    if res["matches_current_identity"]:
        click.echo(f"VERIFIED: these {n} shares reconstruct your current identity.")
        return
    click.echo(
        f"Valid quorum ({n} shares), but it reconstructs a DIFFERENT "
        "identity. These shares are from someone else's recovery setup.",
        err=True,
    )
    raise click.exceptions.Exit(2)


@cli.command("native-status")
def native_status():
    """Show whether the native transfer accelerator is active."""
    from one_link.native_cdc import native_cdc_status

    st = native_cdc_status()
    click.echo(f"native_cdc: {'yes' if st.available else 'no'}")
    click.echo(f"engine:     {st.engine}")
    if st.library:
        click.echo(f"library:    {st.library}")
    if st.reason:
        click.echo(f"reason:     {st.reason}")


@cli.command("runtime-import-smoke", hidden=True)
@click.option("--json", "as_json", is_flag=True)
def runtime_import_smoke(as_json):
    """Import and attest every Python/native surface in a frozen release."""
    import importlib
    import importlib.machinery
    import json as _json
    import sys as _sys
    import types as _types

    from one_link import __version__
    from one_link.build_identity import (
        EXPECTED_NATIVE_RUNTIME_SUBMODULES,
        EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256,
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        STABLE_RUNTIME_FORBIDDEN_MODULES,
        STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256,
        normalized_code_sha256,
        stable_forbidden_runtime_module_statuses,
        stable_runtime_module_statuses,
    )

    if not bool(
        getattr(_sys, "frozen", False) and hasattr(_sys, "executable") and hasattr(_sys, "_MEIPASS")
    ):
        raise click.ClickException("runtime-import-smoke is a frozen-release gate")
    expected_root = Path(os.path.abspath(str(getattr(_sys, "_MEIPASS"))))

    def _inside_runtime_root(path: object) -> bool:
        if not isinstance(path, (str, os.PathLike)):
            return False
        try:
            # The ROOT must exist and resolve strictly. The CANDIDATE must
            # not: a frozen package absorbed into the PYZ reports a virtual
            # __file__ (…/_internal/one_link_native/__init__.py) that has no
            # on-disk entry, and strict resolution turned that into OSError →
            # "outside the runtime root" for every native module on every
            # platform in the first release binaries to reach this smoke.
            # Non-strict resolution still normalizes traversal and resolves
            # links through every EXISTING ancestor, so containment keeps its
            # meaning for real files.
            candidate = Path(path).resolve(strict=False)
            root = expected_root.resolve(strict=True)
        except OSError:
            return False
        return candidate == root or root in candidate.parents

    source_manifest_path = expected_root / "one_link" / "_build" / "runtime-source-manifest.json"
    source_manifest_status = "PRESENT"
    source_manifest_sha256: str | None = None
    source_manifest_modules: dict[str, object] = {}
    try:
        source_manifest_bytes = source_manifest_path.read_bytes()
        source_manifest_sha256 = __import__("hashlib").sha256(source_manifest_bytes).hexdigest()
        source_manifest = _json.loads(source_manifest_bytes)
        if not isinstance(source_manifest, dict):
            raise ValueError("manifest root is not an object")
        if source_manifest.get("schema") != "one-link-runtime-source-manifest-v1":
            raise ValueError("manifest schema mismatch")
        if (
            source_manifest.get("runtime_module_manifest_sha256")
            != EXPECTED_STABLE_RUNTIME_MODULES_SHA256
        ):
            raise ValueError("runtime-module manifest digest mismatch")
        candidate_modules = source_manifest.get("modules")
        if not isinstance(candidate_modules, dict) or set(candidate_modules) != set(
            EXPECTED_STABLE_RUNTIME_MODULES
        ):
            raise ValueError("manifest module keys mismatch")
        source_manifest_modules = candidate_modules
    except (OSError, UnicodeError, ValueError, _json.JSONDecodeError) as exc:
        source_manifest_status = f"INVALID_{type(exc).__name__.upper()}"

    preflight = stable_runtime_module_statuses(expected_root)
    imports: dict[str, str] = {}
    errors: dict[str, str] = {}
    code_digests: dict[str, str] = {}
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        status = preflight.get(module, "MISSING")
        if status != "PRESENT":
            imports[module] = status
            continue
        try:
            loaded = importlib.import_module(module)
        except Exception as exc:
            imports[module] = "IMPORT_ERROR"
            errors[module] = type(exc).__name__
            continue
        if getattr(loaded, "__name__", None) != module:
            imports[module] = "IMPORT_NAME_MISMATCH"
            continue
        spec = getattr(loaded, "__spec__", None)
        loader = getattr(spec, "loader", None)
        get_code = getattr(loader, "get_code", None)
        if not callable(get_code):
            imports[module] = "CODE_LOADER_MISSING"
            continue
        try:
            code = get_code(module)
        except Exception as exc:
            imports[module] = "CODE_LOAD_ERROR"
            errors[module] = type(exc).__name__
            continue
        if not isinstance(code, _types.CodeType):
            imports[module] = "CODE_OBJECT_MISSING"
            continue
        code_digest = normalized_code_sha256(code)
        code_digests[module] = code_digest
        manifest_entry = source_manifest_modules.get(module)
        if (
            not isinstance(manifest_entry, dict)
            or manifest_entry.get("normalized_code_sha256") != code_digest
        ):
            imports[module] = "CODE_MISMATCH"
            continue
        imports[module] = "IMPORTED"

    forbidden = stable_forbidden_runtime_module_statuses(expected_root)
    for module in STABLE_RUNTIME_FORBIDDEN_MODULES:
        if module in _sys.modules:
            forbidden[module] = "LOADED"
    invalid_imports = sorted(module for module, status in imports.items() if status != "IMPORTED")
    present_forbidden = sorted(module for module, status in forbidden.items() if status != "ABSENT")

    native_modules: dict[str, str] = {}
    native_errors: dict[str, str] = {}
    native_package_status = "IMPORTED"
    native_package_origin: str | None = None
    native_extension_origin: str | None = None
    native_version: str | None = None
    native_package: object | None = None
    try:
        native_package = importlib.import_module("one_link_native")
        native_package_origin = getattr(native_package, "__file__", None)
        if getattr(native_package, "__name__", None) != "one_link_native":
            native_package_status = "IMPORT_NAME_MISMATCH"
        elif not _inside_runtime_root(native_package_origin):
            native_package_status = "OUTSIDE_RUNTIME_ROOT"
        native_extension = getattr(native_package, "one_link_native", None)
        native_extension_origin = getattr(native_extension, "__file__", None)
        if not _inside_runtime_root(native_extension_origin):
            native_package_status = "EXTENSION_OUTSIDE_RUNTIME_ROOT"
        elif not any(
            str(native_extension_origin).endswith(suffix)
            for suffix in importlib.machinery.EXTENSION_SUFFIXES
        ):
            native_package_status = "EXTENSION_SUFFIX_INVALID"
        native_version = getattr(native_package, "__version__", None)
        if native_version not in {__version__, f"{__version__}.0"}:
            native_package_status = "VERSION_MISMATCH"
        if not isinstance(getattr(native_package, "chunk_version", None), str):
            native_package_status = "REQUIRED_API_MISSING"
    except Exception as exc:
        native_package_status = "IMPORT_ERROR"
        native_errors["one_link_native"] = type(exc).__name__

    for module in EXPECTED_NATIVE_RUNTIME_SUBMODULES:
        if native_package is None or native_package_status != "IMPORTED":
            native_modules[module] = "PACKAGE_INVALID"
            continue
        try:
            loaded = importlib.import_module(module)
        except Exception as exc:
            native_modules[module] = "IMPORT_ERROR"
            native_errors[module] = type(exc).__name__
            continue
        short_name = module.rsplit(".", 1)[1]
        if not isinstance(loaded, _types.ModuleType):
            native_modules[module] = "NOT_MODULE"
        elif getattr(loaded, "__name__", None) not in {module, short_name}:
            native_modules[module] = "IMPORT_NAME_MISMATCH"
        elif getattr(native_package, short_name, None) is not loaded:
            native_modules[module] = "PACKAGE_EXPORT_MISMATCH"
        else:
            native_modules[module] = "IMPORTED"
    invalid_native_modules = sorted(
        module for module, status in native_modules.items() if status != "IMPORTED"
    )

    runtime_failed = bool(
        invalid_imports
        or present_forbidden
        or source_manifest_status != "PRESENT"
        or native_package_status != "IMPORTED"
        or invalid_native_modules
    )
    payload = {
        "runtime_modules": imports,
        "runtime_module_count": len(imports),
        "runtime_module_manifest_sha256": EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        "runtime_code_sha256": code_digests,
        "runtime_import_errors": errors,
        "invalid_runtime_modules": invalid_imports,
        "runtime_source_manifest_path": str(source_manifest_path),
        "runtime_source_manifest_sha256": source_manifest_sha256,
        "runtime_source_manifest_status": source_manifest_status,
        "forbidden_runtime_modules": forbidden,
        "forbidden_runtime_module_count": len(forbidden),
        "forbidden_runtime_module_manifest_sha256": (STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256),
        "present_forbidden_runtime_modules": present_forbidden,
        "native_package_status": native_package_status,
        "native_package_origin": native_package_origin,
        "native_extension_origin": native_extension_origin,
        "native_version": native_version,
        "native_runtime_modules": native_modules,
        "native_runtime_module_count": len(native_modules),
        "native_runtime_module_manifest_sha256": (EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256),
        "native_runtime_import_errors": native_errors,
        "invalid_native_runtime_modules": invalid_native_modules,
        "verification_status": (
            "runtime_imports_ok" if not runtime_failed else "runtime_imports_failed"
        ),
    }
    if as_json:
        click.echo(_json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(
            f"Stable runtime imports: {len(imports) - len(invalid_imports)}/"
            f"{len(imports)}; forbidden modules absent: "
            f"{len(forbidden) - len(present_forbidden)}/{len(forbidden)}; "
            f"native ABI modules: {len(native_modules) - len(invalid_native_modules)}/"
            f"{len(native_modules)}"
        )
    if runtime_failed:
        raise click.exceptions.Exit(1)


@cli.command("runtime-feature-smoke", hidden=True)
@click.option("--json", "as_json", is_flag=True)
def runtime_feature_smoke(as_json):
    """Run side-effect-free dependency operations inside a frozen release."""
    import importlib
    import importlib.util
    import io
    import json as _json
    import sys as _sys

    if not bool(
        getattr(_sys, "frozen", False) and hasattr(_sys, "executable") and hasattr(_sys, "_MEIPASS")
    ):
        raise click.ClickException("runtime-feature-smoke is a frozen-release gate")

    expected_statuses = {
        "aiortc_datachannel": "OK",
        "keyring_backend": "OK",
        "native_cdc_scan": "OK",
        "packaging_updater": "OK",
        "pillow_tray_icon": "OK",
        "psutil_process": "OK",
        "pyav_primitives": "OK",
        "pystray_backend": "OK",
        "qrcode_svg_stdlib": "OK",
        "sigstore_frozen_update_boundary": (
            "NOT_APPLICABLE_FROZEN_UPDATES_DISABLED"
        ),
        "sqlcipher_roundtrip": "OK",
        "watchdog_observer": "OK",
    }
    # Some probes are inapplicable by ENVIRONMENT, not by packaging: the
    # allowed set per feature captures every honest terminal status, and a
    # probe declares inapplicability by raising _FeatureNotApplicable with
    # the exact status string.
    allowed_statuses = {
        name: frozenset({status}) for name, status in expected_statuses.items()
    }
    allowed_statuses["pystray_backend"] |= frozenset(
        {"NOT_APPLICABLE_HEADLESS_NO_DISPLAY"}
    )
    for _media_feature in ("aiortc_datachannel", "pyav_primitives"):
        allowed_statuses[_media_feature] |= frozenset(
            {"NOT_APPLICABLE_NO_UPSTREAM_WIN_ARM64_WHEELS"}
        )
    features = {name: "NOT_RUN" for name in expected_statuses}
    errors: dict[str, str] = {}

    class _FeatureNotApplicable(Exception):
        pass

    def _probe(name: str, operation) -> None:
        try:
            operation()
        except _FeatureNotApplicable as not_applicable:
            features[name] = str(not_applicable)
        except Exception as exc:
            features[name] = "FAILED"
            errors[name] = type(exc).__name__
        else:
            features[name] = "OK"

    def _numpy_status() -> str:
        if "numpy" in _sys.modules or any(name.startswith("numpy.") for name in _sys.modules):
            return "LOADED"
        try:
            return "PRESENT" if importlib.util.find_spec("numpy") is not None else "ABSENT"
        except (ImportError, ModuleNotFoundError, ValueError):
            return "ABSENT"

    initial_numpy_status = _numpy_status()

    def _qrcode_svg() -> None:
        import qrcode
        from qrcode.compat.etree import ET
        from qrcode.image.svg import SvgPathImage

        # lxml is an optional QR accelerator and forbidden in stable bundles;
        # exercise the supported stdlib fallback, not merely the import edge.
        if getattr(ET, "__name__", "") != "xml.etree.ElementTree":
            raise RuntimeError("qrcode did not select the stdlib XML backend")
        image = qrcode.make("one-link-runtime-feature-smoke", image_factory=SvgPathImage)
        output = io.BytesIO()
        image.save(output)
        rendered = output.getvalue()
        if b"<svg" not in rendered or len(rendered) < 100:
            raise RuntimeError("qrcode SVG renderer returned an invalid document")

    def _pillow_tray_icon() -> None:
        from PIL import Image
        from one_link.tray import TrayIcon, _icon_image

        image = _icon_image()
        tinted = TrayIcon._tinted_icon("online")
        if not isinstance(image, Image.Image) or image.size != (64, 64) or image.mode != "RGBA":
            raise RuntimeError("tray base icon has an invalid Pillow representation")
        if not isinstance(tinted, Image.Image) or tinted.size != (64, 64):
            raise RuntimeError("tray status icon has an invalid Pillow representation")

    def _pystray_backend() -> None:
        # On Linux, pystray's X11 backend resolves the DISPLAY at IMPORT
        # time; on a headless host (CI runners, servers) that raises
        # DisplayNameError before any packaging question can even be asked.
        # Headless is an environment condition, not a bundle defect -- the
        # module bytes are covered by the inventory and import gates -- so
        # the probe reports NOT_APPLICABLE there, mirroring the existing
        # sigstore-boundary pattern. A desktop session still exercises the
        # real backend end to end.
        if _sys.platform not in ("win32", "darwin") and not (
            os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        ):
            raise _FeatureNotApplicable("NOT_APPLICABLE_HEADLESS_NO_DISPLAY")
        backend_name = (
            "pystray._win32"
            if _sys.platform == "win32"
            else "pystray._darwin"
            if _sys.platform == "darwin"
            else "pystray._xorg"
        )
        backend = importlib.import_module(backend_name)
        module = importlib.import_module("pystray")
        if not isinstance(getattr(backend, "Icon", None), type):
            raise RuntimeError(f"platform pystray backend has no Icon class: {backend_name}")
        if not callable(getattr(module, "Menu", None)):
            raise RuntimeError("pystray platform backend has no Menu primitive")

    def _keyring_backend() -> None:
        import keyring.backend

        if not isinstance(keyring.backend.KeyringBackend, type):
            raise RuntimeError("keyring backend contract is unavailable")
        if _sys.platform == "win32":
            windows = importlib.import_module("keyring.backends.Windows")
            win32cred = importlib.import_module("win32ctypes.pywin32.win32cred")
            importlib.import_module("win32ctypes.pywin32.pywintypes")
            if not isinstance(getattr(windows, "WinVaultKeyring", None), type):
                raise RuntimeError("Windows Credential Manager backend is unavailable")
            if not callable(getattr(win32cred, "CredRead", None)):
                raise RuntimeError("Windows credential bindings are unavailable")
        elif _sys.platform == "darwin":
            macos = importlib.import_module("keyring.backends.macOS")
            if not isinstance(getattr(macos, "Keyring", None), type):
                raise RuntimeError("macOS Keychain backend is unavailable")
        else:
            fallback = importlib.import_module("keyring.backends.fail")
            if not isinstance(getattr(fallback, "Keyring", None), type):
                raise RuntimeError("keyring fallback backend is unavailable")

    def _sqlcipher_roundtrip() -> None:
        import tempfile

        module = importlib.import_module("sqlcipher3")
        if not callable(getattr(module, "connect", None)):
            raise RuntimeError("SQLCipher connect primitive is unavailable")

        with tempfile.TemporaryDirectory(prefix="one-link-sqlcipher-smoke-") as raw:
            database = Path(raw) / "probe.db"
            connection = module.connect(str(database))
            try:
                connection.execute("PRAGMA key = 'one-link-frozen-smoke-key'")
                cipher_row = connection.execute("PRAGMA cipher_version").fetchone()
                if not cipher_row or not str(cipher_row[0]).strip():
                    raise RuntimeError("SQLCipher engine did not report cipher_version")
                connection.execute(
                    "CREATE TABLE smoke (id INTEGER PRIMARY KEY, value BLOB NOT NULL)"
                )
                expected = b"one-link-sqlcipher-roundtrip"
                connection.execute("INSERT INTO smoke(value) VALUES (?)", (expected,))
                connection.commit()
                row = connection.execute("SELECT value FROM smoke WHERE id = 1").fetchone()
                if row is None or bytes(row[0]) != expected:
                    raise RuntimeError("SQLCipher encrypted database round-trip failed")
            finally:
                connection.close()
            if not database.is_file() or database.stat().st_size <= 0:
                raise RuntimeError("SQLCipher did not materialize the temporary database")

    def _watchdog_observer() -> None:
        import tempfile
        import threading

        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        observed = threading.Event()

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory and Path(event.src_path).name == "created.bin":
                    observed.set()

        with tempfile.TemporaryDirectory(prefix="one-link-watchdog-smoke-") as raw:
            observer = Observer()
            observer.schedule(Handler(), raw, recursive=False)
            observer.start()
            try:
                (Path(raw) / "created.bin").write_bytes(b"one-link-watchdog")
                if not observed.wait(8.0):
                    raise RuntimeError("watchdog observer did not deliver a file event")
            finally:
                observer.stop()
                observer.join(timeout=8.0)
            if observer.is_alive():
                raise RuntimeError("watchdog observer did not shut down")

    def _psutil_process() -> None:
        import psutil

        process = psutil.Process(os.getpid())
        if process.pid != os.getpid():
            raise RuntimeError("psutil resolved the wrong current process")

    def _win_arm64_media_stack_absent() -> bool:
        # pyproject EXCLUDES aiortc (and its PyAV dependency) on Windows
        # ARM64 by environment marker: upstream ships no cp3*-win_arm64
        # wheels. Demanding those features there made the release gate
        # contradict the project's own deliberate dependency contract.
        import platform as _platform

        return _sys.platform == "win32" and _platform.machine().upper() in {
            "ARM64",
            "AARCH64",
        }

    def _aiortc_datachannel() -> None:
        import asyncio

        if _win_arm64_media_stack_absent():
            raise _FeatureNotApplicable("NOT_APPLICABLE_NO_UPSTREAM_WIN_ARM64_WHEELS")

        from aiortc import RTCConfiguration, RTCPeerConnection

        async def _roundtrip() -> None:
            # Empty ICE-server lists categorically prevent STUN/TURN traffic;
            # two peers in this process exercise DTLS/SCTP over host candidates.
            configuration = RTCConfiguration(iceServers=[])
            sender = RTCPeerConnection(configuration)
            receiver = RTCPeerConnection(configuration)
            received = asyncio.Event()
            expected = "one-link-aiortc-local-roundtrip"

            @receiver.on("datachannel")
            def on_datachannel(channel):
                @channel.on("message")
                def on_message(message):
                    if message == expected:
                        received.set()

            channel = sender.createDataChannel("one-link-runtime-feature-smoke")
            opened = asyncio.Event()

            @channel.on("open")
            def on_open():
                opened.set()
                channel.send(expected)

            try:
                await sender.setLocalDescription(await sender.createOffer())
                await receiver.setRemoteDescription(sender.localDescription)
                await receiver.setLocalDescription(await receiver.createAnswer())
                await sender.setRemoteDescription(receiver.localDescription)
                await asyncio.wait_for(opened.wait(), timeout=15.0)
                await asyncio.wait_for(received.wait(), timeout=15.0)
            finally:
                await sender.close()
                await receiver.close()

        asyncio.run(_roundtrip())

    def _native_cdc_scan() -> None:
        from one_link.native_cdc import get_native_cdc_scanner, validate_native_cdc_library

        scanner = get_native_cdc_scanner()
        if scanner is None:
            raise RuntimeError("mandatory frozen native CDC scanner is unavailable")
        validate_native_cdc_library(scanner.library)

    def _pyav_primitives() -> None:
        if _win_arm64_media_stack_absent():
            raise _FeatureNotApplicable("NOT_APPLICABLE_NO_UPSTREAM_WIN_ARM64_WHEELS")

        import av

        packet = av.Packet(b"one-link")
        frame = av.VideoFrame(2, 2, "rgb24")
        if bytes(packet) != b"one-link" or packet.size != 8:
            raise RuntimeError("PyAV packet primitive did not round-trip")
        if frame.width != 2 or frame.height != 2 or frame.format.name != "rgb24":
            raise RuntimeError("PyAV frame primitive is unavailable")

    def _packaging_updater() -> None:
        from packaging.tags import sys_tags
        from packaging.utils import parse_wheel_filename
        from packaging.version import Version
        from one_link import updater

        distribution, version, _build, tags = parse_wheel_filename(
            "one_link_native-0.21.0a0-cp311-abi3-win_amd64.whl"
        )
        if str(distribution) != "one-link-native" or version != Version("0.21.0a0") or not tags:
            raise RuntimeError("packaging wheel parser returned an invalid result")
        if next(iter(sys_tags()), None) is None:
            raise RuntimeError("packaging exposed no compatible platform tags")
        try:
            updater.write_updater_script(Path(os.devnull), parent_pid=os.getpid())
        except RuntimeError as exc:
            if "disabled" not in str(exc):
                raise
        else:
            raise RuntimeError("frozen in-place updater unexpectedly became executable")

    _probe("qrcode_svg_stdlib", _qrcode_svg)
    _probe("pillow_tray_icon", _pillow_tray_icon)
    _probe("pystray_backend", _pystray_backend)
    _probe("keyring_backend", _keyring_backend)
    _probe("sqlcipher_roundtrip", _sqlcipher_roundtrip)
    _probe("watchdog_observer", _watchdog_observer)
    _probe("psutil_process", _psutil_process)
    _probe("aiortc_datachannel", _aiortc_datachannel)
    _probe("native_cdc_scan", _native_cdc_scan)
    _probe("pyav_primitives", _pyav_primitives)
    _probe("packaging_updater", _packaging_updater)
    # Stable frozen applications deliberately refuse in-place installation;
    # Sigstore verification remains active for source installs and release CI,
    # while its CLI/dependency graph must not expand the frozen attack surface.
    try:
        sigstore_present = (
            "sigstore" in _sys.modules
            or importlib.util.find_spec("sigstore") is not None
        )
    except (ImportError, ModuleNotFoundError, ValueError):
        sigstore_present = False
    if sigstore_present:
        features["sigstore_frozen_update_boundary"] = "UNEXPECTEDLY_PRESENT"
        errors["sigstore_frozen_update_boundary"] = "ForbiddenModulePresent"
    else:
        features["sigstore_frozen_update_boundary"] = (
            "NOT_APPLICABLE_FROZEN_UPDATES_DISABLED"
        )

    final_numpy_status = _numpy_status()
    numpy_status = (
        "ABSENT"
        if initial_numpy_status == "ABSENT" and final_numpy_status == "ABSENT"
        else final_numpy_status
    )
    failed = (
        set(features) != set(allowed_statuses)
        or any(
            features[name] not in allowed_statuses[name] for name in allowed_statuses
        )
        or bool(errors)
        or numpy_status != "ABSENT"
    )
    payload = {
        "features": features,
        "feature_count": len(features),
        "feature_errors": errors,
        "numpy_status": numpy_status,
        "side_effect_policy": (
            "no_external_network_no_ui_no_keychain_access_isolated_temporary_io_only"
        ),
        "verification_status": (
            "runtime_features_failed" if failed else "runtime_features_ok"
        ),
    }
    if as_json:
        click.echo(_json.dumps(payload, indent=2, sort_keys=True))
    else:
        passed = sum(
            status in allowed_statuses[name]
            for name, status in features.items()
        )
        click.echo(
            f"Runtime dependency features: {passed}/{len(features)}; "
            f"NumPy: {numpy_status}"
        )
    if failed:
        raise click.exceptions.Exit(1)


@cli.command("verify-this-install")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of human text.",
)
@click.option(
    "--expected-rollup",
    metavar="SHA256",
    help=(
        "Compare with an exact 64-hex SHA-256 rollup obtained from an "
        "independently authenticated release record."
    ),
)
@click.option(
    "--inventory-only",
    is_flag=True,
    help=(
        "Print a local inventory without a baseline and exit 0. This does not "
        "verify authenticity or release provenance."
    ),
)
def verify_this_install(as_json, expected_rollup, inventory_only):
    """Inventory this install and optionally compare an authenticated baseline.

    Local hashes alone cannot prove authenticity, so the default fails closed.
    Supply --expected-rollup only after authenticating that value independently,
    or use --inventory-only for an explicitly non-verifying diagnostic. Every
    stable file in the managed Python package and separately installed native
    extension package is included. A frozen executable is bound into the same
    rollup when present.

    The launcher source fingerprint exposed by the Web UI is a compatibility
    signal, not this complete content inventory and not a signed-release proof.

    For Sigstore verification of a released artifact, replace the placeholder
    with the exact tag and keep the workflow identity exact:

        python -m sigstore verify identity \\
          --cert-identity 'https://github.com/coherence-energy-labs/one-link/.github/workflows/release.yml@refs/tags/v<exact-version>' \\
          --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \\
          --bundle one-link.exe.sigstore \\
          one-link.exe

    Never substitute a wildcard certificate identity.
    """
    import hashlib
    import json as _json
    import stat as _stat
    import struct
    import sys as _sys

    from one_link import __version__
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        STABLE_RUNTIME_FORBIDDEN_MODULES,
        STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256,
        _FINGERPRINT_FILES,
        installation_inventory_files,
        native_package_root,
        package_root,
        stable_forbidden_runtime_module_statuses,
        stable_runtime_module_statuses,
    )

    if expected_rollup is not None:
        expected_rollup = expected_rollup.strip().lower()
        if len(expected_rollup) != 64 or any(
            character not in "0123456789abcdef" for character in expected_rollup
        ):
            raise click.BadParameter(
                "must be exactly 64 hexadecimal characters",
                param_hint="--expected-rollup",
            )
    if expected_rollup is not None and inventory_only:
        raise click.UsageError("--expected-rollup and --inventory-only are mutually exclusive")

    is_frozen = bool(getattr(_sys, "frozen", False) and hasattr(_sys, "executable"))
    frozen_executable: Path | None = None
    frozen_executable_label: str | None = None
    macos_bundle = False
    internal_root: Path | None = None
    data_root: Path | None = None
    if is_frozen:
        # PyInstaller stores Python bytecode in the executable's PYZ archive,
        # so nonexistent source-module paths are not meaningful verification
        # targets.  An onedir release is one managed artifact: hash every
        # physical file beneath the launcher's directory exactly once.
        frozen_executable = Path(os.path.abspath(_sys.executable))
        macos_bundle = (
            frozen_executable.parent.name == "MacOS"
            and frozen_executable.parent.parent.name == "Contents"
            and frozen_executable.parent.parent.parent.suffix.lower() == ".app"
        )
        if macos_bundle:
            inventory_root = frozen_executable.parent.parent.parent
            internal_root = inventory_root / "Contents" / "Frameworks"
            data_root = inventory_root / "Contents" / "Resources"
            inventory_mode = "frozen_macos_app_bundle"
        else:
            inventory_root = frozen_executable.parent
            internal_root = inventory_root / "_internal"
            data_root = internal_root
            inventory_mode = "frozen_onedir_bundle"
        root = internal_root / "one_link"
        native_root: Path | None = internal_root / "one_link_native"
        frozen_executable_label = (
            "bundle/" + frozen_executable.relative_to(inventory_root).as_posix()
        )
    else:
        root = package_root().resolve()
        native_root = native_package_root()
        inventory_root = root
        inventory_mode = "source_or_installed_packages"
    file_hashes: dict[str, str] = {}
    missing: list[str] = []
    unsafe_entries: list[str] = []
    rollup = hashlib.sha256()
    rollup.update(b"ONE-LINK-INSTALL-ROLLUP-SHA256-V1\x00")

    def _rollup_entry(relative: str, status: bytes, digest: bytes = b"") -> None:
        name = relative.encode("utf-8", "surrogatepass")
        rollup.update(struct.pack(">Q", len(name)))
        rollup.update(name)
        rollup.update(struct.pack(">B", len(status)))
        rollup.update(status)
        rollup.update(struct.pack(">Q", len(digest)))
        rollup.update(digest)

    inventory_paths: list[tuple[str, Path]] = []
    frozen_inventory_before: tuple[str, ...] | None = None
    layout_statuses: dict[str, str] = {}

    def _bundle_label(path: Path) -> str:
        return "bundle/" + path.relative_to(inventory_root).as_posix()

    def _safe_bundle_link_digest(path: Path) -> bytes:
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise RuntimeError("bundle link target is unreadable") from exc
        target_path = Path(target)
        if target_path.is_absolute():
            raise RuntimeError("bundle link target is absolute")
        try:
            resolved_root = inventory_root.resolve(strict=True)
            resolved_target = (path.parent / target_path).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError("bundle link target is broken or cyclic") from exc
        if resolved_target != resolved_root and resolved_root not in resolved_target.parents:
            raise RuntimeError("bundle link target escapes inventory root")
        encoded = target.encode("utf-8", "surrogatepass")
        digest = hashlib.sha256(b"ONE-LINK-BUNDLE-SYMLINK-V1\x00")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        return digest.digest()

    def _frozen_inventory_files() -> tuple[str, ...]:
        entries: list[str] = []

        def _walk_error(error: OSError) -> None:
            raise error

        for directory, directory_names, file_names in os.walk(
            inventory_root,
            followlinks=False,
            onerror=_walk_error,
        ):
            directory_names.sort()
            file_names.sort()
            parent = Path(directory)
            for name in list(directory_names):
                child = parent / name
                metadata = child.lstat()
                attributes = int(getattr(metadata, "st_file_attributes", 0))
                reparse_flag = int(getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                if _stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
                    if not macos_bundle:
                        raise OSError(f"unsafe link in frozen inventory: {child}")
                    try:
                        _safe_bundle_link_digest(child)
                    except RuntimeError as exc:
                        raise OSError(f"unsafe link in frozen inventory: {child}") from exc
                    entries.append(child.relative_to(inventory_root).as_posix())
                    directory_names.remove(name)
                elif not _stat.S_ISDIR(metadata.st_mode):
                    raise OSError(f"non-directory in frozen inventory: {child}")
            entries.extend(
                (parent / name).relative_to(inventory_root).as_posix() for name in file_names
            )
        return tuple(sorted(entries))

    def _layout_status(path: Path, expected_kind: str) -> str | None:
        try:
            metadata = path.lstat()
        except OSError:
            return "MISSING"
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if _stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
            if not macos_bundle:
                return "UNSAFE_LINK"
            try:
                _safe_bundle_link_digest(path)
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError):
                return "UNSAFE_LINK"
            if expected_kind == "directory" and not resolved.is_dir():
                return "UNSAFE_NON_DIRECTORY"
            if expected_kind == "file" and not resolved.is_file():
                return "UNSAFE_NON_REGULAR"
            return None
        if expected_kind == "directory" and not _stat.S_ISDIR(metadata.st_mode):
            return "UNSAFE_NON_DIRECTORY"
        if expected_kind == "file" and not _stat.S_ISREG(metadata.st_mode):
            return "UNSAFE_NON_REGULAR"
        return None

    try:
        if is_frozen:
            assert frozen_executable is not None
            assert frozen_executable_label is not None
            from one_link.native_cdc import native_library_name, native_platform_tag

            assert internal_root is not None
            assert data_root is not None
            runtime_package_root = internal_root / "one_link"
            package_root_in_bundle = data_root / "one_link"
            native_root_in_bundle = internal_root / "one_link_native"
            cdc_root = runtime_package_root / "native" / native_platform_tag()
            cdc_library = cdc_root / native_library_name()
            cdc_library_label = _bundle_label(cdc_library)
            cdc_sidecar = (
                package_root_in_bundle
                / "native"
                / native_platform_tag()
                / f"{cdc_library.name}.sha256"
            )
            cdc_sidecar_label = _bundle_label(cdc_sidecar)
            runtime_root_label = _bundle_label(internal_root)
            data_root_label = _bundle_label(data_root)
            package_root_label = _bundle_label(package_root_in_bundle)
            native_root_label = _bundle_label(native_root_in_bundle)
            # The material native contract in a FROZEN bundle is the compiled
            # extension: PyInstaller absorbs the pure __init__.py shim into
            # the PYZ, and the bundle-content gate rightly forbids loose .py
            # files -- so the historical "__init__.py exists as a file"
            # expectation was unsatisfiable by construction and failed the
            # first release binaries ever gated, on every platform at once.
            # The extension's exact name is platform-suffixed; find it, and
            # fall back to a deterministic MISSING label when absent.
            native_extension_in_bundle = None
            if native_root_in_bundle.is_dir():
                for _candidate in sorted(native_root_in_bundle.iterdir()):
                    if (
                        _candidate.is_file()
                        and _candidate.name.startswith("one_link_native")
                        and _candidate.suffix in (".pyd", ".so", ".dylib")
                    ):
                        native_extension_in_bundle = _candidate
                        break
            if native_extension_in_bundle is None:
                native_extension_in_bundle = (
                    native_root_in_bundle / "one_link_native.pyd"
                )
            expectations: list[tuple[str, Path, str, str | None]] = [
                ("bundle/<root>", inventory_root, "directory", None),
                (
                    frozen_executable_label,
                    frozen_executable,
                    "file",
                    "bundle/<root>",
                ),
                (
                    runtime_root_label,
                    internal_root,
                    "directory",
                    "bundle/<root>",
                ),
                (
                    _bundle_label(internal_root / "base_library.zip"),
                    internal_root / "base_library.zip",
                    "file",
                    runtime_root_label,
                ),
                (
                    package_root_label,
                    package_root_in_bundle,
                    "directory",
                    data_root_label,
                ),
                (
                    _bundle_label(package_root_in_bundle / "web" / "index.html"),
                    package_root_in_bundle / "web" / "index.html",
                    "file",
                    package_root_label,
                ),
                (
                    _bundle_label(package_root_in_bundle / "data" / "bip39-english.txt"),
                    package_root_in_bundle / "data" / "bip39-english.txt",
                    "file",
                    package_root_label,
                ),
                (
                    _bundle_label(package_root_in_bundle / "data" / "oui_prefixes.txt.gz"),
                    package_root_in_bundle / "data" / "oui_prefixes.txt.gz",
                    "file",
                    package_root_label,
                ),
                (
                    _bundle_label(
                        package_root_in_bundle / "_build" / "runtime-source-manifest.json"
                    ),
                    package_root_in_bundle / "_build" / "runtime-source-manifest.json",
                    "file",
                    package_root_label,
                ),
                (
                    cdc_library_label,
                    cdc_library,
                    "file",
                    runtime_root_label,
                ),
                (
                    cdc_sidecar_label,
                    cdc_sidecar,
                    "file",
                    package_root_label,
                ),
                (
                    native_root_label,
                    native_root_in_bundle,
                    "directory",
                    runtime_root_label,
                ),
                (
                    _bundle_label(native_extension_in_bundle),
                    native_extension_in_bundle,
                    "file",
                    native_root_label,
                ),
            ]
            if data_root != internal_root:
                expectations.insert(
                    3,
                    (
                        data_root_label,
                        data_root,
                        "directory",
                        "bundle/<root>",
                    ),
                )
                expectations.insert(
                    1,
                    (
                        "bundle/Contents/Info.plist",
                        inventory_root / "Contents" / "Info.plist",
                        "file",
                        "bundle/<root>",
                    ),
                )
            for label, path, expected_kind, parent_label in expectations:
                if parent_label is not None and parent_label in layout_statuses:
                    parent_status = layout_statuses[parent_label]
                    layout_statuses[label] = (
                        "MISSING" if parent_status == "MISSING" else "UNSAFE_LAYOUT_PARENT"
                    )
                    continue
                status = _layout_status(path, expected_kind)
                if status is not None:
                    layout_statuses[label] = status

            if (
                cdc_library_label not in layout_statuses
                and cdc_sidecar_label not in layout_statuses
            ):
                try:
                    cdc_digest = hashlib.sha256(cdc_library.read_bytes()).hexdigest()
                    cdc_sidecar_text = cdc_sidecar.read_text(encoding="ascii")
                except (OSError, UnicodeError):
                    layout_statuses["bundle/<native-cdc-integrity>"] = "UNSTABLE_OR_UNREADABLE"
                else:
                    if cdc_sidecar_text != f"{cdc_digest}  {cdc_library.name}\n":
                        layout_statuses["bundle/<native-cdc-integrity>"] = "HASH_MISMATCH"

            runtime_root = getattr(_sys, "_MEIPASS", None)
            runtime_label = "bundle/<pyinstaller-runtime-root>"
            if runtime_root is None:
                layout_statuses[runtime_label] = "MISSING"
            elif os.path.normcase(os.path.abspath(str(runtime_root))) != os.path.normcase(
                os.path.abspath(str(internal_root))
            ):
                layout_statuses[runtime_label] = "UNSAFE_LAYOUT_ROOT"

            native_extension_present = False
            if native_root_label not in layout_statuses:
                for candidate in native_root_in_bundle.iterdir():
                    if candidate.suffix.lower() not in {".pyd", ".so", ".dylib"}:
                        continue
                    if _layout_status(candidate, "file") is None:
                        native_extension_present = True
                        break
            if not native_extension_present:
                layout_statuses[f"{native_root_label}/<native-extension>"] = "MISSING"

            if "bundle/<root>" not in layout_statuses:
                frozen_inventory_before = _frozen_inventory_files()
                inventory_paths.extend(
                    (f"bundle/{relative}", inventory_root / relative)
                    for relative in frozen_inventory_before
                )
        else:
            primary_inventory = sorted(
                set(installation_inventory_files(root)) | set(_FINGERPRINT_FILES)
            )
            inventory_paths.extend((relative, root / relative) for relative in primary_inventory)
            if native_root is None:
                native_marker = "one_link_native/<package>"
                file_hashes[native_marker] = "MISSING"
                missing.append(native_marker)
                _rollup_entry(native_marker, b"MISSING")
            else:
                inventory_paths.extend(
                    (f"one_link_native/{relative}", native_root / relative)
                    for relative in installation_inventory_files(native_root)
                )
    except OSError as exc:
        raise click.ClickException(
            f"could not enumerate the complete installed package tree: {type(exc).__name__}"
        ) from exc

    for rel, status in sorted(layout_statuses.items()):
        file_hashes[rel] = status
        if status == "MISSING":
            missing.append(rel)
        else:
            unsafe_entries.append(rel)
        _rollup_entry(rel, status.encode("ascii"))

    for rel, path in sorted(inventory_paths):
        if rel in layout_statuses:
            continue
        try:
            before = path.lstat()
        except OSError:
            file_hashes[rel] = "MISSING"
            missing.append(rel)
            _rollup_entry(rel, b"MISSING")
            continue

        attributes = int(getattr(before, "st_file_attributes", 0))
        reparse_flag = int(getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if _stat.S_ISLNK(before.st_mode) or attributes & reparse_flag:
            if macos_bundle:
                try:
                    digest_bytes = _safe_bundle_link_digest(path)
                except RuntimeError:
                    file_hashes[rel] = "UNSAFE_LINK"
                    unsafe_entries.append(rel)
                    _rollup_entry(rel, b"UNSAFE_LINK")
                    continue
                file_hashes[rel] = digest_bytes.hex()
                _rollup_entry(rel, b"SYMLINK", digest_bytes)
                continue
            file_hashes[rel] = "UNSAFE_LINK"
            unsafe_entries.append(rel)
            _rollup_entry(rel, b"UNSAFE_LINK")
            continue
        if not _stat.S_ISREG(before.st_mode):
            file_hashes[rel] = "UNSAFE_NON_REGULAR"
            unsafe_entries.append(rel)
            _rollup_entry(rel, b"UNSAFE_NON_REGULAR")
            continue

        h = hashlib.sha256()
        try:
            with path.open("rb") as file_handle:
                opened = os.fstat(file_handle.fileno())
                identity_before = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                )
                identity_opened = (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                )
                if identity_before != identity_opened:
                    raise RuntimeError("entry changed before hashing")
                for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                    h.update(chunk)
                after_open = os.fstat(file_handle.fileno())
            after_path = path.lstat()
            identity_after_open = (
                after_open.st_dev,
                after_open.st_ino,
                after_open.st_size,
                after_open.st_mtime_ns,
            )
            identity_after_path = (
                after_path.st_dev,
                after_path.st_ino,
                after_path.st_size,
                after_path.st_mtime_ns,
            )
            if identity_opened != identity_after_open or identity_opened != identity_after_path:
                raise RuntimeError("entry changed while hashing")
        except (OSError, RuntimeError):
            file_hashes[rel] = "UNSTABLE_OR_UNREADABLE"
            unsafe_entries.append(rel)
            _rollup_entry(rel, b"UNSTABLE_OR_UNREADABLE")
            continue
        digest_bytes = h.digest()
        file_hashes[rel] = digest_bytes.hex()
        _rollup_entry(rel, b"FILE", digest_bytes)

    # A complete file walk is necessary but insufficient for a PyInstaller
    # onedir: Python modules live inside the PYZ archive and are not individual
    # files below ``_internal``.  Resolve the explicit stable-module contract
    # through the active importer and require every origin to remain inside
    # this install.  This catches omitted lazy modules and external shadowing.
    runtime_expected_root = internal_root if is_frozen else root
    assert runtime_expected_root is not None
    runtime_modules = stable_runtime_module_statuses(runtime_expected_root)
    missing_runtime_modules: list[str] = []
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        status = runtime_modules.get(module, "MISSING")
        label = f"runtime-module/{module}"
        _rollup_entry(label, f"MODULE_{status}".encode("ascii"))
        if status == "PRESENT":
            continue
        missing_runtime_modules.append(module)
        if status == "MISSING":
            missing.append(label)
        else:
            unsafe_entries.append(label)

    runtime_module_count = len(EXPECTED_STABLE_RUNTIME_MODULES)
    _rollup_entry(
        "runtime-module-manifest/<count>",
        b"COUNT",
        runtime_module_count.to_bytes(8, "big"),
    )
    _rollup_entry(
        "runtime-module-manifest/<sha256>",
        b"MANIFEST",
        bytes.fromhex(EXPECTED_STABLE_RUNTIME_MODULES_SHA256),
    )

    forbidden_runtime_modules: dict[str, str] = {}
    present_forbidden_runtime_modules: list[str] = []
    if is_frozen:
        forbidden_runtime_modules = stable_forbidden_runtime_module_statuses(runtime_expected_root)
        for module in STABLE_RUNTIME_FORBIDDEN_MODULES:
            status = forbidden_runtime_modules.get(module, "SPEC_ERROR")
            label = f"forbidden-runtime-module/{module}"
            _rollup_entry(label, f"MODULE_{status}".encode("ascii"))
            if status == "ABSENT":
                continue
            present_forbidden_runtime_modules.append(module)
            unsafe_entries.append(label)
    forbidden_runtime_module_count = len(forbidden_runtime_modules)
    _rollup_entry(
        "forbidden-runtime-module-manifest/<sha256>",
        b"MANIFEST",
        bytes.fromhex(STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256),
    )

    frozen_binary: Optional[str] = None
    if is_frozen:
        assert frozen_executable_label is not None
        candidate_digest = file_hashes.get(frozen_executable_label)
        if candidate_digest is not None and len(candidate_digest) == 64:
            frozen_binary = candidate_digest
        if frozen_inventory_before is not None:
            try:
                frozen_inventory_after = _frozen_inventory_files()
            except OSError:
                frozen_inventory_after = ()
            if frozen_inventory_after != frozen_inventory_before:
                stability_marker = "bundle/<inventory-stability>"
                file_hashes[stability_marker] = "UNSTABLE_OR_UNREADABLE"
                unsafe_entries.append(stability_marker)
                _rollup_entry(stability_marker, b"UNSTABLE_OR_UNREADABLE")

    rollup_hex = rollup.hexdigest()
    baseline_match = None if expected_rollup is None else rollup_hex == expected_rollup
    if missing or unsafe_entries:
        verification_status = "incomplete_install"
        exit_code = 1
    elif baseline_match is False:
        verification_status = "baseline_mismatch"
        exit_code = 1
    elif baseline_match is True:
        verification_status = "matches_supplied_baseline"
        exit_code = 0
    elif inventory_only:
        verification_status = "inventory_only"
        exit_code = 0
    else:
        verification_status = "baseline_required"
        exit_code = 2

    out = {
        "version": __version__,
        "inventory_mode": inventory_mode,
        "inventory_root": str(inventory_root),
        "package_root": str(root),
        "native_package_root": None if native_root is None else str(native_root),
        "files": file_hashes,
        "file_count": len(file_hashes),
        "missing": missing,
        "rollup_sha256": rollup_hex,
        "frozen_binary_sha256": frozen_binary,
        "expected_rollup_sha256": expected_rollup,
        "baseline_match": baseline_match,
        "verification_status": verification_status,
        "unsafe_entries": unsafe_entries,
        "runtime_modules": runtime_modules,
        "runtime_module_count": runtime_module_count,
        "runtime_module_manifest_sha256": EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        "missing_runtime_modules": missing_runtime_modules,
        "forbidden_runtime_modules": forbidden_runtime_modules,
        "forbidden_runtime_module_count": forbidden_runtime_module_count,
        "forbidden_runtime_module_manifest_sha256": (STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256),
        "present_forbidden_runtime_modules": present_forbidden_runtime_modules,
        # Matching a caller-supplied value does not authenticate its source.
        "authenticity_verified": False,
    }

    if as_json:
        click.echo(_json.dumps(out, indent=2, sort_keys=True))
        if exit_code:
            raise click.exceptions.Exit(exit_code)
        return

    click.echo(f"One Link version:   {__version__}")
    click.echo(f"Inventory mode:     {inventory_mode}")
    click.echo(f"Inventory root:     {inventory_root}")
    click.echo(f"Package payload:    {root}")
    click.echo("")
    click.echo("Managed install files (SHA-256 content hash):")
    name_w = max(len(n) for n in file_hashes)
    for name, hx in sorted(file_hashes.items()):
        click.echo(f"  {name:<{name_w}}  {hx}")
    if missing:
        click.echo("")
        click.echo(
            "WARNING: some load-bearing files are missing on disk.",
            err=True,
        )
        for m in missing:
            click.echo(f"  - {m}", err=True)
        click.echo(
            "This usually means the install is incomplete or "
            "tampered. Re-install from a verified source.",
            err=True,
        )
    click.echo("")
    click.echo(f"Rollup (local inventory): {rollup_hex}")
    if verification_status == "baseline_required":
        click.echo(
            "NOT VERIFIED: no independently authenticated expected rollup was supplied.",
            err=True,
        )
    if unsafe_entries:
        click.echo("")
        click.echo(
            "WARNING: links, special files, or unstable entries are not "
            "accepted in a verified install.",
            err=True,
        )
        for entry in unsafe_entries:
            if entry.startswith("runtime-module/"):
                detail = runtime_modules.get(entry.removeprefix("runtime-module/"))
            else:
                detail = file_hashes.get(entry)
            click.echo(f"  - {entry}: {detail or 'INVALID'}", err=True)
        click.echo(
            "Use --expected-rollup <64-hex> after authenticating that value, or "
            "--inventory-only for a non-verifying diagnostic.",
            err=True,
        )
    elif verification_status == "baseline_mismatch":
        click.echo("FAILED: installed files do not match the supplied rollup.", err=True)
    elif verification_status == "matches_supplied_baseline":
        click.echo(
            "MATCH: installed files match the supplied rollup. This command did "
            "not authenticate the source of that rollup."
        )
    else:
        click.echo("INVENTORY ONLY: authenticity and release provenance were not verified.")
    if frozen_binary:
        click.echo(f"Frozen binary SHA-256:               {frozen_binary}")
        click.echo("")
        click.echo("To verify this binary against the published Sigstore bundle:")
        click.echo("  python -m sigstore verify identity \\")
        click.echo(
            "    --cert-identity "
            f"'https://github.com/coherence-energy-labs/one-link/"
            f".github/workflows/release.yml@refs/tags/v{__version__}' \\"
        )
        click.echo("    --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \\")
        click.echo(f"    --bundle {Path(_sys.executable).name}.sigstore \\")
        click.echo(f"    {Path(_sys.executable).name}")
    else:
        click.echo("(running from source; no frozen-binary hash to report)")
    if exit_code:
        raise click.exceptions.Exit(exit_code)


@cli.command()
def peers():
    """List discovered peers on the LAN."""
    res = _request("peers")
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "unknown error"))
    me = res["me"]
    click.echo(f"me: {me['short_id']}  {me['hostname']}")
    plist = res["peers"]
    if not plist:
        # "give it a few seconds" was printed for every cause, and most of them
        # never resolve by waiting: an orphaned firewall rule, a guest network,
        # or the other machine simply being off. Point at the command that can
        # tell them apart rather than asking the user to wait out a fault.
        click.echo("(no peers discovered yet)")
        click.echo("Run  one-link doctor  to find out why — it names the cause.")
        return
    click.echo("")
    click.echo(f"{'short_id':10} {'hostname':24} {'address':18} port")
    click.echo("-" * 60)
    for p in plist:
        click.echo(f"{p['short_id']:10} {p['hostname']:24} {p['address']:18} {p['port']}")


@cli.command()
@click.option("--seconds", default=6.0, show_default=True,
              help="How long to listen for other devices before deciding.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable verdict.")
def doctor(seconds, as_json):
    """Diagnose why this device cannot reach the other one.

    Checks the things that actually stop peer traffic and names ONE cause:
    whether the daemon is listening, whether a firewall rule matches the
    program it is really running as, whether multicast is reaching us at all,
    whether we are announcing, and whether any peer is out there.
    """

    from one_link import reachability_doctor as rd

    daemon_running = True
    self_short_id: str | None = None
    try:
        res = _request("peers")
        daemon_running = bool(res.get("ok"))
        self_short_id = (res.get("me") or {}).get("short_id")
    except Exception:
        # The daemon being unreachable IS a finding, not an error to abort on:
        # it is the first cause the diagnosis checks for.
        daemon_running = False

    # The peer port is NOT asked for here. The control API's `me` record does
    # not carry one, and reading a field that does not exist produced a
    # confident "daemon not listening" for a daemon that was listening. The
    # device's own mDNS announcement is authoritative: it is literally the port
    # a peer would dial.
    facts = rd.collect_facts(
        daemon_running=daemon_running,
        peer_port=None,
        peer_port_listening=False,
        self_short_id=self_short_id,
        mdns_seconds=float(seconds),
    )
    verdict = rd.diagnose(facts)

    if as_json:
        import json as _json

        click.echo(_json.dumps({
            "cause": verdict.cause,
            "severity": verdict.severity,
            "headline": verdict.headline,
            "remedy": list(verdict.remedy),
            "also": list(verdict.also),
            "facts": dict(verdict.facts),
        }, indent=2, sort_keys=True))
    else:
        click.echo(verdict.render())
        click.echo("")
        click.echo("What was observed:")
        click.echo(rd.summarize(facts))

    # Exit non-zero on a blocking cause so a script or a support flow can branch
    # on it without parsing prose.
    if verdict.severity == rd.SEVERITY_BLOCKED:
        raise click.exceptions.Exit(2)


@cli.command()
@click.argument("peer")
@click.argument("body")
def send(peer, body):
    """Send a chat message to PEER (short_id or hostname)."""
    res = _request("send", timeout=30.0, peer=peer, body=body)
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send failed"))
    r = res["result"]
    click.echo(f"sent  id={r['sent']['id'][:8]}  ack={r['ack']['t']}")


@cli.command("send-file")
@click.argument("peer")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def send_file(peer, path):
    """Send a file to PEER.

    One Link imposes no user-configured quota here, but disk, filesystem,
    memory, transport, route, and peer-policy limits still apply.
    """
    size = path.stat().st_size
    click.echo(f"sending {path.name} ({size} bytes)...")
    timeout = max(300.0, min(3600.0, size / (512 * 1024)))
    res = _request(
        "send_file",
        timeout=timeout,
        peer=peer,
        path=str(path.resolve()),
    )
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send-file failed"))
    r = res["result"]
    click.echo(f"sent  blob={r['blob'][:12]}  chunks={r['chunks']}  size={r['size']}")


@cli.command()
@click.option("--no-browser", is_flag=True, help="Don't auto-open a window.")
@click.option(
    "--browser-tab",
    is_flag=True,
    help=(
        "Open as a regular browser tab instead of a standalone "
        "Chromium app-mode window. Default opens in app-mode "
        "(frameless, no URL bar / tabs) when Edge or Chrome is "
        "available, falling back to a tab otherwise."
    ),
)
@click.option(
    "--lan/--loopback-only",
    default=False,
    help=(
        "Explicitly bind the pairing surface to 0.0.0.0 so devices on your "
        "local Wi-Fi can reach it. Default is loopback-only; remote plain "
        "HTTP never accepts owner UI credentials."
    ),
)
@click.option(
    "--supervise/--no-supervise",
    default=True,
    help=(
        "Run the daemon under a watchdog that auto-restarts it on "
        "crash. The supervisor has exponential backoff + a "
        "circuit-breaker (5 crashes in 60s stops trying). The UI's "
        "client-side reconnect handles the restart gap. Default on; "
        "pass --no-supervise to launch the daemon bare (e.g. for "
        "interactive debugging where you want the crash to take down "
        "the process visibly)."
    ),
)
def app(no_browser, browser_tab, lan, supervise):
    """Open the One Link desktop app (auto-starts daemon, opens UI).

    Default opens a standalone Chromium-style app-mode window (no
    browser chrome — looks/feels like a native app). Pass
    ``--browser-tab`` to fall back to a regular browser tab, or
    ``--no-browser`` to start the daemon headless. ``--supervise``
    wraps the daemon in an auto-restart watchdog."""
    from one_link.app import run_app

    raise SystemExit(
        run_app(
            no_browser=no_browser,
            standalone=not browser_tab,
            lan=lan,
            supervise=supervise,
        )
    )


@cli.command("open-url")
@click.argument("url")
def open_url(url: str):
    """Open a one-link:// URL in the local desktop app."""
    from one_link.app import run_app
    from one_link.protocol_handler import local_ui_url_for_deep_link

    code = run_app(no_browser=True, standalone=True, lan=False)
    if code != 0:
        raise SystemExit(code)
    try:
        # A deep link is opened in a browser, so it carries the single-use nonce --
        # never the long-lived bearer. `local_ui_url_for_deep_link` names its parameter
        # `token`; what it wants is "the credential in the URL", and that is the nonce.
        info = _resolve_running_daemon_for_url()
        local = local_ui_url_for_deep_link(
            url,
            port=info[0],
            token=info[1],
        )
    except Exception as exc:
        raise click.ClickException(str(exc))
    click.echo("open: authenticated One Link UI on loopback")
    launch_loopback_url(local)


@cli.command()
def chat():
    """Open the interactive terminal REPL. Auto-starts a daemon if none running."""
    from one_link.chat import run_chat

    raise SystemExit(run_chat())


@cli.command()
def audit():
    """Print a self-audit of this binary's network surface.

    Reports declared destination classes, registered local HTTP routes, and
    the peer protocol vocabulary. Optional services are included even when
    disabled. This inventory is not a packet-capture attestation; use the
    sovereignty status and outbound log for current policy and recent calls.
    """
    res = _request("audit")
    if res.get("error") or res.get("ok") is False:
        # The control socket doesn't have audit; we go via the UI port.
        try:
            ui_port, token = _ui_launch_info()
        except (RuntimeError, click.ClickException) as e:
            raise click.ClickException(f"daemon not running ({e})")
        import urllib.request
        import json as _json

        req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with validated_urlopen(req, timeout=5, allow_loopback_http=True) as r:
                res = _json.loads(r.read())
        except Exception as e:
            raise click.ClickException(f"audit fetch failed: {e}")

    click.echo(f"One Link version {res.get('version', '?')}")
    click.echo(f"  UI bind:           {res.get('ui_bind')}")
    click.echo(f"  UI auth:           {res.get('ui_auth')}")
    click.echo(f"  External telemetry: {'NO' if res.get('no_external_telemetry') else 'YES'}")
    doctrine = res.get("sovereign_network", {})
    if doctrine:
        click.echo(f"  Mission:            {doctrine.get('mission', '')}")
        click.echo("  Principles:")
        for p in doctrine.get("principles", []):
            click.echo(f"    - {p}")
        click.echo("  Sovereign capabilities:")
        for c in doctrine.get("capabilities", []):
            click.echo(f"    - {c['name']} [{c['status']}]")
    pp = res.get("peer_protocol", {})
    click.echo("  Peer protocol:")
    click.echo(f"    transport:   {pp.get('transport')}")
    click.echo(f"    auth:        {pp.get('auth')}")
    click.echo(f"    encryption:  {pp.get('encryption')}")
    click.echo(f"    msg types:   {', '.join(pp.get('message_types', []))}")
    click.echo(f"    max frame:   {pp.get('max_frame_bytes')} bytes")
    if res.get("local_capabilities"):
        click.echo(f"    local caps:  {', '.join(res.get('local_capabilities', []))}")
    if pp.get("sessions"):
        click.echo("    sessions:")
        for s in pp.get("sessions", []):
            click.echo(f"      - {s.get('name')}")
    click.echo("  Outbound destinations:")
    if res.get("outbound_inventory_scope"):
        click.echo(f"    scope: {res['outbound_inventory_scope']}")
    for o in res.get("outbound_destinations", []):
        click.echo(f"    - {o['kind']}: {o['destination']}")
        click.echo(f"        protocol: {o['protocol']}")
        if o.get("activation"):
            click.echo(f"        activation: {o['activation']}")
    click.echo("  Local UI routes:")
    for r in res.get("local_ui_routes", []):
        click.echo(f"    {r['method']:6} {r['path']}")
    primitives = res.get("sovereign_primitives", [])
    if primitives:
        click.echo("  Sovereign primitives:")
        for p in primitives:
            status = p.get("status", "?")
            ref = p.get("audit_ref", "")
            click.echo(f"    {p['name']:42} [{status}]  {ref}")
            click.echo(f"      {p['summary']}")


@cli.command()
@click.argument("query")
@click.option("--peer", default=None, help="Filter by peer (short_id or fingerprint).")
@click.option("--limit", default=50, type=int, help="Max results.")
def search(query, peer, limit):
    """Full-text search across message history."""
    try:
        ui_port, token = _ui_launch_info()
    except (RuntimeError, click.ClickException) as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.parse
    import urllib.request
    import json as _json

    qs = {"q": query, "limit": str(limit)}
    if peer:
        qs["peer"] = peer
    url = f"http://127.0.0.1:{ui_port}/api/search?{urllib.parse.urlencode(qs)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with validated_urlopen(req, timeout=10, allow_loopback_http=True) as r:
            res = _json.loads(r.read())
    except Exception as e:
        raise click.ClickException(f"search failed: {e}")

    msgs = res.get("messages", [])
    click.echo(f"{len(msgs)} result(s) for {query!r}\n")
    for m in msgs:
        if m.get("t") != "TEXT":
            continue
        ts = m.get("ts", 0)
        peer = m.get("peer", "?")
        body = m.get("body", "")
        click.echo(f"  [{ts}] {peer}: {body}")


@cli.command()
def tail():
    """Stream incoming and outgoing message events. Ctrl-C to stop."""
    s, _ = _connect_control()
    stream = None
    try:
        secret = control_ipc.read_control_secret()
        credential, exchange = control_ipc.begin_authenticated_request(
            s,
            {"cmd": "tail"},
            secret=secret,
        )
        s.settimeout(None)
        stream = s.makefile("rb")
        first = stream.readline(control_ipc.CONTROL_RESPONSE_MAX_BYTES + 2)
        if len(first) > control_ipc.CONTROL_RESPONSE_MAX_BYTES or not first.endswith(b"\n"):
            raise click.ClickException("daemon returned an oversized tail response")
        envelope = json.loads(first.decode("utf-8"))
        ack = control_ipc.verify_server_response(envelope, credential, exchange)
        if ack.get("ok") is not True or not ack.get("tailing"):
            raise click.ClickException(ack.get("error") or "daemon refused tail stream")
        click.echo("(tailing — Ctrl-C to stop)")
        while True:
            line = stream.readline(control_ipc.CONTROL_RESPONSE_MAX_BYTES + 2)
            if not line:
                break
            if len(line) > control_ipc.CONTROL_RESPONSE_MAX_BYTES or not line.endswith(b"\n"):
                raise click.ClickException("daemon tail event exceeds byte limit")
            if not line.strip():
                continue
            obj = json.loads(line.decode("utf-8"))
            msg = obj.get("msg") or obj
            _print_event(msg)
    except KeyboardInterrupt:
        pass
    finally:
        if stream is not None:
            stream.close()
        s.close()


def _print_event(m: dict) -> None:
    direction = m.get("dir", "?")
    arrow = "<-" if direction == "in" else "->"
    peer = m.get("peer", "?")
    t = m.get("t", "?")
    if t == "TEXT":
        click.echo(f"[{m.get('ts', '')}] {arrow} {peer}: {m.get('body', '')}")
    elif t == "FILE_OFFER":
        click.echo(
            f"[{m.get('ts', '')}] {arrow} {peer} OFFER {m.get('name', '')} "
            f"({m.get('size', '?')} bytes, blob={m.get('blob', '')[:8]})"
        )
    elif t == "FILE_DONE":
        ok = "OK" if m.get("ok") else "BAD"
        click.echo(
            f"[{m.get('ts', '')}] {arrow} {peer} FILE_DONE [{ok}] "
            f"{m.get('name', '')} -> {m.get('path', '')}"
        )
    else:
        click.echo(f"[{m.get('ts', '')}] {arrow} {peer} {t}")


def _ui_request(method: str, path: str, *, payload=None) -> dict:
    """Helper for hitting the daemon's UI API from CLI commands."""
    try:
        ui_port, token = _ui_launch_info()
    except (RuntimeError, click.ClickException) as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.error
    import urllib.request
    import json as _json

    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = _json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://127.0.0.1:{ui_port}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with validated_urlopen(req, timeout=30, allow_loopback_http=True) as r:
            return _json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read())
        except Exception:
            raise click.ClickException(f"{path} failed: {e}")
    except Exception as e:
        raise click.ClickException(f"{path} failed: {e}")


@cli.group()
def folder():
    """Synced-folder management. Folders sync between paired peers."""


@folder.command("add")
@click.argument("name")
@click.argument("local_path", type=click.Path(file_okay=False, path_type=Path))
@click.option(
    "--share", "share", multiple=True, help="Peer fingerprint to share with (repeatable)."
)
def folder_add(name, local_path, share):
    """Designate a folder to sync. NAME is a label, LOCAL_PATH is the directory."""
    res = _ui_request(
        "POST",
        "/api/folders",
        payload={
            "name": name,
            "local_path": str(local_path.expanduser().resolve()),
            "shared_with": list(share),
        },
    )
    if res.get("error"):
        raise click.ClickException(res["error"])
    f = res.get("folder", {})
    click.echo(f"added: {f.get('name')}  ->  {f.get('local_path')}")
    if f.get("shared_with"):
        click.echo("  shared with:")
        for fp in f["shared_with"]:
            click.echo(f"    {fp[:16]}…")


@folder.command("list")
def folder_list():
    """List all configured sync folders."""
    res = _ui_request("GET", "/api/folders")
    folders = res.get("folders", [])
    if not folders:
        click.echo("(no folders configured — try: one-link folder add)")
        return
    click.echo(f"{'name':16} {'files':>6} {'in_store':>9}  path")
    click.echo("-" * 60)
    for f in folders:
        click.echo(
            f"{f['name']:16} {f.get('files', 0):>6} {f.get('in_store', 0):>9}  {f['local_path']}"
        )
        if f.get("shared_with"):
            click.echo(
                f"{'':16} shared with: " + ", ".join(fp[:8] + "…" for fp in f["shared_with"])
            )


@folder.command("share")
@click.argument("name")
@click.argument("fingerprint")
def folder_share(name, fingerprint):
    """Add a peer FINGERPRINT to the sharing list of folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/share", payload={"peer_fp": fingerprint})
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"shared {name!r} with {fingerprint[:16]}…")


@folder.command("remove")
@click.argument("name")
def folder_remove(name):
    """Stop syncing folder NAME. Local files are not deleted."""
    res = _ui_request("DELETE", f"/api/folders/{name}")
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"removed: {name}")


@folder.command("sync")
@click.argument("name")
def folder_sync(name):
    """Force an immediate sync cycle for folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/sync", payload={})
    if res.get("error"):
        raise click.ClickException(res["error"])
    for r in res.get("results", []):
        peer = r.get("peer_fp", "?")[:8] + "…"
        if r["status"] == "pushed":
            click.echo(
                f"  {peer}  pushed  wants={r.get('wants', 0)}  blobs_sent={r.get('blobs_sent', 0)}"
            )
        else:
            click.echo(f"  {peer}  {r['status']}")


@cli.command("daemon-stop")
def daemon_stop():
    """Stop the background daemon.

    The daemon is detached from the launcher (so closing the desktop
    window does NOT stop it — paired peers stay online, in-flight
    transfers complete). Use this command when you actually want to
    shut down: One Link will no longer be reachable until you
    re-launch it.
    """
    try:
        daemon_mod.read_control_port()
    except RuntimeError:
        click.echo("daemon is not running.")
        return
    # Tell the daemon to shut down cleanly via authenticated control IPC.
    authenticated_pid: int | None = None
    try:
        status = _request("status", timeout=3.0)
        reported_pid = status.get("pid")
        if status.get("ok") is True and isinstance(reported_pid, int) and reported_pid > 0:
            authenticated_pid = reported_pid
        result = _request("shutdown", timeout=3.0)
        if result.get("ok") is not True:
            raise RuntimeError(result.get("error") or "shutdown refused")
        click.echo("daemon shutdown requested.")
    except Exception as e:
        # A PID file alone is untrusted: stale PIDs can be recycled into an
        # unrelated process.  Only fall back after this very connection
        # authenticated the daemon's PID and OS process inspection still
        # confirms it is One Link for the current home.
        if authenticated_pid is not None and daemon_mod._pid_matches_one_link_daemon(
            authenticated_pid
        ):
            try:
                if os.name == "nt":
                    _force_kill_windows_pid(authenticated_pid)
                else:
                    try:
                        os.kill(authenticated_pid, signal.SIGTERM)
                    except ProcessLookupError:
                        click.echo(f"daemon already exited (pid {authenticated_pid}).")
                        return
                click.echo(f"daemon terminated (pid {authenticated_pid}).")
                return
            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as fallback_exc:
                raise click.ClickException(
                    "could not stop daemon: authenticated process fallback "
                    f"failed ({type(fallback_exc).__name__}); clean shutdown "
                    f"also failed ({type(e).__name__})"
                ) from fallback_exc
        raise click.ClickException(f"could not stop daemon: {e}")


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
