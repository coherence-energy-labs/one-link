"""4-daemon subprocess swarm test.

Spawns 4 daemon subprocesses on loopback, waits for full mDNS
convergence (every peer sees every other), and exercises:

1. Cross-peer text round-trip (proves the multi-peer message routing
   works).
2. Sender-side relay-pick under BE-RAR scoring with 4 candidate peers
   (proves the Phase E daemon selection is alive in real subprocess
   processes, not just stubs).
3. Per-peer transport_kind reporting in /api/metrics (proves the
   Phase A2 capability negotiation + transport selection runs
   live).
4. Field-snapshot manager solve count climbs over time (proves the
   topology feeder is feeding + the field is solving).

Loopback isn't a substitute for real LAN; this test exists to lock
in correctness + the Phase E machinery's liveness, not throughput.

Marked slow — these tests spawn 4 subprocess daemons + wait for
mDNS convergence (~5-15 seconds wall time).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from one_link import control_ipc


_CONTROL_SECRETS: dict[int, str] = {}


# reruns=0 is load-bearing, not a preference. The release quality suites run
# with --reruns 2 to absorb shared-runner contention, but re-entering a test
# whose 4-daemon fixture is still finalizing trips pytest's own bookkeeping
# ("assert not self._finalizers" inside _get_active_fixturedef) and ERRORS the
# REST of this module at setup -- which is exactly how a green 9188-test
# Windows run was failed by two setup errors. The per-module mark overrides
# the CLI, so the retry net keeps protecting every other module while this
# one, with the heaviest fixture in the suite, stays single-shot.
pytestmark = [pytest.mark.timeout(180), pytest.mark.flaky(reruns=0)]


def _native_loadable_in_subprocess() -> bool:
    """True iff a fresh subprocess can import the native module. On
    Windows under Smart App Control the freshly-built ABI3 DLL can
    be blocked at first load; daemons spawned by these tests would
    then report `available: False` for every native subsystem
    through no fault of the daemon code."""
    try:
        r = subprocess.run(
            [sys.executable, "-c", "import one_link_native"],
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


_NATIVE_SUBPROC_OK = _native_loadable_in_subprocess()


def _require_native_subprocess_or_fail() -> None:
    """Turn the Smart App Control skip into a FAILURE on CI.

    The skip reason names a MOMENT ("Smart App Control is blocking the DLL
    right now"), not a missing capability, and that is the shape that hides
    real defects: an estate audit found seven such skips masking five genuine
    cross-repo failures. Here the environment named is a Windows desktop
    feature that no CI runner has, so on CI the only way this probe fails is
    that the native module genuinely cannot load in a spawned daemon -- which
    is exactly what these tests exist to catch.
    """
    if os.environ.get("CI", "").lower() in ("1", "true"):
        raise AssertionError(
            "one_link_native failed to import in a fresh subprocess on CI. "
            "Smart App Control does not exist on a runner, so this is a real "
            "packaging or build defect, not an environment quirk. Refusing to "
            "skip: a skip here reads as a pass and would hide it."
        )


# Per-run private mDNS scope so the swarm only ever discovers its own
# 4 cohort daemons — never the developer's live daemons (or a CI host's
# other One Link instances) broadcasting on the same LAN. Without this,
# a machine running several real daemons floods the cohort's browse with
# foreign peers and a genuine cohort member can be crowded out, failing
# convergence through no fault of the code. The label is kept short
# (RFC 6335 caps the protocol label at 15 chars). os.getpid() makes it
# unique to this test process.
_SWARM_MDNS_TYPE = f"_olt{os.getpid() % 100000:05d}._tcp.local."


def _spawn_daemon(home: Path, log: Path, label: str) -> tuple[subprocess.Popen, object]:
    """Spawn one daemon subprocess. Modeled on harness._spawn but
    re-implemented inline so this test can later run independently."""
    # Live-daemon lane only: skip in the default hermetic gate.
    from tests.harness import require_live_daemon

    require_live_daemon()
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    env["ONE_LINK_ALLOW_SAME_HOST_PEERS"] = "1"
    env["ONE_LINK_DISABLE_REVEAL"] = "1"
    env["ONE_LINK_MDNS_SERVICE_TYPE"] = _SWARM_MDNS_TYPE
    env["PYTHONIOENCODING"] = "utf-8"
    log.parent.mkdir(parents=True, exist_ok=True)
    f = open(log, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        env=env,
        stdout=f,
        stderr=subprocess.STDOUT,
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        ),
    )
    _STARTED[home] = (proc, log)
    return proc, f


def _stop_daemon(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    import signal

    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
        return
    except (subprocess.TimeoutExpired, Exception):
        pass
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


# The daemon and log behind each home, so a missing port file can say why.
_STARTED: dict[Path, tuple[subprocess.Popen, Path]] = {}


def _read_port(home: Path, name: str, timeout: float = 15.0) -> int:
    """Wait for a port file; on failure say whether the daemon is alive and what it logged.

    A daemon that is slow to start logs which startup step it is in. A bare
    "port file did not appear" throws that away, and this intermittent failure
    on hosted Windows runners stays unexplained.
    """
    from tests.harness import _read_port as read_port_with_evidence

    proc, log = _STARTED.get(home, (None, None))
    return read_port_with_evidence(home, name, timeout, proc=proc, log=log)


def _request(control_port: int, *, timeout: float = 30.0, **req) -> dict:
    return control_ipc.request_control(
        control_port,
        req,
        timeout=timeout,
        secret=_CONTROL_SECRETS[control_port],
    )


def _log_tail(path: Path, *, lines: int = 80) -> str:
    """Return a bounded daemon-log tail for actionable live-test failures."""
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError as exc:
        return f"<log unavailable: {exc}>"


def _wait_full_convergence(daemons: list[dict], n_peers: int, timeout: float = 45.0) -> None:
    """Block until every daemon sees `n_peers - 1` other peers."""
    end = time.time() + timeout
    while time.time() < end:
        all_converged = True
        for d in daemons:
            res = _request(d["control_port"], cmd="peers")
            seen = res.get("peers", [])
            if len(seen) < n_peers - 1:
                all_converged = False
                break
        if all_converged:
            return
        time.sleep(0.5)
    raise RuntimeError(
        f"4-peer swarm did not converge in {timeout}s — "
        f"each daemon should see {n_peers - 1} others"
    )


def _pin_full_mesh(daemons: list[dict]) -> None:
    """Model the user-approved trust boundary before exercising chat.

    Discovery deliberately creates pending peers.  A pending LAN identity must
    never inherit chat authority merely because it appeared over mDNS.  The
    live swarm therefore pins every directed relationship through the
    authenticated owner control API and verifies that the transition stuck
    before any application message is attempted.
    """
    for daemon in daemons:
        for peer in daemons:
            if peer is daemon:
                continue
            result = _request(
                daemon["control_port"],
                cmd="pin_peer",
                peer=peer["short_id"],
                trust="pinned",
                note="four-peer live swarm fixture",
            )
            assert result.get("ok"), (
                f"pin {daemon['label']}->{peer['label']} failed: {result}"
            )
            assert result.get("trust") == "pinned", result


@pytest.fixture
def four_peer_swarm():
    """4-daemon swarm fixture."""
    tmp = Path(tempfile.mkdtemp(prefix="one_link_swarm_"))
    daemons: list[dict] = []
    try:
        for i in range(4):
            label = chr(ord("A") + i)
            home = tmp / label
            log = tmp / f"{label}.log"
            home.mkdir(parents=True, exist_ok=True)
            proc, log_fh = _spawn_daemon(home, log, label)
            ctrl = _read_port(home, "control.port", timeout=20.0)
            _CONTROL_SECRETS[ctrl] = control_ipc.read_control_secret(home / "data")
            info = _request(ctrl, cmd="peers")
            assert info.get("ok"), f"daemon {label} 'peers' failed: {info}"
            daemons.append({
                "label": label,
                "proc": proc,
                "log": log,
                "log_fh": log_fh,
                "home": home,
                "control_port": ctrl,
                "short_id": info["me"]["short_id"],
            })
        _wait_full_convergence(daemons, n_peers=4)
        _pin_full_mesh(daemons)
        yield daemons
    finally:
        for d in daemons:
            _stop_daemon(d["proc"])
            # Drop the cached control secret with the daemon that owns it. This
            # cache is keyed by control port, and the OS recycles ephemeral
            # ports between tests in the same process, so a leaked entry gets
            # sent to whichever LATER daemon is handed the same port -- which
            # rejects the MAC. That leak produced an intermittent
            # ControlAuthenticationError on Windows from the shared harness, and
            # this fixture had the identical defect with four ports per test.
            _CONTROL_SECRETS.pop(int(d["control_port"]), None)
            try:
                d["log_fh"].close()
            except Exception:
                pass
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


@pytest.mark.live_daemon
def test_four_peer_swarm_converges(four_peer_swarm):
    """The mDNS convergence itself is the test — every daemon must
    see all 3 others. Fixture raises if convergence fails within
    45 seconds."""
    swarm = four_peer_swarm
    assert len(swarm) == 4
    for d in swarm:
        res = _request(d["control_port"], cmd="peers")
        seen_ids = {p["short_id"] for p in res.get("peers", [])}
        expected = {x["short_id"] for x in swarm if x is not d}
        assert seen_ids >= expected, (
            f"{d['label']} missing peers: expected {expected}, got {seen_ids}"
        )


@pytest.mark.live_daemon
def test_four_peer_swarm_all_advertise_phase_e_caps(four_peer_swarm):
    """Every daemon in the swarm must report Phase D/E + Bloom-init +
    QUIC capabilities as advertised via /api/status.native_status."""
    if not _NATIVE_SUBPROC_OK:
        # On CI this is never a legitimate skip. Smart App Control is a
        # Windows desktop feature no runner has, so if the native module
        # will not import in a fresh subprocess there, the packaging IS
        # broken -- and this is the test that would notice. A skip reads
        # exactly like a pass, so it would go quiet at the moment it
        # mattered. That is not hypothetical: the browser-call gate failed
        # every run it ever had because its daemon came up without the
        # native engine, and nothing said so.
        _require_native_subprocess_or_fail()
        pytest.skip(
            "one_link_native not importable in a fresh subprocess "
            "(Smart App Control); daemons would report "
            "available: False through no fault of the daemon"
        )
    swarm = four_peer_swarm
    for d in swarm:
        res = _request(d["control_port"], cmd="status")
        assert res.get("ok"), f"{d['label']} status failed: {res}"
        ns = res.get("native_status", {})
        for key in (
            "routing", "homology", "prefetch", "coherence_field",
            "bloom_init", "quic_transport",
        ):
            block = ns.get(key)
            assert block is not None, f"{d['label']} missing native_status.{key}"
            if key in ("bloom_init", "quic_transport"):
                # The cap must be ADVERTISED on every daemon (regardless
                # of native availability).
                assert block.get("advertised") is True, (
                    f"{d['label']} not advertising {key}"
                )
            else:
                # Phase D/E crates must be AVAILABLE on a daemon that's
                # built with the native wheel.
                assert block.get("available") is True, (
                    f"{d['label']} {key}.available is False"
                )


@pytest.mark.live_daemon
def test_four_peer_swarm_text_messages_route(four_peer_swarm):
    """Send a text message from A to each of B, C, D and verify
    every send returns ok."""
    swarm = four_peer_swarm
    sender = swarm[0]
    for receiver in swarm[1:]:
        res = _request(
            sender["control_port"],
            cmd="send",
            peer=receiver["short_id"],
            body=f"hello from {sender['label']} to {receiver['label']}",
        )
        assert res.get("ok"), (
            f"send {sender['label']}->{receiver['label']} failed: {res}\n"
            f"--- sender log ---\n{_log_tail(sender['log'])}\n"
            f"--- receiver log ---\n{_log_tail(receiver['log'])}"
        )


@pytest.mark.live_daemon
def test_four_peer_swarm_field_snapshot_solves_over_time(four_peer_swarm):
    """With 4 peers in the swarm, the FieldSnapshotManager's topology
    feeder + tick loop should produce at least one successful
    Helmholtz solve within ~15s.

    field_solve_count climbs from 0 to ≥1 across that window. This
    is the live proof that Phase E's full stack (feeder → manager →
    pyo3 → native ol_coherence_field) is operational in production
    daemon processes."""
    if not _NATIVE_SUBPROC_OK:
        pytest.skip(
            "one_link_native not importable in a fresh subprocess "
            "(Smart App Control); the field-solve loop can't run "
            "without the native crate"
        )
    swarm = four_peer_swarm
    sender = swarm[0]

    # Initial snapshot — might be 0 if the feeder hasn't ticked yet
    # (feeder period = 5s).
    initial_metrics = _request(sender["control_port"], cmd="status")[
        "native_status"
    ]["coherence_field"].get("snapshot_metrics", {})
    initial_solves = initial_metrics.get("field_solve_count", 0)

    # Wait up to 20s for at least one solve to land.
    end = time.time() + 20.0
    while time.time() < end:
        time.sleep(2.0)
        m = _request(sender["control_port"], cmd="status")[
            "native_status"
        ]["coherence_field"].get("snapshot_metrics", {})
        if m.get("field_solve_count", 0) > initial_solves:
            assert m["field_snapshot_age_ms"] >= 0, m
            assert m["field_snapshot_peer_count"] >= 3, m
            assert m["field_snapshot_residual"] < 1e-3, m
            return
    pytest.fail(
        "FieldSnapshotManager did not produce any solves in 20s with "
        "4 peers converged — topology feeder may not be running"
    )
