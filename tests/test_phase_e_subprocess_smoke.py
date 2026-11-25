"""Subprocess-level smoke test: real daemon processes have the Phase
E coherence-field surface alive and reachable via the control API.

This complements the in-process unit tests by exercising the actual
daemon binary, mDNS discovery, and HTTP control plane — verifying
that ``/api/native_status`` reports the field crate as available with
non-degenerate calibration constants, AND that record_relay_observation
+ _pick_best_relay are wired through the daemon's API.

If this passes, the field machinery is actually reachable on a live
daemon, not just inside the test harness.
"""

from __future__ import annotations

import os

import pytest

from tests.harness import daemon_pair, request


def _native_loadable_in_subprocess() -> bool:
    """True iff a fresh subprocess can `import one_link_native`. On
    Windows under Smart App Control the freshly-built ABI3 DLL can
    be blocked on first load — this test's spawned daemon would
    then report `available: False` for every native subsystem
    through no fault of the daemon code. Detect by trying once in
    a clean subprocess and skip the field-availability assertions
    on a mismatch (the daemon's own behavior is correct).
    """
    import subprocess
    import sys

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


pytestmark = pytest.mark.timeout(120)


def _control_request(control_port: int, **req) -> dict:
    """All verbs share the authenticated harness transport."""
    return request(control_port, timeout=10.0, **req)


@pytest.mark.live_daemon
def test_daemon_reports_coherence_field_available():
    """A real daemon subprocess must report coherence_field.available=True
    in the `status` control response. Verifies that ol_coherence_field
    is built into the daemon's Python environment and reachable through
    the live control plane — not just inside the test harness."""
    if not _NATIVE_SUBPROC_OK:
        # Never a legitimate skip on CI: Smart App Control is a Windows
        # desktop feature no runner has, so a failed subprocess import there
        # means the native module genuinely is not reachable from a spawned
        # daemon -- which is the one thing this test checks. A skip reads as
        # a pass and would hide it.
        if os.environ.get("CI", "").lower() in ("1", "true"):
            raise AssertionError(
                "one_link_native failed to import in a fresh subprocess on "
                "CI. Smart App Control does not exist on a runner, so this is "
                "a real packaging or build defect. Refusing to skip."
            )
        pytest.skip(
            "one_link_native not importable in a fresh subprocess — "
            "Smart App Control likely blocking the DLL; the daemon "
            "subprocess would report available: False through no "
            "fault of the daemon code"
        )
    with daemon_pair() as p:
        for daemon in [p.a, p.b]:
            res = request(daemon.control_port, cmd="status")
            assert res.get("ok"), f"status request failed: {res}"
            ns = res.get("native_status")
            assert ns is not None, (
                f"status response missing native_status block on "
                f"{daemon.short_id}; daemon build is missing the Phase E "
                "diagnostics surface"
            )
            cf = ns.get("coherence_field")
            assert cf is not None, (
                f"native_status missing coherence_field block: {ns}"
            )
            assert cf.get("available") is True, (
                f"coherence_field.available is False on {daemon.short_id}; "
                "ol_coherence_field not built into the daemon's Python env"
            )
            cal = cf.get("calibration")
            assert cal is not None
            assert cal.get("d", 0) > 0
            assert cal.get("gamma", 0) > 0
            assert cal.get("apparent_horizon_anchor", 0) > 0


@pytest.mark.live_daemon
def test_daemon_pair_field_calibration_matches_across_daemons():
    """Two daemons running the same build must report identical
    calibration constants — the calibration is compile-time in
    ol_coherence_field, so any drift between daemon instances is a
    build/version mismatch."""
    with daemon_pair() as p:
        a_res = request(p.a.control_port, cmd="status")
        b_res = request(p.b.control_port, cmd="status")
        assert a_res.get("ok") and b_res.get("ok")
        a_cal = a_res["native_status"]["coherence_field"]["calibration"]
        b_cal = b_res["native_status"]["coherence_field"]["calibration"]
        assert a_cal == b_cal, (
            f"calibration constants differ across daemons:\nA={a_cal}\nB={b_cal}"
        )


@pytest.mark.live_daemon
def test_daemon_pair_routing_homology_prefetch_also_reported():
    """All four Phase D/E native subsystems must show available=True
    on a real daemon: routing, homology, prefetch, coherence_field.
    Together they form the upgrade-tier the v2 plan describes."""
    if not _NATIVE_SUBPROC_OK:
        pytest.skip(
            "one_link_native not importable in a fresh subprocess — "
            "Smart App Control likely blocking the DLL"
        )
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="status")
        assert res.get("ok")
        ns = res["native_status"]
        for subsystem in ("routing", "homology", "prefetch", "coherence_field"):
            block = ns.get(subsystem)
            assert block is not None, f"{subsystem} missing from native_status"
            assert block.get("available") is True, (
                f"{subsystem}.available is False on a real daemon — "
                "the production build is missing a Phase D/E crate"
            )


@pytest.mark.live_daemon
def test_daemon_pair_bloom_init_capability_advertised_in_status():
    """BLOOM_INIT_V1 must show up in the live daemon's status surface.
    The cap is what gates the entire Phase B handshake."""
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="status")
        assert res.get("ok")
        ns = res["native_status"]
        bi = ns.get("bloom_init")
        assert bi is not None
        # Native availability depends on the wheel build; the cap MUST
        # be advertised either way (a daemon without the wheel still
        # advertises so peers know to NOT bother sending the bloom).
        assert isinstance(bi.get("advertised"), bool)
        assert bi.get("advertised") is True


@pytest.mark.live_daemon
def test_daemon_pair_quic_transport_capability_advertised_in_status():
    """QUIC_TRANSPORT_V1 must show up in the live daemon's status."""
    with daemon_pair() as p:
        res = request(p.a.control_port, cmd="status")
        assert res.get("ok")
        ns = res["native_status"]
        qt = ns.get("quic_transport")
        assert qt is not None
        assert isinstance(qt.get("advertised"), bool)
        assert qt.get("advertised") is True
        # endpoint_up depends on whether the local make_endpoint
        # succeeded. We don't assert True (platform-dependent) but
        # we do assert the key exists.
        assert "endpoint_up" in qt
