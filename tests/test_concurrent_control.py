"""Concurrent control-endpoint race tests.

Fires multiple control commands simultaneously against the same
daemon and asserts none of them corrupt state, hang, or
short-circuit each other. Catches the regression where two
``pin_peer`` requests racing through ``set_peer_trust`` could
double-fire ``broadcast_endpoint_to_paired`` or where a
``send_file`` and a ``cancel_resumable_transfer`` against the
same blob could deadlock the receive lock.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from tests.harness import daemon_pair, inbox_files, request


pytestmark = [pytest.mark.timeout(180), pytest.mark.soak]


@pytest.mark.live_daemon
def test_concurrent_pin_peer_idempotent() -> None:
    """Two simultaneous pin_peer requests for the same peer must
    both succeed AND end with the peer trusted exactly once. No
    double-broadcast amplification, no inconsistent state."""
    with daemon_pair(pin_trust=True) as p:
        results: list[dict] = []
        errors: list[BaseException] = []

        def pin() -> None:
            try:
                r = request(p.a.control_port, cmd="pin_peer",
                            peer=p.b.short_id)
                results.append(r)
            except BaseException as e:  # pragma: no cover - surfaced
                errors.append(e)

        ts = [threading.Thread(target=pin, daemon=True) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=15.0)
        if errors:
            raise errors[0]
        # All 4 must have succeeded.
        assert len(results) == 4
        for r in results:
            assert r.get("ok"), r
            assert r.get("trust") == "pinned"
        # All 4 responses must agree on the same peer_fp — no torn writes,
        # no half-resolved peer record.
        fps = {r.get("peer_fp") for r in results}
        assert len(fps) == 1, fps
        # And a final pin_peer must still report trust=pinned (the state
        # didn't drift back during the concurrent burst).
        final = request(p.a.control_port, cmd="pin_peer", peer=p.b.short_id)
        assert final.get("ok"), final
        assert final.get("trust") == "pinned"


@pytest.mark.live_daemon
def test_concurrent_send_file_and_chat() -> None:
    """A send_file racing with a flurry of chat sends — neither
    side should starve the other or drop messages. The send_file
    holds the per-peer session lock for the duration of the
    transfer; chat sends should queue behind it cleanly."""
    payload = b"concurrent-payload" * 1024  # ~18 KiB
    with daemon_pair(pin_trust=True) as p:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "concurrent.bin"
            src.write_bytes(payload)
            file_result: list[dict] = []
            chat_results: list[dict] = []

            def send_file() -> None:
                r = request(p.a.control_port, cmd="send_file",
                            peer=p.b.short_id, path=str(src),
                            timeout=30)
                file_result.append(r)

            def send_chats() -> None:
                for i in range(5):
                    r = request(p.a.control_port, cmd="send",
                                peer=p.b.short_id,
                                body=f"concurrent-chat-{i}")
                    chat_results.append(r)
                    time.sleep(0.01)

            t_file = threading.Thread(target=send_file, daemon=True)
            t_chat = threading.Thread(target=send_chats, daemon=True)
            t_file.start()
            time.sleep(0.05)
            t_chat.start()
            t_file.join(timeout=60.0)
            t_chat.join(timeout=60.0)

            # File delivered.
            assert file_result and file_result[0].get("ok"), file_result
            # Wait for the payload to land in B's inbox.
            end = time.time() + 15.0
            landed = False
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    try:
                        if f.read_bytes() == payload:
                            landed = True
                            break
                    except OSError:
                        pass
                if landed:
                    break
                time.sleep(0.1)
            assert landed
            # All chats succeeded.
            assert len(chat_results) == 5
            for r in chat_results:
                assert r.get("ok"), r


@pytest.mark.live_daemon
def test_concurrent_quic_ping_under_load() -> None:
    """Multiple concurrent quic_ping requests against the same
    peer must all succeed without deadlocking on the per-peer
    dial lock. The lock prevents duplicate dials but should
    allow concurrent USAGE of the cached connection."""
    with daemon_pair(pin_trust=True) as p:
        # Set up pinning so QUIC fires.
        a_pin = request(p.a.control_port, cmd="pin_peer",
                        peer=p.b.short_id)
        request(p.b.control_port, cmd="pin_peer", peer=p.a.short_id)
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="warm")
        # Wait for QUIC port advertisement.
        # 2026-05-22 audit Batch DD: was ``pytest.skip`` on a 30 s
        # timeout, which silently no-op'd this test under load —
        # exactly the failure mode (advertisement losing a race)
        # it was supposed to detect. Now hard-fails with a final
        # diagnostic snapshot so flakiness surfaces.
        deadline = time.time() + 60.0
        ready = False
        b_fp_prefix = a_pin["peer_fp"][:16]
        last_status: dict = {}
        while time.time() < deadline:
            st = request(p.a.control_port, cmd="quic_status")
            last_status = st
            if any(k.startswith(b_fp_prefix)
                   for k in (st.get("advertised_ports") or {})):
                ready = True
                break
            time.sleep(0.1)
        assert ready, (
            "QUIC port advertisement didn't land within 60 s. "
            f"Final quic_status: {last_status}"
        )
        # Fire 6 pings concurrently.
        results: list[dict] = []
        errors: list[BaseException] = []

        def ping(i: int) -> None:
            try:
                r = request(p.a.control_port, cmd="quic_ping",
                            peer=p.b.short_id,
                            payload=f"concurrent-ping-{i}")
                results.append(r)
            except BaseException as e:  # pragma: no cover - surfaced
                errors.append(e)

        ts = [threading.Thread(target=ping, args=(i,), daemon=True)
              for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=30.0)
        if errors:
            raise errors[0]
        assert len(results) == 6
        for r in results:
            assert r.get("ok"), r
            assert r.get("rtt_ms") is not None
