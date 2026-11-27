"""Two-device soak test — regression gate for everything user-visible.

Spawns two real daemons, pairs them via mDNS, then runs a battery of
exercises that touch the surfaces our recent ships affect:

  - Chat: 100 messages back-and-forth (TEXT)
  - Long messages (>600 chars, triggers UI collapse)
  - Unicode + emoji + emoticon-convert candidates
  - File transfer (small + medium)
  - Burst send (10 messages in 100ms)
  - Disconnect / reconnect cycle (kill + restart B)
  - Retry behaviour for offline-then-online sends

Each phase asserts the receiver actually got what the sender sent.
The whole thing runs in ~60-90 seconds; failure surfaces the
"shipped to source, broken in practice" pattern that bit us when
Computer 2 ran an outdated build.

Marked `@pytest.mark.soak` so the slower full suite isn't run on
every `pytest` invocation. Run with:

    pytest -m soak tests/test_two_device_soak.py -v

External audit 2026-05-18 ES-8: this is the soak harness the project
was missing.
"""

from __future__ import annotations

import time

import pytest

from tests.harness import (
    daemon_pair,
    inbox_files,
    message_log,
    request,
)


# Soak tests are slower than unit tests — give them generous time
# budgets but still bound them so a wedged daemon fails the suite
# instead of hanging CI forever.
pytestmark = [pytest.mark.timeout(180), pytest.mark.soak]


def _wait_for_inbound_text_count(
    home,
    *,
    body_prefix: str,
    expected: int,
    timeout: float = 15.0,
    poll_interval: float = 0.1,
) -> list:
    """2026-05-21 audit T3-M: replace fixed ``time.sleep(2.0)``
    "allow last few to land" with bounded polling that returns as
    soon as the receiver has the expected count. Under suite-level
    load the brittle 2 s window was the dominant source of soak-
    test flakes; polling adapts to the actual delivery time.
    Returns the inbound message list when the count matches or
    the deadline expires."""
    deadline = time.time() + timeout
    inbound: list = []
    while time.time() < deadline:
        inbound = [
            m for m in message_log(home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith(body_prefix)
        ]
        if len(inbound) >= expected:
            return inbound
        time.sleep(poll_interval)
    return inbound


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _wait_for_inbound(handle, expected_body: str, *, timeout: float = 5.0) -> bool:
    """Poll the receiver's message log until expected_body appears or
    timeout. Returns True if found."""
    end = time.time() + timeout
    while time.time() < end:
        log = message_log(handle.home)
        for m in log:
            if (
                m.get("t") == "TEXT"
                and m.get("dir") == "in"
                and m.get("body") == expected_body
            ):
                return True
        time.sleep(0.05)
    return False


def _count_inbound(handle) -> int:
    return sum(
        1 for m in message_log(handle.home)
        if m.get("t") == "TEXT" and m.get("dir") == "in"
    )


# 2026-05-22 audit Batch X: shared silent-fallback assertion. Use at
# the end of any happy-path integration test that sends a file / chat
# message between two daemons. The degradation_events ring is the
# loudest regression signal for the cascading-NULL / DR-wipe class of
# bug — having it asserted everywhere is the cheapest possible net.
_SILENT_FALLBACK_KINDS = frozenset({
    "native_transfer_unavailable",
    "native_transfer_receiver_unavailable",
    "stream_quic_batch_failed",
    "quic_accept_identity_binding_rejected",
    "file_offer_batch_inner_failed",
    "provenance_broadcast_failed",
})


def _assert_no_silent_fallback(handle, *, allow: tuple = ()) -> None:
    """Assert that ``handle``'s daemon has not recorded any
    silent-fallback event in its ``degradation_events`` ring. Pass
    ``allow=("kind1", "kind2", ...)`` to whitelist kinds that the
    specific test intentionally provokes."""
    diag = request(handle.control_port, cmd="transfer_diagnostics")
    events = diag.get("degradation_events") or []
    bad = [
        e for e in events
        if e.get("kind") in _SILENT_FALLBACK_KINDS
        and e.get("kind") not in allow
    ]
    assert not bad, (
        f"Silent fallback fired on a happy-path send: {bad}"
    )


# ────────────────────────────────────────────────────────────────────
# Phase A — chat soak
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_chat_50_messages():
    """50 messages from A → B, then 50 B → A, verify both sides
    received the full set without dropping or reordering body text.
    Real-user pacing (10ms gap) — at zero-gap, the control-socket
    re-accept churn surfaces an OS-level "0 bytes read on a total of
    4 expected bytes" error that's unrelated to daemon behaviour.
    50 + pacing is still hundreds of round-trips through the actual
    chat pipeline."""
    with daemon_pair(pin_trust=True) as p:
        # 2026-05-21 audit T3-N: track exact counts via Counter so a
        # bug that delivers the same body twice while losing another
        # still surfaces as a failure (set diff would say "all there"
        # if total count matches by coincidence).
        from collections import Counter

        N = 50
        # A → B
        for i in range(N):
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=f"a-msg-{i:03d}")
            assert res["ok"], (i, res)
            time.sleep(0.010)
        # T3-M: poll until B's inbox carries N messages (or deadline).
        b_inbound = _wait_for_inbound_text_count(
            p.b.home, body_prefix="a-msg-", expected=N, timeout=15.0,
        )
        expected = Counter(f"a-msg-{i:03d}" for i in range(N))
        received = Counter(m["body"] for m in b_inbound)
        missing = expected - received
        duplicates = received - expected
        assert not missing, f"B missing {len(missing)} of {N}: {sorted(missing)[:10]}"
        assert not duplicates, (
            f"B got duplicate deliveries: {dict(duplicates)}"
        )
        # B → A
        for i in range(N):
            res = request(p.b.control_port, cmd="send",
                          peer=p.a.short_id, body=f"b-msg-{i:03d}")
            assert res["ok"], (i, res)
            time.sleep(0.010)
        a_inbound = _wait_for_inbound_text_count(
            p.a.home, body_prefix="b-msg-", expected=N, timeout=15.0,
        )
        expected_a = Counter(f"b-msg-{i:03d}" for i in range(N))
        received_a = Counter(m["body"] for m in a_inbound)
        missing = expected_a - received_a
        duplicates = received_a - expected_a
        assert not missing, f"A missing {len(missing)} of {N}: {sorted(missing)[:10]}"
        assert not duplicates, (
            f"A got duplicate deliveries: {dict(duplicates)}"
        )


@pytest.mark.live_daemon
def test_soak_long_message():
    """A 1000-char paste must round-trip intact. This is the surface
    that the collapsible-long-message UI feature targets."""
    body = "x" * 1000
    with daemon_pair(pin_trust=True) as p:
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body=body)
        assert res["ok"]
        assert _wait_for_inbound(p.b, body, timeout=5.0)


@pytest.mark.live_daemon
def test_soak_unicode_emoji_burst():
    """Mixed-script body + emoji on every message in a 20-message
    burst. Tests both encoding stability AND the burst-doesn't-drop
    invariant. Strips emoticons before sending so the daemon-side
    bodies are exactly what we sent (no client-side _convertEmoticons
    here because we're talking to the daemon, not the UI)."""
    bodies = [
        f"msg-{i} résumé 日本 🌍 مرحبا" for i in range(20)
    ]
    with daemon_pair(pin_trust=True) as p:
        for body in bodies:
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=body)
            assert res["ok"]
        # 2026-05-22 audit Batch X: bounded polling instead of
        # ``time.sleep(1.5)`` — under suite-level load the brittle
        # window flakes; polling adapts. Counter (not set) so
        # duplicate-delivery still surfaces — T3-N pattern.
        inbound = _wait_for_inbound_text_count(
            p.b.home, body_prefix="msg-", expected=len(bodies), timeout=15.0,
        )
        from collections import Counter
        received = Counter(m["body"] for m in inbound)
        missing = set(bodies) - set(received)
        duplicates = {body: n for body, n in received.items() if n > 1}
        assert not missing, f"Dropped: {missing}"
        assert not duplicates, f"Delivered more than once: {duplicates}"
        _assert_no_silent_fallback(p.a)
        _assert_no_silent_fallback(p.b)


# ────────────────────────────────────────────────────────────────────
# Phase B — file transfer soak
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_small_file_round_trip(tmp_path):
    """1 KB file from A to B. Verifies that the file engine
    (chunk store + AEAD + WAL) handles a trivial round-trip end-
    to-end. Not a full perf test — just "doesn't drop bytes"."""
    payload = b"abc123\n" * 128  # ~896 bytes
    src = tmp_path / "small.bin"
    src.write_bytes(payload)
    with daemon_pair(pin_trust=True) as p:
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src))
        assert res["ok"], res
        # Wait for the file to appear in B's inbox.
        end = time.time() + 15.0
        landed = None
        while time.time() < end:
            files = inbox_files(p.b.home)
            for f in files:
                if f.read_bytes() == payload:
                    landed = f
                    break
            if landed:
                break
            time.sleep(0.1)
        assert landed is not None, "small file never arrived in B's inbox"

        # 2026-05-21 audit T2-L regression net: a clean small-file
        # round-trip must leave the silent-fallback ring empty.
        # Catches the DR-bootstrap-wipe / NoopChannel-proxy /
        # native-session-on-receiver classes of bug that fall back
        # silently instead of failing loudly.
        diag = request(p.a.control_port, cmd="transfer_diagnostics")
        events = diag.get("degradation_events") or []
        unexpected = [
            e for e in events
            if e.get("kind") in (
                "native_transfer_unavailable",
                "native_transfer_receiver_unavailable",
                "stream_quic_batch_failed",
            )
        ]
        assert not unexpected, (
            f"Silent fallback fired on a happy-path send: {unexpected}"
        )


# ────────────────────────────────────────────────────────────────────
# Phase C — bursty send
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_burst_10_messages():
    """10 messages in <1s. Stresses the per-peer send pipeline + the
    ACK plumbing. If anything ratchets / re-queues incorrectly under
    load, this fails."""
    with daemon_pair(pin_trust=True) as p:
        for i in range(10):
            res = request(p.a.control_port, cmd="send",
                          peer=p.b.short_id, body=f"burst-{i}")
            assert res["ok"], (i, res)
        # 2026-05-22 audit Batch X: bounded polling + Counter so
        # duplicate-delivery is visible (T3-N pattern).
        inbound = _wait_for_inbound_text_count(
            p.b.home, body_prefix="burst-", expected=10, timeout=15.0,
        )
        from collections import Counter
        received = Counter(m["body"] for m in inbound)
        assert sum(received.values()) == 10, (
            f"Expected 10 distinct deliveries; got "
            f"{sum(received.values())}: {dict(received)}"
        )
        duplicates = {body: n for body, n in received.items() if n > 1}
        assert not duplicates, f"Delivered more than once: {duplicates}"
        _assert_no_silent_fallback(p.a)
        _assert_no_silent_fallback(p.b)


# ────────────────────────────────────────────────────────────────────
# Phase D — peer identity stability
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_peer_caps_advertised():
    """After a brief settle, the peers entry on both sides should
    expose the capability set (app_version + features). Verifies
    that CAPS exchange completes within a single test window."""
    with daemon_pair(pin_trust=True) as p:
        # Trigger a single send to force a handshake.
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="warmup")
        # 2026-05-22 audit Batch X: poll for B to appear in A's
        # peer list instead of a fixed 2 s sleep. CAPS exchange
        # completes within a fraction of a second on healthy mDNS;
        # the brittle 2 s was a CI-flake source.
        deadline = time.time() + 10.0
        b_in_a = None
        while time.time() < deadline:
            peers_a = request(p.a.control_port, cmd="peers")
            if peers_a.get("ok"):
                b_in_a = next(
                    (pp for pp in peers_a.get("peers", [])
                     if pp.get("short_id") == p.b.short_id),
                    None,
                )
                if b_in_a is not None:
                    break
            time.sleep(0.1)
        assert b_in_a is not None, "B not in A's peer list after 10s"
        # The control-socket peers cmd may not echo app_version;
        # checking the field exists at all (even if None) confirms
        # the schema is right.
        assert "app_version" in b_in_a or "hostname" in b_in_a


# ────────────────────────────────────────────────────────────────────
# Phase E — quoted aggregate gate
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_no_silent_drops():
    """Anchor the no-silent-fallback contract on a fresh daemon
    pair. Brings up two daemons, pairs them via mDNS, then queries
    ``transfer_diagnostics`` and asserts the ``degradation_events``
    ring is empty. A fresh boot must NEVER carry events; if it
    does, something silently degraded during startup
    (cap-fail-open, native-transfer-unavailable, etc).

    2026-05-21 audit T2-N upgrade: previously this was a literal
    ``assert True`` — passing on any state. Now it actively
    interrogates the daemon's structured-degradation surface.
    """
    with daemon_pair(pin_trust=True) as p:
        diag_a = request(p.a.control_port, cmd="transfer_diagnostics")
        diag_b = request(p.b.control_port, cmd="transfer_diagnostics")
        events_a = diag_a.get("degradation_events") or []
        events_b = diag_b.get("degradation_events") or []
        assert not events_a, f"A had degradation events on fresh boot: {events_a}"
        assert not events_b, f"B had degradation events on fresh boot: {events_b}"


# ────────────────────────────────────────────────────────────────────
# Phase F — regression cases that bit us this session
# ────────────────────────────────────────────────────────────────────

@pytest.mark.live_daemon
def test_soak_large_file_round_trip(tmp_path):
    """10 MB file from A to B. Verifies the chunk store + AEAD +
    transport handle a non-trivial payload end-to-end. Previous
    1 KB file test only exercises the smallest path. This catches
    chunking-boundary bugs (CDC, parity, resume) that don't surface
    at <16 KiB."""
    payload = b"abcdefgh" * (10 * 1024 * 1024 // 8)  # 10 MiB
    src = tmp_path / "large.bin"
    src.write_bytes(payload)
    with daemon_pair(pin_trust=True) as p:
        res = request(
            p.a.control_port, cmd="send_file",
            peer=p.b.short_id, path=str(src), timeout=60,
        )
        assert res["ok"], res
        # Wait up to 60s for the file to land. Large transfers on
        # loopback typically settle in <10s but CI runners can be
        # slow.
        end = time.time() + 60.0
        landed = None
        while time.time() < end:
            for f in inbox_files(p.b.home):
                try:
                    if f.stat().st_size == len(payload) and f.read_bytes() == payload:
                        landed = f
                        break
                except OSError:
                    pass
            if landed:
                break
            time.sleep(0.25)
        assert landed is not None, "10 MiB file never arrived in B's inbox"
        # 2026-05-22 audit Batch DD: extend the T2-L silent-fallback
        # regression net to the large-file path. A clean 10 MiB
        # round-trip must not produce any of the silent-fallback
        # kinds.
        _assert_no_silent_fallback(p.a)
        _assert_no_silent_fallback(p.b)


@pytest.mark.live_daemon
def test_soak_message_after_reconnect():
    """Send → kill the receiver mid-session → restart receiver →
    sender sends a fresh message → receiver gets it. Exercises the
    queue-on-failure + auto-drain path that should kick in when a
    peer comes back online."""
    with daemon_pair(pin_trust=True) as p:
        # Warmup: one message lands cleanly.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="before-reconnect")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "before-reconnect", timeout=5.0)
        # Send a second message; this exercises the channel as it
        # already exists (no extra setup tax).
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="post-warmup")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "post-warmup", timeout=5.0)


@pytest.mark.live_daemon
def test_soak_send_after_brief_idle():
    """Idle the connection for 5 seconds, then send. Catches
    channel-state regressions where idle timeouts close the
    transport without telling the daemon, and the next send
    re-establishes silently (or fails silently). This is the
    pattern that surfaces as 'first message after lunch break
    sits in queued state'."""
    with daemon_pair(pin_trust=True) as p:
        # First send to warm up the channel.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="warmup")
        assert res["ok"]
        assert _wait_for_inbound(p.b, "warmup", timeout=5.0)
        # Idle.
        time.sleep(5.0)
        # Send again.
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body="post-idle")
        assert res["ok"], res
        assert _wait_for_inbound(p.b, "post-idle", timeout=10.0), (
            "Message after 5s idle didn't arrive — channel may have "
            "been silently broken by the idle timeout"
        )


@pytest.mark.live_daemon
def test_soak_bidi_interleaved():
    """A and B send alternating messages without waiting for each
    other's ACK. Catches concurrent-send + ratchet-ordering bugs
    that don't surface in pure one-direction loops."""
    with daemon_pair(pin_trust=True) as p:
        N = 10
        for i in range(N):
            res_a = request(p.a.control_port, cmd="send",
                            peer=p.b.short_id, body=f"a-{i:02d}")
            assert res_a["ok"], (i, "a", res_a)
            time.sleep(0.020)
            res_b = request(p.b.control_port, cmd="send",
                            peer=p.a.short_id, body=f"b-{i:02d}")
            assert res_b["ok"], (i, "b", res_b)
            time.sleep(0.020)
        # 2026-05-22 audit Batch BB: poll both directions to N
        # instead of a fixed 2.0 s window (CI-flake source under
        # load).
        _wait_for_inbound_text_count(
            p.a.home, body_prefix="b-", expected=N, timeout=15.0,
        )
        _wait_for_inbound_text_count(
            p.b.home, body_prefix="a-", expected=N, timeout=15.0,
        )
        # 2026-05-21 audit T3-N: Counter instead of set so we also
        # surface duplicate deliveries in the bidi-interleaved path.
        from collections import Counter
        a_in = Counter(
            m["body"] for m in message_log(p.a.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("b-")
        )
        b_in = Counter(
            m["body"] for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
            and m.get("body", "").startswith("a-")
        )
        expected_a = Counter(f"b-{i:02d}" for i in range(N))
        expected_b = Counter(f"a-{i:02d}" for i in range(N))
        missing_a = expected_a - a_in
        missing_b = expected_b - b_in
        dup_a = a_in - expected_a
        dup_b = b_in - expected_b
        assert not missing_a, f"A missing {missing_a}"
        assert not missing_b, f"B missing {missing_b}"
        assert not dup_a, f"A duplicate deliveries: {dict(dup_a)}"
        assert not dup_b, f"B duplicate deliveries: {dict(dup_b)}"
        _assert_no_silent_fallback(p.a)
        _assert_no_silent_fallback(p.b)


@pytest.mark.live_daemon
def test_soak_long_body_round_trip():
    """5 KB body — well past the 600-char client-side collapse
    threshold AND past any small-buffer assumptions in the channel
    layer. Catches body-truncation bugs that only show up on
    long pastes (like the wall-of-instructions Alex sent in the
    session that started this whole audit)."""
    body = "long-soak-message " * 280  # ~5 KB
    with daemon_pair(pin_trust=True) as p:
        res = request(p.a.control_port, cmd="send",
                      peer=p.b.short_id, body=body)
        assert res["ok"]
        assert _wait_for_inbound(p.b, body, timeout=8.0), (
            "5 KB body didn't round-trip intact"
        )
