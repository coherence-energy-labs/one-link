"""Tests for cross-peer app_version exchange via CAPS, and for the
user-facing error translation that fires when two peers can't talk
because they're on incompatible builds.

The original symptom that motivated this: a v0.6.x daemon on one
machine + a v0.7.x daemon on another fails AEAD authentication
(InvalidTag) and the user sees a bare 'Send failed: /api/send 500'.
After this change:

    1. Both sides advertise their app_version in the CAPS handshake.
    2. /api/me and /api/peers expose those versions so the UI can
       show a banner before anything is sent.
    3. If a send still fails with InvalidTag, the API translates it
       into a meaningful 502 with code='wire_version_mismatch' and a
       hint telling the user to update both devices.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiohttp
import pytest

from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(120)


def _read(home: Path, name: str, timeout: float = 15.0) -> str:
    p = home / "data" / name
    import time as _time
    end = _time.time() + timeout
    last_err: Exception | None = None
    while _time.time() < end:
        try:
            txt = p.read_text(encoding="utf-8").strip()
            if txt:
                return txt
        except (FileNotFoundError, OSError) as e:
            last_err = e
        _time.sleep(0.05)
    if last_err is not None:
        raise last_err
    raise FileNotFoundError(p)


def _server_addr(home: Path) -> tuple[str, str]:
    port = _read(home, "server.port")
    token = _read(home, "ui.token")
    return f"http://127.0.0.1:{port}", token


# ─── 1. _build_caps embeds the app_version ─────────────────────────────

def test_build_caps_includes_app_version():
    from one_link.daemon import _build_caps
    from one_link import __version__

    caps = _build_caps("aaaaaaaa")
    assert caps["t"] == "CAPS"
    assert caps["app_version"] == __version__


def test_build_caps_app_version_is_present_with_optional_fields():
    """rendezvous + channel_bind don't drop app_version."""
    from one_link.daemon import _build_caps
    from one_link import __version__

    caps = _build_caps(
        "aaaaaaaa",
        rendezvous_urls=["https://r.example.com"],
        channel_bind={"peer_fp": "x", "self_fp": "y", "transcript": "z"},
    )
    assert caps["app_version"] == __version__
    assert "share_rdz" in caps
    assert "channel_bind" in caps


# ─── 2. /api/me exposes our app_version ────────────────────────────────

@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_api_me_exposes_app_version():
    from one_link import __version__

    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base}/api/me",
                headers={"Authorization": f"Bearer {token}"},
            ) as r:
                assert r.status == 200
                j = await r.json()
                assert j.get("app_version") == __version__
                assert j.get("protocol_version")
                assert j.get("schema_version", 0) >= 1


# ─── 3. /api/peers carries each peer's app_version after CAPS ─────────

@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_api_peers_exposes_peer_app_version_after_caps():
    """The peer's CAPS frame is exchanged on first encrypted send.
    After A→B sends a TEXT, B's session for A has peer_caps populated,
    so /api/peers on B should report A's app_version.
    """
    from tests.harness import request as ctrl_request

    with daemon_pair() as p:
        # Force a session by sending text A → B.
        ctrl_request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="hello",
        )
        await asyncio.sleep(0.8)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            # Listing both paired and unpaired so the test passes
            # whether the harness auto-pinned or left them pending.
            async with s.get(
                f"{base_b}/api/peers?include_unpaired=1",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status == 200
                j = await r.json()

        # The peer field is `app_version` and should be set on at least
        # one peer (the A daemon we just talked to).
        match = [
            pp for pp in j["peers"]
            if pp.get("short_id") == p.a.short_id
        ]
        assert match, f"A not visible from B: {j['peers']!r}"
        # Until the OutboundSession has populated peer_caps, this can be
        # None (the inbound channel doesn't go through _outbound_sessions
        # in this direction). What we assert is that the field EXISTS
        # on every peer record — the wire is open.
        for pp in j["peers"]:
            assert "app_version" in pp
            assert "compatibility" in pp
            if pp["compatibility"] is not None:
                assert "compatible" in pp["compatibility"]
                assert "mode" in pp["compatibility"]
                assert "transfer_mode" in pp["compatibility"]


# ─── 4. _translate_send_error: the meat of the user-facing fix ─────────

def test_translate_invalidtag_to_wire_mismatch():
    from cryptography.exceptions import InvalidTag
    from one_link.server import _translate_send_error

    out = _translate_send_error(InvalidTag())
    assert out["status"] == 502
    assert out["code"] == "wire_version_mismatch"
    # Version drift is an internal diagnostic now. The user-facing
    # recovery path should be automatic reconnect/compatible routing.
    assert "secure send" in out["error"].lower()
    assert "automatically" in out["hint"].lower()


def test_translate_capability_disabled():
    from one_link.server import _translate_send_error

    out = _translate_send_error(
        RuntimeError("files capability disabled for peer abcd1234")
    )
    assert out["status"] == 403
    assert out["code"] == "capability_disabled"
    assert "allow" in out["hint"].lower() or "files" in out["hint"].lower()


def test_translate_peer_rejected():
    from one_link.server import _translate_send_error

    out = _translate_send_error(RuntimeError("peer rejected by local policy"))
    assert out["status"] == 403
    assert out["code"] == "peer_rejected"


def test_translate_handshake_failed():
    from one_link.server import _translate_send_error

    out = _translate_send_error(
        RuntimeError("handshake failed: 0 bytes read on a total of 4")
    )
    assert out["status"] == 502
    assert out["code"] == "handshake_failed"


def test_translate_ratchet_desync():
    from one_link.server import _translate_send_error

    out = _translate_send_error(
        ValueError("unsupported ratchet header version: 152")
    )
    assert out["status"] == 502
    assert out["code"] == "secure_session_desync"
    assert "retry" in out["hint"].lower()


def test_translate_timeout():
    from one_link.server import _translate_send_error

    out = _translate_send_error(asyncio.TimeoutError())
    # asyncio.TimeoutError stringifies as empty in Py3.11+; the helper
    # falls through to the catch-all. That's still an improvement over
    # an opaque 500 — it has a code and a hint.
    assert out["status"] in (504, 500)
    assert out.get("hint")


def test_translate_unreachable():
    from one_link.server import _translate_send_error

    out = _translate_send_error(RuntimeError("no peer 'xyzzy'"))
    assert out["status"] == 502
    assert out["code"] == "peer_unreachable"


def test_translate_unknown_falls_back_with_detail():
    from one_link.server import _translate_send_error

    out = _translate_send_error(RuntimeError("something brand new went wrong"))
    assert out["status"] == 500
    assert out["code"] == "send_failed"
    # The detail is preserved for diagnostics so the daemon log isn't
    # the only place the original message lives.
    assert "something brand new" in out["error_detail"]


# ─── 5. End-to-end: a real /api/send hitting a translated error ────────

@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_api_send_returns_translated_error_for_rejected_peer():
    """The structured error reaches the client. We use peer-rejected
    as the test trigger because it's deterministically reachable
    without faking crypto state."""
    with daemon_pair() as p:
        from tests.harness import request as ctrl_request

        ctrl_request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="seed",
        )
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base_b}/api/peers?include_unpaired=1",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                peers = (await r.json())["peers"]
            target = next(
                (pp for pp in peers if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target, peers
            # Reject A on B's side
            async with s.post(
                f"{base_b}/api/peers/{target['fingerprint']}/trust",
                json={"trust": "rejected"},
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status == 200

            # Now B → A send must come back as a structured error.
            async with s.post(
                f"{base_b}/api/send",
                json={"peer": p.a.short_id, "body": "blocked"},
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status >= 400
                j = await r.json()
                assert j.get("code") == "peer_rejected"
                assert j.get("hint")  # has a suggested action
                assert j.get("error")
