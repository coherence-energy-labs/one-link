"""Two-daemon e2e: accept-first holds an incoming file by default.

Proves the cross-machine behaviour: with the default "always ask"
policy, a standalone FILE_OFFER from peer A is HELD on peer B pending
the user's acceptance (it does NOT auto-download). daemon_pair() gates
itself behind ONE_LINK_RUN_LIVE_INTEGRATION, so this only runs in the
live-integration lane.
"""
from __future__ import annotations

import time
import uuid

import pytest

from tests.harness import daemon_pair, request

pytestmark = pytest.mark.timeout(120)


def _offer_frame(name: str, payload: bytes) -> dict:
    import blake3 as _b3
    h = _b3.blake3(payload).hexdigest()
    return {
        "t": "FILE_OFFER",
        "id": uuid.uuid4().hex,
        "blob": h,
        "name": name,
        "size": len(payload),
        # Current peers negotiate durable commit receipts. Their offer
        # contract therefore requires a stable 128-bit delivery identity so
        # retries can be correlated without creating duplicate inbox files.
        "delivery_id": uuid.uuid4().hex,
        "chunks": [
            {"index": 0, "hash": h, "size": len(payload),
             "start": 0, "end": len(payload)},
        ],
    }


@pytest.mark.live_daemon
def test_incoming_file_is_held_pending_accept_by_default(monkeypatch):
    # The harness defaults accept-first OFF for its daemons; opt back IN
    # here so the spawned pair runs the production default behaviour.
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    # Exercise consent after the normal SAS/pin boundary. Pending identities
    # correctly have neither chat nor file capability, so leaving the harness
    # pair unpinned would test only the trust gate and never reach accept-first.
    with daemon_pair(pin_trust=True) as p:
        # require-accept is ON by default, so B must HOLD A's file offer
        # instead of pulling it.
        assert request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="hi",
        ).get("ok")
        frame = _offer_frame("secret.bin", b"hold-me" * 200)
        request(
            p.a.control_port, cmd="_send_raw_message",
            peer=p.b.short_id, message=frame,
        )
        deadline = time.time() + 20.0
        held = None
        while time.time() < deadline:
            rows = request(p.b.control_port, cmd="transfers")
            for t in rows.get("transfers", []):
                if (
                    t.get("blob_hash") == frame["blob"]
                    and t.get("direction") == "in"
                ):
                    held = t
            if held and (held.get("metadata") or {}).get("needs_accept"):
                break
            time.sleep(0.2)
        assert held is not None, "B never recorded the incoming offer"
        md = held.get("metadata") or {}
        assert md.get("needs_accept") is True, f"offer was not held: {held}"
        assert md.get("delivery_state") == "awaiting_acceptance", held
        assert held.get("status") == "offered", held
