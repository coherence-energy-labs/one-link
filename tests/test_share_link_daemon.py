"""Daemon-level integration tests for Wave 2g share-link.

Verifies the four control endpoints (create_share_link,
redeem_share_link, list_share_links, revoke_share_link) round-
trip cleanly against a real daemon, and that the registry
persists across daemon restarts.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.harness import _bring_up, daemon_pair, inbox_files, request


pytestmark = [pytest.mark.timeout(120), pytest.mark.soak]


@pytest.mark.live_daemon
def test_create_share_link_returns_sas_and_token(tmp_path: Path) -> None:
    """Minting via the control API returns both the human-
    readable SAS phrase and the raw token. Sender shares the SAS
    with the recipient out of band."""
    src = tmp_path / "shared.bin"
    src.write_bytes(b"hello-share-link" * 64)
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="create_share_link",
            path=str(src),
        )
        assert res.get("ok"), res
        assert isinstance(res.get("token_hex"), str)
        assert len(res["token_hex"]) == 64
        assert isinstance(res.get("sas_phrase"), str)
        assert len(res["sas_phrase"].split(" ")) == 8
        assert res["size"] == len(b"hello-share-link" * 64)
        assert res["expires_at_ms"] > int(time.time() * 1000)


@pytest.mark.live_daemon
def test_redeem_consumes_share_link(tmp_path: Path) -> None:
    """Recipient hands the token back through redeem_share_link;
    the registry marks consumed; second redeem with the same
    token reports already_redeemed."""
    src = tmp_path / "consume.bin"
    src.write_bytes(b"consume-payload" * 32)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        token_hex = mint["token_hex"]
        # First redeem succeeds.
        redeem1 = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert redeem1.get("ok"), redeem1
        assert redeem1["blob"] == mint["blob"]
        assert redeem1["redeemed_at_ms"] is not None
        # Second redeem must fail with the single-use guard.
        redeem2 = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert not redeem2.get("ok")
        assert redeem2.get("error") == "already_redeemed"


@pytest.mark.live_daemon
def test_redeem_unknown_token(tmp_path: Path) -> None:
    """A token the daemon never minted must report not_found —
    not crash, not return success."""
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex="0" * 64,
        )
        assert not res.get("ok")
        assert res.get("error") == "not_found"


@pytest.mark.live_daemon
def test_redeem_rejects_malformed_token() -> None:
    """token_hex must be exactly 64 hex chars; anything else is
    rejected at the boundary."""
    with daemon_pair() as p:
        res = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex="short",
        )
        assert not res.get("ok")
        assert "64 hex" in res.get("error", "")


@pytest.mark.live_daemon
def test_list_share_links_omits_token(tmp_path: Path) -> None:
    """Listing surfaces user-facing fields (SAS phrase, size,
    expiry) but never the raw token. Tokens are bearer secrets;
    they go out via the mint endpoint once + don't reappear."""
    src = tmp_path / "lst.bin"
    src.write_bytes(b"x" * 256)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        listed = request(p.a.control_port, cmd="list_share_links")
        assert listed.get("ok"), listed
        assert listed["count"] >= 1
        found = None
        for entry in listed["links"]:
            if entry["blob"] == mint["blob"]:
                found = entry
                break
        assert found is not None
        assert "token_hex" not in found
        assert "token" not in found
        assert found["sas_phrase"] == mint["sas_phrase"]
        assert found["consumed"] is False


@pytest.mark.live_daemon
def test_revoke_share_link_removes(tmp_path: Path) -> None:
    """Sender can revoke a still-active share-link before the
    recipient redeems."""
    src = tmp_path / "rev.bin"
    src.write_bytes(b"r" * 128)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        rev = request(
            p.a.control_port, cmd="revoke_share_link",
            blob=mint["blob"],
        )
        assert rev.get("ok")
        assert rev.get("revoked") is True
        # Subsequent redeem fails.
        redeem = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=mint["token_hex"],
        )
        assert not redeem.get("ok")
        assert redeem.get("error") == "not_found"


@pytest.mark.live_daemon
def test_claim_share_link_from_peer_end_to_end(tmp_path: Path) -> None:
    """Recipient-side public API: ``claim_share_link_from_peer``
    constructs + sends SHARE_LINK_REDEEM behind the scenes. UI
    surfaces should call THIS command, not the test-only raw-
    message hook. End-to-end this commit closes the share-link
    UX loop."""
    src = tmp_path / "claim-payload.bin"
    payload = b"claim-share-link" * 32
    src.write_bytes(payload)
    with daemon_pair(pin_trust=True) as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        # Warm B → A channel so send_to has somewhere to land.
        request(p.b.control_port, cmd="send",
                peer=p.a.short_id, body="warmup")
        time.sleep(0.5)
        # B claims the share-link via the new control endpoint.
        claim = request(
            p.b.control_port, cmd="claim_share_link_from_peer",
            peer=p.a.short_id,
            token_hex=mint["token_hex"],
        )
        assert claim.get("ok"), claim
        # Wait for the file to land in B's inbox.
        end = time.time() + 20.0
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
            time.sleep(0.2)
        assert landed is not None, (
            "claim_share_link_from_peer didn't trigger the transfer"
        )


@pytest.mark.live_daemon
def test_share_link_redeem_wire_frame_triggers_file_offer(tmp_path: Path) -> None:
    """A peer that presents a valid token via SHARE_LINK_REDEEM
    wire frame must trigger the sender to fire a FILE_OFFER for
    the blob the token points at. This is the on-wire half of
    Wave 2g — the recipient-side machinery to construct +
    transmit the frame lives in a follow-up control endpoint, so
    here we use the test-only ``_send_raw_message`` hook to
    inject the frame directly."""
    src = tmp_path / "shared-payload.bin"
    payload = b"share-link-end-to-end" * 32
    src.write_bytes(payload)
    with daemon_pair(pin_trust=True) as p:
        # A is the sender + share-link minter.
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        token_hex = mint["token_hex"]
        # Warm channel.
        request(p.b.control_port, cmd="send",
                peer=p.a.short_id, body="warmup")
        time.sleep(0.5)
        # B sends the redeem frame to A — bypasses any UI flow;
        # the test simulates a future "claim_share_link" control
        # cmd or UI button.
        res = request(
            p.b.control_port, cmd="_send_raw_message",
            peer=p.a.short_id,
            message={"t": "SHARE_LINK_REDEEM", "token_hex": token_hex},
        )
        # ok=True regardless — the receiver ACKs immediately
        # whether accepting or rejecting; in success case the
        # follow-up send_file runs asynchronously.
        assert res.get("ok"), res
        # Wait for the file to land in B's inbox.
        end = time.time() + 20.0
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
            time.sleep(0.2)
        assert landed is not None, (
            "Share-link redeem didn't trigger the file transfer; "
            "either the wire frame handler didn't run or send_file failed."
        )
        # The token must now be marked consumed.
        redeem_again = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert not redeem_again.get("ok")
        assert redeem_again.get("error") == "already_redeemed"


@pytest.mark.live_daemon
def test_share_link_redeem_wire_rejects_bad_token() -> None:
    """A SHARE_LINK_REDEEM with a token that was never minted
    must be rejected — no file offer fires, no spurious transfer
    row appears on the sender side."""
    with daemon_pair() as p:
        # Warm so the channel is alive.
        request(p.b.control_port, cmd="send",
                peer=p.a.short_id, body="warmup")
        time.sleep(0.5)
        # B sends a redeem with garbage token.
        res = request(
            p.b.control_port, cmd="_send_raw_message",
            peer=p.a.short_id,
            message={"t": "SHARE_LINK_REDEEM", "token_hex": "f" * 64},
        )
        # ACK arrives (with rejected= field). _send_raw_message
        # surfaces it either as ok=True (sent fine) or ok=False
        # with the rejected reason — both shapes are acceptable.
        # Critical: no inbound file transfer rows on B.
        time.sleep(1.0)
        rows = request(p.b.control_port, cmd="transfers")
        in_files = [
            t for t in rows.get("transfers", [])
            if t.get("direction") == "in" and t.get("kind") == "file"
            and t.get("status") in ("offered", "active")
        ]
        assert not in_files, (
            f"bad-token redeem should not trigger file offer; got {in_files}"
        )


@pytest.mark.live_daemon
def test_share_link_redeem_wire_rejects_malformed_token() -> None:
    """A SHARE_LINK_REDEEM with a non-64-char token gets the
    rejected=bad_share_link_token ACK and produces no transfer."""
    with daemon_pair() as p:
        request(p.b.control_port, cmd="send",
                peer=p.a.short_id, body="warmup")
        time.sleep(0.5)
        request(
            p.b.control_port, cmd="_send_raw_message",
            peer=p.a.short_id,
            message={"t": "SHARE_LINK_REDEEM", "token_hex": "short"},
        )
        time.sleep(1.0)
        rows = request(p.b.control_port, cmd="transfers")
        in_files = [
            t for t in rows.get("transfers", [])
            if t.get("direction") == "in" and t.get("kind") == "file"
            and t.get("status") in ("offered", "active")
        ]
        assert not in_files


@pytest.mark.live_daemon
def test_share_link_survives_daemon_restart(tmp_path: Path) -> None:
    """Minted tokens persist to disk and the registry reloads on
    daemon restart so recipients can redeem hours later."""
    src = tmp_path / "persist.bin"
    src.write_bytes(b"p" * 256)
    with daemon_pair() as p:
        mint = request(p.a.control_port, cmd="create_share_link", path=str(src))
        assert mint.get("ok"), mint
        token_hex = mint["token_hex"]
        # Kill A and restart on same home.
        p.a.proc.kill()
        try:
            p.a.proc.wait(timeout=5.0)
        except Exception:
            pass
        try:
            if p.a.log_fh is not None:
                p.a.log_fh.close()
        except Exception:
            pass
        # Clear stale ports so _bring_up waits for the new daemon.
        for stale in ("control.port", "peer.port", "instance.lock"):
            sp = p.a.home / "data" / stale
            try:
                sp.unlink()
            except OSError:
                pass
        new_a = _bring_up(p.a.home, p.a.log, "A-restart")
        p.a = new_a
        # Token still valid.
        redeem = request(
            p.a.control_port, cmd="redeem_share_link",
            token_hex=token_hex,
        )
        assert redeem.get("ok"), redeem
        assert redeem["blob"] == mint["blob"]
