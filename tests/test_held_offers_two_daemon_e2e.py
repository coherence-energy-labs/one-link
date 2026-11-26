"""Two real daemons: what happens around a file that is waiting for the owner.

Until this file, no test accepted a held offer between two real daemons; the
one live test of accept-first stopped at "the offer is held". What happens
around a held offer is where a live install went wrong on 2026-11-25:

  12:09:09  a file is offered and HELD for the owner's answer
  12:11:09  the receiver closes that session as "idle for 120s", though the
            sender had been told to wait and waits five minutes
  12:11:13  the sender's command having failed, the file is sent again: refused,
            ``admission_blob_in_use_by_another_delivery`` (13 times by 12:27)
  later     with three files held, every further file is refused,
            ``admission_peer_inbound_transfer_quota``

The receiving owner had not been asked anything they could see. Each step has a
test here against the real offer handler, the real wire and the real accept
API. The decisions themselves are unit-tested in
tests/test_held_offer_makes_later_offers_wait.py.

A sender daemon offers one file at a time to a given peer and keeps the rest
behind it, so "a second offer while the first is held" is produced here the way
the existing accept-first test produces offers: as wire frames through the
sender's authenticated session. That is the receiver's view of a sender whose
earlier session has ended.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from tests.daemon_readiness import wait_for_owner_http
from tests import harness
from tests.harness import DaemonHandle, daemon_pair, request, wait_for_inbox_file

pytestmark = pytest.mark.timeout(120)

_LOAD_REFUSALS = (
    "blob_in_use_by_another_delivery",
    "peer_inbound_transfer_quota",
    "peer_inbound_byte_quota",
    "global_inbound_transfer_quota",
    "global_inbound_byte_quota",
)


def _owner_api(handle: DaemonHandle, method: str, path: str) -> dict:
    """Call the daemon's owner API the way its window does."""
    port, token, _elapsed = wait_for_owner_http(handle.home, handle.proc, timeout=60.0)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method=method,
        data=b"" if method == "POST" else None,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"{method} {path} -> HTTP {exc.code}: {exc.read()[:300]!r}") from exc


def _pending(handle: DaemonHandle) -> list[dict]:
    return _owner_api(handle, "GET", "/api/transfers/pending")["offers"]


def _wait_for_pending(handle: DaemonHandle, count: int, *, timeout: float = 40.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    offers: list[dict] = []
    while time.monotonic() < deadline:
        offers = _pending(handle)
        if len(offers) == count:
            return offers
        time.sleep(0.2)
    raise AssertionError(f"expected {count} held offer(s), saw {[o['name'] for o in offers]}")


def _log(handle: DaemonHandle) -> str:
    return handle.log.read_text(encoding="utf-8", errors="replace")


def _wait_for_log(handle: DaemonHandle, needle: str, *, at_least: int = 1, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    seen = 0
    while time.monotonic() < deadline:
        seen = _log(handle).count(needle)
        if seen >= at_least:
            return
        time.sleep(0.2)
    raise AssertionError(f"{needle!r} appeared {seen} time(s) in the receiver's log, expected {at_least}")


def _rows_refused_for_load(handle: DaemonHandle) -> list[dict]:
    rows = request(handle.control_port, cmd="transfers").get("transfers", [])
    return [
        {"name": row.get("name"), "error": (row.get("metadata") or {}).get("error")}
        for row in rows
        if row.get("direction") == "in" and (row.get("metadata") or {}).get("error") in _LOAD_REFUSALS
    ]


def _offer_frame(name: str, payload: bytes) -> dict:
    """A FILE_OFFER as a current peer sends it: a new message id and a new delivery id each time."""
    import blake3

    digest = blake3.blake3(payload).hexdigest()
    return {
        "t": "FILE_OFFER",
        "id": uuid.uuid4().hex,
        "blob": digest,
        "name": name,
        "size": len(payload),
        "delivery_id": uuid.uuid4().hex,
        "chunks": [{"index": 0, "hash": digest, "size": len(payload), "start": 0, "end": len(payload)}],
    }


def _offer(p, frame: dict) -> None:
    # The hook's own reply only says whether an ACK came back. An offer that
    # is held is answered with FILE_OFFER_HELD instead, so the hook reports
    # "not ok" for a frame that was delivered and handled. What the receiver
    # did with it is read from the receiver, below.
    request(p.a.control_port, cmd="_send_raw_message", peer=p.b.short_id, message=frame)


def _open_session(p) -> None:
    assert request(p.a.control_port, cmd="send", peer=p.b.short_id, body="hi").get("ok")


class _Send(threading.Thread):
    """One blocking `send_file` control call, as the command line makes it."""

    def __init__(self, sender: DaemonHandle, receiver: DaemonHandle, path: Path, *, timeout: float) -> None:
        super().__init__(daemon=True)
        self._args = (sender.control_port, receiver.short_id, str(path), timeout)
        self.reply: dict | None = None
        self.error: str | None = None

    def run(self) -> None:
        port, peer, path, timeout = self._args
        try:
            self.reply = request(port, timeout=timeout, cmd="send_file", peer=peer, path=path)
        except Exception as exc:  # the pair may be torn down under a send still waiting
            self.error = f"{type(exc).__name__}: {exc}"

    def outcome(self) -> str:
        if self.is_alive():
            return "waiting"
        if self.reply is not None and self.reply.get("ok"):
            return "delivered"
        return f"failed: {self.error or (self.reply or {}).get('error')}"


@pytest.mark.live_daemon
def test_a_second_offer_of_a_held_file_waits_and_is_not_recorded_as_refused(monkeypatch):
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    with daemon_pair(pin_trust=True) as p:
        _open_session(p)
        payload = b"held-then-sent-again\n" * 300
        _offer(p, _offer_frame("twice.txt", payload))
        held = _wait_for_pending(p.b, 1)

        # The same file again under a new delivery, three times, as a sender
        # does when its earlier command has ended without an answer.
        for attempt in range(1, 4):
            _offer(p, _offer_frame("twice.txt", payload))
            _wait_for_log(p.b, "file offer WAITS behind a held offer", at_least=attempt)

        assert _rows_refused_for_load(p.b) == []
        assert "REFUSED (blob_in_use_by_another_delivery)" not in _log(p.b)
        # One question for the owner, however many times the sender asked,
        # and it is still the first one.
        assert [o["transfer_id"] for o in _pending(p.b)] == [held[0]["transfer_id"]]


@pytest.mark.live_daemon
def test_files_beyond_the_transfer_limit_wait_while_the_owner_has_not_answered(monkeypatch):
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    with daemon_pair(pin_trust=True) as p:
        _open_session(p)
        frames = [
            _offer_frame(f"batch-{index}.txt", f"file number {index}\n".encode() * (40 + index))
            for index in range(5)
        ]
        for frame in frames[:3]:
            _offer(p, frame)
        held = _wait_for_pending(p.b, 3)
        assert sorted(o["name"] for o in held) == ["batch-0.txt", "batch-1.txt", "batch-2.txt"]

        # The per-device limit on admitted transfers is three. The next two
        # are not transfers yet; nobody has answered the first three.
        for frame in frames[3:]:
            _offer(p, frame)
        _wait_for_log(p.b, "file offer WAITS for earlier offers to be answered", at_least=2)
        assert _rows_refused_for_load(p.b) == [], "a file was refused while the owner had not been asked"
        assert len(_pending(p.b)) == 3

        # The owner answers one. The file that waited is asked for again (a
        # sender retries the same delivery) and now reaches the owner.
        first = next(o for o in held if o["name"] == "batch-0.txt")
        assert _owner_api(p.b, "POST", f"/api/transfers/{first['transfer_id']}/decline").get("ok") is True
        _wait_for_pending(p.b, 2)
        retry = dict(frames[3], id=uuid.uuid4().hex)
        _offer(p, retry)
        after = _wait_for_pending(p.b, 3)
        assert sorted(o["name"] for o in after) == ["batch-1.txt", "batch-2.txt", "batch-3.txt"]
        assert _rows_refused_for_load(p.b) == []


@pytest.mark.live_daemon
def test_a_held_file_arrives_after_the_owner_accepts(monkeypatch):
    """The ordinary flow, end to end: send, held, accept, arrives, sender is told."""
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    with daemon_pair(pin_trust=True) as p:
        payload = b"accepted and delivered\n" * 400
        source = p.tmp / "wanted.txt"
        source.write_bytes(payload)

        send = _Send(p.a, p.b, source, timeout=100.0)
        send.start()
        held = _wait_for_pending(p.b, 1)
        assert held[0]["name"] == "wanted.txt" and held[0]["size"] == len(payload)
        assert send.outcome() == "waiting"
        assert not list((p.b.home / "data" / "inbox").glob("*wanted.txt")), "bytes arrived before consent"

        accepted = _owner_api(p.b, "POST", f"/api/transfers/{held[0]['transfer_id']}/accept")
        assert accepted == {"ok": True}

        received = wait_for_inbox_file(p.b.home, "wanted.txt", expected_size=len(payload), timeout=60.0)
        assert received.read_bytes() == payload
        send.join(timeout=60.0)
        assert send.outcome() == "delivered", send.outcome()
        assert _pending(p.b) == []
        assert _rows_refused_for_load(p.b) == []


@pytest.mark.live_daemon
@pytest.mark.timeout(300)
def test_a_session_waiting_for_the_owner_outlives_the_ordinary_idle_limit(monkeypatch):
    """Two minutes is not how long a person has to notice a prompt.

    The receiver used to close a held offer's session at its ordinary idle
    limit (120 s), although it had told the sender to keep waiting and the
    sender waits five minutes. An owner who clicked Accept after that was told
    the sender had gone offline. Here the owner answers 135 seconds in, and the
    acceptance must reach the sender on the session that carried the offer.
    """
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    with daemon_pair(pin_trust=True) as p:
        payload = b"worth the wait\n" * 300
        source = p.tmp / "patient.txt"
        source.write_bytes(payload)

        send = _Send(p.a, p.b, source, timeout=280.0)
        send.start()
        held = _wait_for_pending(p.b, 1)
        held_at = time.monotonic()

        while time.monotonic() - held_at < 135.0:
            assert send.outcome() == "waiting", (
                f"the sender stopped waiting {time.monotonic() - held_at:.0f}s in: {send.outcome()}"
            )
            time.sleep(5.0)

        accepted = _owner_api(p.b, "POST", f"/api/transfers/{held[0]['transfer_id']}/accept")
        # ``ok: False`` with "sender offline; it will resend" is what an
        # owner got when the session had been closed under the offer.
        assert accepted == {"ok": True}, accepted

        received = wait_for_inbox_file(p.b.home, "patient.txt", expected_size=len(payload), timeout=60.0)
        assert received.read_bytes() == payload
        send.join(timeout=60.0)
        assert send.outcome() == "delivered", send.outcome()

@pytest.mark.live_daemon
@pytest.mark.timeout(240)
def test_accepted_offer_survives_sender_disconnect_and_new_delivery(monkeypatch):
    """Real owner consent, a dead sender, a fresh session and a new delivery.

    The initial raw offer deliberately carries no outbound queue entry, so a
    later normal send_file creates a new delivery rather than replaying the
    first one. No sender mock or direct mutation of the receiver is involved.
    """
    monkeypatch.setenv("ONE_LINK_REQUIRE_FILE_ACCEPT", "1")
    scope = harness.private_mdns_type()
    monkeypatch.setattr(harness, "private_mdns_type", lambda: scope)
    with daemon_pair(pin_trust=True, periodic_folder_sync=False) as p:
        _open_session(p)
        payload = b"owner accepted while sender was away\\n" * 800
        source = p.tmp / "reconnect.txt"
        source.write_bytes(payload)
        first = _offer_frame(source.name, payload)
        _offer(p, first)
        held = _wait_for_pending(p.b, 1)
        old_tid = held[0]["transfer_id"]
        old_fp = p.a.fingerprint
        assert held[0]["size"] == len(payload)

        stop = request(p.a.control_port, cmd="shutdown")
        assert stop.get("ok") is True and stop.get("stopping") is True
        assert p.a.proc.wait(timeout=20) == 0
        # The offer channel may already have disconnected before shutdown
        # (for example due to endpoint/transport changes); no particular log
        # count is an invariant. The process exit and owner response are.
        accepted = _owner_api(p.b, "POST", f"/api/transfers/{old_tid}/accept")
        assert accepted == {"ok": False, "error": "sender offline; it will resend"}, accepted
        assert _pending(p.b) == []
        assert not list((p.b.home / "data" / "inbox").glob("*reconnect.txt"))

        # Restart only the disposable sender in its original private scope.
        # The context manager owns this handle; mutate its fields so teardown
        # reaps the restarted process even if an assertion fails.
        if p.a.log_fh is not None:
            p.a.log_fh.close()
        for stale in ("server.port", "control.port", "peer.port", "ui.token"):
            (p.a.home / "data" / stale).unlink(missing_ok=True)
        replacement = harness._bring_up(
            p.a.home, p.a.log, "A (fresh session)", mdns_type=scope,
            periodic_folder_sync=False,
        )
        p.a.__dict__.update(replacement.__dict__)
        assert p.a.fingerprint == old_fp
        assert _owner_api(p.a, "POST", f"/api/peers/{p.b.fingerprint}/_test_force_dial") == {
            "ok": True, "fingerprint": p.b.fingerprint,
        }

        # Same content is not enough: a changed public name must not inherit
        # the consent. The receiver's real admission path must refuse it.
        renamed = _offer_frame("not-accepted.txt", payload)
        _offer(p, renamed)
        _wait_for_log(p.b, "REFUSED (blob_in_use_by_another_delivery)")
        assert not list((p.b.home / "data" / "inbox").glob("*not-accepted.txt"))

        # Only the identical presentation from the same authenticated device
        # may inherit that single consent. No second owner click is supplied.
        send = _Send(p.a, p.b, source, timeout=100.0)
        send.start()
        _wait_for_log(p.b, "accepted file offer SUPERSEDED")
        received = wait_for_inbox_file(p.b.home, source.name, expected_size=len(payload), timeout=60.0)
        assert received.read_bytes() == payload
        send.join(timeout=60.0)
        assert send.outcome() == "delivered", send.outcome()
        assert _pending(p.b) == []
        rows = request(p.b.control_port, cmd="transfers")["transfers"]
        old = next(row for row in rows if row["id"] == old_tid)
        assert old["status"] == "failed"
        assert old["metadata"]["delivery_state"] == "superseded"
        completed = [row for row in rows if row["direction"] == "in"
                     and row["name"] == source.name and row["status"] == "complete"]
        assert len(completed) == 1
        assert completed[0]["id"] != old_tid
        assert completed[0]["metadata"]["delivery_id"] != first["delivery_id"]
